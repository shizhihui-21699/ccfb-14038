"""实验入口: 10 家医院 × 6 攻击场景 × 8 聚合器。

用法:
    python -m robust_fl.run_experiments --smoke     # 快速冒烟(2 轮, 子集)
    python -m robust_fl.run_experiments             # 完整实验
"""
from __future__ import annotations

import argparse
import json
import os
import time

import numpy as np
import torch

from .aggregators import AGGREGATORS, TOLERANCE
from .data import (NUM_CLASSES, dirichlet_noniid_split, make_dataset,
                   ArrayDataset)
from .model import TinyCNN, flatten_params
from .plotting import (plot_data_distribution, plot_final_bars,
                       plot_scenario_curves, write_summary_csv)
from .simulation import make_scenario, run_federation

NUM_CLIENTS = 10

# 6 个攻击场景。malicious 比例从 20% 到 40%, 覆盖各防御的理论失效边界。
SCENARIOS = [
    {"name": "S0_benign", "attack": "benign", "num_malicious": 0},
    {"name": "S1_gaussian_30pct", "attack": "gaussian",
     "num_malicious": 3, "noise_sigma": 3.0},
    {"name": "S2_signflip_20pct", "attack": "sign_flip",
     "num_malicious": 2, "norm_mult": 2.0},
    {"name": "S3_backdoor_30pct", "attack": "backdoor",
     "num_malicious": 3, "source_class": 0, "target_class": 1},
    {"name": "S4_stealth_30pct", "attack": "stealth_flip",
     "num_malicious": 3, "source_class": 0, "target_class": 1,
     "stealth_blend": 0.15, "norm_mult": 1.5},
    {"name": "S5_collusion_40pct", "attack": "collusion",
     "num_malicious": 4, "source_class": 0, "target_class": 1,
     "stealth_blend": 0.15, "norm_mult": 1.5},
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true", help="冒烟测试: 2 轮")
    ap.add_argument("--rounds", type=int, default=None)
    ap.add_argument("--out", default="results")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    torch.set_num_threads(max(1, os.cpu_count() - 1))
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    rounds = 2 if args.smoke else (args.rounds or 30)
    out_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), args.out + ("_smoke" if args.smoke else ""))
    os.makedirs(out_dir, exist_ok=True)

    # ---- 数据: 6 类 × 1100 张, 10 家医院 Dirichlet(α=0.3) 非 IID
    X, y = make_dataset(n_per_class=1100, seed=args.seed)
    n_test = 900
    X_test, y_test = X[:n_test], y[:n_test]
    X_pool, y_pool = X[n_test:], y[n_test:]
    test_ds = ArrayDataset(X_test, y_test)

    splits = dirichlet_noniid_split(X_pool, y_pool, NUM_CLIENTS,
                                    alpha=0.3, seed=args.seed)
    print("各医院类别样本数:")
    for s in splits:
        print(f"  医院{s.client_id:2d} (n={len(s.y):4d}): {s.class_counts.tolist()}")

    # 服务器可信根数据集: 300 张 IID 抽样(模拟公开基准/外购脱敏数据)
    rng = np.random.default_rng(args.seed + 1)
    root_idx = rng.choice(len(X_pool), size=300, replace=False)
    root_ds = ArrayDataset(X_pool[root_idx], y_pool[root_idx])

    # 固定初始化, 所有组合同一起点
    torch.manual_seed(args.seed + 999)
    init_flat = flatten_params(TinyCNN())

    results = []
    t0 = time.time()
    for spec in SCENARIOS:
        scenario = make_scenario(spec, NUM_CLIENTS)
        for agg_name in AGGREGATORS:
            ts = time.time()
            r = run_federation(
                scenario, agg_name, splits, test_ds, root_ds,
                rounds=rounds, local_epochs=2, lr=0.05,
                batch_size=32, base_seed=args.seed, init_flat=init_flat)
            results.append(r)
            print(f"[{time.time()-ts:6.1f}s] {scenario.name:22s} × "
                  f"{agg_name:13s} acc={r['tail_accuracy']:.3f} "
                  f"src_recall={r['tail_source_recall']:.3f} "
                  f"asr={(r['tail_asr'] if not np.isnan(r['tail_asr']) else float('nan')):.3f} "
                  f"TPR={(r['detection_tpr'] if not np.isnan(r['detection_tpr']) else float('nan')):.2f} "
                  f"FPR={(r['detection_fpr'] if not np.isnan(r['detection_fpr']) else float('nan')):.2f}")

    print(f"\n总耗时 {time.time()-t0:.1f}s")

    csv_path = write_summary_csv(results, out_dir)
    plot_data_distribution(splits, out_dir)
    plot_scenario_curves(results, out_dir)
    plot_final_bars(results, out_dir)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump({"results": results, "tolerance": TOLERANCE}, f,
                  ensure_ascii=False, indent=1)
    from .make_report import build_report
    build_report(os.path.join(out_dir, "results.json"),
                 os.path.join(out_dir, "report.md"))
    print(f"结果已写入 {out_dir}/ (summary.csv + 曲线图 + 柱状图 + "
          f"results.json + report.md)")


if __name__ == "__main__":
    main()
