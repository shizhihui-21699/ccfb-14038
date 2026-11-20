"""AdaGuard 消融实验: 逐层关闭防御组件, 验证每层的独立贡献。

运行: .venv/bin/python -m robust_fl.ablation
输出: results/ablation.csv
"""
from __future__ import annotations

import csv
import os

import numpy as np
import torch

from .aggregators import _cos, _greedy_cosine_clusters
from .data import ArrayDataset, dirichlet_noniid_split, make_dataset
from .model import TinyCNN, flatten_params
from .run_experiments import SCENARIOS
from .simulation import make_scenario, run_federation

ROUNDS = 20


def _variant(use_l1: bool, use_l2: bool, use_l4: bool, use_l3: bool,
             soft_cap: bool):
    """按开关组合出一个 AdaGuard 变体, 签名与标准聚合器一致。"""
    def fn(updates, is_malicious, root_update, **kw):
        U = torch.stack(updates)
        n = U.shape[0]

        if use_l1:  # L1 范数裁剪
            norms = U.norm(dim=1)
            tau = norms.median() * 2.0
            U = U * ((tau / norms).clamp(max=1.0)).unsqueeze(1)

        if use_l2:  # L2 根信任分
            trust = torch.tensor(
                [max(0.0, _cos(u, root_update).item()) for u in U])
            if trust.sum() <= 0:
                return root_update.clone(), {
                    "weights": torch.zeros(n),
                    "flags": torch.ones(n, dtype=torch.bool)}
            w = trust / trust.sum()
        else:
            trust = torch.ones(n) / n
            w = trust.clone()

        if use_l4:  # L4 簇上限
            clusters = _greedy_cosine_clusters(U, 0.90)
            cap = 2.0 / n
            for _ in range(3):
                overflow, uncapped = 0.0, 0.0
                for cl in clusters:
                    mass = w[cl].sum()
                    if mass > cap + 1e-12:
                        overflow += mass - cap
                    else:
                        uncapped += mass
                if overflow <= 1e-12 or uncapped <= 1e-12:
                    break
                for cl in clusters:
                    mass = w[cl].sum()
                    if mass > cap + 1e-12:
                        w[cl] = cap * w[cl] / mass
                    else:
                        w[cl] += overflow * w[cl] / uncapped
        else:
            clusters = []

        if use_l3:  # L3 加权坐标截断
            order = U.argsort(dim=0)
            U_sorted = torch.gather(U, 0, order)
            w_exp = w[order]
            cum = w_exp.cumsum(0)
            keep = (cum > 0.1) & (cum <= 0.9 + 1e-9)
            k_trim = max(1, int(round(0.1 * n)))
            keep[:n - 2 * k_trim, :] |= True
            w_kept = w_exp * keep
            out = ((w_kept * U_sorted * keep).sum(0)
                   / w_kept.sum(0).clamp_min(1e-12))
        else:
            out = (w.unsqueeze(1) * U).sum(0)

        if soft_cap:
            rn = root_update.norm().clamp_min(1e-12)
            if out.norm() > 2.0 * rn:
                out = out * (2.0 * rn / out.norm())

        return out, {"weights": w,
                     "flags": trust < (0.5 / n),
                     "clusters": clusters}
    return fn


VARIANTS = {
    "full_adaguard":      (True, True, True, True, True),
    "no_L1_clip":         (False, True, True, True, True),
    "no_L2_trust":        (True, False, True, True, True),
    "no_L4_cluster_cap":  (True, True, False, True, True),
    "no_L3_trim":         (True, True, True, False, True),
    "no_soft_cap":        (True, True, True, True, False),
    "L2_only_like_fltrust_minus_align": (False, True, False, False, False),
}


def main():
    torch.set_num_threads(max(1, os.cpu_count() - 1))
    seed = 42
    torch.manual_seed(seed)
    np.random.seed(seed)

    X, y = make_dataset(n_per_class=1100, seed=seed)
    test_ds = ArrayDataset(X[:900], y[:900])
    Xp, yp = X[900:], y[900:]
    splits = dirichlet_noniid_split(Xp, yp, 10, alpha=0.3, seed=seed)
    rng = np.random.default_rng(seed + 1)
    ri = rng.choice(len(Xp), 300, replace=False)
    root_ds = ArrayDataset(Xp[ri], yp[ri])
    torch.manual_seed(seed + 999)
    init = flatten_params(TinyCNN())

    # 良性(误伤代价) + 后门(L3/步长闸门) + 合谋(L4 簇上限) 三个场景最能区分组件
    specs = {s["name"]: s for s in SCENARIOS}
    pick = [specs["S0_benign"], specs["S3_backdoor_30pct"],
            specs["S4_stealth_30pct"], specs["S5_collusion_40pct"]]

    from .aggregators import AGGREGATORS
    rows = []
    for vname, switches in VARIANTS.items():
        AGGREGATORS["_ablation"] = _variant(*switches)
        for spec in pick:
            scn = make_scenario(spec, 10)
            r = run_federation(scn, "_ablation", splits, test_ds, root_ds,
                               rounds=ROUNDS, local_epochs=2, lr=0.05,
                               batch_size=32, base_seed=seed, init_flat=init)
            rows.append({
                "variant": vname, "scenario": scn.name,
                "accuracy": round(r["final_accuracy"], 4),
                "source_recall": round(r["final_source_recall"], 4),
                "asr": (None if np.isnan(r["final_asr"])
                        else round(r["final_asr"], 4)),
                "detection_fpr": round(r["detection_fpr"], 3)})
            print(rows[-1])

    out_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "results")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "ablation.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"消融结果写入 {path}")


if __name__ == "__main__":
    main()
