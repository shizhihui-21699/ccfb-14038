"""防御选型决策辅助: 根据参与方数量与威胁假设给出聚合器适配建议。

用法:
    .venv/bin/python -m robust_fl.selector --hospitals 10 --max-malicious 4
"""
from __future__ import annotations

import argparse

# 选型依据: 理论容忍度 + 本项目实验实测表现(results/report.md)
PROFILES = {
    "fedavg": {
        "tolerance_ratio": 0.0,
        "needs_root": False,
        "benign_cost": "无",
        "best_for": "完全可信的封闭联盟, 仅作基线对照",
        "fails_on": "任何恶意更新都会按比例进入全局模型",
    },
    "clip_avg": {
        "tolerance_ratio": 0.5,
        "needs_root": False,
        "benign_cost": "极低",
        "best_for": "只防裸奔大范数攻击、无服务器根数据时的最低配防御",
        "fails_on": "范数伪装的定向攻击与后门(实测 ASR=1.0)",
    },
    "krum": {
        "tolerance_ratio": 0.4,
        "needs_root": False,
        "benign_cost": "高(非 IID 下良性准确率显著下降)",
        "best_for": "恶意方明确少于 (n-2)/2 且各自为战",
        "fails_on": "合谋比例超限后投票被接管(实测 40% 合谋时准确率 0.53)",
    },
    "multi_krum": {
        "tolerance_ratio": 0.4,
        "needs_root": False,
        "benign_cost": "中",
        "best_for": "同 Krum 前提, 但需要多更新平均以稳定收敛",
        "fails_on": "与 Krum 相同的合谋接管问题",
    },
    "trimmed_mean": {
        "tolerance_ratio": 0.5,
        "needs_root": False,
        "benign_cost": "低",
        "best_for": "无根数据时的稳健次选, 对独立离群更新有效",
        "fails_on": "后门(实测 ASR=1.0)与高比例合谋",
    },
    "coord_median": {
        "tolerance_ratio": 0.5,
        "needs_root": False,
        "benign_cost": "高(逐坐标中位数系统性低估步长, 收敛慢)",
        "best_for": "理论分析基准, 不建议单独生产使用",
        "fails_on": "后门部分残留(实测 ASR≈0.72)",
    },
    "fltrust": {
        "tolerance_ratio": 1.0,
        "needs_root": True,
        "benign_cost": "低",
        "best_for": "有代表性根数据、攻击以独立方为主的场景",
        "fails_on": "长期后门累积(30 轮 ASR 升至 0.99)与高比例同向合谋",
    },
    "adaguard": {
        "tolerance_ratio": 1.0,
        "needs_root": True,
        "benign_cost": "低(实测良性准确率损失约 1.3 个百分点)",
        "best_for": "同时存在定向攻击、后门与合谋风险的生产联邦",
        "fails_on": "根数据严重不代表全局分布时根锚失效(需保障根数据 IID)",
    },
}


def recommend(hospitals: int, max_malicious: int,
              has_root_data: bool) -> None:
    ratio = max_malicious / hospitals
    print(f"参与医院 {hospitals} 家, 假设最多 {max_malicious} 家恶意 "
          f"(比例 {ratio:.0%}), 服务器根数据: {'有' if has_root_data else '无'}\n")
    rows = []
    for name, p in PROFILES.items():
        if p["needs_root"] and not has_root_data:
            verdict = "✗ 依赖根数据, 当前不可用"
        elif ratio > p["tolerance_ratio"]:
            verdict = f"✗ 容忍上限 {p['tolerance_ratio']:.0%} < 威胁 {ratio:.0%}"
        else:
            verdict = "✓ 理论可用"
        rows.append((name, verdict, p))
    for name, verdict, p in rows:
        print(f"[{verdict}] {name}")
        print(f"    适用: {p['best_for']}")
        print(f"    失效: {p['fails_on']}")
        print(f"    良性代价: {p['benign_cost']} | 需根数据: {p['needs_root']}\n")

    viable = [n for n, v, _ in rows if v.startswith("✓")]
    print("推荐优先级:")
    if has_root_data and "adaguard" in viable:
        print("  1. adaguard (覆盖定向/后门/合谋三类威胁, 实测综合最优)")
        print("  2. fltrust (根锚可信但无合谋防护时的简化替代)")
    elif "trimmed_mean" in viable:
        print("  1. trimmed_mean (无根数据时的稳健次选)")
        print("  2. clip_avg (最低配, 需知晓其无法防定向攻击)")
    else:
        print("  当前威胁比例超出所有无根数据方法的容忍上限,")
        print("  建议: 降低单轮参与医院数中的恶意占比, 或建设服务器根数据后启用 adaguard。")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hospitals", type=int, default=10)
    ap.add_argument("--max-malicious", type=int, default=4)
    ap.add_argument("--no-root-data", action="store_true")
    args = ap.parse_args()
    recommend(args.hospitals, args.max_malicious,
              has_root_data=not args.no_root_data)


if __name__ == "__main__":
    main()
