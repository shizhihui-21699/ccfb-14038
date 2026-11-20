"""从 results.json 自动生成 Markdown 对比报告。"""
from __future__ import annotations

import json
import math
import os


def _fmt(v, nd=3):
    if v is None:
        return "—"
    try:
        if math.isnan(v):
            return "—"
    except TypeError:
        return "—"
    return f"{v:.{nd}f}"


def build_report(results_path: str, out_path: str) -> None:
    with open(results_path, encoding="utf-8") as f:
        payload = json.load(f)
    rows = payload["results"]
    tolerance = payload["tolerance"]

    scenarios = sorted({r["scenario"] for r in rows})
    aggs = sorted({r["aggregator"] for r in rows})

    lines = [
        "# 联邦学习鲁棒聚合实验报告\n",
        "指标均取**尾部 5 轮平均**（对抗定向攻击的逐轮震荡）；",
        "ASR 为后门攻击成功率，越低越好；受害类召回越高越好。\n",
    ]

    for scn in scenarios:
        sub = sorted((r for r in rows if r["scenario"] == scn),
                     key=lambda r: r["aggregator"])
        is_bd = any(not math.isnan(r["tail_asr"]) for r in sub)
        lines.append(f"\n## {scn}\n")
        header = ("| 聚合器 | 尾部准确率 | 受害类召回 | 最差类召回 |"
                  + (" 后门ASR |" if is_bd else "")
                  + " 检测TPR | 检测FPR |")
        sep = "|---|---|---|---|" + ("---|" if is_bd else "") + "---|---|"
        lines += [header, sep]
        for r in sub:
            cells = [
                r["aggregator"],
                _fmt(r["tail_accuracy"]),
                _fmt(r["tail_source_recall"]),
                _fmt(r["tail_min_recall"]),
            ]
            if is_bd:
                cells.append(_fmt(r["tail_asr"]))
            cells += [_fmt(r["detection_tpr"], 2),
                      _fmt(r["detection_fpr"], 2)]
            lines.append("| " + " | ".join(cells) + " |")

    # 综合排名
    lines.append("\n## 综合表现（跨攻击场景平均 + 良性代价）\n")
    lines.append("| 聚合器 | 良性准确率(代价) | 攻击下平均准确率 | "
                 "攻击下平均受害类召回 | 平均后门ASR | 理论容忍度 |")
    lines.append("|---|---|---|---|---|---|")
    summary = []
    for agg in aggs:
        sub = [r for r in rows if r["aggregator"] == agg]
        benign = next(r for r in sub if r["attack"] == "benign")
        attacked = [r for r in sub if r["attack"] != "benign"]
        mean_acc = sum(r["tail_accuracy"] for r in attacked) / len(attacked)
        mean_rec = sum(r["tail_source_recall"] for r in attacked) / len(attacked)
        asrs = [r["tail_asr"] for r in attacked if not math.isnan(r["tail_asr"])]
        mean_asr = sum(asrs) / len(asrs) if asrs else float("nan")
        summary.append((agg, benign["tail_accuracy"], mean_acc,
                        mean_rec, mean_asr))
    for agg, bacc, macc, mrec, masr in sorted(
            summary, key=lambda x: (x[3], x[2]), reverse=True):
        lines.append(
            f"| {agg} | {_fmt(bacc)} | {_fmt(macc)} | {_fmt(mrec)} | "
            f"{_fmt(masr)} | {tolerance.get(agg, '')} |")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"报告写入 {out_path}")


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    build_report(os.path.join(base, "results", "results.json"),
                 os.path.join(base, "results", "report.md"))
