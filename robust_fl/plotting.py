"""实验结果可视化与汇总表。"""
from __future__ import annotations

import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = ["Arial Unicode MS", "PingFang SC",
                                   "Helvetica", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

COLORS = ["#4477AA", "#EE6677", "#228833", "#CCBB44", "#66CCEE",
          "#AA3377", "#BBBBBB", "#000000"]


def plot_data_distribution(splits: list, out_dir: str) -> None:
    """医院 × 类别 的样本数热力图, 直观展示 Dirichlet 非 IID 偏斜。"""
    mat = np.stack([s.class_counts for s in splits]).astype(float)  # (H, C)
    fig, ax = plt.subplots(figsize=(8, 5))
    im = ax.imshow(mat, aspect="auto", cmap="YlOrRd")
    ax.set_xticks(range(mat.shape[1]))
    ax.set_xticklabels([f"类别 {c}" for c in range(mat.shape[1])])
    ax.set_yticks(range(mat.shape[0]))
    ax.set_yticklabels([f"医院 {s.client_id}" for s in splits])
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            v = int(mat[i, j])
            ax.text(j, i, str(v), ha="center", va="center",
                    fontsize=8, color="black" if v < mat.max() * 0.6
                    else "white")
    ax.set_title("各医院类别样本分布（Dirichlet α=0.3 非 IID，0 表示该病种缺失）")
    fig.colorbar(im, ax=ax, label="样本数")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "hospital_distribution.png"), dpi=130)
    plt.close(fig)


def plot_scenario_curves(results: list[dict], out_dir: str) -> None:
    """每个攻击场景一张图: 上排全局准确率, 下排受害类召回/后门 ASR。"""
    scenarios = {}
    for r in results:
        scenarios.setdefault(r["scenario"], []).append(r)

    for scn, rs in scenarios.items():
        is_bd = any(not np.isnan(x["final_asr"]) for x in rs)
        fig, axes = plt.subplots(2, 1, figsize=(9, 8), sharex=True)
        for i, r in enumerate(sorted(rs, key=lambda x: x["aggregator"])):
            rounds = [h["round"] for h in r["history"]]
            acc = [h["accuracy"] for h in r["history"]]
            c = COLORS[i % len(COLORS)]
            axes[0].plot(rounds, acc, label=r["aggregator"], color=c, lw=1.6)
            if is_bd:
                asr = [h["asr"] for h in r["history"]]
                axes[1].plot(rounds, asr, label=r["aggregator"], color=c, lw=1.6)
            else:
                rec = [h["source_recall"] for h in r["history"]]
                axes[1].plot(rounds, rec, label=r["aggregator"], color=c, lw=1.6)

        axes[0].set_ylabel("全局准确率")
        axes[0].set_title(f"场景: {scn}")
        axes[0].grid(alpha=0.3)
        axes[0].legend(fontsize=8, ncol=2)
        axes[1].set_ylabel("后门 ASR" if is_bd else "受害类召回率")
        axes[1].set_xlabel("联邦轮次")
        axes[1].grid(alpha=0.3)
        fig.tight_layout()
        path = os.path.join(out_dir, f"curves_{scn}.png")
        fig.savefig(path, dpi=130)
        plt.close(fig)


def plot_final_bars(results: list[dict], out_dir: str) -> None:
    """跨场景的最终指标分组柱状图: 准确率 / 受害类召回 / ASR。"""
    scenarios = sorted({r["scenario"] for r in results})
    aggs = sorted({r["aggregator"] for r in results})
    metrics = [("tail_accuracy", "尾部5轮平均准确率"),
               ("tail_source_recall", "受害类尾部5轮平均召回"),
               ("tail_asr", "后门尾部5轮平均 ASR")]
    x = np.arange(len(scenarios))
    width = 0.8 / max(len(aggs), 1)

    for key, title in metrics:
        fig, ax = plt.subplots(figsize=(12, 5))
        for i, agg in enumerate(aggs):
            vals = []
            lookup = {(r["scenario"], r["aggregator"]): r for r in results}
            for scn in scenarios:
                v = lookup[(scn, agg)][key]
                vals.append(0.0 if np.isnan(v) else v)
            ax.bar(x + i * width - 0.4, vals, width, label=agg,
                   color=COLORS[i % len(COLORS)])
        ax.set_xticks(x)
        ax.set_xticklabels(scenarios, rotation=20, ha="right")
        ax.set_ylabel(title)
        ax.set_title(title)
        ax.set_ylim(0, 1.05)
        ax.grid(axis="y", alpha=0.3)
        ax.legend(fontsize=8, ncol=4)
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, f"bar_{key}.png"), dpi=130)
        plt.close(fig)


def write_summary_csv(results: list[dict], out_dir: str) -> str:
    path = os.path.join(out_dir, "summary.csv")
    fields = ["scenario", "aggregator", "attack", "final_accuracy",
              "final_min_recall", "final_source_recall", "final_asr",
              "tail_accuracy", "tail_source_recall", "tail_min_recall",
              "tail_asr", "detection_tpr", "detection_fpr"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in sorted(results, key=lambda x: (x["scenario"], x["aggregator"])):
            w.writerow({k: r[k] for k in fields})
    return path
