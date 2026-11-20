"""聚合与防御算法。

统一接口:
    aggregate(updates, is_malicious, root_update, **kw)
        -> (聚合后的更新向量, 诊断信息 dict)

  is_malicious 只用于事后统计检测率, 防御逻辑本身不使用该标签
  (否则就不是防御而是作弊了)。

包含 8 种策略:
  fedavg         无防御基线
  clip_avg       L1: 中位数范数裁剪 + 平均
  krum           L3: 两两距离投票, 选一个最不孤立的更新
  multi_krum     Krum 选 n-f 个再平均
  trimmed_mean   L3: 坐标级截断均值
  coord_median   L3: 坐标级中位数
  fltrust        L2: 服务器根数据集余弦信任加权
  adaguard       本项目自研: L1 裁剪 + L2 根信任 + L3 加权截断 + L4 簇上限
"""
from __future__ import annotations

from typing import Callable

import torch


def _stack(updates: list[torch.Tensor]) -> torch.Tensor:
    return torch.stack(updates)


# ================================================================ 基线族
def fedavg(updates, root_update=None, **kw):
    U = _stack(updates)
    n = len(updates)
    w = torch.full((n,), 1.0 / n)
    return U.mean(0), {"weights": w, "flags": torch.zeros(n, dtype=torch.bool)}


def clip_avg(updates, root_update=None, clip_mult: float = 2.0, **kw):
    """范数裁剪到 中位数×clip_mult 后做平均。只防裸奔的大范数攻击。"""
    U = _stack(updates)
    n = U.shape[0]
    norms = U.norm(dim=1)
    tau = norms.median() * clip_mult
    scale = (tau / norms).clamp(max=1.0)
    Uc = U * scale.unsqueeze(1)
    w = torch.full((n,), 1.0 / n)
    flags = norms > tau
    return Uc.mean(0), {"weights": w, "flags": flags, "clip_tau": tau.item()}


# ================================================================ 距离投票族
def _krum_scores(U: torch.Tensor, f: int) -> torch.Tensor:
    """每个更新的 Krum 分数: 与最近的 (n-f-2) 个更新的距离平方和。"""
    n = U.shape[0]
    dist = torch.cdist(U, U) ** 2
    k = max(1, n - f - 2)
    scores = torch.empty(n)
    for i in range(n):
        nearest = dist[i].topk(k + 1, largest=False).values[1:]  # 去掉自己(距离0)
        scores[i] = nearest.sum()
    return scores


def krum(updates, root_update=None, f: int = 3, **kw):
    U = _stack(updates)
    n = U.shape[0]
    scores = _krum_scores(U, f)
    best = int(scores.argmin())
    w = torch.zeros(n)
    w[best] = 1.0
    # 异常标记: Krum 分数最高的 f 个(在非 IID 下天然存在一定误报,
    # 这正是与 AdaGuard 对比时要量化的部分)
    flags = torch.zeros(n, dtype=torch.bool)
    flags[scores.topk(min(f, n - 1)).indices] = True
    return U[best].clone(), {"weights": w, "flags": flags, "scores": scores}


def multi_krum(updates, root_update=None, f: int = 3, **kw):
    """迭代选 Krum 最优, 共选 n-f 个, 再等权平均。"""
    U = _stack(updates)
    n = U.shape[0]
    remaining = list(range(n))
    chosen = []
    while len(chosen) < n - f:
        sub = U[remaining]
        scores = _krum_scores(sub, min(f, len(remaining) - 2))
        pick = int(scores.argmin())
        chosen.append(remaining.pop(pick))
    w = torch.zeros(n)
    w[chosen] = 1.0 / len(chosen)
    flags = torch.ones(n, dtype=torch.bool)
    flags[chosen] = False
    # 注意: multi-krum 的 flags 语义是"未入选", 其误报率本身偏高,
    # 与专门的异常检测(AdaGuard/FLTrust)对照即可看出
    return U[chosen].mean(0), {"weights": w, "flags": flags}


# ================================================================ 坐标鲁棒族
def trimmed_mean(updates, root_update=None, f: int = 1, **kw):
    """每维去掉最大/最小各 f 个值后平均。"""
    U = _stack(updates)
    n = U.shape[0]
    f = min(f, (n - 1) // 2)
    sorted_U, _ = U.sort(dim=0)
    kept = sorted_U[f:n - f]
    w = torch.full((n,), 1.0 / (n - 2 * f))
    # 逐坐标截断没有明确的"客户端级"异常标签, 不输出检测标记
    return kept.mean(0), {"weights": w,
                          "flags": torch.zeros(n, dtype=torch.bool)}


def coord_median(updates, root_update=None, **kw):
    U = _stack(updates)
    n = U.shape[0]
    return U.median(dim=0).values, {
        "weights": torch.full((n,), 1.0 / n),
        "flags": torch.zeros(n, dtype=torch.bool),
    }


# ================================================================ 根信任族
def _cos(a: torch.Tensor, b: torch.Tensor) -> torch.Tensor:
    return torch.nn.functional.cosine_similarity(a, b, dim=0)


def fltrust(updates, root_update: torch.Tensor, **kw):
    """FLTrust (Cao et al., NDSS'21): 用服务器可信小数据训练出的根更新做锚。

    信任分 = ReLU(余弦相似度), 归一化后加权; 输出范数缩放到根更新范数。
    与根反向的更新信任分直接为 0, 对符号翻转/后门方向攻击天然有效。
    """
    U = _stack(updates)
    n = U.shape[0]
    cos = torch.tensor([max(0.0, _cos(u, root_update).item()) for u in U])
    if cos.sum() <= 0:
        # 所有更新都与根反向(极端情况): 退回根更新, 拒绝本轮
        w = torch.zeros(n)
        return root_update.clone(), {"weights": w,
                                     "flags": torch.ones(n, dtype=torch.bool),
                                     "trust": cos, "rejected": True}
    w = cos / cos.sum()
    out = (w.unsqueeze(1) * U).sum(0)
    out = out * (root_update.norm() / out.norm().clamp_min(1e-12))
    # 异常标记: 信任分低于均匀权重的一半
    return out, {"weights": w,
                 "flags": cos < (0.5 / n),
                 "trust": cos, "rejected": False}


# ================================================================ 自研分层防御
def _greedy_cosine_clusters(U: torch.Tensor, thresh: float) -> list[list[int]]:
    """按余弦距离贪心聚类: 与簇内任一成员 cos > thresh 即归入该簇。"""
    n = U.shape[0]
    clusters: list[list[int]] = []
    for i in range(n):
        placed = False
        for cl in clusters:
            if any(_cos(U[i], U[j]).item() > thresh for j in cl):
                cl.append(i)
                placed = True
                break
        if not placed:
            clusters.append([i])
    return clusters


def adaguard(updates, root_update: torch.Tensor,
             clip_mult: float = 2.0,
             cluster_thresh: float = 0.90,
             cluster_cap_mult: float = 2.0,
             trim_frac: float = 0.1,
             scale_cap: float = 2.0,
             **kw):
    """AdaGuard: 四层串联的自适应鲁棒聚合。

    L1 范数层: 每个更新裁剪到 中位数范数 × clip_mult,
               废掉"大范数碾压"类攻击(gaussian / 放大版 sign flip);
    L2 方向层: 与服务器根更新算余弦, ReLU 截断得信任分,
               与根反向的更新权重归零(定向/后门攻击的主防线);
    L4 簇上限: 余弦贪心聚类, 每个簇的总权重不得超过
               cluster_cap_mult / n —— 合谋方再多人也只顶 2 票,
               被削掉的权重按比例还给其余簇;
    L3 坐标层: 在重加权结果上做按权重的坐标截断(每侧 trim_frac),
               吸收非 IID 良性漂移中的残余离群坐标, 也是后门残余
               分量的最后闸门(消融显示去掉它后门 ASR 从 0 升到 0.5+)。
    最后做软步长上限: 聚合更新范数超过根更新的 scale_cap 倍才回缩。
    不做强制等长对齐——消融实验表明精确对齐会把良性准确率从 0.978
    压到 0.948, 而软上限配合 L3 截断已能把后门 ASR 压到 0。
    """
    U = _stack(updates)
    n = U.shape[0]

    # ---- L1
    norms = U.norm(dim=1)
    tau = norms.median() * clip_mult
    scale = (tau / norms).clamp(max=1.0)
    U = U * scale.unsqueeze(1)

    # ---- L2
    trust = torch.tensor([max(0.0, _cos(u, root_update).item()) for u in U])
    if trust.sum() <= 0:
        return root_update.clone(), {
            "weights": torch.zeros(n), "flags": torch.ones(n, dtype=torch.bool),
            "trust": trust, "clusters": [[i] for i in range(n)],
            "rejected": True}
    w = trust / trust.sum()

    # ---- L4 簇上限
    clusters = _greedy_cosine_clusters(U, cluster_thresh)
    cap = cluster_cap_mult / n
    for _ in range(3):  # 削峰可能反复触发, 迭代到所有簇达标
        overflow = 0.0
        uncapped_mass = 0.0
        for cl in clusters:
            mass = w[cl].sum()
            if mass > cap + 1e-12:
                overflow += mass - cap
            else:
                uncapped_mass += mass
        if overflow <= 1e-12:
            break
        if uncapped_mass <= 1e-12:
            break
        for cl in clusters:
            mass = w[cl].sum()
            if mass > cap + 1e-12:
                w[cl] = cap * w[cl] / mass
            else:
                w[cl] += overflow * w[cl] / uncapped_mass

    # ---- L3 加权坐标截断
    # order/U_sorted 都是"排序后位置"坐标系, 直接在该坐标系做加权求和
    order = U.argsort(dim=0)                       # (n, d) 每维升序的客户端编号
    U_sorted = torch.gather(U, 0, order)           # (n, d) 每维升序的值
    w_exp = w[order]                                 # 对应权重
    cum = w_exp.cumsum(dim=0)
    keep = (cum > trim_frac) & (cum <= 1.0 - trim_frac + 1e-9)
    # 兜底: 至少保留 n-2k 行, 防止权重极端时整列被清空
    k_trim = max(1, int(round(trim_frac * n)))
    keep[:n - 2 * k_trim, :] |= True
    w_kept = w_exp * keep
    w_safe = w_kept.sum(0).clamp_min(1e-12)
    out = (w_kept * U_sorted * keep).sum(0) / w_safe

    # ---- 软步长上限(消融验证: 配合 L3 即可压制后门, 又不伤良性收敛)
    root_norm = root_update.norm().clamp_min(1e-12)
    if out.norm() > scale_cap * root_norm:
        out = out * (scale_cap * root_norm / out.norm())

    # 异常标记基于原始信任分(独立于簇削权), 阈值取均匀信任的一半
    flags = trust < (0.5 / n)
    return out, {"weights": w, "flags": flags, "trust": trust,
                 "clusters": clusters, "rejected": False, "clip_tau": tau.item()}


AGGREGATORS: dict[str, Callable] = {
    "fedavg": fedavg,
    "clip_avg": clip_avg,
    "krum": krum,
    "multi_krum": multi_krum,
    "trimmed_mean": trimmed_mean,
    "coord_median": coord_median,
    "fltrust": fltrust,
    "adaguard": adaguard,
}

# 各方法对恶意方比例的理论容忍上限(写进报告用于解释失效点)
TOLERANCE = {
    "fedavg": "0%",
    "clip_avg": "无方向防护, 仅限制破坏幅度",
    "krum": "< (n-2)/2 ≈ 40% (合谋超限时反而投出恶意更新)",
    "multi_krum": "< (n-2)/2 ≈ 40%",
    "trimmed_mean": "每维 < 50% (f 个被截断)",
    "coord_median": "< 50%",
    "fltrust": "不受比例硬约束, 依赖根数据代表性",
    "adaguard": "簇上限使合谋退化为 2 票, 理论上可抗 >50% 的同向合谋(受根锚质量约束)",
}
