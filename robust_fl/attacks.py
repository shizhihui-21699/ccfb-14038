"""恶意更新构造。

统一接口:
    attack_fn(honest_updates, mal_native_updates, rng, cfg) -> list[Tensor]

  honest_updates:      本轮良性医院的更新(梯度差 delta = 本地训练后参数 - 全局参数)
  mal_native_updates:  恶意医院在投毒数据上本地训练得到的"原生"更新
                       (后门/标签翻转类攻击用; 噪声/符号翻转类忽略)

攻击者能力设定(故意取偏强的自适应模型):
  * 能看到本轮所有良性更新(等价于能观测聚合前流量的强对手);
  * 知道防御使用的范数中位数统计, 并把恶意更新范数伪装到该尺度;
  * 能向良性中位数方向混合, 让余弦相似度看起来"正常";
  * 合谋方共享同一攻击方向, 只加微小抖动, 伪装成一个紧密簇。
"""
from __future__ import annotations

from dataclasses import dataclass, field

import torch


@dataclass
class AttackConfig:
    name: str
    num_malicious: int
    source_class: int = 0          # 定向攻击受害类别
    target_class: int = 1          # 定向攻击目标类别
    norm_mult: float = 1.5         # 恶意更新范数 = 良性范数中位数 × 该倍数
    stealth_blend: float = 0.35    # 向良性中位数方向混合的比例(隐蔽攻击)
    noise_sigma: float = 3.0       # 高斯攻击的标准差倍数
    collusion_jitter: float = 0.02 # 合谋方之间的抖动
    extra: dict = field(default_factory=dict)


def _median_norm(updates: list[torch.Tensor]) -> float:
    norms = torch.stack([u.norm() for u in updates])
    return norms.median().item()


def _median_direction(updates: list[torch.Tensor]) -> torch.Tensor:
    return torch.stack(updates).median(dim=0).values


def _rescale(delta: torch.Tensor, target_norm: float) -> torch.Tensor:
    n = delta.norm().clamp_min(1e-12)
    return delta * (target_norm / n)


def _stealth_wrap(delta: torch.Tensor, honest: list[torch.Tensor],
                  cfg: AttackConfig) -> torch.Tensor:
    """自适应范数伪装 + 向良性方向混合, 所有定向攻击的统一收尾。"""
    med_norm = _median_norm(honest)
    med_dir = _median_direction(honest)
    target_norm = med_norm * cfg.norm_mult
    if cfg.stealth_blend > 0:
        # 混合后再缩放到目标范数: 方向像良性, 但保留攻击分量
        mixed = (cfg.stealth_blend * _rescale(med_dir, 1.0)
                 + (1 - cfg.stealth_blend) * _rescale(delta, 1.0))
        return _rescale(mixed, target_norm)
    return _rescale(delta, target_norm)


# ---------------------------------------------------------------- 攻击实现
def attack_gaussian(honest, native, rng, cfg: AttackConfig):
    """无差别破坏: 大范数高斯噪声更新。

    朴素版本不做方向伪装, 用来检验 L1 范数层与 Krum 类基线的检测力。
    """
    med_norm = _median_norm(honest)
    d = honest[0].shape[0]
    out = []
    for _ in range(cfg.num_malicious):
        z = torch.randn(d, generator=torch.Generator().manual_seed(
            int(rng.integers(1 << 30))))
        out.append(_rescale(z, med_norm * cfg.noise_sigma))
    return out


def attack_sign_flip(honest, native, rng, cfg: AttackConfig):
    """符号翻转/拜占庭: 朝良性中位数的反方向更新并放大范数。

    经典的 fallback/数据中毒建模, 破坏力强但方向异常明显。
    """
    med_dir = _median_direction(honest)
    med_norm = _median_norm(honest)
    out = []
    for _ in range(cfg.num_malicious):
        out.append(_rescale(-med_dir, med_norm * cfg.norm_mult))
    return out


def attack_backdoor(honest, native, rng, cfg: AttackConfig):
    """后门攻击: 原生投毒更新 + 范数伪装(不混合方向, 保留触发器学习)。"""
    return [_stealth_wrap(d, honest,
                          AttackConfig(**{**cfg.__dict__, "stealth_blend": 0.0}))
            for d in native]


def attack_stealth_flip(honest, native, rng, cfg: AttackConfig):
    """隐蔽定向攻击(本项目重点威胁): 标签翻转 + 方向混合 + 范数伪装。

    目标: 只拉低 source 类的召回, 整体准确率几乎不动,
    且每个恶意更新单独看都"像正常医院的非 IID 漂移"。
    """
    return [_stealth_wrap(d, honest, cfg) for d in native]


def attack_collusion(honest, native, rng, cfg: AttackConfig):
    """多家医院合谋: 共享攻击方向, 彼此只加微小抖动, 伪装成紧密簇。

    针对 Krum/坐标中位数这类"靠两两距离投票"的防御:
    合谋簇规模超过 f 假设时, 簇内距离为 0, 投票机制会把恶意更新选成最优点。
    """
    base = _stealth_wrap(torch.stack(native).mean(0), honest, cfg)
    med_norm = _median_norm(honest)
    out = []
    for i in range(cfg.num_malicious):
        g = torch.Generator().manual_seed(int(rng.integers(1 << 30)))
        jitter = torch.randn(base.shape[0], generator=g)
        jitter = _rescale(jitter, med_norm * cfg.collusion_jitter)
        out.append(_rescale(base + jitter, med_norm * cfg.norm_mult))
    return out


ATTACK_REGISTRY = {
    "gaussian": attack_gaussian,
    "sign_flip": attack_sign_flip,
    "backdoor": attack_backdoor,
    "stealth_flip": attack_stealth_flip,
    "collusion": attack_collusion,
}


def build_attack_config(scenario: dict) -> AttackConfig:
    return AttackConfig(
        name=scenario["attack"],
        num_malicious=scenario["num_malicious"],
        source_class=scenario.get("source_class", 0),
        target_class=scenario.get("target_class", 1),
        norm_mult=scenario.get("norm_mult", 1.5),
        stealth_blend=scenario.get("stealth_blend", 0.35),
        noise_sigma=scenario.get("noise_sigma", 3.0),
        collusion_jitter=scenario.get("collusion_jitter", 0.02),
    )
