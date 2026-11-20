"""联邦训练模拟: 本地训练、根更新、逐轮评估。

性能设计: 同一场景下 8 个聚合器面对的本地更新/攻击更新/根更新完全相同,
因此由 ScenarioCache 按轮预计算一次, 各聚合器只做廉价的聚合运算,
完整实验的训练成本从 48 份降到 6 份(按场景数)。
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader

from .aggregators import AGGREGATORS
from .attacks import ATTACK_REGISTRY, build_attack_config
from .data import (NUM_CLASSES, ArrayDataset, backdoor_poison,
                   label_flip_poison, trigger_testset)
from .model import TinyCNN, flatten_params, set_flat_params


# --------------------------------------------------------------- 本地训练
def local_train(model: TinyCNN, ds: ArrayDataset, *, epochs: int, lr: float,
                batch_size: int, seed: int, weight_decay: float = 1e-4,
                ) -> torch.Tensor:
    """在本地数据上从当前全局参数出发训练, 返回参数更新 delta。"""
    g = torch.Generator()
    g.manual_seed(seed)
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True, generator=g)
    opt = torch.optim.SGD(model.parameters(), lr=lr, momentum=0.9,
                          weight_decay=weight_decay)
    loss_fn = nn.CrossEntropyLoss()
    w0 = flatten_params(model)
    model.train()
    for _ in range(epochs):
        for xb, yb in loader:
            opt.zero_grad()
            loss = loss_fn(model(xb), yb)
            loss.backward()
            opt.step()
    return flatten_params(model) - w0


def root_update(model: TinyCNN, root_ds: ArrayDataset, *, epochs: int,
                lr: float, seed: int) -> torch.Tensor:
    """服务器在可信小数据集上训练得到"根更新"(FLTrust/AdaGuard 的锚)。"""
    return local_train(model, root_ds, epochs=epochs, lr=lr,
                       batch_size=32, seed=seed, weight_decay=0.0)


# --------------------------------------------------------------- 评估
@torch.no_grad()
def evaluate(model: TinyCNN, ds: ArrayDataset) -> dict:
    loader = DataLoader(ds, batch_size=256)
    model.eval()
    correct, total = 0, 0
    pred_all, true_all = [], []
    for xb, yb in loader:
        pred = model(xb).argmax(1)
        correct += (pred == yb).sum().item()
        total += len(yb)
        pred_all.append(pred.numpy())
        true_all.append(yb.numpy())
    pred_all = np.concatenate(pred_all)
    true_all = np.concatenate(true_all)
    recalls = []
    for c in range(NUM_CLASSES):
        m = true_all == c
        recalls.append((pred_all[m] == c).mean() if m.any() else np.nan)
    return {"accuracy": correct / total,
            "class_recall": np.array(recalls)}


@torch.no_grad()
def backdoor_asr(model: TinyCNN, test_ds: ArrayDataset,
                 target: int) -> float:
    """带触发器的 source 类样本被误判为 target 类的比例(攻击成功率)。"""
    loader = DataLoader(test_ds, batch_size=256)
    model.eval()
    hit, total = 0, 0
    for xb, _ in loader:
        pred = model(xb).argmax(1)
        hit += (pred == target).sum().item()
        total += len(pred)
    return hit / max(total, 1)


# --------------------------------------------------------------- 场景
@dataclass
class Scenario:
    name: str
    attack: str                 # benign / gaussian / ...
    num_malicious: int
    malicious_ids: list[int]
    source_class: int = 0
    target_class: int = 1
    kwargs: dict = None

    @property
    def is_backdoor(self) -> bool:
        return self.attack == "backdoor"


def make_scenario(spec: dict, num_clients: int) -> Scenario:
    m = spec["num_malicious"]
    # 固定恶意方编号, 保证不同聚合器面对完全相同的对手
    mal_ids = list(range(num_clients - m, num_clients))
    return Scenario(
        name=spec["name"], attack=spec["attack"], num_malicious=m,
        malicious_ids=mal_ids,
        source_class=spec.get("source_class", 0),
        target_class=spec.get("target_class", 1),
        kwargs={k: v for k, v in spec.items()
                if k not in ("name", "attack", "num_malicious",
                             "source_class", "target_class")})


# --------------------------------------------------------------- 场景预计算
class ScenarioCache:
    """预计算一个场景每轮的 (全部客户端更新, 根更新, 恶意标签)。

    恶意标签仅用于事后 TPR/FPR 统计, 聚合器内部不读取。
    """

    def __init__(self, scenario: Scenario, splits: list,
                 test_ds: ArrayDataset, root_ds: ArrayDataset, *,
                 rounds: int, local_epochs: int, lr: float,
                 batch_size: int, base_seed: int):
        self.scenario = scenario
        self.splits = splits
        self.test_ds = test_ds
        self.root_ds = root_ds
        self.rounds = rounds
        self.local_epochs = local_epochs
        self.lr = lr
        self.batch_size = batch_size
        self.base_seed = base_seed
        self.trig_ds, _ = trigger_testset(test_ds, scenario.source_class)
        self.mal_set = set(scenario.malicious_ids)
        self.attack_fn = ATTACK_REGISTRY.get(scenario.attack)
        self.cfg = build_attack_config({
            "attack": scenario.attack,
            "num_malicious": scenario.num_malicious,
            "source_class": scenario.source_class,
            "target_class": scenario.target_class,
            **(scenario.kwargs or {}),
        })
        self.rounds_data: list[dict] = []

    def precompute(self, init_flat: torch.Tensor) -> None:
        """逐轮生成更新包。注意: 预计算在"参考全局轨迹"上进行。

        参考轨迹用 fedavg 聚合产生, 只用于提供本地训练的起点;
        各聚合器正式实验时从同一初始化独立聚合, 二者的全局参数在 r>0
        后并不相同——这是缓存方案的近似代价。精确实验不要启用缓存,
        run_federation 默认即走实时精确模式(cache=None)。
        """
        ref_model = TinyCNN()
        set_flat_params(ref_model, init_flat.clone())
        for rnd in range(self.rounds):
            bundle = self._compute_round(rnd, flatten_params(ref_model))
            self.rounds_data.append(bundle)
            # 参考轨迹用 fedavg 推进
            ref_delta = torch.stack(bundle["updates"]).mean(0)
            set_flat_params(ref_model,
                            flatten_params(ref_model) + ref_delta)

    def _compute_round(self, rnd: int,
                       w_global: torch.Tensor) -> dict:
        round_seed = self.base_seed + rnd * 101
        rng = np.random.default_rng(round_seed)
        honest_updates, native_mal = [], []
        for cid, split in enumerate(self.splits):
            model = TinyCNN()
            set_flat_params(model, w_global)
            if cid in self.mal_set and self.scenario.attack != "benign":
                if self.scenario.attack == "backdoor":
                    ds = backdoor_poison(
                        ArrayDataset(split.X, split.y),
                        self.scenario.target_class)
                elif self.scenario.attack in ("stealth_flip", "collusion"):
                    ds = label_flip_poison(
                        ArrayDataset(split.X, split.y),
                        self.scenario.source_class,
                        self.scenario.target_class)
                else:
                    ds = ArrayDataset(split.X, split.y)
                delta = local_train(model, ds, epochs=self.local_epochs,
                                    lr=self.lr, batch_size=self.batch_size,
                                    seed=round_seed + cid)
                native_mal.append(delta)
            else:
                ds = ArrayDataset(split.X, split.y)
                delta = local_train(model, ds, epochs=self.local_epochs,
                                    lr=self.lr, batch_size=self.batch_size,
                                    seed=round_seed + cid)
                honest_updates.append(delta)

        if self.scenario.attack == "benign":
            all_updates = honest_updates
        else:
            mal_updates = self.attack_fn(honest_updates, native_mal, rng,
                                         self.cfg)
            all_updates = []
            hi, mi = 0, 0
            for cid in range(len(self.splits)):
                if cid in self.mal_set:
                    all_updates.append(mal_updates[mi])
                    mi += 1
                else:
                    all_updates.append(honest_updates[hi])
                    hi += 1

        root_model = TinyCNN()
        set_flat_params(root_model, w_global)
        r_update = root_update(root_model, self.root_ds, epochs=2,
                               lr=self.lr, seed=round_seed + 777)
        is_mal = torch.tensor(
            [cid in self.mal_set for cid in range(len(self.splits))])
        return {"updates": all_updates, "root_update": r_update,
                "is_malicious": is_mal, "round_seed": round_seed}


# --------------------------------------------------------------- 主循环
def run_federation(
    scenario: Scenario,
    aggregator_name: str,
    splits: list,
    test_ds: ArrayDataset,
    root_ds: ArrayDataset,
    *,
    rounds: int,
    local_epochs: int,
    lr: float,
    batch_size: int,
    base_seed: int,
    init_flat: torch.Tensor,
    cache: ScenarioCache | None = None,
) -> dict:
    """跑一个 (场景 × 聚合器) 组合, 返回逐轮指标与检测统计。

    cache 为 None 时实时计算本地训练(精确模式); 传入预计算缓存时,
    本地/攻击/根更新复用缓存(快速模式, 近似说明见 ScenarioCache 文档)。
    """
    agg_fn = AGGREGATORS[aggregator_name]
    global_model = TinyCNN()
    set_flat_params(global_model, init_flat.clone())

    # 精确模式(默认): 每轮在该聚合器自己的全局轨迹上实时本地训练,
    # 保证 8 个聚合器的对比不受参考轨迹污染。
    live = ScenarioCache(scenario, splits, test_ds, root_ds,
                         rounds=rounds, local_epochs=local_epochs,
                         lr=lr, batch_size=batch_size, base_seed=base_seed)
    history = []
    detect_tp, detect_fp, detect_n_pos, detect_n_neg = 0, 0, 0, 0

    for rnd in range(rounds):
        if cache is not None:
            # 可选快速模式: 复用预计算更新包(近似, 见 ScenarioCache 文档)
            bundle = cache.rounds_data[rnd]
            all_updates = bundle["updates"]
            r_update = bundle["root_update"]
            is_mal = bundle["is_malicious"]
        else:
            bundle = live._compute_round(rnd, flatten_params(global_model))
            all_updates = bundle["updates"]
            r_update = bundle["root_update"]
            is_mal = bundle["is_malicious"]

        w_global = flatten_params(global_model)
        agg_delta, diag = agg_fn(all_updates, is_malicious=is_mal,
                                 root_update=r_update)
        set_flat_params(global_model, w_global + agg_delta)

        # ---- 评估
        metrics = evaluate(global_model, test_ds)
        row = {
            "round": rnd + 1,
            "accuracy": metrics["accuracy"],
            "min_class_recall": float(np.nanmin(metrics["class_recall"])),
            "source_recall": float(
                metrics["class_recall"][scenario.source_class]),
        }
        if scenario.is_backdoor:
            trig_ds = (cache.trig_ds if cache is not None
                       else live.trig_ds)
            row["asr"] = backdoor_asr(global_model, trig_ds,
                                      scenario.target_class)
        else:
            row["asr"] = np.nan
        history.append(row)

        # ---- 检测率统计(防御的 flags 与真实标签对照)
        flags = diag["flags"]
        detect_tp += int((flags & is_mal).sum())
        detect_fp += int((flags & ~is_mal).sum())
        detect_n_pos += int(is_mal.sum())
        detect_n_neg += int((~is_mal).sum())

    final = history[-1]
    tail = history[-5:]  # 后 5 轮, 对抗定向攻击下的逐轮震荡

    def _tail_mean(key):
        vals = [h[key] for h in tail if not np.isnan(h[key])]
        return float(np.mean(vals)) if vals else np.nan

    return {
        "scenario": scenario.name,
        "aggregator": aggregator_name,
        "attack": scenario.attack,
        "history": history,
        "final_accuracy": final["accuracy"],
        "final_min_recall": final["min_class_recall"],
        "final_source_recall": final["source_recall"],
        "final_asr": final["asr"],
        # 尾部 5 轮均值: 比单轮末值更能反映防御的稳定水平
        "tail_accuracy": _tail_mean("accuracy"),
        "tail_source_recall": _tail_mean("source_recall"),
        "tail_min_recall": float(np.mean(
            [h["min_class_recall"] for h in tail])),
        "tail_asr": _tail_mean("asr"),
        "detection_tpr": (detect_tp / detect_n_pos)
        if detect_n_pos else np.nan,
        "detection_fpr": (detect_fp / detect_n_neg)
        if detect_n_neg else np.nan,
    }
