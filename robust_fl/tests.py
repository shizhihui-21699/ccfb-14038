"""聚合器与攻击模块的单元测试。

运行: .venv/bin/python -m robust_fl.tests
不依赖 pytest, 直接断言并打印结果。
"""
from __future__ import annotations

import torch

from .aggregators import (AGGREGATORS, _greedy_cosine_clusters,
                          _krum_scores, adaguard, coord_median,
                          trimmed_mean)
from .attacks import (AttackConfig, attack_collusion, attack_gaussian,
                      attack_sign_flip)
from .data import (NUM_CLASSES, backdoor_poison, dirichlet_noniid_split,
                   make_dataset, ArrayDataset)
from .model import TinyCNN, flatten_params, set_flat_params

torch.manual_seed(0)
N, D = 10, 200


def _honest_batch(n=N, d=D):
    base = torch.randn(d)
    ups = []
    for _ in range(n):
        ups.append(base + 0.3 * torch.randn(d))  # 同向 + 抖动
    return base, ups


def test_all_aggregators_run_and_finite():
    _, ups = _honest_batch()
    root = ups[0] + 0.1 * torch.randn(D)
    is_mal = torch.zeros(N, dtype=torch.bool)
    for name, fn in AGGREGATORS.items():
        out, diag = fn(ups, is_malicious=is_mal, root_update=root)
        assert out.shape == (D,), name
        assert torch.isfinite(out).all(), name
        assert diag["flags"].shape == (N,), name
        assert torch.isfinite(diag["weights"]).all(), name
    print("[ok] 所有聚合器输出形状/有限性正确")


def test_fedavg_exact_mean():
    _, ups = _honest_batch()
    out, _ = AGGREGATORS["fedavg"](ups, is_malicious=None, root_update=ups[0])
    assert torch.allclose(out, torch.stack(ups).mean(0), atol=1e-6)
    print("[ok] fedavg 等于算术平均")


def test_coord_median_matches_elementwise():
    _, ups = _honest_batch()
    out, _ = coord_median(ups, root_update=ups[0])
    expect = torch.stack(ups).median(0).values
    assert torch.allclose(out, expect)
    print("[ok] coord_median 与逐元素中位数一致")


def test_trimmed_mean_removes_extremes():
    ups = [torch.zeros(5) for _ in range(8)]
    ups.append(torch.full((5,), 100.0))   # 极端高
    ups.append(torch.full((5,), -100.0))  # 极端低
    out, _ = trimmed_mean(ups, root_update=torch.zeros(5), f=1)
    # 两侧各截 1 个后应回到 0
    assert torch.allclose(out, torch.zeros(5), atol=1e-6)
    print("[ok] trimmed_mean 正确剔除两侧极值")


def test_krum_picks_center_under_outlier():
    base, ups = _honest_batch()
    ups[9] = base * (-5) + 5 * torch.randn(D)  # 明显离群
    scores = _krum_scores(torch.stack(ups), f=1)
    assert scores.argmin() != 9, "Krum 不应选中离群更新"
    assert scores[9] > scores.median(), "离群更新的 Krum 分数应偏高"
    print("[ok] Krum 在离群点存在时选中中心更新")


def test_fltrust_zeroes_opposite_direction():
    _, ups = _honest_batch()
    root = ups[0].clone()
    ups[9] = -root * 3  # 与根反向
    out, diag = AGGREGATORS["fltrust"](ups, is_malicious=None,
                                       root_update=root)
    assert diag["trust"][9].item() == 0.0
    assert diag["weights"][9].item() == 0.0
    assert torch.isfinite(out).all()
    print("[ok] FLTrust 给反向更新零信任")


def test_fltrust_all_opposite_falls_back_to_root():
    _, ups = _honest_batch()
    root = torch.randn(D)
    bad = [-root / root.norm() * (u.norm()) for u in ups]
    out, diag = AGGREGATORS["fltrust"](bad, is_malicious=None,
                                       root_update=root)
    assert diag["rejected"] is True
    assert torch.allclose(out, root)
    print("[ok] FLTrust 全员反向时回退根更新并拒绝本轮")


def test_adaguard_cluster_cap_caps_collusion():
    base, _ = _honest_batch()
    # 4 个高度雷同的合谋更新: 攻击方向与良性近正交(模拟隐蔽定向),
    # 但彼此几乎完全同向(模拟合谋簇)
    attack_dir = torch.randn(D)
    attack_dir -= attack_dir.dot(base) / base.dot(base) * base  # 正交化
    coll = [attack_dir + 0.01 * torch.randn(D) for _ in range(4)]
    good = [base + 0.3 * torch.randn(D) for _ in range(6)]
    ups = good + coll
    root = base.clone()
    out, diag = adaguard(ups, root_update=root)
    clusters = diag["clusters"]
    big = max(clusters, key=len)
    # 合谋 4 家应被聚到同一簇
    assert len(big) >= 4, f"合谋簇识别失败: {[len(c) for c in clusters]}"
    # 该簇削权后总权重不超过 2/n
    assert diag["weights"][big].sum() <= 2.0 / N + 1e-6
    assert torch.isfinite(out).all()
    print("[ok] AdaGuard 簇上限把 4 家合谋压到 2 票以内")


def test_greedy_clusters_group_similar():
    a = torch.randn(50)
    ups = [a + 0.001 * torch.randn(50) for _ in range(4)]
    ups += [torch.randn(50) for _ in range(3)]
    cl = _greedy_cosine_clusters(torch.stack(ups), 0.9)
    assert max(len(c) for c in cl) >= 4
    print("[ok] 余弦贪心聚类正确归并相似更新")


def test_gaussian_large_norm_but_random_direction():
    import numpy as np
    _, honest = _honest_batch()
    cfg = AttackConfig("gaussian", 3, noise_sigma=3.0)
    mal = attack_gaussian(honest, [], np.random.default_rng(0), cfg)
    h_med = torch.stack([u.norm() for u in honest]).median()
    assert all(u.norm().item() > 2 * h_med.item() for u in mal)
    print("[ok] 高斯攻击范数显著放大")


def test_sign_flip_opposes_median():
    import numpy as np
    _, honest = _honest_batch()
    cfg = AttackConfig("sign_flip", 2)
    mal = attack_sign_flip(honest, [], np.random.default_rng(0), cfg)
    med = torch.stack(honest).median(0).values
    for u in mal:
        cos = torch.nn.functional.cosine_similarity(u, med, dim=0)
        assert cos.item() < -0.99
    print("[ok] 符号翻转与良性中位数反向")


def test_collusion_updates_tight_cluster():
    _, honest = _honest_batch()
    native = [torch.randn(D) for _ in range(4)]
    cfg = AttackConfig("collusion", 4, collusion_jitter=0.02)
    rng = torch.Generator().manual_seed(1)
    import numpy as np
    mal = attack_collusion(honest, native, np.random.default_rng(0), cfg)
    # 两两余弦应非常接近 1
    for i in range(len(mal)):
        for j in range(i + 1, len(mal)):
            cos = torch.nn.functional.cosine_similarity(
                mal[i], mal[j], dim=0).item()
            assert cos > 0.99, f"合谋更新不够雷同: cos={cos}"
    print("[ok] 合谋更新构成紧密余弦簇")


def test_noniid_split_covers_all_samples_and_classes():
    X, y = make_dataset(n_per_class=60, seed=1)
    splits = dirichlet_noniid_split(X, y, 10, alpha=0.3, seed=1, min_size=20)
    total = sum(len(s.y) for s in splits)
    assert total == len(y)
    assert all(s.class_counts.sum() == len(s.y) for s in splits)
    # 强非 IID 下应至少出现一家类别缺失
    missing = any((s.class_counts == 0).any() for s in splits)
    assert missing
    print("[ok] Dirichlet 切分样本守恒且出现类别缺失(非 IID 生效)")


def test_backdoor_poison_label_and_patch():
    X, y = make_dataset(n_per_class=30, seed=2)
    ds = ArrayDataset(X, y)
    bd = backdoor_poison(ds, target=3)
    assert (bd.y == 3).all()
    assert (bd.X[:, :, -3:, -3:] == 3.0).all()
    print("[ok] 后门投毒: 标签与触发器均正确写入")


def test_flatten_roundtrip():
    m = TinyCNN()
    flat = flatten_params(m)
    m2 = TinyCNN()
    set_flat_params(m2, flat)
    assert torch.allclose(flatten_params(m2), flat)
    print("[ok] 参数扁平化/还原可逆")


def test_scenario_cache_precompute_deterministic():
    from .simulation import ScenarioCache, make_scenario as _ms
    X, y = make_dataset(n_per_class=80, seed=3)
    test_ds = ArrayDataset(X[:120], y[:120])
    pool_X, pool_y = X[120:], y[120:]
    splits = dirichlet_noniid_split(pool_X, pool_y, 5, alpha=0.3,
                                    seed=3, min_size=15)
    root_ds = ArrayDataset(pool_X[:60], pool_y[:60])
    spec = {"name": "t", "attack": "gaussian", "num_malicious": 1}
    scn = _ms(spec, 5)
    init = flatten_params(TinyCNN())
    cache = ScenarioCache(scn, splits, test_ds, root_ds, rounds=2,
                          local_epochs=1, lr=0.05, batch_size=16,
                          base_seed=3)
    cache.precompute(init)
    assert len(cache.rounds_data) == 2
    for bundle in cache.rounds_data:
        assert len(bundle["updates"]) == 5
        assert bundle["root_update"].shape == init.shape
        assert bundle["is_malicious"].sum() == 1
    print("[ok] ScenarioCache 预计算签名与输出结构正确")


def main():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
    print(f"\n全部 {len(fns)} 项测试通过。")


if __name__ == "__main__":
    main()
