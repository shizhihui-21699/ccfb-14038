"""合成"医学影像"数据与非 IID 切分。

为什么用合成数据而不是真实影像数据集:
1. 本机离线、无法下载 MNIST 等公开集;
2. 合成数据可以精确控制类别原型、噪声水平和各家医院的分布偏斜,
   便于公平复现实验;
3. 数据生成过程模拟影像特征: 每类疾病有特定空间位置/朝向/频率的
   纹理原型(Gabor 样条 + 类特异性亮斑),叠加泊松级噪声,
   小 CNN 可以学到真实的特征而不是靠标签记忆。
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
import torch
from torch.utils.data import Dataset

NUM_CLASSES = 6
IMG_SIZE = 16


def _class_prototype(cls: int, rng: np.random.Generator, n: int) -> np.ndarray:
    """生成某一类别的原型影像批次 (n, 1, H, W)。

    每类绑定: 一个高斯亮斑的位置 + 一组不同朝向/频率的条纹,
    同类内部有位置抖动和强度抖动。
    """
    h = w = IMG_SIZE
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    # 每类固定的亮斑中心(两象限以上分散开)
    cx = (cls * 5 + 3) % h
    cy = (cls * 7 + 2) % w
    # 每类固定的条纹朝向与频率
    angle = cls * math.pi / NUM_CLASSES
    freq = 0.6 + 0.25 * cls
    imgs = np.empty((n, 1, h, w), dtype=np.float32)
    blob_sigma = 2.0 + 0.3 * cls
    for i in range(n):
        jx = rng.normal(0, 1.2)
        jy = rng.normal(0, 1.2)
        blob = np.exp(-(((xx - cx - jx) ** 2) + ((yy - cy - jy) ** 2))
                      / (2 * blob_sigma ** 2))
        phase = rng.uniform(0, 2 * math.pi)
        stripes = np.cos(2 * math.pi * freq *
                         (xx * math.cos(angle) + yy * math.sin(angle)) + phase)
        amp = rng.uniform(0.8, 1.2)
        img = amp * (0.65 * blob + 0.35 * stripes)
        img += rng.normal(0, 0.35, img.shape).astype(np.float32)  # 传感器噪声
        imgs[i, 0] = img
    return imgs


def make_dataset(n_per_class: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """生成全局数据集, 返回 (X, y), X 已做逐样本标准化。"""
    rng = np.random.default_rng(seed)
    xs, ys = [], []
    for c in range(NUM_CLASSES):
        x = _class_prototype(c, rng, n_per_class)
        xs.append(x)
        ys.append(np.full(n_per_class, c, dtype=np.int64))
    X = np.concatenate(xs, 0)
    y = np.concatenate(ys, 0)
    perm = rng.permutation(len(y))
    X, y = X[perm], y[perm]
    # 逐样本标准化, 模拟影像预处理
    mean = X.mean(axis=(1, 2, 3), keepdims=True)
    std = X.std(axis=(1, 2, 3), keepdims=True) + 1e-6
    X = (X - mean) / std
    return X.astype(np.float32), y


class ArrayDataset(Dataset):
    def __init__(self, X: np.ndarray, y: np.ndarray):
        self.X = torch.from_numpy(X)
        self.y = torch.from_numpy(y)

    def __len__(self) -> int:
        return len(self.y)

    def __getitem__(self, idx: int):
        return self.X[idx], self.y[idx]


@dataclass
class HospitalSplit:
    """一家医院(一个联邦参与方)的数据。"""
    client_id: int
    X: np.ndarray
    y: np.ndarray
    class_counts: np.ndarray


def dirichlet_noniid_split(
    X: np.ndarray,
    y: np.ndarray,
    num_clients: int,
    alpha: float,
    seed: int,
    min_size: int = 80,
) -> list[HospitalSplit]:
    """Dirichlet 非 IID 切分。

    alpha 越小偏斜越严重: 某些医院几乎只见到少数类别,
    模拟专科医院/地区病谱差异。比例低于阈值的类别在该医院直接缺失,
    制造"罕见病科室空白"这一真实场景。
    """
    rng = np.random.default_rng(seed)
    client_idx: list[list[int]] = [[] for _ in range(num_clients)]
    for c in range(NUM_CLASSES):
        idx_c = np.where(y == c)[0]
        rng.shuffle(idx_c)
        props = rng.dirichlet(alpha * np.ones(num_clients))
        # 极端小配额归零, 形成类别缺失
        props[props < 0.05] = 0.0
        props = props / props.sum()
        cuts = (np.cumsum(props) * len(idx_c)).astype(int)[:-1]
        for i, chunk in enumerate(np.split(idx_c, cuts)):
            client_idx[i].extend(chunk.tolist())

    # 防止切出过小的医院: 从最大医院匀样本
    sizes = [len(s) for s in client_idx]
    while min(sizes) < min_size:
        big = int(np.argmax(sizes))
        small = int(np.argmin(sizes))
        move = client_idx[big].pop(rng.integers(0, len(client_idx[big])))
        client_idx[small].append(move)
        sizes = [len(s) for s in client_idx]

    splits = []
    for i, idxs in enumerate(client_idx):
        idxs_arr = np.array(sorted(idxs), dtype=np.int64)
        counts = np.bincount(y[idxs_arr], minlength=NUM_CLASSES)
        splits.append(HospitalSplit(i, X[idxs_arr], y[idxs_arr], counts))
    return splits


# ---------------------------------------------------------------- 投毒数据
def backdoor_poison(ds: ArrayDataset, target: int,
                    patch: int = 3) -> ArrayDataset:
    """后门投毒: 右下角加白色方块, 标签改为目标类。

    模拟"影像仪水印/校准贴片被利用为触发器"。
    """
    X = ds.X.clone()
    y = ds.y.clone()
    X[:, :, -patch:, -patch:] = 3.0  # 标准化后的强信号方块
    y[:] = target
    return ArrayDataset(X.numpy(), y.numpy())


def trigger_testset(ds: ArrayDataset, source: int,
                    patch: int = 3) -> tuple[ArrayDataset, np.ndarray]:
    """构造后门评估集: 只取 source 类样本并打触发器, 保留原标签用于 ASR。"""
    mask = (ds.y.numpy() == source)
    X = ds.X[mask].clone()
    y_orig = ds.y[mask].clone()
    X[:, :, -patch:, -patch:] = 3.0
    return ArrayDataset(X.numpy(), y_orig.numpy()), y_orig.numpy()


def label_flip_poison(ds: ArrayDataset, source: int, target: int) -> ArrayDataset:
    """定向标签翻转: 只把 source 类翻成 target, 其余样本保持干净。

    对应"只让某一类病例判断变差"的隐蔽攻击: 整体准确率只受单类影响。
    """
    y = ds.y.clone()
    y[y == source] = target
    return ArrayDataset(ds.X.numpy(), y.numpy())
