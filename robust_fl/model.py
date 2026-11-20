"""模型定义与参数扁平化工具。"""
from __future__ import annotations

import torch
from torch import nn

from .data import IMG_SIZE, NUM_CLASSES


class TinyCNN(nn.Module):
    """两层卷积的轻量影像分类网络, 参数量约 2 万, CPU 上一轮训练毫秒级。"""

    def __init__(self, num_classes: int = NUM_CLASSES):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(1, 8, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),                       # 16 -> 8
            nn.Conv2d(8, 16, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.AvgPool2d(2),                       # 8 -> 4
        )
        self.head = nn.Sequential(
            nn.Linear(16 * 4 * 4, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes),
        )

    def forward(self, x):
        x = self.features(x)
        x = x.flatten(1)
        return self.head(x)


def flatten_params(model: nn.Module) -> torch.Tensor:
    """把模型参数拷贝并拼接成一维向量。"""
    return torch.cat([p.detach().clone().flatten() for p in model.parameters()])


def set_flat_params(model: nn.Module, flat: torch.Tensor) -> None:
    """用一维向量覆盖模型参数。"""
    offset = 0
    for p in model.parameters():
        n = p.numel()
        p.data.copy_(flat[offset:offset + n].view_as(p))
        offset += n


def model_like(model: nn.Module) -> TinyCNN:
    """新建一个同结构、同初始化种子隔离的模型(由调用方再灌参数)。"""
    return TinyCNN(model.head[-1].out_features)
