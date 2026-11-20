"""抗恶意参与方的联邦学习模拟框架。

模块划分:
  data.py        合成影像数据 + 非 IID 医院切分 + 投毒数据集
  model.py       小型 CNN 与参数扁平化工具
  attacks.py     六类攻击更新构造(含自适应范数伪装)
  aggregators.py 八种聚合/防御策略(含自研分层防御 AdaGuard)
  simulation.py  联邦轮次循环与评估指标
  plotting.py    曲线/柱状图与结果汇总
"""
