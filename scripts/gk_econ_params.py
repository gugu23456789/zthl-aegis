#!/usr/bin/env python3
"""经济参数**单源**（credit-economic-control plan §9.2；owner 2026-10-31 已签 #4）。

参数值 = 按**真提额**实测重导（§9.2.1）：
  · 严格分布（`to_max > from_max`）：33 个 UTC 日共 10 次，**max = 1 次/日**
  · 宽松分布（含历史无 `from_max` 行）：37 次，q90=4 / q95=5 / q99=7

取值依据（禁止再在本门内另立常量，见 `gk_edit_gate.py` 顶部禁令）：
  F=1     免费额度 = 严格分布 max（正常作业永不付熵）
  K=4     饱和：n=3 → 0.50（不阻断，强制 --api）、n=4 → 0.75（越线）= 宽松 q90
  CAP=6   每日真提额硬上限，夹在宽松 q95=5 与 q99=7 之间
  N=15    score 阈值 = 一个 `fail(−15)` 量子（相对 `econ_enabled_at` 基线）

env 覆盖（仅供实验；默认值与签定值一致）：GK_ECON_F / GK_ECON_K / GK_ECON_CAP /
GK_ECON_N / GK_ECON_T_API / GK_ECON_T_BLOCK。非法值回退默认（门禁不应因环境串而崩溃）。
"""
import os


def _env_num(name: str, default, cast=int):
    try:
        return cast(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


F = max(0, _env_num("GK_ECON_F", 1))
K = max(1, _env_num("GK_ECON_K", 4))
CAP = max(1, _env_num("GK_ECON_CAP", 6))
N = _env_num("GK_ECON_N", 15)
T_API = _env_num("GK_ECON_T_API", 0.3, float)       # > T_API ⟹ 强制 monitor --api
T_BLOCK = _env_num("GK_ECON_T_BLOCK", 0.5, float)   # 严格 > T_BLOCK ⟹ 熵阻断


def raise_entropy(n: int) -> float:
    """当日提额 n 次的熵贡献：`min(1, max(0, n−F)/K)`（分段成本，非 n/3 一刀切）。"""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return 0.0
    return min(1.0, max(0.0, (n - F) / K))


def should_force_api(rate: float) -> bool:
    """熵 > T_API ⟹ monitor 从 --local 升到 --api（测量升级，不是阻断）。"""
    return float(rate) > T_API


def should_block(rate: float) -> bool:
    """熵严格 > T_BLOCK ⟹ 阻断（调用方仍受 `GK_ENTROPY_RAISE_ENFORCE` 开关约束）。"""
    return float(rate) > T_BLOCK
