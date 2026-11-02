#!/usr/bin/env python3
"""模型/端点**可换配置**回归锁（2026-10-02）。

动机（用户）：模型保质期 ~3 个月（旧模型退役 / 新模型上线，更好更便宜），降级链的目标是
  **兜底防爆** ⟹ 换代应**只改配置（env）不改代码**。既有原则（`gatekeeper-cli.sh` L374-375）=
  「不再把模型名写死为某代产品，只保留 **默认值 + env 覆盖**」——但 **MiMo 侧违反**（base/model 硬编码）。

判据（5 臂，**源码解析**、零依赖）：
  ① DS 侧三旋钮（base / ACTOR / CRITIC）为 `${ENV:-默认}` 形态；
  ② MiMo 侧三旋钮（base / ACTOR / CRITIC）为 `${ENV:-默认}` 形态；
  ③ 消费链未断：`_resolve_provider_config` 仍由这些变量派生 `API_BASE` / `API_MODEL`；
  ④ 防回归：bash 侧不得再出现**硬编码**的 provider base/model 字面量赋值；
  ⑤ 防回归：python `gk_monitor_api.py::PROVIDERS` 的 base/model 亦 env 覆盖形态（2026-10-02 补齐）。

⚠ 覆盖面 = **bash 单源**（真正生效路径：monitor① / subagent② / appeal 三者均取 `$API_BASE`/`$API_MODEL`，
  见 `gk_appeal.py` docstring「解析链：显式参数 → env → 默认」）**+ python 第二份**
  （`gk_monitor_api.py::PROVIDERS`，**当前未接线**，属 G5 收编面）。两者现**同 env 作用域**
  （`DEEPSEEK_BASE_URL` / `GK_CRITIC_MODEL` / `MIMO_BASE_URL` / `GK_MIMO_CRITIC_MODEL`）⟹
  换代只改配置即两侧同变；收编/接线（含 zthl ACP daemon）时不再静默用旧模型。
"""
import re
from pathlib import Path

SH = (Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
PY = (Path(__file__).resolve().parent / "gk_monitor_api.py").read_text(encoding="utf-8")


def _is_env_overridable(var: str) -> bool:
    """`VAR="${ENV:-默认}"` 形态（env 可覆盖）。"""
    return bool(re.search(r'^%s="\$\{[A-Za-z_][A-Za-z0-9_]*:-[^}]*\}"' % re.escape(var), SH, re.M))


def test_ds_side_knobs_env_overridable():
    """① DS 侧：base / ACTOR / CRITIC 三旋钮 env 可覆盖（既有设计，防回退为硬编码）。"""
    for v in ("DS_API_BASE", "DS_MODEL_ACTOR", "DS_MODEL_CRITIC"):
        assert _is_env_overridable(v), f"{v} 非 env 覆盖形态 ⟹ 换代须改代码"


def test_mimo_side_knobs_env_overridable():
    """② MiMo 侧：base / ACTOR / CRITIC 三旋钮 env 可覆盖（本批补齐，与 DS 对称）。"""
    for v in ("MIMO_API_BASE", "MIMO_MODEL_ACTOR", "MIMO_MODEL_CRITIC"):
        assert _is_env_overridable(v), f"{v} 非 env 覆盖形态 ⟹ MiMo 换代须改代码"


def test_resolve_provider_config_consumes_knobs():
    """③ 消费链未断：`_resolve_provider_config` 仍由上述旋钮派生 `API_BASE` / `API_MODEL`。"""
    m = re.search(r"_resolve_provider_config\(\)\s*\{(.*?)\n\}", SH, re.S)
    assert m, "未定位 `_resolve_provider_config`"
    body = m.group(1)
    assert 'API_BASE="$MIMO_API_BASE"' in body and 'API_MODEL="$MIMO_MODEL_CRITIC"' in body, \
        "MiMo 分支未消费 MIMO_* 旋钮（消费链断）"
    assert 'API_BASE="$DS_API_BASE"' in body and 'API_MODEL="$DS_MODEL_CRITIC"' in body, \
        "DS 分支未消费 DS_* 旋钮（消费链断）"


def test_no_new_hardcoded_provider_literals():
    """④ 防回归：不得再出现**硬编码**的 provider base/model 字面量赋值（须走 env 默认）。"""
    bad = re.findall(
        r'^(MIMO_MODEL_[A-Z]+|MIMO_API_BASE|DS_MODEL_[A-Z]+|DS_API_BASE)="[^$][^"]*"', SH, re.M)
    assert not bad, f"发现硬编码 provider 旋钮（应改 `${{ENV:-默认}}` 形态）：{bad}"


def test_python_providers_env_overridable():
    """⑤ 防回归：python `gk_monitor_api.py::PROVIDERS` 的 base/model 为 env 覆盖形态（与 bash 对称）。
    2026-10-02：原为**硬编码第二份**（未接线，属 G5 收编面）⟹ 现 env 化，防收编/接线
    （含 zthl ACP daemon，其原型 `gk_worker.py` 预载本模块）时静默用旧模型。"""
    for key in ("DEEPSEEK_BASE_URL", "GK_CRITIC_MODEL", "MIMO_BASE_URL", "GK_MIMO_CRITIC_MODEL"):
        assert f'os.environ.get("{key}"' in PY, f"python PROVIDERS 未 env 化：{key}"
