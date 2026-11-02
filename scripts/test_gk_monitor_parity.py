#!/usr/bin/env python3
"""`G5` 收编切片 —— **证据 parity 臂**（2026-10-02）。

背景（读码实测，非推断）：`scripts/gk_monitor_api.py` 头部自称
「Extracted from gatekeeper-cli.sh _monitor_api() … Full alignment: failover chain, retry,
GitNexus injection, hard evidence, …」——但四份「第二实现」与 bash 侧**单源**实际**不对等**：

| 第二实现（python） | bash 单源 | 实测关系 |
|:--|:--|:--|
| `FAILOVER_CHAIN` (`gk_monitor_api.py::FAILOVER_CHAIN`) | `gatekeeper-cli.sh::GK_FAILOVER_CHAIN` | ✅ **已机制合并（2026-10-02）**：两侧同读 env 作用域 `GK_FAILOVER_CHAIN`（bash `export` + python `os.environ`），默认串机检守 |
| `_is_retryable` (`gk_monitor_api.py::_is_retryable`) | `gatekeeper-cli.sh::_is_retryable` | **契约不同**：bash 收**消息串**（正则），python 收**状态码**（int）⟹ 非同形 |
| `_collect_hard_evidence` (`gk_monitor_api.py::_collect_hard_evidence`) | `gatekeeper-cli.sh::_collect_hard_evidence` | python 键集是 bash 的**子集**且键名漂移（`git_workflow_marker` ≠ `git_workflow`） |
| `_inject_gitnexus` (`gk_monitor_api.py::_inject_gitnexus`) | bash `_monitor_api` **内联**（无具名函数） | 无 bash 具名对应物 ⟹ 非单源 |

**本文件用途 = 把上述关系编码成机检证据**：

- **降级链（已合并，2026-10-02）**：3 条**绿臂** —— 默认串 parity / python 读 env 作用域 / bash `export`。
- **其余 3 份缺口**：`xfail(strict=True)` 臂断言**应收敛到单源**；当前**必然红** ⟹ 即 G5 收编的待办证据。
  `strict=True` 使其在**收编落地后**变 `XPASS` 失败 ⟹ 提醒移除该 `xfail`（**自动退役**，不会
  静默遗留）。**不得**为了让本文件全绿而改实现之外的语义 —— 本文件只**记录**已合并项与缺口。

解析方式：**源码解析**（`re`），不 import 被测模块 ⟹ 零依赖（`requests` 缺失亦可跑）、确定性。
"""
import re
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
PY_SRC = (SCRIPT_DIR / "gk_monitor_api.py").read_text(encoding="utf-8")
SH_SRC = (SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8")


def _py_failover_chain() -> list:
    """python `FAILOVER_CHAIN` 的**默认串**（env fallback）。

    机制合并后 `FAILOVER_CHAIN` 由 `os.environ.get("GK_FAILOVER_CHAIN", "<默认>")` 派生
    ⟹ 从源码解析该**默认串**（不再是字面量列表）。
    """
    m = re.search(r'GK_FAILOVER_CHAIN"\s*,\s*"([^"]*)"', PY_SRC)
    assert m, "gk_monitor_api.py 未从 `GK_FAILOVER_CHAIN` env 读取（缺默认串）"
    return m.group(1).split(",")


def _sh_failover_default() -> list:
    m = re.search(r'GK_FAILOVER_CHAIN="\$\{GK_FAILOVER_CHAIN:-([^}"]*)\}"', SH_SRC)
    assert m, "gatekeeper-cli.sh 未见 `GK_FAILOVER_CHAIN=\"${GK_FAILOVER_CHAIN:-…}\"` 定义"
    return m.group(1).split(",")


def test_parity_failover_chain_default_equals_bash():
    """**绿臂**：python `FAILOVER_CHAIN` **默认串** == bash `GK_FAILOVER_CHAIN` **默认串**。

    防后续单侧改动把两侧默认改歪（合并后两侧默认仍在各自文件，靠本臂机检守）。
    """
    py = _py_failover_chain()
    bs = _sh_failover_default()
    assert py == bs, f"降级链默认值漂移：python={py} bash={bs}"


def test_parity_failover_chain_reads_env_scope():
    """**绿臂（机制合并）**：python `FAILOVER_CHAIN` 从**同一 env 作用域** `GK_FAILOVER_CHAIN`
    读取（与 bash 同源同接口）⟹ 宿主/环境改一处即两实现同变（原为硬编码第二实现，改不了）。"""
    assert re.search(r'os\.environ\.get\(\s*"GK_FAILOVER_CHAIN"', PY_SRC), \
        "python `FAILOVER_CHAIN` 未从 `GK_FAILOVER_CHAIN` env 作用域读取"


def test_parity_failover_chain_is_exported_by_bash():
    """**绿臂（机制合并）**：bash `GK_FAILOVER_CHAIN` 须 **export** ⟹ 成为**可继承的单一作用域**
    （python 等子进程可直接继承，无需各写一份默认）。"""
    assert re.search(r"^export GK_FAILOVER_CHAIN=", SH_SRC, re.M), \
        "bash 未 `export GK_FAILOVER_CHAIN`（子进程不可继承 ⟹ 作用域不共享）"


@pytest.mark.xfail(strict=True, reason=(
    "G5 未收编：bash `_is_retryable` 收**消息串**（`$1` + rg 正则），python 收**状态码**（int）"
    "⟹ 两实现不可互换（同调用点会 TypeError / 语义错配）。收编后应绿 ⟹ 移除本 xfail。"))
def test_parity_is_retryable_message_contract_matches_bash():
    """**证据臂**：`_is_retryable` 应与 bash 同形（收消息串，判 `timeout|5xx|refused|…`）。"""
    m = re.search(r"def _is_retryable\(([^)]*)\)", PY_SRC)
    assert m, "gk_monitor_api.py 未见 `def _is_retryable(...)`"
    assert "msg" in m.group(1), \
        f"python `_is_retryable` 契约应为**消息串**（bash 同形），实为：{m.group(1).strip()}"


@pytest.mark.xfail(strict=True, reason=(
    "G5 未收编：python 证据键集是 bash 的**子集**且键名漂移（`git_workflow_marker`≠`git_workflow`）"
    "⟹ 评审硬证据口径两侧不一致。收编后应绿 ⟹ 移除本 xfail。"))
def test_parity_hard_evidence_keys_cover_bash():
    """**证据臂**：python `_collect_hard_evidence` 的键集应覆盖 bash 的 `ev_*` 键集。"""
    py_keys = set(re.findall(r'evidence\["([a-z_]+)"\]\s*=', PY_SRC))
    sh_keys = set(re.findall(r"^  ev_([a-z_]+)=", SH_SRC, re.M))
    missing = sh_keys - py_keys
    assert not missing, f"python 缺 bash 证据键（键名漂移/漏项）：{sorted(missing)}"


@pytest.mark.xfail(strict=True, reason=(
    "G5 未收编：bash 的 GitNexus 注入是 `_monitor_api` **内联**（无具名函数），python 有 "
    "`_inject_gitnexus` ⟹ 无单源对应物。收编后应绿 ⟹ 移除本 xfail。"))
def test_parity_inject_gitnexus_is_single_source():
    """**证据臂**：GitNexus 注入应在两侧**同源**（bash 应提取为具名函数）。"""
    assert re.search(r"^_inject_gitnexus\(\)", SH_SRC, re.M), \
        "bash 无 `_inject_gitnexus` 具名函数（仍为 _monitor_api 内联 ⟹ 非单源）"


# ── 降级链**作用域边界臂**（2026-10-02；用户关注点：「降级链是否服务两套主体」）──────────────
# 实测：技能侧有**两套**降级机制，服务**两套主体** ——
#   ① **API 评审（critic）**：`_monitor_api`（数组遍历 `GK_FAILOVER_CHAIN` + 每跳重试 + `_is_retryable`）；
#   ② **subagent 执行（worker）**：`cmd_monitor --subagent` 降级段 = **硬编码 DS→mimo 两腿翻转**
#      （`GK_MIMO_DISABLED` / `MIMO_API_KEY` 守卫），**不读** `GK_FAILOVER_CHAIN`。
# 风险：若把①的 env 键**串**给②（或反之），改一处的调度会**意外改另一主体** ⟹ 误伤。
# 故本组臂把「① 读 / ② 不读」钉死（防未来"统一所有模型路由"时静默串用）。

def test_scope_subject1_monitor_reads_env_chain():
    """**作用域臂**：主体①（`_monitor_api`）**确**读 `GK_FAILOVER_CHAIN`（数组遍历形态）。"""
    assert re.search(r"failover_chain=\(\$\{GK_FAILOVER_CHAIN", SH_SRC), \
        "主体①（`_monitor_api`）未读 `GK_FAILOVER_CHAIN`（数组遍历形态变了？）"


def test_scope_subject2_subagent_does_not_read_env_chain():
    """**作用域臂**：主体②（`--subagent` 降级段）**不得**读 `GK_FAILOVER_CHAIN`
    —— 它是独立主体（硬编码 DS→mimo），共用同一 env 键会与主体①**互相串扰**。"""
    m = re.search(r"if \$subagent_failed; then(.*?)\n    fi\n", SH_SRC, re.S)
    assert m, "未定位 `--subagent` 降级段（锚漂移？）"
    assert "GK_FAILOVER_CHAIN" not in m.group(1), \
        "主体②（`--subagent`）误读 `GK_FAILOVER_CHAIN` ⟹ 两套主体被串用"


def test_scope_python_monitor_is_subject1_not_subagent():
    """**作用域臂**：python `gk_monitor_api.py` 是**主体①的端口**（`Extracted from _monitor_api`），
    **不是**主体② —— 故上文的 env 合并**只作用于①**，不触碰②。"""
    assert "_monitor_api" in PY_SRC, "python 侧未自承主体①来源（Extracted from _monitor_api）"
    assert "--subagent" not in PY_SRC, \
        "python `gk_monitor_api.py` 疑似主体②（subagent）实现 ⟹ 前提不成立"
