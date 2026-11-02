"""F-REV-63 深修 · T1 红先：写点（RED_RESULT 段）须与读点（`_conv_state_path` 域解析）同源。

根因：`gatekeeper-cli.sh` RED_RESULT 段 `upsert_red_findings('$STATE_FILE', new)` 绑 **base**
state，而读点 `_conv_state_path`（`resolve-state`，fail-closed）解析 **域** state ⟹
findings 账与 journal 异源 ⟹ `MU_BACKCAST_NEGATIVE`（收敛门恒 WARN-only）。

红先契约（HEAD 必红）：裸 `$STATE_FILE` 绑 base 仍在 ⟹ arm1a 应 FAIL；
落刀（T1）后：写点改用中枢解析结果 ⟹ 转 GREEN。

锚形态：`RED_RESULT="$red_result"`（块首）—— 符号锚，非行号。
"""
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
CLI = _ROOT / "gatekeeper-cli.sh"


def _red_result_block() -> str:
    src = CLI.read_text(encoding="utf-8")
    i = src.find('RED_RESULT="$red_result"')
    assert i != -1, "锚失效：RED_RESULT 写块未找到（block 头 `RED_RESULT=\"$red_result\"`）"
    return src[i:i + 2500]


def test_arm1a_write_point_not_bound_to_base_state():
    """臂1a（静态）：写点不得把 findings 账绑到 base `$STATE_FILE`（域隔离后 = 与读点异源）。"""
    blk = _red_result_block()
    assert "upsert_red_findings('$STATE_FILE'" not in blk, (
        "写点仍绑 base `$STATE_FILE` ⟹ 与读点（域 state）异源（F-REV-63 未修）"
    )


def test_arm1b_write_point_uses_conv_center():
    """臂1b（静态）：写点须经取数中枢解析（`_conv_state_path` / `_CONV_STATE`），与读点同一 state。"""
    blk = _red_result_block()
    assert ("_conv_state_path" in blk) or ("_CONV_STATE" in blk), (
        "写点未使用取数中枢（`_conv_state_path` / `_CONV_STATE`）⟹ 非同一 state（F-REV-63 未修）"
    )


# ── 红先（ECC-F8DC9418D005）：ember 导出 gate_data_full 须与 journal 同构回落 ────────────
_ARCHIVE = _ROOT / "scripts" / "gk_discover_archive.py"


def _ember_block() -> str:
    """ember 导出段全文。

    2026-10-28 重锚（B8 抽取）：该段已从 `gatekeeper-cli.sh` 内联迁到
    `gk_discover_archive.py` ⟹ 锚改为模块文件（CLI 内已无 `"gate_data_full"`）。
    """
    src = _ARCHIVE.read_text(encoding="utf-8")
    i = src.find('"gate_data_full"')
    assert i != -1, "锚失效：ember 导出段 `\"gate_data_full\"` 未找到（gk_discover_archive.py）"
    return src[max(0, i - 1800):i + 1200]


def test_arm_ember_gate_data_full_falls_back_to_default_state():
    """**红先臂（ECC-F8DC9418D005）**：余烬导出的 `gate_data_full` 须与同一段里的
    `finding_journal` **同构回落**——域态（由 carry 建立）自身 `gate_data` 为空时，回落权威
    default state 的 `gate_data`，并记 `gate_data_source`。

    HEAD：全仓无 `gate_data_source` ⟹ 本臂**必红**（实测 `.gatekeeper.ember.ECO-SCAN.json`
    有 835 行 journal 但 `gate_data_full` 为空 dict ⟹ `snapshot_pair` 取不到 `ecc_findings`）。
    """
    blk = _ember_block()
    assert '"gate_data_full": _gd_full' in blk, (
        "gate_data_full 未绑定回落结果 `_gd_full` ⟹ 无 default-state 回落（ECC-F8DC9418D005 未修）"
    )
    assert '"gate_data_source": _gd_source' in blk, (
        "余烬载荷无 `gate_data_source` 记账（**仅注释不算**）⟹ 无法区分「注释 / 实现」"
        "（ECC-F8DC9418D005 未修）"
    )

