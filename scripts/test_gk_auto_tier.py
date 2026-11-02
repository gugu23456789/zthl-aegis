#!/usr/bin/env python3
"""契约臂：`GK_AUTO_TIER` **默认开**（2026-10-08 用户裁定「自动换挡默认开」）。

由 finding `ECC-46C8BF837715`（档位自动换挡补全）延伸：消费块
`gatekeeper-cli.sh::cmd_plan_refinement` 原默认 `GK_AUTO_TIER=0`（只告警）⟹ 现翻为**默认 `1`**
（自动换挡；`0` = 显式 opt-out）。

守卫对象 = **默认语义** + **换挡边界**（本仓配置默认与安全相关，须钉）。判据面 = CLI 源文本。
落刀前（HEAD `3f2807b`）guard = `${GK_AUTO_TIER:-0}" = "1"` ⟹ arm1 红；落刀后绿。
"""
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
CLI = SD / "gatekeeper-cli.sh"


def test_auto_tier_default_on_and_bounded():
    """默认开（缺省 1，`0` = opt-out）+ 单步 +1 + 以最高档封顶（不连跳）。"""
    src = CLI.read_text(encoding="utf-8")
    assert '"${GK_AUTO_TIER:-1}" != "0"' in src, (
        "缺「默认开」guard —— 自动换挡须**默认启用**（`GK_AUTO_TIER` 缺省 1；设 `0` 才关）")
    assert '_new_tier=$(( _cur_tier + 1 ))' in src, "换挡须为**单步 +1**（不连跳）"
    assert '"$_cur_tier" -lt "$_tier_max"' in src, "换挡须以 `max(SUBA_TIERS)` **封顶**（不得越最高档）"


def test_auto_tier_old_default_off_form_absent():
    """旧「默认关」form（`${GK_AUTO_TIER:-0} = 1`）须已消失 —— 防回退。"""
    src = CLI.read_text(encoding="utf-8")
    assert '"${GK_AUTO_TIER:-0}" = "1"' not in src, (
        "仍见旧「默认关」form ⟹ 自动换挡未真正默认开（回退风险）")
