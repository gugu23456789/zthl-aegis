#!/usr/bin/env python3
"""红先臂：provider 单次输出硬上限钳制（`ECC-A34A8540151B`）。

病象（2026-10-10 实测）：`--tier 4`（`max_output_tokens=160000`）打 MiMo
（`https://api.xiaomimimo.com/v1`）→ `400 Param Incorrect: max_tokens is too large:
160000 ... at most 131072` ⟹ 6/6 臂 `empty_ecc`（零内容）。
回归源 = 2026-10-03 撤销 plan-refinement 的 16000 硬覆盖后，**档位值直通模型**。

判据（**HEAD 必红**）：`gk_suba_tiers` 无 `MODEL_MAX_OUTPUT_TOKENS` / `provider_of` /
`clamp_max_output_tokens` ⟹ `ImportError`/`AttributeError` ⟹ 红；修后绿。
"""
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))


def _tiers():
    import gk_suba_tiers as t
    return t


def test_arm1_tier4_mimo_is_clamped():
    """臂1（主判据）：tier4=160000 打 MiMo ⟹ 钳到 131072。"""
    t = _tiers()
    assert t.clamp_max_output_tokens(160000, "mimo") == 131072


def test_arm2_deepseek_tier4_unclamped():
    """臂2（对照）：tier4=160000 打 DeepSeek ⟹ 原值（160000 < 393216 上限）。"""
    t = _tiers()
    assert t.clamp_max_output_tokens(160000, "deepseek") == 160000


def test_arm3_unknown_provider_failopen():
    """臂3（fail-open）：未知 provider ⟹ 不钳制（不因表缺误伤）。"""
    t = _tiers()
    assert t.clamp_max_output_tokens(160000, "") == 160000
    assert t.clamp_max_output_tokens(160000, "ollama") == 160000


def test_arm4_provider_of_infers_from_base():
    """臂4：provider 推断（`xiaomimimo` 须先于 `mimo` 命中）。"""
    t = _tiers()
    assert t.provider_of("https://api.xiaomimimo.com/v1", "mimo-v2.6-flash") == "mimo"
    assert t.provider_of("https://api.deepseek.com", "deepseek-flash") == "deepseek"
    assert t.provider_of("", "") == ""


def test_arm5_runner_applies_clamp_at_tier_resolution():
    """臂5（接线）：`subagent_runner` 在 `--tier` 解析处**消费**钳制（非只加库函数）。"""
    src = (_HERE / "subagent_runner.py").read_text(encoding="utf-8")
    assert "clamp_max_output_tokens(_t[" in src, \
        "runner 未在档位解析处调用钳制（库有函数但未接线 ⟹ 病象仍在）"
    assert "provider_of(" in src, "runner 未推断 provider"
