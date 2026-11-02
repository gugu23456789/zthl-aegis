"""红先测试：三通道 κ 合成（A′，2026-10-06）。

要点：
  · legacy 样本（仅 `cap/tilt`）⟹ 视作 `p_in`，合成值 == P-in 值（**零回归**）；
  · 三通道合成 = `1 − Π(1−κ_tilt_i)`（缺通道按 0）；
  · 全缺 tilt ⟹ `None`（调用方退化为无折扣）；
  · `batch_tilt` 走**合成**值（非单通道）。
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_kappa as K  # noqa: E402


def test_legacy_sample_is_p_in_only():
    s = {"batch": "x", "cap": [1, 2], "tilt": [1, 2]}
    ch = K.kappa_channels(s)
    assert set(ch) == {"p_in"} and ch["p_in"] == (0.5, 0.5)
    assert K.combined_tilt(s) == 0.5          # 1 − (1−0.5)


def test_three_channel_combination():
    s = {"batch": "x", "channels": {
        "p_in": {"cap": [2, 2], "tilt": [1, 2]},      # tilt 0.5
        "p_art": {"cap": [2, 2], "tilt": [1, 2]},     # tilt 0.5
        "p_meta": {"cap": [2, 2], "tilt": [0, 2]}}}   # tilt 0.0
    assert K.combined_tilt(s) == 0.75         # 1 − (0.5·0.5·1.0)


def test_missing_channel_counts_as_zero():
    s = {"batch": "x", "channels": {"p_art": {"cap": [2, 2], "tilt": [1, 2]}}}
    assert K.combined_tilt(s) == 0.5


def test_all_missing_tilt_none():
    assert K.combined_tilt({"batch": "x", "cap": [2, 2], "tilt": [0, 0]}) is None


def test_batch_tilt_uses_combined_channels():
    td = tempfile.mkdtemp(prefix="gk_kappa_ch_")
    p = os.path.join(td, "led.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"samples": [
            {"batch": "multi", "channels": {
                "p_in": {"cap": [2, 2], "tilt": [1, 2]},
                "p_art": {"cap": [2, 2], "tilt": [1, 2]}}}]}, fh)
    assert K.batch_tilt("multi", path=p) == 0.75
    assert K.batch_tilt("nope", path=p) is None


def test_real_ledger_legacy_zero_regression():
    assert K.batch_tilt("12arm-1of4") == 0.75
    assert K.batch_tilt("R5") == 0.0


# ── 接通（2026-10-06 晚）：p_meta/p_art 由真实观测面派生 ─────────────────────
def test_derive_channels_from_observations():
    ch = K.derive_channels(divergence=0.3, defect_rate=0.5)
    assert ch["p_meta"] == {"tilt": 0.3} and ch["p_art"] == {"tilt": 0.5}
    assert K.derive_channels() == {}          # 无观测 ⟹ 不落通道（不冒充已覆盖）
    assert K.derive_channels(divergence=0.0) == {"p_meta": {"tilt": 0.0}}   # 0 是有效观测


def test_tilt_only_channel_entry():
    s = {"batch": "x", "channels": {"p_meta": {"tilt": 0.25}}}
    ch = K.kappa_channels(s)
    assert ch == {"p_meta": (None, 0.25)}     # cap 缺失 ⟹ None（不猜）
    assert K.combined_tilt(s) == 0.25


def test_batch_tilt_with_live_observations():
    td = tempfile.mkdtemp(prefix="gk_kappa_live_")
    p = os.path.join(td, "led.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"samples": [
            {"batch": "b1", "cap": [2, 2], "tilt": [1, 2]}]}, fh)   # p_in tilt 0.5
    # ledger p_in 0.5 + live p_meta 0.5 ⟹ 1 − 0.5·0.5 = 0.75
    assert K.batch_tilt("b1", path=p, divergence=0.5) == 0.75
    # 批不在 ledger + live ⟹ 仅 live（divergence 0.5 ∧ defect_rate 0.0 ⟹ 1−0.5·1.0）
    assert K.batch_tilt("ghost", path=p, divergence=0.5, defect_rate=0.0) == 0.5
    # 两者皆无 ⟹ None（零回归）
    assert K.batch_tilt("ghost", path=p) is None


# ── WS2（2026-10-06）：p_in 现场观测 + 通道级 merge（防同通道双计）──────────────
def test_derive_channels_poison_rate_is_p_in():
    assert K.derive_channels(poison_rate=0.25) == {"p_in": {"tilt": 0.25}}
    assert K.derive_channels(poison_rate=0.0) == {"p_in": {"tilt": 0.0}}   # 0 是有效观测


def test_batch_tilt_channel_level_merge_no_double_count():
    """**通道级 merge**：ledger `p_in` 与 live `p_in` 同通道 ⟹ live **覆盖**（只计一次）。

    修前是「ledger 通道 ⊕ live 全量拼接」⟹ 同通道双计（0.5 ∧ 0.5 = 0.75，错）。
    """
    td = tempfile.mkdtemp(prefix="gk_kappa_merge_")
    p = os.path.join(td, "led.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"samples": [{"batch": "m", "cap": [2, 2], "tilt": [1, 2]}]}, fh)  # p_in 0.5
    assert K.batch_tilt("m", path=p, poison_rate=0.5) == 0.5    # 覆盖，非 1−(0.5·0.5)=0.75
    assert K.batch_tilt("m", path=p, poison_rate=0.25) == 0.25
    # 异通道仍合成：p_in 0.5（ledger）+ p_meta 0.5（live）⟹ 0.75
    assert K.batch_tilt("m", path=p, divergence=0.5) == 0.75

