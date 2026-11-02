#!/usr/bin/env python3
"""§18.2 判据 c4 红先臂：`satellite_index` 进 `update-gate-data` 拦截面（2026-10-04）。

缺陷（遗漏⑤ / 二轮）：`update-gate-data` 顶层是**浅合并** ⟹ fragment 里一个 `satellite_index`
对象把**整份**卫星索引换掉 ⟹ 与前台并发时丢更新（G4 lost-update）。原拦截面**只**护
`edit_budget.sessions`，`satellite_index` 无护。

修法：`cmd_update_gate_data` 增定点校验 —— 若替换会**丢失**既有索引项（`batch_id`）⟹ fail-loud
拒写，指引改用叶子级写 `set-nested gate_data.satellite_index.<batch_id>`。

臂（HEAD 必红：`cmd_update_gate_data` 段内无 `satellite_index`）：
  · `guard_lives_in_update_gate_data_segment` 静态：`satellite_index` 须落在该函数段内（c4 判据）
  · `dropping_index_entry_fails` 行为：丢项 → 拒 + `dropped_batch_ids`
  · `keeping_index_entries_passes` 负臂：全保留 → 放行（零回归，防「全禁」）
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_state_patch as SP  # noqa: E402


def _state(tmp: Path, si) -> Path:
    p = tmp / ".gatekeeper.state"
    p.write_text(json.dumps({"gate_data": {"satellite_index": si}}, ensure_ascii=False),
                 encoding="utf-8", newline="\n")
    return p


def test_guard_lives_in_update_gate_data_segment():
    src = (SCRIPTS / "gk_state_patch.py").read_text(encoding="utf-8")
    seg = src[src.index("def cmd_update_gate_data("):src.index("def cmd_set_top(")]
    assert "satellite_index" in seg, "c4：`satellite_index` 须进 cmd_update_gate_data 定点校验段"


def test_dropping_index_entry_fails(tmp_path):
    st = _state(tmp_path, {"b1": {"file": "x"}})
    out = SP.cmd_update_gate_data(
        str(st), json.dumps({"satellite_index": {"b2": {"file": "y"}}}))
    assert out["ok"] is False and "satellite_index" in out["error"], out
    assert out.get("dropped_batch_ids") == ["b1"], out


def test_keeping_index_entries_passes(tmp_path):
    st = _state(tmp_path, {"b1": {"file": "x"}})
    out = SP.cmd_update_gate_data(
        str(st), json.dumps({"satellite_index": {"b1": {"file": "x"}, "b2": {"file": "y"}}}))
    assert out["ok"] is True, out


# ── D1（2026-10-21，审计署交付门 D1 / 丢叶面）：同 batch 内 per-arm 叶子整段替换 ──
# 已有拦截只比 **batch 层**（`dropped_batch_ids`）⟹ `{b1:{A,B}} → {b1:{A}}` 中 b1 仍在
# ⟹ 原判据放行，臂 B 的索引叶子被静默抹除（卫星片仍在盘上，但读面无从回溯）。
# 卫星索引 append-only ⟹ 既有臂**消失**或被**改写**都必须 fail-loud（禁判 PASS）。

def test_leaf_guard_lives_in_update_gate_data_segment():
    src = (SCRIPTS / "gk_state_patch.py").read_text(encoding="utf-8")
    seg = src[src.index("def cmd_update_gate_data("):src.index("def cmd_set_top(")]
    assert "dropped_arms" in seg and "replaced_arms" in seg, \
        "D1：per-arm 叶子守卫须落在 cmd_update_gate_data 定点校验段"


def test_dropping_per_arm_leaf_fails(tmp_path):
    st = _state(tmp_path, {"b1": {"armA": {"file": "a"}, "armB": {"file": "b"}}})
    out = SP.cmd_update_gate_data(
        str(st), json.dumps({"satellite_index": {"b1": {"armA": {"file": "a"}}}}))
    assert out["ok"] is False, out
    assert out.get("dropped_arms") == {"b1": ["armB"]}, out


def test_replacing_per_arm_leaf_value_fails(tmp_path):
    st = _state(tmp_path, {"b1": {"armA": {"file": "a", "records": 1}}})
    out = SP.cmd_update_gate_data(
        str(st), json.dumps({"satellite_index": {"b1": {"armA": {"file": "evil"}}}}))
    assert out["ok"] is False, out
    assert out.get("replaced_arms") == {"b1": ["armA"]}, out


def test_non_dict_batch_replacement_fails(tmp_path):
    st = _state(tmp_path, {"b1": {"armA": {"file": "a"}}})
    out = SP.cmd_update_gate_data(
        str(st), json.dumps({"satellite_index": {"b1": "gone"}}))
    assert out["ok"] is False, out
    assert out.get("dropped_arms") == {"b1": ["armA"]}, out


def test_adding_per_arm_leaf_passes(tmp_path):
    st = _state(tmp_path, {"b1": {"armA": {"file": "a"}}})
    out = SP.cmd_update_gate_data(
        str(st), json.dumps({"satellite_index": {"b1": {"armA": {"file": "a"},
                                                       "armB": {"file": "b"}}}}))
    assert out["ok"] is True, out
