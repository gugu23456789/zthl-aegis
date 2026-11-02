"""test_gk_state_patch.py — state 增量写入安全网测试（2026-08-25 批次 2 写入类）。

覆盖: update-best 增量（更优才写/不更优不写/r_phase 自动提取）/
update-gate-data 批量 + 类型 coerce + checksum 重算 / subset 过滤排除键 /
写入后 gk_state._verify_checksum 可验证（checksum 闭环）。
安全网 R1: 测试只写 tmp_path 文件，不 patch 标准库全局。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_state
import gk_state_patch as gsp


def _write_state(state_path: Path, data: dict) -> None:
    state_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _base_state(**over):
    d = {
        "r_phase": "R-T6",
        "stage": "STAGE_3",
        "gate_data": {"best": {"score": 0.5, "stage": "STAGE_1",
                               "r_phase": "R-T1", "timestamp": "t0"},
                      "pr_number": "123"},
        "human_resolutions": {
            "G1": {"gate": "G1", "resolution": "allow",
                   "ed25519_sig": "sig-value", "ed25519_hash": "h-value"},
        },
        "current": {"last_updated": "t0"},
    }
    d.update(over)
    return d


class TestUpdateBest:
    def test_better_score_writes(self, tmp_path):
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_update_best(str(p), "0.8", "STAGE_4", "", "t1")
        assert out["ok"] is True and out["new_best"] is True
        data = json.loads(p.read_text(encoding="utf-8"))
        best = data["gate_data"]["best"]
        assert best["score"] == 0.8 and best["stage"] == "STAGE_4"

    def test_worse_score_not_written(self, tmp_path):
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_update_best(str(p), "0.2", "STAGE_9", "", "t1")
        assert out["ok"] is True and out["new_best"] is False
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["gate_data"]["best"]["score"] == 0.5

    def test_r_phase_auto_extracted(self, tmp_path):
        """r_phase 传空 → 从 state 原文自动提取（消除 rg 依赖，对齐原内联语义）。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_update_best(str(p), "0.9", "STAGE_5", "", "t1")
        assert out["ok"] is True and out["new_best"] is True
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["gate_data"]["best"]["r_phase"] == "R-T6"

    def test_written_checksum_verifies(self, tmp_path):
        """写入后 checksum 可被 gk_state._verify_checksum 验证（单一事实闭环）。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        gsp.cmd_update_best(str(p), "0.8", "STAGE_4", "", "t1")
        v = gk_state._verify_checksum(str(p))
        assert v["ok"] is True and v["verified"] is True


class TestUpdateGateData:
    def test_bulk_update_with_coerce(self, tmp_path):
        """JSON 片段 update：bool/字符串按 JSON 语义落地（对齐原 gd.update({...})）。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_update_gate_data(
            str(p), '"branch_cleaned":true,"pr_number":"456"')
        assert out["ok"] is True
        data = json.loads(p.read_text(encoding="utf-8"))
        gd = data["gate_data"]
        assert gd["branch_cleaned"] is True          # JSON bool
        assert gd["pr_number"] == "456"              # JSON 字符串原样

    def test_leading_comma_stripped(self, tmp_path):
        """shell 侧 gd_update 以 ',' 开头（续写），脚本自动剥前导逗号。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_update_gate_data(str(p), ',"commit_shas":"abc123"')
        assert out["ok"] is True
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["gate_data"]["commit_shas"] == "abc123"

    def test_missing_file_reports_error(self, tmp_path):
        out = gsp.cmd_update_gate_data(str(tmp_path / "nope.json"),
                                       '"a":1')
        assert out["ok"] is False

    def test_braced_form_tolerated(self, tmp_path):
        """S7（2026-09-05）：完整 {...} 对象（误带外花括号）亦容错接受。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_update_gate_data(str(p), '{"ci_status": "green"}')
        assert out["ok"] is True
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["gate_data"]["ci_status"] == "green"

    def test_parse_error_gives_guidance(self, tmp_path):
        """S7（2026-09-05）：fragment 解析失败 → ok:false + hint 指引（exit 2 不静默）。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_update_gate_data(str(p), '"broken:unterminated')
        assert out["ok"] is False
        assert "解析失败" in out["error"]
        assert "hint" in out and "外花括号" in out["hint"]

    def test_non_object_rejected(self, tmp_path):
        """S7（2026-09-05）：fragment 解析为数组/标量 → 拒绝并指引。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_update_gate_data(str(p), '[1,2]')
        assert out["ok"] is False
        assert "JSON 对象" in out["error"]

    def test_object_fragment_ending_with_bracket_accepted(self, tmp_path):
        """`ECC-66B6FB76CA65`（红先）：合法对象片段**值恰为数组**（末字符 `]`）不得被误拒。

        原判据 `raw.startswith("[") or raw.endswith("]")` 把**末字符**也当数组信号
        ⟹ 数组值（如 `"some_list":[]`）被误报「疑似数组/标量输入」。
        数组判据只应看**首字符**；标量/畸形由 `json.loads` + `isinstance(obj, dict)` 兜底。
        ⚠ 2026-10-18：本臂只测**解析规则**，故改用非载荷键；`subagent_history` 等载荷键
        已由 `test_gk_host_write_surface.py` 的负臂禁止经第二写面写入。
        """
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_update_gate_data(str(p), '"some_list":[]')
        assert out["ok"] is True, f"合法对象片段（值=空数组）被误拒：{out}"
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["gate_data"]["some_list"] == []


class TestNarrowTasksWriteSurface:
    """P4（2026-10-28 实测）：`gate_data.narrow_tasks` 整表替换绕过三组语义门。

    原实现允许 `update-gate-data '"narrow_tasks":[...]'` 整表替换 ⟹ 合格 6 条可被换成
    2 条 junk（读侧只数条数）。唯一写通路 = `state-patch --narrow-register <json>`
    （`gk_narrow_route.register`：派生 G2 covers / schema / 投毒 / 三组语义，违规零写盘）。
    """

    def _state_with_narrow(self, tmp_path: Path) -> Path:
        p = tmp_path / "state.json"
        d = _base_state()
        d["gate_data"]["narrow_tasks"] = [{"id": "KEEP", "task": "保", "tier": 1}]
        _write_state(p, d)
        return p

    def _narrow_ids(self, p: Path) -> list:
        return [e["id"] for e in json.loads(p.read_text(encoding="utf-8"))
                ["gate_data"]["narrow_tasks"]]

    def test_update_gate_data_rejects_whole_table_replace(self, tmp_path):
        p = self._state_with_narrow(tmp_path)
        out = gsp.cmd_update_gate_data(
            str(p), '"narrow_tasks":[{"id":"JUNK","task":"junk"}]')
        assert out["ok"] is False, out
        assert "唯一写通路" in out["error"], out
        assert "--narrow-register" in out["error"], out
        assert self._narrow_ids(p) == ["KEEP"], "拒绝路径必须零写盘"

    def test_update_gate_data_braced_form_also_rejected(self, tmp_path):
        p = self._state_with_narrow(tmp_path)
        out = gsp.cmd_update_gate_data(
            str(p), '{"narrow_tasks": [], "pr_number": "999"}')
        assert out["ok"] is False, out
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["gate_data"]["pr_number"] == "123", "拒绝须整份不落（不得半写）"
        assert self._narrow_ids(p) == ["KEEP"]

    def test_set_nested_rejects_narrow_tasks(self, tmp_path):
        p = self._state_with_narrow(tmp_path)
        out = gsp.cmd_set_nested(str(p), "gate_data.narrow_tasks",
                                 '[{"id":"JUNK","task":"junk"}]')
        assert out["ok"] is False, out
        assert "--narrow-register" in out["error"], out
        assert self._narrow_ids(p) == ["KEEP"]

    def test_append_list_rejects_narrow_tasks(self, tmp_path):
        p = self._state_with_narrow(tmp_path)
        out = gsp.cmd_append_list(str(p), "gate_data.narrow_tasks",
                                  '{"id":"JUNK","task":"junk"}')
        assert out["ok"] is False, out
        assert "--narrow-register" in out["error"], out
        assert self._narrow_ids(p) == ["KEEP"]

    def test_internal_allow_flag_is_explicit(self, tmp_path):
        """`allow_narrow_tasks=True` 是 register 的内部放行面（非 CLI 可达）。"""
        p = self._state_with_narrow(tmp_path)
        out = gsp.cmd_update_gate_data(
            str(p), '"narrow_tasks":[{"id":"NEW","task":"n","tier":1}]',
            allow_narrow_tasks=True)
        assert out["ok"] is True, out
        assert self._narrow_ids(p) == ["NEW"]


class TestSubset:
    def test_excludes_keys(self, tmp_path):
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_subset(str(p), "human_resolutions", "G1",
                             "ed25519_sig,ed25519_hash")
        assert out["ok"] is True
        assert out["data"] == {"gate": "G1", "resolution": "allow"}

    def test_missing_inner_returns_empty(self, tmp_path):
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_subset(str(p), "human_resolutions", "G2",
                             "ed25519_sig,ed25519_hash")
        assert out["ok"] is True and out["data"] == {}


class TestAppendAchievements:
    """2026-08-26 批次 2 剩余：ach 内联追加提取（L2564/L2646 语义等价）。"""

    def test_appends_new_only(self, tmp_path):
        """已存在的 achievement 不重复追加（幂等）。"""
        p = tmp_path / "state.json"
        _write_state(p, {"achievements": ["a1"],
                         "gate_data": {"pr_number": "1"}})
        cfg = json.dumps({"a1": {"label": "L1", "msg": "M1"},
                          "a2": {"label": "L2", "msg": "M2"}})
        out = gsp.cmd_append_achievements(str(p), '["a1","a2"]', cfg)
        assert out["ok"] is True
        assert [a["id"] for a in out["achievements"]] == ["a2"]
        assert out["achievements"][0]["label"] == "L2"
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["achievements"] == ["a1", "a2"]

    def test_checksum_verifies(self, tmp_path):
        """追加写回后 checksum 可验证（单一事实闭环）。"""
        p = tmp_path / "state.json"
        _write_state(p, {"achievements": [], "gate_data": {"k": 1}})
        gsp.cmd_append_achievements(str(p), '["a1"]', '{"a1":{"label":"x"}}')
        v = gk_state._verify_checksum(str(p))
        assert v["ok"] is True and v["verified"] is True

    def test_empty_unlocked(self, tmp_path):
        p = tmp_path / "state.json"
        _write_state(p, {"achievements": ["a1"]})
        out = gsp.cmd_append_achievements(str(p), "[]", "{}")
        assert out["ok"] is True and out["achievements"] == []

    def test_bad_unlocked_degrades_to_empty(self, tmp_path):
        """unlocked 非法 JSON → 空列表（不崩溃，保守）。"""
        p = tmp_path / "state.json"
        _write_state(p, {"achievements": []})
        out = gsp.cmd_append_achievements(str(p), "not-json", "{}")
        assert out["ok"] is True and out["achievements"] == []


class TestSetTop:
    """`set-top` 顶层键设值（2026-09-23，ECC-089658238011 / ECC-A91DC4562198 修复的**正规通路**）。

    背景：`update-gate-data` 只能写 `gate_data` **内部**；顶层键（如 `worktree`）此前
    **无任何 CLI 通路**可写 ⟹ `apply-worktree` 想改 `state.worktree` 只能绕道，且
    `discover` 是唯一会重写它的命令（但会归档并清空 gate_data）。本子命令补上该通路。
    红先：本类落地时 `gsp.cmd_set_top` 尚不存在（AttributeError）。
    """

    def test_sets_top_level_key(self, tmp_path):
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_set_top(str(p), "worktree", '"/mnt/c/x/wt"')
        assert out["ok"] is True, out
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["worktree"] == "/mnt/c/x/wt"

    def test_written_checksum_verifies(self, tmp_path):
        """写回后 checksum 必须可验证（否则 guard-edit/advance 入口误报 TAMPERED）。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        gsp.cmd_set_top(str(p), "worktree", '"/mnt/c/x/wt"')
        v = gk_state._verify_checksum(str(p))
        assert v["ok"] is True and v["verified"] is True

    def test_non_string_json_value_accepted(self, tmp_path):
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_set_top(str(p), "branch", '"feature/x"')
        assert out["ok"] is True
        assert json.loads(p.read_text(encoding="utf-8"))["branch"] == "feature/x"

    def test_rejects_gate_data_key(self, tmp_path):
        """负臂：顶层 setter **不得**成为绕过 update-gate-data 校验的后门。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_set_top(str(p), "gate_data", '{"best":{}}')
        assert out["ok"] is False
        assert "gate_data" in out["error"]
        # 原 gate_data 未被破坏
        assert json.loads(p.read_text(encoding="utf-8"))["gate_data"]["pr_number"] == "123"

    def test_rejects_underscore_key(self, tmp_path):
        """负臂：`_checksum` 等内部键禁经此写（由 _write_state 单点重算）。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_set_top(str(p), "_checksum", '"deadbeef"')
        assert out["ok"] is False

    def test_rejects_empty_key(self, tmp_path):
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_set_top(str(p), "", '"x"')
        assert out["ok"] is False

    def test_rejects_bad_json_value(self, tmp_path):
        """负臂：非法 JSON 值 → fail-loud，不静默写字符串。"""
        p = tmp_path / "state.json"
        _write_state(p, _base_state())
        out = gsp.cmd_set_top(str(p), "worktree", "not-json")
        assert out["ok"] is False
        assert "value" in out["error"] or "JSON" in out["error"]

    def test_missing_file_reports_error(self, tmp_path):
        out = gsp.cmd_set_top(str(tmp_path / "nope.json"), "worktree", '"/x"')
        assert out["ok"] is False
