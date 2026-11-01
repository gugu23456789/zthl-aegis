"""
test_gk_adjudicate.py -- Tests for gk_adjudicate.py
====================================================
5 组：
  1. Happy path (PASS verdicts)
  2. Edge case (WARN with concessions)
  3. Error path (missing concessions)
  4. Exception handling (IDLE/DONE state)
  5. rc 契约 / JSON-only（R17 §4.4.4-R9；**修前必红**）—— argparse 失败面须回 JSON 信封

R17-R6（2026-09-28，落刀同批订正）：文件版**去写权** —— state 落盘收归 CLI `_state_write`
单点 ⟹ 原 4 处「读 state 断言」（change_items / constraint_level / blind / checksum）
改为断言**回传体 `result["entry"]`** 或「落盘字节不变」。
"""

import json
import subprocess
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

from gk_adjudicate import adjudicate, score_from_verdicts

SCRIPT = Path(__file__).parent / "gk_adjudicate.py"


class TestAdjudicateHappyPath:
    """Test happy path scenarios."""
    
    def test_all_pass(self, tmp_path):
        """All PASS verdicts, no concessions needed."""
        state_file = tmp_path / "state.json"
        state = {
            "stage": "ECO-EDIT",
            "gate_data": {},
            "monitor_scores": {},
            "history": []
        }
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS", "F2": "PASS"},
            score=0.95,
            decision="All checks passed",
            state_path=str(state_file),
        )
        assert result["ok"] is True
        assert "monitor_score" in result
    
    def test_with_concessions(self, tmp_path):
        """WARN verdicts with concessions provided."""
        state_file = tmp_path / "state.json"
        state = {
            "stage": "ECO-EDIT",
            "gate_data": {},
            "monitor_scores": {},
            "history": []
        }
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS", "F2": "WARN"},
            score=0.8,
            decision="Minor concerns",
            concessions={"F2": "Accepted risk"},
            state_path=str(state_file),
        )
        assert result["ok"] is True
    
    def test_with_sealed_score(self, tmp_path):
        """Cross-validate with sealed agent score."""
        state_file = tmp_path / "state.json"
        state = {
            "stage": "ECO-EDIT",
            "gate_data": {
                "_sealed_agent_score": {"sealed": True, "score": 0.85}
            },
            "monitor_scores": {},
            "history": []
        }
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.9,
            decision="Agrees with agent",
            state_path=str(state_file),
        )
        assert result["ok"] is True
        assert result["divergence"] is not None


class TestAdjudicateEdgeCases:
    """Test edge cases."""
    
    def test_warn_with_empty_concession(self, tmp_path):
        """WARN verdict with empty concession string should fail."""
        state_file = tmp_path / "state.json"
        state = {
            "stage": "ECO-EDIT",
            "gate_data": {},
            "monitor_scores": {},
            "history": []
        }
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS", "F2": "WARN"},
            score=0.8,
            decision="test",
            concessions={"F2": ""},
            state_path=str(state_file),
        )
        assert result["ok"] is False
        assert "missing" in result
    
    def test_divergence_flag_overscore(self, tmp_path):
        """Human score much higher than agent score triggers OVERSCORE."""
        state_file = tmp_path / "state.json"
        state = {
            "stage": "ECO-EDIT",
            "gate_data": {},
            "monitor_scores": {"ECO-EDIT": {"score": 0.5}},
            "history": []
        }
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.9,
            decision="test",
            stage="ECO-EDIT",
            state_path=str(state_file),
        )
        assert result["ok"] is True
        assert result.get("flag") == "HUMAN_OVERSCORE"


class TestAdjudicateErrors:
    """Test error scenarios."""
    
    def test_idle_state_blocked(self, tmp_path):
        """IDLE state blocks adjudicate."""
        state_file = tmp_path / "state.json"
        state = {"stage": "IDLE", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.9,
            state_path=str(state_file),
        )
        assert result["ok"] is False
        assert "IDLE/DONE" in result["error"]
    
    def test_done_state_blocked(self, tmp_path):
        """DONE state blocks adjudicate."""
        state_file = tmp_path / "state.json"
        state = {"stage": "DONE", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.9,
            state_path=str(state_file),
        )
        assert result["ok"] is False
        assert "IDLE/DONE" in result["error"]
    
    def test_invalid_score_range(self, tmp_path):
        """Score outside 0.0-1.0 range fails."""
        state_file = tmp_path / "state.json"
        state = {"stage": "ECO-EDIT", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=1.5,
            state_path=str(state_file),
        )
        assert result["ok"] is False
        assert "score" in result["error"]
    
    def test_missing_concessions(self, tmp_path):
        """WARN verdicts without concessions fails."""
        state_file = tmp_path / "state.json"
        state = {"stage": "ECO-EDIT", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS", "F2": "WARN", "F3": "BLOCKED"},
            score=0.7,
            state_path=str(state_file),
        )
        assert result["ok"] is False
        assert "missing" in result
        assert len(result["missing"]) == 2


class TestAdjudicateBoundaries:
    """Test boundary conditions."""
    
    def test_score_zero(self, tmp_path):
        """Score 0.0 is valid."""
        state_file = tmp_path / "state.json"
        state = {"stage": "ECO-EDIT", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.0,
            state_path=str(state_file),
        )
        assert result["ok"] is True
    
    def test_score_one(self, tmp_path):
        """Score 1.0 is valid."""
        state_file = tmp_path / "state.json"
        state = {"stage": "ECO-EDIT", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=1.0,
            state_path=str(state_file),
        )
        assert result["ok"] is True
    
    def test_score_negative(self, tmp_path):
        """Score < 0.0 fails."""
        state_file = tmp_path / "state.json"
        state = {"stage": "ECO-EDIT", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=-0.1,
            state_path=str(state_file),
        )
        assert result["ok"] is False
    
    def test_divergence_underscore(self, tmp_path):
        """Human score much lower than agent score triggers UNDERSCORE."""
        state_file = tmp_path / "state.json"
        state = {
            "stage": "ECO-EDIT",
            "gate_data": {},
            "monitor_scores": {"ECO-EDIT": {"score": 0.9}},
            "history": []
        }
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.5,
            decision="test",
            stage="ECO-EDIT",
            state_path=str(state_file),
        )
        assert result["ok"] is True
        assert result.get("flag") == "HUMAN_UNDERSCORE"
    
    def test_divergence_boundary(self, tmp_path):
        """Divergence exactly 0.2 does not trigger flag."""
        state_file = tmp_path / "state.json"
        state = {
            "stage": "ECO-EDIT",
            "gate_data": {},
            "monitor_scores": {"ECO-EDIT": {"score": 0.8}},
            "history": []
        }
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=1.0,  # divergence = 0.2
            decision="test",
            stage="ECO-EDIT",
            state_path=str(state_file),
        )
        assert result["ok"] is True
        assert result.get("flag") is None  # 0.2 is not > 0.2
    
    def test_change_items(self, tmp_path):
        """Change items > 0 is recorded."""
        state_file = tmp_path / "state.json"
        state = {"stage": "ECO-EDIT", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.9,
            change_items=5,
            state_path=str(state_file),
        )
        assert result["ok"] is True
        # R17-R6（2026-09-28）：文件版**不写** state ⟹ change_items 经 `entry` 回传，由 CLI 落盘
        assert result["entry"]["change_items"] == 5
    
    def test_constraint_level(self, tmp_path):
        """Constraint level is recorded."""
        state_file = tmp_path / "state.json"
        state = {"stage": "ECO-EDIT", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.9,
            constraint_level="H1",
            state_path=str(state_file),
        )
        assert result["ok"] is True
        # R17-R6：同上 —— 断言回传体而非落盘体
        assert result["entry"]["constraint_level"] == "H1"
    
    def test_blind_mode(self, tmp_path):
        """Blind mode is recorded."""
        state_file = tmp_path / "state.json"
        state = {"stage": "ECO-EDIT", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        
        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.9,
            blind=True,
            state_path=str(state_file),
        )
        assert result["ok"] is True
        # R17-R6：同上 —— 断言回传体而非落盘体
        assert result["entry"]["blind"] is True
    
    def test_no_state_write_by_file_version(self, tmp_path):
        """R17-R6：文件版生产路径**零 state 写**（写盘收归 CLI `_state_write` 单点）。

        原 `test_checksum_updated`（断言 `_checksum` 变化）在去写权后语义失效 ——
        checksum 现由 CLI 落盘时重算，本文件只读 ⟹ 断言落盘 mtime + 字节**不变**。
        """
        state_file = tmp_path / "state.json"
        state = {"stage": "ECO-EDIT", "gate_data": {}, "history": []}
        with open(state_file, "w") as f:
            json.dump(state, f)
        before = (state_file.stat().st_mtime_ns, state_file.read_bytes())

        result = adjudicate(
            verdicts={"F1": "PASS"},
            score=0.9,
            state_path=str(state_file),
        )

        assert result["ok"] is True
        assert "entry" in result, "文件版须回传 entry（R17-R6 entry 传输契约）"
        after = (state_file.stat().st_mtime_ns, state_file.read_bytes())
        assert after == before, "文件版仍写 state ⟹ 去写权未落"


# ── R17 §4.4.4-R9：rc 契约 / JSON-only（**红先 = 修前必红**）──────────────────
#
# 病象（实测）：`--verdicts required=True` ⟹ 缺参走 `ArgumentParser.error()` ⟹
#   rc=2 + **stderr usage** 且 **stdout 无 JSON** ⟹ 破坏「Agent ↔ CLI JSON-only」契约。
# 目标契约（§4.4.4-R9 表）—— argparse 三类失败面**一律 rc + JSON 信封**：
#   缺必填参     → rc1（**保真**内联 A5 的 rc1+JSON，见 oracle O3）
#   未知 flag    → rc2（**行为变更**：内联 A3 为 `*) break` 静默吞 rc0，见 oracle O4）
#   类型/范围错  → rc2（**行为变更**：内联 A5 仅判 `-z` 空值，无类型校验）


def _run_adj(args: list, tmp_path) -> subprocess.CompletedProcess:
    """以子进程跑真实 CLI 面（argparse 契约只在进程边界可观测）。

    **一律显式 `--path <tmp>`** —— 否则缺省 `DEFAULT_STATE_FILE` 会落到生产 state。
    """
    state = tmp_path / "rc.state.json"
    state.write_text(json.dumps({"stage": "STAGE_1", "gate_data": {},
                                 "monitor_scores": {}, "history": []},
                                ensure_ascii=False), encoding="utf-8")
    return subprocess.run([sys.executable, str(SCRIPT), *args, "--path", str(state)],
                          capture_output=True, text=True, timeout=120)


def _assert_json_envelope(r: subprocess.CompletedProcess, expect_rc: int) -> dict:
    assert r.returncode == expect_rc, (
        f"rc 应为 {expect_rc}，实得 {r.returncode}"
        f"（stdout={r.stdout[:160]!r} stderr={r.stderr[:160]!r}）")
    assert r.stdout.strip(), f"stdout 无 JSON（stderr={r.stderr[:160]!r}）"
    try:
        d = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise AssertionError(f"stdout 非 JSON（{e}）：{r.stdout[:200]!r}")
    assert d.get("ok") is False, f"信封 ok 应为 false：{d}"
    return d


class TestAdjudicateRcContract:
    """§4.4.4-R9：argparse 失败面必须回 JSON 信封（臂1-4 修前必红）。

    臂6（`..._containing_required_...`）为 **rc 结构判据臂**：修前 rc 误判（散串判据）。
    """

    def test_missing_required_gives_rc1_json(self, tmp_path):
        """缺 --verdicts ⟹ rc1 + JSON（保真内联 A5 / oracle O3）。修前：rc2 且无 JSON。"""
        d = _assert_json_envelope(_run_adj(["--score", "0.5"], tmp_path), 1)
        assert "required" in d["error"], d
        assert d["kind"] == "argparse", d

    def test_unknown_flag_gives_rc2_json(self, tmp_path):
        """未知 flag ⟹ rc2 + JSON（行为变更：内联 A3 静默吞 rc0 / oracle O4）。修前：rc2 且无 JSON。"""
        r = _run_adj(["--verdicts", '{"F1":"PASS"}', "--score", "0.5", "--nope", "x"], tmp_path)
        d = _assert_json_envelope(r, 2)
        assert "unrecognized" in d["error"], d

    def test_non_numeric_score_gives_rc2_json(self, tmp_path):
        """--score 非数值 ⟹ rc2 + JSON。修前：rc2 且无 JSON。"""
        r = _run_adj(["--verdicts", '{"F1":"PASS"}', "--score", "abc"], tmp_path)
        d = _assert_json_envelope(r, 2)
        assert "--score" in d["error"], d

    def test_out_of_range_score_gives_rc2_json(self, tmp_path):
        """--score 越界 ⟹ rc2 + JSON（行为变更：内联无校验）。修前：rc1 + JSON（走 adjudicate 内校验）。"""
        r = _run_adj(["--verdicts", '{"F1":"PASS"}', "--score", "1.5"], tmp_path)
        d = _assert_json_envelope(r, 2)
        assert "0.0-1.0" in d["error"], d

    def test_control_happy_path_still_rc0_json(self, tmp_path):
        """对照（修前也绿）：正常路径仍 rc0 + JSON `ok:true`（防"把成功也改成失败"）。"""
        r = _run_adj(["--verdicts", '{"F1":"PASS"}', "--score", "0.5"], tmp_path)
        assert r.returncode == 0, (
            f"rc={r.returncode} stdout={r.stdout[:160]!r} stderr={r.stderr[:200]!r}")
        assert json.loads(r.stdout).get("ok") is True

    def test_score_value_containing_required_gives_rc2_json(self, tmp_path):
        """**rc 结构判据臂**（ECC-8C29EDF15C74）：`--score required` 是**类型错** ⟹ rc2。

        `_score_in_0_1("required")` 抛 ArgumentTypeError ⟹ argparse 报文为
        `argument --score: invalid float value: 'required'`。原散串判据 `"required" in message`
        命中 ⟹ **误判 rc1**（把类型错当缺必填参）。改前缀锚后须 rc2。
        修前实测：rc=1（错）；修后：rc=2。
        """
        r = _run_adj(["--verdicts", '{"F1":"PASS"}', "--score", "required"], tmp_path)
        d = _assert_json_envelope(r, 2)
        assert "--score" in d["error"], d


def test_score_from_verdicts_excludes_abstain():
    assert score_from_verdicts({"F1": "PASS", "F2": "FAIL", "F3": "ABSTAIN"}) == 0.6


def test_score_from_verdicts_zero_abstain():
    assert score_from_verdicts(
        {"F1": "PASS", "F2": "FAIL", "F3": "ABSTAIN"}, abstain="zero") == 0.4
