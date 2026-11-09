"""
test_gk_appeal.py -- Tests for gk_appeal.py
=============================================
Tests for appeal logic with mock API responses.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def _read_state(path):
    """WAL-aware 读（`appeal` 经 `update_state` 落 WAL，裸读 checkpoint 会滞后）。"""
    import gk_json_utils as gju
    return gju.read_state_file(str(path))


sys.path.insert(0, str(Path(__file__).parent))

from gk_appeal import appeal, _detect_foreign_content, _build_mediation_context, _collect_hard_evidence


class TestForeignContentGuard:
    """Test D3 foreign content guard (2 layers)."""
    
    def test_clean_notes(self):
        """Clean notes pass."""
        assert _detect_foreign_content("normal appeal notes") == "clean"
    
    def test_foreign_user_path(self):
        """Foreign user path detected."""
        result = _detect_foreign_content("<home>\\file.txt")
        assert "foreign_user" in result
        assert "otheruser" in result
    
    def test_foreign_user_mnt(self):
        """Foreign user path via /mnt/c detected."""
        result = _detect_foreign_content("<home>/file.txt")
        assert "foreign_user" in result
    
    def test_own_user_path(self):
        """Own user path passes.

        P2c（2026-10-31）：own 不再取 `USER`（WSL 恒 root）——必须用单源解析出的真实用户名；
        否则 `<home>` 本就不是本机用户根（原测试锁的是旧缺陷语义）。
        """
        import gk_foreign_content as fc
        own = fc.resolve_own_user()
        assert own, "本机用户解析失败（前置不成立）"
        result = _detect_foreign_content(f"C:\\Users\\{own}\\file.txt")
        assert result == "clean"
    
    def test_leakage_marker_xhs(self):
        """XHS copilot marker detected."""
        result = _detect_foreign_content("xhs-copilot injected content")
        assert "leakage_marker" in result
        assert "xhs-copilot" in result
    
    def test_leakage_marker_xiaohongshu(self):
        """Xiaohongshu marker detected."""
        result = _detect_foreign_content("xiaohongshu content")
        assert "leakage_marker" in result
    
    def test_leakage_marker_chinese(self):
        """Chinese marker detected."""
        result = _detect_foreign_content("小红书 content")
        assert "leakage_marker" in result
    
    def test_public_user_path(self):
        """Public user path passes."""
        result = _detect_foreign_content("<home>\\file.txt")
        assert result == "clean"


class TestMediationContext:
    """Test mediation context building."""
    
    def test_empty_state(self):
        """Empty state returns N/A values."""
        ctx = _build_mediation_context({})
        assert ctx["agent_score"] == "N/A"
        assert ctx["human_score"] == "N/A"
    
    def test_with_sealed_score(self):
        """With sealed score returns agent score."""
        state = {
            "gate_data": {
                "_sealed_agent_score": {"score": 0.8, "verdicts": {"F1": "PASS"}},
                "human_calibration_log": [{"human_score": 0.7, "divergence": 0.1}]
            }
        }
        ctx = _build_mediation_context(state)
        assert ctx["agent_score"] == 0.8
        assert ctx["human_score"] == 0.7
        assert ctx["divergence"] == 0.1


class TestHardEvidence:
    """Test hard evidence collection."""
    
    def test_no_worktree(self):
        """No worktree returns default evidence."""
        evidence = _collect_hard_evidence("", "")
        assert evidence["commits_ahead"] == 0
        assert evidence["ci_trigger"] == "absent"
        assert evidence["build_exists"] is False


class TestAppealHappyPath:
    """Test happy path scenarios."""
    
    def test_missing_gate(self, tmp_path):
        """Missing gate returns error."""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}}))
        result = appeal(gate="", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is False
    
    def test_foreign_content_blocked(self, tmp_path):
        """Foreign content is blocked (隔离 state，不依赖真实默认 .gatekeeper.state)。"""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}}))
        result = appeal(gate="ECO-AUDIT", notes="xhs-copilot injected", api_key="test",
                        state_path=str(state_file))
        assert result["ok"] is False
        assert "FOREIGN_CONTENT_DETECTED" in result["error"]
    
    def test_appeal_denied_permanently(self, tmp_path):
        """Appeal denied permanently blocks."""
        state_file = tmp_path / "state.json"
        state = {"appeal_denied_gates": ["ECO-AUDIT"], "gate_data": {}}
        state_file.write_text(json.dumps(state))
        
        result = appeal(gate="ECO-AUDIT", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is False
        assert "APPEAL_DENIED_PERMANENTLY" in result["error"]
    
    def test_already_appealed(self, tmp_path):
        """Already appealed blocks."""
        state_file = tmp_path / "state.json"
        state = {"appeal_records": {"ECO-AUDIT": {"verdict": "DENIED"}}, "gate_data": {}}
        state_file.write_text(json.dumps(state))
        
        result = appeal(gate="ECO-AUDIT", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is False
        assert "ALREADY_APPEALED" in result["error"]


class TestAppealApiCall:
    """Test API call scenarios."""
    
    @patch("gk_appeal.requests.post")
    def test_successful_appeal(self, mock_post, tmp_path):
        """Successful appeal records result."""
        state_file = tmp_path / "state.json"
        state = {"gate_data": {}, "appeal_records": {}}
        state_file.write_text(json.dumps(state))
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.7,
                "appeal_impact": "approved with conditions",
                "checks": []
            })}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        
        result = appeal(gate="ECO-AUDIT", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is True
        assert result["appeal_verdict"] == "APPROVED"
        assert result["appeal_score"] == 0.7

    @patch("gk_appeal.requests.post")
    def test_explicit_base_model_used(self, mock_post, tmp_path):
        """bashpy 薄壳契约：--base/--model 显式传入 → 请求 URL/模型对齐（防未 export env 丢失）。"""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}}))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.6, "appeal_impact": "ok", "checks": []})}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        appeal(gate="ECO-AUDIT", notes="test", api_key="k", state_path=str(state_file),
               base="https://api.xiaomimimo.com/v1", model="mimo")
        url = mock_post.call_args[0][0]
        body = mock_post.call_args[1]["json"]
        assert url == "https://api.xiaomimimo.com/v1/chat/completions"
        assert body["model"] == "mimo"

    @patch("gk_appeal.requests.post")
    def test_default_deepseek_when_no_config(self, mock_post, tmp_path, monkeypatch):
        """无 base/model/API_BASE/API_MODEL → deepseek 默认端点与模型（legacy bash 语义）。"""
        monkeypatch.delenv("API_BASE", raising=False)
        monkeypatch.delenv("API_MODEL", raising=False)
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}}))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.6, "appeal_impact": "ok", "checks": []})}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        appeal(gate="ECO-AUDIT", notes="test", api_key="k", state_path=str(state_file))
        url = mock_post.call_args[0][0]
        body = mock_post.call_args[1]["json"]
        assert url == "https://api.deepseek.com/v1/chat/completions"
        assert body["model"] == "deepseek-flash"
    
    @patch("gk_appeal.requests.post")
    def test_denied_appeal_records_denied_gates(self, mock_post, tmp_path):
        """Denied appeal writes to appeal_denied_gates."""
        state_file = tmp_path / "state.json"
        state = {"gate_data": {}, "appeal_records": {}}
        state_file.write_text(json.dumps(state))
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.3,
                "appeal_impact": "denied",
                "checks": []
            })}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        
        result = appeal(gate="ECO-AUDIT", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is True
        assert result["appeal_verdict"] == "DENIED"
        
        # Verify appeal_denied_gates was written
        state = _read_state(state_file)
        assert "ECO-AUDIT" in state.get("appeal_denied_gates", [])
    
    @patch("gk_appeal.requests.post")
    def test_approved_clears_appeal_required(self, mock_post, tmp_path):
        """Approved appeal clears appeal_required."""
        state_file = tmp_path / "state.json"
        state = {"gate_data": {"appeal_required": "ECO-AUDIT"}, "appeal_records": {}}
        state_file.write_text(json.dumps(state))
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.8,
                "appeal_impact": "approved",
                "checks": []
            })}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        
        result = appeal(gate="ECO-AUDIT", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is True
        
        # Verify appeal_required was cleared
        state = _read_state(state_file)
        assert "appeal_required" not in state.get("gate_data", {})

    @patch("gk_appeal.requests.post")
    def test_approved_clears_only_matching_gate(self, mock_post, tmp_path):
        """X1（2026-10-31）：APPROVED 只清**本 gate**的阻断源，不越权清其它源。"""
        state_file = tmp_path / "state.json"
        state = {
            "gate_data": {
                "appeal_required": "STAGE_3",
                "appeal_entropy_at_block": 0.6,
                "appeal_blocks": {
                    "entropy": {"gate": "STAGE_3", "entropy_rate": 0.6},
                    "credit": {"gate": "ECO-AUDIT", "score": 3},
                },
            },
            "appeal_records": {},
        }
        state_file.write_text(json.dumps(state))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.8,
                "appeal_impact": "approved",
                "checks": []
            })}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = appeal(gate="ECO-AUDIT", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is True

        state = _read_state(state_file)
        gd = state["gate_data"]
        assert set(gd["appeal_blocks"]) == {"entropy"}      # credit 源已清
        assert gd["appeal_required"] == "STAGE_3"           # 熵源镜像保留
        assert gd.get("appeal_entropy_at_block") == 0.6, gd


class TestAppealErrorCodeSafetyNet:
    """A7（2026-09-05）错误码安全网：schema 漂移/env 故障不得误烧永久否决。"""

    @patch("gk_appeal.requests.post")
    def test_invalid_response_missing_score_not_recorded(self, mock_post, tmp_path):
        """裁判输出缺 overall_score → APPEAL_RESPONSE_INVALID，不落任何记录（原按哨兵 -1 判 DENIED 烧死）。"""
        state_file = tmp_path / "state.json"
        state = {"gate_data": {}, "appeal_records": {}}
        state_file.write_text(json.dumps(state))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "appeal_impact": "drifted payload",
                "checks": []
            })}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = appeal(gate="ECO-AUDIT", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is False
        assert result["error"] == "APPEAL_RESPONSE_INVALID"
        st = _read_state(state_file)
        assert st.get("appeal_denied_gates", []) == []
        assert st.get("appeal_records", {}) == {}

    @patch("gk_appeal.requests.post")
    def test_sentinel_denied_repaired_then_retry_allowed(self, mock_post, tmp_path):
        """score==-1 的粘死否决被迁移清除（审计 appeal_repair_log）→ 可重跑并 APPROVED。"""
        state_file = tmp_path / "state.json"
        state = {
            "appeal_denied_gates": ["ECO-AUDIT"],
            "appeal_records": {"ECO-AUDIT": {"verdict": "DENIED", "score": -1}},
            "gate_data": {},
        }
        state_file.write_text(json.dumps(state))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.8, "appeal_impact": "approved", "checks": []
            })}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = appeal(gate="ECO-AUDIT", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is True
        assert result["appeal_verdict"] == "APPROVED"
        st = _read_state(state_file)
        assert "ECO-AUDIT" not in st.get("appeal_denied_gates", [])
        log = st.get("gate_data", {}).get("appeal_repair_log", [])
        assert log and log[-1]["reason"] == "sentinel_denied_repaired"

    def test_real_denied_not_repaired(self, tmp_path):
        """score∈[0,1] 的真实 DENIED 不受迁移影响（仍永久）。"""
        from gk_appeal import appeal as _a
        state_file = tmp_path / "state.json"
        state = {
            "appeal_denied_gates": ["ECO-AUDIT"],
            "appeal_records": {"ECO-AUDIT": {"verdict": "DENIED", "score": 0.3}},
            "gate_data": {},
        }
        state_file.write_text(json.dumps(state))
        result = _a(gate="ECO-AUDIT", notes="test", api_key="test", state_path=str(state_file))
        assert result["ok"] is False
        assert "APPEAL_DENIED_PERMANENTLY" in result["error"]
        st = _read_state(state_file)
        assert "ECO-AUDIT" in st.get("appeal_denied_gates", [])
        assert st.get("gate_data", {}).get("appeal_repair_log", []) == []


class TestAppealTransitionCatch22:
    """F-REV-9 C1（2026-09-08）：appeal 判据 = 进入判据（transition），完成态 schema 降级背景。

    回归 Catch-22：appeal 不得要求"尚未进入的 gate 的完成证据"（不进 STAGE_4 则永不产生
    merge 证据 → 曾必然驳回死锁）。跨阶段被拒（advance 场景）→ 主判据 = gk_advance
    _structural_gates 的 transition 核验；gate 内 monitor 拒 / standing / 无 current_stage
    → 保持原完成态 schema 判据（行为不变）。
    """

    def _state(self):
        return {
            "stage": "STAGE_3", "r_phase": "R1", "branch": "feat/f9",
            "worktree": "", "gate_data": {"sprint_contract": "scope+dim+fail+pass"},
            "appeal_records": {},
        }

    def _mock_ok(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.8, "appeal_impact": "approved", "checks": []})}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

    @patch("gk_appeal.requests.post")
    def test_cross_stage_injects_entry_criteria(self, mock_post, tmp_path):
        """STAGE_3 内被拒后 appeal STAGE_4 → judge 收到进入判据核验（transition），非完成态 requires。"""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(self._state()))
        self._mock_ok(mock_post)
        result = appeal(gate="STAGE_4", notes="appeal advance denial", api_key="k",
                        state_path=str(state_file), current_stage="STAGE_3",
                        env_json='{"plan_backup_exists":true}')
        assert result["ok"] is True
        body = mock_post.call_args[1]["json"]
        user = body["messages"][1]["content"]
        assert "进入判据核验" in user
        assert '"transition": "STAGE_3→STAGE_4"' in user
        assert '"all_ok": true' in user
        assert "完成态 schema（背景参考" in user  # completion 降级为背景（信息透明），不再当主判据
        sys_msg = body["messages"][0]["content"]
        assert "ENTRY criteria" in sys_msg
        assert "Catch-22 anti-pattern" in sys_msg

    @patch("gk_appeal.requests.post")
    def test_gate_internal_monitor_keeps_completion(self, mock_post, tmp_path):
        """gate==current（gate 内 monitor 裁定被申诉）→ 保持原完成态判据（transition 不注入）。"""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(self._state()))
        self._mock_ok(mock_post)
        result = appeal(gate="STAGE_4", notes="monitor ruling wrong", api_key="k",
                        state_path=str(state_file), current_stage="STAGE_4")
        assert result["ok"] is True
        user = mock_post.call_args[1]["json"]["messages"][1]["content"]
        assert "进入判据核验" not in user
        assert "门禁 schema（gate 内 monitor/裁定判据）" in user

    @patch("gk_appeal.requests.post")
    def test_missing_env_conservative_fail_not_deadlock(self, mock_post, tmp_path):
        """env 缺 plan_backup_exists → transition 保守 FAIL 仍注入给 judge（判据可见可裁，非死锁）。"""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(self._state()))
        self._mock_ok(mock_post)
        result = appeal(gate="STAGE_4", notes="n", api_key="k", state_path=str(state_file),
                        current_stage="STAGE_3", env_json="{}")
        assert result["ok"] is True
        user = mock_post.call_args[1]["json"]["messages"][1]["content"]
        assert "进入判据核验" in user
        assert '"all_ok": false' in user or '"all_ok": False' in user

    @patch("gk_appeal.requests.post")
    def test_no_current_stage_falls_back(self, mock_post, tmp_path):
        """无 current_stage（legacy 调用形态）→ 原完成态 schema 判据，不报错。"""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(self._state()))
        self._mock_ok(mock_post)
        result = appeal(gate="STAGE_4", notes="n", api_key="k", state_path=str(state_file))
        assert result["ok"] is True
        user = mock_post.call_args[1]["json"]["messages"][1]["content"]
        assert "进入判据核验" not in user
        assert "门禁 schema（gate 内 monitor/裁定判据）" in user
