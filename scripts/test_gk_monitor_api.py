"""
test_gk_monitor_api.py -- Tests for gk_monitor_api.py
=====================================================
Tests for monitor API with mock API responses.
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


sys.path.insert(0, str(Path(__file__).parent))

from gk_monitor_api import monitor_api, _collect_hard_evidence, _inject_gitnexus, PROVIDERS, FAILOVER_CHAIN


class TestMonitorApiHappyPath:
    """Test happy path scenarios."""
    
    def test_missing_api_key(self):
        """Missing API key returns error."""
        result = monitor_api(stage="STAGE_0", api_key="")
        assert result["ok"] is False
        assert "api-key" in result["error"].lower()
    
    def test_invalid_provider(self, tmp_path):
        """Invalid provider returns error."""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}, "monitor_scores": {}}))
        result = monitor_api(stage="STAGE_0", api_key="test", provider="invalid", state_path=str(state_file))
        assert result["ok"] is False
    
    @patch("gk_monitor_api.requests.post")
    def test_successful_api_call(self, mock_post, tmp_path):
        """Successful API call returns score and verdict."""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}, "monitor_scores": {}}))
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.8,
                "checks": [{"item": "test", "status": "PASS", "score": 0.8}],
                "violations": [],
                "next_action": "proceed",
                "reasoning": "test"
            })}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        
        result = monitor_api(stage="STAGE_0", api_key="test-key", state_path=str(state_file))
        assert result["ok"] is True
        assert result["score"] == 0.8
        assert result["verdict"] == "PASS"
    
    @patch("gk_monitor_api.requests.post")
    def test_score_normalization(self, mock_post, tmp_path):
        """MiMo 0-100 score is normalized to 0-1."""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}, "monitor_scores": {}}))
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 80,
                "checks": [],
                "violations": []
            })}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp
        
        result = monitor_api(stage="STAGE_0", api_key="test-key", state_path=str(state_file))
        assert result["ok"] is True
        assert result["score"] == 0.8  # 80/100 = 0.8


class TestMonitorApiFailover:
    """Test failover chain."""
    
    @patch("gk_monitor_api.requests.post")
    def test_failover_to_second_provider(self, mock_post, tmp_path):
        """Failover to second provider when first fails."""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}, "monitor_scores": {}}))
        
        import requests as req
        mock_fail = MagicMock()
        mock_fail.raise_for_status.side_effect = req.exceptions.Timeout("timeout")
        
        mock_success = MagicMock()
        mock_success.status_code = 200
        mock_success.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.7,
                "checks": [],
                "violations": []
            })}}]
        }
        mock_success.raise_for_status = MagicMock()
        
        # 2026-09-28（H1a 语义对齐）：读超时（`requests.exceptions.Timeout`）与连接类同判 ——
        #   同跳不重试、**立即换跳**（H1a「ms 级切换」）⟹ 首跳只吃 1 次，第 2 次即命中第二跳。
        mock_post.side_effect = [mock_fail, mock_success]
        
        result = monitor_api(stage="STAGE_0", api_key="test-key", state_path=str(state_file))
        assert result["ok"] is True
        assert result["provider"] == "mimo"
        # 强化（对齐 master `dffb6d0` 的 call_count 断言惯例）：首跳 1 次 + 次跳 1 次 = 2 次；
        #   若「同跳重试」回潮，此断言立刻变红（原仅断 ok/provider，掩盖了调用次数语义）。
        assert mock_post.call_count == 2, (
            "读超时应立即换跳（deepseek 1 次 + mimo 1 次），实际 %d 次" % mock_post.call_count)
    
    @patch("gk_monitor_api.requests.post")
    def test_all_providers_fail(self, mock_post, tmp_path):
        """All providers fail returns error."""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}, "monitor_scores": {}}))
        
        import requests as req
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = req.exceptions.Timeout("timeout")
        mock_post.return_value = mock_resp
        
        result = monitor_api(stage="STAGE_0", api_key="test-key", state_path=str(state_file))
        assert result["ok"] is False
        assert "all providers failed" in result["error"]

    @patch("gk_monitor_api.requests.post")
    def test_circuit_breaker_stops_whole_chain(self, mock_post, tmp_path):
        """G5 同族·单侧硬缺陷（2026-09-28）：不可重试错误（如 400）须**停整条降级链**。

        原实现把 `break` 落在**内层** `for retry` ⟹ 只退重试循环，外层 `for fb` 仍换下一个
        provider —— 与 bash `_monitor_api`（`break` 在**外层** failover 循环体内）行为不一致
        ⟹ 一个 400 会被降级链上**每个** provider 各打一遍（放大错误 + 双源语义漂移）。
        判据：400 时 `requests.post` **只被调用 1 次**（链首 provider 的首跳），不触达 mimo。
        """
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}, "monitor_scores": {}}))

        import requests as req
        resp400 = req.models.Response()
        resp400.status_code = 400
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = req.exceptions.HTTPError(response=resp400)
        mock_post.return_value = mock_resp

        result = monitor_api(stage="STAGE_0", api_key="test-key", state_path=str(state_file))
        assert result["ok"] is False
        assert mock_post.call_count == 1, (
            "熔断未停整条链：400（不可重试）仍触达后续 provider（call_count=%d）"
            % mock_post.call_count)

    @patch("gk_monitor_api.requests.post")
    def test_missing_overall_score_not_recorded(self, mock_post, tmp_path):
        """A7（2026-09-06 ㉔）：LLM 返回合法 JSON 但缺 overall_score → 不按哨兵 -1 判 BLOCKED 落盘。

        原实现 `parsed.get("overall_score", -1)` → -1 → BLOCKED 写 monitor_scores + ok:true
        （A7 假否决相邻族真洞）；守卫后走失败链 continue，未落任何记录。
        """
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}, "monitor_scores": {}}))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "checks": [], "violations": [], "next_action": "", "reasoning": "no score"})}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = monitor_api(stage="STAGE_0", api_key="test-key", state_path=str(state_file))
        assert result["ok"] is False
        st = json.loads(state_file.read_text(encoding="utf-8"))
        assert st.get("gate_data", {}).get("monitor_scores", {}).get("STAGE_0") is None
        assert st.get("monitor_scores", {}).get("STAGE_0") is None


class TestMonitorApiRetry:
    """Test retry logic."""
    
    @patch("gk_monitor_api.requests.post")
    def test_retry_on_timeout(self, mock_post, tmp_path):
        """Retry on timeout."""
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"gate_data": {}, "monitor_scores": {}}))
        
        import requests as req
        mock_fail = MagicMock()
        mock_fail.raise_for_status.side_effect = req.exceptions.Timeout()
        
        mock_success = MagicMock()
        mock_success.status_code = 200
        mock_success.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "overall_score": 0.6,
                "checks": [],
                "violations": []
            })}}]
        }
        mock_success.raise_for_status = MagicMock()
        
        mock_post.side_effect = [mock_fail, mock_success]
        
        result = monitor_api(stage="STAGE_0", api_key="test-key", state_path=str(state_file))
        assert result["ok"] is True
        assert result["score"] == 0.6


class TestHardEvidence:
    """Test hard evidence collection."""
    
    def test_no_worktree(self):
        """No worktree returns default evidence."""
        evidence = _collect_hard_evidence("", "", "", "/tmp/test.json")
        assert evidence["commits_ahead"] == 0
        assert evidence["ci_trigger"] == "absent"
        assert evidence["build_exists"] is False
    
    def test_with_worktree(self, tmp_path):
        """With worktree collects evidence."""
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        (worktree / ".github" / "workflows").mkdir(parents=True)
        ci_content = "on:\n  push:\n    branches: [test-branch]\n"
        (worktree / ".github" / "workflows" / "ci.yml").write_text(ci_content)
        
        # _collect_hard_evidence(stage, worktree, branch, state_path)
        evidence = _collect_hard_evidence("STAGE_0", str(worktree), "test-branch", str(tmp_path / "state.json"))
        assert evidence["ci_trigger"] == "present"
        assert evidence["build_exists"] is False
    
    def test_ci_trigger_absent(self, tmp_path):
        """Branch not in ci.yml returns absent."""
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        (worktree / ".github" / "workflows").mkdir(parents=True)
        (worktree / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
        
        evidence = _collect_hard_evidence("STAGE_0", str(worktree), "other-branch", str(tmp_path / "state.json"))
        assert evidence["ci_trigger"] == "absent"


class TestGitNexusInjection:
    """Test GitNexus injection."""
    
    def test_no_gitnexus_data(self, tmp_path):
        """No GitNexus data returns empty string."""
        state_file = tmp_path / "state.json"
        state = {"gate_data": {}}
        state_file.write_text(json.dumps(state))
        
        result = _inject_gitnexus(str(state_file), "", "STAGE_0")
        assert result == ""
    
    def test_with_gitnexus_data(self, tmp_path):
        """With GitNexus data returns baseline."""
        state_file = tmp_path / "state.json"
        state = {
            "gate_data": {
                "gitnexus": {
                    "nodes": "100",
                    "edges": "200",
                    "clusters": "10",
                    "flows": "5",
                    "stage": "STAGE_0",
                    "timestamp": "2026-06-23"
                }
            }
        }
        state_file.write_text(json.dumps(state))
        
        result = _inject_gitnexus(str(state_file), "", "STAGE_0")
        assert "GITNEXUS BASELINE" in result
        assert "100" in result


class TestProviderConfig:
    """Test provider configuration."""
    
    def test_providers_defined(self):
        """Providers are defined."""
        assert "deepseek" in PROVIDERS
        assert "mimo" in PROVIDERS

    def test_mimo_provider_config_not_stale(self):
        """P0 回归锁（2026-09-22）：MiMo **默认**域名/模型名不得回退到已失效值。
        旧默认 api.mimo.ai / mimo-chat = failover 第二跳死；v2.5 系列 2026-10-21 下线。
        2026-10-02：PROVIDERS 支持 env 覆盖 ⟹ 本臂钉**默认值常量**（env 无关）+ 核「无 env 时生效值 = 默认」；
        覆盖行为另由 `test_gk_model_config_swappable.py` 第⑤臂守护。"""
        from gk_monitor_api import _MIMO_BASE_DEFAULT, _MIMO_MODEL_DEFAULT
        assert _MIMO_BASE_DEFAULT == "https://api.xiaomimimo.com/v1"
        assert _MIMO_MODEL_DEFAULT.startswith("mimo-v2.6")
        assert PROVIDERS["mimo"]["base"] == os.environ.get("MIMO_BASE_URL", _MIMO_BASE_DEFAULT)
        assert PROVIDERS["mimo"]["model"] == os.environ.get("GK_MIMO_CRITIC_MODEL", _MIMO_MODEL_DEFAULT)
        assert "reasoning_effort" not in PROVIDERS["mimo"]  # MiMo 不认该参数（payload 仅对 deepseek 注入）
    
    def test_failover_chain(self):
        """Failover chain is defined."""
        assert len(FAILOVER_CHAIN) >= 2
        assert "deepseek" in FAILOVER_CHAIN
