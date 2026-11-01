"""
test_gk_self_check.py -- Tests for gk_self_check.py
===================================================
4 scenarios per check:
  1. Happy path (normal operation)
  2. Edge case (boundary conditions)
  3. Error path (invalid input)
  4. Exception handling (missing file, etc.)
"""

import hashlib
import json
import os
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))




class TestHookRegistrationCheck:
    """2026-10-31：self-check 缺 hooks.json **注册态** 观测（原只查 wrapper 可执行）。

    判据（与 `gk_hook_manage.py status --json` 的 source 同源）：
      registered ⟹ PASS；absent/foreign ⟹ WARN（未安装/被他人条目占用）；
      unparseable ⟹ FAIL（hook 面整体不可加载）；工具缺失 ⟹ SKIP。
    """

    def _fake_tool(self, tmp_path, payload):
        s = tmp_path / "scripts"
        s.mkdir()
        (s / "gk_hook_manage.py").write_text(
            "import json\nprint(json.dumps(%r))\n" % payload, encoding="utf-8")
        return tmp_path

    def test_registered_pass(self, tmp_path):
        from gk_self_check import check_hook_registration
        d = self._fake_tool(tmp_path, {"source": "registered", "ours": 1,
                                       "foreign": 0, "command_ok": True})
        r = check_hook_registration(str(d))
        assert r["check"] == "hook_registration"
        assert r["status"] == "PASS", r

    def test_absent_warn(self, tmp_path):
        from gk_self_check import check_hook_registration
        d = self._fake_tool(tmp_path, {"source": "absent", "ours": 0, "foreign": 0})
        assert check_hook_registration(str(d))["status"] == "WARN"

    def test_foreign_warn(self, tmp_path):
        from gk_self_check import check_hook_registration
        d = self._fake_tool(tmp_path, {"source": "foreign", "ours": 0, "foreign": 2})
        assert check_hook_registration(str(d))["status"] == "WARN"

    def test_unparseable_fail(self, tmp_path):
        from gk_self_check import check_hook_registration
        d = self._fake_tool(tmp_path, {"source": "unparseable", "ours": 0, "foreign": 0})
        assert check_hook_registration(str(d))["status"] == "FAIL"

    def test_tool_missing_skip(self, tmp_path):
        from gk_self_check import check_hook_registration
        assert check_hook_registration(str(tmp_path))["status"] == "SKIP"


class TestGitnexusVersionCheck:
    """2026-10-31：self-check 缺 gitnexus **版本/耗时** 观测（原只跑 status 看首行）。"""

    def test_semver_parse(self):
        from gk_self_check import _parse_semver
        assert _parse_semver("gitnexus v1.6.10 (build)") == (1, 6, 10)
        assert _parse_semver("no version here") is None

    def test_verdict_old_version_warn(self):
        from gk_self_check import _gitnexus_verdict
        status, detail = _gitnexus_verdict((1, 5, 9), 100, 5000)
        assert status == "WARN" and "1.6.0" in detail

    def test_verdict_slow_warn(self):
        from gk_self_check import _gitnexus_verdict
        status, detail = _gitnexus_verdict((1, 6, 10), 9000, 5000)
        assert status == "WARN" and "9000" in detail

    def test_verdict_ok_pass(self):
        from gk_self_check import _gitnexus_verdict
        assert _gitnexus_verdict((1, 6, 10), 1200, 5000)[0] == "PASS"

    def test_missing_runner_skip(self, tmp_path, monkeypatch):
        from gk_self_check import check_gitnexus_version
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        assert check_gitnexus_version(str(tmp_path))["status"] == "SKIP"


class TestModelConfigCheck:
    """2026-10-31：self-check 缺**模型/env 取值合法性**校验（原只看 key 是否存在）。"""

    _KEYS = ("GK_ACTOR_MODEL", "GK_CRITIC_MODEL", "GK_MIMO_ACTOR_MODEL",
             "GK_MIMO_CRITIC_MODEL", "GK_REASONING_EFFORT", "GK_FAILOVER_CHAIN",
             "DEEPSEEK_BASE_URL", "MIMO_BASE_URL")

    def _clear(self, monkeypatch):
        for k in self._KEYS:
            monkeypatch.delenv(k, raising=False)

    def test_defaults_pass(self, monkeypatch):
        from gk_self_check import check_model_config
        self._clear(monkeypatch)
        r = check_model_config()
        assert r["check"] == "model_config"
        assert r["status"] == "PASS", r

    def test_bad_effort_warn(self, monkeypatch):
        from gk_self_check import check_model_config
        self._clear(monkeypatch)
        monkeypatch.setenv("GK_REASONING_EFFORT", "ultra")
        assert check_model_config()["status"] == "WARN"

    def test_bad_failover_chain_warn(self, monkeypatch):
        from gk_self_check import check_model_config
        self._clear(monkeypatch)
        monkeypatch.setenv("GK_FAILOVER_CHAIN", "deepseek,unknown")
        assert check_model_config()["status"] == "WARN"

    def test_model_id_with_space_warn(self, monkeypatch):
        from gk_self_check import check_model_config
        self._clear(monkeypatch)
        monkeypatch.setenv("GK_CRITIC_MODEL", "deep seek")
        assert check_model_config()["status"] == "WARN"

    def test_base_url_without_scheme_warn(self, monkeypatch):
        from gk_self_check import check_model_config
        self._clear(monkeypatch)
        monkeypatch.setenv("DEEPSEEK_BASE_URL", "api.deepseek.com")
        assert check_model_config()["status"] == "WARN"


class TestSandboxCheck:
    """2026-10-31：层 1 沙箱生效态（包装器缺失 ⟹ FAIL；显式关闭 ⟹ WARN）。"""

    def _mk(self, tmp_path, wrapper=True, probe_rc=0):
        s = tmp_path / "scripts"
        s.mkdir()
        if wrapper:
            w = s / "suagent_sandbox.sh"
            w.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            w.chmod(0o755)
        (s / "gk_sandbox.py").write_text(
            "import sys; sys.exit(%d)\n" % probe_rc, encoding="utf-8")
        return tmp_path

    def test_explicit_off_warn(self, tmp_path, monkeypatch):
        from gk_self_check import check_sandbox
        monkeypatch.setenv("GK_SANDBOX_SUBAGENT", "0")
        d = self._mk(tmp_path)
        assert check_sandbox(str(d))["status"] == "WARN"

    def test_missing_wrapper_fail(self, tmp_path, monkeypatch):
        from gk_self_check import check_sandbox
        monkeypatch.delenv("GK_SANDBOX_SUBAGENT", raising=False)
        d = self._mk(tmp_path, wrapper=False)
        assert check_sandbox(str(d))["status"] == "FAIL"

    def test_probe_failure_warn(self, tmp_path, monkeypatch):
        from gk_self_check import check_sandbox
        monkeypatch.delenv("GK_SANDBOX_SUBAGENT", raising=False)
        d = self._mk(tmp_path, probe_rc=1)
        assert check_sandbox(str(d))["status"] == "WARN"

    def test_probe_ok_pass(self, tmp_path, monkeypatch):
        from gk_self_check import check_sandbox
        monkeypatch.delenv("GK_SANDBOX_SUBAGENT", raising=False)
        d = self._mk(tmp_path)
        r = check_sandbox(str(d))
        assert r["status"] == "PASS", r
        assert r["mode"] == "limits"

    def test_bwrap_mode_without_binary_fail(self, tmp_path, monkeypatch):
        from gk_self_check import check_sandbox
        monkeypatch.delenv("GK_SANDBOX_SUBAGENT", raising=False)
        monkeypatch.setenv("GK_SANDBOX_MODE", "bwrap")
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        d = self._mk(tmp_path)
        assert check_sandbox(str(d))["status"] == "FAIL"


class TestCronHealthCheck:
    """2026-11-01：tick 停摆/作业逾期（cron_tick.bat 的 `cd ~` 根因）必须可观测。"""

    NOW = 1_800_000_000

    def _mk(self, tmp_path, monkeypatch, next_offset, tick_age=60, enabled=True):
        import datetime
        cron = tmp_path / ".gatekeeper" / "cron"
        cron.mkdir(parents=True)
        nr = datetime.datetime.fromtimestamp(
            self.NOW + next_offset, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        (cron / "jobs.json").write_text(json.dumps(
            [{"name": "audit-daily", "enabled": enabled, "next_run_at": nr}]),
            encoding="utf-8")
        t = cron / "tick.log"
        t.write_text("x", encoding="utf-8")
        os.utime(t, (self.NOW - tick_age, self.NOW - tick_age))
        monkeypatch.setenv("HOME", str(tmp_path))

    def test_fresh_pass(self, tmp_path, monkeypatch):
        from gk_self_check import check_cron_health
        self._mk(tmp_path, monkeypatch, next_offset=1800)
        assert check_cron_health(now_ts=self.NOW)["status"] == "PASS"

    def test_stale_tick_warn(self, tmp_path, monkeypatch):
        from gk_self_check import check_cron_health
        self._mk(tmp_path, monkeypatch, next_offset=1800, tick_age=3 * 3600)
        assert check_cron_health(now_ts=self.NOW)["status"] == "WARN"

    def test_overdue_job_warn(self, tmp_path, monkeypatch):
        from gk_self_check import check_cron_health
        self._mk(tmp_path, monkeypatch, next_offset=-7200)
        r = check_cron_health(now_ts=self.NOW)
        assert r["status"] == "WARN"
        assert "audit-daily" in r["detail"]

    def test_missing_jobs_skip(self, tmp_path, monkeypatch):
        from gk_self_check import check_cron_health
        monkeypatch.setenv("HOME", str(tmp_path))
        assert check_cron_health(now_ts=self.NOW)["status"] == "SKIP"


class TestStateFileCheck:
    """Test check_state_file — state file existence + JSON validity."""

    def test_happy_path(self, tmp_state):
        """Valid state file with 'stage' field returns PASS."""
        from gk_self_check import check_state_file
        result = check_state_file(tmp_state)
        assert result["check"] == "state_file"
        assert result["status"] == "PASS"

    def test_missing_stage_field(self, tmp_path):
        """State file without 'stage' field returns FAIL."""
        from gk_self_check import check_state_file
        bad_file = tmp_path / "no_stage.json"
        bad_file.write_text('{"r_phase": "ECO-SCAN"}', encoding="utf-8")
        result = check_state_file(str(bad_file))
        assert result["check"] == "state_file"
        assert result["status"] == "FAIL"

    def test_missing_file(self, tmp_path):
        """Non-existent state file returns MISSING."""
        from gk_self_check import check_state_file
        result = check_state_file(str(tmp_path / "nonexistent.json"))
        assert result["check"] == "state_file"
        assert result["status"] == "MISSING"

    def test_invalid_json(self, tmp_path):
        """Corrupted JSON returns FAIL."""
        from gk_self_check import check_state_file
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json{{{", encoding="utf-8")
        result = check_state_file(str(bad_file))
        assert result["check"] == "state_file"
        assert result["status"] == "FAIL"


class TestGateDataCheck:
    """Test check_gate_data — gate_data health parsing."""

    def test_happy_path_empty(self, tmp_state):
        """Empty gate_data returns PASS with zero counts."""
        from gk_self_check import check_gate_data
        result = check_gate_data(tmp_state)
        assert result["check"] == "gate_data"
        assert result["status"] == "PASS"
        assert result["rejected_count"] == 0
        assert result["block_log_count"] == 0
        assert result["needs_analysis"] is False

    def test_with_rejected_edits(self, tmp_path):
        """Gate data with rejected edits reports correct count."""
        from gk_self_check import check_gate_data
        state = {
            "r_phase": "ECO-SCAN", "stage": "STAGE_0",
            "gate_data": {
                "rejected_edits": [{"file": "a.txt"}, {"file": "b.txt"}],
                "needs_analysis": True,
                "block_log": [{"cmd": "advance", "reason": "IDLE"}]
            }
        }
        f = tmp_path / "state.json"
        f.write_text(json.dumps(state), encoding="utf-8")
        result = check_gate_data(str(f))
        assert result["status"] == "PASS"
        assert result["rejected_count"] == 2
        assert result["block_log_count"] == 1
        assert result["needs_analysis"] is True

    def test_missing_gate_data(self, tmp_path):
        """State file without gate_data key handles gracefully with PASS and zero counts."""
        from gk_self_check import check_gate_data
        state = {"r_phase": "ECO-SCAN", "stage": "STAGE_0"}
        f = tmp_path / "state.json"
        f.write_text(json.dumps(state), encoding="utf-8")
        result = check_gate_data(str(f))
        assert result["check"] == "gate_data"
        assert result["status"] == "PASS"
        assert result["rejected_count"] == 0
        assert result["block_log_count"] == 0
        assert result["needs_analysis"] is False

    def test_missing_state_file(self, tmp_path):
        """Missing state file returns FAIL."""
        from gk_self_check import check_gate_data
        result = check_gate_data(str(tmp_path / "nope.json"))
        assert result["check"] == "gate_data"
        assert result["status"] == "FAIL"


class TestChecksumCheck:
    """Test check_checksum — SHA256 checksum verification."""

    def test_happy_path_valid(self, tmp_state_with_checksum):
        """Valid checksum returns PASS."""
        from gk_self_check import check_checksum
        result = check_checksum(tmp_state_with_checksum)
        assert result["check"] == "checksum_integrity"
        assert result["status"] == "PASS"
        assert "checksum" in result

    def test_tampered_checksum(self, tmp_state_tampered):
        """Tampered checksum returns FAIL."""
        from gk_self_check import check_checksum
        result = check_checksum(tmp_state_tampered)
        assert result["check"] == "checksum_integrity"
        assert result["status"] == "FAIL"
        assert "mismatch" in result["detail"]

    def test_no_checksum_in_state(self, tmp_state):
        """State without _checksum field returns WARN."""
        from gk_self_check import check_checksum
        result = check_checksum(tmp_state)
        assert result["check"] == "checksum_integrity"
        assert result["status"] == "WARN"

    def test_missing_state_file(self, tmp_path):
        """Missing state file returns FAIL."""
        from gk_self_check import check_checksum
        result = check_checksum(str(tmp_path / "nope.json"))
        assert result["check"] == "checksum_integrity"
        assert result["status"] == "FAIL"


class TestHmacKeyCheck:
    """Test check_hmac_key — GATEKEEPER_HMAC_KEY env var."""

    def test_set_valid_key(self, monkeypatch):
        """Valid 64-char hex key returns PASS."""
        from gk_self_check import check_hmac_key
        monkeypatch.setenv("GATEKEEPER_HMAC_KEY", "a" * 64)
        result = check_hmac_key()
        assert result["check"] == "env_hmac_key"
        assert result["status"] == "PASS"

    def test_short_key(self, monkeypatch):
        """Key shorter than 64 chars returns WARN."""
        from gk_self_check import check_hmac_key
        monkeypatch.setenv("GATEKEEPER_HMAC_KEY", "abc123")
        result = check_hmac_key()
        assert result["check"] == "env_hmac_key"
        assert result["status"] == "WARN"
        assert "SHORT" in result["detail"]

    def test_missing_key(self, monkeypatch):
        """Missing HMAC key returns WARN."""
        from gk_self_check import check_hmac_key
        monkeypatch.delenv("GATEKEEPER_HMAC_KEY", raising=False)
        result = check_hmac_key()
        assert result["check"] == "env_hmac_key"
        assert result["status"] == "WARN"
        assert "MISSING" in result["detail"]

    def test_empty_string_key(self, monkeypatch):
        """Empty string HMAC key returns WARN (same as missing)."""
        from gk_self_check import check_hmac_key
        monkeypatch.setenv("GATEKEEPER_HMAC_KEY", "")
        result = check_hmac_key()
        assert result["check"] == "env_hmac_key"
        assert result["status"] == "WARN"
        assert "MISSING" in result["detail"]

    def test_near_miss_key(self, monkeypatch):
        """Key with 63 chars (almost valid) returns WARN."""
        from gk_self_check import check_hmac_key
        monkeypatch.setenv("GATEKEEPER_HMAC_KEY", "a" * 63)
        result = check_hmac_key()
        assert result["check"] == "env_hmac_key"
        assert result["status"] == "WARN"
        assert "SHORT" in result["detail"]


class TestKeyIntegrityCheck:
    """Test check_key_integrity — Ed25519 key pair verification."""

    def test_no_meta_file(self, tmp_path):
        """No key-meta.json yet returns PASS (no keys = nothing to check)."""
        from gk_self_check import check_key_integrity
        result = check_key_integrity(
            key_meta=str(tmp_path / "nope.json"),
            key_integrity=str(tmp_path / "nope.integrity"),
            audit_key_dir=str(tmp_path)
        )
        assert result["check"] == "key_integrity"
        assert result["status"] == "PASS"

    def test_missing_integrity_file(self, tmp_path):
        """Key-meta exists but integrity file missing returns FAIL."""
        from gk_self_check import check_key_integrity
        meta_file = tmp_path / "key-meta.json"
        meta_file.write_text(json.dumps({"context_ed25519": {}}), encoding="utf-8")
        result = check_key_integrity(
            key_meta=str(meta_file),
            key_integrity=str(tmp_path / "nope.integrity"),
            audit_key_dir=str(tmp_path)
        )
        assert result["check"] == "key_integrity"
        assert result["status"] == "FAIL"

    def test_sha256_match(self, tmp_path):
        """SHA256 hash matches returns PASS."""
        from gk_self_check import check_key_integrity
        meta_file = tmp_path / "key-meta.json"
        meta_file.write_text(json.dumps({"context_ed25519": {"fingerprint": "abc"}}), encoding="utf-8")
        # Write integrity hash
        integrity_file = tmp_path / "key-meta.integrity"
        actual_hash = hashlib.sha256(open(meta_file, "rb").read()).hexdigest()
        integrity_file.write_text(actual_hash, encoding="utf-8")
        result = check_key_integrity(
            key_meta=str(meta_file),
            key_integrity=str(integrity_file),
            audit_key_dir=str(tmp_path)
        )
        assert result["check"] == "key_integrity"
        assert result["status"] == "PASS"

    def test_pubkey_fingerprint_mismatch(self, tmp_path):
        """Pubkey fingerprint in key-meta doesn't match actual pubkey returns FAIL."""
        from gk_self_check import check_key_integrity
        # Create key-meta with fingerprint that won't match
        meta_file = tmp_path / "key-meta.json"
        meta_file.write_text(json.dumps({
            "context_ed25519": {"fingerprint": "0000000000000000"}
        }), encoding="utf-8")
        integrity_file = tmp_path / "key-meta.integrity"
        actual_hash = hashlib.sha256(open(meta_file, "rb").read()).hexdigest()
        integrity_file.write_text(actual_hash, encoding="utf-8")
        # Create pubkey file with different content
        pub_dir = tmp_path / "context"
        pub_dir.mkdir()
        pub_file = pub_dir / "context_ed25519.pub"
        pub_file.write_bytes(b"fake pubkey content")
        result = check_key_integrity(
            key_meta=str(meta_file),
            key_integrity=str(integrity_file),
            audit_key_dir=str(tmp_path)
        )
        assert result["check"] == "key_integrity"
        assert result["status"] == "FAIL"
        assert "pubkey replaced" in result["detail"]

    def test_corrupted_meta_json(self, tmp_path):
        """Corrupted key-meta.json returns FAIL."""
        from gk_self_check import check_key_integrity
        meta_file = tmp_path / "key-meta.json"
        meta_file.write_text("not valid json", encoding="utf-8")
        integrity_file = tmp_path / "key-meta.integrity"
        integrity_file.write_text("anything", encoding="utf-8")
        result = check_key_integrity(
            key_meta=str(meta_file),
            key_integrity=str(integrity_file),
            audit_key_dir=str(tmp_path)
        )
        assert result["check"] == "key_integrity"
        assert result["status"] == "FAIL"


class TestForeignContentGuard:
    """Test check_foreign_content_guard — _FOREIGN_USER_PATTERNS count."""

    def test_happy_path(self):
        """Patterns loaded returns PASS with count."""
        from gk_self_check import check_foreign_content_guard
        result = check_foreign_content_guard(str(Path(__file__).parent))
        assert result["check"] == "foreign_content_guard"
        assert result["status"] in ("PASS", "WARN")
        if result["status"] == "PASS":
            assert result["count"] > 0

    def test_bad_path(self):
        """Non-existent scripts dir returns WARN."""
        from gk_self_check import check_foreign_content_guard
        result = check_foreign_content_guard("/nonexistent/path")
        assert result["check"] == "foreign_content_guard"
        assert result["status"] == "WARN"

    def test_missing_scripts_dir(self, tmp_path):
        """Directory without scripts/ subdir returns WARN."""
        from gk_self_check import check_foreign_content_guard
        result = check_foreign_content_guard(str(tmp_path))
        assert result["check"] == "foreign_content_guard"
        assert result["status"] == "WARN"
        assert "not found" in result["detail"]


class TestSubagentRunnerCheck:
    """Test check_subagent_runner — TOOL_REGISTRY import."""

    def test_happy_path(self):
        """Subagent runner imports returns PASS with tool count."""
        from gk_self_check import check_subagent_runner
        result = check_subagent_runner(str(Path(__file__).parent))
        assert result["check"] == "subagent_runner"
        assert result["status"] in ("PASS", "WARN")
        if result["status"] == "PASS":
            assert "tools OK" in result["detail"]

    def test_bad_path(self):
        """Non-existent scripts dir returns WARN."""
        from gk_self_check import check_subagent_runner
        result = check_subagent_runner("/nonexistent/path")
        assert result["check"] == "subagent_runner"
        assert result["status"] == "WARN"


class TestJwtSigningCheck:
    def test_happy_path(self):
        """joserfc importable => PASS (if joserfc installed)."""
        from gk_self_check import check_jwt_signing
        result = check_jwt_signing(str(Path(__file__).parent.parent))
        assert result["check"] == "jwt_signing"
        # System-dependent: may be PASS or FAIL
        assert result["status"] in ("PASS", "FAIL", "SKIP")

    def test_no_scripts_dir(self):
        """Non-existent scripts dir returns SKIP."""
        from gk_self_check import check_jwt_signing
        result = check_jwt_signing("/nonexistent/path")
        assert result["check"] == "jwt_signing"
        assert result["status"] == "SKIP"


class TestProviderCheck:
    def test_no_key_returns_skip(self, monkeypatch):
        """No API key set => SKIP."""
        from gk_self_check import check_provider
        for k in ("API_KEY", "DEEPSEEK_API_KEY", "GATEKEEPER_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        result = check_provider()
        assert result["check"] == "provider"
        assert result["status"] == "SKIP"

    def test_with_key_no_network(self, monkeypatch):
        """Key set but network unreachable => WARN (not FAIL)."""
        from gk_self_check import check_provider
        monkeypatch.setenv("GATEKEEPER_API_KEY", "sk-test-fake-key-12345")
        result = check_provider()
        assert result["check"] == "provider"
        assert result["status"] in ("WARN", "PASS")  # may pass if network available


class TestGitnexusCheck:
    def test_no_node(self, monkeypatch):
        """No node.exe => FAIL."""
        from gk_self_check import check_gitnexus
        result = check_gitnexus("/nonexistent/path")
        assert result["check"] == "gitnexus"
        assert result["status"] in ("FAIL", "WARN")

    def test_happy_path_skill_dir(self):
        """Real skill dir => PASS or WARN (system-dependent)."""
        from gk_self_check import check_gitnexus
        skill_dir = str(Path(__file__).parent.parent)
        result = check_gitnexus(skill_dir)
        assert result["check"] == "gitnexus"
        assert result["status"] in ("PASS", "WARN", "FAIL")


class TestL9RuntimeSafenet:
    """L9 运行时安全网（2026-08-26）— 升级对账三要素静态探测。"""

    def test_happy_path_real_skill(self):
        """真实 skill 目录: gk_bashpy_upgrade.py 存在且三要素齐全 => PASS。"""
        from gk_self_check import check_l9_runtime_safenet
        r = check_l9_runtime_safenet(str(Path(__file__).parent.parent))
        assert r["check"] == "l9_runtime_safenet"
        assert r["status"] in ("PASS", "WARN")
        assert "三要素齐全" in r.get("detail", "")

    def test_module_missing(self, tmp_path):
        """模块缺失 => FAIL（运行时安全网不可用）。"""
        from gk_self_check import check_l9_runtime_safenet
        r = check_l9_runtime_safenet(str(tmp_path))
        assert r["status"] == "FAIL"

    def test_partial_keywords_warn(self, tmp_path):
        """模块在但缺备份/白名单 => WARN（明细列缺项）。"""
        from gk_self_check import check_l9_runtime_safenet
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "gk_bashpy_upgrade.py").write_text(
            "import hashlib\nsha512 = hashlib.sha512\nsha256 = hashlib.sha256\n",
            encoding="utf-8")
        r = check_l9_runtime_safenet(str(tmp_path))
        assert r["status"] == "WARN"
        assert "备份 manifest" in r.get("detail", "")

    def test_unreadable_file_warn(self, tmp_path, monkeypatch):
        """读取异常 => WARN（check 崩溃隔离）。"""
        from gk_self_check import check_l9_runtime_safenet
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        bad = scripts / "gk_bashpy_upgrade.py"
        bad.write_text("x", encoding="utf-8")
        monkeypatch.setattr("pathlib.Path.read_text",
                            lambda self, **kw: (_ for _ in ()).throw(OSError("boom")))
        r = check_l9_runtime_safenet(str(tmp_path))
        assert r["status"] == "WARN"


class TestL9GatechainPrereq:
    """L9 门禁链前置（2026-08-26）— 复用 _eco_prereq_heuristic 产物检查。"""

    def _write(self, tmp_path, data):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return str(sf)

    def test_happy_eco_ready(self, tmp_path):
        """ECO-EDIT 前置齐全 => PASS。"""
        from gk_self_check import check_l9_gatechain_prereq
        sf = self._write(tmp_path, {
            "stage": "ECO-EDIT",
            "gate_data": {
                "subagent_history": [{"task": "plan-refinement: 质询收敛"}],
                "human_calibration_log": [{"stage": "ECO-EDIT", "verdict": "PASS"}],
            },
        })
        r = check_l9_gatechain_prereq(sf)
        assert r["check"] == "l9_gatechain_prereq"
        assert r["status"] == "PASS"

    def test_missing_prereq_warn(self, tmp_path):
        """ECO-EDIT 前置全缺 => WARN + missing 明细。"""
        from gk_self_check import check_l9_gatechain_prereq
        sf = self._write(tmp_path, {"stage": "ECO-EDIT", "gate_data": {}})
        r = check_l9_gatechain_prereq(sf)
        assert r["status"] == "WARN"
        assert len(r.get("missing", [])) >= 2

    def test_non_eco_stage_info(self, tmp_path):
        """非 ECO 阶段 => INFO（门禁链前置不适用）。"""
        from gk_self_check import check_l9_gatechain_prereq
        sf = self._write(tmp_path, {"stage": "STAGE_1", "gate_data": {}})
        r = check_l9_gatechain_prereq(sf)
        assert r["status"] == "INFO"

    def test_missing_state_info(self, tmp_path):
        """state 缺失 => INFO。"""
        from gk_self_check import check_l9_gatechain_prereq
        r = check_l9_gatechain_prereq(str(tmp_path / "none.json"))
        assert r["status"] == "INFO"

    def test_bad_json_warn(self, tmp_path):
        """state 损坏 => WARN（check 崩溃隔离）。"""
        from gk_self_check import check_l9_gatechain_prereq
        sf = tmp_path / "s.json"
        sf.write_text("{bad json", encoding="utf-8")
        r = check_l9_gatechain_prereq(str(sf))
        assert r["status"] == "WARN"


class TestL9EntropyAppeal:
    """L9 熵/appeal 链路（2026-08-26）— 熵阈值 + 死锁检测。"""

    def _write(self, tmp_path, gd):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"gate_data": gd}), encoding="utf-8")
        return str(sf)

    def test_entropy_ok_pass(self, tmp_path):
        """entropy < 0.5 且无 appeal => PASS。"""
        from gk_self_check import check_l9_entropy_appeal
        r = check_l9_entropy_appeal(self._write(tmp_path, {"entropy_rate": 0.2}))
        assert r["check"] == "l9_entropy_appeal"
        assert r["status"] == "PASS"

    def test_entropy_high_fail(self, tmp_path):
        """entropy >= 0.5 => FAIL（需人类裁决）。"""
        from gk_self_check import check_l9_entropy_appeal
        r = check_l9_entropy_appeal(self._write(tmp_path, {"entropy_rate": 0.8}))
        assert r["status"] == "FAIL"

    def test_entropy_invalid_ignored(self, tmp_path):
        """entropy 非数值 => 忽略，不误报 FAIL。"""
        from gk_self_check import check_l9_entropy_appeal
        r = check_l9_entropy_appeal(self._write(tmp_path, {"entropy_rate": "abc"}))
        assert r["status"] == "PASS"

    def test_appeal_denied_warn(self, tmp_path):
        """appeal_denied_gates 非空 => WARN（永久拒绝清单，顶层布局）。"""
        from gk_self_check import check_l9_entropy_appeal
        sf = tmp_path / "s.json"
        # 真实状态布局：appeal_denied_gates 在顶层（cmd_appeal 写入 d['appeal_denied_gates']）
        sf.write_text(json.dumps({"gate_data": {}, "appeal_denied_gates": ["ECO-EDIT"]}),
                      encoding="utf-8")
        r = check_l9_entropy_appeal(str(sf))
        assert r["status"] == "WARN"

    def test_appeal_required_warn(self, tmp_path):
        """appeal_required 存在 => WARN（advance 被锁，须先 appeal）。"""
        from gk_self_check import check_l9_entropy_appeal
        r = check_l9_entropy_appeal(self._write(tmp_path, {"appeal_required": "ECO-AUDIT"}))
        assert r["status"] == "WARN"

    def test_missing_state_info(self, tmp_path):
        """state 缺失 => INFO。"""
        from gk_self_check import check_l9_entropy_appeal
        r = check_l9_entropy_appeal(str(tmp_path / "none.json"))
        assert r["status"] == "INFO"


class TestEccForm:
    """ECC 写入规范 · 机械（A 类）体检（2026-09-28 s4；`ECC-03F2EB7D6607`）——只读监管。"""

    def _write(self, tmp_path, findings):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}), encoding="utf-8")
        return str(sf)

    def test_valid_pass(self, tmp_path):
        """合规（含**未分类** `""` 与缺字段）=> PASS。"""
        from gk_self_check import check_ecc_form
        r = check_ecc_form(self._write(tmp_path, [
            {"id": "ECC-A", "source": "manual", "closure_oracle": "mechanical", "root_key": "rk-a"},
            {"id": "ECC-B", "source": "manual", "closure_oracle": "judgment"},
            {"id": "ECC-C", "source": "manual"},
            {"id": "ECC-D", "source": "manual", "closure_oracle": "", "root_key": ""},
        ]))
        assert r["check"] == "ecc_form" and r["status"] == "PASS", r

    def test_bad_closure_oracle_fail(self, tmp_path):
        from gk_self_check import check_ecc_form
        r = check_ecc_form(self._write(tmp_path, [{"id": "ECC-X", "closure_oracle": "bogus"}]))
        assert r["status"] == "FAIL" and "closure_oracle" in r["detail"], r

    def test_bad_root_key_whitespace_fail(self, tmp_path):
        from gk_self_check import check_ecc_form
        r = check_ecc_form(self._write(tmp_path, [{"id": "ECC-Y", "root_key": "has space"}]))
        assert r["status"] == "FAIL" and "root_key" in r["detail"], r

    def test_bad_root_key_too_long_fail(self, tmp_path):
        from gk_self_check import check_ecc_form
        r = check_ecc_form(self._write(tmp_path, [{"id": "ECC-Z", "root_key": "x" * 65}]))
        assert r["status"] == "FAIL", r

    def test_unclassified_is_legal(self, tmp_path):
        """`closure_oracle` 留空 = **未分类合法**（存量不追责）⟹ 不 FAIL。"""
        from gk_self_check import check_ecc_form
        r = check_ecc_form(self._write(tmp_path, [{"id": "ECC-OK", "source": "manual", "closure_oracle": ""}]))
        assert r["status"] == "PASS", r

    def test_nonconforming_source_warns_not_fails(self, tmp_path):
        """存量 `source` 非规范（缺字段 / 私名 / 散文）=> **WARN 非 FAIL**（2026-09-28 裁定：存量不追责）。"""
        from gk_self_check import check_ecc_form
        r = check_ecc_form(self._write(tmp_path, [
            {"id": "ECC-LEGACY-1"},                     # 缺 source
            {"id": "ECC-LEGACY-2", "source": "R25.9"},  # 私名/散文
        ]))
        assert r["status"] == "WARN" and "source" in r["detail"], r

    def test_no_findings_info(self, tmp_path):
        from gk_self_check import check_ecc_form
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
        assert check_ecc_form(str(sf))["status"] == "INFO"

    def test_missing_state_info(self, tmp_path):
        from gk_self_check import check_ecc_form
        assert check_ecc_form(str(tmp_path / "none.json"))["status"] == "INFO"

    def test_readonly_zero_write(self, tmp_path):
        """只读纪律：读前后字节不变（**监管 ≠ 写入者**，N4）。"""
        from gk_self_check import check_ecc_form
        p = Path(self._write(tmp_path, [{"id": "ECC-A", "closure_oracle": "bogus"}]))
        before = p.read_bytes()
        check_ecc_form(str(p))
        assert p.read_bytes() == before

    def test_verify_source_free_text_segment_not_a_kind(self, tmp_path):
        """`_verify_source_kinds` 须与 `gk_finding._assert_verify_source` **同构**：无冒号段不是 kind。

        原实现 `part.split(":",1)[0]` 把无冒号自由文本段整段当 kind ⟹ 合法源串里的括号补充
        被误判（实测 `ECC-9130E7CA8625`：`tests:… (…; mu_tgt 11/8/3/0);review:…` ⟹ 恒 FAIL）。
        """
        from gk_self_check import _verify_source_kinds, check_ecc_form
        vs = ("tests:repro/all.sh 16/16 (P7 recomputed; mu_tgt 11/8/3/0);"
              "review:repro/web_pilot_verdict.py")
        assert _verify_source_kinds(vs) == ["tests", "review"], _verify_source_kinds(vs)
        r = check_ecc_form(self._write(tmp_path, [
            {"id": "ECC-S", "source": "manual", "status": "closed",
             "basis_ref": "abc", "verify_source": vs}]))
        assert r["status"] == "PASS", r


class TestRunAllEccFormWiring:
    """RED-PY-MISS：`check_ecc_form` 已实装却未挂 `run_all` ⟹ 门禁盲区（新机制未入自检）。"""

    def test_run_all_includes_ecc_form(self, tmp_state, monkeypatch):
        import gk_self_check
        monkeypatch.setattr(gk_self_check, "check_tests",
                            lambda skill_dir: {"check": "tests", "status": "PASS"})
        monkeypatch.setattr(gk_self_check, "check_provider",
                            lambda: {"check": "provider", "status": "SKIP"})
        out = gk_self_check.run_all(tmp_state, str(Path(__file__).parent.parent))
        names = {c["check"] for c in out["checks"]}
        assert "ecc_form" in names, names


class TestL9RunAllWiring:
    """run_all 挂载验证（2026-08-26）— 3 个 L9 检查进入聚合输出。"""

    def test_run_all_includes_l9(self, tmp_state, monkeypatch):
        import gk_self_check
        monkeypatch.setattr(gk_self_check, "check_tests",
                            lambda skill_dir: {"check": "tests", "status": "PASS"})
        monkeypatch.setattr(gk_self_check, "check_provider",
                            lambda: {"check": "provider", "status": "SKIP"})
        out = gk_self_check.run_all(tmp_state, str(Path(__file__).parent.parent))
        names = {c["check"] for c in out["checks"]}
        assert {"l9_runtime_safenet", "l9_gatechain_prereq", "l9_entropy_appeal",
                "review_layer_coverage"} <= names


class TestSequenceNodeSafety:
    """序列节点安全网健全程度（2026-09-05）— S11 空壳站回归（self-check 第 17 项）。"""

    @staticmethod
    def _stub(**kw):
        import types
        ng = types.SimpleNamespace(
            _ROUTES={"standard": {"name": "R 序列", "nodes": ["A", "B", "C"]},
                     "red": {"name": "RED", "nodes": ["R1", "R2"]}},
            _GATES={}, _CHECKLISTS={}, _SAFETY={})
        for k, v in kw.items():
            setattr(ng, k, v)
        return ng

    def test_full_three_facets_pass(self):
        from gk_self_check import check_sequence_node_safety
        nodes = ("A", "B", "C", "R1", "R2")
        ng = self._stub(_GATES={n: "g" for n in nodes},
                        _CHECKLISTS={n: ["x"] for n in nodes},
                        _SAFETY={n: ["s"] for n in nodes})
        r = check_sequence_node_safety("", ng)
        assert r["status"] == "PASS"
        assert r["routes"][0]["gate_explicit"] == "3/3"

    def test_standard_wide_gap_bare_fail(self):
        """S11 类回归：整条序列只挂 ROUTES 名、三面全空（全默认空壳）→ FAIL + 明细。"""
        from gk_self_check import check_sequence_node_safety
        r = check_sequence_node_safety("", self._stub())
        assert r["status"] == "FAIL"
        assert "standard:A" in r["bare_stations"]
        assert r["detail"]

    def test_partial_thin_warn(self):
        """全站 ≥1/3（仅 checklist，无 bare）→ WARN，thin 明细可定位。"""
        from gk_self_check import check_sequence_node_safety
        ng = self._stub(_CHECKLISTS={n: ["x"] for n in ("A", "B", "C", "R1", "R2")})
        r = check_sequence_node_safety("", ng)
        assert r["status"] == "WARN"
        assert r["bare_stations"] == []
        assert any(t.startswith("standard:A") for t in r["thin_stations"])

    def test_route_coverage_matrix_present(self):
        from gk_self_check import check_sequence_node_safety
        nodes = ("A", "B", "C", "R1", "R2")
        ng = self._stub(_CHECKLISTS={n: ["x"] for n in nodes},
                        _SAFETY={n: ["s"] for n in nodes})
        r = check_sequence_node_safety("", ng)
        by = {row["route"]: row for row in r["routes"]}
        assert by["standard"]["gate_explicit"] == "0/3"
        assert by["red"]["safety_explicit"] == "2/2"

    def test_real_node_guard_data_no_bare(self):
        """真实 gk_node_guard（2026-09-05 S11 修复后）：无空壳站，至少 WARN 级。"""
        import gk_node_guard
        from gk_self_check import check_sequence_node_safety
        r = check_sequence_node_safety("", gk_node_guard)
        assert r["bare_stations"] == []
        assert r["status"] in ("PASS", "WARN")

    def test_dispatcher_route_not_thin(self):
        """WAD 复核（2026-09-07 批③ ⑤）：walk=dispatcher 路线（red/audit 引擎分发）
        三面全空也不计 bare/thin——站级门禁语义在引擎分发/registry 面，非 advance 逐站 walk。"""
        from gk_self_check import check_sequence_node_safety
        ng = self._stub()
        ng._ROUTES["red"] = {"name": "RED", "nodes": ["R1", "R2"], "walk": "dispatcher"}
        # red 三面全空 → 不计 bare；standard A/B/C 全空 → 仍 FAIL（advance 序列不被豁免）
        r = check_sequence_node_safety("", ng)
        assert "red:R1" not in r["bare_stations"]
        assert "red:R2" not in r["bare_stations"]
        assert "standard:A" in r["bare_stations"]
        assert any(row["route"] == "red" and row.get("walk") == "dispatcher"
                   for row in r["dispatcher_routes"])
        assert r["status"] == "FAIL"


class TestGovernedBaseline:
    """派生联动（2026-09-05）：元数据只引用 — 活动项目 ∈ scopes + registry 基线条目派生。"""

    def _setup(self, tmp_path, registry_hit=True, scopes_gov=True, state_stage="STAGE_2"):
        root = tmp_path / "proj"
        root.mkdir(parents=True, exist_ok=True)
        skill = tmp_path / "skill"
        skill.mkdir(exist_ok=True)
        st = root / ".gatekeeper.state"
        st.write_text(json.dumps({"stage": state_stage, "r_phase": "R9"}), encoding="utf-8")
        projects = []
        if scopes_gov:
            projects.append({"markers": ["proj-marker"],
                             "state_file": str(st).replace("\\", "/")})
        (skill / ".gatekeeper.scopes.json").write_text(
            json.dumps({"version": 2, "governed_projects": projects}), encoding="utf-8")
        reg_entries = []
        if registry_hit:
            reg_entries.append({"name": "proj_reg", "path": str(root).replace("\\", "/")})
        reg = tmp_path / "registry.json"
        reg.write_text(json.dumps(reg_entries), encoding="utf-8")
        return str(skill), str(st), str(reg)

    def test_pass_governed_and_baseline(self, tmp_path):
        from gk_self_check import check_governed_baseline
        skill, st, reg = self._setup(tmp_path)
        r = check_governed_baseline(st, skill, registry_path=reg)
        assert r["status"] == "PASS"
        assert "proj_reg" in r["detail"]

    def test_fail_governed_no_baseline(self, tmp_path):
        from gk_self_check import check_governed_baseline
        skill, st, reg = self._setup(tmp_path, registry_hit=False)
        r = check_governed_baseline(st, skill, registry_path=reg)
        assert r["status"] == "FAIL"
        assert "project-register" in r["detail"]

    def test_idle_info(self, tmp_path):
        from gk_self_check import check_governed_baseline
        skill, st, reg = self._setup(tmp_path, state_stage="IDLE")
        r = check_governed_baseline(st, skill, registry_path=reg)
        assert r["status"] == "INFO"

    def test_no_state_info(self, tmp_path):
        from gk_self_check import check_governed_baseline
        skill, _, reg = self._setup(tmp_path)
        r = check_governed_baseline(str(tmp_path / "none.state"), skill, registry_path=reg)
        assert r["status"] == "INFO"

    # ── 2026-10-01：worktree 兜底（基线按**仓库身份**判定，非目录字面）──────────
    def _make_git_worktree(self, tmp_path):
        """造「主仓 + 真实 git worktree（`.git` 为文件）」。git 不可用则 skip。"""
        import subprocess
        import pytest

        def _run(*a):
            return subprocess.run(["git", *a], cwd=str(tmp_path),
                                  capture_output=True, text=True, timeout=30)

        if _run("--version").returncode != 0:
            pytest.skip("git 不可用")
        main = tmp_path / "main"
        main.mkdir()
        assert _run("init", str(main)).returncode == 0
        (main / "f.txt").write_text("x", encoding="utf-8")
        assert _run("-C", str(main), "add", "f.txt").returncode == 0
        assert _run("-C", str(main), "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-m", "init").returncode == 0
        wt = tmp_path / "wt"
        r = _run("-C", str(main), "worktree", "add", str(wt))
        if r.returncode != 0:
            pytest.skip("git worktree 不可用: " + (r.stderr or ""))
        return main, wt

    def _setup_worktree(self, tmp_path, registry_hit=True):
        """state.worktree 指向 worktree；registry 登记**主仓**路径。"""
        main, wt = self._make_git_worktree(tmp_path)
        skill = tmp_path / "skill"
        skill.mkdir(exist_ok=True)
        st = wt / ".gatekeeper.state"
        st.write_text(json.dumps({"stage": "STAGE_2", "r_phase": "R9",
                                  "worktree": str(wt).replace("\\", "/")}),
                      encoding="utf-8")
        (skill / ".gatekeeper.scopes.json").write_text(json.dumps(
            {"version": 2, "governed_projects": [
                {"markers": ["wt-marker"], "state_file": str(st).replace("\\", "/")}]}),
            encoding="utf-8")
        reg_entries = []
        if registry_hit:
            reg_entries.append({"name": "main_reg", "path": str(main).replace("\\", "/")})
        reg = tmp_path / "registry.json"
        reg.write_text(json.dumps(reg_entries), encoding="utf-8")
        return str(skill), str(st), str(reg)

    def test_repo_identity_dir_resolves_worktree_to_main(self, tmp_path):
        """真实 git worktree：`.git`-文件 → `--git-common-dir` 反推主仓根；非 git 目录 → ""。"""
        import gk_self_check as g
        main, wt = self._make_git_worktree(tmp_path)
        assert os.path.realpath(g._repo_identity_dir(str(wt))) == os.path.realpath(str(main))
        assert os.path.realpath(g._repo_identity_dir(str(main))) == os.path.realpath(str(main))
        assert g._repo_identity_dir(str(tmp_path / "nope")) == ""

    def test_worktree_of_registered_pass(self, tmp_path):
        """worktree 直配未命中、仓库身份命中 registry ⟹ PASS 且 detail 标注 via=worktree-of。"""
        from gk_self_check import check_governed_baseline
        skill, st, reg = self._setup_worktree(tmp_path, registry_hit=True)
        r = check_governed_baseline(st, skill, registry_path=reg)
        assert r["status"] == "PASS"
        assert "main_reg" in r["detail"]
        assert "via=worktree-of" in r["detail"]

    def test_worktree_of_unregistered_still_fail(self, tmp_path):
        """仓库身份可解析但 registry 无条目 ⟹ 仍 FAIL（非无条件放行）。"""
        from gk_self_check import check_governed_baseline
        skill, st, reg = self._setup_worktree(tmp_path, registry_hit=False)
        r = check_governed_baseline(st, skill, registry_path=reg)
        assert r["status"] == "FAIL"
        assert "project-register" in r["detail"]


class TestTenantIsolation:
    """租户隔离（2026-09-05，域 token 门小步）：scopes 租户根双形态重复/嵌套检测。"""

    def _scopes(self, tmp_path, roots):
        entries = []
        for i, r in enumerate(roots):
            entries.append({"markers": [f"m{i}"], "state_file": os.path.join(r, ".gatekeeper.state")})
        p = tmp_path / "scopes.json"
        p.write_text(json.dumps({"governed_projects": entries}), encoding="utf-8")
        return str(p)

    def test_clean_sibling_roots_pass(self, tmp_path):
        from gk_self_check import check_tenant_isolation
        a = tmp_path / "ta"
        b = tmp_path / "tb"
        a.mkdir(exist_ok=True)
        b.mkdir(exist_ok=True)
        sp = self._scopes(tmp_path, [str(a), str(b)])
        r = check_tenant_isolation(str(tmp_path), scopes_path=sp)
        assert r["status"] == "PASS"
        assert r["duplicate_roots"] == [] and r["nested_roots"] == []

    def test_nested_root_warn(self, tmp_path):
        from gk_self_check import check_tenant_isolation
        outer = tmp_path / "outer"
        inner = outer / "child" / "gk"
        inner.mkdir(parents=True, exist_ok=True)
        sp = self._scopes(tmp_path, [str(outer), str(inner)])
        r = check_tenant_isolation(str(tmp_path), scopes_path=sp)
        assert r["status"] == "WARN"
        assert r["nested_roots"]

    def test_dual_form_duplicate_warn(self, tmp_path):
        from gk_self_check import check_tenant_isolation
        # 同一物理目录的 Windows 与 /mnt/c 双形态并存 = 域边界虚置
        win = r"<home>\.trae\skills\spz-gatekeeper-r-sequence"
        mnt = "<home>/.trae/skills/spz-gatekeeper-r-sequence"
        sp = self._scopes(tmp_path, [win, mnt])
        r = check_tenant_isolation("", scopes_path=sp)
        assert r["status"] == "WARN"
        assert r["duplicate_roots"]

    def test_no_projects_skip(self, tmp_path):
        from gk_self_check import check_tenant_isolation
        p = tmp_path / "empty.json"
        p.write_text(json.dumps({"governed_projects": []}), encoding="utf-8")
        r = check_tenant_isolation(str(tmp_path), scopes_path=str(p))
        assert r["status"] == "SKIP"


class TestReviewLayerCoverage:
    """审查层四件套覆盖（2026-09-05 C1/E4，self-check 第 20 项）。

    必配面语义对齐 A4 序列节点三面：分母 = 注册表声明的必配面数；0 命中 = bare FAIL，
    部分缺失 = thin WARN，齐备 = PASS。na 面为设计说明不计缺失。
    """

    def test_full_four_facets_pass(self, tmp_path):
        from gk_self_check import check_review_layer_coverage
        scripts = tmp_path / "scripts"
        scripts.mkdir(parents=True, exist_ok=True)
        (scripts / "test_x.py").write_text("def test_ok():\n    pass\n", encoding="utf-8")
        reg = {"L10": {"name": "Red-team", "cli": ["audit"],
                       "doc": ["L10 红队"], "red": ["RED-SCOPE"],
                       "tests": ["test_x.py"]}}
        r = check_review_layer_coverage(str(tmp_path), registry=reg,
                                        cli_text="_CMD_REG[audit]=x",
                                        review_doc_text="L10 红队行",
                                        red_text="RED-SCOPE-01")
        assert r["status"] == "PASS"
        assert r["bare_layers"] == [] and r["thin_layers"] == []
        assert r["rows"][0]["present"] == ["cli", "doc", "red", "tests"]

    def test_missing_required_face_thin_warn(self, tmp_path):
        """已声明必配面（red）缺失 → WARN thin，明细可定位缺哪个面。"""
        from gk_self_check import check_review_layer_coverage
        scripts = tmp_path / "scripts"
        scripts.mkdir(parents=True, exist_ok=True)
        (scripts / "test_x.py").write_text("def test_ok():\n    pass\n", encoding="utf-8")
        reg = {"L10": {"name": "Red-team", "cli": ["audit"],
                       "doc": ["L10 红队"], "red": ["RED-SCOPE"],
                       "tests": ["test_x.py"]}}
        r = check_review_layer_coverage(str(tmp_path), registry=reg,
                                        cli_text="_CMD_REG[audit]=x",
                                        review_doc_text="L10 红队行",
                                        red_text="RED-OTHER")  # RED-SCOPE 缺失
        assert r["status"] == "WARN"
        assert r["bare_layers"] == []
        assert any("缺 red" in t for t in r["thin_layers"])
        assert r["rows"][0]["missing"] == ["red"]

    def test_bare_degenerate_fail(self, tmp_path):
        """注册表必配面 0 命中（cli/doc/tests 全缺）→ FAIL bare。"""
        from gk_self_check import check_review_layer_coverage
        reg = {"LX": {"name": "x", "cli": ["nonexistent"],
                      "doc": ["NO SUCH"], "tests": ["nope.py"]}}
        r = check_review_layer_coverage(str(tmp_path), registry=reg,
                                        review_doc_text="dummy")  # 阻断 SKIP，cli/doc/tests 全 False
        assert r["status"] == "FAIL"
        assert "LX" in r["bare_layers"]

    def test_manual_layer_na_pass(self, tmp_path):
        """L4 人工对照层：cli_manual + na 说明 → 必配面齐备 PASS（na 不构成 thin）。"""
        from gk_self_check import check_review_layer_coverage
        reg = {"L4": {"name": "Reference Projects", "cli": [], "cli_manual": True,
                      "doc": ["L4 Reference Projects"], "red": [], "tests": [],
                      "na": {"cli": "requesting-code-review L4 YAML 人工对照",
                             "red": "人工核查", "tests": "外部副本"}}}
        r = check_review_layer_coverage(str(tmp_path), registry=reg,
                                        review_doc_text="L4 Reference Projects 行")
        assert r["status"] == "PASS"
        assert r["rows"][0]["cli_manual"] is True
        assert r["rows"][0]["na"]  # na 面已登记（matrix 输出可见）

    def test_no_source_files_skip(self, tmp_path):
        from gk_self_check import check_review_layer_coverage
        r = check_review_layer_coverage(str(tmp_path))  # 三源全不可读 → SKIP
        assert r["status"] == "SKIP"

    def test_real_skill_pass_and_matrix_single_source(self):
        """真实技能仓库：无 bare、必配面齐备 PASS；REVIEW_LAYER_MATRIX = doc_align 旧 MATRIX 同构
        （共享单源契约——doc_align cross_review_matrix 消费同一数据）。"""
        import gk_self_check
        skill = str(Path(__file__).parent.parent)
        r = gk_self_check.check_review_layer_coverage(skill)
        assert r["bare_layers"] == []
        assert r["status"] == "PASS"
        assert {row["layer"] for row in r["rows"]} >= {"L1", "L2", "L3", "L4", "L5",
                                                       "L6", "L7", "L8", "L9", "L10", "PR"}
        m = gk_self_check.REVIEW_LAYER_MATRIX
        assert m == {"L1": ["audit"], "L2": ["plan-refinement"], "L3": ["audit"],
                     "L5": ["audit"], "L6": ["doc-align"], "L7": ["audit"],
                     "L8": ["self-check", "audit"], "L9": ["monitor", "node-guard"],
                     "L10": ["audit"], "PR": ["audit"]}
        assert "L4" not in m


class TestBashWriteDrift:
    """#26 bash 写函数防再引入漂移（2026-09-07 批② C66D7831EF73）。

    FAIL=EXEMPT 注册表回归（注记数≠8 / EXEMPT 函数名消失）；WARN=未登记新写函数候选。
    """

    _MARK = "[write_guard 裁决 2026-09-06 EXEMPT]"

    @staticmethod
    def _write_cli(tmp_path, text):
        p = tmp_path / "gatekeeper-cli.sh"
        p.write_text(text, encoding="utf-8")
        return str(tmp_path)

    def _base_cli(self, drop_marker=None, drop_fn=None):
        import gk_self_check as sc
        lines = []
        for name in sc._EXEMPT8:
            if drop_fn == name:
                continue
            if drop_marker != name:
                lines.append(self._MARK)
            lines.append(f"{name}() {{")
            lines.append("  :")
            lines.append("}")
        return "\n".join(lines) + "\n"

    def test_pass_registry_intact(self, tmp_path):
        from gk_self_check import check_bash_write_drift
        skill = self._write_cli(tmp_path, self._base_cli())
        r = check_bash_write_drift(skill)
        assert r["status"] == "PASS"
        assert r["exempt_marks"] == 8
        assert r["unknown_writers"] == []

    def test_fail_marker_removed(self, tmp_path):
        """EXEMPT 注记被静默删除（8→7）→ FAIL（注册表回归）。"""
        from gk_self_check import check_bash_write_drift
        skill = self._write_cli(tmp_path, self._base_cli(drop_marker="_state_write"))
        r = check_bash_write_drift(skill)
        assert r["status"] == "FAIL"
        assert r["exempt_marks"] == 7
        assert any("注记数" in m for m in r["missing"])

    def test_fail_exempt_fn_disappeared(self, tmp_path):
        """§2.5 EXEMPT 函数从代码消失 → FAIL（注册表与代码漂移）。"""
        from gk_self_check import check_bash_write_drift
        skill = self._write_cli(tmp_path, self._base_cli(drop_fn="cmd_audit"))
        r = check_bash_write_drift(skill)
        assert r["status"] == "FAIL"
        assert any("cmd_audit" in m for m in r["missing"])

    def test_warn_new_unknown_writer(self, tmp_path):
        """新增未登记 bash 写函数（含 _state_write）→ WARN 候选（防再引入队列）。"""
        from gk_self_check import check_bash_write_drift
        text = self._base_cli() + (
            "rogue_writer() {\n"
            "  _state_write \"d['gate_data']['x']=1\"\n"
            "}\n")
        skill = self._write_cli(tmp_path, text)
        r = check_bash_write_drift(skill)
        assert r["status"] == "WARN"
        assert r["unknown_writers"] == ["rogue_writer"]
        assert any("rogue_writer" in w for w in r["warnings"])

    def test_missing_file_fail(self, tmp_path):
        from gk_self_check import check_bash_write_drift
        r = check_bash_write_drift(str(tmp_path))
        assert r["status"] == "FAIL" and "缺失" in r["detail"]


class TestPrScoreAnchorPreRotation:
    """f4（ECC-50F4AED30AF4，2026-09-22，**红先**）：PR-SCORE 锚定的**轮换副作用归因**。

    现场（**实测**）：`docs/plans/.prscore-2026-08-28-security-hardening-assessment.json` 的
    `sealed_at=2026-09-06T04:55:44Z`（= 其 mtime）**早于**审计钥轮换点
    `2026-09-22T08:56:29Z`，且 `seal.key_fp=7cff897f…`（旧钥）⟹ 验签必然 invalid。
    原实现把 `seal_st in ("invalid","error")` 一律判 **FAIL** ⟹ `self-check` **永久假红**
    （每轮都报同一份），把真篡改淹没在噪声里。修法 = 与 `_check_ember_replay` 的 A3 seal
    **同族同判据**：先判「轮换预期副作用」，再判篡改。

    两条要件（缺一不可）：① 纯验签失败（`mismatches` 空 ⟹ plan 区块字段一致、内容未被改）
    ② 签发时刻（`sealed_at`，缺则 mtime）< 轮换点。任一不满足 ⟹ 仍 FAIL。

    ⚠ 以 monkeypatch 替身锁契约（不产生真密钥/真签名）：被测函数只消费 `cmd_verify` 的返回值。
    """

    SNAP = ".prscore-demo.json"

    @staticmethod
    def _env(tmp_path, monkeypatch, *, sealed_at, created, verify):
        skill = tmp_path / "skill"
        plans = skill / "docs" / "plans"
        plans.mkdir(parents=True)
        (plans / TestPrScoreAnchorPreRotation.SNAP).write_text(
            json.dumps({"sealed_at": sealed_at, "schema": "v1"}), encoding="utf-8")
        (plans / "demo.md").write_text("<!-- PR-SCORE -->\n", encoding="utf-8")
        keys = tmp_path / ".keys"
        keys.mkdir()
        (keys / "key-meta.json").write_text(
            json.dumps({"audit_ed25519": {"created": created, "fingerprint": "new"}}),
            encoding="utf-8")
        sys.path.insert(0, str(Path(__file__).parent))
        import gk_pr_score
        monkeypatch.setattr(gk_pr_score, "cmd_verify", lambda plan, kd="": verify)
        import gk_self_check
        return gk_self_check, str(skill), str(keys)

    def test_pre_rotation_invalid_is_degraded(self, tmp_path, monkeypatch):
        """判据：轮换前签发 + 无字段不一致 ⟹ 降级 PASS 标注（不再是 FAIL 假红）。"""
        sc, skill, keys = self._env(
            tmp_path, monkeypatch,
            sealed_at="2026-09-06T04:55:44Z", created="2026-09-22T08:56:29Z",
            verify={"anchored": False, "seal": "invalid", "mismatches": []})
        r = sc._check_pr_score_anchor(skill, keys)
        assert r["status"] == "PASS", r
        assert "pre_rotation" in r["detail"], r
        assert "2026-09-06" in r["detail"] and "2026-09-22" in r["detail"], r

    def test_post_rotation_invalid_still_fails(self, tmp_path, monkeypatch):
        """要件②的反臂：轮换**之后**签发仍 invalid ⟹ 必须 FAIL（不得被归因闸洗白）。"""
        sc, skill, keys = self._env(
            tmp_path, monkeypatch,
            sealed_at="2026-09-23T00:00:00Z", created="2026-09-22T08:56:29Z",
            verify={"anchored": False, "seal": "invalid", "mismatches": []})
        r = sc._check_pr_score_anchor(skill, keys)
        assert r["status"] == "FAIL", r

    def test_pre_rotation_with_field_mismatch_still_fails(self, tmp_path, monkeypatch):
        """要件①的反臂：plan 区块字段不一致 ⟹ 内容被改过，**不得**归因为轮换副作用。"""
        sc, skill, keys = self._env(
            tmp_path, monkeypatch,
            sealed_at="2026-09-06T04:55:44Z", created="2026-09-22T08:56:29Z",
            verify={"anchored": False, "seal": "invalid",
                    "mismatches": ["field_mismatch:f1_f7"]})
        r = sc._check_pr_score_anchor(skill, keys)
        assert r["status"] == "FAIL", r
        assert "field_mismatch" in r["detail"], r

    def test_unknown_rotation_point_keeps_fail(self, tmp_path, monkeypatch):
        """轮换点不可判（`key-meta.json` 无 created）⟹ fail-closed，不得降级。"""
        sc, skill, keys = self._env(
            tmp_path, monkeypatch,
            sealed_at="2026-09-06T04:55:44Z", created="",
            verify={"anchored": False, "seal": "invalid", "mismatches": []})
        r = sc._check_pr_score_anchor(skill, keys)
        assert r["status"] == "FAIL", r

    def test_sealed_at_missing_falls_back_to_mtime(self, tmp_path, monkeypatch):
        """`sealed_at` 缺失 ⟹ 退到文件 mtime（本用例 mtime=now ⟹ 晚于轮换点 ⟹ 不降级）。"""
        sc, skill, keys = self._env(
            tmp_path, monkeypatch,
            sealed_at="", created="2026-09-22T08:56:29Z",
            verify={"anchored": False, "seal": "invalid", "mismatches": []})
        r = sc._check_pr_score_anchor(skill, keys)
        assert r["status"] == "FAIL", r


class TestCliHookExecutableProbe:
    """第 30 项：CLI 可经 hook 执行（2026-10-22，owner 裁定「只加自检探针」）。

    病象（实测死锁）：CLI 自身含危险命令族 ⟹ hook Gate R0.3 `_scan_script_content`
    读整份脚本内容判危险 ⟹ `bash gatekeeper-cli.sh <cmd>` **整条不可执行** ⟹
    `advance` / `apply-worktree` / `state-patch` 全部不可达 ⟹ 额度与写面都无法复位。
    修复 = `377ea77` 信任根豁免（`_TRUST_ROOT_SCRIPTS`）；本探针**只观测、不复位**，
    职责是让「新增危险词 / 有人删掉豁免」立刻变红，而不是等下一个人再撞死锁。
    """

    def test_missing_cli_fails(self, tmp_path):
        from gk_self_check import check_cli_hook_executable
        r = check_cli_hook_executable(str(tmp_path))
        assert r["check"] == "cli_hook_executable"
        assert r["status"] == "FAIL"
        assert "missing" in r["detail"]

    def test_blocked_cli_fails(self, tmp_path):
        """反臂（红先语义）：CLI 被拦 = 非零退出 + `GATEKEEPER-BLOCK` ⟹ FAIL，不得假绿。"""
        (tmp_path / "gatekeeper-cli.sh").write_text(
            "#!/usr/bin/env bash\n"
            "echo 'GATEKEEPER-BLOCK: dangerous command: find -delete' >&2\n"
            "exit 1\n", encoding="utf-8")
        from gk_self_check import check_cli_hook_executable
        r = check_cli_hook_executable(str(tmp_path))
        assert r["status"] == "FAIL", r
        assert "rc=1" in r["detail"], r

    def test_zero_exit_without_registry_marker_fails(self, tmp_path):
        """反臂②：rc=0 但输出无命令注册表锚（`cmd_`）⟹ 仍 FAIL（防「碰巧 rc=0」假绿）。"""
        (tmp_path / "gatekeeper-cli.sh").write_text(
            "#!/usr/bin/env bash\necho 'nothing useful'\nexit 0\n", encoding="utf-8")
        from gk_self_check import check_cli_hook_executable
        r = check_cli_hook_executable(str(tmp_path))
        assert r["status"] == "FAIL", r

    def test_marker_present_but_blocked_fails(self, tmp_path):
        """反臂③：即便输出里有 `cmd_`，只要带 `GATEKEEPER-BLOCK` ⟹ 仍是 FAIL。"""
        (tmp_path / "gatekeeper-cli.sh").write_text(
            "#!/usr/bin/env bash\necho '### cmd_advance'\n"
            "echo 'GATEKEEPER-BLOCK: blocked' >&2\nexit 0\n", encoding="utf-8")
        from gk_self_check import check_cli_hook_executable
        r = check_cli_hook_executable(str(tmp_path))
        assert r["status"] == "FAIL", r

    def test_real_cli_passes(self):
        """正臂：仓库真实 CLI 可执行 ⟹ PASS（死锁复发的唯一守卫）。"""
        from gk_self_check import check_cli_hook_executable
        r = check_cli_hook_executable(str(Path(__file__).parent.parent))
        assert r["status"] == "PASS", r

    def test_run_all_registers_probe(self, tmp_state, monkeypatch):
        """挂载臂：run_all 聚合输出必须含 `cli_hook_executable`（防「函数在但没接线」）。"""
        import gk_self_check
        monkeypatch.setattr(gk_self_check, "check_tests",
                            lambda skill_dir: {"check": "tests", "status": "PASS"})
        monkeypatch.setattr(gk_self_check, "check_provider",
                            lambda: {"check": "provider", "status": "SKIP"})
        monkeypatch.setattr(gk_self_check, "check_cli_hook_executable",
                            lambda skill_dir: {"check": "cli_hook_executable", "status": "PASS"})
        out = gk_self_check.run_all(tmp_state, str(Path(__file__).parent.parent))
        assert "cli_hook_executable" in {c["check"] for c in out["checks"]}

