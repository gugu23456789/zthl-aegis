"""test_gk_plugin_manifest.py — 插件 manifest + 生命周期测试（2026-08-25）。

覆盖: manifest 查询 / validate 门禁（Theorem 7 write 分级）/ 能力白名单 /
load-unload 往返（sys.path 快照回滚）/ unload 幂等 / CLI 入口。
安全网 R1: 只 patch 被测模块边界（_DEV_SOURCE_DIRS / MANIFESTS 模块级名），
不 patch 标准库全局。
"""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_plugin_manifest as gpm


@pytest.fixture(autouse=True)
def _clean_active():
    gpm._ACTIVE.clear()
    yield
    gpm._ACTIVE.clear()


class TestGetManifest:
    def test_known_plugin(self):
        m = gpm.get_manifest("bashpy-migrate")
        assert m is not None
        # 对齐 Definition 74 六字段
        for key in ("id", "url", "isolate", "intercept", "config", "disabled"):
            assert key in m

    def test_unknown_plugin(self):
        assert gpm.get_manifest("nope") is None


class TestValidateManifest:
    def test_known_pass(self):
        out = gpm.validate_manifest("bashpy-migrate")
        assert out["ok"] is True
        assert out["errors"] == []

    def test_unknown_blocked(self):
        out = gpm.validate_manifest("nope")
        assert out["ok"] is False
        assert any("unknown" in e for e in out["errors"])

    def test_disabled_blocked(self):
        with patch.dict("gk_plugin_manifest.MANIFESTS",
                        {"x": {"id": "x", "write": False, "undo": None,
                               "disabled": True, "intercept": ()}}):
            out = gpm.validate_manifest("x")
        assert out["ok"] is False
        assert any("disabled" in e for e in out["errors"])

    def test_write_plugin_without_undo_blocked(self):
        """Theorem 7 代码级强制: write=true 无 undo → 拒绝加载（DSH 400G 事故模式）。"""
        with patch.dict("gk_plugin_manifest.MANIFESTS",
                        {"w": {"id": "w", "write": True, "undo": None,
                               "disabled": False, "intercept": ()}}):
            out = gpm.validate_manifest("w")
        assert out["ok"] is False
        assert any("undo" in e for e in out["errors"])

    def test_write_plugin_with_undo_pass(self):
        with patch.dict("gk_plugin_manifest.MANIFESTS",
                        {"w": {"id": "w", "write": True, "undo": "pkg.mod:revert",
                               "disabled": False, "intercept": ()}}):
            out = gpm.validate_manifest("w")
        assert out["ok"] is True


class TestCheckCapability:
    def test_whitelisted(self):
        out = gpm.check_capability("bashpy-migrate", "verify")
        assert out["ok"] is True

    def test_lifecycle_whitelisted(self):
        """生命周期子命令（2026-08-27 统一入口扩展）在白名单内。"""
        for cap in ("status", "check", "upgrade", "rollback"):
            out = gpm.check_capability("bashpy-migrate", cap)
            assert out["ok"] is True, cap

    def test_not_in_whitelist(self):
        """白名单外能力拒绝（对齐 Cordis §6.3 能力最小化）。"""
        out = gpm.check_capability("bashpy-migrate", "rm_rf")
        assert out["ok"] is False
        assert "whitelist" in out["error"]

    def test_unknown_plugin(self):
        out = gpm.check_capability("nope", "analyze")
        assert out["ok"] is False


class TestLoadUnloadRoundtrip:
    def test_load_injects_dev_dir_and_unload_restores(self, tmp_path):
        """load → dev 源注入 sys.path；unload → 恢复（Theorem 7 recover 不变性）。"""
        with patch.object(gpm, "_DEV_SOURCE_DIRS", (str(tmp_path),)):
            out = gpm.load_plugin("bashpy-migrate")
        assert out["ok"] is True
        assert out["status"] == "active"
        assert str(tmp_path) in sys.path
        assert "bashpy-migrate" in gpm._ACTIVE

        out = gpm.unload_plugin("bashpy-migrate")
        assert out["ok"] is True
        assert out["reverted"] is True
        assert str(tmp_path) not in sys.path
        assert "bashpy-migrate" not in gpm._ACTIVE

    def test_load_validate_gate_blocks_disabled(self):
        """define 门禁未过 → load 拒绝且不注入。"""
        with patch.dict("gk_plugin_manifest.MANIFESTS",
                        {"x": {"id": "x", "write": False, "undo": None,
                               "disabled": True, "intercept": ()}}):
            out = gpm.load_plugin("x")
        assert out["ok"] is False
        assert "BLOCKED" in out["action"]
        assert "x" not in gpm._ACTIVE

    def test_unload_idempotent(self):
        out = gpm.unload_plugin("bashpy-migrate")
        assert out["ok"] is True
        assert out["reverted"] is False

    def test_double_unload_safe(self, tmp_path):
        with patch.object(gpm, "_DEV_SOURCE_DIRS", (str(tmp_path),)):
            gpm.load_plugin("bashpy-migrate")
            first = gpm.unload_plugin("bashpy-migrate")
            second = gpm.unload_plugin("bashpy-migrate")
        assert first["reverted"] is True
        assert second["reverted"] is False
        assert str(tmp_path) not in sys.path


class TestDshEcosystemAdapter:
    """DSH 生态插件对接（2026-08-25）: 模拟 '@deepseek-ai/dsh-*' npm 插件登记到
    manifest 后，插件类标准安全网必须依然生效——
    未登记拒绝 / 白名单外能力拒绝 / write 无 undo 拒绝（对齐 cordis_define→run 前置门禁）。
    """

    def test_unregistered_dsh_plugin_rejected(self):
        """DSH 生态插件未登记 → define 门禁拒绝（能力最小化: 未登记入口无能力）。"""
        out = gpm.validate_manifest("@deepseek-ai/dsh-tool-fs")
        assert out["ok"] is False
        assert any("unknown" in e for e in out["errors"])

    def test_registered_dsh_plugin_capability_gate(self):
        """登记 DSH 插件后: 白名单内能力放行，白名单外（如 shell）仍被拒。"""
        with patch.dict(gpm.MANIFESTS, {
            "dsh-tool-fs": {
                "id": "dsh-tool-fs",
                "name": "@deepseek-ai/dsh-tool-fs",
                "url": "npm:@deepseek-ai/dsh-tool-fs",
                "isolate": True,          # 对齐 DSH sandbox: 需要沙箱执行边界
                "intercept": ("read", "edit"),
                "config": {"integrity": "pnpm-lockfile"},
                "disabled": False,
                "write": True,
                "undo": "dsh_tool_fs:revert",
            }}):
            assert gpm.validate_manifest("dsh-tool-fs")["ok"] is True
            assert gpm.check_capability("dsh-tool-fs", "read")["ok"] is True
            out = gpm.check_capability("dsh-tool-fs", "shell")
            assert out["ok"] is False
            assert "whitelist" in out["error"]

    def test_registered_dsh_plugin_write_requires_undo(self):
        """DSH 可写插件（fs 写/编辑）无 undo → 拒绝加载（Theorem 7）。"""
        with patch.dict(gpm.MANIFESTS, {
            "dsh-tool-fs": {
                "id": "dsh-tool-fs", "name": "@deepseek-ai/dsh-tool-fs",
                "url": "npm:@deepseek-ai/dsh-tool-fs", "isolate": True,
                "intercept": ("read", "edit"), "config": {},
                "disabled": False, "write": True, "undo": None,
            }}):
            out = gpm.validate_manifest("dsh-tool-fs")
        assert out["ok"] is False
        assert any("undo" in e for e in out["errors"])


class TestNpmSupplyChainPin:
    """npm 供应链 pin（2026-08-25 登记）: DSH 生态 npm 插件必须登记 config.integrity。

    对齐 Python 侧 _RELEASE_PINS 的 SHA256 pin 语义——npm 包供应链保护 = pnpm lockfile
    integrity；不登记 = 供应链不可信 → 拒绝加载（DSH 400G 事故供应链投毒面）。
    """

    _NPM_BASE = {
        "dsh-npm-plugin": {
            "id": "dsh-npm-plugin",
            "name": "@example/dsh-npm-plugin",
            "url": "npm:@example/dsh-npm-plugin@1.0.0",
            "isolate": True,
            "intercept": ("probe",),
            "config": {"integrity": "sha512-<pnpm-lockfile-hash>"},
            "disabled": False,
            "write": False,
            "undo": None,
        },
    }

    def test_npm_plugin_without_integrity_blocked(self):
        """url=npm: 但 config.integrity 缺失 → 拒绝（供应链 pin 缺口已封）。"""
        m = dict(self._NPM_BASE["dsh-npm-plugin"])
        m = {**m, "config": {}}
        with patch.dict(gpm.MANIFESTS, {"dsh-npm-plugin": m}):
            out = gpm.validate_manifest("dsh-npm-plugin")
        assert out["ok"] is False
        assert any("integrity" in e for e in out["errors"])

    def test_npm_plugin_with_integrity_pass(self):
        """url=npm: 且 config.integrity 已登记 → 通过 define 门禁。"""
        with patch.dict(gpm.MANIFESTS, self._NPM_BASE):
            out = gpm.validate_manifest("dsh-npm-plugin")
        assert out["ok"] is True

    def test_non_npm_plugin_unaffected(self):
        """纯 pip 源插件（url 各 | 段均非 npm:）不受 integrity 强制影响（零回归）。"""
        with patch.dict(gpm.MANIFESTS, {
            "pip-only-plugin": {
                "id": "pip-only-plugin", "name": "zthl-x",
                "url": "pip:zthl-x | dev:${ZTHL_BASHPY_DIR}",
                "isolate": False, "intercept": ("probe",),
                "config": {}, "disabled": False, "write": False, "undo": None,
            }}):
            out = gpm.validate_manifest("pip-only-plugin")
        assert out["ok"] is True

    def test_registered_bashpy_manifest_npm_segment_passes(self):
        """真实登记: bashpy-migrate url 含 npm: 段 + config.integrity（sha512 tarball）→ PASS。"""
        with patch.object(gpm, "_DEV_SOURCE_DIRS", ()):
            out = gpm.validate_manifest("bashpy-migrate")
        assert out["ok"] is True

    def test_npm_segment_without_integrity_blocked_multi_source(self):
        """url 多段源（pip | npm）但 config.integrity 缺失 → 按段检查拒绝 npm 段。"""
        with patch.dict(gpm.MANIFESTS, {
            "multi": {
                "id": "multi", "name": "@example/multi",
                "url": "pip:zthl-x | npm:@example/dsh-x@0.1.0",
                "isolate": False, "intercept": ("probe",),
                "config": {}, "disabled": False, "write": False, "undo": None,
            }}):
            out = gpm.validate_manifest("multi")
        assert out["ok"] is False
        assert any("integrity" in e for e in out["errors"])

    def test_npm_segment_with_integrity_pass_multi_source(self):
        """url 多段源 + config.integrity 已登记 → PASS。"""
        with patch.dict(gpm.MANIFESTS, {
            "multi": {
                "id": "multi", "name": "@example/multi",
                "url": "pip:zthl-x | npm:@example/dsh-x@0.1.0",
                "isolate": False, "intercept": ("probe",),
                "config": {"integrity": "sha512-abc123"},
                "disabled": False, "write": False, "undo": None,
            }}):
            out = gpm.validate_manifest("multi")
        assert out["ok"] is True


class TestCli:
    def test_validate_exit_2_on_block(self, capsys):
        code = gpm.main(["validate", "nope"])
        assert code == 2
        assert "unknown" in capsys.readouterr().out

    def test_cap_exit_0_on_allow(self, capsys):
        code = gpm.main(["cap", "bashpy-migrate", "audit"])
        assert code == 0

    def test_cap_exit_2_on_deny(self, capsys):
        code = gpm.main(["cap", "bashpy-migrate", "evil"])
        assert code == 2
        assert "whitelist" in capsys.readouterr().out

    def test_list_contains_registered(self, capsys):
        code = gpm.main(["list"])
        assert code == 0
        assert "bashpy-migrate" in capsys.readouterr().out


class TestGitnexusSkillsRegistration:
    """F-REV-101（2026-09-17，用户裁定「101 可以」）：gitnexus 官方 skills 纳入 manifest 治理。

    与 ccf-a-skills 同为**外部内容源**，但登记面不同 —— CCF-A 是 prompt-based skill（登记**能力**），
    本项是 npm 包 gitnexus **自带的文档**（登记**内容源 + 消费方 + 能力面**）。
    """

    PID = "gitnexus-skills"

    def test_registered_and_validates(self):
        assert gpm.get_manifest(self.PID) is not None
        out = gpm.validate_manifest(self.PID)
        assert out["ok"] is True, out["errors"]

    def test_read_only_probe_plugin(self):
        """探测式只读（write=False, undo=None）—— 对齐 Theorem 7：f = id, 免逆。"""
        m = gpm.get_manifest(self.PID)
        assert m["write"] is False
        assert m["undo"] is None
        assert m["disabled"] is False

    def test_intercept_matches_runner_topic_whitelist(self):
        """**核心守护**：声明面（manifest.intercept）与实际面（runner topic 白名单）必须等值。

        这条把"两处事实源"变成机检等值关系（同 TOOL_REGISTRY ↔ valid_tools 的既有守护模式）：
        只改 runner 加 topic 而忘了登记 → 本测试红；反之亦然。
        """
        import subagent_runner as sr
        assert set(gpm.get_manifest(self.PID)["intercept"]) == set(sr._GX_SKILLS_TOPICS)

    def test_intercept_has_twelve_topics(self):
        """npm 包自带 12 份（8 单文件 md + plan/review/work/lfg 四个多文件 skill）。"""
        assert len(gpm.get_manifest(self.PID)["intercept"]) == 12

    @pytest.mark.parametrize("cap", ["guide", "impact-analysis", "taint-analysis", "lfg"])
    def test_capability_whitelisted(self, cap):
        assert gpm.check_capability(self.PID, cap)["ok"] is True

    def test_capability_outside_whitelist_rejected(self):
        """路径穿越/未知 topic 不在白名单 → 拒绝（对齐 Cordis §6.3 能力最小化）。"""
        out = gpm.check_capability(self.PID, "../../etc/passwd")
        assert out["ok"] is False
        assert "whitelist" in out["error"]

    def test_url_has_no_npm_segment(self):
        """⚠ url **刻意**不含 `npm:` 段 —— 因 tarball sha512 本机无法离线取得、尚未登记；
        含 `npm:` 会被 validate 的门禁**正确拒绝**（不规避门禁，缺口靠 config.pinning_gap 显式登记）。

        本测试锁定"缺口是明示的、而非靠绕门禁换来"：日后补上 integrity 时，可把 url 改为 `npm:`
        并同步删除本测试 —— 届时是**显式改动**，不可悄悄绕过。
        """
        segs = [s.strip() for s in gpm.get_manifest(self.PID)["url"].split("|")]
        assert not [s for s in segs if s.startswith("npm:")]

    def test_pinning_gap_explicitly_recorded(self):
        """供应链缺口必须显式落在 config 里（不静默）。"""
        cfg = gpm.get_manifest(self.PID)["config"]
        assert "pinning_gap" in cfg
        assert "sha512" in cfg["pinning_gap"]

    def test_consumer_recorded(self):
        """消费方（谁在用这份内容源）必须登记，否则登记只是装饰。"""
        assert gpm.get_manifest(self.PID)["config"]["entry"] == "subagent_runner:gx_guide_gk"

    def test_listed_by_cli(self, capsys):
        assert gpm.main(["list"]) == 0
        assert self.PID in capsys.readouterr().out
