"""test_gk_plugin_manifest_redteam.py — 插件加载安全网红队测试（2026-11-04）。

攻击者视角：构造**假插件 / 恶意插件**，尝试突破 `gk_plugin_manifest` 的治理层拦截。
正向测试证明「正常插件能加载」，本文件证明「恶意声明进不来」（对齐
`references/plugin-loading-test-framework.md` §插件红队测试模板）。

攻击面 G 组（治理层，承接既有 A-F 供应链/调用门禁面）：

| 编号 | 攻击面 | 恶意载荷 | 期望拦截 |
|:--|:--|:--|:--|
| G1 | 幽灵登记 | 完全未登记的 id + 伪造 manifest 形状 | define 拒绝（unknown） |
| G2 | 身份混淆 | registry key = 别名，manifest.id = 已登记插件 | 拒绝（id/key 不一致） |
| G3 | 白名单回写 | `get_manifest()` 返回值追加能力后调用 | cap 仍拒绝（返回值是副本） |
| G4 | 快照回写 | `load_plugin()["manifest"]` 追加能力后调用 | cap 仍拒绝（返回值是副本） |
| G5 | 类型混淆 | `write=0` / `disabled=0` 等非 bool 值 | 拒绝（声明必须是 bool） |
| G6 | 空壳 undo | `write=True` + `undo="   "` | 拒绝（无实质回滚钩子） |
| G7 | 子串白名单 | `intercept="audit"`（字符串而非名单） | 拒绝 + `cap("aud")` 不得命中 |
| G8 | 空壳 integrity | `url=npm:` + `config.integrity="  "` | 拒绝（供应链 pin 未落实） |
| G9 | 崩溃诱导 | 非字符串 pid（list/dict/int/None） | fail-closed，不抛异常 |
| G10 | 残留注入 | 插件运行期重复把自己目录塞回 sys.path | 卸载后恢复载入前计数 |
| G11 | 停用旁路 | `disabled=True` 但能力在白名单 | cap 拒绝（纵深防御） |
| G12 | 假插件包 | 未登记插件目录内放带副作用 `audit.py` | 不注入 sys.path、不执行副作用 |

威胁模型边界（明确不属本层防护面）：
- 插件若已获得 Python 代码执行权，可直接改写 `gk_plugin_manifest.MANIFESTS`（同进程无隔离）；
  本层防的是**声明面**绕过，执行面隔离由 `isolate` 标记 + 外层沙箱承担。
- npm `integrity` 的**实际哈希对账**在 loader 接入 npm 源时实现；本层只强制「必须声明有效值」。

测试安全网 R1：只 patch 被测模块边界（`_DEV_SOURCE_DIRS` / `MANIFESTS` / `_ACTIVE`），
不 patch 标准库全局。每个用例前后恢复 `sys.path`，避免残留注入污染后续用例。
"""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_plugin_manifest as gpm


def _base_manifest(**over):
    """最小合法 manifest 模板（攻击用例只改需要投毒的那一项）。"""
    m = {
        "id": "evil",
        "name": "evil",
        "url": "pip:evil",
        "isolate": False,
        "intercept": ("analyze",),
        "config": {},
        "disabled": False,
        "write": False,
        "undo": None,
    }
    m.update(over)
    return m


@pytest.fixture(autouse=True)
def _isolate_state():
    """清 _ACTIVE + 快照/恢复 sys.path；夹具副作用显式声明：不触碰 MANIFESTS。"""
    gpm._ACTIVE.clear()
    saved = list(sys.path)
    yield
    sys.path[:] = saved
    gpm._ACTIVE.clear()


class TestG1GhostRegistration:
    def test_unregistered_id_rejected(self):
        """G1: 未登记 id 无法获得任何能力（Definition 74 登记制）。"""
        out = gpm.validate_manifest("ghost-plugin")
        assert out["ok"] is False
        assert any("unknown" in e for e in out["errors"])

    def test_unregistered_load_never_injects(self):
        """G1: 未登记插件 load 被拒且不产生 sys.path 注入。"""
        before = list(sys.path)
        out = gpm.load_plugin("ghost-plugin")
        assert out["ok"] is False
        assert "BLOCKED" in out["action"]
        assert sys.path == before


class TestG2IdentityConfusion:
    def test_alias_key_cannot_borrow_registered_id(self):
        """G2: 别名 key 冒用已登记 id（借壳取能力）→ 拒绝。"""
        evil = _base_manifest(id="bashpy-migrate", name="evil-alias")
        with patch.dict(gpm.MANIFESTS, {"evil-alias": evil}):
            out = gpm.validate_manifest("evil-alias")
        assert out["ok"] is False
        assert any("id" in e for e in out["errors"])

    def test_alias_key_cannot_load(self):
        evil = _base_manifest(id="bashpy-migrate")
        with patch.dict(gpm.MANIFESTS, {"evil-alias": evil}):
            out = gpm.load_plugin("evil-alias")
        assert out["ok"] is False
        assert "evil-alias" not in gpm._ACTIVE


class TestG3G4WhitelistWriteback:
    def test_get_manifest_result_is_detached_copy(self):
        """G3: 改写 get_manifest() 返回值不得污染能力白名单。"""
        m = gpm.get_manifest("bashpy-migrate")
        assert m is not None
        m["intercept"] = tuple(m["intercept"]) + ("rm_rf",)
        assert gpm.check_capability("bashpy-migrate", "rm_rf")["ok"] is False

    def test_load_result_manifest_is_detached_copy(self, tmp_path):
        """G4: 改写 load_plugin() 返回的 manifest 不得提权。"""
        with patch.object(gpm, "_DEV_SOURCE_DIRS", (str(tmp_path),)):
            out = gpm.load_plugin("bashpy-migrate")
        assert out["ok"] is True
        out["manifest"]["intercept"] = ("rm_rf",)
        out["manifest"]["write"] = False
        assert gpm.check_capability("bashpy-migrate", "rm_rf")["ok"] is False

    def test_nested_config_mutation_does_not_leak(self):
        """G3 补: 嵌套 config 也是副本（防经 config 回写 integrity 等 pin）。"""
        m = gpm.get_manifest("bashpy-migrate")
        m["config"]["integrity"] = "sha512-forged"
        assert "sha512-forged" not in str(gpm.get_manifest("bashpy-migrate")["config"])


class TestG5TypeConfusion:
    @pytest.mark.parametrize("bad_write", [0, 1, "false", "true"])
    def test_non_bool_write_rejected(self, bad_write):
        """G5: write 非 bool（如 0 恒假）→ 不得绕过 Theorem 7 的 undo 强制。"""
        evil = _base_manifest(id="evil", write=bad_write, undo=None)
        with patch.dict(gpm.MANIFESTS, {"evil": evil}):
            out = gpm.validate_manifest("evil")
        assert out["ok"] is False
        assert any("write" in e or "undo" in e for e in out["errors"])

    def test_non_bool_disabled_rejected(self):
        """G5: disabled 非 bool（如 0）→ 不得把已停用插件「解停用」。"""
        evil = _base_manifest(id="evil", disabled=0)
        with patch.dict(gpm.MANIFESTS, {"evil": evil}):
            out = gpm.validate_manifest("evil")
        assert out["ok"] is False
        assert any("disabled" in e for e in out["errors"])


class TestG6HollowUndo:
    @pytest.mark.parametrize("bad_undo", ["", "   ", "\t\n", None, 0])
    def test_write_plugin_with_blank_undo_rejected(self, bad_undo):
        """G6: undo 空白/空值 = 无实质回滚钩子 → 拒绝（Theorem 7）。"""
        evil = _base_manifest(id="evil", write=True, undo=bad_undo)
        with patch.dict(gpm.MANIFESTS, {"evil": evil}):
            out = gpm.validate_manifest("evil")
        assert out["ok"] is False
        assert any("undo" in e for e in out["errors"])

    def test_undo_string_still_accepted(self):
        """G6 对照: 合法的 "module:func" undo 仍放行（零回归）。"""
        ok = _base_manifest(id="evil", write=True, undo="pkg.mod:revert")
        with patch.dict(gpm.MANIFESTS, {"evil": ok}):
            assert gpm.validate_manifest("evil")["ok"] is True


class TestG7SubstringWhitelist:
    def test_string_intercept_rejected(self):
        """G7: intercept 写成字符串 → 名单语义被破坏（子串即命中）→ 拒绝。"""
        evil = _base_manifest(id="evil", intercept="audit")
        with patch.dict(gpm.MANIFESTS, {"evil": evil}):
            out = gpm.validate_manifest("evil")
        assert out["ok"] is False
        assert any("intercept" in e for e in out["errors"])

    def test_substring_capability_denied(self):
        """G7: 即便绕过 define，`cap("aud")` 也不得被子串命中放行。"""
        evil = _base_manifest(id="evil", intercept="audit")
        with patch.dict(gpm.MANIFESTS, {"evil": evil}):
            out = gpm.check_capability("evil", "aud")
        assert out["ok"] is False
        assert "whitelist" in out["error"] or "intercept" in out["error"]


class TestG8HollowIntegrity:
    @pytest.mark.parametrize("bad", ["", "   ", None, 0])
    def test_npm_blank_integrity_rejected(self, bad):
        """G8: npm 段 integrity 空白 → 供应链 pin 未落实 → 拒绝。"""
        evil = _base_manifest(id="evil", url="npm:@evil/pkg@1.0.0",
                              config={"integrity": bad})
        with patch.dict(gpm.MANIFESTS, {"evil": evil}):
            out = gpm.validate_manifest("evil")
        assert out["ok"] is False
        assert any("integrity" in e for e in out["errors"])


class TestG9CrashInduction:
    @pytest.mark.parametrize("bad_pid", [[], {}, 123, None, ["bashpy-migrate"]])
    def test_non_str_pid_fails_closed(self, bad_pid):
        """G9: 非字符串 pid 不得抛 TypeError（异常逃逸 = 调用方可能当作放行）。"""
        assert gpm.validate_manifest(bad_pid)["ok"] is False
        assert gpm.check_capability(bad_pid, "analyze")["ok"] is False
        assert gpm.load_plugin(bad_pid)["ok"] is False
        assert gpm.unload_plugin(bad_pid)["reverted"] is False

    def test_get_manifest_non_str_returns_none(self):
        assert gpm.get_manifest([]) is None


class TestG10ResidualInjection:
    def test_unload_heals_duplicate_injection(self, tmp_path):
        """G10: 插件卸载前重复注入自身目录 → 卸载恢复载入前出现次数（recover 不变性）。"""
        d = str(tmp_path)
        before = sys.path.count(d)
        with patch.object(gpm, "_DEV_SOURCE_DIRS", (d,)):
            out = gpm.load_plugin("bashpy-migrate")
            assert out["ok"] is True
            assert sys.path.count(d) == before + 1
            sys.path.insert(0, d)  # 恶意插件运行期再次注入
            un = gpm.unload_plugin("bashpy-migrate")
        assert un["reverted"] is True
        assert sys.path.count(d) == before


class TestG11DisabledBypass:
    def test_disabled_plugin_capability_denied(self):
        """G11: 已停用插件即便能力在旧白名单 → cap 也必须拒绝（纵深防御）。"""
        evil = _base_manifest(id="evil", disabled=True, intercept=("analyze",))
        with patch.dict(gpm.MANIFESTS, {"evil": evil}):
            out = gpm.check_capability("evil", "analyze")
        assert out["ok"] is False


class TestG12FakePluginPackage:
    def test_fake_plugin_package_not_imported_nor_injected(self, tmp_path):
        """G12: 未登记插件目录内的恶意 audit.py 不得被注入/导入/执行副作用。"""
        pkg = tmp_path / "zthl_bashpy_migrate"
        pkg.mkdir()
        marker = tmp_path / "pwned.txt"
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "audit.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('pwned', encoding='utf-8')\n"
            "def bomb_scan(*a, **k):\n    return {'pwned': True}\n",
            encoding="utf-8",
        )
        with patch.object(gpm, "_DEV_SOURCE_DIRS", (str(tmp_path),)):
            out = gpm.load_plugin("evil-fake-plugin")
        assert out["ok"] is False
        assert str(tmp_path) not in sys.path
        assert not marker.exists()
        assert "zthl_bashpy_migrate.audit" not in sys.modules


class TestCliRedTeam:
    def test_cli_denies_unknown(self, capsys):
        assert gpm.main(["cap", "ghost-plugin", "analyze"]) == 2
        assert "unknown" in capsys.readouterr().out

    def test_cli_denies_non_str_argv(self, capsys):
        """CLI 只拿到字符串；伪造空串/空白不得命中任何登记项。"""
        for pid in ("", " ", "bashpy-migrate "):
            assert gpm.main(["validate", pid]) == 2
        capsys.readouterr()
