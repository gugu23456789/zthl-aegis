#!/usr/bin/env python3
"""test_gk_gitnexus_launcher.py — A1 单一 launcher + 跨进程缓存的行为锁（2026-10-28）

覆盖：
  1. 缓存准入：写类子命令**永不**缓存；开关关闭/无 repo/无 HEAD sha ⟹ 不缓存。
  2. 命中不 spawn（monkeypatch `subprocess.Popen` 抛错也能返回），未命中 spawn 并落盘。
  3. 缓存键含 HEAD sha（sha 变 ⟹ 换键 ⟹ 不读到旧图）。
  4. `invalidate_cache()` 清空。
  5. `run_json` 的 strict 两态（rc≠0 → error / 忽略 rc 只解析 stdout）。
  6. 探测面为零：node/js 只读 env；posix 下 `D:\\...` 归一为 `/mnt/d/...`。

⚠ 2026-11-09：`run_raw` 已从 `subprocess.run` 迁到 `Popen`（独立进程组 + 整树击杀，
  见 `gk_gitnexus.py` 进程树回收段）⟹ 本文件的 spawn 替身**必须钉 `Popen`**；
  旧版钉 `run` 的 4 条臂因此从未真正拦截 spawn（真去起 `/fake/node.exe` ⟹ 恒 False）。
"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_gitnexus as gx  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_worker_pidfile(tmp_path, monkeypatch):
    """worker pidfile 落 tmp：测试**不得**写真实 `~/.gatekeeper`。"""
    monkeypatch.setattr(gx, "_WORKER_PIDFILE", tmp_path / "gitnexus-workers.json")
    yield


@pytest.fixture
def cache_env(monkeypatch, tmp_path):
    """隔离缓存目录 + 真值开关，**不触碰** ~/.gatekeeper。"""
    monkeypatch.setenv("GK_GX_CACHE_DIR", str(tmp_path / "gxcache"))
    monkeypatch.setenv("GK_GX_CACHE", "1")
    monkeypatch.setenv("GX_REPO", "demo-repo")
    monkeypatch.setenv("GX_REPO_DIR", str(tmp_path))
    monkeypatch.setenv("GX_NODE", "/fake/node.exe")
    monkeypatch.setenv("GX_JS", r"C:\fake\index.js")
    monkeypatch.setattr(gx, "head_sha", lambda d="": "deadbeef" * 5)
    return tmp_path / "gxcache"


class _FakePopen:
    """`run_raw` 的 spawn 替身（`Popen` 契约：argv/pid/returncode/communicate）。"""

    def __init__(self, argv, out="", err="", rc=0, sink=None, **_k):
        self.argv = argv
        self.pid = 424242
        self.returncode = rc
        self._out, self._err = out, err
        if sink is not None:
            sink.append(argv)

    def communicate(self, timeout=None):
        return self._out, self._err


def _popen(out="", err="", rc=0, sink=None):
    """→ 可作 `gx.subprocess.Popen` 替身的工厂（固定单次返回）。"""
    return lambda argv, **k: _FakePopen(argv, out=out, err=err, rc=rc, sink=sink)


# ─── 1. 缓存准入 ───────────────────────────────────────────────────────────

def test_write_subcommands_never_cacheable(cache_env):
    for cmd in ("analyze", "publish", "index", "init", "delete"):
        assert gx.cacheable([cmd]) is False, f"{cmd} 改库，禁缓存"
    assert gx.cacheable(["query", "foo"]) is True
    assert gx.cacheable(["context", "Bar"]) is True


def test_flag_off_disables_cache(cache_env, monkeypatch):
    monkeypatch.delenv("GK_GX_CACHE", raising=False)
    assert gx.cacheable(["query", "foo"]) is False
    assert gx.cacheable(["query", "foo"], force=True) is True


def test_no_repo_or_no_head_disables_cache(cache_env, monkeypatch):
    monkeypatch.delenv("GX_REPO", raising=False)
    assert gx.cacheable(["query", "foo"]) is False, "repo 不可解析 ⟹ 不缓存（不猜）"
    monkeypatch.setenv("GX_REPO", "demo-repo")
    monkeypatch.setattr(gx, "head_sha", lambda d="": "")
    assert gx.cacheable(["query", "foo"]) is False, "HEAD 不可解析 ⟹ 不缓存（防陈旧图）"


# ─── 2/3. 命中不 spawn / 未命中落盘 / 键含 HEAD ────────────────────────────

def test_cache_hit_skips_spawn(cache_env, monkeypatch):
    key = gx._cache_key(["query", "foo"], "demo-repo", "deadbeef" * 5)
    gx._cache_put(key, '{"markdown":"| c |","row_count":1}')

    def _boom(*a, **k):
        raise AssertionError("缓存命中却仍然 spawn 了 node")

    monkeypatch.setattr(gx.subprocess, "Popen", _boom)
    ok, out, err, cached = gx.run_raw(["query", "foo"])
    assert (ok, cached) == (True, True)
    assert "row_count" in out


def test_cache_miss_spawns_and_writes(cache_env, monkeypatch):
    calls = []
    monkeypatch.setattr(gx.subprocess, "Popen",
                        _popen(out='{"row_count":7}\n', sink=calls))
    ok, out, _err, cached = gx.run_raw(["query", "bar"])
    assert (ok, cached) == (True, False)
    assert calls and calls[0][-2:] == ["query", "bar"], f"argv 未透传: {calls}"
    # 第二次同参与同 HEAD ⟹ 命中，不再 spawn
    ok2, out2, _e2, cached2 = gx.run_raw(["query", "bar"])
    assert cached2 is True and out2 == out


def test_cache_key_changes_with_head(cache_env, monkeypatch):
    monkeypatch.setattr(gx.subprocess, "Popen", _popen(out='{"n":1}\n'))
    gx.run_raw(["query", "baz"])
    # 换 HEAD ⟹ 键变 ⟹ 必须重新 spawn（否则会读到旧图）
    monkeypatch.setattr(gx, "head_sha", lambda d="": "cafebabe" * 5)
    seen = []
    monkeypatch.setattr(gx.subprocess, "Popen",
                        _popen(out='{"n":2}\n', sink=seen))
    ok, out, _e, cached = gx.run_raw(["query", "baz"])
    assert cached is False and seen, "HEAD 变化后仍命中旧缓存"
    assert json.loads(out)["n"] == 2


# ─── 4. 失效 ──────────────────────────────────────────────────────────────

def test_invalidate_cache_removes_entries(cache_env):
    gx._cache_put(gx._cache_key(["query", "x"], "demo-repo", "deadbeef" * 5), "{}")
    assert gx.invalidate_cache() >= 1
    assert not list(gx._cache_dir().glob("*.json"))


# ─── 5. run_json strict 两态 ───────────────────────────────────────────────

def test_run_json_strict_reports_rc_error(monkeypatch):
    monkeypatch.setenv("GX_NODE", "/fake/node.exe")
    monkeypatch.setenv("GX_JS", r"C:\fake\index.js")
    monkeypatch.setattr(gx.subprocess, "Popen",
                        _popen(out="boom", err="bad flag", rc=1))
    d = gx.run_json(["cypher", "x"], strict=True)
    assert "error" in d


def test_run_json_non_strict_parses_stdout(monkeypatch):
    monkeypatch.setenv("GX_NODE", "/fake/node.exe")
    monkeypatch.setenv("GX_JS", r"C:\fake\index.js")
    monkeypatch.setattr(gx.subprocess, "Popen",
                        _popen(out='{"ok":1}', rc=3))
    d = gx.run_json(["detect-changes", "-s", "compare"], strict=False)
    assert d == {"ok": 1}


def test_run_json_text_fallback(monkeypatch):
    monkeypatch.setenv("GX_NODE", "/fake/node.exe")
    monkeypatch.setenv("GX_JS", r"C:\fake\index.js")
    monkeypatch.setattr(gx.subprocess, "Popen",
                        _popen(out="变更：1 个文件\n", rc=0))
    d = gx.run_json(["detect-changes"], strict=False)
    assert d == {"raw": "变更：1 个文件\n"}


# ─── 6. 探测面为零 ────────────────────────────────────────────────────────

def test_env_missing_fails_loud(monkeypatch):
    monkeypatch.delenv("GX_NODE", raising=False)
    monkeypatch.delenv("GX_JS", raising=False)
    d = gx.run_json(["query", "x"])
    assert "error" in d and "GX_NODE" in d["error"]


def test_node_normalizes_on_posix(monkeypatch):
    monkeypatch.setenv("GX_NODE", r"D:\Program Files\nodejs\node.exe")
    if os.name == "posix":
        assert gx.node_exe() == "/mnt/d/Program Files/nodejs/node.exe"
    else:
        assert gx.node_exe() == r"D:\Program Files\nodejs\node.exe"


# ─── 7. bash 通道委托（A1 收口，2026-10-28）────────────────────────────────
# 病：python 侧收敛成一条 launcher 后，`gatekeeper-cli.sh::_run_gitnexus_raw` 仍**自己** spawn
#   `node <js> <args>` ⟹ 第二条 spawn 通道，identity cache / analyze 钉 cpu / 超时三策略双写。
# 修：bash 只做宿主编排（node 定位 / js 路径 / repo 目录 / cwd），spawn 委托 `gk_gitnexus.py run`。

_CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _raw_body() -> str:
    import re
    src = _CLI.read_text(encoding="utf-8")
    m = re.search(r"\n(_run_gitnexus_raw\(\)\s*\{.*?\n\})\n", src, re.DOTALL)
    assert m, "_run_gitnexus_raw 结构变了（改名/拆分）⟹ 同步本测试"
    return m.group(1)


def test_bash_channel_delegates_to_launcher():
    body = _raw_body()
    assert "gk_gitnexus.py" in body, "bash 侧未委托 python launcher（第二 spawn 通道复活）"
    assert " run --timeout" in body, "委托时未透传 --timeout（超时语义会退回默认）"


def test_bash_channel_has_no_direct_node_spawn():
    body = _raw_body()
    assert '"$_gx_js_arg" $gx_args' not in body, "bash 仍在直接 spawn node（策略双写）"
    assert "timeout \"${GK_GX_TIMEOUT:-300}\" \"$_node_exe\"" not in body


def test_cli_run_forwards_argv_timeout_cwd(monkeypatch, capsys):
    seen = {}

    def fake_run_raw(args, **kw):
        seen["args"] = list(args)
        seen.update(kw)
        return True, "OUT\n", "", False

    monkeypatch.setattr(gx, "run_raw", fake_run_raw)
    rc = gx.main(["run", "--timeout", "12", "--cwd", "/tmp/x", "--", "status", "-r", "r1"])
    assert rc == 0
    assert seen["args"] == ["status", "-r", "r1"]
    assert seen["timeout"] == 12 and seen["cwd"] == "/tmp/x"
    assert capsys.readouterr().out == "OUT\n"


def test_cli_run_cache_flags(monkeypatch):
    seen = {}

    def fake_run_raw(args, **kw):
        seen.update(kw)
        return True, "", "", False

    monkeypatch.setattr(gx, "run_raw", fake_run_raw)
    gx.main(["run", "--cache", "--", "status"])
    assert seen["cache"] is True
    gx.main(["run", "--no-cache", "--", "status"])
    assert seen["cache"] is False
    gx.main(["run", "--", "status"])
    assert seen["cache"] is None      # 未显式指定 ⟹ 交回 `GK_GX_CACHE` 自动判定


@pytest.mark.parametrize("argv", [[], ["bogus"], ["run"], ["run", "--timeout", "x", "--", "status"]])
def test_cli_usage_errors(argv):
    assert gx.main(argv) == 2


# ─── 8. 形态断言（2026-11-01 owner 裁定 B 方案）─────────────────────────────
# 病：Linux 形态 node spawn Windows 原生包（`core-win32-x64`）⟹ `invalid ELF header`、
#   图调用输出恒空 ⟹ runner 仍写 528B 兜底模板（空壳报告）。修：执行前断言 node 形态
#   与包形态一致；可自动纠正则改写 `GX_NODE` 并留 WARN，纠正不了 ⟹ fail-closed（rc=2）。

def _fake_pkg(tmp_path, arch):
    """伪 gitnexus 安装：`<tmp>/node_modules/gitnexus/dist/cli/index.js` + 指定 arch 原生包。"""
    pkg = tmp_path / "node_modules" / "gitnexus"
    (pkg / "dist" / "cli").mkdir(parents=True)
    (pkg / "dist" / "cli" / "index.js").write_text("", encoding="utf-8")
    (pkg / "package.json").write_text("{}", encoding="utf-8")
    (pkg / "node_modules" / "@ladybugdb" / ("core-" + arch)).mkdir(parents=True)
    return str(pkg / "dist" / "cli" / "index.js")


def test_arch_guard_noop_without_env(monkeypatch):
    monkeypatch.delenv("GX_NODE", raising=False)
    monkeypatch.delenv("GX_JS", raising=False)
    assert gx.arch_guard() == ""


def test_arch_guard_passes_on_same_side(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GX_NODE", "/fake/win/node.exe")
    monkeypatch.setenv("GX_JS", _fake_pkg(tmp_path, "win32-x64"))
    monkeypatch.setattr(gx, "_node_form", lambda n: "win32-x64")
    assert gx.arch_guard() == ""
    assert os.environ["GX_NODE"] == "/fake/win/node.exe"      # 同侧不改写
    assert capsys.readouterr().err == ""


def test_arch_guard_autocorrects_to_package_side(tmp_path, monkeypatch, capsys):
    """混血 ⟹ 包侧权威：发现同侧 node 并改写 GX_NODE，只留 WARN（不阻断）。"""
    monkeypatch.setenv("GX_NODE", "/usr/bin/node")
    monkeypatch.setenv("GX_JS", _fake_pkg(tmp_path, "win32-x64"))
    monkeypatch.setattr(gx, "_node_form",
                        lambda n: "linux-x64" if n == "/usr/bin/node" else "win32-x64")
    monkeypatch.setattr(gx, "_discover_node", lambda form: "/fake/win/node.exe")
    assert gx.arch_guard() == ""
    assert os.environ["GX_NODE"] == "/fake/win/node.exe"
    assert "自动改用同侧 node" in capsys.readouterr().err


def test_arch_guard_fail_closed_when_no_same_side_node(tmp_path, monkeypatch):
    monkeypatch.setenv("GX_NODE", "/usr/bin/node")
    monkeypatch.setenv("GX_JS", _fake_pkg(tmp_path, "win32-x64"))
    monkeypatch.setattr(gx, "_node_form", lambda n: "linux-x64")
    monkeypatch.setattr(gx, "_discover_node", lambda form: "")
    out = gx.arch_guard()
    assert "形态不一致" in out and "core-win32-x64" in out


def test_cli_run_blocks_on_arch_mismatch(tmp_path, monkeypatch, capsys):
    """混血且无法纠正 ⟹ `run` 在 spawn 前就拒绝（rc=2，不产生空壳输出）。"""
    monkeypatch.setenv("GX_NODE", "/usr/bin/node")
    monkeypatch.setenv("GX_JS", _fake_pkg(tmp_path, "win32-x64"))
    monkeypatch.setattr(gx, "_node_form", lambda n: "linux-x64")
    monkeypatch.setattr(gx, "_discover_node", lambda form: "")
    called = {"spawn": 0}

    def _boom(*a, **kw):
        called["spawn"] += 1
        return True, "", "", False

    monkeypatch.setattr(gx, "run_raw", _boom)
    rc = gx.main(["run", "--", "status"])
    assert rc == 2 and called["spawn"] == 0
    assert "GX_ARCH_MISMATCH" in capsys.readouterr().out


def test_arch_guard_source_has_no_machine_paths():
    """公开包安全：形态发现必须**发现式**（不得写死本机 node / gitnexus 路径）。"""
    src = (Path(__file__).parent / "gk_gitnexus.py").read_text(encoding="utf-8", errors="replace")
    for bad in ("D:\\Program Files", "/usr/bin/node", "/opt/venv/bin/python",
                "<home>", "AppData\\Local\\Temp\\gk-gitnexus-identity"):
        assert bad not in src, "公开源码残留机器绝对路径: %s" % bad


# ── GPU 设备策略（2026-11-08，最小接线 + 显存闸）──────────────────────────
def test_analyze_gpu_request_falls_back_when_vram_low(monkeypatch):
    import gk_hub_scheduler as hs

    monkeypatch.setenv("GITNEXUS_EMBEDDING_DEVICE", "dml")
    monkeypatch.setattr(hs, "gpu_admit", lambda *a, **k: {"ok": False, "reason": "low_vram"})
    env = gx._build_env("analyze --embeddings")
    assert env["GITNEXUS_EMBEDDING_DEVICE"] == "cpu", "显存不足必须回落 cpu（不静默 OOM）"
    assert env["GK_GITNEXUS_GPU_FALLBACK"] == "low_vram"


def test_analyze_gpu_request_kept_when_vram_ok(monkeypatch):
    import gk_hub_scheduler as hs

    monkeypatch.setenv("GITNEXUS_EMBEDDING_DEVICE", "dml")
    monkeypatch.setattr(hs, "gpu_admit", lambda *a, **k: {"ok": True, "gpu": {"free_mb": 7000}})
    env = gx._build_env("analyze --embeddings")
    assert env["GITNEXUS_EMBEDDING_DEVICE"] == "dml"
    assert "GK_GITNEXUS_GPU_FALLBACK" not in env


def test_analyze_default_pins_cpu_without_probe(monkeypatch):
    """默认 cpu 路径不得探 GPU（沙箱里驱动触碰会被判 restricted）。"""
    import gk_hub_scheduler as hs

    monkeypatch.delenv("GITNEXUS_EMBEDDING_DEVICE", raising=False)
    called = {"n": 0}

    def _spy(*a, **k):
        called["n"] += 1
        return {"ok": True}

    monkeypatch.setattr(hs, "gpu_admit", _spy)
    env = gx._build_env("analyze")
    assert env["GITNEXUS_EMBEDDING_DEVICE"] == "cpu"
    assert called["n"] == 0


def test_non_analyze_subcommand_does_not_set_device(monkeypatch):
    monkeypatch.delenv("GITNEXUS_EMBEDDING_DEVICE", raising=False)
    env = gx._build_env("status")
    assert "GITNEXUS_EMBEDDING_DEVICE" not in env
