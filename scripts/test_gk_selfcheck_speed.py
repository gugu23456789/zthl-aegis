#!/usr/bin/env python3
"""红先臂：self-check **提速不降判决**（2026-11-01）。

背景（实测）：self-check 全量 80.8s，其中 `check_gitnexus` 单项 **60.0s**（本机 `gitnexus status`
挂起，被 60s 超时兜底且判 FAIL）；`check_tests` 无条件跑全部 575+ 测试文件 + 180s 超时 ⟹ 必超时 ⟹
恒 FAIL「pytest 超时」。两项都属「环境卡顿被当门禁红」，不是真缺陷。

判据：
  1. `check_gitnexus` 默认**不派子进程**（读 `.gitnexus` 元数据）：有索引 ⟹ PASS + `index_age_s`，
     无索引 ⟹ WARN「index missing」；显式 `GK_SELFCHECK_GITNEXUS_PROBE=cli` 才深探；
  2. `check_tests` 三档：`skip` ⟹ SKIP；`quick`（缺省）⟹ 只跑快速子集，且子进程 env
     **强制 `GK_SELFCHECK_TESTS=skip`**（禁 self-check 套娃）；
  3. **超时 ⟹ WARN(inconclusive)**，不再 FAIL；pytest 缺失 ⟹ SKIP；rc≠0 ⟹ FAIL（硬门禁保留）。
"""
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_self_check as SC  # noqa: E402


# ── ① gitnexus：默认零子进程 ─────────────────────────────────────────────────

def _boom(*a, **k):
    raise AssertionError("check_gitnexus 默认路径不得派子进程（应读元数据）")


def test_gitnexus_metadata_pass_without_subprocess(tmp_path, monkeypatch):
    gx = tmp_path / ".gitnexus"
    gx.mkdir()
    (gx / "gitnexus.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(SC.subprocess, "run", _boom)
    r = SC.check_gitnexus(str(tmp_path))
    assert r["status"] == "PASS" and r["probe"] == "metadata", r
    assert "index_age_s" in r, r


def test_gitnexus_missing_index_is_warn(tmp_path, monkeypatch):
    monkeypatch.setattr(SC.subprocess, "run", _boom)
    r = SC.check_gitnexus(str(tmp_path))
    assert r["status"] == "WARN" and "index missing" in r["detail"], r


def test_gitnexus_deep_probe_opt_in_and_timeout_is_warn(tmp_path, monkeypatch):
    gx = tmp_path / ".gitnexus"
    gx.mkdir()
    (gx / "meta.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("GK_SELFCHECK_GITNEXUS_PROBE", "cli")

    def _timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="node", timeout=20)

    monkeypatch.setattr(SC.subprocess, "run", _timeout)
    r = SC.check_gitnexus(str(tmp_path))
    assert r["status"] == "WARN" and r["probe"] == "cli", r
    assert "不可判" in r["detail"], r


# ── ② / ③ check_tests 三档 + 超时语义 ───────────────────────────────────────

class _FakeRun:
    """subprocess.run 替身：pytest 探测 OK，正式跑返回指定 rc / 抛超时。"""

    def __init__(self, rc=0, timeout=False):
        self.calls, self.rc, self.timeout = [], rc, timeout

    def __call__(self, cmd, **kw):
        self.calls.append((list(cmd), dict(kw)))
        if "import pytest" in " ".join(cmd):
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if self.timeout:
            raise subprocess.TimeoutExpired(cmd="pytest", timeout=kw.get("timeout", 0))
        return subprocess.CompletedProcess(cmd, self.rc, "999 passed in 1s", "")


def test_tests_skip_mode(tmp_path, monkeypatch):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "test_x.py").write_text("", encoding="utf-8")
    monkeypatch.setenv("GK_SELFCHECK_TESTS", "skip")
    monkeypatch.setattr(SC.subprocess, "run", _FakeRun())
    r = SC.check_tests(str(tmp_path))
    assert r["status"] == "SKIP", r


def test_tests_quick_runs_subset_and_forbids_recursion(tmp_path, monkeypatch):
    sd = tmp_path / "scripts"
    sd.mkdir()
    for n in ("test_gk_state_wall_levels.py", "test_gk_two_legs.py", "test_zzz_other.py"):
        (sd / n).write_text("", encoding="utf-8")
    fake = _FakeRun()
    monkeypatch.delenv("GK_SELFCHECK_TESTS", raising=False)
    monkeypatch.setattr(SC.subprocess, "run", fake)
    r = SC.check_tests(str(tmp_path))
    assert r["status"] == "PASS" and r["mode"] == "quick", r
    cmd, kw = fake.calls[-1]
    joined = " ".join(cmd)
    assert "test_gk_state_wall_levels.py" in joined and "test_zzz_other.py" not in joined, cmd
    assert kw["env"]["GK_SELFCHECK_TESTS"] == "skip", "子进程未禁套娃"
    assert kw["timeout"] == SC._QUICK_TIMEOUT_S, kw["timeout"]


def test_tests_timeout_is_warn_not_fail(tmp_path, monkeypatch):
    sd = tmp_path / "scripts"
    sd.mkdir()
    (sd / "test_gk_two_legs.py").write_text("", encoding="utf-8")
    monkeypatch.delenv("GK_SELFCHECK_TESTS", raising=False)
    monkeypatch.setattr(SC.subprocess, "run", _FakeRun(timeout=True))
    r = SC.check_tests(str(tmp_path))
    assert r["status"] == "WARN" and "inconclusive" in r["detail"], r


def test_tests_failure_is_fail(tmp_path, monkeypatch):
    sd = tmp_path / "scripts"
    sd.mkdir()
    (sd / "test_gk_two_legs.py").write_text("", encoding="utf-8")
    monkeypatch.delenv("GK_SELFCHECK_TESTS", raising=False)
    monkeypatch.setattr(SC.subprocess, "run", _FakeRun(rc=1))
    r = SC.check_tests(str(tmp_path))
    assert r["status"] == "FAIL", r


def test_tests_no_pytest_is_skip(tmp_path, monkeypatch):
    sd = tmp_path / "scripts"
    sd.mkdir()
    (sd / "test_gk_two_legs.py").write_text("", encoding="utf-8")

    def _no_pytest(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.delenv("GK_SELFCHECK_TESTS", raising=False)
    monkeypatch.setattr(SC.subprocess, "run", _no_pytest)
    assert SC.check_tests(str(tmp_path))["status"] == "SKIP"


def _seed_quick(tmp_path, monkeypatch):
    sd = tmp_path / "scripts"
    sd.mkdir()
    (sd / "test_gk_two_legs.py").write_text("", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("GK_SELFCHECK_TESTS", raising=False)
    monkeypatch.delenv("GK_SELFCHECK_TESTS_TTL", raising=False)
    monkeypatch.setattr(SC, "_git_fingerprint", lambda skill_dir: "fp-test")


def test_tests_quick_cache_hit_skips_pytest(tmp_path, monkeypatch):
    """同代码（HEAD+工作树指纹不变）⟹ 命中缓存，**不派 pytest**（第二次 ~0s）。"""
    _seed_quick(tmp_path, monkeypatch)
    monkeypatch.setattr(SC.subprocess, "run", _FakeRun())
    r1 = SC.check_tests(str(tmp_path))
    assert r1["status"] == "PASS" and not r1.get("cached"), r1
    monkeypatch.setattr(SC.subprocess, "run", _boom)
    r2 = SC.check_tests(str(tmp_path))
    assert r2.get("cached") is True and r2["status"] == "PASS", r2


def test_tests_cache_disabled_by_ttl_zero(tmp_path, monkeypatch):
    _seed_quick(tmp_path, monkeypatch)
    monkeypatch.setattr(SC.subprocess, "run", _FakeRun())
    SC.check_tests(str(tmp_path))
    monkeypatch.setenv("GK_SELFCHECK_TESTS_TTL", "0")
    monkeypatch.setattr(SC.subprocess, "run", _boom)
    with pytest.raises(AssertionError):
        SC.check_tests(str(tmp_path))   # 关缓存 ⟹ 必须真跑（子进程被 _boom 拦下）


def test_tests_full_mode_selects_all_files(tmp_path, monkeypatch):
    """full 档必须跑**全部** test_*.py（不是子集）——`--tests full` / CI / 发布前用。"""
    sd = tmp_path / "scripts"
    sd.mkdir()
    for n in ("test_gk_two_legs.py", "test_zzz_not_in_subset.py"):
        (sd / n).write_text("", encoding="utf-8")
    monkeypatch.setenv("GK_SELFCHECK_TESTS", "full")
    fake = _FakeRun()
    monkeypatch.setattr(SC.subprocess, "run", fake)
    r = SC.check_tests(str(tmp_path))
    assert r["mode"] == "full", r
    joined = " ".join(fake.calls[-1][0])
    assert "test_gk_two_legs.py" in joined and "test_zzz_not_in_subset.py" in joined, joined
    assert fake.calls[-1][1]["timeout"] == SC._FULL_TIMEOUT_S


def test_cli_exposes_tests_tiers_and_call_sites():
    """三档必须在 CLI 可显式选择，且调用点**显式**（不再「全部默认小部分」）。"""
    src = (Path(__file__).parent.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "--tests)" in src and "GK_SELFCHECK_TESTS" in src, "CLI 未暴露 --tests 分档"
    assert "self-check --tests skip" in src, "红队证据面未显式 skip（会被测试腿拖慢）"
    assert '"self-check", "--tests", "quick"' in src, "审计链 L8 未显式 quick"


def test_scan_cache_hit_and_invalidate(tmp_path, monkeypatch):
    """全仓 AST 扫描结果按文件指纹缓存：同内容命中、文件一变即失效。"""
    (tmp_path / "scripts").mkdir()
    f = tmp_path / "scripts" / "a.py"
    f.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GK_SELFCHECK_SCAN_TTL", "3600")
    calls = []

    def fn():
        calls.append(1)
        return {"check": "scan", "status": "PASS"}

    r1 = SC._cached_scan("t", str(tmp_path), fn)
    r2 = SC._cached_scan("t", str(tmp_path), fn)
    assert len(calls) == 1 and not r1.get("cached") and r2.get("cached") is True, (calls, r2)
    f.write_text("x = 2222222\n", encoding="utf-8")   # 改内容 ⟹ 指纹变（大小也变，避免 mtime 同秒）
    SC._cached_scan("t", str(tmp_path), fn)
    assert len(calls) == 2, "文件变了仍命中旧扫描结果（缓存失效判据失守）"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
