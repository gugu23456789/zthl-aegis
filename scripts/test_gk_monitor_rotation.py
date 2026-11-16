"""monitor 事件驱动 + 旋转门（gk_monitor_rotation）—— 红先臂集（2026-11-11）。

**红先对照**：`scripts/gk_monitor_rotation.py` 尚不存在 ⟹ 本文件对 HEAD 必红（ImportError）。

判据（不放宽）：
  · **无信号 ⟹ 零激活 / 零 API**（monitor 不应在闲置时烧 token）；
  · 有信号 ⟹ 确定性 triage 分档，且同批信号只消费一次（游标推进）；
  · LLM 车道只在 endpoint 已配 + 等级达标 + 滚动 1h 预算内才调用；超预算保留 deterministic 分；
  · `--dry-run` 只读（不轮转 / 不调 LLM / 不写游标与审计行）；
  · 中/高等级信号触发诱饵轮转（旋转门），退役诱饵仍在册。
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_canary as C  # noqa: E402
import gk_monitor_rotation as R  # noqa: E402  （红先：模块不存在 ⟹ ImportError）
import gk_threat as T  # noqa: E402


def _state(tmp_path) -> str:
    return str(tmp_path / ".gatekeeper.state")


def _repo(tmp_path) -> Path:
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "master"],
                   capture_output=True, text=True)
    (repo / "a.txt").write_text("x", encoding="utf-8")
    return repo


def _signal(sid: str = "attacker", n: int = 3, state: str = "",
            now0: float | None = None) -> None:
    # 默认放在 60s 前：避免「事件 ts 略晚于 run 的 now」被窗口上界裁掉（实测踩中）
    base = (time.time() - 60) if now0 is None else float(now0)
    for i in range(n):
        T.record(sid, "canary_hit", detail="probe", state=state, now=base + i * 0.01)


def test_no_signal_means_zero_activation(tmp_path):
    st = _state(tmp_path)
    out = R.run(repo="", state=st)
    assert out["ok"] is True and out["activated"] is False, out
    assert out["reason"] == "no_signal" and out["api_calls"] == 0, out
    assert not Path(st + ".threat.monitor.json").exists(), "无信号也写了游标（闲置面被污染）"


def test_signal_triages_and_consumes_once(tmp_path):
    st = _state(tmp_path)
    _signal(state=st)
    out = R.run(repo="", state=st, endpoint="")
    assert out["activated"] is True and out["level"] >= 2, out
    assert out["api_calls"] == 0, out                     # endpoint 未配 ⟹ 不联网
    assert out["monitor"]["mode"] == "--local", out
    assert out["monitor"].get("advisory") == "endpoint_unset", out
    log = Path(st + ".threat.monitor.jsonl")
    assert log.is_file() and log.read_text(encoding="utf-8").strip(), "激活无审计行"
    # 同批信号只消费一次（游标推进）⟹ 不重复烧 monitor
    again = R.run(repo="", state=st, endpoint="")
    assert again["activated"] is False and again["reason"] == "no_signal", again


def test_dry_run_is_read_only(tmp_path):
    st = _state(tmp_path)
    _signal(n=1, state=st)
    out = R.run(repo="", state=st, dry_run=True)
    assert out["activated"] is True and out["api_calls"] == 0, out
    assert out["rotation"].get("reason") == "dry_run", out
    assert not Path(st + ".threat.monitor.json").exists(), "dry-run 写了游标"
    assert not Path(st + ".threat.monitor.jsonl").exists(), "dry-run 写了审计行"


def test_budget_caps_llm_calls(tmp_path, monkeypatch):
    import gk_monitor_decision as MD
    calls = []

    def _stub(*a, **k):
        calls.append((a, k))
        return {"ok": True, "mode": "--api", "verdict": "FAIL", "score": 0.0}

    monkeypatch.setattr(MD, "run", _stub)
    st = _state(tmp_path)
    base = time.time()
    _signal(state=st, now0=base)
    o1 = R.run(repo="", state=st, endpoint="http://stub", max_api_per_hour=1,
               now=base + 1)
    assert o1["api_calls"] == 1 and len(calls) == 1, o1
    # 新一批信号（时间晚于游标），但 1h 预算已用尽
    _signal(state=st, now0=base + 2)
    o2 = R.run(repo="", state=st, endpoint="http://stub", max_api_per_hour=1,
               now=base + 3)
    assert o2["activated"] is True and o2["api_calls"] == 0, o2
    assert o2["monitor"].get("advisory") == "budget_exhausted", o2
    assert len(calls) == 1, "预算闸失效（又调了一次 LLM）"


def test_medium_signal_rotates_decoys(tmp_path):
    st = _state(tmp_path)
    repo = _repo(tmp_path)
    C.install(str(repo), owner_sid="owner")
    old = repo / ".gatekeeper-canary" / "state.json"
    _signal(state=st)
    out = R.run(repo=str(repo), state=st, endpoint="")
    rot = out.get("rotation") or {}
    assert rot.get("rotated") is True and rot.get("generation") == 2, out
    assert old.is_file(), "退役诱饵被删（旧地图不再暴露）"
    assert C.check_access(str(old), cwd=str(repo))["hit"] is True
    new = repo / rot["active_dir"] / "state.json"
    assert new.is_file() and C.check_access(str(new), cwd=str(repo))["hit"] is True


def test_concurrent_run_is_locked(tmp_path):
    """cron 重叠/人工与定时同跑 ⟹ 单消费者锁：拿不到锁不双跑、不双花 LLM 预算。"""
    fcntl = pytest.importorskip("fcntl")
    st = _state(tmp_path)
    _signal(state=st)
    p = Path(st + ".threat.monitor.lock")
    p.parent.mkdir(parents=True, exist_ok=True)
    f = open(p, "a+")
    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        out = R.run(repo="", state=st, endpoint="")
        assert out["activated"] is False and out["reason"] == "locked", out
        assert out["api_calls"] == 0, out
    finally:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        f.close()


def test_status_reports_cursor_and_budget(tmp_path):
    st = _state(tmp_path)
    _signal(n=1, state=st)
    R.run(repo="", state=st, endpoint="")
    out = R.status(state=st)
    assert out["ok"] and out["cursor"] > 0 and out["last"]["level"] >= 1, out
    assert out["api_per_hour"] >= 1 and out["rotation_period_s"] >= 0, out
