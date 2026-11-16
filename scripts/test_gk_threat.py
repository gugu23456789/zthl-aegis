"""per-sid 违约台账（gk_threat）—— 红先臂集（2026-11-11）。

**红先对照**：`scripts/gk_threat.py` 尚不存在 ⟹ 本文件对 HEAD 必红（ImportError）。

判据（不放宽）：
  · 分级：窗口内 0 / >=1 / >=3 ⟹ normal / suspicious / quarantined（阈值可 env 覆盖）；
  · 隔离后 `check()` 必须 `denied=True`，且唯一可见行是 `SINGLE_LINE`（零信息：
    不含 sid / 路径 / 错误码 / state / 原因）；
  · 窗口滑动即 decay（读侧过滤），显式 `decay()` 压缩前先归档；
  · per-sid 隔离（A 的违约不连坐 B）；append-only（只在尾追加，`reset()` 只改名归档）。
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_threat as T  # noqa: E402  （红先：模块不存在 ⟹ ImportError）


def _sf(tmp_path) -> str:
    return str(tmp_path / ".gatekeeper.state")


def _reset_env(monkeypatch):
    for k in ("GK_THREAT_WINDOW_S", "GK_THREAT_SUSPICIOUS_AT",
              "GK_THREAT_QUARANTINE_AT", T.COOLDOWN_ENV, T.BYPASS_ENV):
        monkeypatch.delenv(k, raising=False)


def test_levels_and_zero_info_line(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    assert T.status("a", state=sf)["name"] == "normal"

    r1 = T.record("a", "canary_hit", detail="decoy=state", state=sf)
    assert r1["ok"] and r1["name"] == "suspicious" and r1["count"] == 1, r1
    c1 = T.check("a", state=sf)
    assert c1["denied"] is False and c1["line"] == ""

    T.record("a", "canary_hit", state=sf)
    r3 = T.record("a", "canary_hit", state=sf)
    assert r3["name"] == "quarantined" and r3["count"] == 3, r3
    c3 = T.check("a", state=sf)
    assert c3["denied"] is True and c3["line"] == T.SINGLE_LINE, c3
    # 零信息：可见行不得含任何可用于调整策略的内部面
    for leak in ("canary", "state", "worktree", "/tmp", "sid", "quarantin", "a"):
        assert leak not in c3["line"], (leak, c3["line"])


def test_window_decay_is_read_side(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    old = 1000.0
    T.record("a", "canary_hit", state=sf, now=old)
    T.record("a", "canary_hit", state=sf, now=old + 1)
    T.record("a", "canary_hit", state=sf, now=old + 2)
    # 窗口内 = 隔离
    assert T.check("a", state=sf, now=old + 3)["denied"] is True
    # 窗口滑过（1h 后）⟹ 自动回到 normal（文件没被改写，只是读侧过滤）
    assert T.check("a", state=sf, now=old + T.window_s() + 10)["level"] == 0
    assert len(T.ledger_path("a", sf).read_text(encoding="utf-8").splitlines()) == 3


def test_explicit_decay_archives_then_compacts(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    now = time.time()          # decay 的窗口是**墙钟**，测试必须用真时间
    T.record("a", "canary_hit", state=sf, now=now - T.window_s() - 100)
    T.record("a", "canary_hit", state=sf, now=now)
    out = T.decay("a", state=sf)
    assert out["ok"] and out["kept"] == 1 and out["dropped"] == 1, out
    assert Path(out["archived"]).is_file(), out
    assert len(T.events("a", state=sf)) == 1


def test_ledger_read_is_tail_bounded(tmp_path, monkeypatch):
    """台账 append-only 会变长；hook 每次调用只读尾部 ⟹ 旧账不得把判级/hook 拖慢。"""
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    now = time.time()
    p = T.ledger_path("a", sf)
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": round(now - 1, 3), "iso": "", "sid": "a", "kind": "canary_hit",
                       "detail": "x" * 200, "target": ""}) + "\n"
    with open(p, "w", encoding="utf-8") as f:
        f.write(line * (T.READ_MAX_BYTES // len(line) + 100))
    for _ in range(3):
        T.record("a", "canary_hit", state=sf, now=now)
    assert p.stat().st_size > T.READ_MAX_BYTES
    st = T.status("a", state=sf, now=now)
    assert st["count"] >= 3 and st["name"] == "quarantined", st
    assert T.check("a", state=sf, now=now)["denied"] is True


def test_per_sid_isolation(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    for _ in range(3):
        T.record("attacker", "canary_hit", state=sf)
    assert T.check("attacker", state=sf)["denied"] is True
    assert T.check("innocent", state=sf)["denied"] is False
    assert T.status("innocent", state=sf)["count"] == 0


def test_reset_archives_instead_of_deleting(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    for _ in range(3):
        T.record("a", "canary_hit", state=sf)
    p = T.ledger_path("a", sf)
    before = p.read_text(encoding="utf-8")
    out = T.reset("a", state=sf)
    assert out["ok"] and out["removed"] is True, out
    assert not p.exists()
    assert Path(out["archived"]).read_text(encoding="utf-8") == before
    assert T.check("a", state=sf)["denied"] is False


def test_bypass_env_for_defender(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    for _ in range(3):
        T.record("a", "canary_hit", state=sf)
    monkeypatch.setenv(T.BYPASS_ENV, "1")
    chk = T.check("a", state=sf)
    assert chk["denied"] is False and chk.get("bypass") is True, chk


def test_thresholds_are_env_overridable(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    monkeypatch.setenv("GK_THREAT_QUARANTINE_AT", "2")
    sf = _sf(tmp_path)
    T.record("a", "canary_hit", state=sf)
    assert T.check("a", state=sf)["denied"] is False
    T.record("a", "canary_hit", state=sf)
    assert T.check("a", state=sf)["denied"] is True


def test_cli_record_then_check(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    rc = T.main(["record", "--sid", "cli", "--kind", "canary_hit", "--state", sf])
    assert rc == 0
    assert T.status("cli", state=sf)["count"] == 1
    assert T.main(["check", "--sid", "cli", "--state", sf]) == 0
    for _ in range(2):
        T.record("cli", "canary_hit", state=sf)
    assert T.main(["check", "--sid", "cli", "--state", sf]) == 3


# ─── 违约 → 额度银行的只读投影（冷却期，2026-11-11）───
# 口径（violation-charter §4.1）：只读、不扣款、不进熵、不阻断 advance；仅供注入点封顶。

def test_budget_freeze_cooldown_is_read_only(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    now = 1_000_000.0
    assert T.budget_freeze("a", state=sf, now=now)["active"] is False
    T.record("a", "canary_hit", state=sf, now=now - 10)
    fr = T.budget_freeze("a", state=sf, now=now)
    assert fr["active"] is True and fr["count"] >= 1 and fr["cooldown_s"] == 3600, fr
    assert 0 <= fr["age_s"] <= 11, fr
    # 冷却期外 ⟹ 不再生效（读侧窗口过滤，台账文件本身不被重写）
    p = T.ledger_path("a", sf)
    before = p.read_text(encoding="utf-8")
    assert T.budget_freeze("a", state=sf, now=now + 4000)["active"] is False
    assert p.read_text(encoding="utf-8") == before


def test_budget_freeze_matches_plaintext_sid_by_prefix(tmp_path, monkeypatch):
    """台账 24 hex / 银行 8 hex 是同一会话的两种写法 ⟹ 必须按**行内明文 sid** 对齐。"""
    _reset_env(monkeypatch)
    sf = _sf(tmp_path)
    now = 2_000_000.0
    T.record("6aee8af5b97fc743497ba69c", "canary_hit", state=sf, now=now - 5)
    assert T.budget_freeze("6aee8af5", state=sf, now=now)["active"] is True
    assert T.budget_freeze("deadbeef", state=sf, now=now)["active"] is False
    assert T._sid_match("6aee8af5b97f", "6aee") is False   # 短串 < 8 位不得前缀匹配
    assert T._sid_match("6aee8af5b97fc743497ba69c", "6aee8af5") is True


def test_budget_freeze_resolves_session_alias(tmp_path, monkeypatch):
    """台账记载荷 sid（24 hex）、银行用 worktree token（8 hex）—— 两者不是哈希截断，
    只能靠 `pre_tool_hook` 落盘的 `.gatekeeper.session.alias.<sid>` 双向解析。"""
    _reset_env(monkeypatch)
    monkeypatch.setattr(T, "SKILL_DIR", tmp_path)
    (tmp_path / (T._SESSION_ALIAS_PREFIX + "pay6aee8af5")).write_text(
        "396aa76b\n", encoding="utf-8")
    sf = _sf(tmp_path)
    now = 4_000_000.0
    T.record("pay6aee8af5", "canary_hit", state=sf, now=now - 3)
    assert T.budget_freeze("396aa76b", state=sf, now=now)["active"] is True   # token → 别名反查
    assert T.budget_freeze("pay6aee8af5", state=sf, now=now)["active"] is True
    assert T.budget_freeze("ffffffff", state=sf, now=now)["active"] is False


def test_cooldown_env_overridable(tmp_path, monkeypatch):
    _reset_env(monkeypatch)
    monkeypatch.setenv(T.COOLDOWN_ENV, "10")
    assert T.cooldown_s() == 10
    sf = _sf(tmp_path)
    now = 3_000_000.0
    T.record("a", "canary_hit", state=sf, now=now - 20)
    assert T.budget_freeze("a", state=sf, now=now)["active"] is False
    T.record("a", "canary_hit", state=sf, now=now - 5)
    assert T.budget_freeze("a", state=sf, now=now)["active"] is True
