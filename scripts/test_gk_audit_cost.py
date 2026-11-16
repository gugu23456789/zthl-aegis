"""Phase 4g AUDIT-COST — 动态攻防面防退化审计（红先，2026-11-11）。

**红先对照**：`gk_audit_state.check_cost` 尚不存在 ⟹ 本文件 ImportError/AttributeError（必红）。

判据（不放宽）：
  · 未安装诱饵 = N/A 通过（opt-in）；**装了但注册表/路径/哈希/边界任一坏** ⟹ 失败；
  · 阈值不得被放宽（1/3/3600）；零信息行不得含路径/state/canary 等内部面；
  · hook 接线顺序：`_deception_gate(` 必须早于 `scope_out = False`；
  · monitor 新鲜度：24h 内有信号但游标滞后 ⟹ 失败；消费后 ⟹ 通过。
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_audit_state as A  # noqa: E402
import gk_canary as C  # noqa: E402
import gk_monitor_rotation as R  # noqa: E402
import gk_threat as T  # noqa: E402

SKILL = Path(__file__).resolve().parent.parent


def _repo(tmp_path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "master"],
                   capture_output=True, text=True)
    (repo / "a.txt").write_text("x", encoding="utf-8")
    return repo


def _ok(res: dict, field: str) -> bool:
    return next(c for c in res["cost_checks"] if c["field"] == field)["match"]


def test_positive_with_installed_canary(tmp_path):
    repo = _repo(tmp_path)
    assert C.install(str(repo), owner_sid="owner")["ok"]
    res = A.check_cost(str(SKILL), repo=str(repo))
    assert res["audit_summary"]["matches"] == len(res["cost_checks"]) == 9, res
    assert res["cost_failures"] == [], res
    assert res["cost_registry"]["installed"] is True
    assert res["cost_registry"]["generation"] == 1


def test_not_installed_is_na_pass(tmp_path):
    repo = _repo(tmp_path)
    res = A.check_cost(str(SKILL), repo=str(repo))
    assert _ok(res, "cost_canary_registry") is True
    assert _ok(res, "cost_canary_paths") is True
    assert _ok(res, "cost_canary_bounded") is True
    assert res["cost_registry"]["installed"] is False


def test_missing_decoy_fails(tmp_path):
    repo = _repo(tmp_path)
    C.install(str(repo), owner_sid="owner")
    (repo / C.DECOY_DIRNAME / "state.json").unlink()
    res = A.check_cost(str(SKILL), repo=str(repo))
    assert _ok(res, "cost_canary_paths") is False, res
    assert any(f["field"] == "cost_canary_paths" for f in res["cost_failures"])


def test_tampered_decoy_hash_fails(tmp_path):
    repo = _repo(tmp_path)
    C.install(str(repo), owner_sid="owner")
    (repo / C.DECOY_DIRNAME / "state.json").write_text("{}", encoding="utf-8")
    res = A.check_cost(str(SKILL), repo=str(repo))
    assert _ok(res, "cost_canary_hashes") is False, res


def test_threshold_weakened_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "SUSPICIOUS_AT_DEFAULT", 5)
    res = A.check_cost(str(SKILL), repo=str(tmp_path / "nope"))
    assert _ok(res, "cost_threat_thresholds") is False, res


def test_zero_info_leak_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "SINGLE_LINE", "GATEKEEPER: denied at /tmp/x")
    res = A.check_cost(str(SKILL), repo=str(tmp_path / "nope"))
    assert _ok(res, "cost_threat_zero_info") is False, res


def test_monitor_freshness(tmp_path):
    st = str(tmp_path / "s.state")
    Path(st).write_text("{}", encoding="utf-8")
    T.record("a", "canary_hit", detail="probe", state=st)
    bad = A.check_cost(str(SKILL), state_path=st, repo=str(tmp_path / "nope"))
    assert _ok(bad, "cost_monitor_freshness") is False, bad
    R.run(repo="", state=st, endpoint="")          # 消费信号 ⟹ 游标推进
    good = A.check_cost(str(SKILL), state_path=st, repo=str(tmp_path / "nope"))
    assert _ok(good, "cost_monitor_freshness") is True, good


def test_threat_budget_projection(tmp_path):
    """违约 → 额度银行：无违约 = N/A pass；sid 可对齐 = pass；键错配 = FAIL（必须暴露）。"""
    st = str(tmp_path / "s.state")
    Path(st).write_text(json.dumps({"gate_data": {"edit_budget": {
        "max": 24, "sessions": {"sess1234": {"max": 24, "used": 3, "remaining": 21}}}}}),
        encoding="utf-8")
    res = A.check_cost(str(SKILL), state_path=st, repo=str(tmp_path / "nope"))
    assert _ok(res, "cost_threat_budget") is True, res
    T.record("sess1234abcd", "canary_hit", state=st)      # 12 位 vs 8 位会话键也须对齐
    res = A.check_cost(str(SKILL), state_path=st, repo=str(tmp_path / "nope"))
    assert _ok(res, "cost_threat_budget") is True, res
    T.record("other9999xyz", "canary_hit", state=st)      # 银行无此账户 ⟹ 键错配
    res = A.check_cost(str(SKILL), state_path=st, repo=str(tmp_path / "nope"))
    assert _ok(res, "cost_threat_budget") is False, res
    assert any(f["field"] == "cost_threat_budget" for f in res["cost_failures"]), res


def test_threat_budget_wiring_guard(tmp_path):
    """接线被删（gk_advance 不再调 `_threat_budget_cap`/`budget_freeze`）⟹ 该项必须 FAIL。"""
    sk = tmp_path / "sk"
    (sk / "scripts").mkdir(parents=True)
    (sk / "scripts" / "gk_advance.py").write_text("def x():\n    pass\n", encoding="utf-8")
    assert A._advance_freeze_wired(str(sk)) is False
    st = str(tmp_path / "s.state")
    Path(st).write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    res = A.check_cost(str(sk), state_path=st, repo=str(tmp_path / "nope"))
    assert _ok(res, "cost_threat_budget") is False, res


def test_pure_helpers():
    assert A._opaque_line_ok("GATEKEEPER: request rejected.") is True
    assert A._opaque_line_ok("denied /tmp/x") is False
    assert A._opaque_line_ok("state=corrupt") is False
    # 违约台账明文 sid ↔ 额度银行会话键（短者 ≥8 才允许前缀对齐）
    assert A._bank_key("abcdef1234567890", {"abcdef12": {}}) == "abcdef12"
    assert A._bank_key("abcdef12", {"abcdef1234567890": {}}) == "abcdef1234567890"
    assert A._bank_key("zzzzzzzz", {"abcdef12": {}}) is None
    # 载荷 sid 与 worktree token 不同哈希 ⟹ 只能靠别名分片对齐
    assert A._bank_key("6aee8af5b97fc743497ba69c", {"396aa76b": {}}, "396aa76b") == "396aa76b"
    assert A._advance_freeze_wired(str(SKILL)) is True
    # 真实文件形态：先 def，后调用，再 scope 解析；调用点必须早于 scope_out
    good = "def _deception_gate(a):\n    return 0\nx = _deception_gate(a)\nscope_out = False\n_opaque_block(t)"
    assert A._hook_order_ok(good) is True
    assert A._hook_order_ok("scope_out = False\nx = _deception_gate(a)") is False
    assert A._hook_order_ok("x = _deception_gate(a)\nscope_out = False") is False  # 缺 _opaque_block
