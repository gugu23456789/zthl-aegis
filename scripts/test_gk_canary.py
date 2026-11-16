"""自有仓诱饵面（gk_canary）—— 红先臂集（2026-11-11）。

**红先对照**：`scripts/gk_canary.py` 尚不存在 ⟹ 本文件对 HEAD 必红（ImportError）。

判据（不放宽）：
  · 三类诱饵真实落盘：假 state（credit_balance=999999）/ 假 claims / 假池槽（**无 lease**）/
    假 token+假密钥；注册表 `prefixes` 只含诱饵前缀；
  · 判定 O(1)：相对路径与绝对路径都命中，无关文本不命中（禁恒真）；
  · 命中记账走 `gk_threat`（非 owner ⟹ 违约；owner ⟹ 不记，且不影响别人）；
  · 注册表已属别的会话 ⟹ 拒绝覆写（`ALREADY_INSTALLED`）。
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_canary as C  # noqa: E402  （红先：模块不存在 ⟹ ImportError）
import gk_threat as T  # noqa: E402


def _repo(tmp_path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "master"],
                   capture_output=True, text=True)
    (repo / "a.txt").write_text("x", encoding="utf-8")
    return repo


def _sf(tmp_path) -> str:
    return str(tmp_path / ".gatekeeper.state")


def test_install_deploys_all_three_families(tmp_path):
    repo = _repo(tmp_path)
    out = C.install(str(repo), owner_sid="owner")
    assert out["ok"], out
    d = repo / ".gatekeeper-canary"
    state = json.loads((d / "state.json").read_text(encoding="utf-8"))
    assert state["credit_balance"] == 999999, state
    assert (d / "claims.json").is_file()
    assert (d / "pool" / "slot-99" / ".git").is_file()
    # 假槽**无 lease/claim**：抢了也交付不出东西
    assert not list((d / "pool").rglob("*lease*")), "假槽带了 lease（会被当成可派发）"
    assert not list((d / "pool").rglob("*claim*"))
    assert (d / ".env").is_file() and (d / "credentials.json").is_file()
    assert (d / "id_rsa").is_file()
    reg = C.load(repo)
    assert reg and reg["prefixes"] == [C.PREFIX], reg
    assert reg["owner_sid"] == "owner"
    kinds = {x["kind"] for x in reg["decoys"]}
    assert {"fake_state", "fake_claims", "fake_slot", "fake_token", "fake_key"} <= kinds, kinds


def test_scan_is_o1_prefix_and_not_tautological(tmp_path):
    repo = _repo(tmp_path)
    C.install(str(repo), owner_sid="owner")
    reg = C.load(repo)
    assert C.scan("ls -la src/ && pytest -q", reg) == []
    assert C.scan("cat .gatekeeper-canary/state.json", reg)
    assert C.scan("cat %s" % (repo / ".gatekeeper-canary" / ".env"), reg)
    assert C.scan("python3 scripts/gk_canary.py status --repo .", reg) == []


def test_check_access_resolves_repo_from_command_text(tmp_path):
    repo = _repo(tmp_path)
    C.install(str(repo), owner_sid="owner")
    # cwd 在仓外，仅凭命令串里的绝对路径也要能定位到注册表
    hit = C.check_access("head -3 %s" % (repo / ".gatekeeper-canary" / "id_rsa"),
                         cwd=str(tmp_path))
    assert hit["hit"] is True and hit["repo"] == str(repo), hit
    miss = C.check_access("head -3 %s" % (repo / "a.txt"), cwd=str(tmp_path))
    assert miss["hit"] is False, miss


def test_non_owner_hit_records_violation_owner_does_not(tmp_path):
    repo = _repo(tmp_path)
    sf = _sf(tmp_path)
    C.install(str(repo), owner_sid="owner")
    hit = C.check_access(str(repo / ".gatekeeper-canary" / "state.json"), cwd=str(repo))
    assert hit["hit"] is True
    decoy = hit["decoys"][0]
    out = C.record_hit(decoy, "attacker", repo=str(repo), state=sf)
    assert out["ok"] and out["count"] == 1, out
    assert T.status("attacker", state=sf)["count"] == 1
    # owner 命中不记违约（否则防御方巡检会把自己关进隔离区）
    assert T.status("owner", state=sf)["count"] == 0


def test_install_refuses_to_overwrite_other_owner(tmp_path):
    repo = _repo(tmp_path)
    assert C.install(str(repo), owner_sid="owner")["ok"]
    out = C.install(str(repo), owner_sid="intruder")
    assert out["ok"] is False and out.get("error") == "ALREADY_INSTALLED", out
    assert C.load(repo)["owner_sid"] == "owner"


def test_status_and_registry_self_describe(tmp_path):
    repo = _repo(tmp_path)
    assert C.status(repo) == {"ok": True, "installed": False, "repo": str(repo)}
    C.install(str(repo), owner_sid="owner")
    st = C.status(repo)
    assert st["installed"] is True and st["decoy_count"] >= 5 and st["owner_sid"] == "owner", st
    assert st["generation"] == 1 and st["retired_count"] == 0, st


# ── 旋转门（A+B，2026-11-11）────────────────────────────────────────────────
def test_rotate_new_generation_keeps_retired_bait(tmp_path):
    """旋转后：新世代生效；**退役诱饵仍在册且继续判定**（旧地图反而必暴露）。"""
    repo = _repo(tmp_path)
    C.install(str(repo), owner_sid="owner")
    old = repo / ".gatekeeper-canary" / "state.json"
    old_text = old.read_text(encoding="utf-8")
    out = C.rotate(str(repo), owner_sid="owner", nonce="abcd1234")
    assert out["ok"] and out["generation"] == 2, out
    assert out["active_dir"] == ".gatekeeper-canary-abcd1234", out
    assert out["retired"] == 8, out
    new = repo / ".gatekeeper-canary-abcd1234" / "state.json"
    assert new.is_file()
    assert new.read_text(encoding="utf-8") != old_text, "新世代内容未换（旧 token 未失效）"
    assert old.is_file(), "退役诱饵被删了（旧地图不再暴露）"
    assert C.check_access(str(old), cwd=str(repo))["hit"] is True
    assert C.check_access(str(new), cwd=str(repo))["hit"] is True
    reg = C.load(repo)
    assert {".gatekeeper-canary", ".gatekeeper-canary-abcd1234"} <= set(reg["prefixes"])
    st = C.status(repo)
    assert st["generation"] == 2 and st["retired_count"] == 8, st


def test_rotate_requires_install_and_owner(tmp_path):
    repo = _repo(tmp_path)
    assert C.rotate(str(repo)).get("error") == "NOT_INSTALLED"
    C.install(str(repo), owner_sid="owner")
    assert C.rotate(str(repo), owner_sid="intruder").get("error") == "NOT_OWNER"


def test_rotation_ring_is_bounded(tmp_path):
    """旋转门必须**有界**：多代之后目录数/注册表/判定面都不膨胀（防动态防护打爆系统）。"""
    repo = _repo(tmp_path)
    C.install(str(repo), owner_sid="owner")
    for i in range(5):
        out = C.rotate(str(repo), owner_sid="owner", nonce="n%d" % i)
        assert out["ok"], out
    st = C.status(repo)
    assert st["generation"] == 6, st
    assert len(st["slots"]) <= C.MAX_SLOTS, st
    assert st["decoy_count"] <= C.MAX_SLOTS * 8 + 1, st
    # 所有在世槽位仍在册且继续判定（旧地图仍暴露）
    for d in st["slots"]:
        assert C.check_access(str(repo / d / "state.json"), cwd=str(repo))["hit"], d


def test_maybe_rotate_first_hit_immediate_then_debounced(tmp_path):
    repo = _repo(tmp_path)
    C.install(str(repo), owner_sid="owner")
    t0 = float(C.load(repo)["installed_ts"])
    # 周期面不吃「首次」豁免：未到间隔不得轮转
    periodic = C.maybe_rotate(str(repo), min_interval_s=6 * 3600, now=t0 + 10)
    assert periodic.get("rotated") is False, periodic
    first = C.maybe_rotate(str(repo), min_interval_s=60, on_hit=True, now=t0 + 10)
    assert first.get("rotated") is True and first["generation"] == 2, first
    again = C.maybe_rotate(str(repo), min_interval_s=60, on_hit=True, now=t0 + 20)
    assert again.get("rotated") is False and again.get("reason") == "debounced", again
    later = C.maybe_rotate(str(repo), min_interval_s=60, now=t0 + 80)
    assert later.get("rotated") is True and later["generation"] == 3, later
