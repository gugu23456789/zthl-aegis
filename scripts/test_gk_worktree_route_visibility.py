"""F7 族（worktree/隔离·申请—分发）红先臂 —— **先看它红**，再落刀转绿。

病根（`ECC-5756951C56C8` 视野硬编码侧）：`gk_route_center.resolve_worktree` 的跨仓
dirscan **只**扫 `<root>/<repo>/feature/<branch>`（`base.glob("*/feature/*")`），且分支名
须命中 `r[0-9.]+` ⟹ `standing/<slug>` 与 `agent/session/<sha8>` 两类 worktree 对 L3
**完全不可见**（落 `detected=False`）。

契约（本窄切片，落点单一 = `scripts/gk_route_center.py`）—— dirscan 认三种 route：
  · `feature`  `<repo>/feature/<rN>`         → r_phase = `r<N>`（既有语义**逐字不变**）
  · `standing` `<repo>/standing/<slug>`      → r_phase = `""`
  · `agent`    `<repo>/agent/session/<sha8>` → r_phase = `""`
并**新增**返回键 `route ∈ {"feature","standing","agent"}`（未命中 → `""`）。
非白名单 route（如 `<repo>/misc/<x>`）**不得**被认（防判据过宽）。

为什么 r_phase 对 standing/agent 取空：CLI `cmd_discover` 在 `detected` 后按
`r_phase ∈ valid_phases` 做绑定门（`gatekeeper-cli.sh` 计费段之后）；r_phase 为空时既有
代码**不重置** worktree（`if [ -n "$r_phase" ]` 分支不触发）⟹ 恰好让 standing/agent
worktree 被**看见并绑定**，而 feature 路由仍受相位门约束（原语义不破）。

隔离手法：monkeypatch `gk_route_center.DEV_WORKTREE_ROOTS` → 临时 root；清空
`GATEKEEPER_WORKTREE_ROOT` / `GK_WORKTREE_REPO` / `GK_WORKTREE_CWD` ⟹ 只扫本测试构造的
树（不碰本机真实 worktree 树，判定稳定）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_route_center as rc


def _sandbox(root_dir, monkeypatch):
    """把 dev worktree 根收敛到临时目录，并清空三个会影响 dirscan 判定的 env。"""
    monkeypatch.setattr(rc, "DEV_WORKTREE_ROOTS", (str(root_dir) + os.sep,))
    monkeypatch.delenv("GATEKEEPER_WORKTREE_ROOT", raising=False)
    monkeypatch.delenv("GK_WORKTREE_REPO", raising=False)
    monkeypatch.delenv("GK_WORKTREE_CWD", raising=False)
    # 2026-10-28（计划建树单一入口）：`GK_PLAN_FILE` 一旦泄漏进本测试环境，dirscan 的
    #   「计划声明的树优先」会改变候选顺序 ⟹ 必须显式清空（各臂自行按需设置）。
    monkeypatch.delenv("GK_PLAN_FILE", raising=False)


def _mk(root, *parts):
    d = root.joinpath(*parts)
    d.mkdir(parents=True)
    return d


def _resolve():
    # skill_dir 传真实技能目录 ⟹ 打开 dirscan（tmp/隔离 skill_dir 会走另一分支）
    return rc.resolve_worktree(skill_dir=str(rc.DEFAULT_SKILL))


# ── 对照臂（落刀前**已绿**）─────────────────────────────────────────────────

def test_control_feature_route_still_detected(tmp_path, monkeypatch):
    """既有 feature 路由语义逐字不变（本次放宽不得漫溢到 feature）。"""
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    wt = _mk(root, "myrepo", "feature", "r7.3")
    out = _resolve()
    assert out["detected"] is True
    assert out["worktree"] == str(wt)
    assert out["branch"] == "feature/r7.3"
    assert out["r_phase"] == "R7.3"


# ── 红先正臂（落刀前必红）────────────────────────────────────────────────

def test_standing_route_is_detected(tmp_path, monkeypatch):
    """`standing/<slug>` 须可见（现状 `feature/*` glob 扫不到 ⟹ 红）。"""
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    wt = _mk(root, "myrepo", "standing", "xenv-form-fix")
    out = _resolve()
    assert out["detected"] is True, "standing/<slug> 仍不可见（ECC-5756951C56C8 未修）"
    assert out["worktree"] == str(wt)
    assert out["branch"] == "standing/xenv-form-fix"
    assert out["r_phase"] == ""


def test_agent_session_route_is_detected(tmp_path, monkeypatch):
    """`agent/session/<sha8>` 须可见（现状完全不可见 ⟹ 红）。"""
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    wt = _mk(root, "myrepo", "agent", "session", "4b1f09fb")
    out = _resolve()
    assert out["detected"] is True, "agent/session/<sha8> 仍不可见"
    assert out["worktree"] == str(wt)
    assert out["branch"] == "agent/session/4b1f09fb"
    assert out["r_phase"] == ""


def test_agent_family_route_is_detected(tmp_path, monkeypatch):
    """`agent/<family>/<sha8>`（= `apply_worktree` 实际布局，**两段**）须可见。

    实测（2026-09-28 `git worktree list`）本仓实存 `agent/F-hook-lock-observability/009961cb`
    等 ⟹ 只认 `agent/session/<sha8>` 会漏掉**全部** code-fix 族 worktree。
    """
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    wt = _mk(root, "myrepo", "agent", "F-hook-lock-observability", "009961cb")
    out = _resolve()
    assert out["detected"] is True, "agent/<family>/<sha8> 仍不可见"
    assert out["worktree"] == str(wt)
    assert out["branch"] == "agent/F-hook-lock-observability/009961cb"
    assert out["r_phase"] == ""
    assert out.get("route") == "agent"


def test_dryrun_is_not_a_worktree_route(tmp_path, monkeypatch):
    """负臂：`dryrun/` 实测只容 `*.state` 文件、**非** worktree route ⟹ 其下目录不得被认。"""
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    _mk(root, "myrepo", "dryrun", "crossfull-20260925-172402")
    out = _resolve()
    assert out["detected"] is False


def test_route_key_reports_standing_and_agent(tmp_path, monkeypatch):
    """返回键 `route` 须如实报告命中形态（feature/standing/agent）。"""
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    _mk(root, "myrepo", "feature", "r7.3")
    assert _resolve().get("route") == "feature"

    root2 = tmp_path / "wt2"
    root2.mkdir()
    _sandbox(root2, monkeypatch)
    _mk(root2, "myrepo", "standing", "xenv-form-fix")
    assert _resolve().get("route") == "standing"

    root3 = tmp_path / "wt3"
    root3.mkdir()
    _sandbox(root3, monkeypatch)
    _mk(root3, "myrepo", "agent", "session", "4b1f09fb")
    assert _resolve().get("route") == "agent"


# ── 负臂（守强度：防判据过宽）──────────────────────────────────────────────

def test_unknown_route_is_not_detected(tmp_path, monkeypatch):
    """非白名单 route（`<repo>/misc/<x>`）不得被认。"""
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    _mk(root, "myrepo", "misc", "foo-bar")
    out = _resolve()
    assert out["detected"] is False


def test_empty_root_is_not_detected(tmp_path, monkeypatch):
    """空 root ⟹ detected=False，route 为空串（未命中形态不得伪造 route）。"""
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    out = _resolve()
    assert out["detected"] is False
    assert out.get("route", "") == ""


# ── 族判定实测（与 test_gk_agent_family.py::test_f3_members_route_to_the_right_subfamily
#    同法：真实 references/ 缺席的 red-first 沙箱 ⟹ skip；accept 面必判）──────────────

_FAMS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "references", "agent-families")


def test_f7_family_routes_the_real_finding():
    """`ECC-5756951C56C8`（worktree 无「申请—分发」入口）须路由到 F7 族；不沾者回空串。"""
    if not os.path.isdir(_FAMS_DIR):
        pytest.skip("red-first 沙箱无 references/agent-families（accept 面必判）")
    import gk_agent_family as af
    fid = af.classify({"id": "ECC-5756951C56C8",
                       "title": "worktree 无「申请—分发」入口：L3 resolve-worktree 只定位不分配，"
                                "dirscan 硬编码 feature/ 段 + r[0-9.]+ 分支名"})
    assert fid == "F7-worktree-route-visibility", fid
    # 负臂：与 F7 关键词不沾的占位 finding 仍须回空串（防族判定过宽）
    assert af.classify({"id": "ECC-000000000000",
                        "title": "与本仓任何族关键词无关的占位缺陷"}) == ""


# ── 计划声明的树优先（2026-10-28，计划建树单一入口）────────────────────────────
# 病象（实测）：`apply-worktree --plan` 建 `feature/<plan-stem>`（名里没有 `rN`）⟹ dirscan 的
#   feature 相位门把它滤掉 ⟹ discover 探回「mtime 最新的别的 feature 树」⟹ 计划的
#   `state.worktree` 每次 discover 都被改绑。规则 = `GK_PLAN_FILE` 的 stem 与目录名逐字相等
#   ⟹ 直接胜出（压过 mtime / 相位门）。

def test_plan_stem_tree_wins_over_newer_feature_tree(tmp_path, monkeypatch):
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    plan_wt = _mk(root, "myrepo", "feature", "2026-10-28-demo-plan")
    other = _mk(root, "myrepo", "feature", "r7.3")
    # 让「别的树」更新 ⟹ 旧判据（mtime 最新）必选它；本臂判别力即来自此
    os.utime(str(other), (9e9, 9e9))
    monkeypatch.setenv("GK_PLAN_FILE", "docs/plans/2026-10-28-demo-plan.md")
    out = _resolve()
    assert out["detected"] is True
    assert out["worktree"] == str(plan_wt), out
    assert out["branch"] == "feature/2026-10-28-demo-plan"


def test_plan_stem_absent_falls_back_to_mtime(tmp_path, monkeypatch):
    """反臂：计划 stem 与任何目录都不等 ⟹ 不得凭「有 plan 文件」就乱绑。"""
    root = tmp_path / "wt"
    root.mkdir()
    _sandbox(root, monkeypatch)
    _mk(root, "myrepo", "feature", "2026-10-28-demo-plan")
    other = _mk(root, "myrepo", "feature", "r7.3")
    os.utime(str(other), (9e9, 9e9))
    monkeypatch.setenv("GK_PLAN_FILE", "docs/plans/2026-10-28-some-other-plan.md")
    out = _resolve()
    assert out["worktree"] == str(other), out
