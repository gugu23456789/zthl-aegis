#!/usr/bin/env python3
"""红先臂：§17-2 state 去具体化 —— 域化活动写面（`gate_data.wt_domain[<token>][]`）。

计划：`docs/plans/2026-09-28-state-single-authority-plan.md` §17-2（键文法定形，候选 1）。

方案 (a)：域键 token **只**取 env `GK_SESSION_ID`；缺失 / 非法 ⟹ 不查域桶（回落 base，**零回归**）。
键文法（单源 `gk_finding._DOMAIN_TOKEN_RE`）：`^[A-Za-z0-9][A-Za-z0-9._-]*$`，长度 ≤64。

红先基线：HEAD 上 `gk_route_center._session_token` / `_domain_roots` 与 `gk_state_patch.cmd_wt_domain`
**皆不存在**（且 `active_roots` 不并域桶）⟹ 本模块行为臂必红。本臂钉住：
  · 读侧 `gk_route_center.active_roots` 并入域桶；
  · **token 劫持**：token 只由 env 传入（**非** cwd / 被判定路径派生）；**他 token 的域桶对本会话不可见**；
  · **篡改污染**：`wt_domain` 形态污染（非 dict / 桶非 list / 元素非法）⟹ 忽略、不崩（fail-soft）；
  · **env 污染**：`GK_SESSION_ID` 垃圾 / 超长 / 含非法字符 ⟹ 视为缺失（零回归）；
  · 写侧 `gk_state_patch.cmd_wt_domain` = 域桶**唯一写通路**（`set-nested`/`append-list`/`update-gate-data` 触达均拒）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
SCRIPTS = SD / "scripts"
RC = SCRIPTS / "gk_route_center.py"
SP = SCRIPTS / "gk_state_patch.py"
CLI = SD / "gatekeeper-cli.sh"
PY = sys.executable

sys.path.insert(0, str(SCRIPTS))
import gk_state  # noqa: E402 — checksum 单一事实（写后闭环核验）


def _state(tmp: Path, gate_data=None, name=".gatekeeper.state", **top) -> Path:
    d = {"stage": "ECO-EDIT", "r_phase": "R1",
         "gate_data": gate_data if gate_data is not None else {}}
    d.update(top)
    p = tmp / name
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    return p


def _active_roots(state: Path, gk_session_id, cwd=None):
    """子进程直调 `gk_route_center.active_roots`（显式喂 `GK_SESSION_ID`；隔离本进程 env）。"""
    child = (
        "import json,os,sys\n"
        "sys.path.insert(0, os.environ['GK_SCRIPTS'])\n"
        "import gk_route_center as R\n"
        "st=json.loads(os.environ['GK_STATE'])\n"
        "print(json.dumps(R.active_roots(st)))\n"
    )
    env = dict(os.environ, GK_SCRIPTS=str(SCRIPTS),
               GK_STATE=state.read_text(encoding="utf-8"),
               GK_SESSION_ID=gk_session_id)
    p = subprocess.run([PY, "-c", child], capture_output=True, text=True, timeout=120,
                       env=env, cwd=str(cwd) if cwd else None)
    assert p.returncode == 0, "helper 子进程失败（函数缺席/异常）：%s" % (p.stderr[-400:],)
    return json.loads(p.stdout.strip().splitlines()[-1])


def _run_sp(*args):
    p = subprocess.run([PY, str(SP), *args], capture_output=True, text=True, timeout=60)
    try:
        return p.returncode, json.loads((p.stdout or "").strip())
    except Exception:  # noqa: BLE001 — 容忍前置噪声行
        try:
            return p.returncode, json.loads((p.stdout or "").strip().splitlines()[-1])
        except Exception:  # noqa: BLE001
            return p.returncode, {}


def _load(state: Path) -> dict:
    return json.loads(state.read_text(encoding="utf-8"))


# ── wd-a：API 缺席（静态，红先）───────────────────────────────────────────────
def test_wd_a_api_exists():
    rc = RC.read_text(encoding="utf-8")
    sp = SP.read_text(encoding="utf-8")
    cli = CLI.read_text(encoding="utf-8")
    assert "def _session_token(" in rc, "缺 `_session_token`（域键 token 单源，§17-2 方案 a）"
    assert "def _domain_roots(" in rc, "缺 `_domain_roots`（域桶读点）"
    assert "def cmd_wt_domain(" in sp, "缺 `cmd_wt_domain`（域桶唯一写通路）"
    assert "wt-domain" in sp, "`gk_state_patch.main` 未注册 `wt-domain`"
    assert "--wt-domain" in cli, "`gatekeeper-cli.sh state-patch` 未开 `--wt-domain` 分支"


# ── wd-b：读侧并入域桶（红先）───────────────────────────────────────────────
def test_wd_b_read_side_unions_domain_bucket(tmp_path):
    st = _state(tmp_path, {"wt_domain": {"sess1": ["/mnt/c/x/wtA"]}},
                worktree="/mnt/c/x/base")
    roots = _active_roots(st, "sess1")
    assert roots[0] == "/mnt/c/x/base", f"主值应居首：{roots}"
    assert "/mnt/c/x/wtA" in roots, f"域桶未并入活动写面：{roots}"
    # 合并顺序：主值 → worktrees_extra → 域桶
    st2 = _state(tmp_path, {"wt_domain": {"sess1": ["/dom"]}},
                 worktree="/base", worktrees_extra=["/extra"], name=".gk.order")
    assert _active_roots(st2, "sess1") == ["/base", "/extra", "/dom"]


# ── wd-c：token 劫持（他 token 桶不可见 + 非 cwd/路径派生）────────────────────
def test_wd_c_token_hijack_scope(tmp_path):
    """域桶按 token 隔离；token 只来自 env（**禁**由 cwd / 被判定路径派生，否则 Gate 3 自证恒真）。"""
    st = _state(tmp_path, {"wt_domain": {"victim": ["/mnt/c/x/victim_wt"]}},
                worktree="/mnt/c/x/base")
    # (i) 本会话 = attacker ⟹ 看不到 victim 桶
    assert "/mnt/c/x/victim_wt" not in _active_roots(st, "attacker"), "token 劫持：他 token 域桶可见"
    # (ii) env 未给 token：即使 cwd 落在 victim 桶路径上，也不得派生 token
    cwd = tmp_path / "victim_wt"
    cwd.mkdir()
    assert "/mnt/c/x/victim_wt" not in _active_roots(st, "", cwd=cwd), "token 由 cwd 派生（劫持）"
    # (iii) 阳性对照：本会话自身 token 的桶**可见**（防「恒不并入」假绿）
    assert "/mnt/c/x/victim_wt" in _active_roots(st, "victim")


# ── wd-d：篡改污染（fail-soft，不崩）────────────────────────────────────────
def test_wd_d_tamper_pollution_ignored(tmp_path):
    cases = [
        ("/x", []),                                    # wt_domain 非 dict（str）
        (["/x"], []),                                  # wt_domain 非 dict（list）
        ({"s1": "not-a-list"}, []),                    # 桶非 list
        ({"s1": {"nested": 1}}, []),                   # 桶非 list（dict）
        ({"s1": ["", 123, None, "/ok"]}, ["/ok"]),     # 元素污染 ⟹ 仅保留合法 str
        ({"s1": [["nested-list"]]}, []),               # 嵌套 list 非 str ⟹ 忽略
        ({"s1": ["/a", "/a"]}, ["/a"]),                # 去重
        ({"s1": ["C:\\x\\wt"]}, ["/mnt/c/x/wt"]),      # 归一化
    ]
    for i, (wd, exp_dom) in enumerate(cases):
        st = _state(tmp_path, {"wt_domain": wd}, worktree="/base", name=".gk.t%d" % i)
        roots = _active_roots(st, "s1")
        assert roots[:1] == ["/base"], f"污染下主值受损：wd={wd!r} got={roots}"
        assert roots[1:] == exp_dom, f"篡改污染未按 fail-soft 处置：wd={wd!r} got={roots}"


# ── wd-e：env 污染（零回归）────────────────────────────────────────────────
def test_wd_e_env_pollution_zero_regression(tmp_path):
    st = _state(tmp_path, {"wt_domain": {"sess1": ["/mnt/c/x/wtA"]}},
                worktree="/mnt/c/x/base")
    bad = ["", "   ", "bad token", "a" * 65, ".lead", "_lead", "a/b", "a\\b", "sess/1"]
    for b in bad:
        assert _active_roots(st, b) == ["/mnt/c/x/base"], \
            f"env 污染 `{b!r}` 未回落 base（零回归）：{_active_roots(st, b)}"
    # 阳性对照：合法 token ⟹ 明确并入（防「恒回落」假绿）
    assert "/mnt/c/x/wtA" in _active_roots(st, "sess1")
    # 长度边界：64 合法 / 65 已在上方判污染
    tok64 = "a" * 64
    st2 = _state(tmp_path, {"wt_domain": {tok64: ["/wt64"]}}, worktree="/base", name=".gk.64")
    assert "/wt64" in _active_roots(st2, tok64), "64 长 token 应合法"


# ── wd-f：写侧 bind/unbind 幂等 + checksum 闭环（红先）───────────────────────
def test_wd_f_write_bind_unbind_idempotent_checksum(tmp_path):
    st = _state(tmp_path, {})
    rc, out = _run_sp("wt-domain", str(st), "bind", "sess1", "C:\\x\\wt")
    assert out.get("ok") is True and out.get("changed") is True, f"bind 未生效：{out}"
    assert _load(st)["gate_data"]["wt_domain"]["sess1"] == ["/mnt/c/x/wt"], _load(st)
    assert gk_state._verify_checksum(str(st)).get("verified") is True, "写后 checksum 未闭环"

    before = st.read_bytes()
    out2 = _run_sp("wt-domain", str(st), "bind", "sess1", "/mnt/c/x/wt")[1]
    assert out2.get("ok") is True and out2.get("changed") is False, f"幂等 bind 语义错：{out2}"
    assert st.read_bytes() == before, "幂等 bind 竟写盘"

    out3 = _run_sp("wt-domain", str(st), "unbind", "sess1", "/mnt/c/x/wt")[1]
    assert out3.get("ok") is True and out3.get("changed") is True, f"unbind 未生效：{out3}"
    assert _load(st)["gate_data"]["wt_domain"]["sess1"] == []
    out4 = _run_sp("wt-domain", str(st), "unbind", "sess1", "/mnt/c/x/wt")[1]
    assert out4.get("changed") is False, f"幂等 unbind 语义错：{out4}"


# ── wd-g：写侧 fail-loud（非法 token / op / path）───────────────────────────
def test_wd_g_failloud_bad_inputs(tmp_path):
    st = _state(tmp_path, {})
    # 阳性对照（防「全拒」假绿）
    assert _run_sp("wt-domain", str(st), "bind", "ok1", "/w")[1].get("ok") is True
    bads = [
        ("bind", "", "/w"),               # 空 token
        ("bind", "bad token", "/w"),      # 含空格
        ("bind", "a" * 65, "/w"),         # 超长
        ("bind", ".lead", "/w"),          # 首字符非 alnum
        ("bind", "_lead", "/w"),          # 首字符非 alnum（域文法不许前导 `_`）
        ("bind", "a/b", "/w"),            # 含 `/`
        ("xx", "tok", "/w"),              # 非法 op
        ("bind", "tok", ""),              # 空 path
    ]
    for bad in bads:
        out = _run_sp("wt-domain", str(st), *bad)[1]
        assert out.get("ok") is False, f"负臂失效：{bad} 竟被接受 → {out}"


# ── wd-h：dry-run 零写盘 ───────────────────────────────────────────────────
def test_wd_h_dryrun_zero_write(tmp_path):
    st = _state(tmp_path, {})
    before = st.read_bytes()
    out = _run_sp("wt-domain", str(st), "bind", "sess1", "/x", "--dry-run")[1]
    assert out.get("ok") is True and out.get("dry_run") is True and out.get("changed") is True, out
    assert st.read_bytes() == before, "dry-run 竟写盘"


# ── wd-i：单一写通路（旁路皆拒）────────────────────────────────────────────
def test_wd_i_single_write_path_denies_bypass(tmp_path):
    st = _state(tmp_path, {"edit_budget": {"sessions": {}}})
    # 阳性对照：合法叶子可写（防「全拒」假绿）
    assert _run_sp("set-nested", str(st), "gate_data.edit_budget.sessions.S.max", "1")[1].get("ok") is True
    for p in ("gate_data.wt_domain.sess1", "wt_domain.sess1"):
        out = _run_sp("set-nested", str(st), p, '["/x"]')[1]
        assert out.get("ok") is False, f"set-nested 竟可写域桶 `{p}` → {out}"
    out = _run_sp("append-list", str(st), "gate_data.wt_domain.sess1", '"/x"')[1]
    assert out.get("ok") is False, f"append-list 竟可写域桶 → {out}"
    out = _run_sp("update-gate-data", str(st), '"wt_domain":{"sess1":["/x"]}')[1]
    assert out.get("ok") is False, f"update-gate-data 竟可整份换域桶 → {out}"
    assert "wt_domain" not in _load(st).get("gate_data", {}), "旁路竟已落地域桶"


# ── wd-j：写→读闭环（bind 后 active_roots 可见）────────────────────────────
def test_wd_j_bind_then_active_roots(tmp_path):
    st = _state(tmp_path, {"wt_domain": {"s1": []}}, worktree="/base")
    assert _run_sp("wt-domain", str(st), "bind", "s1", "/w")[1].get("ok") is True
    assert "/w" in _active_roots(st, "s1"), "写侧 bind 未与读侧 active_roots 咬合"
