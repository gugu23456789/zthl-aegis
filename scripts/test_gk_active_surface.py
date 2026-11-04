#!/usr/bin/env python3
"""RC1 活动写面 红先臂（`ECC-089658238011` + `ECC-20DB32FC0E55`，2026-09-27）。

缺陷（§4.13.30 八 / §8.9-③）：`state.worktree` **单键双职责** ⟹ Gate 3 只认单值
（跨技能收编撞墙 `ECC-089658238011`），且谓词是裸 `path.startswith(wt)` **无目录边界**
（`ECC-73ACEA635A78`：`wt=/a/b` 会放行 `/a/bc/x`）。RC1 = 允许集 `worktrees_extra[]`
（缺省 `[]` == 今日逐字）+ **单一 helper**（Gate 3 与 Gate 5/6/7 同调）。

helper 落在**已跟踪**文件 `scripts/gk_route_center.py`（L5 路由中枢；hook 已 import 其
`_main_worktree`）—— 而非新建脚本：red-first 沙箱会把**未跟踪**的新脚本软链回工作树
（`_redfirst_cli.sh` 覆盖层），新文件在 HEAD 沙箱里**照样存在** ⟹ 行为臂会假绿。

臂清单（红先 = 落刀前必失败；HEAD 无 `in_active_surface` / hook 仍是裸谓词 ⟹ 全红）：
  arm16a 静态：`gk_route_center` 暴露 `active_roots` / `in_active_surface`
  arm16b 静态：`pre_tool_hook.py` 的 Gate 3 与 Gate 5/6/7 **同调** `in_active_surface`，
               且**不再**含裸 `if not path_norm.startswith(wt_norm)`
  arm16c 行为：目录边界 + 允许集语义 + CLI exit 契约（子进程；HEAD 无该函数 ⟹ rc≠0 ⟹ 红）
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SD = Path(__file__).resolve().parent.parent
SCRIPTS = SD / "scripts"
RC = SCRIPTS / "gk_route_center.py"
CLI = SD / "gatekeeper-cli.sh"


def test_arm16a_helper_single_source_in_route_center():
    """arm16a（静态，红先）：helper 在 `gk_route_center` 内且暴露单源函数。"""
    src = RC.read_text(encoding="utf-8")
    assert "def active_roots(" in src, "缺 `active_roots`（`worktree ∪ worktrees_extra` 解析单源）"
    assert "def in_active_surface(" in src, "缺 `in_active_surface`（Gate 3/5/6/7 同调进口）"


def test_arm16b_gate_wiring_uses_helper():
    """arm16b（静态，红先）：Gate 3 与 Gate 5/6/7 同调 helper，裸前缀谓词已清除。"""
    src = (SCRIPTS / "pre_tool_hook.py").read_text(encoding="utf-8")
    assert src.count("in_active_surface(") >= 2, (
        "Gate 3 与 Gate 5/6/7 未**同调** `in_active_surface`（需 ≥2 处调用）")
    assert "if not path_norm.startswith(wt_norm)" not in src, (
        "仍存在裸前缀谓词（无目录边界 + 只认单值）⟹ 未收敛到 helper")


def _run_cases(cases):
    child = (
        "import json,os,sys\n"
        "sys.path.insert(0, os.environ['GK_SCRIPTS'])\n"
        "import gk_route_center as R\n"
        "cs=json.loads(os.environ['GK_CASES'])\n"
        "out=[R.in_active_surface(p, {'worktree': w, 'worktrees_extra': e}) for (w,e,p) in cs]\n"
        "print(json.dumps(out))\n"
    )
    p = subprocess.run([sys.executable, "-c", child],
                       env=dict(os.environ, GK_SCRIPTS=str(SCRIPTS),
                                GK_CASES=json.dumps(cases, ensure_ascii=False)),
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, "helper 子进程失败（函数缺席/异常）：%s" % (p.stderr[-300:],)
    return json.loads(p.stdout.strip().splitlines()[-1])


def test_arm17_cli_p7_delegates_to_helper():
    """arm17（静态）：CLI 写类判定**委派单一实现** `gk_edit_gate.py`（2026-09-28 结构性收敛）。

    演进：本臂原锚 `CLI P7 (R6 lesson)` 注释块（委派 `gk_route_center active-surface`）——
    该块连同 junction / 受保护目录 / 预算读数一并**收归** `scripts/gk_edit_gate.py`
    （见 `docs/plans/2026-09-28-edit-gate-ecc-convergence-plan.md` §2）⟹ 旧锚失效。
    现判据改为：① 两消费点（`cmd_guard_edit` / `pre_tool_check`）**都**委派单源脚本；
    ② 裸 rg 前缀谓词已清除；③ 单源脚本自身复用 `gk_route_center` 的活动写面 helper。
    """
    src = CLI.read_text(encoding="utf-8")
    assert "gk_edit_gate.py" in src, "CLI 写类判定未委派 `gk_edit_gate.py`（单源收敛未落）"
    assert src.count("gk_edit_gate.py") >= 2, (
        "两消费点（guard-edit 与 pre-tool-check）须**同源**委派；实得 %d 处" % src.count("gk_edit_gate.py"))
    assert "wt_wsl" not in src, (
        "CLI 仍是裸 rg 前缀谓词（`wt_wsl` 尚在 ⟹ 无目录边界 + 只认单值，未收敛到 helper）")
    eg = (SCRIPTS / "gk_edit_gate.py").read_text(encoding="utf-8")
    assert "in_active_surface(" in eg and "active_roots(" in eg, (
        "单源脚本未复用 `gk_route_center` 的活动写面 helper（制造第二套写面口径）")
    assert "P7 (R6 lesson)" not in src, "旧 P7 内联块未清除（与单源委派并存 = 两套判定）"


def test_arm16c_dir_boundary_extras_and_cli_contract():
    """arm16c（行为，红先）：目录边界 + 允许集 + CLI exit 契约。

    HEAD 上 `gk_route_center` 无 `in_active_surface` ⟹ 子进程 rc≠0 ⟹ 本臂红（非 error）。
    """
    a, c = "/a/b", "/a/c"
    cases = [
        [a, [], "/a/b/x", True],          # ① 主值内
        [a, [], "/a/bc/x", False],        # ② **目录边界**（裸 startswith 会错判 True）
        [a, [], "/other/x", False],       # ③ 面外
        [a, [c], "/a/c/d", True],         # ④ 允许集内
        [a, [c], "/a/cd/e", False],       # ⑤ 允许集**同前缀兄弟** ⟹ False（边界）
        [a, [c], "/a/b", True],           # ⑥ 主值本身
        [a, ["", 123, None], "/a/b/x", True],  # ⑦ 非法 extras 形态 ⟹ 忽略、不抛
    ]
    got = _run_cases([[w, e, p] for (w, e, p, _x) in cases])
    exp = [x[3] for x in cases]
    assert got == exp, "活动写面判定错：got=%r exp=%r（边界/允许集）" % (got, exp)

    def cli(state_file, path):
        p = subprocess.run([sys.executable, str(RC), "active-surface",
                            "--state", str(state_file), "--path", path],
                           capture_output=True, text=True, timeout=60)
        try:
            j = json.loads((p.stdout or "").strip().splitlines()[-1])
        except Exception:
            j = {}
        return p.returncode, j

    with tempfile.TemporaryDirectory() as td:
        st = Path(td) / ".gatekeeper.state"
        st.write_text(json.dumps({"worktree": "C:\\wt", "worktrees_extra": []}),
                      encoding="utf-8", newline="\n")
        rc_out, j_out = cli(st, "/mnt/c/other/x")
        assert rc_out == 1 and "in_surface" in j_out, (
            "面外路径应 rc=1 且带 `in_surface` 字段（调用方 BLOCK）；实得 rc=%s json=%r"
            % (rc_out, j_out))
        rc_in, j_in = cli(st, "/mnt/c/wt/a")
        assert rc_in == 0 and j_in.get("in_surface") is True, (
            "面内路径应 rc=0/in_surface=True；实得 rc=%s json=%r" % (rc_in, j_in))
        st2 = Path(td) / "empty.json"
        st2.write_text(json.dumps({"worktree": ""}), encoding="utf-8", newline="\n")
        rc_empty, j_empty = cli(st2, "/any")
        assert rc_empty == 1 and j_empty.get("in_surface") is False, (
            "§17-6-P4：无 root（空值）不得产生放行（rc=1/in_surface=False）；实得 rc=%s json=%r"
            % (rc_empty, j_empty))


# ════════════════════ S2：读点声明臂（防误放开；**非红回归** + 非空转自证）════════════════════
# §8.9-③ 的「读点逐项键名清单（10 项）」—— **#5–#9 必须只读 `worktree`（主值）**，不得掺入
# `worktrees_extra`（允许集）走 helper。RC1 只放开**写面**（Gate 3/5/6/7 = #1–#4）；
# 存在性（Gate 2 #5）/ 路由（#6–#7）/ 主门禁视图（#8–#9）**一律保持单键**。
#
# ⚠ 本组是**回归守卫**（HEAD 即绿，其"通过"态就是"未放开"），故**不入选红先集**
#   （同 ledger 先例：arm27b / arm28 / arm37 / arm51 / arm59 / arm66 均标"非红…不入选"）。
#   代价 = "全绿"可能只是断言写空了 ⟹ 每条都带**非空转自证**（注入违禁串必须被报出）。
_S2_TOKENS = ("worktrees_extra", "in_active_surface", "active_roots")

# 读点 #6–#9 的**整文件**面（这些模块本就不该知道允许集）
_S2_READONLY_FILES = ("gk_state_route.py", "gk_advance.py", "gk_self_check.py",
                      "gk_moa_aggregate.py", "_red_attacks.py")


def _s2_leaks(src: str) -> list:
    """src 中出现的违禁串（空列表 = 干净）。"""
    return [t for t in _S2_TOKENS if t in src]


def _py_func(src: str, name: str) -> str:
    """切 `def <name>(` 到下一个**列 0** 的 `def `（与函数长度解耦）。"""
    i = src.index("def %s(" % name)
    rest = src[i:]
    m = re.search(r"(?m)^def ", rest[1:])
    return rest if m is None else rest[:m.start() + 1]


def test_arm21a_readonly_modules_keep_single_key():
    """arm21a（静态守卫，**非红**）：读点 #6–#9 的模块只读 `worktree`，不掺允许集。"""
    for fn in _S2_READONLY_FILES:
        src = (SCRIPTS / fn).read_text(encoding="utf-8")
        assert "worktree" in src, f"{fn} 竟不含 `worktree` ⟹ 扫描面失效（臂空转）"
        assert not _s2_leaks(src), f"{fn} 掺入允许集/helper（读点被误放开）：{_s2_leaks(src)}"
        assert _s2_leaks(src + "\n# worktrees_extra\n"), f"{fn}: 检查器空转（注入违禁串却未报）"


def test_arm21b_route_center_readpoints_keep_single_key():
    """arm21b（静态守卫，**非红**）：`gk_route_center` 的读点函数（#9）不掺允许集。

    ⚠ 只切**函数体**、不整文件 —— 该文件同时是 helper（`active_roots`/`in_active_surface`）的
    **定义地**，整文件断言会假红。
    """
    src = (SCRIPTS / "gk_route_center.py").read_text(encoding="utf-8")
    for fn in ("apply_worktree", "calibration_from_route"):
        seg = _py_func(src, fn)
        assert "worktree" in seg, f"{fn} 切片不含 `worktree` ⟹ 切片失效（臂空转）"
        assert not _s2_leaks(seg), f"{fn} 掺入允许集/helper（读点被误放开）：{_s2_leaks(seg)}"
    assert _s2_leaks(_py_func(src, "apply_worktree") + "\n# worktrees_extra\n"), "检查器空转"


def test_arm21c_gate2_reads_main_value_only():
    """arm21c（静态守卫，**非红**）：Gate 2（存在性，#5）只读**主值** `worktree`。"""
    src = (SCRIPTS / "pre_tool_hook.py").read_text(encoding="utf-8")
    a = src.index("# ── Gate 2:")
    b = src.index("# ── Gate 3:")
    seg = src[a:b]
    assert "worktree" in seg, "Gate 2 切片不含 `worktree` ⟹ 切片失效（臂空转）"
    assert not _s2_leaks(seg), f"Gate 2 掺入允许集/helper（存在性被误放开）：{_s2_leaks(seg)}"
    assert _s2_leaks(seg + "\n# worktrees_extra\n"), "检查器空转"


# ════════════════════ S5：真 git 行为臂（放行/拦阻**同表**；`ECC-089658238011`）════════════════
# §8.6 最低判据的**第三条**（质询 F5 升级：形态臂不足）—— **真 git 仓 + 两个真 worktree**，
# 直喂 `pre_tool_hook.py` 的 stdin（`STATE_FILE` 显式），断言 hook 级**端到端**放行/拦阻：
#   ① 只设 `worktree`=wt1，编辑 wt2 内 ⟹ **BLOCK**（现状不变，落刀前后同）；
#   ② 设 `worktrees_extra=[wt2]`，编辑 wt2 内 ⟹ **放行**（rc=0）—— **本行是红先判据**；
#   ③ 设 `worktrees_extra=[wt2]`，编辑两面之外 ⟹ **仍 BLOCK**（负向判别力）。
# ⚠ 「沙箱无 git ⟹ skip」的前提**已实测证伪**：红先沙箱自身即 `git archive`/`git show` 构建
#   （`_redfirst_cli.sh:181/:184`），子进程 PATH 里 `git`在手 ⟹ 本臂**不预置 skip**，在
#   **沙箱面与 accept 面**均实跑（`skipif` 只在真无 git 时兜底 = 唯一 skip 路径）。
_GIT_SKIP = pytest.mark.skipif(shutil.which("git") is None, reason="git unavailable")


def _s5_git(repo, *a):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    return subprocess.run(["git", "-C", str(repo), *a],
                          capture_output=True, text=True, env=env, timeout=120)


def _s5_feed_hook(state_path, tool, target, cwd):
    """直喂 hook stdin（**不传 `session_id`** ⟹ 不落 `.gatekeeper.session`，零会话副作用）。"""
    payload = json.dumps({"tool_name": tool, "tool_input": {"file_path": target},
                          "cwd": str(cwd)})
    p = subprocess.run([sys.executable, str(SCRIPTS / "pre_tool_hook.py")],
                       input=payload, capture_output=True, text=True, timeout=180,
                       env={**os.environ, "STATE_FILE": str(state_path)}, cwd=str(cwd))
    return p.returncode, (p.stdout or "") + (p.stderr or "")


@_GIT_SKIP
def test_arm22_realgit_hook_surface_same_table(tmp_path):
    """arm22（行为·真 git，红先）：真 git 仓 + 两个真 worktree ⟹ 放行/拦阻**同表**断言。

    HEAD(落刀前) 上 hook Gate 3 仍是裸前缀 `startswith(worktree)`、且不认 `worktrees_extra`
    ⟹ 行② 被 BLOCK（exp 放行）⟹ 本臂红；落刀后（`in_active_surface` + 允许集）行② rc=0 ⟹ 绿。

    ⚠ 判据面 = **hook 退出码**（2=BLOCK / 0=ALLOW），**不是 BLOCK 文案** —— 文案在落刀前后
    由「NOT in active **worktree**」改为「NOT in active **write surface**」⟹ 拿文案当判据会把
    「措辞变更」误当判别力（实测：行① 会因文案不匹配而假红，红因错位）。
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    assert _s5_git(repo, "init", "-q", "-b", "main").returncode == 0
    (repo / "a.txt").write_text("x", encoding="utf-8")
    assert _s5_git(repo, "add", ".").returncode == 0
    assert _s5_git(repo, "commit", "-qm", "init").returncode == 0
    wt1, wt2 = tmp_path / "wt1", tmp_path / "wt2"
    assert _s5_git(repo, "worktree", "add", "-b", "b1", str(wt1)).returncode == 0, "未建成 wt1"
    assert _s5_git(repo, "worktree", "add", "-b", "b2", str(wt2)).returncode == 0, "未建成 wt2"
    assert (wt1 / "a.txt").is_file() and wt2.is_dir(), "两 worktree 未落到真目录"
    (wt2 / "b.txt").write_text("y", encoding="utf-8")

    st = tmp_path / ".gatekeeper.state"
    in_wt2, outside = str(wt2 / "b.txt"), str(tmp_path / "out" / "c.txt")
    # (标签, worktrees_extra, 目标, 期望拦阻?)
    rows = [
        ("① 只设 worktree：wt2 内编辑 ⟹ BLOCK", [], in_wt2, True),
        ("② extras=[wt2]：wt2 内编辑 ⟹ 放行", [str(wt2)], in_wt2, False),
        ("③ extras=[wt2]：两面之外编辑 ⟹ 仍 BLOCK", [str(wt2)], outside, True),
    ]
    got = []
    for _label, extra, tgt, _exp in rows:
        st.write_text(json.dumps({"stage": "ECO-EDIT", "r_phase": "R1",
                                  "worktree": str(wt1), "worktrees_extra": extra},
                                 ensure_ascii=False), encoding="utf-8", newline="\n")
        rc, out = _s5_feed_hook(st, "SearchReplace", tgt, wt1)
        got.append((rc, out, tgt))

    # 同表逐行断言（判据面 = 退出码；拦阻行另核「BLOCK 文案命中目标路径」以防他门顶替）
    for (rc, out, tgt), (label, _e, _t, exp) in zip(got, rows):
        assert (rc == 2) == exp, (
            "同表行错：%s（rc=%s，期望 %s）" % (label, rc, "BLOCK(2)" if exp else "ALLOW(0)"))
        if exp:
            assert "GATEKEEPER-BLOCK" in out and tgt in out, (
                "拦阻行未被『写面』门拿下（文案未命中目标路径）：%s\n%s" % (label, out[-400:]))
        else:
            assert rc == 0 and "GATEKEEPER-BLOCK" not in out, (
                "放行行仍被拦：%s\n%s" % (label, out[-400:]))


# ════════════════════ S6：两消费点**同源**臂（guard-edit ≡ pre-tool-check）═══════════════════════
# 缺陷（用户实测报告，2026-09-28）：**同一 feature worktree 路径** ——
#   `guard-edit` 返回 `{"allowed":true,"path_type":"feature_worktree",…}`（尾部分支只看**硬编码
#   前缀** `<home>/.trae/worktrees/spz_gatekeeper_project/feature/`），
#   而 `pre-tool-check` 返回 `BLOCK: Path not in active write surface` ⟹ **同一规则的两个消费点
#   口径不一致**：`cmd_guard_edit` 从不查 active-surface（RC1 的 helper 只在 P7 落了刀）。
# ⟹ 判据：对**同一路径**，`guard-edit` 的 `allowed` 必须与 `pre-tool-check` 的放行/拦阻**同结论**。
# ⚠ 判据面 = guard-edit 的 `allowed` 字段 + pre-tool-check 的**退出码/`BLOCK` 文案**（不拿措辞当判据）。


def _last_json(text: str) -> dict:
    """取 stdout 中**最后一个**可解析的 JSON 对象（容忍前置 WARN 噪声行）。"""
    for ln in reversed((text or "").splitlines()):
        ln = ln.strip()
        if ln.startswith("{"):
            try:
                return json.loads(ln)
            except Exception:  # noqa: BLE001 — 非 JSON 行跳过
                continue
    return {}


def _sandbox_guard_state(tmp_path, worktree, extras, *, stage="ECO-EDIT", gate_data=None,
                         name=".gatekeeper.state"):
    """最小可用 state：`_checksum` 缺省（`gk_gate_checksum` 对**空** saved 视为 OK）⟹ 免造 checksum。"""
    gd = {"project_type": "standard"}
    if gate_data:
        gd.update(gate_data)
    st = tmp_path / name
    st.write_text(json.dumps({
        "stage": stage, "r_phase": "R1",
        "worktree": str(worktree), "worktrees_extra": [str(x) for x in extras],
        "gate_data": gd}, ensure_ascii=False),
        encoding="utf-8", newline="\n")
    return st


def _wsl(p) -> str:
    """Windows 绝对路径 → WSL `/mnt/<drive>/...`（分类学 #13）。

    只用于**交给 bash 的脚本路径**（bash 自己打不开 `C:\\...`）；参数与 `STATE_FILE`
    保持原形态 —— 判定层已是**双形态比较**（`gk_route_center._path_forms`，方案 C）。
    """
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _gate_env(state_file):
    """显式清空 `GK_SESSION_ID` / `GK_BUDGET_OVERRIDE` ⟹ 预算走**全局**口径且逃逸舱不介入。

    `STATE_FILE` 必须是 **WSL 形态**：bash 侧要 `[ -f ]` 判存在，`C:\\...` 在 WSL 里不存在
    ⟹ 会被当成"显式但缺失"再回落到真实 state（假红）。python 侧由 `_gk_py_path` 转回盘符形态。
    """
    return {**os.environ, "STATE_FILE": _wsl(state_file),
            "GK_SESSION_ID": "", "GK_BUDGET_OVERRIDE": "0"}


def _run_guard_edit(state_file, path):
    p = subprocess.run(["bash", _wsl(CLI), "guard-edit", str(path)],
                       capture_output=True, text=True, timeout=180,
                       env=_gate_env(state_file))
    return p.returncode, _last_json(p.stdout), (p.stdout or "") + (p.stderr or "")


def _run_pre_tool_check(state_file, path, cwd):
    p = subprocess.run(["bash", _wsl(CLI), "pre-tool-check", "edit", str(path)],
                       capture_output=True, text=True, timeout=180,
                       env=_gate_env(state_file), cwd=str(cwd))
    return p.returncode, (p.stdout or "")


def test_arm23_guard_edit_parity_with_pre_tool_check(tmp_path):
    """arm23（行为，红先）：`guard-edit` 与 `pre-tool-check` 对同一路径**同源**判活动写面。

    HEAD（落刀前）上 `cmd_guard_edit` 只判硬编码前缀 ⟹ 面外路径（含旧 feature 前缀）返回
    `allowed:true`（行③④）⟹ 本臂红；落刀后（`cmd_guard_edit` 补 helper 判定）转绿。
    行①②（面内放行）是**负向判别力**：防「一刀切成恒 BLOCK」把放行面打死。
    """
    wt_main = tmp_path / "wt_main"
    wt_extra = tmp_path / "wt_extra"
    out_dir = tmp_path / "out"
    for d in (wt_main, wt_extra, out_dir):
        d.mkdir()
        (d / "a.py").write_text("x = 1\n", encoding="utf-8")
    st = _sandbox_guard_state(tmp_path, wt_main, [wt_extra])

    rows = [
        ("① 主值面内", str(wt_main / "a.py"), True),
        ("② 允许集面内", str(wt_extra / "a.py"), True),
        ("③ 两面之外", str(out_dir / "a.py"), False),
        ("④ 旧 feature 前缀（用户报告的错口径）",
         "<home>/.trae/worktrees/spz_gatekeeper_project/feature/x/y.py", False),
    ]
    for label, path, exp in rows:
        rc_g, j_g, raw_g = _run_guard_edit(st, path)
        allowed = j_g.get("allowed")
        assert allowed is not None, (
            "%s：guard-edit 未输出合法 JSON（rc=%s）\n%s" % (label, rc_g, raw_g[-400:]))
        assert bool(allowed) == exp, (
            "%s：guard-edit 判 `allowed=%s`（期望 %s，rc=%s）路径=%s\n%s"
            % (label, allowed, exp, rc_g, path, raw_g[-400:]))
        if not exp:
            assert j_g.get("reason") == "PATH_NOT_IN_ACTIVE_SURFACE", (
                "%s：BLOCK 须带可机检 reason=PATH_NOT_IN_ACTIVE_SURFACE，实得 %r"
                % (label, j_g.get("reason")))

        rc_p, out_p = _run_pre_tool_check(st, path, wt_main)
        blocked_p = ("BLOCK" in out_p) or (rc_p != 0)
        assert (not allowed) == blocked_p, (
            "%s：**两消费点口径不一致** —— guard-edit allowed=%s / pre-tool-check blocked=%s(rc=%s)\n"
            "路径=%s\npre-tool-check 尾：%s" % (label, allowed, blocked_p, rc_p, path, out_p[-300:]))


# ════════════════════ S7：写类判定**全表**同源臂（结构性收敛的完成判据）════════════════════════
# 承接 S6（只覆盖活动写面）。本臂把 §1.1 的**全部**语义差异一次钉住：**同一路径、同一结论**。
# 旧实现下必红的 4 行（guard-edit 侧全缺）：① stage=DONE ② 受保护目录 `.git/` ③ 预算耗尽
# ④ 经 symlink 进入（junction/mount 形态）。⑤⑥ 为**负向判别力**（防「一刀切成恒 BLOCK」）。
# 排除项：`state` checksum（#6）是**故意**的单侧更严（guard-edit 有、pre_tool_check 无），
#   不纳入同源判据 —— 否则会把「更严」误判成「不一致」。


def test_arm24_edit_gate_parity_full_table(tmp_path):
    """arm24（行为，红先）：写类判定全表 —— `guard-edit` ≡ `pre-tool-check`（同路径同结论）。"""
    wt_main = tmp_path / "wt_main"
    out_dir = tmp_path / "out"
    gitdir = wt_main / ".git"
    for d in (wt_main, out_dir, gitdir):
        d.mkdir()
    (wt_main / "a.py").write_text("x = 1\n", encoding="utf-8")
    (gitdir / "config").write_text("[core]\n", encoding="utf-8")
    (out_dir / "a.py").write_text("y = 1\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(wt_main, target_is_directory=True)

    cases = [
        # (标签, state 关键字, 目标路径, 期望拦阻?)
        ("① stage=DONE", dict(stage="DONE"), str(wt_main / "a.py"), True),
        ("② 受保护目录 .git/", {}, str(gitdir / "config"), True),
        ("③ 预算耗尽（全局 remaining=0）",
         dict(gate_data={"edit_budget": {"max": 1, "used": 1, "remaining": 0}}),
         str(wt_main / "a.py"), True),
        ("④ 经 symlink 进入（junction/mount 形态）", {}, str(link / "a.py"), True),
        ("⑤ 面内常规路径（负向：须放行）", {}, str(wt_main / "a.py"), False),
        ("⑥ 面外路径（负向：须拦阻）", {}, str(out_dir / "a.py"), True),
    ]
    for i, (label, kw, path, exp) in enumerate(cases):
        st = _sandbox_guard_state(tmp_path, wt_main, [], name=".gatekeeper.state.%d" % i, **kw)
        rc_g, j_g, raw_g = _run_guard_edit(st, path)
        allowed = j_g.get("allowed")
        assert allowed is not None, (
            "%s：guard-edit 未输出合法 JSON（rc=%s）\n%s" % (label, rc_g, raw_g[-400:]))
        got_block = not bool(allowed)
        rc_p, out_p = _run_pre_tool_check(st, path, wt_main)
        blocked_p = ("BLOCK" in out_p) or (rc_p != 0)

        assert got_block == exp, (
            "%s：guard-edit 判 blocked=%s（期望 %s，rc=%s）路径=%s\n%s"
            % (label, got_block, exp, rc_g, path, raw_g[-300:]))
        assert blocked_p == exp, (
            "%s：pre-tool-check 判 blocked=%s（期望 %s，rc=%s）路径=%s\n%s"
            % (label, blocked_p, exp, rc_p, path, out_p[-300:]))
        assert got_block == blocked_p, (
            "%s：**两消费点口径不一致**（guard-edit blocked=%s / pre-tool-check blocked=%s）"
            % (label, got_block, blocked_p))


def test_arm25_guard_edit_is_query_only(tmp_path):
    """arm25（行为）：`guard-edit` 是**查询**——调用前后 `edit_budget` 逐字节不变（零副作用）。"""
    wt_main = tmp_path / "wt_main"
    wt_main.mkdir()
    (wt_main / "a.py").write_text("x = 1\n", encoding="utf-8")
    eb = {"max": 4, "used": 1, "remaining": 3, "overrides": []}
    st = _sandbox_guard_state(tmp_path, wt_main, [], gate_data={"edit_budget": eb})
    before = json.loads(st.read_text(encoding="utf-8"))["gate_data"]["edit_budget"]
    _run_guard_edit(st, str(wt_main / "a.py"))
    after = json.loads(st.read_text(encoding="utf-8"))["gate_data"]["edit_budget"]
    assert after == before, "guard-edit 改变了 edit_budget（查询语义被破坏）：%r -> %r" % (before, after)


# ════════════════════ S8：空值三态 × 两消费面（§17-6-P4，红先）════════════════════
# 纪律（§17-6-P4）：空值**三态一律不产生放行**；「非 worktree 模式」= **显式 root 集合**；
#   禁「空值 = 跳过归属校验」。两消费面 = `guard-edit` / `pre-tool-check`（同源 `gk_edit_gate`）。
# HEAD 上 `gk_edit_gate` 有 `roots and …` legacy-skip ⟹ 空 roots 放行 ⟹ 本组红。


def _empty_root_state(tmp_path, tristate, name):
    """空值三态 state：`missing`（键缺失）/ `null`（None）/ `empty`（""）。"""
    d = {"stage": "ECO-EDIT", "r_phase": "R1",
         "gate_data": {"project_type": "standard"}}
    if tristate == "null":
        d["worktree"] = None
    elif tristate == "empty":
        d["worktree"] = ""
    # missing ⟹ 不写该键
    st = tmp_path / name
    st.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    return st


@pytest.mark.parametrize("tristate", ["missing", "null", "empty"])
def test_arm16d_empty_roots_no_skip_tristate(tmp_path, tristate):
    """§17-6-P4（红先）：空值三态 × 两消费面（`guard-edit` / `pre-tool-check`）**一律不放行**。"""
    (tmp_path / "target.py").write_text("x = 1\n", encoding="utf-8")
    target = str(tmp_path / "target.py")
    st = _empty_root_state(tmp_path, tristate, ".gk.p4.%s" % tristate)

    rc_g, j_g, raw_g = _run_guard_edit(st, target)
    assert j_g.get("allowed") is False, (
        "空值态 `%s`：`guard-edit` 竟放行（allowed=%r）—— legacy-skip 未被 P4 消除\n%s"
        % (tristate, j_g.get("allowed"), raw_g[-300:]))

    rc_p, out_p = _run_pre_tool_check(st, target, tmp_path)
    assert ("BLOCK" in out_p) or (rc_p != 0), (
        "空值态 `%s`：`pre-tool-check` 竟放行（rc=%s）\n%s" % (tristate, rc_p, out_p[-300:]))


# ════════════════════ S9：空值三态 × hook 门（§17-3，红先）════════════════════
# §17-3「空值三态一律不产生放行」的 **hook 侧**（`pre_tool_hook.py` Gate 2）。
#   HEAD 上 Gate 2：`worktree = state.get("worktree", "")` → `_win_to_wsl(worktree)`；
#   键为 `null` 时 `worktree=None` ⟹ `_win_to_wsl(None)` 抛 `TypeError` ⟹ hook **崩溃退出
#   （rc=1）**、Gate 2 之后整链（Gate 3/4/5/6/7/8）**不执行** = 非确定性「既非放行亦非 BLOCK」。
#   三态 = 键缺失 / `null` / `""`；判据 = hook rc==2（确定性 BLOCK），且**禁** rc==1（崩溃）。
#   注：Gate 2 是 hook 侧唯一可达的「空 roots」门 —— worktree 非空且存在时 `active_roots`
#   必含之 ⟹ Gate 3/5/6/7 的「空 roots」分支结构上不可达（Gate 2 已先行拦）。


@pytest.mark.parametrize("tristate", ["missing", "null", "empty"])
def test_arm26_hook_empty_tristate_blocks(tmp_path, tristate):
    """§17-3（红先）：hook 侧空值三态（Gate 2）**一律确定性 BLOCK**（rc=2）；禁崩溃（rc=1）。"""
    (tmp_path / "t.py").write_text("x = 1\n", encoding="utf-8")
    st = _empty_root_state(tmp_path, tristate, ".gk.p3.%s" % tristate)
    rc, out = _s5_feed_hook(st, "SearchReplace", str(tmp_path / "t.py"), tmp_path)
    assert rc == 2, (
        "§17-3：空值态 `%s` 下 hook 未确定性 BLOCK（rc=%s；期望 2；rc=1=崩溃 / rc=0=放行）\n%s"
        % (tristate, rc, out[-400:]))

