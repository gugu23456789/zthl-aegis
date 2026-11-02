"""F7 基座：CLI 接线（_CMD_REG 注册 + valid_tools 含 edit + usage 串）。"""
import json
import os
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
SK = os.path.dirname(HERE)
CLI = os.path.join(SK, "gatekeeper-cli.sh")
RC = os.path.join(SK, "scripts", "gk_route_center.py")


def _txt(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_cmd_reg_has_apply_worktree():
    assert re.search(r'^_CMD_REG\[apply-worktree\]="cmd_apply_worktree\|', _txt(CLI), re.M)


def test_apply_worktree_has_code_fix_mode():
    """T8 **路线 A**（2026-09-23 用户裁定）：code-fix 编排挂 `cmd_apply_worktree` 的 `--code-fix` 模式，
    **不新注册命令** —— `_CMD_REG` 在 `PROTECTED_REGION::gate` 内（SKILL.md T48b：
    「agent 无法修改注册表绕过门禁」），故走**区外**既有函数体，零保护区改动。"""
    txt = _txt(CLI)
    assert not re.search(r'^_CMD_REG\[code-fix\]', txt, re.M), "路线 A 下不得新注册 code-fix"
    # 2026-10-28：原按固定 3200 字符窗口切片 —— `--plan` 模式插入后 `--dry-run` 被挤出窗口
    # ⟹ **假红**（与 `_code_fix_seg` 已记录的同一坑）。改按**函数边界**切片，判据面不变
    # （仍是「函数体内须含这四个旗标」）且与函数长度解耦。
    seg = _code_fix_seg()
    for flag in ("--code-fix", "--finding", "--dry-run", "--state"):
        assert flag in seg, f"cmd_apply_worktree 的 code-fix 模式缺 {flag}"


def test_agent_family_resolve_is_single_source():
    """族判定/窄任务编译的单一事实源 = `gk_agent_family.resolve`（CLI 只做参数编排）。"""
    fam_txt = _txt(os.path.join(SK, "scripts", "gk_agent_family.py"))
    assert "def resolve(" in fam_txt and "def main(argv" in fam_txt
    # 2026-09-23（P4）：原用**固定 3200 字符**内联窗口 —— P4 的批量层插在函数开头（~2.5KB）
    # 把单发路径的 `gk_agent_family.py` 引用挤出窗口 ⟹ **假红**。改用函数边界切片。
    assert "gk_agent_family.py" in _code_fix_seg(), "CLI 须委托 gk_agent_family（禁第二实现）"


def test_valid_tools_contains_edit():
    m = re.search(r'^    local valid_tools="([^"]+)"', _txt(CLI), re.M)
    assert m and "edit" in m.group(1).split(",")


def test_route_center_usage_lists_apply_worktree():
    assert "apply-worktree" in _txt(RC)


def _code_fix_seg():
    """`cmd_apply_worktree` **整个函数体**（切到下一个列 0 的 `}` 为止）。

    2026-09-23（P4 落刀后即踩第二次）：原按**固定字符窗口**（6000 → 9000）切片，函数一长
    就把回显串挤出窗口 ⟹ 本臂**假红**。判据面是「函数体内的一条串」，与函数长度无关 ⟹
    改为按**函数边界**切片，从此与长度解耦。
    """
    txt = _txt(CLI)
    rest = txt[txt.index("cmd_apply_worktree()"):]
    m = re.search(r"(?m)^\}\s*$", rest)
    return rest[: m.end()] if m else rest


def test_code_fix_injects_worktree_into_narrow_task():
    """ECC-8BE02C8CBB5F（2026-09-23）— `--code-fix` 非 dry-run 必须把 worktree 路径喂进窄任务。

    依据：`gk_agent_edit.apply_edit(worktree, rel_path, ...)` **以 worktree 为根**做路径拼接与
    逃逸预检（`realpath(join(wt, rel))` 须落在 wt 内）⟹ 该路径是隔离的**唯一入口**。
    原实现在建 worktree **之前**编译窄任务、且调 `resolve` 时不带 `--worktree`
    ⟹ 窄任务串的 `worktree:` 行**恒为空**（dry-run 实测 `worktree: \n`），subagent 只能退到
    CLI cwd（技能主树）作业 —— worktree 白建、A2「禁自行挑选目录」名存实亡。
    """
    seg = _code_fix_seg()
    assert '--worktree "$_wt"' in seg, \
        "code-fix 须把已建 worktree 路径传给 resolve（否则窄任务 worktree: 行恒空、隔离失效）"


# ─── ECC-FBAEA0AD4B77：保护区文案**不得承诺不存在的通道** ─────────────────────
# 根因（git 考古，见 docs/plans/2026-09-21-hook-xenv-form-fix-plan.md §Q1）：文案
#   `require R-phase guard-edit` 自 `116be6d`（2026-05-29 T39 保护区初版）引入后从未更新，
#   而它描述的机制语义此后**两度反转**：① 初版 `cmd_guard_edit` = stage=IDLE **提前放行**、
#   R 相位内才拦 ⟹ 今天 = IDLE 直接拒入（`NO_ACTIVE_R_PHASE`）+ 行级拦；② 初版 `_protected_region_check`
#   = **纯文件级** ⟹ 今天 = 行级 BLOCK + 文件级 WARN（F-REV-45 2026-09-13）。
#   **且 R-T/batch8 计划内亦无该通道设计**（R-T7.13 攻击面 #6 的防御恰是"保护不能被绕过"；
#   Gate 8 的「活跃 R-phase 授权」是**防裸跑**语义，非保护区放行）⟹ 该句是空承诺。

def test_arm69_protected_region_message_promises_no_channel():
    """BLOCK 文案须如实：**不得**出现 `require R-phase guard-edit`（通道不存在），
    但保护区拦截本身不得被削弱（`is in PROTECTED_REGION` 仍在）。"""
    t = _txt(CLI)
    assert "require R-phase guard-edit" not in t, (
        "BLOCK 文案仍承诺 R-phase guard-edit 通道 —— 该通道不存在"
        "（`_protected_region_check` 无 token 分支 / `cmd_guard_edit` 纯咨询 / R-T 计划亦无该设计）"
        "：ECC-FBAEA0AD4B77")
    assert "is in PROTECTED_REGION" in t, "保护区拦截判据被误删（本臂只允许改措辞）"
    # SKILL.md 半：red-first 沙箱只含 scripts/ + CLI ⟹ 沙箱内不判；accept 面必判。
    md = os.path.join(SK, "SKILL.md")
    if os.path.isfile(md):
        assert "整个文件被锁" not in _txt(md), (
            "SKILL.md 仍称「未传 target_line ⟹ 整个文件被锁」—— 实为**文件级 WARN 放行**"
            "（F-REV-45，2026-09-13）：ECC-FBAEA0AD4B77")


# 显式安全例外（**逐行**匹配，非按旗标名 —— 防同名旗标在新上下文里被误判豁免）：
#   `--type` 处于 `while [ $# -ge 2 ]`（进入循环即保证 `$#>=2` ⟹ `shift 2` 恒成功）。
_FLAG_SHIFT_SAFE_LINES = {
    '--type) audit_type="${3:-performance}"; shift 2 ;;',
}


def test_no_unguarded_shift_two_in_flag_branches():
    """flag 缺值族（`ECC-AAD612CC8270`）静态面：`case` 旗标支裸 `shift 2` 即死循环。

    机制：`while [ $# -gt 0 ]` 内旗标支写 `var="${2:-}"; shift 2 ;;` —— 尾随缺值（`$#==1`）时
    `shift 2` **返回非零且不移位**（`set -uo pipefail` 无 `-e` ⟹ 不中止）⟹ 循环判据恒真。
    实测（2026-09-24 修前）：`apply-worktree --code-fix --family` `timeout 12` → **rc=124（挂起）**。
    判据：旗标支内 `shift 2` 须带 `2>/dev/null || shift` 守卫（缺值退化为单步 `shift`，循环得以退出）。
    """
    txt = _txt(CLI)
    bad = []
    for m in re.finditer(r"(?m)^\s+-{1,2}[A-Za-z0-9_.-]+\)[^\n]*$", txt):
        line = m.group(0).strip()
        if "shift 2" not in line or "2>/dev/null" in line:
            continue
        if line in _FLAG_SHIFT_SAFE_LINES:
            continue
        bad.append(line)
    assert not bad, f"旗标支裸 shift 2（尾随缺值即死循环）: {bad}"


def test_worktree_root_self_resolve_hoisted_before_mode_dispatch():
    """`ECC-0A9B349F31BA`（2026-09-25，用户裁定「code-fix 路径没有自解析——显式补 env」）。

    现场：`gk_route_center.apply_worktree` 要求 `GATEKEEPER_WORKTREE_ROOT` 显式给出（且须 ∈
    `DEV_WORKTREE_ROOTS`），缺则 fail-loud。原实现把自解析只写在 `--session` 分支里，而
    `--code-fix` 的建 worktree 走**子进程自调**、plain 走函数尾部 ⟹ 那两条路径撞
    `GATEKEEPER_WORKTREE_ROOT 未设置`（2026-09-25 实测 plain 与 code-fix 均复现）。
    判据：自解析须在**模式分派之前**（三路共用），且全函数**恰好一处**（禁第二实现）。

    2026-10-29（载荷外移）：派生表达式从 bash 内联 `python3 -c` 移到
    `scripts/gk_apply_worktree_cli.py route-root` ⟹ 判据面随之改两点：
      ① bash 函数体内 `route-root` 调用**恰好一处**且位于模式分派之前（禁第二实现）；
      ② bash 侧**不得**再出现 `DEV_WORKTREE_ROOTS` 字面量（派生单源只在模块里）。
    意图（单点派生 + 三路共用）不变。
    """
    seg = _code_fix_seg()
    deriv = 'gk_apply_worktree_cli.py" route-root'
    n = seg.count(deriv)
    assert n == 1, f"GATEKEEPER_WORKTREE_ROOT 自解析须恰好一处（禁第二实现），实测 {n} 处"
    i_deriv = seg.index(deriv)
    i_session = seg.find('if [ -n "$session" ]')
    assert i_session != -1, "未找到 `--session` 模式分派锚（函数结构已变，判据须重校）"
    assert i_deriv < i_session, \
        "自解析须在模式分派**之前**（否则 plain / --code-fix 路径仍无兜底 ⟹ RouteError）"
    assert "DEV_WORKTREE_ROOTS" not in seg, (
        "bash 侧禁第二实现（派生只许在 gk_apply_worktree_cli.route-root）")
    mod = _txt(os.path.join(SK, "scripts", "gk_apply_worktree_cli.py"))
    assert mod.count('getattr(rc, "DEV_WORKTREE_ROOTS"') == 1, \
        "route-root 的派生实现须恰好一处"


def test_code_fix_next_cmd_avoids_unparsed_tier_flag():
    """ECC-8BE02C8CBB5F（2026-09-23）— 回显的 next 派发串不得下发 `monitor` **不解析**的 `--tier`。

    `cmd_monitor` 的参数表无 `--tier` 分支（档位只来自 `resolve-narrow` 窄任务清单或角色默认，
    经 `SUBAGENT_TIER` env 下发）⟹ `--tier N` 会被 `*)` 分支当**位置参数**连续覆盖、静默丢弃
    （更坏：单独跑 `monitor --subagent --tier 3` 时 `stage` 变成 `"3"` ⟹ 把 `3` 当任务下发）。
    """
    seg = _code_fix_seg()
    assert "SUBAGENT_TIER=" in seg, "档位须以 SUBAGENT_TIER env 形态下发"
    assert not re.search(r'monitor --subagent[^\n"]*--tier ', seg), \
        "next 串不得下发 monitor 不解析的 --tier"


def test_apply_worktree_honors_main_repo_flag():
    """ECC-68EDF1CDA4D5（2026-10-02）— `--main-repo` 须被捕获并透传给路由中枢。

    现场：旗标支 `--main-repo) shift 2 ... ;;` 只丢值；route-center 调用点硬编码
    `--main-repo "$SKILL_DIR"` ⟹ `apply-worktree --session --main-repo <外部仓>` 恒落技能仓
    （finding「apply-worktree 仅技能仓（CLI 丢弃 --main-repo）」）。
    判据：① 旗标支捕获 `main_repo_arg`；② **每一处**调用点均透传 `${main_repo_arg:-$SKILL_DIR}`
    （route-center ×3 + `--receive-check` ×1，DRAFT-16 补后者、2026-10-28 的 `--plan`
    计划建树补第三处 route-center；缺省仍技能仓 ⟹ 零回归）。
    """
    seg = _code_fix_seg()
    assert "--main-repo) main_repo_arg=" in seg, \
        "`--main-repo` 未被捕获（仍丢弃值 ⟹ 只能落技能仓）"
    n = seg.count('--main-repo "${main_repo_arg:-$SKILL_DIR}"')
    assert n == 4, \
        "四处调用点须透传 ${main_repo_arg:-$SKILL_DIR}（route-center ×3 + --receive-check ×1），实测 %d 处" % n


def test_session_identity_worktree_token_chain():
    """ECC-AB2FA16E9133（2026-10-02）— 身份链 = env > worktree token > marker(legacy)。

    病象：单槽 `.gatekeeper.session` 被并发会话（含 subagent）覆写 ⟹ CLI 自解析到**外来 sid**
    ⟹ 其 `.gatekeeper.plan.<sid>` 缺失 ⟹ **静默**落默认 state（实测：6 条 `plan-refinement
    --task` 入队仅 1 条落域、5 条落默认）。
    修法：由本进程 `$PWD` 所在 git worktree 派生**平台无关** token（不依赖任何宿主 hook API ⟹
    Trae / WorkBuddy 通用；worktree 天然按会话隔离 ⟹ 无共享单槽、无竞态）。token 档须在 marker
    裸读**之前**（Q3a：env > token > marker）。解析单源 = `scripts/gk_session_identity.py`。
    """
    txt = _txt(CLI)
    i_tok = txt.find('gk_session_identity.py" derive --path "$PWD"')
    assert i_tok != -1, "启动块未接 worktree 身份 token 派生（平台无关兜底缺失）"
    i_marker = txt.find('.gatekeeper.session" ]; then')
    assert i_marker != -1, "未找到 marker 裸读锚（结构已变，判据须重校）"
    assert i_tok < i_marker, "token 档须在 marker 裸读**之前**（Q3a：env > token > marker）"
    assert "*[!0-9A-Za-z_-]*)" in txt, "缺 token 非法字符护栏（须文件名安全）"


# ─── 接收侧纯检测接线（2026-10-03，计划 DRAFT-9 §2.2/§2.4/T2）────────────────────
def test_apply_worktree_receive_check_delegates_single_source():
    """`--receive-check <wt>` 分支须**只读**且委托单源 `scripts/gk_receive_check.py`。

    依据（DRAFT-9 §2.2）：检测单源（rc 全函数 + 优先级链 + `hook_live_from` 派生 +
    `--diff-filter=ACDMRTUXB` + 复用 `expected_worktrees`）**只许一处**；CLI 只做参数编排
    （同 `gk_agent_family` 先例，**禁第二实现**）。留痕 = 回包字段（**不写 state**）。
    且须登记**计费豁免**（零副作用形态显式列举，P9）。
    """
    seg = _code_fix_seg()
    assert "--receive-check" in seg, "cmd_apply_worktree 缺 --receive-check 分支"
    assert "gk_receive_check.py" in seg, "须委托单源 gk_receive_check.py（禁第二实现）"
    assert os.path.isfile(os.path.join(SK, "scripts", "gk_receive_check.py")), "检测单源脚本缺失"
    assert '" --receive-check "' in _txt(CLI), "缺 --receive-check 计费豁免登记（零副作用）"


# ─── §3-T2 判据载体（DRAFT-16：真 git 夹具 + 构造先验 + 必失败负样本 + 元判据）────────
# 前身仅静态串断言（= §4-C4 自判的假绿形态）；本组改为**行为臂**：真跑 CLI 端到端。
_T2_PRIOR = ("ff", False, 0)   # 构造先验：可FF + 空 diff ⟹ (ancestor, surface_review, rc)


def _t2_git(cwd, *a):
    r = subprocess.run(["git", "-C", str(cwd), *a], capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"git {a} rc={r.returncode}: {r.stderr}")
    return r


def _t2_env(tmp_path):
    """真 git 仓（master=A）+ linked worktree（与 master 同点 ⟹ 空 diff）+ 空 state。

    期望值由**构造先验**给出（**不**从被测回包回读，§3-T2 禁回读）。
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _t2_git(repo, "init", "-q")
    _t2_git(repo, "config", "user.email", "t@t")
    _t2_git(repo, "config", "user.name", "t")
    (repo / "f.txt").write_text("A\n", encoding="utf-8")
    _t2_git(repo, "add", "f.txt")
    _t2_git(repo, "commit", "-q", "-m", "A")
    _t2_git(repo, "branch", "-M", "master")
    wt = tmp_path / "wt"
    _t2_git(repo, "worktree", "add", "-q", "-b", "b", str(wt))
    state = tmp_path / "st.state"
    state.write_text("{}\n", encoding="utf-8")
    return repo, wt, state


def _t2_cli(wt, repo, state):
    """真跑 CLI `apply-worktree --receive-check`（行为面）。`--main-repo` 走 DRAFT-16 新补的透传。"""
    r = subprocess.run(
        ["bash", CLI, "apply-worktree", "--receive-check", str(wt),
         "--main-repo", str(repo), "--state", str(state)],
        capture_output=True, text=True, timeout=120)
    return json.loads(r.stdout)


def test_t2_receive_check_cli_fixture_truth(tmp_path):
    """§3-T2 判据载体：真 git 夹具 ⟹ 三元组 == **构造先验**（非回读）。"""
    repo, wt, state = _t2_env(tmp_path)
    o = _t2_cli(wt, repo, state)
    assert (o["ancestor"], o["surface_review"], o["rc"]) == _T2_PRIOR


def test_t2_negative_missing_fixture(tmp_path):
    """§3-T2 必失败负样本 ①：夹具缺失 ⟹ fail-loud（rc=2 / alive=false），**不得** clean。"""
    repo, _wt, state = _t2_env(tmp_path)
    o = _t2_cli(tmp_path / "nope", repo, state)
    assert o["rc"] == 2 and o["alive"] is False


def test_t2_negative_tampered_fixture_deviates(tmp_path):
    """§3-T2 必失败负样本 ② + **元判据**：向夹具追加一次提交（空→非空）⟹ 三元组**必偏离**先验。

    若篡改后仍等于先验 ⟹ 判据同源恒过 ⟹ 判据本身不合格（元判据）。
    """
    repo, wt, state = _t2_env(tmp_path)
    base = _t2_cli(wt, repo, state)
    assert (base["ancestor"], base["surface_review"], base["rc"]) == _T2_PRIOR
    (wt / "g.txt").write_text("B\n", encoding="utf-8")
    _t2_git(wt, "add", "g.txt")
    _t2_git(wt, "commit", "-q", "-m", "B")          # 已知篡改
    after = _t2_cli(wt, repo, state)
    triple = (after["ancestor"], after["surface_review"], after["rc"])
    assert triple != _T2_PRIOR                       # 元判据：篡改后必偏离
    assert triple == ("ff", True, 1)                 # 构造先验：可FF + 非空 ⟹ rc=1
