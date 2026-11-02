#!/usr/bin/env python3
"""L1 自动派发 + 预算解耦接线红先臂（2026-09-23，用户裁定「next 可直接执行」）。

用户裁定原文（本轮）：「coder 用的 worktree 申请下发、分配 coder 专用窄任务，这些流程应该
从**手动拼接**变成**瞬时自动填空自动下发**，刚才的操作失误堵住」+「把节点 `edit_budget.max`
与批次数解耦」。

三条被堵的坑（均有实测锚，非推测）：
  ① `next` 串尾部是**字面量 `<narrow-task>`** ⟹ 5~10 KB 窄任务须人工拼进命令行（引号/换行/
     中文标点全是雷）；
  ② `--dry-run` 回的窄任务 **worktree: 行为空**（它在建 worktree **之前**编译）⟹ 直接拿去派发
     会把落刀打回调用方 cwd（实测 = 主树，`ECC-D398E70B7E72`）；
  ③ coder 落刀**不**吃主 agent 配额（F2 起 `GK_BUDGET_OVERRIDE=1`）⟹ 主 agent 的「验收 + 收口
     + 修坏」手改需求没有来源，只能人工 `state-patch` 抬 max（**绕过梯度**、刷 `overrides[]` 噪声）。

红先语义：修前臂 ①②③④⑥ 必红（无 `--task-file`、无 `dispatchable`、无 `_grant_node_budget`、
CLI 内无预算常量、`next` 仍留 `<narrow-task>` 占位符）。
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SK = HERE.parent
# 红先对照臂：`GK_CLI_UNDER_TEST=<修复前 CLI 绝对路径>`（默认 = 仓内 CLI）
# ⟹ 指向 `git show HEAD:gatekeeper-cli.sh` 的副本即可复现「修前必红」。
CLI = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SK / "gatekeeper-cli.sh"))

sys.path.insert(0, str(HERE))


def _txt(p) -> str:
    with open(p, encoding="utf-8") as f:
        return f.read()


def _wsl(p) -> str:
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _code_fix_seg() -> str:
    """`cmd_apply_worktree` **整个函数体**（切到下一个列 0 的 `}` 为止）。

    2026-09-23（P4 批量派发落刀后即踩）：原实现按**固定字符窗口**（6000→9000）切片，
    函数每长一次就假红一次（找不到 `SUBAGENT_TIER=`）。判据面是「函数体内的一条串」，
    与函数长度**无关** ⟹ 改为按**函数边界**切片，从此与长度解耦。
    """
    t = _txt(CLI)
    rest = t[t.index("cmd_apply_worktree()"):]
    m = re.search(r"(?m)^\}\s*$", rest)
    return rest[: m.end()] if m else rest


# ─── 臂① `--task-file` 通道 ──────────────────────────────────────────────────

def test_monitor_has_task_file_flag():
    """`cmd_monitor` 必须解析 `--task-file`（否则 next 串无落点、窄任务仍须人工拼命令行）。"""
    t = _txt(CLI)
    seg = t[t.index("cmd_monitor()"):][:3200]
    assert "--task-file)" in seg, (
        "`cmd_monitor` 未解析 `--task-file` ⟹ L1 的 next 串无落点")


def test_monitor_task_file_fail_loud_paths_are_typed():
    """文件不存在 / 为空 / 非 `--subagent` 三条路径都须 `return 2`（结构性钉住）。

    ⚠ 不做**功能臂**跑 `--subagent --task-file <缺失>`：修前该形态会把文件路径当 `task`
    继续走进派发前置，有真实发起 API 调用的风险 ⟹ 红线（不得为造红先而触外呼）。
    """
    t = _txt(CLI)
    i = t.index('if [ -n "$task_file" ]; then')
    body = t[i:i + 1200]
    assert "--task-file 不存在" in body, f"缺「文件不存在」拒绝：{body[:400]}"
    assert "--task-file 为空" in body, f"缺「文件为空」拒绝：{body[:400]}"
    assert "--task-file 仅与 --subagent 同用" in body, f"缺「非 subagent」拒绝：{body[:400]}"
    assert body.count("return 2") >= 3, f"拒绝路径未全部 fail-loud：{body[:400]}"


@pytest.mark.skipif(shutil.which("bash") is None, reason="本机无 bash")
def test_monitor_rejects_task_file_outside_subagent_mode(tmp_path):
    """`--task-file` 只与 `--subagent` 同用；否则 exit 2 且点名参数面。

    修前行为：`--task-file` 落 `cmd_monitor` 的 `*)` 分支被当**位置参数**吃掉 ⟹ 文件路径
    变成 `stage`，随后去查 `<path>.json` schema 失败 → 报「no schema for …」
    （**误导性错误 + rc 1**）。本臂钉住「错就错在参数面」，不让人再被 schema 报错带偏。
    """
    f = tmp_path / "task.txt"
    f.write_text("dummy", encoding="utf-8", newline="\n")
    r = subprocess.run(
        ["bash", "-lc", 'bash "%s" monitor --task-file "%s"' % (_wsl(CLI), _wsl(f))],
        capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert r.returncode == 2, f"非 --subagent 形态未 fail-loud（rc={r.returncode}）：{out[:300]}"
    assert "--task-file 仅与 --subagent 同用" in out, f"错误文案未点名参数面：{out[:300]}"


# ─── 臂② next 串无占位符 ────────────────────────────────────────────────────

def test_code_fix_next_is_directly_executable():
    """`next` 串必须**可直接执行**：带 `--task-file <实体路径>`，且不得残留字面量占位符。

    判据落在**回显的 next 串本身**（而非整段函数体）：函数体注释里为了说明历史会**引用**
    该占位符字样，那不是可执行契约；契约是「下发的那一行里不能再有占位符」。
    """
    seg = _code_fix_seg()
    # 回显串是 `echo "{\"ok\":true,…,\"next\":\"…\"}"` ⟹ 源码里是**转义引号**形态，
    # 故按字面 `\"next\":\"` 切分（原用 `"next":"` 正则匹配不到 ⟹ 会**假红**）。
    # 2026-09-23（会话入口落刀后即踩）：本函数现在**有两处** `next`（`--session` 分支的
    # `next` 在前）⟹ 按裸 `"next":"` 取**首个**会取到会话串、本臂假红。改为**锚定 code-fix
    # 回显的专属前导**（`narrow_task_file` 紧邻 `next`），判据强度不变。
    _mark = '\\"narrow_task_file\\":\\"$_task_file\\",\\"next\\":\\"'
    assert _mark in seg, f"cmd_apply_worktree 未回 code-fix next 串：{seg[-600:]}"
    nxt = seg.split(_mark, 1)[1].split('\\"')[0]
    assert "<narrow-task>" not in nxt, (
        f"next 串仍留字面量占位符 ⟹ 仍要人工拼接（用户明令堵掉）：{nxt}")
    assert "--task-file " in nxt, f"next 串未带 --task-file（仍要手工喂任务）：{nxt}"
    assert "--role coder" in nxt and "SUBAGENT_TIER=" in nxt, (
        f"next 串未自填 role/tier（仍要手抄）：{nxt}")


def test_code_fix_writes_narrow_task_to_file():
    """窄任务必须落盘到 `"$STATE_FILE".dispatch/`（被 `.gitignore` 的 `.gatekeeper.state*` 覆盖）。"""
    seg = _code_fix_seg()
    assert '_task_dir="${_st}.dispatch"' in seg, "未定义任务文件目录（须 state 旁路 + gitignore 覆盖）"
    assert '>"$_task_file"' in seg, "窄任务未写入 task file"


# ─── 臂③ dry-run 显式标注不可派发 ──────────────────────────────────────────

def test_code_fix_dry_run_marks_not_dispatchable():
    """`--dry-run` 回包须带 `dispatchable: false` + 原因（源头堵 `ECC-D398E70B7E72` 类事故）。

    2026-10-29（载荷外移）：判定从 bash 内联 `python3 -c` 移到
    `scripts/gk_apply_worktree_cli.py codefix-dry` ⟹ 判据面拆两半（判据不放松）：
      ① bash dry 分支**必须**走该子命令（禁回到内联载荷）；
      ② 模块内**必须**同时置 `dispatchable=False` 与 `not_dispatchable_reason`。
    """
    seg = _code_fix_seg()
    assert 'gk_apply_worktree_cli.py" codefix-dry' in seg, (
        "dry-run 分支未走 codefix-dry ⟹ 操作者仍可能直接拿空 worktree 的窄任务去派发")
    mod = _txt(SK / "scripts" / "gk_apply_worktree_cli.py")
    assert 'obj["dispatchable"] = False' in mod, "dry-run 未标注不可派发"
    assert 'obj["not_dispatchable_reason"]' in mod, "dry-run 未给出不可派发**原因**"


# ─── 臂④⑤⑥ 预算解耦接线 ───────────────────────────────────────────────────

def test_code_fix_grants_node_budget():
    """派发须为主 agent 追加节点额度，且留痕 `source=code-fix`（设计 §4 additive）。"""
    seg = _code_fix_seg()
    assert '_grant_node_budget "code-fix"' in seg, (
        "派发未追加节点额度 ⟹ 主 agent 的验收/收口手改仍需人工 state-patch 抬 max")


def test_grant_helper_writes_through_single_writer():
    """追加须走 CLI 内部单一出纳 `_state_write`，**不得**走 `state-patch`
    （后者会**额外**记一条 `source=state_patch` ⟹ 与 code-fix 条重复成台账噪声）。

    2026-10-27（U3 归因）：原取 `_grant_node_budget() {` 起**固定 1600 字**窗口 —— 2026-10-24
    的 D4 注释块（额度兑换总量上限 + 冷却）把 `_state_write` 推出窗口 ⟹ 源码合规仍判红。
    改用下方 `_grant_body()` 切**整个函数体**（与函数长度解耦，判据不放松）。
    """
    body = _grant_body()
    assert "_state_write " in body, f"未走单一出纳：{body[:400]}"
    tail = body.split("# 走 `_state_write`")[-1]
    assert "gatekeeper-cli.sh" not in tail and "state-patch \"" not in tail, (
        "追加疑似走了 `state-patch` ⟹ 覆盖台账会被记两条：%s" % tail[:300])


def _grant_body() -> str:
    """`_grant_node_budget` 整个函数体（切到下一个列 0 的 `}`，与函数长度解耦）。"""
    t = _txt(CLI)
    rest = t[t.index("_grant_node_budget() {"):]
    m = re.search(r"(?m)^\}\s*$", rest)
    return rest[: m.end()] if m else rest


# ─── ECC-28DB1E33027A：额度授予**永不降**（人工抬高的 max 不得被夹回硬顶）────────
# 病象（实测 2 次）：用户 2026-09-24 裁定把 `edit_budget.max` 抬到 500；此后每次
#   `apply-worktree --code-fix` 派发，`_grant_node_budget` 的 `min(<cur>+g, CAP)` 都把它
#   **夹回 16** ⟹ 后续编辑全被 Gate4 拦死（`used=130/max=16/remaining=0`）。注释自称
#   「additive」只对 `max ≤ CAP` 成立 —— 对已被人抬高到 CAP 之上的值，它是**向下夹**。
#   ⚠ 行为面不可跑：`--code-fix --dry-run` 在授予**之前**返回；非 dry-run 会建真 worktree，
#     且授予写的是 `$STATE_FILE`（非 `--state`）⟹ 会污染真 state（本就是本缺陷的现场）。
#     故判据面 = **源形态臂**（arm67）+ **载荷语义臂**（arm68，直接求值生产载荷，非副本）。

def test_arm67_grant_never_lowers_max_source():
    """不得对 `max` / `remaining` 直接 `min(<cur>+g, CAP)` 夹取；须为永不降形态 `max(<cur>, min(...))`。"""
    body = _grant_body()
    for field in ("max", "remaining"):
        assert ("min(int(eb.get('%s',0))+$_g,$_EDIT_BUDGET_HARD_CAP)" % field) not in body, (
            "`%s` 仍直接夹取 ⟹ 会把人工抬高的 max 夹回硬顶（ECC-28DB1E33027A）" % field)
    assert "eb['max']=max(" in body, "max 未改成永不降形态（缺 `eb['max']=max(...)`）"
    assert "eb['remaining']=max(" in body, "remaining 未改成永不降形态"


def test_arm68_grant_payload_semantics_never_lower():
    """语义臂：把函数体里的 `_state_write` 载荷**原样取出求值**（非副本实现），
    代入 `g=4` / `CAP=16` 且 `max=remaining=500` ⟹ 结果不得低于 500（含 `sessions.*` 域）。"""
    body = _grant_body()
    m = re.search(r'_state_write "\n(.*?)\n" >/dev/null', body, re.S)
    assert m, "未在 `_grant_node_budget` 内定位 `_state_write` 载荷（判据面失锚）"
    payload = m.group(1).replace("$_g", "4").replace("$_EDIT_BUDGET_HARD_CAP", "16")
    d = {"gate_data": {"edit_budget": {
        "max": 500, "remaining": 500,
        "sessions": {"s1": {"max": 500, "remaining": 500}}}}}
    exec(compile(payload, "<grant-payload>", "exec"), {"d": d})
    eb = d["gate_data"]["edit_budget"]
    assert eb["max"] >= 500 and eb["remaining"] >= 500, eb
    assert all(v["max"] >= 500 and v["remaining"] >= 500 for v in eb["sessions"].values()), eb


def test_budget_constants_match_advance():
    """CLI 侧常量须与 `gk_advance` 同源（梯度×2 / 硬顶 16）—— 防两语言漂移。"""
    t = _txt(CLI)
    m1 = re.search(r"^_EDIT_BUDGET_PER_LR=(\d+)$", t, re.M)
    m2 = re.search(r"^_EDIT_BUDGET_HARD_CAP=(\d+)$", t, re.M)
    assert m1 and m2, "CLI 侧未定义 `_EDIT_BUDGET_PER_LR` / `_EDIT_BUDGET_HARD_CAP`"
    from gk_advance import EDIT_BUDGET_HARD_CAP, EDIT_BUDGET_PER_LR  # noqa: E402
    assert int(m1.group(1)) == EDIT_BUDGET_PER_LR, (
        f"每单位梯度额度漂移：CLI={m1.group(1)} py={EDIT_BUDGET_PER_LR}")
    assert int(m2.group(1)) == EDIT_BUDGET_HARD_CAP, (
        f"单节点硬顶漂移：CLI={m2.group(1)} py={EDIT_BUDGET_HARD_CAP}")


def test_budget_hard_cap_never_exceeds_ceiling():
    """不变式（2026-10-07；`ECC-B1EC1904B96A`）：CLI 单节点硬顶须 **≤** `gk_advance.EDIT_BUDGET_CEILING`
    —— 补上面那条同源机检**未覆盖**的 `CEILING` 面。防两语言常量**反转**：`_grant_node_budget`
    的 additive 上限（=`_EDIT_BUDGET_HARD_CAP`）一旦越过 §17.2 外生安全上限（=24），
    就等于把「②夹取」放宽到 CEILING 之外。现状 16 ≤ 24 已满足 ⟹ **绿臂（不变式，非红先）**。
    """
    t = _txt(CLI)
    m = re.search(r"^_EDIT_BUDGET_HARD_CAP=(\d+)$", t, re.M)
    assert m, "CLI 侧未定义 `_EDIT_BUDGET_HARD_CAP`"
    from gk_advance import EDIT_BUDGET_CEILING  # noqa: E402
    assert int(m.group(1)) <= EDIT_BUDGET_CEILING, (
        f"CLI 硬顶越过外生上限（预算被放宽）：CLI={m.group(1)} > CEILING={EDIT_BUDGET_CEILING}")


def test_cli_syntax_is_valid():
    """落刀后 CLI 必须仍能通过 `bash -n`（红先阶段的静态底线）。"""
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash")
    r = subprocess.run(["bash", "-n", _wsl(CLI)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"gatekeeper-cli.sh 语法错误：{r.stdout}{r.stderr}"


# ─── P4 批量派发（2026-09-23 用户裁定「实装 P4」）─────────────────────────────
# `--batch --finding a,b,…` = 一次申请 N 个 worktree + 回 N 条可直接执行的 next；
# k ≤ 2（用户裁定起步值）、族间 allowed_paths 两两 disjoint、合并必须串行。

def test_batch_flag_and_k_max_default_are_present():
    """`--batch` 必须在**两个** case 位都注册，且 k 默认 = 2。

    只加 while 里那一处会漏：函数开头的**首个位置** case 会把它当 finding 吃掉并 `shift 2`
    （连下一个 `--finding` 一起吞）⟹ 静默解析错位。
    """
    seg = _code_fix_seg()
    assert seg.count("--batch)") >= 2, f"`--batch` 未在两个 case 位均注册：{seg[:600]}"
    assert "GK_SUBAGENT_K_MAX:-2" in seg, "k 上限默认值不是 2（用户裁定 k=2 起步）"


def test_batch_reuses_single_dispatch_path():
    """**禁第二实现**：批量层只做「上限门 + 互斥门 + 回封套」，逐 fid 递归复用单发路径。"""
    seg = _code_fix_seg()
    assert 'cmd_apply_worktree --code-fix --finding "$_f"' in seg, (
        "批量层未复用单发路径 ⟹ 违反设计 §11.2「CLI 只做参数编排，族判定/窄任务编译单一事实源」")


def test_batch_enforces_disjoint_allowed_paths():
    """互斥门（设计 §11.3-1）：同批各族 `allowed_paths` 重叠即拒（否则两个 coder 写同一文件）。"""
    seg = _code_fix_seg()
    assert "collisions" in seg and "allowed_paths 重叠" in seg, "缺同批互斥门"


def test_single_dispatch_exposes_allowed_paths():
    """单发回显须带 `allowed_paths`（批量互斥门的唯一数据源）。"""
    seg = _code_fix_seg()
    assert '\\"allowed_paths\\":$_ap_esc' in seg, "单发回显未透出 allowed_paths ⟹ 互斥门无数据源"


def test_batch_serial_merge_headsup_present():
    """回封套须带「合并必须串行」提示（设计 §11.3-3：禁并发 merge）。"""
    seg = _code_fix_seg()
    assert "合并**必须串行**" in seg and "merge --abort" in seg, "缺串行合并提示"


def test_batch_over_k_max_is_fail_loud():
    """功能臂（红先）：请求数 > k_max ⟹ exit 2 且点名上限；发生在**任何建 worktree 之前**。

    修前：`--batch` 不被识别 ⟹ 报的是 `unknown arg: --batch`（rc 同为 2 但原因不同）⟹ 本臂红。
    """
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash")
    r = subprocess.run(
        # `GK_BUDGET_OVERRIDE=1`（`ECC-1F6514B84334`，2026-09-26 实测）：本条验的是**上限门**
        # （超 k_max 即 fail-loud），不是用户编辑 ⟹ 与生产面 `gk_agent_edit._cli_gate_ok` 同一口径；
        # 否则该次 `apply-worktree`（写类子命令）扣**真** state 的主 agent 额度 1 次/验收轮。
        ["bash", "-lc", 'GK_BUDGET_OVERRIDE=1 bash "%s" apply-worktree --batch --finding a,b,c'
         % _wsl(CLI)],
        capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert r.returncode == 2, f"超限未 fail-loud（rc={r.returncode}）：{out[:300]}"
    assert "并发上限" in out, f"未点名并发上限：{out[:300]}"


# ─── 臂⑦ 顶层键设值通路（ECC-089658238011 / ECC-A91DC4562198）─────────────────

def _state_patch_seg() -> str:
    """`cmd_state_patch` **整个函数体**（切到下一个列 0 的 `}` 为止，同 `_code_fix_seg` 解耦法）。"""
    t = _txt(CLI)
    rest = t[t.index("cmd_state_patch()"):]
    m = re.search(r"(?m)^\}\s*$", rest)
    return rest[: m.end()] if m else rest


def test_state_patch_has_top_key_setter_branch():
    """`state-patch --set-top` 必须存在并转发 `gk_state_patch.py set-top`。

    红先对照：HEAD 版 CLI 中 `--set-top` 出现次数 = 0（`git show HEAD:gatekeeper-cli.sh |
    grep -c -- '--set-top'` → 0）⟹ 本臂在 HEAD 上必红。
    背景：顶层键（如 `state.worktree`）此前**无任何 CLI 通路**，唯一重写者是 `cmd_discover`
    （会归档并清空 `gate_data`）⟹ `apply-worktree` 无法把 worktree 落到被 `pre_tool_check`
    强制消费的字段。
    """
    seg = _state_patch_seg()
    assert '"--set-top"' in seg, "`cmd_state_patch` 未解析 `--set-top` ⟹ 顶层键仍无 CLI 通路"
    assert "gk_state_patch.py\" set-top" in seg, "`--set-top` 未转发到 gk_state_patch.py set-top"


def test_state_patch_keeps_gate_data_path():
    """负臂：新增分支不得改坏既有 `update-gate-data` 通路（`gate_data` 唯一正规写入口）。"""
    seg = _state_patch_seg()
    assert "update-gate-data" in seg, "既有 gate_data 写入通路被破坏"
    assert 'fragment="$1"' in seg, "既有 fragment 参数契约被破坏"


# ─── 臂⑧ per-coder worktree 本地 state（隔离闭环 ECC-089658238011）─────────────

def test_dispatch_creates_worktree_local_state():
    """派发必须为 coder 建**worktree 本地 state**（其 `worktree` = 该 agent worktree）。

    根因（P3 实测）：单一全局 `state.worktree` 同时充当「技能自维护活动面」与「coder 落刀面」
    ⟹ 写门禁（pre_tool_hook Gate 3 / CLI pre-tool-check）只认 `state.worktree`，而它指向技能
    目录 ⟹ coder 落刀被推回**主树**（实测主树 dirty 3→7）。修法 = 派发串改指本地 state。
    红先：落地时 `cmd_apply_worktree` 无 `_wt_state`。
    """
    seg = _code_fix_seg()
    assert "_wt_state" in seg, (
        "`cmd_apply_worktree` 未为 coder 建 worktree 本地 state ⟹ 门禁面与落刀面仍异源")
    assert 'set-top "$_wt_state" worktree' in seg, (
        "本地 state 未把 `worktree` 指向该 agent worktree")


def test_next_string_uses_worktree_local_state():
    """`next` 串的 `STATE_FILE=` 必须指向 worktree 本地 state（否则 coder 落刀被推回主树）。"""
    seg = _code_fix_seg()
    assert "STATE_FILE=$_wt_state" in seg, (
        "`next` 串仍以主 state 派发 ⟹ pre_tool_check 会把落刀判到主树")


def test_dispatch_never_writes_main_state_worktree():
    """负臂：派发侧**不得**改写主 state 的 `worktree`（会污染主门禁取证面，原注释的顾虑）。"""
    seg = _code_fix_seg()
    assert '"$_st" worktree' not in seg, (
        "派发侧把主 state 的 worktree 改写了 ⟹ 污染 advance/audit/self-check 的取证面")


# ─── 臂⑫-⑮ 会话级隔离：`apply-worktree --session <name>`（2026-09-23 用户裁定
#     「为了加速我会并行跑几个会话，并行会话需要可以申请独立 worktree 独立域化 state
#      且编辑预算不共享不冲突，并发会话今天被 state 隔离和编辑预算卡住了」）──────────────
# 病灶：此前 worktree 申请只有 `--code-fix`（绑 finding/族），人跑的并行会话用不了；而
# `discover --plan` 的隔离指针是**全局单点文件**（`SKILL_DIR/.gatekeeper.plan`）⟹ 两个会话
# 互相覆盖指针 = 「state 隔离被卡住」；且 `edit_budget` 是**单一全局计数器** ⟹ 共用即互相饿死。
# 出口 = 会话专用 worktree（2026-09-27 序④-A v5「甲」：**归主树 state**，废副本；
#   预算隔离走 `edit_budget.sessions.<sid>`）。门禁侧由 hook 的 `_resolve_state_by_target_path`
#   自动认领（`agent/session/**` → 主树，无需设 env）。
# 红先语义：修前 `--session` 未实现 ⟹ 臂⑫ 全红。
# ⚠ 2026-09-27：旧「副本 + 就近 `.gatekeeper.state`」语义已被「甲」取代 ⟹ 臂⑬/⑮ 同步改为断言新语义
#   （无副本 / 无预算重置 / `state_file`=base / 可信 note）。

def test_apply_worktree_has_session_mode():
    """臂⑫：`cmd_apply_worktree` 必须解析并实现 `--session`（人跑的并行会话入口）。"""
    seg = _code_fix_seg()
    assert "--session)" in seg, "`--session` 未解析 ⟹ 并行会话无独立 worktree 入口"
    assert 'if [ -n "$session" ]' in seg, "`--session` 分支未实现"


def test_session_mode_no_copy_no_budget_reset():
    """臂⑬（甲）：`--session` **不得**再复制 state / 重置预算 —— 隔离改走 `edit_budget.sessions.<sid>`。

    旧设计（副本 + `eb['used']=0` / `session_reset`）已由 owner 2026-09-27 裁定废止（序④-A v5）。
    """
    seg = _code_fix_seg()
    assert "eb['used'] = 0" not in seg, "仍在重置副本预算（旧副本设计未撤）"
    assert "session_reset" not in seg, "仍写 session_reset（旧副本语义未撤）"
    assert "session-state-archive" in seg, "未走幂等归档（甲迁移步缺失）"


def test_session_mode_never_grants_main_node_budget():
    """臂⑭（负臂）：会话入口**不得**调用 `_grant_node_budget`（那是 coder 派发的语义，
    会话隔离不应顺手抬主节点额度 —— 两件事混在一起会让「额度为什么涨了」不可归因）。"""
    seg = _code_fix_seg()
    m = re.search(r'if \[ -n "\$session" \].*?(?=\n  \[ -z "\$fid" \])', seg, re.S)
    assert m, "找不到 `--session` 分支体（臂⑫ 未过）"
    assert "_grant_node_budget" not in m.group(0), (
        "会话入口调了 `_grant_node_budget` ⟹ 混入 coder 语义、额度来源不可归因")


def test_session_mode_returns_base_state_file_and_truthful_note():
    """臂⑮（甲）：回包 `state_file` = **base** state；note 说明「worktree 归主树 state」。"""
    seg = _code_fix_seg()
    assert '"state_file\\":\\"$_s_st' in seg, "回包缺 base `state_file` ⟹ 使用者不知 CLI 该指哪个 state"
    assert "主树 state" in seg, (
        "缺「归主树 state」说明 ⟹ 使用者会以为还要自己 export STATE_FILE")
    assert "就近 .gatekeeper.state" not in seg, "旧虚假 note 未清除（ECC-B9395FC8E23C）"
    assert 'STATE_FILE=$_s_st' in seg, "`next` 串未前置 `STATE_FILE=`"
