#!/usr/bin/env python3
"""edit_budget 计量回归（S1-c / ECC-F5FE1042A7BA，2026-09-19）。

背景（读码 + 实测）：standing 的编辑预算由 `pre_tool_check` 的 edit 分支消费，而该点
**只写 `remaining`**、从不写 `used`：

    _state_write "…['edit_budget']['remaining']=$_new_remaining"   # 仅此一条

⟹ `edit_budget.used` 恒 `0`。后果 = **消耗不可见**：`state` / `audit --report` / BLOCK 文案
都只能看到 `remaining` 在掉，看不到「这一节点已经改了几次」，于是「预算 4 还是 8」只能靠
撞墙次数反推（本轮即如此：连撞两次墙后靠人工 `state-patch` 硬补）。

**⚠ 2026-09-30 口径变更（REV-5 §13.2 / G4-d）**：计费判据由**统一模型**（凡
`side_effects=state_write` 一律计费）改为**分流模型**（记账通道免 / 工程通道计费）。
本文件里以「写类子命令」为代表的夹具由 `state-patch '{"probe":1}'`（记账通道，现**免计费**）
换为 `apply-worktree --bind --path`（`side_effects=state_write` 的**真工程写**，**仍计费**）。
**各臂判据（计费 / 不计费）不变**，仅换夹具。分流模型口径正本见 `scripts/test_gk_bill_channel.py`。

本文件锁两条判据：
  ① 放行消费必须**同时**写 `used` 与 `remaining`（`used += 1` 且 `remaining -= 1`）
  ② 耗尽 BLOCK 的文案必须报出 `used=<n>/max=<n>`（在**最需要可见**的那一刻可见）

red-first 对照臂：`GK_CLI_UNDER_TEST=<旧版 CLI 绝对路径>`（默认 = 仓内 CLI）
⟹ 修复前判据①②均红（`used` 恒 0、BLOCK 文案只有 `remaining`）。

✅ 已覆盖（2026-09-19，用户裁定「本轮就改」）：**standard 侧**同批补齐 —— 原状是
`gk_advance._edit_budget` 以 `gate_data.edit_count` 计 `used`（`remaining = max - edit_count`），
而全仓 `edit_count` **只有读点、没有写点**（`--env-json` 也不传 `edit_used`）⟹ standard 的
`remaining` 恒 `== max`，预算形同虚设。**窗口语义已裁定 = 本 R-phase**（对齐 `_edit_budget`
返 None 时那句「no more edits in this R-phase」）⟹ 归零点 = `r_phase` 切换，由 `_edit_budget`
自持 `edit_count_phase`；消费点**两型同扣**（`remaining`−1 + `used`+1 + `edit_count`+1）。
同批修两条同族缺陷：`_edit_budget` 的 cosine **饱和**（`min(step,total)` → 回绕）、
以及整字典赋值**抹掉 `overrides` 台账**（同 S1-b 在 standing 侧的病灶）—— 判据 ③④⑤ 分别锁之。
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SKILL_DIR / "gatekeeper-cli.sh"))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import gk_budget_ledger as B  # noqa: E402（批次计价的判据面：append_verify / append_edit）


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）；`bash` 此处是 WSL bash。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _mk_sandbox(tmp_path: Path, budget: dict, worktree=None) -> Path:
    """沙箱技能根：`scripts` 软链 + CLI 实拷 + 最小 state（standing）+ 一个待编辑目标文件。

    必须避开 `pre_tool_check` 的前置门：`stage` 非 IDLE/DONE、路径 realpath 稳定、
    不含 `build/`/`.git/`/`node_modules/`。`worktree`（§17-6-P4）：缺省 = 沙箱根（**显式 root**，
    空值不得放行）；显式传 `""` 保留「无 worktree」环境（供不涉写面的臂，如 `ask_hold_kill`）。
    """
    sb = (tmp_path / "sb").resolve()
    sb.mkdir()
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), w, _wsl(CLI_SRC), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    (sb / ".gatekeeper.state").write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1",
        "worktree": _wsl(sb) if worktree is None else worktree,  # §17-6-P4：缺省 = 显式 root
        "gate_data": {
            "project_type": "standing",
            "edit_budget": budget,
            "scheduler": {"mode": "constant", "max_lr": 4, "min_lr": 1,
                          "total_steps": 6, "current_step": 1, "current_lr": 4},
        },
    }, ensure_ascii=False), encoding="utf-8", newline="\n")
    (sb / "note.md").write_text("x", encoding="utf-8", newline="\n")
    (sb / "wt").mkdir()   # 2026-09-30 口径升级：写类代表命令 `apply-worktree --bind` 的目标目录
    return sb


def _consume(sb: Path):
    """走一次 `pre-tool-check edit <file>`（= hook Gate 4 的真实消费点）。"""
    w = _wsl(sb)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"' % (w, w)],
        capture_output=True, text=True, timeout=120)


def _budget(sb: Path) -> dict:
    st = json.loads((sb / ".gatekeeper.state").read_text(encoding="utf-8"))
    return st.get("gate_data", {}).get("edit_budget", {})


def _consume_as(sb: Path, sid: str, target: str = "note.md"):
    """同 `_consume`，但带**会话键** `GK_SESSION_ID`（编辑预算按会话隔离的判据面）。"""
    w = _wsl(sb)
    return subprocess.run(
        ["bash", "-lc",
         'cd "%s" && GK_SESSION_ID=%s bash gatekeeper-cli.sh pre-tool-check edit "%s/%s"'
         % (w, sid, w, target)],
        capture_output=True, text=True, timeout=120)


def test_consumption_makes_used_visible(tmp_path):
    """判据①：放行一次 ⟹ `used` 1→2、`remaining` 8→7（两者同步）。"""
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 1, "remaining": 8})
    r = _consume(sb)
    out = r.stdout + r.stderr
    assert "OK" in out, f"消费点未放行：{out[:400]}"
    b = _budget(sb)
    assert b.get("remaining") == 7, f"remaining 未扣：{b}"
    assert b.get("used") == 2, (
        f"used 未自增 ⟹ 消耗不可见（ECC-F5FE1042A7BA）：{b}")


def test_exhausted_block_reports_used_and_max(tmp_path):
    """判据②：耗尽 BLOCK 的文案须报出 `used=<n>/max=<n>`。"""
    sb = _mk_sandbox(tmp_path, {"max": 1, "used": 1, "remaining": 0})
    r = _consume(sb)
    out = r.stdout + r.stderr
    assert "BLOCK" in out, f"预算 0 未阻断：{out[:400]}"
    assert re.search(r"used=1/max=1", out), (
        f"BLOCK 文案未报出真实消耗（只报 remaining）：{out[:400]}")


def test_edit_budget_is_isolated_per_session(tmp_path):
    """判据⑫（红先 · 2026-09-25 用户裁定「预算控制应该被隔离开，并发会话也不应该和这边抢」）：
    会话 A 把自己那份额度用尽后，**会话 B 必须仍被放行**（各有各的额度）。

    修前（全局单计数器 `gate_data.edit_budget.remaining`）：A 用完 ⟹ B 也吃 BLOCK
    = 多会话互相饿死（`_run_cli` 注释 ECC-3104B66AA4EE 只钉了 STATE_FILE，未钉会话键）。
    修后：`edit_budget.sessions[<sid>]` 逐会话计数（`billed_files` 亦逐会话）⟹ B 走自己的新鲜额度。
    """
    sb = _mk_sandbox(tmp_path, {"max": 1, "used": 0, "remaining": 1})
    (sb / "note2.md").write_text("x", encoding="utf-8", newline="\n")
    ra = _consume_as(sb, "aaaa1111aaaa1111aaaa1111")
    assert "OK" in (ra.stdout + ra.stderr), (
        f"会话 A 首次放行失败：{(ra.stdout + ra.stderr)[:400]}")
    rb = _consume_as(sb, "bbbb2222bbbb2222bbbb2222", "note2.md")
    outb = rb.stdout + rb.stderr
    assert "OK" in outb, (
        "会话 B 被**他人**耗尽的全局计数饿死 ⟹ 预算未按会话隔离："
        + outb[:400] + " | budget=" + json.dumps(_budget(sb), ensure_ascii=False))


# ── S1-c 后半 / `ECC-E05F3517A965`（2026-09-19 用户裁定「本轮就改」）：standard 侧 ──────
# 原状：`gk_advance._edit_budget` 以 `gate_data.edit_count` 计 `used`，但全仓 `edit_count`
# **只有读点没有写点**（`--env-json` 里也没有 `edit_used`）⟹ standard 的 `remaining` 恒 `== max`，
# 预算形同虚设。本组把「计量」补上，窗口语义**定为 = 本 R-phase**（对齐 `_edit_budget` 返 None 时
# 那句「no more edits in this R-phase」）⟹ 归零点 = `r_phase` 切换，并由 `_edit_budget` 内自持。

def _as_standard(sb: Path, budget: dict) -> None:
    """把沙箱 state 改成 standard 并写入给定预算（避开改 `_mk_sandbox` 的签名）。"""
    f = sb / ".gatekeeper.state"
    st = json.loads(f.read_text(encoding="utf-8"))
    st["gate_data"]["project_type"] = "standard"
    st["gate_data"]["edit_budget"] = budget
    st["gate_data"]["edit_count"] = budget.get("used", 0)
    f.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8", newline="\n")


def test_standard_consumption_is_metered(tmp_path):
    """判据③：standard 侧放行一次 ⟹ `edit_count`/`used` 各 +1、`remaining` −1。"""
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 0, "remaining": 4})
    _as_standard(sb, {"max": 4, "used": 0, "remaining": 4})
    r = _consume(sb)
    out = r.stdout + r.stderr
    assert "OK" in out, f"消费点未放行：{out[:400]}"
    b = _budget(sb)
    assert b.get("used") == 1, f"standard `used` 未自增 ⟹ 预算形同虚设：{b}"
    assert b.get("remaining") == 3, f"standard `remaining` 未扣：{b}"
    st = json.loads((sb / ".gatekeeper.state").read_text(encoding="utf-8"))
    assert st["gate_data"].get("edit_count") == 1, (
        f"`edit_count` 未自增（`_edit_budget` 下次 advance 仍读到旧值）：{st['gate_data'].get('edit_count')}")


def _sched(step: int) -> dict:
    return {"mode": "cosine", "max_lr": 4, "min_lr": 1,
            "total_steps": 6, "current_step": step, "current_lr": 1}


def test_edit_budget_cosine_wraps_not_saturates():
    """判据④：`_edit_budget` 的 cosine 须**回绕**（`step ≥ total` 后 lr 不得恒 = min_lr）。

    原式 `t = min(step,total)/total` **饱和** ⟹ `step ≥ total` 后 `t ≡ 1` ⟹ lr 恒 min_lr
    （退火永久失效，与 standing 分支注释自述的同一病灶；standing 早已改 `(step % total)/total`）。
    """
    from gk_advance import _edit_budget
    d = {"r_phase": "R1", "gate_data": {"project_type": "standard",
                                        "scheduler": _sched(6)}}
    got = _edit_budget(d, {}, True)          # dry_run ⟹ 零副作用
    assert got is not None, got
    assert got["max"] > 1, (
        f"cosine 饱和未修：step=6/total=6 时 max 仍退化到 min_lr：{got}")


def test_edit_budget_keeps_overrides_ledger():
    """判据⑤：`_edit_budget` 重置 `edit_budget` 时须**带过** `overrides` 台账。

    同 S1-b 在 standing 侧修的病灶：整字典赋值 `gd["edit_budget"] = {...}` 会连带抹掉台账
    （实测 standing 侧曾把一条 state_patch 记录丢成 `[]`）；standard 侧同样有此句。
    """
    from gk_advance import _edit_budget
    d = {"r_phase": "R1", "gate_data": {
        "project_type": "standard", "edit_count": 0, "scheduler": _sched(1),
        "edit_budget": {"max": 4, "used": 0, "remaining": 4,
                        "overrides": [{"source": "state_patch", "reason": "x"}]}}}
    _edit_budget(d, {}, True)
    ov = d["gate_data"]["edit_budget"].get("overrides")
    assert ov, f"overrides 台账被整字典赋值抹掉：{d['gate_data']['edit_budget']}"


# ── 2026-10-23 计价单位改「**批次**」（owner 裁定，REV-24）────────────────────────
# 旧口径（2026-09-23 起）= 每个**唯一文件** 1 单位 ⟹ 一个 5 文件轮次 = 5 单位，12 的地板被
# 单轮批次量吃光（实测：一轮 5 文件即耗尽，只能手工 `state-patch` 抬）。
# 现口径：**批次边界 = verify** —— 同 `(session,node)` 内自最近一次 verify 以来的放行编辑同属
# 一批；本批**首刀**扣 1、后续刀 0；T4′/T6 命中 = **附加费 +1**（不再是「整价 2」）。
# `billed_files[]` 退为**观测面**（`gk_bill_observe` 的来源反推），不再驱动扣减。

def test_same_file_is_billed_once(tmp_path):
    """判据⑥：同一文件**第二次**落刀不再扣（批次内重复落刀免费）。"""
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    r1 = _consume(sb)
    assert "OK" in (r1.stdout + r1.stderr), f"首次触达未放行：{(r1.stdout + r1.stderr)[:300]}"
    b1 = _budget(sb)
    assert b1.get("remaining") == 7 and b1.get("used") == 1, f"首次触达未计费：{b1}"
    r2 = _consume(sb)
    assert "OK" in (r2.stdout + r2.stderr), f"二次触达未放行：{(r2.stdout + r2.stderr)[:300]}"
    b2 = _budget(sb)
    assert b2.get("remaining") == 7 and b2.get("used") == 1, (
        f"同一文件被**重复计费**（批次内应只收首刀）：{b2}")


def test_second_file_same_batch_is_free(tmp_path):
    """判据⑥b（REV-24 新口径 · 红先）：同批内第二个**不同**文件**不再扣**。

    旧口径下这里会 `remaining` 8→6（每个文件 1 单位）⟹ 本臂在旧 CLI 上红。
    """
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    (sb / "note2.md").write_text("y", encoding="utf-8", newline="\n")
    _consume(sb)                                    # 第一次：note.md（本批首刀）
    w = _wsl(sb)
    r2 = subprocess.run(
        ["bash", "-lc",
         'cd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note2.md"' % (w, w)],
        capture_output=True, text=True, timeout=120)
    assert "OK" in (r2.stdout + r2.stderr), f"第二个文件未放行：{(r2.stdout + r2.stderr)[:300]}"
    b = _budget(sb)
    assert b.get("remaining") == 7 and b.get("used") == 1, (
        f"同批第二个文件被计费（说明单位仍是「文件数」而非「批次」）：{b}")


def test_verify_opens_new_batch(tmp_path):
    """判据⑦（负臂 · 守「批次 ≠ 永久免费」）：verify 之后**下一刀**重新扣 1。"""
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    _consume(sb)
    assert _budget(sb).get("remaining") == 7, "首刀未计费"
    B.append_verify(str(sb / ".gatekeeper.state"), session="", node="STAGE_0", cmd="pytest -q")
    _consume(sb)
    b = _budget(sb)
    assert b.get("remaining") == 6 and b.get("used") == 2, (
        f"verify 之后未开新批（批次边界失效 ⟹ 一批永不结束）：{b}")


def test_reject_does_not_open_batch(tmp_path):
    """判据⑦b：被拒编辑（`result=reject`）**不**算「已开账」⟹ 下一刀仍按首刀计。"""
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    B.append_edit(str(sb / ".gatekeeper.state"), session="", node="STAGE_0",
                  path=str((sb / "note.md").resolve()), result="reject")
    _consume(sb)
    b = _budget(sb)
    assert b.get("remaining") == 7 and b.get("used") == 1, (
        f"reject 事件被当成「本批已开账」（下一刀漏计）：{b}")


# ── 2026-09-23 并发会话堵漏（用户裁定，紧接「更新 09-22 计划」之后）────────────────────
# 病灶（读码实测）：`_bill_edit` 在**锁外**读 `remaining`（`gk_state_query.py`）、在**锁内**写
# **绝对值** `eb['remaining']=$_nr` ⟹ 两个并发写者各读 N、各写 N-1 ⟹ **丢一次扣减**
# （额度 fail-open，即「并发会话」可绕过节点额度）。对照 = hook 侧 `pre_tool_check`
# （L2730）本就是**锁内相对扣减**（正确口径）。
# 修法 = 把「读 remaining + 判 >=1 + 相对减 + `used`/`edit_count` 自增」整体搬进
# `_state_write` 的**锁内 payload**（与 hook 侧同一原子口径）。正典 = 设计稿 §11.7-4。

def _bill_cli(sb: Path, background: bool = False, sid: str = "", path_name: str = "wt"):
    """走一次 **CLI 写类子命令**消费点（代表 = `apply-worktree --bind` ⟹ `_bill_edit`）。

    ⚠ 刻意**不**用 `pre-tool-check`：那条走 hook 侧扣减（本就锁内），测不到 `_bill_edit`。
    **2026-09-30 口径升级（REV-5 §13.2）**：计费豁免改为**按通道**白名单 —— 原代表
    `state-patch` 已整体豁免（记账通道）、`finding` 亦然，故代表命令换为仍计费的**工程**动作
    `apply-worktree --bind`（幂等、零外部副作用、不触发 `_budget_override_record`）。
    口径正本见 `scripts/test_gk_bill_channel.py`。
    `sid` 非空 ⟹ 以 `GK_SESSION_ID` 注入会话身份（判据㉑ 要 ①/② 落**同一**会话桶）。
    `path_name`（`REV-15` 归化，2026-10-05）：`--path` 目标名 —— 决定 `_bill_edit` 的**身份**
    （实参向量哈希）；不同名 ⟹ 不同身份 ⟹ 各计一次；同名两次 ⟹ 去重（判据⑲″）。
    """
    w = _wsl(sb)
    env = ("GK_SESSION_ID=%s " % sid) if sid else ""
    cmd = ["bash", "-lc",
           "cd \"%s\" && %sbash gatekeeper-cli.sh apply-worktree --bind --path \"%s/%s\""
           % (w, env, w, path_name)]
    if background:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=180)


def _bill_edit_seg(src: str = "") -> str:
    """`_bill_edit()` 整函数体（切到下一个**列 0** 的 `}`），并**剔除整行注释**。

    形态判据只能看**代码**：注释里引用旧实现（`$_nr` 等）不构成缺口，若不过滤会把
    「解释为什么这样修」的注释误判成「仍在写绝对值」（本臂首版即踩）。
    `src` 缺省读仓内 CLI；显式传入则对**给定源码**切片（口径检查器用，见判据⑲/⑳）。
    """
    src = src or CLI_SRC.read_text(encoding="utf-8")
    rest = src[src.index("_bill_edit() {"):]
    m = re.search(r"(?m)^\}\s*$", rest)
    seg = rest[: m.end()] if m else rest
    return "\n".join(ln for ln in seg.split("\n") if not ln.strip().startswith("#"))


def test_bill_edit_reads_remaining_inside_lock():
    """判据⑧（红先 · 形态）：`remaining` 的读-判-减必须在**同一次** `_state_write` payload 内。

    HEAD 实测段内同时含 ① `--get gate_data.edit_budget.remaining`（**锁外**读）
    ② `eb['remaining']=$_nr`（锁内写**绝对值**）⟹ 本臂红。
    """
    seg = _bill_edit_seg()
    assert "--get gate_data.edit_budget.remaining" not in seg, (
        "仍在**锁外**读 remaining ⟹ 与并发写者构成 TOCTOU 丢更新窗口")
    assert "$_nr" not in seg, "仍写**绝对值**（`$_nr`）⟹ 并发丢更新"
    assert "remaining" in seg, "锁内 payload 丢了 remaining 判据（会退化成无条件扣减）"


def test_cli_write_class_subcommand_is_billed(tmp_path):
    """判据⑨（正臂 · 守消费点）：写类子命令**确实**经 `_bill_edit` 扣 1。"""
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    r = _bill_cli(sb)
    assert r.returncode == 0, f"apply-worktree --bind 失败：{r.stdout}{r.stderr}"
    b = _budget(sb)
    assert b.get("remaining") == 7 and b.get("used") == 1, f"写类子命令未计费：{b}"


def test_bill_edit_payload_guards_exhaustion(tmp_path):
    """判据⑩（负臂 · 守「判据没被删掉」）：`remaining=0` 时写类子命令**不扣**。"""
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 4, "remaining": 0})
    _bill_cli(sb)
    b = _budget(sb)
    assert b.get("remaining") == 0 and b.get("used") == 4, f"额度耗尽仍被扣（判据被删）：{b}"


def test_concurrent_billing_has_no_lost_update(tmp_path):
    """判据⑪（红先 · 真两进程并发）：两个并发写类子命令 ⟹ `remaining` 必须 **−2**。

    修前实测：两进程各读 8、各写 7 ⟹ `remaining == 7`（丢一次扣减）；修后 = 6。

    ⚠ **2026-10-05 归化（`REV-15` 修订 X）**：`_bill_edit` 补**身份去重** ⟹ 两次**完全相同**
    的调用只计一次。故本臂改用**两次不同目标**（`--path wt` / `wt2` ⟹ 不同身份）—— 否则
    去重会掩盖并发丢更新（前者=预期语义，后者=要守的缺陷）。
    """
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    ps = [_bill_cli(sb, background=True, path_name="wt"),
          _bill_cli(sb, background=True, path_name="wt2")]
    for p in ps:
        p.wait(timeout=300)
    b = _budget(sb)
    assert b.get("remaining") == 6, f"并发扣减**丢更新**（额度 fail-open）：{b}"
    assert b.get("used") == 2, f"并发下 `used` 未 +2：{b}"


# ── §4.13.5「高并发②」使能切片（2026-09-25）：**会话身份出口** ────────────────────────────
# 病象：`session_id` 只在 hook 进程内（PreToolUse 载荷），唯一出口 = `_run_cli` env ⟹ 只达
#   Gate 4；**agent 自己跑的 CLI 无任何身份** ⟹ 落全局平面、与 hook 的会话平面分叉（两套账）。
# 修法：hook 每次 PreToolUse 把 sid 落 `<SKILL_DIR>/.gatekeeper.session`；CLI **启动块**在
#   `GK_SESSION_ID` 为空时自解析它（须 24 位 hex + 未超 `GK_SESSION_TTL`，默认 1800s）⟹ 同一
#   工具调用内的两条路径携带**同一身份**。缺失 / 形态非法 / 超窗 ⟹ 保持空（零回归）。

def _write_marker(sb: Path, sid: str, age_s: int = 0, tool: str = "RunCommand",
                  cwd: str = "") -> None:
    """写 hook 的会话标记（`sid<TAB>epoch<TAB>tool<TAB>cwd`）。

    `cwd` 缺省 = **沙箱的 WSL 路径**（= 下列 `_consume`/`_state_via_cli` 里 `cd` 进去的那个
    `${PWD}`）。2026-10-07 起启动块加了**同源门**（`ECC-8CEA5388F1DC`：marker 第 4 列须与本次
    调用 `${PWD}` 一致，否则判为**外来会话的单槽覆写**、不采纳 sid）⟹ 旧夹具的缺省 `"C:/x"`
    在 `/tmp` 沙箱下**恒不匹配**，臂①③⑥⑦ 因此恒落全局平面（假红）。夹具改为写真实 cwd；
    「外来 cwd 不得采纳」这条判据由 `test_arm21b` 单独锁。
    """
    if not cwd:
        cwd = _wsl(sb)
    (sb / ".gatekeeper.session").write_text(
        "%s\t%d\t%s\t%s\n" % (sid, int(time.time()) - age_s, tool, cwd),
        encoding="utf-8", newline="\n")


def test_arm21_cli_self_resolves_session_from_marker(tmp_path):
    """判据⑬（红先）：**不设** `GK_SESSION_ID`，仅放 hook 的 `.gatekeeper.session` 标记 ⟹
    启动块须自解析出同一 sid ⟹ 消费落 `edit_budget.sessions.<sid>`（而非全局计数）。

    修前：agent 侧 CLI 无身份 ⟹ 恒落全局 `edit_budget.remaining` = 与 hook 的会话平面分叉。
    """
    sid = "0123456789abcdef01234567"
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    _write_marker(sb, sid)
    r = _consume(sb)                      # 刻意**不**传 GK_SESSION_ID
    out = r.stdout + r.stderr
    assert "OK" in out, f"消费点未放行：{out[:400]}"
    b = _budget(sb)
    got = b.get("sessions") or {}
    assert sid in got, (
        "启动块未自解析会话身份 ⟹ agent 侧仍落全局平面（与 hook 会话平面分叉 = 两套账）："
        + json.dumps(b, ensure_ascii=False))
    assert got[sid].get("remaining") == 7, f"会话桶未扣：{got}"


def test_arm21b_marker_from_foreign_cwd_not_adopted(tmp_path):
    """判据⑬b（守**同源门**，`ECC-8CEA5388F1DC`）：marker 第 4 列（写入时 cwd）与本次调用的
    `${PWD}` 不一致 ⟹ 判为**外来会话的单槽覆写** ⟹ **不采纳** sid（回落全局口径，与 arm22 同形）。

    必要性：arm21 的夹具现在写的是**真实 cwd**（同源）；若有人删掉同源门，arm21 仍绿（它本就
    同源），只有本臂会响 —— 防「拆门后并发会话互相劫持身份」静默回归。
    """
    sid = "0123456789abcdef01234567"
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    _write_marker(sb, sid, cwd="/tmp/some-other-session")
    r = _consume(sb)
    assert "OK" in (r.stdout + r.stderr), f"消费点未放行：{(r.stdout + r.stderr)[:300]}"
    b = _budget(sb)
    assert not (b.get("sessions") or {}), (
        "外来 cwd 的 marker 被采纳 ⟹ 并发会话可互相劫持身份：" + json.dumps(b, ensure_ascii=False))
    assert b.get("remaining") == 7, json.dumps(b, ensure_ascii=False)


def test_arm22_stale_or_invalid_marker_falls_back_to_global(tmp_path):
    """判据⑭（负臂 · 守零回归）：标记**超窗** / **形态非法** ⟹ 不 export `GK_SESSION_ID`
    ⟹ 走既有全局口径（`edit_budget.remaining` 扣、不建会话桶）。"""
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    _write_marker(sb, "0123456789abcdef01234567", age_s=10 ** 6)   # 远超 TTL=1800
    r = _consume(sb)
    assert "OK" in (r.stdout + r.stderr), f"未放行：{(r.stdout + r.stderr)[:300]}"
    b = _budget(sb)
    assert b.get("remaining") == 7 and b.get("used") == 1, (
        f"超窗标记仍被采信 ⟹ 零回归被破坏：{json.dumps(b, ensure_ascii=False)}")
    assert not (b.get("sessions") or {}), f"超窗标记不应建会话桶：{b}"

    sb2_root = tmp_path / "b"
    sb2_root.mkdir()
    sb2 = _mk_sandbox(sb2_root, {"max": 8, "used": 0, "remaining": 8})
    _write_marker(sb2, "not-a-hex-sid")           # 形态非法（长度/字符集）
    r2 = _consume(sb2)
    assert "OK" in (r2.stdout + r2.stderr), f"未放行：{(r2.stdout + r2.stderr)[:300]}"
    b2 = _budget(sb2)
    assert b2.get("remaining") == 7 and not (b2.get("sessions") or {}), (
        f"非法标记被采信 ⟹ 零回归被破坏：{json.dumps(b2, ensure_ascii=False)}")


# ── §4.13.5「高并发②」②b：**会话级句柄**（指针按 sid 分片 + env `PLAN_POINTER` 认 + 过期 sweep）──
# 病象：指针是**全局单文件** ⟹ 会话 B 的 `discover`（无 --plan）会 rm 掉会话 A 刚写的绑定 ⟹
#   A 静默回落默认 state（= 抢写同一 state）；且 env `PLAN_POINTER` **启动块不认**（只有 route
#   center 认）。修法：**跟随目标**三级优先（env → 会话指针 `.gatekeeper.plan.<sid>` → 全局），
#   与**写/清目标**（OWN，有会话身份时恒为本会话指针）分离 ⟹ 会话间不再互相清绑定。

def _sess_state(sb: Path, name: str, r_phase: str) -> Path:
    """沙箱里造一个**可辨识** state（以 `r_phase` 区分 ⟹ 只读 `state` 即可读出解析到了哪个）。"""
    p = sb / ("." + name)
    p.write_text(json.dumps({"r_phase": r_phase, "stage": "STAGE_0", "worktree": "",
                             "gate_data": {"project_type": "standing"}}, ensure_ascii=False),
                 encoding="utf-8", newline="\n")
    return p


def _ptr(sb: Path, fname: str, state_file: Path, plan: str = "p") -> Path:
    from datetime import datetime, timezone
    p = sb / fname
    p.write_text(json.dumps({
        "state_file": _wsl(state_file), "plan": plan, "writer": "discover",
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ensure_ascii=False), encoding="utf-8", newline="\n")
    return p


def _state_via_cli(sb: Path, env_prefix: str = "") -> dict:
    """跑一次只读 `state` ⟹ 回**启动块实际解析到**的那个 state 的内容（指针选择的判据面）。"""
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && %s bash gatekeeper-cli.sh state' % (w, env_prefix)],
        capture_output=True, text=True, timeout=120)
    lines = [ln for ln in r.stdout.strip().splitlines() if ln.startswith("{")]
    assert lines, f"`state` 未回 JSON：{(r.stdout + r.stderr)[:400]}"
    return json.loads(lines[-1])


def test_arm23_startup_prefers_session_pointer_over_global(tmp_path):
    """判据⑮（红先 · ②b 读侧）：会话指针 `.gatekeeper.plan.<sid>` 须**优先**于全局指针。

    修前：启动块恒读全局指针 ⟹ 本会话自己的绑定被忽略（= 「抢写同一 state」的读侧）。
    """
    sid = "0123456789abcdef01234567"
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    a = _sess_state(sb, "gatekeeper.state.sA", "SESS")
    b = _sess_state(sb, "gatekeeper.state.sB", "GLOB")
    _ptr(sb, ".gatekeeper.plan." + sid, a)
    _ptr(sb, ".gatekeeper.plan", b)
    _write_marker(sb, sid)
    got = _state_via_cli(sb)
    assert got.get("r_phase") == "SESS", (
        "启动块未优先会话指针 ⟹ 读到的仍是全局绑定的 state："
        + json.dumps(got, ensure_ascii=False))


def test_arm24_startup_honors_env_plan_pointer(tmp_path):
    """判据⑯（红先 · ②b 读侧）：env `PLAN_POINTER` 必须被**启动块**认（§4.13.5② 记的缺口：
    此前只有 route center 认 ⟹ 显式注入在 CLI 链上是死通道）。"""
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    e = _sess_state(sb, "gatekeeper.state.sE", "ENVPTR")
    g = _sess_state(sb, "gatekeeper.state.sG", "GLOB")
    _ptr(sb, ".gatekeeper.plan", g)
    _ptr(sb, ".gatekeeper.plan.custom", e)
    got = _state_via_cli(sb, "PLAN_POINTER=%s " % _wsl(sb / ".gatekeeper.plan.custom"))
    assert got.get("r_phase") == "ENVPTR", (
        "启动块未认 env `PLAN_POINTER` ⟹ 显式注入被忽略（回落全局指针）："
        + json.dumps(got, ensure_ascii=False))


def test_arm25_without_sid_still_follows_global_pointer(tmp_path):
    """判据⑰（负臂 · 守零回归）：**无**会话身份 ⟹ 仍跟全局指针（既有行为逐字一致）。"""
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    g = _sess_state(sb, "gatekeeper.state.sG2", "GLOB2")
    _ptr(sb, ".gatekeeper.plan", g)
    got = _state_via_cli(sb)
    assert got.get("r_phase") == "GLOB2", json.dumps(got, ensure_ascii=False)


def test_arm26_discover_writes_session_pointer_not_global(tmp_path):
    """判据⑱（红先 · ②b 写侧）：带会话身份时 `discover --plan` 须写**会话指针**（不动全局指针
    = 会话间不再互相清绑定），并顺带 sweep 过期会话指针。"""
    sid = "0123456789abcdef01234567"
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    (sb / "docs" / "plans").mkdir(parents=True)
    (sb / "docs" / "plans" / "p1.md").write_text(
        "<!-- META\nphases: R1\ntarget_repo: skill\nproject_type: standing\n-->\nbody",
        encoding="utf-8", newline="\n")
    gptr = _ptr(sb, ".gatekeeper.plan", Path("/x"), plan="keep")   # 悬空但**新鲜**（stale 会被启动块自清）
    stale = sb / ".gatekeeper.plan.deadbeefdeadbeefdeadbeef"
    stale.write_text("{}", encoding="utf-8", newline="\n")
    os.utime(stale, (time.time() - 10 ** 6, time.time() - 10 ** 6))     # 远超 GK_PLAN_POINTER_TTL
    _write_marker(sb, sid)
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh discover --plan p1' % _wsl(sb)],
        capture_output=True, text=True, timeout=180)
    sess = sb / (".gatekeeper.plan." + sid)
    assert sess.is_file(), (
        "带会话身份时 `discover --plan` 未写**会话指针** ⟹ 绑定仍是全局一份（互相覆盖）；"
        f"rc={r.returncode} out={(r.stdout + r.stderr)[:400]}")
    assert not stale.exists(), "过期会话指针未被 sweep"
    assert json.loads(gptr.read_text(encoding="utf-8")).get("plan") == "keep", (
        "全局指针被本会话的 discover 覆盖 ⟹ 会话间仍互相清绑定")


def test_arm27_session_without_own_binding_does_not_adopt_global(tmp_path):
    """判据⑲（红先 · 并发写 · 跨会话劫持）：**有**会话身份但本会话**无自身指针** ⟹ **不得**
    采纳全局指针（全局指针属他会话/僵尸 ⟹ 跟随即跨会话绑定劫持）。应回落默认 state。

    现场（2026-09-28 实测）：某会话的 `finding register` 因「本会话无自身绑定」而走了
    （L221-224 的）全局回退，把 finding 写进了**别的计划**的域 state（id 落错台账）。
    零回归护栏 = arm25：**无**会话身份时仍跟全局指针（逐字不变）。
    """
    sid = "0123456789abcdef01234567"
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    g = _sess_state(sb, "gatekeeper.state.sG3", "GLOB3")
    _ptr(sb, ".gatekeeper.plan", g)      # 全局/他会话指针（新鲜，未被 sweep）
    _write_marker(sb, sid)               # 本会话有身份，但**无** `.gatekeeper.plan.<sid>`
    got = _state_via_cli(sb)
    assert got.get("r_phase") == "R1", (
        "本会话无自身绑定却采纳了全局指针 ⟹ 跨会话绑定劫持（应回落默认 state r_phase=R1）："
        + json.dumps(got, ensure_ascii=False))


# ── T2 计费三条之① / `ECC-CB8579F9D826`（2026-09-26）：**两套实现 · 口径漂移的机检化** ──────
# 病灶（读码 + 实测）：`edit_budget` 的扣减**有两套实现**，口径**不同**且**共享同一额度**：
#   ① `pre_tool_check` 的 EDIT_TOOLS 面（hook Gate 4）—— 按**触及文件数**（`billed_files[]` 去重）；
#      **在 `PROTECTED_REGION::gate` 之内 ⟹ 不可改、也不调 ②**（② 定义在区**外**、且在其**后**）。
#   ② 区外单点 `_bill_edit`（`_dispatch` 分派的写类子命令）—— 按**调用次数**（无去重）。
# ⟹ 任一侧改口径必须同步另一侧，否则两面对同一 `remaining` 用不同单位消费（漂移）；而 HEAD
#    **无任何可机检的锚**（正典 §1395：RC5「缺红先臂 ⟹ 不落刀」）。
# 修法（区外等价加固 —— 区内不可动）：在区外「计费单点」头部落一行**机器可读声明**
#   `BILL_UNITS_DECL path1=… path2=… counter=…`，并由判据⑲**从两侧源码反推**口径与之比对：
#   声明 = 两实现的**单一事实源**；任一侧改单位即失配、臂即响，强迫同步。

_BILL_DECL_RE = re.compile(r"(?m)^\s*#\s*BILL_UNITS_DECL\s+(.+)$")


def _parse_bill_units_decl(src: str) -> dict:
    """解析区外头部那行 `BILL_UNITS_DECL k=v …`；缺行 ⟹ `{}`（判据⑲据此报「无可检锚」）。"""
    m = _BILL_DECL_RE.search(src)
    if not m:
        return {}
    out = {}
    for tok in m.group(1).split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            out[k.strip()] = v.strip()
    return out


def _bill_payload1(src: str) -> str:
    """①（hook Gate 4 · `pre_tool_check` EDIT_TOOLS 面）的**扣减 payload 本体**（两端锚定）。"""
    a = src.index('GK_BILL_PATH="$real_path" _state_write "')
    b = src.index('" >/dev/null 2>&1 || true', a)
    return src[a:b]


def _bill_payload2(src: str) -> str:
    """②（区外单点 `_bill_edit`）的**扣减 payload 本体**（注释已剔，见 `_bill_edit_seg`）。"""
    seg = _bill_edit_seg(src)
    a = seg.index('_state_write "')
    b = seg.index('" 2>/dev/null', a)
    return seg[a:b]


def _unit_of(payload: str) -> str:
    """从 payload **反推**计价单位：含 `batch_open` ⟹ `batches`；带去重台账 ⟹ `files_dedup`；否则 `calls`。"""
    if "batch_open" in payload:
        return "batches"
    return "files_dedup" if "billed_files" in payload else "calls"


def test_arm27_bill_units_decl_matches_both_implementations():
    """判据⑲（红先 · `ECC-CB8579F9D826`）：区外头部须有 `BILL_UNITS_DECL` 声明，且
    **两侧源码反推的口径必须与声明一致**、两侧必须写**同一组**计数键（= 共享额度）。

    HEAD 实测：`BILL_UNITS_DECL` 不存在 ⟹ 本臂红（= 「口径漂移无人可检」这一事实本身）。
    修后：任一侧改单位（如 ① 抽掉去重台账、或 ② 补去重）⟹ 反推值 ≠ 声明值 ⟹ 本臂再红，
    强迫作者把两侧拉回同一张声明（这就是「任一处改口径须同步另一处」的**执行面**）。
    """
    src = CLI_SRC.read_text(encoding="utf-8")
    decl = _parse_bill_units_decl(src)
    assert decl, (
        "CLI 缺机器可读的计费单位声明 ⟹ 两套扣减实现（区内按文件数 / 区外按调用次数）的口径"
        "漂移无人可检：请在**区外**「计费单点」头部落一行 "
        "`# BILL_UNITS_DECL path1=<…> path2=<…> counter=edit_budget.remaining`"
        "（ECC-CB8579F9D826）")
    p1, p2 = _bill_payload1(src), _bill_payload2(src)
    assert _unit_of(p1) == decl.get("path1"), (
        "①（hook Gate 4）实际口径 %r ≠ 声明 %r ⟹ 一侧改了单位，另一侧 / 声明未同步（漂移）"
        % (_unit_of(p1), decl.get("path1")))
    assert _unit_of(p2) == decl.get("path2"), (
        "②（区外 `_bill_edit`）实际口径 %r ≠ 声明 %r ⟹ 漂移"
        % (_unit_of(p2), decl.get("path2")))
    assert decl.get("counter") == "edit_budget.remaining", (
        "共享计数键声明须为 `edit_budget.remaining`（两套实现消费的是**同一**额度）：%r" % decl)
    for name, pay in (("path1", p1), ("path2", p2)):
        for k in ("remaining", "used", "edit_count"):
            assert k in pay, (
                "%s 的 payload 未触及共享计数键 %r ⟹ 两套实现不再共享同一额度 / 留痕（账目分叉）：%s"
                % (name, k, pay[:200]))
    # 声明必须落在**区外**：区内 `PROTECTED_REGION::gate` 不可维护 ⟹ 声明放那里只是又一个死锚。
    assert src.index("BILL_UNITS_DECL") > src.rindex("PROTECTED_REGION_END::gate"), (
        "`BILL_UNITS_DECL` 落在受保护区之内 ⟹ 该声明无法随实现同步维护（本臂要求它在区外）")
    hdr = src[src.rindex("# ─── 计费单点"):src.index("_bill_edit() {")]
    assert "BILL_UNITS_DECL" in hdr and "ECC-CB8579F9D826" in hdr, (
        "声明须留在「计费单点」头部并带 finding 锚（可追溯）：%r" % hdr[:200])


_FAKE_DECL = "# BILL_UNITS_DECL path1=files_dedup path2=calls counter=edit_budget.remaining\n"
_FAKE_IMPL1 = (
    'GK_BILL_PATH="$real_path" _state_write "\n'
    "_bf = eb.setdefault('billed_files', [])\n"
    "if _p and _p not in _bf:\n"
    "    _bf.append(_p)\n"
    "    eb['remaining'] = max(0, int(eb.get('remaining', 0)) - 1)\n"
    "    eb['used'] = eb.get('used', 0) + 1\n"
    '" >/dev/null 2>&1 || true\n')
_FAKE_IMPL2 = (
    "_bill_edit() {\n"
    '  _nr=$(_state_write "\n'
    "_box = eb\n"
    "if _r >= 1:\n"
    "    _box['remaining'] = _r - 1\n"
    "    _box['used'] = int(_box.get('used', 0) or 0) + 1\n"
    '" 2>/dev/null | tail -n 1)\n'
    "}\n")
_FAKE_SRC = _FAKE_DECL + _FAKE_IMPL1 + _FAKE_IMPL2


def test_arm28_bill_unit_drift_checker_detects_change():
    """判据⑳（负臂 · 守「检查器非空转」）：抽掉 ① 的去重台账（= 单位从「文件数」翻成「调用次数」）
    ⟹ 反推口径必须随之翻转并与声明失配（即判据⑲**会**响）。

    无本臂时，把 `_unit_of` 写成恒返常量也能让判据⑲转绿 ⟹ 「漂移可检」是假的而不自知。
    """
    assert _unit_of(_bill_payload1(_FAKE_SRC)) == "files_dedup", "① 反推口径错（合成源码）"
    assert _unit_of(_bill_payload2(_FAKE_SRC)) == "calls", "② 反推口径错（合成源码）"
    drifted = _FAKE_SRC.replace(
        "_bf = eb.setdefault('billed_files', [])", "_bf = []")
    assert drifted != _FAKE_SRC, "负臂构造失败（未改动合成源码）"
    assert _unit_of(_bill_payload1(drifted)) == "calls", (
        "① 去重台账被抽掉后反推口径未翻转 ⟹ 检查器空转（读不出单位变更）")
    assert _unit_of(_bill_payload1(drifted)) != _parse_bill_units_decl(drifted)["path1"], (
        "单位改了口径检查器却不报 ⟹ 漂移仍无人可检")


def test_arm29_both_paths_consume_one_shared_counter(tmp_path):
    """判据㉑（守「共享额度」不变式）：同一会话下 ①（Gate 4，两个**不同**文件）与 ②（CLI 写类
    子命令）必须消费**同一个** `sessions.<sid>.remaining` ⟹ 两次不同单位的消费累加在同一额度上。

    这条是「单位混合」之所以危险的**行为面**：若将来有人把 ①/② 各自拆成独立额度（分叉），
    两套单位便不再互相挤兑 —— 那是**另一种**静默失效（额度翻倍），本臂守着它。
    """
    sid = "0123456789abcdef01234567"
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    (sb / "note2.md").write_text("y", encoding="utf-8", newline="\n")
    _consume_as(sb, sid, "note.md")             # ①：本批**首刀** ⟹ −1
    # REV-24（批次边界 = verify）：要让第二次 Gate4 消费也各记 1，须先开新批 ⟹ 本臂强度不变。
    B.append_verify(str(sb / ".gatekeeper.state"), session=sid, node="STAGE_0", cmd="pytest -q")
    _consume_as(sb, sid, "note2.md")            # ①：**新批**首刀 ⟹ 再 −1
    _bill_cli(sb, sid=sid)                      # ②：一次写类子命令 ⟹ 按次 −1
    box = (_budget(sb).get("sessions") or {}).get(sid) or {}
    assert box.get("remaining") == 5, (
        "① 与 ② 未消费同一额度（单位混合却各记各账 = 额度分叉）："
        + json.dumps(box, ensure_ascii=False))
    assert box.get("used") == 3, (
        "共享 `used` 未累加两面消费：" + json.dumps(box, ensure_ascii=False))


# ── T2 计费三条之② / `ECC-0530B31DF9F1`（2026-09-26）：**零副作用形态不得计费**（假计费）────
# 病象（本机实测：沙箱技能根 + HEAD 版 CLI + `edit_budget.max=8/remaining=8`）：
#   · `apply-worktree --code-fix --dry-run …` ⟹ `remaining` **8→7**（该形态在 `cmd_apply_worktree`
#     内于**建 worktree 之前** return ⟹ 零副作用）= **假计费**；
#   · `apply-worktree --reclaim`（**缺省即 dry-run**，只报告；`--apply` 才落刀）⟹ **8→7**（同族）；
#   · 对照 `state-patch '{"…"}'`（真写 state）⟹ 8→7 —— **应当**计费。
# 修法 = 区外计费块前置「零副作用豁免」闸 `_bill_is_noop_invoke`：**只**豁免**有据的显式形态**
#   （实测 / 代码路径可证），**不**放宽到命令级（否则整类命令免费 = 额度失效）。

def _func_seg(src: str, header: str) -> str:
    """取 `header` 起、到下一个**列 0** `}` 的整段，并**剔除整行注释**（形态判据只看代码）。"""
    rest = src[src.index(header):]
    m = re.search(r"(?m)^\}\s*$", rest)
    seg = rest[: m.end()] if m else rest
    return "\n".join(ln for ln in seg.split("\n") if not ln.strip().startswith("#"))


def _cli(sb: Path, args: str):
    """在沙箱里跑一条**任意** CLI 命令行（判据㉒ 要试多种「零副作用形态」）。"""
    w = _wsl(sb)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh %s' % (w, args)],
        capture_output=True, text=True, timeout=180)


def _reset_budget(sb: Path, n: int = 8) -> None:
    """把沙箱 `edit_budget` 复位（判据㉒ 要逐形态量同一把尺）。"""
    f = sb / ".gatekeeper.state"
    st = json.loads(f.read_text(encoding="utf-8"))
    st["gate_data"]["edit_budget"] = {"max": n, "used": 0, "remaining": n}
    f.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8", newline="\n")


def test_arm30_read_only_invocations_are_not_billed(tmp_path):
    """判据㉒（红先 · `ECC-0530B31DF9F1`「假计费」）：**零副作用形态**不得消耗 `edit_budget`。

    HEAD 实测：前两条形态**各扣 1**（`remaining` 8→7）⟹ 本臂红；第三条为**正向对照**
    （真写 state 必须仍计费）⟹ 守「豁免不得放宽过头」。
    """
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    _cli(sb, "apply-worktree --code-fix --dry-run --finding ECC-PROBE01 "
             "--family F3b-edit-budget-accounting")
    b = _budget(sb)
    assert b.get("remaining") == 8 and b.get("used") == 0, (
        "`apply-worktree --code-fix --dry-run`（在建 worktree **之前** return ⟹ 零副作用）被计费 = "
        "假计费：" + json.dumps(b, ensure_ascii=False))
    _reset_budget(sb)
    _cli(sb, "apply-worktree --reclaim")
    b = _budget(sb)
    assert b.get("remaining") == 8 and b.get("used") == 0, (
        "`apply-worktree --reclaim`（**缺省即 dry-run**，只报告 ⟹ 零副作用）被计费 = 假计费："
        + json.dumps(b, ensure_ascii=False))
    _reset_budget(sb)
    _bill_cli(sb)
    b = _budget(sb)
    assert b.get("remaining") == 7 and b.get("used") == 1, (
        "**真工程写** state 的写类子命令未计费 ⟹ 豁免放宽过头（额度失效）："
        + json.dumps(b, ensure_ascii=False))


def test_arm31_noop_invoke_guard_covers_measured_forms():
    """判据㉓（红先 · 形态）：区外计费块须带「零副作用豁免」闸，其**声明**须覆盖已取证形态
    （`apply-worktree` 的 `--code-fix`+`--dry-run`、`--reclaim` 无 `--apply`、`commit` 的
    `--verify-only`），**且不得**退化成命令级豁免。

    无本臂时行为臂只钉住当时跑过的两条 ⟹ 后人删掉 `commit --verify-only` 一档无人发现。
    """
    src = CLI_SRC.read_text(encoding="utf-8")
    assert "_bill_is_noop_invoke() {" in src, (
        "区外计费块缺「零副作用豁免」闸 ⟹ 假计费未修（dry-run / verify-only 形态仍按次计费）")
    seg = _func_seg(src, "_bill_is_noop_invoke() {")
    for tok in ("apply-worktree", "commit", "--code-fix", "--dry-run",
                "--reclaim", "--apply", "--verify-only"):
        assert tok in seg, (
            "豁免闸缺已取证形态 %r（后人删档无人发现）：%s" % (tok, seg[:300]))
    assert '_bill_is_noop_invoke "$cmd" "$@"' in src, "豁免闸定义了却**没接**到计费块上（死码）"
    assert "_CMD_REG" not in seg, (
        "豁免闸读 `_CMD_REG` ⟹ 恐退化成命令级豁免（整类命令免费 = 额度失效）")


# ── T2 计费三条之③ / `ECC-1F6514B84334`（2026-09-26）：**测试面不得消耗真额度** ─────────────
# 病象（本机**实测定位**，2026-09-26）：`accept --full` **每跑一次**把主 agent 会话的
#   `edit_budget.remaining` 扣 **10**（两次独立量测 305→295、295→285 逐条一致；且会话
#   `billed_files` **不变**（54 条）⟹ 扣减全走区外 `_bill_edit` 的**按次**面，**非** Gate4）。
# 真因 = 5 个测试文件用**仓内真 CLI**、不带状态隔离地跑**写类子命令**（计费**先于** `_dispatch`
#   ⟹ 命令随即失败也照扣），命令分布经 `_bill_edit` 调试日志取证 = plan-refinement ×5 /
#   apply-worktree ×4 / audit ×1：
#     `test_gk_preflight_warn.py`（PR ×2）· `test_gk_q4_registration_action.py`（PR ×3）·
#     `test_gk_apply_worktree_errors.py`（AW ×3）· `test_gk_dispatch_autofill.py`（AW ×1）·
#     `test_r19_keys_inherit.py`（AU ×1）—— 逐文件单跑量测：2 / 3 / 3 / 1 / 1 = **10** ✓
# ⚠ **附带实测发现**：`--state <p>` **挡不住**计费 —— `_bill_edit` 的判据面是 `${STATE_FILE:-}`，
#   而 `--state` 只在 `cmd_*` 内部生效（计费发生在**之前**）⟹ `test_gk_apply_worktree_errors.py`
#   三条臂里两条带 `--state`，该文件仍扣 **3**（= 臂数）。故修法**不能**靠 `--state`。
# 修法 = 各站点声明「这是**探测**，不是用户编辑」：`GK_BUDGET_OVERRIDE=1`（与生产面
#   `gk_agent_edit._cli_gate_ok` **同一口径**，不引入第二机制）。实测：同 5 文件 10 → **0**
#   （55 passed）。

_LEAK_SITES = (
    ("scripts/test_gk_preflight_warn.py", "def _check_only("),
    ("scripts/test_gk_q4_registration_action.py", "def _cli("),
    ("scripts/test_gk_apply_worktree_errors.py", "def _run_cli("),
    ("scripts/test_gk_dispatch_autofill.py", "def test_batch_over_k_max_is_fail_loud("),
    ("scripts/test_r19_keys_inherit.py", "def _run("),
)


def test_arm32_repo_cli_probe_sites_declare_budget_override():
    """判据㉔（红先 · `ECC-1F6514B84334`）：五个「测试面打真 CLI」站点须声明
    `GK_BUDGET_OVERRIDE`（= 探测，非用户编辑）⟹ 验收不再消耗主 agent 节点配额。

    HEAD 实测：五处**全无**该声明，且 `accept --full` 每轮扣 **10**（两次量测一致）⟹ 本臂红；
    修后同 5 文件 **10 → 0**（本臂只钉「声明在」；端到端量测见 docs §4.13.27）。
    """
    for rel, anchor in _LEAK_SITES:
        src = (SKILL_DIR / rel).read_text(encoding="utf-8")
        i = src.find(anchor)
        assert i >= 0, (
            "%s 未找到站点锚 %r（改名/搬移后须同步本臂，**勿**静默失效）" % (rel, anchor))
        seg = src[i:i + 2400]        # helper 体 / 单条臂体：声明须落在站点近旁
        assert "GK_BUDGET_OVERRIDE" in seg, (
            "%s 的 %r 仍在跑**真** CLI 探测却不声明 `GK_BUDGET_OVERRIDE` ⟹ pytest 会扣真 state 的"
            "主 agent 节点额度（`ECC-1F6514B84334`；实测 10 次/验收轮）" % (rel, anchor))


# ── `ECC-033715F5215A`（2026-09-26）：`advance … --check` 归入「零副作用形态不计费」────────────
# 病象（实测）：`advance <stage> --check`（= dry-run）被**按次计费**（沙箱实测 `remaining` 8→7），
#   而它的 state 写面实测为 **0**（代码路径穷举，逐点如下）：
#   · python `scripts/gk_advance.py` —— `_write_state` 调用点 6 处全在 `if not dry_run:` 内，
#     且成功路径在 `if dry_run: return {check_only:True,…}` **早退** ⟹ 终写（`d["stage"]=to` + 写盘）
#     不可达；`_monitor_eval` 见 `force or dry_run` 即 `return None`（不写 `rejected_edits`）；
#     `_edit_budget` 的额度/调度变更亦 `not dry_run`。
#   · bash `cmd_advance` —— 4 个写块（red ledger `upsert_red_findings` / auto-audit / audit_extra /
#     achievements+`_write_context_file`）全在 `[ "$dry_run" = "false" ]` 下。
# ⟹ 复用 §4.13.26 的同一豁免闸 `_bill_is_noop_invoke`（**不**新增机制）。
# ⚠ 本批**不**追「成功路径」行为量测：合成 standing state 下守卫恒拒（`advance ECO-AUDIT/EDIT/READ/DOC`
#   皆 rc=1，实测），故主证据 = **写点穷举 + 守卫锚**，并以 arm35 的**下限守卫**把它机检化。

def test_arm34_advance_check_is_not_billed(tmp_path):
    """判据㉖（红先 · 行为）：`advance … --check`（dry-run）不得扣 `edit_budget`；**非** `--check`
    形态（真写类调用）仍须扣 —— 守「豁免不得放宽到命令级」。

    `--force` 只为**跳过 monitor**（standing 的 `advance ECO-*` 会触发 PRM monitor，其 `--api` 模式
    会真调 API）；它与计费无关（计费在 `_dispatch` **之前**，与命令成败无关）。
    """
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    _cli(sb, "advance ECO-DOC --check --force")
    b = _budget(sb)
    assert b.get("remaining") == 8 and b.get("used") == 0, (
        "`advance … --check`（dry-run，state 写面 = 0）被计费 = 假计费："
        + json.dumps(b, ensure_ascii=False))
    _reset_budget(sb)
    _cli(sb, "advance ECO-DOC --force")
    b = _budget(sb)
    assert b.get("remaining") == 7 and b.get("used") == 1, (
        "**非** `--check` 的 advance 未计费 ⟹ 豁免放宽过头（整类命令免费 = 额度失效）："
        + json.dumps(b, ensure_ascii=False))


def test_arm35_advance_check_zero_write_guard_lower_bound():
    """判据㉗（红先 · 形态 · **下限守卫**）：豁免声明须含 `advance` 的 `--check`，且「零副作用」
    的两侧守卫锚须在 —— 防后人**删守卫**而让豁免变 **fail-open**。

    ⚠ 如实标注：本臂是**下限**（计数 + 锚点），**非**写点穷举（穷举结论见 docs §4.13.29）。
    """
    src = CLI_SRC.read_text(encoding="utf-8")
    seg = _func_seg(src, "_bill_is_noop_invoke() {")
    assert "advance" in seg and '" --check "' in seg, (
        "豁免闸未声明 `advance` 的 `--check` 形态 ⟹ 假计费未修：%s" % seg[:300])
    adv = _func_seg(src, "cmd_advance() {")          # bash 侧：`--check` 语义锚 + 写块守卫下限
    assert "--check) dry_run=true" in adv, "`cmd_advance` 的 `--check` 语义锚丢失（改名须同步本臂）"
    n_guard = adv.count('"$dry_run" = "false"')
    assert n_guard >= 5, (
        "`cmd_advance` 的 `dry_run=false` 写块守卫由 ≥5 降到 %d ⟹ 零副作用前提可能已被破坏"
        "（豁免变 fail-open），须重测后再改本臂" % n_guard)
    py = (SKILL_DIR / "scripts" / "gk_advance.py").read_text(encoding="utf-8")
    n_w = py.count("_write_state(") - py.count("def _write_state(")
    n_nd = py.count("not dry_run")
    assert n_w > 0 and n_nd >= n_w, (
        "`gk_advance.py` 的 `_write_state` 调用点 %d 多于 `not dry_run` 守卫 %d ⟹ 疑有**无守卫写点**"
        "（零副作用前提不成立）" % (n_w, n_nd))
    assert "if dry_run:" in py and "check_only" in py, (
        "`gk_advance.py` 丢了成功路径的 `if dry_run:` 早退（`check_only`）⟹ `--check` 会真写终态")


# ── ③ 修订 X（`REV-15`，2026-10-05）：**② 向 ① 归化** —— 两侧计价单位须**单源** ─────────────
# 病象：①（hook Gate4，保护区内，按 `billed_files` 去重）= `files_dedup`；②（区外 `_bill_edit`，
#   按调用次数）= `calls` ⟹ **两套单位共享同一 `remaining`**。`arm27` 判的是「**声明==两实现**」
#   （声明如实描述两套 ⟹ **恒绿** ⟹ 绿恰证「两套仍在」⟹ 拿它撑「单源」= 证据错配）。
# 修法 = 归化：区外 `_bill_edit` 补**文件身份 + 去重**，使 ② 单位 == ① 单位。


def test_arm36_bill_unit_is_single_source():
    """判据⑲′（**声明即契约** · `REV-15` 修订 X → `REV-24` 重述）：

    原判据 = 「两侧单位**必须相等**」（归化目标 = 两通道同单位）。**2026-10-23 owner 裁定
    「批次作计价单位」**后，两通道**维度主动分化**：① Gate4 = `batches`（自上次 verify 以来
    整批 = 1）、② CLI 写类子命令 = `files_dedup`（命令向量去重）。相等不再成立、也不该成立。

    重述后的判据（**不放松**）：两侧反推值必须**逐字等于**区外声明；任一侧静默改口径 ⟹ 红。
    """
    src = CLI_SRC.read_text(encoding="utf-8")
    decl = _parse_bill_units_decl(src)
    p1, p2 = _bill_payload1(src), _bill_payload2(src)
    assert (_unit_of(p1), _unit_of(p2)) == ("batches", "files_dedup"), (
        "两通道口径偏离 REV-24 裁定（①=batches / ②=files_dedup）：实得 (%r, %r)。"
        "改口径须同步声明并更新本臂。" % (_unit_of(p1), _unit_of(p2)))
    assert decl.get("path1") == "batches" and decl.get("path2") == "files_dedup", (
        "声明未与实现同步（漂移）：%r" % (decl,))


def test_arm37_bill_edit_identity_dedup(tmp_path):
    """判据⑲″（归化行为 · 红先 · `REV-15` 修订 X）：`_bill_edit` 按**身份**（实参向量哈希）去重 ——
    同一调用两次只计**一次**；不同调用各计一次。

    HEAD（归化前）红：② 按**调用次数**计 ⟹ 同名两次 = `remaining` 8→6。归化后：同名第二次去重
    ⟹ 8→7；换名 ⟹ 7→6。对照红先：`GK_CLI_UNDER_TEST=<归化前 CLI>` ⟹ 本臂红。
    """
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    _bill_cli(sb, path_name="wt")
    b = _budget(sb)
    assert b.get("remaining") == 7 and b.get("used") == 1, (
        "首次写类子命令未计费：" + json.dumps(b, ensure_ascii=False))
    _bill_cli(sb, path_name="wt")                       # 同一身份 ⟹ 去重（不再扣）
    b = _budget(sb)
    assert b.get("remaining") == 7 and b.get("used") == 1, (
        "**同一**调用（同身份）被重复计费 ⟹ 身份去重未生效（② 仍是 `calls` 单位）："
        + json.dumps(b, ensure_ascii=False))
    _bill_cli(sb, path_name="wt2")                      # 不同身份 ⟹ 再计一次
    b = _budget(sb)
    assert b.get("remaining") == 6 and b.get("used") == 2, (
        "**不同**调用（异身份）未计费 ⟹ 去重放宽过头（额度失效）："
        + json.dumps(b, ensure_ascii=False))
    assert len(b.get("billed_files") or []) == 2, (
        "去重台账未按身份入账（应 2 条）：" + json.dumps(b, ensure_ascii=False))


# ── ③ Phase A（`REV-16` §22.3，2026-10-05）：**只读双通道观测** —— 观测面 + 单位混用率 ──────────
# 交付（§21.3 修订 Y / §22.3）：`scripts/gk_bill_observe.py` —— 纯读 state + 只读 CLI 源 ⟹
#   零写盘 / 零阻断 / 不夺锁 / 不经 `_CMD_REG`。判据⑳′（单位混用率）红先**双样本差分**。

def _unit_drift(src: str) -> float:
    """**实现 vs 声明**的口径漂移率（`REV-24` 重述；单源 `_unit_of`，禁第二实现）：
    任一实现反推单位 ≠ 声明 ⟹ `1.0`；两侧一致 ⟹ `0.0`；无声明 ⟹ `1.0`。

    原口径 = 「两通道单位必须相等」—— owner 2026-10-23 裁定「批次作计价单位」后两通道**维度
    主动分化**（① batches / ② files_dedup），"相等" 不再是判据，"实现 == 声明" 才是。
    """
    decl = _parse_bill_units_decl(src)
    if not decl:
        return 1.0
    p1, p2 = _bill_payload1(src), _bill_payload2(src)
    ok = (_unit_of(p1) == decl.get("path1")) and (_unit_of(p2) == decl.get("path2"))
    return 0.0 if ok else 1.0


def test_arm38_unit_drift_zero_and_red_side_responds():
    """判据⑳′（**声明即契约** · `REV-15` → `REV-24` 重述 · **双样本差分**）：漂移率两条腿。

    病象（§21.4-5）：只断言「漂移率 >0」即**恒真**（空转闸机）。故须两腿：
    **绿侧** = 现网源码：两侧实现反推 == 声明 ⟹ `==0`；
    **红侧** = 合成**声明与实现不符**的样本 ⟹ `>0`（证判据**能**响，非空转）。
    """
    assert _unit_drift(CLI_SRC.read_text(encoding="utf-8")) == 0.0, (
        "实现与 `BILL_UNITS_DECL` 声明不符 ⟹ 漂移率 >0（一侧改了口径却未同步声明）")
    drifted = ("# BILL_UNITS_DECL path1=batches path2=files_dedup counter=edit_budget.remaining\n"
               + _FAKE_IMPL1 + _FAKE_IMPL2)   # 实现里没有 batch_open ⟹ path1 反推为 files_dedup
    assert _unit_drift(drifted) > 0.0, (
        "喂入**声明≠实现**的样本仍 ==0 ⟹ 判据**空转**（读不出漂移）")


def test_arm39_bill_observe_reports_split_usage_and_mismatch(tmp_path):
    """判据㉘（Phase A 观测面 · 红先）：`gk_bill_observe` 须只读报出**分账 usage**
    （`path1`=realpath / `path2`=身份哈希）+ 声明视图（`REV-24` 后两通道**主动分化** ⟹
    `units_declared_equal is False`）+ 失配/漏记告警，且 **λ=UNKNOWN**；跑完 state **逐字不变**。

    红先：脚本不存在 ⟹ `import` 失败（本臂红）；落刀后绿。
    """
    import gk_bill_observe as ob
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 2, "remaining": 6,
                                "billed_files": ["/x/a.md", "0123456789ab"]})
    st = sb / ".gatekeeper.state"
    before = st.read_text(encoding="utf-8")
    rep = ob.observe(str(st), CLI_SRC.read_text(encoding="utf-8"))
    assert st.read_text(encoding="utf-8") == before, "观测脚本写了 state ⟹ 非纯读"
    g = rep["boxes"]["global"]
    assert g["usage"] == {"path1": 1, "path2": 1, "other": 0}, g
    assert rep["units_declared_equal"] is False and rep["lambda"] == "UNKNOWN", rep
    assert g["mismatch"] is False and g["unaccounted"] == 0, g


def test_arm40_bill_observe_flags_mismatch_and_unaccounted(tmp_path):
    """判据㉙（Phase A 观测面 · 负臂 · 守非空转）：账目不守恒（`used+remaining≠max`）⟹ `mismatch`
    为真；② 未归化式的**漏记**（`used > len(billed_files)`）⟹ `unaccounted > 0`。
    """
    import gk_bill_observe as ob
    src = CLI_SRC.read_text(encoding="utf-8")
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 2, "remaining": 6,
                                "billed_files": ["/x/a.md"]})          # used=2 但仅 1 条
    g = ob.observe(str(sb / ".gatekeeper.state"), src)["boxes"]["global"]
    assert g["mismatch"] is False and g["unaccounted"] == 1, g
    r2 = tmp_path / "b"
    r2.mkdir()
    sb2 = _mk_sandbox(r2, {"max": 8, "used": 2, "remaining": 5})       # 2+5≠8
    g2 = ob.observe(str(sb2 / ".gatekeeper.state"), src)["boxes"]["global"]
    assert g2["mismatch"] is True, g2


# ── shell 注入守卫（`ae35631`，2026-10-05）：`_bill_edit` payload 禁 shell 展开元字符 ──────────
# 病象（实测）：`_bill_edit` 经 `_state_write "…"` 传 Python payload ⟹ 该串是 **bash 双引号串**，
#   其中的**反引号**与 **`$`**（命令/参数替换）会被 shell **整体**展开 —— **注释行也不例外**。
#   `ae35631` 实测触发点：payload 内一行 Python 注释含反引号 `REV-15` ⟹ `REV-15: command not found`。
#   ⚠ 既有 `_bill_payload2`（走 `_bill_edit_seg`）**剔整行注释** ⟹ 结构上**抓不到**此病因 ⟹ 守卫
#   必须切**原始** payload（含注释行）。

def _bill_payload2_raw(src: str) -> str:
    """②（区外 `_bill_edit`）传给 `_state_write "…"` 的**整段 shell 串**（**含** Python 注释行）。"""
    rest = src[src.index("_bill_edit() {"):]
    a = rest.index('_state_write "')
    b = rest.index('" 2>/dev/null', a)
    return rest[a:b]


def test_arm41_bill_edit_payload_has_no_shell_expansion():
    """判据㉚（shell 注入守卫 · 红先 · 承 `ae35631`）：`_bill_edit` 的 `_state_write "…"` payload
    不得含 **bash 展开元字符**（反引号 / `$`）——注释行亦然（bash 对双引号串**整体**展开）。

    红先：`GK_CLI_UNDER_TEST=<修复前 CLI>`（注释含反引号）⟹ 红；`ae35631` 修复后 ⟹ 绿。
    """
    pay = _bill_payload2_raw(CLI_SRC.read_text(encoding="utf-8"))
    for bad in ("`", "$"):
        hits = [ln for ln in pay.split("\n") if bad in ln]
        msg = ('`_bill_edit` 的 `_state_write "…"` payload 含 shell 展开元字符 %r ⟹ 双引号内被执行'
               "（实测 'REV-15 not found'，注释行同样展开）；动态值须走 **env**（同 GK_BILL_PATH/GK_BILL_ID），"
               "字面量须转义：%r") % (bad, hits[:3])
        assert not hits, msg
