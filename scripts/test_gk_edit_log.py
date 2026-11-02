"""T4′/T6 载体（edit-log）红先臂 —— `gk_budget_ledger` 的 `kind=edit` 扩展。

落刀前：`gk_budget_ledger` 无 `append_edit` / `read_edits` ⟹ 本套件**红**（AttributeError）。
落刀后：edit 级事件写入**独立**旁挂 `<state>.edit-log.jsonl`（**裸追加**：零子进程、**不**逐条 seal）；
        且**不污染**提额账本 `<state>.budget-log.jsonl`（含其封印）。

背景（为什么必须补载体；见 edit-budget 正本 §9 / 本轮 2026-10-08 实读核实）：
  · `billed_files` = **dedup 集合** ⟹ 同文件重复被折叠、无 `ts` ⟹ 不可测 T4′（同文件重复）。
  · `rejected_edits` = `gk_advance._monitor_eval` 的 **advance 阻断**窗口 ⟹ **语义错配**（非编辑级）。
  · 故新增**独立**旁挂 append-only edit-log 作事件级载体。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gk_budget_ledger as B  # noqa: E402


def _mkstate(tmp_path):
    st = str(tmp_path / ".gkstate")
    Path(st).write_text(json.dumps({"gate_data": {"edit_budget": {"max": 24, "used": 0, "remaining": 24}}}),
                        encoding="utf-8")
    return st


def test_arm_edit_log_appends_per_edit_not_deduped(tmp_path):
    """载体臂：同文件连续 2 次编辑 ⟹ 2 条事件（对照 `billed_files` dedup 只 1 条）。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s1", node="ECO-EDIT", path="/x/a.py")
    B.append_edit(st, session="s1", node="ECO-EDIT", path="/x/a.py")
    recs = B.read_edits(st)
    assert len(recs) == 2, "edit-log 必须逐事件（不 dedup）；实得 %d 条" % len(recs)


def test_arm_edit_log_kind_and_ts_present(tmp_path):
    """载体臂：每条带 `kind=edit` + 非空 `ts` + `path`（T4′/T6 需要时间窗与目标面）。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s1", node="n", path="/x/a.py")
    rec = B.read_edits(st)[0]
    assert rec.get("kind") == "edit"
    assert rec.get("ts"), "缺 ts ⟹ 无法做窗口判定"
    assert rec.get("path") == "/x/a.py"


def test_arm_edit_log_is_separate_file(tmp_path):
    """零回归臂（隔离）：edit 事件走**独立** edit-log，**不**触碰提额账本（`count_raises` 仍 0）。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s1", node="n", path="/x/a.py")
    assert Path(str(st) + B.EDIT_SUFFIX).exists(), "缺 edit-log 文件"
    assert not Path(str(st) + B.SUFFIX).exists(), "edit 事件污染了提额账本 budget-log"
    total, today = B.count_raises(st)
    assert (total, today) == (0, 0), "edit 行被误计为提额 ⟹ C1 口径破（实得 %r）" % ((total, today),)


def test_arm_edit_log_no_per_record_seal(tmp_path):
    """性能臂：`append_edit` 为**裸追加** ⟹ **不**写 edit-log 的 `.seal`（seal 由节点级低频重算）。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s1", node="n", path="/x/a.py")
    assert not Path(str(st) + B.EDIT_SEAL_SUFFIX).exists(), \
        "append_edit 不应逐条重算 seal（高频 ⟹ Gate4 旁爆）"


def test_arm_edit_log_window(tmp_path):
    """窗口臂：`count_edits(window=N)` 只数**最近 N 条**（T4′ 同文件重复判据用）。"""
    st = _mkstate(tmp_path)
    for p in ("/x/a.py", "/x/b.py", "/x/c.py"):
        B.append_edit(st, session="s1", node="n", path=p)
    assert B.count_edits(st) == 3
    assert B.count_edits(st, window=2) == 2


# ───────── 集成臂（① 面接线；owner 裁定 A 2026-10-08）─────────
# 复用 `test_gk_edit_budget_metering.py` 的沙箱形态：`scripts` 软链 + CLI 实拷 + 最小 standing state。
# 红先证据：`GK_CLI_UNDER_TEST=<改动前 CLI>` ⟹ 本臂**红**（① 面未写 edit-log）。
SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SKILL_DIR / "gatekeeper-cli.sh"))


def _mk_sandbox(tmp_path, remaining=8):
    sb = (tmp_path / "sb").resolve()
    sb.mkdir()
    w = str(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (str(SCRIPT_DIR), w, str(CLI_SRC), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, "沙箱搭建失败：%s%s" % (r.stdout, r.stderr)
    (sb / ".gatekeeper.state").write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1", "worktree": w,
        "gate_data": {"project_type": "standing",
                      "edit_budget": {"max": 8, "used": 0, "remaining": remaining},
                      "scheduler": {"mode": "constant", "max_lr": 4, "min_lr": 1,
                                    "total_steps": 6, "current_step": 1, "current_lr": 4}},
    }, ensure_ascii=False), encoding="utf-8", newline="\n")
    (sb / "note.md").write_text("x", encoding="utf-8", newline="\n")
    return sb


def test_arm_edit_log_face1_writes_on_pre_tool_check(tmp_path):
    """集成臂（① 面）：走一次 `pre-tool-check edit` ⟹ `<state>.edit-log.jsonl` 落 1 条 `kind=edit`。"""
    sb = _mk_sandbox(tmp_path)
    w = str(sb)
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"' % (w, w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, "pre-tool-check 未放行：%s%s" % (r.stdout, r.stderr)
    el = Path(str(sb / ".gatekeeper.state") + ".edit-log.jsonl")
    assert el.exists(), "① 面未写 edit-log（载体未接线）"
    lines = [json.loads(x) for x in el.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(lines) == 1 and lines[0].get("kind") == "edit", "edit-log 内容不符：%r" % (lines,)
    assert str(lines[0].get("path", "")).endswith("note.md"), "edit-log 目标面不符：%r" % (lines[0].get("path"),)
    assert lines[0].get("node") == "STAGE_0", \
        "node 来源未接线（应取 state.stage = NODE_REGISTRY 节点）：%r" % (lines[0].get("node"),)


# ───────── 落刀3 臂：节点级封印 + 轮转归档（§23.3 对策①②）─────────
def test_arm_seal_edits_writes_verifiable_seal(tmp_path):
    """封印臂：`seal_edits` 写 `<state>.edit-log.jsonl.seal` 且**可验证**；追加篡改 ⟹ 校验失败。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s1", node="n", path="/x/a.py")
    r = B.seal_edits(st)
    assert r.get("ok"), "seal_edits 失败：%r" % (r,)
    assert Path(str(st) + B.EDIT_SEAL_SUFFIX).exists(), "未写 edit-log 封印"
    assert B.verify_edits_seal(st).get("ok") is True, "封印自校验未过"
    with open(str(st) + B.EDIT_SUFFIX, "a", encoding="utf-8") as f:
        f.write('{"ts":"x","kind":"edit","path":"/x/tampered"}\n')
    assert B.verify_edits_seal(st).get("ok") is False, "封印未检出篡改"


def test_arm_rotate_edits_archives_and_keeps_window(tmp_path):
    """轮转臂：超阈值 ⟹ 旧行进 archive、主文件保留最近 `keep`；且**不碰** budget-log。"""
    st = _mkstate(tmp_path)
    for i in range(10):
        B.append_edit(st, session="s1", node="n", path="/x/f%d.py" % i)
    r = B.rotate_edits(st, max_lines=4, keep=2)
    assert r.get("ok"), "rotate_edits 失败：%r" % (r,)
    assert (r.get("archived"), r.get("kept")) == (8, 2), "轮转计数不符：%r" % (r,)
    assert B.count_edits(st) == 2, "主文件未保留窗口"
    arch = Path(str(st) + B.EDIT_ARCHIVE_SUFFIX)
    assert arch.exists(), "未生成 archive"
    assert len([x for x in arch.read_text(encoding="utf-8").splitlines() if x.strip()]) == 8, "archive 行数不符"
    assert not Path(str(st) + B.SUFFIX).exists(), "轮转污染了 budget-log"


def test_arm_audit_triggers_edit_log_maintenance(tmp_path):
    """集成臂（区外低频边界）：跑 `gk_audit_state.py --all` ⟹ edit-log 被**封印**（并轮转）。"""
    sb = _mk_sandbox(tmp_path)
    st = str(sb / ".gatekeeper.state")
    for i in range(6):
        B.append_edit(st, session="s1", node="STAGE_0", path="/x/f%d.py" % i)
    r = subprocess.run(
        [sys.executable, str(SCRIPT_DIR / "gk_audit_state.py"), "--all", "--state-file", st],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, "audit 失败：%s%s" % (r.stdout, r.stderr)
    assert Path(str(st) + B.EDIT_SEAL_SUFFIX).exists(), "审计边界未触发 edit-log 封印"
    assert B.verify_edits_seal(st).get("ok") is True, "审计后 edit-log 封印不可验"


# ───────── M 批红先臂（ED1–ED9；承 §23.8.1「判据落刀前置」，2026-10-08）─────────
# 落刀前红：ED1（写侧双实现）/ ED3（result 恒 allow、拒绝零事件）/ ED4（坏行静默）/ ED5（无锁）/
#           ED6（无 node_seq）/ ED8（CLI 本地时区 ts）⟹ 下列臂 HEAD 必红。
def test_arm_edit_log_result_three_states(tmp_path):
    """ED3 臂：`result` 三态（allow/reject/override）如实落盘；非法值降回 `allow`。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s1", node="n", path="/x/a.py", result="reject")
    B.append_edit(st, session="s1", node="n", path="/x/a.py", result="override")
    B.append_edit(st, session="s1", node="n", path="/x/a.py", result="bogus")
    rs = [r.get("result") for r in B.read_edits(st)]
    assert rs == ["reject", "override", "allow"], "result 三态落盘不符：%r" % (rs,)


def test_arm_edit_log_bad_lines_counted(tmp_path):
    """ED4 臂：坏行**显式计数**（原静默跳过 ⟹「0 条」可被读成「无 thrash」）。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s1", node="n", path="/x/a.py")
    with open(str(st) + B.EDIT_SUFFIX, "a", encoding="utf-8") as f:
        f.write("{not json}\n")
    edits, stat = B.read_edits_stat(st)
    assert stat["bad"] == 1 and stat["edits"] == 1, "坏行计数不符：%r" % (stat,)
    assert len(edits) == 1


def test_arm_append_edit_node_seq_runs(tmp_path):
    """ED6 臂：`node_seq` = 同会话节点**实例序**（节点变化 +1）⟹ 区分同类型节点的多次进入。"""
    st = _mkstate(tmp_path)
    for node in ("ECO-EDIT", "ECO-EDIT", "ECO-READ", "ECO-EDIT"):
        B.append_edit(st, session="s1", node=node, path="/x/a.py")
    seqs = [r.get("node_seq") for r in B.read_edits(st)]
    assert seqs == [1, 1, 2, 3], "node_seq 实例序不符：%r" % (seqs,)
    B.append_edit(st, session="s2", node="ECO-EDIT", path="/x/a.py")
    assert B.read_edits(st)[-1].get("node_seq") == 1, "异会话 node_seq 未独立起算"


def test_arm_edit_log_lock_file_created(tmp_path):
    """ED5 臂（结构）：写/轮转/封印走 `_edit_lock` ⟹ 生成 `<state>.edit-log.lock`。"""
    st = _mkstate(tmp_path)
    lock = Path(str(st) + B.EDIT_LOCK_SUFFIX)
    assert not lock.exists()
    B.append_edit(st, session="s1", node="n", path="/x/a.py")
    assert lock.exists(), "append_edit 未走 _edit_lock（无锁文件 ⟹ ED5 未接线）"


def test_arm_rotate_edits_concurrent_no_loss(tmp_path):
    """ED5 臂（并发）：4 进程并发轮转 ⟹ 主文件 + archive 行数 == 原始条数（无重复/无丢失）。"""
    st = _mkstate(tmp_path)
    n = 40
    for i in range(n):
        B.append_edit(st, session="s1", node="n", path="/x/f%d.py" % i)
    code = ("import sys; sys.path.insert(0, %r); import gk_budget_ledger as B;"
            "B.rotate_edits(%r, max_lines=5, keep=3)" % (str(SCRIPT_DIR), st))
    procs = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(4)]
    for p in procs:
        p.wait(timeout=120)
    main = [l for l in Path(str(st) + B.EDIT_SUFFIX).read_text(encoding="utf-8").splitlines() if l.strip()]
    arch_p = Path(str(st) + B.EDIT_ARCHIVE_SUFFIX)
    arch = [l for l in arch_p.read_text(encoding="utf-8").splitlines() if l.strip()] if arch_p.exists() else []
    assert len(main) + len(arch) == n, "并发轮转丢/重事件：main=%d arch=%d 期望 %d" % (len(main), len(arch), n)
    assert len(set(main + arch)) == n, "并发轮转出现重复行（无锁 RMW 的典型后果）"


def test_arm_edit_log_stats_reader(tmp_path):
    """ED2 臂：`edit_log_stats`（生产读取面）如实摘要 edits/bad/by_result/archived。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s1", node="n", path="/x/a.py", result="allow")
    B.append_edit(st, session="s1", node="n", path="/x/b.py", result="reject")
    with open(str(st) + B.EDIT_SUFFIX, "a", encoding="utf-8") as f:
        f.write("garbage\n")
    s = B.edit_log_stats(st)
    assert s["edits"] == 2 and s["bad"] == 1, "stats 计数不符：%r" % (s,)
    assert s["by_result"].get("allow") == 1 and s["by_result"].get("reject") == 1, \
        "by_result 不符：%r" % (s["by_result"],)
    assert s["last_ts"], "last_ts 缺失"


def test_arm_face1_ts_is_utc(tmp_path):
    """ED8 臂（集成）：① 面写入的 `ts` 必须是 **UTC**（原内联 `printf` 为本地时区 + 字面 Z）。

    ⚠ 强制 `TZ=Asia/Shanghai`（+08:00）⟹ 落刀前（本地时区）ts 会偏 8h，本臂确定性红。
    """
    import datetime
    sb = _mk_sandbox(tmp_path)
    w = str(sb)
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"' % (w, w)],
        capture_output=True, text=True, timeout=120, env=dict(os.environ, TZ="Asia/Shanghai"))
    assert r.returncode == 0, "pre-tool-check 未放行：%s%s" % (r.stdout, r.stderr)
    el = Path(str(sb / ".gatekeeper.state") + ".edit-log.jsonl")
    rec = json.loads([x for x in el.read_text(encoding="utf-8").splitlines() if x.strip()][0])
    ts = datetime.datetime.fromisoformat(str(rec["ts"]).replace("Z", "+00:00"))
    now = datetime.datetime.now(datetime.timezone.utc)
    assert abs((now - ts).total_seconds()) < 180, \
        "ts 非 UTC（本地时区 + 字面 Z 双源）：%r（now=%s）" % (rec["ts"], now.isoformat())


def test_arm_reject_event_logged_on_budget_block(tmp_path):
    """ED3 臂（集成）：额度耗尽 ⟹ 门禁 BLOCK 且 edit-log 记一条 `result=reject`（原为零事件）。"""
    sb = _mk_sandbox(tmp_path, remaining=0)
    w = str(sb)
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"' % (w, w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode != 0, "额度耗尽应 BLOCK，实得 rc=%d：%s" % (r.returncode, r.stdout)
    el = Path(str(sb / ".gatekeeper.state") + ".edit-log.jsonl")
    assert el.exists(), "拒绝路径未写 edit-log（ED3 未接线）"
    recs = [json.loads(x) for x in el.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(recs) == 1 and recs[0].get("result") == "reject", "拒绝事件不符：%r" % (recs,)


def test_arm_override_event_logged(tmp_path):
    """ED3 臂（集成）：`GK_BUDGET_OVERRIDE=1` 放行 ⟹ edit-log 记一条 `result=override`（原零事件）。"""
    sb = _mk_sandbox(tmp_path, remaining=0)
    w = str(sb)
    env = dict(os.environ, GK_BUDGET_OVERRIDE="1")
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"' % (w, w)],
        capture_output=True, text=True, timeout=120, env=env)
    assert r.returncode == 0, "override 应放行，实得 rc=%d：%s%s" % (r.returncode, r.stdout, r.stderr)
    el = Path(str(sb / ".gatekeeper.state") + ".edit-log.jsonl")
    recs = [json.loads(x) for x in el.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(recs) == 1 and recs[0].get("result") == "override", \
        "override 事件不符（原逃生舱期零记录）：%r" % (recs,)


# ───────── T4′ 判据 / T6 telemetry（§3 T4′ / §25；2026-10-08 owner 裁定）─────────
# 落刀前红：`append_verify` / `edit_spam_flag` / `read_events_stat` / `KIND_VERIFY` / `EDIT_SPAM_*`
#           均**不存在** ⟹ HEAD 版本套件 ImportError/AttributeError 收集期红。
def test_arm_verify_and_spam_constants():
    """常量臂：`KIND_VERIFY` 与 T4′ 窗口/阈值（[ASSUMPTION-10]：N=50 / K=3）。"""
    assert B.KIND_VERIFY == "verify"
    assert B.EDIT_SPAM_K == 3, "T4′ 阈值 K 应为 3，实得 %r" % (B.EDIT_SPAM_K,)
    assert B.EDIT_SPAM_WINDOW == 50, "T4′ 窗口 N 应为 50，实得 %r" % (B.EDIT_SPAM_WINDOW,)


def test_arm_verify_event_isolated_from_edits(tmp_path):
    """T6 载体臂：`append_verify` 落 `kind=verify`；`read_edits` **不**含它；`bad` 不增。"""
    st = _mkstate(tmp_path)
    B.append_verify(st, session="s", node="n", cmd="ctest")
    evs, stat = B.read_events_stat(st)
    assert stat["verifies"] == 1 and stat["edits"] == 0 and stat["bad"] == 0, \
        "verify 事件被误计（应 kind 分流，不算 bad）：%r" % (stat,)
    assert len(evs) == 1 and evs[0].get("kind") == "verify"
    assert len(B.read_edits(st)) == 0, "verify 事件混入 read_edits（kind 过滤失效）"
    assert not Path(str(st) + B.SUFFIX).exists(), "verify 事件污染了提额账本"


def test_arm_verify_then_edit_order_preserved(tmp_path):
    """窗口臂：`read_events` 保持**文件序**（T4′/T6 窗口 + 最近 verify 判定依赖序）。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s", node="n", path="/x/a.py")
    B.append_verify(st, session="s", node="n", cmd="pytest")
    B.append_edit(st, session="s", node="n", path="/x/a.py")
    kinds = [e.get("kind") for e in B.read_events(st)]
    assert kinds == ["edit", "verify", "edit"], "事件序错乱：%r" % (kinds,)


def test_arm_reject_leg_flags(tmp_path):
    """T4′ 被拒腿：同 path 3 条 `result=reject` ⟹ flagged；且**并计不重复**（count==3）。"""
    st = _mkstate(tmp_path)
    for _ in range(3):
        B.append_edit(st, session="s", node="n", path="/x/a.py", result="reject")
    f = B.edit_spam_flag(st, "/x/a.py")
    assert f["reject"] == 3 and f["count"] == 3, "被拒计数或并计去重错：%r" % (f,)
    assert f["flagged"] is True, "3 次被拒应 flagged：%r" % (f,)
    assert B.edit_spam_flag(st, "/x/other.py")["flagged"] is False, "异路径被误标"


def test_arm_verify_resets_unverified_leg(tmp_path):
    """T4′ 未验证腿（主齿）：verify 之前/之后的编辑分别起算；达到 K ⟹ flagged。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s", node="n", path="/x/a.py")
    B.append_edit(st, session="s", node="n", path="/x/a.py")
    B.append_verify(st, session="s", node="n", cmd="pytest")
    B.append_edit(st, session="s", node="n", path="/x/a.py")
    f = B.edit_spam_flag(st, "/x/a.py")
    assert f["unverified"] == 1 and f["flagged"] is False, \
        "verify 未重置未验证计数：%r" % (f,)
    B.append_edit(st, session="s", node="n", path="/x/a.py")
    B.append_edit(st, session="s", node="n", path="/x/a.py")
    assert B.edit_spam_flag(st, "/x/a.py")["flagged"] is True, "verify 后 3 次编辑应 flagged"


def test_arm_spam_window_and_k_honored(tmp_path):
    """窗口/阈值臂：显式 window=2 ⟹ 只数最近 2 条（同一 a.py 3 条中仅末 2 条入窗）。"""
    st = _mkstate(tmp_path)
    for _ in range(3):
        B.append_edit(st, session="s", node="n", path="/x/a.py")
    assert B.edit_spam_flag(st, "/x/a.py", window=2, k=3)["flagged"] is False, \
        "窗口未生效（应只数最近 2 条）"
    assert B.edit_spam_flag(st, "/x/a.py", window=3, k=3)["flagged"] is True


# ───────── T4′ 的**验证要求**（2026-10-23 owner 令「把 T4′ 的验证要求也加上」）─────────
# 病象（旧语义）：`result=reject` 的「被拒腿」**无条件**计数 ⟹ 同一文件撞墙 3 次后，即使
#   补跑验证，该 path 仍被判 spam（`flagged=True`），下一刀继续 `cost=2`
#   = **罚得下去、兑付不了**（与 T6 修前「只罚不兑付」同型）。现两腿统一为
#   「最近一次 verify 之后的编辑」⟹ 验证可销账；`reject` 降为**诊断读数**（不参与判罚）。
def test_arm_verify_resets_reject_leg(tmp_path):
    """被拒腿也要验证要求：3 次被拒 → flagged；verify 后 ⟹ 不 flagged（但 reject 读数保留）。"""
    st = _mkstate(tmp_path)
    for _ in range(3):
        B.append_edit(st, session="s", node="n", path="/x/a.py", result="reject")
    assert B.edit_spam_flag(st, "/x/a.py")["flagged"] is True, "前提失效：3 次被拒应先 flagged"
    B.append_verify(st, session="s", node="n", cmd="pytest")
    f = B.edit_spam_flag(st, "/x/a.py")
    assert f["reject"] == 3, "`reject` 仍应作为诊断读数保留：%r" % (f,)
    assert f["count"] == 0 and f["flagged"] is False, \
        "验证未给被拒腿销账（verify 后仍 flagged = 只罚不兑付）：%r" % (f,)


def test_arm_reject_after_verify_still_counts(tmp_path):
    """守卫：验证**之后**再撞墙仍计 spam（验证不是永久免罪符）。"""
    st = _mkstate(tmp_path)
    B.append_verify(st, session="s", node="n", cmd="pytest")
    for _ in range(3):
        B.append_edit(st, session="s", node="n", path="/x/a.py", result="reject")
    f = B.edit_spam_flag(st, "/x/a.py")
    assert f["count"] == 3 and f["flagged"] is True, \
        "verify 之后的被拒未计数（豁免过宽 = 撞墙免费）：%r" % (f,)


def test_arm_edit_log_stats_reports_verifies(tmp_path):
    """ED2 读数面扩：`edit_log_stats` 报 `verifies` + `by_kind`（T6 telemetry 读数）。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s", node="n", path="/x/a.py")
    B.append_verify(st, session="s", node="n", cmd="pytest")
    s = B.edit_log_stats(st)
    assert s["edits"] == 1 and s["verifies"] == 1, "edits/verifies 摘要不符：%r" % (s,)
    assert s["by_kind"] == {"edit": 1, "verify": 1}, "by_kind 不符：%r" % (s["by_kind"],)


def test_arm_edit_log_stats_t6_readface(tmp_path):
    """T6 读数臂（§25.7，只读）：`edit_log_stats.t6.by_node` 按 `session/node` 报未验证编辑数。

    落刀前红：`edit_log_stats` 无 `t6` 键（`KeyError`）。
    """
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s", node="ECO-EDIT", path="/x/a.py")
    B.append_edit(st, session="s", node="ECO-EDIT", path="/x/b.py")
    B.append_verify(st, session="s", node="ECO-EDIT", cmd="pytest")
    B.append_edit(st, session="s", node="ECO-EDIT", path="/x/c.py")
    t6 = B.edit_log_stats(st)["t6"]
    d = t6["by_node"]["s/ECO-EDIT"]
    assert d["edits"] == 3 and d["verifies"] == 1, "t6 计数不符：%r" % (d,)
    assert d["unverified"] == 1, "t6 未验证腿应= verify 后 1 次编辑：%r" % (d,)
    assert t6["k"] == B.EDIT_SPAM_K and t6["window"] == B.EDIT_SPAM_WINDOW
    # reject 归 T4′ 被拒腿 ⟹ **不**计入 T6 未验证腿
    B.append_edit(st, session="s", node="ECO-EDIT", path="/x/d.py", result="reject")
    d2 = B.edit_log_stats(st)["t6"]["by_node"]["s/ECO-EDIT"]
    assert d2["unverified"] == 1, "reject 被误计入 T6 未验证腿：%r" % (d2,)


# ───────── T6 判罚（§3 T6 / §25.8；跨文件散点 thrash）─────────
def test_arm_node_unverified_flag(tmp_path):
    """T6 判据臂：同 (session,node) 未验证编辑 ≥ K ⟹ flagged；verify 重置；异节点不误标。"""
    st = _mkstate(tmp_path)
    for i in range(3):
        B.append_edit(st, session="s", node="N1", path="/x/f%d.py" % i)
    assert B.node_unverified_flag(st, "s", "N1")["flagged"] is True
    assert B.node_unverified_flag(st, "s", "N2")["flagged"] is False, "异节点被误标"
    B.append_verify(st, session="s", node="N1", cmd="pytest")
    assert B.node_unverified_flag(st, "s", "N1")["unverified"] == 0, "verify 未重置 T6"
    assert B.node_unverified_flag(st, "s", "N1", k=1)["unverified"] == 0


def test_arm_t6_cross_file_unverified_costs_two(tmp_path):
    """T6 集成臂：同节点 3 条**不同文件**的未验证编辑 ⟹ 本刀 **+1 附加费**。

    `REV-24`（批次计价）：预置事件 ⟹ 本批**已开账** ⟹ 基准 0，所以 remaining = 8−1 = **7**；
    若 T6 关掉则本刀 **0**（= 8）—— 两次读数之差就是 T6 的附加费（差分臂，防「本来就扣 1」混淆）。
    关键 = 3 条**异 path** ⟹ 每 path 仅 1 次（T4′ 不 flagged），但节点累计 3 次 ⟹ T6 flagged。
    """
    sb = _mk_sandbox(tmp_path, remaining=8)
    w = str(sb)
    _seed_events(str(sb / ".gatekeeper.state"), os.path.realpath(w + "/note.md"), 1)  # 触 T6 计数用
    for i in range(2):
        B.append_edit(str(sb / ".gatekeeper.state"), session="", node="STAGE_0",
                      path=os.path.realpath(w + "/g%d.py" % i))
    r = _pre_tool_edit(w, sb)
    assert r.returncode == 0, "pre-tool-check 未放行：%s%s" % (r.stdout, r.stderr)
    assert _remaining(sb) == 7, "T6 未生效（期望 8-1=7；实得 %r）" % _remaining(sb)
    d2 = tmp_path / "b"
    d2.mkdir()
    sb2 = _mk_sandbox(d2, remaining=8)
    w2 = str(sb2)
    for i in range(3):
        B.append_edit(str(sb2 / ".gatekeeper.state"), session="", node="STAGE_0",
                      path=os.path.realpath(w2 + "/g%d.py" % i))
    _pre_tool_edit(w2, sb2, env=dict(os.environ, GK_T6="0"))
    assert _remaining(sb2) == 8, "T6 关闭时仍扣了附加费（差分臂失效）：%r" % _remaining(sb2)


def test_arm_t6_kill_switch_disables_penalty(tmp_path):
    """T6 kill switch：`GK_T6=0` ⟹ 3 条非同文件未验证编辑也不加价（本批已开账 ⟹ 扣 **0**）。"""
    sb = _mk_sandbox(tmp_path, remaining=8)
    w = str(sb)
    for i in range(3):
        B.append_edit(str(sb / ".gatekeeper.state"), session="", node="STAGE_0",
                      path=os.path.realpath(w + "/h%d.py" % i))
    r = _pre_tool_edit(w, sb, env=dict(os.environ, GK_T6="0"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert _remaining(sb) == 8, "T6 kill switch 未生效（期望 8-0=8）：%r" % _remaining(sb)


# ───────── T4′ 集成臂（计费咽喉：pre_tool_check）─────────
def _seed_events(st, path, n, result="allow"):
    for _ in range(n):
        B.append_edit(st, session="", node="STAGE_0", path=path, result=result)


def _pre_tool_edit(w, sb, env=None):
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"' % (w, w)],
        capture_output=True, text=True, timeout=120, env=env)


def _remaining(sb):
    return json.loads((sb / ".gatekeeper.state").read_text(encoding="utf-8"))["gate_data"]["edit_budget"]["remaining"]


def test_arm_t4p_same_file_unverified_costs_two(tmp_path):
    """T4′ 集成臂：窗口内同 path 未验证编辑 ≥ K ⟹ 本刀 **+1 附加费**。

    `REV-24`（批次计价）：3 条预置事件 ⟹ 本批已开账 ⟹ 基准 0 ⟹ remaining = 8−1 = **7**
    （旧口径下是 8−2=6；本臂因此在新旧 CLI 上读数不同 ⟹ 仍是红先臂）。
    """
    sb = _mk_sandbox(tmp_path, remaining=8)
    w = str(sb)
    _seed_events(str(sb / ".gatekeeper.state"), os.path.realpath(w + "/note.md"), 3)
    r = _pre_tool_edit(w, sb)
    assert r.returncode == 0, "pre-tool-check 未放行：%s%s" % (r.stdout, r.stderr)
    assert _remaining(sb) == 7, \
        "T4′ 未生效（期望 8-1=7；实得 %r ⟹ 附加费未接线）" % _remaining(sb)


def test_arm_t4p_below_threshold_no_penalty(tmp_path):
    """T4′ 负臂：仅 2 条（< K=3）⟹ **不加附加费**（本批已开账 ⟹ 扣 0）。"""
    sb = _mk_sandbox(tmp_path, remaining=8)
    w = str(sb)
    _seed_events(str(sb / ".gatekeeper.state"), os.path.realpath(w + "/note.md"), 2)
    r = _pre_tool_edit(w, sb)
    assert r.returncode == 0, r.stdout + r.stderr
    assert _remaining(sb) == 8, "阈值下不应加价（期望 8-0=8）：%r" % _remaining(sb)


def test_arm_t4p_kill_switch_disables_penalty(tmp_path):
    """T4′ kill switch：`GK_EDIT_LOG=0` ⟹ 3 条也不加价（本批已开账 ⟹ 扣 0）。

    ⚠ 同批关 `GK_T6=0`（否则 T6 会对同一批 3 条未验证编辑独立加价 ⟹ **无法隔离** T4′ 回退）。
    """
    sb = _mk_sandbox(tmp_path, remaining=8)
    w = str(sb)
    _seed_events(str(sb / ".gatekeeper.state"), os.path.realpath(w + "/note.md"), 3)
    r = _pre_tool_edit(w, sb, env=dict(os.environ, GK_EDIT_LOG="0", GK_T6="0"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert _remaining(sb) == 8, "kill switch 未生效（期望 8-0=8）：%r" % _remaining(sb)


# ───────── §23.6-2 标定取数器（`calibrate`；finding ECC-6A0F7E9F0F5C）─────────
def _seed_calib(st):
    """3 个 `(session,node)` 组：s1/nA=5 未验证；s1/nB=2 编辑+1 verify（⟹ 0 未验证）；s2/nA=3 未验证。"""
    for _ in range(5):
        B.append_edit(st, session="s1", node="nA", path="/x/a.py")
    B.append_edit(st, session="s1", node="nB", path="/x/b.py")
    B.append_edit(st, session="s1", node="nB", path="/x/b.py")
    B.append_verify(st, session="s1", node="nB", cmd="pytest -q")
    for _ in range(3):
        B.append_edit(st, session="s2", node="nA", path="/x/c.py")


def test_arm_calibrate_insufficient_data_is_explicit(tmp_path):
    """空样本 ⟹ 显式 `insufficient_data` + `suggest=None`（**禁**少量样本外推 / 禁合成）。"""
    st = _mkstate(tmp_path)
    out = B.calibrate(st)
    assert out["insufficient_data"] is True
    assert out["suggest"] is None, "样本不足竟给了 K/N 建议 ⟹ 外推（禁）"
    assert out["need"] == {"min_nodes": B.EDIT_CALIB_MIN_NODES, "have_nodes": 0}
    assert "禁合成" in out["note"]


def test_arm_calibrate_suggests_k_n_from_real_events(tmp_path):
    """足量样本 ⟹ 由**真实**事件分布出 K/N（分位法，确定性）。"""
    st = _mkstate(tmp_path)
    _seed_calib(st)
    out = B.calibrate(st, percentile=50, min_nodes=3)
    assert out["insufficient_data"] is False
    assert out["sample"]["nodes"] == 3 and out["sample"]["edits"] == 10, out["sample"]
    # p50(unverified [0,3,5]) = 3；p50(edits_per_node [2,3,5]) = 3
    assert out["suggest"]["K"] == 3 and out["suggest"]["N"] == 3, out["suggest"]
    assert out["suggest"]["EDIT_MAX_LINES"] is None, "本载体不含行数 ⟹ 不得臆造 EDIT_MAX_LINES"


def test_arm_calibrate_single_source_with_t6_groups(tmp_path):
    """取数面**单源**：`basis` 与判据 `_t6_groups` 同源（禁第二实现 ⟹ 防漂移）。"""
    st = _mkstate(tmp_path)
    _seed_calib(st)
    out = B.calibrate(st, percentile=100, min_nodes=3)
    grp = B._t6_groups(B.read_events(st))
    assert out["basis"]["t6_unverified"]["max"] == max(d["unverified"] for d in grp.values())
    assert out["suggest"]["K"] == 5, out["suggest"]          # max unverified = 5


def test_arm_calibrate_cli_wired(tmp_path):
    """CLI 臂：`gk_budget_ledger.py calibrate` 子命令可调用并回 JSON（§23.6-2 取数口）。"""
    st = _mkstate(tmp_path)
    _seed_calib(st)
    r = subprocess.run([sys.executable, str(SCRIPTS / "gk_budget_ledger.py"), "calibrate",
                        "--state", st, "--percentile", "50", "--min-nodes", "3"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["ok"] is True and out["suggest"]["K"] == 3, out


def test_arm_verify_append_cli_wired(tmp_path):
    """CLI 臂（2026-10-23 发现并修）：`verify-append --cmd` 必须真的落 verify。

    缺陷：`add_subparsers(dest="cmd")` 与子命令的 `--cmd` **同名 dest** ⟹ 命令串把子命令名
    覆写掉 ⟹ 分发落到 `else`（`count_raises`）分支，**rc=0 但什么都没写**。hook 走的是
    in-process `append_verify`，所以线上 T6 不受影响，但 CLI 面是死的。
    """
    st = _mkstate(tmp_path)
    r = subprocess.run([sys.executable, str(SCRIPTS / "gk_budget_ledger.py"), "verify-append",
                        "--state", st, "--session", "s", "--node", "N", "--cmd", "pytest -q"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    recs = B.read_events(st)
    assert [x["kind"] for x in recs] == [B.KIND_VERIFY], "verify-append CLI 未落盘：%r" % (recs,)
    assert recs[0]["cmd"] == "pytest -q", recs[0]
