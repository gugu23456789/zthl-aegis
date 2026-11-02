#!/usr/bin/env python3
"""gk_cron_night_batch.py — 夜间批次（dream 窗口）cron 作业内核（T-SLEEP-03 实装）

用户裁定（2026-09-17「其他都同意」）:
  「dream 机制只在北京时间凌晨生效，白天不执行。这应该做成个 cron 插件？」
  → 本脚本 = cron 插件的**确定性内核**（`no_agent + script` 作业，**0 API**）。
内容（2026-09-17 用户点名五件 + 2026-09-23 追加第 ⑥ 件，全部**只读 / 零副作用**
 —— 用户规约「删除或覆盖现有文件」须显式许可）:
  ① 临时件盘点（**只盘点，不删**）      ② bomb 统计快照
  ③ 系统回收站只读盘点                  ④ self-check（规范入口）
  ⑤ 检查器「缺项 / 静默报错」探测（**复用** ④ 的 checks[]，不造第二份检查器）
  ⑥ 红先模版漂移（**复用** doc-align 的 `red_arm_templates` 单点检查器，禁第二份实现；
     2026-09-23 用户裁定「红先测试模版需要被 doc-align 检查是否存在漂移。顺便加个夜间任务」）

窗口: **UTC 18:00–22:00**（= 北京 02:00–06:00）。`cron_jobs._utcnow()` 是 **UTC**，
  故「北京时间凌晨」必须写 UTC 18–22（tick.log 实测 `21:49:04` ↔ 作业内 `(05:49:04)`）。
  窗口外 → 末尾输出 `{"wakeAgent": false}` **且零副作用**（含 **不** 落 no-ask 标志）。

调度相位（2026-09-18 实测 + 用户裁定 C1 **(ii)+(iii)**）:
  本系统只有一个时钟 = Windows 计划任务 `GatekeeperCronTick`（**每小时 :49 跑一次**
  `cron_scheduler.py --once`；WSL 侧**无**常驻调度器，`--interval 60` 只存在于 `cron start`
  路径）⟹ 作业时刻被**量化到该相位**，最大误差 = tick 间隔。
  实测：名义 `0 18 * * *` 实际 **`18:50:22`** 才落盘（`tick.log`「Job night-batch …: ok」；
  对比窗口外那次是 `wake gate=false, skipped agent`）⟹ 相位后移 **50m**，no-ask 覆盖
  3h10m（设计 4h），北京 **02:00–02:50 无保护**。
  处置：作业表达式**对齐相位**（`49 18 * * *`，改动经 `cron edit` 落台账）+ 本段文档化；
  **不改**计划任务重复间隔 —— 晚触发**不丢作业**：`cron_jobs.get_due_jobs` 的 catch-up
  语义（超宽限期仍入 due + fast-forward 下一轮）保证补跑，实测证据 = 2026-09-17 缺
  `10:49` 整个 tick，下一 tick `11:49` 把 external-ref 补跑。

Wake gate 契约（`cron_jobs.parse_wake_gate`）: stdout **最后一行**须是含 `wakeAgent` 的 JSON。
  ⚠ 已知上游缺口（**登记，本次不修** —— 属 cron_scheduler 派发语义）:
  `cron_scheduler._run_job` 的 `no_agent and script` 分支消费 wake gate 后**没有** LLM 派发路径
  （`wakeAgent:true` 只走到 `mark_job_run`）。故本作业里 `true` 的语义 =
  「夜间窗口已开 + 报告已落 cron output + no-ask 标志已 arm」，以**待办形态**留给在线 agent
  消费，**不**承诺自动拉起 LLM（对齐「0 API」设计）。

F-REV-96 配套: 窗口内 arm `SKILL_DIR/.gatekeeper.no-ask`（deadline = 当日 UTC 22:00）
  ⟹ PreToolUse 的【提问挂起闸】(Gate 9) H1 档生效 —— 夜间 agent 无法用 AskUserQuestion
  挂起到用户醒来（§8.17 实测卡数小时的失败面）。
"""
import datetime
import json
import os
import re
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPT_DIR)
CLI = os.path.join(SKILL_DIR, "gatekeeper-cli.sh")
NO_ASK_FLAG = os.path.join(SKILL_DIR, ".gatekeeper.no-ask")

NIGHT_START_UTC_H = 18          # 北京 02:00
NIGHT_END_UTC_H = 22            # 北京 06:00
TMP_OLD_S = 6 * 3600            # 「陈旧」临时件阈值（盘点用，不删）
_RECYCLE_MAX_ENTRIES = 40000    # 回收站递归上限（防慢盘把 tick 拖死）
# 自有探针/临时件前缀（只盘这些 —— 绝不触碰用户其它临时文件）
_PROBE_RE = re.compile(r"^(gk[_-]|bomb_|tmp_|\.tmp_|nightbatch|gk_inv|gk_head_cli)", re.IGNORECASE)
SELF_CHECK_MIN_ITEMS = 30       # 检查器条数下限（低于即判「缺项」；2026-09-17 实测 35）
# RED-MIGRATE 单点的 finding id → counts 键（id 是契约，title 只取首位整数）
_BOMB_ID_MAP = {
    "RED-MIGRATE-INLINE": "inline_python",
    "RED-MIGRATE-SWALLOW": "stderr_swallow",
    "RED-MIGRATE-DANGER": "dangerous_command",
    "RED-MIGRATE-FD": "fd_redirect",
}


def _log(msg):
    sys.stderr.write(f"[night-batch] {msg}\n")


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _night_window(now=None):
    """返回 (active, deadline_epoch, note)。UTC 18–22 内 → active。"""
    now = now or _utcnow()
    if os.environ.get("GK_NIGHT_FORCE") == "1":     # 手动/测试：强制视为窗口内
        end = now.replace(hour=NIGHT_END_UTC_H, minute=0, second=0, microsecond=0)
        if end <= now:
            end += datetime.timedelta(days=1)
        return True, end.timestamp(), "forced (GK_NIGHT_FORCE=1)"
    active = NIGHT_START_UTC_H <= now.hour < NIGHT_END_UTC_H
    end = now.replace(hour=NIGHT_END_UTC_H, minute=0, second=0, microsecond=0)
    return active, end.timestamp(), f"UTC {NIGHT_START_UTC_H}-{NIGHT_END_UTC_H}"


def _arm_no_ask(deadline):
    """arm 无人时段标志（F-REV-96 H1）。内容 `<deadline_epoch>|<note>`。"""
    try:
        with open(NO_ASK_FLAG, "w", encoding="utf-8") as f:
            f.write(f"{int(deadline)}|night-batch (北京 02:00-06:00)\n")
        return True
    except OSError as e:
        _log(f"arm no-ask flag failed: {e}")
        return False


def _temp_roots():
    """临时件盘点根（本机 WSL + Windows 用户 Temp；去重、只取存在者）。"""
    import tempfile
    cands = [tempfile.gettempdir(), os.environ.get("TEMP"), os.environ.get("TMP"),
             "/tmp", "/var/tmp"]
    try:
        for u in os.listdir("/mnt/c/Users"):
            cands.append(os.path.join("/mnt/c/Users", u, "AppData", "Local", "Temp"))
    except OSError:
        pass
    out = []
    for c in cands:
        if not c or not os.path.isdir(c):
            continue
        rp = os.path.realpath(c)
        if rp not in out:
            out.append(rp)
    return out


def _inv_tmp():
    """① 临时件盘点（**只读**）: 自有探针前缀的候选件数 / 字节 / 陈旧数 / Top N。"""
    now = time.time()
    res = {"roots": _temp_roots(), "candidates": 0, "bytes": 0,
           "stale_6h": 0, "top": [], "unreadable": 0}
    hits = []
    for root in res["roots"]:
        try:
            with os.scandir(root) as it:
                for e in it:
                    if not _PROBE_RE.match(e.name):
                        continue
                    try:
                        st = e.stat()
                    except OSError:
                        res["unreadable"] += 1
                        continue
                    res["candidates"] += 1
                    res["bytes"] += st.st_size
                    if now - st.st_mtime > TMP_OLD_S:
                        res["stale_6h"] += 1
                    hits.append((st.st_size, e.path))
        except OSError:
            res["unreadable"] += 1
    res["top"] = [p for _, p in sorted(hits, reverse=True)[:10]]
    return res


def _inv_recycle(roots=None):
    """③ 系统回收站**只读**盘点（文件数 / 字节 / 是否到扫描上限）。"""
    res = {"roots": [], "files": 0, "bytes": 0, "truncated": False}
    if roots is None:
        roots = []
        for d in range(ord("C"), ord("Z") + 1):
            wsl = f"/mnt/{chr(d).lower()}/$Recycle.Bin"
            win = f"{chr(d)}:\\$Recycle.Bin"
            for p in (wsl, win):
                if os.path.isdir(p):
                    roots.append(p)
    res["roots"] = list(roots)
    for root in roots:
        for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda e: None):
            for fn in filenames:
                if res["files"] >= _RECYCLE_MAX_ENTRIES:
                    res["truncated"] = True
                    return res
                try:
                    res["bytes"] += os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    pass
                res["files"] += 1
    return res


def _bomb_snapshot():
    """② bomb 统计快照 —— **复用** RED 引擎单点（`_red_attacks.py migrate`）。

    ⚠ 该单点输出是 **indent=2 的多行 JSON**（实测，不是单行）⟹ 须整段解析。
    counts 不直接暴露，按 `details[].id` 契约映射 + `title` 首位整数回读。
    """
    res = {"ok": False, "counts": {}, "total": 0, "details": [], "error": ""}
    try:
        p = subprocess.run([sys.executable, os.path.join(SCRIPT_DIR, "_red_attacks.py"), "migrate"],
                           capture_output=True, text=True, timeout=180, cwd=SCRIPT_DIR,
                           env=_sanitized_env())
        raw = (p.stdout or "").strip()
        start = raw.find("{")
        payload = None
        if start >= 0:
            try:
                payload = json.loads(raw[start:])
            except ValueError:
                payload = None
        if payload is None:
            res["error"] = f"未产出 JSON（rc={p.returncode}）: {(p.stderr or '')[:200]}"
        else:
            res["ok"] = bool(payload.get("ok"))
            res["details"] = payload.get("details") or []
            for f in res["details"]:
                key = _BOMB_ID_MAP.get(str(f.get("id", "")))
                m = re.match(r"^(\d+)", str(f.get("title", "")))
                if key and m:
                    res["counts"][key] = int(m.group(1))
            res["total"] = sum(res["counts"].values())
    except Exception as e:
        res["error"] = str(e)
    return res


def _sanitized_env():
    """去掉敏感变量（对齐 cron_scheduler._sanitize_subprocess_env）。"""
    env = os.environ.copy()
    for k in list(env):
        ku = k.upper()
        if any(s in ku for s in ("API_KEY", "API_SECRET", "TOKEN", "PASSWORD",
                                 "SECRET", "PRIVATE_KEY", "SIGNING_KEY")):
            env.pop(k, None)
    return env


def _self_check():
    """④ self-check（规范入口）+ ⑤ 检查器「缺项 / 静默报错」探测。

    ⑤ **复用** ④ 的 `checks[]`（项目原则: 「不再维护第二份检查器」，见 gatekeeper-cli.sh:2796）
    + 对 `scripts/*.py` 做 `py_compile` 语法/编译面探测（零误报的最低成本「能否运行」判据）。
    """
    out = {"ok": False, "issues": -1, "items": 0, "fail": [], "skip": [],
           "silent": [], "missing": [], "compile_failures": [], "error": ""}
    try:
        p = subprocess.run(["bash", CLI, "self-check"], capture_output=True, text=True,
                           timeout=300, cwd=SKILL_DIR, env=_sanitized_env())
        payload = None
        for line in (p.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("{") and '"checks"' in line:
                try:
                    payload = json.loads(line)
                except ValueError:
                    payload = None
        if payload is None:
            out["error"] = f"self-check 未产出 JSON（rc={p.returncode}）: {(p.stderr or '')[:200]}"
        else:
            checks = payload.get("checks") or []
            out["ok"] = bool(payload.get("ok"))
            out["issues"] = int(payload.get("issues", -1))
            out["items"] = len(checks)
            for c in checks:
                st = str(c.get("status", "")).upper()
                name = str(c.get("check", "?"))
                if st == "FAIL":
                    out["fail"].append(name)
                    # 静默报错 = FAIL 但 detail 为空（无归因 ⟹ 无法排查）
                    if not str(c.get("detail", "")).strip():
                        out["silent"].append(name)
                elif st == "SKIP":
                    out["skip"].append(name)
            if out["items"] < SELF_CHECK_MIN_ITEMS:
                out["missing"] = [f"self-check 仅 {out['items']} 项 < 下限 {SELF_CHECK_MIN_ITEMS}"]
    except Exception as e:
        out["error"] = str(e)
    out["compile_failures"] = _compile_probe()
    return out


def _compile_probe():
    """⑤a 语法/编译面探测（缺项 + 不可运行）—— `scripts/*.py` 全量语法编译。
    零误报的最低成本「能否运行」判据（纯内存 `compile()`，不落 .pyc、不执行、无副作用）。"""
    failures = []
    try:
        for fn in sorted(os.listdir(SCRIPT_DIR)):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(SCRIPT_DIR, fn)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    compile(f.read(), path, "exec")
            except Exception as e:
                failures.append(f"{fn}: {str(e)[:120]}")
    except Exception as e:
        failures.append(f"<scan>: {e}")
    return failures


def _red_arm_drift():
    """⑥ 红先模版漂移 —— **复用** doc-align 的 `red_arm_templates` 单点检查器。

    单一事实源 = `references/red-arm-templates.json`；实现 = `gk_doc_align.check_red_arm_templates`
    （`doc-align` 23 项之一）。**本文件不重写一份检查器**（项目原则：不维护第二份检查器）。
    **只读 / 0 API**。例外态（导入失败/检查器抛错）⟹ `ok=False` + `error` 归因，**不抛异常**
    拖垮整轮夜间批次（与 `_bomb_snapshot` / `_self_check` 同一容错口径）。
    """
    res = {"ok": False, "status": "", "detail": "", "error": ""}
    try:
        if SCRIPT_DIR not in sys.path:
            sys.path.insert(0, SCRIPT_DIR)
        import gk_doc_align as _da
        r = _da.check_red_arm_templates(SKILL_DIR) or {}
        res["status"] = str(r.get("status") or "")
        res["detail"] = str(r.get("detail") or "")
        res["ok"] = res["status"] == "PASS"
    except Exception as e:  # noqa: BLE001
        res["error"] = f"{type(e).__name__}: {e}"
    return res


def _fmt(report):
    """人读报告（stdout；末行另出 wake gate JSON）。"""
    L = []
    L.append("# 夜间批次报告（dream 窗口）")
    L.append(f"- 生成: {_utcnow().isoformat()[:19]}Z  (北京 {(_utcnow() + datetime.timedelta(hours=8)).strftime('%H:%M')})")
    L.append(f"- 窗口: UTC {NIGHT_START_UTC_H}-{NIGHT_END_UTC_H} / {report['window_note']}")
    L.append(f"- no-ask 标志: {'已 arm' if report['no_ask_armed'] else '未 arm'}")
    t = report["tmp"]
    L.append("")
    L.append("## ① 临时件盘点（只读，**不删**）")
    L.append(f"- 根: {len(t['roots'])} 个")
    L.append(f"- 自有探针候选: **{t['candidates']}** 件 / {t['bytes'] / 1024:.0f} KB"
             f"（其中 mtime > 6h 的陈旧件 **{t['stale_6h']}**）")
    for p in t["top"][:5]:
        L.append(f"    - {p}")
    b = report["bomb"]
    L.append("")
    L.append("## ② bomb 统计快照（RED 引擎单点）")
    L.append(f"- ok={b['ok']} total=**{b['total']}** counts={b['counts'] or '(未解析出来)'}"
             + (f" err={b['error']}" if b["error"] else ""))
    r = report["recycle"]
    L.append("")
    L.append("## ③ 系统回收站只读盘点")
    L.append(f"- 根: {r['roots'] or '(未发现)'}")
    L.append(f"- **{r['files']}** 文件 / **{r['bytes'] / 1048576:.1f} MB**"
             + ("（**达扫描上限，已截断**）" if r["truncated"] else ""))
    s = report["self_check"]
    L.append("")
    L.append("## ④ self-check（规范入口）")
    L.append(f"- ok={s['ok']} issues=**{s['issues']}** items={s['items']}")
    L.append(f"- FAIL: {s['fail'] or '无'}")
    L.append(f"- SKIP: {s['skip'] or '无'}")
    if s["error"]:
        L.append(f"- error: {s['error']}")
    L.append("")
    L.append("## ⑤ 检查器「缺项 / 静默报错」探测")
    L.append(f"- 缺项(条数<{SELF_CHECK_MIN_ITEMS}): {s['missing'] or '无'}")
    L.append(f"- 静默报错(FAIL 且无 detail): {s['silent'] or '无'}")
    L.append(f"- 语法/编译失败: {s['compile_failures'] or '无'}")
    ra = report["red_arm"]
    L.append("")
    L.append("## ⑥ 红先模版漂移（复用 doc-align 的 red_arm_templates 单点）")
    L.append(f"- status=**{ra['status'] or '(无)'}** ok={ra['ok']}")
    L.append(f"- detail: {ra['detail'] or '(无)'}")
    if ra["error"]:
        L.append(f"- error: {ra['error']}")
    L.append("")
    L.append("## 待办（留给在线 agent 消费；本作业 0 API、不改任何文件）")
    todo = []
    if t["stale_6h"]:
        todo.append(f"梳理/清理陈旧临时件 {t['stale_6h']} 件（{t['bytes'] / 1024:.0f} KB）— 删除须用户显式许可")
    if not b["ok"]:
        todo.append(f"RED-MIGRATE 单点未产出可解析 JSON: {b['error']}")
    elif b["counts"].get("dangerous_command"):
        todo.append(f"复核 dangerous_command {b['counts']['dangerous_command']} 条"
                    "（不可逆覆盖面，逐条定性为非真风险或真风险）")
    if s["items"] < SELF_CHECK_MIN_ITEMS:
        todo.append(f"自查 self-check 为何只剩 {s['items']} 项（<{SELF_CHECK_MIN_ITEMS} 判缺项）")
    if s["silent"]:
        todo.append(f"补 self-check 静默项归因: {s['silent']}")
    if s["compile_failures"]:
        todo.append(f"修语法/编译失败: {s['compile_failures']}")
    for f in s["fail"]:
        todo.append(f"self-check FAIL: {f}")
    if not ra["ok"]:
        todo.append(f"红先模版漂移（{ra['status'] or 'error'}）: "
                    f"{ra['detail'] or ra['error']}"
                    " — 跑 doc-align / 对齐 references/red-arm-templates.json")
    L.append("\n".join(f"- {x}" for x in todo) if todo else "- （无）")
    return "\n".join(L)


def run(now=None):
    """主流程。返回 (exit_code, report_dict, human_report)。"""
    active, deadline, note = _night_window(now)
    if not active:
        # 窗口外: 零副作用 + **不静默**（cron output 留一行，可区分「未触发」vs「触发但跳过」）
        return 0, {"wakeAgent": False, "reason": f"outside night window ({note})",
                   "utc_hour": _utcnow().hour}, \
            (f"# 夜间批次: 窗口外（{note}，当前 UTC {_utcnow().strftime('%H:%M')}）→ 跳过，零副作用")
    report = {"window_note": note, "no_ask_armed": _arm_no_ask(deadline)}
    report["tmp"] = _inv_tmp()
    report["bomb"] = _bomb_snapshot()
    report["recycle"] = _inv_recycle()
    report["self_check"] = _self_check()
    report["red_arm"] = _red_arm_drift()
    return 0, {"wakeAgent": True, "window": note, "no_ask_armed": report["no_ask_armed"],
               "self_check_issues": report["self_check"]["issues"],
               "self_check_items": report["self_check"]["items"],
               "red_arm_drift": report["red_arm"]["status"] or "error",
               "tmp_stale": report["tmp"]["stale_6h"],
               "recycle_mb": round(report["recycle"]["bytes"] / 1048576.0, 1)}, _fmt(report)


def main(argv=None):
    code, gate, human = run()
    if human:
        print(human)
    print(json.dumps(gate, ensure_ascii=False))   # wake gate: 必须末行
    return code


if __name__ == "__main__":
    sys.exit(main())
