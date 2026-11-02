#!/usr/bin/env python3
"""ember burn（让余烬系统**定期处理** state 体积）回归（L2 自动触发，`ECC-3802B43E4EF9`，2026-09-25）。

病根（实测，非推断）：`gk_finding.archive_closed`（配额驱动的代数归档）与 CLI 子命令
`finding archive-closed` **都已实现**、也已登记红先臂，但**生产零调用** —— 全仓唯一写余烬的
路径是 `cmd_discover` 内的**相位切换快照**（条件 `prev_entry.r_phase` 且相位真变化），而技能
自维护序列十几天不换相位 ⟹ state 单调增长到 margin 1.2%（258,971 / 262,144 B），只能靠人工
调配额（= 用户点名「受余烬管理却一直没被余烬系统处理过」）。

本刀 = 给该通道一个**确定性入口**（`ember burn`）+ 定时作业（cron `ember-burn`，每小时对齐
tick 相位 :49）。本文件在**沙箱真 CLI** 上锁三条判据（非模块自证）：
  ① 越线 ⟹ 真归档：`archived>0`、state 回落到「墙 − 预留」内、旁挂余烬逐条可回溯、代际
     `purged_fids` 覆盖本次 id（否则 `reconcile` 把归档误报「记录被删」）；
  ② 预算足 ⟹ **零写盘**：state 字节 + mtime 逐字不变、无旁挂档、journal 零新增（cron 每小时
     跑的前提 = 幂等且无副作用）；
  ③ 接线面：作业内核 `scripts/_cron_ember_burn.sh` 存在且契约齐（调 `ember burn`、末行
     `wakeAgent`、`bash -n` 干净）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = SKILL_DIR / "gatekeeper-cli.sh"

sys.path.insert(0, str(SCRIPT_DIR))
import gk_json_utils as gju  # noqa: E402 —— 计量单源（禁第二份口径）

WALL = gju.STATE_SIZE_WALL
RESERVE = gju.STATE_SIZE_RESERVE


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`bash` 此处是 WSL bash）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _mk_sandbox(tmp_path: Path, findings: list) -> Path:
    """沙箱技能根：`scripts` 软链 + CLI 实拷 + 最小 state（standing，含给定 ledger）。"""
    sb = (tmp_path / "sb").resolve()
    sb.mkdir()
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), _wsl(sb), _wsl(CLI_SRC), _wsl(sb))],
        capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    (sb / ".gatekeeper.state").write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1", "worktree": "",
        "gate_data": {"project_type": "standing", "ecc_findings": findings},
    }, ensure_ascii=False), encoding="utf-8", newline="\n")
    return sb


def _closed_findings(n: int, title_chars: int = 400) -> list:
    """造 `n` 条**已终态** findings（长中文 title/source ≈ 生产形态）。"""
    return [{"id": "ECC-%012d" % i, "title": "T%d-" % i + "甲" * title_chars,
             "source": "S%d " % i + "乙" * 200, "status": "closed",
             "created_at": "2026-09-%02dT00:00:00+00:00" % (i % 28 + 1),
             "closed_at": "2026-09-%02dT01:00:00+00:00" % (i % 28 + 1),
             "family": "", "cover_layers": [], "gap": False}
            for i in range(n)]


def _n_for_wall() -> int:
    """按**当前墙**反推条目数（wall-relative）。

    2026-10-16 owner 裁定「给 state 加个0」（`STATE_SIZE_WALL` ×10）后，原先**硬编码 200 条**
    （实测 412,311 B）不再越线（旧线 245,760 / 新线 2,605,056）⟹ 前提断言当场红。改为按
    `WALL − RESERVE` 除以**单条实测字节**反推（+50 条余量），使本臂随墙值自适应、零硬编码。
    """
    per = len(json.dumps(_closed_findings(1), ensure_ascii=False).encode("utf-8"))
    return (WALL - RESERVE) // max(per, 1) + 50


def _burn(sb: Path):
    """沙箱内跑 `ember burn`（= cron 作业 `ember-burn` 的真实动作面）。

    [ECC-43056A1C0F35] 归档路径经 `gk_satellite.append → claim_anchor` 会写 **write-claims 台账**。
    本调用是 **WSL bash 子进程** ⟹ conftest 的宿主 env（`GK_WRITE_CLAIMS_PATH`）**不透传**（Windows
    宿主 env 须经 `WSLENV` 白名单才进 WSL，见 `pre_tool_hook`）⟹ 必须在**命令内**把台账钉到沙箱，
    否则写脏生产台账（`_default_repo` 落到真实技能仓）。
    """
    claims = os.environ.get("GK_WRITE_CLAIMS_PATH") \
        or _wsl(sb / ".gatekeeper.write-claims.jsonl")
    return subprocess.run(
        ["bash", "-lc",
         'cd "%s" && GK_WRITE_CLAIMS_PATH="%s" bash gatekeeper-cli.sh ember burn'
         % (_wsl(sb), _wsl(claims))],
        capture_output=True, text=True, timeout=300)


def _last_json(out: str) -> dict:
    lines = [ln for ln in out.strip().splitlines() if ln.startswith("{")]
    assert lines, f"未回 JSON：{out[:400]}"
    return json.loads(lines[-1])


def _journal_events(sb: Path) -> list:
    jp = sb / ".gatekeeper.state.finding-journal.jsonl"
    if not jp.is_file():
        return []
    evs = []
    for ln in jp.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            try:
                evs.append(json.loads(ln))
            except ValueError:
                continue
    return evs


def test_arm31_ember_burn_archives_over_budget_state(tmp_path):
    """判据㉑（红先）：state 越线 ⟹ `ember burn` 须真烧掉最旧 closed 台账（= L2 通道被触发）。

    修前：`ember burn` 不存在（`cmd_ember` 把 `burn` 当 `gk_ember_replay` 子命令转发）⟹ 回
    `{"ok":false,"error":"ember burn failed"}` ⟹ 归档 0 条、体积不动（真红）。
    """
    sb = _mk_sandbox(tmp_path, _closed_findings(_n_for_wall()))
    before = gju.state_size_report(str(sb / ".gatekeeper.state"))
    assert before["canon_bytes"] > WALL - RESERVE, (
        "前提失败：沙箱 state 未越线（%d vs %d）" % (before["canon_bytes"], WALL - RESERVE))
    r = _burn(sb)
    out = (r.stdout + r.stderr)
    d = _last_json(out)
    assert d.get("ok") is True, f"ember burn 不可用（= 余烬仍无触发口）：{out[:600]}"
    st = d.get("status") or {}
    assert st.get("archived", 0) > 0, f"越线却零归档：{out[:600]}"
    after = gju.state_size_report(str(sb / ".gatekeeper.state"))
    trim_line = WALL * gju.WALL_TRIM_PCT // 100
    assert after["canon_bytes"] <= trim_line, (
        "归档后仍在 90%% 裁剪线外：%d > %d" % (after["canon_bytes"], trim_line))
    # 闭环判据：归档后普通写必须**不再**被 95% 墙闸拦（否则 burn 只清了一次，state 仍锁死）。
    probe = gju.update_state(str(sb / ".gatekeeper.state"),
                             lambda d: d.setdefault("gate_data", {}).__setitem__(
                                 "_post_burn_probe", 1))
    assert probe.get("ok"), "burn 后普通写仍被拒：%r" % (probe,)
    arch = sb / ".gatekeeper.state.finding-archive.jsonl"
    assert arch.is_file(), "旁挂余烬档未落 ⟹ 归档不可回溯"
    rows = [ln for ln in arch.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(rows) == st["archived"], (
        "旁挂档行数 %d ≠ 申报 archived %d" % (len(rows), st["archived"]))
    assert {json.loads(x)["id"] for x in rows} == set(st["archived_ids"]), (
        "旁挂档 id 与归档申报不一致")
    evs = _journal_events(sb)
    purged = set()
    for e in evs:
        if e.get("event") == "epoch":
            purged |= {str(x) for x in (e.get("purged_fids") or [])}
    assert purged, "未打代际声明 purged_fids ⟹ reconcile 会把归档误报「记录被删」"
    assert set(st["archived_ids"]) <= purged, "purged_fids 未覆盖本次归档 id"


def test_arm32_ember_burn_is_zero_write_under_budget(tmp_path):
    """判据㉒（负臂 · 零写盘）：预算足 ⟹ `ember burn` **一字不写**（cron 每小时跑的前提）。

    修前同样红（入口不存在 ⟹ 报 `ok:false`）—— 本臂守的是「修后**不得**为了"有动作"而写盘」。
    """
    sb = _mk_sandbox(tmp_path, _closed_findings(3, title_chars=60))
    sp = sb / ".gatekeeper.state"
    jp = sb / ".gatekeeper.state.finding-journal.jsonl"
    before_bytes, before_mtime = sp.read_bytes(), sp.stat().st_mtime_ns
    before_journal = jp.read_bytes() if jp.is_file() else b""
    r = _burn(sb)
    out = (r.stdout + r.stderr)
    d = _last_json(out)
    assert d.get("ok") is True, f"ember burn 不可用：{out[:400]}"
    st = d.get("status") or {}
    assert st.get("archived", 0) == 0, f"预算足时仍归档（越权裁台账）：{out[:400]}"
    assert sp.read_bytes() == before_bytes, "预算足时 state 被改写（应零写盘）"
    assert sp.stat().st_mtime_ns == before_mtime, "预算足时 state mtime 变化（应零写盘）"
    assert (jp.read_bytes() if jp.is_file() else b"") == before_journal, "预算足时写了 journal"
    assert not (sb / ".gatekeeper.state.finding-archive.jsonl").exists(), "预算足时落了旁挂档"


def test_arm33_cron_ember_burn_shim_contract():
    """判据㉓（接线面 · 形态臂）：作业内核 `scripts/_cron_ember_burn.sh` 存在且契约齐 ——
    ① 动作走 `ember burn`（单源，禁第二实现）；② 末行 `wakeAgent`（`cron_scheduler` 的
    no_agent 分支据此决定不唤醒 agent）；③ `bash -n` 可解析。"""
    sh = SCRIPT_DIR / "_cron_ember_burn.sh"
    assert sh.is_file(), "cron 作业内核缺失 ⟹ 余烬仍无自动触发（本刀病根未闭）"
    src = sh.read_text(encoding="utf-8")
    assert "ember burn" in src, "作业内核未调 ember burn（动作非单源 / 接错入口）"
    assert "wakeAgent" in src, "作业内核缺 wake gate 契约 ⟹ cron 会误判需唤醒 agent"
    # [ECC-83E090F17D35] 同族（Windows 宿主 `bash` = WSL bash 不认盘符路径）：须传 **WSL 形态**
    #   脚本路径，否则 `bash -n C:\\…sh` → rc=127「No such file or directory」（假红）。
    r = subprocess.run(["bash", "-n", _wsl(sh)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"作业内核语法错：{r.stderr[:200]}"
