#!/usr/bin/env python3
"""F1/F2 红先臂：派发隔离 + 节点 `edit_budget` 不被 coder 吞噬（2026-09-23 第三族并发实测暴露）。

背景（实测，非推测）：
  - `ECC-D398E70B7E72`（F1）：`apply_edit(worktree="", …)` 原走 `os.path.realpath("")`
    = **cwd 静默兜底** ⟹ 落刀打到调用方 cwd（实测 = **主树**），且任何闸都不拦
    （target 仍在 `wt_abs` 前缀内）。产空 worktree 的来源 = 派发链的 `--dry-run`
    （它在**建 worktree 之前** compile 窄任务 ⟹ `worktree:` 行恒空）。
  - `ECC-ABD2BF0E5655`（F2）：`apply_edit` 的 ③ 调 CLI `pre-tool-check` —— 那是**唯一扣减
    咽喉**（`_CMD_REG[pre-tool-check]` 的 side_effects 为空 ⟹ 不经 F3b 计费尾，由
    `pre_tool_check` 的 Gate 4 本体扣）⟹ coder 的每一刀都吃**主 agent 的节点 `edit_budget`**
    （实测：第三族并发后节点配额被吃光，主 agent 其后所有 Edit/Write 被 BLOCK）。而 coder 的量
    已由族 `edit_quota`（闸④）+ worktree diff 派生量（`agent_used`）独立封顶
    ⟹ 对节点配额再计一次是**重复计费**。

判据（红先）：
  ① `test_empty_worktree_is_refused`（F1）：空/不存在 worktree 必须 **fail-loud**
     （`blocked_by=no_worktree`），**不得**回落到 cwd。
  ② `test_apply_edit_does_not_consume_node_edit_budget`（F2）：一次落刀**不得**改变沙箱 state 的
     `edit_budget.remaining`。

沙箱：复刻 `test_gk_edit_budget_accounting.py`（`scripts` 软链 + CLI 实拷 + 最小 state），
**不触真实 `.gatekeeper.state`**；stage=`STAGE_1`（活跃态 ⟹ Gate 4 可达）。
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = SKILL_DIR / "gatekeeper-cli.sh"

sys.path.insert(0, str(SCRIPT_DIR))
import gk_agent_edit as gae  # noqa: E402


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _canon(state: dict) -> str:
    gd = json.dumps(state.get("gate_data", {}), sort_keys=True)
    return hashlib.sha256(gd.encode()).hexdigest()[:16]


def _sandbox(root: Path, stage: str = "STAGE_1") -> Path:
    """最小技能根 + 合法 checksum state（stage=STAGE_1 ⟹ Gate 4 可达）。"""
    sb = (root / "sb").resolve()
    sb.mkdir(parents=True)
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), w, _wsl(CLI_SRC), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    state = {
        "stage": stage, "r_phase": "R1", "branch": "master", "worktree": "",
        "gate_data": {
            "project_type": "standing",
            "edit_budget": {"max": 4, "used": 0, "remaining": 4, "overrides": []},
            "scheduler": {"mode": "constant", "max_lr": 4, "min_lr": 1,
                          "total_steps": 6, "current_step": 1, "current_lr": 4},
        },
        "monitor_scores": {}, "history": [],
    }
    state["_checksum"] = _canon(state)
    (sb / ".gatekeeper.state").write_text(
        json.dumps(state, ensure_ascii=False), encoding="utf-8")
    return sb


def _budget(sb: Path) -> dict:
    d = json.loads((sb / ".gatekeeper.state").read_text(encoding="utf-8"))
    return d.get("gate_data", {}).get("edit_budget", {})


def _probe_fam() -> dict:
    return {"family": "probe-family", "edit_quota": 3,
            "allowed_paths": ["scripts"], "forbidden_paths": []}


def test_empty_worktree_is_refused(tmp_path, monkeypatch):
    """① F1：空 worktree 必须 fail-loud（`no_worktree`），不得回落到 cwd。"""
    sb = _sandbox(tmp_path)
    monkeypatch.setattr(gae, "SKILL_DIR", _wsl(sb))
    monkeypatch.setenv("STATE_FILE", _wsl(sb / ".gatekeeper.state"))
    r = gae.apply_edit("", "scripts/__gk_probe_nonexistent__.py", "A", "B",
                       _probe_fam(), 0, 3)
    assert r.get("ok") is False, f"空 worktree 竟被接受：{r}"
    assert r.get("blocked_by") == "no_worktree", (
        f"空 worktree 未 fail-loud（禁 cwd 兜底）——实得 blocked_by={r.get('blocked_by')!r}：{r}")


def test_apply_edit_does_not_consume_node_edit_budget(tmp_path, monkeypatch):
    """② F2：一次真落刀不得改变节点 `edit_budget`（coder 已由族 edit_quota 封顶）。"""
    sb = _sandbox(tmp_path)
    wt = sb / "wt"
    (wt / "scripts").mkdir(parents=True)
    (wt / "scripts" / "a.py").write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(gae, "SKILL_DIR", _wsl(sb))
    monkeypatch.setenv("STATE_FILE", _wsl(sb / ".gatekeeper.state"))
    before = _budget(sb)
    r = gae.apply_edit(_wsl(wt), "scripts/a.py", "old", "new", _probe_fam(), 0, 3)
    after = _budget(sb)
    assert after.get("remaining") == before.get("remaining"), (
        "coder 落刀消耗了节点 edit_budget（重复计费）："
        f"remaining {before.get('remaining')} -> {after.get('remaining')}；落刀返回={r}")


# ─── ECC-6C0742C3BC90（闸① 在 Windows 宿主**恒拒**）类级加固 ───────────────────────────────
# 复现（2026-09-26，Windows py311 宿主实测）：`gk_agent_edit._cli_gate_ok` **自建**了一份
# `["bash", os.path.join(SKILL_DIR, "gatekeeper-cli.sh"), …]` ⟹ 脚本路径是 `C:\…` 形态，被
# `bash.exe`（WSL 启动器）吞掉反斜杠 ⟹ `/bin/bash: C:UsersHP…: No such file or directory`、
# **rc=127** ⟹ 闸① `guard-edit` 恒拒（coder 唯一落刀闸静默失效），而工具层
# `subagent_runner._bash_script_argv`（有转换）同路径却正常 ⟹「**第二份实现漏转换**」。
# 修法：形态归一**单源** `gk_host_paths`（工具层与落刀闸共用）+ 空输出时 detail fail-loud。


def _fake_run(monkeypatch, rc=0, out="", err=""):
    """替换 `subprocess.run` 以捕获 argv（不真起进程）。返回可读 `seen["argv"]`。"""
    seen = {}

    def _run(argv, **kw):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, rc, out, err)

    monkeypatch.setattr(gae.subprocess, "run", _run)
    return seen


def test_cli_gate_ok_converts_argv_on_windows_host(monkeypatch):
    """Windows 宿主（`os.name=='nt'`）下，闸① 的 argv 必须**全 POSIX 形态**。

    脚本路径与目标路径**都**要转：前者不转 = `bash` 找不到脚本（rc=127 ⟹ 闸①恒拒）；
    后者不转 = CLI 侧 `PROTECTED_REGION` 的 region 串匹配失配（**保护面假阴性**）。
    """
    monkeypatch.setattr(gae, "SKILL_DIR", r"C:\sk")
    monkeypatch.setattr(gae.os, "name", "nt")
    seen = _fake_run(monkeypatch)
    ok, det = gae._cli_gate_ok("guard-edit", r"C:\wt\gatekeeper-cli.sh")
    assert ok is True and det == ""
    argv = seen["argv"]
    assert argv[0] == "bash"
    assert argv[1] == "/mnt/c/sk/gatekeeper-cli.sh", (
        "CLI 脚本路径未转 WSL 形态 ⟹ Windows 宿主 rc=127、闸①恒拒: %r" % (argv[1],))
    assert argv[-1] == "/mnt/c/wt/gatekeeper-cli.sh", (
        "目标路径未转 WSL 形态 ⟹ 保护区 region 串匹配失配（保护面假阴性）: %r" % (argv[-1],))


def test_cli_gate_ok_empty_output_detail_is_fail_loud(monkeypatch):
    """非零退出且**无输出** ⟹ `detail` 不得为空串（空 detail = 真因不可见 = 摩擦源）。"""
    _fake_run(monkeypatch, rc=127, out="", err="")
    ok, det = gae._cli_gate_ok("guard-edit", "/w/f.sh")
    assert ok is False
    assert det.strip(), "非零退出 + 空输出 ⟹ detail 为空串（操作者无从定位真因）"
    assert "127" in det, "detail 未含退出码: %r" % (det,)


def test_state_patch_converts_argv_and_fails_loud(monkeypatch):
    """**同根第二站点**（由单源守护臂揪出）：`_state_patch` 亦须转形态 + 空输出 fail-loud。

    原实现 = 自建 argv（形态漏转）+ `json.loads(p.stdout or "{}")` ⟹ Windows 宿主下 rc≠0 且空
    stdout 被当空 dict ⟹ state-patch 通道**静默失败**（与闸① 同根）。
    """
    monkeypatch.setattr(gae, "SKILL_DIR", r"C:\sk")
    monkeypatch.setattr(gae.os, "name", "nt")
    seen = _fake_run(monkeypatch, rc=127, out="", err="")
    r = gae._state_patch('"a":1')
    assert seen["argv"][1] == "/mnt/c/sk/gatekeeper-cli.sh", (
        "state-patch 通道未转形态 ⟹ Windows 宿主 rc≠0、静默失败: %r" % (seen["argv"][1],))
    assert r.get("ok") is False and r.get("rc") == 127, (
        "空输出 + 非零 rc 未 fail-loud（回了空 dict = 静默失败）: %r" % (r,))


def test_host_paths_is_single_source_for_edit_gate():
    """形态归一须**单源**：落刀闸与工具层都不许自建 bash argv（须共用 `gk_host_paths`）。"""
    edit_src = (SKILL_DIR / "scripts" / "gk_agent_edit.py").read_text(encoding="utf-8")
    assert "gk_host_paths" in edit_src, (
        "闸① 未走形态归一单一事实源（第二份实现 = ECC-6C0742C3BC90 根因）")
    assert 'subprocess.run(["bash"' not in edit_src, "仍有自建的 bash argv 构造点"
    runner_src = (SKILL_DIR / "scripts" / "subagent_runner.py").read_text(encoding="utf-8")
    assert "gk_host_paths" in runner_src, "工具层未与落刀闸同源（须共用 gk_host_paths）"
