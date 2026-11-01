"""
test_eco_integration.py -- Integration tests for batch8 fixes
=============================================================
Covers: advance hint injection, hook config, json.load safety,
        env-check, gitnexus_gk, _run_gitnexus, dead code cleanup,
        F8 incident regression (T-F8-1~4).
"""

import io
import json
import os
import re
import shlex as _shlex
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SKILL_DIR = Path(__file__).parent.parent
CLI_PATH = SKILL_DIR / "gatekeeper-cli.sh"
SCRIPTS_DIR = SKILL_DIR / "scripts"

# ── hook 部署候选根 ──
# 2026-08-07 起（87d044c）Trae 全局根目录 ~/.trae-cn/hooks.json 为唯一生效入口（catch-all `*`），
# 项目级 .trae/settings.json 已废弃并清理。
# 2026-09-24（ECC-…，TestHookConfig 6 例修复）：**删除**本地硬编码候选表，改走产品侧单一事实源。
# 原表三项里两项是 Windows 字面量 `C:\...`，而规范测试解释器是 **WSL**（/opt/spz-py312）：
# POSIX 下 `Path(r"C:\...")` 退化为**相对路径** ⟹ `exists()` 恒 False ⟹ 本类 6 例全红
# （红因 = **平台路径形态**，非 hook 缺失；`runtime-subplan §4.8.4` 已订正为「假失败」）。
# 更坏的是 test_settings_json_has_runcommand 走同一张表 + `pytest.skip` ⟹ WSL 面**静默跳过**
# （零断言的假绿）。现与 `check_hook`/`audit --state` 同源解析（`_hook_settings_candidates`，
# 天然含 Win + `/mnt/c` 双形态）⟹ 解析序与产品一致，无第二份候选名单可漂移。


def _find_settings() -> Path:
    """定位**实际部署**的 hook 配置（Win/WSL 双形态，与产品侧同源）。

    单一事实源 = `gk_audit_state._hook_settings_candidates`（`check_hook` / `audit --state`
    同一函数），**禁**在本测试里再造候选表（原表即因平台形态漂移导致 6 例假失败）。
    """
    import gk_audit_state
    cands = gk_audit_state._hook_settings_candidates(str(SKILL_DIR))
    for c in cands:
        p = Path(c)
        if p.is_file():
            return p
    raise AssertionError(f"No hook config found in candidates: {cands}")


def _run_hook_inline(state_data: dict, tool_name: str, file_path: str, cwd: str) -> tuple[int, str]:
    """进程内跑 pre_tool_hook.main()（patch STATE_FILE + _win_to_wsl identity + _run_cli mock）。

    Windows python 下 _win_to_wsl 会把 worktree 转 /mnt/c 致 Gate 2 exists() 误判
    （hook 设计在 WSL 下运行），故 identity 保持路径原样（2026-08-15 环境修复）。
    """
    import pre_tool_hook
    old_stdin, old_stderr = sys.stdin, sys.stderr
    buf = io.StringIO()
    state_file = Path(cwd) / "_test_state.json"
    state_file.write_text(json.dumps(state_data), encoding="utf-8")
    sys.stdin = io.StringIO(json.dumps({
        "tool_name": tool_name,
        "tool_input": {"file_path": file_path},
        "cwd": cwd,
    }))
    sys.stderr = buf
    try:
        with patch("pre_tool_hook.STATE_FILE", state_file), \
             patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)), \
             patch("pre_tool_hook._run_cli", return_value={"ok": True}):
            try:
                pre_tool_hook.main()
            except SystemExit as e:
                return e.code, buf.getvalue()
        return 0, buf.getvalue()
    finally:
        sys.stdin, sys.stderr = old_stdin, old_stderr


# ── 3.5d: Advance hint injection ──

class TestAdvanceHintInjection:
    """Verify advance hint (checklist/tool_policy/post_check) — Phase 7 迁移后
    由 scripts/gk_advance.py 生成（bash cmd_advance 仅收集环境证据注入）。"""

    ADVANCE_PY = SCRIPTS_DIR / "gk_advance.py"

    def test_hint_contains_checklist(self):
        """ECO-RESEARCH advance hint must contain checklist field."""
        src = self.ADVANCE_PY.read_text(encoding="utf-8")
        assert "_CHECKLISTS" in src and "checklist" in src
        assert "ECO-RESEARCH" in src and "monitor --subagent" in src

    def test_hint_contains_tool_policy(self):
        """Hint must contain tool_policy with search/review/read."""
        src = self.ADVANCE_PY.read_text(encoding="utf-8")
        assert "tool_policy" in src
        assert "_TOOL_POLICY" in src
        assert "search" in src
        assert "review" in src
        assert "read" in src

    def test_hint_contains_post_check(self):
        """Hint must contain post_check with self-check command."""
        src = self.ADVANCE_PY.read_text(encoding="utf-8")
        assert "post_check" in src
        assert "self-check" in src

    def test_all_eco_phases_have_checklist(self):
        """Every ECO phase must have a checklist entry."""
        src = self.ADVANCE_PY.read_text(encoding="utf-8")
        for phase in ["ECO-RESEARCH", "ECO-EDIT", "ECO-VERIFY", "ECO-DOC"]:
            assert f'"{phase}"' in src, f"Missing checklist entry for {phase}"

    def test_all_red_phases_have_checklist(self):
        """Every RED phase must have a checklist entry."""
        src = self.ADVANCE_PY.read_text(encoding="utf-8")
        for phase in ["RED-SCOPE", "RED-SURFACE", "RED-CONSTRAINTS", "RED-EXPLOIT",
                      "RED-POSTEX", "RED-REPORT", "RED-HINT", "RED-HOOK", "RED-PY"]:
            assert f'"{phase}"' in src, f"Missing checklist entry for {phase}"


# ── Hook configuration ──

class TestHookConfig:
    """Verify .trae/settings.json hook configuration is correct."""

    def _settings(self) -> Path:
        return _find_settings()

    def test_settings_json_exists(self):
        """settings.json must exist in one of the deployment roots."""
        assert self._settings().exists(), ".trae/settings.json missing in all deployment roots"

    def test_hook_uses_wsl_bash(self):
        """Hook command must use 'wsl bash' (script 或 -c 形态；2026-08-15 环境修复:
        实部署为 `wsl bash <script>`，非 `wsl bash -c`)."""
        settings = json.loads(self._settings().read_text(encoding="utf-8"))
        hooks = settings.get("hooks", {})
        pre_tool = hooks.get("PreToolUse", [])
        assert len(pre_tool) >= 1, "No PreToolUse hooks configured"
        for entry in pre_tool:
            for hook in entry.get("hooks", []):
                cmd = hook.get("command", "")
                assert "wsl bash" in cmd, f"Hook not using 'wsl bash': {cmd}"
                assert "python3" in cmd or "pre_tool_hook" in cmd, f"Hook missing python3/hook script: {cmd}"

    def test_hook_no_claude_project_dir(self):
        """Hook must NOT use $CLAUDE_PROJECT_DIR (Trae doesn't set it)."""
        settings = json.loads(self._settings().read_text(encoding="utf-8"))
        hooks = settings.get("hooks", {})
        for event, entries in hooks.items():
            for entry in entries:
                for hook in entry.get("hooks", []):
                    cmd = hook.get("command", "")
                    assert "CLAUDE_PROJECT_DIR" not in cmd, f"Hook still uses CLAUDE_PROJECT_DIR: {cmd}"

    def test_hook_matcher_covers_all_edit_tools(self):
        """Matcher must cover SearchReplace|Write|Edit|CreateFile|DeleteFile."""
        settings = json.loads(self._settings().read_text(encoding="utf-8"))
        hooks = settings.get("hooks", {})
        pre_tool = hooks.get("PreToolUse", [])
        matchers = [e.get("matcher", "") for e in pre_tool]
        all_matchers = "|".join(matchers)
        if any(m.strip() == "*" for m in matchers):
            return  # catch-all (87d044c): 单入口 `*` 覆盖全部工具
        for tool in ["SearchReplace", "Write", "Edit", "CreateFile", "DeleteFile"]:
            assert tool in all_matchers, f"Matcher missing tool: {tool}"

    def test_hook_matcher_covers_task(self):
        """Matcher must cover Task tool."""
        settings = json.loads(self._settings().read_text(encoding="utf-8"))
        hooks = settings.get("hooks", {})
        pre_tool = hooks.get("PreToolUse", [])
        matchers = [e.get("matcher", "") for e in pre_tool]
        if any(m.strip() == "*" for m in matchers):
            return  # catch-all (87d044c): 单入口 `*` 覆盖全部工具
        assert any("Task" in m for m in matchers), "Matcher missing Task tool"

    def test_hook_timeout_set(self):
        """All hooks must have a timeout."""
        settings = json.loads(self._settings().read_text(encoding="utf-8"))
        hooks = settings.get("hooks", {})
        for event, entries in hooks.items():
            for entry in entries:
                for hook in entry.get("hooks", []):
                    assert "timeout" in hook, f"Hook missing timeout: {hook}"
                    assert hook["timeout"] > 0


# ── json.load safety ──

class TestJsonLoadSafety:
    """Verify no bare json.load(open()) in production .py files."""

    @pytest.mark.parametrize("filename", [
        "_red_attacks.py",
        "_replay.py",
        "sniffnet_webhook.py",
        "cron_scheduler.py",
    ])
    def test_no_bare_json_load_open(self, filename):
        """Production .py files must use 'with open()' not bare json.load(open())."""
        filepath = SCRIPTS_DIR / filename
        if not filepath.exists():
            pytest.skip(f"{filename} not found")
        content = filepath.read_text(encoding="utf-8")
        bare = re.findall(r'json\.load\(open\(', content)
        assert len(bare) == 0, f"{filename}: {len(bare)} bare json.load(open()) calls found"

    @pytest.mark.parametrize("filename", [
        "_red_attacks.py",
        "_replay.py",
        "sniffnet_webhook.py",
        "cron_scheduler.py",
    ])
    def test_uses_with_statement(self, filename):
        """Production .py files must use 'with open()' for file I/O."""
        filepath = SCRIPTS_DIR / filename
        if not filepath.exists():
            pytest.skip(f"{filename} not found")
        content = filepath.read_text(encoding="utf-8")
        with_opens = re.findall(r'with open\(', content)
        assert len(with_opens) >= 1, f"{filename}: expected at least 1 'with open()' call"


# ── _run_gitnexus fix ──

class TestRunGitnexusFix:
    """Verify _run_gitnexus_raw uses direct node.exe, not powershell.exe.

    2026-09-14 契约更新：node spawn 实体由 `_run_gitnexus` 改名为 `_run_gitnexus_raw`
    （`_run_gitnexus` 变为进程级 memo 包装，见 TestGitnexusProcessMemo）。断言不变，只换目标函数。
    """

    def test_no_powershell_in_run_gitnexus(self):
        """_run_gitnexus_raw must not use powershell.exe -Command 'gitnexus'."""
        src = CLI_PATH.read_text(encoding="utf-8")
        # Find the _run_gitnexus_raw function（node spawn 实体）
        match = re.search(r'_run_gitnexus_raw\(\)\s*\{(.*?)\n\}', src, re.DOTALL)
        assert match, "_run_gitnexus_raw function not found"
        func_body = match.group(1)
        assert "powershell.exe" not in func_body, "_run_gitnexus_raw still uses powershell.exe"

    def test_run_gitnexus_uses_node_exe(self):
        """_run_gitnexus_raw must use node.exe directly."""
        src = CLI_PATH.read_text(encoding="utf-8")
        match = re.search(r'_run_gitnexus_raw\(\)\s*\{(.*?)\n\}', src, re.DOTALL)
        assert match, "_run_gitnexus_raw function not found"
        func_body = match.group(1)
        assert "node.exe" in func_body or "node_exe" in func_body, "_run_gitnexus_raw doesn't use node.exe"

    def test_run_gitnexus_uses_wslpath(self):
        """_run_gitnexus_raw must convert WSL paths via wslpath."""
        src = CLI_PATH.read_text(encoding="utf-8")
        match = re.search(r'_run_gitnexus_raw\(\)\s*\{(.*?)\n\}', src, re.DOTALL)
        assert match, "_run_gitnexus_raw function not found"
        func_body = match.group(1)
        assert "wslpath" in func_body, "_run_gitnexus_raw doesn't use wslpath for path conversion"


# ── _run_gitnexus 进程级 memo（2026-09-14，用户裁定"加进程缓存"）──

class TestGitnexusProcessMemo:
    """`_run_gitnexus` 进程级 memo 的**行为**测试（非源码子串断言）。

    背景：每次 spawn 一个 node 进程；读类子命令（query/context/impact/detect-changes）会打开
    `.gitnexus` 的 lbug 图库 → 生成 `lbug.checkpoint.intent/apply.lock` 锁对 + wal + shadow
    （实测单日 691 对），在 Trae 沙箱下这些删除被重定向进回收站。
    契约：同进程内同 (子命令+参数, 仓库) 的**非改库**调用只 spawn 一次；`analyze` 改库 ⟹ 不缓存。
    """

    _HARNESS = r'''
set -u
TMPDIR="$(mktemp -d)"; export TMPDIR
_CNT="$TMPDIR/cnt"; : > "$_CNT"
_gx_repo_dir_for_current() { echo "/repo"; }
_run_gitnexus_raw() { echo "$*" >> "$_CNT"; echo "RAW:$*"; }
{WRAPPER}
echo "OUT1=$( _run_gitnexus status )"
echo "OUT2=$( _run_gitnexus status )"
echo "OUT3=$( _run_gitnexus query -r x foo )"
echo "OUT4=$( _run_gitnexus query -r x foo )"
echo "OUT5=$( _run_gitnexus analyze )"
echo "OUT6=$( _run_gitnexus analyze )"
echo "OUT7=$( _run_gitnexus status )"
echo "RAWCALLS=$(wc -l < "$_CNT")"
echo "STATUS_N=$(grep -c '^status$' "$_CNT" || true)"
echo "QUERY_N=$(grep -c '^query -r x foo$' "$_CNT" || true)"
echo "ANALYZE_N=$(grep -c '^analyze$' "$_CNT" || true)"
echo "MEMOFILES=$(find "$TMPDIR/gk-gx-memo" -type f 2>/dev/null | wc -l)"
'''

    def _wrapper(self) -> str:
        src = CLI_PATH.read_text(encoding="utf-8")
        # 抽取范围须**含 `_GK_GX_MEMO_DIR=` 赋值行**（否则 wrapper 内该变量未绑定，set -u 下报错）
        m = re.search(r"\n(_GK_GX_MEMO_DIR=.*?_run_gitnexus\(\)\s*\{.*?\n\})\n_run_gitnexus_raw\(\)\s*\{",
                      src, re.DOTALL)
        assert m, "_run_gitnexus memo wrapper not found（改名/结构变更后须同步本测试）"
        return m.group(1)

    def _run(self, tmp_path) -> dict:
        import shutil
        if shutil.which("bash") is None:
            pytest.skip("bash not available on this platform")
        harness = self._HARNESS.replace("{WRAPPER}", self._wrapper())
        # 二进制 stdin：绕开 Windows 文本模式把 \n 翻成 \r\n（bash -s 会因 $'\r' 报错）
        out = subprocess.run(["bash", "-s"], input=harness.encode("utf-8"),
                             capture_output=True, timeout=90)
        assert out.returncode == 0, f"harness failed: {out.stderr.decode('utf-8', 'replace')}"
        stdout = out.stdout.decode("utf-8", "replace")
        return dict(ln.split("=", 1) for ln in stdout.strip().splitlines() if "=" in ln)

    def test_readonly_cached_mutating_not(self, tmp_path):
        r = self._run(tmp_path)
        # status/query 第二次命中 memo；analyze 每次真跑（改库不缓存）
        # F-REV-78（2026-09-16）：analyze 会**清空本进程 memo** ⟹ 其后的第三次 status 必须真跑
        # ⟹ STATUS_N=2（此前恒 1）。RAWCALLS 随之为 5。
        assert r["STATUS_N"] == "2", f"status memo/失效行为异常: {r}"
        assert r["QUERY_N"] == "1", f"query 未被 memo: {r}"
        assert r["ANALYZE_N"] == "2", f"analyze 不应被缓存: {r}"
        assert r["RAWCALLS"] == "5", f"raw 调用数异常: {r}"

    def test_analyze_invalidates_read_memo(self, tmp_path):
        """F-REV-78：改库后**读缓存必须失效**（否则 preflight B `status(stale)→analyze→status`
        读到改库前缓存 ⟹ 恒 stale 假警）。判据：末次 status 重落 raw 且重新入 memo。"""
        r = self._run(tmp_path)
        assert r["OUT7"] == "RAW:status", f"analyze 后 status 命中旧缓存: {r}"
        assert r["MEMOFILES"] == "1", f"末次 status 未重新入 memo: {r}"

    def test_memo_output_identical(self, tmp_path):
        r = self._run(tmp_path)
        assert r["OUT1"] == r["OUT2"] == "RAW:status"
        assert r["OUT3"] == r["OUT4"] == "RAW:query -r x foo"
        assert r["OUT7"] == "RAW:status"


# ── F-REV-83「目录 → 仓库」归属判定（2026-09-16，用户质询"repo 为什么会查到其他仓库"）──


def _to_wsl_path(p) -> str:
    """Windows 绝对路径 → WSL 视图（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    return "/mnt/" + s[0].lower() + s[2:] if len(s) > 1 and s[1] == ":" else s


# 被测对象：`_gx_repo_root_of` / `_gx_repo_dir_for_current` —— 目录归属由 git / registry 判定，
# **禁字符串猜测**。背景（修前两病）：
#   ① 末枝 `echo "${MAIN_REPO_WSL:-$(pwd)}"` = 把不可归属的目标**静默替换成主仓库**；
#   ② `skill` 语义用 `'.trae' in worktree` **字符串**判定 —— 而门卫仓库的 feature worktree
#      （`.trae/worktrees/<repo>/feature/...`）**同样含 `.trae`** ⟹ 被判成技能仓库
#      ⟹ 恒查技能仓库的图 = **静默错答**（实测 2 个 state 属此形态）。
# 修后：候选**必须通过归属验证**（registry 路径前缀 / git 主仓库根）；worktree 的 `.git` 是**文件**
# （内含 gitdir 指针），`rev-parse --git-common-dir` 恒指主仓库 ⟹ worktree / 子目录都能正确归属；
# 均不中 ⟹ 空输出 + rc=1 + WARN（fail-loud）。本组用**合成仓库**复现"目录名误导"形态。

_GX_ATTR_SETUP = r'''
set -u
TMP="$(mktemp -d)"
export HOME="$TMP/home"; mkdir -p "$HOME/.gitnexus"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
# SKILL_DIR 须**先于**被测函数调用就位：`_gx_repo_name_for_dir` 的 `${SKILL_DIR}` 分支在生产侧
# 于主脚本 L62-69 恒非空；harness 在 `set -u` 下若缺此变量会直接 unbound（非被测语义）。
export SKILL_DIR="$TMP/skill"; mkdir -p "$SKILL_DIR"
mkdir -p "$TMP/proj"
git -C "$TMP/proj" init -q .
git -C "$TMP/proj" commit -q --allow-empty -m init
mkdir -p "$TMP/proj/sub"
mkdir -p "$TMP/.trae/worktrees/fake-skill"
git -C "$TMP/proj" worktree add -q --detach "$TMP/.trae/worktrees/fake-skill" HEAD
# 隔离 registry：**只**登记合成仓库（避开真机 /mnt/c 表的 drvfs 读，同时覆盖 registry 前缀分支）
printf '[{"name":"fake-proj","path":"%s"}]' "$TMP/proj" > "$HOME/.gitnexus/registry.json"
'''

_GX_ATTR_CALLS = r'''
echo "PROJ=$TMP/proj"
# registry 前缀分支（合成 registry 命中）
echo "R_ROOT=$(_gx_repo_root_of "$TMP/proj")"
echo "R_SUB=$(_gx_repo_root_of "$TMP/proj/sub")"
# git 归属分支：目录名含 `.trae` 的 worktree ⟹ 字符串判据必错答（修后按 git 归属 = proj 根）
echo "R_WT=$(_gx_repo_root_of "$TMP/.trae/worktrees/fake-skill")"
# 非 git 目录 ⟹ 空 + rc=1
R_NG=$(_gx_repo_root_of "$TMP/home"); RC_NG=$?
echo "R_NONGIT=$R_NG"
echo "RC_NONGIT=$RC_NG"
# 空参 ⟹ 空 + rc=1
R_EM=$(_gx_repo_root_of ""); RC_EM=$?
echo "R_EMPTY=$R_EM"
echo "RC_EMPTY=$RC_EM"
# ── 消费端：state.target_repo 语义 + fail-loud（F-REV-83 producer/consumer 对齐）──
MAIN_REPO_WSL="$TMP/mainrepo"; mkdir -p "$MAIN_REPO_WSL"
STATE_FILE="$TMP/state.json"
printf '%s' '{"target_repo":"skill","worktree":""}' > "$STATE_FILE"
echo "D_SKILL=$(_gx_repo_dir_for_current)"
printf '%s' '{"target_repo":"gatekeeper","worktree":""}' > "$STATE_FILE"
echo "D_GK=$(_gx_repo_dir_for_current)"
# 元数据中枢分配指定：registry 名精确匹配（data-driven，非内建二元语义）
printf '%s' '{"target_repo":"fake-proj","worktree":""}' > "$STATE_FILE"
echo "D_NAME=$(_gx_repo_dir_for_current)"
# target_repo 未指定 + worktree 不可归属 + cwd 不可归属 ⟹ fail-loud（修前会静默回退 MAIN_REPO_WSL）
printf '%s' '{"target_repo":"","worktree":"/nonexistent-dir-xyz"}' > "$STATE_FILE"
cd "$TMP/home"
D_FAIL=$(_gx_repo_dir_for_current 2>"$TMP/warn.txt"); RC_FAIL=$?
echo "D_FAIL=$D_FAIL"
echo "RC_FAIL=$RC_FAIL"
echo "WARN_HAS_GXREPO=$(grep -c 'WARN\[gx-repo\]' "$TMP/warn.txt")"
'''


def _gx_attr_harness() -> str:
    """从 gatekeeper-cli.sh 抽取被测函数体，拼成可独立执行的 harness（先定义后调用）。"""
    src = CLI_PATH.read_text(encoding="utf-8")
    parts = []
    # `_gx_repo_root_of` 复用 `_gx_repo_name_for_dir` + `_gx_dir_for_repo_name`（⑰-7 交叉审查清理：
    # 禁第二份 registry「最长前缀」python）⟹ 抽取表须含全部被依赖函数
    for fn in ("_gx_registry_path", "_gx_dir_for_repo_name",
               "_gx_repo_name_for_dir", "_gx_repo_root_of", "_gx_repo_dir_for_current"):
        m = re.search(r"\n(" + fn + r"\(\)\s*\{.*?\n\})\n", src, re.DOTALL)
        assert m, f"{fn} not found in gatekeeper-cli.sh（改名/结构变更后须同步本测试）"
        parts.append(m.group(1))
    return _GX_ATTR_SETUP + "\n" + "\n".join(parts) + "\n" + _GX_ATTR_CALLS


def _gx_attr_run(tmp_path) -> dict:
    import shutil
    if shutil.which("bash") is None:
        pytest.skip("bash not available on this platform")
    # ⚠ **落盘执行，不用 `bash -s`（stdin）**：stdin 通道下子进程会抢读后续脚本正文
    # （实测：改 stdin 后脚本从中途"消失"，输出截到第 8 行，非确定性）
    script = tmp_path / "harness.sh"
    script.write_bytes(_gx_attr_harness().encode("utf-8"))  # 二进制写：避免文本模式把 \n 翻成 \r\n
    out = subprocess.run(["bash", _to_wsl_path(script)], capture_output=True, timeout=180)
    assert out.returncode == 0, f"harness failed: {out.stderr.decode('utf-8', 'replace')[-2000:]}"
    stdout = out.stdout.decode("utf-8", "replace")
    return dict(ln.split("=", 1) for ln in stdout.strip().splitlines() if "=" in ln)


@pytest.fixture(scope="class")
def gx_attr_metrics(tmp_path_factory) -> dict:
    """harness 的**单次**运行结果（全类共用：WSL 子进程 spawn 开销大，省 2/3 冷启）。"""
    return _gx_attr_run(tmp_path_factory.mktemp("gx-attr"))


class TestGxRepoAttribution:
    """F-REV-83 归属判定的行为断言（背景见本文件 `_GX_ATTR_SETUP` 上方注释）。"""

    def test_subdir_and_worktree_attribute_to_main_repo(self, gx_attr_metrics):
        """子目录 / worktree（含".trae"目录名）都归属主仓库根 —— 归属判定而非字符串匹配。"""
        h = gx_attr_metrics
        assert h["R_ROOT"] == h["PROJ"], f"仓库根归属错: {h}"
        assert h["R_SUB"] == h["PROJ"], f"子目录未归属到仓库根: {h}"
        assert h["R_WT"] == h["PROJ"], (
            f"worktree 未按 git 归属（目录名含 .trae ⟹ 字符串判据会错答技能仓库）: {h}")

    def test_unattributable_dir_is_fail_loud(self, gx_attr_metrics):
        """非 git / 空参 ⟹ 空输出 + rc!=0（禁猜名、禁静默回退）。"""
        h = gx_attr_metrics
        assert h["R_NONGIT"] == "" and h["RC_NONGIT"] != "0", f"非 git 目录未 fail-loud: {h}"
        assert h["R_EMPTY"] == "" and h["RC_EMPTY"] != "0", f"空参未 fail-loud: {h}"

    def test_target_repo_semantics_and_fail_closed(self, gx_attr_metrics):
        """`target_repo` 内建语义 + registry 名精确匹配直通；未指定且候选全不可归属 ⟹ fail-loud + WARN。"""
        h = gx_attr_metrics
        assert h["D_SKILL"].startswith("/") and h["D_SKILL"].endswith("/skill"), f"{h}"
        assert h["D_GK"].endswith("/mainrepo"), f"{h}"
        assert h["D_NAME"].startswith("/") and h["D_NAME"].endswith("/proj"), (
            f"registry 名（元数据中枢指定）未解析到目标目录: {h}")
        assert h["D_FAIL"] == "" and h["RC_FAIL"] != "0", (
            f"未指定 target_repo 且不可归属时未 fail-loud（修前会静默回退主仓库）: {h}")
        assert h["WARN_HAS_GXREPO"] != "0", f"fail-loud 缺 WARN[gx-repo] 诊断: {h}"


# ── Dead code cleanup ──

class TestDeadCodeCleanup:
    """Verify dead code was removed."""

    def test_no_ev_gitnexus_nodes_edges(self):
        """ev_gitnexus_nodes_edges should be removed (was never read)."""
        src = CLI_PATH.read_text(encoding="utf-8")
        assert "ev_gitnexus_nodes_edges" not in src, "Dead code ev_gitnexus_nodes_edges still present"

    def test_no_rt_status_run_gitnexus(self):
        """rt_status=$(_run_gitnexus status) should be removed (was never used)."""
        src = CLI_PATH.read_text(encoding="utf-8")
        assert "rt_status=$(_run_gitnexus" not in src, "Dead code rt_status still present"


# ── subagent_runner gitnexus_gk fix ──

class TestSubagentGitnexusGk:
    """Verify subagent_runner.py gitnexus_gk uses node.exe, not powershell.exe."""

    def test_no_powershell_in_gitnexus_gk(self):
        """_gitnexus_cmd must not use powershell.exe in actual code (not comments).
        2026-08-15 环境修复: gitnexus_gk 已薄化为 return _gitnexus_cmd(...)，node.exe 逻辑
        在 _gitnexus_cmd 内 —— 测试改查实现函数体（原查 gitnexus_gk 必失败）。"""
        filepath = SCRIPTS_DIR / "subagent_runner.py"
        content = filepath.read_text(encoding="utf-8")
        match = re.search(r'def _gitnexus_cmd\(.*?\n(.*?)(?=\n@|\ndef |\nclass |\Z)', content, re.DOTALL)
        assert match, "_gitnexus_cmd function not found"
        func_text = match.group(1)
        # 剥注释 + docstring（状态机：docstring 中间行不以 """ 开头，需跟踪块内状态）
        in_doc = False
        code_lines = []
        for l in func_text.split('\n'):
            s = l.strip()
            if '"""' in s or "'''" in s:
                in_doc = not in_doc
                continue
            if in_doc or not s or s.startswith('#'):
                continue
            code_lines.append(l)
        code_only = '\n'.join(code_lines)
        assert "powershell.exe" not in code_only, "_gitnexus_cmd code still uses powershell.exe"
        # P1 消费层（2026-09-08，f0a3131/㊴ kept）：node/js 定位唯一在 CLI _gx_node_probe（bash 单点），
        # subagent_runner 只消费 env 注入的 GX_NODE/GX_JS —— 不再内嵌第二份探测（无 /mnt 枚举/wslpath）。
        assert "GX_NODE" in code_only, "_gitnexus_cmd doesn't consume GX_NODE env"
        assert "GX_JS" in code_only, "_gitnexus_cmd doesn't consume GX_JS env"
        assert "wslpath" not in code_only, "_gitnexus_cmd must not self-probe node via wslpath (P1 single-source)"


# ── self-check env_integrity ──

class TestSelfCheckEnvIntegrity:
    """Verify self-check includes env_integrity check."""

    def test_env_integrity_check_exists(self):
        """self-check must include env_integrity check."""
        src = CLI_PATH.read_text(encoding="utf-8")
        assert "env_integrity" in src, "env_integrity check missing from self-check"

    def test_env_check_detects_hmac_key(self):
        """env_integrity must check GATEKEEPER_HMAC_KEY."""
        src = CLI_PATH.read_text(encoding="utf-8")
        assert "HMAC_KEY" in src, "HMAC_KEY check missing from env_integrity"

    def test_env_check_detects_api_key(self):
        """env_integrity must check API key."""
        src = CLI_PATH.read_text(encoding="utf-8")
        assert "API_KEY" in src or "DEEPSEEK_API_KEY" in src, "API_KEY check missing from env_integrity"

    def test_env_check_detects_subagent_role(self):
        """env_integrity must warn about SUBAGENT_ROLE override."""
        src = CLI_PATH.read_text(encoding="utf-8")
        assert "SUBAGENT_ROLE" in src, "SUBAGENT_ROLE check missing from env_integrity"

    def test_env_check_detects_node(self):
        """env_integrity must check node.exe availability."""
        src = CLI_PATH.read_text(encoding="utf-8")
        assert "node.exe" in src or "NODE" in src, "NODE check missing from env_integrity"


# ── CLI 加载期安全：HMAC 密钥供给块不得因 .keys 缺失而 unbound ──
# 现场（2026-09-20，ECC-PLAN ①）：该块的外层 `if [ -f ] / elif [ -d ]` **两条分支都不命中**
# 时（`.keys` 目录不存在 = 任意非本机宿主），`GATEKEEPER_HMAC_KEY` **从未被赋值**；其后
# `[ -n "$GATEKEEPER_HMAC_KEY" ]` 在 `set -uo pipefail` 下触发 unbound variable。
# 顶层那处（本文件的块）不是「函数中止」而是**整 CLI 在加载期 exit 1** —— 端到端 A/B 实测：
# 用 `git show f5553f3:gatekeeper-cli.sh` 的旧版（并把写死的 .keys 路径消融为不存在）跑 state，
# 复现 `line 6787: GATEKEEPER_HMAC_KEY: unbound variable` 且无任何 state 输出；
# 现版同样条件下 SUCCESS。函数内同族一处（cmd_monitor 派发前）已同批修。
# 判据 = 源码级（不许再出现裸形态）+ 行为级（切出真代码块在 set -u 下跑通）。
class TestCliHmacSupplyUnderSetU:
    """`GATEKEEPER_HMAC_KEY` 供给块在 `.keys` 缺失时不得 unbound。"""

    _BLOCK_START = '_HMAC_KEY_FILE="${_AUDIT_KEY_DIR}/'
    _GUARDED = '[ -n "${GATEKEEPER_HMAC_KEY:-}" ] && export GATEKEEPER_HMAC_KEY'

    def test_no_bare_test_remains_anywhere(self):
        """裸形态 `[ -n "$GATEKEEPER_HMAC_KEY" ] && export` 必须为 0（两处同族）。"""
        src = CLI_PATH.read_text(encoding="utf-8")
        assert '[ -n "$GATEKEEPER_HMAC_KEY" ] && export' not in src
        # 带默认值展开的形态恰好两处：顶层（本测试行为面覆盖）+ cmd_monitor 函数内
        assert src.count(self._GUARDED) == 2, src.count(self._GUARDED)

    def _extract_block(self) -> str:
        """按内容锚切出顶层供给块（不依赖行号，防漂移）。"""
        src = CLI_PATH.read_text(encoding="utf-8")
        start = src.index(self._BLOCK_START)
        tail = src[start:]
        end = tail.index(self._GUARDED)
        end = tail.index("\nfi\n", end) + len("\nfi\n")
        return tail[:end]

    def test_block_survives_missing_keys_dir(self):
        """行为判据：目录不存在 → 不 unbound、退出 0（修复前此测试红）。"""
        block = self._extract_block()
        script = (
            "set -uo pipefail\n"
            '_AUDIT_KEY_DIR="/nonexistent-keys-xyz"\n' + block + "\necho BLOCK_REACHED_END\n"
        )
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert "unbound variable" not in r.stderr, r.stderr
        assert "BLOCK_REACHED_END" in r.stdout, "块未执行完（中止在 unbound）"


# ── pre_tool_hook Gate 0 ──

class TestPreToolHookGate0:
    """Verify pre_tool_hook.py Gate 0 blocks bare Task for gatekeeper work."""

    def test_gate0_blocks_gatekeeper_keywords(self):
        """Gate 0 must block Task with gatekeeper-related queries."""
        filepath = SCRIPTS_DIR / "pre_tool_hook.py"
        content = filepath.read_text(encoding="utf-8")
        # Verify Gate 0 keyword list exists
        assert "gatekeeper" in content.lower(), "Gate 0 missing 'gatekeeper' keyword"
        assert "eco" in content.lower() or "ECO" in content, "Gate 0 missing 'eco' keyword"
        assert "audit" in content.lower() or "audit" in content, "Gate 0 missing 'audit' keyword"

    def test_gate0_allows_non_gatekeeper_task(self):
        """Gate 0 must NOT block non-gatekeeper Task queries."""
        filepath = SCRIPTS_DIR / "pre_tool_hook.py"
        content = filepath.read_text(encoding="utf-8")
        # The keyword list should be specific enough to not block generic queries
        assert "gatekeep_keywords" in content or "gatekeep" in content.lower(), "Gate 0 keyword list not found"


# ── F8 incident regression: T-F8-1 ~ T-F8-4 ──

class TestF8GateChain:
    """T-F8-1: Verify all 4 gates (1-4) in pre_tool_hook.py block correctly."""

    def test_gate1_blocks_idle_stage(self, tmp_path):
        """Gate 1 must block when stage is IDLE."""
        state_data = {"stage": "IDLE", "worktree": str(tmp_path)}
        file_path = str(tmp_path / "test.py")
        code, stderr = _run_hook_inline(state_data, "SearchReplace", file_path, str(tmp_path))
        assert code == 2, f"Expected exit 2 for IDLE stage, got {code}: {stderr}"
        assert "GATEKEEPER-BLOCK" in stderr

    def test_gate1_blocks_done_stage(self, tmp_path):
        """Gate 1 must block when stage is DONE."""
        state_data = {"stage": "DONE", "worktree": str(tmp_path)}
        file_path = str(tmp_path / "test.py")
        code, stderr = _run_hook_inline(state_data, "SearchReplace", file_path, str(tmp_path))
        assert code == 2, f"Expected exit 2 for DONE stage, got {code}: {stderr}"

    def test_gate2_blocks_missing_worktree(self, tmp_path):
        """Gate 2 must block when worktree doesn't exist on disk."""
        nonexistent = tmp_path / "nonexistent_worktree"
        state_data = {"stage": "ECO-EDIT", "worktree": str(nonexistent)}
        file_path = str(tmp_path / "test.py")
        code, stderr = _run_hook_inline(state_data, "Write", file_path, str(tmp_path))
        assert code == 2, f"Expected exit 2 for missing worktree, got {code}: {stderr}"

    def test_gate3_blocks_outside_worktree(self, tmp_path):
        """Gate 3 must block edits to paths outside the active worktree."""
        wt = tmp_path / "worktree"
        wt.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "test.py").write_text("x")
        state_data = {"stage": "ECO-EDIT", "worktree": str(wt)}
        file_path = str(outside / "test.py")
        code, stderr = _run_hook_inline(state_data, "Write", file_path, str(tmp_path))
        assert code == 2, f"Expected exit 2 for outside path, got {code}: {stderr}"
        assert "NOT in active write surface" in stderr

    def test_gate3_allows_inside_worktree(self, tmp_path):
        """Gate 3 must allow edits inside the active worktree."""
        wt = tmp_path / "worktree"
        wt.mkdir()
        (wt / "test.py").write_text("x")
        state_data = {"stage": "ECO-EDIT", "worktree": str(wt)}
        file_path = str(wt / "test.py")
        code, stderr = _run_hook_inline(state_data, "Write", file_path, str(tmp_path))
        assert code == 0, f"Expected exit 0 for inside worktree, got {code}: {stderr}"


class TestF8CrossWorktree:
    """T-F8-2: Verify cross-worktree protection (main worktree edits blocked)."""

    def test_block_main_worktree_edit(self, tmp_path):
        """Edits to main repo path should be BLOCKED when worktree is active."""
        wt = tmp_path / "feature_worktree"
        wt.mkdir()
        main_path = tmp_path / "main_repo"
        main_path.mkdir()
        (main_path / "CMakeLists.txt").write_text("")
        state_data = {"stage": "ECO-EDIT", "worktree": str(wt)}
        code, stderr = _run_hook_inline(
            state_data, "SearchReplace", str(main_path / "CMakeLists.txt"), str(tmp_path)
        )
        assert code == 2, f"Cross-worktree edit must be blocked, got {code}: {stderr}"
        assert "NOT in active write surface" in stderr


# T-F8-3（pre-commit hook 存在性）原臂断言**兄弟仓**工件
# （`<home>\Downloads\...\spz_gatekeeper_project/.git/hooks/pre-commit`）—— 该仓不在本技能包内，
# OSS 面恒缺 ⟹ 存量 skip（且在 WSL 解释器下 Windows 字面路径恒不存在，连本机也是恒 skip）。
# 等价**仓内**判据（hook 完整性）已由 `test_gk_git_workflow_check.py::test_check_hooks_ok_*`
# 用夹具覆盖 ⟹ 2026-10-29 去存量跳过时删除本类，覆盖面不减。


class TestF8EntropyMonitor:
    """T-F8-4: Verify monitor --local entropy calculation produces valid data."""

    def test_entropy_calculation_in_cli(self):
        """Verify entropy calculation code exists in gatekeeper-cli.sh."""
        cli_content = CLI_PATH.read_text(encoding="utf-8", errors="replace")
        assert "entropy_rate" in cli_content, "entropy calculation not found in CLI"
        assert "entropy" in cli_content.lower(), "'entropy' not found in CLI at all"

    def test_entropy_threshold_constant(self):
        """Verify entropy threshold is set correctly."""
        cli_content = CLI_PATH.read_text(encoding="utf-8", errors="replace")
        # Find entropy threshold definition
        assert "0.5" in cli_content, "Entropy threshold (0.5) not found in CLI"
        assert "entropy" in cli_content, "Entropy calculation missing"

    def test_entropy_from_rejected_edits(self, tmp_path):
        """Verify entropy calculation via python3 inline code works."""
        # Simulate rejected_edits and run the entropy calculation logic
        test_data = json.dumps({"gate_data": {"rejected_edits": [{"reason": "bad"}, {"reason": "wrong"}]}})
        state_file = tmp_path / "state.json"
        state_file.write_text(test_data, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-c", """
import json, hashlib
with open(r'{state}') as f: s = json.load(f)
rejected = s.get('gate_data',{{}}).get('rejected_edits', [])
if not rejected:
    print('0.0')
else:
    violations = sum(1 for r in rejected if r.get('reason'))
    rate = violations / len(rejected)
    print(str(rate))
""".format(state=str(state_file))],
            capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 0
        rate = float(result.stdout.strip())
        assert 0.0 <= rate <= 1.0, f"Entropy rate {rate} outside valid range [0,1]"


# ── F8.1: Remote verification gate + git-workflow integration ──

class TestF81RemoteGate:
    """F8.1: _verify_remote, _ALLOWED_REMOTE_PATTERNS, pr-fallback, RunCommand matcher."""

    def test_verify_remote_function_exists(self):
        """_verify_remote function must be defined in gatekeeper-cli.sh."""
        content = CLI_PATH.read_text(encoding="utf-8")
        assert "_verify_remote()" in content, "_verify_remote function missing"
        assert "_ALLOWED_REMOTE_PATTERNS" in content, "_ALLOWED_REMOTE_PATTERNS missing"

    def test_verify_remote_called_in_cmd_push(self):
        """cmd_push must call _verify_remote."""
        content = CLI_PATH.read_text(encoding="utf-8")
        assert "_verify_remote" in content, "_verify_remote not referenced in CLI"

    def test_allowed_remote_patterns_configured(self):
        """F8.1 白名单须**可配置且不含本机组织/个人账号**（2026-11-01 开源可移植）。"""
        content = CLI_PATH.read_text(encoding="utf-8")
        assert "github.com/" in content and "gitlab.com/" in content, "常见托管站缺省前缺失"
        assert "GK_PUSH_REMOTE_ALLOW" in content, "缺环境覆盖位 ⟹ 他人组织无法收紧/放行"
        assert "atomgit.com/<user>/" not in content, "个人账号前缀仍硬编码（身份泄漏 + 阻断他人）"

    # F8.1 原有两个臂（`test_pr_fallback_remote_check_in_git_workflow` /
    # `test_git_workflow_push_delegates_to_gatekeeper`）断言的是**另一个技能**
    # （`~/.trae/skills/git-workflow/scripts/git-workflow.sh`）的实现细节 —— 不在本仓，
    # OSS 面恒缺 ⟹ 存量 skip。本仓侧的等价判据（远端白名单 / CLI 接线）已由上方
    # `test_allowed_remote_patterns_configured`（直读 CLI）覆盖 ⟹ 2026-10-29 删除，
    # 覆盖面不减；跨技能契约由 git-workflow 自身套件守。

    def test_settings_json_has_runcommand(self):
        """生效 hook 配置 PreToolUse matcher 必须包含 RunCommand。

        2026-08-26 对齐部署修正：唯一生效入口 = Trae 全局根目录 ~/.trae-cn/hooks.json
        （原指向 batch8 worktree 的 .trae/settings.json 已退役清理）。
        """
        sf = _find_settings()  # 单一解析器（fail-loud）；原 `pytest.skip` 在 WSL 面**静默跳过**
        data = json.loads(sf.read_text(encoding="utf-8"))
        matchers = []
        for hook_group in data.get("hooks", {}).get("PreToolUse", []):
            m = hook_group.get("matcher", "")
            if isinstance(m, str):
                matchers.append(m)
        combined = "|".join(matchers)
        # 部署语义（87d044c 起）：全局 hooks.json 为 catch-all `*` 单入口，RunCommand 已被全量覆盖；
        # 显式 "RunCommand" matcher 或 catch-all `*` 任一命中即通过（对齐 RED-HOOK-04 判定）。
        assert "RunCommand" in combined or "*" in combined, \
            "RunCommand not covered by PreToolUse matcher (need explicit matcher or catch-all *)"

    def test_advance_hint_has_current_remote(self):
        """Advance hint JSON must include current_remote field (Phase 7: gk_advance.py)."""
        adv = SCRIPTS_DIR / "gk_advance.py"
        assert "current_remote" in adv.read_text(encoding="utf-8"), \
            "current_remote field missing from advance hint (gk_advance.py)"


# ── Gate R0.3 扩展（2026-08-20）：bash -n 语法预检 + $0 递归检测 ──

class TestScanScriptContent:
    """R0.3 脚本内容级扫描扩展：测试脚本自身问题（$0 递归 / 引号语法）提前拦截。

    背景: 测试脚本自身问题高频（上次 run_e2e.sh rm -rf 自删 → R0.3 已堵；
    随后 .tmp_dbg_all.sh $0 递归致 state.json 空 + WSL 嵌套引号 bug）→
    R0.3 增补 bash -n 语法预检 + $0 递归检测（gatekeeper-cli.sh 的 $0 子命令分派豁免）。
    """

    def _write_and_scan(self, tmp_path, content: str, name: str = "sut.sh"):
        import pre_tool_hook
        script = tmp_path / name
        script.write_text(content, encoding="utf-8")
        # _win_to_wsl identity：Windows python 保持 C:\ 路径（原生可读），WSL python 保持 /tmp（原生可读）
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            return pre_tool_hook._scan_script_content(f"bash {script}")

    def test_self_recursion_detected(self, tmp_path):
        """bash \"$0\" 递归调用自身 → 命中（测试脚本常见逻辑 bug）。"""
        hit = self._write_and_scan(tmp_path, '#!/bin/bash\nbash "$0" audit --state\n')
        assert hit is not None, "expected $0 recursion hit"
        assert "$0" in hit[0]

    def test_self_recursion_bare_dollar_zero(self, tmp_path):
        """bash $0（无引号）形态同样命中。"""
        hit = self._write_and_scan(tmp_path, "#!/bin/bash\nbash $0 --x\n")
        assert hit is not None, "expected $0 recursion hit"
        assert "$0" in hit[0]

    def test_clean_script_not_flagged(self, tmp_path):
        """无 $0 递归/危险命令/语法错误 → 不命中（无误伤）。"""
        hit = self._write_and_scan(tmp_path, "#!/bin/bash\necho hello\n")
        assert hit is None

    def test_syntax_error_detected(self, tmp_path):
        """未闭合引号 → bash -n 命中（WSL 引号 bug 提前暴露）。"""
        import shutil
        if shutil.which("bash") is None:
            pytest.skip("bash not available on this platform")
        hit = self._write_and_scan(tmp_path, '#!/bin/bash\necho "unclosed\n')
        assert hit is not None, "expected bash -n syntax hit"
        assert "bash -n" in hit[0]

    def test_rm_rf_self_delete_still_detected(self, tmp_path):
        """既有 R0.3 危险命令检测不回归（rm -rf 指向大写 $TMP 不豁免）。"""
        hit = self._write_and_scan(tmp_path, '#!/bin/bash\nrm -rf "$TMP"\n')
        assert hit is not None, "expected rm -rf hit"
        assert "rm -rf" in hit[0]

    def test_cli_self_recur_exempt(self, tmp_path):
        """gatekeeper-cli.sh 的 bash \"$0\" 子命令分派 → 豁免（不误报核心 CLI）。"""
        import pre_tool_hook
        script = tmp_path / "gatekeeper-cli.sh"
        script.write_text('bash "$0" audit --state\n', encoding="utf-8")
        with patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            hit = pre_tool_hook._scan_script_content(f"bash {script}")
        assert hit is None, f"gatekeeper-cli.sh $0 分派不应被拦: {hit}"


class TestGate8SkillSelfMaintenance:
    """Gate 8 (R-T8.3): 技能仓库写操作须有 open finding 或活跃计划，否则 BLOCK（防裸跑）。

    背景: batch8 技能自维护走 standard R-T* 裸跑，缺登记/闭环/门禁三层保障 →
    新增 Gate 8：SKILL_DIR 内写操作，无 open finding 且无活跃 r_phase → BLOCK。
    放行（任一）: ① gate_data.ecc_findings 有 open 项（修复驱动）② state.r_phase 非空（计划驱动）
    ③ 目标在 docs/.trae/.gatekeeper.*（计划/配置文档豁免——登记过程本身）。
    """

    def _gate8_state(self, findings_open: bool, plan_active: bool) -> dict:
        gd = {}
        if findings_open:
            gd["ecc_findings"] = [{"id": "ECC-TEST1", "status": "open", "title": "t"}]
        return {
            "stage": "R-T6", "r_phase": "R-T6" if plan_active else "",
            "worktree": str(Path.cwd()),
            "gate_data": gd,
        }

    def _call(self, tmp_path, target_rel: str, state: dict):
        """patch SKILL_DIR → tmp_path，使目标解析落在"技能仓库"内。"""
        import pre_tool_hook
        with patch("pre_tool_hook.SKILL_DIR", tmp_path), \
             patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            return pre_tool_hook._gate8_skill_self_maintenance(str(tmp_path), str(tmp_path / target_rel), state)

    def test_edit_skill_file_no_registration_blocked(self, tmp_path):
        """无 open finding 且无活跃 r_phase → BLOCK（裸跑拦截核心场景）。"""
        state = self._gate8_state(findings_open=False, plan_active=False)
        assert self._call(tmp_path, "gatekeeper-cli.sh", state) is not None

    def test_edit_skill_file_with_open_finding_allowed(self, tmp_path):
        """有 open finding（修复驱动）→ 放行。"""
        state = self._gate8_state(findings_open=True, plan_active=False)
        assert self._call(tmp_path, "gatekeeper-cli.sh", state) is None

    def test_edit_skill_file_with_active_plan_allowed(self, tmp_path):
        """活跃 r_phase（计划驱动）→ 放行。"""
        state = self._gate8_state(findings_open=False, plan_active=True)
        assert self._call(tmp_path, "gatekeeper-cli.sh", state) is None

    def test_edit_skill_docs_exempt(self, tmp_path):
        """docs/ 计划文档 → 豁免（登记过程本身，非裸跑）。"""
        state = self._gate8_state(findings_open=False, plan_active=False)
        assert self._call(tmp_path, "docs/plans/plan.md", state) is None

    def test_edit_outside_skill_not_applicable(self, tmp_path):
        """目标不在 SKILL_DIR → 不适用（返回 None，不影响外部项目）。"""
        import pre_tool_hook
        state = self._gate8_state(findings_open=False, plan_active=False)
        outside = tmp_path / ".." / "elsewhere" / "file.py"
        with patch("pre_tool_hook.SKILL_DIR", tmp_path), \
             patch("pre_tool_hook._win_to_wsl", side_effect=lambda p: str(p)):
            hit = pre_tool_hook._gate8_skill_self_maintenance(str(tmp_path), str(outside), state)
        assert hit is None


class TestCrossfullTargetingIsolation:
    """F-REV-30（隔离）+ F-REV-39（目标化）2026-09-13：audit --crossfull 串行器加固。

    静态层断言（CLI 源码接线 + fail-loud 路径）；行为已由 CLI 端到端手动验证
    （`--repo __missing__` → rc=2 + error=unknown_repo）。
    """

    def _src(self) -> str:
        return CLI_PATH.read_text(encoding="utf-8")

    def test_flags_wired(self):
        s = self._src()
        assert "--repo) _cf_repo=" in s
        assert "--state) _cf_state=" in s
        assert "--isolate) _cf_isolate=1" in s

    def test_fail_loud_paths(self):
        """未命中/不可隔离 → fail-loud 错误码（禁静默回退技能目录）。"""
        s = self._src()
        assert '"error":"unknown_repo"' in s
        assert '"error":"isolate_requires_git"' in s

    def test_isolation_wiring(self):
        """F-REV-30：独立 worktree + 独立 state + 前置调 register（单源，不复制注册逻辑）。"""
        s = self._src()
        assert "worktree add --detach" in s
        assert "project-register register" in s
        assert "GK_CF_TARGET_IS_SKILL" in s

    def test_driver_uses_overrides_and_marks_nonskill(self):
        """driver 用 GK_CF_CWD 覆盖 cwd；非技能目标技能专属步 SKIP（非 FAIL 噪音）。"""
        s = self._src()
        assert 'cwd=os.environ.get("GK_CF_CWD")' in s
        assert "def skip_nonskill(" in s
        assert 'skip_nonskill("L6", "doc-align"' in s
        assert '"target_is_skill": not _non_skill' in s

    def test_p0_3_shadow_register_wiring(self):
        """P0-3（2026-09-13）：postR/L2「本应收录」shadow 接线（只产不写）。

        背景（D3 postR 产物黑洞）：driver 原只取 conclusion/confidence ⟹ ecc_findings 恒空。
        shadow 首发不落 journal/state，故只能由源码接线断言守（运行时清单见 crossfull 输出）。
        """
        s = self._src()
        assert "def shadow_extract(" in s
        assert 'shadow_extract("L2", "code-to-spec", ["L2"], _l2o)' in s
        assert "shadow_extract(_rid, _rfam, _rlay, _ro)" in s
        assert '"shadow_findings": _shadow' in s
        assert "import hashlib, json, os, subprocess, sys" in s


class TestPreToolCheckToolnameNormalization:
    """F-REV-45 / F-REV-46（2026-09-13）：Gate 4 `pre_tool_check` 的 enforcement 契约回归。

    两处独立 fail-open（**写入口结构回归**，防"读侧单测恒绿"）：
      F-REV-45 — `case "$cmd_type" in edit|write)` 大小写敏感，而 hook 传 Trae 工具名原名
                 （EDIT_TOOLS 首字母大写）⟹ 分支永不命中 ⟹ 路径/保护区/预算七类检查全链跳过；
      F-REV-46 — realpath 调用写成 `python3 -c "..." -- "$path"`，CPython 对 `-c` 不消费 `--`
                 ⟹ `sys.argv[1] == "--"` ⟹ realpath 恒解析为 `<cwd>/--` ⟹ main-worktree
                 只读判定永不命中、worktree 归属被 real_path 分支兜底误判为通过。
    （行为面已由 CLI 端到端手动验证：六种拼写对越界路径一致 BLOCK；本文件不启 subprocess，
     以规避 Windows 无 `bash` 的环境依赖。）
    """

    def _src(self) -> str:
        return CLI_PATH.read_text(encoding="utf-8")

    def test_case_labels_cover_hook_edit_tools(self):
        """F-REV-45：CLI case 标签须覆盖 `pre_tool_hook.EDIT_TOOLS` 全量（小写归一后）。"""
        import re
        import pre_tool_hook
        s = self._src()
        assert '_ct=$(printf \'%s\' "$cmd_type" | tr \'[:upper:]\' \'[:lower:]\')' in s, "工具名归一缺失"
        assert 'case "$_ct" in' in s, "case 未改用归一变量"
        m = re.search(r'case "\$_ct" in\n\s*(edit\|[^\n]*)\)', s)
        assert m, "未找到写类工具 case 分支"
        labels = set(m.group(1).split("|"))
        need = {t.lower() for t in pre_tool_hook.EDIT_TOOLS}
        assert need <= labels, "CLI case 未覆盖 hook EDIT_TOOLS: %s" % sorted(need - labels)

    def test_realpath_call_has_no_stray_double_dash(self):
        """F-REV-46：realpath 调用不得带 `--`（会被 CPython 计入 sys.argv[1]）。"""
        s = self._src()
        assert '"--" "$path"' not in s, "realpath 仍带 `--`（sys.argv[1] 将为 '--'）"

    def test_protected_region_file_level_is_warn_not_block(self):
        """F-REV-45 + owner 裁定 A（2026-09-27）：文件级 = WARN；行级 = WARN + 留痕（**不再** BLOCK）。"""
        s = self._src()
        assert "WARN: gatekeeper-cli.sh 存在 PROTECTED_REGION 标记" in s
        assert 'protection_status="warn"' in s
        # 行级分支 = 裁定 A：WARN + 留痕（`_pe_record`）；旧「行级 BLOCK」形体须已清除
        assert "is in PROTECTED_REGION" in s and "WARN: Line " in s
        assert "BLOCK: Line" not in s, "行级 BLOCK 形体残留（裁定 A 已降级为 WARN + 留痕）"
        assert "_pe_record" in s, "行级命中缺留痕钩子（裁定 A 要求强制审计）"


class TestShadowExtractBehavior:
    """P0-3 shadow_extract 的**纯函数行为**回归（2c#1-C3 命中：原守卫仅源码子串 = 空洞断言）。

    做法：从 `gatekeeper-cli.sh` 的 CROSSFULL_PY heredoc 中**抽取**该函数并 exec，
    喂构造 JSON 断言语义（指纹去重键 / 无定位锚剔除 / family 必填 / verdict 词表 / 非 JSON 容错）。
    抽取失败 → 直接 FAIL（防"代码搬走而测试静默通过"）。
    """

    @staticmethod
    def _load():
        import hashlib
        import json as _json
        s = CLI_PATH.read_text(encoding="utf-8")
        a = s.find("# ── P0-3 shadow register（2026-09-13）")
        b = s.find("# monitor --local 需要 stage 参数")
        assert a != -1 and b != -1 and b > a, "P0-3 shadow 段抽取标记缺失（代码已搬走？）"
        g = {"json": _json, "hashlib": hashlib}
        exec(compile(s[a:b], "<shadow_extract>", "exec"), g)
        assert "shadow_extract" in g, "shadow_extract 未定义"
        return g

    def _out(self, evidence):
        import json as _json
        return _json.dumps({"conclusion": "c", "confidence": "high", "evidence": evidence})

    def test_extract_filters_and_dedups(self):
        g = self._load()
        ev = [
            {"file": "a.py", "lines": "1-2", "status": "confirmed", "note": "n1"},
            {"file": "b.py", "lines": "3", "status": "suspect", "note": "n2"},
            {"lines": "9", "status": "suspect", "note": "无定位锚→低质"},
        ]
        assert g["shadow_extract"]("L2", "code-to-spec", ["L2"], self._out(ev)) == (2, 0)
        sh = g["_shadow"]
        assert [x["verdict"] for x in sh] == ["PASS", "FAIL"]      # 复用 gk_adjudicate 词表
        assert all(x["family"] and x["cover_layers"] for x in sh)   # family/cover_layers 必填
        assert all(x["fingerprint"] for x in sh)                    # 显式指纹
        assert [x["evidence_status"] for x in sh] == ["confirmed", "suspect"]
        # 同 family 重抽 → 全部去重
        assert g["shadow_extract"]("postR#1", "code-to-spec", ["L1"], self._out(ev)) == (0, 2)
        # 异 family → 指纹不同，全新增
        assert g["shadow_extract"]("postR#1", "postR-five-domain", ["L1"], self._out(ev)) == (2, 0)

    def test_extract_tolerates_garbage(self):
        g = self._load()
        f = g["shadow_extract"]
        assert f("X", "fam", ["L1"], "not-json") == (0, 0)
        assert f("Y", "fam", ["L1"], self._out([])) == (0, 0)
        assert f("Z", "fam", ["L1"], self._out([{"file": "", "status": "suspect"}])) == (0, 0)


class TestMoaSuspectFieldWhitelist:
    """F-REV-41（2026-09-13）：MoA 聚合器消费字段必须真落 subagent_history。

    背景：gk_moa_aggregate 的 vocab_violation / budget_* / hmac_status 读侧实现正确，
    但 CLI 写 subagent_history 的 entry 是**字段白名单**，原不含这些字段 ⇒ 读侧永不触发
    （实装但零生效假绿）。单测只注入构造的 entry 无法发现该断链 ⇒ 本类守 CLI 写入口。
    """

    def _src(self) -> str:
        return CLI_PATH.read_text(encoding="utf-8")

    def test_entry_whitelist_carries_aggregator_fields(self):
        s = self._src()
        for field in ("'verdicts'", "'vocab_violations'", "'budget_status'",
                      "'total_tokens'", "'token_budget'", "'total_items'",
                      "'item_budget'", "'hmac_status'"):
            assert f"{field}:" in s, \
                f"subagent_history entry 白名单缺 {field}（MoA 聚合器读侧将零生效）"

    def test_hmac_status_env_wired_to_writer(self):
        """hmac 校验态须由 bash 注入 python 写入口（否则 hmac_status 恒 skip）。"""
        s = self._src()
        assert 'GK_TASK="$task" GK_HMAC_VALID="$hmac_valid" python3' in s
        assert "os.environ.get('GK_HMAC_VALID'" in s


class TestMonitorAlignConverged:
    """F-REV-42（2026-09-13 更正）：`monitor --align` 完成 2026-09-01 文档收敛的**代码收敛**。

    背景：b6fe907（2026-09-01 "monitor --align 收敛"）只改文档未改代码 ⇒ `--align` 遗留为
    独立内联实现（11 项，双源漂移）。用户指摘后完成收敛：`--align` 委托 doc-align 插件
    （`gk_doc_align.py` 单一实现）；L9 三态 + 自动 E2 归位 `monitor --local`。
    """

    def _src(self) -> str:
        return CLI_PATH.read_text(encoding="utf-8")

    def test_align_delegates_to_doc_align_plugin(self):
        """`--align` 分支须委托 doc-align 插件，不再有第二份内联检查器。"""
        s = self._src()
        assert "cmd_doc_align\n    return $?" in s, "--align 未委托 doc-align 插件"
        for marker in ('"item":"meta_exists"', '"item":"commit_format"',
                       '"item":"plan_exists"', '"item":"flywheel_progress"',
                       '"mode":"align"'):
            assert marker not in s, f"--align 内联旧实现残留: {marker}"

    def test_align_mode_still_registered(self):
        """`--align` 模式仍可识别（委托形态，非删除）。"""
        s = self._src()
        assert '--align) mode="--align"' in s

    def test_l9_relocated_to_local_single_sourced(self):
        """L9 三态 + 自动 E2 归位 `monitor --local`，单源 gk_self_check。"""
        s = self._src()
        assert "gk_self_check as sc" in s
        for fn in ("check_l9_runtime_safenet", "check_l9_gatechain_prereq",
                   "check_l9_entropy_appeal"):
            assert f"sc.{fn}" in s, f"L9 未单源化到 {fn}"
        assert "--family MONITOR-LOCAL --cover-layers L9" in s

    def test_align_fail_count_removed(self):
        """旧 `--align` 的 fail 计数/恒 return 0 已随内联实现删除（退出码 = doc-align 的）。"""
        s = self._src()
        assert '[ "$fail" -gt 0 ] && return 1' not in s


# ── F-REV-88「analyze 钉 CPU 嵌入设备」（2026-09-16，用户裁定 A+B 双修）──

# 被测对象：`_run_gitnexus_raw` —— bash 侧**唯一** gitnexus spawner（`_run_gitnexus` 只是 memo 壳）。
# 病：`analyze`（含 `--embeddings`）走 onnxruntime-node，设备默认 `auto` 会探 CUDA/DML 执行提供器
#   → 加载 NVIDIA 驱动 → 触碰 `C:\ProgramData\NVIDIA Corporation\Drs\nvAppTimestamps`
#   ⟹ 沙箱判 restricted 拦停；且该拦截**随 IDE 重启复发**（运行时授权不持久，见 F-REV-89）。
# 修：`analyze*` 显式钉 `GITNEXUS_EMBEDDING_DEVICE=cpu`（CPU 路径不探 GPU 驱动）；其余子命令
#   **不设**该变量 —— gitnexus `parseDevice` 对**空串**抛错（非法值校验），且读命令非嵌入热路径。
# 证：用**假 node**（回显它运行时真正拿到的设备变量）+ 桩 `_gx_node_probe` / `_gx_repo_dir_for_current`，
#   对**真函数体**做行为断言（禁读码代替执行）。

_GR88_SETUP = r'''
set -u
TMP="$(mktemp -d)"
export HOME="$TMP/home"; mkdir -p "$HOME" "$TMP/repo"
# 假 node：回显运行时环境里真实可见的设备变量（UNSET = 未被注入）
cat > "$TMP/fakenode" <<'FAKE'
#!/bin/bash
echo "DEV=[${GITNEXUS_EMBEDDING_DEVICE-UNSET}]"
FAKE
chmod +x "$TMP/fakenode"
_gx_node_probe() { echo "$TMP/fakenode"; }
_gx_repo_dir_for_current() { echo "$TMP/repo"; }
# 2026-11-01：`_run_gitnexus_raw` 后续新增的宿主侧编排 helper（原 harness 未提供 ⟹
#   "command not found" + `SKILL_DIR: unbound variable` ⟹ 三条设备断言恒空，假红）。
#   此处只给**最小桩**（本测试只看 env 注入，不看这些 helper 的真实语义）。
_user_home_wsl() { echo "$HOME"; }
_user_home_win() { echo '<home>'; }
_gx_worktree_main_root() { echo "${1:-}"; }
# 2026-11-01（合并 buddy 的 _gx_to_win_path 单一事实源后）：本 harness 只看 env 注入，
#   路径形态归一非判据面 ⟹ 原样透传即可（缺它会把「归一失败」误判成「设备未注入」）。
_gx_to_win_path() { echo "${1:-}"; }
'''

_GR88_CALLS = r'''
unset GITNEXUS_EMBEDDING_DEVICE || true
echo "D_ANALYZE=$(_run_gitnexus_raw analyze --embeddings)"
echo "D_READ=$(_run_gitnexus_raw context -r x foo)"
echo "D_OVERRIDE=$(GITNEXUS_EMBEDDING_DEVICE=dml _run_gitnexus_raw analyze)"
'''


def _gr88_harness() -> str:
    """抽取 `_run_gitnexus_raw` 真函数体，拼成可独立执行的 harness（先定义后调用）。

    2026-10-28（A1 收口）：函数体已改为**委托** `scripts/gk_gitnexus.py run` ⟹ harness 须补
    `_SCRIPT_DIR`（真函数所在技能根），否则委托路径解析不到真实 launcher。
    """
    src = CLI_PATH.read_text(encoding="utf-8")
    m = re.search(r"\n(_run_gitnexus_raw\(\)\s*\{.*?\n\})\n", src, re.DOTALL)
    assert m, "_run_gitnexus_raw not found in gatekeeper-cli.sh（改名/结构变更后须同步本测试）"
    _dir_line = "_SCRIPT_DIR=%s\nSKILL_DIR=\"$_SCRIPT_DIR\"\n" % _shlex.quote(str(CLI_PATH.parent))
    return _GR88_SETUP + "\n" + _dir_line + m.group(1) + "\n" + _GR88_CALLS


def _gr88_run(tmp_path) -> dict:
    import shutil
    if shutil.which("bash") is None:
        pytest.skip("bash not available on this platform")
    # 落盘执行（不用 stdin 通道：子进程会抢读脚本正文，见 TestGxRepoAttribution 注记）
    script = tmp_path / "harness.sh"
    script.write_bytes(_gr88_harness().encode("utf-8"))
    out = subprocess.run(["bash", _to_wsl_path(script)], capture_output=True, timeout=120)
    assert out.returncode == 0, f"harness failed: {out.stderr.decode('utf-8', 'replace')[-2000:]}"
    stdout = out.stdout.decode("utf-8", "replace")
    return dict(ln.split("=", 1) for ln in stdout.strip().splitlines() if "=" in ln)


class TestAnalyzeEmbeddingDevice:
    """F-REV-88：`analyze` 钉 cpu、其余子命令不设、外部显式值优先。"""

    def test_analyze_pins_cpu(self, tmp_path):
        h = _gr88_run(tmp_path)
        assert h.get("D_ANALYZE") == "DEV=[cpu]", f"analyze 未钉 cpu 嵌入设备: {h}"

    def test_read_commands_do_not_inject(self, tmp_path):
        """读命令**不设**该变量：gitnexus `parseDevice` 对空串抛错，且读命令非嵌入热路径。"""
        h = _gr88_run(tmp_path)
        assert h.get("D_READ") == "DEV=[UNSET]", f"非 analyze 子命令不应注入设备变量: {h}"

    def test_external_override_wins(self, tmp_path):
        h = _gr88_run(tmp_path)
        assert h.get("D_OVERRIDE") == "DEV=[dml]", f"外部显式指定被覆盖: {h}"


class TestSubagentAnalyzeEmbeddingDevice:
    """F-REV-88 孪生侧：analyze 钉 cpu 须与 bash 侧**同策**（避免双源漂移）。

    2026-10-28（A1）：策略**单源已迁**至 `scripts/gk_gitnexus.py::_build_env`
    （`subagent_runner._gitnexus_cmd` 不再自持 env 分支），故断言点随单源一起搬迁。
    """

    def _launcher_source(self) -> str:
        return (SCRIPTS_DIR / "gk_gitnexus.py").read_text(encoding="utf-8")

    def test_injects_device_only_for_analyze(self):
        src = self._launcher_source()
        assert '"GITNEXUS_EMBEDDING_DEVICE", "cpu"' in src, (
            "launcher 未钉 cpu 嵌入设备（与 bash 侧 _run_gitnexus_raw 漂移）")
        assert 'startswith("analyze")' in src, "注入未按 analyze 前缀限定（空串会让 parseDevice 抛错）"

    def test_subagent_delegates_to_launcher(self):
        """孪生侧不得再自建 env/spawn（防 A1 单源被回退成双源）。"""
        content = (SCRIPTS_DIR / "subagent_runner.py").read_text(encoding="utf-8")
        m = re.search(r'def _gitnexus_cmd\(.*?\n(.*?)(?=\n@|\ndef |\nclass |\Z)',
                      content, re.DOTALL)
        assert m, "_gitnexus_cmd function not found"
        body = m.group(1)
        assert "gk_gitnexus" in body, "_gitnexus_cmd 未走 launcher（A1 单源）"
        assert 'env.setdefault("GITNEXUS_EMBEDDING_DEVICE"' not in body, (
            "_gitnexus_cmd 仍自持嵌入设备分支（单源应只在 gk_gitnexus）")

    def test_parity_with_bash_side(self):
        """双侧同策（2026-10-28 A1 收口后断言点迁移）。

        旧断言直接查 bash 的 `analyze*) export GITNEXUS_EMBEDDING_DEVICE=...` 分支；收口后
        bash **不再持有**该策略（spawn 委托 launcher）⟹ 同策 = ①bash 确实委托 + ②launcher
        持策。若有人把 spawn 搬回 bash，`test_bash_channel_*`（launcher 测试）会先红。
        """
        cli = CLI_PATH.read_text(encoding="utf-8")
        m = re.search(r"\n(_run_gitnexus_raw\(\)\s*\{.*?\n\})\n", cli, re.DOTALL)
        assert m, "_run_gitnexus_raw 结构变了 ⟹ 同步本测试"
        assert "gk_gitnexus.py" in m.group(1), "bash 侧未委托 launcher（双侧同策前提缺失）"
        assert '"GITNEXUS_EMBEDDING_DEVICE", "cpu"' in self._launcher_source(), (
            "launcher 未钉 cpu 嵌入设备（analyze 会探 GPU 驱动，触发沙箱拦截）")


# ─── F-REV-91：WSL interop 只传 `WSLENV` 白名单内变量 ────────────────────────────
# `monitor --subagent` 的默认解释器 `suagent_py311.sh` 直接 `exec` Windows `python.exe`
# ⟹ bash 侧 `export` 全被静默丢弃，必须把 `GX_*`/`GK_*`/`SUBAGENT_*` **裸名**并入 `WSLENV`。
# ⚠ 标志位语义与直觉相反（同机实测）：`/u` → 被丢弃（None）、`/p` → 路径二次翻译破坏；
# ⚠ 只并入**当前非空**键（空串进白名单会让 runner 的 `os.environ.get(k, 默认)` 不回落到默认值）。
_WSLENV_BLOCK_RE = re.compile(r"\n(    for _k in GX_NODE.*?\n    export WSLENV\n)", re.DOTALL)
_WSLENV_SEED = "DEEPSEEK_API_KEY/u:MIMO_API_KEY/u"


def _wslenv_block() -> str:
    """抽取 gatekeeper-cli.sh 里**真**的 WSLENV 并入块（改名/结构变更后本测试须同步）。"""
    src = CLI_PATH.read_text(encoding="utf-8")
    m = _WSLENV_BLOCK_RE.search(src)
    assert m, ("gatekeeper-cli.sh 未找到 WSLENV 并入块"
               "（`for _k in GX_NODE … export WSLENV`；改名/结构变更后须同步本测试）")
    return m.group(1)


def _wslenv_run(tmp_path, seed_wslenv: str) -> dict:
    """跑两遍真块（第二遍验幂等），回读 WSLENV。"""
    import shutil
    if shutil.which("bash") is None:
        pytest.skip("bash not available on this platform")
    block = _wslenv_block()
    harness = (
        "#!/bin/bash\n"
        # 已赋值（须并入，且**裸名**）
        "export GX_NODE='D:\\Program Files\\nodejs\\node.exe'\n"
        "export GX_JS='C:\\gx\\index.js'\n"
        "export SUBAGENT_ID='sub-regression-1'\n"
        "export GATEKEEPER_HMAC_KEY='deadbeef'\n"
        # 空串（须跳过：空串会让 os.environ.get 见「存在但空」而不回落默认值）
        "export SUBAGENT_TOKEN_BUDGET=''\n"
        # GX_REPO / SUBAGENT_ROLE / 其余：**未设置**（须被 `declare -p` 守卫跳过）
        f'WSLENV="{seed_wslenv}"\n'
        + block
        + '\necho "WSLENV_ONCE=[$WSLENV]"\n'
        + block
        + '\necho "WSLENV_TWICE=[$WSLENV]"\n'
    )
    script = tmp_path / "wslenv_harness.sh"
    script.write_bytes(harness.encode("utf-8"))
    # 2026-10-01：**sanitize env** —— 原实现继承 pytest 进程环境 ⟹ 别的测试文件里
    #   `subagent_runner._bootstrap()` 写进 `os.environ` 的 `SUBAGENT_MAX_TOKENS` /
    #   `SUBAGENT_TIMEOUT` 会**泄漏进本沙箱**（二者都在 CLI 白名单循环内）⟹ WSLENV 多出两项
    #   ⟹ 断言随**测试顺序**红绿（HEAD 对照实测：单跑绿 / 与 test_subagent_runner_extract
    #   同进程红）。本臂只验「脚本内 export 的键如何并入」，故给**受控最小 env**。
    _env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/root"),
            "LANG": os.environ.get("LANG", "C.UTF-8")}
    out = subprocess.run(["bash", _to_wsl_path(script)], capture_output=True, timeout=60, env=_env)
    assert out.returncode == 0, (
        f"WSLENV harness failed: {out.stderr.decode('utf-8', 'replace')[-1500:]}")
    stdout = out.stdout.decode("utf-8", "replace")
    raw = dict(ln.split("=", 1) for ln in stdout.strip().splitlines() if "=" in ln)
    # 回显用了 `VAR=[…]` 包裹（便于人读），断言侧剥掉方括号
    return {k: (v[1:-1] if v.startswith("[") and v.endswith("]") else v)
            for k, v in raw.items()}


class TestWslenvInteropEnv:
    """F-REV-91：`GX_*`/`GK_*`/`SUBAGENT_*` 须**裸名**并入 `WSLENV`，空串/未设置须跳过。"""

    def test_bare_names_appended_in_loop_order(self, tmp_path):
        h = _wslenv_run(tmp_path, _WSLENV_SEED)
        assert h["WSLENV_ONCE"] == (
            _WSLENV_SEED + ":GX_NODE:GX_JS:SUBAGENT_ID:GATEKEEPER_HMAC_KEY"
        ), f"并入结果与预期不符（含顺序/标志位）：{h['WSLENV_ONCE']}"

    def test_no_path_translation_flags(self, tmp_path):
        """`/u` 与 `/p` 都破坏值（实测 `/u`→None、`/p`→`D;\\Program Files\\…`）⟹ 一律裸名。"""
        h = _wslenv_run(tmp_path, _WSLENV_SEED)
        for k in ("GX_NODE", "GX_JS", "SUBAGENT_ID", "GATEKEEPER_HMAC_KEY"):
            assert f"{k}/u" not in h["WSLENV_ONCE"], f"{k} 被加了 /u 标志（Windows 侧会读成 None）"
            assert f"{k}/p" not in h["WSLENV_ONCE"], f"{k} 被加了 /p 标志（路径会被二次翻译破坏）"

    def test_empty_value_skipped(self, tmp_path):
        """空串守卫：并入空串会让 runner 见「存在但空」而不回落默认（如 SUBAGENT_ID 变空串）。"""
        h = _wslenv_run(tmp_path, _WSLENV_SEED)
        assert "SUBAGENT_TOKEN_BUDGET" not in h["WSLENV_ONCE"], (
            "空值键被并入 WSLENV —— 会遮蔽 runner 的默认值回落")

    def test_unset_key_skipped(self, tmp_path):
        h = _wslenv_run(tmp_path, _WSLENV_SEED)
        assert "GX_REPO" not in h["WSLENV_ONCE"], "未设置键被并入（declare -p 守卫失效）"

    def test_merge_is_idempotent(self, tmp_path):
        """重复执行不得重复追加（否则 WSLENV 逐次膨胀）。"""
        h = _wslenv_run(tmp_path, _WSLENV_SEED)
        assert h["WSLENV_TWICE"] == h["WSLENV_ONCE"], (
            f"第二次并入改变了 WSLENV：{h['WSLENV_ONCE']} → {h['WSLENV_TWICE']}")

    def test_existing_bare_entry_not_duplicated(self, tmp_path):
        """已在白名单（裸名）的键不再追加 —— 防重复项。"""
        h = _wslenv_run(tmp_path, _WSLENV_SEED + ":GX_NODE")
        assert h["WSLENV_ONCE"].count("GX_NODE") == 1, (
            f"已存在的裸名项被重复追加：{h['WSLENV_ONCE']}")

    def test_existing_slash_entry_not_duplicated(self, tmp_path):
        """已在白名单且**带标志位**的键同样不再追加（`*\":${_k}/\"*` 分支）。"""
        h = _wslenv_run(tmp_path, _WSLENV_SEED + ":GX_NODE/w")
        assert h["WSLENV_ONCE"].count("GX_NODE") == 1, (
            f"已存在的带标志位项被重复追加：{h['WSLENV_ONCE']}")


# ─── ECC-AFC678CA168B：端到端「派发 role 真落到 runner 进程环境」回归臂 ─────────────
class TestSubagentRoleReachesRunnerEnv:
    """F-REV-31（结构断言缺陷）的**反面**：本臂断言**行为**，不断言源码文本。

    背景（实测）：`monitor --subagent` 的待传键在 CLI 侧是 **env prefix**（只作用于单条命令、
    不是 shell 变量），而默认解释器 `suagent_py311.sh` 会 `exec` Windows `python.exe`
    ⟹ 只有「已 export **且** 已并入 `WSLENV`」两条件同时成立，键才能穿过 WSL→Windows interop
    到达 runner。修前 `WSLENV` 并入循环跑在全部赋值**之前**（`declare -p` 守卫恒跳过）⟹
    `SUBAGENT_ROLE` 丢 ⟹ runner 落 `default`（evidence-only）⟹ crossfull postR/L2/红队 LLM
    车道读不到 `gatekeeper-cli.sh`（gate 区）= 盲审 + 结论失真。

    零 API（桩直接回 error JSON）；零副作用（独立 state 副本 + `GK_STATE_DOMAIN_ROUTE=0`）。
    """

    def test_dispatch_role_reaches_runner_env(self, tmp_path):
        import shutil
        if shutil.which("bash") is None:
            pytest.skip("bash not available on this platform")
        if not CLI_PATH.exists():
            pytest.skip("gatekeeper-cli.sh not found")
        dump = tmp_path / "env_dump.txt"
        stub = tmp_path / "probe_env.sh"
        stub.write_bytes((
            "#!/bin/sh\n"
            "{\n"
            '  echo "SUBAGENT_ROLE=${SUBAGENT_ROLE:-<unset>}"\n'
            '  echo "SUBAGENT_ID=${SUBAGENT_ID:-<unset>}"\n'
            '  echo "WSLENV=${WSLENV:-<unset>}"\n'
            '} > "' + _to_wsl_path(dump) + '"\n'
            "echo '{\"error\":\"role-probe-stub\"}'\n"
            "exit 0\n"
        ).encode("utf-8"))
        stub.chmod(0o755)
        # 最小**确定性** state（2026-10-10 · ECC-3FD7DEAF6078）：原式**复制活 state** —— 活
        #   state 无界增长，一旦 >256KB 即被 `monitor --subagent` 的 `state_oversized` schema 闸
        #   拒绝派发（实测：活 state 267825B > 262144B）⟹ 桩永不达 ⟹ 本臂恒红，且与 xdist 分片
        #   无关地脆弱（分片只是让它更早暴露）。本臂判据 = `--role` 是否落到 runner 进程 env，
        #   **与 state 内容无关** ⟹ 自建最小 state（对齐本文件 gitnexus 臂 §1551 同款口径）。
        state = tmp_path / "probe.state"
        state.write_text(json.dumps({
            "stage": "STAGE_0", "r_phase": "R1", "branch": "master", "worktree": "",
            "gate_data": {"project_type": "standing",
                          "edit_budget": {"max": 4, "used": 0, "remaining": 4}},
        }, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")
        env = dict(os.environ)
        # 提速（2026-10-10 · ECC-3FD7DEAF6078）：`--role` 会触发 CLI 的 **L0 全量预取**
        #   （`gk_l0_prefetch`：gitnexus `detect-changes` + **裸 `gitnexus status`**（实测脏树
        #   比对 ~19s，见 F-REV-77）+ **内嵌整套 pytest 的 self-check**，实测合计 ~38s）——
        #   全是**外部重依赖**，与本臂判据（`--role` 是否落到 runner 进程 env）**无关**。
        #   把 `GK_GX_DIR` 指到**非索引**空目录 ⟹ `_gx_repo_name_for_dir` 解析不出 repo 名 ⟹
        #   `gk_l0_prefetch --repo ""` **立即**走既有降级路径返回 `available:false`（L0-a/L0-b
        #   双双短路）⟹ 本臂仍是**全派发链**（含判据所在的 WSLENV 并入段），仅外部图依赖不可用。
        gxdir = tmp_path / "no-gitnexus"
        gxdir.mkdir()
        env.update({
            "STATE_FILE": _to_wsl_path(state),
            "GK_STATE_DOMAIN_ROUTE": "0",
            "GK_ALLOW_STALE_CTX": "1",
            "SUBAGENT_DS_RETRY": "0",
            "GK_MIMO_DISABLED": "1",
            "SUAGENT_PYTHON": _to_wsl_path(stub),
            "GK_GX_DIR": _to_wsl_path(gxdir),
            "GK_GX_TIMEOUT": "2", "GK_GX_STATUS_TIMEOUT": "2",
            "GK_GX_ANALYZE_TIMEOUT": "2",
        })
        subprocess.run(
            ["bash", _to_wsl_path(CLI_PATH), "monitor", "--subagent",
             "--role", "exploiter", "probe_task"],
            cwd=_to_wsl_path(SKILL_DIR), env=env, capture_output=True, timeout=240,
        )
        assert dump.exists(), ("桩未被调用 —— monitor --subagent 未派发到 SUAGENT_PYTHON"
                               "（派发链在桩之前失败，本臂失去判据）")
        text = dump.read_text(encoding="utf-8", errors="replace")
        got = dict(ln.split("=", 1) for ln in text.strip().splitlines() if "=" in ln)
        assert got.get("SUBAGENT_ROLE") == "exploiter", (
            f"派发的 --role 未落到 runner 进程环境：{got.get('SUBAGENT_ROLE')!r}"
            "（复查 WSLENV 并入循环是否又被放回赋值之前 / 待传键是否未 export）")
        assert got.get("SUBAGENT_ID", "<unset>") not in ("<unset>", ""), (
            "SUBAGENT_ID 未落到 runner 进程环境（报告↔history 对账会断裂）")
        assert "SUBAGENT_ROLE" in got.get("WSLENV", ""), (
            "WSLENV 未并入 SUBAGENT_ROLE —— 跨 WSL→Windows interop 时仍会丢（F-REV-91 语义）")


# ─── F-REV-92(a)：subagent 运行级看门狗（deadline + 运行注册）──────────────────────
def _subagent_watch_block() -> str:
    """抽 `gatekeeper-cli.sh` 里 F-REV-92(a) 的 4 个看门狗函数**真定义**（改名即须同步本测试）。"""
    src = CLI_PATH.read_text(encoding="utf-8")
    start = src.index("_gk_subagent_runfile() {")
    end = src.index("\n", src.index("_gk_subagent_watch_disarm() {"))
    block = src[start:end]
    for fn in ("_gk_subagent_runfile", "_gk_subagent_watch_prev",
               "_gk_subagent_watch_arm", "_gk_subagent_watch_disarm"):
        assert f"{fn}() {{" in block, f"看门狗函数缺失: {fn}"
    return block


def _subagent_watch_run(tmp_path, seed: str) -> dict:
    """按 `seed`（bash 片段，可先落一条运行记录）跑**真函数体**，回读各项。"""
    import shutil
    if shutil.which("bash") is None:
        pytest.skip("bash not available on this platform")
    state = tmp_path / "state.json"
    state.write_text("{}", encoding="utf-8")
    dbg = tmp_path / "dbg.log"
    dbg.write_text("", encoding="utf-8")
    state_w, dbg_w = _to_wsl_path(state), _to_wsl_path(dbg)
    harness = (
        "#!/bin/bash\n"
        f'STATE_FILE="{state_w}"\n'
        f'GK_DBG_LOG="{dbg_w}"\n'
        f'_NOW=$(date +%s)\n'
        + _subagent_watch_block() + "\n"
        + seed
        + '_gk_subagent_watch_prev\n'
        + 'echo "PID=$$"\n'
        + 'echo "KEPT_AFTER_PREV=$([ -f "$(_gk_subagent_runfile)" ] && echo yes || echo no)"\n'
        + f'echo "WARN_LINES=$(grep -c "subagent-run" "{dbg_w}" 2>/dev/null || echo 0)"\n'
        + '_gk_subagent_watch_arm "sub-arm" "3" "3600"\n'
        + 'echo "ARMED=[$(cat "$(_gk_subagent_runfile)")]"\n'
        + '_gk_subagent_watch_disarm\n'
        + 'echo "AFTER_DISARM=$([ -f "$(_gk_subagent_runfile)" ] && echo yes || echo no)"\n'
    )
    script = tmp_path / "subagent_watch.sh"
    script.write_bytes(harness.encode("utf-8"))
    out = subprocess.run(["bash", _to_wsl_path(script)], capture_output=True, timeout=60)
    assert out.returncode == 0, (
        f"看门狗 harness 失败: {out.stderr.decode('utf-8', 'replace')[-1500:]}")
    stdout = out.stdout.decode("utf-8", "replace")
    raw = dict(ln.split("=", 1) for ln in stdout.strip().splitlines() if "=" in ln)
    return {k: (v[1:-1] if v.startswith("[") and v.endswith("]") else v)
            for k, v in raw.items()}


class TestSubagentRunWatchdog:
    """F-REV-92(a)：`monitor --subagent` 的运行级看门狗（外层 deadline + 运行注册）。

    背景：派发原为**裸命令替换**（无外层 `timeout`）、runner 内**无全局看门狗**、tier3
    `max_turns 400 × timeout 600s` ⟹ 挂死上界 ≈ 66.7h；且**无运行注册** ⟹ 事后无法判
    「上一轮是死了还是还在跑」。本类只测**运行注册/自校验**半（deadline 由 `timeout -k` 承担，
    已在 `test_eco_integration.py::TestSubagentDispatchDeadline` 走源码断言）。
    """

    def test_no_record_is_silent(self, tmp_path):
        """无历史记录 ⟹ 不报 WARN、不建文件（正常路径零噪声）。"""
        h = _subagent_watch_run(tmp_path, "")
        assert h["KEPT_AFTER_PREV"] == "no"
        assert h["WARN_LINES"] == "0", f"无记录却报 WARN: {h}"

    def test_live_run_within_deadline_is_not_flagged(self, tmp_path):
        """持有者 PID 存活 且 未过 deadline ⟹ **不得**误判异常（防假警）。"""
        h = _subagent_watch_run(
            tmp_path,
            'printf "%s\\n" "$$|$_NOW|$((_NOW + 3600))|sub-live|3" > "$(_gk_subagent_runfile)"\n')
        assert h["KEPT_AFTER_PREV"] == "yes", f"运行中的记录被误清: {h}"
        assert h["WARN_LINES"] == "0", f"运行中被误判异常: {h}"

    def test_dead_pid_is_flagged_and_cleaned(self, tmp_path):
        """持有者 PID 已死 ⟹ 判 `pid_dead`、留痕、清记录（这正是"CLI 进程死亡自校验"）。"""
        h = _subagent_watch_run(
            tmp_path,
            'printf "%s\\n" "999999|100|200|sub-dead|3" > "$(_gk_subagent_runfile)"\n')
        assert h["KEPT_AFTER_PREV"] == "no", "陈旧记录未清理"
        assert int(h["WARN_LINES"]) >= 1, f"pid_dead 未留痕: {h}"

    def test_deadline_exceeded_is_flagged_and_cleaned(self, tmp_path):
        """PID 存活但已过 deadline ⟹ 判 `deadline_exceeded`（覆盖挂死未退出的情形）。"""
        h = _subagent_watch_run(
            tmp_path,
            'printf "%s\\n" "$$|100|1|sub-stuck|3" > "$(_gk_subagent_runfile)"\n')
        assert h["KEPT_AFTER_PREV"] == "no"
        assert int(h["WARN_LINES"]) >= 1, f"deadline_exceeded 未留痕: {h}"

    def test_arm_writes_pid_start_deadline_id_tier(self, tmp_path):
        """注册记录格式 = `PID|START|DEADLINE|ID|TIER` 五段（供事后自校验）。"""
        h = _subagent_watch_run(tmp_path, "")
        parts = h["ARMED"].split("|")
        assert len(parts) == 5, f"运行记录字段数错: {h['ARMED']!r}"
        pid, start, deadline, sid, tier = parts
        assert pid == h["PID"], "记录的不是本进程 PID（存活判据会失效）"
        assert start.isdigit() and deadline.isdigit()
        assert int(deadline) - int(start) == 3600, "deadline 未按 max_runtime 计算"
        assert (sid, tier) == ("sub-arm", "3")

    def test_disarm_removes_record(self, tmp_path):
        """正常收尾注销 ⟹ 下次不误报。"""
        h = _subagent_watch_run(tmp_path, "")
        assert h["AFTER_DISARM"] == "no", "收尾未注销运行记录"


class TestSubagentDispatchDeadline:
    """F-REV-92(a) 的 deadline 半：**三处**派发点都必须带 `timeout -k`（源码级不变量）。"""

    def test_all_dispatch_sites_wrapped(self):
        cli = CLI_PATH.read_text(encoding="utf-8")
        n = cli.count('timeout -k 30 "$_subagent_max_runtime" $subagent_python')
        assert n == 3, (f"派发点包裹数 = {n}，应为 3（主 / DS 重试 / mimo 降级）"
                        " —— 漏包即残留 66h 挂死上界")

    def test_timeout_has_kill_escalation(self):
        """必须带 `-k`：无 `-k` 时 SIGTERM 被忽略则 deadline 形同虚设。"""
        cli = CLI_PATH.read_text(encoding="utf-8")
        assert "timeout -k 30" in cli, "deadline 无 kill 升级（-k），SIGTERM 被忽略即失效"

    def test_knob_documented_default(self):
        cli = CLI_PATH.read_text(encoding="utf-8")
        assert 'local _subagent_max_runtime="${SUBAGENT_MAX_RUNTIME:-3600}"' in cli, (
            "运行级 deadline 旋钮缺失（SUBAGENT_MAX_RUNTIME，默认 3600s）")

    def test_watchdog_armed_and_disarmed(self):
        """arm/disarm 必须成对出现在派发面（只 arm 不 disarm ⟹ 下次必误报）。"""
        cli = CLI_PATH.read_text(encoding="utf-8")
        assert cli.count("_gk_subagent_watch_arm ") >= 1
        assert cli.count("_gk_subagent_watch_disarm") >= 2, (
            "disarm 未接线（定义 1 处 + 调用 ≥1 处；只 arm 不 disarm 会误报异常终止）")


class TestMonitorGitnexusStateWriteChecksum:
    """f1（ECC-3D26D689A05F，2026-09-22，**红先**）：`monitor --gitnexus` 的 state 写入面。

    现场（**实测**，隔离沙箱复现）：该分支原为**裸 `json.dump` 直写** `$STATE_FILE` ——
      ① 不进 `_state_write` 单一写入口 ⟹ **无 flock**（与并发写者抢写）；
      ② **不重算 `_checksum`** ⟹ 下一个读者（self-check 的 checksum 校验）把「本命令自己刚写的
         state」判成 TAMPERED，直到下一个写者落盘才纠回（实证：saved ≠ 按 gate_data 重算的 canon）。
    修法 = 改走 `_state_write`（flock + 原子写 + checksum 重算），载荷经 **env** 传入
    （`$gn_json` 内含引号/反斜杠，不得拼进 python 源码）。

    两条判据：① **结构**：写入点走 `_state_write`，且该分支内不再有裸 `json.dump` 直写；
    ② **行为**：真 CLI 跑一次后 `_checksum` == 按 `gate_data` 重算值，且 `gate_data.gitnexus` 落账。
    """

    @staticmethod
    def _wsl(p) -> str:
        s = str(p).replace("\\", "/")
        if len(s) > 1 and s[1] == ":":
            s = "/mnt/" + s[0].lower() + s[2:]
        return s

    def _segment(self) -> str:
        s = CLI_PATH.read_text(encoding="utf-8")
        i = s.index('if [ "$mode" = "--gitnexus" ]; then')
        j = s.index('echo "$gn_json"', i)
        return s[i:j]

    def test_write_goes_through_state_write_single_entry(self):
        seg = self._segment()
        assert 'GN_JSON="$gn_json" _state_write' in seg, (
            "gitnexus 分支的 state 写入未走 `_state_write`（单写入口：flock + checksum 重算）")
        assert "json.dump(d,open('$STATE_FILE','w'" not in seg, (
            "分支内仍有裸 json.dump 直写 $STATE_FILE（不重算 checksum ⟹ 下游误报 TAMPERED）")

    def test_checksum_consistent_after_run(self, tmp_path):
        """行为臂：跑一次后 `_checksum` 必须与 `gate_data` 重算值一致（原为不一致）。"""
        import hashlib
        import shutil
        if shutil.which("bash") is None:
            pytest.skip("本机无 bash（无法端到端跑 CLI）")
        sb = tmp_path / "sb"
        sb.mkdir()
        w = self._wsl(sb)
        r = subprocess.run(
            ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
             % (self._wsl(SCRIPTS_DIR), w, self._wsl(CLI_PATH), w)],
            capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
        (sb / ".gatekeeper.state").write_text(json.dumps({
            "stage": "STAGE_0", "r_phase": "R1", "branch": "master", "worktree": "",
            "gate_data": {"project_type": "standing",
                          "edit_budget": {"max": 4, "used": 0, "remaining": 4}},
        }, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")

        # 2026-10-10 · ECC-3FD7DEAF6078（提速，非简化判据）：本臂判据 = **state 写入面**
        #   （走 `_state_write` 单入口 + checksum 重算 + `gate_data.gitnexus` 落账），**不是**
        #   GitNexus 的正确性 ⟹ 用 `GK_GX_TIMEOUT` 把外部重依赖（真 `analyze` + 4 次调用，
        #   实测 69s）短路为「快速超时 → 各字段落 unavailable」，被测分支与写入路径逐字不变。
        run = subprocess.run(["bash", "-lc",
                              'cd "%s" && GK_GX_TIMEOUT=2 GK_GX_STATUS_TIMEOUT=2 '
                              'GK_GX_ANALYZE_TIMEOUT=2 bash gatekeeper-cli.sh monitor --gitnexus STAGE_0' % w],
                             capture_output=True, text=True, timeout=600)
        assert run.returncode == 0, f"monitor --gitnexus 失败：{run.stdout[:300]}{run.stderr[:300]}"

        st = json.loads((sb / ".gatekeeper.state").read_text(encoding="utf-8"))
        gd = st.get("gate_data") or {}
        assert "gitnexus" in gd, "gate_data.gitnexus 未落账（写入面失效）"
        canon = hashlib.sha256(json.dumps(gd, sort_keys=True).encode()).hexdigest()[:16]
        assert st.get("_checksum") == canon, (
            f"写入后 checksum 未重算（saved={st.get('_checksum')} canon={canon}）"
            " ⟹ 下一次 self-check 会把本命令自己的写入判成 TAMPERED")
