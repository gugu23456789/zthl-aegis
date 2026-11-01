#!/usr/bin/env python3
"""PROTECTED_REGION 行级判定在**自动拦截路径**的语义（红先谱系：ECC-BFE933526D0B → owner 裁定 A）。

历史：ECC-BFE933526D0B（2026-09-22）把 `_protected_region_check` 的行级分支从「恒不可达」修成
「行级 BLOCK」，并补 hook 的多行行号通路（`_protected_target_line`）。

**现行（owner 裁定 A，2026-09-27，裁决记录 `ECC-D6115EC0C74D`）**：行级 **BLOCK → WARN + 强制留痕**
（放行 rc=0，同时 append `${STATE_FILE}.protected-edits.jsonl` 审计记录）—— 使 owner 授权的落刀
不必人工手敲。文件级（无有效行号）语义不变（F-REV-45，2026-09-13：WARN 放行）。

判据（五臂）：
  ① **行级命中**保护区 → 放行（rc=0）**且**写审计 JSONL（region 名可查）—— 裁定 A 前为 BLOCK；
  ② **行级在保护区外** → 放行（rc=0，且**不**写审计）；
  ③ **无行号（2 参形态）** → 仍为文件级 WARN 放行（**F-REV-45 语义不回退**）；
  ④ 多行入参「首行区外 + 次行区内」→ 放行 + 留痕（逐行判仍生效，只是判决由 BLOCK 降为 WARN）；
  ⑤ 多行入参全部在区外 → 放行（防过度修复）。

做法：与 f8 同形的最小沙箱（`scripts` 软链 + CLI 实拷 + 最小 standing state）。
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SKILL_DIR / "gatekeeper-cli.sh"))


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _sandbox(root: Path) -> Path:
    """最小技能根：`scripts` 软链 + CLI 实拷 + 最小 standing state（stage 非 IDLE/DONE）。"""
    sb = (root / "sb").resolve()
    sb.mkdir(parents=True)
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), w, _wsl(CLI_SRC), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    (sb / ".gatekeeper.state").write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1", "branch": "master", "worktree": _wsl(sb),  # §17-6-P4：显式 root
        "gate_data": {
            "project_type": "standing",
            "edit_budget": {"max": 4, "used": 0, "remaining": 4, "overrides": []},
            "scheduler": {"mode": "constant", "max_lr": 4, "min_lr": 1,
                          "total_steps": 6, "current_step": 1, "current_lr": 4},
        },
    }, ensure_ascii=False), encoding="utf-8", newline="\n")
    return sb


def _cli_run(sb: Path, *args: str):
    """在沙箱里跑一次 `pre-tool-check <args...>`（不经 `bash -c` 传载荷）。"""
    w = _wsl(sb)
    argv = " ".join('"%s"' % a for a in args)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check %s' % (w, argv)],
        capture_output=True, text=True, timeout=120)


def _out(r) -> str:
    return (r.stdout or "") + (r.stderr or "")


def _region_line(sb: Path) -> int:
    """沙箱 CLI 内 `declare -A _CMD_REG` 所在行 —— 必在 `PROTECTED_REGION::gate` 内。"""
    txt = (sb / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    for i, ln in enumerate(txt.split("\n"), 1):
        if "declare -A _CMD_REG" in ln:
            return i
    raise AssertionError("沙箱 CLI 内未找到 `declare -A _CMD_REG`")


@pytest.fixture()
def sandbox():
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下 pre_tool_check 无法执行）")
    root = Path(tempfile.mkdtemp(prefix="gk_pr_region_"))
    try:
        yield _sandbox(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _audit(sb: Path) -> Path:
    """行级命中留痕文件（`${STATE_FILE}.protected-edits.jsonl`；裁定 A）。"""
    return sb / ".gatekeeper.state.protected-edits.jsonl"


def test_line_inside_region_is_allowed_but_audited(sandbox):
    """判据①：行级命中保护区 → 放行（rc=0）+ 强制留痕（owner 裁定 A，2026-09-27）。"""
    line = _region_line(sandbox)
    r = _cli_run(sandbox, "SearchReplace", _wsl(sandbox / "gatekeeper-cli.sh"), str(line))
    out = _out(r)
    assert r.returncode == 0, f"行级命中保护区被拦（裁定 A：应收敛为 WARN 放行）：{out[:300]}"
    audit = _audit(sandbox)
    assert audit.is_file(), "行级命中未写审计 JSONL（留痕缺失）"
    txt = audit.read_text(encoding="utf-8")
    assert '"region":"gate"' in txt, f"审计记录未标 region：{txt[:300]}"


def test_line_outside_region_is_allowed(sandbox):
    """判据②：行级在保护区外 → 放行（rc=0，且**不**写审计）。"""
    r = _cli_run(sandbox, "SearchReplace", _wsl(sandbox / "gatekeeper-cli.sh"), "3")
    out = _out(r)
    assert r.returncode == 0, f"保护区外行被误伤：{out[:300]}"
    assert not _audit(sandbox).is_file(), "区外行误写审计（留痕应只记命中）"


def test_no_line_keeps_frev45_file_level_warn(sandbox):
    """判据③：无行号（2 参 hook 形态）→ 仍放行（F-REV-45「文件级 WARN」语义不回退）。"""
    r = _cli_run(sandbox, "SearchReplace", _wsl(sandbox / "gatekeeper-cli.sh"))
    out = _out(r)
    assert r.returncode == 0, f"F-REV-45 文件级放行被破坏：{out[:300]}"


def test_multiline_second_in_region_is_allowed_but_audited(sandbox):
    """判据④（R25 洞口补漏 × 裁定 A）：多行入参「首行区外 + 次行区内」→ 放行 + 留痕。

    修前（ECC-BFE933526D0B 前）：`_protected_region_check` 只做**单值**数值比较，逗号串
    `3,<region>` 作为整体非数字 ⟹ 区间比较双双失败 ⟹ fail-open。修后：逐行判，任一行命中即判。
    裁定 A（2026-09-27）后判决由 BLOCK 降为 WARN + 留痕，故此处断言放行 + 审计存在。
    """
    line = _region_line(sandbox)
    r = _cli_run(sandbox, "SearchReplace", _wsl(sandbox / "gatekeeper-cli.sh"), f"3,{line}")
    out = _out(r)
    assert r.returncode == 0, f"多行入参次行命中保护区被拦（裁定 A：应收敛为 WARN 放行）：{out[:300]}"
    audit = _audit(sandbox)
    assert audit.is_file() and '"region":"gate"' in audit.read_text(encoding="utf-8"), \
        "多行次行命中未留痕"


def test_multiline_all_outside_region_is_allowed(sandbox):
    """判据⑤（防过度修复）：多行入参全部在区外 → 放行。"""
    r = _cli_run(sandbox, "SearchReplace", _wsl(sandbox / "gatekeeper-cli.sh"), "3,5,7")
    out = _out(r)
    assert r.returncode == 0, f"多行全在区外被误伤：{out[:300]}"


class TestProtectedTargetLines:
    """hook 侧行号提取：必须回**全部**命中行（R25 洞口补漏）。

    洞：原 `_protected_target_line` 只回「首个匹配行 / 首个差异行」⟹ 与判据④同因但更上游——
    整文件重写时若首行差异在区外，后续差异行**根本不进 CLI** ⟹ 即便 CLI 支持多行也无从判定。
    """

    @staticmethod
    def _hook():
        import sys
        sys.path.insert(0, str(SCRIPT_DIR))
        import pre_tool_hook
        return pre_tool_hook

    def test_searchreplace_returns_whole_replaced_span(self, tmp_path, monkeypatch):
        m = self._hook()
        f = tmp_path / "x.sh"
        f.write_text("a\nb\nc\nd\ne\n", encoding="utf-8")
        monkeypatch.setattr(m, "_host_form", lambda p: str(p))
        got = m._protected_target_line(
            "SearchReplace", {"old_str": "c", "new_str": "C1\nC2\nC3"}, str(f))
        assert got == "3,4,5", got

    def test_write_returns_all_diff_lines(self, tmp_path, monkeypatch):
        m = self._hook()
        f = tmp_path / "x.sh"
        f.write_text("a\nb\nc\nd\ne\n", encoding="utf-8")
        monkeypatch.setattr(m, "_host_form", lambda p: str(p))
        got = m._protected_target_line("Write", {"content": "a\nB\nc\nd\nE\n"}, str(f))
        assert got == "2,5", got

    def test_write_identical_content_returns_zero(self, tmp_path, monkeypatch):
        m = self._hook()
        f = tmp_path / "x.sh"
        f.write_text("a\nb\n", encoding="utf-8")
        monkeypatch.setattr(m, "_host_form", lambda p: str(p))
        got = m._protected_target_line("Write", {"content": "a\nb\n"}, str(f))
        assert got == "0", got


class TestHostConfigProtected:
    """宿主配置保留集（2026-09-29，owner 裁定 A′，相位 `R-HOSTCFG`）。

    判据（三臂，全部走 `pre-tool-check` = hook Gate 4 的**实际拦截点**）：
      ① `mcp.json` → **WARN + 强制留痕**：放行（rc=0）**且**写 `${STATE_FILE}.protected-edits.jsonl`
         且 `region=HOST-CONFIG` —— 使 owner 在移动端也能由 agent 代改 MCP 配置，但可审计；
      ② `hooks.json` → **BLOCK**（rc≠0）—— 它是**门禁本体**（Trae `PreToolUse` 注册表），
         被治理者不得自拆门禁（改它 = 关掉本 hook = 治理自毁）；
      ③ 普通 `.json` → 不受影响（防误伤）。

    夹具：复用 `_sandbox()`，但把 state 的 `worktree` **覆写为沙箱路径** —— 否则目标路径落在
    活动写面外，会被 `PATH_NOT_IN_ACTIVE_SURFACE` **抢先拦** ⟹ arm-2 会「假绿」（拦是拦了，但拦错点）。
    故 arm-2 额外断言输出**不含** `PATH_NOT_IN_ACTIVE_SURFACE`。
    """

    @staticmethod
    def _in_surface(root: Path) -> Path:
        sb = _sandbox(root)
        st = sb / ".gatekeeper.state"
        data = json.loads(st.read_text(encoding="utf-8"))
        data["worktree"] = _wsl(sb)
        st.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8", newline="\n")
        return sb

    @pytest.fixture()
    def sandbox(self):
        if shutil.which("bash") is None:
            pytest.skip("本机无 bash（Windows 语义下 pre_tool_check 无法执行）")
        root = Path(tempfile.mkdtemp(prefix="gk_hostcfg_"))
        try:
            yield self._in_surface(root)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_arm1_mcp_json_allowed_and_audited(self, sandbox):
        """arm-1（**红臂**）：`mcp.json` → 放行 + 强制留痕（region=HOST-CONFIG）。"""
        r = _cli_run(sandbox, "Write", _wsl(sandbox / "mcp.json"))
        out = _out(r)
        assert r.returncode == 0, f"mcp.json 被拦（应 WARN 放行）：{out[:300]}"
        assert "BLOCK" not in out, f"mcp.json 被 BLOCK：{out[:300]}"
        audit = _audit(sandbox)
        assert audit.is_file(), "mcp.json 放行但未写审计 JSONL（宿主配置留痕缺失）"
        txt = audit.read_text(encoding="utf-8")
        assert '"region":"HOST-CONFIG"' in txt, f"审计未标 region=HOST-CONFIG：{txt[:200]}"

    def test_arm2_hooks_json_blocked_by_this_rule(self, sandbox):
        """arm-2（**红臂**）：`hooks.json`（门禁本体）→ BLOCK，且必须由**本规则**拦。"""
        r = _cli_run(sandbox, "Write", _wsl(sandbox / "hooks.json"))
        out = _out(r)
        assert r.returncode != 0, f"hooks.json（门禁本体）未被拦：{out[:300]}"
        assert "BLOCK" in out, f"未出现 BLOCK：{out[:300]}"
        assert "PATH_NOT_IN_ACTIVE_SURFACE" not in out, \
            f"被写面闸抢先拦（夹具 worktree 未覆写 ⟹ 测错点）：{out[:300]}"

    def test_arm3_plain_json_unaffected(self, sandbox):
        """arm-3（**负臂**）：普通 `.json` 不得被误保护（防 `case` 匹配写宽）。"""
        r = _cli_run(sandbox, "Write", _wsl(sandbox / "notes.json"))
        out = _out(r)
        assert r.returncode == 0, f"普通 json 被误拦：{out[:300]}"
        assert not _audit(sandbox).is_file(), "普通 json 误写宿主配置留痕（匹配过宽）"

    def test_arm4_settings_json_allowed_and_audited(self, sandbox):
        """arm-4（**红臂**，2026-09-29 owner 裁定「1 纳入加留痕」）：`settings.json` →
        放行 + 强制留痕（region=HOST-CONFIG）—— 同 `mcp.json` 档（含明文 token / 宿主行为开关）。"""
        r = _cli_run(sandbox, "Write", _wsl(sandbox / "settings.json"))
        out = _out(r)
        assert r.returncode == 0, f"settings.json 被拦（应 WARN 放行）：{out[:300]}"
        assert "BLOCK" not in out, f"settings.json 被 BLOCK：{out[:300]}"
        audit = _audit(sandbox)
        assert audit.is_file(), "settings.json 放行但未写审计 JSONL（宿主配置留痕缺失）"
        assert '"region":"HOST-CONFIG"' in audit.read_text(encoding="utf-8"), \
            "审计未标 region=HOST-CONFIG"

    def test_arm5_settings_json_bak_allowed_and_audited(self, sandbox):
        """arm-5（**红臂**）：`settings.json.bak_*`（宿主自动备份，同样可能含 token）→ 同档留痕。"""
        r = _cli_run(sandbox, "Write", _wsl(sandbox / "settings.json.bak_20260101"))
        out = _out(r)
        assert r.returncode == 0, f"settings.json.bak_* 被拦（应 WARN 放行）：{out[:300]}"
        assert "BLOCK" not in out, f"settings.json.bak_* 被 BLOCK：{out[:300]}"
        audit = _audit(sandbox)
        assert audit.is_file(), "settings.json.bak_* 放行但未写审计 JSONL"
        assert '"region":"HOST-CONFIG"' in audit.read_text(encoding="utf-8"), \
            "审计未标 region=HOST-CONFIG"

    def test_arm6_settings_lookalike_unaffected(self, sandbox):
        """arm-6（**负臂**）：`settings.json` 的**相似名**不得被误保护（防 `case` 匹配写宽）。"""
        for name in ("my-settings.json", "settings.jsonx", "xsettings.json.bak"):
            r = _cli_run(sandbox, "Write", _wsl(sandbox / name))
            out = _out(r)
            assert r.returncode == 0, f"{name} 被误拦：{out[:300]}"
        assert not _audit(sandbox).is_file(), "相似名误写宿主配置留痕（匹配过宽）"
