#!/usr/bin/env python3
"""R16 基线新态 `reusable` 修复批 —— 七臂红先测试（文件 2/2：臂 6-7）。

配套文件 1 = `test_r16_baseline_reusable_state.py`（臂 1-5）。夹具三份真实样本的定义与出处
见该文件 docstring（本文只复用它需要的 2 份：COMMIT_BEHIND / CONTENT_DIFF）。

臂 6 [RED]  crossrev preflight B：`reusable` ⟹ **零 analyze + 零 degrade 警告**（修前落 else ⟹ degrade 警告）；
              并同时落「`stale` 才 analyze」的收紧条件（修前无条件…见红先合取项）。
臂 7 [RED]  九消费点一致性钉：`_run_gitnexus status` 的**直调**必须收敛到单点
              （8 处直调 / 7 个位置：`_collect_hard_evidence` 两支含 **fail-open** · `cmd_monitor`
              STAGE_5 退休支 · `cmd_monitor` ECO 健康支 · `_collect_advance_env` 两分支 ·
              `_write_gate_data` STAGE_3（把 status stdout **当 JSON** 解析）· `cmd_self_check`）。

⚠ 臂 7 为**结构性钉**（计数/形态），非行为臂 —— 如实声明，不冒充行为验证：
   其覆盖的 7 个位置分散在巨型函数体内（`cmd_monitor` / `_write_gate_data` / `cmd_self_check`），
   逐处抽取真函数体的成本与脆性都不可接受；行为面由臂 1-6 承担。
   结构性钉的价值 = 每次跑 CI 都能机检「单点收编未回退」，这正是 H4（"单点"声明不成立）的反面钉子。
"""
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI = SKILL_DIR / "gatekeeper-cli.sh"
sys.path.insert(0, str(SCRIPT_DIR))

STATUS_FN = "_gitnexus_baseline_status"

# 与文件 1 同源的真实样本（`_gxstatus2.txt` / `_gxstatus.txt`，此处仅保留判据相关行）
COMMIT_BEHIND = (
    "索引提交: ebcd3f1\n"
    "当前提交: 59dfa5b\n"
    "状态: ⚠️ 已过期（重新运行 gitnexus analyze）\n"
)
CONTENT_DIFF = (
    "索引提交: ebcd3f1\n"
    "当前提交: ebcd3f1\n"
    "索引内容：2 个已修改，0 个新增，0 个已删除\n"
    "  已修改: references/subagent-context.json\n"
    "状态: ⚠️ 已过期（重新运行 gitnexus analyze）\n"
)

B_START = "# ── B: L3 基线 status-fresh 复用"
B_END = "# ── C: 节点绑定"


def _wsl(p) -> str:
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _code_lines(src: str):
    """只取**可执行**行 —— 注释里叙述 `_run_gitnexus status` 不算直调点（同既有测试约定）。"""
    return [l for l in src.splitlines() if not l.lstrip().startswith("#")]


_RE_BASH_STR = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")


def _brace_delta(line: str) -> int:
    """行内花括号**净增量** —— 先剥离引号字符串与注释，再计数（2026-10-31）。

    原实现直接 `line.count("{") - line.count("}")` ⟹ 被两类**字面量**击穿（实测）：
      · 注释里的 `` `}` `` 与 `{SearchReplace, Write, …}`（`pre_tool_check` 头注）；
      · Python heredoc 里的 `if not line.startswith("{"):`
        （`_gitnexus_baseline_status` 解析 `status --json` 时跳过 banner 行）。
    后者的 `"{"` 使该函数 depth 恒 +1 ⟹ 扫描越过函数体直到文件尾（depth=-9）⟹
    `test_arm7_status_calls_single_sourced` / `test_arm7d_single_point_produces_reusable`
    两个臂误报「抽取失败」（此时被测代码本身语法正确、功能正常）。
    """
    s = _RE_BASH_STR.sub("", line)     # 先剥字符串（`#` 可能在字符串内）
    s = s.split("#", 1)[0]             # 再剥注释
    return s.count("{") - s.count("}")


def _extract_function(src: str, name: str) -> str:
    lines = src.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith(name + "() {")), None)
    assert start is not None, f"{name} 未定义"
    depth = 0
    for i in range(start, len(lines)):
        depth += _brace_delta(lines[i])
        if depth == 0:
            return "\n".join(lines[start:i + 1])
    raise AssertionError(f"{name} 花括号不配对（抽取失败）")


def _extract_block(src: str, start_marker: str, end_marker: str) -> str:
    """按两处注释标记抽取代码块（含 start_marker 行；到 end_marker 前一行止）。"""
    lines = src.splitlines()
    s = next((i for i, l in enumerate(lines) if start_marker in l), None)
    assert s is not None, f"起始标记未找到：{start_marker}（片段提取失败 ⟹ fail-loud）"
    e = next((i for i in range(s + 1, len(lines)) if end_marker in lines[i]), None)
    assert e is not None, f"结束标记未找到：{end_marker}"
    return "\n".join(l for l in lines[s:e] if l.strip())


# ── 臂 6 ──────────────────────────────────────────────────────────────────────
def _run_preflight_b(tmp_path: Path, status_value: str, channel: str = "crossrev"):
    """抽取真 preflight B 块 → 以桩驱动；返回 (analyze 调用数, 输出)。

    ⚠ 桩 **直接回三/四态值**（`current|stale|unavailable`，或修复后新增的 `reusable`），
    而非回原始 status 文本 —— 否则 `[ "$gn_status" = "stale" ]` 拿整段文本比较恒不等，
    红因会错位到"文本不等于 stale"而非"消费点不认新值"（本文件首轮即踩此坑，留痕）。

    2026-11-02（owner 裁定）后语义分通道：plan-refinement 的 stale 改 **advisory 放行**
    （不再 analyze）、unavailable 才阻断；crossrev 维持 WARN。故 `channel` 可注入。
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    src = CLI.read_text(encoding="utf-8")
    block = _extract_block(src, B_START, B_END)
    helper = _extract_function(src, "_gitnexus_refresh_if_stale")
    w = _wsl(tmp_path)
    (tmp_path / "calls.txt").write_text("", encoding="utf-8")
    h = tmp_path / "preflight.sh"
    h.write_text("\n".join([
        "#!/usr/bin/env bash",
        'RG="$(command -v rg || echo rg)"',
        'GK_DBG_LOG="%s/dbg.log"' % w,
        'CALLS_FILE="%s/calls.txt"' % w,
        ': > "$GK_DBG_LOG"; : > "$CALLS_FILE"',
        'channel="%s"' % channel,
        '_gx_repo_dir_for_current() { echo "%s/repo"; }' % w,
        '%s() { echo "%s"; }' % (STATUS_FN, status_value),
        "_run_gitnexus() { printf '%s\\n' \"$*\" >> \"$CALLS_FILE\"; return 0; }",
        helper,
        '_gx_analyze_embeddings() { _run_gitnexus analyze "$1"; }',
        "",
        "_under_test() {",
        block,
        "}",
        "_under_test",
    ]), encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", _wsl(h)], capture_output=True, text=True, timeout=60)
    calls = [l for l in (tmp_path / "calls.txt").read_text(encoding="utf-8").splitlines()
             if l.strip()]
    return [c for c in calls if "analyze" in c], r.stdout + r.stderr


def test_arm6_preflight_reusable_no_analyze_no_degrade(tmp_path):
    """[RED] preflight B：`reusable` ⟹ **零 analyze、零 degrade 警告**（复用增量基线）。

    修前：`reusable` 既非 current 也非 stale ⟹ 穿透到 `else` ⟹ 打出
    `gitnexus status unavailable — degrade (L3 图级证据降级)` 并降级审查面 ——
    状态其实**是好的**（内容一致），却被当成"探测不可用"降级（判据指向错误方向，同 H3 族）。
    """
    ana, out = _run_preflight_b(tmp_path, "reusable")
    assert ana == [], f"reusable 应复用增量基线、不得 analyze，实跑 {ana}"
    assert "degrade" not in out, f"reusable 被误判为不可用并降级：{out[:400]}"


def test_arm6b_preflight_stale_still_analyzes(tmp_path):
    """[CTRL] plan-refinement：stale 改 advisory 放行（2026-11-02 owner 裁定），
    不再 analyze；必须留痕（不得静默）。"""
    ana, out = _run_preflight_b(tmp_path, "stale", channel="plan-refinement")
    assert ana == [], f"stale 已改 advisory，不得再触发 analyze，实跑 {ana}"
    assert "advisory" in out, f"stale 放行未留痕：{out[:400]}"


def test_arm6c_preflight_unavailable_degrades_only(tmp_path):
    """[CTRL] plan-refinement：unavailable 才阻断（BASELINE_UNAVAILABLE），不 analyze。"""
    ana, out = _run_preflight_b(tmp_path, "unavailable", channel="plan-refinement")
    assert ana == [], f"探测失败不得 analyze，实测 {ana}"
    assert "BASELINE_UNAVAILABLE" in out, f"unavailable 未显式阻断：{out[:400]}"


# ── 臂 7 ──────────────────────────────────────────────────────────────────────
def test_arm7_status_calls_single_sourced():
    """[RED] `_run_gitnexus status` 直调必须全部收敛到单点 `_gitnexus_baseline_status`。

    修前实测：**8 处直调 / 7 个位置**（`_collect_hard_evidence` 两支 · `cmd_monitor` 两支 ·
    `_collect_advance_env` 两支 · `_write_gate_data` STAGE_3 · `cmd_self_check`）⟹
    C2′ 落刀后同仓同时刻会并存两套"基线新鲜"口径（讲多源、却造新多源 = H4）。
    """
    src = CLI.read_text(encoding="utf-8")
    body = _extract_function(src, STATUS_FN)
    total = sum(l.count("_run_gitnexus status") for l in _code_lines(src))
    inside = sum(l.count("_run_gitnexus status") for l in _code_lines(body))
    assert total == inside, (
        f"单点外仍存 `_run_gitnexus status` 直调（应全部收编）：全文可执行行 {total} 处 / 单点体内 {inside} 处")


def test_arm7b_no_fail_open_on_status_exit_code():
    """[RED] 禁 fail-open：不得以 `_run_gitnexus status >/dev/null` 的**退出码**判 current。

    修前形态（`_collect_hard_evidence`）：`status` 是**信息性命令**，stale 时退出码仍为 0
    ⟹ `>/dev/null 2>&1) && 判 current` 恒真 ⟹ 把过期索引报成 `current`（假绿，与 F-REV-84 同族）。
    """
    src = CLI.read_text(encoding="utf-8")
    bad = [l.strip() for l in _code_lines(src) if "_run_gitnexus status >/dev/null" in l]
    assert bad == [], f"存在 fail-open 形态（退出码代替状态判读）：{bad}"


def test_arm7c_status_stdout_not_parsed_as_json():
    """[RED] 禁把 `gitnexus status` 的**文本 stdout 当 JSON** 解析。

    修前形态（`_write_gate_data` STAGE_3）：`status | python3 -c "json.loads(...)"` ——
    真 status 是**彩色文本**（`索引提交: …` / `状态: …`）⟹ 解析必失败 ⟹ 恒落空 dict
    ⟹ `gate_data.gitnexus_baseline` 四个维度**永远为空**（静默降级）。
    """
    src = CLI.read_text(encoding="utf-8")
    lines = _code_lines(src)
    idx = [i for i, l in enumerate(lines) if "_run_gitnexus status" in l]
    offenders = []
    for i in idx:
        # 窗口取 6 行：管道 + `python3 -c "` 后的正文常有 import/try 两行再落 json.loads
        window = "\n".join(lines[i:i + 6])
        if re.search(r"status[^\n]*\|\s*python3", window) or "json.loads(" in window:
            offenders.append(window.strip()[:200])
    assert offenders == [], f"status 文本被当 JSON 解析（维度恒空）：{offenders}"


def test_arm7d_single_point_produces_reusable():
    """[RED] 新态 `reusable` 必须由单点产出（`_gitnexus_baseline_status` 体内出现该字面量）。

    这条与臂 1 互为内外：臂 1 打行为（输入 → 输出），本钉打**归属**（新态由单点定义，
    不得在消费点各自造态 —— 否则重演多源）。
    """
    body = _extract_function(CLI.read_text(encoding="utf-8"), STATUS_FN)
    assert "reusable" in body, "新态 reusable 未由单点产出（消费点各自造态 = 多源）"


# ── 臂 8 ──────────────────────────────────────────────────────────────────────
S5_START = "# P2: GitNexus status — verify index is current before retirement"
S5_END = """elif echo "$stage" | "$RG" -q '^ECO-'"""


def _run_pre_retire(tmp_path: Path, status_value: str):
    """抽取真 `cmd_monitor` 的 STAGE_5 退休支块 → 桩驱动 → 返回 (checks 文本, passed)。"""
    tmp_path.mkdir(parents=True, exist_ok=True)
    block = _extract_block(CLI.read_text(encoding="utf-8"), S5_START, S5_END)
    w = _wsl(tmp_path)
    h = tmp_path / "retire.sh"
    h.write_text("\n".join([
        "#!/usr/bin/env bash",
        'RG="$(command -v rg || echo rg)"',
        'GK_DBG_LOG="%s/dbg.log"' % w,
        ': > "$GK_DBG_LOG"',
        'checks=""; passed=0',
        '_gx_repo_dir_for_current() { echo "%s/repo"; }' % w,
        '%s() { echo "%s"; }' % (STATUS_FN, status_value),
        "",
        "_under_test() {",
        block,
        "}",
        "_under_test",
        'printf "OUT=%s\\n" "$checks"',
        'printf "PASSED=%s\\n" "$passed"',
    ]), encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", _wsl(h)], capture_output=True, text=True, timeout=60)
    out = r.stdout + r.stderr
    m = re.search(r"^OUT=(.*)$", out, re.M)
    assert m, f"STAGE_5 块未输出 OUT：{out[:500]}"
    p = re.search(r"^PASSED=(\d+)$", out, re.M)
    return m.group(1).strip(), (int(p.group(1)) if p else -1)


def test_arm8_stage5_pre_retire_no_fail_open(tmp_path):
    """[RED] STAGE_5 退休支：探测失败（`unavailable`）**不得**报 PASS「index current」。

    修前写法 = `gn_retire_status=$(… || echo "unavailable")` + `if echo … | rg -q "stale"` ⟹
    **只要文本不含 "stale" 就 PASS**，把"未出现 stale"当成"已验证是 current" ⟹ 未验证却报绿
    （fail-open）。修后：`stale` → FAIL（真过期）；`unavailable` → **WARN**（未验证，不阻断退休）；
    `current|reusable` → PASS。与同文件 `cmd_self_check` / ECO 支口径一致。
    """
    un, passed_un = _run_pre_retire(tmp_path / "a", "unavailable")
    assert '"status":"WARN"' in un, f"探测失败须 WARN（未验证不得报绿），实得 {un}"
    assert '"status":"PASS"' not in un, f"探测失败不得报 PASS（fail-open）：{un}"
    assert passed_un == 0, f"WARN 不应计入 passed，实得 {passed_un}"

    st, _ = _run_pre_retire(tmp_path / "b", "stale")
    assert '"status":"FAIL"' in st, f"真过期须 FAIL，实得 {st}"

    for ok in ("current", "reusable"):
        s, passed = _run_pre_retire(tmp_path / ("c" + ok), ok)
        assert '"status":"PASS"' in s and passed == 1, f"{ok} 须 PASS，实得 {s} passed={passed}"
