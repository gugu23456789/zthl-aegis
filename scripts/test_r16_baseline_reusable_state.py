#!/usr/bin/env python3
"""R16 基线新态 `reusable` 修复批 —— 七臂红先测试（文件 1/2：臂 1-5）。

落点：worktree `standing/xenv-form-fix`（**A 未合并** ⟹ 天然满足 R6 的「A 缺席」前提，见文件 2）。

背景（实测留痕，2026-09-21）：
  `_gitnexus_baseline_status` 判 stale 有**两个独立维度**：
    ① 索引快照 vs 工作树内容（A 已修：运行期产物脱离 tracked）
    ② **索引提交 ≠ 当前提交**（A/B 均无解）⟹ R 序列推进**必然产生提交**
       ⟹ 推进阶段 `baseline_status=current` 恒不可满足（只在 analyze 之后、下一次提交之前成立）
  修法 C2′ = 增第三态 `reusable`（**内容一致、仅 commit 落后**），并让全部消费点认它。

三份夹具 = **真实样本逐字回放**（非构造文案；观测条件见 2026-09-21-review-runtime-subplan §3.1）：
  FRESH         ← `_gxstatus3.txt`（索引提交 = 当前提交 = 59dfa5b / `索引内容：与覆盖的全部 558 个文件一致` / `✅ 已是最新`）
  COMMIT_BEHIND ← `_gxstatus2.txt`（`ebcd3f1` **≠** `59dfa5b` / **`索引内容` 段落整段缺失** / `⚠️ 已过期`）
  CONTENT_DIFF  ← `_gxstatus.txt` （`ebcd3f1` = `ebcd3f1` / `索引内容：2 个已修改，0 个新增，0 个已删除` / `⚠️ 已过期`）

七臂与红先角色（`[RED]` = 修前必失败；`[CTRL]` = 防降级对照行）：
  臂1 [RED]  commit-behind-only → `reusable`（修前落 `stale`）
  臂2 [RED]  真 fresh 仍 `current`（对照行）+ commit-behind → `reusable`（红先合取项）
  臂3 [RED]  真 content-diff 仍 `stale`（对照行）+ commit-behind → `reusable`（红先合取项）
  臂4 [RED]  `_gitnexus_ensure_baseline` 对 `reusable` **复用、零 analyze**（修前 analyze 1 次 → `failed`）
  臂5 [RED]  python 侧值域白名单：`baseline_status="reusable"` 不得报「未注入」；
             且 `{"baseline": true}` 无 status **必须判缺**（废 bool —— 修前该组合是**假绿**：ok=True）

红先纪律：`[CTRL]` 行**不与新态行同表断言即不成立**（对照臂单独断言则修前也绿 = 假绿）。

⚠ 未覆盖（如实登记，不假装已验）：真实 gitnexus 二进制**不参与**本文件 —— `_run_gitnexus`
  以桩替换、只回放上述三份逐字样本。被测函数体由本文件从 `gatekeeper-cli.sh` **按花括号
  配对抽取**（同 `test_gx_analyze_embeddings_selfheal.py` 约定），故与入库代码逐字节同源。
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI = SKILL_DIR / "gatekeeper-cli.sh"

sys.path.insert(0, str(SCRIPT_DIR))

STATUS_FN = "_gitnexus_baseline_status"
ENSURE_FN = "_gitnexus_ensure_baseline"

# ── 夹具模式（2026-11-01 起 `status --json` 是唯一判据面）────────────────────
# 原三份中文文本样本已被结构化 JSON 取代（语言无关）。内容差异用 `incompleteReasons`；
# commit-behind 的 reusable 判据用**真实临时 git 仓**（只改非代码文件 ⟹ diff 计数 0）。
FRESH = "fresh"
COMMIT_BEHIND = "commit_behind"
CONTENT_DIFF = "content_diff"
EMPTY = "empty"
NOT_INDEXED = "not_indexed"


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`bash` 在这里是 WSL bash，喂 `C:\\...` 会被当相对文件名）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


_RE_BASH_STR = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")


def _brace_delta(line: str) -> int:
    """行内花括号净增量 —— 先剥离引号字符串与注释再计数。

    原实现直接 `line.count("{") - line.count("}")` 被字面量击穿：函数体内的
    `if not line.startswith("{"):`（解析 status --json 时跳过 banner 行）使 depth
    恒 +1 ⟹ 抽取越过文件尾。本文件与 `test_r16_status_consumers._brace_delta` 同判据。
    """
    s = _RE_BASH_STR.sub("", line)
    s = s.split("#", 1)[0]
    return s.count("{") - s.count("}")


def _extract_function(src: str, name: str) -> str:
    """按花括号配对抽取 `name() { ... }` 全文；找不到 → AssertionError（= 修前形态即红）。"""
    lines = src.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith(name + "() {")), None)
    assert start is not None, f"{name} 未定义"
    depth = 0
    for i in range(start, len(lines)):
        depth += _brace_delta(lines[i])
        if depth == 0:
            return "\n".join(lines[start:i + 1])
    raise AssertionError(f"{name} 花括号不配对（抽取失败）")


def _probe_status(tmp_path: Path, mode: str) -> str:
    """建真实临时 git 仓 + JSON status 样本，驱动真 `_gitnexus_baseline_status`。

    · fresh      → index/current 同提交；
    · commit_behind → index 落后 c1、current=c2，且 c1→c2 只改非代码文件 ⟹ diff 计数 0；
    · content_diff  → `incompleteReasons` 非空 ⟹ stale；
    · empty      → 探测器无输出 ⟹ unavailable。
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)

    def g(*a):
        return subprocess.run(["git", "-C", str(repo), *a], capture_output=True,
                              text=True, check=True).stdout.strip()

    g("init", "-q")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    (repo / "a.py").write_text("print(1)\n", encoding="utf-8")
    g("add", "a.py")
    g("commit", "-qm", "c1")
    c1 = g("rev-parse", "HEAD")
    (repo / "README.md").write_text("doc\n", encoding="utf-8")
    g("add", "README.md")
    g("commit", "-qm", "c2")
    c2 = g("rev-parse", "HEAD")

    text = ""
    if mode == FRESH:
        text = json.dumps({"index": {"commit": c2, "incompleteReasons": []},
                           "current": {"commit": c2}})
    elif mode == COMMIT_BEHIND:
        text = json.dumps({"index": {"commit": c1, "incompleteReasons": []},
                           "current": {"commit": c2}})
    elif mode == CONTENT_DIFF:
        text = json.dumps({"index": {"commit": c1,
                                     "incompleteReasons": ["content mismatch"]},
                           "current": {"commit": c1}})
    elif mode == NOT_INDEXED:
        text = json.dumps({"error": "not-indexed"})
    w = _wsl(tmp_path)
    (tmp_path / "status.txt").write_text(text, encoding="utf-8")
    h = tmp_path / "probe.sh"
    h.write_text("\n".join([
        "#!/usr/bin/env bash",
        'RG="$(command -v rg || echo rg)"',
        'GK_DBG_LOG="%s/dbg.log"' % w,
        ': > "$GK_DBG_LOG"',
        "_run_gitnexus() { cat \"%s/status.txt\"; }" % w,
        "",
        _extract_function(CLI.read_text(encoding="utf-8"), STATUS_FN),
        "",
        'printf "OUT=%%s\\n" "$(%s "%s/repo")"' % (STATUS_FN, w),
    ]), encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", _wsl(h)], capture_output=True, text=True, timeout=60)
    out = r.stdout + r.stderr
    m = re.search(r"^OUT=(.*)$", out, re.M)
    assert m, f"probe 未输出 OUT：{out[:500]}"
    return m.group(1).strip()


def _run_ensure(tmp_path: Path, status_text: str):
    """抽取真 `_gitnexus_ensure_baseline` 体 → 桩 status（固定回放）+ 桩 analyze（计数）。"""
    body = _extract_function(CLI.read_text(encoding="utf-8"), ENSURE_FN)
    w = _wsl(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True, exist_ok=True)
    (tmp_path / "status.txt").write_text(status_text, encoding="utf-8")
    (tmp_path / "calls.txt").write_text("", encoding="utf-8")
    h = tmp_path / "ensure.sh"
    h.write_text("\n".join([
        "#!/usr/bin/env bash",
        'RG="$(command -v rg || echo rg)"',
        'GK_DBG_LOG="%s/dbg.log"' % w,
        'STATUS_FILE="%s/status.txt"' % w,
        'CALLS_FILE="%s/calls.txt"' % w,
        ': > "$GK_DBG_LOG"; : > "$CALLS_FILE"',
        "_run_gitnexus() { printf '%s\\n' \"$*\" >> \"$CALLS_FILE\"; return 0; }",
        "%s() { cat \"$STATUS_FILE\"; }" % STATUS_FN,
        # 2026-10-07（ECC-9FD1BEB74F82）起，ensure 的刷新落点下沉到**单源自愈**
        # `_gx_analyze_embeddings`（残态修复 + 跨进程单飞）⟹ 桩必须按该**缝**替换并记一次 refresh，
        # 否则 bash 报 command not found、`|| true` 吞掉 ⟹ analyze 计数恒 0（本臂假红）。
        # 同 `test_r16_status_consumers.py::_probe` 的既有约定。
        '_gx_analyze_embeddings() { _run_gitnexus analyze "$1"; }',
        "",
        body,
        "",
        'printf "OUT=%%s\\n" "$(%s "%s/repo")"' % (ENSURE_FN, w),
    ]), encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", _wsl(h)], capture_output=True, text=True, timeout=60)
    out = r.stdout + r.stderr
    m = re.search(r"^OUT=(.*)$", out, re.M)
    assert m, f"ensure harness 未输出 OUT：{out[:500]}"
    calls = [l for l in (tmp_path / "calls.txt").read_text(encoding="utf-8").splitlines()
             if l.strip()]
    return m.group(1).strip(), calls, out


def _analyze_calls(calls):
    return [c for c in calls if "analyze" in c]


# ── 臂 1 ──────────────────────────────────────────────────────────────────────
def test_arm1_commit_behind_only_yields_reusable(tmp_path):
    """[RED] 内容一致、仅 commit 落后（真实样本 `_gxstatus2`：无 `索引内容` 行）→ 必判 `reusable`。

    修前：`已过期` 文本命中 `过期` ⟹ 落 `stale` ⟹ 推进阶段恒不可满足（R16 死锁本体）。
    """
    got = _probe_status(tmp_path, COMMIT_BEHIND)
    assert got == "reusable", (
        f"commit-落后-内容一致 应判 reusable（推进阶段恒用例），实得 {got!r}；"
        "落 stale ⟹ R16 结构性死锁未消")


def test_arm1b_content_count_edge_cases(tmp_path):
    """[RED] 内容计数边界 + 无索引对照：commit-behind → `reusable`；有 incompleteReasons → `stale`；
    无索引 → `unavailable`（**不得**进 reusable）。

    ① 全零计数是**落刀前预检实测抓到的坑**（已留痕）：内容差异判据若用**全角括号分组**
    `（a|b）`，分组退化为字面/歧义 ⟹ `0 个已修改，0 个新增，0 个已删除`（= 内容一致）
    被误判 `stale`（逐支打印实证：`DIFF_ZERO hits: P3`）。故判据改写为**三条显式并列**，
    本臂即该修正的钉子。2026-11-01 起 status 判据走 JSON（`incompleteReasons`）。
    ②【对照行】无索引（`not-indexed`）**不得**进 `reusable` —— 无索引就没有
    "内容一致"可言（R3）；同表断言，红先义务由①承担。
    """
    got = _probe_status(tmp_path, COMMIT_BEHIND)
    assert got == "reusable", f"commit-behind+内容一致，应判 reusable，实得 {got!r}"

    diff = _probe_status(tmp_path / "b", CONTENT_DIFF)
    assert diff == "stale", f"有 incompleteReasons 必须 stale（不得被新态吞并），实得 {diff!r}"

    ni = _probe_status(tmp_path / "c", NOT_INDEXED)
    assert ni == "unavailable", f"无索引不得进 reusable（R3 对照行），实得 {ni!r}"


# ── 臂 2 ──────────────────────────────────────────────────────────────────────
def test_arm2_true_fresh_stays_current(tmp_path):
    """[CTRL] 真 fresh（`✅ 已是最新`）**不得**被降级为新态。

    红先合取项：同表断言 commit-behind 判 `reusable` —— 否则本对照臂修前也绿（假绿）。
    """
    fresh = _probe_status(tmp_path / "a", FRESH)
    assert fresh == "current", f"真 fresh 被降级：{fresh!r}（判据静默放松方向 = 假绿）"
    behind = _probe_status(tmp_path / "b", COMMIT_BEHIND)
    assert behind == "reusable", f"新态未产出（本臂红先合取项）：{behind!r}"


# ── 臂 3 ──────────────────────────────────────────────────────────────────────
def test_arm3_real_content_diff_stays_stale(tmp_path):
    """[CTRL] 真 content-diff（`索引内容：2 个已修改`）**不得**被新态吞并 → 仍 `stale`。

    红先合取项：同表断言 commit-behind 判 `reusable`。
    """
    diff = _probe_status(tmp_path / "a", CONTENT_DIFF)
    assert diff == "stale", f"真 content-diff 被吞进新态：{diff!r}（新态判据写在 up-to-date 之前）"
    behind = _probe_status(tmp_path / "b", COMMIT_BEHIND)
    assert behind == "reusable", f"新态未产出（本臂红先合取项）：{behind!r}"


def test_arm3b_probe_failure_is_unavailable(tmp_path):
    """[CTRL] 探测失败（空输出 = 超时/硬崩）→ `unavailable`；**不得**静默复用、也不得进新态。"""
    got = _probe_status(tmp_path, EMPTY)
    assert got == "unavailable", f"探测失败应 fail-closed 判 unavailable，实得 {got!r}"


# ── 臂 4 ──────────────────────────────────────────────────────────────────────
def test_arm4_ensure_baseline_reuses_reusable_without_analyze(tmp_path):
    """[RED] `_gitnexus_ensure_baseline` 认新态：**零 analyze** 且不落 `failed`。

    修前：`reusable` 既非 current ⟹ 走 analyze 刷新臂（1 次）⟹ 复验仍非 current ⟹ `failed`。
    实测后果 = 每次 register/advance 都付一轮全量 analyze，且恒回落 failed（成本 + 噪音）。
    """
    out, calls, raw = _run_ensure(tmp_path, "reusable")
    obj = json.loads(out)
    ana = _analyze_calls(calls)
    assert ana == [], f"新态应复用、不得 analyze，实跑 {ana}"
    assert obj.get("gitnexus_baseline") in ("reusable", "current"), (
        f"新态应被 ensure 认下（reusable/current），实得 {obj.get('gitnexus_baseline')!r}：{raw[:400]}")
    assert "failed" not in json.dumps(obj, ensure_ascii=False)


def test_arm4b_ensure_baseline_still_analyzes_on_content_diff(tmp_path):
    """[CTRL] 真 content-diff 仍必须 analyze（新态**不得**成为"永不重建"的挡箭牌）。"""
    out, calls, raw = _run_ensure(tmp_path, "stale")
    ana = _analyze_calls(calls)
    assert len(ana) == 1, f"真 stale 必须刷新 1 次，实测 {calls}"
    obj = json.loads(out)
    assert obj.get("gitnexus_baseline") in ("rebuilt", "failed", "current")


# ── 臂 5 ──────────────────────────────────────────────────────────────────────
def _ctx(tmp_path, **kw):
    f = tmp_path / "ctx.json"
    f.write_text("{}", encoding="utf-8")
    (tmp_path / "ctx.json.sig").write_bytes(b"\x00")
    base = {"context_file": str(f), "source_docs": [], "narrow_tasks": 2}
    base.update(kw)
    return base


def test_arm5_python_accepts_reusable_value(tmp_path):
    """[RED] python 侧值域白名单：`baseline_status="reusable"` **不得**报「未注入」。

    修前：`reusable` 不落 current/stale/unavailable 三分支 ⟹ 穿透到「存在性兜底已撤销」支
    ⟹ 报 `baseline_status 未注入`（H3：状态其实注入了，只是值不认识 —— 判据指向**错误方向**）。
    """
    from gk_node_guard import node_guard
    r = node_guard("ECO-EDIT", _ctx(tmp_path, baseline_status="reusable"))
    assert not any("未注入" in m for m in r["missing"]), (
        f"新态被误报为「未注入」（H3 形态）：{r['missing']}")
    assert r["ok"] is True, f"真 reusable 应齐备（可复用），实得 ok=False：{r['missing']}"


def test_arm5b_baseline_bool_fallback_removed(tmp_path):
    """[RED] 废 `baseline`(bool) 兜底：**只给** `{"baseline": true}` 而无 status ⟹ 必须判缺。

    修前：`elif not ctx.get("baseline")` 取反后 `baseline=True` ⟹ **不判缺** = **假绿**
    （老索引/硬崩索引只要文件在就过门，F-REV-76 撤销的存在性兜底以 bool 形态残留）。
    """
    from gk_node_guard import node_guard
    r = node_guard("ECO-EDIT", _ctx(tmp_path, baseline=True))
    assert r["ok"] is False, "bool 兜底未废：无 status 仍过门（假绿）"
    assert any("基线" in m for m in r["missing"]), f"应判基线缺失，实得 {r['missing']}"


@pytest.mark.parametrize("bad", ["reusable", "not-indexed", "weird-value"])
def test_arm5c_unknown_value_reports_real_reason(tmp_path, bad):
    """[RED] 白名单外值的**真因**文案：不得回「未注入」；须回可诊断的真因。

    与 R12（判据失败不可诊断）同族：错误文案必须指向**真实原因**，否则把排查引向错误方向。
    """
    from gk_node_guard import node_guard
    r = node_guard("ECO-EDIT", _ctx(tmp_path, baseline_status=bad))
    if bad == "reusable":
        assert r["ok"] is True, "reusable 属白名单，须齐备"
    else:
        assert r["ok"] is False
        assert not any("未注入" in m for m in r["missing"]), (
            f"值 {bad!r} 已注入却被报「未注入」：{r['missing']}")
