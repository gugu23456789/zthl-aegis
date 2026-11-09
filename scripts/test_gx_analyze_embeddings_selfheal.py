#!/usr/bin/env python3
"""`_gx_analyze_embeddings` 残留态自愈回归（ECC-4BDBA3605F47，2026-09-19）。

背景（实测取证）：gitnexus 索引一旦进入残留态（lbug 里已存旧 CodeEmbedding 行 + 新一遍
「从头插」），`gitnexus analyze --embeddings` 必撞主键约束失败：

    CREATE (e:CodeEmbedding {id: $id, ...}) 主键冲突

伴生证据（实测三件同时存在）：`meta.json.embeddingCheckpoint {nodesProcessed: 0,
totalNodes: 2968}`、`meta.json.incrementalInProgress {phase: "load-graph"}`、
`.gitnexus/lbug.wal.dirty-recovery`；而 gitnexus **永不自清**这些标记 ⟹ `gitnexus status`
恒 `stale`、技能侧 `context --update` 恒 `unavailable`（**自激死锁**）。
逃逸路径实测唯一：`analyze --embeddings --drop-embeddings`（366.3s 成功，8714 节点）。

本文件锁五条判据：
  ① **单一事实源**：CLI 内所有 `analyze --embeddings` 出现点都在 `_gx_analyze_embeddings`
     函数体内（该函数外的直调 = 无自愈臂，正是本缺陷形态）
  ② **正常路径零额外代价**：首试即 current ⟹ 只 1 次 `analyze`、**不**带 `--drop-embeddings`
  ③ **残态证据才重试**：首试 stderr 含主键冲突等残态证据 ⟹ 第 2 次带 `--drop-embeddings`
  ④ **复验失败 ≠ 残态**（2026-11-01 owner 裁定）：无残态证据时**不**付全量重嵌，返回非 0
  ⑤ **单飞**：同一目录 30min 内只自愈一次（跨进程 marker），二次调用直接跳过

判据 ②③④⑤ 是**行为测试**，且不靠「重写一份逻辑」：函数体由本文件从 `gatekeeper-cli.sh`
**按花括号配对抽取**（见 `_extract_function`），故被测代码与入库代码逐字节同源、不会漂移。
`_run_gitnexus` / `_gitnexus_baseline_status` 以桩替换 —— 桩只做两件事：记录 argv、
按「是否带 --drop-embeddings」改写 status 文件。

red-first 对照臂：修复前 CLI **无** `_gx_analyze_embeddings` ⟹ 抽取失败 ⟹ 三条判据全红。

⚠ 未覆盖（如实登记，不假装已验）：真实残留态**未在本文件复现**。复现需把 `analyze`
  中途杀掉（原生事故形态）⟹ 约 7–12 分钟且会改写共享索引；判据 ②③ 验的是**修复新增的
  判定逻辑**，不是 gitnexus 自身行为。该缺口由用户决定是否补「杀进程」级 E2E。
"""
import re
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI = SKILL_DIR / "gatekeeper-cli.sh"

FUNC_NAME = "_gx_analyze_embeddings"
FLAG = "--embeddings"
FALLBACK_FLAG = "--drop-embeddings"


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）；`bash` 在这里是 WSL bash，
    直接喂 `C:\\...` 会被当成相对文件名（实测报 `C:UsersHP...: No such file or directory`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _code_lines(src: str):
    """只取**可执行**行（去注释）—— 注释里叙述 `analyze --embeddings` 不算调用点。

    本仓 §8.17 的教训：行锚/字面量校验器会把文档里的「举例/记述」当真引用；此处的计数
    同理必须排除注释，否则判据① 会把诊断文字误判为直调点。
    """
    return [l for l in src.splitlines() if not l.lstrip().startswith("#")]


def _extract_function(src: str, name: str) -> str:
    """按花括号配对抽取 `name() { ... }` 全文（含首尾行）。找不到 → AssertionError。"""
    lines = src.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith(name + "() {")), None)
    assert start is not None, f"{name} 未定义（修复前的 CLI 即此形态 ⟹ 红）"
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth == 0:
            return "\n".join(lines[start:i + 1])
    raise AssertionError(f"{name} 花括号不配对（抽取失败）")


def _run_helper(tmp_path: Path, first_to: str, recover_to: str,
                residue: bool = False, keep_calls: bool = False,
                store_residual: bool = False):
    """抽取真实函数体 → 拼桩 → 跑；返回 (returncode, [每次 analyze 的 argv 行], 输出)。

    residue=True ⟹ 桩在首试时向 stderr 打**残态证据**（主键冲突），用于判据③；
    否则只改 status（复验失败但无残态证据 ⟹ 判据④不得重试）。
    keep_calls=True ⟹ 不清空调用记录（判据⑤ 单飞：同目录二次调用不得再 analyze）。
    """
    body = _extract_function(CLI.read_text(encoding="utf-8"), FUNC_NAME)
    w = _wsl(tmp_path)
    harness = tmp_path / "harness.sh"
    calls = tmp_path / "calls.txt"
    harness.write_text(
        "\n".join([
            "#!/usr/bin/env bash",
            'GK_DBG_LOG="%s/dbg.log"' % w,
            'STATUS_FILE="%s/status.txt"' % w,
            'CALLS_FILE="%s/calls.txt"' % w,
            ': > "$GK_DBG_LOG"',
            ('' if keep_calls else ': > "$CALLS_FILE"'),
            'printf %s "stale" > "$STATUS_FILE"',
            "_run_gitnexus() {",
            '  printf "%s\\n" "$*" >> "$CALLS_FILE"',
            '  if [ "${RESIDUE:-0}" = "1" ] && [ "$(wc -l < "$CALLS_FILE")" = "1" ]; then',
            '    echo "Constraint validation failed: primary key already exists" >&2',
            "  fi",
            '  case "$*" in',
            '    *"%s"*) printf %%s "%s" > "$STATUS_FILE" ;;' % (FALLBACK_FLAG, recover_to),
            '    *) printf %%s "%s" > "$STATUS_FILE" ;;' % first_to,
            "  esac",
            "  return 0",
            "}",
            '_gitnexus_baseline_status() { cat "$STATUS_FILE"; }',
            # 2026-11-09：store 残态探针（stub）；STORE_RESIDUAL=1 模拟 lbug.wal/dirty-recovery
            '_gx_store_residual_evidence() { [ "${STORE_RESIDUAL:-0}" = "1" ] && return 0; return 1; }',
            "",
            body,
            "",
            '%s%s "%s"' % (("STORE_RESIDUAL=1 " if store_residual else "")
                            + ("RESIDUE=1 " if residue else ""), FUNC_NAME, w),
            'echo "RC=$?"',
        ]), encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", _wsl(harness)], capture_output=True, text=True, timeout=60)
    out = r.stdout + r.stderr
    recorded = [l for l in calls.read_text(encoding="utf-8").splitlines() if l.strip()] \
        if calls.exists() else []
    rc = re.search(r"^RC=(\d+)$", out, re.M)
    assert rc, f"harness 未输出 RC：{out[:500]}"
    return rc.group(1), recorded, out


def test_analyze_embeddings_is_single_sourced():
    """判据①：所有**可执行**的 `analyze --embeddings` 出现点必须落在 helper 函数体内。"""
    src = CLI.read_text(encoding="utf-8")
    body = _extract_function(src, FUNC_NAME)
    total = sum(l.count("analyze " + FLAG) for l in _code_lines(src))
    inside = sum(l.count("analyze " + FLAG) for l in _code_lines(body))
    assert total == inside, (
        "存在 helper 之外的 `analyze --embeddings` 直调点（无残留自愈臂）："
        f"全文可执行行 {total} 处 / 函数体内 {inside} 处")


def test_healthy_path_does_not_drop_embeddings(tmp_path):
    """判据②：首试后即 current ⟹ 只 1 次 analyze，且不带 --drop-embeddings。"""
    rc, recorded, out = _run_helper(tmp_path, first_to="current", recover_to="current")
    assert rc == "0", out
    assert len(recorded) == 1, f"应只跑 1 次 analyze，实际 {recorded}"
    assert FALLBACK_FLAG not in recorded[0], f"正常路径不应付全量重嵌代价：{recorded[0]}"


def test_residue_state_triggers_drop_embeddings_retry(tmp_path):
    """判据③：首试 stderr 有**残态证据**（主键冲突）⟹ 第 2 次 analyze 必带 --drop-embeddings。"""
    _, recorded, out = _run_helper(tmp_path, first_to="stale", recover_to="current", residue=True)
    assert len(recorded) == 2, f"残态应有且仅有 1 次重试，实际 {recorded}"
    assert FALLBACK_FLAG in recorded[1], f"重试臂未带自愈旗标：{recorded[1]}"
    assert FALLBACK_FLAG not in recorded[0], f"首试不应预设自愈旗标：{recorded[0]}"


def test_unresolved_without_residue_does_not_reembed(tmp_path):
    """判据④（2026-11-01 owner 裁定）：复验失败但**无残态证据** ⟹ 不付全量重嵌，且非 0。

    原实现无条件重试 ⟹ 「一次 stale = 一次 40min 级全量重嵌」（实测 10-30 12:14 六连重试）。
    """
    rc, recorded, out = _run_helper(tmp_path, first_to="stale", recover_to="current")
    assert rc != "0", out
    assert len(recorded) == 1, f"无残态证据不得重试全量重嵌，实际 {recorded}"
    assert "不付全量重嵌" in out or "无残态证据" in (tmp_path / "dbg.log").read_text(encoding="utf-8")


def test_single_flight_per_dir(tmp_path):
    """判据⑤：同目录 30min 内二次调用 ⟹ 直接跳过（跨进程 marker），不再 analyze。"""
    _run_helper(tmp_path, first_to="stale", recover_to="stale")
    rc2, recorded2, out2 = _run_helper(
        tmp_path, first_to="stale", recover_to="stale", keep_calls=True)
    assert len(recorded2) == 1, f"二次调用不得再 analyze（marker 单飞），实际 {recorded2}"
    assert rc2 != "0", out2

def test_store_residue_triggers_drop_embeddings_retry(tmp_path):
    """判据③b（2026-11-09）：stderr 无残态关键词，但索引目录有 `lbug.wal` /
    `lbug.wal.dirty-recovery` ⟹ 仍须 `--drop-embeddings`。

    红先性：修复前函数只 grep stderr ⟹ store_residual=True 时仍只跑 1 次 analyze ⟹ 本臂红。
    """
    _, recorded, out = _run_helper(tmp_path, first_to="stale", recover_to="current",
                                   store_residual=True)
    assert len(recorded) == 2, f"store 残态应有且仅有 1 次重试，实际 {recorded}"
    assert FALLBACK_FLAG in recorded[1], f"store 残态重试臂未带自愈旗标：{recorded[1]}"
    assert FALLBACK_FLAG not in recorded[0], f"首试不应预设自愈旗标：{recorded[0]}"

