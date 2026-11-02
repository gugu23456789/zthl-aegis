#!/usr/bin/env python3
"""R17 落刀批 · 验收臂集（**P2 载体 + P4 对照体 + P5 留痕面**）—— 落盘 2026-09-28。

角色（§4.4.4「按角色分列」，**禁混列**；计数按 §4.4.20 的 P5 实测**订正**）：
  · **红先臂（修前必红）6 条**：`adjudicate_parity` · `adjudicate_verdicts_file` ·
    `adjudicate_rc_semantics` · `adjudicate_output_keys` · `adjudicate_single_source` ·
    `adjudicate_no_state_write`
  · **对照/回归护栏（修前即绿）6 条**：`adjudicate_state_path`（落刀**后**的回归护栏）·
    `adjudicate_none_score`（守卫「待搬 ≠ 待新增」）· `adjudicate_inline_coverage`（冻结树恒绿）·
    `adjudicate_impact_append`（`--impact` 内联**本就实现** ⟹ 修前即绿；落刀后护栏）·
    `adjudicate_idle_block` · `adjudicate_r2a_gate`

  ⚠ **二次订正（2026-09-28 落刀批实测）**：`adjudicate_impact_append` 原记「红先」是**假红** ——
  其断言写成字面量 `<!-- DECISION -->`（**空注释**），而内联真实形态是
  `<!-- DECISION score=… verdicts=… decision=… -->`（A10 保真面）；断言订正后在**内联（修前）**
  实测**即绿** ⟹ 据实改判为**对照/回归护栏**（红先 7→6、对照 5→6）。判据与命令见 §4.4.20。

三件工件（§4.4.4「须补实测」表）：
  · **P2** = 本文件 `canonicalize()` + `RC_CONTRACT`（键排序 + 形态归一 + rc 映射表，与 §4.4.4-R9 同表）
  · **P4 对照体侧** = 本文件自身（可运行对照体，不进生产路径）；sha 落盘后实测登记
  · **P5** = 本文件跑一次的 failed/passed 集合（如实留痕，**不得**倒填）

目标契约（§4.4.4-R9 表 —— 单一事实源）：
  · 缺必填参        → **rc1 + JSON**（**保真**内联 A5 / oracle `O3`）
  · 未知 flag       → **rc2 + JSON**（**行为变更**：内联 A3 `*) break` 静默吞 rc0 / oracle `O4`）
  · `--score` 非数值 / 越界 → **rc2 + JSON**（**行为变更**：内联 A5 只判 `-z`、无类型校验）
  · 成功            → **rc0 + JSON**

信封键集（**A13/R7 owner 裁定 2026-09-28 = 保留旧键 + 新增键**，plan 原标"待裁"）：
  · 旧键 `{ok,decision,score,verdicts,recorded_to,cross_validation}` 值须与内联/oracle **逐字等价**；
  · 新增键 `{monitor_score,divergence,flag?,entry}`（`entry` 供 CLI 回写 state，R17-R6）。

⚠ **禁逐字节比新跑结果**：oracle 的时间戳为**录制时刻快照**（`r17_oracle_adjudicate.json` 自述）
   ⟹ 一律 `canonicalize()` 后比**语义 JSON**；时间面另由 parity 臂的 `--ts` 定源断言承担。
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
CLI = SKILL_DIR / "gatekeeper-cli.sh"
FILE_VER = SKILL_DIR / "scripts" / "gk_adjudicate.py"
ORACLE = SKILL_DIR / "scripts" / "test_baselines" / "r17_oracle_adjudicate.json"
FROZEN_COMMIT = "fd0452a"  # §4.4.1a 基准 commit

# ── P2：canonicalization 函数锚（键排序 + 形态归一 + rc 映射表）──────────────────────────
RC_CONTRACT = {  # §4.4.4-R9 表的机读形态（单一事实源；禁第二份映射）
    "ok": 0,
    "missing_required": 1,   # 保真内联 A5 / oracle O3
    "unknown_flag": 2,       # 行为变更（内联 A3 静默 rc0 / oracle O4）
    "score_not_number": 2,   # 行为变更（内联无类型校验）
    "score_out_of_range": 2,  # 行为变更（内联无范围校验）
    "idle_block": 1,         # F-16（内联已实现，对照臂）
    "r2a_gate": 1,           # R2a 让步门（内联已实现，对照臂）
}
# 旧键集（A13/R7 owner 裁定 2026-09-28「保留旧键 + 新增键」）：对拍**只覆盖旧键**；
# 新增键（`monitor_score`/`divergence`/`flag`/`entry`）是**已宣告的键集变更** ⟹ 只断"存在"。
_OLD_KEYS = ("ok", "decision", "score", "verdicts", "recorded_to", "cross_validation")
# 时间面：parity 臂**固定 `--ts`** ⟹ `entry.timestamp` 为**确定值、可作判据** ⟹ 无需剔 volatile。
# ⚠ 原 `("timestamp",)` 会连 `entry.timestamp` 一并剔掉，与「`--ts` 定源断言」**结构性互斥**
#   （该断言永远取不到值 ⟹ 假红/不可达）—— 2026-09-28 落刀批实测发现并订正。
_VOLATILE: tuple = ()


def _norm(v):
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in sorted(v.items()) if k not in _VOLATILE}
    if isinstance(v, list):
        return [_norm(x) for x in v]
    return v


def canonicalize(stdout: str, rc: int) -> dict:
    """**P2 归一化**：`(stdout, rc)` → 可对拍语义 JSON。

    形态归一：`json.loads` 吸收外层 bash 紧凑信封与内嵌 python 默认分隔符（`, `/`: `）之差
    ——§4.4.4 已实测 `O1` 是**混合形态**，故「紧凑」表述不精确、**必须**做分隔符归一。
    键排序；rc 原样入对拍体（rc 契约由 `RC_CONTRACT` 另判）。现行 `_VOLATILE` 为空 ⟹
    `entry.timestamp` 保留（时间面改由 parity 臂的 `--ts` 定源断言承担）。
    """
    try:
        d = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError:
        d = {"_nonjson": stdout}
    return {"rc": rc, "sem": _norm(d)}


def _sha8(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:8]


def _mk_state(tmp_path, **over) -> Path:
    st = {"r_phase": "R17", "stage": "STAGE_1", "gate_data": {}, "monitor_scores": {},
          "history": []}
    st.update(over)
    p = tmp_path / "adj.state.json"
    p.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")
    return p


def _cli(args, state: Path, extra_env=None) -> subprocess.CompletedProcess:
    """跑**真 CLI**（修前 = 内联；修后 = 薄调用），显式 `STATE_FILE`（禁污染生产 state）。"""
    env = dict(os.environ)
    env["STATE_FILE"] = str(state)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["bash", str(CLI), *args], capture_output=True, text=True,
                          timeout=180, env=env)


def _oracle(case_id: str) -> dict:
    d = json.loads(ORACLE.read_text(encoding="utf-8"))
    return [c for c in d["cases"] if c["id"] == case_id][0]


# ── 臂组一（×10：6 红先 + 4 对照）─────────────────────────────────────────────────────────────────────────
def test_arm_r17_adjudicate_parity(tmp_path):
    """`adjudicate_parity`（红先）：CLI **旧键**语义 == oracle `O1` **且** `entry.timestamp` 由 `--ts` 定源。

    修前（内联）：A3 不识别 `--ts` ⟹ `entry` 键**不存在** ⟹ 红。
    口径（**A13/R7 owner 裁定 2026-09-28 = 保留旧键 + 新增键**）：旧键
    `{ok,decision,score,verdicts,recorded_to,cross_validation}` 值须与 oracle **逐字等价**；
    新增键（`monitor_score`/`divergence`/`flag`/`entry`）是**已宣告的键集变更** ⟹ 不在对拍体内，
    但须**存在**。`recorded_to` 为**录制机绝对路径** ⟹ 对齐到本次 tmp impact 路径（禁逐字节比）。
    """
    oc = _oracle("O1")
    st = _mk_state(tmp_path, **oc["seed"])
    imp = tmp_path / "O1.impact.md"
    imp.write_text("<!-- IMPACT -->\n", encoding="utf-8")
    ts = "1700000000"
    # `__IMPACT__` 占位符须**替换**为真实路径（原实现只删占位符 ⟹ 留下孤儿 `--impact` ⟹ argv 错位）
    argv = [str(imp) if a == "__IMPACT__" else a for a in oc["argv"]]
    r = _cli(argv + ["--ts", ts], st)
    assert r.returncode == RC_CONTRACT["ok"], (r.returncode, r.stdout[:300], r.stderr[:200])
    got = canonicalize(r.stdout, r.returncode)
    exp = canonicalize(base64.b64decode(oc["stdout_b64"]).decode("utf-8", "replace"), oc["rc"])
    exp["sem"]["recorded_to"] = str(imp)  # 录制路径 → 本次 tmp 路径
    got_old = {k: got["sem"].get(k) for k in _OLD_KEYS}
    exp_old = {k: exp["sem"].get(k) for k in _OLD_KEYS}
    assert got_old == exp_old, f"旧键语义不等：{got_old} vs {exp_old}"
    missing_new = {"monitor_score", "divergence", "entry"} - set(got["sem"])
    assert not missing_new, f"新增键缺 {sorted(missing_new)}（A13/R7 键集变更未落）"
    entry = got["sem"].get("entry") or {}
    assert str(entry.get("timestamp")) == ts, (
        f"--ts 定源未生效（entry.timestamp={entry.get('timestamp')!r}）⟹ entry.timestamp 无单点来源")
    # R8：**生产路径** `entry.timestamp` 须单点声明（CLI 注入 `date -u`），不得以"测试过了"代替定源
    cli_src = (SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    m = re.search(r"^cmd_adjudicate\(\) \{(.*?)^\}", cli_src, re.S | re.M)
    assert m, "未找到 cmd_adjudicate 函数体"
    assert "date -u +%Y-%m-%dT%H:%M:%SZ" in m.group(1), (
        "生产路径 entry.timestamp 无单点来源（CLI 未注入 date -u / 未走 --ts）")


def test_arm_r17_adjudicate_verdicts_file(tmp_path):
    """`adjudicate_verdicts_file`（红先）：`--verdicts-file` 含 NUL/BOM 填充须容错成功。"""
    vf = tmp_path / "v.json"
    vf.write_bytes(b"\xef\xbb\xbf" + b'{"F1":"PASS"}' + b"\x00\x00\n")
    r = _cli(["adjudicate", "--verdicts-file", str(vf), "--score", "0.5",
              "--decision", "d"], _mk_state(tmp_path))
    assert r.returncode == 0, (r.returncode, r.stdout[:200], r.stderr[:200])
    assert canonicalize(r.stdout, 0)["sem"].get("ok") is True, r.stdout[:200]


def test_arm_r17_adjudicate_impact_append(tmp_path):
    """`adjudicate_impact_append`（**对照/回归护栏**）：`--impact` 追加 `<!-- DECISION score=… -->`；`[ -f ]` 前置保真。

    内联（修前）**本就实现**该段 ⟹ 修前即绿（原记「红先」是空注释断言造成的**假红**）；
    真实价值 = 落刀后**护栏**：若文件版漏搬 `--impact`/`[ -f ]` 前置，本臂立即转红。
    """
    imp = tmp_path / "impact.md"
    imp.write_text("<!-- IMPACT -->\n", encoding="utf-8")
    r = _cli(["adjudicate", "--verdicts", '{"F1":"PASS"}', "--score", "0.5",
              "--decision", "d", "--impact", str(imp)], _mk_state(tmp_path))
    assert r.returncode == 0, (r.returncode, r.stdout[:200], r.stderr[:200])
    body = imp.read_text(encoding="utf-8")
    # A10 保真：注释形态 = `<!-- DECISION score=… verdicts=… decision=… -->`（**带内容**，非空注释）
    assert "<!-- DECISION score=0.5" in body and "decision=d -->" in body, (
        f"--impact 未追加 DECISION 段：{body!r}")
    ghost = tmp_path / "absent.md"
    r2 = _cli(["adjudicate", "--verdicts", '{"F1":"PASS"}', "--score", "0.5",
               "--decision", "d", "--impact", str(ghost)], _mk_state(tmp_path))
    assert r2.returncode == 0, (r2.returncode, r2.stdout[:200], r2.stderr[:200])
    assert not ghost.exists(), "`[ -f ]` 前置失效：对不存在的 impact 文件建了新文件"


def test_arm_r17_adjudicate_rc_semantics(tmp_path):
    """`adjudicate_rc_semantics`（红先）：CLI 未知 flag ⟹ **rc2 + JSON**（契约表 `unknown_flag`）。

    修前（内联 A3 `*) break`）：静默吞 ⟹ rc0；且 oracle `O4` 实测 **state 被写 790 B**（fail-open）。
    """
    r = _cli(["adjudicate", "--verdicts", '{"F1":"PASS"}', "--score", "0.5", "--nope", "x"],
             _mk_state(tmp_path))
    assert r.returncode == RC_CONTRACT["unknown_flag"], (r.returncode, r.stdout[:200], r.stderr[:200])
    assert r.stdout.strip(), f"stdout 无 JSON（stderr={r.stderr[:160]!r}）"


def test_arm_r17_adjudicate_state_path(tmp_path):
    """`adjudicate_state_path`（红先）：薄调用写 **`$STATE_FILE`** 而**不写** `DEFAULT_STATE_FILE`。"""
    st = _mk_state(tmp_path)
    default_state = SKILL_DIR / ".gatekeeper.state"
    before = default_state.read_bytes() if default_state.is_file() else None
    r = _cli(["adjudicate", "--verdicts", '{"F1":"PASS"}', "--score", "0.5",
              "--decision", "d"], st)
    assert r.returncode == 0, (r.returncode, r.stdout[:200], r.stderr[:200])
    assert json.loads(st.read_text(encoding="utf-8")).get("gate_data") is not None, "未写 $STATE_FILE"
    after = default_state.read_bytes() if default_state.is_file() else None
    assert after == before, "写到了 DEFAULT_STATE_FILE（禁依赖文件版自解析）"


def test_arm_r17_adjudicate_none_score(tmp_path):
    """`adjudicate_none_score`（红先）：`sealed.score=null` 必须走 `isinstance` 守卫。"""
    st = _mk_state(tmp_path, gate_data={"_sealed_agent_score":
                                        {"sealed": True, "score": None, "task_id": "t-1"}})
    r = _cli(["adjudicate", "--verdicts", '{"F1":"PASS"}', "--score", "0.9",
              "--decision", "d"], st)
    assert r.returncode == 0, (r.returncode, r.stdout[:200], r.stderr[:200])
    assert "TypeError" not in (r.stderr or ""), f"isinstance 守卫缺失：{r.stderr[:200]!r}"


def test_arm_r17_adjudicate_output_keys(tmp_path):
    """`adjudicate_output_keys`（红先）：输出键集**逐键**（薄调用后键集由文件版定义）。"""
    r = _cli(["adjudicate", "--verdicts", '{"F1":"PASS"}', "--score", "0.5",
              "--decision", "d"], _mk_state(tmp_path))
    assert r.returncode == 0, (r.returncode, r.stdout[:200], r.stderr[:200])
    keys = set(json.loads(r.stdout).keys())
    missing = {"ok", "monitor_score", "divergence"} - keys
    assert not missing, f"键集缺 {sorted(missing)}（实得 {sorted(keys)}）"


def test_arm_r17_adjudicate_single_source(tmp_path):
    """`adjudicate_single_source`（红先，**收窄口径**）：`divergence/flag/entry` 的**唯一生产者**。

    口径 = 「计算这三者的**唯一生产者**」（§4.4.4 明确收窄：原"全仓仅一处实现"会被注释/文档/
    队列裁决通道的引用**假红**）。修前内联 A8 与文件版 `adjudicate()` 各算一份 ⟹ 红。
    """
    src = (SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    m = re.search(r"^cmd_adjudicate\(\) \{(.*?)^\}", src, re.S | re.M)
    assert m, "未找到 cmd_adjudicate 函数体"
    body = m.group(1)
    producers = [t for t in ("divergence", "HUMAN_OVERSCORE", "AGENT_OVERSCORE")
                 if t in body]
    assert not producers, (
        f"CLI 内联仍是 {'/'.join(producers)} 的生产者 ⟹ 双源未合并（薄调用后应只留 argv 转发）")


def test_arm_r17_adjudicate_inline_coverage(tmp_path):
    """`adjudicate_inline_coverage`（红先）：内联段**逐行归区间、0 行无归属**（冻结树取值）。

    取值面 = `git show fd0452a:gatekeeper-cli.sh`（落刀后内联已删 ⟹ **禁**对工作树断言）。
    判据 = §4.4.1a 的 14 段对 `L8964-L9114` **无缝全覆盖**（`Σ行数 = 151`、`end_i + 1 = start_{i+1}`）。
    """
    spans = [(8964, 8964), (8965, 8967), (8968, 8984), (8985, 8987), (8988, 8989), (8990, 8992),
             (8993, 9014), (9015, 9088), (9089, 9096), (9097, 9109), (9110, 9111), (9112, 9112),
             (9113, 9113), (9114, 9114)]
    lines = subprocess.run(["git", "-C", str(SKILL_DIR), "show",
                            f"{FROZEN_COMMIT}:gatekeeper-cli.sh"],
                           capture_output=True, text=True, timeout=120)
    assert lines.returncode == 0, lines.stderr[:200]
    body = lines.stdout.splitlines()
    fn = "\n".join(body[8963:9114])
    assert hashlib.sha256(fn.encode()).hexdigest()[:8] == "622d2df2", "冻结树内联函数体 sha 漂移"
    total = sum(b - a + 1 for a, b in spans)
    assert total == 151, f"覆盖行数 {total} ≠ 151"
    for (a1, b1), (a2, _) in zip(spans, spans[1:]):
        assert b1 + 1 == a2, f"区间不连续：{b1} → {a2}"


def test_arm_r17_adjudicate_no_state_write(tmp_path):
    """`adjudicate_no_state_write`（红先，`R17-R6` 裁定配套）：文件版生产路径**零 state 写**。

    口径 = 真跑文件版并比对 state 副本的 mtime + 字节（只读副本，不碰生产 state）。
    """
    st = _mk_state(tmp_path)
    before = (st.stat().st_mtime_ns, st.read_bytes())
    r = subprocess.run([sys.executable, str(FILE_VER), "--verdicts", '{"F1":"PASS"}',
                        "--score", "0.5", "--decision", "d", "--path", str(st)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.returncode, r.stdout[:200], r.stderr[:200])
    after = (st.stat().st_mtime_ns, st.read_bytes())
    assert after == before, "文件版仍写 state ⟹ R17-R6「写盘收归 CLI 单点」未落"


# ── 臂组二（×2：对照/回归护栏）────────────────────────────────────────────────
def test_arm_r17_adjudicate_idle_block(tmp_path):
    """对照：F-16 IDLE/DONE 门（内联 A6 已实现 ⟹ 修前即绿；oracle `O5`）。"""
    r = _cli(["adjudicate", "--verdicts", '{"F1":"PASS"}', "--score", "0.5"],
             _mk_state(tmp_path, stage="IDLE"))
    assert r.returncode == RC_CONTRACT["idle_block"], (r.returncode, r.stdout[:200])
    assert "IDLE" in r.stdout or "IDLE" in (r.stderr or ""), r.stdout[:200]


def test_arm_r17_adjudicate_r2a_gate(tmp_path):
    """对照：R2a 让步门（内联 A7 已实现 ⟹ 修前即绿；oracle `O2`）。"""
    r = _cli(["adjudicate", "--verdicts", '{"F1":"PASS","F2":"WARN"}', "--score", "0.5"],
             _mk_state(tmp_path))
    assert r.returncode == RC_CONTRACT["r2a_gate"], (r.returncode, r.stdout[:200])
    assert "F2" in r.stdout, r.stdout[:200]
