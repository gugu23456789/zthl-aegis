"""T8 红先臂：**单一回执**（stdout 只出**单行** JSON 封套；禁伪拼接 JSON）。

正本 = `docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T8（`| 8 | 单一回执 | A | 无（T8 待）|`）。

判据：
  1) **形态**：`--chain` 的 stdout = **单行** JSON（与 `--accept`/`--group` 分支「stdout 末行 = 完整
     JSON」契约一致；原 `indent=2` 多行）；
  2) **恰一份**：`json.loads(stdout)` 成功且 `mode=="moa_chain"`（**无伪拼接**）；
  3) **守卫**：`chain()` 子调用若向 stdout 打印，须被 `redirect_stdout(sys.stderr)` 引走
     ——「stdout = 单一 JSON」由**机制**保证，而非依赖「子调用恰好不打印」。

HEAD 必红：chain 分支 `print(..., indent=2)`（多行）且**无** stdout 守卫。
"""
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

PY = sys.executable
PLAN = "/p/docs/plans/x-plan.md"
BATCH = "abc123def456"


def _state(tmp_path, rows, name="state.json"):
    hist = [{"subagent_id": sid, "batch_id": bid, "arm_group": g,
             "task": "plan-refinement: %s — 质询 %s" % (PLAN, sid),
             "conclusion": "结论" * 200,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for (sid, bid, g) in rows]
    d = {"gate_data": {"subagent_history": hist, "ecc_findings": []}}
    p = tmp_path / name
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    return str(p)


def _rows(n=6):
    return [("sub-%d" % i, BATCH, "G1") for i in range(n)]


def _run_cli(sf, prefix=""):
    code = ("import sys; sys.path.insert(0, %r); import gk_moa_aggregate as M;"
            "%ssys.argv=['x','--chain','--state',%r,'--plan',%r,'--no-html'];"
            "raise SystemExit(M.main())" % (str(SCRIPT_DIR), prefix, sf, PLAN))
    return subprocess.run([PY, "-c", code], capture_output=True, text=True, timeout=180)


def test_arm1_shape_and_guard_present():
    """机检：chain 分支须 `redirect_stdout(sys.stderr)` + **单行** print（无 indent）。"""
    src = (SCRIPT_DIR / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert "redirect_stdout(sys.stderr)" in src, "T8 未接：缺 stdout 污染守卫"
    i = src.index("with contextlib.redirect_stdout(sys.stderr):")
    seg = src[i:i + 500]
    assert "print(json.dumps(res, ensure_ascii=False))" in seg, "T8 未接：chain 未改单行"
    assert "indent=2" not in seg, "T8 未接：chain 仍多行（indent=2）"


def test_arm2_stdout_is_exactly_one_single_line_json(tmp_path):
    sf = _state(tmp_path, _rows())
    p = _run_cli(sf)
    assert p.stdout.strip(), ("chain stdout 为空", p.stderr[-400:])
    assert "\n" not in p.stdout.strip(), ("stdout 非单行（多行/伪拼接）", p.stdout[:300])
    doc = json.loads(p.stdout)                      # 恰一份 JSON（多份 ⟹ JSONDecodeError）
    assert doc.get("mode") == "moa_chain" and doc.get("ok") is True, doc


def test_arm3_guard_isolates_child_stdout_pollution(tmp_path):
    """注入会向 stdout 打印的子调用 ⟹ 污染须落 **stderr**，stdout 仍恰一份封套。"""
    sf = _state(tmp_path, _rows())
    prefix = ("M.emit_aggregate_finding="
              "lambda *a,**k:(print('POLLUTION_LINE'),{'ok':True})[1];")
    p = _run_cli(sf, prefix=prefix)
    assert "POLLUTION_LINE" not in p.stdout, ("污染冲进 stdout ⟹ 伪拼接", p.stdout[:300])
    assert "POLLUTION_LINE" in p.stderr, "污染未落 stderr（守卫未生效 / 污染侧未触发）"
    doc = json.loads(p.stdout)
    assert doc.get("mode") == "moa_chain", doc
