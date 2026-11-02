#!/usr/bin/env python3
"""T15 红先臂：MoA 链**头**入参 `--from-plan`（从计划文本起跑）。

链路（`gk_moa_aggregate.chain_head` / `chain`）：
  plan-lint(PW-SN，high/medium>0 即拒) → 派臂（**委托** plan-refinement --run）→ 聚合 → 链尾 HTML。

判据（**HEAD 必红** —— `chain_head` 不存在）：
  1) **机检阻断 ⟹ 零派臂**：计划缺 `<!-- META -->` ⟹ `error=plan_lint_blocking`，runner **一次都不调**，
     **不产出 HTML**（fail-closed，不烧臂去质询机检不过的计划）；
  2) **派臂失败 ⟹ 不产出 HTML**：runner 返回 `ok=False` ⟹ `error=arms_failed` 且 HTML 不存在；
  3) **正常 ⟹ 产出 HTML**：stub runner 落 6 臂 ⟹ 聚合成功、`steps.html.status=written` 且文件落盘；
  4) **CLI 接线**：`--from-plan` 单独给出 ⟹ rc=2；与 `--chain` 同用 ⟹ 机检阻断透传到单行 JSON 封套。
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import gk_moa_aggregate as M  # noqa: E402

BATCH = "abc123def456"
META_OK = """<!-- META
target_repo: spz-gatekeeper-r-sequence
project_type: analysis
worktree_needed: false
state_domain: spz-gatekeeper-r-sequence.clean-plan
phases: T1
-->

<!-- 质询目标（与 §1 逐字一致）：
核验链头入参。
-->
"""


def _plan(tmp_path, text, name="plan.md"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def _state(tmp_path, n=6, plan=""):
    # 真实派发臂的 task 内嵌**计划路径**（`plan-refinement: <PLAN> — …`）⟹ 链头按计划过滤批锚。
    hist = [{"subagent_id": "sub-%d" % i, "batch_id": BATCH, "arm_group": "G%d" % (i // 2 + 1),
             "task": "plan-refinement: %s — 质询 %d" % (plan or "plan", i),
             "conclusion": "结论" * 200,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for i in range(n)]
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"gate_data": {"subagent_history": hist, "ecc_findings": []}},
                            ensure_ascii=False), encoding="utf-8")
    return str(p)


def test_from_plan_lint_blocking_zero_dispatch(tmp_path):
    plan = _plan(tmp_path, "没有 META 的计划\n")     # 缺 META ⟹ L-META high
    sf = _state(tmp_path)
    html = str(tmp_path / "out.html")
    calls = []

    def _runner(*a, **kw):
        calls.append(1)
        return {"ok": True}

    r = M.chain(sf, from_plan=plan, html_path=html, runner=_runner)
    assert r["ok"] is False and r["error"] == "plan_lint_blocking", r
    assert r["head"]["lint"]["high"] >= 1, r["head"]
    assert calls == [], "机检阻断时**禁止**派臂"
    assert not Path(html).exists(), "机检阻断时**禁止**产出 HTML"


def test_from_plan_arms_failed_no_html(tmp_path):
    plan = _plan(tmp_path, META_OK)
    sf = _state(tmp_path)
    html = str(tmp_path / "out.html")

    r = M.chain(sf, from_plan=plan, html_path=html,
                runner=lambda *a, **kw: {"ok": False, "error": "boom"})
    assert r["ok"] is False and r["error"] == "arms_failed", r
    assert r["head"]["dispatch"].get("error") == "boom", r["head"]
    assert not Path(html).exists(), "派臂失败时**禁止**产出 HTML"


def test_from_plan_ok_writes_html(tmp_path):
    plan = _plan(tmp_path, META_OK)
    sf = _state(tmp_path, plan=plan)
    html = str(tmp_path / "out.html")

    r = M.chain(sf, from_plan=plan, html_path=html,
                runner=lambda *a, **kw: {"ok": True, "rc": 0, "dispatched": "last-batch"})
    assert r["ok"] is True, r
    assert r["steps"]["head"]["ok"] is True, r["steps"]["head"]
    assert r["steps"]["batch_resolved"] == BATCH, r["steps"]
    assert r["steps"]["html"]["status"] == "written", r["steps"]["html"]
    body = Path(html).read_text(encoding="utf-8")
    assert BATCH in body, "HTML 须带批次锚"


def test_from_plan_cli_requires_chain(tmp_path):
    sf = _state(tmp_path)
    p = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_moa_aggregate.py"),
                        "--state", sf, "--from-plan", "x.md"],
                       capture_output=True, text=True)
    assert p.returncode == 2, (p.returncode, p.stdout, p.stderr)
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert "--chain" in out.get("error", ""), out


def test_from_plan_cli_blocking_is_single_envelope(tmp_path):
    plan = _plan(tmp_path, "没有 META 的计划\n")
    sf = _state(tmp_path)
    p = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_moa_aggregate.py"),
                        "--state", sf, "--chain", "--from-plan", plan,
                        "--html", str(tmp_path / "o.html")],
                       capture_output=True, text=True)
    assert p.returncode == 1, (p.returncode, p.stderr)
    out = json.loads(p.stdout.strip().splitlines()[-1])   # stdout 单封套
    assert out["mode"] == "moa_chain" and out["error"] == "plan_lint_blocking", out
    assert not (tmp_path / "o.html").exists()


def test_from_plan_resumes_pending_without_reenqueue(tmp_path):
    """**续跑**：本计划已有 pending ⟹ 只下发（`resume=True`），不再入队 6 臂。"""
    plan = _plan(tmp_path, META_OK)
    sf = _state(tmp_path, plan=plan)
    d = json.loads(Path(sf).read_text(encoding="utf-8"))
    d["gate_data"]["task_pipeline"] = [{"id": "pr-x-1", "status": "pending", "target": plan}]
    Path(sf).write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    seen = {}

    def _runner(*a, **kw):
        seen.update(kw)
        return {"ok": True, "rc": 0, "elapsed_s": 1.0}

    r = M.chain(sf, from_plan=plan, html_path=str(tmp_path / "out.html"), runner=_runner)
    assert r["ok"] is True, r
    assert r["steps"]["head"]["resume"] is True, r["steps"]["head"]
    assert seen.get("resume") is True, seen


def test_default_runner_times_out_and_kills_group(tmp_path, monkeypatch):
    """**超时**：缺省 runner 不得无界阻塞 —— 超时即具名 `dispatch_timeout` 并杀整组。"""
    stub = tmp_path / "slow-cli.sh"
    stub.write_text("#!/usr/bin/env bash\nsleep 30\n", encoding="utf-8")
    monkeypatch.setenv("GK_CHAIN_CLI", str(stub))
    monkeypatch.setenv("GK_CHAIN_DISPATCH_TIMEOUT", "1")
    t0 = time.time()
    r = M._default_arm_runner("/x/plan.md")
    dt = time.time() - t0
    assert r["ok"] is False and r["error"] == "dispatch_timeout", r
    assert r["timeout_s"] == 1, r
    assert dt < 10, "超时后必须立即返回（实测 %.1fs）" % dt


def test_chain_without_plan_or_batch_returns_no_anchor(tmp_path):
    """回归（2026-10-30）：`--chain` 不带 `--plan`/`--from-plan` 时 `head` 未绑定 ⟹
    `UnboundLocalError: head`。正确行为 = fail-loud 返回 `no_anchor`，禁抛异常。"""
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"gate_data": {"subagent_history": []}}), encoding="utf-8")
    r = M.chain(str(st))
    assert isinstance(r, dict)
    assert r.get("ok") is False and r.get("error") == "no_anchor", r


def test_chain_emits_stage_notes_and_clears_runfile(tmp_path, capsys):
    """**阶段性状态回传**：stderr 出 step 行；`${state}.chain-run` 结束后清理。"""
    plan = _plan(tmp_path, META_OK)
    sf = _state(tmp_path, plan=plan)
    html = str(tmp_path / "out.html")
    r = M.chain(sf, from_plan=plan, html_path=html,
                runner=lambda *a, **kw: {"ok": True, "rc": 0, "elapsed_s": 0.1})
    assert r["ok"] is True, r
    err = capsys.readouterr().err
    for step in ("step=start", "step=head:lint:start", "step=head:lint:done",
                 "step=head:dispatch:start", "step=head:dispatch:done",
                 "step=aggregate:done", "step=done"):
        assert step in err, (step, err[-600:])
    assert not Path(sf + ".chain-run").exists(), "链结束后应清理运行注册文件"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
