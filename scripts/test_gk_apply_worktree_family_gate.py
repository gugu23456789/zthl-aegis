"""F-F 红先臂（2026-10-15）：`apply-worktree --code-fix` 显式 `--family` 必须与**自动族判定**一致。

病象（实测）：`--family F` 是人工覆盖，原实现**无条件采信** ⟹ 与 finding 无关的族被静默采纳，
coder 被派去做**无关落刀**（强塞 `F-ECC-PLAND`，按 raw-车道 finding 却去 `gk_doc_align.py`
实现 `check_plan_landing_drift`）。落刀前**必红**：错误族被接受、无 `FAMILY_MISMATCH`。
"""
import json
import os
import subprocess
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SKILL = _HERE.parent
_PLAN = str(_SKILL / "docs/plans/2026-10-12-w2a-p2-phase-experiment-plan.md")


def _run(args, state=""):
    # GK_PLAN_POINTER_STRICT=1：不跟随各会话 discover 留下的域化指针 ⟹ 恒用默认 state
    # （本臂只验族判定 gate；全局指针属环境态，跟着它跑会让用例依赖别的会话的计划路由）
    env = {**os.environ, "GK_PLAN_FILE": _PLAN, "GK_PLAN_POINTER_STRICT": "1",
           # 本臂只验族判定 gate；域路由属环境态（域化 state 可能不存在）⟹ 显式关闭。
           "GK_STATE_DOMAIN_ROUTE": "0"}
    if state:
        env["STATE_FILE"] = state
        env["STATE_FILE_EXPLICIT"] = "1"
    return subprocess.run(["bash", str(_SKILL / "gatekeeper-cli.sh"), *args],
                          capture_output=True, text=True, env=env, cwd=str(_SKILL))


def test_apply_worktree_rejects_mismatched_family(tmp_path):
    """显式 --family 与自动判定不一致 ⟹ 必须 fail-loud `FAMILY_MISMATCH`（禁静默采信人工覆盖）。

    2026-11-09：finding 不再假设活在**主 state**（历史批已归档）⟹ 自建最小 state 钉住
    「raw 车道 finding → F-w2a-phase-obs」，避免用例依赖外部 state 的可变性。
    """
    st = tmp_path / "state.json"
    st.write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1",
        "gate_data": {"ecc_findings": [{
            "id": "ECC-B50421D75233", "status": "open", "source": "monitor",
            "title": "相位观测 stride 双源 cache 假零", "facets": ["cache"]}]}}),
        encoding="utf-8")
    r = _run(["apply-worktree", "--code-fix", "--finding", "ECC-B50421D75233",
              "--family", "F-ECC-PLAND", "--dry-run"], state=str(st))
    out = (r.stdout or "").strip()
    assert "FAMILY_MISMATCH" in out, (
        "错误族被静默接受（未 fail-loud）—— 会把 coder 派去做无关落刀；stdout=%r rc=%d" % (out[:300], r.returncode))
    assert r.returncode != 0, "FAMILY_MISMATCH 应以非零退出（fail-loud）"
