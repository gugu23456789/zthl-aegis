#!/usr/bin/env python3
"""C4（`ECC-D9D2382BB535`）红先臂 —— 落库白名单**投影丢机检字段面**（2026-09-28）。

病象（计划 §十一-C4）：`entry`（落库白名单）仅 ~20 键，缺
`verification`/`evidence_anchor`/`gx_status`/`token_usage`/`agent_payload`/`guardrail`/`turns`/
`mode`/`nonce`/`timestamp` ⟹ 机检面在 state 侧不可见（读侧只能看见 `hmac_status`/`budget_status`）。

已核事实（2026-09-28）：`docs/analysis/subagent/<subagent_id>.json` **已 = 全量 ECC**（实测最新臂带
`gx_status`/`verification`/`evidence_anchor`/`token_usage`/`agent_payload`）⟹ **外置面已存在**；
故本切片 = ① **落盘校验**（可解析 + 关键键非缺席，失败 fail-loud）；② `entry` 增 `machine_check`
**最小摘要**（字节上限常量 512，由全量**派生**、禁独立计算）；③ 投影键集**单源**（常量声明）。

判据（红先，HEAD **必红**）：HEAD 的 entry 白名单既无 `machine_check`、无键集单源常量、无落盘
校验 fail-loud 标记 ⟹ 4 臂全红。
"""
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _hist_region() -> str:
    """落库载荷源码（B2 下沉后 = `scripts/gk_monitor_payload.py` 全文）。

    2026-11-04：载荷从 CLI 内联块搬到模块文件 ⟹ 判据面随代码迁移。先钉「CLI 仍接线到该模块」，
    再把模块当作落库段返回；断言点（machine_check / 字节上限 / 键集单源）不变。
    """
    txt = CLI.read_text(encoding="utf-8")
    assert "gk_monitor_payload.py" in txt, "CLI 未接线到下沉模块（锚失效，臂失去意义）"
    return (CLI.parent / "scripts" / "gk_monitor_payload.py").read_text(encoding="utf-8")


def _dump_region() -> str:
    """报告落盘段：`local sub_out_file=` → 其后的审计留痕注释（`Write subagent output to`）。"""
    txt = CLI.read_text(encoding="utf-8")
    i = txt.index("local sub_out_file=")
    j = txt.index("Write subagent output to", i)
    return txt[i:j]


def test_entry_carries_machine_check():
    """② 落库 entry 须带 `machine_check` 最小摘要（机检面在 state 侧可见）。"""
    seg = _hist_region()
    assert "'machine_check'" in seg or '"machine_check"' in seg, (
        "落库 entry 缺 machine_check 摘要 ⟹ verification/evidence_anchor/gx_status 等机检面仍不可见（C4② 未落）")


def test_machine_check_size_capped():
    """② 摘要须有**字节上限**常量（受 C1 体积约束）。"""
    seg = _hist_region()
    assert "_MACHINE_CHECK_MAX_BYTES" in seg, (
        "缺 machine_check 字节上限常量 ⟹ 摘要可无界膨胀，与 C1 体积目标对撞（C4②）")


def test_entry_projection_keys_single_source():
    """③ 投影键集须**单源**声明（常量），防再次丢面。"""
    seg = _hist_region()
    assert "_ENTRY_KEYS" in seg, (
        "缺投影键集单源常量 _ENTRY_KEYS ⟹ 「投影键集 == 声明集」无判据面（C4③）")


def test_report_dump_validated():
    """① 全量报告落盘后须**校验**（可解析 + 关键键非缺席），失败 fail-loud。"""
    seg = _dump_region()
    assert "DUMP_REPORT_INVALID" in seg, (
        "报告落盘后未校验（缺 DUMP_REPORT_INVALID fail-loud 标记）⟹ 损坏 .json 静默（C4① 未落）")


# ─── 行为臂：真跑落库载荷（合成 ECC）⟹ entry 必须带 machine_check ───

def _run_payload(tmp_path, ecc: dict) -> dict:
    """喂合成 ECC 真跑落库载荷，返回写后的 state。

    2026-11-04（B2 下沉）：载荷已是 `scripts/gk_monitor_payload.py`（**文件调用**）⟹ 不再从
    CLI 切双引号区、也不再手工代入 bash 插值；路径统一走 env（真因 D 的口径保留）。
    """
    import json
    import os
    import subprocess
    import sys
    state = tmp_path / ".gatekeeper.state"
    state.write_text('{"gate_data":{}}', encoding="utf-8")
    out = tmp_path / "sub-1.json"
    out.write_text(json.dumps(ecc, ensure_ascii=False), encoding="utf-8")
    env = dict(os.environ, GK_TASK=ecc.get("task", ""), GK_HMAC_VALID="skip",
               GK_OUTPUT_FILE=str(out), GK_REPORT_FILE=str(tmp_path / "sub-1.md"),
               # 真因 D（2026-11-02）：路径经 env 传入（形态锚在解释器，见 `_gk_py_path`）
               GK_PY_SCRIPTS=str(CLI.parent / "scripts"), GK_PY_STATE=str(state))
    r = subprocess.run([sys.executable, str(CLI.parent / "scripts" / "gk_monitor_payload.py")],
                       input=json.dumps(ecc), capture_output=True, text=True, env=env, timeout=90)
    assert r.returncode == 0, (r.returncode, r.stdout[-600:], r.stderr[-600:])
    return json.loads(state.read_text(encoding="utf-8"))


def test_payload_writes_machine_check(tmp_path):
    """行为臂：真跑载荷 ⟹ `subagent_history[-1]['machine_check']` 由全量**派生**（红先必红）。"""
    ecc = {"mode": "subagent", "subagent_id": "sub-1", "nonce": "n1",
           "timestamp": "2026-09-28T00:00:00+00:00", "task": "t", "conclusion": "c",
           "gx_status": {"verdict": "ok"}, "verification": {"status": "ok"},
           "evidence_anchor": {"status": "ok"}, "token_usage": {"rounds": 3},
           "guardrail": "passed", "turns": 2}
    d = _run_payload(tmp_path, ecc)
    ent = d["gate_data"]["subagent_history"][-1]
    assert ent.get("machine_check", {}).get("gx_status") == "ok", ent.get("machine_check")
    assert ent["machine_check"]["token_usage_rounds"] == 3, ent["machine_check"]

