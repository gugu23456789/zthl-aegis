#!/usr/bin/env python3
"""`monitor --api` 决策后端通道红先臂（2026-10-31，owner 裁定 A）。

背景：旧 `--api` = 每次一次 v4-flash PRM 调用，分不可校准（同族自评 / 无人类裁决对照 /
生产零记录）。裁决 = 分数改由**审计署决策后端**产出（同一 `POST /v1/systemone`、同一
typed-choice 协议），只作 advisory；`machine_check.monitor_last` 留痕以便复盘。

判据（红先）：HEAD 无 `gk_monitor_decision.py` ⟹ ImportError 必红。
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_monitor_decision as MD  # noqa: E402

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


@pytest.fixture()
def fake_backend():
    """最小决策后端：回 typed-choice 信封（choice/confidence 可配）。"""
    box = {"choice": "pass", "confidence": 0.87, "seen": None}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 — http.server 契约
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n).decode("utf-8"))
            box["seen"] = body
            resp = {"answers": {MD.QUESTION_ID: {"choice": box["choice"],
                                                 "confidence": box["confidence"]}}}
            raw = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):  # noqa: A003 — 静默
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield "http://127.0.0.1:%d" % srv.server_port, box
    finally:
        srv.shutdown()
        srv.server_close()


def test_endpoint_unset_returns_advisory_without_network():
    """未配端点 ⟹ 只 advisory（不联网、不伪造分数、不回落到旧 PRM 车道）。"""
    r = MD.run("STAGE_3", endpoint="")
    assert r["ok"] is True and r["advisory"] == "endpoint_unset"
    assert r["score"] is None and r["verdict"] == "SKIP"


def test_choice_projection_mapping():
    """choice/confidence → monitor 形状（投影规则单源）。"""
    assert MD.project("pass", 0.9) == {"choice": "pass", "verdict": "PASS",
                                       "score": 0.9, "confidence": 0.9}
    f = MD.project("fail", 0.9)
    assert f["verdict"] == "FAIL" and abs(f["score"] - 0.1) < 1e-9
    u = MD.project("uncertain", 0.3)
    assert u["verdict"] == "WARN" and u["score"] == 0.5
    with pytest.raises(ValueError):
        MD.project("maybe", 0.5)


def test_build_request_shape_is_typed_choice():
    req = MD.build_request("STAGE_4", worktree="/w", branch="b")
    q = req["questions"][MD.QUESTION_ID]
    assert q["type"] == "choice" and set(q["criteria"]) == {"pass", "fail", "uncertain"}
    assert req["state"]["stage"] == "STAGE_4" and req["return_details"] is True


def test_parse_response_missing_or_invalid_answer():
    assert MD.parse_response({})["ok"] is False
    bad = {"answers": {MD.QUESTION_ID: {"choice": "maybe", "confidence": 0.5}}}
    assert MD.parse_response(bad)["ok"] is False


def test_run_end_to_end_against_fake_backend(fake_backend):
    """真 HTTP 环：请求体是 gate_stage typed-choice；回包投影为 PASS/score。"""
    endpoint, box = fake_backend
    r = MD.run("STAGE_3", endpoint=endpoint, worktree="/w", branch="b")
    assert r["ok"] and r["verdict"] == "PASS" and r["score"] == 0.87
    assert r["provider"] == "systemone"
    assert box["seen"]["questions"][MD.QUESTION_ID]["type"] == "choice"
    # 失败类 choice 也走同一通道
    box["choice"] = "fail"
    r2 = MD.run("STAGE_3", endpoint=endpoint)
    assert r2["ok"] and r2["verdict"] == "FAIL" and abs(r2["score"] - 0.13) < 1e-9


def test_backend_unreachable_is_named_error():
    """后端不可达 ⟹ 具名错误（禁静默给默认分）。"""
    r = MD.run("STAGE_3", endpoint="http://127.0.0.1:1", timeout=2.0)
    assert r["ok"] is False and r["error"].startswith("backend_error")
    assert r["verdict"] == "UNKNOWN" and r["score"] is None


def test_cli_wires_decision_backend_and_keeps_legacy_escape_hatch():
    """接线面：`_monitor_api` 主路径调决策后端；旧 PRM 车道只由 env 逃生舱开启；
    机检面带 `monitor_last`（复盘可见）。"""
    src = CLI.read_text(encoding="utf-8")
    assert "gk_monitor_decision.py" in src
    assert "GK_MONITOR_API_LEGACY" in src
    assert "monitor_last" in src


def test_sink_machine_check_carries_monitor_last(tmp_path):
    """`gk_ecc_sink` 投影把 monitor_history 末条带进 machine_check（复盘面）。"""
    import gk_ecc_sink as SINK
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"monitor_history": [
        {"score": 0.42, "verdict": "WARN", "mode": "--api", "ts": "2026-10-31T00:00:00Z"}]}}),
        encoding="utf-8")
    ecc = {"subagent_id": "sub-x", "task": "t", "conclusion": "c", "timestamp": "now"}
    r = SINK.persist(str(st), json.dumps(ecc), domain="audit", batch_id="b1",
                     arm="a1", root=str(tmp_path))
    assert r["ok"], r
    rec = json.loads(Path(str(st) + ".history-archive.jsonl").read_text(encoding="utf-8")
                     .splitlines()[0])
    assert rec["machine_check"]["monitor_last"]["score"] == 0.42
    assert rec["machine_check"]["monitor_last"]["verdict"] == "WARN"


# ─── 合成样本校准（2026-10-31，owner 裁定：最小可行性合成测试验证）───────────────
# 说明：合成样本**只证明仪器可跑**（ρ/一致率/门槛判定实现正确），不证明模型可用。
# 真实转正须用真实样本 + owner 复核；本组臂同时钉死「不足 n 不得宣称可转正」。

def _mk_calib_state(tmp_path, n, invert=False, mismatch=False):
    mons, hums = [], []
    for i in range(n):
        s = i / float(max(1, n - 1))
        hs = (1.0 - s) if invert else s
        mons.append({"stage": "ECO-EDIT", "to": "ECO-EDIT",
                     "score": round(s, 4), "mode": "--api"})
        hums.append({"stage": ("STAGE_3" if mismatch else "ECO-EDIT"),
                     "human_score": round(hs, 4), "verdicts_json": {}})
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"monitor_history": mons,
                                            "human_calibration_log": hums}}),
                  encoding="utf-8")
    return str(st)


def test_spearman_monotone_inverse_and_degenerate():
    assert MD.spearman([1, 2, 3, 4], [10, 20, 30, 40]) == 1.0
    assert MD.spearman([1, 2, 3, 4], [40, 30, 20, 10]) == -1.0
    assert MD.spearman([1, 2, 3], [5, 5, 5]) is None      # 方差 0 ⟹ 不猜 0
    assert MD.spearman([1], [1]) is None                  # n<2


def test_verdict_thresholds_single_source():
    assert [MD.verdict_of(x) for x in (0.9, 0.75, 0.6, 0.5, 0.2)] ==         ["PASS", "PASS", "WARN", "WARN", "FAIL"]


def test_calibrate_synthetic_20_pairs_is_promotable(tmp_path):
    """合成 20 对单调样本 ⟹ ρ=1.0 / 一致率 1.0 / promotable（仪器正确）。"""
    st = _mk_calib_state(tmp_path, 20)
    r = MD.calibrate(st)
    assert r["ok"] and r["n"] == 20
    assert r["spearman"] == 1.0 and r["agreement"] == 1.0
    assert r["promotable"] is True and r["unmatched"] == 0
    assert "synthetic" in r["note"]


def test_calibrate_below_min_n_not_promotable(tmp_path):
    """样本不足 MIN_N ⟹ **不得**宣称可转正（n=10）。"""
    st = _mk_calib_state(tmp_path, 10)
    r = MD.calibrate(st)
    assert r["n"] == 10 and r["promotable"] is False


def test_calibrate_inverse_correlation_not_promotable(tmp_path):
    """方向相反（ρ=-1）即便 n 足够也不可转正（防止拿绝对值糊弄）。"""
    st = _mk_calib_state(tmp_path, 20, invert=True)
    r = MD.calibrate(st)
    assert r["n"] == 20 and r["spearman"] == -1.0 and r["promotable"] is False


def test_calibrate_stage_mismatch_counts_unmatched(tmp_path):
    """两侧 stage 不同 ⟹ 该对作废并计数（不重排硬凑）。"""
    st = _mk_calib_state(tmp_path, 20, mismatch=True)
    r = MD.calibrate(st)
    assert r["n"] == 0 and r["unmatched"] == 20
    assert r["promotable"] is False


def test_calibrate_cli_prints_json(tmp_path):
    """CLI calib 子命令可用（合成 state → rc=0 + JSON 读数）。"""
    import subprocess
    st = _mk_calib_state(tmp_path, 20)
    mod = str(Path(__file__).with_name("gk_monitor_decision.py"))
    p = subprocess.run([sys.executable, mod, "calib", "--state", st],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    assert out["n"] == 20 and out["promotable"] is True
