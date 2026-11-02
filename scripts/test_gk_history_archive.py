#!/usr/bin/env python3
"""C1②（`ECC-0F1DAF8C787C`）红先臂 —— `subagent_history` 溢出条目**代数归档**（2026-09-28）。

病象（计划 §十一-C1②）：落库块以 `while … hist.pop(0)` 把溢出条目**直接丢弃**（不可回溯），
与 2026-09-27「提配额 + **归档释放**」裁定相悖 ⟹ state 撞墙时历史静默蒸发。

判据（红先，HEAD 必红）：溢出的出窗条目须先 append 到旁挂 `<state>.history-archive.jsonl`
（append-only，可回溯、不删），再出窗；归档失败须留痕（`HISTORY_ARCHIVE_FAILED`）。
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _hist_pipeline() -> str:
    txt = CLI.read_text(encoding="utf-8")
    i = txt.index("GK_HMAC_VALID=")
    j = txt.index('\n"', i) + 1
    k = txt.index("\n", j + 1)
    return txt[i:k]


def _run_payload(tmp_path, ecc: dict, hist: list) -> Path:
    """抽取落库载荷、代入路径、以给定 history 预置 state，真跑后返回 state 路径。"""
    txt = CLI.read_text(encoding="utf-8")
    i = txt.index("GK_HMAC_VALID=")
    src = txt[i:txt.index('\n"', i) + 1]
    body = src.split('python3 -c "', 1)[1]
    state = tmp_path / ".gatekeeper.state"
    state.write_text(json.dumps({"gate_data": {"subagent_history": hist}}, ensure_ascii=False),
                     encoding="utf-8")
    out = tmp_path / "sub-1.json"
    out.write_text(json.dumps(ecc, ensure_ascii=False), encoding="utf-8")
    # [ECC-BECE9B3C0F5E] 抽出的 `body` 是 **python 源码** ⟹ 代入的路径须用**正斜杠**：Windows 盘符
    #   路径 `C:\Users\…` 里的 `\U` 在源码里是**非法 unicode 转义**（SyntaxError: unicodeescape）
    #   ⟹ 该臂在 Windows 宿主必红。正斜杠在 Windows python 上等价可用。
    def _pysrc(p):
        return str(p).replace("\\", "/")
    body = (body.replace("$SKILL_DIR", _pysrc(CLI.parent)).replace("$STATE_FILE", _pysrc(state))
                .replace("$GK_DBG_LOG", _pysrc(tmp_path / "dbg.log")))
    env = dict(os.environ, GK_TASK=ecc.get("task", ""), GK_HMAC_VALID="skip",
               GK_OUTPUT_FILE=str(out), GK_REPORT_FILE=str(tmp_path / "sub-1.md"))
    r = subprocess.run([sys.executable, "-c", body], input=json.dumps(ecc),
                       capture_output=True, text=True, env=env, timeout=90)
    assert r.returncode == 0, (r.returncode, r.stdout[-600:], r.stderr[-600:])
    return state


def _ecc(sid: str) -> dict:
    return {"mode": "subagent", "subagent_id": sid, "nonce": "n-" + sid,
            "timestamp": "2026-09-28T00:00:00+00:00", "task": "t", "conclusion": "c"}


def _hist_max_bytes() -> int:
    """历史裁剪线（**源码单源**）：行为臂按当前线值造数据 —— 禁压线（`GK_STATE_TRIM_KB` 会把
    行为臂跑在生产不存在的配置上）、禁硬编码条数（2026-10-26 抬线 96KB→128KB 后 3×40KB
    不再越线，该臂即失配变红）。"""
    m = re.search(r"_HIST_MAX_BYTES=(\d+)", CLI.read_text(encoding="utf-8"))
    assert m, "CLI 里找不到 _HIST_MAX_BYTES 赋值（裁剪线单源漂移？）"
    return int(m.group(1))


def test_history_block_archives_overflow():
    """② 落库段须含旁挂归档落点（`history-archive.jsonl`）。"""
    assert "history-archive.jsonl" in _hist_pipeline(), (
        "落库段未接线溢出条目归档 ⟹ pop(0) 直接丢弃、历史不可回溯（C1② 未落）")


def test_overflow_entries_archived_not_dropped(tmp_path):
    """行为臂：预置超配额 history ⟹ 出窗条目落 `history-archive.jsonl` 且不再驻留 state（红先必红）。"""
    # 每条 ~40KB；条数按**当前线值**动态取（线值//40KB + 2 ⟹ 必越线且至少溢出一条）
    n = _hist_max_bytes() // 40000 + 2
    big = [{"subagent_id": "old-%d" % i, "conclusion": "x" * 40000} for i in range(n)]
    state = _run_payload(tmp_path, _ecc("sub-new"), big)
    arc = Path(str(state) + ".history-archive.jsonl")
    assert arc.is_file(), "溢出条目未归档（缺 history-archive.jsonl）⟹ 历史静默蒸发"
    ids = [json.loads(ln)["subagent_id"] for ln in arc.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert "old-0" in ids, ids
    d = json.loads(state.read_text(encoding="utf-8"))
    kept = [e.get("subagent_id") for e in d["gate_data"]["subagent_history"]]
    assert "old-0" not in kept, kept
    assert kept[-1] == "sub-new", kept
