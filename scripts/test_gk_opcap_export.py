#!/usr/bin/env python3
"""判据5 载体红先臂：`gk_opcap_export`（只读结算导出，2026-10-24）。

口径来自外部复现包的 `opcap_evidence.py`：
  · 借款 = budget-log 中 `source=code-fix`；结算桶 = 背书 finding 的关闭状态；
  · 分母**只能是借款数**（finding 计数不进分母）；
  · x8 = register→close 时延；只读、零写盘。
"""
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gk_opcap_export as X  # noqa: E402


@pytest.fixture(autouse=True)
def _no_ambient_hook_log(tmp_path, monkeypatch):
    """隔离：默认指到不存在的 hook 日志（否则测试会读仓库真实日志 ⟹ 结果随环境漂移）。"""
    monkeypatch.setenv("GK_HOOK_LOG", str(tmp_path / "no-hook.log"))


def _mk(tmp_path, findings, events):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}, ensure_ascii=False),
                  encoding="utf-8", newline="\n")
    bl = Path(str(st) + ".budget-log.jsonl")
    bl.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events),
                  encoding="utf-8", newline="\n")
    return str(st)


F1 = {"id": "ECC-AAAAAAAAAAAA", "status": "fixed",
      "created_at": "2026-10-01T00:00:00Z", "verified_at": "2026-10-01T02:00:00Z"}
F2 = {"id": "ECC-BBBBBBBBBBBB", "status": "open", "created_at": "2026-10-02T00:00:00Z"}


def _fix(reason):
    return {"ts": "2026-10-03T00:00:00Z", "kind": "raise", "source": "code-fix",
            "from_max": 12, "to_max": 24, "reason": reason}


def test_opcap_settlement_buckets_and_ratio(tmp_path):
    st = _mk(tmp_path, [F1, F2], [
        _fix("grant for ECC-AAAAAAAAAAAA"),
        _fix("grant for ECC-BBBBBBBBBBBB"),
        _fix("grant for ECC-CCCCCCCCCCCC"),      # 不在视 ⟹ unbacked
        {"ts": "2026-10-03T00:00:00Z", "kind": "raise", "source": "state_patch",
         "reason": "manual"},                    # 非 code-fix ⟹ 不算借款
        {"ts": "2026-10-03T00:00:00Z", "kind": "degrade", "source": "degrade"},
    ])
    out = X.export(st)
    assert out["ok"] is True, out
    lo = out["loans"]
    assert (lo["n"], lo["realized"], lo["outstanding"], lo["unbacked"]) == (3, 1, 1, 1), lo
    assert lo["settlement_ratio"] == round(1 / 3, 4), lo
    assert lo["n_degrade_events"] == 1, lo


def test_opcap_denominator_is_loans_not_findings(tmp_path):
    """把 finding 数改成 50，结算比不应变化（禁 finding 计数当分母）。"""
    many = [{"id": "ECC-%012X" % i, "status": "open"} for i in range(50)] + [F1]
    st = _mk(tmp_path, many, [_fix("ECC-AAAAAAAAAAAA")])
    out = X.export(st)
    assert out["loans"]["n"] == 1, out["loans"]
    assert out["loans"]["settlement_ratio"] == 1.0, out["loans"]
    assert out["n_findings_in_view"] == 51, out   # 上下文面仍在，但不进分母


def test_opcap_x8_latency(tmp_path):
    st = _mk(tmp_path, [F1, F2], [])
    out = X.export(st)
    x8 = out["x8_register_to_close"]
    assert x8["n_closed"] == 1, x8
    assert x8["median_hours"] == 2.0, x8


def test_opcap_is_read_only(tmp_path):
    """零写盘：state 与 budget-log 字节不变，且不新增文件。"""
    st = _mk(tmp_path, [F1], [_fix("ECC-AAAAAAAAAAAA")])
    sp, bp = Path(st), Path(st + ".budget-log.jsonl")
    before = (sp.read_bytes(), bp.read_bytes(), sorted(p.name for p in tmp_path.iterdir()))
    X.export(st)
    after = (sp.read_bytes(), bp.read_bytes(), sorted(p.name for p in tmp_path.iterdir()))
    assert before == after, "导出器写盘了（只读纪律破）"


def test_opcap_bad_lines_are_skipped(tmp_path):
    st = _mk(tmp_path, [F1], [_fix("ECC-AAAAAAAAAAAA")])
    with open(st + ".budget-log.jsonl", "a", encoding="utf-8") as f:
        f.write("{not json}\n")
    out = X.export(st)
    assert out["loans"]["n"] == 1, out["loans"]


def test_opcap_missing_state_fails_closed(tmp_path):
    out = X.export(str(tmp_path / "nope"))
    assert out["ok"] is False and out["error"] == "no_state_file", out


def test_opcap_cli_ok(tmp_path, capsys):
    st = _mk(tmp_path, [F1], [_fix("ECC-AAAAAAAAAAAA")])
    rc = X.main(["--state", st])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["ok"] is True and out["schema_version"] == "opcap-1", out


def test_opcap_view_includes_finding_archive(tmp_path):
    """ECC-CD6B34C8EB95：溢出到 `<state>.finding-archive.jsonl` 的条目须进视图（读侧 union）。

    旧实现只读 `gate_data.ecc_findings` ⟹ 溢出条在 opcap 视图里消失（同 state 两套账）。
    """
    st = _mk(tmp_path, [F1], [_fix("ECC-DDDDDDDDDDDD")])
    arch = Path(st + ".finding-archive.jsonl")
    arch.write_text(json.dumps({"id": "ECC-DDDDDDDDDDDD", "status": "closed",
                                "created_at": "2026-10-01T00:00:00Z",
                                "closed_at": "2026-10-01T01:00:00Z"}) + "\n",
                    encoding="utf-8", newline="\n")
    out = X.export(st)
    assert out["n_findings_in_view"] == 2, out
    assert out["loans"]["realized"] == 1, out["loans"]
    assert out["loans"]["outstanding"] == 0, out["loans"]


# ── 判据5（2026-11-16）：x3 / x4 本地化载体（只读，复用既有日志）──────────────
# 裁定 B：x3 = credit-ledger `exempt` 计数 / hook `INVOKE event=PreToolUse` 计数；
#        x4 = budget-log 提额事件 / state `_advance_log` 推进条数。**不新增埋点**。
def test_x3_x4_carriers_from_existing_logs(tmp_path, monkeypatch):
    st = _mk(tmp_path, [F1], [
        {"ts": "2026-10-03T00:00:00Z", "kind": "raise", "source": "advance_env", "to_max": 24},
        {"ts": "2026-10-03T00:01:00Z", "kind": "raise", "source": "state_patch_set_nested", "to_max": 24},
        {"ts": "2026-10-03T00:02:00Z", "kind": "raise", "source": "code-fix",
         "reason": "grant for ECC-AAAAAAAAAAAA", "to_max": 24},
        {"ts": "2026-10-03T00:03:00Z", "kind": "grant", "source": "advance", "to_max": 24},
    ])
    # 真实形态（2026-11-16 实测）：`_advance_log` 在 **gate_data** 下，不在顶层。
    d = json.loads(Path(st).read_text(encoding="utf-8"))
    d["gate_data"]["_advance_log"] = [{"to_stage": "STAGE_1"}] * 4
    Path(st).write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    Path(st + ".credit-ledger.jsonl").write_text(
        "".join(json.dumps({"ts": "x", "kind": "exempt", "delta": -1}) + "\n" for _ in range(3)),
        encoding="utf-8", newline="\n")
    # 真实形态：hook 日志行以时间戳开头（`<ts> INVOKE event=PreToolUse …`）。
    hl = tmp_path / "hook.log"
    hl.write_text("2026-10-06 00:06:11 INVOKE event=PreToolUse tool=Edit cwd=/x\n"
                  "2026-10-06 00:06:54 INVOKE event=PreToolUse tool=Bash cwd=/x\n"
                  "2026-10-06 00:07:01 INVOKE event=PostToolUse tool=Edit cwd=/x\n",
                  encoding="utf-8")
    monkeypatch.setenv("GK_HOOK_LOG", str(hl))
    out = X.export(st)
    assert out["x3_ack_injected"] == {"exempt": 3, "gate_invokes": 2}, out.get("x3_ack_injected")
    assert out["x4_overrides"] == {"events": 3, "gate_invokes": 2, "advances": 4}, \
        out.get("x4_overrides")


def test_x4_advance_log_top_level_legacy_fallback(tmp_path):
    """兼容旧形态：`_advance_log` 在顶层时仍可计数（仅作上下文，不当分母）。"""
    st = _mk(tmp_path, [F1], [
        {"ts": "2026-10-03T00:00:00Z", "kind": "raise", "source": "advance_env", "to_max": 24},
    ])
    d = json.loads(Path(st).read_text(encoding="utf-8"))
    d["_advance_log"] = [{"to_stage": "STAGE_1"}] * 7
    Path(st).write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    out = X.export(st)
    assert out["x4_overrides"] == {"events": 1, "gate_invokes": None, "advances": 7}, \
        out.get("x4_overrides")


def test_x3_x4_carriers_absent_report_none(tmp_path, monkeypatch):
    st = _mk(tmp_path, [F1], [])
    monkeypatch.setenv("GK_HOOK_LOG", str(tmp_path / "missing.log"))
    out = X.export(st)
    assert out["x3_ack_injected"] == {"exempt": None, "gate_invokes": None}, out.get("x3_ack_injected")
    assert out["x4_overrides"] == {"events": 0, "gate_invokes": None, "advances": 0}, \
        out.get("x4_overrides")
