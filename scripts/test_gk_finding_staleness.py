#!/usr/bin/env python3
"""时效性置信度只读标签（owner 2026-11-12）。

需求原话：「ecc-finding 需要加个时效性置信度只读标签，唯一作用是提醒时间过了很久大概这个
finding 内容全错了」。

口径（刻意收窄，防止变成第二个自动关单通道）：
  · **只读派生**：不写盘、不改 `status`、不参与任何门禁；
  · 基准 = 最近一次**复核**动作（`_last_touch`：verify / amend-title / close / created_at 取最大）；
  · `<14d` = `fresh`（不展示）；`14–29d` = `aging`（可能已过时）；`≥30d` = `stale`（大概率已失真）；
  · 无时间戳 = `unknown`（不臆造时间）。
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_finding as GF  # noqa: E402

NOW = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
FID = "ECC-STALETEST01"


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def _finding(**kw):
    f = {"id": FID, "title": "staleness 夹具", "status": "open", "created_at": _iso(0)}
    f.update(kw)
    return f


def _state(tmp_path, findings):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}, ensure_ascii=False),
                  encoding="utf-8", newline="\n")
    return str(st)


def test_fresh_finding_has_no_label(tmp_path):
    st = _state(tmp_path, [_finding(created_at=_iso(2))])
    r = GF.stale_labels(st, now=NOW)
    assert r["counts"]["fresh"] == 1 and r["items"] == [], r


def test_aging_threshold_and_label(tmp_path):
    st = _state(tmp_path, [_finding(created_at=_iso(20))])
    r = GF.stale_labels(st, now=NOW)
    assert r["counts"]["aging"] == 1, r
    assert r["items"][0]["confidence"] == "aging"
    assert "可能已过时" in r["items"][0]["label"], r


def test_stale_threshold_and_label(tmp_path):
    st = _state(tmp_path, [_finding(created_at=_iso(45))])
    r = GF.stale_labels(st, now=NOW)
    assert r["counts"]["stale"] == 1, r
    assert "大概率已失真" in r["items"][0]["label"], r
    assert 44 < r["items"][0]["age_days"] < 46, r


def test_recent_verify_resets_age(tmp_path):
    """基准 = 最近一次**复核**：created 很久但 2 天前 verify 过 ⟹ 不算过期。"""
    st = _state(tmp_path, [_finding(created_at=_iso(90), verified_at=_iso(2))])
    r = GF.stale_labels(st, now=NOW)
    assert r["counts"]["fresh"] == 1 and r["items"] == [], r


def test_closed_uses_closed_at(tmp_path):
    st = _state(tmp_path, [_finding(created_at=_iso(90), status="closed", closed_at=_iso(1))])
    r = GF.stale_labels(st, now=NOW)
    assert r["counts"]["fresh"] == 1, r


def test_unknown_when_no_timestamp(tmp_path):
    f = _finding()
    f.pop("created_at")
    st = _state(tmp_path, [f])
    r = GF.stale_labels(st, now=NOW)
    assert r["counts"]["unknown"] == 1 and r["items"] == [], r


def test_read_only_no_write_and_no_status_change(tmp_path):
    """**只读纪律**：跑完 state 逐字节不变、status 不变（禁做成自动关单/重开通道）。"""
    st = _state(tmp_path, [_finding(created_at=_iso(60))])
    before = Path(st).read_text(encoding="utf-8")
    GF.stale_labels(st, now=NOW)
    assert Path(st).read_text(encoding="utf-8") == before, "只读标签写了 state"
    d = json.loads(before)
    assert d["gate_data"]["ecc_findings"][0]["status"] == "open", "只读标签改了 status"


def test_status_output_carries_stale_labels(tmp_path, capsys):
    """接线：`gk_finding.py status` 输出须带 `stale_labels`（与 dual_form/repo_index 同层）。"""
    st = _state(tmp_path, [_finding(created_at=_iso(60))])
    GF.main(["status", st])
    out = json.loads(capsys.readouterr().out)
    body = out.get("status") or {}
    assert "stale_labels" in body, out
    assert body["stale_labels"]["counts"]["stale"] == 1, body["stale_labels"]


# ── 文档契约：**事实块自动刷新** ⟷ 代码登记点（2026-11-12 owner 令：正本改自动事实块）──────
SKILL = SCRIPTS.parent


def _spec_text() -> str:
    return (SKILL / "references" / "ecc-write-spec.md").read_text(encoding="utf-8")


def test_spec_has_autogen_facts_block_with_code_values():
    """正本须含自动事实块，且阈值/白名单取自 `gk_finding`（禁手写第二份清单）。"""
    import gk_docgen_facts as DG
    spec = _spec_text()
    assert DG._FSTART in spec and DG._FEND in spec, "正本缺 GK-FINDING-FACTS 标记"
    block = DG.render_finding_facts(DG.collect_finding_facts(SKILL))
    assert block in spec, "事实块与生成结果不一致（跑 gk_docgen_facts.py --write）"
    for v in (str(GF.STALE_AGING_DAYS), str(GF.STALE_STALE_DAYS)):
        assert ("| 时效 " in block and v in block), "事实块缺时效阈值 %r" % v
    assert "`review`" in block and "弱证据" in block, "事实块缺「review 弱证据」口径"


def test_spec_prose_does_not_hardcode_thresholds():
    """正文**不得**再写死时效天数（否则改了代码不重生成 ⟹ 正文静默滞后）。"""
    spec = _spec_text()
    head = spec.split("### 3.3")[0]          # 只看事实块之前的手写正文
    assert "%dd" % GF.STALE_STALE_DAYS not in head, "正文仍写死 stale 阈值"
    assert "%d–" % GF.STALE_AGING_DAYS not in head, "正文仍写死 aging 区间"


def test_generated_block_tracks_code_change():
    """负臂（守非空转）：换一套登记点 ⟹ 渲染结果必须随之变化（不是写死字符串）。"""
    import gk_docgen_facts as DG
    live = DG.collect_finding_facts(SKILL)
    base = DG.render_finding_facts(live)
    drifted = dict(live)
    drifted["accept_kinds"] = list(live.get("accept_kinds") or []) + ["probe-kind"]
    assert DG.render_finding_facts(drifted) != base, "换了登记点渲染结果不变 ⟹ 事实块是写死的"
