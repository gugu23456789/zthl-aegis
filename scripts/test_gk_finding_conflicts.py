#!/usr/bin/env python3
"""`gk_finding.conflicts`（跨源联邦冲突 **收敛**）单测。

归属（2026-09-28，user 裁「多源联邦管控应该收进元数据中枢」）：本缺陷 = 元数据中枢·全序列打通
②（命名族 4→1）/③（单一 `resolve_state`）之**实现缺口**，叶 finding `ECC-95175BA03B50`。

被测面：`gk_finding.conflicts(state_file, converge=, apply=, dedupe=)` ——
  · 默认：只报（三源同 id 者；附 `kind` ∈ {mirror, divergent, archive-only}）；
  · `converge`（dry-run）：按确定性策略算权威（**只在可写源内裁**，archive 不得当选）+ 报拟动，**零写盘**；
  · `converge + apply`：把权威 `status` 对齐到**所有可写源**（base/domain；archive 只读），幂等；
  · `+ dedupe`：**只清真镜像**（同 id 跨可写源且指纹全等），代际分歧**只报不删**（人工裁决）。
策略（user 裁）= **终态优先（closed/fixed/rejected > open）+ 最近时间戳 + base 兜底**。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_finding as gf  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_ledger(monkeypatch):
    """本文件全是**单目录**语义（base/domain 同在 tmp）⟹ 必须关掉跨仓候选。

    否则 `_candidate_repos` 会把技能仓实账并进来：实测 `writable_duplicates` 被实账 12 条
    双源 id 污染（计划「开源前置」§5.2 U13），用例全红且与断言无关。
    """
    monkeypatch.setenv("GK_FINDING_ISOLATE", "1")


def _mk(path: Path, findings: list) -> None:
    path.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}), encoding="utf-8")


def _f(fid: str, status: str, **kw) -> dict:
    d = {"id": fid, "title": "t-" + fid, "status": status}
    d.update(kw)
    return d


def _setup(tmp_path: Path) -> str:
    """base：A=open(旧) / B=closed(旧)；域 demo：A=closed(新) / B=open(新) ⟹ 两条冲突。"""
    base, dom = tmp_path / ".gatekeeper.state", tmp_path / ".gatekeeper.state.demo"
    _mk(base, [_f("ECC-AAAA00000001", "open", created_at="2026-01-01T00:00:00+00:00"),
               _f("ECC-BBBB00000002", "closed", closed_at="2026-01-01T00:00:00+00:00")])
    _mk(dom, [_f("ECC-AAAA00000001", "closed", closed_at="2026-02-01T00:00:00+00:00"),
              _f("ECC-BBBB00000002", "open", created_at="2026-03-01T00:00:00+00:00")])
    return str(base)


def test_ledger_sees_cross_source_conflicts(tmp_path):
    """① 联邦视图能识别同 id 跨源状态不一致（前置：冲突判定本身）。"""
    led = gf.ledger(_setup(tmp_path))
    assert {c["id"] for c in led["conflicts"]} == {"ECC-AAAA00000001", "ECC-BBBB00000002"}, \
        led["conflicts"]


def test_converge_dry_run_reports_but_does_not_write(tmp_path):
    """② `converge`（不 apply）= **零写盘**，且按策略报权威（终态胜）。"""
    base = _setup(tmp_path)
    before = Path(base).read_text(encoding="utf-8")
    out = gf.conflicts(base, converge=True, apply=False)
    assert out["converged"] == 0, "dry-run 不得记改动数"
    assert len(out["conflicts"]) == 2
    assert all(c["winner"]["status"] == "closed" for c in out["conflicts"]), out["conflicts"]
    assert Path(base).read_text(encoding="utf-8") == before, "dry-run 必须零写盘"


def test_converge_apply_aligns_all_sources_then_idempotent(tmp_path):
    """③ `converge+apply` 把权威对齐到所有可写源 ⟹ 冲突归零；**二次 apply 幂等**（0 改动）。"""
    base = _setup(tmp_path)
    out = gf.conflicts(base, converge=True, apply=True)
    assert out["applied"] is True and out["converged"] >= 1
    assert gf.ledger(base)["conflicts"] == [], "收敛后应无跨源冲突"
    assert gf.conflicts(base, converge=True, apply=True)["converged"] == 0, "二次 apply 应幂等"


def test_policy_terminal_first_and_recency_tiebreak(tmp_path):
    """④ 策略：三源（base open / d1 closed 旧 / d2 closed 新）⟹ 终态胜且**权威取最近** = d2。"""
    base, d1, d2 = (tmp_path / ".gatekeeper.state", tmp_path / ".gatekeeper.state.d1",
                    tmp_path / ".gatekeeper.state.d2")
    _mk(base, [_f("ECC-CCCC00000003", "open")])
    _mk(d1, [_f("ECC-CCCC00000003", "closed", closed_at="2026-01-01T00:00:00+00:00")])
    _mk(d2, [_f("ECC-CCCC00000003", "closed", closed_at="2026-04-01T00:00:00+00:00")])
    c = gf.conflicts(str(base), converge=True, apply=False)["conflicts"][0]
    assert c["winner"]["status"] == "closed"
    assert c["winner"]["source"].endswith(".d2"), c["winner"]


def test_dedupe_reaches_single_authority_for_true_mirrors(tmp_path):
    """⑤ **单一权威本体**：多源同 id **真镜像**（指纹全等）⟹ 写前置唯一性门**拒写**（禁多源可写）；
    `--dedupe` 后只剩胜者那份 ⟹ `writable_duplicates`/`writable_mirrors` 归零 ⟹ 写恢复。"""
    base, dom = tmp_path / ".gatekeeper.state", tmp_path / ".gatekeeper.state.demo"
    _mk(base, [_f("ECC-DDDD00000004", "closed", closed_at="2026-05-01T00:00:00+00:00")])
    _mk(dom, [_f("ECC-DDDD00000004", "closed", closed_at="2026-05-01T00:00:00+00:00")])
    b = str(base)
    assert gf.writable_duplicates(b) == ["ECC-DDDD00000004"]
    assert gf.writable_mirrors(b) == ["ECC-DDDD00000004"], "同内容 ⟹ 真镜像"
    with pytest.raises(ValueError, match="FINDING_MULTI_SOURCE"):
        gf.close(b, "ECC-DDDD00000004", "x")           # 多源 ⟹ 拒写
    out = gf.conflicts(b, converge=True, apply=True, dedupe=True)
    assert out["deduped"] >= 1
    assert gf.writable_duplicates(b) == [], "dedupe 后应达单一权威"
    assert gf.writable_mirrors(b) == []
    assert gf.close(b, "ECC-DDDD00000004", "after-dedupe")["id"] == "ECC-DDDD00000004"


def test_divergent_duplicates_reported_but_never_deleted(tmp_path):
    """⑥ **代际分歧只报不删**（user 裁「只清真镜像，分歧仅登记」）：同 id 跨源**内容不同**
    （status/时间戳不同）⟹ `kind=divergent`、`dedupe` **零删**（否则丢一代记录）；写门仍拒写。"""
    base, dom = tmp_path / ".gatekeeper.state", tmp_path / ".gatekeeper.state.demo"
    _mk(base, [_f("ECC-EEEE00000005", "closed", closed_at="2026-05-01T00:00:00+00:00")])
    _mk(dom, [_f("ECC-EEEE00000005", "open", created_at="2026-01-01T00:00:00+00:00")])
    b = str(base)
    assert gf.writable_mirrors(b) == [], "内容不同 ⟹ 非镜像"
    kind = {c["id"]: c["kind"] for c in gf.conflicts(b, converge=True)["conflicts"]}
    assert kind["ECC-EEEE00000005"] == "divergent", kind
    out = gf.conflicts(b, converge=True, apply=True, dedupe=True)
    assert out["deduped"] == 0, "分歧不得被删"
    assert gf.writable_duplicates(b) == ["ECC-EEEE00000005"]
    assert len({f["status"] for f in gf.load_findings(b)
                if f["id"] == "ECC-EEEE00000005"}) == 1, "base 未被 dedupe 触及"
    with pytest.raises(ValueError, match="FINDING_MULTI_SOURCE"):
        gf.close(b, "ECC-EEEE00000005", "x")


def test_archive_never_authoritative_for_dedupe(tmp_path):
    """⑦ **archive 只读，不得当选权威**（2026-09-28 实测数据丢失 bug 回归）：base↔archive 同 id
    且 archive **更新时间更新**时，旧实现让 archive 当选 ⟹ `--dedupe` **删掉 base 活体条目**。
    现应：`writable_duplicates`/`writable_mirrors` 均空（除 archive 外仅 1 可写源）且 `deduped=0`。"""
    base = tmp_path / ".gatekeeper.state"
    _mk(base, [_f("ECC-FFFF00000006", "closed", closed_at="2026-06-01T00:00:00+00:00")])
    (tmp_path / ".gatekeeper.state.finding-archive.jsonl").write_text(
        json.dumps(_f("ECC-FFFF00000006", "closed", closed_at="2026-12-01T00:00:00+00:00")) + "\n",
        encoding="utf-8")
    b = str(base)
    assert gf.writable_duplicates(b) == [] and gf.writable_mirrors(b) == []
    out = gf.conflicts(b, converge=True, apply=True, dedupe=True)
    assert out["deduped"] == 0, "archive 不得驱动删除"
    ids = [f["id"] for f in gf.load_findings(b)]
    assert ids == ["ECC-FFFF00000006"], "base 活体条目必须保留（不得被 archive 挤掉）"


def test_converge_align_does_not_create_unsourced_closure(tmp_path):
    """⑧ 2026-10-08（converge 合规修复）：**converge 不得制造「无据关闭」**。

    权威为终态但缺 `basis_ref` / `verify_source` kind 非白名单时，旧实现只写 status ⟹ 目标源
    变「无据关闭」（monitor `ecc_form` bad_close FAIL）。修后：补 `basis_ref`，仍不合规则回落
    `register-only`（c9 显式「仅登记」出口）。"""
    base, dom = tmp_path / ".gatekeeper.state", tmp_path / ".gatekeeper.state.demo"
    _mk(base, [_f("ECC-111100000007", "open")])
    _mk(dom, [_f("ECC-111100000007", "closed", closed_at="2026-05-01T00:00:00+00:00",
                 verify_source="metric-class non-defect (cf X)")])
    b = str(base)
    gf.conflicts(b, converge=True, apply=True)
    e = next(f for f in gf.load_findings(b) if f["id"] == "ECC-111100000007")
    assert e["status"] == "closed"
    # 合规：basis_ref 非空 **或** vsrc == register-only（否则 bad_close FAIL）
    assert (e.get("basis_ref") or "") or e.get("verify_source") == "register-only", e
    if e.get("verify_source") != "register-only":
        _kinds = [p.split(":", 1)[0].strip().lower()
                  for p in e["verify_source"].split(";") if p.strip()]
        assert all(k in gf._VERIFY_SOURCES for k in _kinds), e
