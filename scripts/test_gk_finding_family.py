"""红先臂：family 级聚合视图 `gk_finding.family_view` / `finding family`（只读）。

背景：红队 finding 已在 EccOutput 里带 `family`（缺陷族），但台账视图只有逐条/RC 级，
没有「按族聚账」的总览 ⟹ 分族 open/gap 覆盖只能人工数。

**红先对照**：HEAD 版 `gk_finding` 无 `family_view`、无 `family` 子命令
`git show HEAD:scripts/gk_finding.py | grep -c 'def family_view'` → **0**
⟹ 本文件整体 `AttributeError` 必红。契约：全源合并（`_entries_by_id` + `_pick_winner`，
与 `principal` 同源）、空族归 `(unassigned)`、排序 open↓ → total↓ → family↑、零写盘。

注：`_ledger_sources` 默认跨仓（技能仓活体 ledger 也在全域对账面内），故本文件用
`ZZTEST-*` 唯一族名并**按族取桶**（不断言全局 families 列表/总量），避免宿主台账污染。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_finding  # noqa: E402


def _mk(tmp_path, name, findings):
    p = os.path.join(str(tmp_path), name)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"gate_data": {"ecc_findings": findings}}, fh, ensure_ascii=False)
    return p


def _fam(out, name):
    return next((f for f in out["families"] if f["family"] == name), None)


def test_family_groups_counts_gap_and_layers(tmp_path):
    """正臂：同族 open/terminal 计数、gap 计数、cover_layers 并集、severity_max。"""
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-F1", "status": "open", "family": "ZZTEST-MIGRATE", "severity": "high",
         "cover_layers": ["L5", "L9"]},
        {"id": "ECC-F2", "status": "closed", "family": "ZZTEST-MIGRATE", "severity": "low",
         "cover_layers": ["L9"]},
        {"id": "ECC-F3", "status": "open", "family": "ZZTEST-CONSTRAINTS", "gap": True},
        {"id": "ECC-F4", "status": "open", "family": "ZZTEST-CONSTRAINTS"},
    ])
    out = gk_finding.family_view(base)
    assert out["ok"] is True
    mig = _fam(out, "ZZTEST-MIGRATE")
    assert mig["total"] == 2
    assert mig["open"] == 1 and mig["terminal"] == 1
    assert mig["severity_max"] == 4.0
    assert mig["cover_layers"] == ["L5", "L9"]
    assert mig["status"] == {"closed": 1, "open": 1}
    assert mig["members"] == ["ECC-F1", "ECC-F2"]
    con = _fam(out, "ZZTEST-CONSTRAINTS")
    assert con["gap"] == 1 and con["open"] == 2
    assert out["stats"]["total"] >= 4


def test_family_unassigned_bucket(tmp_path):
    """负臂：空/缺失 family 归入 `(unassigned)`，不得丢弃或并入他族。"""
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-U1", "status": "open", "family": ""},
        {"id": "ECC-U2", "status": "open"},
        {"id": "ECC-U3", "status": "open", "family": "  "},
    ])
    out = gk_finding.family_view(base)
    un = _fam(out, "(unassigned)")
    assert un is not None
    assert {"ECC-U1", "ECC-U2", "ECC-U3"} <= set(un["members"])
    assert not [f for f in out["families"] if f["family"] != "(unassigned)"
                and {"ECC-U1", "ECC-U2", "ECC-U3"} & set(f["members"])]


def test_family_cross_source_winner_not_double_counted(tmp_path):
    """全源合并：同 id 在 base(open) 与域(closed) ⟹ 按 `_pick_winner` 记终态一次，不重复计数。"""
    _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-X1", "status": "open", "family": "ZZTEST-GHOST",
         "created_at": "2026-01-01T00:00:00+00:00"},
    ])
    _mk(tmp_path, ".gatekeeper.state.domtest1", [
        {"id": "ECC-X1", "status": "closed", "family": "ZZTEST-GHOST",
         "created_at": "2026-01-01T00:00:00+00:00", "closed_at": "2026-02-01T00:00:00+00:00"},
    ])
    base = os.path.join(str(tmp_path), ".gatekeeper.state")
    out = gk_finding.family_view(base)
    fam = _fam(out, "ZZTEST-GHOST")
    assert fam["total"] == 1
    assert fam["open"] == 0 and fam["terminal"] == 1
    assert fam["members"] == ["ECC-X1"]


def test_family_ordering_open_first_then_name(tmp_path):
    """确定性排序：open↓ → total↓ → family 字典序（不依赖遍历顺序）。"""
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-O1", "status": "open", "family": "ZZTEST-B-FAM"},
        {"id": "ECC-O2", "status": "open", "family": "ZZTEST-A-FAM"},
        {"id": "ECC-C1", "status": "closed", "family": "ZZTEST-C-FAM"},
    ])
    out = gk_finding.family_view(base)
    names = [f["family"] for f in out["families"]]
    assert names.index("ZZTEST-A-FAM") < names.index("ZZTEST-B-FAM") < names.index("ZZTEST-C-FAM")


def test_family_is_read_only(tmp_path):
    """只读负臂：`family_view` 零写盘（源文件字节不变）。"""
    base = _mk(tmp_path, ".gatekeeper.state",
               [{"id": "ECC-R1", "status": "open", "family": "RED-INLINE"}])
    before = open(base, "rb").read()
    gk_finding.family_view(base)
    assert open(base, "rb").read() == before


def test_family_cli_dispatch(tmp_path, capsys, monkeypatch):
    """接线臂：`gk_finding.py family <state>` 走 CLI 分发并出 JSON（cmd_finding 通用转发）。"""
    base = _mk(tmp_path, ".gatekeeper.state",
               [{"id": "ECC-D1", "status": "open", "family": "ZZTEST-SWALLOW"}])
    monkeypatch.setattr(sys, "argv", ["gk_finding.py", "family", base])
    gk_finding.main()
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert _fam(out, "ZZTEST-SWALLOW")["members"] == ["ECC-D1"]
