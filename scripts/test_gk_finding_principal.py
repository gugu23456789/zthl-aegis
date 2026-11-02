"""红先臂：台账级「主要矛盾」提取器 `gk_finding.principal`（finding `ECC-02710BDFAC8E`）。

背景：ECC 的 `principal` 此前只有**形式判据**（`monitor-schemas/ECC-WRITE.json`
`principal_singular_if_present`：principal 若给出则恰 1 条），**没有**「吃台账 → 吐主要矛盾」
的函数。本臂落刀该函数。

契约（用户 2026-10-10 裁定）：
  · 输入 = finding ledger **全源合并**（base + 活体域 state + archive），同 id 按 `_pick_winner` 取权威；
  · 聚类键 = `root_key` 优先（精确成组）；余项 = **锚集 Jaccard**（平均连接凝聚，τ）；
  · 排序 = 簇内 `open` 数 × severity（severity 缺失按 carrier 兜底，默认 1.0）；
  · 输出 = `principal`（**恰 1**）+ `root_causes[]`（每 RC 溶解清单）+ `orphans[]`（未归并孤项）。

**红先对照**：HEAD 版 `gk_finding` 无 `principal` ⟹ 本文件整体 `AttributeError` 必红；
`git show HEAD:scripts/gk_finding.py | grep -c 'def principal'` → **0**。
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_finding  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_host_ledger(monkeypatch, tmp_path):
    """隔离宿主台账：`_ledger_sources` 默认跨仓（会扫到技能仓活体 state），
    `principal` 的「全源合并」臂须只看见本测试的 tmp 目录。"""
    monkeypatch.setattr(gk_finding, "_candidate_repos", lambda state_file: [str(tmp_path)])


def _mk(tmp_path, name, findings):
    """造一个最小 state（`gate_data.ecc_findings`）并返回其绝对路径。"""
    p = os.path.join(str(tmp_path), name)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"gate_data": {"ecc_findings": findings}}, fh, ensure_ascii=False)
    return p


def test_principal_picks_max_open_root_key(tmp_path):
    """正臂：同 `root_key` 的 3 条 open 应聚成 1 个 RC 并被选为主矛盾（principal 恰 1）。"""
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-A1", "status": "open", "root_key": "RC1", "facets": ["carrier:M"]},
        {"id": "ECC-A2", "status": "open", "root_key": "RC1"},
        {"id": "ECC-A3", "status": "open", "root_key": "RC1", "severity": "high"},
        {"id": "ECC-B1", "status": "open", "root_key": "RC2"},
    ])
    out = gk_finding.principal(base)
    assert out["ok"] is True
    assert out["principal"] is not None
    assert out["principal"]["key"] == "root_key:RC1"
    assert set(out["principal"]["members"]) == {"ECC-A1", "ECC-A2", "ECC-A3"}
    assert out["principal"]["open"] == 3


def test_principal_cross_source_merge(tmp_path):
    """全源合并：base 与域 state 的同根因 finding 同入一图（跨源不分裂）。"""
    _mk(tmp_path, ".gatekeeper.state",
        [{"id": "ECC-X1", "status": "open", "root_key": "RCX"}])
    _mk(tmp_path, ".gatekeeper.state.domtest1", [
        {"id": "ECC-X2", "status": "open", "root_key": "RCX"},
        {"id": "ECC-X3", "status": "open", "root_key": "RCX"}])
    base = os.path.join(str(tmp_path), ".gatekeeper.state")
    out = gk_finding.principal(base)
    assert out["stats"]["total"] == 3
    assert set(out["principal"]["members"]) == {"ECC-X1", "ECC-X2", "ECC-X3"}


def test_principal_closed_not_counted(tmp_path):
    """终态不计分：全 closed 的 RC 不得被选为主矛盾。"""
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-C1", "status": "closed", "root_key": "RC1"},
        {"id": "ECC-C2", "status": "closed", "root_key": "RC1"},
        {"id": "ECC-O1", "status": "open", "root_key": "RC2"},
        {"id": "ECC-O2", "status": "open", "root_key": "RC2"},
    ])
    out = gk_finding.principal(base)
    assert out["principal"]["key"] == "root_key:RC2"
    assert out["principal"]["open"] == 2


def test_principal_orphans_listed_not_rc(tmp_path):
    """负臂：锚集不相似的孤项不得并进 RC（进 orphans，不充数）。"""
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-P1", "status": "open", "root_key": "RC1"},
        {"id": "ECC-P2", "status": "open", "root_key": "RC1"},
        {"id": "ECC-Z9", "status": "open", "anchors": ["mod:scripts/zzz.py"]},
    ])
    out = gk_finding.principal(base)
    assert "ECC-Z9" in out["orphans"]
    assert "ECC-Z9" not in out["principal"]["members"]


def test_principal_is_read_only(tmp_path):
    """只读负臂：`principal` 零写盘（源文件字节不变）。"""
    base = _mk(tmp_path, ".gatekeeper.state",
               [{"id": "ECC-R1", "status": "open", "root_key": "RC1"}])
    before = open(base, "rb").read()
    gk_finding.principal(base)
    assert open(base, "rb").read() == before


def test_principal_never_singleton(tmp_path):
    """负臂（`ECC-7F6AC6625A45`）：principal **不得**是单例孤项——即便其 score 最高。

    造：`RC1` = 2 条 open（carrier:P ⟹ score 2×2=4）；`S1` = 1 条 open severity=critical（score 8）。
    未修（HEAD）会选 `S1`（n=1）⟹ 本断言红；修后只从 n≥2 的 RC 里选 ⟹ 选 `RC1` ⟹ 绿。
    """
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-G1", "status": "open", "root_key": "RC1", "facets": ["carrier:P"]},
        {"id": "ECC-G2", "status": "open", "root_key": "RC1", "facets": ["carrier:P"]},
        {"id": "ECC-S1", "status": "open", "severity": "critical",
         "anchors": ["mod:scripts/only_here.py"]},
    ])
    out = gk_finding.principal(base)
    assert out["principal"] is not None
    assert out["principal"]["n"] >= 2
    assert out["principal"]["key"] == "root_key:RC1"


def test_title_signature_merges_reworded(tmp_path):
    """正臂（`ECC-7F6AC6625A45`）：无 root_key、无共享锚，但 title 高度重合 ⟹ 应聚成 1 个 RC。

    HEAD（签名只吃 anchors）⟹ 两条 token 皆空、`_jaccard(∅,∅)=0` ⟹ 各成单例、`root_causes=0` ⟹ 红；
    加入 title 词后过 τ=0.6 ⟹ 绿。
    """
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-T1", "status": "open", "title": "台账 主要矛盾 提取器 缺失 无法 塌缩 根因组"},
        {"id": "ECC-T2", "status": "open", "title": "台账 主要矛盾 提取器 缺失 无法 塌缩 为 根因组"},
    ])
    out = gk_finding.principal(base)
    assert out["stats"]["root_causes"] == 1
    assert set(out["principal"]["members"]) == {"ECC-T1", "ECC-T2"}


def test_singleton_root_keys_merge_by_similarity(tmp_path):
    """跨措辞合并：不同 root_key 的**单例** finding 仍须进入锚集 Jaccard 聚类。

    病象：`convert` 给每条散文标题生成唯一 `root_key`；`principal` 若把所有带
    `root_key` 的 finding 都预分组，跨措辞同根因会被永久隔成孤项。修法 = 只预分组
    `n>=2` 的 root_key 组，单例交给 ② 的 Jaccard/embedding。
    """
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-RK1", "status": "open", "root_key": "prose:aaaa",
         "title": "联网 取证 端点 载体 未定"},
        {"id": "ECC-RK2", "status": "open", "root_key": "prose:bbbb",
         "title": "联网 取证 端点 载体 未定"},
    ])
    out = gk_finding.principal(base)
    assert out["stats"]["root_causes"] == 1
    assert out["principal"] is not None
    assert set(out["principal"]["members"]) == {"ECC-RK1", "ECC-RK2"}


def test_relevance_out_excluded_from_principal(tmp_path):
    """relevance:out 留在台账供审计，但不得进 principal/orphans。"""
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-OUT", "status": "open", "root_key": "prose:out",
         "title": "离题结论", "facets": ["relevance:out"]},
        {"id": "ECC-IN1", "status": "open", "root_key": "prose:a",
         "title": "同 根因 证据 缺失", "facets": ["relevance:in"]},
        {"id": "ECC-IN2", "status": "open", "root_key": "prose:b",
         "title": "同 根因 证据 缺失", "facets": ["relevance:in"]},
    ])
    out = gk_finding.principal(base)
    assert out["stats"]["total"] == 2
    assert "ECC-OUT" not in out["orphans"]
    assert set(out["principal"]["members"]) == {"ECC-IN1", "ECC-IN2"}
