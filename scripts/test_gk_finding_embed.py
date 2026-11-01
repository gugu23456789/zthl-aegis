"""红先臂：principal 的 embedding 粗筛 + 离线嵌入 producer（finding `ECC-FAF2A8F0A0DF`）。

背景（2026-10-10，用户裁定 ③-A「完整（consumer+producer）」）：
`principal` 的 ② 阶段此前只用**锚集/词集 Jaccard**（`ECC-7F6AC6625A45` 后加 title 词）。
真台账 551 条仍 **537 孤项** —— 中文 finding 标题的**语义近重复**（措辞不同、token 不重叠）
Jaccard 恒 0，无法召回。A/B 实测：`bge-small-zh-v1.5`（中文）P@1=79.2%、
`gap=0.130`，显著优于 gitnexus 自带的英文 `arctic-embed-xs`（P@1=60.4%、gap=0.079）。

契约（用户裁定 ③-A）：
  · 旁挂契约文件 `<state>.finding-embeddings.jsonl`（每行 `{"id":..,"vec":[..]}`，不进 git）；
  · `principal` **自动探测**该文件：存在 ⟹ ② 阶段对 `cos >= emb_tau` 的 finding 对**强制直连**
    （粗筛召回，与 Jaccard 取并集）；缺失 ⟹ **fail-open 退回纯 Jaccard**（现况不变）；
  · **主判据仍是 root_key/锚集**，embedding 只做粗筛召回；
  · producer = `gk_finding_embed`（读 ledger → 调本地嵌入 → 写契约文件）。

**红先对照**：HEAD 版 `principal` 无 embedding 分支 ⟹ `test_principal_uses_embeddings_file`
两词集不重叠条各成单例（`root_causes=0`）必红；`gk_finding_embed` 模块不存在 ⟹
`test_embed_write_contract` import 必红。
`test_principal_no_embeddings_fail_open` 为**非红**（HEAD 即绿），不进红先集。
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_finding  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_ledger(monkeypatch):
    """本文件用 tmp state 造最小台账 ⟹ 关掉跨仓候选，避免读到技能仓实账。

    实测未隔离时 `principal` 的 `root_causes` 由 1 变 13（计划「开源前置」§5.2 U13）。
    """
    monkeypatch.setenv("GK_FINDING_ISOLATE", "1")


def _mk(tmp_path, name, findings):
    """造一个最小 state（`gate_data.ecc_findings`）并返回其绝对路径。"""
    p = os.path.join(str(tmp_path), name)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"gate_data": {"ecc_findings": findings}}, fh, ensure_ascii=False)
    return p


def _write_emb(base, vectors):
    """写旁挂契约文件 `<base>.finding-embeddings.jsonl`（每行 {"id":..,"vec":[..]}）。"""
    p = base + ".finding-embeddings.jsonl"
    with open(p, "w", encoding="utf-8") as fh:
        for fid, vec in vectors.items():
            fh.write(json.dumps({"id": fid, "vec": vec}) + "\n")
    return p


def test_principal_uses_embeddings_file(tmp_path):
    """正臂：无 root_key、无共享锚、**词集零重叠**但向量高余弦 ⟹ 应被 embedding 粗筛并成 1 个 RC。

    HEAD（无 embedding 分支）⟹ Jaccard=0 ⟹ 各成单例、`root_causes=0` ⟹ 红；
    读契约文件后 `cos=1.0 >= emb_tau` ⟹ 直连 ⟹ 绿。
    """
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-E1", "status": "open", "title": "缓存失效数据陈旧"},
        {"id": "ECC-E2", "status": "open", "title": "过期快照读到旧值"},
    ])
    _write_emb(base, {"ECC-E1": [1.0, 0.0, 0.0], "ECC-E2": [1.0, 0.0, 0.0]})
    out = gk_finding.principal(base)
    assert out["stats"]["root_causes"] == 1
    assert out["principal"] is not None
    assert set(out["principal"]["members"]) == {"ECC-E1", "ECC-E2"}


def test_embed_write_contract(tmp_path):
    """正臂：producer 的纯函数 `write_contract` 应把关书写到 `<state>.finding-embeddings.jsonl`。

    HEAD 无 `gk_finding_embed` 模块 ⟹ import 失败 ⟹ 红。
    """
    import gk_finding_embed  # 惰性 import：HEAD 缺失时只有本臂红
    base = os.path.join(str(tmp_path), ".gatekeeper.state")
    with open(base, "w", encoding="utf-8") as fh:
        json.dump({"gate_data": {"ecc_findings": []}}, fh, ensure_ascii=False)
    p = gk_finding_embed.write_contract(base, {"ECC-E1": [1.0, 0.0, 0.0]}, model="unit-test-bge", dim=3)
    assert p == base + ".finding-embeddings.jsonl"
    lines = [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]
    assert lines[0]["id"] == "ECC-E1"
    assert lines[0]["vec"] == [1.0, 0.0, 0.0]


def test_principal_no_embeddings_fail_open(tmp_path):
    """守卫（**非红**，HEAD 即绿）：无契约文件 ⟹ 退回纯 Jaccard，行为不变、不崩。"""
    base = _mk(tmp_path, ".gatekeeper.state", [
        {"id": "ECC-E1", "status": "open", "title": "缓存失效数据陈旧"},
        {"id": "ECC-E2", "status": "open", "title": "过期快照读到旧值"},
    ])
    out = gk_finding.principal(base)
    assert out["ok"] is True
    assert out["stats"]["root_causes"] == 0
    assert out["principal"] is None
