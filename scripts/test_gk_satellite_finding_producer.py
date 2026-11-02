#!/usr/bin/env python3
"""卫星生产者接线 · finding 归档面（`gk_finding.archive_closed` → `gk_satellite.append('finding')`）。

计划：`docs/plans/2026-10-04-state-satellite-storage-plan.md`
  §8（落刀点表·「片唯一写者 = 中枢」·禁第二直写者）/ §10（反例表·二写者）/ §12（命名单源）。

缺陷（HEAD）：`archive_closed` 用 `open(_archive_path(state_file), "a")` **直写**旁挂
`<state>.finding-archive.jsonl` —— 与「卫星片唯一写者 = 中枢 `gk_satellite`」冲突：
  · 无 per-arm 索引叶子（`satellite_index` 无从读回该片 ⟹ 读分裂）；
  · 无判活锚（`claim_anchor` 未被调用 ⟹ `reclaim` 一旦转 live 即可误删在用片）。

修法（本臂钉住）：改调 `gk_satellite.append(state_file, "finding", removed, batch_id=…, arm=…)`。

臂（红先 = 落刀前必红）：
  arm1 静态：`gk_finding` 无 `open(_archive_path(…), "a")` 直写；且归档路径调 `gk_satellite.append`。
  arm2 行为：`archive_closed` 归档 ⟹ ① 片落盘且逐条可回溯 ② `satellite_index` 出现 per-arm 叶子（kind=finding）。
  arm3 行为：`dry_run` ⟹ 零片、零索引叶子（零写盘）。
"""
import json
import sys
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
SCRIPTS = SD / "scripts"
sys.path.insert(0, str(SCRIPTS))

import gk_finding  # noqa: E402
import gk_satellite as SAT  # noqa: E402


def _seed(sf: str, n_closed: int, pad: int = 900) -> None:
    """造 n_closed 条 closed + 1 条 open（title 加长以撑出可观测体积）。"""
    for i in range(n_closed):
        fid = gk_finding.register(sf, "归档探针 C%d %s" % (i, "x" * pad), "manual")["id"]
        gk_finding.verify(sf, fid, True)
        gk_finding.close(sf, fid, "归档测试收口")
    gk_finding.register(sf, "归档探针 O %s" % ("x" * pad), "manual")


def test_arm1_static_no_second_direct_writer():
    """静态：`archive_closed` 不得再直写卫星片（禁第二直写者）；须调中枢。"""
    src = (SCRIPTS / "gk_finding.py").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
    assert "open(_archive_path(" not in code, \
        "archive_closed 仍直写卫星片（第二直写者，绕开中枢）"
    assert "import gk_satellite" in code and "gk_satellite" in code, \
        "归档路径未收敛为调中枢 gk_satellite"


def test_arm2_archive_registers_per_arm_index_leaf(tmp_path):
    """行为：归档 ⟹ 片落盘（可回溯）+ `satellite_index` per-arm 叶子（中枢读回面）。"""
    sf = str(tmp_path / "s.json")
    _seed(sf, 12)
    r = gk_finding.archive_closed(sf, target_total=8192)
    assert r["ok"] and r["archived"] >= 1, r
    shard = Path(sf + SAT.KIND_SUFFIX["finding"])
    assert shard.is_file(), "归档片未落 ⟹ 不可回溯"
    rows = [json.loads(x)["id"]
            for x in shard.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert set(rows) == set(r["archived_ids"]), (rows, r["archived_ids"])
    idx = SAT.index_entries(sf)
    leaves = [lf for arms in idx.values() if isinstance(arms, dict)
              for lf in arms.values() if isinstance(lf, dict)]
    assert any(lf.get("kind") == "finding" for lf in leaves), (
        "archive_closed 未登记 per-arm 索引叶子（片无中枢读回面）: %r" % idx)


def test_arm3_dry_run_zero_write(tmp_path):
    """行为：`dry_run` 零写盘（不改 state、不落片、不写索引叶子）。"""
    sf = str(tmp_path / "s.json")
    _seed(sf, 6)
    b0 = Path(sf).read_bytes()
    r = gk_finding.archive_closed(sf, target_total=1024, dry_run=True)
    assert r["dry_run"] and r["archived"] >= 1, r
    assert Path(sf).read_bytes() == b0, "dry_run 写了 state"
    assert not Path(sf + SAT.KIND_SUFFIX["finding"]).exists(), "dry_run 落了片"
    assert SAT.index_entries(sf) == {}, "dry_run 写了索引叶子"
