#!/usr/bin/env python3
"""文档自动生成 / FIFO 归档红先臂（2026-11-01）。

判据：
  1. README 索引 = **公开面集合**（排除面单源 `oss_scrub.is_excluded`），不漏不多；
  2. 两处事实块 + README 索引块与活文件一致（`gk_docgen_facts.check`）；
  3. 缺标记 ⟹ fail-loud（不静默通过）；
  4. `rejected_edits` 出窗**先归档再截断**：live 20 条、归档 append-only、读面不撑大。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_advance as A  # noqa: E402
import gk_docgen_facts as F  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def test_readme_index_matches_public_surface():
    names = {r["name"] for r in F.collect_refs(ROOT)}
    assert "state-storage.md" in names
    assert "standard-maintenance-module.md" in names
    # 导出排除面（whitelist）里的不应出现
    assert "stage-1-code.md" not in names
    assert "predicate-applicability.md" not in names
    block = F.render_refs(ROOT)
    for n in names:
        assert "(%s)" % n in block, n


def test_generator_check_passes_on_repo():
    out = F.check(str(ROOT))
    assert out["status"] == "PASS", out["detail"]


def test_generator_requires_markers(tmp_path):
    p = tmp_path / "x.md"
    p.write_text("no markers\n", encoding="utf-8")
    try:
        F._replace_block(p.read_text(encoding="utf-8"), "block")
    except ValueError as e:
        assert "GK-FACTS" in str(e)
    else:
        raise AssertionError("缺标记应 fail-loud")


def test_rejected_edits_archive_before_truncate(tmp_path):
    sf = str(tmp_path / ".gatekeeper.state")
    gd = {}
    cap = A.REJECTED_CAP
    for i in range(cap + 5):
        A._append_rejected(gd, {"stage": "ECO-EDIT", "source": "gate", "i": i}, sf)
    live = gd["rejected_edits"]
    assert len(live) == cap
    assert live[0]["i"] == 5, "live 应保留最新 cap 条"
    arch = Path(sf + A.REJECTED_JOURNAL_SUFFIX)
    assert arch.is_file()
    lines = arch.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5 and '"i": 0' in lines[0]


def test_rejected_edits_without_state_file_still_caps():
    gd = {}
    for i in range(A.REJECTED_CAP + 5):
        A._append_rejected(gd, {"i": i})
    assert len(gd["rejected_edits"]) == A.REJECTED_CAP


def test_state_capacity_and_wall_blocks_reflect_constants():
    import gk_json_utils as J
    import gk_satellite as S
    d = F.collect_state(ROOT)
    cap = F.render_state_cap(d)
    wall = F.render_state_wall(d)
    assert "{:,}".format(S.SAT_SHARD_BUDGET_BYTES) in cap
    assert "%d KB" % (S.SAT_ARM_BUDGET_BYTES // 1024) in cap
    assert "{:,}".format(J.STATE_SIZE_WALL) in wall
    for pct in ("50", "80", "90", "95"):
        assert "≥ %s%%" % pct in wall
    # 2026-11-05：原断言钉死「WALL_BLOCK / 512 KB」两个已不存在的字面量（生成块早已改为
    #   `STATE_SIZE_WALL = 2,621,440 B（2.5 MB）` + 运维覆盖口说明）⟹ 判据错位。
    #   改为验证**现存契约**：整墙数值（上行 L78 已断言）+ 覆盖口必须写明。
    assert "运维覆盖口" in wall and "GK_STATE_TRIM_KB" in wall
    assert "ECC_MAX_ENTRIES=256" in wall and "ECC_MAX_OPEN=96" in wall


# ── CI 无依赖回退（2026-11-04）──────────────────────────────────────────────
# preflight 作业不装 openai/agents ⟹ import subagent_runner 失败 ⟹ 角色数从 8 变 0
# ⟹ GK-FACTS 假红（v0.9.6.12 实测）。静态解析必须与同一字典字面量等价。

def test_static_roles_include_known_entries():
    roles = F._static_roles(ROOT)
    assert len(roles) >= 8, roles
    for name in ("default", "scanner", "exploiter", "auditor", "reporter"):
        assert name in roles, (name, roles)


def test_static_roles_matches_live_when_importable():
    try:
        import subagent_runner as SR
    except Exception:  # noqa: BLE001 — CI 未装依赖时跳过对照臂
        return
    assert F._static_roles(ROOT) == sorted(SR.ROLE_TOOLS)
