#!/usr/bin/env python3
"""序④-A / `ECC-CB64985A85AD` 红先臂 —— 信任锚 `_skill_dir_trusted` 的 worktree 盲区（2026-09-28）。

病象：`gk_route_center._skill_dir_trusted` 首层要求 `Path(sd).name == "spz-gatekeeper-r-sequence"`；
从 **feature / agent worktree** 调用时目录名 = 分支名 / sha8（≠ 技能名）⟹ 同一仓的**合法 worktree**
被判不可信 ⟹ 从 worktree 跑全量验收新增 9 条红（`test_env_trust_self_path` 等）。

修法（计划 §3092 已给方向；§3179 要求**先查保护区归属 + 配负臂**）：先按 **git 权威视图**归一到
该仓**主 worktree**（复用 `_main_worktree`，禁第二实现）再校验名字与结构；非 git / 非本仓 worktree
⟹ 归一为空 ⟹ 退回原样 ⟹ **不放松**空壳伪装防护。

判据：① 正臂（红先必红）—— worktree 路径（经 `_main_worktree` 归一到本仓）须判可信；
② ③ 负臂（守边界，非红先）—— 归一到**非技能名**目录 / 空壳伪装仍须判**不可信**。
"""
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gk_route_center as grc  # noqa: E402


def _fake_skill_dir(base: Path) -> Path:
    """自建**假技能目录**（内容标记齐备）—— 不借真实 `DEFAULT_SKILL`：沙箱（`gk-redfirst-cache/<rev>`）
    下其 basename 是 rev 而非技能名，借它会假红。"""
    sd = base / "spz-gatekeeper-r-sequence"
    (sd / "scripts").mkdir(parents=True)
    (sd / "gatekeeper-cli.sh").write_text("# stub\nSKILL_REPO_HASH=deadbeef\n", encoding="utf-8")
    (sd / "SKILL.md").write_text("# spz-gatekeeper-r-sequence\n", encoding="utf-8")
    (sd / "scripts" / "gk_route_center.py").write_text("# stub\n", encoding="utf-8")
    return sd


def test_skill_dir_trusted_accepts_repo_worktree(tmp_path, monkeypatch):
    """① 正臂：`_main_worktree` 归一到本仓 ⟹ 目录名非技能名的 worktree 也须判**可信**（红先必红）。"""
    fake = _fake_skill_dir(tmp_path)
    monkeypatch.setattr(grc, "_main_worktree", lambda p: str(fake))
    assert grc._skill_dir_trusted(str(tmp_path / "agent" / "abc1234f")) is True, \
        "同仓合法 worktree（目录名=sha8）被判不可信 ⟹ worktree 内全量验收必假红（CB64985A85AD 未落）"


def test_skill_dir_trusted_negative_main_worktree_wrong_name(monkeypatch, tmp_path):
    """② 负臂：归一到**非技能名**目录 ⟹ 仍须判不可信（防「归一即放行」扩大授权面）。"""
    monkeypatch.setattr(grc, "_main_worktree", lambda p: str(tmp_path / "repo-x"))
    assert grc._skill_dir_trusted(str(tmp_path / "whatever")) is False


def test_skill_dir_trusted_negative_empty_masquerade_unchanged(monkeypatch, tmp_path):
    """③ 负臂：非 git（归一回空）时的空壳伪装仍须判不可信（内容防线不因归一而降）。"""
    monkeypatch.setattr(grc, "_main_worktree", lambda p: "")
    sd = tmp_path / "spz-gatekeeper-r-sequence"
    sd.mkdir()
    assert grc._skill_dir_trusted(str(sd)) is False
