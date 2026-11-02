#!/usr/bin/env python3
"""drvfs 跨侧陈旧读的**安全通道**回归（2026-09-28；`ECC-FAA686AB1791` / `ECC-C2BE2C56A7BD`）。

病根（均实测，非推断）：
  · `ECC-FAA686AB1791`：Windows 侧改 `gatekeeper-cli.sh` + WSL git ⟹ drvfs 跨侧页缓存不一致 ——
    `git hash-object`（相对/绝对/`-C`/`--no-filters` 四形态）读**旧** blob `ef007824`，而
    `dd`/`md5sum`/`cp`（read 路径）得真内容（真 blob `bf0304cd`）⟹ 索引暂存旧 blob ⟹ 提交门
    `BLOB_MISMATCH` 拦下（拦对了），但**无法识别**这是宿主缓存问题、也**没有机械通道**。
  · `ECC-C2BE2C56A7BD`：人工处置手法（`cp f /tmp && cp /tmp f`）**本身会把 Windows 侧新编辑回滚**
    （实测 `c5366fc` 被回滚、`9dcb6e8` 补落）—— 回写的缓冲可能正是**陈旧**内容。

本文件锁三条（非模块自证）：
  arm53（`ECC-C2BE2C56A7BD` · 守门行为）：两路读**不一致** ⟹ `verified_refresh` **拒绝回写**、
         目标文件**逐字节未变**、报 `DRVFS_CROSS_VIEW_MISMATCH`（= 回滚守门）。
  arm54（`ECC-FAA686AB1791` · 行为）：提交门对「blob ≠ 工作树」**区分成因** —— 两路不一致 ⟹
         reason 带 `DRVFS_CROSS_VIEW_MISMATCH`（可识别、指向安全通道）；两路一致 ⟹ 仍 `BLOB_MISMATCH`。
  回归（**非红**，不入选 `-k`）：两路一致 ⟹ 安全往返成功且内容逐字节不变；CLI 接线面。

口径（2026-09-28 升级）：两路都取 **blob 口径** sha1（`git hash-object`），blob 计算改
`--stdin` 直喂读到的字节（**免临时件**）—— `git hash-object` 含 `blob <len>\\0` 头，拿裸
`sha1(内容)` 比必假报不一致（实测 `hello\\n` → git `ce013625…` vs 裸 sha1 `f572d396…`）。
"""
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
import gk_commit_verify as gcv  # noqa: E402 —— 判据单源（禁第二份比对实现）


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, timeout=120)


def _mk_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    return repo


def test_arm53_drvfs_refresh_refuses_on_divergent_views(tmp_path, monkeypatch):
    """`ECC-C2BE2C56A7BD` 守门臂：两路读互相不一致 ⟹ **拒绝回写**（防把 Windows 侧编辑回滚）。

    HEAD 真红：`verified_refresh` 不存在 ⟹ AttributeError（failed）。
    """
    repo = _mk_repo(tmp_path)
    f = repo / "a.txt"
    f.write_text("真内容-v1\n", encoding="utf-8")
    before = f.read_bytes()

    # 伪造「两路独立读互相不一致」= drvfs 跨侧页缓存不一致（git 路径 ≠ read 路径）
    monkeypatch.setattr(gcv, "worktree_views",
                        lambda r, p: {"exists": True, "read_sha1": "deadbeef" * 5,
                                      "git_sha1": "cafebabe" * 5, "agree": False})
    out = gcv.verified_refresh(str(repo), "a.txt")
    assert out.get("ok") is False, f"双视图不一致时仍回写（会回滚一侧编辑）：{out}"
    assert out.get("error") == "DRVFS_CROSS_VIEW_MISMATCH", out
    assert f.read_bytes() == before, "拒绝回写时目标文件被改动（守门失效）"


def test_arm54_drvfs_cross_view_mismatch_named_in_verify(tmp_path, monkeypatch):
    """`ECC-FAA686AB1791` 行为臂：提交门须**区分成因** —— 两路读不一致 ⟹ `DRVFS_CROSS_VIEW_MISMATCH`；
    不一致消失 ⟹ 仍 `BLOB_MISMATCH`（**判据不放松**，只改诊断）。

    HEAD 真红：`worktree_views` 不存在 ⟹ failed。
    """
    repo = _mk_repo(tmp_path)
    f = repo / "a.sh"
    f.write_text("#!/bin/bash\necho v1\n", encoding="utf-8")
    _git(repo, "add", "a.sh")
    f.write_text("#!/bin/bash\necho v2-changed-on-disk\n", encoding="utf-8")  # 索引 blob ≠ 工作树

    # ① 两路不一致（伪造 read 路径 ≠ git 路径）⟹ 报 drvfs 成因
    monkeypatch.setattr(gcv, "worktree_views",
                        lambda r, p: {"exists": True, "read_sha1": "a" * 40,
                                      "git_sha1": "b" * 40, "agree": False})
    out = gcv.verify(str(repo), "staged")
    assert out["ok"] is False, out
    assert any("DRVFS_CROSS_VIEW_MISMATCH" in (b.get("reason") or "") for b in out["bad"]), out
    assert not any("BLOB_MISMATCH" in (b.get("reason") or "") for b in out["bad"]), out

    # ② 两路一致（真实：git 与 read 读同一文件）⟹ 仍是 BLOB_MISMATCH（判据不放松）
    monkeypatch.undo()
    out2 = gcv.verify(str(repo), "staged")
    assert out2["ok"] is False, out2
    assert any("BLOB_MISMATCH" in (b.get("reason") or "") for b in out2["bad"]), out2


def test_cli_commit_refresh_is_wired():
    """接线面（**非红**，不入选 `-k`）：`cmd_commit` 须暴露 `--refresh` 并转发到**判据单源**
    （`ECC-FAA686AB1791` 的「无机械通道」闭法 = 走既有单一入口，禁第二实现）。"""
    src = (SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "--refresh)" in src, "cmd_commit 未解析 --refresh"
    assert 'gk_commit_verify.py" --repo "$repo" --refresh' in src, \
        "cmd_commit 未把 --refresh 转发到判据单源（gk_commit_verify.py）"


def test_drvfs_refresh_byte_identical_when_views_agree(tmp_path):
    """回归（**非红**，不入选 `-k`）：两路一致 ⟹ 安全往返成功且内容逐字节不变。"""
    repo = _mk_repo(tmp_path)
    f = repo / "b.txt"
    f.write_text("内容-abc\n", encoding="utf-8")
    before = f.read_bytes()
    out = gcv.verified_refresh(str(repo), "b.txt")
    assert out.get("ok") is True, out
    assert out.get("refreshed") is True, out
    assert f.read_bytes() == before, "安全刷新改变了内容（应逐字节等值）"
