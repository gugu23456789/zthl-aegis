#!/usr/bin/env python3
"""
test_gk_tamper_detect.py — 白名单篡改攻击 × 检测引擎 漏检矩阵（2026-09-02 红队）
==============================================================================
用户质询「如果篡改了白名单怎么办？红队主动挖掘缺陷」的确定性底座：
预置 N 种白名单篡改变异 → 跑检测引擎（doc-align route_center_alignment ⑤⑥⑦ +
_skill_dir_trusted 内容特征 + _skill_dir_env_trusted git 锚定）→ 断言全部被检出。
漏检 = 测试失败（检测缺口）。所有变异在隔离副本上进行，用后即恢复，无副作用。

攻击面建模（篡改目标 → 攻击目标）:
  攻击 A: 让 env SKILL_DIR 指向攻击者目录被信任     → 变异: 空壳/结构缺失/改名/非 git 副本/git dirty/HEAD 漂移
  攻击 B: 让 GATEKEEPER_WORKTREE_ROOT 逃逸白名单     → 变异: DEV_WORKTREE_ROOTS 单/双副本/bash 第三副本/`..` 穿越(已单测)
  攻击 C: 让路由锚点漂移（主仓库/搜索目录）           → 变异: MAIN_REPO_WSL / SEARCH_DIRS 代码常量改值
  攻击 D: 篡改代码同时篡改文档基线（本地静态不可检） → 变异: 代码+文档同改 → git 环（clone 后 status）兜底检出
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_doc_align as gda
import gk_route_center as grc

# XENV-FORM（2026-09-27，环境性 failed 清单）：字面 Windows 路径在规范 runner（WSL 侧
# 隔离 venv）下不可达 ⟹ `git clone`/`copytree` 必败（实测 clone exit 128，本文件
# 11 臂红/错）。改为**宿主自适应**（真目录在 `/mnt/c/…`；Windows 宿主原样命中）。
REAL = Path(r"c:\Users\HP\.trae\skills\spz-gatekeeper-r-sequence")
if not REAL.is_dir():
    _mnt = Path("<home>/.trae/skills/spz-gatekeeper-r-sequence")
    if _mnt.is_dir():
        REAL = _mnt
SCRIPT_DIR = Path(__file__).resolve().parent


@contextmanager
def _mutate(path: Path):
    """篡改文件 → 恢复（测试无副作用）。"""
    orig = path.read_bytes()
    try:
        yield path
    finally:
        path.write_bytes(orig)


def _alignment(dirpath) -> dict:
    return gda.check_route_center_alignment(str(dirpath))


def _sweep_stale_tempdirs(prefix: str = "gk-tamper-", min_age_h: float = 6.0) -> int:
    """**测试自愈**：清掉本前缀且**超龄**的临时残留，返回清掉的数量。

    病根：`teardown_class` 只在**正常结束**时清 ⟹ 一旦 `setup_class` 中途抛错
    （本地实测：`REAL` 写死 Windows 路径 ⟹ WSL 下 `copytree` 必败），`teardown_class`
    **根本不会跑**，而 `mkdtemp` 早已建好目录 ⟹ 残留只增不减（`/tmp` 实测累计 **58 个**
    `gk-tamper-*`，每个都含整棵技能仓副本）。这与「隔离区只进不出」是同一类缺陷
    （清理动作只在成功路径上）。

    **为什么是龄期而非全清**：**并发会话**可能正在跑同一套测试 ⟹ 全清会当场打断别人。
    默认 6h 远大于本套测试耗时（~2s）⟹ 活目录必被排除。**不做外部定时器**
    （本机无 cron/systemd；且「临时」≠「可删」，定时器会构成第二套裁决）。
    """
    tmp = Path(tempfile.gettempdir())
    try:
        entries = list(tmp.iterdir())
    except OSError:
        return 0
    now, swept = time.time(), 0
    for p in entries:
        if not p.name.startswith(prefix):
            continue
        try:
            if (now - p.stat().st_mtime) / 3600.0 < min_age_h:
                continue                                  # 未超龄 ⟹ 可能是并发会话的活目录
        except OSError:
            continue
        if p.is_dir():
            shutil.rmtree(str(p), ignore_errors=True)
        else:
            try:
                p.unlink()
            except OSError:
                continue
        swept += 1
    return swept


class TestTamperDocAlign:
    """攻击 B/C: 白名单/锚点常量篡改 → doc-align ⑤⑥⑦ 检出。"""

    @classmethod
    def setup_class(cls):
        # 自愈（2026-09-24）：先清**超龄**残留 —— 本类的清理只在成功路径上，一旦
        #   `setup_class` 中途抛错，`teardown_class` 不会跑，`mkdtemp` 的目录就永久留下。
        _sweep_stale_tempdirs()
        # 单次 copytree（含 .git，与运行仓库同 HEAD）→ 各用例就地篡改+恢复
        cls.copy = Path(__import__("tempfile").mkdtemp(prefix="gk-tamper-")) / "spz-gatekeeper-r-sequence"
        shutil.copytree(str(REAL), str(cls.copy))
        assert _alignment(cls.copy)["status"] == "PASS", "篡改副本基线必须 PASS（否则基线本身漂移）"

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(str(cls.copy.parent), ignore_errors=True)

    def test_tamper_worktree_roots_route_center(self):
        """B1: DEV_WORKTREE_ROOTS（route_center 副本）追加 /tmp/evil/ → ⑤+⑦ 检出。"""
        p = self.copy / "scripts" / "gk_route_center.py"
        with _mutate(p):
            t = p.read_text(encoding="utf-8")
            p.write_text(t.replace('"/root/.config/superpowers/worktrees/",',
                                   '"/root/.config/superpowers/worktrees/",\n    "/tmp/evil/",'),
                          encoding="utf-8")
            r = _alignment(self.copy)
            assert r["status"] == "WARN"
            assert "DEV_WORKTREE_ROOTS" in r["detail"]

    def test_tamper_worktree_roots_state_route(self):
        """B2: DEV_WORKTREE_ROOTS（state_route 副本）追加 /tmp/evil/ → ⑤ 双副本差分检出。"""
        p = self.copy / "scripts" / "gk_state_route.py"
        with _mutate(p):
            t = p.read_text(encoding="utf-8")
            p.write_text(t.replace('"/root/.config/superpowers/worktrees/",',
                                   '"/root/.config/superpowers/worktrees/",\n    "/tmp/evil/",'),
                          encoding="utf-8")
            r = _alignment(self.copy)
            assert r["status"] == "WARN"
            assert "双副本不一致" in r["detail"]

    def test_tamper_bash_third_copy_fallback(self):
        """B3（2026-09-04 方案 A 语义更新）：bash 重新引入内嵌 worktree fallback
        （`[ -d ...worktrees... ]` 字面量 = 第三副本复活/注入）→ ⑥ 检出 WARN。"""
        p = self.copy / "gatekeeper-cli.sh"
        with _mutate(p):
            t = p.read_text(encoding="utf-8")
            anchor = 'SKILL_REPO_HASH="d67b1270"'
            evil = '\nif [ -d "/tmp/evil/worktrees/spz_gatekeeper_project/feature/" ]; then :; fi'
            assert anchor in t, "anchor 必须存在（篡改点失效 = 测试无效）"
            p.write_text(t.replace(anchor, anchor + evil, 1), encoding="utf-8")
            r = _alignment(self.copy)
            assert r["status"] == "WARN"
            assert "第三副本" in r["detail"]

    def test_tamper_doc_baseline_unsynced(self):
        """D1: 代码+代码双副本一致改（route_center+state_route 同加 /tmp/evil/）+ 文档基线未改
        → ⑤ 不报（副本一致）但 ⑦ 文档基线检出（D 层价值点：单靠代码内差分不够）。"""
        p1 = self.copy / "scripts" / "gk_route_center.py"
        p2 = self.copy / "scripts" / "gk_state_route.py"
        evil = '"/root/.config/superpowers/worktrees/",\n    "/tmp/evil/",'
        with _mutate(p1), _mutate(p2):
            t1 = p1.read_text(encoding="utf-8").replace('"/root/.config/superpowers/worktrees/",', evil)
            t2 = p2.read_text(encoding="utf-8").replace('"/root/.config/superpowers/worktrees/",', evil)
            p1.write_text(t1, encoding="utf-8")
            p2.write_text(t2, encoding="utf-8")
            r = _alignment(self.copy)
            assert r["status"] == "WARN"
            assert "偏离文档基线" in r["detail"]  # ⑦ 生效；⑤ 不应触发

    def test_tamper_search_dirs_baseline(self):
        """C2: SEARCH_DIRS 代码追加攻击者搜索层 + 文档基线未改 → ⑦ 检出。"""
        p = self.copy / "scripts" / "gk_route_center.py"
        with _mutate(p):
            t = p.read_text(encoding="utf-8")
            # 锚兼容旧/新两形态（旧：写死用户目录；新：`{user}` 占位）
            needle = next((n for n in ('"{user}/.codex/docs/plans/"',
                                       '"<home>/.codex/docs/plans/"') if n in t), "")
            assert needle, "SEARCH_DIRS 末项锚缺失"
            p.write_text(t.replace(needle + ",",
                                   needle + ',\n    "/tmp/evil/plans/",', 1),
                         encoding="utf-8")
            r = _alignment(self.copy)
            assert r["status"] == "WARN"
            assert "SEARCH_DIRS" in r["detail"]

    def test_tamper_main_repo_baseline(self):
        """C1: 代码常量被改而**文档基线未改** → ⑦ 检出。

        2026-11-01（锚点更新）：`MAIN_REPO_WSL` 自 2026-10-31 起为**运行时解析**（常量置空，
        不再有字面量可比）⟹ 原锚点失效。改钉仍在文档基线里的 `SEARCH_DIRS`（同一检查器 ⑦）。
        """
        p = self.copy / "scripts" / "gk_route_center.py"
        with _mutate(p):
            t = p.read_text(encoding="utf-8")
            anchor = '    "{main}/docs/plans/",'
            assert anchor in t, "anchor 必须存在（篡改点失效 = 测试无效）"
            p.write_text(t.replace(anchor, anchor + '\n    "{main}/tmp/evil/",', 1),
                         encoding="utf-8")
            r = _alignment(self.copy)
            assert r["status"] == "WARN"
            assert "SEARCH_DIRS" in r["detail"]

    def test_tamper_code_and_doc_git_ring(self):
        """D2（诚实边界实证）: 代码双副本 + 文档基线三方一致改 → 本地静态不可检（doc-align PASS）
        → 外环 = git tracked 状态：改的是 tracked 文件 → 仓库 status 非空（git 环兜底）。"""
        p1 = self.copy / "scripts" / "gk_route_center.py"
        p2 = self.copy / "scripts" / "gk_state_route.py"
        d = self.copy / "references" / "meta-routing-protocol.md"
        evil = '"/root/.config/superpowers/worktrees/",\n    "/tmp/evil/",'
        evil_doc = "`<home>/.trae/worktrees/`, `c:/users/hp/.trae/worktrees/`, `/root/.config/superpowers/worktrees/`, `/tmp/evil/`"
        with _mutate(p1), _mutate(p2), _mutate(d):
            t1 = p1.read_text(encoding="utf-8").replace('"/root/.config/superpowers/worktrees/",', evil)
            t2 = p2.read_text(encoding="utf-8").replace('"/root/.config/superpowers/worktrees/",', evil)
            p1.write_text(t1, encoding="utf-8")
            p2.write_text(t2, encoding="utf-8")
            mt = d.read_text(encoding="utf-8").replace(
                "`<home>/.trae/worktrees/`, `c:/users/hp/.trae/worktrees/`, `/root/.config/superpowers/worktrees/`",
                evil_doc)
            d.write_text(mt, encoding="utf-8")
            r = _alignment(self.copy)
            assert r["status"] == "PASS", "代码+文档同改 → 本地静态层应诚实 PASS（边界）"
            # git 环：篡改的是 tracked 文件 → 有 diff（copytree 继承 .git，含真实未提交改动亦为非空）
            st = subprocess.run(["git", "status", "--porcelain"], cwd=str(self.copy),
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=15)
            assert st.returncode == 0 and st.stdout.strip(), "git 环应检出 tracked 篡改"


class TestTamperTrustGate:
    """攻击 A: 使 env SKILL_DIR 指向攻击者目录被信任 → 信任门各层拒绝。"""

    @classmethod
    def setup_class(cls):
        cls.base = Path(__import__("tempfile").mkdtemp(prefix="gk-trust-"))

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(str(cls.base), ignore_errors=True)

    def _full_copy(self, name="spz-gatekeeper-r-sequence") -> Path:
        """完整特征副本（内容标记齐全 + scripts/gk_route_center.py）。"""
        sd = self.base / name
        (sd / "scripts").mkdir(parents=True, exist_ok=True)
        (sd / "gatekeeper-cli.sh").write_text("SKILL_REPO_HASH=1", encoding="utf-8")
        (sd / "SKILL.md").write_text("# spz-gatekeeper-r-sequence", encoding="utf-8")
        (sd / "scripts" / "gk_route_center.py").write_text("def main(): pass", encoding="utf-8")
        return sd

    def test_masquerade_empty_files(self):
        """A1: 空文件伪装（目录名对 + 文件空）→ 内容特征层拒。"""
        sd = self._full_copy()
        (sd / "gatekeeper-cli.sh").write_text("", encoding="utf-8")
        (sd / "SKILL.md").write_text("", encoding="utf-8")
        assert grc._skill_dir_trusted(str(sd)) is False
        assert grc._skill_dir_env_trusted(str(sd)) is False

    def test_missing_route_center(self):
        """A2: 缺 scripts/gk_route_center.py 结构 → 拒。"""
        sd = self._full_copy()
        (sd / "scripts" / "gk_route_center.py").unlink()
        assert grc._skill_dir_trusted(str(sd)) is False

    def test_wrong_dirname(self):
        """A3: 目录名非 spz-gatekeeper-r-sequence（copy 变体）→ 拒。"""
        sd = self._full_copy(name="spz-gatekeeper-r-sequence-copy")
        assert grc._skill_dir_trusted(str(sd)) is False

    def test_non_git_copy_env_trust(self):
        """A4: 完整特征副本但非 git 仓库（任何能写盘的攻击者都能造）→ env git 锚定层拒。"""
        sd = self._full_copy()
        assert grc._skill_dir_trusted(str(sd)) is True   # 内容层过（证明单靠内容不够）
        assert grc._skill_dir_env_trusted(str(sd)) is False  # git 锚定层收口

    def test_git_anchor_accepts_clean_same_head(self, monkeypatch):
        """A5(正例, git 锚定层隔离): 干净同源克隆（同 HEAD + clean）→ 信任。
        monkeypatch 内容层为 True —— 隔离验证 git 锚定分支本身
        （真实克隆内容层受「提交基线落后于工作树」制约，见 C 层注释，非 git 层语义）。"""
        clone = self.base / "clone-skill"
        # 2026-10-03 修（N4，ECC-94AA4F0B3D3A）：clone 源从写死 `REAL`（=主树）改为
        # **运行仓**（`grc.DEFAULT_SKILL` = `gk_route_center.__file__` 的 parent²）——
        # 判据要求 clone.HEAD == DEFAULT_SKILL.HEAD（gk_route_center L450），linked
        # worktree 下二者不等 ⟹ 原式恒 False（worktree 新增红）；改后天然同源、位置无关。
        subprocess.run(["git", "clone", "-q", str(grc.DEFAULT_SKILL), str(clone)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=120, check=True)
        monkeypatch.setattr(grc, "_skill_dir_trusted", lambda d: True)
        assert grc._skill_dir_env_trusted(str(clone)) is True

    def test_git_anchor_rejects_dirty_injection(self, monkeypatch):
        """A6: 干净克隆 + 注入恶意计划（untracked → git dirty）→ git 锚定层拒。"""
        clone = self.base / "clone-dirty"
        subprocess.run(["git", "clone", "-q", str(REAL), str(clone)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=120, check=True)
        plan = clone / "docs" / "plans"
        plan.mkdir(parents=True, exist_ok=True)
        (plan / "2026-09-02-evil-plan.md").write_text(
            "<!-- META\nphases: R9\ntarget_repo: gatekeeper\n-->", encoding="utf-8")
        monkeypatch.setattr(grc, "_skill_dir_trusted", lambda d: True)
        assert grc._skill_dir_env_trusted(str(clone)) is False

    def test_git_anchor_rejects_committed_drift(self, monkeypatch):
        """A7: 干净克隆 + 本地提交恶意计划 → HEAD 漂移 vs 运行仓库 → git 锚定层拒
        （完整复制 + commit 攻击失效）。"""
        clone = self.base / "clone-commit"
        subprocess.run(["git", "clone", "-q", str(REAL), str(clone)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=120, check=True)
        subprocess.run(["git", "-C", str(clone), "config", "user.name", "gk-tamper"],
                       capture_output=True, timeout=15)
        subprocess.run(["git", "-C", str(clone), "config", "user.email", "gk-tamper@local"],
                       capture_output=True, timeout=15)
        plan = clone / "docs" / "plans"
        plan.mkdir(parents=True, exist_ok=True)
        (plan / "2026-09-02-evil-plan.md").write_text(
            "<!-- META\nphases: R9\ntarget_repo: skill\n-->", encoding="utf-8")
        subprocess.run(["git", "-C", str(clone), "add", "docs/plans/2026-09-02-evil-plan.md"],
                       capture_output=True, timeout=30, check=True)
        subprocess.run(["git", "-C", str(clone), "commit", "-q", "-m", "evil plan"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=30, check=True)
        monkeypatch.setattr(grc, "_skill_dir_trusted", lambda d: True)
        assert grc._skill_dir_env_trusted(str(clone)) is False


class TestCEnvGateSiblings:
    """C 层收口（2026-09-02）：信任门不只在 gk_route_center 入口——
    L4 state 路由（gk_state_route.py）+ 状态机写路径（gk_advance.py）独立入口
    直读 env SKILL_DIR 同样会被注入（env SKILL_DIR=/tmp/evil 直接 python 调用）。
    两个入口必须 fail-closed 回退 __file__ 推导默认。"""

    @classmethod
    def setup_class(cls):
        cls.base = Path(__import__("tempfile").mkdtemp(prefix="gk-gate-"))

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(str(cls.base), ignore_errors=True)

    def _masquerade(self) -> Path:
        """空壳伪装目录（目录名正确 + 空文件，非 git）。"""
        evil = self.base / "spz-gatekeeper-r-sequence"
        evil.mkdir(exist_ok=True)
        (evil / "gatekeeper-cli.sh").write_text("", encoding="utf-8")
        (evil / "SKILL.md").write_text("", encoding="utf-8")
        return evil

    def _run_py(self, script: str, env_extra, argv=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT_DIR / script)] + (argv or []),
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=dict(os.environ, **env_extra), timeout=60)

    def test_state_route_env_masquerade_blocked(self):
        """L4 独立入口：env SKILL_DIR=空壳伪装 → 信任门拒 → 路由回退默认技能目录。"""
        evil = self._masquerade()
        out = self._run_py("gk_state_route.py", {"SKILL_DIR": str(evil)})
        assert out.returncode == 0, out.stderr
        d = json.loads(out.stdout)
        assert "expected" in d
        assert str(evil) not in str(d.get("expected", ""))
        assert str(d.get("expected", "")).startswith(str(grc.DEFAULT_SKILL))

    def test_state_route_env_fullcopy_non_git_blocked(self):
        """L4 独立入口：env SKILL_DIR=完整特征副本（非 git）→ git 锚定层拒 → 回退默认。"""
        copy = self.base / "spz-gatekeeper-r-sequence-copy"
        (copy / "scripts").mkdir(parents=True, exist_ok=True)
        (copy / "gatekeeper-cli.sh").write_text("SKILL_REPO_HASH=1", encoding="utf-8")
        (copy / "SKILL.md").write_text("# spz-gatekeeper-r-sequence", encoding="utf-8")
        (copy / "scripts" / "gk_route_center.py").write_text("x", encoding="utf-8")
        out = self._run_py("gk_state_route.py", {"SKILL_DIR": str(copy)})
        assert out.returncode == 0, out.stderr
        d = json.loads(out.stdout)
        assert str(copy) not in str(d.get("expected", ""))

    def test_state_route_env_self_allowed(self):
        """L4 独立入口：env SKILL_DIR=自身路径 → 信任（CLI 正常流不误伤）。"""
        out = self._run_py("gk_state_route.py", {"SKILL_DIR": str(grc.DEFAULT_SKILL)})
        assert out.returncode == 0, out.stderr
        d = json.loads(out.stdout)
        assert "expected" in d

    def test_advance_env_masquerade_blocked(self):
        """状态机入口：env SKILL_DIR=空壳伪装 → 信任门拒 → 回退默认，不把判定/写入指向攻击者目录。"""
        evil = self._masquerade()
        out = self._run_py("gk_advance.py", {"SKILL_DIR": str(evil)},
                           argv=["STAGE_1", "--check"])
        assert out.returncode == 0, out.stderr
        d = json.loads(out.stdout)
        assert str(evil) not in out.stdout
        assert "ok" in d or "allowed" in d or "error" in d


# ══════════ 测试自愈（2026-09-24，用户裁定「2」）══════════
# 为什么**放在类外**：`TestTamperDocAlign.setup_class` 依赖 `REAL`（写死 Windows 路径），
#   在 WSL 下必败 ⟹ 类内臂会被 setup 拖成 ERROR、验不了自愈。自愈本身与那套夹具无关。
def test_sweep_stale_tempdirs_respects_prefix_and_age(tmp_path, monkeypatch):
    """**判别力臂**：自愈只能清「本前缀 **且** 超龄」的 —— 三例各自击穿一种错误实现。

      `gk-tamper-old`   —— 本前缀 **且** 超龄 ⟹ 应清（正例）；
      `gk-tamper-fresh` —— 本前缀但**新** ⟹ 不清（若全清 ⟹ 会当场打断并发会话的活目录）；
      `somebody-else`   —— 超龄但**非本前缀** ⟹ 不清（越界删别人的东西）。
    """
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    (tmp_path / "gk-tamper-old").mkdir()
    (tmp_path / "gk-tamper-fresh").mkdir()
    (tmp_path / "somebody-else").mkdir()
    old = time.time() - 8 * 3600
    os.utime(str(tmp_path / "gk-tamper-old"), (old, old))
    os.utime(str(tmp_path / "somebody-else"), (old, old))
    assert _sweep_stale_tempdirs() == 1, "自愈计数不对（应只清本前缀且超龄的那一个）"
    assert not (tmp_path / "gk-tamper-old").exists(), "超龄的本前缀残留未被清 ⟹ 自愈无效"
    assert (tmp_path / "gk-tamper-fresh").exists(), "活目录被清 ⟹ 会打断并发会话"
    assert (tmp_path / "somebody-else").exists(), "别人的目录被清 ⟹ 越界"


def test_setup_class_calls_self_heal():
    """形态臂：自愈必须**真的挂在** `TestTamperDocAlign.setup_class` 上（否则只是摆设）。

    只加函数不加调用点 = 典型的「实现了但没接上」（本仓同类教训：回收链脚本写好了
    却无调用点，只产不消）。
    """
    src = Path(__file__).read_text(encoding="utf-8")
    seg = src[src.index("class TestTamperDocAlign:"):src.index("class TestTamperTrustGate:")]
    assert "_sweep_stale_tempdirs()" in seg, "自愈未挂在会残留的那个类的 setup_class 上"
