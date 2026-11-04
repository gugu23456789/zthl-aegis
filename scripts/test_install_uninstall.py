"""test_install_uninstall.py — 安装/卸载的「不误装、不误删」契约（2026-11-01）

覆盖四类回归：
  1. manifest v2 只记录安装器实际写入的文件 ⟹ 用户自己放进技能目录的文件不被卸载；
  2. 已存在且内容不同的文件默认**不覆盖**（--force 才覆盖，并留时间戳 .bak）；
  3. 旧版 manifest（无 manifest-version: 2）默认拒删（防误删用户文件）；
  4. uninstall --dest 与 install --dest 对称（宿主无关落点可卸载）。

全部在 pytest 的 tmp_path 内运行，HOME / hooks.json 都重定向，不触碰真实用户配置。
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="需要 bash")


def _bash_path(p):
    """Windows 绝对路径 → WSL 可解析的 `/mnt/<drive>/...`；非 Windows 原样（分类学 #13）。

    现场：本机 `bash` = `C:\\windows\\system32\\bash.EXE`（WSL），传入 `<home>`
    会被吞成 `C:UsersHP...` ⟹ `/bin/bash: No such file or directory`（rc=127）。
    因此**传给 bash 的参数**与 bash 读取的 env（HOME / GK_HOOKS_JSON）都换算成 POSIX 形态；
    `cwd` 仍用 Windows 形态（由 CreateProcess 解释）。
    """
    if os.name != "nt":
        return str(p)
    q = str(p).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", q)
    return "/mnt/%s/%s" % (m.group(1).lower(), m.group(2)) if m else q


def _fake_src(tmp_path: Path) -> Path:
    """最小安装源：只含安装器需要的文件，避免复制整个仓。

    `newline="\\n"` 是必需的（Windows 实测）：默认写文本会把 `\\n` 翻成 `\\r\\n`，
    而 WSL bash 读到 CRLF 会报 `$'\\r': command not found` / `set: pipefail` 断行
    ⟹ 安装器根本没执行（rc=2），与"安装逻辑错"完全同形。
    """
    src = tmp_path / "src"
    (src / "scripts").mkdir(parents=True)
    for name in ("install.sh", "uninstall.sh", "gatekeeper-cli.sh", "SKILL.md"):
        txt = (ROOT / name).read_text(encoding="utf-8") if (ROOT / name).is_file() else "#!/usr/bin/env bash\nexit 0\n"
        (src / name).write_text(txt, encoding="utf-8", newline="\n")
    for name in ("gk_hook_manage.py", "pre_tool_hook_wrapper.sh"):
        (src / "scripts" / name).write_text(
            (ROOT / "scripts" / name).read_text(encoding="utf-8"),
            encoding="utf-8", newline="\n")
    return src


def _env(tmp_path: Path) -> dict:
    env = dict(os.environ)
    env["HOME"] = _bash_path(tmp_path / "home")
    env["GK_HOOKS_JSON"] = _bash_path(tmp_path / "hooks.json")
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)
    return env


def _run(args, tmp_path, cwd=None):
    return subprocess.run([BASH] + [_bash_path(a) for a in args], capture_output=True,
                          text=True, timeout=120, cwd=str(cwd or tmp_path), env=_env(tmp_path))


def _install(tmp_path, src, dest, *extra):
    return _run([src / "install.sh", "--dest", dest, "--no-hooks", *extra], tmp_path)


def _uninstall(tmp_path, dest, *extra):
    return _run([dest / "uninstall.sh", "--dest", dest, "--yes", *extra], tmp_path)


def test_manifest_excludes_preexisting_user_file_and_uninstall_keeps_it(tmp_path):
    src = _fake_src(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()
    user_file = dest / "my_notes.md"
    user_file.write_text("用户自己的文件", encoding="utf-8")

    r = _install(tmp_path, src, dest)
    assert r.returncode == 0, r.stdout + r.stderr
    manifest = (dest / ".spz-manifest").read_text(encoding="utf-8")
    assert "# manifest-version: 2" in manifest
    assert "my_notes.md" not in manifest, "manifest 不得收录安装前就存在的用户文件"

    r = _uninstall(tmp_path, dest)
    assert r.returncode == 0, r.stdout + r.stderr
    assert user_file.exists(), "卸载不得删除用户文件"
    assert not (dest / "gatekeeper-cli.sh").exists()
    assert not (dest / ".spz-manifest").exists()


def test_conflict_kept_without_force_and_backup_on_force(tmp_path):
    src = _fake_src(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "SKILL.md").write_text("用户改过的版本\n", encoding="utf-8")

    r = _install(tmp_path, src, dest)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (dest / "SKILL.md").read_text(encoding="utf-8") == "用户改过的版本\n"
    assert "conflict (kept): SKILL.md" in r.stdout

    r = _install(tmp_path, src, dest, "--force")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (dest / "SKILL.md").read_text(encoding="utf-8") == (src / "SKILL.md").read_text(encoding="utf-8")
    backups = list(dest.glob("SKILL.md.bak-*"))
    assert len(backups) == 1 and backups[0].read_text(encoding="utf-8") == "用户改过的版本\n"


def test_legacy_manifest_requires_force_legacy(tmp_path):
    src = _fake_src(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()
    assert _install(tmp_path, src, dest).returncode == 0
    # 伪造 v1（无版本行）：其中混入一条用户文件，模拟旧安装器把整目录写进 manifest
    user_file = dest / "notes.md"
    user_file.write_text("keep me", encoding="utf-8")
    (dest / ".spz-manifest").write_text("gatekeeper-cli.sh\nnotes.md\n",
                                        encoding="utf-8", newline="\n")

    r = _uninstall(tmp_path, dest)
    assert r.returncode == 2, r.stdout + r.stderr
    assert (dest / "gatekeeper-cli.sh").exists(), "拒删必须是零副作用"
    assert user_file.exists()

    r = _uninstall(tmp_path, dest, "--force-legacy")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (dest / "gatekeeper-cli.sh").exists()


def test_uninstall_dest_matches_install_dest(tmp_path):
    src = _fake_src(tmp_path)
    dest = tmp_path / "claude" / "skills" / "spz-gatekeeper-r-sequence"
    r = _install(tmp_path, src, dest)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (dest / "scripts" / "gk_hook_manage.py").exists()

    r = _uninstall(tmp_path, dest)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not dest.exists(), "空目录应被清理"


def test_cron_dir_not_removed(tmp_path):
    src = _fake_src(tmp_path)
    dest = tmp_path / "dest"
    cron = tmp_path / "home" / ".gatekeeper" / "cron"
    cron.mkdir(parents=True)
    (cron / "jobs.json").write_text("[]", encoding="utf-8")
    assert _install(tmp_path, src, dest).returncode == 0

    r = _uninstall(tmp_path, dest)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (cron / "jobs.json").exists(), "用户级 cron 目录不得被自动删除"
    assert "未删除用户级任务目录" in r.stdout


def test_hook_assets_installed(tmp_path):
    src = _fake_src(tmp_path)
    (src / "assets").mkdir()
    (src / "assets" / "echarts.min.js").write_text("// stub", encoding="utf-8")
    dest = tmp_path / "dest"
    assert _install(tmp_path, src, dest).returncode == 0
    assert (dest / "assets" / "echarts.min.js").exists(), "assets/ 必须随安装复制（缺则图表静默降级）"
