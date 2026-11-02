"""
test_bash_static_scan.py -- Tests for gk_bash_static_scan.py P8 危险命令模式
==============================================================================
Covers: P8 rm -rf / git push --force / git reset --hard / git clean -f 检测,
        $_tmp 变量豁免, .py 目标跳过 P8, 安全脚本无命中, 真实仓库 scan_skill P8 PASS.
"""
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

import gk_bash_static_scan as bs


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestP8ShellDetection:
    """P8: .sh 目标危险命令字面量检测"""

    def test_rm_rf_detected(self, tmp_path):
        p = _write(tmp_path, "evil.sh", "#!/bin/bash\nrm -rf /var/backups\n")
        finds = bs.scan_file(p)
        assert any(f[0] == "P8" and "rm" in f[2] for f in finds)

    def test_rm_rf_variable_target_detected(self, tmp_path):
        """F10 事件形态: 变量指向任意目录 (非 $_tmp) → 必须拦"""
        p = _write(tmp_path, "evil2.sh", 'rm -rf "$TMP"\n')
        finds = bs.scan_file(p)
        assert any(f[0] == "P8" for f in finds)

    def test_rm_rf_tmp_var_exempt(self, tmp_path):
        """CLI 内部 $_tmp 临时目录变量 → 豁免"""
        p = _write(tmp_path, "ok.sh", 'rm -rf "$_tmp_audit_dir"\n')
        finds = bs.scan_file(p)
        assert not any(f[0] == "P8" for f in finds)

    def test_git_push_force_detected(self, tmp_path):
        p = _write(tmp_path, "g.sh", "git push --force origin main\n")
        finds = bs.scan_file(p)
        assert any(f[0] == "P8" and "push --force" in f[2] for f in finds)

    def test_git_reset_hard_detected(self, tmp_path):
        """git 与子命令间允许选项（对齐 R0.2 2026-08-15 红队修正）"""
        p = _write(tmp_path, "g2.sh", "git -C /repo reset --hard HEAD\n")
        finds = bs.scan_file(p)
        assert any(f[0] == "P8" and "reset --hard" in f[2] for f in finds)

    def test_git_clean_f_detected(self, tmp_path):
        p = _write(tmp_path, "g3.sh", "git clean -fd\n")
        finds = bs.scan_file(p)
        assert any(f[0] == "P8" and "clean" in f[2] for f in finds)

    def test_safe_script_no_p8(self, tmp_path):
        p = _write(tmp_path, "safe.sh", "#!/bin/bash\necho hello\nls -la\n")
        finds = bs.scan_file(p)
        assert not any(f[0] == "P8" for f in finds)


class TestP8SkipPython:
    """P8 仅扫 .sh 目标；.py 目标跳过（检测器/业务字符串天然含危险命令字面量）"""

    def test_py_target_skipped(self, tmp_path):
        p = _write(tmp_path, "hook.py", 'return ("dangerous command: git push --force")\n')
        finds = bs.scan_file(p)
        assert not any(f[0] == "P8" for f in finds)


class TestP8RealRepo:
    """真实仓库 scan_skill: P8 必须 PASS（gatekeeper-cli.sh 无危险命令裸奔，$_tmp 豁免生效）"""

    def test_real_skill_repo_p8_pass(self):
        result = bs.scan_skill(bs.DEFAULT_SKILL)
        p8 = next(c for c in result["checks"] if c["check"] == "bash_static_p8")
        assert p8["status"] == "PASS"
