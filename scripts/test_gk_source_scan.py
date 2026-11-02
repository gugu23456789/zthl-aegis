"""test_gk_source_scan.py — B9a 红先（2026-10-27，锚 RED-MIGRATE-INLINE）

两处「文件结构扫描」内联块抽成 gk_source_scan.py：
  · protected-regions   ← `_protected_region_check`（PROTECTED_REGION 区间表）
  · large-inline-blocks ← cmd_self_check dead_code_gate3（>N 行内联 python 块计数）
两者都是纯只读解析：无 state、无网络、无副作用。
"""
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).parent / "gk_source_scan.py"


def _run(*args):
    return subprocess.run([sys.executable, str(CLI)] + list(args),
                          capture_output=True, text=True, encoding="utf-8")


class TestProtectedRegions:
    def test_basic_pair(self, tmp_path):
        f = tmp_path / "x.sh"
        f.write_text("\n".join([
            "#!/bin/bash",
            "# PROTECTED_REGION_START::gate",
            "echo hi",
            "# PROTECTED_REGION_END::gate",
            "tail",
        ]), encoding="utf-8")
        p = _run("protected-regions", str(f))
        assert p.returncode == 0 and p.stdout == "2:4:gate\n", p

    def test_multiple_and_order(self, tmp_path):
        f = tmp_path / "x.sh"
        f.write_text("\n".join([
            "# PROTECTED_REGION_START::a",      # 1
            "# PROTECTED_REGION_START::b",      # 2
            "# PROTECTED_REGION_END::b",        # 3
            "# PROTECTED_REGION_END::a",        # 4
        ]), encoding="utf-8")
        p = _run("protected-regions", str(f))
        assert p.stdout == "2:3:b\n1:4:a\n", p

    def test_end_without_start_ignored(self, tmp_path):
        f = tmp_path / "x.sh"
        f.write_text("\n".join([
            "# PROTECTED_REGION_END::ghost",
            "# PROTECTED_REGION_START::ok",
            "# PROTECTED_REGION_END::ok",
        ]), encoding="utf-8")
        assert _run("protected-regions", str(f)).stdout == "2:3:ok\n"

    def test_indented_marker_still_matches(self, tmp_path):
        f = tmp_path / "x.sh"
        f.write_text("  # PROTECTED_REGION_START::x\n    # PROTECTED_REGION_END::x\n",
                     encoding="utf-8")
        assert _run("protected-regions", str(f)).stdout == "1:2:x\n"

    def test_non_region_comment_ignored(self, tmp_path):
        f = tmp_path / "x.sh"
        f.write_text("# PROTECTED_REGION_START_gate\necho x\n", encoding="utf-8")
        assert _run("protected-regions", str(f)).stdout == ""

    def test_missing_file_nonzero(self, tmp_path):
        p = _run("protected-regions", str(tmp_path / "nope.sh"))
        assert p.returncode != 0, p


class TestLargeInlineBlocks:
    def test_counts_blocks_over_threshold(self, tmp_path):
        f = tmp_path / "x.sh"
        big = ("python3 -c \"\n" + "\n".join("x=%d" % i for i in range(45))
               + "\n\" 2>/dev/null || echo \"\"")
        small = ("python3 -c \"\n" + "\n".join("y=%d" % i for i in range(10))
                 + "\n\" 2>/dev/null || echo \"\"")
        f.write_text(big + "\n" + small + "\n", encoding="utf-8")
        p = _run("large-inline-blocks", str(f))
        assert p.returncode == 0 and p.stdout == "1\n", p

    def test_threshold_override(self, tmp_path):
        f = tmp_path / "x.sh"
        blk = ("python3 -c \"\n" + "\n".join("x=%d" % i for i in range(12))
               + "\n\" 2>/dev/null || echo \"\"")
        f.write_text(blk + "\n", encoding="utf-8")
        assert _run("large-inline-blocks", str(f)).stdout == "0\n"
        assert _run("large-inline-blocks", str(f), "--min-lines", "10").stdout == "1\n"

    def test_single_line_block_not_counted(self, tmp_path):
        f = tmp_path / "x.sh"
        f.write_text('python3 -c "print(1)" 2>/dev/null\n', encoding="utf-8")
        assert _run("large-inline-blocks", str(f)).stdout == "0\n"

    def test_legacy_closing_quirk_preserved(self, tmp_path):
        """旧式收尾判据是 `q + '"'`（双引号块需行内出现 `""`）。

        单引号收尾 `" 2>/dev/null` 不闭合 ⟹ 不计入。本测试锁定该历史怪癖，
        迁移**不得**顺手“修正”成 `q in s`（实测仓内 21 vs 23 会漂移）。
        """
        f = tmp_path / "x.sh"
        blk = ("python3 -c \"\n" + "\n".join("x=%d" % i for i in range(45))
               + "\n\" 2>/dev/null")
        f.write_text(blk + "\n", encoding="utf-8")
        assert _run("large-inline-blocks", str(f)).stdout == "0\n"

    def test_empty_file_zero(self, tmp_path):
        f = tmp_path / "x.sh"
        f.write_text("", encoding="utf-8")
        assert _run("large-inline-blocks", str(f)).stdout == "0\n"

    def test_missing_file_nonzero(self, tmp_path):
        assert _run("large-inline-blocks", str(tmp_path / "nope.sh")).returncode != 0


class TestDispatch:
    def test_unknown_verb_exit_2(self):
        assert _run("nope").returncode == 2

    def test_no_args_exit_2(self):
        assert _run().returncode == 2
