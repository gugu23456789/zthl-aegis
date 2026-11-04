"""test_gk_threat_patterns.py — 威胁模式单一来源（2026-11-04）。

约束（用户裁定「收敛为单一来源」）：
  - cron prompt 扫描（宽口径）与编辑载荷闸 R0.19（高置信）在**同一模块**定义；
  - `cron_jobs` / `pre_tool_hook` 只做**别名引用**（同一对象），不得各存一份；
  - 宽口径不得下沉到载荷面（`chmod 0600` / `sudo` / `eval(` 这类正常代码不许被拦）。
"""
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent))

import gk_threat_patterns as T


class TestSingleSource:
    def test_cron_jobs_aliases_are_the_same_objects(self):
        import cron_jobs
        assert cron_jobs._THREAT_PATTERNS is T.PROMPT_THREAT_PATTERNS
        assert cron_jobs._EXFIL_PATTERNS is T.PROMPT_EXFIL_PATTERNS
        assert cron_jobs._INVISIBLE_UNICODE is T.INVISIBLE_UNICODE

    def test_hook_uses_shared_payload_table(self):
        import pre_tool_hook
        assert pre_tool_hook._MALWARE_PATTERNS is T.PAYLOAD_MALWARE_PATTERNS


class TestTierSeparation:
    """宽口径不下沉：正常代码不得被载荷面拦。"""

    @pytest.mark.parametrize("code", [
        "chmod(0o600, path)",
        "sudo = True",
        "eval(user_expr)",
        "subprocess.run(['sudo', 'apt', 'install', 'x'])",
    ])
    def test_normal_code_not_matched_by_payload_tier(self, code):
        for label, pat in T.PAYLOAD_MALWARE_PATTERNS:
            assert not __import__("re").search(pat, code, __import__("re").IGNORECASE), \
                f"载荷层误伤正常代码: {label} / {code}"

    def test_wide_tier_would_match_that_code(self):
        """反证：同一段代码在宽口径（cron prompt）里是命中的 —— 两层口径确实不同。"""
        assert any(p.search("chmod 0700 x") for p in T.PROMPT_THREAT_PATTERNS)


class TestPrimitiveReuse:
    def test_payload_uses_shared_primitives(self):
        pats = [p for _label, p in T.PAYLOAD_MALWARE_PATTERNS]
        assert T.DEV_TCP_RE in pats
        assert T.PIPE_TO_SHELL_RE in pats
        assert T.B64_TO_SHELL_RE in pats

    def test_no_duplicate_pattern_text(self):
        """同一正则文本不得在载荷层出现两次（两张表漂移的起点）。"""
        texts = [p for _label, p in T.PAYLOAD_MALWARE_PATTERNS]
        assert len(texts) == len(set(texts))
