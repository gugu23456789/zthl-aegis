#!/usr/bin/env python3
"""hook 治理台账删除闸红先臂（2026-11-01）。

判据：
  1. `rm/unlink/shred/truncate` 命中 `.gatekeeper.state*` ⟹ BLOCK（含归档旁挂）；
  2. `find … -delete` 命中同一模式 ⟹ BLOCK；
  3. 可逆归档入口 `state --archive-isolated` 不吃误伤；
  4. 普通删除（非 state 台账）仍走既有通用规则，不被本闸接管。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pre_tool_hook as H  # noqa: E402


def test_rm_state_archive_is_blocked():
    for cmd in ("rm -f .gatekeeper.state.rejected-edits-archive.jsonl",
                "rm .gatekeeper.state.history-archive.jsonl",
                "truncate -s 0 .gatekeeper.state"):
        r = H._dangerous_chain(cmd)
        assert r and "治理台账" in r[0], (cmd, r)


def test_find_delete_state_is_blocked():
    r = H._dangerous_chain("find . -name '.gatekeeper.state*' -delete")
    assert r and "治理台账" in r[0], r


def test_archive_isolated_is_not_blocked():
    assert H._dangerous_chain("bash gatekeeper-cli.sh state --archive-isolated --apply") is None


def test_unrelated_delete_still_uses_generic_rules():
    assert H._dangerous_chain("rm -f /tmp/scratch.txt") is None
    r = H._dangerous_chain("rm -rf /tmp/somedir")
    assert r and "rm -rf" in r[0], r
