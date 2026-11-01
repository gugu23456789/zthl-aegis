#!/usr/bin/env python3
"""SAFE-TERMINATION GATE 回归：--no-aggregate 默认可见、开启后拦截。"""
import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAN = "docs/plans/2026-10-04-audit-bureau-plan.md"


class SafeTerminationGateTest(unittest.TestCase):
    def _run(self, enabled: bool):
        env = os.environ.copy()
        env["GK_SAFE_TERMINATION"] = "1" if enabled else "0"
        return subprocess.run(
            ["bash", "gatekeeper-cli.sh", "plan-refinement", PLAN, "--no-aggregate"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=60,
        )

    def test_default_visible_not_blocking(self):
        r = self._run(False)
        self.assertIn('"gate":"safe_termination"', r.stderr)
        self.assertNotIn("safe_termination_gate", r.stdout)

    def test_enabled_blocks_before_downstream(self):
        r = self._run(True)
        self.assertIn("safe_termination_gate", r.stdout)
        self.assertIn('"exit_code":2', r.stdout)


if __name__ == "__main__":
    unittest.main()
