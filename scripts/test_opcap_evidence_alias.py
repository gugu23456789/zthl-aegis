#!/usr/bin/env python3
"""`opcap_evidence.py` 薄别名的机检臂（2026-11-02）。

守三件事：
  ① 入口存在且 CLI 与 `gk_opcap_export.py` **同形**（`--state` / `--pretty`）；
  ② 同一 state 下**输出逐字相等**（别名不是第二实现）；
  ③ 源码不含 `def export`（禁复制判定逻辑）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ALIAS = SCRIPT_DIR / "opcap_evidence.py"
CANON = SCRIPT_DIR / "gk_opcap_export.py"


def _run(script: Path, *args):
    return subprocess.run([sys.executable, str(script), *args],
                          capture_output=True, text=True, timeout=60)


def _state(tmp_path: Path) -> Path:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({
        "gate_data": {
            "ecc_findings": [
                {"id": "ECC-AAAAAAAAAAAA", "status": "closed", "created_at": "2026-01-01T00:00:00Z",
                 "closed_at": "2026-01-02T00:00:00Z", "root_key": "demo"}
            ]
        }
    }), encoding="utf-8")
    log = Path(str(st) + ".budget-log.jsonl")
    log.write_text(json.dumps({"source": "code-fix", "kind": "raise",
                               "reason": "ECC-AAAAAAAAAAAA", "ts": "2026-01-01T00:00:00Z"}) + "\n",
                   encoding="utf-8")
    return st


def test_alias_help_has_same_flags():
    r = _run(ALIAS, "--help")
    assert r.returncode == 0, r.stderr
    assert "--state" in r.stdout and "--pretty" in r.stdout, r.stdout


def test_alias_output_is_identical_to_canonical(tmp_path):
    st = _state(tmp_path)
    a = _run(ALIAS, "--state", str(st), "--pretty")
    b = _run(CANON, "--state", str(st), "--pretty")
    assert a.returncode == b.returncode, (a.returncode, b.returncode)
    assert json.loads(a.stdout) == json.loads(b.stdout), "别名输出与正本不等 ⟹ 出现第二实现"


def test_alias_has_no_second_implementation():
    src = ALIAS.read_text(encoding="utf-8")
    assert "def export(" not in src, "别名内出现第二份 export()"
    assert len(src.splitlines()) < 40, "别名文件膨胀，疑似复制实现"
