#!/usr/bin/env python3
"""test_gk_bomb_inventory.py — 内联载荷清点/棘轮门禁单测（N-1）。

覆盖：分类计数、`--freeze` 冻结、`--assert-baseline` 只报 NEW、`--max-payload` 棘轮。
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent / "gk_bomb_inventory.py"

BASE_CLI = """#!/usr/bin/env bash
f1() {
  local v
  v=$(python3 -c 'print(1)')
  python3 -c 'import json'
  python3 -c "$v"
  # 注释里的 python3 -c 不算载荷
  python3 -c "
import sys
print(sys.argv)
"
}

python3 <<'PY'
print("heredoc")
PY
"""


def _run(capsys, *args):
    rc = subprocess.run([sys.executable, str(SCRIPT), *args],
                        capture_output=True, text=True)
    out = rc.stdout.strip()
    data = json.loads(out) if out.startswith("{") else None
    return rc.returncode, data


def test_categories(tmp_path):
    cli = tmp_path / "cli.sh"
    cli.write_text(BASE_CLI, encoding="utf-8")
    rc, d = _run(None, "--cli", str(cli), "--json")
    assert rc == 0
    assert d["by_cat"]["payload"] >= 3      # 单行 + 多行 + heredoc
    assert d["by_cat"]["import_probe"] == 1
    assert d["by_cat"]["wrapper"] == 1
    assert d["by_cat"]["comment"] == 1


def test_freeze_and_no_new(tmp_path):
    cli = tmp_path / "cli.sh"
    cli.write_text(BASE_CLI, encoding="utf-8")
    b = tmp_path / "base.json"
    rc, d = _run(None, "--cli", str(cli), "--freeze", str(b), "--note", "fixture")
    assert rc == 0 and d["ok"] is True
    snap = json.loads(b.read_text(encoding="utf-8"))
    assert snap["schema"] == "gk-bomb-inventory/1"
    assert snap["note"] == "fixture" and snap["frozen_at"]
    rc, d = _run(None, "--cli", str(cli), "--assert-baseline", str(b))
    assert rc == 0 and d["new_count"] == 0 and d["verdict"] == "NO_NEW"


def test_new_payload_detected(tmp_path):
    cli = tmp_path / "cli.sh"
    cli.write_text(BASE_CLI, encoding="utf-8")
    b = tmp_path / "base.json"
    assert _run(None, "--cli", str(cli), "--freeze", str(b))[0] == 0
    cli.write_text(BASE_CLI + "\npython3 -c 'print(999)'\n", encoding="utf-8")
    rc, d = _run(None, "--cli", str(cli), "--assert-baseline", str(b))
    assert rc == 1 and d["new_count"] >= 1 and d["verdict"] == "NEW_FOUND"


def test_max_payload_ratchet(tmp_path):
    cli = tmp_path / "cli.sh"
    cli.write_text(BASE_CLI, encoding="utf-8")
    _, d = _run(None, "--cli", str(cli), "--json")
    n = d["by_cat"]["payload"]
    assert _run(None, "--cli", str(cli), "--max-payload", str(n))[0] == 0
    rc, d = _run(None, "--cli", str(cli), "--max-payload", str(n - 1))
    assert rc == 1 and d["check"] == "max-payload" and d["overflow"] == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


def test_public_baseline_strips_absolute_paths(tmp_path):
    """2026-11-04 工程债：`--public-baseline` 冻结时把 file 脱敏为仓内相对形态。

    `--assert-baseline` 只用 (func,cat,sha)，file 仅为展示；但 `pack_release.py` 的
    身份扫描会把绝对路径判为残留 ⟹ 公开面基线必须零绝对路径，且仍能 NO_NEW。
    """
    cli = tmp_path / "cli.sh"
    cli.write_text(BASE_CLI, encoding="utf-8")
    out = tmp_path / "public-base.json"
    rc, d = _run(None, "--cli", str(cli), "--public-baseline", str(out), "--note", "public")
    assert rc == 0 and d["ok"] is True

    snap = json.loads(out.read_text(encoding="utf-8"))
    files = [it.get("file", "") for it in snap["items"]]
    assert files, "基线为空，测试无意义"
    for f in files:
        assert not Path(f).is_absolute(), f
        assert ":" not in f[:3], f          # 不带 Windows 盘符
        assert not f.startswith("/mnt/"), f
        assert ".." not in Path(f).parts, f

    rc, d = _run(None, "--cli", str(cli), "--assert-baseline", str(out))
    assert rc == 0 and d["verdict"] == "NO_NEW"
