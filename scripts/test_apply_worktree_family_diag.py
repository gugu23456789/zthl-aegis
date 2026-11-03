#!/usr/bin/env python3
"""apply-worktree 自动族判定诊断回归（2026-11-03）。

病象：显式 `--family` 时，自动判定用 `resolve ... || true` + `json-field family 2>/dev/null`
⟹ resolve 的 `FAMILY_ANCHOR_MISMATCH` 等真因被吞成 `auto=<none>`，只回一条泛化 hint，
操作者无法区分「无族命中」与「族↔finding 落点错配」。

判据（源码级，0.01s）：该段必须
  ① 不吞 resolve 的非零退出（禁 `|| true`）；
  ② 回包带 `auto_rc` 与 `auto_error`；
  ③ `auto_error` 经 `json-escape` 转义（防坏 JSON）。
"""
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _seg() -> str:
    lines = CLI.read_text(encoding="utf-8").splitlines()
    start = next(i for i, l in enumerate(lines) if 'if [ -n "$family" ]; then' in l)
    end = next(i for i in range(start, len(lines))
               if "--dry-run：只回族判定" in lines[i])
    # 只看代码行：注释里会复述旧写法（`|| true`），不得被当成现行代码。
    return "\n".join(l for l in lines[start:end] if not l.lstrip().startswith("#"))


def test_family_resolve_error_not_swallowed():
    seg = _seg()
    assert "|| true" not in seg, "自动族判定仍吞掉 resolve 非零退出 ⟹ auto_rc 不可见"
    assert "auto_rc" in seg, "FAMILY_MISMATCH 回包缺 auto_rc ⟹ 退出码不可见"
    assert "auto_error" in seg, (
        "FAMILY_MISMATCH 回包缺 auto_error ⟹ FAMILY_ANCHOR_MISMATCH 真因不可见")
    assert "json-escape" in seg, "auto_error 未转义 ⟹ 回包可能非法 JSON"
