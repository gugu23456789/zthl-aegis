#!/usr/bin/env python3
"""R3 红先：隔离 worktree 的**身份/密钥面继承**（2026-09-21）。

缺陷（实测，非推断）：`.keys/` 被 `.gitignore:19` 排除、不入 HEAD 树
（`git ls-tree -r HEAD -- .keys` 为空）⟹ `audit --crossfull --isolate` 建出的隔离 worktree
**必然没有** `.keys/`；而嵌套 CLI 的 `SKILL_DIR` 按**脚本目录**派生（外部 env 不生效）⟹
`_CONTEXT_PUB_KEY` 指空文件 ⟹ `_ctx_inject_probe` 恒 `sig_invalid` ⟹ **preflight A 硬阻断**；
且失败以 L2=`WARN(受限)` 呈现而 crossfull 整体 **rc=0**（**假绿**）。

测法（与 R5 同构）：**抽取 CLI 的实际源片段** → 在夹具上 `bash -c` 跑 → 断言产物。
不跑 git / 不跑 crossfull ⟹ 零派发、零 API。

三臂：
  1 正臂   源有 `.keys` + worktree 无 → 建链；且**用链上的公钥能验证**签名（行为，非子串）
  2 负臂   源无 `.keys`               → 不建链、不报错（`[ -d ]` 守卫生效）
  3 幂等   源有 `.keys` + worktree 已有 → 不覆盖（`[ ! -e ]` 守卫生效）
"""
import re
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
CLI = HERE.parent / "gatekeeper-cli.sh"

_FRAG_RE = re.compile(
    r'(        if \[ -d "\$_cf_iso_src/\.keys" \] && \[ ! -e "\$_cf_wt/\.keys" \]; then\n.*?\n        fi\n)',
    re.S)


def _extract() -> str:
    txt = CLI.read_text(encoding="utf-8", errors="replace")
    m = _FRAG_RE.search(txt)
    assert m, "CLI 中找不到隔离面继承片段（R3 未接线？）"
    return m.group(1)


def _run_frag(src: Path, wt: Path) -> subprocess.CompletedProcess:
    frag = _extract()
    script = ("set -u\n_cf_iso_src=\"$1\"\n_cf_wt=\"$2\"\nGK_DBG_LOG=/dev/null\n"
              "_cf_wt_root=unused\n" + frag + "\necho INHERIT_DONE\n")
    return subprocess.run(["bash", "-c", script, "_", str(src), str(wt)],
                          capture_output=True, text=True, timeout=60)


def _mkkv(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                    "-out", str(d / "context_ed25519.pem")], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(d / "context_ed25519.pem"),
                    "-pubout", "-out", str(d / "context_ed25519.pub")], check=True, capture_output=True)


def _sign_ok(wt: Path, payload: Path) -> bool:
    """用**链上**的公钥验签（真行为断言：链指向的确实是同一把私钥的对应公钥）。"""
    sig = payload.with_suffix(".sig")
    return subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin",
         "-inkey", str(wt / ".keys" / "context_ed25519.pub"),
         "-rawin", "-in", str(payload), "-sigfile", str(sig)],
        capture_output=True, text=True).returncode == 0


class TestIsolateKeysInherit:
    def test_arm1_positive_link_and_verify(self, tmp_path):
        src, wt = tmp_path / "src", tmp_path / "wt"
        _mkkv(src / ".keys")
        wt.mkdir()
        payload = tmp_path / "ctx.json"
        payload.write_text("ctx", encoding="utf-8")
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(src / ".keys" / "context_ed25519.pem"),
                        "-rawin", "-in", str(payload), "-out", str(payload.with_suffix(".sig"))],
                       check=True, capture_output=True)
        r = _run_frag(src, wt)
        assert "INHERIT_DONE" in r.stdout, r.stderr
        assert (wt / ".keys").is_symlink(), "应建软链（单源密钥面）"
        assert _sign_ok(wt, payload), "链上公钥必须能验源私钥的签名"

    def test_arm2_negative_no_source_keys(self, tmp_path):
        src, wt = tmp_path / "src", tmp_path / "wt"
        src.mkdir()
        wt.mkdir()
        r = _run_frag(src, wt)
        assert "INHERIT_DONE" in r.stdout, r.stderr
        assert not (wt / ".keys").exists(), "源无 .keys ⟹ 不得凭空建链"

    def test_arm3_idempotent_no_clobber(self, tmp_path):
        src, wt = tmp_path / "src", tmp_path / "wt"
        _mkkv(src / ".keys")
        (wt / ".keys").mkdir(parents=True)
        (wt / ".keys" / "sentinel").write_text("keep", encoding="utf-8")
        r = _run_frag(src, wt)
        assert "INHERIT_DONE" in r.stdout, r.stderr
        assert (wt / ".keys" / "sentinel").exists(), "已存在的 .keys 不得被覆盖"
        assert not (wt / ".keys").is_symlink()

    def test_wiring_fail_loud(self):
        """接线断言：继承失败须 **fail-loud**（拒绝继续），不得留假绿。"""
        frag = _extract()
        assert "isolate_keys_inherit_failed" in frag
        assert "return 2" in frag
