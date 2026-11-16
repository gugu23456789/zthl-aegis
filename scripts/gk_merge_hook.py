#!/usr/bin/env python3
"""gk_merge_hook.py — 主树 ref 更新闸（git `reference-transaction` 钩子实现，R0.24，2026-11-13）。

契约:
  - 输入: 位置参数 `prepared|committed|aborted`；stdin 每行 `<old> <new> <ref>`
  - 输出: exit 0 = 放行；exit 1 = 拒绝本次 ref 更新（git 自行中止 merge/pull/reset/branch -f）
  - 失败: 票据缺失/签名不符/过期/ref 不匹配 ⟹ **拒绝**（fail-closed，不回退成"放行")

单一事实源: 本模块；`.git/hooks/reference-transaction` 只是 shim（`gatekeeper-cli.sh merge-hook
--install` 生成，禁手改）。禁止第二实现: 不要在 bash 里重写 HMAC 或"是否放行"的判据。

判据（2026-11-13 扩面：**任何**向主树的写入都要过闸）:
  ① `ref ∈ {refs/heads/master, refs/heads/main}` 且 `old != new` ⟹ 必须持有与 `(ref, old)`
     匹配的一次性票据；**不再区分**「合并式 / 单条直接提交」。
  ② 主 ref **删除**（`new == ZERO`）⟹ 直接拒绝：删主分支不可恢复，且无票据通道。
  ③ 主 ref **新建**（`old == ZERO`）⟹ 放行（init / 首提交引导，此时无既存主树可写）。
  背景：首版只拦「合并式」更新（≥2 父 / 多提交快进），单条直接提交放行 —— 实测 2026-11-13
  有人直接 `git commit` 到 master（`7a835309`）绕过整个前置闸 ⟹ owner 裁定扩面。日常主树
  修字改为「建分支 → commit → `gatekeeper-cli.sh merge`」。

变更记录（append-only）:
  - 2026-11-13 R0.24: 首版（票据 = HMAC-SHA256(common-dir 密钥, {ref,old,source,ts})；一次性）。
  - 2026-11-13 R0.24-b: 判据扩面 —— 主 ref 的**任何**前进都需票据（原「只拦合并式」被单条
    直接提交绕过，实测 `7a835309`）；主 ref 删除一律拒；`old == ZERO` 的引导放行。
"""
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time

MAIN_REFS = ("refs/heads/master", "refs/heads/main")
TICKET_TTL = 900          # 秒；覆盖「闸① → 解冲突 → 闸② → 提交」的正常耗时
ZERO = "0" * 40


def _git(repo: str, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)


def common_dir(repo: str = ".") -> str:
    """git 公共目录（worktree 共享 .git 的绝对路径）；解析失败 ⟹ 空串（调用方 fail-closed）。"""
    r = _git(repo, "rev-parse", "--git-common-dir")
    p = (r.stdout or "").strip()
    if r.returncode != 0 or not p:
        return ""
    if not os.path.isabs(p):
        p = os.path.normpath(os.path.join(os.path.abspath(repo), p))
    return p


def _key(cd: str) -> bytes:
    """读/建 0600 密钥（一仓一把；不进 git，不进 state）。失败 ⟹ 抛 OSError（调用方拒绝）。"""
    p = os.path.join(cd, "gatekeeper-merge.key")
    if not os.path.exists(p):
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    with open(p, "rb") as f:
        return f.read()


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sig(cd: str, obj: dict) -> str:
    return hmac.new(_key(cd), _canon(obj), hashlib.sha256).hexdigest()


def ticket_path(cd: str) -> str:
    return os.path.join(cd, "gatekeeper-merge.ticket")


def write_ticket(cd: str, ref: str, old: str, source: str) -> str:
    """签发一次性合并票据（只由 `gk_merge_cli.py` 在闸① PASS 后调用）。"""
    body = {"v": 1, "ref": ref, "old": old, "source": source, "ts": int(time.time())}
    body["sig"] = _sig(cd, body)
    p = ticket_path(cd)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(body, f, ensure_ascii=False, sort_keys=True)
    os.chmod(p, 0o600)
    return p


def verify_and_consume(cd: str, ref: str, old: str) -> tuple:
    """校验并**消费**票据。返回 `(ok, reason)`；成功时删除票据（一次性，防重放）。"""
    p = ticket_path(cd)
    if not os.path.exists(p):
        return False, "NO_TICKET"
    try:
        with open(p, encoding="utf-8") as f:
            body = json.load(f)
    except (OSError, ValueError):
        return False, "TICKET_UNREADABLE"
    sig = str(body.pop("sig", ""))
    try:
        want = _sig(cd, body)
    except OSError:
        return False, "KEY_UNREADABLE"
    if not hmac.compare_digest(sig, want):
        return False, "TICKET_BAD_SIGNATURE"
    if body.get("ref") != ref:
        return False, "TICKET_REF_MISMATCH"
    if body.get("old") != old:
        return False, "TICKET_STALE_OLD"
    if int(time.time()) - int(body.get("ts") or 0) > TICKET_TTL:
        return False, "TICKET_EXPIRED"
    try:
        os.unlink(p)
    except OSError:
        pass
    return True, "OK"


_HINT = (
    "Fix: 主树写入的唯一入口是 `bash gatekeeper-cli.sh merge --source <branch> [--target master]`"
    "（内部 闸①→merge→闸②→提交，自动签发票据）。主树上的直接 `git commit` / `merge` / `pull` /"
    " `reset` / `branch -f` 一律被拒；日常主树修字请「建分支 → commit → merge」。"
)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    phase = argv[0] if argv else ""
    if phase != "prepared":               # committed/aborted 无需动作
        return 0
    cd = common_dir(os.getcwd())
    if not cd:
        sys.stderr.write("BLOCK[merge-hook]: 解析不到 git common dir（fail-closed）\n" + _HINT + "\n")
        return 1
    for line in sys.stdin.read().splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        old, new, ref = parts[0], parts[1], parts[2]
        if ref not in MAIN_REFS or old == new:
            continue
        if new == ZERO:
            # 主 ref 删除不可恢复，且没有"删除票据"通道 ⟹ 一律拒（fail-closed）。
            sys.stderr.write(
                "BLOCK[merge-hook]: 主分支引用删除被拒（%s）⟹ 删除主分支不可恢复，本闸无删除通道\n%s\n"
                % (ref, _HINT))
            return 1
        if old == ZERO:
            # 引导：init / 首提交。此时没有既存主树可写，票据无从谈起。
            continue
        ok, why = verify_and_consume(cd, ref, old)
        if not ok:
            sys.stderr.write(
                "BLOCK[merge-hook]: %s 的主树写入未经前置闸（%s；old=%s → new=%s）⟹ 已拒绝本次 ref 更新\n%s\n"
                % (ref, why, old[:12], new[:12], _HINT))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
