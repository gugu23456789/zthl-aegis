#!/usr/bin/env python3
"""context 签名在密钥轮换后必须被重签（2026-09-20 现场缺陷，登记号见 docs/plans/2026-09-20-*.md）。

现场取证（2026-09-20，全实测）：
  cron 作业 `key-rotate-check`（every 24h）于 2026-09-20 08:49:09 轮换了 context 密钥，但
  `references/subagent-context.json.sig` 的 mtime 仍停在 2026-09-19 07:53:44
  （= gk_dbg.log 最后一条「context 自动重签完成」）⟹ 该 .sig 对**当前** pub 验签**失败**、
  对上一代 `context_ed25519.pub.20260920_084908.bak` 验签**成功**。
  下游实证后果：`node-guard ECO-READ` 把「代码库地图 (subagent-context.json 签名有效)
  (sig_stale_after_key_rotation)」列为 missing ⟹ 序列节点被实际阻断，非纸面问题。

根因：cmd_audit 的 rotate 臂那行注释写 "Re-sign context if context key rotated"，
  实现却是 `_sign_raw "$ctx_file" > /dev/null 2>&1` —— `_sign_raw` 只把 **base64 JSON** 打到
  stdout、从不落盘 ⟹ 丢弃 stdout = 完全 no-op（且把该 JSON 直写 .sig 也是错形态：
  .sig 是 64 字节裸签名）。真正的实现早已存在并被启动路径复用：`_context_resign`
  （sign → base64 decode → 写 `${ctx}.sig` + 记 gk_dbg.log）—— 同族两处、一处对一处废。

本文件锁「轮换后 .sig 必须被重签、且只对新公钥有效」这一**行为**，不锁实现形态
（原地修 / 改调 `_context_resign` / 未来别的写法都应通过）。

沙箱必须建在 WSL 侧：`os.symlink` 在无特权 Windows 下报 WinError 1314
（`test_gk_cli_skildir_guard._mk_sandbox` / `test_gk_audit_all_aggregation._wsl` 同形踩点）。
`scripts/` 逐项软链（`gk_dbg.log` 换成沙箱内真实空文件）⟹ SKILL_DIR 过租户校验且不污染真日志。

red-first 对照臂：`GK_CLI_UNDER_TEST=<旧版 CLI 绝对路径>`（默认 = 仓内 CLI）。
"""
import os
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SKILL_DIR / "gatekeeper-cli.sh"))

CTX_REL = "references/subagent-context.json"
SIG_REL = CTX_REL + ".sig"
KEY_META = ('{"context_ed25519": {"created": "2026-01-01T00:00:00Z",'
            ' "expires": "2026-01-02T00:00:00Z", "status": "active", "rotation_days": 1}}')


def _wsl(p: Path) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _sh(cmd: str):
    return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=180)


def _build_sandbox(sb: Path) -> None:
    """WSL 侧建隔离技能根：scripts/ 整目录实拷 + CLI 实拷 + 一对全新 context 密钥。

    刻意**不用** `ln -s` 逐项软链：含 shell 变量 + glob 的载荷在本机 WSL 启动器下实测被吞
    （`for f in "<src>"/*` 里 `$f` 展开为空串 ⟹ `ln` 报 `failed to create symbolic link '<dst>/' -> ''`，
    2026-09-20 踩点）。`cp -r` 无变量、无 glob，且把 `gk_dbg.log` 一并复制成沙箱副本
    ⟹ `_context_resign` 的留痕落在副本上，不污染真日志（该日志正是本次定位 stale 的取证源）。
    """
    sh = (
        'mkdir -p "%(sb)s"'
        ' && cp -r "%(src)s" "%(sb)s/scripts"'
        ' && cp "%(cli)s" "%(sb)s/gatekeeper-cli.sh"'
        ' && mkdir -p "%(sb)s/references" "%(sb)s/.keys"'
        ' && openssl genpkey -algorithm ED25519 -out "%(sb)s/.keys/context_ed25519.pem"'
        ' && openssl pkey -in "%(sb)s/.keys/context_ed25519.pem" -pubout -out "%(sb)s/.keys/context_ed25519.pub"'
        % {"sb": _wsl(sb), "src": _wsl(SCRIPT_DIR), "cli": _wsl(CLI_SRC)}
    )
    r = _sh(sh)
    assert r.returncode == 0, "沙箱搭建失败：%s%s" % (r.stdout, r.stderr)


def _verify(pub: Path, ctx: Path, sig: Path) -> bool:
    r = _sh('openssl pkeyutl -verify -pubin -inkey "%s" -rawin -in "%s" -sigfile "%s"'
            % (_wsl(pub), _wsl(ctx), _wsl(sig)))
    return "Verified" in (r.stdout + r.stderr)


def test_rotate_resigns_context(tmp_path):
    """rotate context 后：.sig 存在、64 字节、只对新公钥有效、mtime 不早于新 pub。"""
    sb = (tmp_path / "sb").resolve()
    sb.mkdir()
    _build_sandbox(sb)
    (sb / CTX_REL).write_text('{"files": [], "r_phase": "ECO-SCAN"}\n', encoding="utf-8")
    (sb / ".keys" / "key-meta.json").write_text(KEY_META, encoding="utf-8")

    r = _sh('cd "%s" && bash "%s/gatekeeper-cli.sh" audit --key rotate context' % (_wsl(sb), _wsl(sb)))
    out = r.stdout + r.stderr
    assert '"ok":true' in out, out

    ctx, sig = sb / CTX_REL, sb / SIG_REL
    assert sig.exists(), (
        "轮换后 .sig 缺失 —— `_sign_raw ... > /dev/null` 是 no-op（stdout 是 base64 JSON，不落盘）：\n" + out)
    assert sig.stat().st_size == 64, "Ed25519 裸签名应为 64 字节，实得 %s" % sig.stat().st_size

    baks = sorted((sb / ".keys").glob("context_ed25519.pub.*.bak"))
    assert baks, "未找到轮换备份 —— rotate 未真正发生，本用例前置不成立"
    assert _verify(sb / ".keys" / "context_ed25519.pub", ctx, sig), "重签后的 .sig 对**新**公钥验签失败"
    assert not _verify(baks[-1], ctx, sig), ".sig 仍是**旧**密钥所签 —— 重签未发生"

    # 对齐 gk_node_guard._context_signature_fresh 的判据（mtime 序），否则注入侧仍判 stale
    assert sig.stat().st_mtime >= (sb / ".keys" / "context_ed25519.pub").stat().st_mtime - 1.0, \
        "sig 早于 pub ⟹ 注入侧仍会判 sig_stale_after_key_rotation"


def test_auto_rotate_does_not_pollute_stdout(tmp_path):
    """只读命令触发自动轮换时，stdout 必须是**纯 JSON**（首字符 `{`）。

    2026-11-02 实测：`_key_rotate_if_expired` 内联的 `audit --key rotate … 2>/dev/null`
    只静默 stderr ⟹ 其 stdout（openssl 的 `Signature Verified Successfully`）混进调用方
    输出，把 `finding status` 的 JSON 契约打断（agent 侧解析失败）。本臂钉住三件事：
      ① stdout 首字符是 `{`（无污染）；② 过期密钥**确实**轮换（前置成立）；
      ③ 轮换留痕到 `gk_dbg.log`（静默不等于无审计）。
    """
    sb = (tmp_path / "sb").resolve()
    sb.mkdir()
    _build_sandbox(sb)
    (sb / ".keys" / "key-meta.json").write_text(KEY_META, encoding="utf-8")
    st = sb / ".gatekeeper.state"
    st.write_text('{"gate_data": {}, "stage": "IDLE"}\n', encoding="utf-8")
    pub = sb / ".keys" / "context_ed25519.pub"
    before = pub.read_bytes()

    r = _sh('cd "%s" && bash "%s/gatekeeper-cli.sh" finding status "%s"'
            % (_wsl(sb), _wsl(sb), _wsl(st)))
    out = r.stdout.strip()
    assert out.startswith("{"), "stdout 被非 JSON 前缀污染：%r" % out[:160]
    assert pub.read_bytes() != before, "前置不成立：过期密钥未触发自动轮换"
    log = sb / "scripts" / "gk_dbg.log"
    assert log.exists(), "沙箱未带 gk_dbg.log（留痕断言前置不成立）"
    assert "[key-rotate] auto rotate context_ed25519 ok" in log.read_text(encoding="utf-8"), \
        "自动轮换未留痕（静默不得等于无审计）"
