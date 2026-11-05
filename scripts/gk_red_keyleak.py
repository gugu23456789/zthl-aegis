#!/usr/bin/env python3
"""gk_red_keyleak.py — 密钥泄露红队向量（确定性、离线、可进 CI；2026-11-05）。

为什么存在
==========
2026-11-05 红队（用户：「尝试把秘钥挖出来找漏洞」）确认了两类真问题：
  · `bash -x` 的 xtrace 会把变量展开（含 API key）打到 stderr；
  · key 曾以 `-H "Authorization: Bearer …"` 形式进入 **argv**（`ps` 可见）；
  · `set-key <key>` 的 key 落在 **shell history**；持久化到 Windows 时又进了 powershell argv。
本套件把这些教训固化成**可复跑的攻击向量**（不靠人记），push/PR + 每周定时跑一次。

向量（HIGH = 代码回归，必须绿；MEDIUM = 环境面，advisory）
=========================================================
  RK-01 argv_header           任何 `-H "Authorization: Bearer …"` ⟹ argv 泄露
  RK-02 auth_config_stdin     凡打 `/chat/completions` / `/user/balance` 的 curl 必须 `--config -`
  RK-03 xtrace_guard          `cmd_balance` 必须关 xtrace；CLI 派发前必须有全局 xtrace 告警
  RK-04 setkey_stdin          `set-key <provider> -` 必须支持 stdin（不进 shell history）
  RK-05 powershell_no_argv    PowerShell 持久化不得把 key 拼进 `-Command` 字面量
  RK-06 no_log_echo_key       不得把 `${API_KEY}` 写进 echo/日志（curl stdin 配置行除外）
  RK-07 keys_excluded         `.keys/` 必须在 gitignore + 导出白名单 + 打包排除面
  RK-08 no_tracked_secrets    已跟踪文件不得含 `sk-*` / 私钥 / `.pem|.key|.env`
  RK-09 key_file_perms        `.keys/*` 组/他人可读 ⟹ 环境告警（WSL drvfs 上 chmod 失效）
  RK-10 bak_age_policy        `.bak` 是否超出**轮换宽限期**（对齐 `audit --key rotate` 的
                              `find -mtime +7` 清理；只看年龄，不数个数 —— 1d 轮换下
                              14 份 `.bak` 是设计内稳态，不是问题）

用法：`python3 scripts/gk_red_keyleak.py [--json] [--advisory]`
退出码：0 = 无 HIGH；1 = 有 HIGH（`--advisory` 时恒 0）。
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "gatekeeper-cli.sh"
HIGH, MEDIUM = "high", "medium"

_AUTH_HEADER = re.compile(r'-H\s+["\']Authorization:\s*Bearer', re.I)
_API_URL = re.compile(r"/(chat/completions|user/balance)")
_XTRACE_WARN = "bash -x 已开启"
_KEY_VARS = re.compile(r"\$\{?(?:API_KEY|api_key|DEEPSEEK_API_KEY|GATEKEEPER_API_KEY)\b")
_CURL_STDIN = 'header = "Authorization'


def _read(p):
    try:
        return Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _tracked():
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                             capture_output=True, text=True, timeout=30)
        if out.returncode == 0:
            return [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    except (OSError, subprocess.SubprocessError):
        pass
    return []


def _logical_lines(text):
    """把 `\\` 续行拼成逻辑行（curl 多行调用才看得全）。"""
    buf, out = "", []
    for raw in text.splitlines():
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        out.append(buf + raw)
        buf = ""
    if buf:
        out.append(buf)
    return out


def check_argv_header(sh_files):
    """RK-01：Authorization 出现在 curl 参数里 ⟹ argv 泄露（ps / 任务管理器可见）。"""
    bad = []
    for p in sh_files:
        for i, ln in enumerate(_read(p).splitlines(), 1):
            if _AUTH_HEADER.search(ln) and _CURL_STDIN not in ln:
                bad.append("%s:%d" % (p, i))
    return ([] if not bad else [{
        "id": "RK-01", "severity": HIGH, "title": "Authorization 进了 argv",
        "detail": "改用 `curl --config -` 从 stdin 传 header；命中：%s" % ", ".join(bad[:5])}]), len(sh_files)


def check_auth_config_stdin():
    """RK-02：所有打模型/余额 API 的 curl 必须走 `--config -`。"""
    bad, seen = [], 0
    for p in [CLI] + sorted((ROOT / "scripts").glob("*.sh")):
        for ln in _logical_lines(_read(p)):
            if "curl" not in ln or not _API_URL.search(ln):
                continue
            seen += 1
            if "--config -" not in ln:
                bad.append("%s: %s" % (p.name, ln.strip()[:90]))
    return ([] if not bad else [{
        "id": "RK-02", "severity": HIGH, "title": "API 请求未走 --config -",
        "detail": "；".join(bad[:3])}]), seen


def check_xtrace():
    """RK-03：balance 关 xtrace + 派发前全局告警（xtrace 会打印变量展开）。"""
    text = _read(CLI)
    out = []
    seg = text[text.find("cmd_balance() {"):text.find("_cmd_balance_body() {")]
    if "set +x" not in seg:
        out.append({"id": "RK-03a", "severity": HIGH,
                    "title": "cmd_balance 未关闭 xtrace", "detail": "key 会随 xtrace 进 stderr"})
    if _XTRACE_WARN not in text:
        out.append({"id": "RK-03b", "severity": HIGH,
                    "title": "缺全局 xtrace 告警", "detail": "调试模式泄密无提示"})
    return out, 2


def check_setkey_stdin():
    """RK-04：`set-key <provider> -` 从 stdin 读（否则 key 落 shell history）。"""
    text = _read(CLI)
    i = text.find("cmd_set_key() {")
    if i < 0:
        return [{"id": "RK-04", "severity": HIGH, "title": "找不到 cmd_set_key", "detail": ""}], 1
    seg = text[i:text.find("\n}\n", i)] if "\n}\n" in text[i:] else text[i:]
    ok = ('"$key" = "-"' in seg) or ("= '-'" in seg) or ('= "-"' in seg)
    return ([] if ok else [{
        "id": "RK-04", "severity": HIGH, "title": "set-key 只能从 argv 收 key",
        "detail": "补 `set-key <provider> -`（stdin）以免 key 进 shell history"}]), 1


def check_powershell_argv():
    """RK-05：PowerShell 持久化不得把 key 作为 `-Command` 字面量（argv 泄露）。"""
    text = _read(CLI)
    pat = re.compile(r"SetEnvironmentVariable\([^)]*\$env:", re.S)
    uses_env = bool(pat.search(text))
    literal = re.search(r"SetEnvironmentVariable\('[^']+',\s*'[^']{8,}'", text)
    out = []
    if literal and not uses_env:
        out.append({"id": "RK-05", "severity": HIGH,
                    "title": "PowerShell 持久化把 key 写进 argv", "detail": literal.group(0)[:80]})
    return out, 1


def check_log_sinks():
    """RK-06：不得把 key 变量写进 echo/日志（curl stdin 配置行是唯一允许的出口）。

    判据只认**输出面**：`echo/printf` 的**参数**里出现 key 变量，或重定向到文件/`tee`。
    `echo "$api_key" | subagent_runner`（stdin 通道）不算 —— 那是输入不是日志。
    """
    bad = []
    key_arg = re.compile(r"(?<!\\)\$\{?(?:API_KEY|api_key|DEEPSEEK_API_KEY|GATEKEEPER_API_KEY)\b")
    for p in [CLI] + sorted((ROOT / "scripts").glob("*.sh")):
        for i, ln in enumerate(_read(p).splitlines(), 1):
            if _CURL_STDIN in ln or ln.lstrip().startswith("#") or "subagent_runner" in ln:
                continue
            m = re.search(r"\b(echo|printf)\b([^|;]*)", ln)
            hit = False
            if m:
                arg = m.group(2)
                for km in key_arg.finditer(arg):
                    # 单引号内不展开（`echo '{"error":"Set $API_KEY"}'` 是提变量名，不是泄值）
                    if arg.count("'", 0, km.start()) % 2 == 0:
                        hit = True
                        break
            if not hit and "tee" in ln and key_arg.search(ln):
                hit = True
            if hit:
                bad.append("%s:%d" % (p.name, i))
    return ([] if not bad else [{
        "id": "RK-06", "severity": HIGH, "title": "key 变量进入输出/日志面",
        "detail": ", ".join(bad[:5])}]), 2


def check_keys_excluded():
    """RK-07：`.keys/` 三处排除面（gitignore / 导出白名单 / 打包排除）。"""
    out = []
    if ".keys" not in _read(ROOT / ".gitignore"):
        out.append({"id": "RK-07a", "severity": HIGH, "title": ".keys 未 gitignore", "detail": ""})
    wl = _read(ROOT / "references" / "oss-export-whitelist.json")
    if ".keys/" not in wl:
        out.append({"id": "RK-07b", "severity": HIGH, "title": "导出白名单缺 .keys/", "detail": ""})
    if '".keys"' not in _read(ROOT / "scripts" / "pack_release.py"):
        out.append({"id": "RK-07c", "severity": HIGH, "title": "打包 EXCLUDE_DIRS 缺 .keys", "detail": ""})
    return out, 3


def check_tracked_secrets(tracked):
    """RK-08：已跟踪文件不得含密钥形态（单源 = oss_scrub.SECRET_PATTERNS）。"""
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        import oss_scrub  # noqa: WPS433
        patterns = oss_scrub.SECRET_PATTERNS
    except Exception:  # noqa: BLE001 — 导出树/白名单缺失 ⟹ 用最小集，不静默跳过
        patterns = (("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
                    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")))
    bad = []
    for rel in tracked:
        if Path(rel).suffix.lower() in {".pem", ".key", ".p12", ".env"}:
            bad.append("%s（敏感扩展名）" % rel)
            continue
        p = ROOT / rel
        try:
            if p.stat().st_size > 512 * 1024:
                continue
        except OSError:
            continue
        text = _read(p)
        for name, rx in patterns:
            if rx.search(text):
                bad.append("%s（%s）" % (rel, name))
                break
    return ([] if not bad else [{
        "id": "RK-08", "severity": HIGH, "title": "已跟踪文件含密钥形态",
        "detail": "; ".join(bad[:5])}]), len(tracked)


_BROAD_SIDS = {
    "S-1-1-0",        # Everyone
    "S-1-5-11",       # Authenticated Users
    "S-1-5-32-545",   # BUILTIN\Users
    "S-1-5-32-546",   # BUILTIN\Guests
    "S-1-5-7",        # ANONYMOUS LOGON
}


def _win_path(p) -> str:
    """`/mnt/c/...` → `C:\\...`（Windows 工具不认 WSL 形态；已是 Windows 形态则原样）。"""
    s = str(p)
    m = re.match(r"^/mnt/([A-Za-z])/(.*)$", s)
    if m:
        return "%s:\\%s" % (m.group(1).upper(), m.group(2).replace("/", "\\"))
    return s


def _is_drvfs(p) -> bool:
    return bool(re.match(r"^/mnt/[A-Za-z]/", str(p)) or re.match(r"^[A-Za-z]:\\", str(p)))


def _acl_broad_grants(kd):
    """Windows ACL 判定（**权威面**）：返回被宽泛主体 Allow 的条目；无法判定 → None。

    为什么不能只看 POSIX mode：`/mnt/c`（drvfs）未开 `metadata` 挂载选项时，`ls -l` 恒
    显示 0777 —— 那只是**合成值**，真实判据是 NTFS ACL。按 SID 判（locale 无关）。
    """
    ps = ""
    for cand in ("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                 "powershell.exe"):
        if os.path.isfile(cand) or shutil.which(cand):
            ps = cand
            break
    if not ps:
        return None
    cmd = ("(Get-Acl '%s').Access | ForEach-Object { "
           "$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value "
           "+ '|' + $_.AccessControlType }" % _win_path(kd))
    try:
        # WSL 下 powershell 输出走 GBK/本地代码页 ⟹ 必须 errors=replace（SID 是 ASCII，不受影响）
        r = subprocess.run([ps, "-NoProfile", "-Command", cmd],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    bad = [ln.strip() for ln in r.stdout.splitlines()
           if "|Allow" in ln and ln.split("|")[0].strip() in _BROAD_SIDS]
    return bad


def check_env_perms():
    """RK-09/10：本地 `.keys/` 权限与备份副本（环境面，advisory）。

    ⚠ 判定口径（2026-11-05 实测修正）：`/mnt/c` 上 `mode` 恒 0777（drvfs 合成值，chmod
    不生效），**不能**拿它判「组/他人可读」。Windows 侧走 ACL（SID 判，locale 无关）；
    非 Windows 才看 POSIX mode。
    """
    kd = ROOT / ".keys"
    out, n = [], 0
    if not kd.is_dir():
        return out, 0
    for _p in sorted(kd.iterdir()):
        n += 1
    broad = _acl_broad_grants(kd)
    if broad:
        out.append({"id": "RK-09", "severity": MEDIUM,
                    "title": ".keys ACL 含宽泛主体（Anyone/Users 可访问）",
                    "detail": ", ".join(broad[:5])})
    elif broad is None and not _is_drvfs(kd):
        # 只有**原生 POSIX** 面才用 mode 判；drvfs 上 mode 是合成值 ⟹ 判不了就说不准（不冒充）
        for p in sorted(kd.iterdir()):
            try:
                mode = p.stat().st_mode
            except OSError:
                continue
            if mode & 0o077:
                out.append({"id": "RK-09", "severity": MEDIUM,
                            "title": ".keys/%s 组/他人可访问（mode=%o）" % (p.name, mode & 0o777),
                            "detail": "POSIX 面上 0600 未生效"})
                break
    baks = list(kd.glob("*.bak"))
    # 2026-11-05（对齐轮换机制）：`.bak` 由 `audit --key rotate` 生成，清理策略是
    #   `find .keys -name '*.bak' -mtime +7 -exec rm`（protected region 内，勿重复实现）。
    #   context key 1d 轮换 ⟹ 稳态 ≈ 14 份（2 文件 × 7 天）；**数量不是判据**，年龄才是。
    try:
        grace = float(os.environ.get("GK_KEY_BAK_GRACE_DAYS", "7"))
    except ValueError:
        grace = 7.0
    now = time.time()
    stale = []
    for p in baks:
        try:
            if (now - p.stat().st_mtime) / 86400.0 > grace:
                stale.append(p.name)
        except OSError:
            continue
    if stale:
        out.append({"id": "RK-10", "severity": MEDIUM,
                    "title": ".bak 超出 %g 天宽限期（轮换清理未生效）" % grace,
                    "detail": "%d 份：%s" % (len(stale), ", ".join(sorted(stale)[:5]))})
    return out, n


def run():
    tracked = _tracked()
    sh_files = [p for p in tracked if p.endswith(".sh")] or \
               [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.sh")]
    checks = [
        ("RK-01", lambda: check_argv_header(sh_files)),
        ("RK-02", check_auth_config_stdin),
        ("RK-03", check_xtrace),
        ("RK-04", check_setkey_stdin),
        ("RK-05", check_powershell_argv),
        ("RK-06", check_log_sinks),
        ("RK-07", check_keys_excluded),
        ("RK-08", lambda: check_tracked_secrets(tracked)),
        ("RK-09/10", check_env_perms),
    ]
    findings, ran = [], 0
    for _name, fn in checks:
        got, n = fn()
        findings += got
        ran += n
    high = [f for f in findings if f["severity"] == HIGH]
    return {"ok": not high, "vectors": len(checks), "observations": ran,
            "high": len(high), "findings": findings}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="gk_red_keyleak.py")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--advisory", action="store_true", help="有 HIGH 也退出 0（只报告）")
    a = ap.parse_args(argv)
    r = run()
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("RED-KEYLEAK %s — vectors=%d high=%d" % (
            "OK" if r["ok"] else "FAIL", r["vectors"], r["high"]))
        for f in r["findings"]:
            print("[%s] %s %s — %s" % (f["severity"], f["id"], f["title"], f["detail"]))
    return 0 if (r["ok"] or a.advisory) else 1


if __name__ == "__main__":
    sys.exit(main())
