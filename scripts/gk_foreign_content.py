#!/usr/bin/env python3
"""gk_foreign_content.py — 跨租户/污染检测的**单一事实源**（P2c，2026-10-31 落刀）。

背景（`docs/plans/2026-09-13-crossreview-optimization-plan.md` §4.1(c) / P2c）：
原实现有 4 份副本 + 第 5 消费点 + 第 6 份同族词表，接口互不同构：

| 位置 | 原契约 | 原缺陷 |
|:--|:--|:--|
| `subagent_runner._check_foreign_content` | `str \\| None` | 依赖 Windows interop 解析本机用户；detached 会话下全源失败 ⇒ 全量 `UNRESOLVED_OWN_USER` |
| `gk_appeal._detect_foreign_content` | `"clean" \\| "foreign_user:x" \\| "leakage_marker:x"` | `USER` 兜底（WSL 恒 `root`）+ **硬编码 `"HP"`** ⇒ 自家路径被判外租户 |
| `gk_escalate_resolve._detect_foreign_content` | 同上 | 同上（第二份） |
| `gk_foreign_scan.py` | file → stdout | 第三份实现，词表与上面不同步 |
| `gk_self_check._parse_subagent_constants` | AST 计数 | 常量搬走即恒 0（fail-open 空转） |
| `gk_moa_aggregate._POISON_PATTERNS` | 词表 | 与上面双份漂移 |

**统一契约（禁 `str|None` 与 `"clean"` 混用）**：`check()` 返回 `None` = 干净；否则返回
具名 reason（`foreign_user:<u>` / `traversal:<seg>` / `leakage_marker:<p>` /
`UNRESOLVED_OWN_USER`）。消费方若需旧哨兵（如 `"clean"`），在**各自 wrapper** 内映射，不再
在本模块产生第二套语义。

**本机用户解析（多源，确定性优先）**：`GK_OWN_USER` → 持久缓存 → Windows interop（powershell /
cmd）→ 路径段推断（`SKILL_DIR` / 仓根 / cwd / `~`；Windows `Users/<n>` 与 POSIX `/home/<n>` 双形态）。
`USER`/`USERNAME` **不参与**（WSL 下恒 `root`）；传参里若是通用名（`root`/`user`/…）也视为「未知」，
交由本模块重解析 —— 这样 CLI 侧传 `"${USER:-HP}"` 时也不会把自家路径判成外租户。
解析成功即写缓存；全源失败返回 `""`，由 `check()` 交调用侧 fail-loud（**禁**静默放行）。

**开关**：
- `GK_OWN_USER=<name>` 显式指定（换机/多用户/开源部署）。
- `GK_NO_OWN_USER_CACHE=1` 忽略/不写缓存。
- `GK_FOREIGN_PATTERNS_RESET=1` 清空部署方历史租户字面量（开源构建建议置 1）。
- `GK_FOREIGN_USER_PATTERNS=a,b` 追加私有标记（逗号分隔）。
- `GK_FOREIGN_GUARD_DISABLE=1` **排障用**：`check()` 直接返回 `None` 并 WARN 到 stderr。
"""
import os
import re
import sys
from pathlib import Path

#: 已知泄漏标记（Trae 跨租户事件实锤；勿删）。含部署方历史租户字面量。
#: 首个 List 字面量由 `gk_self_check._parse_subagent_constants` 以 AST 计数（勿改成表达式）。
LEAKAGE_MARKERS = [
    "<home>", "<home>",
    "xhs-copilot", "xiaohongshu", "小红书", "副驾驶",
    "identity-tracker", "pc-web",
]
if os.environ.get("GK_FOREIGN_PATTERNS_RESET", "0") == "1":
    LEAKAGE_MARKERS.clear()
LEAKAGE_MARKERS.extend(
    _p.strip() for _p in os.environ.get("GK_FOREIGN_USER_PATTERNS", "").split(",") if _p.strip())

#: 投毒词表（跨租户 + 指令注入 + 角色伪装 + 多 Agent 感染）。单一源 = 本模块；
#: `gk_moa_aggregate` 直接 import（原第 6 份副本）。
POISON_PATTERNS = [
    (r"<home>", "cross-tenant: peng user path"),
    (r"<home>", "cross-tenant: v_ user path"),
    (r"xhs-copilot", "cross-tenant: xhs-copilot"),
    (r"xiaohongshu", "cross-tenant: xiaohongshu"),
    (r"小红书", "cross-tenant: 小红书"),
    (r"identity-tracker", "cross-tenant: identity-tracker"),
    (r"pc-web", "cross-tenant: pc-web"),
    (r"忽略(?:上述|上面|以上|之前|先前|所有|全部|这|那|任何|一切|的)*(?:指令|内容|要求|规则|提示|命令)",
     "instruction-injection: 忽略"),
    (r"ignore\s+(?:all\s+)?previous\s+(?:instructions|prompts|rules)",
     "instruction-injection: ignore-previous"),
    (r"不要[理会管执行](?:上面|之前|上述)?(?:的)?(?:指令|内容)", "instruction-injection: 不要理会"),
    (r"system\s*:", "role-spoof: system:"),
    (r"assistant\s*:", "role-spoof: assistant:"),
    (r"你(?:现在|从此)是", "role-spoof: 你现在是"),
    (r"You are now", "role-spoof: you-are-now"),
    (r"<\|(?:im_start|im_end|system|assistant|user|tool|endoftext)\|>", "role-spoof: chatml-tag"),
    (r"</?(?:system|assistant|user|im_start|im_end)\s*>", "role-spoof: xml-role-tag"),
    (r"<<\s*/?\s*SYS\s*>>", "role-spoof: llama-sys-tag"),
    (r"\[/?INST\]", "role-spoof: llama-inst-tag"),
    (r"(?m)^\s*#{2,4}\s*(?:system|assistant|human|user|tool)\b", "role-spoof: markdown-header"),
    (r"(?:^|\n)\s*(?:BEGIN|END)\s+SYSTEM\s+PROMPT", "role-spoof: begin-system-prompt"),
    (r"(?:转发|复制|传播|扩散|传递).{0,8}(?:给|至|到)?\s*(?:其他|其它|下一个|所有|全部)?\s*"
     r"(?:agent|subagent|sub-agent|子代理|智能体)", "infection: propagate"),
    (r"(?:ignore|disregard).{0,24}(?:repeat|forward|propagate|copy|include).{0,24}"
     r"(?:instruction|prompt|message)", "infection: self-replicate"),
]

# 用户根形态（匹配前先 `\` → `/` 归一）。
_WIN_USER_ROOT_RE = re.compile(
    r"(?:[a-zA-Z]:|/mnt/[a-zA-Z]|//\?/[a-zA-Z]:|(?<!:)//[^/\s]+)/Users/([^/\s\"'<>|,;)\]]+)",
    re.IGNORECASE)
_WIN_USER_ROOT_REL_RE = re.compile(
    r"(?<![a-zA-Z0-9])/Users/([^/\s\"'<>|,;)\]]+)", re.IGNORECASE)
_POSIX_HOME_RE = re.compile(
    r"(?<![a-zA-Z0-9])/home/([^/\s\"'<>|,;)\]]+)(?=/|\s|$)")
_TRAVERSAL_RE = re.compile(r"/(?:Users|home)/[^/\s]+/\.\.(?=/|$|\s)", re.IGNORECASE)

_WIN_SYSTEM_NAMES = frozenset({"public", "default", "all users", "defaultuser0"})
_GENERIC_USER_NAMES = frozenset({
    "root", "user", "users", "username", "youruser", "me", "example", "test", "tester",
    "ubuntu", "runner", "vscode", "node", "app", "admin", "administrator",
    "public", "shared", "default", "desktop", "documents",
})

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
CACHE_BASENAME = ".gatekeeper.state.own_user"


def cache_path() -> str:
    return os.path.join(os.environ.get("SKILL_DIR") or _REPO_ROOT, CACHE_BASENAME)


def read_cache() -> str:
    if os.environ.get("GK_NO_OWN_USER_CACHE", "0") == "1":
        return ""
    try:
        with open(cache_path(), encoding="utf-8") as f:
            return (f.readline() or "").strip()
    except OSError:
        return ""


def write_cache(user: str) -> None:
    if os.environ.get("GK_NO_OWN_USER_CACHE", "0") == "1" or not user:
        return
    p = cache_path()
    try:
        with open(p + ".tmp", "w", encoding="utf-8", newline="\n") as f:
            f.write(user + "\n")
        os.replace(p + ".tmp", p)
    except OSError:
        pass


def user_from_path(p: str) -> str:
    """从路径段取用户名（Windows `Users/<n>` / POSIX `/home/<n>` 双形态）；取不到返回 `""`。"""
    n = (p or "").replace("\\", "/")
    for rx in (_WIN_USER_ROOT_RE, _WIN_USER_ROOT_REL_RE, _POSIX_HOME_RE):
        m = rx.search(n)
        if m:
            return m.group(1)
    return ""


def _valid(name: str) -> bool:
    n = (name or "").strip()
    return bool(n) and n.lower() not in _GENERIC_USER_NAMES and n.lower() not in _WIN_SYSTEM_NAMES


def resolve_own_user() -> str:
    """多源解析本机用户名；全源失败返回 `""`（**禁退化**，调用侧 fail-loud）。"""
    cands = [os.environ.get("GK_OWN_USER", ""), read_cache()]
    import subprocess  # 仅 interop 分支用；延迟导入避免无谓开销
    try:
        _ps = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        if os.path.exists(_ps):
            r = subprocess.run([_ps, "-NoProfile", "-Command", "[Environment]::UserName"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                cands.append(r.stdout.strip())
    except Exception:
        pass
    try:
        _cmd = "/mnt/c/Windows/System32/cmd.exe"
        if os.path.exists(_cmd):
            r = subprocess.run([_cmd, "/c", "echo %USERNAME%"],
                               capture_output=True, text=True, timeout=10)
            o = (r.stdout or "").strip()
            if r.returncode == 0 and o and "%" not in o:
                cands.append(o)
    except Exception:
        pass
    for p in (os.environ.get("SKILL_DIR", ""), _REPO_ROOT, os.getcwd(), os.path.expanduser("~")):
        u = user_from_path(p)
        if u:
            cands.append(u)
    for c in cands:
        if _valid(c):
            write_cache(c)
            return c.strip()
    return ""


def check(text: str, own: str | None = None) -> str | None:
    """返回 `None`（干净）或具名 reason。`own` 缺省/为通用名时由本模块重解析。"""
    if not text:
        return None
    if os.environ.get("GK_FOREIGN_GUARD_DISABLE", "0") == "1":
        print("[foreign-guard] DISABLED by GK_FOREIGN_GUARD_DISABLE=1", file=sys.stderr)
        return None
    text_lower = str(text).lower()
    for pattern in LEAKAGE_MARKERS:
        if pattern.lower() in text_lower:
            return f"leakage_marker:{pattern}"
    if own is None:
        own = resolve_own_user()          # 未指定：单源自行解析
    elif not str(own).strip():
        return "UNRESOLVED_OWN_USER"      # **显式空** = 上游已知解析失败 ⟹ fail-loud（禁静默放行）
    elif not _valid(own):
        own = resolve_own_user()          # CLI 传 `root`/通用名：不可信，重解析
    if not own:
        return "UNRESOLVED_OWN_USER"
    own = own.lower()
    norm = str(text).replace("\\", "/")
    mt = _TRAVERSAL_RE.search(norm)
    if mt:
        return f"traversal:{mt.group(0)}"
    for rx in (_WIN_USER_ROOT_RE, _WIN_USER_ROOT_REL_RE):
        for m in rx.finditer(norm):
            u = m.group(1)
            if u.lower() != own and u.lower() not in _WIN_SYSTEM_NAMES:
                return f"foreign_user:{u}"
    for m in _POSIX_HOME_RE.finditer(norm):
        u = m.group(1)
        if u.lower() == own or u.lower() in _GENERIC_USER_NAMES:
            continue
        return f"foreign_user:{u}"
    return None


def check_file(path: str, own: str | None = None) -> str | None:
    """文件版（读失败 ⇒ `None`，保留 `gk_foreign_scan` 的 file→stdout 历史语义）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return check(f.read(), own=own)
    except OSError:
        return None
