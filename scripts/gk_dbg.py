#!/usr/bin/env python3
"""gk_dbg.py — 诊断日志路径**单一事实源**（ECC-67C0B937A54B，2026-11-12）。

病象：`scripts/gk_dbg.log` 是**单文件、跨会话共用**——写点分布在 CLI 起步变量
（`GK_DBG_LOG`，225 处 `>> "$GK_DBG_LOG"`）+ 4 个 loader + `gk_monitor_payload`，
并发会话 / 子 agent 的行交错落同一文件 ⟹ 出现异常时无法判定「哪一行属于哪次会话」，
排障只能靠猜（本仓 2026-09/10 多次事故的定位成本即为此）。

修法：路径按**会话切片** `gk_dbg.<sid>.log`，sid 取平台既有单一变量 `GK_SESSION_ID`
（CLI 启动块解析身份后 export；hook 与 CLI 同源）。无 sid（owner 手工 / 身份未解析）
⟹ 回落 `gk_dbg.log`，单会话行为逐字不变。

约定（全仓唯一实现，禁第二处手写路径）：
  ① 优先级：env `GK_DBG_LOG`（CLI 已解析后显式给出 / 测试注入）→ `gk_dbg.<sid>.log` → `gk_dbg.log`
  ② sid 只保留 `[A-Za-z0-9_-]`（与 CLI 的身份字符门同口径），其余字符 ⟹ 视为无 sid（防路径穿越）
  ③ 追加写走**单次 `os.write`（O_APPEND）**：单行 < PIPE_BUF ⟹ 并发进程不互相截断
  ④ 诊断面**永不**因写失败打断主流程（返回 False，不抛）
"""
import os
from pathlib import Path

_DEFAULT_BASE = Path(__file__).resolve().parent


def sanitize_sid(sid) -> str:
    """只留 `[A-Za-z0-9_-]`；含其它字符 ⟹ `""`（与 CLI 身份门 `*[!0-9A-Za-z_-]*` 同口径）。"""
    s = str(sid or "").strip()
    if not s:
        return ""
    for ch in s:
        if not (ch.isalnum() or ch in "_-"):
            return ""
    return s


def log_path(base=None) -> Path:
    """本进程应写的诊断日志绝对路径（切片优先，见模块 docstring）。"""
    env = str(os.environ.get("GK_DBG_LOG") or "").strip()
    if env:
        return Path(env)
    b = Path(base) if base else _DEFAULT_BASE
    sid = sanitize_sid(os.environ.get("GK_SESSION_ID", ""))
    return b / (("gk_dbg.%s.log" % sid) if sid else "gk_dbg.log")


def write(msg, base=None) -> bool:
    """追加一行（自动补 `\\n`）。成功 True / 任何 OS 错误 False（诊断面不抛）。"""
    try:
        line = (str(msg).rstrip("\n") + "\n").encode("utf-8", "replace")
        fd = os.open(str(log_path(base)), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
        return True
    except OSError:
        return False
