#!/usr/bin/env python3
"""gk_threat_patterns.py — 威胁模式**单一来源**（2026-11-04）。

为什么单独立模块：同族正则此前只在 `cron_jobs.py` 里有一份（prompt 注入扫描），
编辑载荷要用的高置信子集如果另抄一遍，就会出现**两份会各自漂移的模式表**。
本模块把两种口径放在同一处，并明确它们**不是同一套判据**：

  PROMPT_*（宽口径）  —— 扫描对象是「提交给 cron 的任务 prompt」。误伤代价 = 一条任务被拒，
                        可以宽：`eval(` / `sudo ` / `chmod 0700` 全算可疑。
  PAYLOAD_*（高置信） —— 扫描对象是「agent 要写进项目的代码/脚本」。误伤代价 = 正常开发被拦，
                        必须零误伤：只认**执行形**（设备文件回连 / 管道进解释器 / 解码即执行 /
                        凭据与外网同行 / 持久化写点）。

纪律：两层的正则文本**只在本文件出现一次**；`cron_jobs` 与 `pre_tool_hook` 都从这里取，
不得在各自文件里再写一份。宽口径**不得**下沉到载荷面（否则 `chmod 0600` 这类正常代码全被拦）。
"""
import re

# ── primitive：同族概念的唯一文本（供两层按各自口径引用）──
DEV_TCP_RE = r"/dev/(?:tcp|udp)/[A-Za-z0-9.\-]+/\d{1,5}"
PIPE_TO_SHELL_RE = r"\b(?:curl|wget)\b[^\n|;]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k|d)?sh\b"
B64_TO_SHELL_RE = r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,80}\|\s*(?:sudo\s+)?(?:ba|z|k|d)?sh\b"

# ── 宽口径：cron 任务 prompt（原样迁移自 cron_jobs.py，**逐字不变**）──
PROMPT_THREAT_PATTERNS = [
    re.compile(r"(?i)(rm\s+-rf|shred|mkfs|dd\s+if=)"),
    re.compile(r"(?i)(curl|wget)\s.*\|\s*(bash|sh|python)"),
    re.compile(r"(?i)(eval|exec)\s*\("),
    re.compile(r"(?i)import\s+(os|subprocess|sys)\s*;\s*(os|subprocess)\."),
    re.compile(r"(?i)__import__\s*\("),
    re.compile(r"(?i)(chmod|chown)\s+[0-7]{3,4}"),
    re.compile(r"(?i)(sudo|su)\s+"),
    re.compile(r"(?i)(base64|xxd)\s+-d"),
]
PROMPT_EXFIL_PATTERNS = [
    re.compile(r"(?i)(curl|wget|nc|ncat)\s+.*https?://"),
    re.compile(r"(?i)>\s*/dev/tcp/"),
]
INVISIBLE_UNICODE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")

# ── 高置信口径：编辑载荷（Gate R0.19）。每条 = (人类可读标签, 正则) ──
PAYLOAD_MALWARE_PATTERNS = (
    ("反弹 shell（/dev/tcp 回连）", DEV_TCP_RE),
    ("反弹 shell（nc -e / socat exec）",
     r"\b(?:nc|ncat|netcat)\b[^\n]{0,40}?\s-e\s+[^\n]{0,40}|\bsocat\b[^\n]{0,80}\bexec:"),
    ("下载即执行（curl/wget 管道进 shell）", PIPE_TO_SHELL_RE),
    ("下载即执行（PowerShell iwr/curl 管道进 iex）",
     r"\b(?:iwr|Invoke-WebRequest|curl|wget)\b[^\n|;]{0,200}\|\s*(?:iex|Invoke-Expression)\b"),
    ("base64 解码即执行", B64_TO_SHELL_RE),
    ("动态 exec 载荷", r"\bexec\s*\(\s*(?:base64|bytes\.fromhex|codecs\.decode|__import__)"),
    ("凭据外送", r"(?:\.ssh[/\\]id_|\.aws[/\\]credentials|\.npmrc|\.git-credentials)"
                r"[^\n]{0,200}(?:curl|wget|nc\b|https?://)"),
    ("持久化（管道进 crontab / rc 追加带载荷 / schtasks / Run 注册表）",
     r"\|\s*crontab\s+-|\bschtasks\s+/create\b|reg(?:\.exe)?\s+add\b[^\n]{0,120}\\Run\b"
     # rc 追加：**单看 `>> ~/.bashrc` 是良性的**（安装脚本天天这么写），必须同行同时出现
     # 载荷特征（下载 / 外网 / 临时目录 / 解码 / netcat）才算持久化投毒。
     r"|(?=[^\n]*\.(?:bashrc|zshrc|bash_profile|profile)\b)"
     r"(?=[^\n]*(?:curl|wget|https?://|/tmp/|base64\s|nc\s))[^\n]*"),
    ("fork bomb", r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
)
