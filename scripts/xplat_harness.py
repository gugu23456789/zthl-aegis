#!/usr/bin/env python3
r"""xplat_harness.py — 跨平台 subprocess 安全网（MSYS/Windows/WSL 四坑收敛，2026-11-01）。

【为什么存在】写**行为级**测试时连踩四个**叠加**坑（不是独立坑——每修一个就撞下一个）：
  ① 多行字符串作**单个 argv 元素**传 `bash -c` ⟹ MSYS 在 argv 层做换行转换，
     脚本**注释里**的反引号内容被 shell 当命令执行（rc≠0，且报错内容与脚本意图无关 ⟹ 极难定位）；
  ② 改 tempfile 落盘 + `bash <file>` ⟹ `tempfile` 给的是 **Windows 反斜杠路径**
     `<home>` ⟹ MSYS bash 不认该形态（rc=127）；
  ③ 改 `bash -s` + **text-mode** stdin ⟹ Python 在 Windows 下把管道字节里的 `\n`
     翻译成 `\r\n` ⟹ bash 逐行收到 `a=1\r` ⟹ 赋值带隐形 \r 或 `$'{\r'` 语法错；
  ④ 修③后仍炸：`bash -s` 读 stdin 时**末行无换行符则整行不执行** ⟹ 空输出且 **rc=0**
     （`printf %s "$V"` 无尾 \n ⟹ 极隐蔽的静默 no-op）。

【正解】本模块唯一出口 `run_bash()` = `bash -s` + **bytes 模式** stdin + **强制补尾换行**：
  · 脚本不经 argv       ⟹ 坑①免疫；
  · 脚本不经临时文件路径 ⟹ 坑②免疫；
  · stdin 为 bytes 直通、无 CRLF 翻译 ⟹ 坑③免疫；
  · 自动补 `\n` 结尾    ⟹ 坑④免疫。

【与 hook 换行防护的层次关系】`pre_tool_hook._quote_regions` 把**引号内**的
  `;`/`&&`/`||`/`|`/换行当非分隔符 —— 那防的是「命令被**错误分段解析**」（放行**前**的静态层）。
  本模块防的是「放行**后**」的 argv/管道**字节层**破坏。两层正交，互不覆盖。

【路径形态】`posix_path()` 按 bash flavor 给正确形态：
  MSYS(Git Bash) = `/c/Users/...`；WSL = `<home>`。
  ⚠ 两者不可混用 —— 仓内旧 helper `_wsl()` 只服务 WSL bash（`wsl.exe`），
    而 pytest(Windows python) 直接 spawn 的 `bash` 是 **MSYS**，形态必须是 `/c/...`。

测试: scripts/test_xplat_harness.py。
"""
from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from pathlib import Path

__all__ = [
    "run_bash",
    "bash_flavor",
    "posix_path",
    "win_path",
    "find_manual_json_splices",
    "find_sq_path_injections",
    "find_unnormalized_state_sources",
    "BASH",
]

#: 入口 bash。**必须钉到 MSYS bash**，不能裸写 `"bash"`。
#:
#: 2026-11-02 实测（本机）：Windows python `subprocess.run(["bash", …])` 命中的是
#:   `C:\Windows\System32\bash.exe`（**WSL 启动器**），`uname -r` = `…-microsoft-standard-WSL2`、
#:   `MSYSTEM` 为空 ⟹ 于是 ① `posix_path` 给出 `/mnt/c/…`（MSYS 下不存在）；
#:   ② **`env=` 传参对 WSL bash 完全无效**（Windows 环境变量不跨 interop，除非登记 `WSLENV`）
#:   ⟹ `a4` env 透传臂、`b2b` 行为臂双双假红，且报错方向完全指错（看起来像"函数没定义"）。
#:   根因：`shutil.which("bash")` 与 CreateProcess 的查找顺序不一致 —— which 给 PortableGit，
#:   实际起的是 System32 那个。**这正是"混合环境"的又一形态**：同一个名字两个解释器。
#:   修：按**已知安装位置**发现 MSYS bash（`GK_BASH` 显式胜），全路径钉死；
#:   真找不到才回落 `"bash"`（此时 `bash_flavor` 会如实报 `wsl`/`unknown`，测试自会红）。
def _find_msys_bash() -> str:
    import os
    env = (os.environ.get("GK_BASH") or "").strip()
    if env and Path(env).is_file():
        return env
    cands = [
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
    ]
    # WorkBuddy 自带 PortableGit（不写死用户名，走 LOCALAPPDATA）
    _la = os.environ.get("LOCALAPPDATA") or ""
    if _la:
        cands.append(_la + r"\Programs\WorkBuddy\resources\vendor\PortableGit\usr\bin\bash.exe")
    for c in cands:
        if Path(c).is_file():
            return c
    return "bash"


BASH = _find_msys_bash()


# --------------------------------------------------------------------------- #
# 入口：唯一安全的 bash 驱动（bytes stdin，不经 argv / 不经临时文件路径）
# --------------------------------------------------------------------------- #
def run_bash(script: str, *, cwd: str | Path | None = None,
             env: dict | None = None, timeout: int = 120,
             bash: str = BASH) -> subprocess.CompletedProcess:
    """以 **bytes stdin** 驱动 `bash -s`，免疫上述三坑。

    与 `subprocess.run([bash, "-c", script])` 的差异就是本模块的全部价值：
    脚本走 stdin 而非 argv（坑①②），且 input 是 `bytes` 而非 `str`（坑③）。

    Args:
        script: bash 脚本正文。可含多行、注释、反引号 —— 均安全。
        cwd: 工作目录。传 Windows 形态（`C:/...`）或 POSIX 形态均可（由 python 侧解释，
             不经 MSYS argv）。
        env: 附加环境变量（覆盖式合并到继承环境之上）。
        timeout: 秒。
        bash: bash 可执行文件（默认 `bash`；可传绝对路径）。
    Returns:
        `subprocess.CompletedProcess`（`stdout`/`stderr` 已 decode 为 str，errors=replace）。
    """
    import os
    env_full = dict(os.environ) if env is None else dict(os.environ)
    if env is not None:
        env_full.update({k: str(v) for k, v in env.items()})
    # 2026-11-08 修（Windows 实测 rc=127）：只继承 Windows 形态 PATH 时，MSYS bash 找不到
    # 同目录的 awk/sed（`awk: command not found`）。把 bash 自身目录前置进 PATH；
    # POSIX 侧 bash 就在 /usr/bin，前置为幂等无副作用。
    _bash_dir = os.path.dirname(os.path.abspath(bash))
    if os.name == "nt" and _bash_dir:
        _cur = env_full.get("PATH", "")
        if _bash_dir.lower() not in _cur.lower():
            env_full["PATH"] = _bash_dir + os.pathsep + _cur
    # 坑④：`bash -s` 读 stdin 时**末行无换行符则整行不执行**（实测 2026-11-01：
    # `printf %s "$V"` 无尾 \n ⟹ 空输出且 rc=0，极隐蔽）。一律补尾换行。
    if not script.endswith("\n"):
        script += "\n"
    # 关键：input 必须是 bytes —— Windows text-mode pipe 会把 \n 翻译成 \r\n（坑③）
    r = subprocess.run(
        [bash, "-s"],
        input=script.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd) if cwd is not None else None,
        env=env_full,
        timeout=timeout,
    )
    return subprocess.CompletedProcess(
        r.args, r.returncode,
        r.stdout.decode("utf-8", errors="replace"),
        r.stderr.decode("utf-8", errors="replace"),
    )


# --------------------------------------------------------------------------- #
# 路径形态：按 bash flavor 给正确 posix 形态
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def bash_flavor(bash: str = BASH) -> str:
    """探测 bash flavor：`msys` | `wsl` | `unknown`。

    判据顺序（2026-11-02 修：原只看 `uname -r` 含 `microsoft`，被 System32 的 WSL 启动器
    骗过去 ⟹ 把**本机 MSYS** 判成 `wsl` ⟹ `posix_path` 全给 `/mnt/…` ⟹ 测试假红）：
      ① `MSYSTEM` 非空 ⟹ **msys**（Git for Windows 专属变量，WSL 不设）；
      ② `uname -s` 含 `MINGW`/`MSYS` ⟹ msys；
      ③ `uname -r` 含 `microsoft` ⟹ wsl；
      ④ 其它 ⟹ unknown（调用方据此 fail-loud，不猜）。
    缓存结果（一次会话只探一次）。
    """
    try:
        r = subprocess.run([bash, "-c", 'printf "%s|" "${MSYSTEM:-}"; uname -s; uname -r'],
                           capture_output=True, timeout=30)
        out = (r.stdout or b"").decode("utf-8", "replace")
    except Exception:
        return "unknown"
    msystem, _, rest = out.partition("|")
    if msystem.strip():
        return "msys"
    low = rest.lower()
    if "mingw" in low or "msys" in low:
        return "msys"
    if "microsoft" in low or "wsl" in low:
        return "wsl"
    return "unknown"


def posix_path(p: str | Path, flavor: str | None = None) -> str:
    r"""Windows 绝对路径 → 目标 bash 的 posix 形态。

    `<home>` 或 `<home>` →
      · flavor="msys" → `/c/Users/x`
      · flavor="wsl"  → `<home>`
    非 Windows 形态（已是 posix / 纯相对）原样返回。flavor 缺省 = 自动探测。
    """
    s = str(p).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):(/.*)$", s)
    if not m:
        return s                                   # 已是 posix / 相对 / 其它
    fl = flavor or bash_flavor()
    drive, rest = m.group(1).lower(), m.group(2)
    if fl == "wsl":
        return f"/mnt/{drive}{rest}"
    return f"/{drive}{rest}"                        # msys / unknown 都按 msys（本机常态）


def win_path(p: str | Path) -> str:
    r"""任意 posix/Windows 形态 → `C:/...` Windows 形态（正斜杠，python/JSON 安全）。

    `/mnt/c/x` → `C:/x`；`/c/x` → `C:/x`；`C:\x` → `C:/x`。其余原样。
    """
    s = str(p).replace("\\", "/")
    m = re.match(r"^(?:/mnt/|/)([A-Za-z])/(.*)$", s)
    if m:
        return f"{m.group(1).upper()}:{'/' + m.group(2)}"
    m2 = re.match(r"^([A-Za-z]):(/.*)$", s)
    if m2:
        return f"{m2.group(1).upper()}:{m2.group(2)}"
    return s


# --------------------------------------------------------------------------- #
# 源码级守卫：扫描 gatekeeper-cli.sh 的两类跨平台炸弹
# --------------------------------------------------------------------------- #
def _cli_lines(cli_path: str | Path) -> list[str]:
    return Path(cli_path).read_text(encoding="utf-8", errors="replace").splitlines()


def _is_comment(line: str) -> bool:
    r"""整行注释判定（`#` 起始，允许前导空白）—— 注释里的示例**不是**病灶。

    2026-11-01 补：守卫① 原先不跳注释 ⟹ 修复病灶时**新写的注释**（引用原写法说明
    「为什么错」）自己被守卫命中 = 修复动作反而让守卫更红（假阳）。守卫② 早已跳注释，
    此处对齐两守卫口径。
    ⚠ 只判**行首** `#`：bash 行内 `#` 可能是字符串内容（如 `"#id"`），不当注释。
    """
    return line.lstrip().startswith("#")


#: 路径类变量（嵌进 JSON/python 源码即有注入/转义风险）
_PATH_VARS = (
    r"\$\{?(?:STATE_FILE|SKILL_DIR|_DEFAULT_STATE_FILE|PLAN_FILE|GK_PLAN_FILE"
    r"|_dom_state|_PLAN_POINTER(?:_OWN)?|MAIN_REPO_WIN)\}?"
)

#: 手工拼 JSON：`echo " ... {" ... "` —— 双引号区内直接写 JSON 字面量。
#: ⚠ 真实形态是 bash 转义引号 `echo "{\"state_file\":...` ⟹ `{` 前**有反斜杠**，
#:   故必须允许 `\\?`（否则恒不命中 = 假绿，2026-11-01 c1 臂实测抓到）。
_MANUAL_JSON = re.compile(r'echo\s+"\\?\{')


def find_manual_json_splices(cli_path: str | Path) -> list[tuple[int, str]]:
    r"""找出**手工拼 JSON 且嵌路径变量**的行 —— Windows 反斜杠 ⟹ `\U` 非法转义。

    判据（三条件同时成立才算）：
      ① 行内有 `echo "` 且该双引号区含 JSON 字面量起始 `{"`；
      ② 同一双引号区内嵌了路径类变量；
      ③ **未**经任何转义/序列化出口（`gk_json.py` / `_gk_json_str` / `printf '%s'` 包裹）。
    返回 `[(行号, 原文), ...]`。正确写法 = 走 `gk_json.py build`（JSON 构造单一事实源）。
    """
    hits = []
    for i, line in enumerate(_cli_lines(cli_path), 1):
        if _is_comment(line):
            continue
        if not _MANUAL_JSON.search(line):
            continue
        if not re.search(_PATH_VARS, line):
            continue
        if re.search(r"gk_json\.py|_gk_json_str", line):
            continue
        hits.append((i, line.rstrip()))
    return hits


_SQ_INJECT = re.compile(r"'(?:\$STATE_FILE|\$SKILL_DIR|\$\{(?:STATE_FILE|SKILL_DIR)\})'")


def find_sq_path_injections(cli_path: str | Path) -> list[tuple[int, str]]:
    r"""找出**内联 python 单引号路径注入**的行 —— `open('$STATE_FILE')` ⟹ `\U` SyntaxError。

    真实形态是**多行** `python3 -c "..."` 载荷（`$STATE_FILE` 常在独立行上，
    如 `_lk=state_lock('$STATE_FILE')`）⟹ 判据**不能**要求同行有 `python3 -c`
    （否则恒不命中 = 假绿）。改判：非注释行内出现**单引号包住的路径变量**
    ⟹ bash 在双引号区展开 ⟹ python 源码变成 `open('<home>')`
    ⟹ `\U` 触发 unicodeescape SyntaxError（Windows 反斜杠路径专属）。

    正确写法 = **env 传参**（仓内先例：`_budget_override_record` 的
    「reason 经 env 传入（而非拼进 python 源码）⟹ 规避引号/换行注入」）。
    返回 `[(行号, 原文), ...]`。
    """
    hits = []
    for i, line in enumerate(_cli_lines(cli_path), 1):
        if _is_comment(line):                 # 注释无害（注释里的示例不算注入）
            continue
        if _SQ_INJECT.search(line):
            hits.append((i, line.rstrip()))
    return hits


# 内部已知 POSIX 来源（值是本地拼接出来的，不含 Windows 反斜杠）—— 不算"外部来源"
_INTERNAL_SF_SRC = ("_DEFAULT_STATE_FILE", "STATE_FILE", "state_override")
# ⚠ 只认**赋值语句**（命令位）—— 不认 `STATE_FILE="$STATE_FILE" python3 ...` 这类
#   「env 前缀调用」（仓内有 40+ 处，它们只是把当前值透传给子进程，不是重新赋值）。
#   判据：`STATE_FILE=` 前面必须是行首 / `;` `&` `|` / `then` `else` `do`。
_SF_FOREIGN = re.compile(r'(?:^|[;&|]|\bthen\b|\belse\b|\bdo\b)[ \t]*STATE_FILE="\$([A-Za-z_]\w*)"')


def find_unnormalized_state_sources(cli_path: str | Path) -> list[tuple[int, str]]:
    r"""找出 `STATE_FILE` 的**外部来源赋值点**未经 `_gk_fwd` 归一的那些行。

    【为什么判据从"禁内联"改成"断言归一"】（2026-11-02，owner 质询后修正）
      原守卫口径 = 「出现 `'$STATE_FILE'` 即红」，隐含要求把 32 处内联 python 全改成
      env 传参。但**真因不是"用了内联"**，而是「同一个变量存在两种路径形态」——
      路由中枢（`resolve-state`）回来的是 `<home>`，而本地拼接出来的是 `/c/Users/...`；
      只有前者会让 python 源码出现 `\U`。
      逐个改 32 处（多数在无测试覆盖的审计/收口路径）风险远大于收益，且**没修到真因**。
      正解 = 在**外部来源进入变量的那两个边界**归一（单一事实源 `_gk_fwd`）⟹
      变量恒为正斜杠形态 ⟹ 32 处内联拼接**同时**变安全（Windows API / bash / python 都收 `/`）。
      故新判据 = **外部来源赋值点必须经 `_gk_fwd`**；`find_sq_path_injections` 保留作
      "还有哪些内联点"的清单（不再作为闸门，避免用放宽判据来换绿）。
    """
    hits = []
    for i, line in enumerate(_cli_lines(cli_path), 1):
        if _is_comment(line):
            continue
        m = _SF_FOREIGN.search(line)
        if not m:
            continue
        if "_gk_fwd" in line:
            continue
        if m.group(1) in _INTERNAL_SF_SRC:
            continue
        hits.append((i, line.rstrip()))
    return hits
