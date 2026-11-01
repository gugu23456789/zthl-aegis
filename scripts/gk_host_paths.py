"""跨宿主路径形态归一 —— **唯一归一入口**（禁各处再写第二份判断）。

生产宿主 = Windows py311（`scripts/suagent_py311.sh`），而 `gatekeeper-cli.sh` / `rg` 等权威实现
都在 **WSL 侧**。python 侧把 Windows 形态路径（`C:\\...`）直接交给 bash 必然失败（反斜杠被 WSL
启动器吞掉 → 脚本 / `cd` 找不到）；反过来把硬编码 WSL 根（`/mnt/c/...`）与 Windows `normpath`
结果做 `startswith` 也恒 False。

**实装史（教训）**：F-REV-26（2026-09-11）首次在 `subagent_runner` 落这三器，并声明「**唯一归一
入口**」；但 `gk_agent_edit._cli_gate_ok` 仍**自建**了一份 `subprocess.run(["bash", <CLI>, …])`
⟹ 形态转换缺席。后果（`ECC-6C0742C3BC90` 复现实证，Windows py311 宿主）：
`bash C:\\…\\gatekeeper-cli.sh` → `/bin/bash: C:UsersHP…gatekeeper-cli.sh: No such file or directory`
`rc=127` ⟹ **coder 唯一落刀闸（闸① `guard-edit`）恒拒**，且真因只表现为「文件不存在」⟹ 极易被
误读成 worktree 路径问题（流程摩擦 → 诱导放宽闸①）。
2026-09-26 上移为**独立模块**，供 `subagent_runner`（工具层）与 `gk_agent_edit`（落刀闸）**共用**。
刻意**零第三方依赖** —— `gk_agent_edit` 处不得引入 `agents` SDK 依赖。
"""
import os
import re

WIN_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")
MNT_ABS_RE = re.compile(r"^/mnt/([a-zA-Z])/(.*)$", re.S)


def user_home() -> str:
    """用户目录（**不写死用户名**）：env `GK_USER_HOME` > 技能目录上溯 `.trae` 的父目录 > `~`。

     技能目录形如 `<home>/.trae/skills/<skill>` 或 `<home>/.trae/worktrees/<repo>/<branch>`
     ⟹ 上溯到名为 `.trae` 的祖先，其父目录即用户目录。本机默认根（`<home>/Downloads/...`、
     `<home>/zthl-*`）一律由此派生 —— 换用户/换机器自洽（OSS 可移植面），且仍是**单一事实源**。
    """
    env = (os.environ.get("GK_USER_HOME") or "").strip()
    if env:
        return env
    roots = []
    sd = (os.environ.get("SKILL_DIR") or "").strip()
    if sd:
        roots.append(sd)
    roots.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for root in roots:
        p = os.path.abspath(root)
        while True:
            parent = os.path.dirname(p)
            if parent == p:
                break
            if os.path.basename(p) == ".trae":
                return parent
            p = parent
    return os.path.expanduser("~")



def win_abs_to_wsl(p: str) -> str:
    """Windows 绝对路径 → WSL `/mnt` 形态（`C:\\x` / `C:/x` → `/mnt/c/x`）；其余原样返回。"""
    p2 = str(p).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", p2, re.S)
    return "/mnt/%s/%s" % (m.group(1).lower(), m.group(2)) if m else p2


def wsl_to_win(p: str) -> str:
    """WSL `/mnt/<d>/x` → Windows `C:/x`（其余原样）—— `win_abs_to_wsl` 的**反向**。

    用途：值将被 **Windows 侧进程**（如 node.exe / gitnexus）消费，而调用方跑在 WSL python 上。
    """
    m = MNT_ABS_RE.match(str(p).replace("\\", "/"))
    return "%s:/%s" % (m.group(1).upper(), m.group(2)) if m else str(p)


def native_root(root: str) -> str:
    """把「可能为 WSL 形态」的根归一到**当前宿主**形态（Windows：`/mnt/c/x` → `C:/x`；Linux 原样）。

    用于 `full.startswith(root)` 前的两侧同形化：`REPO_ROOTS`/`BRIDGE_DIR` 中的值多为硬编码
    WSL 形态，而 Windows `os.path.normpath` 会把 join 结果变反斜杠 ⇒ 原判恒 False（误报 traversal）。
    """
    if os.name != "nt":
        return str(root)
    m = MNT_ABS_RE.match(str(root).replace("\\", "/"))
    return "%s:/%s" % (m.group(1).upper(), m.group(2)) if m else str(root)


def bash_script_argv(script: str, *args: str) -> list:
    """构造「用 bash 跑脚本」的 argv（跨宿主）。

    Windows 宿主：`bash` 实为 **WSL 启动器**（`C:\\windows\\system32\\bash.EXE`），只认 POSIX
    形态 ⇒ 脚本路径 + **Windows 形态绝对路径参数**统一转 `/mnt/...`（非路径参数原样，避免污染
    `--repo skill`/`ECO-EDIT` 等值；`guard-edit` 的绝对路径参数必须转，否则 CLI 侧 region 串匹配
    失配 = 保护面假阴性）。Linux 宿主：原样 `["bash", script, *args]`。
    """
    if os.name != "nt":
        return ["bash", script, *args]
    conv = [win_abs_to_wsl(a) if WIN_ABS_RE.match(str(a)) else a for a in args]
    return ["bash", win_abs_to_wsl(script), *conv]


# ── 宿主配置保留集（`R-HOSTCFG`，2026-10-02）────────────────────────────────────
# **为何单独判**：宿主配置（Trae `hooks.json` / `mcp.json` / `settings.json`）在**治理仓之外**，
# 且会话 cwd 常为 `c:\Users\HP` ⟹ `pre_tool_hook` 的 scope 判定落 `SCOPE-OUT` ⟹ Gate 3/4 整链
# **不执行**（实测：宿主 `mcp.json` 写被放行且**零留痕**）。故须在 scope 判定**之前**认出它们，
# 接给既有单源 `guard-edit`（`_protected_region_check`）。
# **名称集与 bash `case` 逐字同源**（`gatekeeper-cli.sh::_protected_region_check`；尾部 `*` = 前缀
# 规则）—— 一致性由 `test_pre_tool_hook.TestHostConfigRoute.test_arm4_*` 机检防漂移。
HOST_CONFIG_BASENAMES = ("hooks.json", "mcp.json", "settings.json", "settings.json.bak*")

# **根**锚定宿主配置目录：刻意**不按 basename 全库认领**（`settings.json` 是极常见文件名，全库
# 认领会把写面开得过宽）。机器根硬编码沿用仓内 `DEV_WORKTREE_ROOTS` 同款先例。
HOST_CONFIG_ROOTS = ("<home>/AppData/Roaming/Trae CN/User",)


def is_host_config_path(p: str) -> bool:
    """是否为**宿主配置路径**（独立面）：basename 命中保留集 **且** 位于宿主配置根内。

    `p` 可为 Windows（`C:\\...`）或 WSL（`/mnt/c/...`）形态 —— 先经 `win_abs_to_wsl` 同形化。
    """
    s = win_abs_to_wsl(p).rstrip("/")
    name = s.rsplit("/", 1)[-1].lower()
    hit = any(name == pat if not pat.endswith("*") else name.startswith(pat[:-1])
              for pat in HOST_CONFIG_BASENAMES)
    if not hit:
        return False
    return any(s == r.rstrip("/") or s.startswith(r.rstrip("/") + "/")
               for r in HOST_CONFIG_ROOTS)
