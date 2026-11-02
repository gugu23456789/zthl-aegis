"""gk_env_inject.py — WSL 侧 API key 环境注入（2026-08-09）

等价于 wslsh.ps1 的 WSLENV 注入（wslsh 只覆盖走 wslsh 的入口）：
任何非 wslsh 入口（cron 调度器 / Windows 计划任务 / 独立脚本）调用的 Python
进程，若 os.environ 缺 key，从 Windows 注册表拉取注入（仅当前进程，不落盘）。

用法:
    import gk_env_inject; gk_env_inject.inject()
    # 或命令行: python3 gk_env_inject.py   （打印注入状态）

幂等：环境已有 key 时不动。优先级：进程环境 → 注册表 User。
"""
import os
import subprocess

_KEYS = ("DEEPSEEK_API_KEY", "MIMO_API_KEY")
_PS_EXE = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"


def _win_env(name: str, scope: str = "User") -> str:
    try:
        ps = _PS_EXE if os.path.exists(_PS_EXE) else "powershell.exe"
        out = subprocess.run(
            [ps, "-NoProfile", "-Command",
             f'[System.Environment]::GetEnvironmentVariable("{name}","{scope}")'],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def inject() -> str:
    """进程环境缺 key 时从 Windows 注册表注入（仅当前进程）。返回注入后 DS key。"""
    for name in _KEYS:
        if os.environ.get(name):
            continue
        v = _win_env(name)
        if v:
            os.environ[name] = v
    return os.environ.get("DEEPSEEK_API_KEY", "")


if __name__ == "__main__":
    inject()
    print("DEEPSEEK_API_KEY=%s" % ("set" if os.environ.get("DEEPSEEK_API_KEY") else "empty"))
