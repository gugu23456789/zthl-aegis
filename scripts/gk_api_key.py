#!/usr/bin/env python3
"""API key 落点单源（2026-11-02，开源包可用性）。

## 为什么有这个模块

开源包安装后，用户需要一个**跨平台、可持久化**的 API key 配置入口。原实现只认
两类来源：进程环境变量（`GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY`）与 Windows 用户
环境（`[Environment]::SetEnvironmentVariable`，需 PowerShell）。后者在 Linux/macOS
上不存在，`set-key` 因此只能"当前会话有效"，重启即丢 —— 对开源用户等于没有配置面。

本模块给出第三条落点（**文件**），并作为 bash 侧唯一路径逻辑（禁第二实现）：

    <skill>/.keys/api_key      # deepseek（默认 provider）
    <skill>/.keys/mimo_key     # mimo
    $GATEKEEPER_KEY_FILE       # 显式覆盖（任意路径；便于 CI / 容器注入）

约束：
  · `.keys/` 已在 `.gitignore` 与打包排除面（`pack_release.EXCLUDE_DIRS`）内；
  · 文件由 `set-key` 以 `0600` 写入，只有属主可读；
  · `read` 输出**不带换行**，便于 bash `$(...)` 直接取用，且不落日志。

优先级（由 `gatekeeper-cli.sh::_resolve_api_key` 保序，本模块只负责文件面）：
  1) 命令行 `--api-key`   2) `GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY`（或 `MIMO_API_KEY`）
  3) **本模块的 key 文件**  4) Windows 用户环境（PowerShell 回退）

CLI（供 bash 调用）：
    python3 scripts/gk_api_key.py path --provider deepseek --skill-dir .
    python3 scripts/gk_api_key.py read --provider deepseek --skill-dir .
"""
import argparse
import os
import sys

PROVIDER_FILE = {"deepseek": "api_key", "mimo": "mimo_key"}
_SKILL_FALLBACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def key_path(skill_dir: str = "", provider: str = "deepseek") -> str:
    """key 文件路径：`$GATEKEEPER_KEY_FILE` 优先，否则 `<skill>/.keys/<provider 文件名>`。"""
    explicit = (os.environ.get("GATEKEEPER_KEY_FILE") or "").strip()
    if explicit:
        return explicit
    root = skill_dir or _SKILL_FALLBACK
    return os.path.join(root, ".keys", PROVIDER_FILE.get(provider, PROVIDER_FILE["deepseek"]))


def _read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return "".join(f.read().split())
    except OSError:
        return ""


def read_key(skill_dir: str = "", provider: str = "deepseek"):
    """返回 `(key, source)`；无 key 时为 `("", "")`。

    `source` ∈ `{"explicit", "file"}`：
      · explicit —— 命中了 `$GATEKEEPER_KEY_FILE`；
      · file     —— 命中了 `<skill>/.keys/<provider 文件名>`。
    mimo 未单独配置时回退到 `api_key`（与 `_resolve_api_key` 的 deepseek 回退同义）。
    """
    explicit = (os.environ.get("GATEKEEPER_KEY_FILE") or "").strip()
    if explicit:
        k = _read_file(explicit)
        return (k, "explicit") if k else ("", "")
    cands = [PROVIDER_FILE.get(provider, PROVIDER_FILE["deepseek"])]
    if provider == "mimo":
        cands.append(PROVIDER_FILE["deepseek"])
    root = skill_dir or _SKILL_FALLBACK
    for name in cands:
        k = _read_file(os.path.join(root, ".keys", name))
        if k:
            return k, "file"
    return "", ""


def mask(key: str) -> str:
    """展示用脱敏（绝不回显完整 key）。"""
    k = key or ""
    if not k:
        return ""
    if len(k) <= 8:
        return "*" * len(k)
    return k[:4] + "*" * (len(k) - 8) + k[-4:]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="API key file store (single source)")
    ap.add_argument("action", choices=("path", "read", "mask"))
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--skill-dir", default="")
    a = ap.parse_args(argv)
    if a.action == "path":
        print(key_path(a.skill_dir, a.provider), end="")
        return 0
    key, _src = read_key(a.skill_dir, a.provider)
    if not key:
        return 1
    if a.action == "mask":
        print(mask(key), end="")
        return 0
    print(key, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
