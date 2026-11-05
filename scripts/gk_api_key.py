#!/usr/bin/env python3
"""API key 落点单源（2026-11-02 建；2026-11-05 按方案 A 迁到 XDG 数据目录）。

## 为什么有这个模块

开源包安装后，用户需要一个**跨平台、可持久化**的 API key 配置入口。原实现只认
两类来源：进程环境变量（`GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY`）与 Windows 用户
环境（`[Environment]::SetEnvironmentVariable`，需 PowerShell）。后者在 Linux/macOS
上不存在，`set-key` 因此只能"当前会话有效"，重启即丢 —— 对开源用户等于没有配置面。

## 落点（2026-11-05 迁移，方案 A）

    $GK_KEYS_DIR                    # 显式目录覆盖（容器/CI）
    $XDG_DATA_HOME/zthl/.keys/api_key
    ~/.local/share/zthl/.keys/api_key        # 默认（0700 目录 + 0600 文件）
    <skill>/.keys/api_key                    # **旧落点**：只读兼容回退，不再写入
    $GATEKEEPER_KEY_FILE                     # 单文件显式覆盖，最高优先级

迁移动机（2026-11-05 红队 + 408 分析）：技能目录在 WSL 下常位于 `/mnt/c`（drvfs），
`chmod 600` 在那里**不生效**（实测 mode 仍 0777）⟹ 私钥同机任意用户可读。XDG 数据目录
通常在 ext4 上，`0700/0600` 才是真边界。

## 约束

- 新落点**只写**，旧落点**只读**（`read_key` 回退 `legacy`）；`migrate` 只 **copy 不删**。
- 目录 `0700`、文件 `0600`（`set-key` 另用 `umask 077` 双保险）。
- `read` 输出**不带换行**，便于 bash `$(...)` 直接取用，且不落日志。

优先级（由 `gatekeeper-cli.sh::_resolve_api_key` 保序，本模块只负责文件面）：
  1) 命令行 `--api-key`   2) `GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY`（或 `MIMO_API_KEY`）
  3) **本模块的 key 文件（新落点 → 旧落点）**  4) Windows 用户环境（PowerShell 回退）

CLI（供 bash 调用）：
    python3 scripts/gk_api_key.py dir
    python3 scripts/gk_api_key.py path --provider deepseek --skill-dir .
    python3 scripts/gk_api_key.py read --provider deepseek --skill-dir .
    python3 scripts/gk_api_key.py migrate --skill-dir .
"""
import argparse
import json
import os
import shutil
import sys

PROVIDER_FILE = {"deepseek": "api_key", "mimo": "mimo_key"}
_SKILL_FALLBACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def store_dir() -> str:
    """新落点目录（写入面）：`$GK_KEYS_DIR` → `$XDG_DATA_HOME/zthl/.keys` → `~/.local/share/zthl/.keys`。"""
    explicit = (os.environ.get("GK_KEYS_DIR") or "").strip()
    if explicit:
        return os.path.abspath(os.path.expanduser(explicit))
    base = (os.environ.get("XDG_DATA_HOME") or "").strip()
    base = os.path.abspath(os.path.expanduser(base)) if base else \
        os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "zthl", ".keys")


def legacy_dir(skill_dir: str = "") -> str:
    """旧落点目录（只读兼容）：`<skill>/.keys`。"""
    return os.path.join(skill_dir or _SKILL_FALLBACK, ".keys")


def key_path(skill_dir: str = "", provider: str = "deepseek") -> str:
    """**写入**路径：`$GATEKEEPER_KEY_FILE` 优先，否则新落点 `<store>/<provider 文件名>`。"""
    explicit = (os.environ.get("GATEKEEPER_KEY_FILE") or "").strip()
    if explicit:
        return explicit
    return os.path.join(store_dir(), PROVIDER_FILE.get(provider, PROVIDER_FILE["deepseek"]))


def _read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return "".join(f.read().split())
    except OSError:
        return ""


def read_key(skill_dir: str = "", provider: str = "deepseek"):
    """返回 `(key, source)`；无 key 时为 `("", "")`。

    `source` ∈ `{"explicit", "file", "legacy"}`：
      · explicit —— 命中了 `$GATEKEEPER_KEY_FILE`；
      · file     —— 命中了新落点（XDG）；
      · legacy   —— 命中了旧落点 `<skill>/.keys`（迁移前的文件，只读兼容）。
    mimo 未单独配置时回退到 `api_key`（与 `_resolve_api_key` 的 deepseek 回退同义）。
    """
    explicit = (os.environ.get("GATEKEEPER_KEY_FILE") or "").strip()
    if explicit:
        k = _read_file(explicit)
        return (k, "explicit") if k else ("", "")
    cands = [PROVIDER_FILE.get(provider, PROVIDER_FILE["deepseek"])]
    if provider == "mimo":
        cands.append(PROVIDER_FILE["deepseek"])
    for d, src in ((store_dir(), "file"), (legacy_dir(skill_dir), "legacy")):
        for name in cands:
            k = _read_file(os.path.join(d, name))
            if k:
                return k, src
    return "", ""


def mask(key: str) -> str:
    """展示用脱敏（绝不回显完整 key）。"""
    k = key or ""
    if not k:
        return ""
    if len(k) <= 8:
        return "*" * len(k)
    return k[:4] + "*" * (len(k) - 8) + k[-4:]


def ensure_store() -> str:
    """建新落点目录（`0700`，已存在则校正权限）。返回目录路径。"""
    d = store_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def migrate(skill_dir: str = "") -> list:
    """旧落点 → 新落点：**只 copy 不删、不覆盖**。返回逐文件动作列表。

    `action` ∈ `{"copied", "exists", "absent"}`；`exists` 表示新落点已有同名文件（跳过）。
    """
    dst_dir = ensure_store()
    src_dir = legacy_dir(skill_dir)
    out = []
    for name in set(PROVIDER_FILE.values()):
        src = os.path.join(src_dir, name)
        dst = os.path.join(dst_dir, name)
        row = {"name": name, "from": src, "to": dst}
        if not os.path.isfile(src):
            row["action"] = "absent"
        elif os.path.exists(dst):
            row["action"] = "exists"
        else:
            try:
                shutil.copyfile(src, dst)
                os.chmod(dst, 0o600)
                row["action"] = "copied"
            except OSError as e:
                row["action"] = "error"
                row["detail"] = "%s: %s" % (type(e).__name__, e)
        out.append(row)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="API key file store (single source)")
    ap.add_argument("action", choices=("path", "read", "mask", "dir", "migrate"))
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--skill-dir", default="")
    a = ap.parse_args(argv)
    if a.action == "dir":
        print(store_dir(), end="")
        return 0
    if a.action == "path":
        print(key_path(a.skill_dir, a.provider), end="")
        return 0
    if a.action == "migrate":
        print(json.dumps({"ok": True, "store": store_dir(),
                          "actions": migrate(a.skill_dir)}, ensure_ascii=False))
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
