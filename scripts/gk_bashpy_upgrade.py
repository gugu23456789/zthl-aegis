#!/usr/bin/env python3
"""gk_bashpy_upgrade.py — bashpy-migrate 平滑升级命令（skill 侧，2026-08-26）。

设计: docs/plans/2026-08-26-gk-bashpy-upgrade-design.md
- check    查 GitHub releases/latest → 对比登记版本 → 写 last-check 缓存
- upgrade  下载 → sha256/sha512 对账 → 备份 → 替换 _RELEASE_PINS + manifest
- status   当前加载状态 + 登记 pin 清单（离线可用，无网络）
- rollback 恢复上次升级前备份
安全网: 对账失败拒绝升级且配置零改动；配置替换原子 + 可回滚；绝不静默使用未对账的包。
"""
import json
import os
import re
import shutil
import sys
from pathlib import Path

DEFAULT_REPO = "zthl-harness/zthl-bashpy-migrate"
GITHUB_API = "https://api.github.com/repos"
DEFAULT_CACHE = Path.home() / ".cache" / "gk-bashpy"
SCRIPTS_DIR = Path(__file__).resolve().parent
LOADER_FILE = SCRIPTS_DIR / "gk_bashpy_loader.py"
MANIFEST_FILE = SCRIPTS_DIR / "gk_plugin_manifest.py"


def _cache_dir() -> Path:
    return Path(os.environ.get("GK_BASHPY_CACHE", DEFAULT_CACHE))


def _last_check_file() -> Path:
    return _cache_dir() / "last-check.json"


def _read_last_check() -> dict:
    try:
        data = json.loads(_last_check_file().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _current_pins() -> list[dict]:
    """从 gk_bashpy_loader.py 提取 _RELEASE_PINS 登记清单（正则，不 import）。"""
    text = LOADER_FILE.read_text(encoding="utf-8")
    m = re.search(r"_RELEASE_PINS\s*=\s*\{(.*?)\n\}", text, re.DOTALL)
    pins = re.findall(r'"([0-9][0-9.]*[0-9]?)"\s*:\s*"([0-9a-f]{64})"', m.group(1)) if m else []
    return [{"version": v, "sha256": h} for v, h in pins]


def cmd_status() -> dict:
    """离线状态：pins 清单 + last-check 缓存（无网络请求）。"""
    lc = _read_last_check()
    return {"ok": True,
            "pins": _current_pins(),
            "latest_known": lc.get("latest_version"),
            "checked_at": lc.get("checked_at")}


def _semver_key(v: str) -> tuple:
    """'v0.2.3'/'0.2.3'/'0.1.0-dev' → (0,2,3)。忽略后缀；非字符串返回空元组（防投毒崩溃）。"""
    if not isinstance(v, str):
        return ()
    return tuple(int(x) for x in re.split(r"[.\-]", v.lstrip("v")) if x.isdigit())


def _validate_version(v: str) -> bool:
    """semver 白名单：^数字.数字.数字$（防注入）。"""
    return isinstance(v, str) and bool(re.fullmatch(r"\d+\.\d+\.\d+", v))


def _validate_integrity(s: str) -> bool:
    """sha512 integrity 白名单：sha512-128hex（防注入）。"""
    return isinstance(s, str) and bool(re.fullmatch(r"sha512-[0-9a-f]{128}", s))


def _latest_registered() -> str | None:
    pins = _current_pins()
    return max((p["version"] for p in pins), key=_semver_key) if pins else None


def _fetch_json(url: str, timeout: int = 10) -> dict:
    """urllib GET + json 解析；失败抛 RuntimeError（调用方转显式错误）。"""
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "gk-bashpy-upgrade/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        raise RuntimeError(f"GitHub API 请求失败: {url}: {e}") from e


def cmd_check() -> dict:
    """查 releases/latest → 对比登记最高版本 → 写 last-check 缓存。"""
    try:
        rel = _fetch_json(f"{GITHUB_API}/{DEFAULT_REPO}/releases/latest")
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    latest = (rel.get("tag_name") or "").lstrip("v")
    if not latest:
        return {"ok": False, "error": "Release 响应缺 tag_name"}
    cur = _latest_registered()
    newer = _semver_key(latest) > _semver_key(cur) if cur else True
    _write_last_check({"checked_at": _now_iso(), "latest_version": latest,
                       "upgrade_available": newer})
    return {"ok": True, "latest_version": latest, "current_pinned": cur,
            "upgrade_available": newer,
            "hint": "运行 upgrade 替换配置" if newer else "已是最新"}


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_last_check(data: dict) -> None:
    _cache_dir().mkdir(parents=True, exist_ok=True)
    _last_check_file().write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _download_to(url: str, dest: Path) -> None:
    """下载 URL 到 dest（模块级可 patch；测试注入本地 fixture）。"""
    import urllib.request
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "gk-bashpy-upgrade/0.2"})
    with urllib.request.urlopen(req, timeout=30) as r:
        dest.write_bytes(r.read())


def _sha256_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha512_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_audit_sha256(whl: Path) -> str:
    """wheel 解包取 zthl_bashpy_migrate/audit.py 计算 sha256（对齐 _RELEASE_PINS 语义）。"""
    import zipfile
    with zipfile.ZipFile(whl) as z:
        data = z.read("zthl_bashpy_migrate/audit.py")
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _backup_configs(cache: Path) -> Path:
    """备份 loader+manifest 并写 backup-manifest.json（文件→sha256，供 rollback 完整性校验）。"""
    import datetime
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bdir = cache / "backups" / ts
    bdir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(LOADER_FILE, bdir / LOADER_FILE.name)
    shutil.copy2(MANIFEST_FILE, bdir / MANIFEST_FILE.name)
    manifest = {name: _sha256_file(bdir / name) for name in (LOADER_FILE.name, MANIFEST_FILE.name)}
    (bdir / "backup-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bdir


def _update_loader_pins(text: str, version: str, sha256: str) -> str:
    """_RELEASE_PINS 累积登记（新增/覆盖版本条目，不删旧条目 → 降级链不被破坏）。纯文本函数。"""
    m = re.search(r"(_RELEASE_PINS\s*=\s*\{)(.*?)(\n\})", text, re.DOTALL)
    assert m, "_RELEASE_PINS block not found"
    head, body, tail = m.group(1), m.group(2), m.group(3)
    if re.search(rf'"{version}"\s*:', body):
        body = re.sub(rf'"{version}"\s*:\s*"[0-9a-f]{{64}}"', f'"{version}": "{sha256}"', body)
    else:
        body = body.rstrip()
        if not body.endswith(","):
            body += ","
        body += f'\n    "{version}": "{sha256}",'
    return text[: m.start()] + head + body + tail + text[m.end():]


def _update_manifest(text: str, version: str, integrity: str) -> str:
    """manifest 更新 npm 段版本 + config.integrity。纯文本函数。

    integrity 行是跨行字符串拼接格式（`"integrity": ("sha512-<hex1>"`
    换行 `"<hex2>")`，hex1 行末带引号），正则需吞掉可选续行段再整体替换为单行。
    """
    text = re.sub(r"npm:@zthl-harness/dsh-bashpy-migrate@[0-9][0-9.]*",
                  f"npm:@zthl-harness/dsh-bashpy-migrate@{version}", text)
    hex_only = integrity[len("sha512-"):]
    text = re.sub(r'"integrity": \("sha512-[0-9a-f]+(?:"\s*\n\s*"[0-9a-f]+)*"\)',
                  f'"integrity": ("sha512-{hex_only}")', text)
    return text


def cmd_upgrade() -> dict:
    """check + 下载 + 对账 + 备份 + 替换配置。失败路径配置零改动。"""
    try:
        rel = _fetch_json(f"{GITHUB_API}/{DEFAULT_REPO}/releases/latest")
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    version = (rel.get("tag_name") or "").lstrip("v")
    if not version:
        return {"ok": False, "error": "Release 响应缺 tag_name"}
    if not _validate_version(version):
        return {"ok": False, "error": f"非法版本号: {version!r}"}
    cur = _latest_registered()
    if cur and _semver_key(version) <= _semver_key(cur):
        return {"ok": True, "version": version, "upgrade_available": False,
                "detail": f"已是最新（登记 {cur}）"}
    assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
    whl_url = next((u for n, u in assets.items() if n.endswith(".whl")), None)
    tgz_url = next((u for n, u in assets.items() if n.endswith(".tgz")), None)
    int_url = next((u for n, u in assets.items() if n == "npm-integrity.json"), None)
    wint_url = next((u for n, u in assets.items() if n == "wheel-integrity.json"), None)
    if not (whl_url and tgz_url and int_url and wint_url):
        return {"ok": False, "error": f"Release v{version} 资产不完整（缺 whl/tgz/npm-integrity.json/wheel-integrity.json）"}

    cache = _cache_dir()
    dl = cache / "downloads"

    def _fail(msg: str) -> dict:
        """失败统一出口：清理 downloads/ 残留（防投毒文件污染下次升级）后返回错误。"""
        shutil.rmtree(dl, ignore_errors=True)
        return {"ok": False, "error": msg}

    try:
        dl.mkdir(parents=True, exist_ok=True)
        whl_p = dl / f"zthl-bashpy-migrate-{version}.whl"
        tgz_p = dl / f"dsh-bashpy-migrate-{version}.tgz"
        int_p = dl / "npm-integrity.json"
        wint_p = dl / "wheel-integrity.json"
        _download_to(whl_url, whl_p)
        _download_to(tgz_url, tgz_p)
        _download_to(int_url, int_p)
        _download_to(wint_url, wint_p)
        audit_sha = _extract_audit_sha256(whl_p)
        tgz_sha = _sha512_file(tgz_p)
        integrity = json.loads(int_p.read_text(encoding="utf-8"))["integrity"]
        if not _validate_integrity(integrity):
            return _fail("非法 integrity 格式（拒绝登记）")
        if f"sha512-{tgz_sha}" != integrity:
            return _fail(f"npm tarball sha512 与 integrity.json 不符（供应链投毒面，拒绝升级）: {tgz_sha[:12]}…")
        wheel_sha = _sha256_file(whl_p)
        wint = json.loads(wint_p.read_text(encoding="utf-8"))
        official = wint.get("sha256")
        if official != wheel_sha:
            return _fail(f"wheel sha256 与官方清单不符（供应链投毒面，拒绝升级）: {wheel_sha[:12]}…")
    except Exception as e:
        return _fail(f"下载/对账失败: {type(e).__name__}: {e}")

    try:
        bdir = _backup_configs(cache)
    except Exception as e:
        return {"ok": False, "error": f"备份失败（配置未改动）: {type(e).__name__}: {e}"}
    loader_orig = LOADER_FILE.read_text(encoding="utf-8")
    man_orig = MANIFEST_FILE.read_text(encoding="utf-8")
    try:
        LOADER_FILE.write_text(_update_loader_pins(loader_orig, version, audit_sha), encoding="utf-8")
        MANIFEST_FILE.write_text(_update_manifest(man_orig, version, integrity), encoding="utf-8")
    except Exception:
        LOADER_FILE.write_text(loader_orig, encoding="utf-8")
        MANIFEST_FILE.write_text(man_orig, encoding="utf-8")
        return {"ok": False, "error": "配置替换失败（已恢复原样）"}
    _write_last_check({"checked_at": _now_iso(), "latest_version": version,
                       "wheel_sha256": audit_sha, "npm_integrity": integrity})
    return {"ok": True, "version": version, "upgrade_available": True,
            "audit_sha256": audit_sha, "npm_integrity": integrity,
            "backup": str(bdir),
            "hint": "运行 pip install <wheel> 安装新引擎；重启进程后 load_status 显示 pin_status=pinned"}


def _find_backups(cache: Path) -> list[Path]:
    """backups 目录下按目录名（时间戳，UTC）倒序的备份目录列表。"""
    bdir = cache / "backups"
    if not bdir.exists():
        return []
    return sorted((p for p in bdir.glob("*") if p.is_dir()),
                  key=lambda p: p.name, reverse=True)


def cmd_rollback() -> dict:
    """恢复最近一次升级前备份（loader + manifest）。失败路径显式报错。"""
    cache = _cache_dir()
    backups = _find_backups(cache)
    if not backups:
        return {"ok": False, "error": "无可用备份（从未 upgrade 或 backups 已清空）"}
    latest = backups[0]
    restored = []
    manifest_p = latest / "backup-manifest.json"
    if manifest_p.exists():
        manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
        for name, expected in manifest.items():
            f = latest / name
            if not f.exists():
                return {"ok": False, "error": f"备份完整性校验失败（{name} 缺失，可能被篡改），拒绝恢复"}
            if _sha256_file(f) != expected:
                return {"ok": False, "error": f"备份完整性校验失败（{name} 可能被篡改），拒绝恢复"}
    else:
        return {"ok": False, "error": "备份缺少完整性清单（旧格式不可验证），拒绝恢复"}
    missing = [n for n in (LOADER_FILE.name, MANIFEST_FILE.name) if n not in manifest]
    if missing:
        return {"ok": False, "error": f"备份完整性校验失败（{missing} 未在清单中），拒绝恢复"}
    try:
        for target, name in ((LOADER_FILE, LOADER_FILE.name),
                             (MANIFEST_FILE, MANIFEST_FILE.name)):
            src = latest / name
            if src.exists():
                target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
                restored.append(name)
    except Exception as e:
        return {"ok": False, "error": f"回滚失败（已恢复 {restored}）: {type(e).__name__}: {e}"}
    if not restored:
        return {"ok": False, "error": f"备份目录不含可恢复文件: {latest}"}
    return {"ok": True, "restored_from": str(latest), "files": restored}


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.splitlines()[0])
        return 1
    cmd = argv[0]
    if cmd == "status":
        out = cmd_status()
    elif cmd == "check":
        out = cmd_check()
    elif cmd == "upgrade":
        out = cmd_upgrade()
    elif cmd == "rollback":
        out = cmd_rollback()
    else:
        print('{"ok":false,"error":"usage: status | check | upgrade | rollback"}')
        return 1
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok", False) else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
