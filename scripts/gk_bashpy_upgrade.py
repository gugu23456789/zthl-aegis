#!/usr/bin/env python3
"""gk_bashpy_upgrade.py — bashpy-migrate 平滑升级命令（skill 侧，2026-08-26；2026-11-04 升 v0.3）。

设计: docs/plans/2026-08-26-gk-bashpy-upgrade-design.md
- check    查 GitHub releases/latest → 对比登记版本 → 写 last-check 缓存
- upgrade  下载 → sha256/sha512 对账 → 备份 → 原子替换 _RELEASE_PINS + manifest
           （`--install` 追加：pip 装 wheel → 体检 → 体检失败自动回滚配置）
- verify   体检（离线）：已装版本 vs 登记 pin、audit.py 实测哈希 vs pin、可回滚性
- status   当前加载状态 + 登记 pin 清单（离线可用，无网络）
- rollback 恢复上次升级前备份
安全网: 对账失败拒绝升级且配置零改动；配置替换原子 + 可回滚；绝不静默使用未对账的包。

2026-11-04 升级（用户：「安装钩子需要升级（pin/回滚/体检）」）：
  ① 配置写入改**原子**（tmp + os.replace）—— 原实现直接 write_text，中途崩溃会留半截
     文件，而模块 docstring 一直宣称「原子 + 可回滚」（声称与实现不符）。
  ② 新增 `verify` 体检：把「装上了」与「装对了」分开判 —— 版本登记、哈希命中、可回滚。
  ③ `upgrade --install`：装包后**立刻体检**，不通过则回滚配置并显式报错（不留半升级态）。
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
# 发行版名（importlib.metadata 用连字符；模块名是下划线）
PKG_DIST = "zthl-bashpy-migrate"


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


def _atomic_write(path: Path, text: str) -> None:
    """原子落盘：写同目录 tmp → fsync → os.replace。

    2026-11-04：原实现 `path.write_text(...)` 直接截断改写 —— 中途崩溃/断电会留下
    半截 loader（语法坏掉的 pin 表），而 rollback 依赖的正是这份文件。
    tmp 必须与目标**同目录**（跨盘 os.replace 不是原子操作）。
    """
    path = Path(path)
    tmp = path.parent / (path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _read_bytes_sha256(path: Path) -> str:
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _installed_dist() -> tuple:
    """(版本, audit.py 绝对路径 | None) —— 只读发行版元数据，**不 import 包**（避免副作用）。"""
    import importlib.metadata as md
    try:
        dist = md.distribution(PKG_DIST)
    except Exception:
        return None, None
    try:
        ver = dist.version
    except Exception:
        ver = None
    path = None
    try:
        for f in dist.files or []:
            if str(f).replace("\\", "/").endswith("zthl_bashpy_migrate/audit.py"):
                path = Path(dist.locate_file(f))
                break
    except Exception:
        path = None
    return ver, path


def _pip_install(wheel: Path) -> tuple:
    """安装 wheel（--no-deps：引擎是标准库 only，绝不顺带拉第三方依赖）。

    模块级函数 = 测试注入点（R1 纪律：只 patch 被测模块边界）。
    """
    import subprocess
    cmd = [sys.executable, "-m", "pip", "install", "--no-deps",
           "--force-reinstall", "--disable-pip-version-check", str(wheel)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [""]
        return False, "pip rc=%d: %s" % (r.returncode, tail[0])
    return True, ""


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


def cmd_upgrade(install: bool = False) -> dict:
    """check + 下载 + 对账 + 备份 + 替换配置（install=True 时追加装包 + 体检 + 失败回滚）。

    失败路径配置零改动；`install=True` 时若装包或体检失败，配置回滚到备份（不留半升级态）。
    """
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
    loader_new = _update_loader_pins(loader_orig, version, audit_sha)
    man_new = _update_manifest(man_orig, version, integrity)
    try:
        _atomic_write(LOADER_FILE, loader_new)
        _atomic_write(MANIFEST_FILE, man_new)
    except Exception as e:  # noqa: BLE001
        # 单文件原子，但**两文件之间**没有跨文件事务 ⟹ 可能一改一未改。
        # 用原内容把两者都写回，保证「要么全旧、要么全新」，不留混搭态。
        try:
            _atomic_write(LOADER_FILE, loader_orig)
            _atomic_write(MANIFEST_FILE, man_orig)
        except Exception:  # noqa: BLE001
            pass
        return {"ok": False, "error": f"配置替换失败（已恢复原样）: {type(e).__name__}: {e}"}
    _write_last_check({"checked_at": _now_iso(), "latest_version": version,
                       "wheel_sha256": audit_sha, "npm_integrity": integrity})
    out = {"ok": True, "version": version, "upgrade_available": True,
           "audit_sha256": audit_sha, "npm_integrity": integrity,
           "backup": str(bdir),
           "hint": "运行 pip install <wheel> 安装新引擎；重启进程后 load_status 显示 pin_status=pinned"}
    if not install:
        return out

    # ── 装包 + 体检 + 失败回滚（2026-11-04）──
    ok, err = _pip_install(whl_p)
    if not ok:
        _restore_from_backup(bdir)
        return {"ok": False, "error": f"安装失败（配置已回滚）: {err}",
                "rolled_back": str(bdir)}
    chk = cmd_verify()
    out["verify"] = chk
    if not chk["ok"]:
        _restore_from_backup(bdir)
        return {"ok": False, "error": "升级后体检不通过（配置已回滚，已装包需人工核对）",
                "verify": chk, "rolled_back": str(bdir)}
    return out


def _restore_from_backup(bdir: Path) -> None:
    """把备份目录里的配置写回（upgrade 失败路径的自动回滚）。"""
    for target in (LOADER_FILE, MANIFEST_FILE):
        src = Path(bdir) / target.name
        if src.exists():
            _atomic_write(target, src.read_text(encoding="utf-8"))


def cmd_verify() -> dict:
    """离线体检（2026-11-04）：区分「装上了」与「装对了」。

    checks:
      installed        是否检测到 pip 发行版（dev 源码模式 → WARN，不判失败）
      pin_registered   已装版本是否登记在 _RELEASE_PINS（未登记 ⟹ 无法对账 ⟹ FAIL）
      hash_match       已装 audit.py 实测 sha256 是否命中 pin（不符 ⟹ FAIL）
      freshness        已装版本 vs 登记最新（落后 → WARN，不判失败）
      rollback_ready   是否存在可验证备份（无 → WARN：出问题回不去）
    """
    pins = {p["version"]: p["sha256"] for p in _current_pins()}
    latest = _latest_registered()
    ver, path = _installed_dist()
    checks = []

    def add(name, status, detail):
        checks.append({"check": name, "status": status, "detail": detail})

    if ver is None:
        add("installed", "WARN", f"未检测到 pip 发行版 {PKG_DIST}（dev 源码模式可接受）")
    else:
        add("installed", "PASS", f"已装 {ver}")
        if ver in pins:
            add("pin_registered", "PASS", f"{ver} 已登记在 _RELEASE_PINS")
        else:
            add("pin_registered", "FAIL", f"{ver} 未登记 pin ⟹ 无法对账（未发布版本混入运行态）")
        if path is not None and Path(path).exists() and ver in pins:
            actual = _read_bytes_sha256(Path(path))
            if actual == pins[ver]:
                add("hash_match", "PASS", "audit.py sha256 命中 pin")
            else:
                add("hash_match", "FAIL",
                    f"audit.py sha256 不符：实测 {actual[:12]}… ≠ pin {pins[ver][:12]}…")
        elif path is None:
            add("hash_match", "WARN", "发行版文件清单里找不到 audit.py（无法实测哈希）")
        if latest and _semver_key(ver) < _semver_key(latest):
            add("freshness", "WARN", f"已装 {ver} < 登记最新 {latest}（有升级待办）")
        else:
            add("freshness", "PASS", f"已装版本不低于登记最新（{latest}）")

    backups = _find_backups(_cache_dir())
    if backups:
        add("rollback_ready", "PASS", f"可用备份 {backups[0].name}")
    else:
        add("rollback_ready", "WARN", "无备份（从未 upgrade 或 backups 已清空）⟹ 不可回滚")
    return {"ok": not any(c["status"] == "FAIL" for c in checks),
            "installed": ver, "latest_registered": latest, "checks": checks}


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
    cmd, rest = argv[0], argv[1:]
    if cmd == "status":
        out = cmd_status()
    elif cmd == "check":
        out = cmd_check()
    elif cmd == "verify":
        out = cmd_verify()
    elif cmd == "upgrade":
        # `--install` 显式 opt-in：会真的跑 pip 装包（默认只改配置，不碰环境）
        out = cmd_upgrade(install=("--install" in rest))
    elif cmd == "rollback":
        out = cmd_rollback()
    else:
        print('{"ok":false,"error":"usage: status | check | verify | upgrade [--install] | rollback"}')
        return 1
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok", False) else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
