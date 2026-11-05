#!/usr/bin/env python3
"""gk_bashpy_loader.py — bashpy-migrate 加载安全网（2026-08-23 用户定案）。

加载优先级（安全网拦截 漏加载/误加载/错误加载）:
1. **发布包（优先）**: pip 安装的 zthl-bashpy-migrate 且 SHA256 命中 _RELEASE_PINS → source=release
2. **本地开发源码（回退）**: 源目录 sys.path 导入 → source=dev（WARN：非 CI 验证）
3. 均不可用 → source=missing

拦截语义:
- 漏加载: 工具该有却没有 → missing，显式报告不静默
- 误加载: 发布包 SHA256 不匹配固定哈希 → 拒绝发布包（hash_mismatch），回退 dev 并标记
- 错误加载: import/调用抛异常 → error + GK_DBG_LOG 追加（可调试插桩）

哈希固定点: _RELEASE_PINS（version → sha256(audit.py)）。v0.1.0 发布 wheel 的 audit.py
哈希已登记（2026-08-24，从 GitHub Release 产物提取）；新版本发布后登记其哈希
（对齐供应链 G. 组 requirements.in + pip-compile --generate-hashes 纪律）。
"""
import hashlib
import importlib
import importlib.metadata
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_host_paths import user_home as _user_home, win_abs_to_wsl  # noqa: E402

PKG = "zthl_bashpy_migrate"
MODULE_TO_PIN = "audit"          # 校验对象 = 实际导入的模块文件
# 模块级注入点（安全网 R1: 测试只 patch 此名，不 patch 标准库 importlib 全局）
_IMPORT_MODULE = importlib.import_module
_RELEASE_PINS = {                # version → sha256(audit.py)；None=未登记（无 CI 发布）
    # 2026-08-24: v0.1.0 发布 wheel（GitHub Release）audit.py 哈希已登记
    "0.1.0": "faf1f2939dcde30d9ee385a1216d72ddc376d5ba039a4a012e5892e01623721a",
    "0.2.3": "52bd3a9b93acd29bb0fc2040c6b1af2aa35ce8cded531d2f6536adac00333a28",
    # 2026-11-04: v0.3.1（tag a33763d）—— 新增 inventory + SC2155/SC2046/E722/F841 + 性能修复。
    # 该哈希取自 tag 提交的 zthl_bashpy_migrate/audit.py（本机升级后实测；发 wheel 后应复核）。
    "0.3.1": "1ffd11a86aa2ff20a244ee57dac93e454f614523d12517dff9cba0f88a747c55",
    # 2026-11-04: v0.3.2 —— 新增 SARIF（sarif.py + cli.py），**audit.py 零改动** ⟹ 同哈希。
    "0.3.2": "1ffd11a86aa2ff20a244ee57dac93e454f614523d12517dff9cba0f88a747c55",
    # 2026-11-04: v0.3.3（tag 5ae535f）—— 新增分诊模型 triage.py + `audit --triage`，
    #   **audit.py 零改动** ⟹ 同哈希（已从 GitHub Release wheel 实测提取并复核）。
    "0.3.3": "1ffd11a86aa2ff20a244ee57dac93e454f614523d12517dff9cba0f88a747c55",
    # 2026-11-04: v0.4.0 —— 三层精细化（L1 reason/inline_blocks；L2 artifact 归一化器注入；
    #   L3 `audit --mount` 挂载断言）。**audit.py 有改动** ⟹ 新哈希（取自本机源码，
    #   发 wheel 后应复核）。注意：加载器版本取 pip 元数据，升级后需刷新 editable 安装。
    "0.4.0": "0c3240df4c4dbb0b688bacd28da4172dad19d5ce5bea2cb13a6367bafec1af99",
}
_DEV_SOURCE_DIRS = (
    os.environ.get("ZTHL_BASHPY_DIR", ""),
    # 2026-10-29 去硬编码：默认 dev 源由**用户目录**派生（`gk_host_paths.user_home`，不写死用户名）
    os.path.join(_user_home(), "zthl-bashpy-migrate"),
    win_abs_to_wsl(os.path.join(_user_home(), "zthl-bashpy-migrate")),
)
GK_DBG_LOG = Path(__file__).resolve().parent / "gk_dbg.log"

_CACHE_FILE = Path(os.environ.get("GK_BASHPY_CACHE",
                    str(Path.home() / ".cache" / "gk-bashpy"))) / "last-check.json"


def _semver_key(v: str) -> tuple:
    """'0.2.3'/'0.1.0-dev' → (0,2,3)。忽略后缀（对齐 gk_bashpy_upgrade）；非字符串返回空元组（防投毒崩溃）。"""
    if not isinstance(v, str):
        return ()
    return tuple(int(x) for x in re.split(r"[.\-]", v.lstrip("v")) if x.isdigit())


def _read_last_check() -> dict:
    """升级命令写入的 last-check 缓存；缺失/损坏返回 {}（静默）。"""
    try:
        data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _dbg(msg: str) -> None:
    """GK_DBG_LOG 追加（可调试插桩）: 加载决策可审计。"""
    try:
        with open(GK_DBG_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{Path(__file__).name}] {msg}\n")
    except OSError:
        pass


def _imported_module_file() -> Path:
    """当前解析到的 zthl_bashpy_migrate.audit 模块文件路径。"""
    mod = _IMPORT_MODULE(f"{PKG}.{MODULE_TO_PIN}")
    return Path(getattr(mod, "__file__", "") or "")


def _installed_version() -> str | None:
    """pip 发行版元数据版本；未安装返回 None。"""
    try:
        return importlib.metadata.version(PKG)
    except Exception:
        return None


def _import_dev() -> bool:
    """把本地开发源码目录加入 sys.path（幂等）。返回是否有候选目录。"""
    for d in _DEV_SOURCE_DIRS:
        if d and os.path.isdir(d) and d not in sys.path:
            sys.path.insert(0, d)
    return any(d and os.path.isdir(d) for d in _DEV_SOURCE_DIRS)


def load_status() -> dict:
    """加载状态（供 self-check / RED-MIGRATE 消费）。

    source ∈ {release, release_unverified, hash_mismatch, dev, missing, error}
    """
    lc = _read_last_check()
    latest = lc.get("latest_version")
    if not isinstance(latest, str):
        latest = None  # 缓存投毒（非字符串）→ 静默忽略，不参与版本比较

    def _with_extra(d: dict) -> dict:
        ver = d.get("version")
        d["latest_known"] = latest
        d["upgrade_pending"] = (bool(latest and ver and
                                     _semver_key(latest) > _semver_key(ver)))
        # pinned=版本已登记 _RELEASE_PINS，不代表哈希校验通过（哈希状态看 hash_verified）
        d["pin_status"] = "pinned" if (ver and ver in _RELEASE_PINS) else "unpinned"
        return d

    version = _installed_version()
    if version is not None:
        # 发布包路径：校验 SHA256
        try:
            f = _imported_module_file()
            pin = _RELEASE_PINS.get(version)
        except Exception as e:
            _dbg(f"installed import failed: {type(e).__name__}: {e}")
            pin = None
            f = Path()
        if pin is None:
            return _with_extra({"source": "release_unverified", "version": version,
                                "hash_verified": None,
                                "detail": "发布包已装但无 SHA256 固定哈希（CI 发布后登记 _RELEASE_PINS）",
                                "module_file": str(f)})
        if f.exists() and _sha256_file(f) == pin:
            return _with_extra({"source": "release", "version": version,
                                "hash_verified": True,
                                "detail": "发布包 SHA256 校验通过",
                                "module_file": str(f)})
        return _with_extra({"source": "hash_mismatch", "version": version,
                            "hash_verified": False,
                            "detail": f"发布包 SHA256 不匹配固定哈希（拒绝发布包，回退 dev）: {f}",
                            "module_file": str(f)})
    # 未安装 → 本地开发源码回退
    if _import_dev():
        try:
            f = _imported_module_file()
            return _with_extra({"source": "dev", "version": "0.1.0-dev",
                                "hash_verified": None,
                                "detail": f"本地开发版源码（非 CI 验证）: {f}",
                                "module_file": str(f)})
        except Exception as e:
            _dbg(f"dev import failed: {type(e).__name__}: {e}")
            return _with_extra({"source": "error", "version": None, "hash_verified": None,
                                "detail": f"本地源码存在但导入失败: {type(e).__name__}: {e}",
                                "module_file": ""})
    return _with_extra({"source": "missing", "version": None, "hash_verified": None,
                        "detail": "zthl_bashpy_migrate 不可用（发布包未装且无本地源码）",
                        "module_file": ""})


def load_bomb_scan():
    """返回 (bomb_scan 可调用 | None, 加载状态 dict)。"""
    status = load_status()
    if status["source"] == "hash_mismatch":
        # 拒绝发布包 → 回退 dev（若可用）
        _import_dev()
        try:
            f = _imported_module_file()
            mod = _IMPORT_MODULE(f"{PKG}.{MODULE_TO_PIN}")
            status = {"source": "dev", "version": "0.1.0-dev",
                      "hash_verified": None,
                      "detail": f"本地开发版源码（发布包因哈希不匹配被拒绝）: {f}",
                      "module_file": str(f)}
            _dbg(f"fallback to dev after hash_mismatch: {f}")
            return getattr(mod, "bomb_scan", None), status
        except Exception as e:
            _dbg(f"dev fallback import failed: {type(e).__name__}: {e}")
            return None, {"source": "missing", "version": None,
                          "hash_verified": False,
                          "detail": "发布包哈希不匹配且 dev 回退失败", "module_file": ""}
    if status["source"] in ("release", "release_unverified", "dev"):
        try:
            mod = _IMPORT_MODULE(f"{PKG}.{MODULE_TO_PIN}")
            _dbg(f"loaded: source={status['source']} file={status.get('module_file')}")
            return getattr(mod, "bomb_scan", None), status
        except Exception as e:
            _dbg(f"load failed: {type(e).__name__}: {e}")
            return None, {"source": "error", "version": None,
                          "hash_verified": status.get("hash_verified"),
                          "detail": f"加载异常: {type(e).__name__}: {e}", "module_file": ""}
    return None, status


if __name__ == "__main__":
    import json
    _st = load_status()
    print(json.dumps(_st, indent=2, ensure_ascii=False))
