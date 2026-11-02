#!/usr/bin/env python3
"""gk_swe_rb_loader.py — swe-rb 插件加载安全网（2026-08-31 定案，镜像 gk_bashpy_loader.py）。

加载优先级（安全网拦截 漏加载/误加载/错误加载）:
1. **发布包（优先）**: pip 安装的 zthl-swe-rb 且 SHA256 命中 _RELEASE_PINS → source=release
2. **本地开发源码（回退）**: 源目录 sys.path 导入 → source=dev（WARN：非 CI 验证）
3. 均不可用 → source=missing

拦截语义:
- 漏加载: 工具该有却没有 → missing，显式报告不静默
- 误加载: 发布包 SHA256 不匹配固定哈希 → 拒绝发布包（hash_mismatch），回退 dev 并标记
- 错误加载: import/调用抛异常 → error + GK_DBG_LOG 追加

哈希固定点: _RELEASE_PINS（version → sha256(audit.py)）。未发布前为 {}；
发布 wheel 后登记其 audit.py 哈希（对齐供应链 G. 组纪律）。
"""
import hashlib
import importlib
import importlib.metadata
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_host_paths import user_home as _user_home, win_abs_to_wsl  # noqa: E402

PKG = "zthl_swe_rb"
MODULE_TO_PIN = "audit"          # 校验对象 = 实际导入的模块文件
# 模块级注入点（安全网 R1: 测试只 patch 此名，不 patch 标准库 importlib 全局）
_IMPORT_MODULE = importlib.import_module
_DISTRIBUTION = importlib.metadata.distribution
_RELEASE_PINS = {                # version → sha256(audit.py)；空 = 未发布（无 CI 产物）
}
_DEV_SOURCE_DIRS = (
    os.environ.get("ZTHL_SWE_RB_DIR", ""),
    # 2026-10-29 去硬编码：默认 dev 源由**用户目录**派生（`gk_host_paths.user_home`，不写死用户名）
    os.path.join(_user_home(), "zthl-swe-rb"),
    win_abs_to_wsl(os.path.join(_user_home(), "zthl-swe-rb")),
)
GK_DBG_LOG = Path(__file__).resolve().parent / "gk_dbg.log"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _module_file_path(module) -> Path:
    return Path(getattr(module, "__file__", "")).resolve()


def load_status() -> dict:
    """五源分流 → {status, source, version, detail}（tampered → fail-closed）。"""
    # 1) 发布包：importlib.metadata 定位安装包
    try:
        dist = _DISTRIBUTION("zthl-swe-rb")
        version = dist.version
        pin = _RELEASE_PINS.get(version)
        if pin is None:
            return {"status": "dev", "source": "release-unpinned",
                    "version": version,
                    "detail": "已安装但哈希未登记（无 CI 发布）— 降级 dev"}
        mod = _IMPORT_MODULE(f"{PKG}.{MODULE_TO_PIN}")
        digest = _sha256_file(_module_file_path(mod))
        if digest != pin:
            return {"status": "error", "source": "hash_mismatch",
                    "version": version,
                    "detail": f"audit.py SHA256 不匹配固定哈希（{digest[:12]}）"}
        return {"status": "release", "source": "release", "version": version,
                "detail": "发布包哈希命中"}
    except importlib.metadata.PackageNotFoundError:
        pass
    except Exception as e:  # import 失败 → 错误加载
        return {"status": "error", "source": "import", "detail": str(e)}

    # 2) 本地开发源码（回退）
    for d in _DEV_SOURCE_DIRS:
        if not d or not Path(d).is_dir():
            continue
        sys.path.insert(0, d)
        try:
            mod = _IMPORT_MODULE(f"{PKG}.{MODULE_TO_PIN}")
            return {"status": "dev", "source": "dev", "version": "dev",
                    "detail": f"源码目录 {d}（非 CI 验证）"}
        except Exception as e:
            return {"status": "error", "source": "dev-import", "detail": str(e)}
        finally:
            if d in sys.path:
                sys.path.remove(d)
    return {"status": "missing", "source": "missing",
            "detail": "未安装 zthl-swe-rb，且未发现开发源码目录"}


if __name__ == "__main__":
    import json
    print(json.dumps(load_status(), ensure_ascii=False, indent=2))
