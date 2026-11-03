#!/usr/bin/env python3
"""gk_sbom.py — 生成 CycloneDX 1.5 SBOM（零网络、仅标准库、确定性）。

口径（2026-11-03，发布链 B 档）：
  · **组件 = 声明依赖**：`requirements*.txt` / `pyproject.toml [project].dependencies` /
    `package.json`（dependencies + devDependencies）；不把随包文件当组件 ——
    文件级清单在 `SHA256SUMS` 与 `release-manifest.json`，重复一份只会漂移。
  · 本项目自身 = `metadata.component`（name/version + 可选 zip sha256）。
  · **无墙钟时间**，`serialNumber` 由内容派生 ⟹ 同输入逐字节相同（可进确定性发包链）。

用法：
  python3 scripts/gk_sbom.py --tree . --version v0.9.4.3 --out dist/SBOM.cdx.json
  python3 scripts/gk_sbom.py --tree . --version v1 --zip-sha256 <sha> --json
"""
import argparse
import hashlib
import json
import os
import re
import sys
import uuid

_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"
                  r"(?:==\s*([A-Za-z0-9._+-]+))?")
_NAME = "zthl-aegis"


def _pypi(name: str, ver: str = "") -> dict:
    c = {"type": "library", "name": name,
         "purl": "pkg:pypi/%s%s" % (name.lower().replace("_", "-"),
                                    ("@" + ver) if ver else "")}
    if ver:
        c["version"] = ver
    return c


def _req_components(path: str) -> list:
    out = []
    try:
        fh = open(path, encoding="utf-8")
    except OSError:
        return out
    with fh:
        for ln in fh:
            s = ln.split("#", 1)[0].strip()
            if not s or s.startswith("-"):
                continue
            m = _REQ.match(s)
            if m:
                out.append(_pypi(m.group(1), m.group(2) or ""))
    return out


def _pyproject_components(path: str) -> list:
    out = []
    try:
        import tomllib
    except ImportError:                     # Python < 3.11：跳过（不伪造）
        return out
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, ValueError):
        return out
    for spec in (data.get("project") or {}).get("dependencies") or []:
        m = _REQ.match(str(spec))
        if m:
            out.append(_pypi(m.group(1), m.group(2) or ""))
    return out


def _package_json_components(path: str) -> list:
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return out
    for key in ("dependencies", "devDependencies"):
        for name, ver in (data.get(key) or {}).items():
            v = str(ver).lstrip("^~=v")
            c = {"type": "library", "name": name,
                 "purl": "pkg:npm/%s%s" % (name, ("@" + v) if v else "")}
            if v:
                c["version"] = v
            out.append(c)
    return out


def collect_components(tree: str) -> list:
    """扫声明依赖 → 去重（按 purl）→ 按 name/purl 排序（确定性）。"""
    comps = []
    for f in sorted(os.listdir(tree)):
        p = os.path.join(tree, f)
        if not os.path.isfile(p):
            continue
        if f.startswith("requirements") and f.endswith(".txt"):
            comps.extend(_req_components(p))
        elif f == "pyproject.toml":
            comps.extend(_pyproject_components(p))
        elif f == "package.json":
            comps.extend(_package_json_components(p))
    uniq = {c["purl"]: c for c in comps}
    return [uniq[k] for k in sorted(uniq)]


def build(tree: str, version: str, zip_sha256: str = "", name: str = _NAME) -> dict:
    comps = collect_components(tree)
    root_ref = "%s@%s" % (name, version)
    root = {"type": "application", "name": name, "version": version,
            "bom-ref": root_ref}
    if zip_sha256:
        root["hashes"] = [{"alg": "SHA-256", "content": zip_sha256}]
    for c in comps:
        c["bom-ref"] = c["purl"]
    digest = hashlib.sha256(json.dumps(
        {"v": version, "z": zip_sha256, "c": comps},
        sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "urn:uuid:%s" % uuid.uuid5(
            uuid.NAMESPACE_URL, "zthl-sbom:" + digest),
        "metadata": {
            "component": root,
            "properties": [
                {"name": "zthl:runtime-dependencies",
                 "value": "declared" if comps else "stdlib-only"},
                {"name": "zthl:export-policy",
                 "value": "references/oss-export-whitelist.json"},
            ],
        },
        "components": comps,
        "dependencies": [{"ref": root_ref,
                          "dependsOn": [c["bom-ref"] for c in comps]}],
    }
    return bom


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_sbom.py")
    ap.add_argument("--tree", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", default="")
    ap.add_argument("--zip-sha256", default="")
    ap.add_argument("--name", default=_NAME)
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    if not os.path.isdir(ns.tree):
        raise SystemExit("tree 不是目录: %s" % ns.tree)
    bom = build(ns.tree, ns.version, ns.zip_sha256, ns.name)
    text = json.dumps(bom, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if ns.out:
        os.makedirs(os.path.dirname(os.path.abspath(ns.out)), exist_ok=True)
        with open(ns.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    if ns.json or not ns.out:
        sys.stdout.write(text)
    else:
        print("OK %s components=%d" % (ns.out, len(bom["components"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
