#!/usr/bin/env python3
"""gk_release_preflight.py — 发版预检安全网（2026-11-04）。

为什么存在
==========
release.yml 与发布脚本是**两个独立事实源**，二者漂移只在 tag 推上去后才暴露：
v0.9.6.8–v0.9.6.10 连续三版在 `pack` 步 argparse 退出 2（workflow 传 `--source-*`、
`pack_release.py` 不认），且 publish 步要求的 `dist/PROVENANCE.json` 从未产出。
本脚本把这些契约在**打包前**变成可执行判据（fail-loud），而不是等 CI 红。

五项检查（全部确定性、零网络）
==============================
1. `pack_contract`   workflow 中 `pack_release.py` 用到的 flag ⊆ 脚本 parser 支持的 flag；
2. `pack_fixture`    用最小夹具真跑一次 `pack(... --source-*)`，断言 zip / manifest /
                     PROVENANCE 三件套产出且来源字段可核；
3. `docgen`          `gk_docgen_facts.py check` 必须 PASS（事实块未漂移）；
4. `doc_features`    常驻功能覆盖门（`--skip-facts`，避免与 3 重复）；
5. `release_assets`  publish 步必须挂 7 个资产（5 核心 + 2 基准），否则发版资产静默缺项。

用法：`python scripts/gk_release_preflight.py [--json]`；退出码 0 = 全绿，1 = 有失败。
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
_SCRIPTS = str(ROOT / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

# publish 步必须出现的 7 个资产（前 5 核心 + 后 2 基准）
_REQUIRED_ASSETS = (
    "zthl-aegis-$VERSION.zip",
    "dist/SHA256SUMS",
    "dist/PROVENANCE.json",
    "dist/SBOM.cdx.json",
    "dist/release-manifest.json",
    "dist/bench/release.json",
    "dist/bench/release-compare.json",
)


def _shell_block(text: str, needle: str) -> str:
    """取出含 `needle` 的那条命令及其 `\\` 续行（YAML `run: |` 块内的 shell 文本）。"""
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if needle not in ln:
            continue
        out = [ln]
        j = i
        while lines[j].rstrip().endswith("\\") and j + 1 < len(lines):
            j += 1
            out.append(lines[j])
        return "\n".join(out)
    return ""


def _window(text: str, needle: str, before: int = 30, after: int = 15) -> str:
    """取 `needle` 前后窗口（用于 publish 步：资产列表可能写在 `gh release create` **之前**）。"""
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if needle in ln:
            return "\n".join(lines[max(0, i - before): i + after + 1])
    return ""


def _flags(block: str) -> set:
    return set(re.findall(r"--[a-z][a-z0-9-]*", block))


def pack_contract(workflow: str, parser=None) -> dict:
    """workflow 用的 pack 参数必须都在脚本 parser 里（反之不要求）。"""
    import pack_release as P
    ap = parser or P.build_parser()
    supported = {o for a in ap._actions for o in a.option_strings if o.startswith("--")}
    block = _shell_block(workflow, "pack_release.py")
    if not block:
        return {"id": "pack_contract", "status": "FAIL", "detail": "workflow 未找到 pack_release.py 调用"}
    used = _flags(block)
    missing = sorted(used - supported)
    if missing:
        return {"id": "pack_contract", "status": "FAIL",
                "detail": "workflow 传了脚本不认的参数: %s" % ", ".join(missing)}
    return {"id": "pack_contract", "status": "PASS",
            "detail": "flags ⊆ parser（%d 个）" % len(used)}


def pack_fixture() -> dict:
    """最小夹具真跑一次打包：三件套 + 来源绑定。"""
    import pack_release as P
    tmp = Path(tempfile.mkdtemp(prefix="gk-preflight-"))
    tree = tmp / "tree"
    (tree / "scripts").mkdir(parents=True)
    (tree / "LICENSE").write_text("Mulan PSL v2\n", encoding="utf-8")
    (tree / "README.md").write_text("preflight\n", encoding="utf-8")
    (tree / "scripts" / "a.py").write_text("print(1)\n", encoding="utf-8")
    out = tmp / "dist"
    try:
        r = P.pack(str(tree), str(out), "v0.0.0-preflight",
                   source_repo="org/repo", source_commit="deadbeef", source_tag="v0.0.0")
    except SystemExit as e:
        return {"id": "pack_fixture", "status": "FAIL", "detail": "pack SystemExit: %s" % e}
    prov_p = out / "PROVENANCE.json"
    need = [out / "zthl-aegis-v0.0.0-preflight.zip", out / "SHA256SUMS",
            out / "release-manifest.json", prov_p]
    miss = [p.name for p in need if not p.is_file()]
    if not r.get("ok") or miss:
        return {"id": "pack_fixture", "status": "FAIL",
                "detail": "产出缺失: %s" % (", ".join(miss) or "pack ok=false")}
    prov = json.loads(prov_p.read_text(encoding="utf-8"))
    if prov.get("source") != {"repo": "org/repo", "commit": "deadbeef", "tag": "v0.0.0"}:
        return {"id": "pack_fixture", "status": "FAIL",
                "detail": "PROVENANCE.source 不符: %r" % (prov.get("source"),)}
    return {"id": "pack_fixture", "status": "PASS",
            "detail": "zip + SHA256SUMS + manifest + PROVENANCE 四件套"}


def _run_json(args: list) -> dict:
    p = subprocess.run([sys.executable] + args, cwd=str(ROOT),
                       capture_output=True, text=True, timeout=180)
    try:
        return json.loads(p.stdout or "{}")
    except ValueError:
        return {"ok": False, "error": (p.stderr or p.stdout or "")[-300:], "rc": p.returncode}


def docgen_check() -> dict:
    r = _run_json([str(ROOT / "scripts" / "gk_docgen_facts.py"), "check"])
    ok = r.get("status") == "PASS"
    return {"id": "docgen", "status": "PASS" if ok else "FAIL",
            "detail": r.get("detail") or r.get("error") or "status=%r" % r.get("status")}


def doc_features_check() -> dict:
    r = _run_json([str(ROOT / "scripts" / "gk_doc_features.py"), "--skip-facts", "--json"])
    ok = bool(r.get("ok"))
    return {"id": "doc_features", "status": "PASS" if ok else "FAIL",
            "detail": ("checked=%s missing=%d" % (r.get("checked"), len(r.get("missing") or [])))
                      if ok else json.dumps(r.get("missing") or r, ensure_ascii=False)[:300]}


def release_assets(workflow: str) -> dict:
    block = _window(workflow, "gh release create", before=40, after=15)
    if not block:
        return {"id": "release_assets", "status": "FAIL",
                "detail": "workflow 未找到 gh release create"}
    missing = [a for a in _REQUIRED_ASSETS if a not in block]
    if missing:
        return {"id": "release_assets", "status": "FAIL",
                "detail": "发布资产缺项: %s" % ", ".join(missing)}
    return {"id": "release_assets", "status": "PASS", "detail": "7 个资产已挂载"}


def run_all() -> dict:
    try:
        wf = WORKFLOW.read_text(encoding="utf-8")
    except OSError as e:
        return {"ok": False, "checks": [{"id": "workflow", "status": "FAIL",
                                         "detail": "读不到 %s: %s" % (WORKFLOW, e)}]}
    checks = [pack_contract(wf), pack_fixture(), docgen_check(),
              doc_features_check(), release_assets(wf)]
    return {"ok": all(c["status"] == "PASS" for c in checks), "checks": checks}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_release_preflight.py")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    out = run_all()
    if ns.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        for c in out["checks"]:
            print("%-4s %-16s %s" % (c["status"], c["id"], c.get("detail", "")))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
