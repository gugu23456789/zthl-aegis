#!/usr/bin/env python3
"""gk_release_preflight.py — 发版预检安全网（2026-11-04）。

为什么存在
==========
release.yml 与发布脚本是**两个独立事实源**，二者漂移只在 tag 推上去后才暴露：
v0.9.6.8–v0.9.6.10 连续三版在 `pack` 步 argparse 退出 2（workflow 传 `--source-*`、
`pack_release.py` 不认），且 publish 步要求的 `dist/PROVENANCE.json` 从未产出。
本脚本把这些契约在**打包前**变成可执行判据（fail-loud），而不是等 CI 红。

八项检查（全部确定性、零网络）
==============================
1. `pack_contract`   workflow 中 `pack_release.py` 用到的 flag ⊆ 脚本 parser 支持的 flag；
2. `pack_fixture`    用最小夹具真跑一次 `pack(... --source-*)`，断言 zip / manifest /
                     PROVENANCE 三件套产出且来源字段可核；
3. `docgen`          `gk_docgen_facts.py check` 必须 PASS（事实块未漂移）；
4. `doc_features`    常驻功能覆盖门（`--skip-facts`，避免与 3 重复）；
5. `release_assets`  publish 步必须挂 7 个资产（5 核心 + 2 基准），否则发版资产静默缺项；
6. `workflow_paths`  workflow `run:` 引用的仓库内路径必须**存在**，或登记在
                     `references/ci-external-paths.json`（带 reason）。
                     2026-11-05 事故：公开 `ci.yml` 引用 `docs/analysis/bomb-inventory-*.json`
                     （`docs/` 是导出排除面）⟹ 公开 CI 恒红，而私仓 preflight 永远绿；
7. `repo_index`      `FILES.md` / `llms.txt` 必须与当前公开面一致（`gk_repo_index.py --check`）。
                     移动端/抓取入口，手写必漂移 ⟹ 与 GK-FACTS 同款「生成器 + 漂移门」；
8. `vendor_artifact` 随包 wheel 三件套自洽：`PROVENANCE.json` ↔ `SHA256SUMS` ↔ 实际文件哈希
                     必须一致（版本/文件名/哈希）。发新版 wheel 时忘了同步 ⟹ 这里直接红。
9. `bench_regression` 发布前性能门（2026-11-08，owner 裁定）：跑 `gk_bench_state --quick` 并与
                     `references/bench-baseline.json` 比对。**仅真回归判红**；口径不匹配 /
                     机制变化 / 基线过时只提示（不阻断）。`GK_PREFLIGHT_BENCH=0` 可跳过。

用法：`python scripts/gk_release_preflight.py [--json]`；退出码 0 = 全绿，1 = 有失败。
`oss_scrub.py export` 会在**导出树**内自动再跑一次（`--skip-preflight` 可显式跳过）。
"""
import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
_WORKFLOW_DIR = ROOT / ".github" / "workflows"
_CI_EXTERNAL = ROOT / "references" / "ci-external-paths.json"
_VENDOR = ROOT / "vendor" / "bashpy"
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
    return {"id": "release_assets", "status": "PASS",
            "detail": "7 个上传件已挂载（网页另显示 2 个自动源码包 zip/tar.gz ⟹ 共见 9 项）"}


# ── workflow 引用的仓库路径（导出面一致性）────────────────────────────────────
# 只扫 `run:` 块（注释/说明里的路径不算依赖）；`$VERSION` 之类的动态片段因 `$` 不在字符类里
# 自然截断 ⟹ 不会误判。
_PATH_RX = re.compile(
    r"(?<![\w./-])((?:docs|references|scripts|monitor-schemas|assets|RELEASE-NOTES)"
    r"/[A-Za-z0-9_.\-/]+\.[A-Za-z0-9]+)")
_RUN_RX = re.compile(r"^(\s*)(?:-\s*)?run:\s*(\|[-+]?)?\s*(.*)$")


def _run_blocks(text: str) -> list:
    """取出 workflow 里所有 `run:` 的 shell 文本（块标量按缩进收尾）。"""
    lines = text.splitlines()
    out, i = [], 0
    while i < len(lines):
        m = _RUN_RX.match(lines[i])
        if not m:
            i += 1
            continue
        indent, body = len(m.group(1)), []
        if m.group(2):                                # run: |
            i += 1
            while i < len(lines):
                ln = lines[i]
                if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
                    break
                body.append(ln)
                i += 1
        else:                                          # run: <inline>
            body.append(m.group(3))
            i += 1
        out.append("\n".join(body))
    return out


def load_ci_external() -> tuple:
    """→ `(entries, error)`；文件缺失视为空表（不阻断），格式错 fail-closed。"""
    if not _CI_EXTERNAL.is_file():
        return [], ""
    try:
        data = json.loads(_CI_EXTERNAL.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [], "references/ci-external-paths.json 不可解析: %s" % e
    entries = data.get("paths") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return [], "references/ci-external-paths.json 缺 paths 列表"
    for e in entries:
        if not isinstance(e, dict) or not str(e.get("glob") or "").strip():
            return [], "ci-external-paths 条目缺 glob: %r" % (e,)
        if not str(e.get("reason") or "").strip():
            return [], "ci-external-paths 条目 %r 缺 reason" % e.get("glob")
    return entries, ""


def workflow_paths() -> dict:
    """workflow `run:` 引用的仓库路径：存在 或 在允许清单（带 reason）。"""
    files = sorted(list(_WORKFLOW_DIR.glob("*.yml")) + list(_WORKFLOW_DIR.glob("*.yaml")))
    if not files:
        return {"id": "workflow_paths", "status": "FAIL",
                "detail": "未找到任何 workflow（%s）" % _WORKFLOW_DIR}
    refs = {}
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
        except OSError as e:
            return {"id": "workflow_paths", "status": "FAIL",
                    "detail": "读不到 %s: %s" % (f.name, e)}
        for block in _run_blocks(text):
            for m in _PATH_RX.finditer(block):
                refs.setdefault(m.group(1), set()).add(f.name)
    entries, err = load_ci_external()
    if err:
        return {"id": "workflow_paths", "status": "FAIL", "detail": err}
    globs = {str(e["glob"]): str(e["reason"]) for e in entries}

    def _allow(p: str) -> bool:
        return any(fnmatch.fnmatchcase(p, g) for g in globs)

    missing = sorted(p for p in refs if not (ROOT / p).exists() and not _allow(p))
    stale = sorted(g for g in globs if not any(fnmatch.fnmatchcase(p, g) for p in refs))
    if missing or stale:
        bits = []
        if missing:
            bits.append("缺失未登记: %s" % ", ".join(missing[:6]))
        if stale:
            bits.append("允许清单过期（无引用）: %s" % ", ".join(stale[:6]))
        return {"id": "workflow_paths", "status": "FAIL", "detail": "；".join(bits)}
    return {"id": "workflow_paths", "status": "PASS",
            "detail": "%d 个引用路径 / 允许清单 %d 条" % (len(refs), len(globs))}


def repo_index_check() -> dict:
    """`FILES.md` / `llms.txt` 与公开面一致（移动端/抓取入口不漂移）。"""
    r = _run_json([str(ROOT / "scripts" / "gk_repo_index.py"), "--check", "--json"])
    ok = bool(r.get("ok"))
    return {"id": "repo_index", "status": "PASS" if ok else "FAIL",
            "detail": ("files=%s" % r.get("files")) if ok
                      else "；".join(r.get("issues") or ["check 失败"])[:300]}


def vendor_artifact() -> dict:
    """随包 wheel 三件套自洽：PROVENANCE ↔ SHA256SUMS ↔ 实际文件（版本/文件名/哈希）。"""
    import hashlib
    if not _VENDOR.is_dir():
        return {"id": "vendor_artifact", "status": "FAIL",
                "detail": "vendor/bashpy 不存在（本体随包后不该缺）"}
    whls = sorted(_VENDOR.glob("zthl_bashpy_migrate-*.whl"))
    if len(whls) != 1:
        return {"id": "vendor_artifact", "status": "FAIL",
                "detail": "wheel 数量应为 1（实际 %d）" % len(whls)}
    w = whls[0]
    actual = hashlib.sha256(w.read_bytes()).hexdigest()
    try:
        prov = json.loads((_VENDOR / "PROVENANCE.json").read_text(encoding="utf-8"))
        sums = (_VENDOR / "SHA256SUMS").read_text(encoding="utf-8")
    except (OSError, ValueError) as e:
        return {"id": "vendor_artifact", "status": "FAIL",
                "detail": "读不到 PROVENANCE.json / SHA256SUMS: %s" % e}
    problems = []
    if str(prov.get("artifact") or "") != w.name:
        problems.append("PROVENANCE.artifact≠%s" % w.name)
    if str(prov.get("sha256") or "").lower() != actual:
        problems.append("PROVENANCE.sha256≠实际哈希")
    ver = str(prov.get("version") or "")
    if ver and not w.name.startswith("zthl_bashpy_migrate-%s-" % ver):
        problems.append("PROVENANCE.version=%s 与文件名不符" % ver)
    want = ""
    for ln in sums.splitlines():
        parts = ln.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == w.name:
            want = parts[0].strip().lower()
    if want != actual:
        problems.append("SHA256SUMS 未登记或与文件不符")
    if problems:
        return {"id": "vendor_artifact", "status": "FAIL", "detail": "；".join(problems)}
    return {"id": "vendor_artifact", "status": "PASS",
            "detail": "%s / %s…" % (ver or w.name, actual[:12])}


def bench_regression() -> dict:
    """发布前性能门（2026-11-08，owner 裁定）：跑 quick bench 并与基线比对 + 归因。

    判红**仅限**：硬失败（失败写 / 崩溃 checksum / tmp 残留 / 场景 ok=false）与
    `diagnose` 归类为 `regression`（机制模块未变 + 口径一致 + 超阈）。
    口径不匹配 / 机制变化 / 基线过时 ⟹ **PASS + 提示**（避免「新机制与旧基线」误判成回归）。
    跳过条件：`GK_PREFLIGHT_BENCH=0`、无 `.git`（导出树）、无基线、无 bench 脚本。
    """
    if os.environ.get("GK_PREFLIGHT_BENCH", "1") == "0":
        return {"id": "bench_regression", "status": "SKIP",
                "detail": "GK_PREFLIGHT_BENCH=0（显式跳过）"}
    if not (ROOT / ".git").exists():
        return {"id": "bench_regression", "status": "SKIP",
                "detail": "无 .git（导出树）⟹ 基线不可定位，跳过性能门"}
    baseline_p = ROOT / "references" / "bench-baseline.json"
    bench = ROOT / "scripts" / "gk_bench_state.py"
    if not baseline_p.is_file() or not bench.is_file():
        return {"id": "bench_regression", "status": "SKIP",
                "detail": "缺 bench-baseline.json 或 gk_bench_state.py"}
    try:
        p = subprocess.run([sys.executable, str(bench), "--quick", "--json"],
                           cwd=str(ROOT), capture_output=True, text=True, timeout=600)
        cur = json.loads(p.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        return {"id": "bench_regression", "status": "FAIL",
                "detail": "quick bench 执行失败：%s" % e}
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        import gk_bench_compare as BC
        baseline = json.loads(baseline_p.read_text(encoding="utf-8"))
        # 只比**当前档位存在的场景**（基线可能是 full 12 场景、本门跑 quick 4 场景）；
        # 否则「当前结果缺该场景」会被误判成 violation。裁剪只影响对比面，不改基线文件。
        names = {s.get("scenario") for s in (cur.get("scenarios") or [])}
        bstate = ((baseline.get("benchmarks") or {}).get("state") or {})
        bstate = dict(bstate, scenarios=[s for s in (bstate.get("scenarios") or [])
                                         if s.get("scenario") in names])
        baseline = dict(baseline, benchmarks={"state": bstate})
        res = BC.compare(baseline, {"state": cur}, tolerance=1.25, only=["state"])
        dg = BC.diagnose(res, baseline, {"state": cur}, repo=str(ROOT))
    except Exception as e:  # noqa: BLE001 — 边界：对比器自身异常按红（不静默放行）
        return {"id": "bench_regression", "status": "FAIL",
                "detail": "对比/归因失败：%s: %s" % (type(e).__name__, e)}

    hard = [v for v in res.get("violations", [])
            if str(v.get("metric", "")).startswith(("state.failed", "state.crash", "state.ok"))]
    regress = [it for it in dg.get("items", []) if it.get("kind") == "regression"]
    if hard or regress:
        bits = ["硬失败 %d" % len(hard) if hard else "",
                "真回归 %d" % len(regress) if regress else ""]
        detail = "；".join(x for x in bits if x)
        sample = [it.get("metric") for it in (hard + regress)[:3]]
        return {"id": "bench_regression", "status": "FAIL",
                "detail": "%s（%s）" % (detail, ", ".join(str(s) for s in sample))}
    notes = []
    if dg.get("probe_mismatch"):
        notes.append("口径不匹配（amp_per_state 仅一侧）⟹ 建议重采基线")
    if dg.get("changed_modules"):
        notes.append("机制模块有改动（%s）⟹ 确认有意后重采基线"
                     % ",".join(os.path.basename(x) for x in dg["changed_modules"]))
    stale = [w for w in res.get("warnings", []) if w.get("metric") == "baseline.stale"]
    if stale:
        notes.append(stale[0].get("detail", "")[:120])
    ops = [s.get("ops_s") for s in (cur.get("scenarios") or []) if s.get("ops_s")]
    base = ("%d 场景 / 吞吐 %s ops/s" % (len(cur.get("scenarios") or []),
                                         ("%.1f–%.1f" % (min(ops), max(ops))) if ops else "n/a"))
    return {"id": "bench_regression", "status": "PASS",
            "detail": base + (("；" + "；".join(notes)) if notes else "")}


def run_all() -> dict:
    try:
        wf = WORKFLOW.read_text(encoding="utf-8")
    except OSError as e:
        return {"ok": False, "checks": [{"id": "workflow", "status": "FAIL",
                                         "detail": "读不到 %s: %s" % (WORKFLOW, e)}]}
    checks = [pack_contract(wf), pack_fixture(), docgen_check(),
              doc_features_check(), release_assets(wf), workflow_paths(),
              repo_index_check(), vendor_artifact(), bench_regression()]
    # 2026-11-08：允许 SKIP（性能门在导出树/显式关闭时跳过）。既有 8 项从不返回 SKIP ⟹
    #   本行对它们等价于原 `== "PASS"`；FAIL 仍判红（fail-closed 不变）。
    return {"ok": all(c["status"] in ("PASS", "SKIP") for c in checks), "checks": checks}


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
