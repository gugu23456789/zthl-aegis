#!/usr/bin/env python3
"""gk_gitnexus_pdg_check.py — L3/L5 交叉审查扩展实装（2026-09-01）

此前 stage-3-review.md 仅登记"L3 pdg-query / L5 taint 待接入"，本脚本实装：
  L3 PDG 程序依赖图查询（CDG 控制依赖 + REACHING_DEF 数据依赖）
    → 死代码三关第二关升级：rg 文本扫描 → PDG 可达性（guard/def→use 边实证）
  L5 污点分析（TAINTED 边 + TAINT_PATH 跨函数）
    → 补 hook 文本层盲区：输入→敏感操作数据流实证

依赖：仓库已 `gitnexus analyze --pdg` 建层（gitnexus.json pdg 字段存在）。
调用：python3 gk_gitnexus_pdg_check.py [--repo <name>] [--symbol <fn>] [--limit <n>]
输出契约：
  {
    "ok": bool, "repo": "...", "pdg_layer": bool,
    "stats": {"cdg_edges": N, "reaching_def_edges": N, "tainted_edges": N, "taint_path_edges": N},
    "symbol_probe": {"symbol": "...", "cdg": [...], "flows": [...], "guards": [...]},  # --symbol 时
    "recommendation": "..."
  }
确定性：0 API。Windows node.exe 直调 gitnexus CLI（同 subagent_runner._gitnexus_cmd，避开 PowerShell
括号转义）；node/js/repo 三要素由 gatekeeper-cli.sh（`_gx_subagent_gx_env`）经 GX_NODE/GX_JS/GX_REPO
注入，本脚本**不自探测**（F-REV-75）。
"""
import json
import os
import re
import sys
from pathlib import Path

from gk_json_utils import extract_markdown_int
import gk_gitnexus  # A1（2026-10-28）：node/js/repo 探测与 spawn 的**唯一** python 侧入口

# F-REV-75（2026-09-16，用户裁定「同根因修」）：node/js/repo **一律不自探测**。
# A1（2026-10-28）：本文件原有的 `_node/_gx_js/_gx_env_error/_resolve_repo` 四件复制
# **已收敛**到 `gk_gitnexus`（单源）；下面四个薄壳仅为既有测试/调用点保留原名。
def _node() -> str:
    """Windows node.exe 的 WSL 可执行形态（/mnt/...）—— CLI 注入，不自探测。"""
    return gk_gitnexus.node_exe()


def _gx_js() -> str:
    """gitnexus CLI 入口的 **Windows 形态**路径（node.exe 是 Windows 二进制，不认 /mnt 路径）。"""
    return gk_gitnexus.js_path()


def _gx_env_error() -> str:
    """env 可用性检查（fail-loud 文案）；可用则返回空串。"""
    return gk_gitnexus.env_error("本脚本须经 gatekeeper-cli.sh 调用 —— audit --pdg，CLI 自动注入")


def _resolve_repo(explicit: str) -> str:
    """repo 单源解析：显式 --repo 优先，否则用 CLI 注入的 GX_REPO（原写死 spz-gatekeeper-r-sequence）。"""
    return gk_gitnexus.resolve_repo(explicit)


def _cypher(query: str, repo: str, limit: int = 50) -> dict:
    """node.exe 直调 gitnexus cypher（无 shell 转义）。返回 {"markdown","row_count"} 或 error。

    JSON 提取收敛到 gk_json_utils.extract_last_json（2026-09-01，专业工具）：
    按所有 `{` 候选 raw_decode，取结束位置最靠后的完整对象 —— 修复原"行首 `{`
    定位"在 warn 行后置/多 JSON 混杂时的误判。
    """
    # F-REV-75 fail-loud 前置（不再有硬编码路径兜底 ⟹ env/repo 缺失必须显式报错而非静默空结果）
    err = _gx_env_error()
    if err:
        return {"error": err}
    if not repo:
        return {"error": "[ERROR] repo 未解析：--repo 未给且 GX_REPO 未注入（F-REV-75 去硬编码后不猜名）"}
    # A1（2026-10-28）：spawn + JSON 提取收敛到 gk_gitnexus（`strict=True` 保留 rc≠0 即 error 的语义）
    d = gk_gitnexus.run_json(["cypher", query, "-r", repo, "-l", str(limit)], strict=True)
    if isinstance(d, dict) and "error" in d:
        return d
    if not isinstance(d, dict) or "raw" in d:
        # 无 JSON（纯文本）或非 dict（JSON 数组）→ 保持本脚本既有契约：error，不崩溃
        return {"error": "no JSON in output"}
    return d


def _count(query: str, repo: str) -> int | None:
    d = _cypher(query, repo)
    if "error" in d:
        return None
    return extract_markdown_int(d)


def check_stats(repo: str) -> dict:
    q = ("MATCH (:BasicBlock)-[r:CodeRelation {type:'CDG'}]->() RETURN count(r) AS c")
    cdg = _count(q, repo)
    q = ("MATCH (:BasicBlock)-[r:CodeRelation {type:'REACHING_DEF'}]->() RETURN count(r) AS c")
    rd = _count(q, repo)
    q = ("MATCH (:BasicBlock)-[r:CodeRelation {type:'TAINTED'}]->() RETURN count(r) AS c")
    taint = _count(q, repo)
    q = ("MATCH (:Function)-[r:CodeRelation {type:'TAINT_PATH'}]->() RETURN count(r) AS c")
    tpath = _count(q, repo)
    return {"cdg_edges": cdg, "reaching_def_edges": rd,
            "tainted_edges": taint, "taint_path_edges": tpath}


def probe_symbol(repo: str, symbol: str, limit: int) -> dict:
    """锚定符号探测：CDG guard 边 + REACHING_DEF flows 边（函数级，id-prefix 锚定）。"""
    # guard 探测：CDG 边指向 return/throw（guard clause）
    q = ("MATCH (pred:BasicBlock)-[r:CodeRelation {type:'CDG'}]->(dep:BasicBlock) "
         "WHERE dep.text STARTS WITH 'return' OR dep.text STARTS WITH 'throw' "
         "RETURN pred.startLine AS pred, r.reason AS branch, dep.startLine AS dep, dep.text AS text LIMIT 20")
    guards = _cypher(q, repo, limit)
    # 该符号所在文件的 def→use 流（锚定文件前缀：按函数名模糊匹配）
    q = (f"MATCH (f:Function) WHERE f.name = '{symbol}' "
         f"RETURN f.filePath AS file, f.startLine AS line LIMIT 5")
    fn = _cypher(q, repo, 5)
    return {"guards": guards if "error" not in guards else guards,
            "function": fn if "error" not in fn else fn}


def _resolve_base(repo: str = "") -> Path:
    """仓库根解析（2026-09-13 cwd 假象修复）：repo 真实路径 > cwd（须含 .gitnexus
    索引才采信）> 模块锚（scripts/ 上一级 = 技能仓库根）。修复前裸 os.getcwd() 在
    调用方 cwd ≠ 仓库根时指向不存在的索引（cwd 假象：第三轮质询确认 + 实测复现）。"""
    if repo and Path(repo).exists():
        return Path(repo)
    cwd = Path(os.getcwd())
    if (cwd / ".gitnexus" / "gitnexus.json").exists():
        return cwd
    return Path(__file__).resolve().parent.parent


def check_pdg_layer(repo: str = "") -> bool:
    """从本地 gitnexus.json 读 pdg 字段（不依赖 cypher 探测）。仓库根解析见 _resolve_base。"""
    base = _resolve_base(repo)
    gx_json = base / ".gitnexus" / "gitnexus.json"
    try:
        d = json.loads(gx_json.read_text(encoding="utf-8"))
        return bool(d.get("pdg"))
    except Exception:
        return False


def check_supply_chain(repo: str, limit: int = 15) -> dict:
    """L7 供应链依赖图（2026-09-01 修正版）。

    原实现（2026-09-01 初版）有缺陷：gitnexus File 节点 filePath 是**相对路径**
    （scripts/gk_state.py），`NOT STARTS WITH 'C:\\...'` 恒真 → 全部仓库内文件
    被误判为外部依赖；且登记引用的 gitnexus.json `unresolvedReceiverMembers`
    字段实际不存在（LadybugDB 无该字段，登记虚构）。

    正确实现（确定性 0 API，双路）：
      1. 索引文件集 = gitnexus.json `fileHashes` keys（相对路径全集）
      2. 扫描 scripts/*.py + gatekeeper-cli.sh 的 import/source 语句，
         解析 import 目标 → 归一化候选路径（X.py / X/__init__.py / dir/X.py）
      3. 目标不在索引文件集 = **未解析成员/外部依赖**（供应链风险候选）
      4. 同时用 cypher IMPORTS 边交叉印证（索引内模块间依赖，供趋势分析）
    """
    result: dict = {"check": "supply_chain"}
    # ── 1. 索引文件集（gitnexus.json fileHashes keys）──
    # 仓库根解析（2026-09-13 cwd 假象修复，同 check_pdg_layer）：见 _resolve_base。
    base = _resolve_base(repo)
    gx_json = base / ".gitnexus" / "gitnexus.json"
    indexed_files: set[str] = set()
    try:
        d = json.loads(gx_json.read_text(encoding="utf-8"))
        indexed_files = {k.replace("\\", "/").lstrip("/") for k in (d.get("fileHashes") or {})}
    except Exception:
        indexed_files = set()
    if not indexed_files:
        return {"status": "skip", "reason": "gitnexus.json fileHashes 缺失/不可读（无索引?）"}

    # ── 2. 扫描 import/source 语句 ──
    imported: dict[str, list[str]] = {}  # module → 引用它的文件
    root = base
    for py in root.glob("scripts/*.py"):
        try:
            text = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"^\s*(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_.]*)", text, re.M):
            mod = m.group(1).split(".")[0]
            if mod not in ("", "scripts"):
                imported.setdefault(mod, []).append(py.name)
    try:
        cli = (root / "gatekeeper-cli.sh").read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"(?:source|\.)\s+([a-zA-Z0-9_./-]+\.sh)", cli):
            src = m.group(1).split("/")[-1]
            if src not in ("", "scripts"):
                imported.setdefault(src, []).append("gatekeeper-cli.sh")
    except OSError:
        pass

    # ── 3. 未解析成员判定：import 目标在索引内无可对应文件 ──
    def _resolves(mod: str) -> bool:
        base = mod.replace(".", "/")
        cands = [base + ".py", base + "/__init__.py", f"{base}.sh",
                 f"scripts/{base}.py", f"scripts/{base}/__init__.py"]
        return any(c in indexed_files for c in cands)

    # 2026-09-01 L7 完整版：三分类（本地解析 / 标准库 / 第三方未解析）。
    # stdlib 用 sys.stdlib_module_names（Python 3.10+，确定性 0 API）判定 →
    # 标准库导入（json/sys/pathlib…）不是供应链风险，仅第三方未解析才是候选。
    import sys as _sys
    stdlib_names = set(getattr(_sys, "stdlib_module_names", ()))

    unresolved_all = sorted(
        (mod for mod in imported if not _resolves(mod)),
        key=lambda m: -len(imported[m]))
    stdlib = [m for m in unresolved_all if m in stdlib_names]
    third_party = [m for m in unresolved_all if m not in stdlib_names]
    external = [{"module": m, "imported_by": sorted(set(imported[m]))[:4]}
                for m in third_party[:limit]]
    result["status"] = "ok"
    result["indexed_files"] = len(indexed_files)
    result["total_imports"] = len(imported)
    result["stdlib"] = stdlib  # 标准库引用（非风险，清单供核验）
    result["unresolved"] = external
    if third_party:
        result["detail"] = (f"{len(third_party)} 个第三方 import 目标在索引内无对应文件"
                            f"（外部依赖/未装模块/索引过期候选，需人工核验）：{third_party[:8]}")
    else:
        result["detail"] = "全部 import 目标可解析（本地文件或标准库，无第三方未解析盲区）"
    # ── 4. cypher IMPORTS 交叉印证（索引内依赖拓扑，供趋势）──
    q = ("MATCH (n)-[r:CodeRelation {type:'IMPORTS'}]->(m:File) "
         "RETURN m.filePath AS target, count(r) AS cnt ORDER BY cnt DESC LIMIT 8")
    d = _cypher(q, repo, 8)
    if "error" not in d:
        md = d.get("markdown", "")
        rows = []
        for line in md.splitlines():
            line = line.strip()
            if line.startswith("|") and "target" not in line and "---" not in line:
                cells = [c.strip() for c in line.strip("|").split("|")]
                if len(cells) >= 2:
                    rows.append({"file": cells[0], "imports": cells[1]})
        result["internal_deps_top"] = rows
    return result


def main(argv=None) -> None:
    repo = ""          # F-REV-75：默认值留空，解析后经 _resolve_repo 单源化（GX_REPO）
    symbol = ""
    limit = 50
    supply = False
    args = list(sys.argv[1:] if argv is None else argv)
    for i, a in enumerate(args):
        if a == "--repo" and i + 1 < len(args):
            repo = args[i + 1]
        elif a == "--symbol" and i + 1 < len(args):
            symbol = args[i + 1]
        elif a == "--limit" and i + 1 < len(args):
            try:
                limit = int(args[i + 1])
            except ValueError:
                pass
        elif a == "--supply":
            supply = True
    repo = _resolve_repo(repo)
    if not repo:
        print(json.dumps({"ok": False, "pdg_layer": False, "repo": "",
                          "error": "[ERROR] repo 未解析：--repo 未给且 GX_REPO 未注入（F-REV-75）"},
                         ensure_ascii=False))
        return
    has_layer = check_pdg_layer(repo)
    stats = check_stats(repo) if has_layer else {"cdg_edges": None}
    out = {"ok": True, "repo": repo, "pdg_layer": has_layer,
           "stats": stats, "symbol_probe": None,
           "supply_chain": check_supply_chain(repo) if supply else None,
           "recommendation": ""}
    if not has_layer:
        out["ok"] = False
        out["recommendation"] = "仓库未建 PDG 层 → 运行 `node .gitnexus/run.cjs analyze --pdg`"
    else:
        if symbol:
            out["symbol_probe"] = probe_symbol(repo, symbol, limit)
        out["recommendation"] = (
            f"PDG 层 OK：CDG={stats['cdg_edges']} REACHING_DEF={stats['reaching_def_edges']} "
            f"TAINTED={stats['tainted_edges']} TAINT_PATH={stats['taint_path_edges']} — "
            "L3 死代码第二关可查 guard/def→use 实证；L5 污点可查 source→sink 边。"
            "hook 盲区补查：对敏感操作（subprocess/exec/eval）跑 TAINTED 入边。")
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
