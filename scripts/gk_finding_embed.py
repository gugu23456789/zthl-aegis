"""离线嵌入 producer：读 finding ledger 的 (id,title) → 本地嵌入 → 写旁挂契约。

finding `ECC-FAF2A8F0A0DF`（③-A，用户裁定「完整 consumer+producer」）。

契约 = `<state>.finding-embeddings.jsonl`（每行 `{"id":..,"vec":[..]}`），由
`gk_finding.principal` **自动探测**，用于**中文 finding 的塌缩聚类**：`cos>=emb_tau(0.66)`
的对强制直连（must-link, s=1.0），与「`root_key` 精确成组」「锚集 Jaccard 平均连接」**取并集**，
最终把措辞不同 / token 不重叠但语义同根的 finding 塌缩进同一根因组，收敛出**唯一** `principal`。

⚠⚠ **两套 embedding 的边界（禁混谈；2026-10-30 踩坑记录）** ⚠⚠
  本文件（gatekeeper 自有）                vs   gitnexus 代码图索引（`core/embeddings/`）
  · bge-small-zh-v1.5（中文）                    snowflake-arctic-embed-xs（英文），**硬编码常量**
  · 512 维 / **CLS pooling**                     384 维 / **mean pooling**
  · env `GK_EMBED_MODEL` 可换                    `GITNEXUS_EMBEDDING_MODEL` **仅 HTTP 模式有效**；
                                                本地 ONNX 的 modelId 无处可配（`--embedding-model`
                                                被归为 HTTP endpoint flag，本地会 fallback）
  · 用途 = finding **塌缩聚类**                  用途 = 代码语义搜索 / 调用链
  ⟹ 本文件只**借用** gitnexus 的 transformers.js **Node 栈**（`GK_EMBED_TX_FQ`），
    **不**复用其 embedder 配置与 `embedBatch` —— 后者的 mean pooling 会毁掉 bge-zh 的 CLS 语义。
  ⟹ 想给 gitnexus 索引换中文模型：只能走 HTTP 模式（`--embedding-base-url` + `--embedding-model`
    + `--embedding-dims`）或改其源码；**在本仓 `gk_gitnexus.py` 里注入 env 无效**，且误设
    `GITNEXUS_EMBEDDING_DIMS` 会让建表维度与模型输出不符（`Expected 512, Actual 384`）
    ⟹ analyze 恒失败并留下 `incremental-in-progress` 脏标记 ⟹ preflight 反复自愈、派臂卡死。

嵌入后端 = **复用 gitnexus 的本地 transformers.js 栈**（Node，无新依赖）：
  · 默认模型 `onnx-community/bge-small-zh-v1.5-ONNX`（中文 24M/512维/CLS pooling/MIT）；
  · 桥 = `scripts/_gk_embed_bridge.mjs`（读 payload JSON → 写 vectors JSON）；
  · 路径可 env 覆盖：`GK_EMBED_NODE` / `GK_EMBED_TX_FQ` / `GK_EMBED_CACHE` / `GK_EMBED_MODEL`。

⚠ 依赖宿主已就位：Node 可执行 + gitnexus 的 `@huggingface/transformers` + 模型已缓存
（HF 不通时经 ModelScope 镜像离线落盘）。缺失 ⟹ **fail-loud** 并给指引，不静默产空契约。

用法：
  python3 gk_finding_embed.py <state_file> [--model M] [--out P] [--dry-run]
  python3 gk_finding_embed.py <state_file> --from-vectors <vectors.json>   # 离线/测试用（跳过 Node）
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_finding  # noqa: E402

_DEFAULT_MODEL = os.environ.get("GK_EMBED_MODEL", "onnx-community/bge-small-zh-v1.5-ONNX")
# 2026-10-29 去硬编码：transformers ESM 入口与 HF 缓存根由**用户目录**派生
# （`gk_host_paths.user_home`，不写死用户名）；`Path.as_uri()` 按当前宿主形态给出合法的
# `file:///...`（WSL `/mnt/...` 或 Windows `C:/...`）。
from gk_host_paths import user_home as _user_home  # noqa: E402
_GNX_TX_ENTRY = (Path(_user_home()) / "AppData" / "Roaming" / "npm" / "node_modules"
                 / "gitnexus" / "node_modules" / "@huggingface" / "transformers" / "dist"
                 / "transformers.node.mjs")
_DEFAULT_TX_FQ = os.environ.get("GK_EMBED_TX_FQ", _GNX_TX_ENTRY.as_uri())
_NODE_CANDIDATES = ("/mnt/d/Program Files/nodejs/node.exe",
                    "/mnt/c/Program Files/nodejs/node.exe")
_CACHE_CANDIDATES = (str(Path(_user_home()) / ".cache" / "huggingface"),)
_POOLING = "cls"   # bge-zh 用 CLS pooling（gitnexus embedder 写死 mean ⟹ 不复用其 embedBatch）

# ── 内存防线（2026-10-10 `ECC-666539027A62`）─────────────────────────────────
# 全量 552 条一次过 ONNX ⟹ 注意力张量一次性 4.6GB ⟹ OOM ⟹ 拖崩宿主（Trae 报 0xC0000005）。
# 三道硬防线：自适应批 / 预检门 / 内存上限。
_MAX_COUNT_DEFAULT = int(os.environ.get("GK_EMBED_MAX_COUNT", "32"))
_MAX_CHARS_DEFAULT = int(os.environ.get("GK_EMBED_MAX_CHARS", "8000"))
_PEAK_CAP_DEFAULT = int(os.environ.get("GK_EMBED_PEAK_CAP", str(600 * 10 ** 6)))
_HIDDEN_DEFAULT = int(os.environ.get("GK_EMBED_HIDDEN", "512"))
_HEADS_DEFAULT = int(os.environ.get("GK_EMBED_HEADS", "8"))
_MAX_TOKENS_DEFAULT = int(os.environ.get("GK_EMBED_MAX_TOKENS", "512"))
_NODE_MAX_MB = int(os.environ.get("GK_EMBED_NODE_MAX_MB", "2048"))


def plan_batches(texts, max_count=_MAX_COUNT_DEFAULT, max_chars=_MAX_CHARS_DEFAULT):
    """**自适应分批**：每批同时守 `max_count` 与 `max_chars`；保序/无重复/全覆盖。

    单条超 `max_chars` ⟹ 独占一批（不丢料；token 侧由桥的 `truncation/max_length` 兜底）。
    """
    batches, cur, cur_chars = [], [], 0
    for i, t in enumerate(texts):
        n = len(t)
        if cur and (len(cur) >= max_count or cur_chars + n > max_chars):
            batches.append(cur)
            cur, cur_chars = [], 0
        cur.append(i)
        cur_chars += n
    if cur:
        batches.append(cur)
    return batches


def estimate_peak_bytes(texts, batches, hidden=_HIDDEN_DEFAULT, heads=_HEADS_DEFAULT,
                        max_tokens=_MAX_TOKENS_DEFAULT, nbytes=4):
    """估最坏峰值（注意力 scores 张量）：取各批中最大条数 n ⟹ `n×heads×T²×nbytes`。"""
    peak = 0
    for b in batches:
        peak = max(peak, len(b) * heads * max_tokens * max_tokens * nbytes)
    return peak


def preflight_batches(texts, max_count=_MAX_COUNT_DEFAULT, max_chars=_MAX_CHARS_DEFAULT,
                      cap=_PEAK_CAP_DEFAULT, hidden=_HIDDEN_DEFAULT, heads=_HEADS_DEFAULT,
                      max_tokens=_MAX_TOKENS_DEFAULT, nbytes=4):
    """**预检门**：降批（对半）直到估计峰值 ≤ `cap`；降到 `max_count=1` 仍超 ⟹ **fail-loud**。

    返回 `(batches, est_bytes)`；超上限抛 `RuntimeError`（宁可失败也不 OOM 拖崩宿主）。
    """
    mc = max(1, int(max_count))
    while True:
        b = plan_batches(texts, mc, max_chars)
        est = estimate_peak_bytes(texts, b, hidden, heads, max_tokens, nbytes)
        if est <= cap or mc <= 1:
            break
        mc = max(1, mc // 2)
    if est > cap:
        raise RuntimeError("预检门：单批(max_count=1)估计峰值 %d B 超上限 %d B"
                           "（fail-loud，防 OOM 拖崩宿主）" % (est, cap))
    return b, est


def collect_targets(state_file, state_only=False):
    """读 (id,title)；空 title 跳过。`state_only` = 只读本 state，禁跨源宿主泄漏。"""
    if state_only:
        # 读侧 union（遗漏⑤）：嵌入目标 = 本 state 全部台账（含 finding 溢出片）。
        merged = {str(f.get("id")): f for f in gk_finding.load_findings_union(state_file)
                  if f.get("id")}
    else:
        ents = gk_finding._entries_by_id(state_file)
        merged = {fid: gk_finding._pick_winner(e)[2] for fid, e in ents.items()}
    out = []
    for fid, f in merged.items():
        t = str(f.get("title") or "").strip()
        if t:
            out.append({"id": fid, "title": t})
    out.sort(key=lambda x: x["id"])
    return out


def write_contract(state_file, vectors, model="", dim=0):
    """写旁挂契约 `<state_file>.finding-embeddings.jsonl`；返回路径。

    `vectors` = `{fid: [float,...]}`（按 fid 字典序落行，确定性）。空 vectors ⟹ 仍写空文件（显式）。
    """
    path = state_file + ".finding-embeddings.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for fid in sorted(vectors):
            rec = {"id": fid, "vec": vectors[fid]}
            if model:
                rec["model"] = model
            if dim:
                rec["dim"] = dim
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return path


def _first_existing(cands):
    for c in cands:
        if c and os.path.exists(c):
            return c
    return ""


def _wsl_to_win(p):
    """`/mnt/c/...` → `C:/...`（Windows node.exe 需 Windows 形态路径）；非 WSL 形态原样返回。"""
    if p.startswith("/mnt/") and len(p) > 6 and p[6] == "/":
        return p[5].upper() + ":/" + p[7:]
    return p


def embed_targets(targets, model, node, tx_fq, cache_dir, node_flags=None):
    """调 Node 桥嵌入 targets（顺序对应）→ `({fid: vec}, dim)`。缺 Node/桥/栈 ⟹ fail-loud。"""
    bridge = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_gk_embed_bridge.mjs")
    if not node:
        raise RuntimeError("未找到 node 可执行（设 GK_EMBED_NODE 或装 Node）；"
                           "producer 依赖 gitnexus 的 transformers.js 栈")
    if not os.path.exists(bridge):
        raise RuntimeError("缺 Node 桥 " + bridge)
    # ③ 预检门（自适应批 + 峰值上限）：超限 fail-loud，绝不把大张量扔给 ONNX
    texts = [t["title"] for t in targets]
    batches, peak = preflight_batches(texts)
    # 临时件须在 **Windows 可见**路径（node.exe 读不到 WSL 的 /tmp）⟹ 落缓存同级 gk-embed/。
    tmp_base = os.environ.get("GK_EMBED_TMP") or (
        os.path.join(os.path.dirname(cache_dir.rstrip("/")), "gk-embed") if cache_dir else "")
    if tmp_base:
        os.makedirs(tmp_base, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="run-", dir=(tmp_base or None)) as td:
        pin, pout = os.path.join(td, "payload.json"), os.path.join(td, "out.json")
        with open(pin, "w", encoding="utf-8") as fh:
            json.dump({"model": model, "txFq": tx_fq,
                       "cacheDir": _wsl_to_win(cache_dir) if cache_dir else "",
                       "pooling": _POOLING, "device": "cpu", "dtype": "fp32",
                       "maxLength": _MAX_TOKENS_DEFAULT,
                       "batches": batches, "texts": texts}, fh, ensure_ascii=False)
        # ③ 内存上限：Node JS 堆封顶（原生 ONNX 堆由 ①② 的分批/截断约束）
        cmd = [node, "--max-old-space-size=%d" % _NODE_MAX_MB] + list(node_flags or []) + \
              [_wsl_to_win(bridge), _wsl_to_win(pin), _wsl_to_win(pout)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0 or not os.path.exists(pout):
            raise RuntimeError("Node 桥失败（rc=%s）：%s" % (proc.returncode, (proc.stderr or "")[-800:]))
        with open(pout, encoding="utf-8") as fh:
            data = json.load(fh)
    vecs = data.get("vectors") or []
    if len(vecs) != len(targets):
        raise RuntimeError("桥返回 %d 向量，目标 %d（不匹配）" % (len(vecs), len(targets)))
    return {t["id"]: v for t, v in zip(targets, vecs)}, int(data.get("dim") or 0)


def _usage():
    return ("usage: gk_finding_embed.py <state_file> [--model M] [--out P] [--dry-run]"
            " | <state_file> --from-vectors <vectors.json>")


def run(state_file, model=None, out="", dry=False, from_vectors="", state_only=False):
    """执行 producer，返回结果 dict（**不打印**）。供 CLI `finding embed` 与 `main()` 共用。"""
    model = model or _DEFAULT_MODEL
    if not os.path.exists(state_file):
        return {"ok": False, "error": "state 不存在: " + state_file}
    targets = collect_targets(state_file, state_only=state_only)
    if dry:
        return {"ok": True, "dry_run": True, "targets": len(targets), "model": model,
                "out": out or (state_file + ".finding-embeddings.jsonl")}
    try:
        if from_vectors:                       # 离线/测试路径：直接吃 {fid: vec} JSON，跳过 Node
            with open(from_vectors, encoding="utf-8") as fh:
                blob = json.load(fh)
            vectors = {k: [float(x) for x in v] for k, v in (blob.get("vectors") or blob).items()}
            dim = len(next(iter(vectors.values()))) if vectors else 0
        else:
            node = os.environ.get("GK_EMBED_NODE") or _first_existing(_NODE_CANDIDATES)
            cache = os.environ.get("GK_EMBED_CACHE") or _first_existing(_CACHE_CANDIDATES)
            flags = (os.environ.get("GK_EMBED_NODE_FLAGS") or "").split()
            vectors, dim = embed_targets(targets, model, node, _DEFAULT_TX_FQ, cache, flags)
        path = write_contract(state_file, vectors, model=model, dim=dim)
        if out:
            try:
                os.replace(path, out)
                path = out
            except OSError:
                pass
        return {"ok": True, "model": model, "dim": dim, "vectors": len(vectors),
                "targets": len(targets), "path": path}
    except Exception as e:  # noqa: BLE001 — CLI 边界：统一 JSON 错误
        return {"ok": False, "error": str(e)}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(json.dumps({"ok": False, "error": _usage()}, ensure_ascii=False))
        return 2
    state_file, model, out, dry, from_vectors, state_only = argv[0], _DEFAULT_MODEL, "", False, "", False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--model" and i + 1 < len(argv):
            model, i = argv[i + 1], i + 2
        elif a == "--out" and i + 1 < len(argv):
            out, i = argv[i + 1], i + 2
        elif a == "--from-vectors" and i + 1 < len(argv):
            from_vectors, i = argv[i + 1], i + 2
        elif a == "--dry-run":
            dry, i = True, i + 1
        elif a == "--state-only":
            state_only, i = True, i + 1
        else:
            print(json.dumps({"ok": False, "error": "未知参数 " + a + "（" + _usage() + "）"},
                             ensure_ascii=False))
            return 2
    res = run(state_file, model=model, out=out, dry=dry, from_vectors=from_vectors,
              state_only=state_only)
    print(json.dumps(res, ensure_ascii=False))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
