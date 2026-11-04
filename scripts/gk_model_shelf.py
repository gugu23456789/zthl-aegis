#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""模型制品保质期机检 + 一键刷新（tokenizer / 探针 pin）。

背景（2026-10-17，owner 要求）：tokenizer 与各探针参数都会随模型换代失效。本模块把
「哪些常量必须与模型绑定」集中成一份可机检清单，并提供**一条命令**刷新下载物：

  python3 gk_model_shelf.py check      # 离线机检（默认不联网）
  python3 gk_model_shelf.py check --online   # 另查 HF 仓 model_type / commit
  python3 gk_model_shelf.py refresh    # 下载最新 tokenizer.json/config 到缓存并打印新 pin
  python3 gk_model_shelf.py upgrade    # refresh + check（一键升级；源码 pin 仍须人工确认）

检查项：
  1. tokenizer 制品存在 / sha256 / 可被 `tokenizers` 装载 / 词表规模；
  2. `=` filler 的 token 比（验证「每个 `=` ≈ 1 token」这只脚）；
  3. 探针 pin：`NIAH_LONG_PAIRS` / `NIAH_TOP_LOGPROBS` / `stride S`；
  4. （可选）HF 仓 `model_type` 与 commit sha。

**不自动改源码**：`refresh` 只更新缓存 + 打印新的 PINNED 块；探针常量（S / NIAH）是否
随模型换代而变，必须 owner 复核后手工改 —— 自动改写会把「机检」变成「自证」。
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request
from urllib.parse import urlsplit

HF_REPO = "deepseek-ai/DeepSeek-V4.1-Flash-1017"
CACHE_DIR = os.path.expanduser("~/.cache/gk-tokenizer/deepseek-v4.1-flash")

# ── 与模型绑定的 pin（换代时整块更新；refresh 会打印建议值）──────────────────────
PINNED = {
    "alias": "deepseek-flash",
    "canonical": "DeepSeek-V4.1-Flash-1017",
    "hf_repo": HF_REPO,
    "model_type": "deepseek_v41",
    "repo_commit": "1bae0e1088993b9b82de08f59de5be5a34e42170",  # 2026-10-17 换代
    # 1017 与 2026-09-10 旧仓的 tokenizer.json 完全一致（HF / 魔搭同 sha）。
    "tokenizer_sha256": "c90dfa01249db1be4245780a052ede752e1361c612ac6d08e2bdada7d599476b",
    "tokenizer_bytes": 6367257,
    # 运行时指纹（2026-10-17 V4.1-Flash-1017 实测）；换代即变。
    "system_fingerprint": "e72d3c7f663d3e1383b00b3884cb4501",
    # S 的**取证指纹**：S=2 是在 aeb56401… 上钉的；与当前指纹不一致 ⟹ 新鲜度 FAIL。
    "stride_S": 2,
    "stride_S_source_fingerprint": "aeb56401ca74e127821c4f9126dcb669",
    "niah_long_pairs": 16000,
    "niah_top_logprobs": 20,
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url, dest, opener=None, timeout=120):
    """原子下载：先写 `.tmp` 再 rename；返回 `(sha256, bytes)`。"""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    op = opener or urllib.request.urlopen
    req = urllib.request.Request(url, headers={"User-Agent": "gk-model-shelf/1.0"})
    tmp = dest + ".tmp"
    with op(req, timeout=timeout) as r, open(tmp, "wb") as f:
        f.write(r.read())
    os.replace(tmp, dest)
    return sha256_file(dest), os.path.getsize(dest)


def _endpoint_urls(name):
    """制品 URL 候选：`HF_ENDPOINT` → 官方 → hf-mirror（本机 WSL 直连 HF 不可达）。"""
    eps = []
    for e in (os.environ.get("HF_ENDPOINT", ""), "https://huggingface.co",
              "https://hf-mirror.com"):
        e = (e or "").rstrip("/")
        if e and e not in eps:
            eps.append(e)
    return [e + "/" + HF_REPO + "/resolve/main/" + name for e in eps]


def _download_first(urls, dest, opener=None, timeout=120):
    """按候选顺序下载，返回 `(sha256, bytes, url)`；全失败则抛最后一个错误。"""
    last = None
    for u in urls:
        try:
            sha, size = _download(u, dest, opener=opener, timeout=timeout)
            return sha, size, u
        except Exception as e:                   # noqa: BLE001 — 逐个端点重试
            last = e
    raise last


def refresh(cache_dir=None, url=None, opener=None, config_url=None):
    """下载 tokenizer.json（+ config）到缓存；返回制品元数据（不碰源码）。"""
    cache_dir = cache_dir or CACHE_DIR
    tok = os.path.join(cache_dir, "tokenizer.json")
    cfg = os.path.join(cache_dir, "tokenizer_config.json")
    sha, size, used = _download_first(
        [url] if url else _endpoint_urls("tokenizer.json"), tok, opener=opener)
    cfg_sha = cfg_size = 0
    try:
        cfg_url = config_url or used.rsplit("/", 1)[0] + "/tokenizer_config.json"
        cfg_sha, cfg_size, _ = _download_first([cfg_url], cfg, opener=opener)
    except Exception as e:                       # noqa: BLE001 — config 缺失不阻断 tokenizer
        print("[WARN] tokenizer_config.json 下载失败（%s）" % e, file=sys.stderr)
    _u = urlsplit(used)
    meta = {"repo": HF_REPO, "endpoint": "%s://%s" % (_u.scheme, _u.netloc),
            "tokenizer_path": tok, "sha256": sha, "bytes": size,
            "config_path": cfg, "config_sha256": cfg_sha, "config_bytes": cfg_size}
    with open(os.path.join(cache_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    print("\n# 复核后把下面两项写回 PINNED（tokenizer 换代时）：")
    print('    "tokenizer_sha256": "%s",' % sha)
    print('    "tokenizer_bytes": %d,' % size)
    return meta


def _row(name, status, detail=""):
    return {"check": name, "status": status, "detail": detail}


def tokenizer_checks(path=None, pinned=None):
    """离线检查 tokenizer 制品；返回 `(rows, info)`。"""
    p = pinned or PINNED
    path = path or os.path.join(CACHE_DIR, "tokenizer.json")
    rows = []
    if not os.path.isfile(path):
        rows.append(_row("tokenizer_file", "FAIL", "missing: %s（运行 refresh）" % path))
        return rows, {}
    size = os.path.getsize(path)
    sha = sha256_file(path)
    rows.append(_row("tokenizer_file", "PASS", "%d bytes" % size))
    if p.get("tokenizer_sha256"):
        rows.append(_row("tokenizer_sha256",
                         "PASS" if sha == p["tokenizer_sha256"] else "FAIL",
                         "%s vs pinned %s" % (sha[:16], p["tokenizer_sha256"][:16])))
    else:
        rows.append(_row("tokenizer_sha256", "UNKNOWN", "PINNED 未填（先 refresh 再复核）"))
    try:
        from tokenizers import Tokenizer
    except Exception as e:                       # noqa: BLE001
        rows.append(_row("tokenizers_import", "FAIL", str(e)))
        return rows, {"path": path, "sha256": sha, "bytes": size}
    try:
        tok = Tokenizer.from_file(path)
        vocab = tok.get_vocab_size()
        try:
            from gk_turn_cache import filler
        except Exception:                       # noqa: BLE001 — 独立运行时退回内联同义式
            def filler(n):
                return "=\n" * int(n or 0)
        eq_lens = [len(tok.encode(filler(n)).ids) for n in (0, 1, 8, 16)]
        rows.append(_row("tokenizer_load", "PASS", "vocab=%d" % vocab))
        rows.append(_row("filler_token_ratio",
                         "PASS" if eq_lens == [0, 1, 8, 16] else "FAIL",
                         "len(filler(n)) -> %s（n=0,1,8,16；PASS 条件 = 每单元恰 1 token）"
                         % eq_lens))
        return rows, {"path": path, "sha256": sha, "bytes": size, "vocab": vocab,
                      "filler_token_lens": eq_lens}
    except Exception as e:                       # noqa: BLE001
        rows.append(_row("tokenizer_load", "FAIL", str(e)))
        return rows, {"path": path, "sha256": sha, "bytes": size}


def pin_checks():
    """探针常量与 PINNED 的一致性（源码发现漂移即 FAIL）。"""
    rows = []
    try:
        import gk_phase_formats as F
        import gk_phase_probe as P
    except ImportError as e:
        # 2026-11-04（导出面修复）：phase 族属导出**排除面** ⟹ 公开包本就没有这些模块。
        # 记 `NOT_SHIPPED`（信息态）而非 FAIL —— FAIL 只应表示"模块在场但与 PINNED 对不上"
        # （真漂移）。否则公开包每次 model-shelf 都恒定一行假红。
        return [_row("probe_import", "NOT_SHIPPED",
                     "phase 族不随公开包（%s）" % e.__class__.__name__)]
    except Exception as e:                       # noqa: BLE001
        return [_row("probe_import", "FAIL", str(e))]
    rows.append(_row("niah_long_pairs",
                     "PASS" if F.NIAH_LONG_PAIRS == PINNED["niah_long_pairs"] else "FAIL",
                     "%s vs pinned %s" % (F.NIAH_LONG_PAIRS, PINNED["niah_long_pairs"])))
    rows.append(_row("niah_top_logprobs",
                     "PASS" if F.NIAH_TOP_LOGPROBS == PINNED["niah_top_logprobs"] else "FAIL",
                     "%s vs pinned %s" % (F.NIAH_TOP_LOGPROBS, PINNED["niah_top_logprobs"])))
    rows.append(_row("stride_S_candidate",
                     "PASS" if PINNED["stride_S"] in P.CANDIDATE_STRIDES else "FAIL",
                     "pinned %s in %s" % (PINNED["stride_S"], sorted(P.CANDIDATE_STRIDES))))
    fresh = PINNED["stride_S_source_fingerprint"] == PINNED["system_fingerprint"]
    rows.append(_row("stride_S_freshness", "PASS" if fresh else "FAIL",
                     "S=%s 取证于 %s；当前指纹 %s ⟹ %s"
                     % (PINNED["stride_S"], PINNED["stride_S_source_fingerprint"][:12],
                        PINNED["system_fingerprint"][:12],
                        "fresh" if fresh else "须重新取证（禁沿用 S）")))
    return rows


def _api_urls():
    """HF API 候选端点（本机 WSL 直连 huggingface.co 不可达 ⟹ 末尾回退 hf-mirror）。"""
    eps = []
    for e in (os.environ.get("HF_ENDPOINT", ""), "https://huggingface.co",
              "https://hf-mirror.com"):
        e = (e or "").rstrip("/")
        if e and e not in eps:
            eps.append(e)
    return [e + "/api/models/" + HF_REPO for e in eps]


def online_checks(opener=None):
    """HF 仓元数据：model_type / commit sha（`--online` 才跑；含 hf-mirror 回退）。"""
    op = opener or urllib.request.urlopen
    data = None
    used = ""
    last = None
    for u in _api_urls():
        try:
            req = urllib.request.Request(
                u, headers={"User-Agent": "gk-model-shelf/1.0",
                            "Accept": "application/json"})
            with op(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8"))
            used = u
            break
        except Exception as e:                   # noqa: BLE001 — 逐个端点重试
            last = e
    if data is None:
        return [_row("hf_api", "UNKNOWN", "网络失败（含 hf-mirror）：%s" % last)]
    mt = (data.get("config") or {}).get("model_type", "")
    sha = str(data.get("sha", ""))
    return [
        _row("hf_api", "PASS", "%s sha=%s" % (urlsplit(used).netloc, sha[:12])),
        _row("hf_model_type", "PASS" if mt == PINNED["model_type"] else "FAIL",
             "%s vs pinned %s" % (mt, PINNED["model_type"])),
        _row("repo_commit", "PASS" if sha == PINNED["repo_commit"] else "FAIL",
             "%s vs pinned %s（权重仓换代 ⟹ tokenizer 可能随之变）"
             % (sha[:12], PINNED["repo_commit"][:12])),
    ]


def live_fingerprint(api_key=None, opener=None, timeout=60):
    """最小 API 调用取 `system_fingerprint`（约 32 token）；无 key ⟹ UNKNOWN。

    cron 调度器的 script 模式会剥离 API key；定时任务通过 `GK_ENV_INJECT=1`
    显式允许从 Windows 注册表注入（`gk_env_inject`，仅当前进程，不落盘）。
    普通调用/测试不设该变量 ⟹ 缺 key 仍 fail-loud 为 UNKNOWN。
    """
    key = api_key or os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("GATEKEEPER_API_KEY")
    if not key and os.environ.get("GK_ENV_INJECT") == "1":
        try:
            from gk_env_inject import inject
            inject()
            key = (os.environ.get("DEEPSEEK_API_KEY")
                   or os.environ.get("GATEKEEPER_API_KEY"))
        except Exception:                        # noqa: BLE001 — 注入失败按缺 key
            key = None
    if not key:
        return {"fingerprint": None, "reason": "no DEEPSEEK_API_KEY / GATEKEEPER_API_KEY"}
    body = json.dumps({"model": PINNED["alias"],
                       "messages": [{"role": "user", "content": "hi"}],
                       "max_tokens": 1, "stream": False}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.deepseek.com/chat/completions", data=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
    op = opener or urllib.request.urlopen
    try:
        with op(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as e:                       # noqa: BLE001
        return {"fingerprint": None, "reason": "api failed: %s" % e}
    return {"fingerprint": data.get("system_fingerprint"), "model": data.get("model"),
            "usage": data.get("usage")}


def fingerprint_rows(observed):
    """指纹漂移：与 PINNED 不一致 ⟹ FAIL（相位 S 必须重新取证）。"""
    fp = (observed or {}).get("fingerprint")
    if not fp:
        return [_row("system_fingerprint", "UNKNOWN",
                     (observed or {}).get("reason", "no fingerprint"))]
    return [_row("system_fingerprint",
                 "PASS" if fp == PINNED["system_fingerprint"] else "FAIL",
                 "%s vs pinned %s" % (fp[:12], PINNED["system_fingerprint"][:12]))]


def _apply_allow_stale(rows):
    """把已知的 `stride_S_freshness` FAIL 降为 WARN（定时 guard 用）。

    只放行这一条：它表示「S 尚未按新指纹重钉」，是已知状态；
    tokenizer/commit/指纹漂移仍保持 FAIL，不能静默。
    """
    out = []
    for r in rows:
        if (r.get("check") == "stride_S_freshness"
                and r.get("status") == "FAIL"):
            r = dict(r)
            r["status"] = "WARN"
            r["detail"] = "已知过期（allow-stale-phase）: " + str(
                r.get("detail", ""))
        out.append(r)
    return out


def run_check(online=False, fingerprint=False, path=None, opener=None,
              api_key=None, allow_stale_phase=False):
    rows, info = tokenizer_checks(path=path)
    rows += pin_checks()
    if online:
        rows += online_checks(opener=opener)
    observed = None
    if fingerprint:
        observed = live_fingerprint(api_key=api_key, opener=opener)
        rows += fingerprint_rows(observed)
    if allow_stale_phase:
        rows = _apply_allow_stale(rows)
    print("%-22s %-8s %s" % ("check", "status", "detail"))
    for r in rows:
        print("%-22s %-8s %s" % (r["check"], r["status"], r["detail"]))
    bad = [r for r in rows if r["status"] == "FAIL"]
    warns = sum(r["status"] == "WARN" for r in rows)
    if warns:
        print("\nsummary: %d PASS / %d WARN / %d UNKNOWN / %d FAIL"
              % (sum(r["status"] == "PASS" for r in rows), warns,
                 sum(r["status"] == "UNKNOWN" for r in rows), len(bad)))
    else:
        print("\nsummary: %d PASS / %d UNKNOWN / %d FAIL"
              % (sum(r["status"] == "PASS" for r in rows),
                 sum(r["status"] == "UNKNOWN" for r in rows), len(bad)))
    if info:
        print("tokenizer: %s" % json.dumps(info, ensure_ascii=False))
    if bad:
        meta = {"model": PINNED["alias"]}
        fp = (observed or {}).get("fingerprint")
        if fp:
            meta["system_fingerprint"] = fp
        print("\n# 处置（按序）：")
        print("  1) python3 scripts/gk_model_shelf.py upgrade   # 刷新 tokenizer 制品")
        print("  2) python3 scripts/gk_stride_reprobe.py --long --pairs 200"
              "  # 低成本行为层重探（32 次调用）")
        print("  3) bash gatekeeper-cli.sh model-probe --meta '%s'"
              % json.dumps(meta, ensure_ascii=False, separators=(",", ":")))
        print("     # resolved=false ⟹ 需行为层：追加 --series '<L=0..n-1 的观测>'"
              " 或 --known-strides '<fingerprint→S>'")
        print("  4) 回填 PINNED.stride_S / stride_S_source_fingerprint / "
              "system_fingerprint，再重跑 NIAH screening")
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Model artifact shelf-life checks")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="offline checks (optionally --online / --fingerprint)")
    c.add_argument("--online", action="store_true")
    c.add_argument("--fingerprint", action="store_true", help="最小 API 调用取 system_fingerprint")
    c.add_argument("--path", help="override tokenizer.json path")
    sub.add_parser("refresh", help="download latest tokenizer.json -> cache")
    g = sub.add_parser("guard", help="drift gate: online + live fingerprint（cron/CI 用）")
    g.add_argument("--path", help="override tokenizer.json path")
    g.add_argument("--allow-stale-phase", action="store_true",
                   help="已知 stride_S_freshness 过期时记 WARN，不阻塞定时 guard")
    u = sub.add_parser("upgrade", help="refresh + guard")
    u.add_argument("--path", help="override tokenizer.json path")
    args = ap.parse_args(argv)
    if args.cmd == "refresh":
        refresh()
        return 0
    if args.cmd == "upgrade":
        refresh()
        return run_check(online=True, fingerprint=True, path=getattr(args, "path", None))
    if args.cmd == "guard":
        return run_check(online=True, fingerprint=True,
                         path=getattr(args, "path", None),
                         allow_stale_phase=getattr(args, "allow_stale_phase",
                                                   False))
    return run_check(online=getattr(args, "online", False),
                     fingerprint=getattr(args, "fingerprint", False),
                     path=getattr(args, "path", None))


if __name__ == "__main__":
    raise SystemExit(main())
