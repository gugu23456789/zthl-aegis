#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""运行时 turns/prefix 观测（W2A-P2 §6.3(6) 二条件 (b)，2026-10-17）。

背景（D 子计划 §14.7.9）：现有 `gk_cache_observe` 只做**事后**归一；「turns 机制精细化升级」
要求 800+ 轮里**显式管理**相位生效轮次 / 追加语义 / 块对齐 / cache 失效监测。本模块提供
**零 API 的运行时记账原语**，供 `subagent_runner._BudgetHooks` 逐轮调用：

  · `filler(n)` —— 装饰性 `=` 行（**单源**：NIAH 扫描与运行时注入共用；≈ n token）；
  · `prefix_fingerprint(instructions, tools)` —— system + tools 的稳定前缀哈希（不变式证据）；
  · `phase_l(round, l0, n_lengths)` —— 相位档 `L=(l0+round-1) mod n`（l0 = 臂偏移 i·Δ）；
  · `phase_effective(round, stride, l0, n_lengths)` —— `L mod stride == 0`（stride 未声明 ⟹ None）；
  · `phase_suffix(round, stride, directive, l0, n_lengths)` —— 相位**干预载荷**
    （`filler(L)` + L 标记 + directive；append-only 尾附；directive 空 / stride 未声明 ⟹ 空串）；
  · `annotate_calls(calls, stride)` —— 给逐调用 usage 补 `prefix_changed` / `cache_invalidated`
    / `phase_effective`，并汇总 `prefix_changes` / `invalidations` / `phase_effective_turns`；
  · `tokenizer_status()` / `token_length()` —— **无 tokenizer 时返回 `None`（UNKNOWN）**，
    禁止用字符长度冒充 token 长度（块对齐的唯一诚实口径）。

纯函数、无网络、无文件写入。
"""
import hashlib
import json
import os

# 官方 V4.1 tokenizer 缺省缓存位（`gk_model_shelf.py refresh` 写入；env 可覆盖）。
TOKENIZER_ENV = "GK_TOKENIZER_JSON"
DEFAULT_TOKENIZER_PATH = os.path.expanduser(
    "~/.cache/gk-tokenizer/deepseek-v4.1-flash/tokenizer.json")
# transformers 回退路径的模型标识（1017 换代；与 gk_model_shelf.PINNED 同步）。
HF_MODEL_ID = "deepseek-ai/DeepSeek-V4.1-Flash-1017"
_TOK = {"key": None, "obj": None}


def _tool_fields(t):
    if isinstance(t, dict):
        return str(t.get("name", "")), str(t.get("description", ""))
    return str(getattr(t, "name", "")), str(getattr(t, "description", ""))


def filler(n):
    """装饰性无意义行（**单源**：NIAH 扫描与运行时注入共用）：**每单元恰 1 token**。

    口径修正（2026-10-17，V4.1 官方 tokenizer 实测）：旧实现 `"\\n" + "="*n + "\\n"`
    在 V4.1 词表下把整串 `=` 合并成 **1 个 token**（n≥1）⟹ L 扫描退化为常量偏移。
    现实现 `"=" + "\\n"` 重复 n 次；实测 `len(encode(filler(n))) == n`（n=0..32），
    且 `filler(n)+text` 相对 `text` 的 token 位移恰为 n。
    """
    return "=\n" * int(n or 0)


def filler_length(text):
    """解析文本前缀的 filler 单元数（新口径 `=\\n` 重复；兼容旧 `=` 连续串）。"""
    s = str(text or "").lstrip("\n")
    i = n = 0
    while i < len(s) and s[i] == "=":
        n += 1
        i += 1
        if i < len(s) and s[i] == "\n":
            i += 1
    return n


def prefix_fingerprint(instructions="", tools=None, injection_header=""):
    """稳定前缀指纹：instructions + injection header + 每个 tool 的 (name, description)。"""
    parts = [str(instructions or ""), str(injection_header or "")]
    for t in tools or []:
        name, desc = _tool_fields(t)
        parts.append(name + "::" + desc)
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]


def phase_l(round_index, l0=0, n_lengths=16):
    """相位档 `L`：`(l0 + round - 1) mod n_lengths`（臂偏移 `l0` = §6.3(3) 的 `i·Δ`）。

    `n_lengths<=0` ⟹ 不封顶（线性增长）；round 非法 ⟹ `None`（UNKNOWN，不冒充 0）。
    """
    try:
        r = int(round_index)
        base = int(l0 or 0)
        n = int(n_lengths or 0)
    except (TypeError, ValueError):
        return None
    if r <= 0:
        return None
    l = base + r - 1
    return l % n if n > 0 else l


def phase_effective(round_index, stride, l0=0, n_lengths=0):
    """相位生效轮：`stride<=0` ⟹ `None`（未声明，不冒充）；否则 `L mod stride == 0`。"""
    try:
        s = int(stride or 0)
    except (TypeError, ValueError):
        return None
    l = phase_l(round_index, l0, n_lengths)
    if s <= 0 or l is None:
        return None
    return l % s == 0


def phase_suffix(round_index, stride, directive, l0=0, n_lengths=16):
    """相位**干预载荷**（每轮）：`filler(L)` + L 标记 + directive；未声明/空 directive ⟹ 空串。

    `L` 口径与 NIAH filler 扫描同源（`phase_l`），故相位档与注入长度一致；调用方把它
    append 到工具输出末尾（system/tools 前缀不变 ⟹ 缓存前缀不受影响）。
    """
    if not str(directive or "").strip():
        return ""
    if phase_effective(round_index, stride, l0, n_lengths) is None:
        return ""
    l = phase_l(round_index, l0, n_lengths)
    if l is None:
        return ""
    return filler(l) + "[phase L=%d S=%s] %s\n" % (l, stride, str(directive).strip())


def _tokenizer_path():
    return os.environ.get(TOKENIZER_ENV) or DEFAULT_TOKENIZER_PATH


def tokenizer_status():
    """tokenizer 可用性：优先官方 V4.1 词表（`tokenizers`），无则按旧后端，仍无 ⟹ UNKNOWN。"""
    path = _tokenizer_path()
    if os.path.isfile(path):
        try:
            import tokenizers  # noqa: F401
            return {"available": True, "backend": "tokenizers", "path": path}
        except Exception:  # noqa: BLE001 — 文件在但绑定缺失 ⟹ 继续尝试旧后端
            pass
    for name in ("tiktoken", "transformers"):
        try:
            __import__(name)
            return {"available": True, "backend": name, "path": ""}
        except Exception:  # noqa: BLE001 — 缺包/装载失败同判不可用
            continue
    return {"available": False, "backend": "",
            "reason": "no tokenizer backend (gk tokenizer.json / tiktoken / transformers)"}


def token_length(text):
    """token 数；无 tokenizer ⟹ `None`（缺观测量，禁回退 `len(text)`）。"""
    st = tokenizer_status()
    if not st["available"]:
        return None
    try:
        if st["backend"] == "tokenizers":
            from tokenizers import Tokenizer
            path = st["path"]
            key = (path, os.path.getmtime(path))
            if _TOK["key"] != key:
                _TOK["obj"] = Tokenizer.from_file(path)
                _TOK["key"] = key
            return len(_TOK["obj"].encode(str(text)).ids)
        if st["backend"] == "tiktoken":
            import tiktoken
            return len(tiktoken.get_encoding("cl100k_base").encode(str(text)))
        if st["backend"] == "transformers":
            from transformers import AutoTokenizer
            tok = AutoTokenizer.from_pretrained(HF_MODEL_ID)
            return len(tok.encode(str(text)))
        return None
    except Exception:  # noqa: BLE001 — 装载失败不崩，按缺观测处理
        return None


def annotate_calls(calls, stride=None, l0=0, n_lengths=0):
    """逐调用补运行时观测量；返回 `(annotated, summary)`（输入不被修改）。

    `l0` / `n_lengths` 与注入侧同参：相位档 `L` 与 `phase_effective` 由同一口径导出。
    """
    out, prev_prefix, prev_hit = [], None, None
    prefix_changes = invalidations = phase_turns = 0
    for i, c in enumerate(calls or []):
        if not isinstance(c, dict):
            continue
        d = dict(c)
        pf = d.get("prefix_hash")
        d["prefix_changed"] = bool(prev_prefix is not None and pf is not None and pf != prev_prefix)
        if d["prefix_changed"]:
            prefix_changes += 1
        if pf is not None:
            prev_prefix = pf
        hit = int(d.get("prompt_cache_hit_tokens") or 0)
        d["cache_invalidated"] = bool(prev_hit is not None and hit < prev_hit)
        if d["cache_invalidated"]:
            invalidations += 1
        prev_hit = hit
        _round = d.get("round", i + 1)
        d["phase_l"] = phase_l(_round, l0, n_lengths)
        d["phase_effective"] = phase_effective(_round, stride, l0, n_lengths)
        if d["phase_effective"]:
            phase_turns += 1
        out.append(d)
    return out, {"turns": len(out), "prefix_changes": prefix_changes,
                 "invalidations": invalidations, "phase_effective_turns": phase_turns,
                 "phase_turn_stride": stride, "phase_l0": l0,
                 "phase_n_lengths": n_lengths, "tokenizer": tokenizer_status(),
                 "prefix_hashes": sorted({d.get("prefix_hash") for d in out if d.get("prefix_hash")})}


if __name__ == "__main__":
    print(json.dumps(tokenizer_status(), ensure_ascii=False))
