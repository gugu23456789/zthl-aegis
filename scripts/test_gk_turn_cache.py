#!/usr/bin/env python3
"""红先臂：运行时 turns/prefix 观测量（二条件 (b)，`gk_turn_cache`）。

背景（D 子计划 §14.7.9）：现有 `gk_cache_observe` 只做**事后**归一；「turns 机制精细化升级」
要求显式管理相位生效轮次 / 追加语义 / 块对齐 / cache 失效监测。本模块提供零 API 原语。

**红先对照**：HEAD 无 `gk_turn_cache` ⟹ 本文件整体 ImportError/AttributeError 必红。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_turn_cache as T  # noqa: E402


def test_prefix_fingerprint_stable_and_sensitive():
    """前缀指纹：同 instructions/tools 稳定；任一变化 ⟹ 变。"""
    tools = [{"name": "read", "description": "read a file"}]
    a = T.prefix_fingerprint("SYS", tools)
    b = T.prefix_fingerprint("SYS", tools)
    c = T.prefix_fingerprint("SYS2", tools)
    assert a == b and a != c
    assert len(a) == 16


def test_phase_effective_schedule():
    """相位生效轮：stride=2 ⟹ 1,3,5…；臂偏移 l0 平移相位；stride 空/0 ⟹ None（不冒充）。"""
    assert [T.phase_effective(r, 2) for r in (1, 2, 3, 4)] == [True, False, True, False]
    assert [T.phase_effective(r, 2, 1) for r in (1, 2, 3, 4)] == [False, True, False, True]
    assert T.phase_effective(1, "") is None and T.phase_effective(1, 0) is None
    assert T.phase_effective(1, "x") is None


def test_phase_l_matches_filler_sweep():
    """L 口径：`(l0+round-1) mod n`；round 非法 / l0 非法 ⟹ None。"""
    assert T.phase_l(1) == 0 and T.phase_l(17) == 0
    assert T.phase_l(3, l0=2, n_lengths=16) == 4
    assert T.phase_l(1, l0=0, n_lengths=0) == 0        # n<=0 ⟹ 不封顶
    assert T.phase_l(20, l0=0, n_lengths=0) == 19
    assert T.phase_l(0) is None and T.phase_l(1, l0="x") is None


def test_annotate_calls_prefix_change_and_invalidation():
    """逐调用：prefix 变化 / cacheRead 下坠 各自留痕；相位生效轮计数。"""
    calls = [
        {"round": 1, "prefix_hash": "a", "prompt_cache_hit_tokens": 100,
         "prompt_cache_miss_tokens": 20},
        {"round": 2, "prefix_hash": "a", "prompt_cache_hit_tokens": 90,
         "prompt_cache_miss_tokens": 30},
        {"round": 3, "prefix_hash": "b", "prompt_cache_hit_tokens": 200,
         "prompt_cache_miss_tokens": 10},
    ]
    out, s = T.annotate_calls(calls, stride=2)
    assert out[0]["prefix_changed"] is False and out[0]["phase_effective"] is True
    assert out[1]["cache_invalidated"] is True and out[1]["prefix_changed"] is False
    assert out[2]["prefix_changed"] is True and out[2]["phase_effective"] is True
    assert [c["phase_l"] for c in out] == [0, 1, 2]
    assert s["prefix_changes"] == 1 and s["invalidations"] == 1 and s["phase_effective_turns"] == 2
    assert s["prefix_hashes"] == ["a", "b"]


def test_tokenizer_unavailable_is_named_unknown():
    """无 tokenizer ⟹ `token_length` 返回 None（禁止字符长度冒充 token）。"""
    st = T.tokenizer_status()
    assert "available" in st and "backend" in st
    if not st["available"]:
        assert T.token_length("hello world") is None
        assert "reason" in st


def test_token_length_official_tokenizer_file(tmp_path, monkeypatch):
    """官方 tokenizer.json（tokenizers 后端）可装载并给出真 token 数。"""
    pytest.importorskip("tokenizers")
    from tokenizers import Tokenizer, models, pre_tokenizers

    tok = Tokenizer(models.WordLevel({"hello": 0, "world": 1, "[UNK]": 2},
                                     unk_token="[UNK]"))
    tok.pre_tokenizer = pre_tokenizers.Whitespace()
    path = tmp_path / "tokenizer.json"
    tok.save(str(path))
    monkeypatch.setenv(T.TOKENIZER_ENV, str(path))
    st = T.tokenizer_status()
    assert st["available"] is True and st["backend"] == "tokenizers"
    assert T.token_length("hello world") == 2
    assert T.token_length("") == 0


def test_filler_single_source():
    """装饰 filler **单源**：探针与运行时注入逐字一致（禁第二实现）。

    2026-11-04：`gk_phase_probe` 属导出排除面（公开包不随附）⟹ 模块不在场时**具名 skip**
    （`ModuleNotFoundError` 不再是公开树的全量红灯）；私仓照常跑真断言。
    """
    P = pytest.importorskip("gk_phase_probe", reason="phase 族不随公开包")
    for n in (0, 1, 5, 16):
        assert P.filler(n) == T.filler(n)


def test_filler_length_roundtrip():
    """filler 解析单源：新口径往返一致；旧 `=` 连续串仍可解析。"""
    for n in (0, 1, 2, 5, 16, 32):
        assert T.filler_length(T.filler(n)) == n
    assert T.filler_length("\n" + "=" * 7 + "\n") == 7


def test_filler_one_token_per_unit_with_official_v41():
    """官方 V4.1 词表：`filler(n)` 恰为 n token，且前缀位移恰为 n（红先：旧 `"="*n` 恒 1）。"""
    pytest.importorskip("tokenizers")
    if not os.path.isfile(T.DEFAULT_TOKENIZER_PATH):
        pytest.skip("官方 tokenizer.json 未下载（先跑 gk_model_shelf.py refresh）")
    from tokenizers import Tokenizer
    tok = Tokenizer.from_file(T.DEFAULT_TOKENIZER_PATH)
    assert [len(tok.encode(T.filler(n)).ids) for n in (0, 1, 2, 4, 8, 16, 32)] \
        == [0, 1, 2, 4, 8, 16, 32]
    base = "The quick brown fox jumps over the lazy dog. " * 20
    b = len(tok.encode(base).ids)
    assert [len(tok.encode(T.filler(n) + base).ids) - b for n in (0, 1, 8, 16)] == [0, 1, 8, 16]


def test_phase_suffix_follows_filler_l():
    """干预载荷：长度/标记由相位档 L 决定（与 NIAH filler 扫描同源）；臂偏移平移 L。"""
    s1 = T.phase_suffix(1, 2, "D", l0=0, n_lengths=16)
    assert s1.startswith(T.filler(0)) and "L=0" in s1 and "S=2" in s1 and "D" in s1
    s3 = T.phase_suffix(3, 2, "D", l0=0, n_lengths=16)
    assert s3.startswith(T.filler(2)) and "L=2" in s3
    assert T.phase_suffix(17, 2, "D", l0=0, n_lengths=16) == s1      # 封顶循环
    assert "L=2" in T.phase_suffix(1, 2, "D", l0=2, n_lengths=16)    # 臂偏移 i·Δ
    assert T.phase_suffix(1, "", "D") == ""                          # stride 未声明
    assert T.phase_suffix(1, "x", "D") == ""                         # stride 非法
    assert T.phase_suffix(1, 2, "   ") == ""                         # 空 directive


def test_install_phase_scheduler_appends_tail_only():
    """干预层：每轮按 L 向工具输出**尾部**追加；前缀指纹不变；非 str 输出不动。"""
    import asyncio
    import subagent_runner as R

    class _Tool:
        name = "read"
        description = "read a file"

        async def on_invoke_tool(self, ctx, args):
            return "TOOL_OK"

    class _DictTool(_Tool):
        async def on_invoke_tool(self, ctx, args):
            return {"ok": True}

    t, dt = _Tool(), _DictTool()
    before = T.prefix_fingerprint("SYS", [t])
    assert R._install_phase_scheduler(
        [t, dt], directive="PHASE-DIRECTIVE", stride="2", l0="0", n_lengths="16") == 2
    assert T.prefix_fingerprint("SYS", [t]) == before   # 前缀指纹不受干预影响
    u = R._BUDGET["usage"]
    old_rounds, old_inj = u["rounds"], u["phase_injections"]
    try:
        u["phase_injections"] = 0
        u["rounds"] = 1                                  # L=0
        out1 = asyncio.run(t.on_invoke_tool(None, "{}"))
        assert out1.startswith("TOOL_OK") and T.filler(0) in out1
        assert "[phase L=0 S=2] PHASE-DIRECTIVE" in out1
        u["rounds"] = 2                                  # L=1
        out2 = asyncio.run(t.on_invoke_tool(None, "{}"))
        assert T.filler(1) in out2 and "[phase L=1 S=2]" in out2
        u["rounds"] = 3                                  # L=2
        assert asyncio.run(dt.on_invoke_tool(None, "{}")) == {"ok": True}
        assert u["phase_injections"] == 2                # 非 str 不计入
    finally:
        u["rounds"], u["phase_injections"] = old_rounds, old_inj


def test_install_phase_scheduler_default_off():
    """缺省（无 directive / 无 stride）⟹ 不包装，工具输出逐字不变。"""
    import asyncio
    import subagent_runner as R

    class _Tool:
        name = "read"
        description = "read a file"

        async def on_invoke_tool(self, ctx, args):
            return "TOOL_OK"

    t = _Tool()
    assert R._install_phase_scheduler([t], directive="", stride="2") == 0
    u = R._BUDGET["usage"]
    old_rounds, old_inj = u["rounds"], u["phase_injections"]
    try:
        u["phase_injections"] = 0
        u["rounds"] = 1
        assert asyncio.run(t.on_invoke_tool(None, "{}")) == "TOOL_OK"
        assert u["phase_injections"] == 0
    finally:
        u["rounds"], u["phase_injections"] = old_rounds, old_inj

