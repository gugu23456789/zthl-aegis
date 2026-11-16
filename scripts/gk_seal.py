#!/usr/bin/env python3
"""gk_seal.py — 密封分（`_sealed_agent_score`）完整性哈希（RED-SCOPE-02 真修，2026-11-12）。

病象（红队 `red_scope` 实测）：`gate_data._sealed_agent_score` 有 `score` / `verdicts` /
`conclusion`，却**无任何完整性字段** ⟹ 任何能写 state 的路径（含编辑器/脚本/误操作）
都可静默改动盲评结论，adjudicate / appeal / mediation 三个消费者无从判别「这份密封分
是否就是监控面当初写下的那份」。

修法：seal 落盘时附 `hash = sha256(canonical_json(seal 除 hash 以外的键))`；
消费侧 `verify()` 重算比对。单源 = 本模块（写侧 `apply` / 读侧 `verify`，禁第二处实现）。

口径：
  · 规范化 = `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)` —— 与键序、
    空白、缩进无关（同一内容的多次落盘哈希相同）。
  · `hash` 字段自身**不参与**摘要（否则自指）。
  · `verify()` 对「无 hash / 非 dict」一律 False（= 未盖戳或盖戳失败，交由调用方按
    未密封/已篡改分别处置）。
"""
import hashlib
import json

PREFIX = "sha256:"


def digest(seal) -> str:
    """seal 内容（除 `hash`）的规范化 SHA256，形如 `sha256:<hex>`。"""
    body = {k: v for k, v in dict(seal or {}).items() if k != "hash"}
    blob = json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)
    return PREFIX + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def apply(seal):
    """就地给 seal 盖戳（非 dict 原样返回），返回同一个对象。"""
    if isinstance(seal, dict):
        seal["hash"] = digest(seal)
    return seal


def verify(seal) -> bool:
    """seal 是否携带**与当前内容一致**的哈希（无 hash / 非 dict ⟹ False）。"""
    if not isinstance(seal, dict) or not seal.get("hash"):
        return False
    return seal.get("hash") == digest(seal)
