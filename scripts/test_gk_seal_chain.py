"""test_gk_seal_chain.py — D3a 红先臂：本地单调序号 + `prev_hash` 链。

缺口（审计署 §26.6 owner 裁 D3a「该做」）：原封印只覆盖**当前**账本摘要 ⟹
把「旧账本 + 旧封印」成对回放进来，digest 与签名都自洽，`verify_seal` 照绿。

本切片（A 方案）：
  · 每次 `seal_now` / `seal_edits` 都写 `seq` + `prev_seal`，并 append 一条链日志
    `<seal>.seal-chain.jsonl`（append-only）；
  · `verify_seal_at(require_chain=True)` 校验：`seq` 连续、`prev` 链接、**当前封印 == 链头**；
  · 默认 `require_chain=False` 容忍 legacy（无链 ⟹ `chain=legacy`，不判红）。

诚实边界（本文件最后两臂）：**三件套（账本+封印+链）整体回放**仍不可检出 ——
这是单机防呆口径的已知盲区，不靠 B（state 钉头）在生产面加写点来掩盖。
"""
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_budget_ledger as B  # noqa: E402
import gk_credit_ledger as C  # noqa: E402


@pytest.fixture()
def keys(tmp_path):
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d = tmp_path / "keys"
    d.mkdir()
    priv = Ed25519PrivateKey.generate()
    (d / "audit_ed25519.pem").write_bytes(priv.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    (d / "audit_ed25519.pub").write_bytes(priv.public_key().public_bytes(
        ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    return str(d)


def _state(tmp_path) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text("{}\n", encoding="utf-8")
    return str(st)


def _chain_path(state: str, suffix: str = None) -> Path:
    return Path(str(state) + (suffix or B.SEAL_SUFFIX) + B.CHAIN_SUFFIX)


def _read_chain(state: str, suffix: str = None) -> list:
    return [json.loads(x) for x in _chain_path(state, suffix).read_text(encoding="utf-8").splitlines() if x.strip()]


def _append(state: str, keys: str) -> dict:
    return B.append(state, "advance", reason="chain-arm",
                    eb={"max": 16, "used": 1, "remaining": 15}, key_dir=keys)


def _snapshot(state: str) -> tuple:
    led = Path(str(state) + B.SUFFIX).read_bytes()
    seal = Path(str(state) + B.SEAL_SUFFIX).read_bytes()
    chain = _chain_path(state).read_bytes()
    return led, seal, chain


def _restore(state: str, snap: tuple, *, chain: bool = True) -> None:
    led, seal, ch = snap
    Path(str(state) + B.SUFFIX).write_bytes(led)
    Path(str(state) + B.SEAL_SUFFIX).write_bytes(seal)
    if chain:
        _chain_path(state).write_bytes(ch)


# ── ① 首封印 = 链的 genesis（seq=1 / prev=""）────────────────────────────────
def test_first_seal_starts_chain_genesis(tmp_path, keys):
    st = _state(tmp_path)
    r = _append(st, keys)
    assert r["ok"] is True, r
    ch = _read_chain(st)
    assert len(ch) == 1 and ch[0]["seq"] == 1 and ch[0]["prev"] == "", ch
    v = B.verify_seal_at(Path(str(st) + B.SUFFIX), Path(str(st) + B.SEAL_SUFFIX),
                         keys, require_ed25519=True, require_chain=True)
    assert v["ok"] is True and v.get("chain") == "verified", v


# ── ② 第二次封印与链头链接（seq 单调 + prev == 上一条 seal 摘要）──────────────
def test_second_seal_links_previous(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    _append(st, keys)
    ch = _read_chain(st)
    assert [x["seq"] for x in ch] == [1, 2], ch
    assert ch[1]["prev"] == ch[0]["seal"], ch
    v = B.verify_seal_at(Path(str(st) + B.SUFFIX), Path(str(st) + B.SEAL_SUFFIX),
                         keys, require_chain=True)
    assert v["ok"] is True and v.get("seq") == 2, v


# ── ③ legacy 封印：默认容忍（chain=legacy），严格模式判红 chain_missing ────────
def test_legacy_seal_is_lenient_by_default_and_strict_on_demand(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    _chain_path(st).unlink()                      # 模拟升级前的旧封印
    seal_p = Path(str(st) + B.SEAL_SUFFIX)
    rec = json.loads(seal_p.read_text(encoding="utf-8"))
    rec.pop("seq", None)
    rec.pop("prev_seal", None)
    seal_p.write_text(json.dumps(rec, ensure_ascii=False) + "\n", encoding="utf-8")

    lenient = B.verify_seal_at(Path(str(st) + B.SUFFIX), seal_p, keys)
    assert lenient["ok"] is True and lenient.get("chain") == "legacy", lenient

    strict = B.verify_seal_at(Path(str(st) + B.SUFFIX), seal_p, keys, require_chain=True)
    assert strict["ok"] is False and strict["reason"] == "chain_missing", strict


# ── ④ 旧账本+旧封印回放（链保留）⟹ seal_not_head ────────────────────────────
def test_old_pair_replay_with_chain_kept_is_detected(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    snap = _snapshot(st)
    _append(st, keys)                             # 链头推进到 seq=2
    _restore(st, snap, chain=False)               # 只回放账本+封印，链仍是 2 条
    v = B.verify_seal_at(Path(str(st) + B.SUFFIX), Path(str(st) + B.SEAL_SUFFIX),
                         keys, require_chain=True)
    assert v["ok"] is False and v["reason"] == "seal_not_head", v


# ── ⑤ 链被截断（删最后一行）⟹ 当前封印不再是链头 ─────────────────────────────
def test_chain_truncation_is_detected(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    _append(st, keys)
    ch = _read_chain(st)
    _chain_path(st).write_text(json.dumps(ch[0], ensure_ascii=False) + "\n", encoding="utf-8")
    v = B.verify_seal_at(Path(str(st) + B.SUFFIX), Path(str(st) + B.SEAL_SUFFIX),
                         keys, require_chain=True)
    assert v["ok"] is False and v["reason"] in ("seal_not_head", "seq_mismatch"), v


# ── ⑥ 链内 prev 被篡改 ⟹ chain_prev_mismatch ────────────────────────────────
def test_chain_prev_tamper_is_detected(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    _append(st, keys)
    ch = _read_chain(st)
    ch[1]["prev"] = "0" * 64
    _chain_path(st).write_text(
        "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in ch), encoding="utf-8")
    v = B.verify_seal_at(Path(str(st) + B.SUFFIX), Path(str(st) + B.SEAL_SUFFIX),
                         keys, require_chain=True)
    assert v["ok"] is False and v["reason"] == "chain_prev_mismatch", v


# ── ⑦ 信用账本同源接线（consumer arm）────────────────────────────────────────
def test_credit_ledger_append_grows_chain(tmp_path, keys):
    st = _state(tmp_path)
    r = C.append(st, "raise", source="arm", reason="t", key_dir=keys)
    assert r["ok"] is True, r
    assert len(_read_chain(st, C.SEAL_SUFFIX)) == 1
    v = C.verify_seal(st, key_dir=keys, require_ed25519=True)
    assert v["ok"] is True, v
    strict = B.verify_seal_at(C._logical_path(st), C._seal_path(st), keys, require_chain=True)
    assert strict["ok"] is True and strict.get("seq") == 1, strict


# ── ⑧ 已知盲区（诚实边界）：三件套整体回放仍不可检出 ─────────────────────────
def test_full_triple_rollback_is_known_blind_spot(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    snap = _snapshot(st)
    _append(st, keys)
    _restore(st, snap, chain=True)                # 账本 + 封印 + 链 一起回放
    v = B.verify_seal_at(Path(str(st) + B.SUFFIX), Path(str(st) + B.SEAL_SUFFIX),
                         keys, require_chain=True)
    assert v["ok"] is True, (
        "三件套整体回放本应不可检出（单机防呆口径的已知盲区）；"
        "若此处变红，说明新增了链外锚点 —— 请同步更新 §26.6 与威胁模型")
