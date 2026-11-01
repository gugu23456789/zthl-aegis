"""test_gk_seal_chain_b_attack.py — 对 B（state 钉头）的**攻击实验**（决策证据，非生产实现）。

背景（owner 2026-10-27：「针对 B 做攻击测试；A 与 B 应配合但不能过度工程」）：
  · A = D3a 本地封印链（`test_gk_seal_chain.py`，已生产落刀）；
  · B = 把链头钉进 state（`gate_data.ledger_head`）——本文件**只在测试里模拟**，
    不新增生产写点。目的是量出 B 的**边际检出**与**代价/失效面**，再决定是否值得。

结论（本文件即证据）：
  · B 唯一新增检出 = 「只回放账本目录（账本+封印+链），state 未回滚」；
  · state 与账本同目录、同一备份恢复 ⟹ 该场景在单机运维下**不是独立威胁**；
  · B **fail-open**：删掉/回滚 pin 即失效；且新增一个写面与锁耦合；
  · ⟹ B **不进生产**；审计序列只把它作为**对抗臂**定期跑（见计划 §26.6 / D3a）。
"""
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_budget_ledger as B  # noqa: E402


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


def _chain(state: str) -> list:
    p = Path(str(state) + B.SEAL_SUFFIX + B.CHAIN_SUFFIX)
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _snapshot(state: str) -> dict:
    return {
        "ledger": Path(str(state) + B.SUFFIX).read_bytes(),
        "seal": Path(str(state) + B.SEAL_SUFFIX).read_bytes(),
        "chain": Path(str(state) + B.SEAL_SUFFIX + B.CHAIN_SUFFIX).read_bytes(),
    }


def _restore(state: str, snap: dict, *, chain: bool = True) -> None:
    Path(str(state) + B.SUFFIX).write_bytes(snap["ledger"])
    Path(str(state) + B.SEAL_SUFFIX).write_bytes(snap["seal"])
    if chain:
        Path(str(state) + B.SEAL_SUFFIX + B.CHAIN_SUFFIX).write_bytes(snap["chain"])


def _append(state: str, keys: str) -> None:
    r = B.append(state, "advance", reason="b-attack",
                 eb={"max": 16, "used": 1, "remaining": 15}, key_dir=keys)
    assert r["ok"] is True, r


def _pin_path(state: str) -> Path:
    return Path(str(state) + ".ledger-head.pin")


def _pin_write(state: str) -> None:
    """模拟 B 的写侧：把当前链头钉进（独立的）pin 文件；生产方案会写进 state。"""
    head = _chain(state)[-1]
    _pin_path(state).write_text(json.dumps({"seq": head["seq"], "seal": head["seal"]}),
                                encoding="utf-8")


def _b_verdict(state: str) -> str:
    """模拟 B 的检侧：pin 不存在 ⟹ fail-open（`no_pin`）。"""
    pin_p = _pin_path(state)
    if not pin_p.exists():
        return "no_pin"
    pin = json.loads(pin_p.read_text(encoding="utf-8"))
    head = _chain(state)[-1]
    if int(head["seq"]) < int(pin["seq"]):
        return "head_regressed"
    if int(head["seq"]) == int(pin["seq"]) and head["seal"] != pin["seal"]:
        return "head_regressed"
    return "ok"


def _a_verdict(state: str, keys: str) -> dict:
    return B.verify_seal_at(Path(str(state) + B.SUFFIX), Path(str(state) + B.SEAL_SUFFIX),
                            keys, require_chain=True)


# ── ① B 的唯一新增检出：只回放账本目录（pin 保留）────────────────────────────
def test_b_only_gain_is_ledger_dir_only_restore(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    snap = _snapshot(st)
    _append(st, keys)
    _pin_write(st)                                # pin 钉在 v2
    _restore(st, snap, chain=True)                # 账本 + 封印 + 链 全退回 v1

    assert _a_verdict(st, keys)["ok"] is True, "A 对三件套整体回放本应不可检出（已知盲区）"
    assert _b_verdict(st) == "head_regressed", "B 的边际价值应仅限此场景"


# ── ② 共同盲区：state（pin）与账本一起回滚 ⟹ A/B 都不可检出 ─────────────────
def test_b_and_a_are_both_blind_when_state_rolled_back(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    snap = _snapshot(st)
    _pin_write(st)
    old_pin = _pin_path(st).read_bytes()
    _append(st, keys)
    _pin_write(st)

    _restore(st, snap, chain=True)                # 账本三件套回滚
    _pin_path(st).write_bytes(old_pin)            # pin 也回滚（= state 一起被恢复）

    assert _a_verdict(st, keys)["ok"] is True
    assert _b_verdict(st) == "ok", "pin 与账本同源回滚 ⟹ B 不提供任何额外检出"


# ── ③ A 已覆盖的场景，B 不增边际：只回放账本（封印/链保留）──────────────────
def test_b_adds_nothing_when_a_already_catches(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    snap = _snapshot(st)
    _append(st, keys)
    _pin_write(st)

    Path(str(st) + B.SUFFIX).write_bytes(snap["ledger"])   # 只回放账本正文
    assert _a_verdict(st, keys)["ok"] is False, "A 应检出封印/链与正文不一致"
    assert _b_verdict(st) in ("head_regressed", "ok")       # B 不改变结论面


# ── ④ B 的失效面：pin 被删 ⟹ fail-open ───────────────────────────────────────
def test_b_fails_open_when_pin_deleted(tmp_path, keys):
    st = _state(tmp_path)
    _append(st, keys)
    _pin_write(st)
    _pin_path(st).unlink()
    assert _b_verdict(st) == "no_pin", "B 在 pin 缺失时 fail-open（删 pin 即绕过）"
