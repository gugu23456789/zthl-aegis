#!/usr/bin/env python3
"""审计署交付门 D2 红先臂：`outcome` producer（判据4a 生产端）。

缺陷（D2 立项时点）：`gk_credit_ledger.append` 已能校验 outcome 三参数并落行，但**无生产者**
—— 没有任何代码把待审 `raise` 变成 `success` / `fail` / `overspend`。判据4 只有消费端没有生产端。

本批（D2 骨架）：
  · 生产者 = 本地 StartLux-Decision `/v1/systemone` 客户端（typed choice：三选项 = OUTCOME_KINDS）；
  · 落行经 `gk_credit_ledger.append`（ref + model_version/temperature/seed + Ed25519 封印）；
  · **fail-closed**：raise 不存在 / 非 raise 行 / 后端异常 / 决策不在三态内 / 模型版本不可判
    ⟹ 一律不写账本（禁默造 outcome）。

臂（HEAD 必红：`gk_audit_outcome` 模块不存在）：
  · arm1 未知 raise ⟹ 拒，账本零写
  · arm2 后端异常 ⟹ 拒，账本零写
  · arm3 决策不在三态 ⟹ 拒，账本零写
  · arm4 非 raise 行（如 success）⟹ 拒，账本零写
  · arm5 正常路径 ⟹ 落行（ref + 三参数）+ Ed25519 真验签
  · arm6 请求体是 typed choice（三 criteria + think_mode 透传）
  · arm7 `--dry-run` ⟹ 不写账本
"""
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_audit_outcome as O  # noqa: E402
import gk_credit_ledger as C  # noqa: E402


@pytest.fixture()
def keys(tmp_path):
    """临时 Ed25519 audit key（不依赖仓库 `.keys` ⟹ CI/Windows 可移植）。"""
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


def _state_with(tmp_path: Path, records) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text("{}\n", encoding="utf-8", newline="\n")
    led = Path(str(st) + C.SUFFIX)
    led.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
                   encoding="utf-8", newline="\n")
    return str(st)


def _raise_rec(rid="R-1"):
    return {"ts": "2026-10-21T00:00:00Z", "id": rid, "kind": "raise", "delta": 0,
            "source": "budget_override", "reason": "budget exhausted"}


def _resp(choice="success", conf=0.93, model="startlux-4b-autothink"):
    return {"answers": {"outcome": {"type": "choice", "choice": choice,
                                    "confidence": conf,
                                    "probabilities": {"success": 0.93, "fail": 0.05,
                                                      "overspend": 0.02}}},
            "model": model}


def _no_write(tmp_path: Path, state: str) -> None:
    led = Path(str(state) + C.SUFFIX)
    assert len(led.read_text(encoding="utf-8").splitlines()) == 1, "禁写账本"


def test_arm1_unknown_raise_fails_closed(tmp_path, keys, monkeypatch):
    st = _state_with(tmp_path, [_raise_rec("R-1")])
    monkeypatch.setattr(O, "_post_json", lambda *a, **k: _resp())
    out = O.produce(st, "R-404", endpoint="http://127.0.0.1:9", key_dir=keys)
    assert out["ok"] is False and "raise_not_found" in out["error"], out
    _no_write(tmp_path, st)


def test_arm2_backend_error_fails_closed(tmp_path, keys, monkeypatch):
    st = _state_with(tmp_path, [_raise_rec()])

    def _boom(*a, **k):
        raise O.BackendError("connection refused")

    monkeypatch.setattr(O, "_post_json", _boom)
    out = O.produce(st, "R-1", endpoint="http://127.0.0.1:9", key_dir=keys)
    assert out["ok"] is False and "backend_error" in out["error"], out
    _no_write(tmp_path, st)


def test_arm3_invalid_decision_fails_closed(tmp_path, keys, monkeypatch):
    st = _state_with(tmp_path, [_raise_rec()])
    monkeypatch.setattr(O, "_post_json", lambda *a, **k: _resp(choice="maybe"))
    out = O.produce(st, "R-1", endpoint="http://127.0.0.1:9", key_dir=keys)
    assert out["ok"] is False and "invalid_decision" in out["error"], out
    _no_write(tmp_path, st)


def test_arm4_non_raise_record_fails_closed(tmp_path, keys, monkeypatch):
    rec = dict(_raise_rec(), kind="success")
    st = _state_with(tmp_path, [rec])
    monkeypatch.setattr(O, "_post_json", lambda *a, **k: _resp())
    out = O.produce(st, "R-1", endpoint="http://127.0.0.1:9", key_dir=keys)
    assert out["ok"] is False and "not_a_raise" in out["error"], out
    _no_write(tmp_path, st)


def test_arm5_writes_outcome_with_ref_params_and_seal(tmp_path, keys, monkeypatch):
    st = _state_with(tmp_path, [_raise_rec()])
    monkeypatch.setattr(O, "_post_json", lambda *a, **k: _resp())
    out = O.produce(st, "R-1", endpoint="http://127.0.0.1:9", key_dir=keys,
                    temperature=0.0, seed=0)
    assert out["ok"] is True, out
    recs, _ = C.read_records(st)
    last = recs[-1]
    assert last["kind"] == "success" and last["ref"] == "R-1", last
    assert last["model_version"] == "startlux-4b-autothink", last
    assert last["temperature"] == 0.0 and last["seed"] == 0, last
    assert C.verify_seal(st, key_dir=keys, require_ed25519=True)["ok"] is True


@pytest.mark.parametrize("choice,delta", [("success", 5), ("fail", -15), ("overspend", -10)])
def test_arm5b_three_states_end_to_end(tmp_path, keys, monkeypatch, choice, delta):
    """D2 三态端到端：success / fail / overspend 各一臂（落行 + ref + 三参数 + 真验签）。

    说明：本臂用**本地 stub**（与 arm1–7 同口径）证明 producer 的三条路径；真实
    `/v1/systemone` 端点实跑另记（见审计署 §24 / §26）。
    """
    st = _state_with(tmp_path, [_raise_rec()])
    monkeypatch.setattr(O, "_post_json", lambda *a, **k: _resp(choice=choice))
    out = O.produce(st, "R-1", endpoint="http://127.0.0.1:9", key_dir=keys,
                    temperature=0.0, seed=0)
    assert out["ok"] is True, out
    assert out["decision"] == choice, out
    recs, _ = C.read_records(st)
    last = recs[-1]
    assert last["kind"] == choice and last["ref"] == "R-1", last
    assert last["delta"] == delta, last
    assert last["model_version"] and last["temperature"] == 0.0 and last["seed"] == 0, last
    assert C.verify_seal(st, key_dir=keys, require_ed25519=True)["ok"] is True


def test_arm5c_second_produce_same_raise_is_rejected(tmp_path, keys, monkeypatch):
    """D5 × D2 交叉臂：同一 raise 二次产出必须被「一债一票」拦下，且账本不增行。"""
    st = _state_with(tmp_path, [_raise_rec()])
    monkeypatch.setattr(O, "_post_json", lambda *a, **k: _resp(choice="success"))
    first = O.produce(st, "R-1", endpoint="http://127.0.0.1:9", key_dir=keys)
    assert first["ok"] is True, first
    n0 = len(Path(str(st) + C.SUFFIX).read_text(encoding="utf-8").splitlines())
    second = O.produce(st, "R-1", endpoint="http://127.0.0.1:9", key_dir=keys)
    assert second["ok"] is False, second
    assert "duplicate_outcome_ref" in str(second.get("error")), second
    n1 = len(Path(str(st) + C.SUFFIX).read_text(encoding="utf-8").splitlines())
    assert n1 == n0, "被拒的重复 outcome 仍落盘: %d -> %d" % (n0, n1)


def test_arm6_request_is_typed_choice_with_think_mode(tmp_path, keys, monkeypatch):
    st = _state_with(tmp_path, [_raise_rec()])
    seen = {}

    def _capture(url, payload, timeout=30):
        seen.update(payload)
        seen["_url"] = url
        return _resp()

    monkeypatch.setattr(O, "_post_json", _capture)
    out = O.produce(st, "R-1", endpoint="http://127.0.0.1:8091", key_dir=keys,
                    think_mode="auto")
    assert out["ok"] is True, out
    q = seen["questions"]["outcome"]
    assert q["type"] == "choice", q
    assert sorted(q["criteria"]) == sorted(C.OUTCOME_KINDS), q
    assert seen["think_mode"] == "auto", seen
    assert seen["state"]["raise"]["id"] == "R-1", seen
    assert seen["_url"].endswith("/v1/systemone"), seen["_url"]


def test_arm7_dry_run_does_not_write(tmp_path, keys, monkeypatch):
    st = _state_with(tmp_path, [_raise_rec()])
    monkeypatch.setattr(O, "_post_json", lambda *a, **k: _resp())
    out = O.produce(st, "R-1", endpoint="http://127.0.0.1:9", key_dir=keys, dry_run=True)
    assert out["ok"] is True and out["dry_run"] is True, out
    _no_write(tmp_path, st)


def test_arm8_cli_resolves_instant_to_never(monkeypatch):
    """Instant 后端对 `think_mode=auto` 返回 422 ⟹ CLI 按 /health 降级为 never（不静默）。"""
    seen = {}
    monkeypatch.setattr(O, "probe", lambda *a, **k: {"ok": True, "kind": "instant"})
    monkeypatch.setattr(O, "produce",
                        lambda *a, **k: (seen.update(k), {"ok": True})[1])
    rc = O.main(["produce", "--state", "s", "--raise-id", "R-1",
                 "--endpoint", "http://127.0.0.1:9"])
    assert rc == 0, seen
    assert seen.get("think_mode") == "never", seen


def test_arm9_cli_keeps_auto_on_autothink(monkeypatch):
    seen = {}
    monkeypatch.setattr(O, "probe", lambda *a, **k: {"ok": True, "kind": "autothink"})
    monkeypatch.setattr(O, "produce",
                        lambda *a, **k: (seen.update(k), {"ok": True})[1])
    rc = O.main(["produce", "--state", "s", "--raise-id", "R-1",
                 "--endpoint", "http://127.0.0.1:9"])
    assert rc == 0 and seen.get("think_mode") == "auto", seen
