#!/usr/bin/env python3
"""红先臂：R1-b **信用分旁挂账本**（跨会话累积；append-only + 封印）。

来源：`docs/plans/2026-09-18-edit-budget-dual-track-plan.md` §13.5b（R1-b）/ §18。

判据（本臂钉住）：
  · append ⟹ `<state>.credit-ledger.jsonl` 落一条 + 封印重算（`seal_ok=True`）；
  · `score = Σ delta` 且**跨会话**（账本按 state 计，不按会话）；
  · 定价**非对称**：`success +5` / `fail −15` / `overspend −10` / `raise 0`；
  · 篡改账本字节 ⟹ 封印 `digest_mismatch`；
  · **C4 同口径**：坏行（解析失败 / 非对象 / `delta` 非整数）不计入 score。
"""
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import gk_credit_ledger as C  # noqa: E402


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _st(tmp: Path) -> str:
    return str(tmp / ".gatekeeper.state")


def _raw(state: str) -> str:
    return Path(state + C.SUFFIX).read_text(encoding="utf-8")


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


# 判据4a（2026-10-18 收紧）：outcome 行三参数必带 —— 测试统一走本字典，避免漏参。
_OUT = {"model_version": "test-model", "temperature": 0.0, "seed": 0}


# ── arm1：append 落一条 + 封印 ───────────────────────────────────────────────
def test_arm1_append_records_and_seals(tmp_path):
    st = _st(tmp_path)
    out = C.append(st, "raise", source="state_patch", reason="test")
    assert out.get("ok") is True, f"append 失败: {out}"
    assert out["record"]["delta"] == 0, f"raise 应为中性事件(delta=0): {out['record']}"
    assert out.get("score") == 0, f"score 应为 0: {out}"
    assert Path(st + C.SUFFIX).exists(), "账本文件未落地"
    assert C.verify_seal(st).get("ok") is True, f"封印未通过: {C.verify_seal(st)}"


# ── arm2：跨会话累积（账本按 state 计）──────────────────────────────────────
def test_arm2_cross_session_accumulation(tmp_path):
    st = _st(tmp_path)
    C.append(st, "success", source="audit", reason="s1", **_OUT)
    C.append(st, "fail", source="audit", reason="s2", **_OUT)
    assert C.score(st) == -10, f"跨会话累积错（5-15=-10）: {C.score(st)}"


# ── arm3：定价表非对称 ──────────────────────────────────────────────────────
def test_arm3_asymmetric_pricing_table():
    # 2026-10-05（用户令「给豁免加惩罚机制」）：新增 `exempt=-1`（L2 门 `--acknowledge-injected`
    #   逐项豁免的代价）⟹ 本臂期望表同步扩展（定价表仍非对称且逐字受钉）。
    # 2026-10-19（owner 选方案 a）：新增 `bookkeeping=0` —— 预算记账**不是**审计事件，
    #   不得再伪装成 `raise`（待审债）。定价表仍非对称且逐字受钉。
    assert C.DELTA == {"raise": 0, "success": 5, "fail": -15, "overspend": -10,
                       "exempt": -1, "bookkeeping": 0}, \
        f"定价表被改（Sovereign-OS 非对称）: {C.DELTA}"


# ── arm4：篡改 ⟹ 封印失配 ─────────────────────────────────────────────────
def test_arm4_tamper_breaks_seal(tmp_path):
    st = _st(tmp_path)
    C.append(st, "success", source="audit", **_OUT)
    assert C.verify_seal(st).get("ok") is True
    with open(st + C.SUFFIX, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "x", "kind": "success", "delta": 999}) + "\n")
    v = C.verify_seal(st)
    assert v.get("ok") is False and v.get("reason") == "digest_mismatch", f"篡改未被察觉: {v}"


# ── arm5：C4 坏行不计入 ───────────────────────────────────────────────────
def test_arm5_bad_lines_not_counted(tmp_path):
    st = _st(tmp_path)
    C.append(st, "success", source="audit", **_OUT)          # +5
    with open(st + C.SUFFIX, "a", encoding="utf-8") as f:
        f.write("{not json\n")                       # 坏行①：解析失败
        f.write(json.dumps({"ts": "x", "kind": "success", "delta": "NaN"}) + "\n")  # 坏行②：delta 非整数
    recs, stat = C.read_records(st)
    assert stat["bad"] == 2, f"坏行未计入 bad: {stat}"
    assert stat["count"] == 1, f"有效行数错: {stat}"
    assert C.score(st) == 5, f"坏行污染了 score: {C.score(st)}"


# ── arm6：无账本 ⟹ verify ok（无可验）/ score 0 ─────────────────────────────
def test_arm6_no_ledger_is_ok(tmp_path):
    st = _st(tmp_path)
    v = C.verify_seal(st)
    assert v.get("ok") is True and v.get("reason") == "no_ledger", f"无账本应 ok: {v}"
    assert C.score(st) == 0, "无账本 score 应为 0"


# ── arm7–10：对账（审计署 §19 ②b）——「抬额 ⟹ 有对应审计条目」─────────────────
def test_arm7_raise_is_unreconciled_debt(tmp_path):
    st = _st(tmp_path)
    rec = C.append(st, "raise", source="state_patch")["record"]
    assert rec.get("id"), f"raise 行未生成 `id`（待审债号）: {rec}"
    r = C.reconcile(st)
    assert r["ok"] is False and r["unreconciled"] == [rec["id"]], f"待审债未报出: {r}"
    assert r["raises"] == 1 and r["audited"] == 0, f"计数错: {r}"


def test_arm8_outcome_with_ref_reconciles(tmp_path):
    st = _st(tmp_path)
    rid = C.append(st, "raise", source="state_patch")["record"]["id"]
    C.append(st, "success", source="audit", ref=rid, **_OUT)
    r = C.reconcile(st)
    assert r["ok"] is True and r["unreconciled"] == [], f"引用后仍未对账: {r}"
    assert r["audited"] == 1, f"audited 计数错: {r}"
    assert C.score(st) == 5, f"outcome 未计分: {C.score(st)}"


def test_arm9_outcome_without_ref_does_not_reconcile(tmp_path):
    st = _st(tmp_path)
    C.append(st, "raise", source="state_patch")
    C.append(st, "fail", source="audit", **_OUT)            # 无 ref ⟹ 不构成对账
    r = C.reconcile(st)
    assert r["ok"] is False and len(r["unreconciled"]) == 1, f"无 ref 的 outcome 竟算对账: {r}"


def test_arm10_legacy_rows_without_id_not_reported(tmp_path):
    st = _st(tmp_path)
    with open(st + C.SUFFIX, "a", encoding="utf-8") as f:      # 本字段引入前的历史行
        f.write(json.dumps({"ts": "x", "kind": "raise", "delta": 0}) + "\n")
    r = C.reconcile(st)
    assert r["ok"] is True and r["raises"] == 0, f"无 id 的历史行被误报为未审: {r}"


# ── arm11–13：审计署 §3 判据4（owner 裁 A1，2026-10-07）──────────────────────
#   ① 三参数（模型版本/温度/种子）入 **outcome 行**；② 封印须**真验签**（非只比 digest）。
def test_arm11_outcome_row_carries_model_params(tmp_path):
    st = _st(tmp_path)
    rec = C.append(st, "success", source="audit", ref="r1",
                   model_version="deepseek-v4", temperature=0.0, seed=7)["record"]
    assert rec.get("model_version") == "deepseek-v4", f"三参数未入 outcome 行: {rec}"
    assert rec.get("temperature") == 0.0 and rec.get("seed") == 7, f"三参数未入 outcome 行: {rec}"
    r = C.append(st, "raise", source="state_patch")["record"]
    assert "model_version" not in r and "seed" not in r, f"非 outcome 行不应带三参数: {r}"


def test_arm12_seal_signature_really_verified(tmp_path):
    st = _st(tmp_path)
    C.append(st, "success", source="audit", **_OUT)
    assert C.verify_seal(st).get("ok") is True, f"正常封印应通过: {C.verify_seal(st)}"
    sp = Path(st + C.SEAL_SUFFIX)
    seal = json.loads(sp.read_text(encoding="utf-8"))
    assert seal.get("mode") == "ed25519", f"默认 .keys 在场应按 ed25519 签: {seal.get('mode')}"
    sig = str(seal.get("sig") or "")
    assert sig, "ed25519 签名为空"
    seal["sig"] = ("A" if sig[0] != "A" else "B") + sig[1:]     # 篡改签名（digest 逐字不变）
    sp.write_text(json.dumps(seal, ensure_ascii=False), encoding="utf-8")
    v = C.verify_seal(st)
    assert v.get("ok") is False, f"签名被篡改但封印仍判通过（只比 digest，未真验签）: {v}"
    assert "sig" in str(v.get("reason")), f"reason 应指向签名: {v}"


def test_arm13_keyless_seal_is_digest_only(tmp_path):
    st = _st(tmp_path)
    keys = tmp_path / "nokeys"
    keys.mkdir()
    C.append(st, "success", source="audit", key_dir=str(keys), **_OUT)   # 无键 ⟹ sha256-only 降级
    v = C.verify_seal(st, key_dir=str(keys))
    assert v.get("ok") is True and v.get("mode") == "sha256", f"无键应降级 sha256 完整性: {v}"
    with open(st + C.SUFFIX, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "x", "kind": "success", "delta": 1}) + "\n")
    assert C.verify_seal(st, key_dir=str(keys)).get("ok") is False, "sha256-only 也应检篡改"


# ── arm14：outcome 三参数 fail-loud（判据4a 收紧，2026-10-18）────────────────
# 缺陷（6 臂质询 `ECC-458FA591E582`）：缺参照写空值，`{model_version:"", temperature:null,
#   seed:null}` 仍 `ok=True` 并进签名域 ⟹「参数在签名域内」≠「参数被锁住」。
def test_arm14_outcome_requires_all_model_params(tmp_path):
    st = _st(tmp_path)
    bad = (
        {},
        {"model_version": "m"},
        {"model_version": "m", "temperature": 0.0},
        {"temperature": 0.0, "seed": 0},
        {"model_version": "", "temperature": 0.0, "seed": 0},
    )
    for kw in bad:
        out = C.append(st, "success", source="audit", ref="r1", **kw)
        assert out.get("ok") is False, f"outcome 缺参仍写入: kw={kw} out={out}"
        assert "model_params" in str(out.get("error")), f"错误未指参数: {out}"
    assert not Path(st + C.SUFFIX).exists() or _raw(st).strip() == "", \
        "缺参失败仍落盘（应 fail-before-write）"
    ok = C.append(st, "success", source="audit", ref="r1", **_OUT)
    assert ok.get("ok") is True, f"三参数齐全仍失败: {ok}"


# ── arm15–21：方案 a（owner 裁，2026-10-19）────────────────────────────────
#   病象：`state-patch --set-nested` 每次预算记账都发 `kind=raise`（delta=0）⟹ 224 条机械待审债。
#   修法：写侧改发 `kind=bookkeeping`；历史 224 条用**签名基线 cutoff** 一次性划为 legacy。
def test_arm15_bookkeeping_is_not_debt(tmp_path):
    st = _st(tmp_path)
    rec = C.append(st, "bookkeeping", source="state_patch_set_nested",
                   reason="edit_budget bookkeeping")["record"]
    assert rec["kind"] == "bookkeeping", f"kind 应为 bookkeeping: {rec}"
    assert rec["delta"] == 0, f"bookkeeping 应为中性(delta=0): {rec}"
    r = C.reconcile(st)
    assert r["ok"] is True and r["unreconciled"] == [], f"记账被误报为待审债: {r}"
    assert r["raises"] == 0 and r["debt_raises"] == 0, f"记账污染 raise 计数: {r}"
    assert C.score(st) == 0, f"记账污染信用分: {C.score(st)}"
    bad = C.append(st, "bookkeeping", delta=5, source="state_patch_set_nested")
    assert bad.get("ok") is False and "bookkeeping_delta" in str(bad.get("error")), \
        f"bookkeeping 允许非零 delta（可伪装计分）: {bad}"


def test_arm16_baseline_cutoff_excludes_legacy(tmp_path, keys):
    st = _st(tmp_path)
    r1 = C.append(st, "raise", source="legacy")["record"]["id"]
    r2 = C.append(st, "raise", source="legacy")["record"]["id"]
    r3 = C.append(st, "raise", source="legacy")["record"]["id"]
    b = C.write_baseline(st, r2, reason="pre-host bookkeeping raises", key_dir=keys)
    assert b.get("ok") is True, f"基线写入失败: {b}"
    assert b.get("mode") == "ed25519", f"临时 audit key 在场应按 ed25519 签: {b}"
    for k in ("state_id", "cutoff_line", "prefix_sha256", "ledger_lines"):
        assert b.get(k) not in (None, ""), f"基线未绑定账本/state（缺 {k}）: {b}"
    r = C.reconcile(st, key_dir=keys)
    assert r["ok"] is False, f"cutoff 之后的 raise 仍应是债: {r}"
    assert r["raises"] == 3, f"raises 应为全量: {r}"
    assert r["legacy_raises"] == 2, f"legacy 计数错: {r}"
    assert r["debt_raises"] == 1, f"debt 计数错: {r}"
    assert r["unreconciled"] == [r3], f"cutoff 之后的 raise 未被报出: {r}"
    assert r["baseline"]["ok"] is True and r["baseline"]["cutoff_id"] == r2, f"基线状态错: {r}"
    assert r1  # 首条也在 legacy 内（防 1 条漏划）


def test_arm17_tampered_baseline_fails_closed(tmp_path, keys):
    st = _st(tmp_path)
    r1 = C.append(st, "raise", source="legacy")["record"]["id"]
    r2 = C.append(st, "raise", source="legacy")["record"]["id"]
    assert C.write_baseline(st, r2, reason="cut", key_dir=keys)["ok"] is True
    bp = Path(str(st) + C.BASELINE_SUFFIX)
    rec = json.loads(bp.read_text(encoding="utf-8"))
    rec["cutoff_id"] = "99999999T999999-9999"      # 篡改以吞掉全部债
    bp.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
    r = C.reconcile(st, key_dir=keys)
    assert r["baseline"]["ok"] is False, f"篡改基线仍被判有效（可用来藏债）: {r}"
    assert r["baseline"]["reason"] == "digest_mismatch", f"失败原因错: {r}"
    assert r["legacy_raises"] == 0 and r["debt_raises"] == 2, f"篡改基线仍生效: {r}"
    assert r["unreconciled"] == [r1, r2], f"债被篡改基线藏掉: {r}"


def test_arm18_baseline_cutoff_must_exist(tmp_path, keys):
    st = _st(tmp_path)
    r1 = C.append(st, "raise", source="legacy")["record"]["id"]
    b = C.write_baseline(st, "20200101T000000-0001", reason="typo", key_dir=keys)
    assert b.get("ok") is False and b.get("error") == "cutoff_not_found", \
        f"写侧未拒绝不存在的 cutoff: {b}"
    r = C.reconcile(st, key_dir=keys)
    assert r["baseline"]["present"] is False, f"无效基线竟落盘: {r}"
    assert r["legacy_raises"] == 0 and r["unreconciled"] == [r1], f"债被无效基线藏掉: {r}"


def test_d7b_j1_outcome_ref_rejects_finding_id(tmp_path):
    """D7-B J1（2026-10-27）：审计产物（finding id）不得写进 outcome.ref —— 两本账。"""
    st = _st(tmp_path)
    r = C.append(st, "success", ref="ECC-AAAAAAAAAAAA", key_dir="", **_OUT)
    assert r["ok"] is False, r
    assert "outcome_ref_namespace_violation" in r["error"], r
    assert not Path(str(st) + C.SUFFIX).exists(), "被拒的 finding ref 仍落盘"


def test_d7b_j1_rejects_red_finding_id(tmp_path):
    """D7-B E3（2026-10-28 质询）：红队 finding id（`RED-*`，见计划 §21.1 `shared_ids`）
    同样是审计产物 ⟹ 必须与 `ECC-*` 同口径拒写；否则双边计价（I-2 一债一票）仍可绕过。
    """
    st = _st(tmp_path)
    for rid in ("RED-CONSTRAINTS-01", "RED-SCOPE-02", "RED-MIGRATE-X"):
        r = C.append(st, "success", ref=rid, key_dir="", **_OUT)
        assert r["ok"] is False, f"RED-* finding id 未被拒: {rid} -> {r}"
        assert "outcome_ref_namespace_violation" in r["error"], r
    assert not Path(str(st) + C.SUFFIX).exists(), "被拒的 RED-* ref 仍落盘"


def test_d7b_j1_allows_normal_raise_ref(tmp_path):
    """负臂：普通 raise id（时间戳序号形态）不得被 J1 误伤（防过度收紧）。"""
    st = _st(tmp_path)
    rid = C.append(st, "raise", source="host")["record"]["id"]
    r = C.append(st, "success", ref=rid, key_dir="", **_OUT)
    assert r["ok"] is True, f"普通 raise id 被误拒: {rid} -> {r}"


def test_arm19_raise_after_cutoff_is_debt(tmp_path, keys):
    st = _st(tmp_path)
    r1 = C.append(st, "raise", source="legacy")["record"]["id"]
    assert C.write_baseline(st, r1, key_dir=keys)["ok"] is True
    r2 = C.append(st, "raise", source="host")["record"]["id"]
    r = C.reconcile(st, key_dir=keys)
    assert r["baseline"]["ok"] is True, f"基线应有效: {r}"
    assert r["legacy_raises"] == 1 and r["debt_raises"] == 1, f"cutoff 边界错: {r}"
    assert r["unreconciled"] == [r2], f"cutoff 之后的新债未报出: {r}"


# ── arm22–26：复审 BLOCK 反臂（基线伪造 / 降级 / 重放 / 截断 / 前缀改写）────
def test_arm22_keyless_baseline_refused(tmp_path):
    st = _st(tmp_path)
    r1 = C.append(st, "raise", source="legacy")["record"]["id"]
    nokeys = tmp_path / "nokeys"
    nokeys.mkdir()
    b = C.write_baseline(st, r1, key_dir=str(nokeys))
    assert b.get("ok") is False, f"无键仍写基线（弱模式可伪造）: {b}"
    assert "ed25519" in str(b.get("error")), f"错误未指向强模式要求: {b}"
    assert not Path(str(st) + C.BASELINE_SUFFIX).exists(), "无键失败仍落盘"
    r = C.reconcile(st, key_dir=str(nokeys))
    assert r["baseline"]["present"] is False and r["unreconciled"] == [r1]


def test_arm23_mode_downgrade_rejected(tmp_path, keys):
    st = _st(tmp_path)
    r1 = C.append(st, "raise", source="legacy")["record"]["id"]
    r2 = C.append(st, "raise", source="legacy")["record"]["id"]
    assert C.write_baseline(st, r1, key_dir=keys)["ok"] is True
    bp = Path(str(st) + C.BASELINE_SUFFIX)
    rec = json.loads(bp.read_text(encoding="utf-8"))
    rec["mode"], rec["sig"] = "sha256", ""
    rec["cutoff_id"] = r2                       # 顺带扩到全部 raise
    body = {k: rec.get(k) for k in (
        "alg", "mode", "key_fp", "state_id", "cutoff_id", "cutoff_ts",
        "cutoff_line", "prefix_sha256", "ledger_lines", "reason", "created_at")}
    import hashlib
    rec["sha256"] = hashlib.sha256(C._canonical(body)).hexdigest()
    bp.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
    r = C.reconcile(st, key_dir=keys)
    assert r["baseline"]["ok"] is False, f"降级基线仍被接受: {r}"
    assert r["baseline"]["reason"] in {"weak_mode", "digest_mismatch", "sig_invalid"}, r
    assert r["legacy_raises"] == 0 and r["debt_raises"] == 2, f"降级基线藏债: {r}"
    assert r["unreconciled"] == [r1, r2]


def test_arm24_cross_state_replay_rejected(tmp_path, keys):
    a = str(tmp_path / "a" / ".gatekeeper.state")
    Path(a).parent.mkdir(parents=True, exist_ok=True)
    b = str(tmp_path / "b" / ".gatekeeper.state")
    Path(b).parent.mkdir(parents=True, exist_ok=True)
    ra = C.append(a, "raise", source="legacy")["record"]["id"]
    assert C.write_baseline(a, ra, key_dir=keys)["ok"] is True
    # B 复制同一账本内容（同 id），但基线来自 A ⟹ state 绑定必须拒绝
    Path(b + C.SUFFIX).write_text(_raw(a), encoding="utf-8", newline="\n")
    Path(b + C.BASELINE_SUFFIX).write_text(
        Path(a + C.BASELINE_SUFFIX).read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    rb = C.reconcile(b, key_dir=keys)
    assert rb["baseline"]["ok"] is False, f"跨 state 重放被接受: {rb}"
    assert rb["baseline"]["reason"] == "state_mismatch", f"失败原因错: {rb}"
    assert rb["legacy_raises"] == 0 and rb["debt_raises"] == 1, f"重放基线藏债: {rb}"


def test_arm25_truncated_ledger_rejected(tmp_path, keys):
    st = _st(tmp_path)
    ids = [C.append(st, "raise", source="legacy")["record"]["id"] for _ in range(3)]
    assert C.write_baseline(st, ids[-1], key_dir=keys)["ok"] is True
    lines = _raw(st).splitlines()
    Path(str(st) + C.SUFFIX).write_text("\n".join(lines[:2]) + "\n",
                                        encoding="utf-8", newline="\n")
    r = C.reconcile(st, key_dir=keys)
    assert r["baseline"]["ok"] is False, f"截断后基线仍被接受: {r}"
    assert r["baseline"]["reason"] in {"ledger_truncated", "prefix_mismatch"}, r
    assert r["legacy_raises"] == 0 and r["debt_raises"] == 2, f"截断藏债: {r}"


def test_arm26_prefix_rewrite_rejected(tmp_path, keys):
    st = _st(tmp_path)
    ids = [C.append(st, "raise", source="legacy")["record"]["id"] for _ in range(3)]
    assert C.write_baseline(st, ids[1], key_dir=keys)["ok"] is True
    rows = [json.loads(ln) for ln in _raw(st).splitlines() if ln.strip()]
    rows[0]["reason"] = "rewritten"              # 同 id / 同行数，改前缀内容
    Path(str(st) + C.SUFFIX).write_text(
        "\n".join(json.dumps(x, ensure_ascii=False) for x in rows) + "\n",
        encoding="utf-8", newline="\n")
    r = C.reconcile(st, key_dir=keys)
    assert r["baseline"]["ok"] is False, f"前缀被改写后基线仍被接受: {r}"
    assert r["baseline"]["reason"] == "prefix_mismatch", f"失败原因错: {r}"
    assert r["legacy_raises"] == 0 and r["debt_raises"] == 3, f"改写藏债: {r}"



def test_arm20_write_side_emits_bookkeeping():
    """写侧单源（静态臂）：`_budget_override_record` 的信用账本登记必须是 bookkeeping。"""
    src = (SCRIPTS.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    seg = src[src.index("_budget_override_record()"):]
    seg = seg[:seg.index("\n}") + 2]
    assert '_credit_log_append "bookkeeping"' in seg, \
        "`_budget_override_record` 未改发 bookkeeping（仍是 raise ⟹ 继续制造待审债）"
    assert '_credit_log_append "raise"' not in seg, \
        "`_budget_override_record` 仍在发 raise"


def test_arm21_cli_state_patch_writes_bookkeeping(tmp_path):
    """端到端臂：`state-patch --set-nested` 后账本末行 `kind == bookkeeping` 且零待审债。"""
    import shutil
    import subprocess
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下 CLI 无法执行）")
    sb = (tmp_path / "sb").resolve()
    sb.mkdir()
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPTS), w, _wsl(SCRIPTS.parent / "gatekeeper-cli.sh"), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    st = sb / ".gatekeeper.state"
    st.write_text(json.dumps({
        "stage": "ECO-EDIT", "r_phase": "R1", "worktree": w,
        "gate_data": {"project_type": "standing",
                      "edit_budget": {"max": 8, "used": 1, "remaining": 7}},
    }, ensure_ascii=False), encoding="utf-8", newline="\n")
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh state-patch '
                        '--set-nested gate_data.edit_budget.remaining 7' % w],
        capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, f"state-patch 失败：rc={r.returncode} {r.stdout}{r.stderr}"
    rows = [json.loads(ln) for ln in _raw(str(st)).splitlines() if ln.strip()]
    assert rows, "信用账本未落任何行"
    assert rows[-1]["kind"] == "bookkeeping", \
        f"写侧仍发 raise（方案 a 未落刀）：{rows[-1]}"
    rec = C.reconcile(str(st))
    assert rec["debt_raises"] == 0 and rec["unreconciled"] == [], \
        f"预算记账仍进待审债：{rec}"

