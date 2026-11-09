#!/usr/bin/env python3
"""提额旁挂账本 —— owner 裁定 C1–C4 的**红先臂**（2026-09-30）。

口径源：`docs/plans/2026-09-18-edit-budget-dual-track-plan.md` §15.7c（P12–P14）。
被测单源：`scripts/gk_budget_ledger.py`（写侧 CLI/advance 与读侧 entropy/audit **全部委托**它）。

裁定 ↔ 臂映射
  · **C1 就地过滤**：degrade 行不计提额  → `test_c1_degrade_not_counted` / `test_c1_readers_skip_degrade`
                                          / `test_c1_chain_skips_degrade` / `test_c1_legacy_row_defaults_to_raise`
  · **C2 补 seal**：封印可验 + 篡改可检 → `test_c2_seal_roundtrip_and_tamper`
  · **C3 fail-loud**：失败不静默        → `test_c3_fail_loud_on_bad_state`
  · **C4 坏行不计入**：两侧同口径       → `test_c4_bad_line_not_counted` / `test_c4_entropy_and_audit_readers_agree`
"""
import json
import sys
from pathlib import Path

import pytest

SD = Path(__file__).resolve().parent
sys.path.insert(0, str(SD))

import gk_budget_ledger as L  # noqa: E402  （红先：HEAD 无此模块 ⟹ 收集期即红）


def _write(st, rows, seal=True):
    Path(str(st) + L.SUFFIX).write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    if seal:
        # 2026-10-31（§9.4 额外缺口①）：有账本必须有封印，否则读侧 fail-loud
        L.seal_now(str(st))


def _state(tmp_path, eb=None):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"edit_budget": eb or {"max": 10, "used": 0, "remaining": 10}}}),
                  encoding="utf-8")
    return st


def _gen_key_dir(tmp_path, name="keys"):
    """自建 audit Ed25519 钥对 —— 不依赖私仓 `.keys/`（OSS 包排除该目录）。

    2026-11-02（CI 修复）：原用例从 `../.keys/` 复制钥对，公开仓无此目录 ⟹ 断言
    `mode == "ed25519"` 恒红。改为临时生成钥对，判据（真签/真验）不变。
    """
    pytest.importorskip("cryptography", reason="ed25519 封印用例需 cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    d = tmp_path / name
    d.mkdir()
    priv = ed25519.Ed25519PrivateKey.generate()
    (d / "audit_ed25519.pem").write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (d / "audit_ed25519.pub").write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return d


# ── C1 就地过滤 ──────────────────────────────────────────────────────────
def test_c1_degrade_not_counted(tmp_path):
    st = _state(tmp_path)
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE, "to_max": 8},
                {"ts": L._now_str(), "source": "degrade", "kind": L.KIND_DEGRADE, "to_max": 8}])
    total, today = L.count_raises(str(st))
    assert (total, today) == (1, 1), f"C1 失守：degrade 行被计入提额（total={total} today={today}）"


def test_c1_legacy_row_defaults_to_raise(tmp_path):
    st = _state(tmp_path)
    _write(st, [{"ts": L._now_str(), "source": "code-fix"}])       # 存量行：无 kind
    assert L.count_raises(str(st))[0] == 1, "存量行（无 kind）应默认 raise（零回归）"


def test_c1_chain_skips_degrade(tmp_path):
    st = _state(tmp_path)
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE, "to_max": 10},
                {"ts": L._now_str(), "source": "degrade", "kind": L.KIND_DEGRADE, "to_max": 999}])
    out = L.append(str(st), "code-fix", "b")
    assert out.get("ok"), f"C3：append 失败 {out}"
    assert out["record"]["from_max"] == 10, \
        f"C1 失守：提额链被降级行扰动（from_max={out['record']['from_max']}）"


def test_c1_readers_skip_degrade(tmp_path):
    import gk_gate_entropy as E
    import gk_audit_state as A
    st = _state(tmp_path)
    _write(st, [{"ts": L._now_str(), "source": "r2-degrade", "kind": L.KIND_DEGRADE},
                {"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE}])
    assert E._raises_today(str(st)) == 1, "熵第三支把降级行计入提额（C1）"
    assert A._edit_budget_raises(str(st))[0] == 1, "audit 把降级行计入提额（C1）"


# ── C2 补 seal ───────────────────────────────────────────────────────────
def test_c2_seal_roundtrip_and_tamper(tmp_path):
    st = _state(tmp_path)
    out = L.append(str(st), "code-fix", "unit")
    assert out.get("ok"), f"C3：append 失败 {out}"
    assert L.verify_seal(str(st)).get("ok") is True, "C2：append 后封印校验不通过"
    p = Path(str(st) + L.SUFFIX)
    p.write_text(p.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")
    assert L.verify_seal(str(st)).get("ok") is False, "C2 失守：篡改账本后封印仍判通过"


# ── C3 fail-loud ─────────────────────────────────────────────────────────
def test_c3_fail_loud_on_bad_state():
    out = L.append("", "code-fix", "x")
    assert out.get("ok") is False and out.get("error"), "C3 失守：写失败被静默吞掉"


# ── C4 坏行不计入 ────────────────────────────────────────────────────────
def test_c4_bad_line_not_counted(tmp_path):
    st = _state(tmp_path)
    p = Path(str(st) + L.SUFFIX)
    p.write_text("{ not json\n" + json.dumps(
        {"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE}, ensure_ascii=False) + "\n",
        encoding="utf-8")
    L.seal_now(str(st))       # 2026-10-31：封印为硬前提（否则读侧 fail-loud）
    total, _ = L.count_raises(str(st))
    recs, stat = L.read_records(str(st))
    assert total == 1, f"C4 失守：坏行被计入（total={total}）"
    assert stat["bad"] == 1 and len(recs) == 1, f"C4 失守：坏行未隔离（stat={stat}）"


def test_c4_entropy_and_audit_readers_agree(tmp_path):
    import gk_gate_entropy as E
    import gk_audit_state as A
    st = _state(tmp_path)
    p = Path(str(st) + L.SUFFIX)
    p.write_text("{ bad\n" + json.dumps(
        {"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE}, ensure_ascii=False) + "\n",
        encoding="utf-8")
    L.seal_now(str(st))       # 2026-10-31：封印为硬前提（否则读侧 fail-loud）
    assert E._raises_today(str(st)) == 1, "熵第三支把坏行计入了（C4）"
    assert A._edit_budget_raises(str(st))[0] == 1, "audit 把坏行计入 total（C4）"


# ── C2b：真验签（审计署判据4b，owner 裁 A1，2026-10-07）─────────────────────
#   篡改**签名**（digest 逐字不变）⟹ 旧实现（只比 digest）会误判 ok；新实现须判否。
def test_c2b_seal_signature_verified(tmp_path):
    keys = _gen_key_dir(tmp_path)
    st = _state(tmp_path)
    assert L.append(str(st), "code-fix", "unit", key_dir=str(keys)).get("ok"), "append 失败"
    assert L.verify_seal(str(st), key_dir=str(keys)).get("ok") is True, "正常封印应通过"
    sp = Path(str(st) + L.SEAL_SUFFIX)
    seal = json.loads(sp.read_text(encoding="utf-8"))
    assert seal.get("mode") == "ed25519", f"有 audit 钥应按 ed25519 签: {seal.get('mode')}"
    sig = str(seal.get("sig") or "")
    assert sig, "ed25519 签名为空"
    seal["sig"] = ("A" if sig[0] != "A" else "B") + sig[1:]      # 篡改签名（digest 不变）
    sp.write_text(json.dumps(seal, ensure_ascii=False), encoding="utf-8")
    v = L.verify_seal(str(st))
    assert v.get("ok") is False and "sig" in str(v.get("reason")), f"签名未被真验签: {v}"


# ── C2c–C2e：无键 fail-loud + 钥目录同源（审计署判据4b，2026-10-18）──────────
# 缺陷（6 臂质询 `ECC-458FA591E582`）：`mode != ed25519` 时 `verify_seal_at` 直接
#   `ok=True` ⟹ 无外置钥部署下「封印可信」= 摘要自洽，攻击者改账本并重算 sha256 即过；
#   且 `verify` 子命令缺 `--key-dir`，签/验钥目录不同源。
def test_c2c_keyless_strict_fails(tmp_path):
    st = _state(tmp_path)
    keys = tmp_path / "nokeys"
    keys.mkdir()
    assert L.append(str(st), "code-fix", "unit", key_dir=str(keys)).get("ok"), "append 失败"
    weak = L.verify_seal(str(st), key_dir=str(keys))
    assert weak.get("ok") is True and weak.get("mode") == "sha256", f"弱模式基线: {weak}"
    strict = L.verify_seal(str(st), key_dir=str(keys), require_ed25519=True)
    assert strict.get("ok") is False and strict.get("reason") == "weak_mode", \
        f"无键环境在 strict 下仍判绿（4b 假绿）：{strict}"


def test_c2d_key_dir_env_same_as_ember(tmp_path, monkeypatch):
    """`_AUDIT_KEY_DIR` 须与 ember `pubkey_path` 同源：签名与验签落到同一钥目录。"""
    st = _state(tmp_path)
    keys = _gen_key_dir(tmp_path)
    monkeypatch.setenv("_AUDIT_KEY_DIR", str(keys))
    assert L.append(str(st), "code-fix", "unit").get("ok"), "append 失败"
    v = L.verify_seal(str(st), require_ed25519=True)
    assert v.get("ok") is True and v.get("mode") == "ed25519", \
        f"env 钥目录下签/验不同源: {v}"


# ── 2026-10-31 数据层：no-op 写入不是提额（standard §12.4.2 / edit-budget §12.7）──
def test_noop_write_is_bookkeeping_not_raise(tmp_path):
    """`state-patch --set-nested` 改 used/remaining（max 未变）⟹ 不得记 raise。"""
    st = _state(tmp_path, {"max": 24, "used": 5, "remaining": 19})
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE,
                 "from_max": None, "to_max": 24}])
    out = L.append(str(st), "state_patch_set_nested", "edit_budget.sessions.x.used")
    assert out.get("ok"), out
    assert out["record"]["kind"] == L.KIND_BOOKKEEPING, out["record"]
    assert L.count_raises(str(st))[0] == 1, "no-op 被计入真提额"


def test_real_raise_still_raise_and_counted(tmp_path):
    st = _state(tmp_path, {"max": 26, "used": 0, "remaining": 26})
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE,
                 "from_max": None, "to_max": 24}])
    out = L.append(str(st), "code-fix", "raise")
    assert out["record"]["kind"] == L.KIND_RAISE
    assert out["record"]["from_max"] == 24 and out["record"]["to_max"] == 26
    assert L.count_raises(str(st))[0] == 2


def test_legacy_noop_rows_not_counted_but_rows_kept(tmp_path):
    """历史行不改数据：读侧按 `to_max > from_max` 过滤；`raises`（行数）仍供审计对账。"""
    st = _state(tmp_path)
    _write(st, [
        {"ts": L._now_str(), "source": "state_patch_set_nested", "kind": L.KIND_RAISE,
         "from_max": 24, "to_max": 24},
        {"ts": L._now_str(), "source": "state_patch_set_nested", "kind": L.KIND_RAISE,
         "from_max": 32, "to_max": 24},
        {"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE,
         "from_max": 24, "to_max": 26},
    ])
    assert L.count_raises(str(st))[0] == 1
    _, stats = L.read_records(str(st))
    assert stats["raises"] == 3 and stats["true_raises"] == 1


def test_chain_ignores_bookkeeping(tmp_path):
    """链只跟真提额：夹一条 no-op 后，下一条真提额的 `from_max` 仍取上一条真提额。"""
    st = _state(tmp_path, {"max": 24, "used": 0, "remaining": 24})
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE,
                 "from_max": None, "to_max": 24}])
    assert L.append(str(st), "state-patch", "used")["record"]["kind"] == L.KIND_BOOKKEEPING
    out = L.append(str(st), "code-fix", "real", eb={"max": 30, "used": 0, "remaining": 30})
    assert out["record"]["kind"] == L.KIND_RAISE
    assert out["record"]["from_max"] == 24, out["record"]


def test_c2e_verify_cli_accepts_key_dir_and_strict(tmp_path):
    """CLI `verify` 须能接收 `--key-dir` + `--require-ed25519`（原缺 → argparse exit 2）。"""
    import subprocess
    st = _state(tmp_path)
    keys = tmp_path / "nokeys"
    keys.mkdir()
    assert L.append(str(st), "code-fix", "unit", key_dir=str(keys)).get("ok"), "append 失败"
    r = subprocess.run(
        [sys.executable, str(SD / "gk_budget_ledger.py"), "verify",
         "--state", str(st), "--key-dir", str(keys), "--require-ed25519"],
        capture_output=True, text=True)
    assert r.returncode == 1, f"strict 无键 CLI 应 rc=1，得 {r.returncode}: {r.stdout} {r.stderr}"
    assert "weak_mode" in r.stdout, f"CLI 未报 weak_mode: {r.stdout}"


# ── owner 2026-10-31 签 §8 #4：RAISE_DAILY_CAP 与激活基线 ─────────────────────
def test_cap_hit_is_named_fail_loud(tmp_path):
    """当日真提额已达 CAP（6）⟹ `RAISE_DAILY_CAP_HIT`，不得静默写入。"""
    st = _state(tmp_path, {"max": 10, "used": 0, "remaining": 10})
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE,
                 "from_max": i, "to_max": i + 1} for i in range(6)])
    out = L.append(str(st), "code-fix", "over-cap")
    assert out.get("ok") is False
    assert out.get("error") == "RAISE_DAILY_CAP_HIT"
    assert out.get("cap") == 6 and out.get("used_today") == 6


def test_cap_counts_true_raises_only(tmp_path):
    """no-op / 降级 / 扣款不计入 cap 分子（与 `count_raises` 同源）。"""
    st = _state(tmp_path, {"max": 10, "used": 0, "remaining": 10})
    rows = [{"ts": L._now_str(), "source": "state-patch", "kind": L.KIND_BOOKKEEPING,
             "from_max": 9, "to_max": 9} for _ in range(10)]
    rows.append({"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE,
                 "from_max": 9, "to_max": 10})
    _write(st, rows)
    out = L.append(str(st), "code-fix", "second-real", eb={"max": 12, "used": 0, "remaining": 12})
    assert out.get("ok") is True, out


def test_activation_baseline_excludes_prior_rows(tmp_path):
    """`gate_data.econ_enabled_at` 之前的真提额不计入（转当日不自锁）。"""
    st = _state(tmp_path)
    _write(st, [{"ts": "2026-10-01T00:00:00Z", "source": "code-fix", "kind": L.KIND_RAISE,
                 "from_max": 1, "to_max": 2},
                {"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE,
                 "from_max": 2, "to_max": 3}])
    d = json.loads(st.read_text(encoding="utf-8"))
    d["gate_data"]["econ_enabled_at"] = "2026-10-15T00:00:00Z"
    st.write_text(json.dumps(d), encoding="utf-8")
    assert L.count_raises(str(st)) == (1, 1)


def test_missing_baseline_keeps_legacy_counting(tmp_path):
    """无 `econ_enabled_at` ⟹ 旧口径（零回归）。"""
    st = _state(tmp_path)
    _write(st, [{"ts": "2026-10-01T00:00:00Z", "source": "code-fix", "kind": L.KIND_RAISE,
                 "from_max": 1, "to_max": 2}])
    assert L.count_raises(str(st))[0] == 1


# ── §9.4 额外缺口①：封印失效 = 具名 fail-loud（2026-10-31）────────────────────
def test_seal_invalid_count_raises_fails_loud(tmp_path):
    st = _state(tmp_path)
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE}], seal=False)
    with pytest.raises(L.LedgerSealInvalid) as ei:
        L.count_raises(str(st))
    assert ei.value.code == "RAISE_LEDGER_SEAL_INVALID"


def test_seal_invalid_append_returns_named_error(tmp_path):
    """封印失效时连 CAP 都不许算 ⟹ 拒绝写提额（返回同名错误，不 traceback）。"""
    st = _state(tmp_path)
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE}], seal=False)
    out = L.append(str(st), "code-fix", "x")
    assert out.get("ok") is False
    assert out.get("error") == "RAISE_LEDGER_SEAL_INVALID"


def test_no_ledger_is_not_seal_error(tmp_path):
    """无账本 ≠ 封印失效（零提额场景必须照常）。"""
    st = _state(tmp_path)
    assert L.count_raises(str(st)) == (0, 0)


# ── §6 臂 8：人工解锁（非 LLM / append-only / 可复算）─────────────────────
def _seeded_cap(tmp_path):
    st = _state(tmp_path, {"max": 10, "used": 0, "remaining": 10})
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE,
                 "from_max": i, "to_max": i + 1} for i in range(6)])
    return st


def test_human_unlock_allows_one_extra_raise(tmp_path):
    st = _seeded_cap(tmp_path)
    assert L.append(str(st), "code-fix", "over").get("error") == "RAISE_DAILY_CAP_HIT"
    u = L.record_unlock(str(st), "owner", "线上热修，人工确认")
    assert u.get("ok") is True, u
    assert u["unlock"]["kind"] == "human_unlock" and u["unlocks_today"] == 1
    # 6 次 - 1 次解锁 = 5 < 6 ⟹ 允许再提一次
    assert L.append(str(st), "code-fix", "unlocked", eb={"max": 11, "used": 0, "remaining": 11}).get("ok") is True


def test_human_unlock_requires_operator_and_reason(tmp_path):
    st = _seeded_cap(tmp_path)
    assert L.record_unlock(str(st), "", "why").get("error") == "UNLOCK_ARG_REQUIRED"
    assert L.record_unlock(str(st), "owner", "  ").get("error") == "UNLOCK_ARG_REQUIRED"


def test_human_unlock_not_counted_as_raise(tmp_path):
    st = _seeded_cap(tmp_path)
    before = L.count_raises(str(st))
    L.record_unlock(str(st), "owner", "audit")
    assert L.count_raises(str(st)) == before, "解锁行不得计入提额"
    assert L.read_records(str(st))[1]["unlocks"] == 1


def test_human_unlock_rejected_on_unsealed_ledger(tmp_path):
    st = _state(tmp_path)
    _write(st, [{"ts": L._now_str(), "source": "code-fix", "kind": L.KIND_RAISE}], seal=False)
    out = L.record_unlock(str(st), "owner", "x")
    assert out.get("ok") is False and out.get("error") == "RAISE_LEDGER_SEAL_INVALID"

def _concurrent_append_worker(st, key_dir, barrier):
    barrier.wait()
    L.append(st, "degrade", reason="concurrency-arm", key_dir=key_dir)


def test_append_concurrent_no_duplicate_seq(tmp_path):
    """并发 append ⟹ 封链 seq 必须严格 1..N，无重复（2026-11-09 锁根因臂）。

    红先性：旧实现 append = 读记录 → 追加行 → seal_now（读链尾 → 写 seal → 推链）
    **整段无锁** ⟹ 8 路并发会各自 seal 同一账本摘要 ⟹ 链上出现同 seq 重复条目
    （本会话实测 `seq=1582` 逐字重复）⟹ `_verify_chain` 判 `seq_mismatch`。
    """
    import multiprocessing as mp
    st = _state(tmp_path)
    key_dir = str(tmp_path / "nokeys")
    n = 8
    try:
        ctx = mp.get_context("fork")
    except ValueError:                       # 非 POSIX 宿主（无 fork）⟹ 用默认上下文
        ctx = mp.get_context()
    barrier = ctx.Barrier(n)
    ps = [ctx.Process(target=_concurrent_append_worker,
                      args=(str(st), key_dir, barrier)) for _ in range(n)]
    for x in ps:
        x.start()
    for x in ps:
        x.join(30)
    assert all(x.exitcode == 0 for x in ps), [x.exitcode for x in ps]
    chain = Path(str(st) + L.SEAL_SUFFIX + L.CHAIN_SUFFIX)
    seqs = [json.loads(ln)["seq"] for ln in chain.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert seqs == list(range(1, n + 1)), f"封链 seq 非严格递增/有重复: {seqs}"
    assert L.verify_seal(str(st), key_dir=key_dir)["ok"] is True

