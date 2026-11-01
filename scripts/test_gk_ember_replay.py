#!/usr/bin/env python3
"""
test_gk_ember_replay.py — C10 ember-replay-audit 测试（2026-09-05）
覆盖: archived slice reconcile 生命周期一致 / 四形态篡改仿真（伪造裁决·回滚·记录被删）/ pre-C8 epoch
豁免 / A3 seal 往返 + 篡改检出 / no-findings info / 体积与事件数门禁 / list·phase 解析 / CLI 用法纪律。
"""
import base64
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_ember_replay as gem  # noqa: E402
from gk_finding import reconcile_pair  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, Encoding, PrivateFormat, PublicFormat, NoEncryption)
    CRYPTO = True
except Exception:  # pragma: no cover
    CRYPTO = False


def _ts(i):
    return f"2026-09-05T00:00:{i:02d}.000000+00:00"


def _event(i, fid, event, to, ts=None):
    return {"ts": ts or _ts(i), "event": event, "fid": fid, "from": "open", "to": to}


def _finding(fid, status, title="ECC-FAKE-C10"):
    return {"id": fid, "title": f"{title}-{fid}", "status": status,
            "source": "red", "created_at": _ts(1)}


def _make_state_dir(tmp, with_state=True):
    """建 state 文件 + 可写 state 目录；返回 (state_file, state_dir)。"""
    state_file = str(Path(tmp) / "state.json")
    if with_state:
        Path(state_file).write_text(json.dumps({"r_phase": "R7", "gate_data": {"ecc_findings": []}}),
                                    encoding="utf-8")
    return state_file, tmp


def _write_ember(tmp, phase, findings, events, seal=None, journal_field=True,
                 extra=None, state_d=None):
    lines = [json.dumps(e, ensure_ascii=False) for e in events]
    emb = {"archived_at": "2026-09-05T08:00:00+00:00", "r_phase": "R7",
           "gate_data_full": {"ecc_findings": findings}, "prev_entry": {"r_phase": "R7"}}
    if journal_field:
        emb["finding_journal"] = lines
    if extra:
        emb.update(extra)
    if seal:  # seal: (priv_key_bytes) 签规范化 payload（seal 自排除）
        priv = load_pem_private_key(seal, password=None)
        canon = gem.canonical_bytes({k: v for k, v in emb.items() if k != "seal"})
        emb["seal"] = {"alg": "ed25519", "key": "audit_ed25519", "key_fp": "t" * 32,
                       "sig": base64.b64encode(priv.sign(canon)).decode(),
                       "signed_at": emb["archived_at"]}
    d = state_d or tmp
    p = Path(d) / f".gatekeeper.ember.{phase}.json"
    p.write_text(json.dumps(emb, ensure_ascii=False, indent=1), encoding="utf-8")
    return p


def _make_keys(d):
    """生成测试 Ed25519 密钥对到目录；返回 (priv_bytes)。"""
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    Path(d, "audit_ed25519.pem").write_bytes(priv_pem)
    Path(d, "audit_ed25519.pub").write_bytes(pub_pem)
    return priv_pem


@pytest.fixture
def env():
    with tempfile.TemporaryDirectory() as tmp:
        old = {k: os.environ.get(k) for k in ("EMBER_MAX_BYTES", "EMBER_EVENTS_MAX")}
        yield tmp
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class TestArchivedReconcileSlice:
    def test_clean_lifecycle_consistent(self, env):
        sf, sd = _make_state_dir(env)
        findings = [_finding("F1", "closed"), _finding("F2", "open")]
        events = [_event(1, "F1", "register", "open"), _event(2, "F1", "verify", "verified"),
                  _event(3, "F1", "close", "closed"),
                  _event(2, "F2", "register", "open")]
        _write_ember(env, "R7", findings, events, state_d=sd)
        rec = gem.reconcile_ember(str(Path(sd) / ".gatekeeper.ember.R7.json"))
        assert rec["ok"] is True and rec["gate"]["ok"] is True
        assert rec["reconcile"]["anomalies"] == []
        assert rec["reconcile"]["findings"] == 2 and rec["reconcile"]["events"] == 4
        assert rec["phase"] == "R7"

    def test_fake_closed_no_journal_event(self, env):
        """伪造裁决：finding closed 但 slice 内无 to=closed 事件 → anomaly。"""
        sf, sd = _make_state_dir(env)
        findings = [_finding("F1", "closed")]
        events = [_event(1, "F1", "register", "open")]  # 无 close 事件
        _write_ember(env, "R7", findings, events, state_d=sd)
        rec = gem.reconcile_ember(str(Path(sd) / ".gatekeeper.ember.R7.json"))
        assert rec["gate"]["ok"] is False
        assert any("伪造裁决" in str(a.get("reason")) for a in rec["reconcile"]["anomalies"])

    def test_state_rollback_detected(self, env):
        """回滚：finding open 但 journal 末事件=closed → anomaly。"""
        sf, sd = _make_state_dir(env)
        findings = [_finding("F1", "open")]
        events = [_event(1, "F1", "register", "open"), _event(2, "F1", "close", "closed")]
        _write_ember(env, "R7", findings, events, state_d=sd)
        rec = gem.reconcile_ember(str(Path(sd) / ".gatekeeper.ember.R7.json"))
        assert rec["gate"]["ok"] is False
        assert any("回滚" in str(a.get("reason")) for a in rec["reconcile"]["anomalies"])

    def test_out_of_scope_previous_phase_residue_no_fp(self, env):
        """跨相位合法 closure（R6 开 R7 关）不误报：fid 不在 archived findings → out-of-scope INFO。"""
        sf, sd = _make_state_dir(env)
        findings = [_finding("F7A", "closed")]  # R7 相位自身一条
        events = [_event(1, "F6X", "register", "open"), _event(2, "F6X", "close", "closed"),
                  _event(2, "F7A", "register", "open"), _event(3, "F7A", "close", "closed")]
        _write_ember(env, "R7", findings, events, state_d=sd)
        rec = gem.reconcile_ember(str(Path(sd) / ".gatekeeper.ember.R7.json"))
        assert rec["gate"]["ok"] is True, rec
        assert rec["reconcile"]["out_of_scope"] == 2  # F6X 两事件 = 跨相位残留（INFO 不阻断）

    def test_journal_corrupt_line_candidate(self, env):
        sf, sd = _make_state_dir(env)
        findings = [_finding("F1", "closed")]
        events = [_event(1, "F1", "register", "open")]
        _write_ember(env, "R7", findings, events, state_d=sd)
        p = Path(sd) / ".gatekeeper.ember.R7.json"
        emb = json.loads(p.read_text(encoding="utf-8"))
        emb["finding_journal"] = emb["finding_journal"] + ["{broken json"]
        p.write_text(json.dumps(emb, ensure_ascii=False), encoding="utf-8")
        rec = gem.reconcile_ember(str(p))
        assert rec["gate"]["ok"] is False  # 损坏行 + closed 无前序 → 双 anomaly
        assert any("损坏" in str(a.get("reason")) for a in rec["reconcile"]["anomalies"])


class TestEpochAndEmpty:
    def test_pre_c8_epoch_exempt(self, env):
        sf, sd = _make_state_dir(env)
        findings = [_finding("F1", "closed")]
        _write_ember(env, "R7", findings, [], state_d=sd, journal_field=False)  # 无 finding_journal 字段
        rec = gem.reconcile_ember(str(Path(sd) / ".gatekeeper.ember.R7.json"))
        assert rec["ok"] is True and rec["epoch"] == "pre-c8"
        assert rec["gate"]["ok"] is True and rec["gate"]["verdict"] == "epoch-exempt"

    def test_no_findings_phase_info(self, env):
        sf, sd = _make_state_dir(env)
        events = [_event(1, "OLD", "register", "open")]  # 旧相位事件，本相位无登记
        _write_ember(env, "R7", [], events, state_d=sd)
        rec = gem.reconcile_ember(str(Path(sd) / ".gatekeeper.ember.R7.json"))
        assert rec["ok"] is True and rec["gate"]["ok"] is True
        assert rec["gate"]["verdict"] == "no-findings"


@pytest.mark.skipif(not CRYPTO, reason="cryptography 不可用")
class TestA3Seal:
    def _sealed_reconcile(self, env, mutate=None, findings=None, events=None):
        sf, sd = _make_state_dir(env)
        keys = _make_keys(env)
        findings = findings if findings is not None else [_finding("F1", "closed")]
        events = events if events is not None else [
            _event(1, "F1", "register", "open"), _event(2, "F1", "verify", "verified"),
            _event(3, "F1", "close", "closed")]
        p = _write_ember(env, "R7", findings, events, seal=keys, state_d=sd)
        if mutate:
            emb = json.loads(p.read_text(encoding="utf-8"))
            mutate(emb)
            p.write_text(json.dumps(emb, ensure_ascii=False, indent=1), encoding="utf-8")
        return gem.reconcile_ember(str(p), env)

    def test_seal_verified_roundtrip(self, env):
        rec = self._sealed_reconcile(env)
        assert rec["seal"]["status"] == "verified"
        assert rec["gate"]["ok"] is True

    def test_tamper_archived_at_invalidates_seal(self, env):
        rec = self._sealed_reconcile(env, mutate=lambda e: e.update(archived_at="2030-01-01T00:00:00+00:00"))
        assert rec["seal"]["status"] == "invalid"
        assert rec["gate"]["ok"] is False  # seal invalid = 阻断级（协调篡改检出）

    def test_tamper_finding_status_reconcile_and_seal(self, env):
        def m(e):
            for f in e["gate_data_full"]["ecc_findings"]:
                f["status"] = "closed"
            e["finding_journal"] = [json.dumps(_event(1, "F1", "register", "open"), ensure_ascii=False)]
        rec = self._sealed_reconcile(env, mutate=m)
        assert rec["seal"]["status"] == "invalid"
        assert any("伪造裁决" in str(a.get("reason")) for a in rec["reconcile"]["anomalies"])
        assert rec["gate"]["ok"] is False

    def test_no_seal_annotation(self, env):
        sf, sd = _make_state_dir(env)
        findings = [_finding("F1", "closed")]
        events = [_event(1, "F1", "register", "open"), _event(2, "F1", "verify", "verified"),
                  _event(3, "F1", "close", "closed")]
        _write_ember(env, "R7", findings, events, state_d=sd)  # 无 seal
        rec = gem.reconcile_ember(str(Path(sd) / ".gatekeeper.ember.R7.json"), env)
        assert rec["seal"]["status"] == "unverified_no_seal"
        assert rec["gate"]["ok"] is True  # 降级标注不阻断（best-effort）


class TestGates:
    def test_size_cap_explicit_skip(self, env):
        os.environ["EMBER_MAX_BYTES"] = "50"
        sf, sd = _make_state_dir(env)
        findings = [_finding("F1", "closed")]
        events = [_event(1, "F1", "register", "open")]
        _write_ember(env, "R7", findings, events, state_d=sd)
        rec = gem.reconcile_ember(str(Path(sd) / ".gatekeeper.ember.R7.json"))
        assert rec["ok"] is True and rec["skip"] == "too_large"
        assert rec["gate"]["ok"] is False

    def test_events_cap_explicit_skip(self, env):
        os.environ["EMBER_EVENTS_MAX"] = "2"
        sf, sd = _make_state_dir(env)
        findings = [_finding("F1", "closed")]
        events = [_event(1, "F1", "register", "open"), _event(2, "F1", "verify", "verified"),
                  _event(3, "F1", "close", "closed")]
        _write_ember(env, "R7", findings, events, state_d=sd)
        rec = gem.reconcile_ember(str(Path(sd) / ".gatekeeper.ember.R7.json"))
        assert rec["ok"] is True and rec["skip"] == "events_cap"
        assert rec["gate"]["ok"] is False


class TestListGetCli:
    def test_list_reverse_chronological_and_phase_resolve(self, env):
        sf, sd = _make_state_dir(env)
        p1 = _write_ember(env, "R6", [], [], state_d=sd)
        p2 = _write_ember(env, "R7", [_finding("F1", "open")], [_event(1, "F1", "register", "open")], state_d=sd)
        os.utime(p2, (1000, 1000))
        os.utime(p1, (2000, 2000))  # R6 更新 → 最新在前
        files = gem.ember_files(sd)
        assert files[0] == str(p1) and files[1] == str(p2)
        res = gem.resolve_ember(sd, "R7")
        assert res["ok"] and res["path"].endswith(".gatekeeper.ember.R7.json")
        res2 = gem.resolve_ember(sd, "R9")
        assert res2["ok"] is False and res2["error"] == "phase_not_found"

    def test_cli_usage_and_missing_state(self, capsys):
        rc = gem.main([])
        out = capsys.readouterr().out
        assert rc == 1 and "usage" in out
        rc2 = gem.main(["reconcile", "--state-file", "/nonexistent/state.json"])
        out2 = capsys.readouterr().out
        assert rc2 == 1 and "state_file required" in out2

    def test_reconcile_pair_shared_single_source(self):
        """C10 与 C8 共用 reconcile_pair 单源（回归锚：live reconcile 语义不漂移）。"""
        findings = [_finding("F1", "closed")]
        events = [_event(1, "F1", "register", "open")]  # closed 无前序
        r = reconcile_pair(findings, events)
        assert r["ok"] is False and any("伪造裁决" in str(a["reason"]) for a in r["anomalies"])


class TestSnapshotPairSingleSource:
    """A6-T3（2026-09-15）：`snapshot_pair` = 同源 (state, journal) 对**单一取数接口**。

    判据（跨代际 μ 反推的输入契约）：同一 ember 快照 ⟹ **任何消费者**取到的
    `(gate_data_full.ecc_findings, 内嵌 journal)` **逐字相同**；**禁**各写一份读取器
    （F-REV-41 同族：字段链断裂 / 第二实现漂移）。
    """

    def test_pair_matches_archive_bytewise(self, env):
        sf, sd = _make_state_dir(env)
        findings = [_finding("a", "open"), _finding("b", "closed")]
        events = [_event(1, "a", "register", "open"), _event(2, "b", "close", "closed")]
        p = _write_ember(env, "R7", findings, events, state_d=sd)
        a = gem.snapshot_pair(str(p))
        b = gem.snapshot_pair(str(p))
        # ① 两消费者逐字相同；② **且与归档本体逐字相同**（防"两个消费方都错"的假绿）
        assert a["ok"] is True and b["ok"] is True
        raw = json.loads(Path(p).read_text(encoding="utf-8"))
        assert a["ecc_findings"] == b["ecc_findings"] == raw["gate_data_full"]["ecc_findings"]
        assert a["journal"] == b["journal"] == raw["finding_journal"]
        assert a["journal_events"] == [json.loads(x) for x in raw["finding_journal"]]
        assert a["phase"] == "R7" and a["corrupt_lines"] == 0

    def test_pair_single_loader_no_second_reader(self, env, monkeypatch):
        """**单源纪律**：`snapshot_pair` 必须复用 `load_ember` ⟹ 调用计数 == 1（无第二读取器）。"""
        calls = {"n": 0}
        real = gem.load_ember

        def _counted(path):
            calls["n"] += 1
            return real(path)

        monkeypatch.setattr(gem, "load_ember", _counted)
        sf, sd = _make_state_dir(env)
        p = _write_ember(env, "R7", [_finding("a", "open")],
                         [_event(1, "a", "register", "open")], state_d=sd)
        r = gem.snapshot_pair(str(p))
        assert r["ok"] is True and calls["n"] == 1

    def test_pair_no_journal_is_explicit(self, env):
        """pre-C8 快照（无 `finding_journal` 字段）⟹ **显式降级**，禁静默当空 journal。"""
        sf, sd = _make_state_dir(env)
        p = _write_ember(env, "R7", [_finding("a", "open")], [],
                         journal_field=False, state_d=sd)
        r = gem.snapshot_pair(str(p))
        assert r["ok"] is False and r["error"] == "no_finding_journal"

    def test_pair_unreadable_is_explicit(self, env):
        """快照缺失 ⟹ 显式 error（禁抛穿 —— 消费者需要能判决的返回值）。"""
        r = gem.snapshot_pair(str(Path(env) / "nope.json"))
        assert r["ok"] is False and r["error"] == "unreadable"


class TestHookBlockSliceReplay:
    """㉕a（2026-09-06）：ember 快照 hook_block_log 切片一致性回判（回放消费端补缺）。

    管道已通（hook_block_log → gate_data_full/prev_entry 归档）；此处补回放端——
    prev_entry 意图记忆归档段应为 gate_data_full 同窗口尾部子序列；漂移/损坏/归档接线
    缺失 → anomaly；两字段均缺 = pre-hook-block epoch 豁免。best-effort 非对抗级（C3 ⑤ 哲学）。
    """

    def _write(self, env, full, prev, include_prev=True):
        sf, sd = _make_state_dir(env)
        gd = {"ecc_findings": []}
        if full is not None:
            gd["hook_block_log"] = full
        prev_entry = {"r_phase": "R7"}
        if prev is not None and include_prev:
            prev_entry["hook_block_log"] = prev
        emb = {"archived_at": "2026-09-05T08:00:00+00:00", "r_phase": "R7",
               "gate_data_full": gd, "prev_entry": prev_entry, "finding_journal": []}
        p = Path(sd) / ".gatekeeper.ember.R7.json"
        p.write_text(json.dumps(emb, ensure_ascii=False), encoding="utf-8")
        return str(p)

    def _entry(self, i):
        return {"tool": "SearchReplace", "target": f"f{i}.py",
                "reason": "dangerous command", "time": f"2026-09-05T00:00:{i:02d}Z"}

    def test_consistent_tail_slice(self, env):
        full = [self._entry(1), self._entry(2), self._entry(3)]
        rec = gem.reconcile_ember(self._write(env, full, full[-2:]))
        assert rec["ok"] is True and rec["gate"]["ok"] is True
        assert rec["gate"]["verdict"] == "no-findings"
        assert rec["reconcile"]["anomalies"] == []
        assert rec["reconcile"]["hook_block"] == {"full": 3, "prev": 2}

    def test_prev_slice_drift_detected(self, env):
        """prev 归档段非 gate_data_full 尾部子序列 → 记忆改写/烧失候选。"""
        full = [self._entry(1), self._entry(2), self._entry(3)]
        rec = gem.reconcile_ember(self._write(env, full, [self._entry(1), self._entry(3)]))
        assert rec["gate"]["ok"] is False and rec["gate"]["verdict"] == "anomalies"
        assert any("切片漂移" in str(a["reason"]) for a in rec["reconcile"]["anomalies"])

    def test_malformed_prev_entry_detected(self, env):
        """prev 条目缺 reason → 意图记忆烧失候选。"""
        full = [self._entry(1)]
        rec = gem.reconcile_ember(self._write(env, full, [{"tool": "RunCommand"}]))
        assert rec["gate"]["ok"] is False
        assert any("缺 reason" in str(a["reason"]) for a in rec["reconcile"]["anomalies"])

    def test_archiving_wiring_gap_detected(self, env):
        """gate_data_full 有 hook_block_log 但 prev_entry 无归档切片 → 归档接线缺失。"""
        rec = gem.reconcile_ember(self._write(env, [self._entry(1)], None))
        assert rec["gate"]["ok"] is False
        assert any("归档接线缺失" in str(a["reason"]) for a in rec["reconcile"]["anomalies"])

    def test_pre_hook_block_epoch_exempt(self, env):
        """两字段均缺（2026-09-02 前快照）→ 豁免不误报。"""
        rec = gem.reconcile_ember(self._write(env, None, None))
        assert rec["gate"]["ok"] is True and rec["gate"]["verdict"] == "no-findings"
        assert rec["reconcile"]["anomalies"] == []
        assert rec["reconcile"]["hook_block"] == {"full": 0, "prev": 0}

    def test_cross_state_carry_no_false_anomaly(self, env):
        """ECC-727423471579（2026-10-07 质询跨臂共识）：`gate_data_full` 回落自**其它 state**
        （`gate_data_source != prev_entry_source`）时，`prev_entry` 的切片来自本 state 而
        `gate_data_full` 来自另一 state ⟹ 尾部子序列比较**无判据力**，不得据其报
        「归档接线缺失 / 切片漂移」假异常（真断链与跨源伪链此刻不可区分）；
        应显式降级 `baseline_cross_state`（禁静默豁免、禁假红）。"""
        sf, sd = _make_state_dir(env)
        emb = {"archived_at": "2026-09-05T08:00:00+00:00", "r_phase": "R7",
               "gate_data_full": {"ecc_findings": [], "hook_block_log": [self._entry(1)]},
               "gate_data_source": "/default/.gatekeeper.state",
               "prev_entry": {"r_phase": "R7"},  # 域态自身无 hook_block_log 切片
               "prev_entry_source": "/domain/.gatekeeper.state.skill.x",
               "finding_journal": []}
        p = Path(sd) / ".gatekeeper.ember.R7.json"
        p.write_text(json.dumps(emb, ensure_ascii=False), encoding="utf-8")
        rec = gem.reconcile_ember(str(p))
        assert rec["reconcile"]["anomalies"] == [], "跨状态异源不得报假异常"
        assert rec["reconcile"]["hook_block"].get("baseline_cross_state") is True


class TestEmberExportJournalAnchor:
    """C8c（ECC-9C207D6FC458，2026-10-04）：ember 导出的 journal 解析块须在活动 state 的
    `<state>.finding-journal.jsonl` 为空时回落**权威 default state** 的 journal 作锚，否则
    域态（由 carry 建立、无自身 journal）导出会静默嵌**空锚** ⟹ ember_replay 恒判
    「journal 缺失 + closed 无前序事件」（实测 .gatekeeper.ember.ECO-SCAN.json = 14 findings / 0 行）。

    做法同 `test_docgen_generator`：钉点落在实现处（B10h 迁移后由
    `gk_discover_archive._resolve_journal` 承载，不再从 gatekeeper-cli.sh 抽内联块）；
    改名/结构变更后须同步本测试。
    """

    def _run_block(self, tmp, active_journal, default_journal):
        from gk_discover_archive import _resolve_journal
        active = str(Path(tmp) / "active.state")
        default = str(Path(tmp) / "default.state")
        for p, lines in ((active + ".finding-journal.jsonl", active_journal),
                         (default + ".finding-journal.jsonl", default_journal)):
            Path(p).write_text("".join(l + "\n" for l in lines), encoding="utf-8")
        lines, source = _resolve_journal(active, default)
        return {"finding_journal": lines, "journal_source": source}

    def test_active_journal_present_uses_itself(self, tmp_path):
        emb = self._run_block(tmp_path, ["a1", "a2"], ["d1"])
        assert emb["finding_journal"] == ["a1", "a2"]
        assert emb["journal_source"].endswith("active.state.finding-journal.jsonl")

    def test_empty_active_falls_back_to_default(self, tmp_path):
        emb = self._run_block(tmp_path, [], ["d1", "d2"])
        assert emb["finding_journal"] == ["d1", "d2"]
        assert emb["journal_source"].endswith("default.state.finding-journal.jsonl")

    def test_both_empty_records_source_no_fabrication(self, tmp_path):
        emb = self._run_block(tmp_path, [], [])
        assert emb["finding_journal"] == []
        assert emb["journal_source"].endswith("active.state.finding-journal.jsonl")
