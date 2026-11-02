#!/usr/bin/env python3
"""test_gk_discover_archive.py — B10h：discover 跨 R 归档（history + 余烬 + seal + state 重置）。"""
import json
import os
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).parent / "gk_discover_archive.py"


def _run(*args, env=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run([sys.executable, str(CLI)] + list(args),
                          input="", capture_output=True, text=True,
                          encoding="utf-8", env=e)


def _state(tmp_path, obj, name="state.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


TS = "2026-10-28T10:30:00+08:00"


class TestArchive:
    def test_full_archive_and_reset(self, tmp_path):
        st = _state(tmp_path, {
            "stage": "R5", "r_phase": "R5",
            "gate_data": {"best": {"score": 9}, "edit_count": 4,
                          "rejected_edits": [{"violations": ["v1"]}],
                          "key_rotation_log": [{"e": 1}], "cron_health": {"ok": 1}},
            "monitor_scores": {"R5": {"score": 0.8}},
            "history": [{"r_phase": "R4"}],
        })
        dflt = str(tmp_path / "default.json")
        keydir = str(tmp_path / "keys")
        os.makedirs(keydir)
        p = _run("archive", st, dflt, keydir, TS)
        assert p.returncode == 0, p
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert d["gate_data"] == {} and d["monitor_scores"] == {}
        assert len(d["history"]) == 2
        prev = d["history"][-1]
        assert prev["r_phase"] == "R5" and prev["completed_at"] == TS
        assert prev["stages_reached"] == "R5"
        assert prev["rejection_count"] == 1
        assert prev["rejection_patterns"] == [["v1"]]
        assert prev["monitor_scores_summary"] == {"R5": 0.8}
        assert prev["edit_count"] == 4
        assert prev["key_rotation_log"] == [{"e": 1}]
        assert prev["cron_health"] == {"ok": 1}
        ember = json.loads((tmp_path / ".gatekeeper.ember.R5.json").read_text(
            encoding="utf-8"))
        assert ember["archived_at"] == TS and ember["r_phase"] == "R5"
        assert ember["gate_data_full"]["edit_count"] == 4
        assert ember["gate_data_source"] == st
        assert ember["prev_entry_source"] == st
        assert ember["prev_entry"]["rejection_count"] == 1
        assert "seal" not in ember          # 无密钥 ⟹ 不签名（旧式 try/except 吞）

    def test_no_r_phase_no_archive(self, tmp_path):
        st = _state(tmp_path, {"r_phase": None, "gate_data": {"a": 1},
                               "history": [{"x": 1}]})
        assert _run("archive", st, str(tmp_path / "d.json"),
                    str(tmp_path / "k"), TS).returncode == 0
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert d["history"] == [{"x": 1}] and d["gate_data"] == {}
        assert not list(tmp_path.glob(".gatekeeper.ember.*.json"))

    def test_history_capped_100(self, tmp_path):
        st = _state(tmp_path, {"r_phase": "R9", "gate_data": {},
                               "history": [{"i": i} for i in range(105)]})
        _run("archive", st, str(tmp_path / "d.json"), str(tmp_path / "k"), TS)
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert len(d["history"]) == 100
        assert d["history"][-1]["r_phase"] == "R9"

    def test_journal_fallback_to_default_state(self, tmp_path):
        st = _state(tmp_path, {"r_phase": "R1", "gate_data": {}})
        dflt = _state(tmp_path, {"gate_data": {}}, name="default.json")
        Path(st + ".finding-journal.jsonl").write_text("", encoding="utf-8")
        Path(dflt + ".finding-journal.jsonl").write_text('{"a":1}\n\n', encoding="utf-8")
        _run("archive", st, dflt, str(tmp_path / "k"), TS)
        ember = json.loads((tmp_path / ".gatekeeper.ember.R1.json").read_text(
            encoding="utf-8"))
        assert ember["finding_journal"] == ['{"a":1}']
        assert ember["journal_source"] == dflt + ".finding-journal.jsonl"

    def test_gate_data_fallback_to_default_state(self, tmp_path):
        st = _state(tmp_path, {"r_phase": "R2", "gate_data": {}})
        dflt = _state(tmp_path, {"gate_data": {"from_default": True}},
                      name="default.json")
        _run("archive", st, dflt, str(tmp_path / "k"), TS)
        ember = json.loads((tmp_path / ".gatekeeper.ember.R2.json").read_text(
            encoding="utf-8"))
        assert ember["gate_data_full"] == {"from_default": True}
        assert ember["gate_data_source"] == dflt

    def test_keeps_newest_10_embers(self, tmp_path):
        st = _state(tmp_path, {"r_phase": "R3", "gate_data": {}})
        for i in range(11):
            f = tmp_path / (".gatekeeper.ember.OLD%d.json" % i)
            f.write_text("{}", encoding="utf-8")
            os.utime(f, (1000 + i, 1000 + i))
        _run("archive", st, str(tmp_path / "d.json"), str(tmp_path / "k"), TS)
        embers = sorted(p.name for p in tmp_path.glob(".gatekeeper.ember.*.json"))
        assert len(embers) == 10
        assert ".gatekeeper.ember.R3.json" in embers

    def test_monitor_scores_not_dict_nonzero_no_reset(self, tmp_path):
        """`v.get('score')` 对非 dict 值抛 AttributeError ⟹ 整块失败、state 不重置。"""
        st = _state(tmp_path, {"r_phase": "R5", "gate_data": {"a": 1},
                               "monitor_scores": {"R5": "bad"}})
        before = Path(st).read_text(encoding="utf-8")
        p = _run("archive", st, str(tmp_path / "d.json"), str(tmp_path / "k"), TS)
        assert p.returncode != 0
        assert Path(st).read_text(encoding="utf-8") == before

    def test_missing_state_nonzero(self, tmp_path):
        assert _run("archive", str(tmp_path / "no.json"), str(tmp_path / "d.json"),
                    str(tmp_path / "k"), TS).returncode != 0

    def test_bad_state_nonzero(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{broken", encoding="utf-8")
        assert _run("archive", str(p), str(tmp_path / "d.json"),
                    str(tmp_path / "k"), TS).returncode != 0

    def test_usage_exit_2(self):
        assert _run().returncode == 2
        assert _run("archive", "a", "b", "c").returncode == 2


class TestSeal:
    def test_ed25519_seal_when_keys_present(self, tmp_path):
        pytest = __import__("pytest")
        ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
        ser = pytest.importorskip("cryptography.hazmat.primitives.serialization")
        st = _state(tmp_path, {"r_phase": "R6", "gate_data": {"x": 1}})
        kd = tmp_path / "keys"
        kd.mkdir()
        priv = ed.Ed25519PrivateKey.generate()
        (kd / "audit_ed25519.pem").write_bytes(priv.private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        (kd / "audit_ed25519.pub").write_bytes(priv.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
        assert _run("archive", st, str(tmp_path / "d.json"), str(kd), TS).returncode == 0
        ember = json.loads((tmp_path / ".gatekeeper.ember.R6.json").read_text(
            encoding="utf-8"))
        seal = ember.pop("seal")
        assert seal["alg"] == "ed25519" and seal["key"] == "audit_ed25519"
        assert seal["signed_at"] == TS
        canon = json.dumps(ember, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":")).encode("utf-8")
        import base64
        priv.public_key().verify(base64.b64decode(seal["sig"]), canon)
