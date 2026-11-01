#!/usr/bin/env python3
"""host α1 Phase A 红先臂（H1–H8）。

被测模块：`scripts/gk_audit_host.py`（本文件先落，模块后落 ⟹ 初始为红）。
判据正本：`docs/plans/2026-10-19-host-alpha1-skeleton-plan.md` §3。
"""
import ast
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
HOST = SCRIPTS / "gk_audit_host.py"
sys.path.insert(0, str(SCRIPTS))

import gk_credit_ledger as CL  # noqa: E402
import gk_state_patch as SP  # noqa: E402


# ── 夹具 helpers ────────────────────────────────────────────────────────────
def _state(tmp_path: Path) -> str:
    return str(tmp_path / ".gatekeeper.state")


def _raise(i: str, delta: int = 0) -> dict:
    return {"ts": "2026-10-19T00:00:00Z", "id": i, "kind": "raise",
            "delta": delta, "source": "test", "reason": "test"}


def _success(ref: str) -> dict:
    return {"ts": "2026-10-19T00:00:01Z", "id": "o1", "kind": "success",
            "delta": 5, "ref": ref, "model_version": "m",
            "temperature": 0, "seed": 1}


def _write_rows(state: str, rows: list, seal: bool = False) -> Path:
    p = Path(str(state) + CL.SUFFIX)
    p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                 encoding="utf-8")
    if seal:
        CL.seal_now(state)
    return p


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(HOST), *args],
                          capture_output=True, text=True, timeout=30)


def _last_json(proc: subprocess.CompletedProcess) -> dict:
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    assert lines, "host 无 stdout JSON（stderr=%r）" % (proc.stderr,)
    return json.loads(lines[-1])


@pytest.fixture()
def keys(tmp_path):
    """临时 Ed25519 audit key（不依赖仓库 `.keys`）。"""
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


# ── H1 只读对账契约 ─────────────────────────────────────────────────────────
def test_once_reports_pending(tmp_path):
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1"), _raise("r2"), _success("r1")])
    proc = _run("--state", state, "--once")
    assert proc.returncode == 0, proc.stderr
    out = _last_json(proc)
    assert out["raises"] == 2
    assert out["audited"] == 1
    assert out["pending"] == 1
    assert out["ok"] is False
    assert out["unreconciled"] == ["r2"]
    assert out["bad"] == 0
    assert out["seal_ok"] is False
    assert out["seal_mode"] == ""
    assert out["poll_ok"] is True


def test_once_reports_pending_ghost_ref(tmp_path):
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1"), _raise("r2"), _success("ghost")])
    out = _last_json(_run("--state", state, "--once"))
    assert out["raises"] == 2
    assert out["audited"] == 1
    assert out["pending"] == 2
    assert out["unreconciled"] == ["r1", "r2"]
    assert out["ok"] is False


def test_once_reports_pending_duplicate_id(tmp_path):
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1"), _raise("r1")])
    out = _last_json(_run("--state", state, "--once"))
    assert out["raises"] == 2
    assert out["pending"] == 2, "pending 按行计（与 reconcile 逐字一致）"
    assert out["unreconciled"] == ["r1", "r1"]


def test_once_reports_pending_idless_raise(tmp_path):
    state = _state(tmp_path)
    _write_rows(state, [{"ts": "2026-10-19T00:00:00Z", "kind": "raise", "delta": 0}])
    out = _last_json(_run("--state", state, "--once"))
    assert out["raises"] == 0
    assert out["pending"] == 0
    assert out["ok"] is True
    assert out["raises_without_id"] == 1, "无 id raise 必须显式可见，禁静默 0 债"


# ── H2 零写面（行为） ───────────────────────────────────────────────────────
def test_read_only_no_writes(tmp_path):
    state = _state(tmp_path)
    led = _write_rows(state, [_raise("r1"), _raise("r2")], seal=True)
    seal = Path(str(led) + ".seal")
    assert led.is_file() and seal.is_file() and led.stat().st_size > 0
    before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in (led, seal)}
    proc = _run("--state", state, "--once")
    assert proc.returncode == 0, proc.stderr
    after = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in (led, seal)}
    assert before == after, "host 不得写账本 / 封印"


def test_read_only_no_writes_seal_mismatch(tmp_path):
    state = _state(tmp_path)
    led = _write_rows(state, [_raise("r1")], seal=True)
    with open(led, "a", encoding="utf-8") as fh:      # 测试侧篡改（非 host）
        fh.write(json.dumps(_raise("r2"), ensure_ascii=False) + "\n")
    out = _last_json(_run("--state", state, "--once"))
    assert out["seal_ok"] is False
    assert out.get("seal_reason") == "digest_mismatch"


# ── H3 零写面（静态，双探测器 + 双正控） ────────────────────────────────────
def _ast_io_write_hits(src: str) -> list:
    """IO 写面检测器：open(w/a)、write_text/write_bytes、os.* 破坏性、写模块调用。"""
    tree = ast.parse(src)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else "")
            if name == "open":
                modes = [a.value for a in node.args[1:] if isinstance(a, ast.Constant)]
                modes += [kw.value.value for kw in node.keywords
                          if kw.arg == "mode" and isinstance(kw.value, ast.Constant)]
                if any(isinstance(m, str) and any(c in m for c in "wa+") for m in modes):
                    hits.append("open(w/a)")
            if name in {"write_text", "write_bytes", "replace", "remove",
                        "unlink", "rename", "makedirs", "mkdir"}:
                hits.append(name)
            if name in {"append", "seal_now"} and isinstance(fn, ast.Attribute):
                root = fn.value.id if isinstance(fn.value, ast.Name) else ""
                if root in {"CL", "gk_credit_ledger"}:
                    hits.append("gk_credit_ledger." + name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in {"subprocess"}:
                    hits.append("import:subprocess")
        if isinstance(node, ast.ImportFrom) and node.module == "gk_credit_ledger":
            for a in node.names:
                if a.name in {"append", "seal_now"}:
                    hits.append("from:gk_credit_ledger." + a.name)
    return hits


def test_no_write_surface():
    assert HOST.is_file(), "存在性门：gk_audit_host.py 必须先实存（禁空真）"
    src = HOST.read_text(encoding="utf-8")

    from test_gk_audit_evidence_writers import _has_write
    adv = (SCRIPTS / "gk_advance.py").read_text(encoding="utf-8")
    assert _has_write(adv, "rejected_edits"), "键集正控失效"
    assert _has_write(adv, "entropy_history"), "键集正控失效"
    bad_keys = sorted(k for k in SP._STATE_PATCH_DENY_KEYS if _has_write(src, k))
    assert not bad_keys, "host 命中禁写键：%s" % bad_keys

    hits = _ast_io_write_hits(src)
    assert not hits, "host 命中 IO 写面：%s" % sorted(set(hits))

    ctl = _ast_io_write_hits((SCRIPTS / "gk_credit_ledger.py").read_text(encoding="utf-8"))
    assert "open(w/a)" in ctl and "write_text" in ctl, "IO 探测器正控失效"


# ── H4 分权真值来源（平台门 + 注入缝） ──────────────────────────────────────
def _fake_proc(root: Path, pid: int, uid: int, ppid: int) -> None:
    d = root / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "status").write_text("Name:\tt\nUid:\t%d\t%d\t%d\t%d\nPPid:\t%d\n"
                              % (uid, uid, uid, uid, ppid), encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="/proc 与 select 为 POSIX 语义")
def test_separation_report(tmp_path):
    assert HOST.is_file()
    import gk_audit_host as H

    assert H.classify_separation(0, 10, 0, 10) == ("absent", "same_uid")
    assert H.classify_separation(0, 10, 1000, 99) == ("separated", "")
    assert H.classify_separation(0, 10, 1000, 10)[0] == "unknown"

    proc = tmp_path / "proc"
    _fake_proc(proc, os.getpid(), 0, os.getppid())
    _fake_proc(proc, os.getppid(), 1000, 1)
    _fake_proc(proc, 999, 1000, 1)

    host, sep_parent, reason_parent, is_parent = H.host_identity(
        proc_root=str(proc), editor_pid=os.getppid())
    assert sep_parent == "unknown" and is_parent is True
    assert host["uid"] == 0 and host["ppid"] == os.getppid()

    _, sep, reason, is_parent2 = H.host_identity(proc_root=str(proc), editor_pid=999)
    assert sep == "separated" and is_parent2 is False

    _, sep2, reason2, is_parent3 = H.host_identity(platform="nt")
    assert sep2 == "unknown" and reason2
    assert is_parent3 == "unknown", "nt 平台无法判父子 ⟹ 须显式 unknown"

    state = _state(tmp_path)
    _write_rows(state, [_raise("r1")])
    out = _last_json(_run("--state", state, "--once"))
    assert out["separation"] in {"separated", "absent", "unknown"}
    assert "editor_is_parent" in out


# ── H5 无 outcome 生产（AST 导入面） ────────────────────────────────────────
def _ast_forbidden(src: str) -> list:
    tree = ast.parse(src)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in {"urllib", "requests", "http", "subprocess"}:
                    hits.append("import:" + a.name)
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in {
                "urllib", "requests", "http", "subprocess"}:
            hits.append("from:" + (node.module or ""))
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else "")
            if name in {"getattr", "__import__"}:
                hits.append(name)
        if isinstance(node, ast.Import) and any(a.name == "importlib" for a in node.names):
            hits.append("import:importlib")
    return hits


def test_no_outcome_producer():
    assert HOST.is_file()
    src = HOST.read_text(encoding="utf-8")
    assert not _ast_forbidden(src), "host 命中禁导入 / 动态导入：%s" % _ast_forbidden(src)
    assert not [h for h in _ast_io_write_hits(src) if h.startswith(("from:gk_credit_ledger", "gk_credit_ledger."))]

    ctl = _ast_io_write_hits((SCRIPTS / "gk_credit_ledger.py").read_text(encoding="utf-8"))
    assert "open(w/a)" in ctl and "write_text" in ctl, "正控必须命中 open('a')/write_text"


# ── H6 watch 驱动可达（内联 tailing + 注入缝） ──────────────────────────────
def _read_json_line(proc, timeout=3.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([proc.stdout], [], [], max(0.0, end - time.time()))
        if r:
            line = proc.stdout.readline()
            if line.strip():
                return json.loads(line)
    raise AssertionError("watch 未在 %.1fs 内输出新快照" % timeout)


@pytest.mark.skipif(os.name == "nt", reason="select 对管道为 POSIX 语义")
def test_watch_detects_append(tmp_path):
    assert HOST.is_file()
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1")])
    proc = subprocess.Popen([sys.executable, str(HOST), "--state", state,
                             "--watch", "--interval", "0.05"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    try:
        first = _read_json_line(proc)
        assert first["pending"] == 1
        _write_rows(state, [_raise("r1"), _raise("r2")])
        second = _read_json_line(proc)
        assert second["pending"] == 2
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.mark.skipif(os.name == "nt", reason="select 对管道为 POSIX 语义")
def test_watch_detects_append_same_size(tmp_path):
    assert HOST.is_file()
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1")])
    proc = subprocess.Popen([sys.executable, str(HOST), "--state", state,
                             "--watch", "--interval", "0.05"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    try:
        first = _read_json_line(proc)
        assert first["unreconciled"] == ["r1"]
        _write_rows(state, [_raise("r3")])       # 等长重写（r1 -> r3）
        second = _read_json_line(proc)
        assert second["unreconciled"] == ["r3"], "等长重写必须由 mtime_ns 触发"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


# ── H7 缺账本 / 不可读 fail-loud（host 侧） ─────────────────────────────────
def test_missing_ledger_fails(tmp_path):
    assert HOST.is_file()
    proc = _run("--state", _state(tmp_path), "--once")
    assert proc.returncode == 3
    assert _last_json(proc)["error"] == "ledger_missing"


def test_missing_ledger_fails_when_dir(tmp_path):
    assert HOST.is_file()
    state = _state(tmp_path)
    Path(str(state) + CL.SUFFIX).mkdir(parents=True)
    proc = _run("--state", state, "--once")
    assert proc.returncode == 3
    assert _last_json(proc)["error"] == "ledger_is_dir"


def test_missing_ledger_fails_when_unreadable(tmp_path):
    assert HOST.is_file()
    import gk_audit_host as H
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1")])
    assert H.precheck_ledger(state, access_fn=lambda p, m: False) == "ledger_unreadable"


def test_missing_ledger_fails_all_bad(tmp_path):
    assert HOST.is_file()
    state = _state(tmp_path)
    p = Path(str(state) + CL.SUFFIX)
    p.write_text("{bad}\nnot-json\n", encoding="utf-8")
    proc = _run("--state", state, "--once")
    assert proc.returncode == 3
    assert _last_json(proc)["error"] == "all_lines_bad"


# ── H8 半行 / 坏行 / 封印可见 ───────────────────────────────────────────────
def test_torn_tail_visible(tmp_path):
    assert HOST.is_file()
    state = _state(tmp_path)
    p = Path(str(state) + CL.SUFFIX)
    p.write_text(json.dumps(_raise("r1"), ensure_ascii=False) + "\n"
                 + '{"ts": "2026-10-19T00:00:02Z", "kind": "rai',
                 encoding="utf-8")
    proc = _run("--state", state, "--once")
    assert proc.returncode == 0
    out = _last_json(proc)
    assert out["bad"] == 1
    assert out["pending"] == 1, "半行不得导致已完整行的 pending 少报"
    assert out["seal_ok"] is False
    assert out["seal_reason"] == "seal_missing"


# ── H9/H10 方案 a：bookkeeping 分列 + 签名基线 cutoff ────────────────────────
def _bookkeeping(i: str) -> dict:
    return {"ts": "2026-10-19T00:00:02Z", "id": i, "kind": "bookkeeping",
            "delta": 0, "source": "state_patch_set_nested", "reason": "budget"}


def test_once_splits_legacy_and_debt(tmp_path, keys):
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1"), _raise("r2"), _raise("r3"),
                        _bookkeeping("b1")])
    assert CL.write_baseline(state, "r2", reason="pre-host bookkeeping",
                             key_dir=keys).get("ok")
    out = _last_json(_run("--state", state, "--once", "--key-dir", keys))
    assert out["raises"] == 3, "raises 应为 raise 行全量（含 legacy）"
    assert out["legacy_raises"] == 2
    assert out["debt_raises"] == 1
    assert out["pending"] == 1 and out["unreconciled"] == ["r3"]
    assert out["bookkeeping"] == 1, "预算记账必须单独可见"
    assert out["baseline"]["ok"] is True
    assert out["baseline"]["mode"] == "ed25519"
    assert out["baseline"]["cutoff_id"] == "r2"
    assert out["ok"] is False


def test_once_tampered_baseline_does_not_hide_debt(tmp_path, keys):
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1"), _raise("r2")])
    assert CL.write_baseline(state, "r2", reason="cut", key_dir=keys).get("ok")
    bp = Path(str(state) + CL.BASELINE_SUFFIX)
    rec = json.loads(bp.read_text(encoding="utf-8"))
    rec["cutoff_id"] = "99999999T999999-9999"
    bp.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
    out = _last_json(_run("--state", state, "--once", "--key-dir", keys))
    assert out["baseline"]["ok"] is False
    assert out["baseline"]["reason"] == "digest_mismatch"
    assert out["legacy_raises"] == 0
    assert out["debt_raises"] == 2 and out["pending"] == 2
    assert out["unreconciled"] == ["r1", "r2"]


# ── H11 完整性判定（债以外）────────────────────────────────────────────────
def test_once_integrity_verdict(tmp_path):
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1"), _success("r1")], seal=True)
    out = _last_json(_run("--state", state, "--once"))
    assert out["ok"] is True and out["verdict"] == "ok", out
    assert out["integrity_ok"] is True

    bad = _state(tmp_path / "bad")
    Path(bad).parent.mkdir(parents=True, exist_ok=True)
    _write_rows(bad, [_raise("r1"), _success("r1")], seal=True)
    with open(str(bad) + CL.SUFFIX, "a", encoding="utf-8") as fh:
        fh.write("{torn\n")
    out2 = _last_json(_run("--state", bad, "--once"))
    assert out2["ok"] is True, "债已平"
    assert out2["integrity_ok"] is False and out2["verdict"] == "integrity", out2


def test_once_invalid_baseline_breaks_integrity(tmp_path, keys):
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1")], seal=True)
    assert CL.write_baseline(state, "r1", key_dir=keys).get("ok")
    out = _last_json(_run("--state", state, "--once", "--key-dir", keys))
    assert out["integrity_ok"] is True and out["verdict"] == "ok", out
    bp = Path(str(state) + CL.BASELINE_SUFFIX)
    rec = json.loads(bp.read_text(encoding="utf-8"))
    rec["cutoff_id"] = "99999999T999999-9999"
    bp.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
    out2 = _last_json(_run("--state", state, "--once", "--key-dir", keys))
    assert out2["baseline"]["ok"] is False
    assert out2["integrity_ok"] is False and out2["verdict"] == "debt", out2


# ── H12 watch 必须感知基线变化 ──────────────────────────────────────────────
@pytest.mark.skipif(os.name == "nt", reason="select 对管道为 POSIX 语义")
def test_watch_detects_baseline_change(tmp_path, keys):
    assert HOST.is_file()
    state = _state(tmp_path)
    _write_rows(state, [_raise("r1"), _raise("r2")])
    proc = subprocess.Popen([sys.executable, str(HOST), "--state", state,
                             "--watch", "--interval", "0.05", "--key-dir", keys],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    try:
        first = _read_json_line(proc)
        assert first["pending"] == 2
        assert CL.write_baseline(state, "r1", key_dir=keys).get("ok")
        second = _read_json_line(proc)
        assert second["legacy_raises"] == 1, "基线新增未触发重算"
        assert second["pending"] == 1
    finally:
        proc.terminate()
        proc.wait(timeout=5)



