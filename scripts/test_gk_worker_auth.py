#!/usr/bin/env python3
"""test_gk_worker_auth.py — A7（2026-10-28）加固锁

原 worker 的三处硬伤各对应一组臂：
  ① **无鉴权** ⟹ 无 token / 错 token 必须 `unauthorized`；
  ② **任意代码执行** ⟹ 默认只有白名单 op；`eval` 需 `--allow-eval`，且 builtins 收窄
     （`open`/`__import__` 等不可用）；
  ③ **命令替换恒挂 + 同生命周期** ⟹ 客户端 detached 拉起 + pidfile 轮询（测试真起进程）。
"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_worker as W  # noqa: E402
import gk_worker_client as C  # noqa: E402

TOKEN = "t0ken-for-test"


# ─── ① 鉴权 ────────────────────────────────────────────────────────────────

def test_missing_token_unauthorized():
    assert W.handle_payload({"op": "ping"}, TOKEN) == {"ok": False, "error": "unauthorized"}
    assert W.handle_payload({"auth": "wrong", "op": "ping"}, TOKEN)["error"] == "unauthorized"


def test_empty_configured_token_rejects_everything():
    """空 token 不得退化成「无鉴权」—— 宁可全拒。"""
    assert W.handle_payload({"auth": "", "op": "ping"}, "")["ok"] is False


def test_non_dict_payload():
    assert W.handle_payload(["x"], TOKEN)["ok"] is False


# ─── ② 白名单 op ──────────────────────────────────────────────────────────

def test_ping_ok():
    r = W.handle_payload({"auth": TOKEN, "op": "ping"}, TOKEN)
    assert r["ok"] is True and r["result"]["pid"] == os.getpid()


def test_unknown_op_rejected_not_evaluated():
    r = W.handle_payload({"auth": TOKEN, "op": "os.system", "args": {"cmd": "id"}}, TOKEN)
    assert r["ok"] is False and "unknown op" in r["error"]


def test_eval_disabled_by_default():
    r = W.handle_payload({"auth": TOKEN, "op": "eval", "code": "1+1"}, TOKEN)
    assert r["ok"] is False and "eval disabled" in r["error"]


def test_eval_builtins_are_restricted():
    r = W.handle_payload({"auth": TOKEN, "op": "eval", "code": "open('/tmp/x','w')"},
                         TOKEN, allow_eval=True)
    assert r["ok"] is False and "NameError" in r["error"]


def test_eval_allowed_when_opted_in():
    r = W.handle_payload({"auth": TOKEN, "op": "eval", "code": "1+1"},
                         TOKEN, allow_eval=True)
    assert r["ok"] is True and r["result"] == "2"


def test_state_view_reads_dotted_path(tmp_path):
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"gate_data": {"edit_budget": {"used": 7}}}), encoding="utf-8")
    r = W.handle_payload({"auth": TOKEN, "op": "state_view",
                          "args": {"state": str(st), "path": "gate_data.edit_budget.used"}}, TOKEN)
    assert r["ok"] is True and r["result"]["value"] == 7
    # 2026-10-29：`state_view` 必带 stamp（mtime_ns/size/sha256）—— 只读面可自证新鲜度
    assert set(r["result"]["stamp"]) == {"path", "mtime_ns", "size", "sha256"}
    keys = W.handle_payload({"auth": TOKEN, "op": "state_view",
                             "args": {"state": str(st)}}, TOKEN)
    assert keys["result"]["keys"] == ["gate_data"]


def test_state_view_missing_state_fails_loud(tmp_path):
    r = W.handle_payload({"auth": TOKEN, "op": "state_view",
                          "args": {"state": str(tmp_path / "nope.json")}}, TOKEN)
    assert r["ok"] is False and "不可读" in r["error"]


# ─── ③ detached 启动 + pidfile 轮询（真进程）──────────────────────────────

@pytest.fixture
def live_worker(tmp_path):
    pf = str(tmp_path / "worker.pid")
    info = C.ensure_daemon(pf, ttl=60.0)
    assert info, "daemon 未在 5s 内就绪（pidfile 轮询失败）"
    yield pf, info
    C.stop(pf)


def test_pidfile_has_five_lines_0600(live_worker):
    """pid / port / token / **code_epoch**（2026-10-29 A7 接线新增第 4 行）。

    第 4 行的用途见 `gk_worker_epoch.py`：客户端据此拒绝**旧代码 daemon**（TTL 内改过
    `gk_*` 模块而 daemon 未重启时，按旧逻辑作答 = 静默错误）。
    """
    pf, info = live_worker
    assert info["port"] > 0 and info["token"]
    assert info.get("epoch"), "pidfile 缺 code_epoch ⟹ 旧 daemon 无法被识别"
    lines = Path(pf).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    if os.name == "posix":
        assert (os.stat(pf).st_mode & 0o777) == 0o600, "token 文件权限必须 0600"


def test_client_roundtrip_and_auth(live_worker):
    pf, _info = live_worker
    r = C.call("ping", pidfile=pf)
    assert r["ok"] is True, r
    # 拿掉鉴权字段 ⟹ 服务端拒绝（证明不是「谁来都行」）
    import socket
    info = C.read_pidfile(pf)
    with socket.create_connection(("127.0.0.1", info["port"]), timeout=5) as s:
        s.sendall(b'{"op":"ping"}\n')
        raw = s.recv(65536)
    assert json.loads(raw.decode())["error"] == "unauthorized"


def test_client_state_view(live_worker, tmp_path):
    pf, _info = live_worker
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"stage": "ECO-DOC"}), encoding="utf-8")
    r = C.call("state_view", {"state": str(st), "path": "stage"}, pidfile=pf)
    assert r["ok"] is True and r["result"]["value"] == "ECO-DOC"
    assert r["result"]["stamp"]["sha256"], "跨进程调用同样须回吐 stamp"
