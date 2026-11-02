#!/usr/bin/env python3
"""test_gk_worker_state_stamp.py — A7 只读面加固锁（2026-10-29）

原 `_load_state` 的判据是 `mtime(float) <= cached_mtime` ⟹ 两个洞（对应下列臂）：
  ① **同秒改写被吃成命中** —— 本机实测 `/tmp` 时间戳只有 **1s 粒度**：同一秒内两次改写
     `st_mtime`（float）与 `st_size` **完全相同** ⟹ `<=` 直接返回旧 dict = 陈旧读
     （正是「advance 了但门禁没变」那一类：worker 吐旧 stage/预算）。
  ② **无可自证的内容指纹** —— 调用方拿到视图也不知道它对应哪份字节。
下列臂全部**红先**（落刀前必红）：
  · ① 同秒改写不得陈旧（racy 窗口）
  · ② `state_view` 必须回吐 stamp，且 sha256 = 实际服务字节的 sha256
  · ③ 文件变了 stamp 必变（不能说「没变过」）
  · ④ 缺文件/坏 JSON ⟹ op fail-loud（不吐半份视图）
  · ⑤ 深路径 / 缺键 / 顶层键名 三种形态不变（回归，非红先）
"""
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_worker as W  # noqa: E402

TOKEN = "t0ken-for-test"


def _write(p: Path, obj) -> str:
    p.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, ensure_ascii=False)
    p.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _age(p: Path, secs: int = 10) -> None:
    """把 mtime 前移到 racy 窗口外（仅测试手法；真实写者不回拨）。"""
    st = os.stat(p)
    t = st.st_mtime_ns - secs * 10 ** 9
    os.utime(p, ns=(t, t))


def _op_state_view(**args) -> dict:
    return W.handle_payload({"auth": TOKEN, "op": "state_view", "args": args}, TOKEN)


class TestNoStaleRead:
    def test_same_second_rewrite_not_stale(self, tmp_path):
        """① 同秒改写（1s 粒度下 mtime/size 完全相同）⟹ 必须读出新值，不得命中旧缓存。"""
        p = tmp_path / "skill" / ".gatekeeper.state"
        _write(p, {"stage": "STAGE_0", "r_phase": "R-T1"})
        assert W._op_state_view({"state": str(p), "path": "stage"})["value"] == "STAGE_0"
        _write(p, {"stage": "STAGE_2", "r_phase": "R-T1"})   # 同长度、同秒
        got = W._op_state_view({"state": str(p), "path": "stage"})
        assert got["value"] == "STAGE_2", "同秒改写被吃成陈旧读 ⟹ 门禁会按旧 stage 判定"

    def test_rewrite_after_aging_changes_stamp(self, tmp_path):
        """③ 旧文件（窗口外）缓存命中；改写后 stamp 必变（不能「装没变过」）。"""
        p = tmp_path / "skill" / ".gatekeeper.state"
        _write(p, {"stage": "STAGE_0"})
        _age(p)
        first = W._op_state_view({"state": str(p), "path": "stage"})
        again = W._op_state_view({"state": str(p), "path": "stage"})
        assert first["stamp"]["sha256"] == again["stamp"]["sha256"], "同一份字节 ⟹ 同一指纹"
        _write(p, {"stage": "STAGE_9"})
        later = W._op_state_view({"state": str(p), "path": "stage"})
        assert later["value"] == "STAGE_9"
        assert later["stamp"]["sha256"] != first["stamp"]["sha256"]


class TestStampVerifiability:
    def test_stamp_sha_matches_served_bytes(self, tmp_path):
        """② stamp.sha256 必须 = 磁盘字节的 sha256（调用方可据此判新鲜）。"""
        p = tmp_path / "skill" / ".gatekeeper.state"
        want = _write(p, {"stage": "STAGE_0", "worktree": "/repo"})
        got = W._op_state_view({"state": str(p)})
        assert got["stamp"]["sha256"] == want, "指纹不是对实际字节取的 ⟹ 无法自证"
        st = os.stat(p)
        assert got["stamp"]["size"] == st.st_size
        assert got["stamp"]["mtime_ns"] == st.st_mtime_ns

    def test_missing_and_corrupt_fail_loud(self, tmp_path):
        """④ 缺文件 / 坏 JSON ⟹ op 报错（不吐半份视图、不静默空结果）。"""
        d = tmp_path / "skill"
        d.mkdir()
        (d / ".gatekeeper.state").write_text("{corrupt", encoding="utf-8")
        for p in (d / ".gatekeeper.state", d / "nope.state"):
            r = _op_state_view(state=str(p))
            assert r["ok"] is False, r
            assert "不可读" in r["error"], r


class TestViewShapes:
    def test_keys_deep_and_missing(self, tmp_path):
        """⑤ 三种形态回归：顶层键名 / 深路径 / 缺键。"""
        p = tmp_path / "skill" / ".gatekeeper.state"
        _write(p, {"stage": "STAGE_0", "gate_data": {"edit_budget": {"remaining": 7}}})
        keys = _op_state_view(state=str(p))["result"]
        assert "stage" in keys["keys"] and "gate_data" in keys["keys"]
        assert keys["stamp"]["path"] == str(p)
        deep = _op_state_view(state=str(p), path="gate_data.edit_budget.remaining")["result"]
        assert deep["value"] == 7
        miss = _op_state_view(state=str(p), path="gate_data.nope")["result"]
        assert miss["missing"] == "gate_data.nope"
