# -*- coding: utf-8 -*-
"""Q3-① 判别臂（hook-xenv §15.3-Q3）：持久化块日志 vs state ring。

红先证据（2026-09-25，实现前）：`_persistent_block_count` / `_record_block_persistent`
符号不存在（AttributeError）= 持久源能力缺失；且 ring 侧 `_BLOCK_LOG_MAX=24` 结构性
丢历史（30 块压测下 ring 只剩 24）⟹ 误报率分母必须换持久源。

臂：
  A 30 块压测：ring = 24（TTL 内）而持久源 = 30 ⟹ 计数差 6 > 0（判别臂主断言）；
  B 持久源行格式：JSONL 逐行合法 JSON，含 ts/tool/kind；
  C 窗口过滤：window_s 生效（旧 ts 被排除）；
  D fail-quiet 契约：持久写对坏目录不抛（声明过的设计选择，取证据副产品不阻断门禁）。
"""
import json
import os
import sys
import time
from pathlib import Path

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pre_tool_hook as h  # noqa: E402

N = 30  # > _BLOCK_LOG_MAX(24) ⟹ ring 必丢尾


@pytest.fixture()
def sandbox(monkeypatch, tmp_path):
    """隔离沙箱：STATE_FILE 指向 tmp 副本（防写穿真 state），_CALL_* 置为块意图形态。"""
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    monkeypatch.setattr(h, "STATE_FILE", st)
    monkeypatch.setattr(h, "_CALL_IN_SCOPE", True)
    monkeypatch.setattr(h, "_CALL_TOOL", "RunCommand")
    monkeypatch.setattr(h, "_CALL_KIND", "block")
    monkeypatch.setattr(h, "_CALL_TARGET", "")
    monkeypatch.setattr(h, "_CALL_CMD", "")
    monkeypatch.setattr(h, "_CALL_REASON", "")
    return st


def test_arm_a_ring_vs_persistent_divergence(sandbox):
    """臂 A（主判据）：30 块 ⟹ ring=24，持久源=30，差 >0 ⟹ ring 不可作长期分母。"""
    for i in range(N):
        h._CALL_TARGET = "/tmp/gk_q3_t_%d" % i
        h._CALL_CMD = "cmd-%d" % i
        h._CALL_REASON = "r-%d" % i
        h._record_block_intent()
    d = json.loads(sandbox.read_text(encoding="utf-8"))
    ring = d["gate_data"]["hook_block_log"]
    assert len(ring) == h._BLOCK_LOG_MAX, "ring 应停在 24: %d" % len(ring)
    persistent = h._persistent_block_count(str(sandbox))
    assert persistent == N, "持久源应全量保留 %d: %d" % (N, persistent)
    assert persistent - len(ring) > 0, "判别臂未打穿（ring 未丢历史）"


def test_arm_b_jsonl_line_format(sandbox):
    """臂 B：JSONL 逐行合法 JSON，含 ts/tool/kind 字段。"""
    h._CALL_TARGET = "/tmp/gk_q3_fmt"
    h._record_block_intent()
    day_dir = h._persistent_block_dir(str(sandbox))
    files = list(day_dir.glob("*.jsonl"))
    assert len(files) == 1, "按天滚动应单文件: %r" % files
    lines = [ln for ln in files[0].read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1
    rec = json.loads(lines[0])
    for k in ("ts", "tool", "kind"):
        assert k in rec, "缺字段 %s: %r" % (k, rec)


def test_arm_c_window_filter(sandbox):
    """臂 C：window_s 生效——伪造成旧 ts 的行被排除。"""
    h._CALL_TARGET = "/tmp/gk_q3_old"
    h._record_block_intent()
    day_dir = h._persistent_block_dir(str(sandbox))
    f = list(day_dir.glob("*.jsonl"))[0]
    rec = json.loads(f.read_text(encoding="utf-8").splitlines()[0])
    rec["ts"] = time.time() - 99999  # 伪造旧行
    f.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    assert h._persistent_block_count(str(sandbox), window_s=3600) == 0, "窗口过滤未生效（旧行未排除）"
    assert h._persistent_block_count(str(sandbox), window_s=None) == 1, "无窗计数应含旧行"


def test_arm_d_fail_quiet_on_bad_dir(sandbox, monkeypatch):
    """臂 D：持久写对坏目录不抛（fail-quiet 是声明过的设计选择）。"""
    monkeypatch.setattr(h, "_persistent_block_dir",
                        lambda state_path="": Path("/proc/gk_q3_nonexist/hook-block"))
    h._CALL_TARGET = "/tmp/gk_q3_bad"
    try:
        h._record_block_persistent({"ts": time.time(), "tool": "t", "kind": "block"})
    except Exception as e:  # pragma: no cover
        pytest.fail("fail-quiet 契约被破坏: %r" % e)
