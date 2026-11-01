"""
test_gk_dispatch_watch.py -- F4 通用进度探测（coder/质询 共用）红先臂
================================================================================
被测：`scripts/gk_dispatch_watch.py`（0-API 只读）+ `gatekeeper-cli.sh::monitor --watch` 接线。

缺口（用户令「给探针做自动化 / 取代手轮询」）：下发后进度此前只能由主 agent **手轮询**。
本模块给统一探测面：`pipeline`（pr-* 流水线批）/ `aggregation`（12-hex 聚合指纹批）/
`worktree`（coder 落刀，接收裁决复用 gk_receive_check）。

钉定纪律：① 纯只读；② 不可判定 ⟹ done=None（UNKNOWN），**禁**默认熔断；③ 批号双轨不静默。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def _state(tmp_path, *, pipeline=None, history=None) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"task_pipeline": pipeline or [],
                                            "subagent_history": history or []}}),
                  encoding="utf-8")
    return str(st)


# ── ① 对象判别（三类 + 不可判）──────────────────────────────────────────────
def test_classify_targets():
    from gk_dispatch_watch import classify_target
    assert classify_target("pr-1792052350-ab12cd34") == "pipeline"
    assert classify_target("66bae2b0678a") == "aggregation"
    assert classify_target("/mnt/x/wt") == "worktree"
    assert classify_target("nonsense") == ""
    assert classify_target("") == ""


# ── ② pipeline 批：pending 未清 ⟹ 未完成 ────────────────────────────────────
def test_pipeline_pending_not_done(tmp_path):
    from gk_dispatch_watch import snapshot
    st = _state(tmp_path, pipeline=[
        {"id": "a", "batch": "pr-1-ab12cd34", "status": "pending"},
        {"id": "b", "batch": "pr-1-ab12cd34", "status": "approved"}])
    s = snapshot(st, "pr-1-ab12cd34")
    assert s["kind"] == "pipeline" and s["total"] == 2 and s["pending"] == 1
    assert s["done"] is False, s


def test_pipeline_resolved_done(tmp_path):
    from gk_dispatch_watch import snapshot
    st = _state(tmp_path, pipeline=[
        {"id": "a", "batch": "pr-1-ab12cd34", "status": "approved"}])
    s = snapshot(st, "pr-1-ab12cd34")
    assert s["done"] is True, s


# ── ③ aggregation 批：expect 才可判 done；无 expect ⟹ UNKNOWN（禁默认熔断）──
def test_aggregation_expect_gates_done(tmp_path):
    from gk_dispatch_watch import snapshot
    st = _state(tmp_path, history=[
        {"subagent_id": "s1", "batch_id": "66bae2b0678a", "report_file": "/r/1.md"}])
    s = snapshot(st, "66bae2b0678a", expect=2)
    assert s["runs"] == 1 and s["done"] is False and s["report_files"] == ["/r/1.md"], s
    assert snapshot(st, "66bae2b0678a", expect=1)["done"] is True


def test_aggregation_unknown_without_expect(tmp_path):
    from gk_dispatch_watch import snapshot
    st = _state(tmp_path, history=[{"batch_id": "66bae2b0678a"}])
    assert snapshot(st, "66bae2b0678a")["done"] is None   # 禁默认熔断（R3）


# ── ④ 批号双轨不静默：未命中 ⟹ found=False + 可用批号清单（R6）────────────
def test_unresolved_lists_available_batch_ids(tmp_path):
    from gk_dispatch_watch import snapshot
    st = _state(tmp_path, pipeline=[{"batch": "pr-1-ab12cd34", "status": "pending"}])
    s = snapshot(st, "deadbeefcafe")
    assert s["found"] is False, s
    assert "pr-1-ab12cd34" in s["available_batch_ids"], s


# ── ⑤ worktree：接收裁决**复用** gk_receive_check（禁第二实现）─────────────
def test_worktree_reuses_receive_check(tmp_path, monkeypatch):
    import gk_receive_check as rcv
    from gk_dispatch_watch import snapshot
    monkeypatch.setattr(rcv, "check",
                        lambda wt, mr, sf, sd, master="master": {"rc": 1, "files": ["M\ta.py"]})
    s = snapshot(_state(tmp_path), "/x/wt", kind="worktree")
    assert s["kind"] == "worktree" and s["done"] is True, s
    monkeypatch.setattr(rcv, "check",
                        lambda wt, mr, sf, sd, master="master": {"rc": 3, "reason": "不可判"})
    assert snapshot(_state(tmp_path), "/x/wt", kind="worktree")["done"] is None


# ── ⑥ 结构性：monitor --watch 接线（零新增 _CMD_REG）───────────────────────
def test_monitor_watch_wired_no_new_cmd():
    src = (Path(__file__).parent.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "--watch" in src, "monitor 未接线 --watch"
    assert "gk_dispatch_watch.py" in src, "monitor --watch 未调共享模块"
    # 零新增：watch 挂既有 monitor，不得出现新命令注册
    assert "_CMD_REG[dispatch-watch]" not in src and "_CMD_REG[watch]" not in src
