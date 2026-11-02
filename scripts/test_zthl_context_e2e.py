"""H3 **消费方级 e2e**：Context Projector（投影写盘）→ `pre_tool_hook` 读方。

计划 §3 H3 验收面：「**消费方级验证**（pre_tool_hook 经 Context Injector 读到最新 level；
含**丢事件后状态不漂移**）」。本文件把这条验收面钉成可机检的三臂：

1. 读方拿到**最新 level** —— 用真实的 `pre_tool_hook.emit_context_if_changed()`（真读方）
   吃真实投影产物形态（键集/checksum 口径**逐字复刻** `gatekeeper-cli.sh::_write_context_file`）。
2. 读方**幂等** —— checksum 未变不再输出（既有 `context.seen` 语义）。
3. **丢事件不漂移** —— 变更通知经 `SignalHub` + `RateLimiter` 被**丢弃**，读方仍读到最新 level：
   因为 state 是**唯一权威**、通知只决定「何时说」（H3 设计第 3/4 条 + 待裁定 D4 落刀）。

⚠ 本文件**不**改既有实现（H3 只消费不新建）：读方 = 既有 `pre_tool_hook`；投影产物形态在
   `_projection()` 里复刻，若 `_write_context_file` 键集变更，本文件的 `test_shape_matches_projector`
   会失败并提示同步（防夹具与实现漂移成假绿）。
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

_SKILL_ROOT = Path(__file__).resolve().parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

import pre_tool_hook as pt_hook          # noqa: E402  既有读方（本项目根模块）
from zthl import eventbus as eb          # noqa: E402  H3 通知面

_VIEWS = _SKILL_ROOT / "scripts" / "gk_views.py"


def _projection(stage: str, r_phase: str, edits_remaining: int) -> dict:
    """复刻投影写盘器的产物形态（键集 + checksum 口径；实现见 `gk_views.py::cmd_context_cache`）。"""
    ctx = {
        "stage": stage,
        "r_phase": r_phase,
        "branch": "master",
        "worktree": "<home>/.trae/worktrees/x",
        "entropy_rate": 0.0,
        "edit_budget": {"remaining": edits_remaining},
        "previous_rejections": 0,
        "updated_at": "2026-10-01T00:00:00Z",
    }
    payload = json.dumps(ctx, sort_keys=True, ensure_ascii=False)
    ctx["_checksum"] = hashlib.sha256(payload.encode()).hexdigest()[:16]
    return ctx


@pytest.fixture
def ctx_env(tmp_path, monkeypatch):
    """把读方指向沙箱 context 文件（`CONTEXT_FILE` 为既有 env 注入点）。"""
    p = tmp_path / ".gatekeeper.context.json"
    monkeypatch.setattr(pt_hook, "CONTEXT_FILE", p, raising=False)
    monkeypatch.setattr(pt_hook, "_CONTEXT_SEEN_FILE", tmp_path / ".gatekeeper.context.seen")

    def write(**kw):
        p.write_text(json.dumps(_projection(**kw), ensure_ascii=False), encoding="utf-8")
        return p

    return write


class TestProjectorShapePinned:
    def test_shape_matches_projector(self):
        """夹具键集须 ⊆ 实现键集（实现新增键不误报；夹具造出实现没有的键则报警）。

        B10b（2026-10-28）：投影实现已由 `gatekeeper-cli.sh::_write_context_file`
        内联块迁至 `gk_views.py::cmd_context_cache`（cli 侧仅一行委派）⟹ 钉点随单一源迁移。
        """
        impl = _VIEWS.read_text(encoding="utf-8")
        block = impl.split("def cmd_context_cache", 1)[1].split("\ndef ", 1)[0]
        for key in ("stage", "r_phase", "branch", "worktree", "entropy_rate", "edit_budget",
                    "previous_rejections", "updated_at"):
            assert f'"{key}"' in block, f"投影实现不再写 `{key}` —— 请同步本夹具"
        assert "sort_keys=True" in block and "sha256" in block, "checksum 口径变更，请同步本夹具"


class TestConsumerLevelE2E:
    def test_hook_reads_latest_level(self, ctx_env, capsys):
        ctx_env(stage="ZH1", r_phase="ZH1", edits_remaining=6)
        pt_hook.emit_context_if_changed()
        err = capsys.readouterr().err
        assert "GATEKEEPER: ZH1 | ZH1" in err, err
        assert "edits_remaining=6" in err, err

    def test_unchanged_checksum_is_silent(self, ctx_env, capsys):
        ctx_env(stage="ZH1", r_phase="ZH1", edits_remaining=6)
        pt_hook.emit_context_if_changed()
        capsys.readouterr()
        pt_hook.emit_context_if_changed()          # 同 checksum ⟹ 幂等静默
        assert capsys.readouterr().err == ""

    def test_dropped_notification_does_not_drift(self, ctx_env, capsys):
        """核心判据：变更通知被丢弃，读方仍读到**最新 level**（state 为权威，非第二副本）。"""
        ctx_env(stage="ZH1", r_phase="ZH1", edits_remaining=6)
        pt_hook.emit_context_if_changed()
        assert "| ZH1 |" in capsys.readouterr().err

        notified: list = []
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.context.projected"),
                      lambda ev: notified.append(ev.payload.get("stage")),
                      middleware=[eb.RateLimiter(limit=1, per_seconds=60.0)], name="notify")
        hub.publish(eb.Event(eb.EVENTS["CONTEXT_PROJECTED"], {"stage": "ZH1"}))

        ctx_env(stage="ZH2", r_phase="ZH2", edits_remaining=2)          # 权威面前进
        dropped = hub.publish(eb.Event(eb.EVENTS["CONTEXT_PROJECTED"], {"stage": "ZH2"}))
        assert dropped[0].skipped == "rate_limited", dropped           # 通知**丢失**
        assert notified == ["ZH1"]

        pt_hook.emit_context_if_changed()                              # 读方直读权威面
        latest = capsys.readouterr().err
        assert "| ZH2 |" in latest and "ZH1" not in latest, latest
        assert eb.PollFallback(str(pt_hook.CONTEXT_FILE), "stage").read() == "ZH2"

    def test_hub_closed_falls_back_to_file_read(self, ctx_env):
        """降级面：总线不可用 ⟹ 只回读投影文件（不新建事实源、不漂移）。"""
        p = ctx_env(stage="ZH2", r_phase="ZH2", edits_remaining=2)
        hub = eb.SignalHub()
        hub.close()
        assert hub.available() is False
        assert eb.PollFallback(str(p), "r_phase").read() == "ZH2"

    def test_missing_context_file_is_noop(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(pt_hook, "CONTEXT_FILE", tmp_path / "nope.json", raising=False)
        monkeypatch.setattr(pt_hook, "_CONTEXT_SEEN_FILE", tmp_path / ".seen")
        pt_hook.emit_context_if_changed()
        assert capsys.readouterr().err == ""
