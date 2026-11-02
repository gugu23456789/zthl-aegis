"""H3 `zthl/eventbus.py` 单测 —— 逐条钉死「设计七条」的机械判据 + 消费方级降级验证。

设计唯一源 = zthl-adapter 计划 §3「H3 EventBus 设计七条」；本文件按条给臂，禁散文式断言：
  ① 命名法 `zthl.<domain>.<verb>`（含 fail-loud 负例）
  ② 零新增依赖（AST 提 import 根，须 ⊆ 标准库）
  ③ 禁总线内自建状态存储（源码零写盘 API + 实例**无**事实字段）
  ④ 不可用降级文件轮询 + **丢事件后状态不漂移**（消费方级）
  ⑤ 零 `aliveMap`
  ⑥ 新名 `SignalHub` 在技能仓 grep 唯一
另有：typed events / EventFilter / 通配符订阅 / 错误隔离 / 中间件链（断路 + 限流）五组功能臂。
"""
from __future__ import annotations

import ast
import dataclasses
import json
import sys
from pathlib import Path

import pytest

_SKILL_ROOT = Path(__file__).resolve().parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

from zthl import eventbus as eb  # noqa: E402

_MOD_SRC = (_SKILL_ROOT / "zthl" / "eventbus.py").read_text(encoding="utf-8")


# ── 设计第 1 条：事件分类法自研（`zthl.<domain>.<verb>`）─────────────────────────
class TestEventNaming:
    def test_seed_events_match_naming_rule(self):
        assert eb.EVENTS, "种子事件表不得为空（消费方按名订阅的唯一源）"
        for name in eb.EVENTS.values():
            eb.Event(name)  # 不抛 = 合法
            assert name.startswith("zthl."), name

    @pytest.mark.parametrize("bad", [
        "StateChanged",            # 无域前缀
        "zthl",                    # 段数不足
        "zthl.state",              # 段数不足
        "zthl.state.changed.extra",  # 段数过多
        "zthl.State.changed",      # 大写域
        "zthl.state.Changed",      # 大写动词
        "zthl.*.changed",          # 通配符只属订阅侧，事件名禁通配
        "",                        # 空
    ])
    def test_bad_name_fails_loud(self, bad):
        with pytest.raises(eb.EventNameError):
            eb.Event(bad)

    def test_zero_aip_sse_type_reference(self):
        """E9.6 边界除外（计划七条第 1 条）：本模块零 AIP §6.2 SSE 载荷类型引用。"""
        for t in ("TaskStatusUpdateEvent", "ProductChunkEvent"):
            assert t not in _MOD_SRC


# ── 设计第 2 条：三形态可选扩展（零新增服务/依赖）──────────────────────────────
class TestZeroNewDependency:
    def test_imports_are_stdlib_only(self):
        tree = ast.parse(_MOD_SRC)
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
        third_party = sorted(r for r in roots if r not in sys.stdlib_module_names)
        assert not third_party, f"新增第三方依赖（违设计第 2 条）：{third_party}"

    def test_no_service_client_keywords(self):
        for kw in ("requests", "httpx", "pika", "kombu", "aioredis", "boto3"):
            assert kw not in _MOD_SRC, f"疑似引入服务客户端：{kw}"


# ── 设计第 3 条：禁总线内自建状态存储 ────────────────────────────────────────────
class TestNoInternalStateStore:
    @pytest.mark.parametrize("api", ["open(", "json.dump", "write_text", "os.replace", "sqlite3"])
    def test_no_persistence_api(self, api):
        assert api not in _MOD_SRC, f"总线内出现写盘/持久化 API：{api}"

    def test_hub_instance_has_no_fact_fields(self):
        """实例字段 = 订阅表 + 锁 + 关闭位 —— **零**事实/缓存字段（判据：无持久化状态字段）。"""
        hub = eb.SignalHub()
        assert set(vars(hub)) == {"_subs", "_lock", "_closed"}

    def test_publishing_creates_no_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*"), lambda ev: None, name="noop")
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"], {"k": "v"}))
        assert list(tmp_path.iterdir()) == [], "分发过程不得产生任何落盘（含影子缓存）"


# ── 设计第 5 条：零 aliveMap ─────────────────────────────────────────────────────
class TestNoAliveMap:
    """判据 = 「零 `aliveMap` **字段**」（设计第 5 条）。

    ⚠ 只查**代码标识**（名字/属性/参数/关键字），**不**查文档字符串 —— 模块 docstring 按设计
    必须显式记「零 aliveMap（liveness 归 AMP 查询面）」这条禁令，把该词也算违规 = 自锁判据。
    """

    def test_no_alive_identifier_in_code(self):
        idents = set()
        for node in ast.walk(ast.parse(_MOD_SRC)):
            if isinstance(node, ast.Name):
                idents.add(node.id)
            elif isinstance(node, ast.Attribute):
                idents.add(node.attr)
            elif isinstance(node, (ast.arg, ast.keyword)):
                idents.add(node.arg or "")
        bad = sorted(i for i in idents if "alive" in i.lower())
        assert not bad, f"出现 liveness 类字段（违设计第 5 条）：{bad}"

    def test_dataclass_and_hub_surfaces_have_no_liveness_field(self):
        fields = set(vars(eb.SignalHub()))
        for cls in (eb.Event, eb.EventFilter, eb.DeliveryResult):
            fields |= {f.name for f in dataclasses.fields(cls)}
        fields |= set(eb.Subscription("x", lambda e: None).__slots__)
        bad = sorted(f for f in fields if "alive" in f.lower())
        assert not bad, f"运行面暴露 liveness 字段：{bad}"


# ── 功能臂 1：typed events + EventFilter（含 source / predicate 谓词）────────────
class TestEventFilter:
    def _hub_with(self, handler, *_filters):
        hub = eb.SignalHub()
        subs = [hub.subscribe(f, handler, name=f.name) for f in _filters]
        return hub, subs

    def test_filter_by_source(self):
        seen = []
        hub, _ = self._hub_with(lambda ev: seen.append(ev.source),
                                eb.EventFilter(name="zthl.*", source="runner"))
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"], source="runner"))
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"], source="hook"))
        assert seen == ["runner"]

    def test_filter_by_predicate(self):
        seen = []
        hub, _ = self._hub_with(
            lambda ev: seen.append(ev.payload.get("level")),
            eb.EventFilter(name="zthl.*", predicate=lambda ev: ev.payload.get("level") == "L2"))
        hub.publish(eb.Event(eb.EVENTS["CONTEXT_PROJECTED"], {"level": "L2"}))
        hub.publish(eb.Event(eb.EVENTS["CONTEXT_PROJECTED"], {"level": "L1"}))
        assert seen == ["L2"]


# ── 功能臂 2：通配符订阅 ────────────────────────────────────────────────────────
class TestWildcardSubscription:
    def test_all_domains(self):
        got = []
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*"), lambda ev: got.append(ev.name), name="all")
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        hub.publish(eb.Event(eb.EVENTS["FINDING_CLOSED"]))
        assert got == [eb.EVENTS["STATE_CHANGED"], eb.EVENTS["FINDING_CLOSED"]]

    def test_domain_scoped(self):
        got = []
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.state.*"), lambda ev: got.append(ev.name), name="st")
        hub.subscribe(eb.EventFilter(name="zthl.finding.*"), lambda ev: got.append(ev.name), name="fi")
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        hub.publish(eb.Event(eb.EVENTS["CONTEXT_PROJECTED"]))
        hub.publish(eb.Event(eb.EVENTS["FINDING_CLOSED"]))
        assert got == [eb.EVENTS["STATE_CHANGED"], eb.EVENTS["FINDING_CLOSED"]]

    def test_verb_wildcard(self):
        got = []
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*.changed"), lambda ev: got.append(ev.name), name="v")
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        hub.publish(eb.Event(eb.EVENTS["FINDING_CLOSED"]))
        assert got == [eb.EVENTS["STATE_CHANGED"]]

    def test_unsubscribe_stops_delivery(self):
        got = []
        hub = eb.SignalHub()
        sub = hub.subscribe(eb.EventFilter(name="zthl.*"), lambda ev: got.append(ev.name), name="s")
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        assert hub.unsubscribe(sub) is True
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        assert got == [eb.EVENTS["STATE_CHANGED"]]
        assert hub.unsubscribe(sub) is False


# ── 功能臂 3：错误隔离（一个订阅者崩不拖垮其余）────────────────────────────────
class TestErrorIsolation:
    def test_crash_isolates_others(self):
        calls = []
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*"), lambda ev: calls.append("a"), name="a")
        hub.subscribe(eb.EventFilter(name="zthl.*"),
                      lambda ev: (_ for _ in ()).throw(RuntimeError("boom")), name="b")
        hub.subscribe(eb.EventFilter(name="zthl.*"), lambda ev: calls.append("c"), name="c")
        results = hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        by_name = {r.subscription: r for r in results}
        assert calls == ["a", "c"], "崩溃订阅者不得吃掉其余投递"
        assert by_name["a"].ok and by_name["c"].ok
        assert by_name["b"].ok is False and "RuntimeError: boom" in by_name["b"].error

    def test_exception_never_propagates(self):
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*"),
                      lambda ev: (_ for _ in ()).throw(ValueError("x")), name="bad")
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))  # 不抛


# ── 功能臂 4：中间件链（CircuitBreaker / RateLimiter）───────────────────────────
class TestMiddlewareChain:
    def test_rate_limiter_drops_over_limit(self):
        hits = []
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*"), lambda ev: hits.append(ev.name),
                      middleware=[eb.RateLimiter(limit=1, per_seconds=60.0)], name="rl")
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        r2 = hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        assert hits == [eb.EVENTS["STATE_CHANGED"]]
        assert r2[0].ok is False and r2[0].skipped == "rate_limited"

    def test_circuit_breaker_opens_after_threshold(self):
        calls = []

        def flaky(ev):
            calls.append(1)
            raise RuntimeError("down")

        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*"), flaky,
                      middleware=[eb.CircuitBreaker(failure_threshold=2, reset_after=3600.0)],
                      name="cb")
        assert hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))[0].ok is False
        assert hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))[0].ok is False
        assert len(calls) == 2
        r3 = hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        assert r3[0].skipped == "circuit_open", "开路后应**不再调用**处理器"
        assert len(calls) == 2

    def test_circuit_breaker_half_open_recovers(self):
        state = {"fail": True}
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*"),
                      lambda ev: (_ for _ in ()).throw(RuntimeError("x")) if state["fail"] else "ok",
                      middleware=[eb.CircuitBreaker(failure_threshold=1, reset_after=0.0)],
                      name="cb")
        assert hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))[0].ok is False
        state["fail"] = False
        r = hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))  # reset_after=0 ⟹ 半开试探
        assert r[0].ok is True and r[0].value == "ok"

    def test_skip_is_not_counted_as_circuit_failure(self):
        """限流跳过 ≠ 失败：断路器只认处理器异常（否则限流会把电路误开）。"""
        breaker = eb.CircuitBreaker(failure_threshold=1, reset_after=3600.0)
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*"), lambda ev: "ok",
                      middleware=[eb.RateLimiter(limit=1, per_seconds=60.0), breaker], name="m")
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))  # 被限流跳过
        assert breaker.state == "closed"
        assert hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))[0].skipped == "rate_limited"

    def test_middleware_order_is_outermost_first(self):
        order = []

        def mw(tag):
            def _mw(ev, next_):
                order.append(tag)
                return next_(ev)
            return _mw

        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.*"), lambda ev: order.append("handler"),
                      middleware=[mw("outer"), mw("inner")], name="chain")
        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        assert order == ["outer", "inner", "handler"]


# ── 设计第 4 条（消费方级）：降级文件轮询 + 丢事件后状态不漂移 ────────────────────
class TestConsumerLevelFallback:
    @staticmethod
    def _write_state(path: Path, value):
        path.write_text(json.dumps({"gate_data": {"narrow_tasks": value}}, ensure_ascii=False),
                        encoding="utf-8")

    def test_hub_unavailable_switches_to_fallback(self, tmp_path):
        st = tmp_path / ".gatekeeper.state"
        self._write_state(st, ["a"])
        hub = eb.SignalHub()
        hub.close()
        assert hub.available() is False
        res = hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        assert res[0].subscription == "(hub)" and "hub_closed" in res[0].error
        # 降级：只回读既有事实源（不新建第二副本）
        assert eb.PollFallback(str(st), "gate_data.narrow_tasks").read() == ["a"]

    def test_dropped_event_does_not_drift(self, tmp_path):
        """核心判据：事件被**丢弃**只推迟通知，不使消费方读到偏离权威面的值。"""
        st = tmp_path / ".gatekeeper.state"
        self._write_state(st, ["a"])
        fb = eb.PollFallback(str(st), "gate_data.narrow_tasks")
        seen = []
        hub = eb.SignalHub()
        hub.subscribe(eb.EventFilter(name="zthl.state.*"),
                      lambda ev: seen.append(fb.read()),
                      middleware=[eb.RateLimiter(limit=1, per_seconds=60.0)], name="projector")

        hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        assert seen == [["a"]]

        self._write_state(st, ["a", "b"])            # 权威面前进
        r2 = hub.publish(eb.Event(eb.EVENTS["STATE_CHANGED"]))
        assert r2[0].skipped == "rate_limited"       # 事件丢失
        assert len(seen) == 1
        assert fb.read() == ["a", "b"], "丢事件后读到值必须仍等于权威面（不漂移）"

    def test_fallback_missing_file_returns_none(self, tmp_path):
        fb = eb.PollFallback(str(tmp_path / "nope.json"), "gate_data.narrow_tasks")
        assert fb.read() is None

    def test_poll_once_reports_change(self, tmp_path):
        st = tmp_path / ".gatekeeper.state"
        self._write_state(st, ["a"])
        fb = eb.PollFallback(str(st), "gate_data.narrow_tasks")
        val, changed = fb.poll_once(previous=["a"])
        assert val == ["a"] and changed is False
        self._write_state(st, ["a", "b"])
        val, changed = fb.poll_once(previous=["a"])
        assert val == ["a", "b"] and changed is True


# ── 设计第 6 条：命名归口（`SignalHub` 在技能仓 grep 唯一）──────────────────────
class TestNamingUniqueness:
    """判据 = 「新名在技能仓 grep 唯一」（设计第 6 条）。

    白名单按 **H3 工件族前缀**（`zthl/` 本体 + `scripts/test_zthl_*` 其测试），**不**枚举文件名
    —— 枚举式会在新增 H3 测试文件时假红（实测：加 `test_zthl_context_e2e.py` 即触发），
    而前缀式仍能抓住真违规（旧组件/既有链路复用同名 = 同名不同物，正是 D3 要防的）。
    """

    _ALLOWED_PREFIXES = ("zthl/", "scripts/test_zthl_", "docs/analysis/", "docs/plans/",
                         "references/")
    # ECC-F0454B4691C3：`docs/analysis/subagent/**` = subagent 质询/审计**生成产物**（非源），
    #   其正文合法引用 `SignalHub` 之名 ⟹ 计入白名单（避免"生成产物命中即假红"）。
    #   2026-10-02 扩到 `docs/analysis/**`（含 `commit-evolution-*.md` 等仓级分析产物）——同理由
    #   （生成物非第二实现）；真违规（旧组件/既有链路复用同名）仍在 `scripts/`/`zthl/` 下被拦。
    #   2026-10-04 扩到 `docs/plans/**`：计划文档**合法点名** `zthl/eventbus.py::SignalHub`
    #   （H3 EventBus 宿主裁定，正本见 `2026-09-18-edit-budget-dual-track-plan.md`）——「文档描述」
    #   ≠「第二实现」；判据本意是防**同名不同物**，仍由 `scripts/`/`zthl/` 面拦真违规。
    #   2026-10-27 扩到 `references/**`：`references/xspi-defense.md` 同样**合法点名**
    #   `zthl/eventbus.py` 的 `SignalHub`（说明本技能审计面为何不复用该名）⟹ 同理由。
    #   `references/` 只放文档/JSON 产物，无第二实现面。
    _SKIP_DIRS = {".git", "__pycache__", ".gitnexus", ".keys", "node_modules"}
    _MAX_BYTES = 262144

    def test_signalhub_is_repo_unique(self):
        hits = set()
        for p in _SKILL_ROOT.rglob("*"):
            if not p.is_file():
                continue
            if any(part in self._SKIP_DIRS for part in p.parts):
                continue
            if p.suffix.lower() not in {".py", ".sh", ".md", ".json", ".ps1", ".bat"}:
                continue
            try:
                if p.stat().st_size > self._MAX_BYTES:
                    continue
                if "SignalHub" in p.read_text(encoding="utf-8", errors="ignore"):
                    hits.add(p.relative_to(_SKILL_ROOT).as_posix())
            except OSError:
                continue
        bad = sorted(h for h in hits if not h.startswith(self._ALLOWED_PREFIXES))
        assert not bad, f"`SignalHub` 命名越界（同名不同物）：{bad}"
        assert hits, "本臂自身必须能命中（防扫描面失效导致假绿）"
