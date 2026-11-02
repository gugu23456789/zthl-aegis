"""ZTHL 事件分发中枢（`zthl-harness-adapter` 计划 ZH1 · H3）
================================================================

定位
----
`zthl/*` 子包的第一个实装件：**进程内**事件分发 —— typed events + 过滤 + 通配符订阅
+ 错误隔离 + 中间件链（断路器 / 限流器）。

⚠ **跨进程投递面不在此模块**（H3 待裁定 D1 已落刀：owner = CLI 父进程 bash；asyncio 仅活在
runner 子进程内、不承担跨进程投递）。本模块只解决「同一进程内多订阅者扇出」。

命名（设计第 6 条）
------------------
类名 = `SignalHub`。既有 `EventBus` 段落实为 context 投影写盘器（已正名 Context Projector），
新组件**避开**该名；`SignalHub` 在本仓 grep 唯一（唯一性由单测钉死）。

设计七条对齐（唯一源 = 计划 §3「H3 EventBus 设计七条」；此处不复述计划正文）
--------------------------------------------------------------------------
1. 事件名一律 `zthl.<domain>.<verb>`（`Event.__post_init__` fail-loud；零 AIP §6.2 类型引用）。
2. 三形态为**可选扩展**：本模块零新增依赖（仅标准库），不引入 HTTP 回调端 / MQ。
3. **禁本模块自建状态存储**：无落盘、无事实缓存、无查询 API（查询面 owner = 既有
   `gk_state_query.py`；H3 只消费不新建）。⚠ 中间件持**进程内运行时计数**（失效数/令牌）——
   那是熔断/限流自身的运行态，**不是**事实源的第二副本（不落盘、不跨进程、不参与查询）。
4. 不可用时降级为**文件轮询**（`PollFallback`）：只**回读**既有事实源 ⟹ 丢事件只影响
   「何时通知」，不影响「读到什么」（丢事件后状态不漂移）。
5. 零 `aliveMap` 字段（liveness 投影归 AMP 查询面）。

线程模型：单进程多线程（`threading.RLock` 保护订阅表）；**不做跨进程投递**。
"""
from __future__ import annotations

import fnmatch
import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence

__all__ = [
    "EVENTS", "EventNameError", "Event", "EventFilter", "DeliveryResult",
    "DeliverySkipped", "RateLimited", "CircuitOpen",
    "Subscription", "SignalHub", "RateLimiter", "CircuitBreaker", "PollFallback",
]

# ── 事件命名法（设计第 1 条）：`zthl.<domain>.<verb>` ──────────────────────────────
# 判据：三段固定 + domain/verb 为小写字母开头的 `[a-z0-9_]` 串。订阅侧用 fnmatch 通配
# （`zthl.*` / `zthl.state.*` / `zthl.*.changed`），**事件名本身禁通配**（fail-loud）。
_EVENT_NAME_RE = re.compile(r"^zthl\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")

# H3 种子事件名（唯一源；消费方按名订阅，禁各处二次定义/字面量散落）。
EVENTS = {
    "STATE_CHANGED": "zthl.state.changed",
    "CONTEXT_PROJECTED": "zthl.context.projected",
    "FINDING_CLOSED": "zthl.finding.closed",
}


class EventNameError(ValueError):
    """事件名不符合 `zthl.<domain>.<verb>`（设计第 1 条，fail-loud 不静默降级）。"""


@dataclass(frozen=True)
class Event:
    """一次事件。`payload` 约定只承载**普通数据**（dict/list/标量）。

    不在此强制 JSON 可序列化：跨进程投递不在本模块职责内（见模块 docstring 的 D1 说明），
    序列化约束应由真正的跨进程通道（CLI 父进程的 4/5 通道）承担。
    """

    name: str
    payload: dict = field(default_factory=dict)
    source: str = ""
    ts: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not _EVENT_NAME_RE.match(self.name or ""):
            raise EventNameError(
                "事件名须匹配 `zthl.<domain>.<verb>`（小写字母开头的 [a-z0-9_] 串），"
                f"得 {self.name!r}；已知种子事件 = {sorted(EVENTS.values())}")


@dataclass(frozen=True)
class DeliveryResult:
    """单个订阅者的投递结果（错误隔离的可观测面：一个订阅者崩不拖垮其余）。"""

    subscription: str
    ok: bool
    value: Any = None
    error: str = ""
    skipped: str = ""      # "" | "circuit_open" | "rate_limited"


class DeliverySkipped(Exception):
    """中间件**主动跳过**本次投递（非错误）：不计入断路器失败计数。"""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class RateLimited(DeliverySkipped):
    def __init__(self) -> None:
        super().__init__("rate_limited")


class CircuitOpen(DeliverySkipped):
    def __init__(self) -> None:
        super().__init__("circuit_open")


@dataclass(frozen=True)
class EventFilter:
    """订阅侧谓词。`name` 走 fnmatch（支持通配符订阅，设计「通配符订阅」条）。"""

    name: str = "*"
    source: Optional[str] = None
    predicate: Optional[Callable[[Event], bool]] = None

    def matches(self, ev: Event) -> bool:
        if not fnmatch.fnmatchcase(ev.name, self.name):
            return False
        if self.source is not None and ev.source != self.source:
            return False
        if self.predicate is not None and not self.predicate(ev):
            return False
        return True


# 中间件协议：`middleware(event, next_) -> value`；`next_(event)` 调链上下一个（末位 = 处理器）。
Middleware = Callable[[Event, Callable[[Event], Any]], Any]


class RateLimiter:
    """固定窗口限流中间件（进程内运行时态，非事实源副本；见设计第 3 条注）。"""

    def __init__(self, limit: int, per_seconds: float):
        if limit <= 0 or per_seconds <= 0:
            raise ValueError("RateLimiter 需 limit>0 且 per_seconds>0")
        self.limit = int(limit)
        self.per_seconds = float(per_seconds)
        self._hits: "list[float]" = []
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            self._hits = [t for t in self._hits if now - t < self.per_seconds]
            if len(self._hits) >= self.limit:
                return False
            self._hits.append(now)
            return True

    def __call__(self, event: Event, next_: Callable[[Event], Any]) -> Any:
        if not self.allow():
            raise RateLimited()
        return next_(event)


class CircuitBreaker:
    """断路器中间件：连续失败 ≥ `failure_threshold` → 开路（跳投）`reset_after` 秒后
    单次试探（半开）；试探成功 → 闭合，失败 → 重新开路。

    ⚠ 计数为**进程内运行时态**；开路只影响本订阅者的投递，不影响事实源（设计第 3 条）。
    """

    def __init__(self, failure_threshold: int = 3, reset_after: float = 30.0):
        if failure_threshold <= 0 or reset_after < 0:
            raise ValueError("CircuitBreaker 需 failure_threshold>0 且 reset_after>=0")
        self.failure_threshold = int(failure_threshold)
        self.reset_after = float(reset_after)
        self._failures = 0
        self._opened_at = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state_locked()

    def _state_locked(self) -> str:
        if self._failures < self.failure_threshold:
            return "closed"
        if time.monotonic() - self._opened_at >= self.reset_after:
            return "half_open"
        return "open"

    def __call__(self, event: Event, next_: Callable[[Event], Any]) -> Any:
        with self._lock:
            st = self._state_locked()
            if st == "open":
                raise CircuitOpen()
            if st == "half_open":
                # 半开：放行**一次**试探（重置计数，成功即闭合 / 失败再开路）
                self._failures = 0
        try:
            value = next_(event)
        except Exception:
            with self._lock:
                self._failures += 1
                if self._failures >= self.failure_threshold:
                    self._opened_at = time.monotonic()
            raise
        with self._lock:
            self._failures = 0
        return value


class Subscription:
    """订阅句柄（`hub.subscribe(...)` 的返回值；`hub.unsubscribe(sub)` 摘除）。"""

    __slots__ = ("filter", "handler", "middleware", "name")

    def __init__(self, filter_: EventFilter, handler: Callable[[Event], Any],
                 middleware: Sequence[Middleware] = (), name: str = ""):
        self.filter = filter_
        self.handler = handler
        self.middleware = tuple(middleware)
        self.name = name or getattr(handler, "__name__", "anonymous")

    def __repr__(self) -> str:  # pragma: no cover - 诊断用
        return f"<Subscription {self.name} name={self.filter.name!r}>"


class SignalHub:
    """进程内事件分发中枢（H3）。**零持久化**：不落盘、不缓存事实（设计第 3 条）。

    - `subscribe`  → 句柄（可带中间件链）
    - `publish`    → 逐订阅者**隔离**投递，返回 `list[DeliveryResult]`（单个处理器抛错不影响其余）
    - `close`      → 关闭后 `available` 为假；消费方应转入 `PollFallback`（设计第 4 条）
    """

    def __init__(self) -> None:
        self._subs: "list[Subscription]" = []
        self._lock = threading.RLock()
        self._closed = False

    # ── 订阅面 ────────────────────────────────────────────────────────────────
    def subscribe(self, filter_: EventFilter, handler: Callable[[Event], Any],
                  middleware: Sequence[Middleware] = (), name: str = "") -> Subscription:
        sub = Subscription(filter_, handler, middleware, name)
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> bool:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)
                return True
        return False

    @property
    def subscriptions(self) -> "list[Subscription]":
        with self._lock:
            return list(self._subs)

    # ── 可用性（设计第 4 条的降级判据）─────────────────────────────────────────
    @property
    def closed(self) -> bool:
        return self._closed

    def available(self) -> bool:
        """总线可用 ⇔ 未关闭。不可用 ⟹ 消费方转 `PollFallback`（复用既有读面，不新建事实源）。"""
        return not self._closed

    def close(self) -> None:
        with self._lock:
            self._closed = True

    # ── 分发面 ────────────────────────────────────────────────────────────────
    def publish(self, event: Event) -> "list[DeliveryResult]":
        """扇出到全部匹配订阅者。**错误隔离**：逐订阅者 try/except，异常不外泄、不中断其余。"""
        with self._lock:
            if self._closed:
                return [DeliveryResult("(hub)", False, error="hub_closed")]
            targets = [s for s in self._subs if s.filter.matches(event)]
        out: "list[DeliveryResult]" = []
        for sub in targets:
            out.append(self._deliver(sub, event))
        return out

    @staticmethod
    def _deliver(sub: Subscription, event: Event) -> DeliveryResult:
        def _terminal(ev: Event) -> Any:
            return sub.handler(ev)

        chain: Callable[[Event], Any] = _terminal
        for mw in reversed(sub.middleware):
            nxt = chain

            def _wrapped(ev: Event, _mw=mw, _nxt=nxt) -> Any:
                return _mw(ev, _nxt)

            chain = _wrapped
        try:
            return DeliveryResult(sub.name, True, value=chain(event))
        except DeliverySkipped as skip:          # 中间件主动跳过（非错误，不计断路器失败）
            return DeliveryResult(sub.name, False, skipped=skip.reason)
        except Exception as exc:                  # 处理器/中间件异常 → 隔离（其余订阅者照跑）
            return DeliveryResult(sub.name, False,
                                  error=f"{type(exc).__name__}: {exc}")


class PollFallback:
    """总线不可用时的**降级读面**：只回读既有事实源（设计第 4 条）。

    - **不新建事实源**：`path` 指向既有落盘（如 `.gatekeeper.state`），`dotted` = 该文件内的
      点路径（如 `gate_data.narrow_tasks`）。
    - **丢事件不漂移**：`read()` 每次都直读权威面 ⟹ 事件只是「何时通知」，不是「读到什么」
      的第二副本；漏投/跳投只会**推迟**通知，不会让读到值偏离权威值。
    """

    def __init__(self, path: str, dotted: str = "", reader: Optional[Callable[[], Any]] = None):
        self.path = str(path)
        self.dotted = dotted
        self._reader = reader

    def read(self) -> Any:
        """回读权威面当前值（文件缺失/解析失败 → `None`，不抛、不伪造）。"""
        if self._reader is not None:
            return self._reader()
        try:
            cur: Any = json.loads(Path(self.path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        for seg in [s for s in (self.dotted or "").split(".") if s]:
            if isinstance(cur, dict) and seg in cur:
                cur = cur[seg]
            else:
                return None
        return cur

    def poll_once(self, previous: Any = None) -> "tuple[Any, bool]":
        """单次轮询：返回 `(当前值, 是否相对 previous 变化)`。"""
        cur = self.read()
        return cur, cur != previous
