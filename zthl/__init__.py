"""ZTHL Core —— 技能仓内自研子包（`zthl-harness-adapter` 计划 ZH1 · H3 落点）。

定位（计划 §0.1）：**ZTHL Core = 技能仓本体**。本子包是 ZH1 期间的**增量新建**
（H1b：不动既有门禁语义、不与 batch8 R-T6 争写），与既有 `scripts/gk_*.py` 平级协作。

模块
----
- `zthl.eventbus` —— 进程内事件分发：typed events + EventFilter + 通配符订阅
  + 错误隔离 + 中间件链（CircuitBreaker / RateLimiter）+ 文件轮询降级。

设计约束（H3 设计七条，唯一源 = 计划 §3）
----------------------------------------
1. 事件名一律 `zthl.<domain>.<verb>`，零 AIP §6.2 SSE 类型引用。
2. 三形态为**可选扩展**：不引入 HTTP 回调端 / MQ，零新增依赖。
3. **禁总线内自建状态存储** —— 查询面只消费既有事实源
   （`state/gate_data`、`finding-journal.jsonl`）。
4. 不可用时降级为文件轮询（复用既有读面），丢事件后状态不漂移。
5. 零 `aliveMap` 字段（liveness 归 AMP 查询面）。
6. 命名避开既有 `EventBus`（既有段落实为 context 投影写盘器，正名 Context Projector）。
"""

__all__ = ["eventbus"]
