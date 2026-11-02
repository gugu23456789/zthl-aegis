"""ZTHL ACP 协议子包（`zthl-harness-adapter` 计划 ZH2-H10 / ZH3-H14f 落点）。

模块
----
- `zthl.acp.amp` —— AMP 兼容层**规范层**：`LogRecord` 六类日志构造 + 分文件写入
  + 7 天轮转 + 读面查询。schema 唯一源 = ACPs v2.2.0 `09-ACPs-spec-AMP`
  （§5.1.2 `LogRecord` / §5.1.3 `logId` / §5.2-5.6 六类 Body）。
- `zthl.acp.amp_bridge` —— AMP **采集层**：把既有事实源（hook 判定、自检结果、
  access 日志窗口、finding-journal 裁决事件）映射为规范 Body。

零服务依赖（计划 §2.7 ⑧ 唯一裁定 2026-09-24）：**不部署官方 `monitor-server`**；
本包只负责按规范写文件，使输出可被官方栈消费（互通 ≠ 部署）。
"""

__all__ = ["amp", "amp_bridge"]
