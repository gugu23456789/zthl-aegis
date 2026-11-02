# Trae IDE 跨用户上下文注入漏洞报告

<!-- DOC-META
title: Trae IDE 跨用户上下文注入漏洞报告
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

**日期**: 2026-06-15
**严重性**: 高
**报告人**: HP (gatekeeper 安全审计)
**影响范围**: 所有使用 Trae CN 的多租户用户

---

## 1. 漏洞描述

Trae CN IDE 在构造 system prompt 时，将其他用户会话中的文件内容注入到当前用户的请求中。

## 2. 已确认的泄漏事件

| 事件 | 时间 | 泄漏内容 | 泄漏用户 |
|:--|:--|:--|:--|
| peng 项目注入 | 2026-06-15 | `<home>\Desktop\xhs-copilot\app\README.md`（小米营销×小红书副驾驶完整 README） | peng |
| pc-web-identity-tracker 注入 | 2026-06-15 | Trae Task subagent 返回了 `pc-web-identity-tracker` 项目代码审查内容 | 未知用户 |

## 3. 排除的泄漏源

| 排查项 | 方法 | 结果 |
|:--|:--|:--|
| 本机磁盘 | `Test-Path <home>` + 文件搜索 | ❌ 不存在 |
| 小米 MiMo API | 并发隔离/FlashTrace/TTFT/幽灵测试 (5轮) | ✅ CLEAN |
| DeepSeek API | LOO/logprobs/跨请求 marker 测试 | ✅ CLEAN |
| 本机红队测试 | 回溯所有脚本操作 | ✅ 仅本机文件操作，无外部泄漏 |

## 4. 根因定位

```
泄漏时间线:
[Trae 构造 system prompt] → [HTTP 请求] → [MiMo/DS API 接收] → [模型推理]
       ↑ 泄漏在这里           ↑ 干净            ↑ 干净
```

**泄漏发生在 Trae IDE 构造 system prompt 阶段（请求发出之前）**。模型层完全干净。

## 5. 排查手段的局限性

| 手段 | 能否验证 | 原因 |
|:--|:--:|:--|
| mitmproxy 抓包 | ❌ | Trae 使用 ttnet (字节自研网络库)，绕过系统代理 |
| 本地数据库读取 | ❌ | database.db 为加密格式，非 SQLite |
| Trae 日志提取 | ❌ | 仅记录 IPC 调度，不含 system prompt 内容 |
| FlashTrace LOO | ❌ | 只能检测模型层泄漏，不检测客户端 prompt 构造 |

## 6. 证据链

```
证据 1: peng 的 README 反复出现在 <system-reminder> 标签中（10+ 次）
         → 不在本机 (<home> 不存在)
         → MiMo/DS API 均返回 CLEAN
         → 只能是 Trae 客户端或服务端注入

证据 2: pc-web-identity-tracker 内容通过 Task subagent 返回
         → 完全不同的第三用户
         → 证明不是偶发，是系统性问题

证据 3: 两次泄漏均涉及完全不同的项目/用户
         → 多租户隔离失效，非单一用户问题
```

## 7. 建议修复方向

1. **KV Cache 用户隔离**: 确保 prefix cache 按用户/session 隔离，不跨用户复用
2. **System Prompt 审计日志**: 记录发出的完整 system prompt 内容，便于事后审计
3. **请求构造隔离**: 确保每个用户的 prompt 构造在独立的内存空间完成

## 8. 测试环境

- 操作系统: Windows 11 (Build 26100)
- Trae CN: 最新版本 (2026-06-15 更新后出现泄漏)
- 网络库: ttnet (字节跳动自研)

## 9. 附件

- 5 轮 API 测试脚本（已清理）
- mitmproxy 审计代理脚本: `scripts/_prompt_audit_proxy.py`
- 本机数据库/日志路径: `<用户目录>\AppData\Roaming\Trae CN\`
