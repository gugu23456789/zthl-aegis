# ZTHL Aegis v0.9.8.4 — 发布说明

> 2026-11-08。本版是 v0.9.8.3 的 **CI 依赖区间修复补丁**：功能与 v0.9.8.3 完全相同。
> 完整变更见 `RELEASE-NOTES-v0.9.8.3.md`。

## 1. 为什么发这个补丁

v0.9.8.3 推送后 CI 与 release 均红，`smoke gate` / `smoke gate in venv` 失败。
拉取 job 日志定位到**单一根因**（非代码逻辑）：

```
SUAGENT_SDK_VERSION_MISMATCH  got=0.24.0  want=">=0.22,<0.24"
→ 8 条 test_subagent_role_tools.py 用例 SystemExit: 2
```

`subagent_runner.py` 对 `openai-agents` 有硬区间约束（2026-09-08 F-REV-1 隔离 A/B 实测：
0.22 以下的 `tool_calls` 历史组装会让 DeepSeek 返回 400 `insufficient tool messages`）。
而 `.github/workflows/ci.yml` 与 `release.yml` 的 `pip install ... openai-agents` **未钉版本**
⟹ runner 装到 0.24.0 ⟹ 声明区间被违反。

本地全绿是因为本机解释器恰在 0.22/0.23 区间内 —— 属「新机制与测试环境不匹配」，
不是功能回归。

## 2. 变更

- `ci.yml`（smoke job、venv job）与 `release.yml`（release job）的安装行改为
  `"openai-agents>=0.22,<0.24"`，与 `subagent_runner.py` 的声明**同源**。
- 三处均加注释写明区间来源与「上游 0.24 是否已修复该 400 待评估，修复后再放宽上限」，
  避免下一个人误以为可以随手升级。

## 3. 验证

- 私仓 `gk_release_preflight.py`：9/9 PASS（含 `bench_regression`）。
- 公开树 `ci_smoke.sh`：276 passed（本地解释器在区间内）。
- 公开树 `gk_release_preflight.py`：9/9 PASS。
- CI 侧：本次钉版本后 `smoke gate` / `smoke gate in venv` / release `smoke gate` 应转绿。

## 4. 与 v0.9.8.3 的关系

两版是同一发布：v0.9.8.3 = 汇总说明 + 文档漂移修复 + 性能门入预检；
v0.9.8.4 = 该发布在 CI 上的依赖区间修复。对外建议直接使用 v0.9.8.4。
