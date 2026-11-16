# 红队本地确定性护栏（Red Guard）

## 原则

- 未经授权的网络渗透违法；本仓只做**自维护红队**（本仓 / 授权工作树 / 自有资产）。
- 闸门**本地、确定性、fail-closed**；不联网判定合法性，断网也能判。
- 在线法律检索仅作 advisory 证据，**不参与 allow/deny**。

## 放行面

1. **公开只读检索源**：`PRIOR_ART_HOSTS` + `GOVERNED_SEARCH_HOSTS`（只读）。
2. **自维护资产**：`references/red-scope.json`（本机私有，`.gitignore` + 导出排除），必须
   `self_maintained=true`、窗口有效、动作 ∈ `{read, search}`。

## 使用

```bash
cp references/red-scope.example.json references/red-scope.json
# 编辑 assets / window / legal_basis（只列自有资产，禁通配）
python3 scripts/gk_red_guard.py seal --scope references/red-scope.json
python3 scripts/gk_red_guard.py status
python3 scripts/gk_red_guard.py check --url https://localhost:8443/health
```

## 接线（三处出网口）

- `gk_red_intel.gate_url`：公开只读放行；其余必须命中 scope。
- `subagent_runner._prior_art_fetch`：deny ⟹ `RedGuardDenied`（不进入 socket）。
- `pre_tool_hook._egress_identity`：deny ⟹ `McpEgressSealed`（调用点 BLOCK）。

deny 审计写入 `.gatekeeper.red-guard.jsonl`（`GK_RED_GUARD_LOG` 可覆盖）。

## 边界

- 动作面只允许 `read` / `search`；`exploit` / `scan` / `upload` 一律 deny。
- 无 scope、scope 被篡改、窗口过期、`self_maintained=false` → 一律 deny。
- 对外部项目的任何自动化动作，必须先有显式授权并落入 scope；否则不执行。
