# ZTHL Aegis v0.10.1 — CI 修复补丁

> 基于 v0.10.0（`31b905d4`）的 CI 回归修复；功能面无语义变更，仅修正发布面判定与载荷棘轮。

## 一、修的是什么

v0.10.0 推送到公开仓后，`ci` 与 `release` 两个工作流同时转红，失败点三处：

1. **预检把公开树当私仓审**：`doc_align` 的降级判据写成「有没有 `.git`」。公开工作副本本身是 git 仓（有 `.git`、无 `docs/`）⟹ 走全量模式，4 项导出排除面被误判为 FAIL。现改为按 **`docs/` 是否随包** 判定。
2. **依赖缺失被判违规**：CI 镜像无 PyYAML，`gk_ci_security_lint.py` 返回的 issues 只有 `{"error": ...}` 而**没有** `workflow` 键。预检现区分「环境能力不足」与「真实违规」——前者记 WARN 跳过，后者仍判 FAIL。
3. **内联载荷棘轮超限**：`gatekeeper-cli.sh` 内联 Python 载荷 91 条 > 上限 88。本版下沉 3 条：
   - `cmd_commit` 的 warnings 合并 ⟹ `scripts/gk_json_utils.py merge-warnings`
   - `cmd_push` 两处 `time` 计算 ⟹ shell 算术（`date +%s`）
   现为 88 条，棘轮不回退。

## 二、不变量

- 受保护区（`PROTECTED_REGION::constants|evidence|gate|transition|appeal`）零改动：合并闸的 `PROTECTED_REGION_SHRINK` 检查通过（五个区 `lost_lines=0`）。
- 判据单一事实源不变：`report_evidence_ok`、密钥过期判定的内联调用保持原样。

## 三、验证

- `scripts/gk_release_preflight.py --version v0.10.0` ⟹ 15/15 PASS（rc=0）。
- `scripts/gk_bomb_inventory.py --max-payload 88` ⟹ payload=88（rc=0）。
- 新增测试：`test_gk_release_preflight.py`（导出面判据 / 依赖缺失降级）、`test_gk_json_utils.py`（merge-warnings 三臂）。
- `test_gk_node_guard.py::TestL9CliInjection::test_auto_context_file_found` 在 linked worktree 下红属位置依赖（`references/subagent-context.json` 仅主树生成），非本版回归。
