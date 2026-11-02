# ZTHL Aegis v0.9.4.2 — 发布说明

> 2026-11-02。v0.9.4.2 是 v0.9.4.1 之后的补丁版：增加个人独立作品声明、
> 408 research 自动判定、文档 claim 门、payload 配额收紧与 CI/发布供应链加固。
> 不引入新的运行时依赖。

## 1. 为什么发这个补丁

v0.9.4.1 之后完成了几项会影响发布面的改动：

1. README / README.en 增加「个人独立作品声明 / Independent Work Statement」。
2. 408 research frame 从手动 opt-in 改为默认 `auto` 判定，且只做 advisory、不阻塞质询。
3. 文档发布门增加「声明 ↔ 代码」claim 检查，并在 release 模式只检查公开导出面。
4. history / pipeline / findings 三条 payload 腿从 45%/20%/20% 收紧到各 5%（128KB）。
5. CI 与 release workflow 增加最小权限、Action SHA pin、凭据隔离、超时、
   workflow 安全静态门与 SLSA provenance。

## 2. 变更

### 2.1 个人独立作品声明

- README / README.en 明确：本仓是 **Pu Junhan** 的个人独立作品，不代表任何雇主、客户或组织；
  开发未使用雇主/客户专有代码、机密信息或资源；第三方依赖按许可证标注。
- 声明不改变 Mulan PSL v2 许可证与第三方许可归属。

### 2.2 408 research 自动判定

- 默认 `GK_RESEARCH_FRAME=auto`：系统/自维护任务 → `408`；文案/艺术/创作 → `generic`。
- `GK_RESEARCH_FRAME=408|generic` 可强制覆盖。
- 判定结果只写入 `advance` 的 `extras.research_frame`（`blocking:false`），
  不进入 `produces`、不参与任何 gate；缺失/判定失败都不阻塞 advance / EDIT / 质询。

### 2.3 文档 claim 门

- 新增 `scripts/gk_doc_claims.py`：检查文档声明与代码常量、目录路径、CLI 命令、相对链接。
- 新增 `scripts/gk_doc_release.py`：串联 facts → doc-align → claims。
- `gk_doc_align --release` 只检查公开导出面；`docs/plans`、`docs/analysis/subagent`
  等私有树不阻断公开包发布。
- `gk_doc_release --strict` 已清零 WARN。

### 2.4 payload 配额收紧

- `subagent_history`、`task_pipeline`、`ecc_findings` 三条腿各 **5% = 128KB**，
  合计 15%，其余 85% 留给其它 key。
- 依据：卫星片/冷侧车已承接 bulk；history 一窗只需一轮（6 臂 ≈118KB）。
- 容量表由 `docgen` 自动重生成；漂移由 `test_gk_state_trim_lines.py` 守卫。

### 2.5 CI / 发布供应链加固

- CI 顶层 `permissions: contents: read`；所有 job 有 `timeout-minutes`。
- Actions 全部钉 40 位 commit SHA；checkout 一律 `persist-credentials: false`。
- `inputs.plan` 改经 `env` 中转，消除 `run:` 模板注入。
- `security-audit` 去掉 `continue-on-error`；新增 `gk_ci_security_lint.py` 硬门；
  危险命令静态扫描去掉 `|| true`。
- Release：顶层只读，发布 job 单独申请 `contents/id-token/attestations: write`；
  增加 `actions/attest-build-provenance` 与 `gh release create --verify-tag`。
- 单人维护不配置 environment required reviewers（GitHub 不允许触发者自审，会永久等待）；
  tag push / workflow_dispatch 即人工闸门。

## 3. 验证

- 定向回归：payload/finding/task/state 299 passed；ember/wall/satellite/state_ops/moa 155 passed；
  408 + claim + trim 12 passed；advance 67 passed；CI 安全门 + 打包 15 passed。
- `gk_ci_security_lint.py`：54 checks PASS（`ci.yml` / `release.yml`）。
- `gk_doc_release --strict`：PASS（facts PASS / align issues=0 warns=0 / claims PASS）。
- 安装/卸载 round-trip：新脚本与 `references/research-408.md` 均被安装；
  uninstall 后无安装面残留（测试日志除外）。
- 发布包：确定性 zip + `SHA256SUMS` + `release-manifest.json`，打包后逐项回验。

## 4. 发布物

- `dist/zthl-aegis-v0.9.4.2.zip`
- `dist/SHA256SUMS`
- `dist/release-manifest.json`
- 本说明：`RELEASE-NOTES-v0.9.4.2.md`

## 5. 安装 / 升级

```bash
bash install.sh --dest <skill-dir>
bash uninstall.sh --dest <skill-dir> --yes
```

发布包内 README / 本说明用于审阅；`install.sh` 只安装运行时技能文件（脚本、references、
monitor-schemas、assets 等），不复制 README。
