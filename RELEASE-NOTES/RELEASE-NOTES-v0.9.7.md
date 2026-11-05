# ZTHL Aegis v0.9.7

**发布日期**：2026-11-05 ｜ **类型**：安全加固版（密钥面 + 红队常态化 + 余额提醒）

## 亮点

- **API key 不再进 argv**：5 处模型/余额调用统一改为 `curl --config -`（Authorization 走
  stdin），`ps`／任务管理器／错误面都看不到密钥；`balance` 额外关闭 `xtrace`，并在 CLI 派发前
  加一条全局告警（`bash -x` 会打印变量展开，提示勿把 stderr 落盘）。
- **`set-key` 支持 stdin**：`set-key <provider> -` 从管道读，key 不再落进 shell history；
  持久化到 Windows 用户环境时改走**子进程继承的 env**，不再拼进 PowerShell `-Command`。
- **API key 落点迁移（方案 A）**：新落点 `$XDG_DATA_HOME/zthl/.keys`（缺省
  `~/.local/share/zthl/.keys`，目录 `0700`、文件 `0600`）；旧 `<skill>/.keys` 降级为
  **只读兼容**（`source=legacy`），新增 `set-key migrate`（只 copy 不删、不覆盖）。
- **红队常态化攻击机**：新增 `gk_red_keyleak`（9 组密钥泄露向量）与 `gk_red_stand`
  （攻击循环 + `red-history.jsonl` 台账 + 连续 3 波 HIGH 升级），接入 CI、`ci_smoke` 与
  每日 cron 波次 —— 安全判据不再只靠“改代码那次记得跑”。
- **余额投喂提醒**：余额不足一轮质询时追加一行自嘲提醒（仅当用户**显式**设置
  `GK_BALANCE_MIN_CNY`；不投也完全没关系），不阻断任何流程、不进 JSON 结构。
- **发布面卫生**：导出后处理产生的 `__pycache__`／`*.pyc`／`.gatekeeper.state*` 在交付前
  自动清理，避免整树同步时把执行残留带进公开包。

## 变更明细

### 代码

- `scripts/gk_api_key.py`：落点三级解析（`$GK_KEYS_DIR` → XDG → `~/.local/share`），
  新增 `dir` / `migrate` 子命令；读取回退旧落点（`source=legacy`）。
- `scripts/gk_views.py`：新增 `alert_threshold()` / `topup_reminder()`（文案单源）。
- `scripts/balance_format.py`、`scripts/gk_balance_audit.py`：接入提醒（未配置阈值时输出逐字不变；
  `--json` 用 `topup_reminder` 字段，不破坏结构）。
- `gatekeeper-cli.sh`：余额与模型调用改 `--config -`；`cmd_balance` 关 xtrace 并在返回前恢复；
  派发前新增 xtrace 告警；`set-key` 支持 stdin 与 `migrate`，目录 `chmod 700`。
- 新增 `scripts/gk_red_keyleak.py`：RK-01…RK-10（argv / `--config -` / xtrace / history /
  PowerShell argv / 日志面 / 排除面 / 已跟踪密钥形态 / 文件权限 / 备份年龄）。
- 新增 `scripts/gk_red_stand.py`：向量注册表 + 波次台账 + 连击升级（`--strict` / `--register`）。
- `scripts/oss_scrub.py`：导出设 `PYTHONDONTWRITEBYTECODE=1`，交付前 `purge_run_artifacts()` 兜底。

### CI

- `.github/workflows/ci.yml`：新增 `red-keyleak` job；增加每周 `schedule`（红队常态化）。
- `scripts/ci_smoke.sh`：第 3/5 步改为跑密钥泄露向量（HIGH 即红）。

### 测试

- 新增 `test_gk_balance_reminder.py`、`test_gk_red_stand.py`；扩展 `test_gk_api_key.py`
  （XDG 落点 / legacy 回退 / migrate 不删不覆盖）与 `test_oss_scrub.py`（导出残留清理）。

### 已知边界

- 签名/HMAC 私钥仍位于 `<skill>/.keys`（路径被保护区固定），加固方式是 **Windows ACL**：
  断开继承，仅保留当前用户 / SYSTEM / Administrators；`RK-09` 以 ACL（SID）而非 POSIX mode 判定
  ——drvfs 上的 `mode` 是合成值，不能作为权限证据。
- cron 波次需调度器在运行（`gatekeeper-cli.sh cron start`）；未启动时仅登记不执行。
