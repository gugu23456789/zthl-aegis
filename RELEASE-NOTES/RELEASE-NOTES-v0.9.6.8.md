# v0.9.6.8 发布说明

本版处理**公开包导出面**的安全网与遗留清理，并把本批私仓改动同步到公开树；运行契约零变更。

## 导出面修复（本版重点）

- `phase-probe`：脚本属导出排除面，公开包原实现裸派发到缺失文件 ⟹ `rc=2` 且 **stdout 为空**
  （stderr 被吞进 dbg log），用户无法区分"没装"与"坏了"。现返回具名
  `{"ok":false,"error":"PLUGIN_NOT_SHIPPED","source":"missing"}`。
- `gk_model_shelf.pin_checks()`：phase 族缺失由 `FAIL` 改记 `NOT_SHIPPED`（`FAIL` 只保留给
  "模块在场但与 PINNED 对不上"）。
- 公开面两条必红测试改为**具名 skip**：`test_gk_turn_cache::test_filler_single_source`、
  `test_gk_model_shelf::test_pin_checks_match_current_code`；`test_gk_web_tools` 对
  `gk_paper_review` 的裸懒加载同样改为 `importorskip`。
- 清理 646 项排除面遗留：`__pycache__` 634、运行时残留 3、过期模块/测试 4
  （`gk_model_probe.py` / `gk_phase_stats.py` 及对应测试）。
- 导出守护扩面：import 闭包检查下探**函数/类体**（只有 `try:` 包住才算有降级点）；新增
  `git ls-files` 全量扫描，禁止**私有论文仓路径与其记录副本**出现在公开面
  （词面不随文档落盘：本文不写内部路径字面量）。

## 同批同步内容

- **CI/供应链**：`security-audit` job + `gk_sarif.py`（三份静态结果归一为 SARIF 2.1.0，
  `--gate` 使 error 级 finding 真实失败），CI 模板新增 §3.9。
- **写入落盘校验**：`gk_edit_verify.py`（sha256 / 锚点 / 行号回读比对），防"改了但没落盘"。
- **恶意代码拦截**：`gk_threat_patterns.py` 单一来源；Gate R0.19 对 EDIT 载荷范围内外同判。
- **安装钩子自动化**：`gk_hook_manage.py sync`（判漂移 → 改 → 回读校验，无漂移零写入）；
  `install.sh` 改用 `sync`；`safe` 面补齐 `CreateFile`/`DeleteFile`/`run_mcp`/`mcp__.*`。
- **bashpy 升级钩子**：`verify` 体检、`upgrade --install` 装后即检、配置原子写 + 回滚。
- **余额审计**：`balance --audit/--record/--usage/--jitter`（复用 `gk_cache_observe` 判缓存崩溃，
  余额解析单源收敛到 `gk_views.parse_balance`）。
- **环境路径**：安装/卸载测试改 WSL 路径形态 + 强制 LF；worker 探活兜住 `SystemError`；
  主仓命中判定不再把空正则喂给 `rg -qi`（避免"未解析主仓 ⟹ 全量假拦"）。
- **命名**：`paper-review` 中文名统一为「论文写作投稿前置模拟评审（投稿前自检，非同行审稿）」。

## 已知限制

- `phase-probe` / `paper-review` 等排除面能力在公开包**不可用**，这是发布面设计而非缺陷。
- 公开仓仍保留 `PROVENANCE.md`、历史 `RELEASE-NOTES-*.md` 等公开面自有文件（不在私仓导出面）。
