# ZTHL Aegis v0.9.8.6 — 发布说明

> 2026-11-08。本版是**门禁与测试基础设施的紧急修复版**：修掉「主树只读形同虚设」这个安全洞，
> 并把 Windows 全量测试「95% 后永不结束」的根因（子进程继承悬空 stdin 管道）一刀切掉。
> 功能行为不变；不包含仍在分批推进的 CLI 手工拼 JSON 改造。

## 1. 为什么紧急发这一版

1. **主树只读门禁失效**（安全面）：`pre_tool_hook` 在判定「目标落在主检出根」后只打印
   `{"proceed": false}` 却 `sys.exit(0)`；宿主只认退出码 ⟹ 把拒绝当成功继续落盘。
   实测证据：agent 直接改主树 `gatekeeper-cli.sh` 成功，且**既不拦也不计编辑额度**。
   修法 = 与 `block()` 对齐改 `sys.exit(2)`，并加回归臂 `test_main_tree_write_exits_2`。
2. **Windows 全量测试长尾**（可用性面）：xdist worker 继承父进程 stdin 管道（已打开、对端永不写入）
   ⟹ 用例派生的 `bash.exe` / `openssl` / `wsl.exe` 子进程 `readline` 无界阻塞 ⟹ 全量在 95%+
   处「永不结束」（408-research 源码定案：`test_subagent_runner_stdin.py` 顶部注释）。
   修法 = `scripts/conftest.py` 对**未显式指定 stdin** 的 `Popen` 一律注入 `DEVNULL`。

## 2. 变更

| 文件 | 变更 |
|:--|:--|
| `scripts/pre_tool_hook.py` | 主树只读：`exit 0` → `exit 2`（宿主真正拦截） |
| `scripts/test_pre_tool_hook.py` | 新增 `test_main_tree_write_exits_2`（红先转绿） |
| `scripts/conftest.py` | 子进程缺省 `stdin=DEVNULL`（显式 stdin 的调用不受影响） |
| `scripts/test_subagent_runner_stdin.py` | 新增 `test_spawned_child_gets_eof_when_stdin_unset`（10s 超时兜底） |
| `scripts/xplat_harness.py` | `run_bash` 把 `bash.exe` 同目录前置进 PATH ⟹ 修 `awk/sed: command not found`（rc=127） |
| `scripts/test_subagent_runner_extract.py` / `test_subagent_gitnexus_contract.py` | EccOutput 双端同构改「单源口径」（CLI 已无内联 `O()` 副本）；Windows `tmp_path` 臂前置不成立时 skip |
| `references/oss-export-whitelist.json` | 撤出 3 份内部文档：`trae-cross-user-leakage-report`（含第三方用户数据/未修复漏洞细节）、`ecc-impact-20260609-gitnexus`、`prm-monitor-methodology`（与实现严重脱节） |
| `references/sdk-loop-layering.md` | 「不迁国产平替」改为**与国产算力软件栈适配验证是长期目标**（国产镜像 / 国产模型端点 / 国产 GPU 栈，含沐曦 MXMACA；木兰许可证族 2026-06-25 已捐赠开放原子基金会） |
| `FILES.md` / `llms.txt` / `references/README.md` | 随公开面收缩重生成（23 → 22 份） |

## 3. 验证（含可复现数字）

- `test_pre_tool_hook.py`：**338 passed**（含新增主树只读臂）。
- 手工喂 hook 载荷（目标 = 主树真实文件）：`EXITCODE 2` + `MAIN_TREE_READONLY`；agent 的 Edit 被真实拦截。
- 长尾四文件（此前 95% 处卡死的那批）`-n 4`：**102 passed in 49.33s**（修复前无界等待）。
- `gk_release_preflight.py`：8 项 PASS（`bench_regression` 按 `GK_PREFLIGHT_BENCH=0` SKIP）。
- Linux 侧哈希锁下载校验：48 dist 全过（沿用 v0.9.8.5 的锁，未变）。

## 4. 明确不包含

CLI 手工拼 JSON 的 34 处改造仍在分支 `fix/json-splice` 上分批推进（批次 1 已落 5 处、33→28，
`127 passed`）。本版**不含**该分支：它是 Windows `\U` 非法转义的存量债，非本次紧急项，
不合进紧急发布以避免把「本来就红」与「改造引入的红」混在一起归因。

## 5. 与 v0.9.8.5 的关系

v0.9.8.5 = 供应链加固（哈希锁 / zizmor 硬门 / release 特权面拆分 / 暗依赖下沉）。
v0.9.8.6 = 在其之上的**门禁漏洞 + 测试长尾**修复。对外建议直接使用 v0.9.8.6。
