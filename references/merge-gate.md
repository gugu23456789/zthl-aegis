# 合并前置闸（Merge Gate）—— 机制正本

**定位**：主干（`master` / `main`）的**唯一写入口**，以及它在 git 层的那道不可绕过防线。
本文是判据与失败态的正本；阶段流程视角见 `stage-4-merge.md`。

**单一事实源**：`scripts/gk_merge_cli.py`（编排）、`scripts/gk_merge_guard.py`（判定）、
`scripts/gk_merge_hook.py`（git 钩子实现）、`scripts/gk_merge_hook_install.py`（安装/卸载）。
本文只描述契约，判据以脚本为准。

## 0. 机制面（自动生成，勿手改）

<!-- GK-MECH:START id=merge-gate（由 scripts/gk_mechanism_docs.py 生成，勿手改） -->
| 事实 | 值 | 来源（可复算） |
|:--|:--|:--|
| 入口脚本 | `gk_merge_cli.py` · `gk_merge_guard.py` · `gk_merge_hook.py` · `gk_merge_hook_install.py` | `references/mechanism-registry.json` |
| 公开函数 | 18（merge_cli 2 / merge_guard 5 / merge_hook 5 / merge_hook_install 6） | `^def <name>` 计数（入口脚本合计） |
| CLI 入口 | `merge` · `premerge` · `merge-hook` | `gatekeeper-cli.sh`（`_CMD_REG` 或早期 case 分派） |
| 测试 | `scripts/test_gk_merge_cli.py` · `scripts/test_gk_merge_guard.py` · `scripts/test_gk_merge_hook.py` · `scripts/test_gk_merge_cleanup_remote.py` | `scripts/` |
| 校验 | `python scripts/gk_mechanism_docs.py --check --id merge-gate` | 本闸自身 |
<!-- GK-MECH:END id=merge-gate -->

---

## 1. 为什么要两道

只在代理侧拦（命令字符串检查）挡不住人手在终端敲 `git merge`，也挡不住脚本直接提交。
因此同一判据必须在**两处**生效：

| 层 | 位置 | 拦什么 |
|:--|:--|:--|
| 代理面 | 工具调用前置检查（Gate R0.24） | 裸 `git merge` / 直接往主干 `commit` / 直推主干 |
| git 面 | `.git/hooks/reference-transaction` | 任何人、任何脚本对主干的引用更新 |

两层的判据必须同源；改一处忘另一处就会出现「代理说安全、git 说拒绝」的错觉。

## 2. 票据机制

- 合并入口先跑闸①（合并前体检），通过后签发**一次性**票据；提交时由钩子验票并立即消费。
- 票据 = HMAC-SHA256 签名，密钥保存在仓库公共目录（不进 git、不进 state）。
- 票据绑定三元组：**目标引用 + 旧值（old）+ 来源分支**；三者任一不符即拒。
- 有效期 900 秒，覆盖「闸① → 解冲突 → 闸② → 提交」的正常耗时；超时即拒。

## 3. 判定面

- **主干任何前进**都需要票据：不再区分「合并」还是「单条直接提交」。
- **删除主干**一律拒绝：删分支不可恢复，且没有「删除票据」通道。
- **新建主干**（`old` 为零值）放行：仓库初始化阶段没有既存主干可保护。
- 非主干引用（特性分支、tag）不受本闸管辖。

## 4. 闸①（合并前）检查项

- 退化 / 回退检测（目标分支内容是否被削弱）
- 受保护区检查（门禁自身的关键区段不得减少行数）
- 事实数据块是否需重算（触碰事实源时）
- 暂存面删除清单
- 等价补丁检测（避免造出无内容的合并）

## 5. 闸②（暂存后）检查项

- 暂存删除清单（需显式声明才放行）
- 合并结果中受保护区是否缩水
- 归档式改名识别（避免把「移动」误判成「删除」）

## 6. 副作用

- 触碰事实源时自动重算 GK-FACTS 并**显式入暂存**（否则工作区恒脏，下一次合并会被「本地改动会被覆盖」挡住）。
- 提交前清空外部注入的作者/提交者环境变量，防止伪造来源。

## 7. 失败态

| 报错 | 含义 | 处置 |
|:--|:--|:--|
| `NO_TICKET` | 没走唯一入口 | 改用合并入口命令 |
| `TICKET_STALE_OLD` | 票据签发后主干又被推进 | 重新走入口 |
| `TICKET_EXPIRED` | 超过有效期 | 重新走入口 |
| `PROTECTED_REGION_SHRINK` | 合并结果削弱了受保护区 | 恢复该区段后再合并 |
| `MERGE_DELETES_TARGET_FILES` | 源分支删了主干仍在用的文件 | 确认是有意清理后显式声明 |

## 8. 常见坑

1. **Windows 上的解释器桩**：`python3` 可能是应用商店的 0 字节别名，`command -v` 能找到但执行必失败。
   钩子若按「存在即使用」选解释器，会 fail-closed 拒绝**一切**引用更新（连打 tag 都被拒）。
   现行修法：钩子先验证解释器真能执行（`import sys`）再采纳。
2. **跨系统 git 混用**：同一仓库被 Windows 与 WSL 两套 git 同时写会抢锁、损坏引用；
   写操作统一走一个通道。
3. **受保护区注释行也算内容**：删掉几行说明性注释同样会触发缩水判定，改代码时不要顺带删注释。
