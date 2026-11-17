# 工作目录池与路由（Worktree Pool & Routing）—— 机制正本

**定位**：回答两个问题——「这次任务在哪个目录改代码」和「这个目录什么时候还给池子」。
**单一事实源**：`scripts/gk_worktree_pool.py`（池）、`scripts/gk_worktree_owner.py`（归属）、
`scripts/gk_route_center.py`（路由）、`scripts/gk_apply_worktree_cli.py`（入口）。
状态与回收的存储面见 `state-storage.md`。

## 0. 机制面（自动生成，勿手改）

<!-- GK-MECH:START id=worktree-pool（由 scripts/gk_mechanism_docs.py 生成，勿手改） -->
| 事实 | 值 | 来源（可复算） |
|:--|:--|:--|
| 入口脚本 | `gk_worktree_pool.py` · `gk_worktree_owner.py` · `gk_route_center.py` · `gk_apply_worktree_cli.py` | `references/mechanism-registry.json` |
| 公开函数 | 62（worktree_pool 10 / worktree_owner 14 / route_center 25 / apply_worktree_cli 13） | `^def <name>` 计数（入口脚本合计） |
| CLI 入口 | `apply-worktree` · `route-check` | `gatekeeper-cli.sh`（`_CMD_REG` 或早期 case 分派） |
| 测试 | `scripts/test_gk_worktree_pool.py` · `scripts/test_gk_worktree_owner.py` · `scripts/test_gk_apply_worktree_cli.py` · `scripts/test_gk_worktree_route_visibility.py` | `scripts/` |
| 校验 | `python scripts/gk_mechanism_docs.py --check --id worktree-pool` | 本闸自身 |
<!-- GK-MECH:END id=worktree-pool -->

---

## 1. 为什么要池化

并行任务共用一份工作目录会互相踩：A 的未提交改动可能被 B 的切换带走。
池化的做法是预先准备若干独立代码副本（槽位），任务来了一条专用，用完归还。

## 2. 路由：只有一个答案

选目录只有一条链，依次尝试，命中即停：

1. **状态提示**：状态里记录的目录必须存在，且出现在 git 的 worktree 列表里；
2. **当前目录**：确认它本身是一个受管工作目录；
3. **池槽租约**：向池子申请一个空闲槽位；
4. **主干目录（只读）**：以上全部落空时，只允许读，不允许写。

四级全部落空 ⟹ 直接报错（`NO_ROUTE`），**不猜**一个「看起来能写」的位置。
路由自检（`route-check`）能发现悬空状态引用与失效的附加目录登记，发现即返回非零。

## 3. 池的生命周期

| 动作 | 契约 |
|:--|:--|
| 申请（acquire） | 必须带会话标识与目标分支；返回槽位路径、分支、基线提交 |
| 归还（release） | **先归档**当前改动，再把槽位清回基线，最后切回池分支 |
| 状态（status） | 返回池大小、已租用数、空闲数、是否满、各槽位明细与流程提示 |

- 池大小硬上限 8，默认 3。
- 租约默认 7200 秒；过期由清扫回收，回收前同样先归档。
- 归档产物放在池目录的 archive 下，按槽位与时间戳命名，内含变化补丁。

## 4. 拒绝码（申请阶段）

| 码 | 触发 |
|:--|:--|
| `SID_REQUIRED` | 没有会话标识 |
| `BRANCH_PROTECTED` | 目标分支是主干或池自身分支 |
| `SID_ALREADY_LEASED` | 同一会话已占一个槽位 |
| `RATE_LIMITED` | 短时间申请过于频繁 |
| `POOL_EXHAUSTED` | 槽位全满 |

池满时返回体带 `full: true` 与降级标记 `cold-build`，并给出下一步提示：
优先复用已过期租约（提示先清扫），否则按冷建流程新建目录，不再静默等待。

## 5. 归属与身份

- 一个槽位同一时间只归一个会话；其他会话对它发起的 git 写会被拒绝。
- 提交信息带会话与工作目录双标识，事后能把改动对回具体任务。
- 编辑动作会续期租约（按租期一半节流），长时间任务不会被中途回收。

## 6. 回收的三态读法

| 状态 | 含义 | 能否派发 |
|:--|:--|:--|
| leased | 已被会话占用 | 否 |
| free | 空闲 | 是 |
| expired | 租约过期，等清扫 | 清扫后可派发 |

权威判据来自池模块，**不要按目录名猜**。

## 7. 常见坑

1. **在没有租约的槽位上直接改代码**：回收会把改动归档并清回基线，未提交内容随即消失。
   正确做法是走入口申请租约，或在自己的工作目录里改。
2. **手搓 `git worktree add`**：能建出来，但写面没有登记，之后的编辑会被归属检查拒绝。
   建树必须走唯一入口。
3. **把「池分支」当成开发分支**：池分支只是槽位的复位目标，不是提交落点。
