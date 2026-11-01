# bashpy A/B 循环分层序列节点安全网（设计文档）

> **性质**：技能仓库基础设施模式文档（target_repo=skill）。2026-08-29 用户质询驱动——
> "bashpy 的 A 环和 B 环似乎没有对应的分层序列节点安全网" + "SWE Refactor Bench 流程正好和 bashpy 大环对应"。
> **承载模板**：`references/sequence-node-safety-net-template.md`（SN=⟨G,B,C,T,D⟩ 五元组 + A1-A8 公理）。
> **登记**：`docs/plans/2026-08-28-security-hardening-assessment.md §9 P2 / §14`。
> **状态**：**✅ 已实装（2026-08-29）**——SN_A/SN_B 六节点落 `scripts/gk_node_guard.py`
> （`plugin-a`/`plugin-b` 路线 + `_plugin_guard` 真实检查：manifest 登记 / load_status / cap 白名单，
> 注入点 `_GET_MANIFEST/_CHECK_CAP/_LOAD_STATUS` 可测），测试 +15（`TestPluginGuard`）全绿。

---

## 0. 两环定义（用户澄清 2026-08-29）

| 环 | 引擎 | 语义 | 节点 |
|:--|:--|:--|:--|
| **循环 A 插件自维护** | standing（ECO-SCAN→ECO-READ→ECO-EDIT→ECO-AUDIT→ECO-DOC） | 发版/新插件/安全事件 → 插件+技能双文档同步 + 分类学计数更新 | ECO-SCAN→ECO-READ→ECO-EDIT→ECO-AUDIT→ECO-DOC（对象=插件本体） |
| **循环 B 上岗任务执行** | standard（`cmd_migrate` 串联 standard/standing） | 迁移任务 + 生命周期 | analyze→verify→audit（执行）+ status/check/upgrade/rollback（生命周期） |

---

## 1. 循环 A SN 五元组实例化（ECO 插件自维护）

```
SN_A = ⟨G_A, B_A, C_A, T_A, D_A⟩
```

| 分量 | 实例化 | 检查/动作 |
|:--|:--|:--|
| **G_A** 进入谓词 | ① manifest 登记存在（`gk_plugin_manifest.get_manifest(pid)` 非空且未 disabled）；② 加载安全网 `load_status().source ∈ {release, builtin, dev}`（tampered/missing/error → 阻断）；③ 前置产物齐备：分类学计数基线（`migrate audit --script <cli> --bomb` 计数 vs `bashpy-problem-taxonomy.md §2` 记录漂移检测）+ 插件权威源 `zthl-bashpy-migrate/docs/migration-issues.md` 可读 | 缺任一 → 阻断 + 引导补全（fail-safe） |
| **B_A** 拦截/引导/修复 | ECO-READ：审查插件当前状态（loader/upgrade/manifest/config）；ECO-EDIT：收敛改动方案（插件+技能双文档各一份）；ECO-AUDIT：质询验证方案；ECO-DOC：双文档同步 + 分类学 §2 计数更新（漂移 → 循环 A 更新基线） | 状态 read-modify-write 串行化（`_hslsn_transact` 模式） |
| **C_A** 计数器 | 文档同步重试 ≤ 3 次（有界终止 A4） | 超限 → D_A |
| **T_A** 时间守卫 | TTL 1800s（时间自愈 A5）：超时未完成 → 冷却降频 | — |
| **D_A** 降级 | **fail-closed**：插件文档不同步 → 拦截 ECO-DOC 完成态（双文档不同构 = 循环 B 消费错源）| 人工升级（ECO-AUDIT 质询） |

---

## 2. 循环 B SN 五元组实例化（cmd_migrate 上岗执行）

```
SN_B = ⟨G_B, B_B, C_B, T_B, D_B⟩
```

| 分量 | 实例化 | 检查/动作 |
|:--|:--|:--|
| **G_B** 进入谓词 | ① 统一入口（hook R0.4 `_plugin_bare_call` 拦截一切裸调用：直接 CLI / python3 -m / -c import / eval / bash -c / 升级脚本）；② cap 白名单（`check_capability(pid, sub)` 子命令登记）；③ 加载安全网三连（cap → validate → load_status）；④ 窄任务清单（若任务可拆，`narrow_tasks` 非空 + schema 合法） | 缺任一 → fail-closed 阻断 exit 3/4 + 引导 |
| **B_B** | analyze（探测迁移面）→ verify（契约改进白名单：Bash 语义等价）→ audit（bomb 扫描 + RED-MIGRATE 打击点）；生命周期 status/check/upgrade/rollback 转发 `gk_bashpy_upgrade.py`（对账失败拒绝升级且配置零改动） | 输出契约 = ECC 确定性 JSON |
| **C_B** | 3 次（对齐 W9 auto-fix 循环） | — |
| **T_B** | TTL 1800s | — |
| **D_B** | fail-closed：拦截语义映射（plugin-loading-test-framework §1.3）——hash_mismatch/error → FAIL + finding；missing → 漏加载 finding 不静默 | — |

---

## 3. 与 gk_node_guard 衔接（NODE_REGISTRY 扩展）

`gk_node_guard.py` NODE_REGISTRY 新增插件生态节点（advance 未知节点硬阻断机制复用）：

| 节点 key | 归属环 | 前置产物 G 检查 | 状态更新 |
|:--|:--|:--|:--|
| `ECO-SCAN`（插件态） | A | manifest + load_status + 分类学基线 | gate_data.eco_plugin.last_scan |
| `ECO-EDIT`（插件态） | A | 双文档收敛方案存在 | gate_data.eco_plugin.edit_plan |
| `ECO-DOC`（插件态） | A | 双文档同步完成 + 计数更新 | gate_data.eco_plugin.doc_synced |
| `migrate-analyze` | B | 统一入口 + cap + load_status | gate_data.migrate.last_analyze |
| `migrate-verify` | B | 契约白名单就绪 + analyze 产物存在 | gate_data.migrate.verify_result |
| `migrate-audit` | B | verify 通过 + bomb 扫描目标就绪 | gate_data.migrate.audit_findings |

> 复用 route_map 总运行线路 + station_announcement（注入 advance hint），不新建平行机制
> （对齐 §12 重放归口：静态存在性类走 RED-COVERAGE / doc-align，动态行为类走本设计）。

---

## 4. SWE Refactor Bench ↔ bashpy 大环三阶段对齐（防 Blindness）

> **SWE Refactor Bench**（arXiv:2608.23564）：20 全仓库迁移 / 4 类技术债（language/framework/
> platform/build toolchain）/ 三阶段。核心洞见 = **Blindness**：agent 复制原实现骗过行为测试
> （520 runs 仅 5.4% 三阶段全过；迁移完整性 vs 行为正确性独立能力）。

| SWE Refactor Bench 三阶段 | bashpy 大环对应 | 防 Blindness 语义 | 现状 |
|:--|:--|:--|:--|
| ① Migration Audit | `migrate verify`（契约改进白名单） | 验证迁移真的发生（非复制原实现） | ✅ 已实装 |
| ② Behavioural Tests | 迁移后功能等价测试（gatekeeper-cli 行为保持） | 行为正确性 | ✅ 已实装 |
| ③ Agentic Verification（6 独立 agent） | `migrate audit --bomb` 自红队 | 隐藏 Bash 语义差异捕获 | ◐ 已有 bomb 扫描，缺**多独立 agent 交叉生成测试**环节 |

**缺口（登记候选增强）**：bashpy 现无"多独立 agent 交叉生成针对性测试"（SWE Refactor Bench ③
用 6 独立 agent 各 1 小时找差异）——可对齐为：bashpy 迁移后用 `subagent_runner` 委托 N 个独立
agent 各生成针对 Bash 语义陷阱的测试用例，交叉合并进 verify 契约白名单。**不实施，待插件生态改造轮。**

---

## 5. 实施验收清单（§6 模板对齐）

```
[x] 前置清单：manifest/load_status/分类学基线/权威源 纳入 G（_plugin_guard 真实检查）
[x] 名称精确：migrate 子命令名与 cap 白名单精确一致（`_PLUGIN_PROFILES` profile 表映射，未知/歧义 → 阻断）
[ ] 输入完整：subagent read 大文档（migration-issues.md）分页续读标记处理？（登记：上游 read_repo_file 已支持分页，G 层只验可读性）
[x] 数学公理：A1-A8 按环裁剪后满足（C=3/TTL 由调用环保证，G 层有界）
[x] 观测链：判定 → 阻断/放行 JSON 结构化输出（CLI guard exit 2 fail-closed）
[x] 测试：循环 A 漏登记/计数基线/双文档不同步 三态 + 循环 B 裸入口/越界 cap/加载异常 用例（TestPluginGuard +15）
[ ] SWE Refactor Bench 对齐：verify 防 Blindness 用例（复制原实现 → 拦截）——登记候选增强，待插件生态改造轮
```

---

## 参考来源

- sequence-node-safety-net-template.md（SN 五元组 + A1-A8 + 前置产物清单）
- plugin-loading-test-framework.md（加载安全网协议 + 拦截语义映射 + R0.4 调用门禁）
- bashpy-problem-taxonomy.md（循环 A/B 维护职责 + 统计口径）
- docs/plans/2026-08-28-security-hardening-assessment.md §14（登记）+ §12（重放归口）
- SWE Refactor Bench: arXiv:2608.23564（2026-08-25，Einsia.AI/清华）
