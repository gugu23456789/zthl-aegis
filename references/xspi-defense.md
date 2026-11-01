# XSPI 污染攻防机制正本（跨站/间接提示注入）

> **定位**：本文件 = 本技能**污染防线**的机制正本（single source），承载「攻（威胁）」与「防（容器）」
> 两侧的**论文级依据**与**落地映射**。**禁放 docs/plans**（对齐 `convergence-evaluator.md` 体例）。
> **纪律**：本技能核心面 = **确定性、零 LLM、零新依赖**；LLM 依赖类检测（LlamaFirewall 等）只作
> 外部消费者可选层，**不得**进核心判定链路。
> **诚实**：每节标注「已实装 / 部分 / 未实装」，**不冒充已覆盖**。

---

## 0. 一句话结论

> 检测（正则/ML 分类器）**不是**安全边界；**容器化**（限制不可信文本能「导致」什么）才是。
> 现场判据：MCPTox 实测加 `<IMPORTANT>`/「ignore previous」类**措辞**只升 ASR **2–3%** ⟹
> **位置与结构**决定成败，措辞词表必然漏。故单纯扩正则 = fighting physics with a regex。

---

## 1. 威胁模型

- **lethal trifecta**（Willison 2025）：① 访问私有数据 + ② 暴露于不可信内容 + ③ 对外通信能力，
  三者同现 = 可被数据外泄利用。缺一基本是噪声。
- **污染三通道**（对齐审计署计划 §2）：`p_in` 输入 / `p_art` 产物 / `p_meta` 测量（含**人类评审自身**）。
  统计量 `κ=(κ_cap, κ_tilt)`；合成 `tilt_total = 1 − Π(1 − κ_tilt_i)`（缺通道按 0，单一来源
  `gk_moa_kappa.combined_tilt`）。
- **真实事故锚**：EchoLeak `CVE-2025-32711`（CVSS 9.3 **零点击**，穿过微软 XPIA 分类器）；
  GitHub MCP toxic flow（恶意 issue → 读私有仓 → 公开 PR 外泄）；promptware C2（CSA 2026）。

---

## 2. 攻击技术（论文级；按现代 LLM 有效性）

| # | 技术 | 论文/事件 | 关键数据 |
|:--|:--|:--|:--|
| A1 | 间接/跨站注入 (XSPI) | Greshake et al., arXiv:2302.12173 | 攻击者从不接触模型，只在被摄取内容里埋指令 |
| A2 | **Chat 模板伪装**（结构夺权） | ChatInject, arXiv:2509.22830 | 载荷伪装成原生 role/tool 模板 ⟹ 获系统级权威；可抗 template-stripping |
| A3 | 编码/隐形走私 | Reverse CAPTCHA, arXiv:2603.00164；ASCII smuggling | Base64 / ROT13 / emoji / 多语 / 零宽 / **Unicode Tags**(U+E0000–E007F) |
| A4 | 载荷分裂 | 综述 CMC 2025 | 每片无害、拼起来才是攻击 |
| A5 | 对抗后缀 (GCG) | Zou et al., arXiv:2307.15043 | 优化器搜出的 token 串翻转行为（非自然语言） |
| A6 | **工具投毒 (MCP)** | MCPTox, arXiv:2508.14925 | ASR 峰值 **72.8%**(o1-mini)、均 36.5%；**拒绝率 <3%**；line-jumping / rug-pull(`CVE-2025-54136`) / tool-shadowing |
| A7 | **记忆投毒 / 二阶** | AgentPoison, arXiv:2407.12784；SpAIware | **≥80% ASR @ <0.1% 投毒率**、效用仅降 ≤1%；写时投毒、跨会话引爆 |
| A8 | **多 Agent 感染 / AI 蠕虫** | Prompt Infection, arXiv:2410.07283；Agent Smith, arXiv:2402.08567 | 自复制 LLM-to-LLM；100 万 Agent 指数级感染 |
| A9 | 混合威胁（PI × XSS/CSRF） | arXiv:2507.13169 | 传统 WAF/XSS 过滤/CSRF token 对 AI 增强攻击失效 |

**对本技能的靶心**：A2（结构）、A4（分裂）、A7（二阶/记忆）——分别对应 T5-c、T5-e-P6、T5-d。

---

## 3. 防线（四层；论文级）

| 层 | 防线 | 来源 | 效果 / 定位 |
|:--|:--|:--|:--|
| **形式层** | Normalize（NFKC + 零宽 + Tags + 同形字 + 解包） | 本技能 `gk_norm.py` | 封 A3；**可复算、零依赖** |
| **结构层** | **Spotlighting**（随机分隔符 + datamarking + 编码） | Hines et al. / Microsoft Prompt Shields | ASR >50% → **<2%**；**可被扰动绕过**（ChatInject §6.2） |
| **容器层** | **CaMeL**（capability + 双 LLM + 数据流标签） | Debenedetti et al., arXiv:2503.18813 | 按构造可证；假设用户 prompt 可信 |
| **容器层** | **设计模式**（Plan-then-Execute / Dual-LLM / Action-Selector） | arXiv:2506.08837 | 原则：一旦摄入不可信输入，就限制它**不能触发后果性动作** |
| **容器层** | **AgentArmor**（运行时 trace 的 CFG/DFG/PDG + 类型系统） | arXiv:2508.01249 | **零 LLM、确定性** —— 合本技能纪律 |
| **净化层** | **SIC 循环**（检测→改写→再评→halt） | arXiv:2510.21057 | 强对手仍 15% ASR |
| **净化层** | **Firewall Minimizer+Sanitizer** | ServiceNow/Mila | AgentDojo 0% ASR；作者自警**基准被饱和**，提三阶级联攻击 |
| **检测层** | LlamaFirewall（PromptGuard2 / AlignmentCheck / CodeShield） | Meta | **LLM 依赖** ⟹ 不合核心零依赖纪律，仅外部可选 |
| **治理层** | 最小特权 + 不可逆动作人审 + schema hash pinning + 写入时校验/TTL | OWASP MCP03:2025 等 | 唯一**不依赖“能否识别恶意”**的一层 |

**行业共识**：`SPOTLIGHTING/检测` 是**卫生**，`容器化/最小特权/人审` 才是**墙**。

---

## 4. 本技能落地映射（T5）

| 项 | 落点（文件/函数） | 状态 |
|:--|:--|:--|
| **T5-b Spotlighting** | `gk_norm.spotlight_delimit` / `datamark` / `spotlight_encode` | **已实装**（确定性；marker 由调用方给，不取随机） |
| **T5-c 结构检测器** | `gk_moa_aggregate._surfaces` / `poison_labels` / `sanitize_text` + `gk_norm.fold_confusables` / `decode_candidates` | **已实装**：字面/NFKC/同形折叠/**解包候选**(ROT13+Base64) 多面匹配；chat 模板/role 标签/markdown 头入词表 |
| **T5-a 溯源/能力硬门** | `gk_finding._PROVENANCE` / `_sink_blocked` / `set_release_state(declassify=)` / `close/verify(declassify=)` / `release_set.blocked` / CLI `declassify` 子命令 | **已实装**：`provenance=untrusted` 未 `declassify` ⟹ **release/close/verify 禁行**；聚合/散文 finding 由**摄取边界**打 untrusted |
| **T5-d 二阶/记忆校验** | `gk_finding._scan_taint`（复用 `poison_labels`）+ `register` 写入时污点扫描 + `taint[]/quarantined` 字段 | **部分**：写入时扫描 + 隔离**已实装**；记忆/TTL **无基座**（见 §5.3 / §7） |
| **T5-e 红队扩容** | `_red_attacks.red_poison_matrix` P4(结构)/P5(二阶门)/P6(分裂)/P7(多 Agent) | **已实装**；修复后探针自转绿（防回归） |

**taint 只升不降**（`register` merge 路径）：同 `root_key` 二次登记为 untrusted ⟹ 存量升格。

---

## 5. 缺口与后续（诚实登记）

1. **A5 对抗后缀 (GCG)**：非自然语言 token 串，**词表/结构面皆无力**；正解 = 容器层（capability），
   当前**未覆盖**。
2. **A6 工具投毒**：本技能无 MCP 工具面 ⟹ **不适用**；若未来接 MCP，须按 MCP03:2025 做
   schema hash pinning + 逐调用再校验。
3. **T5-d 记忆/TTL：无基座**（2026-10-06 zthl 调研）：本技能**无**可检索、可过期的持久记忆模块；
   ZTHL 记忆层（计划 §2.2）落点 = `state`（燃料）+ AMP ash（灰烬），其核心 = **Frozen Snapshot /
   ImmutablePrefix**（指令面完整性钉），**亦非**可过期条目 ⟹ 「TTL」在两侧皆无对应物。详见 §7。
4. **P-art `defect_rate` 已接通**（2026-10-06，WS2）：观测面 = **本批**产物缺陷率（批内 `rejected`/总数，
   `gk_moa_aggregate._latest_defect_rate`）。仓级 bomb **未接入**（全局与批无关，折入批级 tilt 会饱和成
   常数 = 类别错误），登记为**未来独立信号**。
5. **人审通道**：P-meta 已建模为可污染（`divergence>0.2` 硬门），方向与文献「人审不可作唯一边界」一致。

---

## 6. 论文锚（来源）

- Greshake et al. 2023, arXiv:2302.12173 — 间接提示注入。
- ChatInject, arXiv:2509.22830 — chat 模板伪装（结构夺权）。
- MCPTox, arXiv:2508.14925 — 工具投毒基准（ASR/拒绝率）。
- AgentPoison, arXiv:2407.12784 — 记忆/RAG 后门投毒。
- Prompt Infection, arXiv:2410.07283 — 多 Agent 自复制。
- Agent Smith, arXiv:2402.08567 — 感染性越狱。
- 设计模式, arXiv:2506.08837 — 可证抗注入的 Agent 设计模式。
- SIC, arXiv:2510.21057 — 软指令去升级（净化循环）。
- AgentArmor, arXiv:2508.01249 — 运行时 trace 程序分析。
- Prompt Injection 2.0, arXiv:2507.13169 — 混合威胁（PI×XSS/CSRF）。
- CaMeL 增强, arXiv:2505.22852 — capability 企业化。
- Reverse CAPTCHA, arXiv:2603.00164 — 零宽/Tags 走私。
- Firewall Minimizer+Sanitizer（ServiceNow/Mila）— tool 接口防火墙 + 三阶级联攻击。

---

## 7. 记忆挂件记录（T5-d；**仅文档，不建代码**）

> 裁定（owner 2026-10-06）：「记忆你可以额外放各种模板的位置加个极简的参考说明记录清楚不确定性」；
> 「zthl 那边的记忆层设计大概也是要大改的，卫星计划实装会连带影响余烬系统 ⟹ zthl 那边之后要整体重写；
> 继续 WS1 和 2（WS3 只搞个文档）」。

**调研事实（zthl）**：`zthl/` = 技能仓内 **ZTHL Core** 实装（第一个实装件 = `zthl/eventbus.py` 的
`SignalHub`；核心论文 = 外部预印本（匿名评审期隐去编号）；适配计划见 `docs/plans/2026-07-26-…`）：
- ZTHL 记忆层定案（计划 §2.2 + ZH3-H12）：落点 = 技能仓 **`state`（燃料）+ AMP ash（灰烬）**，自研；
  H12 = **Frozen Snapshot + ImmutablePrefix**（state JSON + SHA256，覆盖对象 = **指令面完整性**）；
  外部后端 seam = **Mem0 / memsearch**（计划 §7「独立可选记忆后端」）。
- ⟹ ZTHL 的「记忆」= **快照/完整性钉**，**非可检索、可过期的对话记忆** ⟹ T5-d 的「TTL」在 ZTHL 侧
  **同样无对应物**。

**本技能现状与处置**：
1. 本技能**无** Agent 持久记忆模块（`gk_audit_memory.py` = 审计历史/校准台账；`subagent_runner` 的
   "memory" = 进程内 list）。
2. T5-d 现存实装 = **写入时污点扫描（`gk_finding._scan_taint`）+ 溯源汇点硬门（`_sink_blocked`）**；
   **无 TTL、无过期语义**（不冒充）。
3. **预设接入点**（未来）：要么接外部记忆后端（Mem0/memsearch），要么接 ZH3-H12 快照；接入后 TTL/
   过期语义才有基座。**当前不建骨架代码** —— zthl 记忆层待整体重写，现在建会被推翻。

**不确定性（显式登记）**：zthl 记忆层 + 余烬系统 + 卫星计划**互相牵连、后续整体重写** ⟹ 本记录的
接入点与 TTL 语义**均未定**；重写落地后须回填本 §7（并同步 §4 映射表 T5-d 行）。
