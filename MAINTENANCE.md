# Maintenance Status / 维护状态

**中文**

- 本项目由维护者以**业余时间**维护，不提供商业 SLA；issue / PR 的响应时间为**尽力而为**。
- **安全修复优先**：涉及密钥、校验绕过、任意写入的问题会优先处理；功能请求按维护者可用时间排期。
- **版本策略**：主干保持可用；破坏性变更在 `CHANGELOG`（或 Release Notes）中显式标注，不静默改名/改语义。
- **停止维护信号**：若连续 12 个月无任何提交与 issue 回复，视为事实上停止维护；届时会在 README 顶部标注，并建议使用者自行 fork。
- **第三方组件**：随包分发的第三方资产见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)，其维护责任归各自上游。

**English**

- Maintained on a **best-effort, spare-time** basis. No commercial SLA; issue/PR response times are best-effort.
- **Security fixes take priority** (secrets, verification bypass, arbitrary writes). Feature requests are scheduled by maintainer availability.
- **Versioning**: the main branch stays usable; breaking changes are called out explicitly in `CHANGELOG` / Release Notes — no silent renames or semantic changes.
- **End-of-life signal**: 12 consecutive months without commits or issue replies means de-facto abandonment; the README will say so and users are advised to fork.
- **Third-party components** shipped with this repository are listed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md); they are maintained by their upstream projects.

## Disclaimer / 免责声明

**中文**

- 本软件按 **“现状”** 提供，不附带任何明示或暗示的担保，包括但不限于适销性、特定用途适用性与不侵权担保。
- 本项目是**开发期治理工具**（门禁 / 台账 / 预算 / 导出），**不是**安全产品，也不替代代码审计、渗透测试或合规审查。
- 使用者自行负责：在生产环境启用前的充分测试、对自动化决策（拦截/放行/评分）的人工复核、以及对所处理数据的合法性与合规性。
- 本项目与任何会议、期刊、企业或基金会的**评审决定**无关；仓库中出现的会议名称仅用于工具配置示例。

**English**

- Provided **“AS IS”**, without warranties of any kind, express or implied, including merchantability, fitness for a particular purpose, and non-infringement.
- This is a **development-time governance toolkit** (gates / ledgers / budgets / export), **not** a security product; it does not replace code review, penetration testing, or compliance audits.
- Users are responsible for adequate testing before production use, for human review of automated decisions (block/allow/score), and for the lawfulness and compliance of the data they process.
- This project is **not affiliated with** any conference, journal, company, or foundation's review decisions; venue names appearing in the repository are configuration examples only.
