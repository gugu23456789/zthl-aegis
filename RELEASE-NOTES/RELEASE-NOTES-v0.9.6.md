# v0.9.6 发布说明

本版是 v0.9.5 的发布链修复与文档可验证性补强，不改变运行时契约。

## 自述文档与发布门

- README 补齐三类常驻能力：**WAL/checkpoint 与基准**、**MCP 工具面安全**、**发布与可核验性**；
  `references/architecture-overview.md` 同步补 WAL、基准、MCP 段落。
- 新增发布门 `scripts/gk_doc_features.py`：
  - 读 `references/resident-features.json`（13 条登记）逐条校验自述文档覆盖；
  - 同时跑 `gk_docgen_facts.py check`，锁定 GK-FACTS / GK-REFS / state 容量水位表不漂移。
- 门禁接入 `ci.yml`（smoke job）与 `release.yml`（pack 之前），未覆盖即判红。

## CI / 发布链修复

- `bench-nightly`：公开树只导出 `references/` 子集，`doc-release --strict` 必然报「文件缺失」；
  该步改为只记录 SLA/rc，不再阻断夜间基准。
- `release.yml`：SLA 记录步骤改为 `continue-on-error`；`publish release` 在缺少
  `RELEASE-NOTES-<tag>.md` 时回退 `--generate-notes`。
- `gk_docgen_facts.py` 的角色数**恢复运行时导入**（`subagent_runner.ROLE_TOOLS`），
  静态解析不可验证；CI 相应安装 `openai` / `openai-agents` / `pydantic`。
- 修正公开面 README 指向未导出文档的悬空链接，并重生成事实块。

## 已知限制

- 公开包只包含 `references/` 子集，`docs/` 与部分内部文档不随包导出；发布门按此口径豁免。
- 旧指纹下标定的 `S`（相位步长）仍需在线上指纹上重探；探针不可解时返回 `resolved=false`。
