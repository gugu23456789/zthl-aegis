# v0.9.6.13 发布说明

本版修复 v0.9.6.12 引入的**preflight 假红**：日常 CI 在 `docgen` 检查处失败。
代码行为无其它变更。

## 根因

`preflight` 作业**不安装** `openai/agents/pydantic`；`gk_docgen_facts.collect()` 依赖
`import subagent_runner` 取 `ROLE_TOOLS` ⟹ 导入失败被 `except` 吞掉 ⟹ `roles=[]`
⟹ GK-FACTS「子代理角色」从 **8 变 0** ⟹ 与已提交的事实块不一致 ⟹ 假红。

## 修复

- 新增 `_static_roles()`：从 `subagent_runner.py` 的 `ROLE_TOOLS` **字典字面量**静态提取角色名
  （与 import 路径同源，不引入第二份角色清单）；
- `collect()` 在 import 失败时回退到静态解析；
- 测试 +2 臂：静态解析必须含已知角色；依赖可用时与 live 表逐项相等。

## 验证

- 本地 `_static_roles` = 8，与 `ROLE_TOOLS` 一致；
- `docgen check` PASS；`test_gk_release_preflight` / `test_pack_release` / `test_gk_docgen_facts` 通过。
