## 改动

<!-- 一句话：改了什么、为什么。 -->

## 影响面

- [ ] 门禁 / hook（`pre_tool_hook.py`、Gate R0.x）
- [ ] CLI 命令（`gatekeeper-cli.sh`，`_CMD_REG` 是否新增）
- [ ] 发布 / 导出（`oss_scrub`、`gk_release_preflight`、workflows）
- [ ] 文档 / 事实块（`references/*`、GK-FACTS/GK-REFS）
- [ ] 仅测试

## 验证

<!-- 贴命令与结果，不要只写“已测试”。 -->

```text
python -m pytest -q scripts/<相关测试>.py
python scripts/gk_release_preflight.py
```

## 检查清单

- [ ] 没有新增未登记的命令 / 插件 / 常驻功能（新增则同步 `_CMD_REG`、manifest、`resident-features.json`）
- [ ] 改代码导致数字变化时，同批更新 GK-FACTS（`gk_docgen_facts.py --write`）
- [ ] 新增/删除文件后重生成 `FILES.md` / `llms.txt`（**先 `git add` 再 `--write`**）
- [ ] 公开面不含本机路径 / 密钥 / 未公开稿件标识
