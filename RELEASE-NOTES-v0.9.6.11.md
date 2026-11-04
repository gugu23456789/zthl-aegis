# v0.9.6.11 发布说明

本版**修复发版 CI**：`pack` 步 argparse 退出 2，导致 v0.9.6.8–v0.9.6.10 的 release 作业
连续三版失败（zip/SBOM/PROVENANCE 均未产出）。代码与运行契约无其它变更。

## 根因

`release.yml` 的 pack 步调用：

```
python scripts/pack_release.py --tree . --out dist --version "$VERSION" \
  --source-repo ... --source-commit ... --source-tag ...
```

而 `pack_release.py` 既不认这三个参数，也不产出 publish 步要求的 `dist/PROVENANCE.json`
（`gh release create` 的资产清单里有它）⟹ 第一步就失败。

## 修复

- `pack_release.py` 新增 `--source-repo` / `--source-commit` / `--source-tag`，并写入
  `PROVENANCE.json`：来源三元组 + 主体哈希（zip 与 SHA256SUMS）+ 文件数 + 生成时间。
- `PROVENANCE.json` 的 zip sha256 与 `release-manifest.json` 对拍一致（同一来源，不二次计算）。
- 测试 +2 臂：参数可接受 + PROVENANCE 字段可核；无 source 时字段为 `null`。

## 验证

- 本地 `test_pack_release.py`：8 passed。
- 本版导出：796 files / 1054 excluded / 6 private blocks stripped；`DOCFACTS OK`（事实块自动重生成）。

## 已知限制

- 失败的历史 tag（v0.9.6.8/9/10）仍指向各自提交，不产生 Release 资产；以 v0.9.6.11 为准。
