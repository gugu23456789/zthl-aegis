# v0.9.6.3 发布说明

本版回填 Zenodo 存档标识，使每个发布包自带永久 DOI；不改变运行时契约。

## 存档标识（Zenodo）

- **Concept DOI**：`10.5281/zenodo.23934594` —— 元 DOI，永久指向最新版本，已写入
  `references/archive.json`，并由 `pack_release.py` 写入 `PROVENANCE.json.archive`。
- **Version DOI**：`10.5281/zenodo.23934595` —— 仅对应 v0.9.6.2 那次归档，按口径只记在本说明里，
  不进 `archive.json`。
- Zenodo 记录 `23934595` 已公开，含 5 个附件（`zthl-aegis-v0.9.6.2.zip`、`SHA256SUMS`、
  `PROVENANCE.json`、`SBOM.cdx.json`、`release-manifest.json`），许可以为
  Mulan Permissive Software License v2（`https://license.coscl.org.cn/MulanPSL2`）。

## 核验

```bash
sha256sum -c SHA256SUMS
python -c "import json;print(json.load(open('PROVENANCE.json'))['archive'])"
# → {'concept_doi': '10.5281/zenodo.23934594', 'zenodo_record': '23934595'}
```

## 已知限制

- Concept DOI 只有首次发布后才会生成，因此 v0.9.6.2 及更早的包不含 `archive` 字段。
- 公开包只包含 `references/` 子集，`docs/` 与部分内部文档不随包导出；发布门按此口径豁免。
