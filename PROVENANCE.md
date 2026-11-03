# 来源声明（Provenance）

<!-- DOC-META
title: 来源声明
type: provenance
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-03
-->

本发布包是 **clean export（清洁导出）**，不是开发仓本身；开发仓的完整历史不随包分发。

## 1. 可对账的三件套

| 文件 | 作用 |
|:--|:--|
| `PROVENANCE.json` | 机器可读的来源声明：canonical 仓库、commit、tag、导出策略文件及其 sha256、导出工具 sha256、排除面声明 |
| `SHA256SUMS` | 包内**每个成员**的 sha256（含 `PROVENANCE.json`，不含自身）；`sha256sum -c SHA256SUMS` 可全量回验 |
| `release-manifest.json`（release 附件） | 文件清单 + 逐文件 sha256 + zip sha256 + 同一份 source/export 字段 |
| `SBOM.cdx.json`（release 附件） | CycloneDX 1.5 依赖清单；stdlib-only 时显式标注 `zthl:runtime-dependencies` |

## 2. 核验顺序（建议）

1. 解开 zip，先跑 `sha256sum -c SHA256SUMS`；任一行失败即停止。
2. 读 `PROVENANCE.json`，确认 `source.repo` / `source.commit` / `source.tag` 指向你信任的仓库与提交。
3. 在该仓库用同一 tag 检出，比对 `export.policy_sha256` 与仓库内导出策略文件是否一致。
4. **构建证明**：`gh attestation verify <zip> --repo <owner>/<repo>`。这是 Sigstore 签名的
   SLSA provenance，把产物与本次 workflow / commit 绑定；此路径不需要维护者的长期密钥。
5. **SBOM**：`SBOM.cdx.json`（CycloneDX 1.5）。本项目为 stdlib-only 时，
   `metadata.properties.zthl:runtime-dependencies = stdlib-only`；若有组件，按 purl 与版本核对。
6. **第三方存档（可选）**：若 release 说明给出 SWHID / DOI，可到 Software Heritage / Zenodo
   独立核验该快照的存档时间与内容；未给出即表示尚未存档，**不要**假定存在。

## 3. 为什么没有 git 历史

本包采用**孤儿快照**发布（单 commit、无内部历史），原因与取舍：

- 内部历史含计划、评审、运行档案与未公开实验面，公开会连带泄露这些内容；
- git 历史可以被本地重写（作者时间、rebase），本身不是真实性或产权的独立证明；
- 可验证性由**内容哈希 + 来源声明 + 第三方构建证明/存档**承担，而不是由历史条数承担。

若需要更强的第三方时间戳，可用 SWH / Zenodo 存档：**Concept DOI 写进 README / 本文件**，
**Version DOI 与 SWHID 写进该版本的 release notes**（口径见下）。本文件不预置这些值，避免伪造。

存档是**人工/凭据步骤**，CI 不自动执行：

- **Software Heritage（SWH）**：源代码的永久存档，给的是内容寻址的 **SWHID**（不是 DOI）。
  在 `https://archive.softwareheritage.org/save/` 提交 canonical 仓库 URL；它按**快照**存档，
  每次发布得到独立 SWHID，写入 release notes。
- **Zenodo（DOI）**：CERN 的通用存档库，有两种 DOI，**不要混用**：
  - **Concept DOI（元 DOI）**：整个项目的固定标识，永远解析到**最新版本** ⟹ 写进 README /
    本文件 / 包说明；它不随版本变化。
  - **Version DOI**：每个发布版本的冻结快照 DOI ⟹ 写进该版本的 release notes。
- **自动更新**：用 Zenodo 的 **GitHub 集成**（Zenodo → Settings → GitHub → 打开仓库开关）。
  之后每次 **GitHub Release** 都会自动创建一个 Zenodo 版本、铸造新的 Version DOI，而
  **Concept DOI 保持不变**。本仓的发版流程本来就用 `gh release create`，与它天然兼容。
- **边界**：GitHub 集成上传的是 GitHub 生成的**源码 tarball**，不是我们的 dist zip；
  若要把自定义 zip 也放进 Zenodo，必须走 API + token（CI 增加密钥与网络失败面），
  本仓**不做**，zip 仍以 GitHub Release 附件为准。

这两步都需要账号权限；未写 SWHID / DOI 的 release 视为**未做第三方存档**，而不是已存档。

## 3.1 去哪里填（本仓的单点）

`references/archive.json`（随包导出）只放**稳定标识**，打包时自动写入 `PROVENANCE.json.archive`：

| 字段 | 何时填 | 说明 |
|:--|:--|:--|
| `concept_doi` | Zenodo 首次发布后**填一次** | 元 DOI，永久指向最新版本 |
| `zenodo_record` | 同上（可留空） | Zenodo record id，便于机器解析 |
| `swhid` | 每次存档后更新 | 该发布快照的 SWHID |

空值会被省略，不产生伪造字段。**Version DOI 不进这个文件**（它在上传后才存在，写 release notes）。

具体操作：

**Zenodo（自动、一次配置）**
1. 确认 canonical 仓库是**公开**的（GitHub）；
2. Zenodo → Settings → GitHub → 打开该仓库开关；
3. 由现有发版流程创建 GitHub Release（`gh release create`，不要 draft）；
4. Zenodo 自动生成记录与 Version DOI，并给出固定的 **Concept DOI**；
5. 把 Concept DOI 填进 `references/archive.json`，此后每个包都自带它。

**Software Heritage（手动）**
1. 打开 `https://archive.softwareheritage.org/save/`，提交 canonical 仓库 URL；
2. 存档完成后复制该快照的 **SWHID**，写进 release notes（可选同步 `archive.json.swhid`）。

SWH 没有 GitHub App，不能随 Release 自动触发；需要每次发布后手动提交（或定期提交）。

## 4. 范围与许可

- 许可与著作权声明以包内 `LICENSE` / `NOTICE`（如有）为准。
- 导出排除面以 `references/oss-export-whitelist.json` 为唯一事实源（该文件随包导出）。
- 本声明只描述**本发布包**；不改变仓库内任何文件的许可或归属。
