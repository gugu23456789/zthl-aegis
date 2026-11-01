# ECC-IMPACT-20260609-gitnexus

**冲击来源**: GitNexus v1.6.6 → **v1.6.7**
**分类**: 直接依赖
**检测方式**: `release-check` (GitHub API)
**分析阶段**: ECO-SCAN → ECO-READ（MPR Standing Plan）

<!-- META
target_repo: skill
project_type: analysis
phases: ECC-IMPACT
worktree_needed: false
-->

## 变更摘要

| 项目 | 值 |
|:--|:--|
| 当前版本 | v1.6.6 |
| 最新版本 | v1.6.7 |
| 安装路径 | `%APPDATA%\npm\gitnexus.ps1` |
| 是否升级 | **待决策** |

## 核心变更：KuzuDB → LadybugDB v0.15

[CHANGELOG Unreleased](https://github.com/abhigyanpatwari/GitNexus/blob/main/CHANGELOG.md)

### 1. 数据库引擎更换
- KuzuDB → LadybugDB v0.15（`@ladybugdb/core`, `@ladybugdb/wasm-core`）
- 存储路径: `.gitnexus/kuzu/` → `.gitnexus/lbug/`
- 旧索引自动清理（`cleanupOldKuzuFiles()`）

### 2. Embedding schema 扩展
- `CodeEmbedding` 表新增: `id`, `chunkIndex`, `startLine`, `endLine`, `contentHash`
- 旧 embedding 全部标记为过期 → 首次 `--embeddings` 会全量重建

### 3. VECTOR 扩展显式加载
- LadybugDB v0.15 要求显式 `loadExtension('vector')`
- Windows 上 vector 扩展存在 SIGSEGV 风险，已加 `vectorExtensionLoaded` 门控

### 4. WAL Checkpoint Driver（新增）
- 分析期间每 5 秒轮询 `CHECKPOINT`
- 3 次重试机制对抗 Windows Defender 文件锁
- 可通过 `GITNEXUS_WAL_MANUAL_CHECKPOINT=0` 关闭

## 冲击面评估

| 领域 | 影响程度 | 说明 |
|:--|:--|:--|
| `gitnexus analyze` | 🟡 中等 | 首次运行全量重建索引，之后增量正常 |
| `gitnexus analyze --embeddings` | 🟡 中等 | 旧 embedding 全量重生成，后续增量 |
| `gitnexus context/impact` | 🟢 低 | 接口不变，查询逻辑不变 |
| `gitnexus query` | 🟢 低 | 查询接口不变 |
| `gitnexus detect-changes` | 🟢 低 | 无影响 |
| `.gitnexus/` 目录 | 🟡 中等 | `.kuzu` 自动清理，`.lbug` 新创建 |
| `npm install` | ⚠️ 高 | 需要升级依赖（LadybugDB v0.15 → ^0.17.0） |

## 建议

**推荐升级**，但需要:
1. 升级后首次 `gitnexus analyze --embeddings` 计划在低负载时段执行（全量重建）
2. 验证 Windows 上 vector 扩展是否正常加载
3. 升级 CLI 的 gitnexus 命令引用指向新版本

<!-- DECISION score=0.92 verdicts={"F1": "PASS", "F2": "PASS", "F3": "PASS", "F4": "PASS", "F5": "WARN", "F6": "PASS", "F7": "PASS"} decision=PASS: upgrade gitnexus v1.6.7 -->
