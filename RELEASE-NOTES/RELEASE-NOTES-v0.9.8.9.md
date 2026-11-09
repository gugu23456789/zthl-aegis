# ZTHL Aegis v0.9.8.9 — 发布说明

> 2026-11-09。本版修**公开面发布门长期恒红**的存量缺陷（夜间 `bench-nightly` 连续失败的实际根因），
> 并清掉一批同类「测试期望与代码语义矛盾」的存量红。功能行为不变。

## 1. 夜间 CI 为什么一直红（根因）

`bench-nightly` 的 `full benchmarks` 步骤里 `gk_bench_release.py` 会跑 `gk_doc_release.py --strict`。
在**公开导出树**里它长期失败，链条是：

1. `README.md` / `README.en.md` 仍链到 `references/security-measures.md` —— 该文档 2026-11-02 起
   属导出排除面（仅私仓留存）⟹ `gk_doc_claims` 判「相对链接目标不存在」⟹ FAIL。
2. `gk_audit_docs` 的 `_export_excluded`、`gk_doc_align` 的 `_doc_excluded` 都 `import oss_scrub`
   —— 而 `oss_scrub.py` **自身不导出**（反查词表即指纹）⟹ 公开树内必然 ImportError ⟹
   排除面判定静默退化为「所有文档必须存在」⟹ 文件地图 / 互引链 / 注释-脚本引用全线误红。
3. `check_doc_freshness` 硬要求 `references/security-measures.md` 存在 ⟹ 公开树恒 FAIL。
4. `check_review_dual_source` / `check_eval_matrix` 硬要求 `stage-3-review.md` /
   `e1e4-evaluator-matrix.md` —— 二者均属导出排除面 ⟹ 公开树恒 FAIL。
5. `gk_docgen_facts` 的 GK-FACTS 块把 `references/入库 md` 写成**私仓全量 34**；公开树实为 22 ⟹
   同一事实块在两侧不可能同时成立 ⟹ 永恒漂移。

## 2. 变更

| 文件 | 变更 |
|:--|:--|
| `scripts/oss_export_surface.py`（新） | 导出排除面判定**单源**：直接消费随包导出的 `references/oss-export-whitelist.json`（不再依赖不导出的 `oss_scrub.py`）；目标树无白名单时回落本模块所在仓（供 tmp 夹具） |
| `scripts/gk_audit_docs.py` | `_export_excluded` 改用上者；`check_docs(..., release=False)`：release 模式下 C5 分类学 / C6 batch8↔评估文档（均在导出排除面）降级 `skipped`（match=True） |
| `scripts/gk_doc_align.py` | `check_doc_freshness(..., release)`：公开树缺席 ⟹ SKIP（私仓仍 FAIL）；`check_review_dual_source` / `check_eval_matrix` 同策 SKIP；`check_crossref_drift` / `check_comment_code_mismatch` 的排除判定统一走单源 |
| `scripts/gk_docgen_facts.py` | `references` 计数改为**公开面**口径（扣除导出排除面）⟹ 两侧事实块一致；索引与计数同源；标签改「references 公开 md」 |
| `README.md` / `README.en.md` | 删掉指向 `references/security-measures.md` 的死链（漏洞报告统一指向 `SECURITY.md`） |
| `references/oss-hooks.md` | 两处指向私仓文档的引用改为自包含表述 |
| `references/architecture-overview.md` | 文件图补 `sdk-loop-layering.md` |
| `scripts/test_gk_gitnexus_launcher.py` | **存量红修复**：`run_raw` 自 2026-11-02 起用 `Popen`（独立进程组），4 条臂仍钉 `subprocess.run` ⟹ 从未真正拦截 spawn（真去起 `/fake/node.exe` ⟹ 恒 False）。改为钉 `Popen` 的 `_FakePopen` 替身，并新增 autouse 夹具把 worker pidfile 落 tmp（测试不再写真实 `~/.gatekeeper`） |
| `scripts/test_gk_doc_align.py` | papers 两臂对齐代码语义：外部论文目录缺失 = SKIP（无法检测 ≠ 漂移）；原断言 WARN 与代码矛盾 |
| `scripts/gk_gitnexus.py` | 注释里的机器绝对路径改为占位形态（源码扫描臂不再命中） |

## 3. 验证（含可复现数字）

- **公开导出面模拟**（把修复后的文件覆盖到公开树副本，跑 `gk_doc_release.py --strict --summary`）：
  修复前 `FAIL facts=FAIL align(issues=5,warns=2) claims=FAIL` ⟹ 修复后
  **`PASS strict=True facts=PASS align(issues=0,warns=0) claims=PASS`**。
- `test_gk_doc_align.py` + `test_gk_audit_docs.py` + `test_gk_docgen_facts.py` +
  `test_gk_c47_ext.py` + `test_gk_gitnexus_launcher.py`：本机 **207 passed**
  （含此前 5 条 gitnexus 存量红 + 2 条 papers 存量红）。
- `test_gk_gitnexus_launcher.py`：**30 passed**（修复前 25 passed / 5 failed）。

## 4. 明确不做

- 不改导出白名单的既有裁定（`security-measures.md` / `prm-monitor-methodology.md` 等仍仅私仓留存）。
- 不改 `gk_doc_release --strict` 的严格度：本次是把「公开树缺席是预期」的判定接进检查器，
  而不是把 FAIL 降级成 PASS；私仓侧（`release=False`）行为逐位不变。

## 5. 与 v0.9.8.8 的关系

v0.9.8.8 = 并发公式标注 + GPU 显存闸 + accept 防爆硬闸。
v0.9.8.9 = 公开面发布门根因修复 + 存量测试红清理。对外建议直接使用 v0.9.8.9。
