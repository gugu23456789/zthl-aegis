# Contributing / 参与贡献

**中文** · [English below](#english)

## 1. 环境

- Python **3.11+**（推荐 3.12）、Bash、`git`；测试依赖 `pytest`（可选 `pytest-xdist`）。
- 不需要安装本仓本身：它是「命令行 + 脚本」形态，直接 clone 即可运行。
- 选择解释器的方式见 [`CONVENTIONS.md`](CONVENTIONS.md#测试解释器硬约定2026-10-27-起由-gate-r016-机检)：
  `ACCEPT_PY` 环境变量 → `scripts/_accept_py.local`（本机私有，已 gitignore）→ `python3`。

## 2. 提交前必须跑的门

```bash
bash scripts/ci_smoke.sh                 # 语法 + 编译 + 快测（分钟级，PR 必过）
bash scripts/_accept_cli.sh --full       # 全量验收（慢；以 NEW/FIXED 判定，不看绝对红数）
bash gatekeeper-cli.sh docgen --check    # 文档与命令表同源检查
bash gatekeeper-cli.sh doc-align --summary
```

PR 描述请写明：**改了什么面**（脚本 / 门禁 / 文档）、**怎么验证的**（贴命令与读数）、
**已知边界**（没做什么、为什么）。

## 3. 三条硬纪律

1. **红先**：先写能复现缺陷的失败测试（`scripts/test_*.py`），再改实现。禁止为通过测试而放宽断言或简化实现。
2. **锚用符号、不用行号**：文档/计划/发现里的定位写成 `path::symbol` 或 `file.ext:N` 可复算形式；
   行号锚会随代码移动而漂移。
3. **凡有产出必留痕**：发现的问题用
   `bash gatekeeper-cli.sh finding register "<可复查事实>" <source>` 登记（`source` 见
   [`references/ecc-write-spec.md`](references/ecc-write-spec.md)）；修复后在提交信息里引用 id。

## 4. 代码结构

| 位置 | 职责 |
|:--|:--|
| `gatekeeper-cli.sh` | 命令面（参数解析 + 编排）；`_CMD_REG` 位于受保护区，**新增命令须维护者评审** |
| `scripts/*.py` | 引擎（门禁、台账、卫星存储、审计、聚合）；单一事实源优先落在模块内 |
| `references/` | 规范正本（协议、写入规范、安全措施、架构图） |
| `docs/plans/` | 计划与留痕（历史计划只增不改） |
| `docs/analysis/` | 运行期产物；仅 `*.md` 报告入库，原始 JSON 不入库 |

## 5. 不要提交

- 任何密钥 / `.keys` / HMAC 主密钥 / 审计私钥；
- `.gatekeeper.state*`（含卫星片）、`docs/analysis/subagent/*.json`、`moa-chain-*.html` 等运行期产物
  （已由 `.gitignore` 覆盖；若发现漏网请一并补规则）；
- 个人路径（本机 venv、家目录绝对路径）——用环境变量或 `_accept_py.local` 这类本机私有文件承载。

## 6. 行为

对事不对人；评审意见请给出可复算依据。安全问题请**不要**开公开 issue，按 [`SECURITY.md`](SECURITY.md) 报告。

---

## English

**Scope.** Bug reports, tests, docs and focused engine changes are welcome. New CLI commands
(`_CMD_REG`) live in a protected region and require maintainer review.

**Before you open a PR**, run the four gates above and paste the output. Describe what changed,
how you verified it, and what you deliberately left out.

**Three rules.** (1) *Red first* — land a failing test that reproduces the defect before the fix;
never weaken assertions to go green. (2) *Symbolic anchors, not line numbers* — use
`path::symbol` so anchors survive refactors. (3) *Everything leaves a trace* — register findings
with `finding register` and cite the id in your commit message.

**Never commit** secrets, `.gatekeeper.state*`, raw analysis JSON, `moa-chain-*.html`, or personal
absolute paths. Security issues: see [`SECURITY.md`](SECURITY.md) — please do not open a public
issue for them.
