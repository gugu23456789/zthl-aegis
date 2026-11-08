# ZTHL Aegis v0.9.8.5 — 发布说明

> 2026-11-08。本版是 **CI 供应链加固版**：依赖从"浮动区间"改成"内容哈希锁"，新增 zizmor 工作流硬门，
> release 特权面拆分，并消减一处暗依赖（非 LLM 命令不再被 SDK 绑架）。功能行为与 v0.9.8.4 一致。

## 1. 为什么发这一版

v0.9.8.4 之后暴露的真实缺口：CI 里的依赖是 `pip install openai-agents>=0.22,<0.24` 这类**浮动区间**——
上游账号被接管后"重发同名同版本、内容不同"的投毒，区间约束**拦不住**；release job 又在**签名/attest 之前**
执行第三方代码（含 `pip install`），一旦中招，被改写的 `dist/` 会带着合法签名发出去。

## 2. 变更

### 2.1 依赖单一事实源 + 内容哈希锁

- 新增 `requirements-runtime.txt`（运行期闭包，40 组件）与 `requirements-ci.txt`（+ pytest / pytest-xdist /
  PyYAML / zizmor）。二者由 `uv pip compile --universal --generate-hashes` 生成，**禁手改**。
- CI / release / bench-nightly 全部改为 `python -m pip install --require-hashes -r requirements-ci.txt`，
  并加 `PIP_ONLY_BINARY=:all:`（禁 sdist 构建钩子）、`PIP_DISABLE_PIP_VERSION_CHECK`、`PIP_NO_INPUT`。
- 删除所有 `--upgrade pip`（自举升级本身就是未锁的第三方代码执行）。
- 机检臂：`gk_ci_security_lint.py` 新增"pip 安装不得浮动、只准 canonical 锁文件"规则（含单测）。

### 2.2 zizmor 硬门 + Dependabot

- `security audit` job 新增 `zizmor --format plain --min-severity medium .github/workflows/`，**无 `|| true`**（红就是红）。
- 新增 `.github/dependabot.yml`：actions + pip 周更，分组 `ci-deps`，`open-pull-requests-limit: 5`，明示**不得自动合并**。

### 2.3 release 特权面拆分

`release.yml` 拆为三段：

| job | 权限 | 干什么 |
| --- | --- | --- |
| `verify` | `contents: read` | checkout / 装锁依赖 / workflow 安全门 / 包完整性 / smoke / 文档门 / 发布预检 |
| `release` | `contents/id-token/attestations: write` | **零 pip install**，只跑 stdlib 脚本 + 系统工具，然后 attest |
| `sync-main` | 继承 | 回写 main |

要点：**特权面里不再执行第三方代码**——投毒包没有机会在 attest 之前改写 `dist/`。

### 2.4 暗依赖消减

角色白名单表下沉为 `scripts/gk_role_regions.py`（零第三方依赖）。`gatekeeper-cli.sh --role` 的角色校验
与 `ROLE_TABLE_UNREADABLE` 修复不再需要装 openai。

### 2.5 分层条款（防表述歧义）

新增 [`references/sdk-loop-layering.md`](../references/sdk-loop-layering.md)：

- **A 层** = 编排/治理 loop（scan→fix→verify→advance、R 序列、审计链、红队链）——本仓自实现，不替换；
- **B 层** = SDK 内部 LLM tool-call 循环（`Runner.run`）——长期按 DSH 等价插件模块替换；
- 「不自研 loop」这一说法**禁用**，必须写全"不自研 SDK 内部的 LLM tool-call 循环"；
- 暗依赖红线：非 LLM 入口不得模块级 `import openai`；
- 不迁国产平替包（无对等物），国产杠杆只有镜像 + 哈希锁 + 国产模型端点。

## 3. 验证

- 公开仓 CI run #114：**9 job 全绿**（含 `zizmor` 硬门、`security audit (static)`、ubuntu/windows platform smoke）。
- Linux 侧 `pip download --only-binary=:all: --require-hashes -r requirements-ci.txt`：48 个 dist 全哈希校验通过。
- `gk_release_preflight.py`：全项 PASS；`gk_ci_security_lint`：workflows=4 issues=0 checks=98。

## 4. 已知坑（写进锁文件头，防复发）

锁必须 `--universal`：单平台（Windows）解析会把 `pywin32` 这类 win32 专属传递依赖写成**无条件**要求 ⟹
ubuntu runner 直接 `No matching distribution found`（v0.9.8.5 之前的首轮 CI 就是这样红的）。

## 5. 与 v0.9.8.4 的关系

v0.9.8.4 = 依赖区间修复补丁。v0.9.8.5 = 在其之上做供应链加固 + 暗依赖消减 + 分层条款。对外建议直接使用 v0.9.8.5。
