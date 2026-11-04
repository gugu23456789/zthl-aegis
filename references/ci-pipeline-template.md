# CI 标准管线模板（通用）

<!-- DOC-META
title: CI 标准管线模板（通用）
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

> **性质**：纯工程样板，适用于含 WASM 构建 + 原生二进制的 C++ 项目（GitHub Actions）。
> **参考实现**：spz2glb `test-wasm-build.yml`（3 jobs，124 次运行全绿）、spz_gatekeeper `ci.yml`（4 jobs + deploy）。
> **原则**：workflow 是 CI/CD 的源代码——改动后必须 actionlint/zizmor 校验。

---

## 0. 适用边界与平台边界

| 维度 | 说明 |
|:--|:--|
| **平台** | 本模板覆盖 **GitHub Actions**。GitCode / 自建 runner 需按等效概念移植（触发器、cache、artifacts 各有对应物），模板不提供双轨适配 |
| **适用项目** | 含原生 C++ 构建（必选）；含 WASM 交付（可选 job）；含 Web Demo 部署（可选 job）；多语言/跨平台（可选 encoding-defense） |
| **参考验证** | "124 次全绿"是 **spz2glb 参考实现的事实**，非模板自身保证——模板落地后必须真实跑绿 |

## 1. Job 架构（必选 / 可选分层）

| 层级 | Job | 内容 | 适用条件 |
|:--|:--|:--|:--|
| ✅ **必选** | `build`（原生） | 多 OS matrix + CTest + 发布门禁 | 全项目 |
| ✅ **必选** | `security-audit` | zizmor（workflow 供应链）+ actionlint + **脚本危险命令静态扫描（D 类 T1059）** | 全项目 |
| ⚙️ **可选** | `test-wasm-build` | WASM 构建 + 后构建检查 + 测试（profile matrix） | 有 WASM 交付 |
| ⚙️ **可选** | `python-tests` | pytest 全量 + 插件加载安全网测试（见 §3.5） | 含 Python 源码/插件/脚本 |
| ⚙️ **可选** | `dead-code-multilang` | 多语言未使用代码静态检查（见 §3.7：Rust clippy / C++ cppcheck / JS·TS eslint / Go staticcheck / Kotlin detekt——重依赖远端跑） | 含对应语言源码（hashFiles 条件启用） |
| ⚙️ **可选** | `encoding-defense` | L1-L5 编码防御（见 §4） | 多语言/跨平台（.sh/.py 混合） |
| ⚙️ **可选** | `deploy_pages` | needs [wasm, build]，main 分支推 Pages | 有 Web Demo |

**规模门槛**（何时启用可选 job）：
- `test-wasm-build`：有 WASM 交付即启用；其中**哈希矩阵**（3 浏览器 × 5 采样）成本高——仅当转换是核心能力且需波动量化时启用，否则只跑 browser smoke
- `python-tests`：仓库含 Python 源码/插件（存在 `test_*.py`）即启用
- `dead-code-multilang`：仓库含 Cargo.toml / *.c·cc·cpp / package.json / go.mod / *.kt 任一即启用（hashFiles 条件自动跳空段）
- `encoding-defense`：仅当仓库含 `.sh`/`.py`/多语言源码
- `deploy_pages`：仅当有公开 Web Demo

## 2. 基础配置（全部项目必带）

```yaml
permissions: { contents: read }
run-name: <Workflow> - ${{ github.ref_name }}   # 固定显示名，防非 ASCII commit 标题变问号
concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }
on:
  workflow_dispatch:
    inputs: { ... }            # 手动触发入口
  push:
    branches: [ main, ... ]    # 显式白名单 (可配置)
    paths: [ 'src/**', 'tests/**', '.github/workflows/*.yml' ]  # paths 过滤 (可配置)
env:
  EMSCRIPTEN_VERSION: "6.0.3"   # (可配置) 当前稳定版
```

> `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"` 是 GitHub Actions Node24 迁移环境的特定兼容变量——**仅当 runner 环境需要时加**，非通用必带。

## 3. WASM 构建 + 测试流水

```
Emscripten SDK（actions/cache 缓存）→ emcmake 配置（profile matrix）→ emmake 构建
→ wabt 安装 → wasm-pre-check.sh（P0-P7，**CI 必须传 `--auto-fix`**）→ wasm-objdump 分析（Import/Export/Memory）
→ 合成夹具生成 → JS 逻辑单测（JSON 报告，fail>0 退出）
→ **注入产物指纹（sha384sum → sed 替换 `__WASM_FP__`/`__FP__` → 残留/一致性断言 fail-closed）**
→ 哈希矩阵（3 浏览器 × 每夹具 5 采样 min/median/max/σ + packMs）← 规模门槛见 §1
→ browser smoke（glue 加载 + 版本/导出检查）→ artifacts 上传
```

**指纹注入 step（CI 回环核心，吸收门卫 R7_1c）**：

```yaml
- name: Inject WASM fingerprints into site (CI loopback)
  shell: bash
  run: |
    set -euo pipefail
    SITE=build-wasm/site
    WASM_FP="$(sha384sum "${SITE}/<app>_wasm.wasm" | cut -d' ' -f1)"
    ENTRY_FP="$(sha384sum "${SITE}/<app>.js" | cut -d' ' -f1)"
    # 先替换 __WASM_FP__（meta 信任根），再替换 __FP__（?v= 内容寻址）——前者不含独立子串 __FP__，两次 sed 无交叉污染
    sed -i "s/__WASM_FP__/${WASM_FP}/g" "${SITE}/index.html"
    sed -i "s/__FP__/${ENTRY_FP}/g" "${SITE}/index.html"
    # 残留占位符 = 源码形态漂移 → fail-closed
    if grep -aqE '__WASM_FP__|__FP__' "${SITE}/index.html"; then
      echo "FAIL: leftover placeholder in ${SITE}/index.html (占位符形态漂移?)" >&2; exit 1
    fi
    # 发布闭环断言：index.html 内嵌信任根 == wasm 产物 SHA-384（定长 96 hex 形态检查）
    META_FP="$(sed -n 's/.*name="spz-wasm-fp" content="\([0-9a-f]\{96\}\)".*/\1/p' "${SITE}/index.html" | head -n1)"
    [ -n "${META_FP}" ] || { echo "FAIL: spz-wasm-fp meta 缺失或非 SHA-384 形态" >&2; exit 1; }
    [ "${META_FP}" = "${WASM_FP}" ] || { echo "FAIL: 信任根 ${META_FP:0:12}... != wasm ${WASM_FP:0:12}..." >&2; exit 1; }
    # 审计辅助 JSON（非校验依据 — 信任根已内嵌 index.html）
    printf '{"wasm":"%s","entry":"%s","algorithm":"sha384","note":"audit-aid-only: trust root inlined in index.html"}\n' \
      "${WASM_FP}" "${ENTRY_FP}" > "${SITE}/wasm-fingerprint.json"
```

**关键约束（踩过的坑）**：
- **替换顺序**：`__WASM_FP__` 必须先于 `__FP__`（`__WASM_FP__` 不含独立子串 `__FP__`，两次 sed 无交叉污染）
- **注入目标仅构建产物** `site/index.html`；`web/` 源码保留占位符（**单一来源** = `web/index.html`）——注入源码会让"占位符→指纹"变成不可逆
- JS 源码里的 `'__WASM_FP__'` 是**哨兵字面量**（信任根判空语义 `content !== '__WASM_FP__'`），**禁止**被 sed 替换
- 残留占位符 / 信任根与产物不一致 → **fail-closed**（占位符形态漂移的可观测出口）
- `wasm-fingerprint.json` = **审计辅助**，**不是**校验依据（信任根已内嵌，避免 TOCTOU）
- **wasm job 必须传 `--auto-fix`**——否则 P0-P7 的确定性修复能力在 CI 中**从不生效**（曾长期空转）

**关键实现约束**：
- **http.server + playwright + node 必须同一步骤**（分步时 trap EXIT 提前 kill server；npm audit 无 lockfile 报 ENOLOCK 使 bash -e 提前退出 → 假绿）
- 异步 API 必须 `await`（如 convert() 返回 Promise）；入参必须正确类型（如 Uint8Array，ArrayBuffer 无 .buffer/.byteOffset → 空写入）
- `fetch-depth: 0`：构建时 `git describe --tags` 派生版本号（浅克隆无 tag → fallback 旧版本）
- 每夹具 5 次采样，统计量在引用前声明（TDZ 修复）

### 3.5 Python 插件/工具测试（python-tests job，可选）

适用于含 Python 源码、脚本或按需加载插件的仓库（技能仓库 / zthl-harness 等）。pytest 全量是**硬门禁**——测试必须真实执行，禁止 `|| true` 吞失败（同 §7.1 假绿教训）。

```yaml
python-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: '3.11', cache: 'pip' }
    - name: 安装依赖（锁版本）
      run: |
        pip install --upgrade pip
        pip install pytest==8.3.*    # 与本地 self-check 版本对齐
    - name: pytest 全量（硬门禁，fail>0 退出）
      run: |
        python -m pytest scripts/test_*.py -q
    - name: 插件加载安全网冒烟（探测式插件的加载状态可审计）
      run: |
        python -c "import sys; sys.path.insert(0,'scripts'); from gk_bashpy_loader import load_status; print(load_status())"
```

**要点**：
- 测试文件统一 `test_*.py`；临时调试文件用 gitignore 形态（如 `_*_test.py`）隔离，不入 CI。
- 插件测试遵循 `references/plugin-loading-test-framework.md`：只 patch 被测模块边界
  （禁 patch 标准库全局——`pkgutil.resolve_name` 内部走 `importlib.import_module`，
  副作用污染后续 patch 目标解析）、夹具副作用显式声明、断言按加载态分层。
- 无 GitHub CI 的私有仓库：等效门禁 = `gk_self_check.py` 的 `check_tests` 项（本地确定性，零 API）。

### 3.6 插件供应链 job（可选，发布 npm/wheel 的插件仓库）

> 适用：仓库发 npm 包（DSH bundle）或 wheel 且消费方（如 skill 升级命令）做供应链对账时。
> 参考实现：`zthl-harness/zthl-bashpy-migrate` 的 `npm-supply-chain` / `wheel-supply-chain` job（2026-08-26）。

**npm 包投毒防护**（tarball sha512 内容确定性，对齐 zizmor 供应链审计同款哲学：无对账 = 无防御）：

```yaml
npm-supply-chain:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: '3.11' }
    - name: 安装引擎（node adapter 往返测试需要 Python 包）
      run: pip install -e .
    - name: Node 引擎测试（npm adapter）
      run: node --test npm/<pkg>/index.test.mjs
    - name: 构建 bundle + integrity 清单
      run: |
        bash scripts/npm-bundle.sh        # 产出 tarball + npm-integrity.json（sha512）
        cat npm/<pkg>/npm-integrity.json
    - name: 校验 pack 内容（声明文件 + npm 自动含入 README）
      run: |
        cd npm/<pkg>
        files=$(tar tzf ./*.tgz | grep -E '^package/[^/]+$' | sed 's#^package/##' | sort)
        printf 'cordis.patch.yml\nengine.js\nindex.js\npackage.json\nREADME.md\n' \
          | sort | cmp -s - <(echo "$files") || { echo "::error::pack 内容与声明不符"; exit 1; }
    - uses: actions/upload-artifact@v4
      with: { name: npm-integrity, path: npm/<pkg>/npm-integrity.json, retention-days: 7 }
```

**wheel 完整性清单**（升级命令对账源——堵 wheel self-certification 漏洞，即投毒 wheel 自证哈希无第三方比对源）：

```yaml
wheel-supply-chain:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: '3.11' }
    - name: 安装构建后端
      run: pip install build
    - name: 构建 wheel
      run: python -m build --wheel
    - name: 生成 wheel-integrity.json（官方 sha256 清单）
      run: |
        python3 - <<'PY'
        import glob, hashlib, json
        whl = glob.glob("dist/*.whl")[0]
        h = hashlib.sha256(open(whl, "rb").read()).hexdigest()
        json.dump({"wheel": whl.split("/")[-1], "sha256": h},
                  open("dist/wheel-integrity.json", "w"), indent=2)
        PY
    - uses: actions/upload-artifact@v4
      with: { name: wheel-integrity, path: dist/wheel-integrity.json, retention-days: 7 }
```

**发布联动**：release workflow 的 build job 必须同样生成 `wheel-integrity.json` 并随 dist 上传到 Release 附件——
Release 附件即**官方对账源**（skill 侧升级命令从 Release 下载 wheel 后比对）。消费方对账协议见
`references/plugin-loading-test-framework.md` §插件红队测试模板（攻击面 A wheel 对账 / 攻击面 F 调用门禁旁路，2026-08-27 扩展）。

### 3.7 多语言死代码检测 job（可选，远端跑语言专用重依赖）

> **定位（2026-09-01 用户定案：死代码检测三关扩展基础检测器，重依赖塞 CI 远端跑——"CI 模版取巧"）**：
> 本地确定性层覆盖 shell+Python（dead_code_gate1/2/3 + l5_blind_spot + python_lint + audit --depth）+ gitnexus 16 语言符号级
> （context/PDG，依赖索引新鲜度）；**语言专用"未使用代码"静态检查器是重依赖/大工具链**（clippy/cppcheck/eslint 等），
> 不在本地装 → 写进 CI 远端跑。swe-rb 重构产物（C→Rust/JS→TS 等新语言代码）的未使用代码检测缺口由本 job 补齐。
> **假绿红线同 §7.1**：检查必须真实失败，禁止 `continue-on-error` / `|| true` 吞失败。

> **两种落地形态（2026-09-01 查证 spz 双项目后校准）**：
> ① **独立 job**（本小节，多语言大矩阵，hashFiles 条件启用）；② **内嵌预检安全网 P 阶段**（先例 =
> spz2glb `scripts/wasm-pre-check.sh` **P7_DEADCODE**——host g++ `-fsyntax-only -Wall -Wextra -Wpedantic
> -Werror -Wunused-variable/-Wunused-function` 对 src/*.cpp 死代码扫描，fail 即 `exit 9`，见
> test-wasm-build.yml 失败摘要 P0-P7 分段。**零第三方依赖**（g++ 即工具链），适合 C/C++ 轻量场景。

```yaml
# 按仓库语言条件启用（存在对应源码即启用，缺失语言段自动跳过）
dead-code-multilang:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    # Rust: 未使用函数/字段（rustc -W dead-code）+ cargo clippy 全 lint 门禁
    - name: Rust dead code
      if: hashFiles('**/Cargo.toml') != ''
      run: |
        cargo clippy --all-targets -- -D warnings -W dead-code
        cargo build 2>&1 | rg 'dead_code|never used' && exit 1 || true
    # C/C++: 未使用函数（cppcheck unusedFunction）+ P7_DEADCODE 先例（g++ -fsyntax-only，零依赖）
    - name: C/C++ dead code
      if: hashFiles('**/*.c', '**/*.cc', '**/*.cpp', '**/*.h') != ''
      run: |
        if command -v g++ >/dev/null 2>&1; then
          find src -maxdepth 1 \( -name '*.cpp' -o -name '*.c' \) -print0 \
            | xargs -0 -r g++ -fsyntax-only -Wall -Wextra -Wpedantic -Werror \
                -Wunused-variable -Wunused-but-set-variable -Wunused-function
        else
          cppcheck --enable=unusedFunction --error-exitcode=1 \
            $(find . -name '*.c' -o -name '*.cc' -o -name '*.cpp' | grep -v node_modules)
        fi
    # JS/TS: 未使用变量（eslint no-unused-vars 硬门禁）
    - name: JS/TS dead code
      if: hashFiles('**/package.json') != ''
      run: |
        npx eslint --no-eslintrc --rule '{"no-unused-vars": "error"}' "**/*.{js,ts,jsx,tsx}" || exit 1
    # Go: 未使用声明（go vet + staticcheck U1000）
    - name: Go dead code
      if: hashFiles('**/go.mod') != ''
      run: |
        go vet ./...
        staticcheck -checks U1000 ./... || exit 1
    # Kotlin / Java: detekt unused / error-prone
    - name: Kotlin dead code
      if: hashFiles('**/*.kt') != ''
      run: detekt --config detekt.yml --build-upon-default-config --excludes "**/test/**" || exit 1
```

**要点**：
- **本地-远端分工**：轻依赖确定性层本地跑（0 API，IDLE 可用，交叉审查即时反馈）；重依赖语言检查器 CI 跑（工具链安装成本高，远端一次装好）。
- **与 gitnexus 的关系**：gitnexus 是符号级（谁调它/它调谁），语言专用 lint 是词法/AST 级（定义未引用）——互补，不替代。
- **启用门槛**：仓库含对应语言源码即启用对应段；`hashFiles` 条件让空段自动跳过（不假失败）。
- **门槛阈值可配置**：`--error-exitcode=1` / `-D warnings` 表示"零容忍"；宽松场景可在 job 内用 `rg` 计数阈值（对齐 dead_code_gate1 的 ≤5 阈值模式）。

### 3.8 swe-rb 契约验证门禁（挂目标项目 CI，可选）

> **适用（2026-09-01 用户定案）**：给**被 swe-rb 转换的目标项目**（State A / 重构产物 repo）配 CI，
> 每个 push/PR 自动验证"重构契约保持"。**允许性查证**：swe-rb CLI 全 `--repo` 参数化 + 纯 Python
> 零依赖 + 无网络调用（network_leak 是检测模式名非自身联网）→ Actions 直接可跑；`verify --contract-only`
> fail → exit 1（真实失败门禁）；契约只来自 State A 工件 + 提交产物，不读 tests/ 树/评分手册，
> verify 无网络 = 不触碰评分 oracle；CI 门禁 ≠ 评分 oracle（SWE-RB 评分仍由评测侧红队 subagent 差分对拍）。

- **模板位置**：`zthl-swe-rb/examples/ci-target-project.yml`（复制到目标项目 `.github/workflows/`）
- **三段结构**：① `contract-gate`（analyze State A 提取基准契约 → verify --contract-only 契约守卫门禁
  → audit --redteam 红队探测 → audit --probe-plan 差分候选上传 artifact，供评测侧红队 subagent 消费）；
  ② `security-audit`（zizmor/actionlint）；③ `dead-code`（目标项目语言：C/C++ P7_DEADCODE g++ -fsyntax-only /
  Rust clippy / JS·TS eslint，hashFiles 条件启用）
- **State A 组织**：`STATE_A_PATH` env（默认 `./state_a` 子目录或 submodule）；`SWE_RB_PKG` 安装源待
  zthl-swe-rb 推远端后生效（git+https 占位）

### 3.9 SARIF + code scanning（可选，任何有静态检查器的仓库）

> **定位（2026-11-04 用户定案）**：静态检查器的价值取决于**结果能否被消费**。私有 JSON 形状
> 只有写脚本的人读得懂；SARIF 2.1.0 是 GitHub code scanning / GitLab SAST / VS Code SARIF
> Viewer 的共同最小公分母 —— 一份结果，三端消费。参考实现：`zthl-aegis` 的
> `scripts/gk_sarif.py` + `ci.yml` 的 `security-audit` job。

**三条硬约束**：

1. **确定性**：SARIF 不带时间戳、不带随机量，同一输入逐字相同 ⟹ 可进棘轮基线、可 diff。
   （`partialFingerprints` 只用 规则/文件/行号/消息 四个稳定量做哈希。）
2. **不伪造位置**：拿不到行号就省略 `region`；树外载体（`../xxx`）**不生成** `locations`
   —— SARIF 的 relative uri 逃出仓库根会被 code scanning 判越界。宁可不给位置，不编路径。
3. **门禁与出口分离**：`--gate` 的退出码是门禁；SARIF **上传**只是报告出口。
   出口失败（仓库未启用 code scanning / 与 CodeQL default setup 互斥）不应把全部 PR 判红。

```yaml
security-audit:
  runs-on: ubuntu-24.04
  timeout-minutes: 20
  permissions:
    contents: read
    security-events: write      # job 级；job 级 permissions 会整体替换顶层，故 contents 必须重复
  steps:
    # ... 各静态门，每个都必须真实失败（禁 || true）...
    - name: SARIF (unified static results)
      # 三份私有 JSON 归一；always()：前面的门红掉时更需要这份清单
      if: always()
      run: python scripts/gk_sarif.py --out results.sarif --gate
    - name: upload SARIF to code scanning
      # fork PR 无 security-events 写权限（平台限制）⟹ 跳过而非判红
      if: always() && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
      continue-on-error: true    # 报告出口，非门禁（门禁在上一 step）
      uses: github/codeql-action/upload-sarif@<40-hex SHA>   # v3.39.2
      with:
        sarif_file: results.sarif
        category: aegis-static
```

**落地要点（踩过的坑）**：

- `upload-sarif` 同样必须 **40-hex SHA pin**（与 §9 action pin 同纪律）；`v3` 浮动 tag 会漂。
- 仓库启用 **CodeQL default setup** 时，workflow 侧 SARIF 上传会被拒（两者互斥）——
  二选一：关掉 default setup，或放弃 workflow 上传。属**配置态**，不该表现为"每次 PR 全红"。
- `--gate` 只是把三份结果再归一一次出判据，**不替代**任何原始门（原门仍各自失败）。
- 别把"无命中"的 PASS 占位项写进 results —— 那会把告警面板灌成噪声。
- **改造前先确认原步骤是不是装饰性的**：`scan --json > f.json` 这类形态多数恒 exit 0
  （数据输出契约），命中缺陷也不红 ⟹ 必须先跑一次门禁形态（无 `--json`，issues>0 ⟹ exit 1）。

## 4. 安全与编码防御

**security-audit**：
```yaml
- pip install zizmor==1.26.0
- zizmor --format plain --min-severity <high|medium> .github/workflows/   # (可配置) 参考: gatekeeper=medium, spz2glb=high
- actionlint（可用 gh CLI 免 Go 工具链）
- python scripts/gk_ci_security_lint.py --json   # 最小权限/SHA pin/persist-credentials/timeout/run 注入
# ── 脚本危险命令静态扫描（D 类 T1059，2026-08-15：脚本内部命令绕过命令字符串级 gate）──
- shell: bash
  run: |
    # 方案 A（零依赖，主防线）：危险命令模式 grep，命中即 FAIL
    #   rm -rf 家族 / git push --force / git reset --hard / git clean -f
    if grep -rnE '\brm[[:space:]]+-r[f]?\b|git push --force|git reset --hard|git clean -[fd]' \
        --include='*.sh' --include='*.bash' . ; then
      echo "::error::dangerous command found in shell script (D 类 T1059)"
      exit 1
    fi
    # 方案 B（可选增强）：ShellCheck 深度静态分析
    #   shellcheck --severity=warning $(find . -name '*.sh' -not -path './node_modules/*')
    # 注意：静态分析对已引用变量（rm -rf "$TMP"）盲——运行时防线仍需保留（见 spz-gatekeeper R0.3）
```
> 教训：`|| true` 让 zizmor 非阻塞 = 无防御（参数 bug，必须真实失败）

**encoding-defense（L1-L5，可选，移植自 TDAI）**：
- L5 乱码扫描：U+FFFD（EF BF BD）替换符 + 无效 UTF-8（排除二进制数据文件）
- L4 管道编码：.gitattributes `eol=lf` + core.autocrlf 检查
- L3 绕过模式：iconv UTF-16 / dos2unix / recode
- L2 CRLF：.sh 含 `\r` → FAIL
- L1 BOM：意外 UTF-8 BOM → FAIL

## 5. 发布门禁（审计类项目可复用）

- **release gate**：生成合法夹具 → 审计 → 断言 `policy_mode=release`、verdict/final_verdict 非 block、budgets 有 `declared` 阈值
- **challenge gate**：manifest 聚合（N 项混合）→ 断言 `policy_mode=challenge`、block 计数正确、分组摘要存在
- **quality gate**：覆盖 / 空壳风险 / 预算接线 / 发布就绪 四合一
- **外部存档预检**（2026-11-04）：包内 `references/archive.json` 的 Concept DOI 必须
  ① 离线可校验（schema + `10.5281/zenodo.<digits>`），② 联网能解析到存档站最新记录。
  离线校验进 CI（确定性、不依赖网络），联网 dry-run 进发包预检（**阻断**）。
  存档步骤本身**禁 `continue-on-error`**：v0.9.6.5 曾因它把 `403 Bucket is locked` 藏成绿色作业。
- **发布流水线契约预检**（2026-11-04，`scripts/gk_release_preflight.py`）：把 workflow 与发布脚本
  之间的三处**跨文件契约**在打包前机检，任一不满足即阻断：
  ① 参数契约：workflow 里 `pack_release.py` 用到的 flag ⊆ 脚本 parser（事故：v0.9.6.8–v0.9.6.10
     连续三版传 `--source-*` 而脚本不认 ⟹ pack 步 argparse 退出 2）；
  ② 产物契约：夹具真跑一次 pack，必须产出 zip / SHA256SUMS / release-manifest.json /
     PROVENANCE.json 四件套，且 `PROVENANCE.source`（repo/commit/tag）可核；
  ③ 资产契约：publish 步必须挂 **7 个资产** = zip + SHA256SUMS + PROVENANCE + SBOM +
     manifest + `dist/bench/release.json` + `dist/bench/release-compare.json`
     （基准步 `continue-on-error`，文件缺失时降级为 5 个，但**挂载点**必须在，禁止静默缺项）。
- **导出期文档自洽**（2026-11-04）：`oss_scrub.py export` 在导出树内自动跑
  `gk_docgen_facts.py --write`（`DOCFACTS OK / SKIP`，执行失败 fail-loud）。事实块含本仓
  `references/*.md` 计数（私仓 50 / 公开 28）⟹ 「同步后在目标仓手工 --write」必然每版漂移；
  生成器必须支持「无 git 时按目录清单回退」，否则导出树会把索引整段清空。
- 非审计类项目：仅保留原生构建 + CTest 作为发布门禁

## 6. 产物与失败诊断

- 上传 artifacts：结构报告 / 单测 JSON / 构建日志 / CMake 配置日志（retention 7 天）
- 失败时：分段失败摘要（按阶段 grep）+ 日志上传 + 导出表
- 诊断流程：CI 红 → 先自动诊断（gh REST）→ 3 轮仍红 → 系统化调试（禁止盲目重推）

## 7. 自愈机制（自动拦截 + 自动修复）

三层闭环：**构建时预检（拦截）→ 确定性自动修复 → 重验门禁**。这是模板的**核心工程能力**，不是静态清单——每个检查要么真实失败（拦截），要么自动修复后重验。

### 7.1 自动拦截（Build-time Gate）

- P0-P7 八级预检：环境 → 构建 → 导出符号 → 产物尺寸 → 前端一致 → 工作流 → 文件完整性
- 检查必须**真实失败**——假绿 = 无防御（ENOLOCK 提前终止、`|| true` 非阻塞、continue-on-error 吞失败，均为已踩教训）
- 叠加：hash matrix（3 浏览器 × 5 采样 σ）、zizmor/actionlint 供应链扫描、encoding L1-L5

### 7.2 确定性自动修复（Deterministic Auto-fix）

> **定位（2026-08-27 用户定案）**: 当前 auto-fix 本质是**工程妥协/经验产物防呆安全网**——覆盖 80% 基础/普通问题的确定性修复（符号前缀/编码/路径/平台差异）；导致 CI 挂掉的 20% → LLM 兜底（default 类 subagent 接入 standard 序列辅助主 agent，W9 流程级循环，batch8 R-T8 前置）。**待门卫 R7.1 推进后本模版须再次更新**（吸收 R7.1 CI 新教训）。✅ **已完成（2026-09-11，R7_1g 回流）**：wasm job 强制传 `--auto-fix`（§3 指纹注入 step 已写明命令侧）、`--ignore-scripts` 供应链加固（§8 红线）。

- **P2 符号 auto-fix**：Emscripten C 符号下划线前缀自动检测 + 修复——"once you know it, obvious; once you don't, mysterious"——首次遇到自动修，免人工排查（T44 light）
- **Auto-Fix 循环**：CI 红 → 自动诊断（gh REST / ci-diagnose）→ 确定性修复 → 重验；**3 次上限**，仍红则 escalate（禁止盲目重推）
- **--auto-fix 回环**：预检脚本支持自动修复模式，修复后重新校验直到 PASS 或达上限

### 7.3 为什么确定性（非 LLM）

- if-then 规则**可解释、可复现、零 API 依赖**——CI 是确定性执行层，不依赖 LLM 判断
- 构建错误通常是**已知类别**（符号前缀/编码/路径/平台差异），确定性规则一次写死
- 原则：确定性结构比对（输入/输出契约匹配）替代表面相似性推理

## 8. 红线（历史教训）

- workflow 改动后必须 actionlint/zizmor——workflow 是 CI/CD 源代码
- **脚本内危险命令须静态扫描**（D 类 T1059，2026-08-15：`bash <script>` 内部 rm -rf 可绕过命令字符串级 gate——E2E 自删事故；静态扫描=写时/CI 主防线，运行时 R0.3 兜底）
- npm audit ENOLOCK 假绿（`bash -e` + continue-on-error）——测试必须真实执行
- http.server 分步 trap kill——server + 测试同一步骤
- `persist-credentials: false` + action **40 位 commit SHA** pin（供应链；tag 会漂移）
- **npm install 必须 `--ignore-scripts`**（防 preinstall/postinstall 钩子投毒——ChainDrop 事件 2026-08-04：keyv@6.0.0 等 1300+ 包带 `"preinstall":"node setup.mjs"`，npm install 即触发窃密器；浏览器等二进制由显式 `npx playwright install` 下载，不受影响）
- zizmor `|| true` 非阻塞 = 无防御；安全 job 不得 `continue-on-error: true`
- **装饰性检查步**（2026-11-04）：`scan --json > f.json` 这类**数据输出契约**多数恒 exit 0 ⟹
  命中缺陷也不红。静态扫描步必须先跑门禁形态（无 `--json`，issues>0 ⟹ exit 1），再落 JSON
- **报告出口 ≠ 门禁**：SARIF 上传 / artifact 上传失败可以容忍（配置态），
  但生成 SARIF 的 `--gate` 步必须真实失败；二者不得混为一个 continue-on-error 步
- 发布 job 必须有 `attest-build-provenance`（`id-token: write` / `attestations: write`）；`environment: release` 可选——**单人维护不要配 required reviewers**，GitHub 不允许触发者自审，会永久等待
- **workflow ↔ 脚本参数契约不得靠人记**（2026-11-04）：v0.9.6.8–v0.9.6.10 连续三版发版失败，
  根因是 workflow 传 `--source-repo/--source-commit/--source-tag` 而 `pack_release.py` 不认，
  外加 publish 要求的 `dist/PROVENANCE.json` 从未产出。修法不是补一次参数，而是把契约做成
  **打包前机检**（`gk_release_preflight.py`）：参数集合、产物四件套、7 个资产挂载点。
- Pages 部署：github-pages 环境 deployment branch 白名单漏加 main → 部署失败
- GitCode 环境无 GitHub Actions 等效语义，模板不可直接照搬（需移植）

## 9. 安全防护基线（2026-11-02）

**必须全部满足**（本地门 = `python scripts/gk_ci_security_lint.py --json`）：

| 项 | 要求 | 原因 |
|:--|:--|:--|
| 最小权限 | 顶层 `permissions: { contents: read }`；写权限只给发布 job | 泄露 token 的爆炸半径 |
| Action pin | `uses: owner/repo@<40-hex SHA>`，禁止 `@v4` 浮动 tag | tag 可被重指，SHA 不可变 |
| 凭据隔离 | 每个 checkout `persist-credentials: false` | 防后续步骤读取 git 凭据 |
| 超时 | 每个 job `timeout-minutes` | 防挂起/资源耗尽 |
| 安全门 | security/audit job 不得 `continue-on-error` / `|| true` | 假绿 = 无防御 |
| 注入 | `inputs.*` / 不可信 `github.event.*` 不得直接进 `run:`，经 `env:` 中转 | 脚本注入 |
| 发布证明 | `actions/attest-build-provenance`；`environment: release` 可选，但单人维护不要配 required reviewers | 供应链可核验，且不自锁 |
| PR 边界 | `pull_request_target` 不得 checkout PR head | 不可信代码 + 写 token |
| 结果可消费 | 静态门结果同时产出 SARIF 2.1.0（确定性、不伪造位置） | 私有 JSON 进不了 code scanning / SAST 面板 = 检查了但没人看得见 |

```yaml
permissions: { contents: read }

jobs:
  release:
    runs-on: ubuntu-24.04
    timeout-minutes: 35
    # environment: release  # 可选；单人维护不要配 required reviewers（会自锁）
    permissions:
      contents: write
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@<40-hex SHA>   # v4
        with: { persist-credentials: false, fetch-depth: 0 }
      - uses: actions/attest-build-provenance@<40-hex SHA>  # v2
        with: { subject-path: dist/*.zip }
```

> 发布包模板的正文仍以 §3–§8 为准；本节是**安全最低线**，新增 workflow 必须过
> `gk_ci_security_lint.py` 才允许进 CI。
