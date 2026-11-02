# 插件加载安全网协议 + 插件导入测试安全网框架

<!-- DOC-META
title: 插件加载安全网协议 + 插件导入测试安全网框架
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

> **性质**：技能仓库基础设施模式文档（target_repo=skill）。沉淀 2026-08-23 加载安全网事件
> （gk_bashpy_loader + test_gk_bashpy_loader）两个测试缺陷的复盘结论。
> **适用范围**：任何按需加载的探测式插件（bashpy-migrate / BASH2PY 常驻节点 / 未来 TOOL_REGISTRY 扩展）。
> **参考实现**：`scripts/gk_bashpy_loader.py`（加载侧）、`scripts/test_gk_bashpy_loader.py`（测试侧）。

---

## 0. 为什么需要这份协议

插件 = 按需加载的探测式工具。加载行为有三种失败模式，缺省实现必然踩：

| 失败模式 | 语义 | 默认实现的坑 |
|:--|:--|:--|
| **漏加载** | 工具该有却没有 | `except Exception: pass` 静默吞掉 → 扫描退化为内置最小版，无告警 |
| **误加载** | 加载到了错误版本（被篡改/哈希不匹配） | 发布包 SHA256 不校验 → 供应链投毒面 |
| **错误加载** | import/调用抛异常 | 异常被吞或裸抛 → 调用点语义不明 |

协议目标：三种失败模式全部**显式报告**，调用点决策可审计（GK_DBG_LOG），
加载优先级确定（发布包 → dev → missing）。

---

## 1. 插件加载安全网协议

### 1.1 加载优先级（确定序）

```
1. 发布包（优先）  pip 安装 + SHA256 命中固定哈希表  → source=release
2. 本地 dev 源码  源目录 sys.path 导入（非 CI 验证）  → source=dev
3. 均不可用                                         → source=missing
```

- **哈希固定点**：`_RELEASE_PINS = {version: sha256}`，只登记**跑过 CI 的发布产物**。
  未登记 = 发布包已装但无哈希 → `release_unverified`（WARN 语义，CI 发布后登记）。
- **dev 源目录**：环境变量优先（`ZTHL_BASHPY_DIR`）+ 已知路径回退（Windows/WSL 双形态）。
- **哈希不匹配**：拒绝发布包 → 回退 dev → 仍不可用则 missing。**永不静默使用哈希不匹配的包**。

### 1.2 双函数契约（调用点唯一入口）

```python
# 状态查询（供 self-check / 审计消费）
load_status() -> {"source": ..., "version": ..., "hash_verified": ...,
                  "detail": ..., "module_file": ...}
# 工具获取（供功能调用点消费）→ (可调用|None, 状态)
load_bomb_scan() -> (bomb_scan, status)
```

- `load_status()` 只读，无副作用，可高频调用。
- `load_*()` 返回 `(fn, status)` 二元组——**调用点必须检查 fn 与 status 双信号**，
  禁止只看 fn 可空而忽略 status（漏加载必须显式报告）。

### 1.3 拦截语义 → 消费方映射

| source | 消费方动作 |
|:--|:--|
| `release` | self-check PASS；功能调用点直接使用 |
| `release_unverified` | self-check WARN（CI 发布后登记 `_RELEASE_PINS`） |
| `dev` | self-check WARN（非 CI 验证）；功能调用点使用 |
| `hash_mismatch` | self-check FAIL（误加载拦截）；调用点报 finding + 回退 dev |
| `missing` | self-check WARN（探测式启用不阻断）；**调用点必须报漏加载 finding，不静默** |
| `error` | self-check FAIL（错误加载拦截）；GK_DBG_LOG 追加 + 调用点报 finding |

### 1.4 可调试插桩

- 每次加载决策 `_dbg()` 追加 `GK_DBG_LOG`（加载来源、拒绝原因、回退路径）。
- 关键路径 stderr 不吞（对齐 2026-08-13 heredoc 吞错教训）。

---

## 2. 插件导入测试安全网框架

### 2.1 规则 R1 — 禁止 patch 标准库/第三方全局模块属性

**教训（2026-08-23）**：`patch("gk_bashpy_loader.importlib.import_module")` 之后，
后续 patch 的目标解析 `pkgutil.resolve_name('gk_bashpy_loader')` 拿到被 mock 的 fake 模块
（`pkgutil.resolve_name` 内部走 `importlib.import_module`，见 CPython pkgutil.py），
抛 `AttributeError: <fake module> does not have '_imported_module_file'`。

- **根因**：patch 全局 `importlib` 模块对象 = 副作用半径不可控；with 内 patch 的 enter 顺序成为隐含依赖。
- **规则**：测试只 patch **被测模块边界**（`gk_bashpy_loader._imported_module_file` 等模块级名），
  不 patch `importlib.import_module`、`os.path`、`sys.path` 等共享全局。
- **兜底**：若确实需要替换模块加载，给被测模块加**模块级注入点**
  （如 `_IMPORT_MODULE = importlib.import_module`），测试 patch 注入点而非标准库。
- **顺序纪律**：任何跨模块副作用 patch（如仍被迫 patch 全局）必须放 with 块**最后一位**，
  其后不得再有依赖目标解析的 patch；违反即视为设计耦合信号。

### 2.2 规则 R2 — 夹具副作用必须显式声明

**教训（2026-08-23）**：`_force_fallback()`（强制 source=missing）创建于"无拦截"时代，
安全网新增 RED-MIGRATE-LOAD finding 后，该夹具触发了新 finding，旧断言 `== []` 失败。

- **规则**：夹具 docstring 必须声明副作用契约，例如
  "强制加载不可用 → 干净 CLI 也会产生 RED-MIGRATE-LOAD（漏加载拦截即 finding）"。
- **规则**：新增拦截/告警语义时，必须审计所有复用该夹具的测试断言。

### 2.3 规则 R3 — 断言按业务态分层

同一输入在不同加载态下契约不同，必须拆分为独立用例：

| 业务态 | 断言契约 |
|:--|:--|
| 加载可用（release/dev） | 干净输入 → 零 finding |
| 加载不可用（missing/hash_mismatch/error） | 干净输入 → 仅拦截 finding |

禁止用一个"总开关"夹具同时断言两个契约（`== []` 一次成立、一次失败 = 语义混叠）。

### 2.4 模板骨架

```python
# 1) 被测模块注入点（生产侧）——若需替换加载
_IMPORT_MODULE = importlib.import_module   # 测试 patch 此模块级名

# 2) 测试侧——只 patch 被测模块边界
def test_dev_fallback(self, tmp_path):
    f = tmp_path / "audit.py"
    f.write_text("x")
    with patch("pkg._installed_version", return_value=None), \
         patch("pkg._import_dev", return_value=True), \
         patch("pkg._imported_module_file", return_value=f):
        st = pkg.load_status()
    assert st["source"] == "dev"

# 3) 夹具副作用声明
def _force_unavailable():
    """强制加载不可用 → 干净输入也会报 LOAD 拦截 finding（漏加载不静默）。"""
    return patch("pkg.load_bomb_scan",
                 return_value=(None, {"source": "missing", "detail": "forced"}))

# 4) 断言分层——两个独立用例
def test_clean_cli_loader_ok(self, tmp_path):   # 可用 → 零 finding
    ...
def test_clean_cli_loader_missing(self, tmp_path):  # 不可用 → 仅 LOAD
    ...
```

### 2.5 插件测试登记表（新增插件测试时登记）

> 插件类测试 = 加载安全网测试 + 生命周期测试两类，必须符合 §2.1-R1 / §2.2-R2 / §2.3-R3。

| 测试文件 | 覆盖层 | 用例数 | 模版规则符合性 |
|:--|:--|:--|:--|
| `test_gk_bashpy_loader.py` | 加载安全网（六源分流 / SHA256 pin / 回退 / 拦截语义 / **upgrade_pending 启动检测**） | 13 | R1 ✓ 只 patch 模块边界（`_IMPORT_MODULE` 注入点）；R3 ✓ 加载可用/不可用分用例 |
| `test_gk_paper_review_loader.py` | paper-review 加载安全网（2026-08-29，bashpy 协议统一应用：builtin/dev/tampered/missing/error 五源分流 / SHA256 pin / manifest 对账 / 双函数契约 load_status+load_reviewer 二元组） | 8 | R1 ✓ 只 patch 模块边界（`_entry_path`/`_PAPER_REVIEW_PINS`）；R2 ✓ 夹具副作用注释；R3 ✓ 可用/不可用分用例 |
| `test_gk_plugin_manifest.py` | 生命周期（manifest 门禁 / 能力白名单 / load-unload 回滚 / 幂等 / **DSH 生态对接** / **npm 供应链 pin** / **生命周期子命令 cap**） | 25 | R1 ✓ 只 patch 模块级常量（`_DEV_SOURCE_DIRS` / `MANIFESTS`）；R2 ✓ `_clean_active` 夹具副作用显式声明；R3 ✓ define 门禁通过/拦截分用例 |
| `test_gk_bashpy_upgrade.py` | 升级命令（status/check/upgrade/rollback 正向 + 边界） | 11 | R1 ✓ 只 patch 模块边界（`_fetch_json`/`_download_to`/`_cache_dir`）；R3 ✓ 成功/失败分用例 |
| `test_gk_bashpy_upgrade_redteam.py` | 升级模块红队（投毒篡改攻击面 A-E / 防护门禁验证） | 8 | R1 ✓ 只 patch 模块边界；R2 ✓ fixture 副作用声明；R3 ✓ 正向对照/攻击用例分列 |
| `test_red_attacks.py`（TestRedHook R0.4 + TestPluginBareCall 向量） | 调用门禁红队（RED-HOOK-10..15 存在性审计：完整/缺失/不完整三态 + 裸调用攻击向量 17 用例） | 3+17 | R1 ✓ 只 patch `SKILL_DIR`；R2 ✓ 夹具副作用声明；R3 ✓ 完整/缺失/不完整分用例（对齐 §2.3） |

---

## 3. 测试门禁（本地确定性 + CI 双轨）

| 轨 | 载体 | 语义 |
|:--|:--|:--|
| 本地确定性门禁 | `gk_self_check.py` 新增 `check_tests`（run_all 第 13 项） | `python -m pytest scripts/test_*.py -q` 全绿；pytest 缺失/测试失败 → FAIL（测试是硬门禁） |
| CI 样板 | `references/ci-pipeline-template.md` §Python 测试节 | 未来 zthl-harness / 技能仓库 CI 的 pytest job 模板 |

- 测试文件命名 `test_*.py`（`scripts/_*_test.py` 是 gitignore 临时调试区，不得放正式测试）。

---

## 4. DSH 安全事件对照（2026-08-25 扩展）

> **触发**：DeepSeek Harness v0.1 开源（2026-08-13，基于 Cordis 元框架）后 24h 内，
> 社区用户安装第三方插件触发 `rmdir` 递归删除（符号链接转义错误），误删 400G 数据。
> 事件本质：**插件获得超出声明的破坏性能力 + 无能力边界校验**。
> 论文参照：Cordis《A Programming Paradigm for Spatiotemporal Composability》§6.3 Access Control and Sandboxing。

### 4.1 事故模式 → 本协议防护映射

| DSH 400G 事故暴露的缺口 | 本协议对应防护 | 落实位置 |
|:--|:--|:--|
| 插件入口无能力边界（`rmdir` 被透传） | **子命令白名单**（拒绝未知子命令）——插件无法经未登记入口获得能力 | `cmd_migrate`（2026-08-25） |
| 供应链投毒面（恶意/被篡改插件） | **SHA256 pin**（`_RELEASE_PINS`，hash_mismatch 拦截）——永不静默使用哈希不匹配的包 | `gk_bashpy_loader`（2026-08-23） |
| 插件破坏性 shell 权限（符号链接操作） | **探测式定位**（只读分析/验证，不执行破坏性命令） | `cmd_migrate` 定位（batch8） |
| 加载失败静默（漏加载=降级无告警） | **双函数契约**（`load_status()` + `load_*()` 双信号，漏加载必须显式报 finding） | 本协议 §1.2 |

### 4.2 与 Cordis 机制的吸收边界（计划质询 2026-08-25 收敛，2026-08-25 晚修订）

| Cordis 机制 | 是否吸收 | 理由 |
|:--|:--|:--|
| declarative configuration（§5.2.1） | ✅ 吸收 | `_RELEASE_PINS` + `ZTHL_BASHPY_DIR` + `load_status()` 对账 + **manifest 注册表**（`gk_plugin_manifest.py`，对齐 Definition 74 entry 六字段） |
| Access Control and Sandboxing（§6.3） | ✅ 吸收 | 能力白名单（对齐 manifest.intercept 声明）+ 只读探测定位 |
| revertible effects（§3.1 可逆效应） | ✅ 吸收（**write 分级**） | **复刻 DSH 完整循环** `define→run→stop→undefine`：write=false 免逆（f=id）；write=true 必须声明 undo 回滚钩子，否则拒绝加载（Theorem 7 代码级强制，2026-08-25） |
| hot module replacement（§5.2.2） | ❌ 不吸收 | 无热插拔需求 |

> **2026-08-25 晚修订**：上一轮计划质询判定"revertible effects ❌ 不吸收（探测式插件无生命周期）"——
> 用户指出探测式插件恰好是**单位效应**（Theorem 10 的 `𝜂Γ`：`f=id, g=id`）特值，完整循环的
> track/recover 一般化对探测式平凡成立、对可写插件构成防护。因此落地生命周期而非砍掉。

### 4.3 事故演练检查清单（新增插件时逐条核对）

```
□ 插件声明了哪些子命令？（能力边界明确）
□ 每个子命令是只读还是破坏性？（破坏性 → 需更高 gate_level，默认拒绝）
□ 发布产物 SHA256 是否登记 _RELEASE_PINS？（未登记 → release_unverified WARN）
□ 加载失败是否显式报告？（漏加载不静默）
□ dev 源目录是否可控？（ZTHL_BASHPY_DIR 环境变量优先 + 已知路径白名单）
```
- 新增插件加载器时：加载协议文档（§1）+ 测试框架（§2）+ self-check 项三件套同步落地。

### 4.4 DSH 生态插件对接（2026-08-25 实测 v0.1.1-rc.2 源码）

> 事实源：`deepseek-harness-dsh-v0.1.1-rc.2`（`examples/*/cordis.yml`、`apps/cli/src/plugin.ts`、`docs/tool-catalog.md` cordis_* 节、`docs/cookbook/adding-a-tool.md`）。

**DSH 插件机制**：静态 = `cordis.yml` entry `{id, name(包名), config}`（对齐 Definition 74）+ npm 包声明 `dsh.bundle`，`dsh plugin`（pnpm 转发）安装后 `reconcilePlugins` 对账层栈；动态 = cordis_* 自进化循环（inspect_list/query/self → define → run → stop → undefine）。工具注册是 **effect-based**（dispose 插件 fiber 即注销工具 = 可逆效应）。

**对接映射（本协议生命周期 ↔ DSH）**：

| 本协议 | DSH | 语义一致 |
|:--|:--|:--|
| `MANIFESTS` 注册表 | 动态 Plugin 实例 / cordis.yml 声明 | ✓ 同为 entry 声明 |
| `validate_manifest` | `cordis_define`（无副作用声明） | ✓ define 仅校验不执行 |
| `load_plugin`（快照+注入+登记） | `cordis_run`（激活 Package） | ✓ 激活才有副作用 |
| `unload_plugin`（保留登记，回滚+注销 _ACTIVE，幂等） | `cordis_stop`（保留 Plugin/Package/grants，幂等） | ✓ 精确一致 |
| 无运行时 undefine（管理侧删登记） | `cordis_undefine`（永久移除+删指针） | 差异：DSH 支持运行时自进化；本协议登记表是管理方预登记（防御姿态） |
| `list` CLI | `cordis_inspect_*` | 本协议为最小版 |

**安全网对 DSH 插件生效性（实测，`test_gk_plugin_manifest.py` TestDshEcosystemAdapter）**：
- 未登记 DSH 插件（如 `@deepseek-ai/dsh-tool-fs`）→ define 门禁拒绝 ✓
- 登记后可写插件无 `undo` → 拒绝加载（Theorem 7）✓
- 白名单外能力（如 `shell`）→ 拒绝 ✓

**对接缺口（npm 供应链 pin）— 已封（2026-08-25）**：DSH 插件 = npm 包，其供应链保护 = **pnpm lockfile integrity 哈希**；
本协议 `_RELEASE_PINS` 是 Python 包 SHA256 视角。配置 DSH 生态插件时，manifest 须在
`config.integrity` 登记 npm 包 lockfile integrity（引用 pnpm-lock.yaml）；`validate_manifest`
对 `url: npm:` 前缀插件**强制要求 integrity 非空**，缺失即拒绝加载（`TestNpmSupplyChainPin`）。
loader 侧实际哈希校验（npm 包安装后的 integrity 对账）仍按 `url: npm:` 前缀分流——**该执行层留待
首个真实 npm 插件接入时实现**。DSH 自带 sandbox/approval/guard 是其
自身防护层，本协议 isolate=True 标记"需沙箱执行边界"，不重复实现。

---

## 4. 红线

- **禁止 `except Exception: pass` 吞加载错误**——漏/误/错加载必须显式报告。
- **禁止 patch 标准库全局**（importlib/__builtins__ 等）——副作用半径不可控。
- **禁止夹具隐式契约**——副作用必须写进 docstring。
- **禁止断言语义混叠**——可用/不可用两态必须拆用例。
- **发布包哈希未登记 = release_unverified（WARN）**，不得当作 release 使用。

---

## 5. 阻断响应自引导协议（usage / limits / next 三要素，2026-10-06）

> **性质**：本协议 = §1/§2 加载安全网在**人机接口面**的对偶。§1.3 要求「加载失败必须显式报告」；
> 本协议要求「**调用面撞错必须显式自引导**」—— 阻断响应本身就是下一步的唯一入口。
> 缺口（实测 2026-10-06）：阻断响应只报「哪里不合规」，不给「下一步敲什么命令」⟹ 调用面只能靠人
> **记得**先 `help`、**记得**真名。两个现场：① 未知 flag `--plan`（真名 `--plan-file`）**无合法集回显**；
> ② `pipeline_over_wall` 只报墙、不给可执行出口（正解 `gk_route_center.py build-state --plan-file <plan>`）。

### 5.1 三要素（阻断响应必带，缺一不可）

| 要素 | 语义 | 纪律 |
|:--|:--|:--|
| `usage` | 该入口的**唯一调用公式** | 与实现内既有 usage 单一事实源**同源**（禁第二份文案、禁手抄） |
| `limits` | 触发的**上限真值** | **运行时取**（import 常量 / 读模块级值）；**禁**在文案里硬编码字面量（复制即第二事实源） |
| `next` | **可执行**的下一步（允许多条备选路径） | 所列命令必须**逐字存在于本仓**（落刀前逐条 `help <cmd>` 回源），**禁**编造 |

### 5.2 适用范围（三类阻断面）

- **调用形态错误** —— 未知子命令 / 未知 flag / 缺值 / 位置参数过多 ⟹ 回显该子命令**真实** `allowed`
  flag 集（单一登记点，禁与解析循环漂移）+ `usage` + `next`（指向 `help <cmd>`）。
- **资源墙** —— 长度上限 / 队列字节上限 / 总量墙 ⟹ 回显 `limits` 真值 + **消解出口**
  （消解既有 pending / 归档 / 按范式改写），禁「只报墙不给路」。
- **加载安全网拦截** —— §1.3 各 source（`missing` / `hash_mismatch` / `error`）⟹ 附**正确调用方式**
  与 `next`，使「被拦」同时是「被指路」。

### 5.3 加性纪律（零回归）

- 新字段**纯加性**：既有键 / 判据 / 返回码逐字不变，旧消费者忽略新字段。
- `next` 未触发时**留空**（零噪声）—— 只有真阻断才注入自引导。
- `next` 的**唯一事实源** = 该命令自身的 `help` / usage 通道，禁在响应文案里另写一份命令清单
  （否则清单与注册表两处漂移）。
- 判据（可机检）：阻断臂断言 `next` 非空且所列命令可回源；守卫臂断言 `limits` 与运行时常量**逐字相等**
  （防未来写死）。

---

## 平滑升级命令（2026-08-26）

`scripts/gk_bashpy_upgrade.py` — bashpy-migrate 插件平滑升级（skill 侧主要用户；DSH 预览仅测试）。

| 子命令 | 行为 | 网络 |
|:--|:--|:--|
| `status` | 当前加载状态 + `_RELEASE_PINS` 登记清单 + last-check 缓存 | 无（离线） |
| `check` | 查 GitHub `releases/latest` → 对比登记最高版本 → 写 last-check 缓存 | 有 |
| `upgrade` | 下载 → wheel `audit.py` sha256 + tarball sha512 双对账 → 备份 → 替换配置 | 有 |
| `rollback` | 恢复最近一次升级前备份（loader + manifest） | 无 |

安全网约束：对账失败拒绝升级且配置零改动；`_RELEASE_PINS` 累积登记不删旧条目（降级链不被破坏）；替换原子 + 备份可回滚。

启动前检测：`load_status()` 追加只读字段 `latest_known` / `upgrade_pending` / `pin_status`（读 `~/.cache/gk-bashpy/last-check.json`，加载决策逻辑零改动，向后兼容）；`cmd_migrate` 安全网段消费 `upgrade_pending` 打 WARN。

---

## 插件红队测试模板（2026-08-26，R0.4 攻击面 F 扩展 2026-08-27）

> 升级/网络类插件的供应链防护必须以**攻击者视角**验证——正向测试证明"功能可用"，红队测试证明"投毒进不来"。
> 调用门禁（R0.4）同样必须以攻击者视角验证——统一入口证明"走正路可用"，红队证明"旁路进不去"。
> 参考实现：`scripts/test_gk_bashpy_upgrade_redteam.py`（8 用例，攻击面 A-E 供应链）+ `scripts/_red_attacks.py` `red_hook`（RED-HOOK-10..15，攻击面 F 调用门禁）。

### 攻击面分级 → 防护门禁

| 攻击面 | 级别 | 投毒篡改场景 | 防护门禁 |
|:--|:--|:--|:--|
| **A wheel self-certification** | Critical | MITM 投毒 wheel——audit.py 哈希自证（自己算自己），无第三方比对源 | CI 发布 `wheel-integrity.json`（官方 wheel sha256），upgrade 下载后比对，不符拒绝 |
| **B 备份完整性** | High | 篡改 `backups/<ts>/` 文件 → rollback 恢复投毒配置 | `backup-manifest.json`（文件→sha256）随备份写入；rollback 前逐文件校验，缺失/不符拒绝 |
| **C 注入** | Medium | 恶意 version/integrity 字符串绕过正则替换（代码注入面） | semver 白名单（`\d+\.\d+\.\d+`）+ sha512-128hex 白名单，非法拒绝 |
| **D 缓存投毒** | Medium | last-check.json 非字符串 `latest_version` → `_semver_key` 崩溃 / upgrade_pending 误报 | `_semver_key` isinstance 防御 + latest 非 str 归一化 None（静默） |
| **E 失败残留** | Low | 对账失败后 `downloads/` 残留投毒文件污染下次升级 | 失败路径清理 downloads（`shutil.rmtree(ignore_errors=True)`） |
| **F 调用门禁旁路** | Critical | 裸调用 bashpy-migrate / `python3 -m` / `python3 -c` / `eval` 内嵌 / 升级脚本绕过统一入口——manifest cap 白名单 + 加载安全网哈希对账全部跳过 | Gate R0.4（pre_tool_hook）：按命令段（`;`/`&&`/`|`）逐段判定 + 引号上下文（`_in_quotes` 防 commit message 误拦）+ 统一入口豁免（`gatekeeper-cli.sh migrate`）；`_red_attacks.red_hook` RED-HOOK-10..15 存在性审计 |

### 统一调用命令契约（2026-08-27）

插件操作**全部**经 `cmd_migrate`（`gatekeeper-cli.sh migrate`）单一入口，禁止旁路：

| 类别 | 子命令 | 入口 |
|:--|:--|:--|
| 执行类 | `analyze` / `verify` / `audit` | `migrate <sub>` → 插件本体（探测链 + loader 安全网） |
| 生命周期类 | `status` / `check` / `upgrade` / `rollback` | `migrate <sub>` → 转发 `gk_bashpy_upgrade.py`（manifest cap 已扩展，R0.4 拦裸 python 调用） |

禁止形态（R0.4 拦截）：直接 `bashpy-migrate`、`python3 -m zthl_bashpy_migrate`、`python3 -c "import zthl_bashpy_migrate"`、
`eval "bashpy-migrate ..."`、`python scripts/gk_bashpy_upgrade.py ...`（含分号/管道拼接段、bash -c 内嵌）。

### 模板骨架（攻击者视角用例）

```python
# 攻击面 A：投毒 wheel 必须被官方清单拒绝（self-certification 漏洞验证）
def test_poisoned_wheel_rejected_by_official_manifest(self, tmp_path):
    clean = _make_wheel(tmp_path, audit_content="CLEAN")
    poisoned = _make_wheel(tmp_path, name="p.whl", audit_content="EVIL")
    wint = {"wheel": clean.name, "sha256": sha256(clean)}   # 官方清单指 clean
    # mock 下载：whl=poisoned, wheel-integrity.json=wint
    out = gbu.cmd_upgrade()
    assert out["ok"] is False          # 投毒 wheel 被拒
    assert config_unchanged            # 配置零改动

# 攻击面 B：篡改备份必须被 manifest 校验拒绝
def test_tampered_backup_rejected_on_rollback(self, tmp_path):
    # 备份文件注入 "# POISONED"，manifest 记录原始哈希
    out = gbu.cmd_rollback()
    assert out["ok"] is False          # 投毒备份被拒
    assert config_unchanged            # 不恢复投毒内容

# 攻击面 F：裸调用必须被 hook 拦截（统一入口旁路验证）
# 参考实现：scripts/test_pre_tool_hook.py TestPluginBareCall（攻击向量 17 用例）
def test_bare_call_blocked(self):
    for evil in (
        "bashpy-migrate audit --bomb",                       # 直接 CLI
        "C:/.../Scripts/bashpy-migrate.exe verify",          # Windows 路径
        "python3 -m zthl_bashpy_migrate.cli audit",          # 模块入口
        'python3 -c "import zthl_bashpy_migrate"',           # -c 内 import
        'eval "bashpy-migrate audit"',                        # eval 内嵌执行
        "gatekeeper-cli.sh migrate; bashpy-migrate audit",   # 分号拼接段
        "python3 scripts/gk_bashpy_upgrade.py upgrade",      # 升级脚本裸调用
    ):
        assert pre_tool_hook._plugin_bare_call(evil) is not None, evil

def test_unified_entry_allowed(self):
    # 统一入口豁免（执行 + 生命周期子命令）
    for good in ("bash gatekeeper-cli.sh migrate audit --bomb",
                 "bash gatekeeper-cli.sh migrate upgrade"):
        assert pre_tool_hook._plugin_bare_call(good) is None, good

def test_quoted_text_not_blocked(self):
    # 引号内文字引用（commit message）不误拦
    assert pre_tool_hook._plugin_bare_call(
        'git commit -m "R0.4: bashpy-migrate 裸调用拦截"') is None
```

### 门禁原则

- **校验先于写入**：所有对账/校验发生在配置写入之前——拒绝路径配置零改动（测试必须断言）。
- **红队测试是硬门禁**：`test_*_redteam.py` 全绿才允许合并；新增网络/下载/备份逻辑时必须配套红队用例。
- **不篡改红队测试**：防护实现要适配测试断言（测试是验收标准），禁止为转绿削弱断言。
- **威胁模型边界**：wheel-integrity.json 与 wheel 同源（均下载自 GitHub Release，HTTPS 传输）；本地 MITM 无法篡改，完整投毒需控制 Release 本体——超出单资产防护能力，属可接受残留（在测试 docstring 标注）。

---

## 插件双循环衔接（2026-08-26，ECO 质询收敛）

> 本框架是**循环 A（插件生命周期维护循环）**的核心产出——加载/运行时安全网协议、平滑升级机制、测试模板、CI 模板、文档。
> 循环 B（插件任务执行循环）消费本框架维护的基础设施。二者经「发版 → 循环 A 登记 → 循环 B 生效」流转（无热插拔，重启生效）。

| 循环 | 引擎 | 驱动 | 产出/行为 | 消费本框架的什么 |
|:--|:--|:--|:--|:--|
| **A 生命周期维护** | standing（ECO-RESEARCH→ECO-EDIT→ECO-VERIFY→ECO-DOC；2026-10-28 A4 4 站口径） | release-check 发版信号 / 新插件接入 / 安全事件 / 红队 finding | 安全网协议、升级命令、测试模板、CI 模板、文档（本文件 + ci-pipeline-template §3.6） | —（本框架即其产出） |
| **B 任务执行** | standard（cmd_migrate） | 迁移任务调用 | 插件执行 analyze/verify/audit + 生命周期 status/check/upgrade/rollback（2026-08-27 统一入口）→ 确定性输出 | `load_status()` 安全网、manifest 门禁、cap 白名单、**hook R0.4 调用门禁**（pre_tool_hook 拦截裸调用） |

**测试模板归属**：本文件 §2 导入测试框架 + §插件红队测试模板 = 循环 A 的测试模板维护产物；
循环 B 的每次任务执行走 cmd_migrate 三连门禁（cap → validate → load_status），不直接触碰测试层。
**hook 层归属（2026-08-27）**：R0.4 是循环 B 的入口强制层——IDE 侧 hook 拦截一切裸调用（含 eval/bash -c 内嵌/升级脚本），
统一入口 cmd_migrate 豁免；`_red_attacks.red_hook` RED-HOOK-10..15 在循环 A 的 ECO-AUDIT/RED-* 阶段审计该入口完整性。
新增插件（未来）时：在 `.gatekeeper.scopes.json` 登记 + release-check 加条目 + 本文件 §2.5 登记表加行 + manifest intercept 登记子命令 —— 循环 A 全流程。

---

## 三面一致性闸（2026-10-06；finding `ECC-CA582C23D36A`，root_key = `plan-family-arm-tri-consistency`）

> **性质**：技能仓库基础设施闸（target_repo=skill）。沉淀 `anchor-verdict` 计划连续两轮 6/6 BLOCKED
> 的复盘 —— 同一语义在「**① 计划文本 / ② 族派发契约 `narrow_task_template` / ③ 红先臂
> `references/red-arm-templates.json::finding_arms`**」三处分裂（病型 = PW-SN 的 A2 修复即改写 +
> A3 单侧 red-first）。载正本 = `docs/plans/2026-10-06-tri-consistency-gate-plan.md`。

**机检落刀点**：`scripts/gk_tri_consistency.py`（三函数 + `check` 子命令）。判据见
`scripts/test_tri_consistency_gate.py`（arm_a/arm_b/arm_c/arm_d）。

| 面 | 规则 | 判据 |
|:--|:--|:--|
| **写面枚举单源** | `enumerate_write_surfaces(src="scripts/gk_finding.py")` | AST 求 `save_findings(` 的**传递可达闭包**（含经 `amend_title` 间接落刀的 `amend_anchors`），**排除**入口 `main`；计划写面表与族 `allowed_paths` 均须与之一致（禁手抄回潮） |
| **族自洽** | `check_family(path)` | R1 `test_first` 的文件存在；R2 `affected_tests` 各项文件存在；R3 `edit_quota ≥ len(allowed_paths)`。合法夹具 PASS、矛盾 FAIL（差异臂，既防过度收紧也防放水） |
| **verdict 值域** | `check_verdict_domain()` | 判决器返回值域 ⊆ `gk_ecc_review._VERDICT_ORDER ∪ _VERDICT_EXTRA`（显式登记例外）；缺口须为空 |

**verdict 值域登记**：`gk_ecc_review._VERDICT_ORDER` **加性**追加 `"ok"`（不改既有值的相对顺序、
不改任何判决逻辑）；新增判决须先在本登记点登记，否则 `check_verdict_domain()` 回非空缺口。

**plan-lint 最小接线**（`scripts/gk_plan_lint.py::lint()` 末尾、去重之前）：受开关
`GK_TRI_CONSISTENCY` 控制（默认 `1`；`0` ⟹ 跳过本闸）。正常情况（`check_verdict_domain()` 返回 `[]`）
⟹ 零 finding、输出逐字不变；**加性调用**，不改任何既有判据与 `main()` 输出格式，可单独关（回退面）。

- **开关**：`GK_TRI_CONSISTENCY`（默认 `1` = 启用；`0` = 跳过三面闸，不阻断）。
- **排除面**：不追求计划**散文语义**对齐（不可机检，留 R 侧）；写面枚举本批**只**覆盖 `gk_finding`
  （旁路 `gk_state_patch` / `gk_discover_carry` 另立项）。
