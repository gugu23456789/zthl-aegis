# WASM 工程标准模板（通用）

> **性质**：纯工程样板，适用于需要浏览器端 WASM 交付的 C++ 项目（转换/验证/审计类）。
> **参考实现**：spz2glb（origin，v2.0.5）、spz_gatekeeper（R7 移植）。
> **原则**：安全优先（串行语义）> 性能（零拷贝）> 可观测（分段计时）。

---

## 0. 适用与不适用边界

> 模板的核心模型是 **WASM 单实例 + 全局预留输入缓冲 + 串行处理**。选择本模板前先对照边界：

| ✅ 适用（本模板覆盖） | ❌ 不适用（模板边界外，需另行设计） |
|:--|:--|
| 单输入 → 单输出：文件转换、格式验证、审计 | 渲染类（连续帧循环，非请求-响应） |
| 请求-响应式浏览器调用 | 真并发多实例（模板强制串行，见 [ASSUMPTION-1]） |
| 大文件（需分块写入 + 零拷贝） | 流式处理（SOG 多 LOD 分块拉取） |
| 需要性能可观测性（面板/计时） | 长驻 WASM worker（生命周期非请求绑定） |

## 0.5 资源面统一（多模块共存时强制）

> **背景**：QR 全链路分发场景下，浏览器可能同时加载多个 WASM 模块（如验证 + 转换）。多模块共存时**必须统一资源面**，否则浏览器资源测算不可控（总峰值无法建模）。**绑定层可不同**（embind 对象语义 vs C API 字节流是合理分工）；**资源面必须一致**：

| 资源维度 | 统一要求 | 参考实现 |
|:--|:--|:--|
| 内存模型 | 统一 `MAXIMUM_MEMORY`（spz 系 = 512MB） | 双项目 |
| 输入上限 | 统一"双层口径"：推荐值走**设备分档**（SmartMemoryManager）+ WASM 层**安全硬顶**（数值按项目安全需求） | 双项目 |
| 队列语义 | 统一 `MAX_PARALLEL=1` 串行（排队等待不计时）；实现 = **计数器 + `while (count < MAX && 待启动数 > 0)`**，**禁用布尔闩**；并发常量单一来源（spz2glb `MAX_PARALLEL` / gatekeeper `kQueueMax`） | ✅ 双项目（gatekeeper R7_1g 已收敛 + 机制对齐） |

> 合并单 WASM 模块**不做**（两项目独立演进，合并耦合发布/依赖/权限，不可维护）——统一资源面即可实现可加性资源测算。

## 1. 分层组件清单

> 标注：`[ASSUMPTION]` = 硬假设（见 §6）；`(可配置)` = 项目按需取值。

| 层 | 组件 | 实现点 | 出处 |
|:--|:--|:--|:--|
| **构建** | Emscripten + CMake | `-Oz` 优化；**禁用 `--closure 1`**（曾致运行时初始化失败）；多档构建 profile（如 `compat`/`perf-lite`） | 双项目 |
| **C API** | 预留输入缓冲 | 契约（两参考实现不同）：spz2glb 四函数 `reserve_input`/`get_input_ptr`/`convert_reserved_input`/`release_output`；gatekeeper 八函数 `gk_*`（含 `gk_get_buffer_used`/`gk_set_buffer_used` 已用字节跟踪）。输入为全局单例 → **必须串行化** [ASSUMPTION-1] | 双项目 |
| **C API** | ABI 自检 | 启动断言（size_t 宽度、stats 结构尺寸），防 ABI 漂移；stats 字段数 `(可配置)`，默认 9 | spz2glb |
| **C API** | 输入硬上限 | `(可配置)` 两种参考模式：spz2glb=SmartMemoryManager **设备分档**（`hardMaxFileSize` 按 tier，high 默认 64MB，`MAXIMUM_MEMORY` 512MB）；gatekeeper=固定 **30MB**（`kMaxSpzBytes`）。前端 + WASM 双层防线 | 双项目 |
| **内存** | HotObjectPool | 预分配 slot，O(1) alloc/dealloc（结果对象）；池大小 `(可配置)` | memory_pool.h |
| **内存** | BumpAllocator | 一次性大块（64KB `(可配置)`）工作区，reset O(1) 回收 | memory_pool.h |
| **内存** | MemoryTracker | 峰值/当前内存、分配/释放/失败计数、工作区统计 | memory_pool.h |
| **绑定** | 零拷贝输出句柄 | `getBytesView()`（WASM 堆字节视图）/ `toBlob()` / `release()` 生命周期契约；消除 JS 大对象拷贝（曾消除 26.6MB，Major-GC 抖动根因） | spz2glb |
| **前端** | 设备感知内存管理 | 设备分档（mobile/desktop）、推荐文件上限、WASM 内存配置注入 | smart_memory_manager.js |
| **前端** | 串行队列 | 统一 `MAX_PARALLEL=1` 串行语义（WASM 单实例，排队等待**不计入处理计时**，计时器须在"开始处理"处起算）；实现 = **计数器（`processing` / `queueRunning`）+ `while (count < MAX && 待启动数 > 0)`**，每启动一项 `await` 一个 `setTimeout(0)`（**宏任务**；spz2glb 源码注释写作"微任务"属术语误标，语义是让出执行权）让队列状态刷新 —— **禁用布尔闩**：闩在任何时刻至多 1 项，常量 >1 时无法扩展，即"**假并发**"（gatekeeper R7 原实现的教训：`kQueueMax=2` 声明值从未生效）。常量命名：spz2glb `MAX_PARALLEL`、gatekeeper `kQueueMax`；载体均为 index.html 内联队列（模块侧的 `BatchQueue` 类只作导出契约面，非前端消费路径）[ASSUMPTION-1] | 双项目 |
| **前端** | 格式魔数预检 | 读文件头嗅探格式（如 gzip `1F8B` / 自定义魔数），错误 fail-fast；**勿**用 WASM 全量校验做预检（需解压，会误拒） | spz2glb |
| **前端** | 分块写入 | 大文件分块（64KB/1MB `(可配置)`）写入预留缓冲，防整块拷贝内存峰值 | 双项目 |
| **前端** | 性能面板 | 版本/构建时间/加载时间戳/处理耗时/JS 开销/**分段计时**/内存统计/池/工作区/推荐上限；行数 `(可配置)` | spz2glb |
| **前端** | i18n + 主题 | 多语言切换 + 日夜主题（CSS 变量） | spz2glb |

## 2. 绑定层选择判据

| 场景 | 选 embind | 选 C API + 纯 JS 绑定（推荐） |
|:--|:--|:--|
| 对象/异常/多返回（如 inspect 报告对象） | ✅ 直接映射 JS 对象 | 需手动序列化 |
| 纯字节流输入输出（转换/验证） | 可，但绕一层 | ✅ 零拷贝句柄直达 |
| 性能敏感（大文件高频） | ⚠️ vector 拷贝开销 | ✅ 预留缓冲 + 零拷贝 |
| 导出符号白名单控制 | 弱（embind 自动导出） | ✅ `EXPORTED_FUNCTIONS` 显式 |
| 参考实现 | gatekeeper（wasm_main.cc） | spz2glb（spz2glb_bindings.js） |

## 3. 分段计时口径（可观测性核心）

```
wasm_core_ms     = WASM 侧全流程（解压/解析/校验）
wasm_tojson_ms   = 报告序列化
wasm_js_parse_ms = JS 端 JSON 回灌
wasm_total_ms    = 总计
```
前端分列 `coreMs`（WASM 处理）vs `totalMs`（端到端含 JS），差值 = JS 开销——**口径必须分开，禁止混报**。

## 4. 集成步骤

1. CMake 加 WASM 目标（`-DEMSCRIPTEN` 分支），导出 C API（`EXPORTED_FUNCTIONS` 白名单）
2. 绑定层按 §2 判据选择（默认 C API + JS 绑定）
3. 前端链路：设备内存管理 → 串行队列 → 魔数预检 → 处理 → 面板刷新
4. 版本同步：CMake → CLI banner → WASM 报告 → 前端面板（多处同步 + CI `fetch-depth:0` 拿 tag 派生版本）

## 5. 组件裁剪关系（回退路径）

| 裁剪场景 | 可移除 | 保留（依赖方） |
|:--|:--|:--|
| 不需要性能面板 | 面板/分段计时展示 | 计时采集（面板依赖） |
| 不需要内存跟踪 | MemoryTracker | —（HotObjectPool/BumpAllocator 可独立） |
| 不需要设备分档 | SmartMemoryManager | 文件上限检查改常量 |
| 小文件（<1MB） | 分块写入 | 预留缓冲（零拷贝仍有效） |
| 不需要零拷贝 | 输出句柄 → 直接 HEAPU8 拷贝 | **代价**：JS 大对象 → Major-GC 抖动（见红线） |

> 规则：**预留缓冲 + 串行队列是核心契约，不可裁剪**；其余均可按上述依赖关系裁剪。

## 6. 假设清单

| # | 假设 | 失效场景 | 变更方法 |
|:--|:--|:--|:--|
| [ASSUMPTION-1] | WASM 处理全局单实例（预留缓冲单例 + 互斥） | 需要真并发多实例 | 每实例独立缓冲 + 非全局状态（重设计，超模板范围） |
| [ASSUMPTION-2] | stats 结构字段数可被 ABI 断言校验（默认 9 字段） | 项目 stats 结构不同 | 调整 `sizeof_*` 断言常量（同步 JS 解析） |
| [ASSUMPTION-3] | 输入有硬上限（默认 30MB `(可配置)`） | 无上限的流式输入 | 不适用本模板（见 §0） |

## 7. 验证

- 构建后预检脚本 P0-P7：环境/构建/导出符号/产物尺寸/前端一致/工作流/文件完整性（UTF-8 + 语法）
- `wasm-objdump -x`：Import/Export/Memory 段分析
- 浏览器 smoke：glue 加载 + 真实处理（多浏览器）
- 哈希矩阵：每夹具 5 采样 min/median/max/σ + 全链打包计时（见 CI 模板）

## 8. 运行时完整性（自动拦截防线）

三层防线——**加载前校验 → 预检 fail-fast → 处理期防护**。失败语义统一为 **fail-closed**（校验失败 = 拒绝加载/处理，不做"容忍继续"）。

### 8.1 加载前：WASM 指纹校验（防缓存投毒）

> **参考实现（已落地）**：gatekeeper R7_1b（commit 1582e85）+ R7_1c CI 回环 + R7_1d 红队 fail-closed 收敛。

**信任根 —— 内嵌 `index.html`**：`<meta name="spz-wasm-fp" content="__WASM_FP__">`，构建时替换为 wasm 产物 SHA-384。
- 内嵌而非独立 JSON 请求：避免"信任根本身可被替换"的 TOCTOU 与额外 fetch（**D5** —— 信任根与页面同源同份）
- 独立 `wasm-fingerprint.json` 仅作**审计辅助**（多产物哈希明细），**不是**校验依据

**校验流程**（loader 函数，如 `maybeLoadRuntime`）：
1. `fetch('*.wasm', { cache: 'no-store' })` 取字节（绕过 HTTP 缓存）
2. 读 meta 信任根；存在 → `crypto.subtle.digest('SHA-384', bytes)` → hex 比对
3. 一致 → **`wasmBinary` 字节直传 glue**（顺带消除 glue 的二次 fetch）；不一致 → **拒绝实例化**
4. 无信任根（开发/静态预览）→ 跳过强制校验但仍直传字节；返回 `null` 走**显式降级**（不静默），UI 侧标注降级来源

**算法**：**SHA-384**（96 hex）；比 sha256 长，发布断言可用定长正则 `[0-9a-f]\{96\}` 做形态检查。

**fail-closed 三态**（R7_1d 红队收敛 —— 三个 fail-open 向量全部封堵）：

| 向量 | 旧行为（fail-open） | 现行为（fail-closed） |
|:--|:--|:--|
| 信任根存在但探测 fetch 失败 | 静默放行 glue 自带 fetch → 可能实例化缓存 wasm | 拒绝加载（`probe_fetch_failed`） |
| `crypto.subtle` 不可用（http 非安全上下文） | 以 "SHA-384 unavailable" 名义放行未校验 wasm | 拒绝加载（`sha384_unavailable`，提示需 HTTPS 安全上下文） |
| 硬性完整性失败 | 仍重试 | 不重试，直接拒绝 |

每次裁决写 `window.__spzWasmVerdict = { ok, reason, expected, actual }`，供 UI / 测试断言消费。

**cache-busting 链（与指纹互补，非替代）**：
- 分工：cache-busting 防**旧缓存**，指纹防**篡改**——ChainDrop 2026-08-04 教训：来源证明 ≠ 可信，必须字节级校验
- 链完整性：`index.html` → `spz_gatekeeper.js` → glue(`.js`) → `.wasm` 四处引用**必须**带版本参数
- **内容寻址**：`?v=W<fp8>`；静态构建替换 `__FP__`，动态运行时缺省 `Date.now()` 兜底——STATIC/DYNAMIC 共用同一占位符，避免两套语义漂移
- 发布态 `index.html` **零残留占位符**（CI 断言 `grep -qE '__WASM_FP__|__FP__'` → fail-closed）

- 定位：SRI 的 loader 级扩展（SRI 是 HTML 标签级；本模板在 loader + 运行时）

### 8.2 预检 fail-fast

- 格式魔数预检（JS 读头，勿用 WASM 全量校验）——错误立即拒绝，不触发解压
- 输入上限双层防线（前端设备分档 + WASM 硬顶）——超限拒绝

### 8.3 处理期防护

- ABI 启动断言（size_t 宽度、stats 结构）——防 ABI 漂移
- 分段计时可观测（处理异常可定位，见 §3）
- 串行锁（并发交错写坏 → 拒绝并发，[ASSUMPTION-1]）

## 9. 红线（历史教训）

- `--closure 1` → 运行时初始化失败（禁用）
- WASM 输入缓冲单例 → 并发交错写坏数据（必须串行锁）
- 魔数预检用 JS 读头，**勿**用 WASM 全量校验（误拒）
- JS 大对象拷贝 → Major-GC 抖动 ±20%（零拷贝消除）
- ABI 漂移 → 启动时 `sizeof_*` 断言
- worktree 用 WSL git 创建 → gitdir `/mnt/c` 路径 Windows 侧 prunable（用 Windows git）
