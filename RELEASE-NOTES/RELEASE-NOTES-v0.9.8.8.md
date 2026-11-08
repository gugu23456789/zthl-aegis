# ZTHL Aegis v0.9.8.8 — 发布说明

> 2026-11-08。本版在 v0.9.8.7 之上补三件事：① 把 408 并发公式明确标注为**特定系统环境配置下的
> 工程妥协**（普遍性未经跨环境验证）；② GPU 面最小接线（显存遥测 + 显存闸 + embedding 设备回落）；
> ③ accept 启动前**防爆硬闸**。功能行为不变，默认路径（f=0/CPU embedding）逐位不变。

## 1. 公式的定位更正（重要）

v0.9.8.7 已落地 408 校正式。本版在代码 docstring 与本文档中明确其证据边界：

- 式中全部系数（×2 I/O 超订、`r=C//4`、`max(1,f)`、8 令牌、80 进程预算、`180+60f` RSS）
  都来自**本机 WSL 5 核 / 5GB + 重活四文件**的实测与量纲推演；
- 它是**特定系统环境配置下的工程妥协**，**不是跨环境定律**；换核数 / 换 OS / 换负载构成
  （纯 CPU-bound、编译、GPU 推理）都必须重新取证；
- 16 核宿主的 f=1..3 → 8 只是**纸面推演**，本机未在 16 核实跑，不得当作已验证结论引用。

## 2. 变更

| 文件 | 变更 |
|:--|:--|
| `scripts/gk_hub_scheduler.py` | ① 公式分支补「空闲内存 < `min_free_mb` ⟹ 压到 1」的防爆下限；② 新增 `gpu_info()`（`nvidia-smi` CSV 只读遥测，失败 None）、`min_free_vram_mb()`（`GK_HUB_MIN_FREE_VRAM_MB`，默认 1024）、`gpu_admit()`（无 GPU/低显存 `ok:false`，fail-closed）；③ `status()` 增 `gpu` / `min_free_vram_mb` 字段 |
| `scripts/_accept_cli.sh` | 启动前防爆硬闸：`ACCEPT_MIN_FREE_MB`（默认 800）以下 **fail-loud exit 2**（`0` 关闭；读数失败不拦，fail-safe） |
| `scripts/gk_gitnexus.py` | `analyze*` 默认仍钉 `cpu`（沙箱驱动触碰面不变）；显式请求 `dml/cuda/gpu/webgpu` 时先过 `gpu_admit()`，不满足即回落 `cpu` 并置 `GK_GITNEXUS_GPU_FALLBACK=<reason>` |
| `scripts/test_gk_hub_scheduler.py` | 新增公式内存下限臂 + GPU 遥测/显存闸/status 共 7 臂 |
| `scripts/test_gk_accept_cli.py` | 新增防爆硬闸机检臂 |
| `scripts/test_gk_gitnexus_launcher.py` | 新增 GPU 回落 4 臂（默认 cpu 路径**零 GPU 探测**、低显存回落、显存充足保留、非 analyze 不设设备） |

## 3. 验证（含可复现数字）

- 工作树定向：`test_gk_hub_scheduler.py` + `test_gk_accept_cli.py` + `test_gk_gitnexus_launcher.py`
  新增臂 **12 passed**（hub 7 + accept 1 + gitnexus 4）；`bash -n _accept_cli.sh` / `py_compile` 均通过。
- 实机 GPU 读数（Windows venv 与 WSL 两侧一致）：
  `NVIDIA GeForce RTX 4060 Laptop GPU, total=8188MB, free=7956MB`；`gpu_admit()` → `ok:true`。
- 公式实机读数（WSL C=5 / free≈4.5GB）：`f=0→4`（旧口径 ×2=8）、`f=1→8`、`f=2→4`、`f=3→2`。
- accept 默认 `f=1` ⟹ `JOBS=8`（与 v0.9.8.6 之前默认一致，无退化）。
- 存量：`test_gk_gitnexus_launcher.py` 有 5 条**非本次引入**的存量失败（`D:\Program Files` 等
  文案命中源码扫描臂），master 同红，已隔离归因。

## 4. GPU 面的诚实边界

- **GPU 不能加速 pytest/accept**：6393 用例是 CPython 解释执行 + 进程孵化，无可 offload kernel
  （`docs/analysis/2026-11-03-accept-bottleneck-forensics.md` §3）。
- GPU 的真实落点是 **embedding / 本地决策模型 / 批量推理**。本版只做最小接线：
  遥测 + 显存闸 + 设备回落，把「显式用 GPU」从「可能 OOM」变成「先过闸、不可用即退回 CPU」。
- 默认仍 `cpu`：沙箱里 ONNX `auto` 会探 CUDA/DML ⟹ 触碰 NVIDIA 驱动 ⟹ 被判 restricted（F-REV-88）。

## 5. 明确未做

- **运行期看门狗**（idle>180s / free<800MB / 45min → `taskkill /T /F`）未做：需要 PowerShell
  侧进程树击杀，跨平台语义与误杀风险都需单独设计；本版只有**启动前**硬闸 + 并发上限。
- `ACCEPT_JOBS` 显式覆盖仍**完全绕过公式**（按设计属紧急逃生舱，刻意保留）；`explicit` 模式
  不取跨会话 flock（2026-10-29 既有裁定）。
- 16 核宿主的公式实测、档3 分布实测、GPU embedding 的 A/B 吞吐对比均未做（无实测不宣称收益）。

## 6. 与 v0.9.8.6 / v0.9.8.7 的关系

v0.9.8.6 = 门禁漏洞 + 测试长尾修复；v0.9.8.7 = 408 公式首版实机校正；
v0.9.8.8 = 定位更正 + GPU/防爆最小接线。对外建议直接使用 v0.9.8.8。
