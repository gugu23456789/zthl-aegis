#!/bin/bash
# _accept_cli.sh — 验收一键器（2026-09-23；用户裁定「基线 + 一键脚本」）
# =============================================================================
# 痛点（实测）：`scripts/` 全量回归 **12.7 min**，而每次验收都要重跑一遍**同一批已知失败**
#   （WSL-python 路径形态 / hook 配置 / env 类；2026-09-23 基线 = 22 failed + 7 errors）。
# 机理：把已知失败固化成**逐用例名**基线（`_accept_baseline.txt`），此后只跑**受影响子集**
#   并与基线 diff ⟹ 只报 `NEW`（新增失败 = 真回归）与 `FIXED`（基线里的已修好）。
#   全量（`--full`）只在基线可能变化时跑，且走 `-n auto` 并行（pytest-xdist）。
# ⚠ 基线**绑定解释器**（同一批测试在 Windows-python 下语义不同）⟹ 换解释器须重跑 `--snapshot`。
#
# Usage:
#   bash scripts/_accept_cli.sh <file.py> ...    # ★快循环：显式指定改动面（秒级~数十秒）
#   bash scripts/_accept_cli.sh --changed         # ★按 git 改动**自动**选面（默认 vs HEAD）
#   bash scripts/_accept_cli.sh --changed --rev <rev>  # 与指定 rev 比较
#   bash scripts/_accept_cli.sh                  # 收口：CLI 面子集（⚠ 实测该面 ≈ 全量，走并行约 6 min）
#   bash scripts/_accept_cli.sh --full           # 全量 scripts/
#   bash scripts/_accept_cli.sh --snapshot       # 用「当前跑出的失败集」**重建**基线（须全量口径）
#   bash scripts/_accept_cli.sh --baseline <f>   # 改用指定基线文件（自测用）
# Env: ACCEPT_PY（缺省见 `gk_accept_py.py` 单源：env → scripts/_accept_py.local → python3）、
#      ACCEPT_JOBS（默认 auto；设 0 关并行）、ACCEPT_BASELINE、
#      ACCEPT_SUBPROC_FACTOR（每用例峰值外部子进程数 f，默认 1；0 ⟹ 退回旧口径 nproc×2）、
#      ACCEPT_MIN_FREE_MB（启动前防爆硬闸，默认 800；0 ⟹ 关闭）、
#      ACCEPT_WATCHDOG（运行期最小看门狗，默认 1；0 ⟹ 关闭）、
#      ACCEPT_WATCHDOG_WALL_S（墙钟闸，默认 2700）、ACCEPT_WATCHDOG_IDLE_S（日志空闲闸，默认 180）、
#      ACCEPT_LOCK_FILE（--full 跨会话互斥锁，默认 /tmp/gk-accept-full.lock）、ACCEPT_LOCK_WAIT（默认 600s）、
#      ACCEPT_REUSE_TTL（复用新鲜全量结果的 TTL，默认 1800s；设 0 关复用）——见 ECC-34EEC2BC12D2
#
# 四档速度（2026-09-23 实测，4 核）：显式改动面 = 秒级；CLI 面子集/全量（-n auto）= ~6 min；串行 = 12.7 min。
# 日常改一个面 → `--changed`（自动）或传显式文件；收口/跨面改动 → 默认或 --full。
# 2026-10-29 实测（5 核，全量口径）：并行段 1166s + 串行段 508s ≈ 28 min（会话内有并发负载）；
#   其中串行段 508s 与「同两条臂单独跑 73s」不符 ⟹ 见下方 SERIAL 段注释的待查项。
#
# Exit: 0 = 无新增失败；1 = **有新增失败**（真回归）；2 = 环境/参数错误。
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 2026-11-03（M1 收尾）：全量复用戳加**工作树指纹**。
#   原戳 = HEAD + 基线指纹 ⟹ 脏树改了 `scripts/*.py` 仍命中旧戳，把旧结果当新结果（危险）。
#   指纹 = tracked diff 全文 + untracked 文件的名字/大小/mtime；`dist/` 与已忽略件不计。
_tree_fp() {
  { git -C "$SKILL_DIR" diff --binary HEAD 2>/dev/null
    while IFS= read -r _f; do
      [ -n "$_f" ] || continue
      case "$_f" in dist/*|*.lock|*.stamp) continue ;; esac
      stat -c '%n:%s:%Y' "$SKILL_DIR/$_f" 2>/dev/null
    done < <(git -C "$SKILL_DIR" ls-files --others --exclude-standard 2>/dev/null)
  } | sha1sum | cut -c1-16
}

PY="${ACCEPT_PY:-$(python3 "$SKILL_DIR/scripts/gk_accept_py.py" 2>/dev/null || echo python3)}"
# 并行度默认 = **nproc×2（上限 12）**（2026-09-24 实测，t4「进一步提高并行能力」）：
#   全量 `-n auto`(=nproc=5) 250s / `-n 8` 211s / `-n 10` 209s / `-n 12` 206s / `-n 15` 211s
#   / `-n 20` 214s ⟹ **plateau ≈210s**（超订 CPU 到 3×/4× 无收益）。三者失败集逐项相同
#   ⟹ 不引入漂移（漂移已由 `scripts/conftest.py` 隔离夹具 + `--dist loadfile` 根治，本行与二者配套）。
#   **「能否提到 3×/4×」的定向实测（2026-09-24，accept 全量口径）**：JOBS=10（=nproc×2）222s /
#     JOBS=15（=nproc×3）207s / JOBS=20（=nproc×4）204s ⟹ 3×/4× 仅 ≤9% 收益，且 **JOBS=15 触发
#     1 例并行假阳性**（`test_gk_edit_budget_metering::test_concurrent_billing_has_no_lost_update`
#     —— 并发计费 lost-update 用例，串行复核通过 ⟹ 是争用暴露而非真回归）。收益 ≪ 误报代价
#     ⟹ **默认维持 nproc×2（上限 12）**，不抬到 3×/4×。
#   `ACCEPT_JOBS=0` 仍可显式关并行；传具体数字即覆盖。
#   ⚠ **归因更正（2026-09-24，实测证伪「I/O 等待主导」）**：本条初稿写「该面是 I/O 等待主导」，
#     依据是「600KB 正文走 CIFS 解析 ≈0.46s」。后续实测**证伪**该假说：同内容 ext4 镜像反而
#     **更慢**（149 例子集 108.42s vs CIFS 99.21s）；`bash -n` 600KB 只需 0.05–0.12s（热缓存）；
#     `strace` 显示**单次 CLI 调用孵 10 次 execve**（`wait4` 占 55.9%，`/mnt/c` 探测仅 9%）
#     ⟹ 主犯 = **子进程孵化**，非 I/O 等待。故上面 plateau 的解释也随之更正：CPU 打满前先被
#     fork/exec 序列化（每次 `bash gatekeeper-cli.sh` 都是一串 python3 子进程）。加速主战场在
#     **减少子进程数**（CLI 启动块在 `PROTECTED_REGION::constants` 内，另立项）。
# 并行度默认 = **硬件自适应基数 × 2（上限 12）**（2026-10-29，user 令「把硬件自适应接进去」）：
#   **基数单一源** = `gk_hub_scheduler.adaptive_workers`（可见核/affinity + 空闲内存闸；
#   全仓单源，accept/redfirst 不得各自再探 nproc）；×2 = 实测 plateau 的超订因子
#   （2026-09-24 实测：`-n auto`(=5) 250s / `-n 8` 211s / `-n 10` 209s / `-n 12` 206s /
#   `-n 15` 211s / `-n 20` 214s ⟹ plateau ≈210s，失败集逐项相同；>2× 无收益且曾引入争用假阳性）。
#   ⚠ 2026-10-29 复核：CPU 从来不是瓶颈（serial 臂 CPU 时间 27.5s / WALL 67s 冷、15.5s 热），
#   并发度只影响并行段的收益边界；**真正的成本项是 /mnt/c 冷读**（见 plan-lint 过的
#   `docs/plans/2026-10-29-accept-throughput-forensics-plan.md`）。
#   `ACCEPT_JOBS=0` 仍可显式关并行；传具体数字即覆盖。
_BASE_W=""
# 2026-11-08（408 校正式）：子进程因子 f 缺省 1（混合面）——
#   W=min(2·max(1,核-min(4,max(1,核//4)))/max(1,f), 0.6R/(180+60f), 80/(1+f), 8, todo)；
#   f>0 时**不再 ×2**（公式已含 I/O 超订与安全垫）。f=0 显式退回旧口径（nproc×2 上限 12）。
_FACTOR="${ACCEPT_SUBPROC_FACTOR:-1}"
# 非法值（含负数）⟹ 归一为公式缺省 1（fail-safe：不得静默退回无公式的旧口径）。
case "$_FACTOR" in ''|*[!0-9]*) _FACTOR=1 ;; esac
# f → 并发度数（单源 = `gk_hub_scheduler.adaptive_workers`；缺 `python3` 时回落 `nproc`）。
_jobs_for_factor() {   # $1 = f（0 ⟹ 旧口径 nproc×2）
  local _f="$1" _w=""
  if [ "$_f" -gt 0 ] 2>/dev/null; then
    _w="$(PYTHONPATH="$SKILL_DIR/scripts" python3 -c "import gk_hub_scheduler as H; print(H.adaptive_workers(1000, subprocess_factor=${_f}))" 2>/dev/null || true)"
  else
    _w="$(PYTHONPATH="$SKILL_DIR/scripts" python3 -c 'import gk_hub_scheduler as H; print(H.adaptive_workers(1000))' 2>/dev/null || true)"
  fi
  case "$_w" in ''|*[!0-9]*) _w="$(nproc 2>/dev/null || echo 4)" ;; esac
  if [ "$_f" -gt 0 ] 2>/dev/null; then printf '%s\n' "$_w"; else printf '%s\n' $(( _w * 2 )); fi
}
_DEF_JOBS="$(_jobs_for_factor "$_FACTOR")"
[ "$_DEF_JOBS" -gt 12 ] && _DEF_JOBS=12; [ "$_DEF_JOBS" -lt 1 ] && _DEF_JOBS=1
JOBS="${ACCEPT_JOBS:-$_DEF_JOBS}"
# 防爆硬闸（2026-11-08）：空闲内存已低于硬阈值时**拒绝启动**（fail-loud，不静默串行）。
#   408 事故复盘：24 worker + WSL+openssl 曾把宿主压到换页/蓝屏；启动前补这一道。
#   `ACCEPT_MIN_FREE_MB=0` 显式关闭（逃生舱）；读数失败/0 不拦（fail-safe，宁可放行）。
_ACCEPT_MIN_FREE_MB="${ACCEPT_MIN_FREE_MB:-800}"
if [ "${ACCEPT_MIN_FREE_MB:-800}" -gt 0 ] 2>/dev/null; then
  _FREE_MB="$(PYTHONPATH="$SKILL_DIR/scripts" python3 -c 'import gk_hub_scheduler as H; print(H.free_avail_mb() or 0)' 2>/dev/null || echo 0)"
  case "$_FREE_MB" in ''|*[!0-9]*) _FREE_MB=0 ;; esac
  if [ "$_FREE_MB" -gt 0 ] && [ "$_FREE_MB" -lt "${_ACCEPT_MIN_FREE_MB:-800}" ]; then
    echo "[accept] FATAL: 空闲内存 ${_FREE_MB}MB < 防爆硬闸 ${_ACCEPT_MIN_FREE_MB}MB —— 拒绝启动；释放内存或 ACCEPT_MIN_FREE_MB=0 显式关闭" >&2
    exit 2
  fi
fi
# 最小看门狗（2026-11-09，user 裁定「不过度设计」）：只在**运行期**兜三道闸 ——
#   墙钟 / 日志空闲 / 空闲内存；命中即**整树**击杀（POSIX killpg / Windows taskkill /T /F），
#   退出码 124/137 由下方既有 FATAL 面报出。
#   为什么需要：启动闸只拦「开局就低内存」，408 事故是**运行中**被 WSL+openssl 档拖进换页。
#   阈值**单源**（防多源漂移）：墙钟/空闲**缺省在 gk_watchdog.py**，本脚本只在显式设
#   `ACCEPT_WATCHDOG_WALL_S/IDLE_S` 时才透传；内存闸与启动前硬闸共用 `ACCEPT_MIN_FREE_MB`。
#   关闭：ACCEPT_WATCHDOG=0。
_WD_PREFIX=()
if [ "${ACCEPT_WATCHDOG:-1}" != "0" ] && [ -f "$SKILL_DIR/scripts/gk_watchdog.py" ]; then
  if command -v python3 >/dev/null 2>&1; then
    _WD_LOG="${TMPDIR:-/tmp}/gk-accept-watchdog.$$.log"
    _WD_EXTRA=()
    [ -n "${ACCEPT_WATCHDOG_WALL_S:-}" ] && _WD_EXTRA+=(--wall "$ACCEPT_WATCHDOG_WALL_S")
    [ -n "${ACCEPT_WATCHDOG_IDLE_S:-}" ] && _WD_EXTRA+=(--idle "$ACCEPT_WATCHDOG_IDLE_S")
    _WD_PREFIX=(python3 "$SKILL_DIR/scripts/gk_watchdog.py" "${_WD_EXTRA[@]}"
      --min-free-mb "${ACCEPT_MIN_FREE_MB:-800}" --log "$_WD_LOG" --)
  fi
fi
# I/O 卫生（2026-09-24；**诚实标注：未单独 A/B**）：pytest 进程自身的 `.pyc` 落 CIFS（本仓在
#   /mnt/c）会在每次冷 import 时付出跨 fs 写代价；改投 /tmp（ext4）。属低成本卫生面，非提速主项。
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/gk-pycache}"
BASE="${ACCEPT_BASELINE:-$SKILL_DIR/scripts/_accept_baseline.txt}"

MODE="subset"; SNAP=0; TARGETS=(); CHANGED_REV=""
while [ $# -gt 0 ]; do
  case "$1" in
    --full)     MODE="full"; shift ;;
    --changed)  MODE="changed"; shift ;;
    --rev)      CHANGED_REV="${2:-HEAD}"; shift 2 ;;
    --snapshot) SNAP=1; shift ;;
    --baseline) BASE="$2"; shift 2 ;;
    -h|--help)  sed -n '2,27p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)          MODE="explicit"; TARGETS+=("${1#scripts/}"); shift ;;
  esac
done
CHANGED_REV="${CHANGED_REV:-HEAD}"
# 基线必须**全量口径**（子集拍基线会把「未覆盖」误当「不失败」⟹ 之后全量必刷假 NEW）。
if [ "$MODE" = "changed" ] && [ "$SNAP" = "1" ]; then
  echo "[accept] FATAL: --changed 不得与 --snapshot 同用（基线必须全量口径）"; exit 2
fi

cd "$SKILL_DIR/scripts" || exit 2

# ── 位置依赖提示（`ECC-94AA4F0B3D3A`，2026-10-02）─────────────────────────────────
# 痛点：`_accept_baseline.txt` 恒在**主树**拍摄，而部分臂**位置依赖**（真实技能目录 vs
#   feature worktree；如 `test_gk_xenv_form_residual` 需 `<repo>/.gatekeeper.state` 存在）。
#   在 worktree 内跑 accept ⟹ 这批臂新增红被当 `NEW` ⟹ **假回归**（实测 2 条）。
# 处置：检出「当前为 linked worktree」即**显式告警**（不阻断）；已知位置依赖臂另见
#   `_accept_location_exempt.txt`（从 `NEW` 剔除 + 列 `EXEMPT`）。**不得**据此重刷基线。
_gd="$(git -C "$SKILL_DIR" rev-parse --git-dir 2>/dev/null || echo '')"
_gc="$(git -C "$SKILL_DIR" rev-parse --git-common-dir 2>/dev/null || echo '')"
_gd="$(cd "$SKILL_DIR" && cd "$_gd" 2>/dev/null && pwd -P || echo "$_gd")"
_gc="$(cd "$SKILL_DIR" && cd "$_gc" 2>/dev/null && pwd -P || echo "$_gc")"
_IN_WORKTREE=0
if [ -n "$_gd" ] && [ "$_gd" != "$_gc" ]; then _IN_WORKTREE=1; fi
if [ "$_IN_WORKTREE" = "1" ]; then
  echo "[accept] ⚠ 当前为 **linked worktree**（$SKILL_DIR）；基线在**主树**拍摄 ⟹" >&2
  echo "[accept]   位置依赖臂的新增红**非**回归（ECC-94AA4F0B3D3A）；不得据此重刷基线掩盖差异。" >&2
fi

# ── 跨会话互斥 + 全量结果复用（ECC-34EEC2BC12D2；2026-09-28 user 裁定「跨会话互斥 flock」）─────
# 痛点：两会话各自 `--full` ⟹ 争 CPU 互相拖慢，且都重跑同一批（= 最慢的串行全量 ×N）。
# 处置：`--full` 入口取**机器级排他 flock**（`$ACCEPT_LOCK_FILE`），后到者**等待**；取得锁后若
#   检出**新鲜结果戳**（同 git HEAD + 同基线指纹 + TTL 内）则**复用**，不再跑。
# 复用为何安全：戳与锁**同派生自 `$BASE`/worktree**（`$BASE.stamp`）⟹ 异 worktree 天然不串味；
#   同 worktree 的并发会话 = 同一工作树 ⟹ 结果必相同，复用即正确（HEAD 兜住「跑后即提交」）。
# Env: ACCEPT_LOCK_FILE（默认 /tmp/gk-accept-full.lock）、ACCEPT_LOCK_WAIT（默认 600s）、
#      ACCEPT_REUSE_TTL（默认 1800s；设 0 = 关复用）
ACCEPT_LOCK_FILE="${ACCEPT_LOCK_FILE:-/tmp/gk-accept-full.lock}"
STAMP="$BASE.stamp"
_REUSED=0
# 2026-10-29（user 裁定「默认模式也加 flock」）：锁从 `--full` 扩到**一切非 explicit 模式**。
#   依据：实测串行段单独跑 46s、在并发 accept 里 508s（11×）⟹ 不互斥就互相拖死。
#   ⚠ **归因更正（2026-10-30，6 臂质询一致证伪「CPU 争抢是主因」）**：并发臂 %CPU 仅 31–50%
#     （serial 臂 CPU 27.5/9.8/7.8s ≪ WALL 67.4/30.9/15.5s），CPU 未饱和 ⟹ 11× 放大的主成分是
#     ①**同一批全量被重复跑 ×N**（互斥缺失本身，flock 正是治这个）+ ②**子进程孵化**（单次
#     `bash gatekeeper-cli.sh` 孵 10 次 execve，本机 EDR 逐进程扫描 300ms+/次）——不是 CPU 争抢，
#     也不是 `/mnt/c` 冷读（strace 实测该面仅 9%，同内容 ext4 反而更慢）。
#   ⚠ 防自锁：本脚本跑 pytest 前导出 `GK_ACCEPT_INNER=1`，被**嵌套**调用的子 accept
#     （`test_gk_accept_cli.py` 就是这种）见到即跳过取锁 —— 否则外层持锁、内层等 600s。
#   逃生：`ACCEPT_LOCK=0` 全局关锁。显式文件模式（秒级）不取锁。
_LOCK_ON=1
[ "$MODE" = "explicit" ] && _LOCK_ON=0
[ "${ACCEPT_LOCK:-1}" = "0" ] && _LOCK_ON=0
[ "${GK_ACCEPT_INNER:-0}" = "1" ] && _LOCK_ON=0
if [ "$_LOCK_ON" = "1" ] && command -v flock >/dev/null 2>&1; then
  _LOCK_FD=""
  { exec {_LOCK_FD}>"$ACCEPT_LOCK_FILE"; } 2>/dev/null || _LOCK_FD=""
  if [ -n "$_LOCK_FD" ]; then
    flock -w "${ACCEPT_LOCK_WAIT:-600}" "$_LOCK_FD" \
      || echo "[accept] ⚠ 跨会话 accept 锁等待超时（${ACCEPT_LOCK_WAIT:-600}s）；降级继续（ECC-34EEC2BC12D2）" >&2
  fi
fi
if [ "$MODE" = "full" ]; then
  _ttl="${ACCEPT_REUSE_TTL:-1800}"
  if [ "$_ttl" != "0" ] && [ -f "$STAMP" ]; then
    _head="$(git -C "$SKILL_DIR" rev-parse HEAD 2>/dev/null || echo '')"
    _bh="$(sha1sum "$BASE" 2>/dev/null | cut -c1-16)"
    _tf="$(_tree_fp)"
    _sfp="$(sed -n '1p' "$STAMP" 2>/dev/null)"
    _sts="$(sed -n '2p' "$STAMP" 2>/dev/null)"
    _now="$(date +%s)"
    if [ "$_sfp" = "${_head}:${_bh}:${_tf}" ] && [ -n "$_sts" ] && [ "$(( _now - _sts ))" -lt "$_ttl" ]; then
      SUM="$(sed -n '3p' "$STAMP" 2>/dev/null)"
      CUR="$(sed -n '4,$p' "$STAMP" 2>/dev/null)"
      _REUSED=1
      echo "[accept] ↻ 复用新鲜全量结果（Δ$(( _now - _sts ))s < ${_ttl}s；stamp=$STAMP；ECC-34EEC2BC12D2）"
    fi
  fi
fi

# ── 选面 ──────────────────────────────────────────────────────────────────────
# ── --changed：按 git 改动自动选面（2026-10-29；accept 提速主路径）────────────────
# 病：日常改动也要跑 CLI 面 ≈ 全量（28 min 量级）。手敲文件名易漏；直接全量又慢。
# 规则（**保守**：宁多勿漏，全部可审计打印）：
#   scripts/test_x.py            ⟹ 只跑它
#   scripts/x.py                 ⟹ test_x.py（若存在）+ rg 文本引用 `x` 的 test_*.py（≤20）
#   scripts/x.sh                 ⟹ rg 定串引用 `x.sh` 的 test_*.py（≤20）
#   gatekeeper-cli.sh            ⟹ **CLI 面全量**（引用点最多，不做细粒度推测）
#   SKILL.md|references/*|docs/* ⟹ 文档面（doc_align / audit_docs / plan_lint）
#   其它（install.sh 等）         ⟹ 回落 CLI 面 + 打印「未归类」
# 选中 0 个 ⟹ exit 2（fail-loud；绝不静默跑全量，也绝不静默放行）。
_changed_files() {
  { git -C "$SKILL_DIR" diff --name-only "$CHANGED_REV" 2>/dev/null
    git -C "$SKILL_DIR" ls-files --others --exclude-standard 2>/dev/null
  } | sed 's#\\#/#g' | sort -u
}
_derive_changed() {
  local f m t
  local -a picked=() unclassified=()
  local _doc=0 _cli=0
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    case "$f" in
      scripts/test_*.py) picked+=("$(basename "$f")") ;;
      scripts/*.py)
        m="$(basename "$f" .py)"
        [ -f "test_${m}.py" ] && picked+=("test_${m}.py")
        while IFS= read -r t; do
          [ -n "$t" ] && picked+=("$(basename "$t")")
        done < <(rg -l --glob 'test_*.py' "(^|[^0-9A-Za-z_])${m}([^0-9A-Za-z_]|$)" . 2>/dev/null | head -20)
        ;;
      scripts/*.sh)
        m="$(basename "$f")"
        while IFS= read -r t; do
          [ -n "$t" ] && picked+=("$(basename "$t")")
        done < <(rg -l --glob 'test_*.py' --fixed-strings "$m" . 2>/dev/null | head -20)
        ;;
      gatekeeper-cli.sh) _cli=1 ;;
      SKILL.md|references/*|docs/*|README.md|CONVENTIONS.md|MAINTENANCE.md) _doc=1 ;;
      *) unclassified+=("$f") ;;
    esac
  done < <(_changed_files)
  if [ "$_cli" = "1" ]; then
    while IFS= read -r t; do [ -n "$t" ] && picked+=("${t#./}"); done \
      < <(rg -l 'gatekeeper-cli\.sh' --glob 'test_*.py' . 2>/dev/null | sort)
  fi
  if [ "$_doc" = "1" ]; then
    for t in test_gk_doc_align.py test_gk_audit_docs.py test_gk_plan_lint.py; do
      [ -f "$t" ] && picked+=("$t")
    done
  fi
  if [ "${#picked[@]}" -eq 0 ] && [ "${#unclassified[@]}" -gt 0 ]; then
    echo "[accept] ⚠ --changed 未归类: ${unclassified[*]} ⟹ 回落 CLI 面" >&2
    while IFS= read -r t; do [ -n "$t" ] && picked+=("${t#./}"); done \
      < <(rg -l 'gatekeeper-cli\.sh' --glob 'test_*.py' . 2>/dev/null | sort)
  fi
  printf '%s\n' "${picked[@]}" 2>/dev/null | sed '/^$/d' | sort -u
}

SELECT=()
if [ "$MODE" = "full" ]; then
  SELECT=()                                   # 空 = pytest 收全部
elif [ "$MODE" = "changed" ]; then
  mapfile -t SELECT < <(_derive_changed)
  if [ "${#SELECT[@]}" -eq 0 ]; then
    echo "[accept] FATAL: --changed 未选出任何测试面（改动: $(_changed_files | tr '\n' ' ')）⟹ 显式传文件或 --full"
    exit 2
  fi
  echo "[accept] --changed（rev=$CHANGED_REV）选面 ${#SELECT[@]} 个文件: ${SELECT[*]}"
elif [ "$MODE" = "explicit" ]; then
  SELECT=("${TARGETS[@]}")
else
  # CLI 面 = 引用 gatekeeper-cli.sh 的测试文件（rg 单源；缺 rg 回退 grep）
  if command -v rg >/dev/null 2>&1; then
    while IFS= read -r f; do [ -n "$f" ] && SELECT+=("${f#./}"); done \
      < <(rg -l 'gatekeeper-cli\.sh' --glob 'test_*.py' . | sort)
  else
    while IFS= read -r f; do [ -n "$f" ] && SELECT+=("$f"); done \
      < <(grep -l 'gatekeeper-cli\.sh' test_*.py | sort)
  fi
  if [ "${#SELECT[@]}" -eq 0 ]; then
    echo "FATAL: 未选到任何 CLI 面测试文件（扫描失效 ⟹ 禁止静默跑全量）"; exit 2
  fi
fi

# f 自动分档（2026-11-09）：只在**未显式指定** ACCEPT_SUBPROC_FACTOR / ACCEPT_JOBS 时生效。
#   口径见 `scripts/gk_accept_factor.py`：全轻 ⟹ 0；重活文件占比 ≥50% ⟹ 3；其余 ⟹ 1。
#   为什么放在这里：分档要看**实际选中的文件集**（此时 SELECT 才定稿）。
if [ -z "${ACCEPT_SUBPROC_FACTOR:-}" ] && [ -z "${ACCEPT_JOBS:-}" ]; then
  _DET="$(python3 "$SKILL_DIR/scripts/gk_accept_factor.py" "${SELECT[@]}" 2>/dev/null || true)"
  case "$_DET" in ''|*[!0-9]*) _DET="" ;; esac
  if [ -n "$_DET" ] && [ "$_DET" != "$_FACTOR" ]; then
    _FACTOR="$_DET"
    _DEF_JOBS="$(_jobs_for_factor "$_FACTOR")"
    [ "$_DEF_JOBS" -gt 12 ] && _DEF_JOBS=12; [ "$_DEF_JOBS" -lt 1 ] && _DEF_JOBS=1
    JOBS="$_DEF_JOBS"
  fi
fi

# ── 跑 ────────────────────────────────────────────────────────────────────────
PYARGS=(-q --tb=no -rfE)
# 并行对**大子集/全量**都必要（首版只在 --full 加 `-n`，而默认「CLI 面」子集实测 ≈ 全量
# ⟹ 串行仍 ~12 min，等同一个假提速）。`ACCEPT_JOBS=0` 可显式关并行。
# 2026-09-24：补 `--dist loadfile`（**确定层**）—— 默认 `--dist load` 按**用例**分配 worker，
#   同文件用例会被拆到不同 worker、不同文件用例会交错进同一进程 ⟹ 跨文件模块级状态泄漏
#   暴露为「并行红 / 串行绿」的**分块漂移**（`ECC-2C6363430A3B`）。`loadfile` 让**同文件恒同
#   worker** ⟹ 分配可复现。配合 `scripts/conftest.py` 的 autouse 全局隔离夹具（根因层）
#   与下方串行复核（检测层），三层各司其职。
[ "$JOBS" != "0" ] && PYARGS+=(-n "$JOBS" --dist loadfile)
# ── 两段式（2026-10-28）：并行段（排除 `serial`）+ 串行段（只跑 `serial`）───────────
# 病（实测 2026-10-28 全量 747s + 串行复核 285s）：时间预算臂在 xdist 下被抢资源 ⟹ 必红 ⟹
#   进「串行复核」二次执行（单臂 2-5min）。根因是**判定环境**不干净，不是回归。
# 处置：`@pytest.mark.serial` 的臂从并行段剔除，并行段结束后**独占整机**跑一次。
#   覆盖率不变（两段并集 = 全量）；命中集合 = `-m serial`（无 --dist ⟹ 真串行）。
#   串行段刻意放在并行段**之后**：HEAD 级 git 溯源缓存（`gk_audit_depth`）已由前面用例预热，
#   性能臂量到的是**生产稳态**延迟，而非冷缓存的一次性成本。
SER_OUT=""; SER_SUM=""
if [ "$_REUSED" = "0" ]; then
  # 2026-10-29：标记「本次 pytest 是 accept 的子进程」⟹ 被测试嵌套调用的 accept 跳过取锁（防自锁）。
  export GK_ACCEPT_INNER=1
  # `ACCEPT_JOBS=0`（全串行）⟹ **单段**：本来就没有并行抢占，`serial` 臂无需隔离，
  #   多跑一遍纯属浪费一次解释器启动（也会打破「复用/串行化」臂对 STUB 调用数的断言）。
  if [ "$JOBS" != "0" ]; then PYARGS+=( -m "not serial" ); fi
  if [ "${#SELECT[@]}" -gt 0 ]; then
    OUT="$("${_WD_PREFIX[@]}" "$PY" -m pytest "${PYARGS[@]}" "${SELECT[@]}" 2>&1)"
  else
    OUT="$("${_WD_PREFIX[@]}" "$PY" -m pytest "${PYARGS[@]}" 2>&1)"
  fi
  SUM="$(printf '%s\n' "$OUT" | grep -E '[0-9]+ (passed|failed|error)' | tail -1)"
  if [ "$JOBS" != "0" ]; then
    # 2026-10-29 **子集预筛**：实测 10 文件子集的串行段 97s（其中 ~90s 是重复收集全树）。
    #   选中面内没有 `pytest.mark.serial` ⟹ 跳过串行段（等价：`-m serial` 本会跑 0 例）。
    _ser_sel=()
    if [ "${#SELECT[@]}" -gt 0 ]; then
      while IFS= read -r _t; do [ -n "$_t" ] && _ser_sel+=("$_t"); done \
        < <(for _f in "${SELECT[@]}"; do rg -l 'pytest\.mark\.serial' "$_f" 2>/dev/null; done | sort -u)
    fi
    # 串行段必须**干净环境**（本脚本可能被嵌套在 xdist worker 内调用，见下方复核段同族注释）
    if [ "${#SELECT[@]}" -eq 0 ]; then
      SER_OUT="$("${_WD_PREFIX[@]}" env -u PYTEST_XDIST_WORKER -u PYTEST_XDIST_WORKER_COUNT -u PYTEST_XDIST_TESTRUNUID \
        "$PY" -m pytest -q --tb=no -rfE -m serial 2>&1)" || true
    elif [ "${#_ser_sel[@]}" -gt 0 ]; then
      SER_OUT="$("${_WD_PREFIX[@]}" env -u PYTEST_XDIST_WORKER -u PYTEST_XDIST_WORKER_COUNT -u PYTEST_XDIST_TESTRUNUID \
        "$PY" -m pytest -q --tb=no -rfE -m serial "${_ser_sel[@]}" 2>&1)" || true
    fi
    SER_SUM="$(printf '%s\n' "$SER_OUT" | grep -E '[0-9]+ (passed|failed|error)' | tail -1)"
  fi
  # 显式选中「只含 serial 臂」的文件时，并行段零用例（无摘要）⟹ 用串行段摘要兜底，
  # 避免下面的零用例 FATAL 误判（覆盖率仍是 100%，由串行段执行）。
  [ -z "$SUM" ] && [ -n "$SER_SUM" ] && SUM="$SER_SUM"
fi

# 2026-09-24（实测假绿）：`SUM` 为空 = pytest **没跑成**（路径写错 / 环境错 / 收集失败），
#   而下游只比 `NEW`（空）⟹ 旧行为会对「零用例执行」打印 `✓ 无新增失败` 并 **exit 0**
#   —— 与本脚本自述的 `Exit: 2 = 环境/参数错误` **自相矛盾**（fail-open）。实测触发面：
#   显式模式传 `scripts/x.py`，脚本 `cd scripts/` 后再拼 ⟹ 路径不存在、pytest exit 4、零摘要。
#   现 fail-loud：无摘要即 exit 2（不静默放行）。显式模式的 `scripts/` 前缀已在参数解析处剥离。
if [ -z "$SUM" ]; then
  echo "[accept] FATAL: pytest 未产出摘要 ⟹ **零用例执行**（路径/收集/环境错误），禁止判「无新增失败」"
  printf '%s\n' "$OUT" | tail -15
  exit 2
fi

# 逐用例名（与 pytest `-rfE` 摘要同格式，去尾部断言文案）
# 2026-10-28 两段式：并行段（`not serial`）与串行段（`serial`）的结果**并集**入 CUR。
if [ "$_REUSED" = "0" ]; then
  CUR="$( { printf '%s\n' "$OUT"; printf '%s\n' "${SER_OUT:-}"; } \
          | sed -n 's/^\(FAILED\|ERROR\) //p' | sed 's/ - .*//' | sort -u)"
fi
# ── 位置依赖豁免（`ECC-94AA4F0B3D3A`，2026-10-02）：从 CUR 剔除已知位置依赖臂 ⟹ 不误报 NEW ──
# 单源清单 = `scripts/_accept_location_exempt.txt`（可 `ACCEPT_EXEMPT=<f>` 覆盖，自测用）。
EXEMPT_FILE="${ACCEPT_EXEMPT:-$SKILL_DIR/scripts/_accept_location_exempt.txt}"
EXEMPT=""; HIT_EXEMPT=""
if [ -f "$EXEMPT_FILE" ]; then
  EXEMPT="$(grep -v '^#' "$EXEMPT_FILE" | grep -v '^[[:space:]]*$' | sort -u)"
fi
if [ -n "$EXEMPT" ]; then
  HIT_EXEMPT="$(comm -12 <(printf '%s\n' "$CUR") <(printf '%s\n' "$EXEMPT"))"
  if [ -n "$HIT_EXEMPT" ]; then
    CUR="$(comm -23 <(printf '%s\n' "$CUR") <(printf '%s\n' "$EXEMPT"))"
  fi
fi
# 结果戳（ECC-34EEC2BC12D2）：仅在**真跑**（未复用）且拿到摘要时写，供并发会话复用。
if [ "$MODE" = "full" ] && [ "$_REUSED" = "0" ] && [ -n "$SUM" ]; then
  _head="$(git -C "$SKILL_DIR" rev-parse HEAD 2>/dev/null || echo '')"
  _bh="$(sha1sum "$BASE" 2>/dev/null | cut -c1-16)"
  _tf="$(_tree_fp)"
  { printf '%s\n' "${_head}:${_bh}:${_tf}" "$(date +%s)" "$SUM"; printf '%s\n' "$CUR"; } > "$STAMP" 2>/dev/null || true
fi

if [ "$SNAP" = "1" ]; then
  {
    echo "# gk-accept 回归基线 v1（勿手改；用 \`bash scripts/_accept_cli.sh --snapshot\` 重建）"
    echo "# runner: <local interpreter>（本机路径不入库；指纹见 _accept_baseline.txt.stamp）"
    echo "# scope:  $([ "$MODE" = full ] && echo 'scripts/ 全量' || echo "$MODE")"
    echo "# totals: ${SUM:-<unknown>}"
    printf '%s\n' "$CUR"
  } > "$BASE"
  echo "[accept] 基线已重建 -> $BASE（$(printf '%s\n' "$CUR" | grep -c . ) 条）"
  echo "[accept] $SUM"
  exit 0
fi

if [ ! -f "$BASE" ]; then
  echo "[accept] FATAL: 基线缺失 $BASE —— 先跑一次 \`--snapshot\`（否则无法区分新增/既有失败）"
  exit 2
fi

BL="$(grep -v '^#' "$BASE" | grep -v '^[[:space:]]*$' | sort -u)"
NEW="$(comm -23 <(printf '%s\n' "$CUR") <(printf '%s\n' "$BL"))"
FIXED="$(comm -13 <(printf '%s\n' "$CUR") <(printf '%s\n' "$BL"))"

echo "[accept] $SUM"
[ -n "$SER_SUM" ] && echo "[accept] (serial 段) $SER_SUM"
# 位置依赖豁免命中（`ECC-94AA4F0B3D3A`）：显式列出，避免「静默吞掉」造成审计盲区。
if [ -n "$HIT_EXEMPT" ]; then
  echo "[accept] ⓘ EXEMPT（位置依赖，非回归；ECC-94AA4F0B3D3A）:"
  printf '  %s\n' $HIT_EXEMPT
fi
# ⚠ `FIXED` 只在**全量口径**下成立：跑子集时，基线里**未被本跑覆盖**的条目也会「不再失败」
# ⟹ 会刷一堆假 FIXED（首版实测：3 文件子集刷出 29 条）。故仅 `--full` 判 FIXED。
if [ "$MODE" = "full" ] && [ -n "$FIXED" ]; then
  echo "[accept] FIXED（基线里已修好，考虑 --snapshot 更新基线）:"
  printf '  %s\n' $FIXED
fi
if [ -n "$NEW" ]; then
  # 2026-09-23（**ECC-2C6363430A3B**）：`-n auto` 下的 NEW 含**假阳性** —— xdist 分块漂移暴露的
  #   跨文件状态泄漏（实测：同一命令两次运行 NEW 集不同，且全部落在同一文件内，而该文件单独跑
  #   151 passed / 1 skipped）。误报真回归会**反噬**一键器的可信度 ⟹ 复核：把 NEW 集合**串行**
  #   重跑一次（串行无分块漂移），只有**仍失败**的才判真回归。
  _confirm=(); _x=""
  while IFS= read -r _x; do [ -n "$_x" ] && _confirm+=("$_x"); done < <(printf '%s\n' "$NEW")
  # 2026-09-24（同族第 3 处，`ECC-2C6363430A3B` 检测层自愈）：复核跑**必须**是干净环境 ——
  #   本脚本自身可能被**嵌套**在一个 xdist worker 内调用（`test_gk_accept_cli.py` 即如此
  #   造「并行失败/串行通过」形态）⟹ 若原样继承 `PYTEST_XDIST_WORKER` 等 env，被反复核的用例
  #   在「串行」复核里仍**看得见** xdist 身份 ⟹ 假阳性滤除逻辑被 env 泄漏绕过（实测该臂假红）。
  _rc_out="$(env -u PYTEST_XDIST_WORKER -u PYTEST_XDIST_WORKER_COUNT -u PYTEST_XDIST_TESTRUNUID \
    "$PY" -m pytest -q --tb=no -rfE "${_confirm[@]}" 2>&1)"
  REAL="$(printf '%s\n' "$_rc_out" | sed -n 's/^\(FAILED\|ERROR\) //p' | sed 's/ - .*//' | sort -u)"
  FLAKY="$(comm -23 <(printf '%s\n' "$NEW") <(printf '%s\n' "$REAL"))"
  if [ -n "$FLAKY" ]; then
    echo "[accept] ⚠ 假阳性（并行下失败 / 串行复核通过，已滤除；见 ECC-2C6363430A3B）："
    printf '  %s\n' $FLAKY
  fi
  if [ -n "$REAL" ]; then
    echo "[accept] ✗ NEW 失败（并行 + 串行**双重复核** ⟹ 真回归）："
    printf '  %s\n' $REAL
    exit 1
  fi
fi
echo "[accept] ✓ 无新增失败（既有失败与基线一致）"
exit 0
