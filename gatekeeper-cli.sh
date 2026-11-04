#!/bin/bash
# ============================================================
# Gatekeeper CLI — Deterministic execution layer + PRM Monitor
# ============================================================
# Design: Agent ↔ CLI JSON-only. grep→rg, --api→v4-flash actor-critic (P2/P3).
# ============================================================
# shellcheck disable=SC2034,SC2155
# SC2034: intentional design contracts (META_*, evidence collectors, case branch vars)
# SC2155: local var=$(cmd) pattern ubiquitous in CLI — return code masking is intentional
set -uo pipefail

# PROTECTED_REGION_START::constants
# ---------- constants ----------
# Repo fingerprint: SHA256(<canonical remote url>)[:8] — disambiguates skill vs gatekeeper repo
# Skill = d67b1270；Gatekeeper = 15309a63（只作稳定标识，不含本机路径/账号）
SKILL_REPO_HASH="d67b1270"
# SECURITY NOTE (V8b, 2026-10-31): 主仓路径**运行时解析**，不再硬编码。
# 优先级：GK_MAIN_REPO（绝对路径）→ state.target_repo → META target_repo → git rev-parse。
# 安全边界不变：只有**已声明**的主仓参与 scope 判定；解析为空 ⟹ 依赖主仓的检查 fail-closed
# （cd / 分支缺失 = 具名错误），绝不静默替换成调用方 cwd。
# 解析单源 = scripts/gk_main_repo.py（bash 侧经 scripts/gk_main_repo.sh 调用），禁止第二实现。
# 相对路径 / 含 '..' 的 GK_MAIN_REPO 一律拒绝（防注入把 scope 边界重定向）。
MAIN_REPO_WSL=""; MAIN_REPO_WIN=""; _MAIN_REPO_WIN_RE=""; _MAIN_REPO_WSL_RE=""   # 2026-10-31：运行时解析（下方 source）
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts/gk_main_repo.sh"  # 2026-09-24 XENV-FORM ECC-9D6B0291E793：WSL 形态同名派生（sed 表达式逐字复用同行 _MAIN_REPO_WIN_RE 写法、输入换 $MAIN_REPO_WSL；**净 0 行**）｜ 2026-09-20 C1a：本正则由本行常量派生（非 env，符合 ECC-PLAN §5）；**净 0 行**以免新增锚漂移；勿提前改值=C1b，须与物理迁移同批
# 2026-09-04 L3 接线（方案 A）：worktree 前缀不再在本文件硬编码——原 FEATURE_PREFIX 自动探测
# （ECC-FINDING-20260802 P1：Windows worktree 优先 / fallback WSL / GATEKEEPER_WORKTREE_ROOT env 覆盖）
# 已并入元数据路由中枢 gk_route_center.resolve_worktree 单一事实源：
#   GATEKEEPER_WORKTREE_ROOT env → 显式前缀优先（DEV_WORKTREE_ROOTS 白名单 + `..` 段拒绝）；
#   否则 DEV_WORKTREE_ROOTS 跨仓库目录扫描（cmd_discover 以 GK_WORKTREE_CWD=调用方 cwd 路径
#   限定当前仓库上下文；仓库段由路由中枢按 git 权威视图归一，2026-09-25 ⑤）。
# 历史引用：references/ecc-finding-20260802-feature-prefix-wsl-hardcode.md（决策记录，非现行代码）。

# P3 (2026-08-02, ECC-FINDING-20260802): git 双环境包装
# Windows worktree 的 .git 文件内容是 Windows 路径 (gitdir: C:/...), WSL git 按相对路径拼接失败。
# → 读 .git 文件 → Windows 路径转 /mnt/<drive>/ → --git-dir + --work-tree 显式指定（绕开 .git 解析）。
_git() {
  local repo="$1"; shift
  local gd=""
  if [ -f "$repo/.git" ]; then
    gd=$(head -1 "$repo/.git" 2>/dev/null | sed 's/^gitdir: //')
    case "$gd" in
      [A-Za-z]:*) gd="/mnt/$(echo "${gd:0:1}" | tr 'A-Z' 'a-z')/${gd:2}"; gd=${gd//\\//} ;;
    esac
    [ -n "$gd" ] && { git --git-dir="$gd" --work-tree="$repo" "$@"; return $?; }
  fi
  git -C "$repo" "$@"
}

# ─── 允许的推送远端白名单 (F8.1 远端验证门禁) ───
# 2026-11-01（开源可移植）：原写死两个本机组织的远端前缀（其一含个人账号）⟹ 他人机器上
#   `push` 恒 `remote_not_allowed`（不可调用 + 身份泄漏）。现默认放行**常见托管站**（任意
#   owner），组织可用 `GK_PUSH_REMOTE_ALLOW`（逗号/冒号分隔）收紧到自己的前缀；未知 host /
#   本地路径仍拒绝（F8.1 判据不变）。
declare -a _ALLOWED_REMOTE_PATTERNS=(
  "github.com/"
  "gitlab.com/"
  "atomgit.com/"
  "gitee.com/"
  "codeberg.org/"
)
if [ -n "${GK_PUSH_REMOTE_ALLOW:-}" ]; then
  _ALLOWED_REMOTE_PATTERNS=()
  while IFS= read -r _pat; do
    [ -n "$_pat" ] && _ALLOWED_REMOTE_PATTERNS+=("$_pat")
  done < <(printf '%s\n' "${GK_PUSH_REMOTE_ALLOW}" | tr ',:' '\n')
fi

# ─── SKILL_DIR 查找（支持安装器部署） ───
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -a LOOKUP_DIRS=(
  "$_SCRIPT_DIR"                                          # 相对于脚本本身
  "$(pwd)/.trae/skills/spz-gatekeeper-r-sequence"         # 当前项目 .trae/skills/
  # 2026-09-20（ECC-PLAN ①·宿主形态）：原为宿主机绝对路径字面量（<home>/.trae/...）
  # ⟹ 非本机宿主上第 3 项恒不命中（前两项通常已够，但一旦全不中即 `exit 1` SKILL_DIR not found）。
  # 改由 $HOME 派生（跨宿主同形；`${HOME:-}` 兼容 `set -u`）。
  "${HOME:-}/.trae/skills/spz-gatekeeper-r-sequence"      # 用户主目录兜底
)
SKILL_DIR=""
for _d in "${LOOKUP_DIRS[@]}"; do
  if [ -f "$_d/gatekeeper-cli.sh" ]; then
    SKILL_DIR="$_d"
    break
  fi
done
[ -z "$SKILL_DIR" ] && { echo '{"error":"SKILL_DIR not found. Run install.sh first."}'; exit 1; }

# ─── SKILL_DIR 租户校验（R-16 ⑰-11d，2026-09-18；用户裁定「加 SKILL_DIR 租户校验」）───
# 事故（取证实测）：2026-09-15 13:53–13:54 一次**人工 J5 沙箱**用相对路径 `ln -s` 且 cwd=`/`
# 以 root 执行 ⟹ 沙箱建在**根目录**（`/scripts -> /scripts`、`/gatekeeper-cli.sh -> /gatekeeper-cli.sh`
# 自指软链）⟹ SKILL_DIR 解析成 `/` ⟹ `_DEFAULT_STATE_FILE=/.gatekeeper.state`（骨架）+ 域孪生
# `/.gatekeeper.state.gp.r1` + 夹具 `/plan.md` + `/ctx.json*` 全落根目录；两天后这批残留被 hook 的
# 就近 state 误领（F5 越界误伤）⟹ **范围外编辑被误 BLOCK**（现场实证）。
# 判据两条（fail-loud；软链可跟随 ⟹ 合法沙箱 = `scripts` 软链到真 scripts/，仍通过）：
#   ① 落在文件系统/挂载根（`/`、`/mnt/<drive>`、Windows 盘根）⟹ 不可能是技能根；
#   ② 解析不到 `scripts/gk_state.py` ⟹ 疑自指软链 / 空沙箱（`/` 现场正是自指软链）。
if [ "$SKILL_DIR" = "/" ]; then
  echo '{"ok":false,"error":"SKILL_DIR_UNSAFE","skill_dir":"/","probe":"文件系统根","fix":"SKILL_DIR 解析到根目录 —— 疑似在错误 cwd（如 /）下运行；显式设置 SKILL_DIR 或用 install.sh 部署"}'; exit 2
fi
case "$SKILL_DIR" in
  /mnt/?|/mnt/?/|[A-Za-z]:|[A-Za-z]:/) 
    echo "{\"ok\":false,\"error\":\"SKILL_DIR_UNSAFE\",\"skill_dir\":\"$SKILL_DIR\",\"probe\":\"挂载根\",\"fix\":\"SKILL_DIR 解析到挂载根 —— 技能根必须在租户根之下\"}"; exit 2 ;;
esac
if [ ! -f "$SKILL_DIR/scripts/gk_state.py" ]; then
  echo "{\"ok\":false,\"error\":\"SKILL_DIR_UNSAFE\",\"skill_dir\":\"$SKILL_DIR\",\"probe\":\"scripts/gk_state.py 不可解析\",\"fix\":\"SKILL_DIR 不像技能根（疑自指软链/空沙箱）；用 LOOKUP_DIRS 兜底或 install.sh 部署\"}"; exit 2
fi
unset _SCRIPT_DIR _d
# ─── 路径形态转换单一事实源（2026-11-01，纯 bash 零外部依赖）──────────────────────
# 病灶（MSYS 跨平台 bug 家族）：原 13 处 `wslpath -w` 把路径转 Windows 形态，但 `wslpath`
#   **只在 WSL 存在** —— Git Bash(MSYS) 下恒空 ⟹ `|| echo ""` 产出空串 ⟹ fail-loud 拦停
#   （`WARN[gx-env] 解析 gitnexus 入口失败` → `unavailable` → `BASELINE_STALE` 硬拦质询）。
#   且同一语义散在 13 处手写、形态判断不一致（有的 `/mnt/*)` 守卫、有的无守卫裸调）。
# 正解 = 单一函数（不引 wslpath/cygpath 外部依赖 —— 那只是把 MSYS 依赖换成 WSL/MSYS 双依赖；
#   也不新增 inline_python bomb —— 纯 bash 字符串处理）：
#   · 已是 Windows 形态（`C:/` 或 `C:\`）⟹ 原样返回（Git Bash 下 MAIN_REPO 解析即此形）
#   · WSL 形态 `/mnt/<d>/…`              ⟹ `<D>:/…`
#   · MSYS 形态 `/<d>/…`                 ⟹ `<D>:/…`
#   · 其它（纯 POSIX `/home/…` 等）      ⟹ 原样（无法转换，交调用方 fail-loud，不臆造）
# 归一后两侧（WSL/MSYS）产出**同一形态** ⟹ 下游拼接/比较不再分叉。
# 2026-11-02（第二轮）：本组函数**前移**到启动块之前 —— 启动期的 state 路由
#   （`gk_route_center.py resolve-state`）就要把 POSIX 形态换成解释器形态；原地定义在其后
#   ⟹ 启动期调用 `_gk_py_path` 会 command not found（净效果 = 静默退回裸 POSIX）。
_gx_to_win_path() {
  local _p="${1:-}" _d
  [ -n "$_p" ] || { printf ''; return 0; }
  case "$_p" in
    [A-Za-z]:[\\/]*) printf '%s' "$_p"; return 0 ;;        # 已是 Windows 形态
    /mnt/[A-Za-z]/*)
      # `${_p#/mnt/?}` 剥 `/mnt/c` 后余下 `/Users/…`（已含前导斜杠）⟹ 只补盘符，禁再加斜杠
      _d="${_p#/mnt/}"; _d="${_d:0:1}"
      printf '%s:%s' "${_d^^}" "${_p#/mnt/?}" ;;
    /[A-Za-z]/*)
      _d="${_p#/}"; _d="${_d:0:1}"
      printf '%s:%s' "${_d^^}" "${_p#/?}" ;;
    *) printf '%s' "$_p" ;;                               # 纯 POSIX：原样
  esac
}
# ─── python 侧路径形态（2026-11-02，真因 D：解释器形态 ≠ bash 形态）──────────────
# 病象（worktree `scripts/gk_dbg.log` 实测，6 臂全中）：
#   · MSYS bash + **原生 Windows python** ⟹ `open('/c/Users/...')` → FileNotFoundError
#     ⟹ 外层报 `DUMP_REPORT_INVALID`（真因被伪装成「报告缺字段」；该告警**不阻断**）；
#   · 同一形态进 `sys.path.insert(0,'/c/.../scripts')` → ModuleNotFoundError
#     ⟹ history 落库块整段未执行 ⟹ `HISTORY_WRITE_FAILED`（**真丢数据**）。
# 口径 = **以解释器为锚**：Windows 原生解释器收 Windows 形态（复用 `_gx_to_win_path`
#   单源，认 `/c/` 与 `/mnt/c/`）；WSL/MSYS 解释器原样（它们自己认得 POSIX 形态）。
#   ⚠ 不用 `_gk_fwd`：它只把反斜杠转正斜杠，对 `/c/…` 是 no-op（实测修不动）。
# `GK_PY_FORM=win|posix` 仅供诊断/测试显式覆盖，缺省按解释器自报 `os.name` 判定（只探一次）。
_GK_PY_FORM_CACHE=""
_gk_py_form() {
  if [ -n "${GK_PY_FORM:-}" ]; then printf '%s' "$GK_PY_FORM"; return 0; fi
  if [ -n "$_GK_PY_FORM_CACHE" ]; then printf '%s' "$_GK_PY_FORM_CACHE"; return 0; fi
  local _f
  _f=$(python3 -c "import os;print('win' if os.name=='nt' else 'posix')" 2>/dev/null) || _f=posix
  case "$_f" in win|posix) ;; *) _f=posix ;; esac
  _GK_PY_FORM_CACHE="$_f"
  printf '%s' "$_f"
}
_gk_py_path() {
  if [ "$(_gk_py_form)" = "win" ]; then _gx_to_win_path "${1:-}"; else printf '%s' "${1:-}"; fi
}
SCHEMA_DIR="${SKILL_DIR}/monitor-schemas"
# ─── 子代理解释器 + 沙箱包裹（2026-10-31：**统一入口**，禁裸 python3 派发）────────────
# 病象：沙箱包装只接在 `cmd_monitor` 的 `$subagent_python` 一处 ⟹ cron agent / audit --crossr
#   / audit --report 三处仍裸 `python3 subagent_runner.py`，**绕过沙箱**；且包装器缺失时
#   `[ -x ]` 静默降级 ⟹ 用户以为「全 subagent 已沙箱」。本函数 = 唯一派发入口：
#   解释器序 = env（GK_PYTHON/SUAGENT_PYTHON/ACCEPT_PY）→ 本机 pin `scripts/_accept_py.local`
#   → 仓内 .venv → 通配发现 → `suagent_py311.sh` → `python3|python`（单源 = scripts/py_resolve.sh）；
#   `GK_SANDBOX_SUBAGENT≠0` ⟹ 套 `suagent_sandbox.sh`（层 1：mem/time/proc）；
#   包装器不可执行 ⟹ **fail-closed**（exit 2），仅 `GK_SANDBOX_FAIL_OPEN=1` 显式降级并留痕。
_subagent_py_real() {
  # 2026-11-01：**去硬编码** —— 原式把某个 /opt 隔离 venv 的绝对路径写死（公开包在别人机器上
  # 必然不存在 ⟹ 直接落到 python3，且与 Windows 侧同级解释器无法并列）。现统一委托
  # `scripts/py_resolve.sh`（发现式：env → 本机 pin → 仓内 .venv* → 通配 → PATH）。
  # 2026-11-01（owner 裁定 B 方案）：子代理**优先取依赖齐全**（openai/agents/pydantic）的
  #   解释器；理论上与 gitnexus 同侧 ⟹ 不再出现「Linux 解释器 spawn Windows 原生包」的混血。
  local py
  py=$(bash "${SKILL_DIR}/scripts/py_resolve.sh" subagent 2>/dev/null || true)
  if [ -z "$py" ]; then
    py=$(bash "${SKILL_DIR}/scripts/py_resolve.sh" any 2>/dev/null || true)
    [ -n "$py" ] && echo "WARN[py] 无满足 openai/agents/pydantic 的解释器 → 回落 any（$py）" >&2
  fi
  [ -n "$py" ] || py=python3
  printf '%s' "$py"
}
_subagent_exec() {
  local py wrap; py=$(_subagent_py_real); wrap="${SKILL_DIR}/scripts/suagent_sandbox.sh"
  if [ "${GK_SANDBOX_SUBAGENT:-1}" = "0" ]; then
    "$py" "$@"; return $?
  fi
  if [ -x "$wrap" ]; then
    GK_SUBAGENT_PY_REAL="$py" "$wrap" "$@"; return $?
  fi
  if [ "${GK_SANDBOX_FAIL_OPEN:-0}" = "1" ]; then
    echo "WARN[sandbox] wrapper missing → unsandboxed（GK_SANDBOX_FAIL_OPEN=1）" >&2
    "$py" "$@"; return $?
  fi
  echo '{"ok":false,"error":"SANDBOX_WRAPPER_MISSING","hint":"scripts/suagent_sandbox.sh 不可执行；修脚本，或显式 GK_SANDBOX_SUBAGENT=0 / GK_SANDBOX_FAIL_OPEN=1"}' >&2
  return 2
}
# 2026-10-28（A4）：monitor schema 查找的旧站别名回退。旧 3 站（SCAN/READ/AUDIT）schema 已删
# （禁第二份 schema 漂移源），别名站名仍可 monitor，但读规范站（RESEARCH/VERIFY）schema。
# 映射单源 = scripts/gk_node_guard.py 的 ECO_ALIASES（此处只查询，不复制表）。
_canon_schema_path() {
  local stage="$1" f="${SCHEMA_DIR}/${stage}.json"
  if [ -f "$f" ]; then echo "$f"; return 0; fi
  local canon
  canon=$(python3 "${SKILL_DIR}/scripts/gk_node_guard.py" canon --node "$stage" 2>/dev/null \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("canon",""))' 2>/dev/null) || return 1
  [ -n "$canon" ] && [ -f "${SCHEMA_DIR}/${canon}.json" ] && { echo "${SCHEMA_DIR}/${canon}.json"; return 0; }
  return 1
}
# 2026-08-13: 调试日志——python heredoc 异常不再被 2>/dev/null 静默吞掉（此前 549 处吞错导致静默失败难排查），
# 关键路径 stderr 追加到此处，供 self-check 安全网与人工排查（无条件定义，外部 STATE_FILE 时也必须可用）
GK_DBG_LOG="${SKILL_DIR}/scripts/gk_dbg.log"

# ─── A7 bash 直连快路（transport2，2026-10-29）────────────────────────────────
# 目的：绕开 python 客户端冷启（实测 ~0.15s/次，启动期两次 = 0.3s）。bash 内建 `/dev/tcp`
#   直连 loopback daemon（单行请求 / 单行响应），实测 ~5ms。
# 安全边界：① pidfile 存在且 pid 存活；② pidfile 第 5 行 == `transport2`（旧 daemon 自动不启用）；
#   ③ token 从 0600 pidfile 读、**不进 argv**；④ daemon **每请求自检 code_epoch**，代码一变即自退；
#   ⑤ 只服务启动期**只读** op（prelude / route_flat），无写面、无 eval。
# 失败面：任何一步失败 ⟹ 非零返回 ⟹ 调用方回退原 python 路径（判据面逐字不变）。
# ⚠ 必须在**顶层**定义：启动块的 sid 分支有 `if/else` 两路，嵌在分支里会漏定义。
_wk_pidfile="${GK_WORKER_PIDFILE:-${HOME:-/root}/.gatekeeper/worker.pid}"
_gk_wreq() {   # $1=op $2=text-field ; 其余 = k=v（值做最小 JSON 转义）
  local _op="$1" _tf="$2"; shift 2
  local _pf="${_wk_pidfile:-}" _pid="" _port="" _tok="" _ep="" _tr=""
  [ "${GK_WORKER_DISABLE:-0}" = "1" ] && return 1
  [ -n "$_pf" ] && [ -f "$_pf" ] || return 1
  { IFS= read -r _pid; IFS= read -r _port; IFS= read -r _tok; IFS= read -r _ep; IFS= read -r _tr; } <"$_pf" 2>/dev/null || return 1
  [ "$_tr" = "transport2" ] || return 1
  case "${_port:-}" in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "${_pid:-0}" 2>/dev/null || return 1
  local _args="" _kv _k _v
  for _kv in "$@"; do
    _k="${_kv%%=*}"; _v="${_kv#*=}"
    _v="${_v//\\/\\\\}"; _v="${_v//\"/\\\"}"; _v="${_v//$'\n'/}"; _v="${_v//$'\r'/}"
    _args="${_args}${_args:+,}\"${_k}\":\"${_v}\""
  done
  local _req="{\"auth\":\"${_tok}\",\"op\":\"${_op}\",\"text\":\"${_tf}\",\"args\":{${_args}}}" _line=""
  exec 9<>"/dev/tcp/127.0.0.1/${_port}" 2>/dev/null || { exec 9<&- 9>&- 2>/dev/null; return 1; }
  printf '%s\n' "$_req" >&9 2>/dev/null || { exec 9<&- 9>&- 2>/dev/null; return 1; }
  IFS= read -r -t 0.3 _line <&9 2>/dev/null
  exec 9<&- 9>&- 2>/dev/null
  case "$_line" in
    "OK "*) printf '%s\n' "${_line#OK }"; return 0 ;;
  esac
  return 1
}
# 与 `gk_worker_client.env_snapshot()` 同口径（前缀 `GK_`/`GATEKEEPER_` + 精确集）：
# daemon 的 env 是首启时冻结的 ⟹ 路由判定所需 env 必须按请求携带。
_gk_wenv_pairs() {
  local _n
  for _n in $(compgen -e); do
    case "$_n" in
      GK_*|GATEKEEPER_*|STATE_FILE|STATE_FILE_EXPLICIT|PLAN_POINTER|PLAN_FILE|HOME|PWD)
        printf 'env__%s=%s\n' "$_n" "${!_n}" ;;
    esac
  done
}

# ─── R19（2026-09-22）：副本 `.keys` 继承 —— 软链单源 + 主工作树派生 ───
# 病象（§4.7.0 实测）：`git worktree add` **不带未跟踪文件** ⟹ worktree 副本无 `.keys/`
#   ⟹ `context --update` 能重建 ctx 却 `{"ok":false,"error":"context sign failed"}`
#   ⟹ 派发恒被 `CONTEXT_STALE_OR_UNSIGNED` 拦，且 L3113 自愈门与失败态同源（**结构性失效**）。
# 纪律（沿用 `7ef0ee4`）：继承「身份/密钥/治理范围」面、**隔离「状态」面**；**软链单源**（非复制）。
# 源派生：`git worktree list --porcelain` **首项 = 主工作树**（= 主副本）—— 不硬编码宿主路径
#   （对齐 §4.5 ECC-PLAN ①：原字面量路径在非本机宿主恒不命中）。
# 侵入面控制：仅在 `.keys` **缺失**时才走派生 ⟹ **稳态零成本**；建链失败**不硬退**
#   （下游签名本就 fail-loud —— 见 `audit --key fingerprint` 空集 fail-loud），只留日志，
#   以免打断 `status` 等只读诊断。硬退只保留在 `--isolate` 自建副本处（那里是抛弃型沙箱，可安全拒绝）。
# 关闭开关：`GK_KEYS_INHERIT=0`
_keys_inherit_src() {
  local _mwt
  # R19-b（2026-09-22，bashpy bomb 修复 + L2 交叉审查 failed#4 同批修）：原命令携带
  #   「丢弃 stderr」重定向（**此处刻意不自陈其字面形态** —— 否则注释自身即成扫描命中，
  #   即「自指陷阱」：修 bomb 的注释又被同一扫描器判为 bomb）
  #   同时是 ⓐ `stderr_swallow` 打击点（本批实测：bomb 增量的**唯一**来源）
  #   ⓑ 「失败真因不可诊断」的成因（L2 复核：失败只落 GK_DBG_LOG + 吞 stderr，用户仍只见
  #   下游 `sig_invalid`/`CONTEXT_STALE_OR_UNSIGNED` ⟹ 判据指向错误方向未消除）。
  #   改为**追加进 GK_DBG_LOG**：诊断可达、且不再吞。
  _mwt=$(git -C "$SKILL_DIR" worktree list --porcelain 2>>"$GK_DBG_LOG" | sed -n 's/^worktree //p' | head -1)
  [ -n "$_mwt" ] || return 1
  # 2026-10-27 修复（U12 成因）：原为**逐字**比较 `[ "$_mwt" != "$SKILL_DIR" ]` —— 当两端**路径形态
  #   不同**（Windows `C:/…` vs WSL `/mnt/c/…`）时判「不相等」，于是「自身即主树」被误判成
  #   「有主副本可继承」⟹ `ln -s <自身>/.keys <自身>/.keys` 落进已存在目录，生成
  #   `.keys/.keys -> .keys` 自指软链（实测 2026-10-14 12:50，炸 copytree/打包 `Errno 40`）。
  #   改为 realpath 归一比较；解析失败时回退逐字比较（fail-closed：宁可不继承，也不造自指链）。
  _mwt_r=$(realpath "$_mwt" 2>/dev/null || printf '%s' "$_mwt")
  _sd_r=$(realpath "$SKILL_DIR" 2>/dev/null || printf '%s' "$SKILL_DIR")
  if [ "$_mwt_r" = "$_sd_r" ]; then
    unset _mwt_r _sd_r
    return 1
  fi
  unset _mwt_r _sd_r
  [ -d "$_mwt/.keys" ] || return 1          # 源无 .keys ⟹ 不继承（下游会显式失败，不静默）
  printf '%s' "$_mwt"
}
if [ "${GK_KEYS_INHERIT:-1}" != "0" ] && [ ! -e "$SKILL_DIR/.keys" ]; then
  if _KEYS_SRC="$(_keys_inherit_src)"; then
    # 双保险：linkname 若已存在目录，`ln -s` 会把链接落进目录内（自指事故的落点形态）。
    if [ -e "$SKILL_DIR/.keys" ] || [ -L "$SKILL_DIR/.keys" ]; then
      echo "[r19] WARN .keys appeared before link (skip) $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
    elif ln -s "$_KEYS_SRC/.keys" "$SKILL_DIR/.keys" 2>>"$GK_DBG_LOG"; then
      echo "[r19] .keys inherited <- $_KEYS_SRC/.keys $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
    else
      # 失败真因**必须可达下游**（否则 R19 病象的「判据指向错误方向」原样复现）：
      # 除落日志外，置 env 供 `_review_channel_preflight` 在 JSON 报文里**附真因**。
      echo "[r19] WARN .keys inherit failed (src=$_KEYS_SRC) $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
      export GK_R19_KEYS_INHERIT_FAILED="src=$_KEYS_SRC"
    fi
  fi
fi
unset _KEYS_SRC
# 默认 state 落点（**契约常量**，2026-09-15 REV-5 / 质询 N2）：域解析（L4 1b）的命名基址
# = **默认 state 同级** —— 落点 `.gatekeeper.state.<token>`，与 `gk_finding.resolve_domain_state`
# 的 `Path(state_file).with_name(_STATE_PREFIX + "." + token)` 同源。改此常量即改全局基址；
# 域块**不得**再内联此字面量（否则基址双份、判据不可判别）。
# ─── 解释器引导：把**解析到的 python** 前置到 PATH（2026-11-02，owner「Windows 也要能用」）──
# 病灶：CLI 内有大量**裸 `python3`** 调用（签名 `_sign_raw` / 路由 / 状态查询…）。它们吃的是
#   PATH 上的解释器 —— 本机实测落到 WorkBuddy 自带 3.13（**无 `cryptography`**）⟹ 签名崩
#   ⟹ `.sig` 空 ⟹ 前置门报 `CONTEXT_STALE_OR_UNSIGNED / sig_invalid`（真因被伪装成"上下文过期"）。
# 正解：启动时**解析一次**（单一事实源 `scripts/py_resolve.sh`：env → 平台标记 pin → 仓内
#   `.venv*`（含 worktree 的主树回落）→ 通配 → PATH），把其目录前置 ⟹ 之后所有裸 `python3`
#   自动同源。**不改任何调用点**（32 处内联拼接维持原样，零漂移面）。
# 兜底：解析失败/解释器不存在 ⟹ 不动 PATH（保持旧行为，不制造新的失败面）。
_gk_py_boot=""
_gk_py_boot=$(bash "$SKILL_DIR/scripts/py_resolve.sh" any 2>/dev/null || true)
case "$_gk_py_boot" in
  */*)
    if [ -x "$_gk_py_boot" ]; then
      _gk_py_dir="$(cd "$(dirname "$_gk_py_boot")" 2>/dev/null && pwd)" || _gk_py_dir=""
      if [ -n "$_gk_py_dir" ]; then
        case ":$PATH:" in
          *":$_gk_py_dir:"*) : ;;                       # 已在 PATH 上，不重复前置
          *) PATH="$_gk_py_dir:$PATH"; export PATH ;;
        esac
      fi
      unset _gk_py_dir
    fi ;;
esac
unset _gk_py_boot
# ─── 路径形态归一：单一事实源（2026-11-02，真因 C）────────────────────────────
# 病象：仓内 32 处 `python3 -c "... open('$STATE_FILE') ..."` 是**内联拼接**。值若含 Windows
#   反斜杠，python 源码里就出现 `'<home>'` ⟹ `\U` 触发 `unicodeescape` SyntaxError。
#   实测现场：`_lk=state_lock('<home>\...')` 整行语法错 ⟹ 锁没取到、state 没写，
#   而症状被上层报成「域判定失败」（又一次真因被伪装）。
#   逐个改成 env 传参的收益远小于风险（32 处，多数在无测试覆盖的审计/收口路径）。
#   正解 = **一个变量只允许一种形态**：凡是**外部来源**（路由中枢 / 跨进程注入 / git 输出）
#   进入 `STATE_FILE` / `SKILL_DIR`，在此归一为**正斜杠形态** ——
#   Windows API、MSYS bash、python 三方都接受；反斜杠不是。
_gk_fwd() { local _p="${1:-}"; printf '%s' "${_p//\\//}"; }
_DEFAULT_STATE_FILE="${SKILL_DIR}/.gatekeeper.state"
# 方案 A（2026-09-23 用户裁定，ECC-B8974A514E81）：技能仓的 **git worktree** 与主树是**同一
# 治理对象** ⟹ 默认 state 落点归**主树**。与 `pre_tool_hook._resolve_state_by_target_path` 的
# 同批归一**必须成对** —— 只改一侧会得到「hook 读主树 / CLI 写 worktree」的读写分裂
# （表现为「advance 了但门禁没变」，正是 ECC-B8974A514E81 的现场）。
# ⚠ 预筛廉价：非常态路径**零成本**（无 git 调用）；仅 `*/worktrees/*` 形态才解析一次。
# ⚠ 双保险：git 不可用 / 解析为空 / 主树 state 不存在 ⟹ 保持原落点（fail-safe，不新造路径）。
case "$SKILL_DIR" in
  */worktrees/*)
    _gk_common="$(git -C "$SKILL_DIR" rev-parse --git-common-dir 2>/dev/null)"
    if [ -n "$_gk_common" ]; then
      _gk_main="$(cd "$SKILL_DIR" 2>/dev/null && cd "$(dirname "$_gk_common")" 2>/dev/null && pwd)"
      if [ -n "$_gk_main" ] && [ -f "$_gk_main/.gatekeeper.state" ]; then
        _DEFAULT_STATE_FILE="$_gk_main/.gatekeeper.state"
      fi
    fi
    unset _gk_common _gk_main
    ;;
esac
# 2026-10-27 修复（ECC-67C0B937A54B 窄面落刀的副作用）：`GK_SID_TAG` 原先只在下方
# 「STATE_FILE 未显式」分支内赋值，而路由块（`if [ -n "$_gkr_route" ]`）无条件引用它 ⟹
# 显式注入 STATE_FILE（测试/集成/hook Gate4）时 `set -u` 报 `unbound variable`，整条 CLI 崩溃。
# 处置：先给全局缺省值，分支内解析到 sid 后再覆盖（搜索 `GK_SID_TAG="sid=`）。
GK_SID_TAG="sid=none"
# 2026-08-23: 外部显式 STATE_FILE（测试/集成注入，如基线对比/隔离 state 副本）
# 优先于默认 + plan 指针；未显式设置时保持原行为（默认 state + plan 指针状态机驱动）。
# 对齐 pre_tool_hook.py 的 STATE_FILE 环境变量优先模式（L32-35）。
# 2026-10-30（环境坑加固）：**显式设置但为空** 的 `STATE_FILE` 是**注入失败**，不得当「未设置」
#   静默回落默认 state。现场（本会话实测）：外层 shell 把 `$VAR` 吞掉后 `STATE_FILE="$ST"` 退化为
#   `STATE_FILE=` ⟹ 原 `[ -z ... ]` 分支把它当缺省 ⟹ finding 查不到 / 写错台账，症状却伪装成
#   「族判定失败」。判据 = set-but-empty（`+x` 区分「未设置」）；rc=2 = 参数错误（对齐 usage 语义）。
if [ -n "${STATE_FILE+x}" ] && [ -z "$STATE_FILE" ]; then
  echo "ERROR[state-routing]: STATE_FILE 显式设置但为空（常见成因：调用方变量未展开/被外壳吞掉）" >&2
  echo '{"ok":false,"error":"STATE_FILE_EMPTY","channel":"state-routing","fix":"去掉该 env 让其走默认 state，或给出非空绝对路径；本 CLI 拒绝把空串当未设置"}'
  exit 2
fi
if [ -z "${STATE_FILE:-}" ]; then
  STATE_FILE="$_DEFAULT_STATE_FILE"
  STATE_FILE_EXPLICIT=0

  # ── 会话身份自解析（§4.13.5「高并发②」使能切片，2026-09-25）──
  # hook 每次 PreToolUse 把本次调用的 sid 落到 `<SKILL_DIR>/.gatekeeper.session`（单行
  # `sid \t epoch \t tool \t cwd`，原子写）。PreToolUse **先于**工具执行 ⟹ **同一次工具调用内**
  # 启动的本 CLI 能读到同一 sid ⟹ agent 侧与 hook 侧携带同一身份（此前 agent 侧无身份 ⟹
  # 编辑预算等落**全局平面**，与 hook 的**会话平面**分叉 = 两套账）。
  # fail-safe：env 已显式给出 ⟹ 不覆盖；文件缺失 / 形态非法（非 24 位 hex）/ 超窗 ⟹ 保持空
  # （= 既有全局口径，**零回归**）。逃生/调参 = `GK_SESSION_TTL`（秒，默认 1800，对齐 hslsn 量级）。
  # ⚠ 位置：必须在 **plan 指针选择之前** —— 指针按会话分片（§4.13.5②「会话级句柄」）依赖本 sid。
  # ── 身份链 Q3a（2026-10-02，平台无关兜底）：env > worktree token > marker(legacy) ──
  # 平台无关兜底（finding ECC-AB2FA16E9133）：由本进程 `$PWD` 所在 git worktree 派生身份
  #   token（`agent/session/<leaf>` / `agent/<family>/<leaf>` → leaf；其余哈希兜底）。**不依赖
  #   任何宿主 hook API** ⟹ Trae / WorkBuddy 通用；worktree 天然按会话隔离 ⟹ 无共享单槽、
  #   无竞态（非概率缓解）。解析单源 = scripts/gk_session_identity.py（禁第二实现）。
  if [ -z "${GK_SESSION_ID:-}" ] && [ -n "${PWD:-}" ]; then
    _gs_tok=""
    _gs_pre_ok=0
    # 快路（A7）：bash `/dev/tcp` 一次往返取 sid（`derive` 是纯函数，daemon 只付一次 import）。
    # 判据用**退出码**而非「非空」：路径不在 dev worktree 树内时 derive 合法地返回空串，
    # 若按空值回退就会白付一次 0.19s 冷启（实测本仓 CWD 常态即如此）。
    if _gs_tok=$(_gk_wreq prelude sid "pwd=$PWD"); then
      _gs_pre_ok=1
    fi
    [ "$_gs_pre_ok" = "1" ] || _gs_tok=$(python3 "$SKILL_DIR/scripts/gk_session_identity.py" derive --path "$PWD" 2>>"$GK_DBG_LOG" || true)
    unset _gs_pre_ok
    case "${_gs_tok:-}" in
      ""|*[!0-9A-Za-z_-]*) ;;                       # 空 / 含非法字符（保文件名安全）⟹ 不采纳
      *) export GK_SESSION_ID="$_gs_tok" ;;
    esac
    unset _gs_tok
  fi
  if [ -z "${GK_SESSION_ID:-}" ] && [ -f "${SKILL_DIR}/.gatekeeper.session" ]; then
    _gs_id="" _gs_ts="" _gs_tool="" _gs_mcwd="" _gs_take=0
    IFS=$'\t' read -r _gs_id _gs_ts _gs_tool _gs_mcwd < "${SKILL_DIR}/.gatekeeper.session" 2>/dev/null || true
    case "${_gs_id:-}" in ""|*[!0-9a-f]*) ;; *) [ "${#_gs_id}" = "24" ] && _gs_take=1 ;; esac
    case "${_gs_ts:-}" in ""|*[!0-9]*) _gs_take=0 ;; esac
    if [ "$_gs_take" = "1" ]; then
      _gs_age=$(( $(date +%s) - _gs_ts ))
      if [ "$_gs_age" -ge 0 ] && [ "$_gs_age" -le "${GK_SESSION_TTL:-1800}" ]; then
        # 2026-10-07 竞态修复（卫星遗留衍生问题：会话身份路由的并发缺陷）───────────────
        #   病象：`.gatekeeper.session` 是**单槽**，任意并发会话/subagent 的 PreToolUse 都会覆写它；
        #     若本会话**不在 worktree 树内**（`gk_session_identity.derive` → token=""，见其 §2
        #     “不在 worktree 树 → 回落全局”），则单槽分支被走到 ⟹ **采纳外来 sid**；外来 sid 的
        #     `.gatekeeper.plan.<sid>` 不存在 ⟹ 静默落**默认 state**，与 `list` 读到的域不一致
        #     （实测：submit 落默认 / list 读他域；2026-09-28 已删“采纳全局”劫持分支，但单槽
        #     覆写这条通道仍在）。
        #   判据 = **同源校验**：marker 第 4 列记了**写入时 cwd**（`pre_tool_hook._write_session_marker`
        #     单行 `sid<TAB>epoch<TAB>tool<TAB>cwd`）——同一工具调用内 hook 与 CLI 的 cwd 相同 ⟹
        #     仅当 `_gs_mcwd` 与本调用 `${PWD}` **一致**（分隔符归一）才采纳；否则**不采纳**，回落
        #     全局/默认（= 注释所述“文件缺失/形态非法 ⟹ 保持空 = 既有全局口径，零回归”，无竞态）。
        #   ⚠ 只加同源门，不动单槽面本身（兼容面不变；分片 `.gatekeeper.session.<sid>` 仍在，供诊断）。
        _gs_mcwd_n="${_gs_mcwd//\\//}"
        _gs_pwd_n="${PWD//\\//}"
        # ECC-8CEA5388F1DC（2026-10-07）：**形态归一** —— marker 第 4 列记**宿主**形态
        #   （`c:/Users/HP`），本调用 `${PWD}` 为 **WSL** 形态（`<home>`）⟹ 原**逐字**
        #   比较对**非 worktree 调用者恒假** ⟹ `GK_SESSION_ID` 恒空 ⟹ `discover --plan` 退写
        #   **全局** `.gatekeeper.plan` = 跨会话路由污染（实测：全局指针 mtime/内容 = 本会话
        #   discover；分片指针 `.gatekeeper.plan.<sid>` 未被写）。两端归一到
        #   `/mnt/<小写盘符>/…` 后比较，恢复同源门的判别力（对齐 `gk_state_route._norm` 双形态口径）。
        case "$_gs_mcwd_n" in
          [A-Za-z]:/*) _gs_mcwd_n="/mnt/$(printf '%s' "${_gs_mcwd_n%:*}" | tr 'A-Z' 'a-z')${_gs_mcwd_n#*:}" ;;
        esac
        case "$_gs_pwd_n" in
          [A-Za-z]:/*) _gs_pwd_n="/mnt/$(printf '%s' "${_gs_pwd_n%:*}" | tr 'A-Z' 'a-z')${_gs_pwd_n#*:}" ;;
        esac
        if [ -n "${_gs_mcwd_n}" ] && [ "${_gs_mcwd_n}" = "${_gs_pwd_n}" ]; then
          export GK_SESSION_ID="$_gs_id"
        fi
        unset _gs_mcwd_n _gs_pwd_n
      fi
    fi
    unset _gs_id _gs_ts _gs_tool _gs_mcwd _gs_take _gs_age
  fi

  # ── 会话身份**丢绑**诊断（2026-10-01，会话隔离 finding；实测复现）─────────────
  # 病象：`.gatekeeper.session` 是**单槽**，任意并发会话（含 subagent）的 PreToolUse 都会覆写
  #   它 ⟹ 本会话 CLI 自解析到**外来 sid**；其 `.gatekeeper.plan.<sid>` 不存在 ⟹
  #   `select_plan_pointer` 返回 `no_pointer_file`，而该 reason **无任何 WARN**（见下方 case，
  #   原先只覆盖 stale/cmd_target_mismatch/strict/domain_route_off）⟹ **静默**把本次调用的读写
  #   落到**默认 state**（实测：6 条 `plan-refinement --task` 入队 1→域 / 5→默认，静默无提示）。
  # 判据（**窄面**：仅当「有 sid 却无本会话指针」**且**「确有其它会话绑定」时触发）——
  #   避免对「从未 discover 过的新会话」这条常见合法路径刷屏。
  # 默认**变响**（WARN）；`GK_STATE_ROUTE_SESSION_STRICT=1` 升级为 **fail-closed**（禁静默落默认）。
  if [ -n "${GK_SESSION_ID:-}" ] && [ ! -f "${SKILL_DIR}/.gatekeeper.plan.${GK_SESSION_ID}" ]; then
    _gs_other=""
    for _gs_pf in "${SKILL_DIR}"/.gatekeeper.plan.*; do
      [ -e "$_gs_pf" ] || continue
      [ "$_gs_pf" = "${SKILL_DIR}/.gatekeeper.plan.${GK_SESSION_ID}" ] && continue
      _gs_other="$_gs_pf"
      break
    done
    unset _gs_pf
    if [ -n "$_gs_other" ]; then
      _gs_other_name="$(basename "$_gs_other")"
      echo "WARN[session-identity]: sid=${GK_SESSION_ID} 无本会话指针，但他会话绑定存在（${_gs_other_name}）— 疑并发会话覆写 .gatekeeper.session；本调用将回落**默认 state**（可能写错账）" >&2
      echo "WARN[session-identity]: session pointer missing for sid=${GK_SESSION_ID} (other bound: ${_gs_other_name})" >> "$GK_DBG_LOG"
      if [ "${GK_STATE_ROUTE_SESSION_STRICT:-0}" = "1" ]; then
        echo "{\"ok\":false,\"error\":\"SESSION_POINTER_MISSING\",\"session_id\":\"${GK_SESSION_ID}\",\"other_bound\":\"${_gs_other_name}\",\"channel\":\"state-routing\",\"fix\":\"本会话先 discover --plan 建立绑定；或 GK_STATE_ROUTE_SESSION_STRICT=0 关闭严格模式\"}"
        exit 1
      fi
    fi
    unset _gs_other _gs_other_name
  fi

# ── 诊断日志**窄面归因**（ECC-67C0B937A54B，2026-10-26）──────────────────────────
# 病象：`GK_DBG_LOG` 单路径、225 写点共用 ⟹ 跨会话混写，读侧无法按会话归因（实测案例 =
#   并发论文会话的 `[state-routing]` WARN 混入质询日志）。
# 本轮处置 = **窄面**：只给「路由族」日志（`[state-routing]` / `[plan-pointer]`）追加 `sid=` 标签，
#   读侧可 `grep "sid=<sid>"` 归因；**不改路径、不改读者** ⟹ 无读分裂风险。
# 全量「诊断日志卫星」（`<state>.dbglog-archive`，唯一写入者=中枢 + 读侧 union）**本轮具名拒用**，
#   理由与触发条件见 `docs/plans/2026-10-04-state-satellite-storage-plan.md` §4 诊断日志卫星条。
GK_SID_TAG="sid=${GK_SESSION_ID:-none}"

  # ── Plan 指针（batch8 advance 竞态修复，2026-08-03）──
  # discover --plan 将隔离 state 路径写入指针；后续任意进程（advance/guard-edit 等）
  # 启动时自动恢复隔离 state，实现 discover→advance 跨进程联动（状态机驱动）。
  # discover（无 --plan）清除指针，回到默认 state。
  # Phase 7b (2026-08-23): 指针 TTL — updated 超 24h 视为失效（对齐 Hermes grace 过期模式，
  # Phase 7c A1）。过期 → WARN + 忽略 + 自愈清理；悬空指针（state_file 不存在）不清理。
  # 2026-09-25（§4.13.5②「会话级句柄」落刀）：指针**跟随目标**（读）三级优先 ——
  #   ① env `PLAN_POINTER`（显式注入；此前只有 route center 认、启动块不认 = 该缺口闭合）
  #   ② 会话指针 `.gatekeeper.plan.<sid>`（本会话自身绑定；sid 已知且文件实存）
  #   ③ 全局 `.gatekeeper.plan`（既有行为 = 零回归）
  # 与 `_PLAN_POINTER_OWN`（**写 / 清**目标）分离：有会话身份时写/清只动**本会话**指针 ⟹
  #   会话间不再互相清掉绑定（病象：会话 B 的 `discover`（无 --plan）rm 掉会话 A 刚写的全局
  #   指针 ⟹ A 静默回落默认 state = 抢写同一 state）。
  # ── F-3 收口（2026-09-27，`ECC-D44630007AE9`）：「命令→计划」透传 ──
  #   命令可经 env `GK_CMD_TARGET_PLAN`（目标计划 basename，与 discover 写指针同口径 = `basename <plan>.md`）
  #   显式声明目标；对**已知携带计划位置参**的命令（plan-refinement / plan-lint）自动派生。
  #   供下方指针对账（显式目标 ≠ 指针计划 ⟹ 不跟随）。
  if [ -z "${GK_CMD_TARGET_PLAN:-}" ]; then
    case "${1:-}" in
      plan-refinement|plan-lint)
        if [ -n "${2:-}" ] && [ -e "${2}" ]; then
          GK_CMD_TARGET_PLAN="$(basename "${2}" .md)"; export GK_CMD_TARGET_PLAN
        fi ;;
    esac
  fi
  _PP_FOLLOWED=false
  # ③ 单源（`ECC-1EC0E0732F0D`）：**指针选择已收进 python** —— 下方 `_gkr_route` 调用内先跑
  #   `select_plan_pointer`（TTL 24h / 命令对账 / strict / 域 kill switch / `/mnt↔C:` 双形态
  #   探测全在其内部）再解析 state。本块**零判定**；`_PLAN_POINTER*` / `_PP_FOLLOWED` 一律由
  #   返回值回填（见解析段）。历史语义（2026-09-28 跨会话劫持修复「有身份 ⟹ 只认本会话指针」/
  #   2026-09-27 F-3 命令对账 / REV-5 域 kill switch）**全部保留**，唯一实现体在 python。
  :
  # 2026-09-28（并发写 · **跨会话劫持修复**）：**删除**「有会话身份但本会话无绑定 → 回退全局」
  #   分支。原分支让「有身份、本会话无自身指针」的命令**静默采纳**全局指针（属他会话/僵尸）
  #   ⟹ 跨会话绑定劫持（实测：某会话的 `finding register` 因此把 finding 写进**别的计划**的
  #   域 state，id 落错台账 = 2026-09-28 现场）。现语义：**有**身份 ⟹ 只认本会话指针，其缺失
  #   = 无绑定 ⟹ 回落默认 state；**无**身份（真·单会话 / 手工）⟹ 仍认全局（`_PLAN_POINTER_OWN`
  #   已落全局 ⟹ 逐字零回归，护栏 = test_gk_edit_budget_metering::test_arm25）。

  # （原内联指针读取 / TTL / 命令对账 / strict / 域 kill switch / 跨形态探测块已删除 —— ③ 单源）
else
  # 显式 env STATE_FILE（测试/集成注入/论文仓库等治理对象）— 保持不覆盖，标记显式态。
  # 2026-08-28 修复：discover（无 --plan）此前无条件复位默认，覆盖显式 env（用户质询"env 覆盖"）。
  STATE_FILE_EXPLICIT=1
  # 2026-09-25（②b）：env `PLAN_POINTER` 显式给出时启动块**认它**（§4.13.5② 记的缺口：
  # 此前只有 route center 认、启动块不认）；显式 STATE_FILE 下 `own` 由 python 回空
  # ⟹ 本进程**不写不删**指针（既有设计：没有指针通道，也无权动他会话的绑定）。
fi; _main_repo_resolve  # 2026-10-31：STATE_FILE 已定，解析主仓（env→state→META→git）
# ── state 路由弹性安全网（batch8 R-T6，2026-08-20）──
# 校验解析到的 state 归属（state.worktree 应标识技能仓库）；冲突时自动
# 纠正到匹配的隔离 state（恰好 1 个候选），否则仅 WARN（防误纠）。
# plan 指针优先（gk_state_route.py 尊重指针，corrected 恒 False）。
# 2026-09-25（§4.13.5「全序列打通①」）：`--derive-domain` —— 启动块亦受理**会话级计划**
#   （env `GK_PLAN_FILE`）声明的 `META.state_domain` ⟹ 1b 步在 CLI 链上**可达**（修前本调用
#   不传 plan/domain ⟹ 1b 恒不触发）。未设该 env / 计划未声明域 ⟹ 与既有链**逐字一致**。
# 2026-09-25（②b）：把**已选定**的指针显式传给中枢 ⟹ 启动块与 `resolve-state` 按**同一**指针
#   判定（否则中枢会自行回退到全局 `.gatekeeper.plan`，抹掉会话分片）；同时闭合 §4.13.5② 记的
#   「env `PLAN_POINTER` 只有 route center 认、启动块不认」缺口。
# ③ 单源（`ECC-1EC0E0732F0D`）：`--skill-dir "$SKILL_DIR"` **必须**走 argv —— bash 的 SKILL_DIR
#   自 `$0` 推导（非 env 注入面，见 L56-73），而 `gk_route_center.main` 会**丢弃不可信 env
#   `SKILL_DIR`**（沙箱 / 非本仓路径的名字不符 + 非 git worktree ⟹ 判不可信）⟹ 只传 env 会被
#   抹成 DEFAULT_SKILL ⟹ 指针选择读到**真仓**指针（沙箱/等价目录里恒不跟随 = 零回归失效）。
#   argv `--skill-dir` = 调用方显式意图（不受信任门限制），与既有 pointer 语义逐字一致。
# 2026-10-29（A7 接线 / 启动提速）：先试**已存活** worker 的快路 —— `--if-alive` 绝不 autostart
#   （冷启 1.7s > 它要省的 ~600ms）、`--epoch-auto` 拒绝旧代码 daemon、`--timeout 0.25` 保证
#   daemon 卡死也不阻塞门禁。未启 / epoch 不符 / 超时 / 坏包 ⟹ **一律回退**下面原调用，
#   判据面（12 字段解析）逐字不变。开关 `GK_WORKER_DISABLE=1` 完全关闭（缺省启用）。
#   零成本保证：pidfile 不存在时**不 spawn 客户端**（bash `-f` 判据，~0.1ms）。
# 2026-10-29（A7 读面收敛）：快路改为取 **`--field flat`** —— daemon 一次往返同时完成
#   `resolve-state` + 12 字段格式化（原先 = route 一次 spawn + parse 一次 spawn）。
#   成品串与内联 payload 逐字等价（单源 `gk_route_center.flat_route`，由 test 对拍）。
_gkr_route=""
_gkr_parsed=""
# bash 直连快路（A7）：daemon 一次往返返回**成品 12 字段串**（route + 格式化），失败即回退。
mapfile -t _gkr_envpairs < <(_gk_wenv_pairs)
_gkr_parsed=$(_gk_wreq route_flat flat "skill_dir=$SKILL_DIR" "derive_domain=1" "${_gkr_envpairs[@]}") || _gkr_parsed=""
unset _gkr_envpairs
[ -n "$_gkr_parsed" ] && echo "INFO[state-routing]: worker fast path hit pidfile=$_wk_pidfile $GK_SID_TAG" >> "$GK_DBG_LOG"
[ -z "$_gkr_parsed" ] && _gkr_route=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" STATE_FILE="$(_gk_py_path "$STATE_FILE")" STATE_FILE_EXPLICIT="${STATE_FILE_EXPLICIT:-0}" PLAN_POINTER="${PLAN_POINTER:-}" python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-state --derive-domain --skill-dir "$SKILL_DIR" 2>>"$GK_DBG_LOG" || echo '{}')
if [ -n "$_gkr_route" ] || [ -n "$_gkr_parsed" ]; then
  # 单次 spawn 解析全部字段（L2 交叉审查 2026-08-20: 原 5 次 spawn → 1 次；
  # 解析失败显式写 GK_DBG_LOG，不再静默失效）
  # A7：快路已给出成品串 ⟹ 跳过本 spawn（判据面不变）。
  [ -z "$_gkr_parsed" ] && _gkr_parsed=$(python3 -c "
import sys,json
try:
    d=json.loads(sys.argv[1])
except Exception:
    print('')
    sys.exit(0)
print('|'.join([str(d.get('corrected',False)), d.get('expected',''), str(d.get('conflict',False)), (d.get('warning') or '').replace('|','/'), d.get('source',''), (d.get('error') or ''), str(d.get('own','')), str(d.get('pointer','')), str(d.get('pointer_followed',False)), str(d.get('pointer_reason','')), str(d.get('pointer_plan','')), str(d.get('pointer_domain',''))]))
" "$_gkr_route" 2>>"$GK_DBG_LOG")
  if [ -z "$_gkr_parsed" ]; then
    echo "WARN[state-routing]: parse failed $GK_SID_TAG" >> "$GK_DBG_LOG"
  else
    IFS='|' read -r _gkr_rc _gkr_rexp _gkr_conf _gkr_w _gkr_src _gkr_err _gkr_own _gkr_ptr _gkr_pfol _gkr_preason _gkr_pplan _gkr_pdom <<< "$_gkr_parsed"
    # ③ 单源（`ECC-1EC0E0732F0D`）回填：`_PLAN_POINTER*` / `_PP_FOLLOWED` 的唯一来源 = python
    #   返回值（下方 discover 的写/清、`_disc_clear_pointer`、末尾 `_PP_FOLLOWED` 判据均消费它们）。
    _PLAN_POINTER_OWN="${_gkr_own:-}"
    _PLAN_POINTER="${_gkr_ptr:-}"
    _PP_FOLLOWED="$(printf '%s' "${_gkr_pfol:-False}" | tr 'A-Z' 'a-z')"
    # 既有 WARN 文案（保真回放）：判定在 python（`select_plan_pointer.reason`），文案仍在 bash。
    case "${_gkr_preason:-}" in
      stale)
        echo "WARN[plan-pointer]: stale (>24h) — ignored, fallback default state (Phase 7b TTL)" >&2
        echo "WARN[plan-pointer]: stale (>24h) — ignored, fallback default state (Phase 7b TTL) $GK_SID_TAG" >> "$GK_DBG_LOG"
        rm -f "$_gkr_ptr" 2>/dev/null || true ;;
      cmd_target_mismatch)
        echo "WARN[plan-pointer]: 命令计划(GK_CMD_TARGET_PLAN=${GK_CMD_TARGET_PLAN:-}) ≠ 指针 plan($_gkr_pplan) — 不跟随（防跨计划劫持）" >&2
        echo "WARN[plan-pointer]: cmd-target-plan mismatch — pointer ignored $GK_SID_TAG" >> "$GK_DBG_LOG" ;;
      strict)
        echo "WARN[plan-pointer]: GK_PLAN_POINTER_STRICT=1 — 不跟随指针(plan=$_gkr_pplan)，回默认 state" >&2
        echo "WARN[plan-pointer]: STRICT=1 — pointer(plan=$_gkr_pplan) ignored $GK_SID_TAG" >> "$GK_DBG_LOG" ;;
      domain_route_off)
        echo "WARN[plan-pointer]: GK_STATE_DOMAIN_ROUTE=0 — 域化指针(domain=$_gkr_pdom)不跟随，回默认 state" >&2
        echo "WARN[plan-pointer]: GK_STATE_DOMAIN_ROUTE=0 — domain-pointer ignored (domain=$_gkr_pdom) $GK_SID_TAG" >> "$GK_DBG_LOG" ;;
    esac
    # §18.2 判据 c3（2026-10-04）：把「声明了指针但未解析」的原因透出给读侧（四读点 fail-closed）。
    #   仅 stale/dangling 置位（缺省空 = 零回归）；no_pointer_file（合法默认，无指针）不置位。
    #   ⚠ 必须用**已算出**的 reason（非重读文件）—— 上方 stale 分支会 rm 失效指针。
    case "${_gkr_preason:-}" in
      stale|dangling_pointer) export GK_PLAN_POINTER_UNRESOLVED="${_gkr_preason}" ;;
    esac
    # 2026-09-15（质询 F1 修订）：域解析结果 source=state_domain 虽**非冲突纠正**（corrected 恒
    # False），但**必须被采用**——原条件只认 corrected=True ⟹ 1b 步在 CLI 链上是**静默 no-op**
    # （A6-P2「路由执行侧强制」实际未生效，F-REV-63 想修的"执行侧看不到域 findings"未修）。
    if [ "$_gkr_rc" = "True" ] || { { [ "$_gkr_src" = "state_domain" ] || [ "$_gkr_src" = "plan_pointer" ]; } && [ -n "$_gkr_rexp" ]; }; then
      # 真因 C 边界①（2026-11-02）：路由中枢回来的是**外部形态**（可能 `C:\...`）
      #   ⟹ 必须归一再进 STATE_FILE，否则下方 32 处内联 python 全部语法错。
      [ -n "$_gkr_rexp" ] && STATE_FILE="$(_gk_fwd "$_gkr_rexp")"
      if [ "$_gkr_src" = "worktree_match" ]; then
        # 2026-09-01: worktree 匹配路由（窄任务随 worktree 隔离 state）——静默切换，非冲突纠正
        echo "INFO[state-routing]: worktree state route -> $_gkr_rexp $GK_SID_TAG" >> "$GK_DBG_LOG"
      elif [ "$_gkr_src" = "state_domain" ]; then
        echo "INFO[state-routing]: state_domain route -> $_gkr_rexp $GK_SID_TAG" >> "$GK_DBG_LOG"
      elif [ "$_gkr_src" = "plan_pointer" ] || [ "$_gkr_pfol" = "True" ]; then
        # ③ 单源（`ECC-1EC0E0732F0D`）：指针跟随现由 python 判定 ⟹ 此处仅记录（原 bash 静默跟随）
        echo "INFO[state-routing]: plan_pointer route -> $_gkr_rexp $GK_SID_TAG" >> "$GK_DBG_LOG"
      else
        echo "WARN[state-routing]: corrected to $_gkr_rexp" >&2
        echo "WARN[state-routing]: corrected to $_gkr_rexp $GK_SID_TAG" >> "$GK_DBG_LOG"
      fi
    elif [ "$_gkr_conf" = "True" ]; then
      echo "WARN[state-routing]: $_gkr_w" >&2
      echo "WARN[state-routing]: $_gkr_w $GK_SID_TAG" >> "$GK_DBG_LOG"
    fi
    # 2026-09-15（质询 F2 修订；REV-4 按 N5 收敛）：`error` 字段此前被整体丢弃 ⟹
    # STATE_DOMAIN_MISSING / STATE_DOMAIN_TOKEN_INVALID 的 fail-closed 在 CLI 层退化为
    # **静默回退 base state**（恰是计划 §3 J2 明令禁止的）。现提升为显式错误通道 + 停止
    # （声明了域却解析不到 ⟹ 继续用 base 就是读错账）。逃生口 = GK_STATE_DOMAIN_ROUTE=0。
    # ⚠ 可达性（REV-4 实测 + 2026-09-25 订正，勿夸大）：`discover` 侧的 `resolve-state` 调用
    # （= 归属预检的 `_owner_json` 取值处）不传 `--domain`/`--plan-file` ⟹ 该处的
    # `source=state_domain` / `error` **仍不可达**（服务显式传参的调用方 = 契约完整性）。
    # **本块（上方 `_gkr_route` 赋值处）自 2026-09-25 起带 `--derive-domain`** ⟹ 设了
    # env `GK_PLAN_FILE` 且该计划声明合法 `META.state_domain` 时，`source=state_domain`
    # （以及 token 非法/域 state 缺失时的 `error`）**在本块可达**（§4.13.5「全序列打通①」）。
    # （2026-09-15：原注释写死行号（`:137`/`:832` ⟹ `:160`/`:948`）已两度被落刀插入顶偏 ⟹ 依 R-9 改符号引用。）
    # 域化 state 的另一条生效路径 = `discover --plan` 写指针 → 本块经 **step 1 plan 指针**命中
    # （`source=plan_pointer`，走上面的 corrected/adopt 分支）。
    if [ -n "$_gkr_err" ]; then
      echo "ERROR[state-routing]: $_gkr_err — $_gkr_w" >&2
      echo "ERROR[state-routing]: $_gkr_err — $_gkr_w $GK_SID_TAG" >> "$GK_DBG_LOG"
      echo "{\"ok\":false,\"error\":\"$_gkr_err\",\"warning\":\"$_gkr_w\",\"channel\":\"state-routing\",\"fix\":\"建域化 state，或 GK_STATE_DOMAIN_ROUTE=0 关闭域解析\"}"
      exit 1
    fi
  fi
fi
unset _gkr_route _gkr_parsed _gkr_rc _gkr_rexp _gkr_conf _gkr_w _gkr_src _gkr_err _gkr_own _gkr_ptr _gkr_pfol _gkr_preason _gkr_pplan _gkr_pdom

PLAN_FILE="2026-05-19-spz-gatekeeper-202-v4-alignment-plan.md"

# API key 来源 (bridge 复用模式: v4-pro 和 v4-flash 共用同一 DEEPSEEK_API_KEY)
# 优先级: 1) 命令行 --api-key  2) GATEKEEPER_API_KEY 环境变量  3) DEEPSEEK_API_KEY 环境变量
#         4) Windows 环境变量 $env:DEEPSEEK_API_KEY (bridge v4.18: 跨 WSL 边界回退)
API_KEY=""
# --- DeepSeek provider (默认) —— 2026-09-10 对齐 DSH `llm-deepseek` 设计（F-REV-17）---
# DSH 原则（packages/llm/llm-deepseek/README.md，直接采用）：
#   ① 单一 route，**model id 透传上线**——"new DeepSeek models need no re-registration"
#      ⇒ 本仓不再把模型名写死为"某代产品"，只保留 **默认值 + env 覆盖**；
#   ② `baseURL`：`$DEEPSEEK_BASE_URL` 优先，否则官方默认（DSH 同序）；
#   ③ `reasoningEffort`：off | low | high | max（DSH 默认 high，本仓审查面用 max）；
#   ④ 默认 catalog 首项 = `deepseek-flash`（V4.1 Flash，text+image，含 in-history 能力）。
# 2026-09-10 F-REV-17 事实：V4 Flash 已下线、V4 Pro 09-14 起全部路由到 V4.1 Flash
# ⇒ 两档模型名均指向 V4.1 Flash，直接用规范名 `deepseek-flash`（旧名仅留兼容）。
# ⚠ alias 不可作**版本判据**（2026-10-12）：模型名可**沿用同一 alias 仅换后端**（上游换代不改名）
#   ⟹ 凡判 stride / 相位周期等**版本相关量**，**禁据 alias 推断**，须**版本探针**实测版本。
#   （W2A §6.1 / §6.3(3) F1b：6 臂 = subagent，走本 `DS_MODEL_CRITIC` = alias `deepseek-flash`，
#    真版本须实测 ⟹ 不可据 alias 预设 `S`。）
DS_API_BASE="${DEEPSEEK_BASE_URL:-https://api.deepseek.com}"
# advisory catalog（DSH 语义：仅供提示/校验，**model id 仍透传**，未登记 id 不报错）
DS_CATALOG_MODELS="deepseek-flash deepseek-v4-flash-vision-exp deepseek-v4-flash deepseek-v4-pro"
# shellcheck disable=SC2034  # DS_MODEL_ACTOR 是设计预留, 主 agent 模型由 Trae 模型选择器控制
DS_MODEL_ACTOR="${GK_ACTOR_MODEL:-deepseek-flash}"
# CRITIC = CLI 审查层（monitor / reflect / subagent）；model id 透传，env 可覆盖（免改代码换模型）
DS_MODEL_CRITIC="${GK_CRITIC_MODEL:-deepseek-flash}"
DS_REASONING_EFFORT="${GK_REASONING_EFFORT:-max}"  # 仅对 CRITIC 生效 (CLI 直接调 API 时)
# --- MiMo provider (小米开放平台 API, 按量付费正常版, DeepSeek 余额空时平替) ---
# 2026-08-09: 用户已弃用 Token Plan → 切换按量付费正常版 API（key 格式 sk-*）。
# 正常版: https://api.xiaomimimo.com/v1 | Token Plan 版(已弃): token-plan-cn.xiaomimimo.com/v1 (tp-*)
# 2026-09-22 (P0): 切换 MiMo-V2.6 系列 —— v2.5 全系 2026-10-21 10:00 下线（官方公告）。
# v2.6-pro: 旗舰全模态强推理 (1M ctx), v2.6-flash: 全模态高效, v2.6-pro-ultraspeed: 20× 速（实时场景备选）。
# 同一 MIMO_API_KEY 可切不同模型
# 2026-10-02（**模型可换**）：与 DS 侧**对称**的 env 覆盖 —— 模型保质期 ~3 个月（旧模型退役 /
#   更好更便宜的新模型上线），降级链目标是**兜底防爆** ⟹ 换代应只改**配置（env）**不改代码。
#   原三者硬编码 ⟹ 违反本文件 L374-375 既有原则（「只保留默认值 + env 覆盖」）。
#   覆盖键：MIMO_BASE_URL / GK_MIMO_ACTOR_MODEL / GK_MIMO_CRITIC_MODEL。
MIMO_API_BASE="${MIMO_BASE_URL:-https://api.xiaomimimo.com/v1}"
# shellcheck disable=SC2034  # Actor-critic 分离: ACTOR 给主 agent 用, CRITIC 给 CLI monitor 用
MIMO_MODEL_ACTOR="${GK_MIMO_ACTOR_MODEL:-mimo-v2.6-pro}"
MIMO_MODEL_CRITIC="${GK_MIMO_CRITIC_MODEL:-mimo-v2.6-flash}"
# 当前生效的 provider (deepseek|mimo), 默认 deepseek
PROVIDER="${GATEKEEPER_PROVIDER:-deepseek}"

# 根据当前 provider 解析 API base + model
_resolve_provider_config() {
  case "$PROVIDER" in
    mimo)
      API_BASE="$MIMO_API_BASE"
      API_MODEL="$MIMO_MODEL_CRITIC"  # critic 用 v2.6-flash（2026-09-22 P0: v2.5 系列 10-21 下线）
      # shellcheck disable=SC2034  # case 分支输出契约: MiMo 不用 reasoning_effort, 但外部 source 可能依赖此变量
      REASONING_EFFORT=""
      # MiMo API key: 优先 MIMO_API_KEY, 回退 DEEPSEEK_API_KEY
      [ -z "$API_KEY" ] && API_KEY="${MIMO_API_KEY:-${DEEPSEEK_API_KEY:-}}"
      ;;
    *)
      API_BASE="$DS_API_BASE"
      API_MODEL="$DS_MODEL_CRITIC"  # CLI 审查层用 CRITIC (v4-flash)
      # shellcheck disable=SC2034  # case 分支输出契约: 给外部 source 或未来代码使用
      REASONING_EFFORT="$DS_REASONING_EFFORT"
      ;;
  esac
}

# ─── API key 文件落点（2026-11-02，开源包可用性）────────────────────────────────
# 背景：原解析链只有 env 与 Windows 用户环境（PowerShell）⟹ Linux/macOS 用户**没有**
#   可持久化的配置入口（`set-key` 只 export 当前进程，重启即丢）。
# 落点单源 = `scripts/gk_api_key.py`（禁 bash 再写一份路径逻辑）：
#   `<skill>/.keys/api_key`（deepseek）/ `mimo_key`（mimo）/ `$GATEKEEPER_KEY_FILE`（显式）。
# 本函数只负责"文件"这一档；优先级由 `_resolve_api_key` 保序（env → 文件 → Windows 环境）。
_gk_key_file() {
  python3 "$SKILL_DIR/scripts/gk_api_key.py" path --provider "${1:-deepseek}" \
    --skill-dir "$SKILL_DIR" 2>/dev/null
}
_gk_key_file_read() {
  python3 "$SKILL_DIR/scripts/gk_api_key.py" read --provider "${1:-deepseek}" \
    --skill-dir "$SKILL_DIR" 2>/dev/null | tr -d '\r\n'
}
_resolve_api_key() {
  # Already resolved
  [ -n "$API_KEY" ] && return 0

  # Provider-specific key resolution (WSL env first)
  local ps_var=""
  case "$PROVIDER" in
    mimo)
      # 2026-09-22 (P0 附带): tp-* 旧版 key 视同空（正常版 API 恒 401，见 _resolve_provider_config 注）
      API_KEY="${MIMO_API_KEY:-}"
      [[ "$API_KEY" == tp-* ]] && API_KEY=""
      [ -n "$API_KEY" ] && return 0
      API_KEY="${DEEPSEEK_API_KEY:-}"
      [ -n "$API_KEY" ] && return 0
      ps_var="MIMO_API_KEY"
      ;;
    *)
      API_KEY="${GATEKEEPER_API_KEY:-${DEEPSEEK_API_KEY:-}}"
      [ -n "$API_KEY" ] && return 0
      ps_var="DEEPSEEK_API_KEY"
      ;;
  esac

  # 2026-11-02（开源包可用性）：key 文件（跨平台持久化；非 Windows 的唯一持久入口）。
  #   ⚠ 必须在 PowerShell 回退**之前** —— 否则 Linux/macOS 永远走不到这一档。
  local _kf_key=""
  _kf_key=$(_gk_key_file_read "$PROVIDER") || _kf_key=""
  [ -n "$_kf_key" ] && { API_KEY="$_kf_key"; return 0; }

  # Cross-WSL-boundary key resolution via PowerShell
  # First try provider-specific key, then fallback to DEEPSEEK_API_KEY
  # 2026-08-09: powershell.exe 绝对路径兜底 — wslsh -c / cron 等环境 PATH 不含
  # Windows System32 → command -v powershell.exe 失败 → key 解析为空 → API 401。
  # 对齐 subagent_runner.py _gitnexus_cmd 的 node.exe 绝对路径教训（同款 PATH 边界）。
  local _ps_exe=""
  if [ -x "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" ]; then
    _ps_exe="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
  elif command -v powershell.exe >/dev/null 2>&1; then
    _ps_exe="powershell.exe"
  fi
  if [ -n "$_ps_exe" ]; then
    # Provider-specific key
    API_KEY=$("$_ps_exe" -NoProfile -Command "[System.Environment]::GetEnvironmentVariable(\"${ps_var}\",\"User\")" 2>/dev/null | tr -d '\r\n ' || echo "")
    [ -n "$API_KEY" ] && return 0
    API_KEY=$("$_ps_exe" -NoProfile -Command "[System.Environment]::GetEnvironmentVariable(\"${ps_var}\",\"Process\")" 2>/dev/null | tr -d '\r\n ' || echo "")
    [ -n "$API_KEY" ] && return 0
    # Fallback to DEEPSEEK_API_KEY (works for both providers — same key format)
    if [ "$ps_var" != "DEEPSEEK_API_KEY" ]; then
      API_KEY=$("$_ps_exe" -NoProfile -Command '[System.Environment]::GetEnvironmentVariable("DEEPSEEK_API_KEY","User")' 2>/dev/null | tr -d '\r\n ' || echo "")
      [ -n "$API_KEY" ] && return 0
      API_KEY=$("$_ps_exe" -NoProfile -Command '[System.Environment]::GetEnvironmentVariable("DEEPSEEK_API_KEY","Process")' 2>/dev/null | tr -d '\r\n ' || echo "")
      [ -n "$API_KEY" ] && return 0
    fi
  fi
  return 1
}

# W10 (2026-08-09): api-key 有效性预检 — 类1 低级基础错误安全网
# 背景: 显式 --api-key 传错值（空/含空白/过短）→ API 401（本次会话教训）。
# 校验: 非空 + 无空白字符 + 长度 >= 20（DS sk-* 35 位, MIMO 51 位）。失败返回 1。
_validate_api_key() {
  local k="${1:-}"
  [ -z "$k" ] && return 1
  [[ "$k" =~ [[:space:]] ]] && return 1
  [ "${#k}" -lt 20 ] && return 1
  return 0
}

# ─── failover chain: Bridge engine.py pattern (T43+++v2) ───
# Configurable via GK_FAILOVER_CHAIN env var. Default: DS→MiMo→Local.
# e.g. export GK_FAILOVER_CHAIN="deepseek,mimo,ollama"
# Each provider maps to: _resolve_provider_config() + curl call
# 2026-10-02（G5 **机制合并**）：**export** —— 本键即**可继承的单一作用域**；python
#   `scripts/gk_monitor_api.py::FAILOVER_CHAIN` 从同一 env 读取（原为硬编码第二实现 ⟹ 环境改不了）。
export GK_FAILOVER_CHAIN="${GK_FAILOVER_CHAIN:-deepseek,mimo,local}"

# ─── is_retryable: filter which errors trigger failover (Bridge L373-L375) ───
# Only network/timeout/5xx errors are retryable. Semantic errors (400) are NOT.
# 2026-10-10（ECC-5E433392C5C7）：**DS 欠费 = HTTP 402 / "Insufficient Balance"** 亦须触发
#   failover —— 目标 =「DeepSeek 余额耗尽 → 自动降级下一条腿 MiMo」，而原判据只认 5xx/网络类
#   ⟹ 402 命中 `_monitor_api` 的 `break`（**不换 provider** ⟹ 直接 "all providers failed"）。
#   本函数吃的是 **curl 响应体文本**（`_monitor_api` 未带 `-w`）⟹ 按**余额语义词**匹配
#   （DeepSeek 实测 message="Insufficient Balance"，case-insensitive），不依赖状态码字面。
#   语义类 400 仍**不可重试**（降级代价不该付）。
_is_retryable() {
  local msg="$1"
  # 2026-08-13 组合短标志同样误用：rg -qiE 中 -E=--encoding 会把 pattern 当 encoding 参数吃掉（unknown encoding 报错）。
  # ripgrep 扩展正则默认开启，去掉 E 语义不变。
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
  echo "$msg" | "$RG" -qi "timeout|timed.out|connection.refused|reset.by.peer|52[0-9]|50[0-3]|curl.*failed|empty.reply|insufficient.balance|insufficient.quota|insufficient.funds|insufficient.credit|arrears" && return 0
  return 1
}

# Critical stages for API routing (bridge v4.15: only gates 3/6/7/8 get v4-flash)
# STAGE_3 (REVIEW) and STAGE_4 (MERGE) are Gatekeeper's equivalents
CRITICAL_STAGES="STAGE_3 STAGE_4"
# Cosine Scheduler defaults — written into gate_data.scheduler on discover
SCHEDULER_MODE="${SCHEDULER_MODE:-cosine}"
# Edit budget: max_lr = max edits allowed at R start, min_lr = min edits at R end
# Adjust via environment: export SCHEDULER_MAX_LR=8 SCHEDULER_MIN_LR=2 SCHEDULER_TOTAL_STEPS=8
# Cosine schedule: lr = min_lr + 0.5*(max_lr-min_lr)*(1+cos(π*t)), t ∈ [0,1]
SCHEDULER_MAX_LR="${SCHEDULER_MAX_LR:-4}"
SCHEDULER_MIN_LR="${SCHEDULER_MIN_LR:-1}"
SCHEDULER_TOTAL_STEPS="${SCHEDULER_TOTAL_STEPS:-6}"
# PROTECTED_REGION_END::constants

# ---------- language-aware linter (industry-standard dead code / quality detection) ----------
# Usage: _run_linter <file_path>
# Returns: JSON {tool, available, issues, recommendation}
# Design: no lookup table — case statement maps extensions to tools inline.
_run_linter() {
  local file="$1"
  local ext="${file##*.}"
  local tool=""

  case "$ext" in
    sh|bash) tool="shellcheck" ;;
    py)      tool="ruff" ;;
    js|ts)   tool="eslint" ;;
    rs)      tool="clippy" ;;
    go)      tool="staticcheck" ;;
    cc|cpp|h|hpp) tool="clang-tidy" ;;
    *)       echo '{"tool":"none","available":false,"issues":0,"recommendation":"No linter mapped for .'"$ext"'"}'; return 0 ;;
  esac

  if ! command -v "$tool" &>/dev/null; then
    echo "{\"tool\":\"$tool\",\"available\":false,\"issues\":0,\"recommendation\":\"Install $tool: see https://github.com/search?q=$tool for installation instructions\"}"
    return 0
  fi

  local output issues
  case "$tool" in
    shellcheck)  output=$(shellcheck --severity=warning "$file" 2>&1 || true) ;;
    ruff)        output=$(ruff check --select F "$file" 2>&1 || true) ;;
    eslint)      output=$(eslint --no-eslintrc "$file" 2>&1 || true) ;;
    clippy)      output=$(cargo clippy -- -W clippy::dead-code 2>&1 || true) ;;
    staticcheck) output=$(staticcheck "$file" 2>&1 || true) ;;
    clang-tidy)  output=$(clang-tidy "$file" 2>&1 || true) ;;
  esac
  issues=$(echo "$output" | wc -l)
  echo "{\"tool\":\"$tool\",\"available\":true,\"issues\":$issues,\"output\":$(echo "$output" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()[:2000]))' 2>/dev/null || echo '""')}"
}

# ---------- plugin shellcheck_scan 降级链（2026-08-26）----------
# dead_code_gate1 / l5_blind_spot 的确定性实现：统一走 cmd_migrate 探测链
# （复用 WSL PATH → WSL python3 → ZTHL_BASHPY_DIR → Windows Python 跨环境探测 +
# loader SHA256 供应链安全网 + manifest define/cap 门禁，对齐 RED-MIGRATE 同款接线）。
# 插件不可用/被拦截 → 空输出 → gate1 回退外部 shellcheck binary（已装则用，未装跳过）。
# 输出 "sc2034_count total"（空格分隔），失败输出空。
_plugin_sc_counts() {
  local _out _sc2034 _total
  # shellcheck disable=SC2086  # cmd_migrate 内部处理参数展开
  _out=$(cmd_migrate audit --script "$SKILL_DIR/gatekeeper-cli.sh" --shellcheck 2>/dev/null) || return 0
  _sc2034=$(echo "$_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field shellcheck_scan.counts.sc2034_unused --strict-path --default 0 --default-invalid '' 2>/dev/null)
  [ -z "$_sc2034" ] && return 0
  _total=$(echo "$_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field shellcheck_scan.total --strict-path --default-invalid '' 2>/dev/null)
  [ -n "$_total" ] && echo "$_sc2034 $_total"
}

# ---------- json helpers (rg replaces grep) ----------
# 2026-09-19（ECC-52E6351D6DB4）：rg 解析**单源 + 可信目录白名单 + 缺失可判**。
# 实测病灶：本机 /usr/bin/rg = **13.0.0**（文件日期 2022-08-18）、/usr/local/bin/rg = **15.2.0**
# （即 PATH 上那个，SKILL.md 记「已升至 15.2.0」指的就是它）。原写死 `/usr/bin/rg` ⟹ 变量派
# （15 行）+ 硬编码派（27 行）**共 42 行走的都是老版 13.0.0**，而 34 行 bare `rg` 走 PATH = 新版
# ⟹ **同一脚本两套语义**（老版缺 SKILL.md 点名依赖的 gitignore 父目录规则等 15.x 修复）。
# 更重的一层：rg 缺位时 `if ... | $RG -q` 恒假 ⟹ 主仓只读与 amend 检测 **fail-open**（WorkBuddy
# 宿主实测即 rg 缺位）。现口径：只认**可信绝对目录**（不做 `command -v` 裸查，防 PATH 劫持），
# /usr/local/bin 优先（新版）；两者皆无 ⟹ `RG=""`，安全判据据 `-z "$RG"` **显式 fail-closed**。
RG=""
# 2026-09-20（ECC-PLAN ②·工具可用性）：原白名单只列 Debian 系两处 ⟹ macOS（Homebrew
# /opt/homebrew/bin、MacPorts /opt/local/bin）、Windows Git-Bash（/mingw64/bin）、Snap
# （/snap/bin）上**装了 rg 却判缺**，而判缺的下游判据是 `-z "$RG"` fail-closed ⟹ 安全门整体
# BLOCK（可用性等价于故障：安全层「宁可拒绝」的设计在异宿主上退化为「不可用」）。
# 现按**宿主形态**枚举可信绝对目录；仍**不做 `command -v` 裸查**（防 PATH 劫持——该决定保持不变）。
# 2026-11-01：`GK_RG` 显式覆盖优先（README 承诺的平替位——此前文档写了但代码没读）。
if [ -n "${GK_RG:-}" ] && [ -x "${GK_RG}" ]; then
  RG="${GK_RG}"
fi
if [ -z "$RG" ]; then
  for _rgc in /usr/local/bin/rg /usr/bin/rg /opt/homebrew/bin/rg /opt/local/bin/rg \
              /snap/bin/rg /mingw64/bin/rg; do
    [ -x "$_rgc" ] && { RG="$_rgc"; break; }
  done
fi
unset _rgc
# 2026-11-01（owner 裁定「入口 fail-loud」）：rg 缺位时多处 `"$RG" -q` 恒假 ⟹ 守卫 fail-open。
#   与其静默放行，不如**入口拒绝**并给出安装/平替（`help`/无参仍可用 ⟹ 用户能先看到用法）。
if [ -z "$RG" ]; then
  case "${1:-}" in
    help|-h|--help|"") ;;
    *)
      printf '{"ok":false,"error":"DEP_MISSING","tool":"rg","hint":"install ripgrep (apt install ripgrep | brew install ripgrep | winget install BurntSushi.ripgrep.MSVC) or export GK_RG=/path/to/rg"}\n'
      echo "ERROR[dep] ripgrep(rg) 未找到：检索与多条守卫判据依赖它（缺位会 fail-open）。安装：apt install ripgrep | brew install ripgrep | winget install BurntSushi.ripgrep.MSVC；或 export GK_RG=/path/to/rg" >&2
      exit 2 ;;
  esac
fi
json_val() {
  local file="$1" key="$2" default="${3:-}"
  local val
  val=$("$RG" -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$file" 2>/dev/null | head -1 | sed "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"//;s/\"$//" || true)
  echo "${val:-$default}"
}

# ---------- 取数中枢（A6-T2 ①，2026-09-15；判据 J18 / J20）----------
# 收敛评估器（T4 段 + pre-check convergence）的 state **必须由 resolve-state 决定**，
# 禁盲取 $STATE_FILE（那正是 F-REV-63 的取数错锚）。语义：
#   ① 采用中枢结果：`expected` 非空且 ≠ 当前 $STATE_FILE ⟹ 覆盖（域解析 / worktree 纠正
#      在启动块之后再次确认，行为单调）；
#   ② **error 非空 ⟹ fail-closed**（返回 1）：域 state 缺失时继续用 base 就是读错账
#      （对齐 §9.3 J2/J20）；**禁静默回 base**。逃生口 GK_STATE_DOMAIN_ROUTE=0（L4 跳过 1b
#      步 ⟹ resolve-state 显式返回 base，属"显式路径"而非静默）。
#   ③ 回包不可解析 ⟹ 同样 fail-closed（宁失败不读错账）。
# 结果：成功写 _CONV_STATE / 返回 0；失败写 _CONV_ERR / 返回 1。
_CONV_STATE=""
_CONV_ERR=""
_conv_state_path() {
  _CONV_STATE=""
  _CONV_ERR=""
  # kill switch 优先（对齐 §9.3 J4/J13/J20 对照臂）：`=0` ⟹ **不采用**域绑定 ⟹ 取数回
  # $STATE_FILE（**显式**路径，非静默）；且**不因域缺失而失败**（开关关着就不该被域拦）。
  # ⚠ 必要性（2026-09-15 实测发现）：L4 的 plan 指针步（step 1）**自身不消费该开关**，
  # 故 `=0` 时 resolve-state 仍可能返回域化 state ⟹ 若此处无条件采用，就会**绕过**开关
  # （与 REV-5 缺口 a 的修复方向相反）。本分支即为此设。
  if [ "${GK_STATE_DOMAIN_ROUTE:-1}" = "0" ]; then
    _CONV_STATE="$STATE_FILE"
    echo "INFO[state-routing]: 取数中枢：域解析关闭 ⟹ 显式回 \$STATE_FILE" >> "$GK_DBG_LOG"
    return 0
  fi
  local _o _p
  # n4-L1（2026-10-05 实测）：`resolve-state --derive-domain` 读的域来源是 env **`GK_PLAN_FILE`**
  #   （**非** `PLAN_FILE`），且须 `--derive-domain` 才启用该分支 ⟹ 两者缺一，中枢就收不到计划、
  #   域不可派生、**静默回落 base**（跨代混账 = F-REV-63）。此处与启动块（L297）**同口径**补齐。
  _o=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" STATE_FILE="$(_gk_py_path "$STATE_FILE")" PLAN_FILE="$PLAN_FILE" \
       GK_PLAN_FILE="${GK_PLAN_FILE:-$PLAN_FILE}" \
       python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-state --derive-domain 2>>"$GK_DBG_LOG" || true)
  _p=$(python3 -c "
import sys, json
try:
    d = json.loads(sys.argv[1])
except Exception:
    d = None
if not isinstance(d, dict):
    print('False||')
else:
    print('|'.join(['True', (d.get('error') or '').replace('|', '/'), d.get('expected') or '']))
" "$_o" 2>>"$GK_DBG_LOG")
  local _ok _err _sf
  IFS='|' read -r _ok _err _sf <<< "$_p"
  if [ "$_ok" != "True" ]; then
    _CONV_ERR="STATE_ROUTE_UNPARSABLE"
    echo "ERROR[state-routing]: resolve-state 回包不可解析（fail-closed）" >&2
    echo "ERROR[state-routing]: STATE_ROUTE_UNPARSABLE" >> "$GK_DBG_LOG"
    return 1
  fi
  if [ -n "$_err" ]; then
    _CONV_ERR="$_err"
    echo "ERROR[state-routing]: $_err (取数中枢 fail-closed)" >&2
    echo "ERROR[state-routing]: $_err" >> "$GK_DBG_LOG"
    return 1
  fi
  if [ -n "$_sf" ] && [ "$_sf" != "$STATE_FILE" ]; then
    echo "INFO[state-routing]: 取数中枢 -> $_sf" >> "$GK_DBG_LOG"
    _CONV_STATE="$_sf"
  else
    _CONV_STATE="$STATE_FILE"
  fi
  return 0
}

# ---------- plan metadata reader (元数据路由中枢 L1, 2026-09-02) ----------
# 全量迁移：META 解析 + 5 层金字塔搜索 + standing 检测全部收编进 gk_route_center.py
# resolve_plan。本函数只做参数传递（PLAN_FILE/SKILL_DIR/MAIN_REPO_WSL）与结果消费
# （META_* 变量赋值）——唯一路由 = gk_route_center。
_read_plan_metadata() {
  META_phases=""
  META_target_repo=""
  META_project_type=""
  META_worktree_needed=""
  META_work_dir=""
  META_commit_obj=""
  META_commit_format=""
  META_review=""
  META_state_domain=""
  local _meta_json
  _meta_json=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" MAIN_REPO_WSL="$MAIN_REPO_WSL" PLAN_FILE="$PLAN_FILE" \
    python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-plan 2>>"$GK_DBG_LOG" || echo '{}')
  # 2026-09-23（**ECC-084E37B42CFB 修复**）：原发射用 `repr()` —— **不是 shell 安全序列化器**：
  #   值含单引号时 repr 改用**双引号**包裹 ⟹ 值里的 `$(...)` / 反引号落在双引号内被 bash 展开
  #   （实测：META 值 `x'$(touch SENTINEL)'` 直接产生副作用文件；`bash -n` 全绿、静态查不到，
  #   属**运行期**由值形态触发的注入；病象 = `json.dump: command not found` /
  #   `command substitution: syntax error near unexpected token '||'`）。改 `shlex.quote`
  #   （POSIX 单引号转义）⟹ 值恒为字面量。守护臂：`test_gk_eval_injection.py`（含对照臂）。
  eval "$(echo "$_meta_json" | python3 -c "
import sys,json,shlex
try:
    d=json.load(sys.stdin)
except Exception:
    d={}
m=d.get('meta',{})
for k in ['phases','target_repo','project_type','worktree_needed','work_dir','commit_obj','commit_format','review','state_domain','source_docs']:
    print(f'META_{k}={shlex.quote(str(m.get(k,\"\")))}')
" 2>>"$GK_DBG_LOG")"
}

# ---------- repo routing (元数据路由中枢 L2, 2026-09-02) ----------
# Prevents agent from searching wrong repo. Usage: path=$(_resolve_repo_path gatekeeper)
# 全量迁移：target_repo → 路径表收编进 gk_route_center.py resolve_repo，本函数仅消费。
_resolve_repo_path() {
  local repo_name="${1:-}"
  [ -z "$repo_name" ] && { echo "error: no repo specified"; return 1; }
  local _rp_json _rp_path _rp_err
  _rp_json=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" MAIN_REPO_WSL="$MAIN_REPO_WSL" \
    python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-repo "$repo_name" 2>>"$GK_DBG_LOG" || echo '{}')
  _rp_path=$(echo "$_rp_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field path \
    --default '' 2>/dev/null || echo "")
  if [ -n "$_rp_path" ]; then
    # 别名提示（对齐原 CLI：引导用规范名）
    local _alias; _alias=$(echo "$_rp_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" \
      field alias_of --default '' 2>/dev/null || echo "")
    [ -n "$_alias" ] && echo "info: use '$_alias' instead of repo name" >&2
    echo "$_rp_path"
    return 0
  fi
  _rp_err=$(echo "$_rp_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field error \
    --default 'unknown repo' --default-invalid "unknown repo: $repo_name" 2>/dev/null \
    || echo "error: unknown repo '$repo_name'")
  echo "$_rp_err"
  return 1
}

# ---------- block log helper (records IDLE/DONE rejections for audit) ----------
_log_block() {
  local cmd="$1" reason="$2"
  [ ! -f "$STATE_FILE" ] && return 0
  # ECC-9F21304266C5（F3a 写 state 单入口收敛）：原实现**内联 python 直写**
  # `json.dump(open($STATE_FILE,'w'))` —— 既不取 flock，也**不重算 `_checksum`**
  # ⟹ 每条 block 记录落盘后 checksum 恒失配（self-check `checksum_integrity` FAIL）。
  # 现改走既有**唯一**写入口 `_state_write`（flock + 原子写 + checksum 重算），
  # 消除"多入口写 state"这一族病根。语义不变：字段/取值/100 条 FIFO 上限逐项保持。
  # cmd/reason 经 **env** 传入（而非拼进 python 源码）⟹ 顺带消除引号/换行注入面
  # （对齐既有 `_budget_override_record` 的写法）。
  GK_BLK_CMD="$cmd" GK_BLK_REASON="$reason" _state_write "
import os as _os, datetime as _dt
gd = d.setdefault('gate_data', {})
log = gd.setdefault('block_log', [])
log.append({'command': _os.environ.get('GK_BLK_CMD', ''), 'reason': _os.environ.get('GK_BLK_REASON', ''), 'stage': d.get('stage', 'IDLE'), 'timestamp': _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')})
del log[:-100]
" >/dev/null 2>>"${GK_DBG_LOG:-/dev/null}" || echo "[log_block] WARN _state_write 失败——本条 block 审计记录未落盘 $(date -u +%FT%TZ)" >>"${GK_DBG_LOG:-/dev/null}"
}

# ---------- calibrate ----------
cmd_calibrate() {
  # 2026-10-09（finding ECC-D72764C0D354）：edit-log K/N 标定/摘要**读面**的唯一 CLI 通路。
  #   形态约束：`_CMD_REG` 在 `PROTECTED_REGION::gate` 内（禁改）⟹ **不新增命令**，只在既有
  #   `calibrate` 上开分支（本函数体区外）。委托读面单源 `gk_budget_ledger.py`：
  #     `calibrate --edit-log [--percentile P] [--min-nodes N]` → `gk_budget_ledger calibrate`
  #     `calibrate --edit-log --stats`                         → `gk_budget_ledger edit-stats`
  #   无 `--edit-log` ⟹ 既有 route-center 五层校准语义**逐字不变**（零回归）。
  if [ "${1:-}" = "--edit-log" ]; then
    shift || true
    local _esub="calibrate"
    if [ "${1:-}" = "--stats" ]; then _esub="edit-stats"; shift; fi
    python3 "$SKILL_DIR/scripts/gk_budget_ledger.py" "$_esub" \
      --state "$STATE_FILE" "$@" 2>>"$GK_DBG_LOG"
    return $?
  fi
  # 2026-09-04 (B)：运行时五层校准 —— 只读诊断（非门禁）。委托 gk_route_center calibrate：
  # route-all 全链路后断言 L1-L5 一致性（repo↔worktree 归属 / plan-worktree-state 相位三角链 /
  # META.state_domain 声明绑定=worktree 须声明对应 state 域）。退出码 0=OK（JSON on stdout），
  # python 异常 → 错误 JSON + 非零（fail-loud，stderr 入 GK_DBG_LOG）。
  # 计划上下文：不自动注入 PLAN_FILE（CLI 全局 PLAN_FILE = 历史锚点默认值，自动注入会把校准
  # 锁到错误计划）——缺省走 route center 5 层金字塔搜索（与 discover 同源）；需显式锚定计划时
  # 调用方传 --plan-file <p>（python 透传）。STATE_FILE 注入 CLI 启动已跟随的隔离 state。
  SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" MAIN_REPO_WSL="$MAIN_REPO_WSL" \
    python3 "$SKILL_DIR/scripts/gk_route_center.py" calibrate \
    ${STATE_FILE:+--state-file "$STATE_FILE"} "$@" 2>>"$GK_DBG_LOG"
}

# 2026-09-15 REV-5（第三轮质询 缺口 c）：fail-closed 路径**必须清理 plan 指针**。
# 机理：`discover --plan X` 失败返回 1 后，**上一次**成功绑定写下的旧指针仍在 ⟹ 后续任意进程
# 在启动块跟随它 ⟹ 静默落到**上一次的**隔离 state。"失败"的语义应是"没有绑定"，而非"回到旧账本"。
# 未启用指针（显式 env STATE_FILE，`_PLAN_POINTER` 为空）时无事可做 → 直接返回。
_disc_clear_pointer() {
  # 2026-09-25（②b）：清**写目标**（`_PLAN_POINTER_OWN`）而非跟随目标 —— 有会话身份时只清
  # 本会话指针，不再误删他会话（或全局）的绑定。显式 STATE_FILE 下 OWN 为空 ⟹ 本进程既未
  # 建立绑定、也无权删除（「构造性 no-op」语义保持，见 discover 内注释）。
  local _pc="${_PLAN_POINTER_OWN:-}"
  [ -n "$_pc" ] || return 0
  [ -f "$_pc" ] || return 0
  rm -f "$_pc" 2>/dev/null || true
  echo "INFO[plan-pointer]: fail-closed 路径清理旧指针 $_pc" >> "$GK_DBG_LOG"
}

# 2026-09-25（②b）：**过期会话指针 sweep** —— 会话级指针每会话一份（`.gatekeeper.plan.<sid>`），
# 启动块只在「读到的那个过期」时自清 ⟹ 他会话的过期件无人回收。本函数在 `discover`（低频）
# 路径收口：只删 mtime 超 `GK_PLAN_POINTER_TTL`（默认 86400s，对齐指针 TTL）的**带后缀**件；
# **绝不碰** `.gatekeeper.plan` 本体（全局指针由启动块 stale 分支 / sid-less discover 处置）。
_disc_sweep_stale_plan_pointers() {
  local _pf _mt _now _age
  _now=$(date +%s)
  for _pf in "${SKILL_DIR}"/.gatekeeper.plan.*; do
    [ -f "$_pf" ] || continue
    _mt=$(stat -c %Y "$_pf" 2>/dev/null || echo 0)
    case "$_mt" in ""|*[!0-9]*) continue ;; esac
    _age=$(( _now - _mt ))
    [ "$_age" -gt "${GK_PLAN_POINTER_TTL:-86400}" ] && rm -f "$_pf" 2>/dev/null || true
  done
}

# ---------- discover ----------
cmd_discover() {
  local plan_override="" build_state=false
  while [ $# -gt 0 ]; do case "$1" in
    --plan) plan_override="${2:-}"; shift 2 2>/dev/null || shift ;;
    --build-state) build_state=true; shift ;;
    *) break ;;
  esac; done
  # n4-L2（2026-10-05）：`--build-state` **只**与 `--plan` 同用才有意义（域来源 = 计划 META
  #   state_domain）⟹ 裸用即具名失败，**禁静默 no-op**（否则用户以为建了域 state，实则空转）。
  if $build_state && [ -z "$plan_override" ]; then
    echo '{"ok":false,"error":"BUILD_STATE_NEEDS_PLAN","fix":"discover --plan <plan> --build-state"}'
    return 1
  fi
  # 显式 env STATE_FILE（STATE_FILE_EXPLICIT=1）下 plan 指针未在启动块定义——
  # 绑定空值防 set -u 崩溃（2026-09-04 修复：此前显式 state 下 discover 直接 unbound）
  _PLAN_POINTER="${_PLAN_POINTER:-}"
  # 2026-09-25（②b）：过期**会话指针**回收 —— 放在 `--plan` / 无 `--plan` 分派**之前** ⟹
  # 两条路径都过（housekeeping，只删 mtime 超 TTL 的带后缀件，不碰全局本体）。
  _disc_sweep_stale_plan_pointers
  # 2026-09-15 REV-5（五轮质询 H3）：**成功路径也要能判读绑定结果**——原成功 JSON 既无
  # `state_file` 也无域字段，指针写失败又被 `|| true` 吞 ⟹ 只读 stdout 的调用方无法确认
  # 域绑定是否生效（与缺口 b 所修的"静默面"同类，属不对称修补）。现成功 JSON 携带
  # `state_file` +（域绑定时）`state_domain` + `pointer_written`。
  local _bind_field=""

  # --plan: isolate state file per plan + auto-resolve plan path
  # Usage: discover --plan batch8  (short name, auto-resolved from plan dirs)
  #        discover --plan /path/to/plan.md  (explicit path)
  if [ -n "$plan_override" ]; then
    # Auto-resolve short name to full path（**前置**：须先有真实路径才能读其 META —— F1 修订）
    case "$plan_override" in
      */*) : ;;  # already an absolute/relative path
      *)
        local _resolved
        # F-REV-44②（2026-09-13）：正本 `docs/plans/` **优先**，`plan-backup/` 仅作兜底。
        # 原序（backup 在前 + `head -1`）会命中**滞后备份副本** ⟹ 静默读旧 META ⟹ 曾致
        # `discover --plan r7` 报 `unknown R-phase: R7.3 — plan declares phases: R7 R7.1`。
        # 2026-09-15 REV-5（质询 N1-歧义）：**不再依赖 `ls` 的多操作数输出顺序**——`ls` 按
        # **全路径**排序（`…/docs/plan-backup/…` < `…/docs/plans/…`），故原写法与"正本优先"
        # 的注释无对应关系。改为**分档显式优先级**：正本 → backup → 技能内置 docs/plans；
        # 同档多命中取 **mtime 最新**（`ls -t`）并留痕，不再由字典序静默裁决。
        for _pdir in "$MAIN_REPO_WSL/docs/plans" "$MAIN_REPO_WSL/docs/plan-backup" \
                     "$SKILL_DIR/docs/plans"; do
          _resolved=$(ls -t "$_pdir"/*"$plan_override"*.md 2>/dev/null | head -1)
          [ -n "$_resolved" ] && break
        done
        # 2026-09-15 REV-4（质询 N1）：搜索面补 `$SKILL_DIR/docs/plans`（技能自带计划
        # `target_repo: skill` 恰在原搜索面之外）；且**未命中即 fail-closed**——原行为会让
        # 裸 token 落到 `resolve_plan` 的 5 层金字塔兜底，用**另一份最新计划**的
        # `META.state_domain` 命名本 state 并持久化指针（误读爆炸半径被 REV-3 放大到 state 命名）。
        if [ -z "$_resolved" ]; then
          _disc_clear_pointer
          echo "{\"ok\":false,\"error\":\"PLAN_NOT_FOUND\",\"plan\":\"$plan_override\",\"fix\":\"传计划完整路径（禁止未解析短名落入金字塔兜底）\"}"
          return 1
        fi
        plan_override="$_resolved" ;;
    esac
    local _plan_basename; _plan_basename=$(basename "$plan_override" .md)
    # 2026-09-15（质询 F1 主刀 / A6-P2「路由执行侧强制」；REV-4 按 N2/N3/N8 修订）：
    # 计划声明 `META.state_domain` 时，隔离 state 按**域 token** 命名而非 plan-basename ——
    # 这正是 assessment 记录的「`discover --plan` 找不到域化 state」。绑定写入 plan 指针 ⟹
    # 后续任意 CLI 进程经启动块跟随指针 ⟹ STATE_FILE 端到端切换（判据 J5）。
    # REV-4 修订三点：
    #   ① 路径**不再自拼**：交 L4 1b 步（`resolve-state --domain`）解析 ⟹ 委托
    #      `gk_finding.resolve_domain_state`，token 校验与落点解析**单一事实源**（N2/N8）；
    #   ② 命名基址 = **默认 state 同级**（`$SKILL_DIR/.gatekeeper.state` 的所在目录）——
    #      确定性、不受上一次绑定残留影响；绑定成功后 STATE_FILE 即域 state，其同级目录
    #      与之一致 ⟹ 与 gk_finding 写入点同源；
    #   ③ kill switch `GK_STATE_DOMAIN_ROUTE=0` ⟹ 整块跳过，回 plan-basename 原链（N3）。
    # `--plan-pointer /nonexistent`：跳过 step 1（避免被上一次绑定的旧指针抢先返回）。
    PLAN_FILE="$plan_override"
    _read_plan_metadata
    local _dom="${META_state_domain:-}"
    # 域绑定生效标记（供指针写入域标记，缺口 a）
    local _dom_bound=""
    if [ -n "$_dom" ] && [ "${GK_STATE_DOMAIN_ROUTE:-1}" != "0" ]; then
      # n4-L2（2026-10-05）：`--build-state` —— 域 state **首建**（元数据中枢派生种子 + 单建者）。
      #   缺口：`gk_route_center.py build-state`（§18.2 c2）是 sanctioned 入口但**无 CLI 包装** ⟹
      #   直调 py 被 hook 拦 ⟹ CLI 无路建域 state（`discover --plan` 域缺失即 fail-closed 且无解除
      #   手段）。裁法：**不新增命令**（`_CMD_REG` 在 `PROTECTED_REGION::gate` 内，SKILL.md T48b）
      #   —— 挂既有 `cmd_discover` 的 `--build-state` 模式，薄转发 route-center。
      #   幂等：域 state 已存在 ⟹ `built=false`（单建者不覆盖）；失败 ⟹ 具名 fail-closed，禁静默绑定。
      if $build_state; then
        local _bs_json _bs_err
        _bs_json=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 "$SKILL_DIR/scripts/gk_route_center.py" build-state \
                     --skill-dir "$SKILL_DIR" --state-file "$_DEFAULT_STATE_FILE" \
                     --plan-file "$plan_override" --main-repo "$MAIN_REPO_WSL" 2>>"$GK_DBG_LOG" || echo '{}')
        _bs_err=$(printf '%s' "$_bs_json" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print('' if d.get('ok') else (d.get('error') or 'BUILD_STATE_FAILED'))
except Exception:
    print('BUILD_STATE_UNPARSABLE')
" 2>>"$GK_DBG_LOG")
        if [ -n "$_bs_err" ]; then
          _disc_clear_pointer
          echo "{\"ok\":false,\"error\":\"BUILD_STATE_FAILED\",\"detail\":\"$_bs_err\",\"domain\":\"$_dom\",\"plan\":\"$plan_override\"}"
          return 1
        fi
        echo "INFO[build-state]: 域 state 首建/确认 $_dom（$_bs_json）" >> "$GK_DBG_LOG"
      fi
      local _dom_json _dom_state _dom_err
      _dom_json=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-state \
                    --state-file "$_DEFAULT_STATE_FILE" --plan-pointer /nonexistent \
                    --domain "$_dom" 2>>"$GK_DBG_LOG" || echo '{}')
      _dom_state=$(printf '%s' "$_dom_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" \
        field expected --default '' 2>>"$GK_DBG_LOG")
      _dom_err=$(printf '%s' "$_dom_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" \
        field error --default '' 2>>"$GK_DBG_LOG")
      if [ -n "$_dom_err" ]; then
        # fail-closed：声明域后不静默回退（对齐 gk_finding.resolve_domain_state / ECC-C98BDE1D2B3B）
        # REV-5（缺口 c）：失败即清理旧指针（否则后续进程跟随**上一次**绑定的旧指针）
        _disc_clear_pointer
        echo "{\"ok\":false,\"error\":\"$_dom_err\",\"domain\":\"$_dom\",\"fix\":\"建域化 state（骨架可克隆自 $_DEFAULT_STATE_FILE），或移除计划 META 的 state_domain，或 GK_STATE_DOMAIN_ROUTE=0 关闭域解析\"}"
        return 1
      fi
      if [ -z "$_dom_state" ]; then
        # REV-5（缺口 c）：同上——解析未报错但无 expected 亦属"绑定未成立"
        _disc_clear_pointer
        echo "{\"ok\":false,\"error\":\"STATE_DOMAIN_UNRESOLVED\",\"domain\":\"$_dom\"}"
        return 1
      fi
      if [ "${STATE_FILE_EXPLICIT:-0}" = "1" ]; then
        # 2026-09-15 REV-5（第三轮质询 缺口 b）：原行为 = WARN 后**继续**——显式 STATE_FILE
        # 压过计划声明的域，而成功 JSON 无任何域字段 ⟹ 只读 stdout 的调用方无从得知
        # "域未生效" = **静默降级**（WARN 只进 stderr / dbg log）。现 fail-closed：
        # 显式 state 恰等域化 state 时放行（幂等），否则拒绝并要求显式取舍。
        if [ "$STATE_FILE" = "$_dom_state" ]; then
          _dom_bound="$_dom"
          echo "INFO[state-domain]: 显式 STATE_FILE 即域化 state（$_dom），幂等放行" >> "$GK_DBG_LOG"
        else
          # 2026-09-15 REV-5（四轮质询 G1）：**此处不调 `_disc_clear_pointer`** —— 显式
          # STATE_FILE 下启动块未定义 `_PLAN_POINTER`（:545 兜底空串），该函数立即 return 0
          # 是**构造性 no-op**（原写法看似"清理"实则空转，判据同为空真）。语义上也不该清：
          # 本进程**没有**指针通道，既未建立绑定，也无权删除**他进程**的绑定。故此处保持
          # "本进程不写不删"，由 J14 断言**指针原样保留**（而非断言"不存在"）。
          echo "{\"ok\":false,\"error\":\"STATE_DOMAIN_EXPLICIT_CONFLICT\",\"domain\":\"$_dom\",\"state_file\":\"$STATE_FILE\",\"domain_state\":\"$_dom_state\",\"fix\":\"去掉显式 STATE_FILE（让域绑定生效），或显式 GK_STATE_DOMAIN_ROUTE=0 声明放弃域解析\"}"
          return 1
        fi
      else
        # 真因 C 边界②（2026-11-02）：`build-state` 的域 state 路径同样是外部形态 ⟹ 归一。
        STATE_FILE="$(_gk_fwd "$_dom_state")"
        _dom_bound="$_dom"
        echo "INFO[state-domain]: discover --plan 绑定域化 state -> $_dom_state（token=$_dom）" >> "$GK_DBG_LOG"
      fi
    else
      # 幂等拼接：STATE_FILE 若已带该 plan 后缀（重复 discover --plan）则不再叠加
      # （修复 2026-08-08: 重复 discover 产生 .state.<plan>.<plan> 双重后缀）
      case "$STATE_FILE" in
        *".${_plan_basename}") : ;;
        *) STATE_FILE="${STATE_FILE}.${_plan_basename}" ;;
      esac
    fi
    # 持久化 plan 指针：跨进程联动隔离 state（修复 discover→advance 竞态，2026-08-03）
    # Phase 7b (2026-08-23): writer 字段标记写入者，供会话绑定 WARN 使用
    # 2026-09-04: 显式 STATE_FILE 上下文（指针未启用）跳过写入，防 > "" 语义
    # 2026-09-15 REV-5（缺口 a）：`domain` 字段标记**域化绑定**——启动块据此在
    # `GK_STATE_DOMAIN_ROUTE=0` 时拒绝跟随（kill switch 跨进程生效）。
    _bind_field=",\"state_file\":\"$STATE_FILE\""
    [ -n "$_dom_bound" ] && _bind_field="$_bind_field,\"state_domain\":\"$_dom_bound\""
    # 2026-09-25（②b）：写**本会话**指针（`_PLAN_POINTER_OWN`）—— 有会话身份时不再覆盖全局
    #   指针（会话级句柄）；显式 STATE_FILE 下 OWN 为空 ⟹ 跳过写入（既有语义保持）。
    if [ -n "${_PLAN_POINTER_OWN:-}" ]; then
      # 2026-11-01（ECC-55339EF8A5C6 / ECC-3057D0512735 现场）：路由中枢未拿到 sid 时
      #   `own` 退化为**全局** `.gatekeeper.plan` ⟹ discover 会覆盖顶层会话绑定。
      #   修法：写前若 own==全局且 `.gatekeeper.session` 有 sid，则改写到会话指针。
      if [ "$_PLAN_POINTER_OWN" = "$SKILL_DIR/.gatekeeper.plan" ]; then
        _sid_own=$(cut -f1 "$SKILL_DIR/.gatekeeper.session" 2>/dev/null | head -1)
        [ -n "$_sid_own" ] && _PLAN_POINTER_OWN="$SKILL_DIR/.gatekeeper.plan.$_sid_own"
      fi
      _ptr_dom=""
      [ -n "$_dom_bound" ] && _ptr_dom="domain=$_dom_bound"
      # 2026-09-28（并发写修复）：**原子写**（tmp + rename）—— 原 `> "$_PLAN_POINTER_OWN"` 是
      #   非原子重定向，并发 `discover`（多会话 / sid-less 同写一路径）可致读者见**半行** ⟹
      #   `json.load` 失败（静默回落默认 state）或读到损坏绑定。先例 = `.gatekeeper.session`
      #   （`pre_tool_hook._write_session_marker` 显式 tmp + os.replace）。
      # 2026-09-28（**J17 真回归修复**，`ECC-B69B9910C995`）：`mv -f <tmp> <dir>` **rc=0** ——
      #   目标已是**目录**时 mv 会把文件**搬进目录里**（实测：`mkdir T; echo x > p; mv -f p T`
      #   ⟹ rc0 且 `T/p` 存在）⟹ 原「目录 ⟹ 重定向必失败」的 J17 语义被原子写**误判为成功**。
      #   故**先判目录** = 写失败（保 WARN + `pointer_written:false`），再走 tmp + rename。
      # 2026-10-18（跨平台 ①A 修复）：**禁止手工拼 JSON**。原写法
      #   `echo "{\"state_file\":\"$STATE_FILE\",\"plan\":\"...\"}"`
      # 把 `$STATE_FILE` 的**原样字节**嵌进 JSON 字符串。Windows 侧解析出的 state 是
      #   `<home>\.trae\skills\...\.gatekeeper.state.skill.xxx`
      # ⟹ `\U` / `\H` / `\.`
      #   均为**非法 JSON 转义**（JSON 只认 `\" \\ \/ \b \f \n \r \t \uXXXX`）。
      # 后果链（**伪装成 stale**）：
      #   整份指针不是合法 JSON ⟹ 读侧 `json.loads` 抛 `Invalid \escape` ⟹ 调用方
      #   `except Exception: d = {}` ⟹ `d["updated"]` 缺失 ⟹ `_pointer_fresh` 返回 False
      #   ⟹ `reason="stale"` ⟹ CLI 报 **`STATE_POINTER_STALE`**。
      #   报错指向「指针过期」，真因是「JSON 写坏了」——跨平台静默降级 + 误导性诊断，
      #   且诱使调用方去拿 `GK_ALLOW_STALE_BASELINE=1` 这类降级钥匙（见豁免机制审计）。
      # 修法 = 走 `gk_json.py build`（**JSON 构造单一事实源**，`json.dumps` 正确转义路径）。
      # 先例：gatekeeper-cli.sh L6085-6126 已用 `build` 构造含路径的 JSON（`diff_files=$_diff`）。
      #   ⚠ 值经 argv 传入，路径里的空格/换行不再经过 shell 引号二次解释。
      # 守卫：`scripts/test_xplat_harness.py::b1_manual_json_splices_forbidden`。
      _ptr_json="$(python3 "$SKILL_DIR/scripts/gk_json.py" build \
                     "state_file=$STATE_FILE" "plan=$_plan_basename" \
                     "writer=discover" ${_ptr_dom:+"$_ptr_dom"} \
                     "updated=$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>>"$GK_DBG_LOG")"
      # `_ptr_json` 为空 = `gk_json.py` 自身失败（python 不在 PATH / 脚本缺失）——
      # 不静默：走下方 else 分支（`pointer_written:false` + WARN），跨进程绑定**未生效**可见。
      if [ ! -d "$_PLAN_POINTER_OWN" ] \
         && [ -n "$_ptr_json" ] \
         && printf '%s\n' "$_ptr_json" > "${_PLAN_POINTER_OWN}.tmp" 2>/dev/null \
         && mv -f "${_PLAN_POINTER_OWN}.tmp" "$_PLAN_POINTER_OWN" 2>/dev/null; then
        _bind_field="$_bind_field,\"pointer_written\":true"
      else
        # 五轮质询 H3：写失败不再被 `|| true` 吞 —— 跨进程绑定**未生效**必须可见
        _bind_field="$_bind_field,\"pointer_written\":false"
        echo "WARN[plan-pointer]: 指针写入失败（$_PLAN_POINTER_OWN）—— 跨进程绑定未生效" >&2
        echo "WARN[plan-pointer]: pointer write failed ($_PLAN_POINTER_OWN)" >> "$GK_DBG_LOG"
      fi
      unset _ptr_dom
    fi
  fi

  if [ -n "$plan_override" ]; then
    # 2026-09-15 REV-5（四轮质询 G2）：指针已在上面写好 ⟹ 此后任何 return 1 都会**留下一个新绑定**
    # （且目标 state 可能尚未初始化）⟹ "失败 = 没有绑定" 在全命令范围内不成立。两条后置失败出口
    # 都必须清理（cd 失败 + no META phases）。
    cd "$SKILL_DIR" 2>/dev/null || { _disc_clear_pointer; echo '{"ok":false,"error":"skill dir not found"}'; return 1; }
    PLAN_FILE="$plan_override"
  else
    # 清除 plan 指针 + 复位 STATE_FILE 到默认（无 --plan 的 discover 退出隔离计划。
    # 进程启动可能已跟随指针，变量不复位会导致本次 discover 仍操作隔离 state — 2026-08-03 补丁）
    # 2026-08-28 修复：显式 env STATE_FILE（STATE_FILE_EXPLICIT=1）不覆盖——用户显式指定优先。
    # 2026-09-25（②b）：清**本会话/本进程的写目标**（OWN）而非跟随目标 —— 会话间不再互相清
    # 绑定（`OWN` 在显式 STATE_FILE 下为空 ⟹ 保持"本进程既未建立绑定也无权删除"）。
    rm -f "${_PLAN_POINTER_OWN:-$_PLAN_POINTER}" 2>/dev/null || true
    _disc_sweep_stale_plan_pointers
    if [ "${STATE_FILE_EXPLICIT:-0}" != "1" ]; then
      STATE_FILE="$_DEFAULT_STATE_FILE"
    fi
    cd "$MAIN_REPO_WSL" 2>/dev/null || { echo '{"ok":false,"error":"main repo not found"}'; return 1; }
  fi

  local branch="" r_phase="" stage="" worktree="" detected=false warnings=""

  # R5.8++: read plan metadata — dynamic phases, no hardcoded lists
  _read_plan_metadata

  # If no phases defined in plan, error out — no hardcoded fallback
  local valid_phases="${META_phases}"
  if [ -z "$valid_phases" ]; then
    # REV-5（G2）：后置失败出口——清掉本进程刚写入的绑定（"失败 = 没有绑定"）
    _disc_clear_pointer
    echo '{"error":"no META phases found in plan document","hint":"Add <!-- META phases: R7 --> to your plan"}' >&2
    return 1
  fi
  local project_type="${META_project_type:-standard}"
  # project_type: standard (STAGE_0-5 machine), standing (ECO phases, no gate), analysis (ECC phases, no gate)

  # 2026-09-04 L3 接线（方案 A）：worktree 定位统一委托元数据路由中枢 resolve-worktree ——
  # 单一事实源（取代内嵌 git branch --list + FEATURE_PREFIX 判定，消除双实现漂移与
  # "其他仓库 worktree 漏检"）。仓库上下文原为 `basename "$(pwd)"`，2026-09-25（⑤ worktree
  # 落点归一）改为注入**调用方 cwd 路径** `GK_WORKTREE_CWD`：调用方 cwd 常落在 feature worktree
  # 目录（`.trae/worktrees/<repo>/feature/<branch>`）或技能仓子目录 ⟹ 目录名 ≠ 仓库名 ⟹ 段名
  # 过滤恒不命中（静默漏检本仓 worktree / 被他仓最新 worktree 顶替）。归一由路由中枢用 **git
  # 权威视图**（该仓主 worktree 目录名）完成（禁第二实现，对齐 `ECC-DEBCB4AC53C3`）；
  # 仍以 GK_WORKTREE_REPO 语义限定"只列本仓库 feature worktree"（防他仓库最新顶替）；
  # GATEKEEPER_WORKTREE_ROOT env 显式前缀仍优先（python 白名单 + `..` 段拒绝）。
  local _wt_json
  _wt_json=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" MAIN_REPO_WSL="$MAIN_REPO_WSL" \
    GK_WORKTREE_CWD="$(pwd)" GK_PLAN_FILE="$PLAN_FILE" \
    python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-worktree 2>>"$GK_DBG_LOG" || echo '{}')
  # 2026-09-23（**ECC-084E37B42CFB 修复**，同 META 块同根因）：`repr()` 非 shell 安全序列化器
  #   ⟹ 改 `shlex.quote`。注意 `detected` 走 `str(bool)`：`shlex.quote('True')` = `True`（无需引号），
  #   与下行 `[ "$detected" = "True" ]` 的语义**逐字等价**。
  eval "$(echo "$_wt_json" | python3 -c "
import sys,json,shlex
try:
    d=json.load(sys.stdin)
except Exception:
    d={}
print('branch='+shlex.quote(str(d.get('branch',''))))
print('worktree='+shlex.quote(str(d.get('worktree',''))))
print('r_phase='+shlex.quote(str(d.get('r_phase',''))))
print('detected='+shlex.quote(str(bool(d.get('detected')))))
" 2>>"$GK_DBG_LOG")"
  [ "$detected" = "True" ] && detected=true || detected=false

  if $detected; then
    # R5.8++: validate R-phase against plan metadata —— 2026-09-04 L3 接线后升级为绑定门：
    # 自动探测已跨仓库化，可命中他仓库/残留 worktree（如 spz2glb-r7）；r_phase 非空且
    # ∉ plan phases → 不绑定，回退下方 standing/META-only 落位（保持 discover
    # "worktree 相位须匹配当前计划"语义；原单仓库扫描天然无法命中他仓库故无需此门）。
    local valid=false
    for p in $valid_phases; do
      [ "$r_phase" = "$p" ] && { valid=true; break; }
    done
    if ! $valid; then
      warnings="unknown R-phase: $r_phase — plan declares phases: $valid_phases"
      if [ -n "$r_phase" ]; then
        branch=""; worktree=""; r_phase=""; detected=false
      fi
    fi

    # R5.8++: worktree_needed validation from plan metadata
    if [ "$META_worktree_needed" = "false" ] && [ -n "$worktree" ]; then
      warnings="${warnings:+$warnings, }plan says worktree_needed=false but worktree exists ($worktree)"
    fi
  fi

  if ! $detected; then
    # --plan override: skip standing plan fallback (user explicitly specified plan)
    if [ -z "$plan_override" ]; then
      # Standing plan fallback: look for docs/plans/000-*.md in skill dir
      local standing_plan
      standing_plan=$(ls "$SKILL_DIR"/docs/plans/*-standing-plan.md 2>/dev/null | head -1)
      if [ -n "$standing_plan" ] && [ "$project_type" = "standard" ]; then
        local saved_plan="$PLAN_FILE"
        PLAN_FILE="docs/plans/$(basename "$standing_plan")"
        _read_plan_metadata
        project_type="${META_project_type:-standard}"
        if [ -n "${META_phases:-}" ]; then
          local first_phase; first_phase=$(echo "$META_phases" | awk '{print $1}')
          local cur_branch; cur_branch=$(cd "$SKILL_DIR" 2>/dev/null && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
          r_phase="$first_phase"
          branch="$cur_branch"
          worktree="$SKILL_DIR"
          detected=true
          if [ "$project_type" = "standard" ]; then
            stage="STAGE_0"
          else
            stage="$first_phase"
          fi
        else
          PLAN_FILE="$saved_plan"
        fi
    fi
  fi
  fi

  if ! $detected; then
    # META-only fallback: no git branch but META has phases
    if [ -n "${META_phases:-}" ]; then
      local first_phase; first_phase=$(echo "$META_phases" | awk '{print $1}')
      local cur_branch; cur_branch=$(cd "$SKILL_DIR" 2>/dev/null && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
      r_phase="$first_phase"
      branch="$cur_branch"
      worktree="$SKILL_DIR"
      detected=true
      if [ "$project_type" = "standard" ]; then
        stage="STAGE_0"
      else
        stage="$first_phase"
      fi
    fi
  fi

  if ! $detected; then
    # ECC-7EC88E41702A（2026-10-07 质询 6 臂）：IDLE 早退原用裸 `cat >` 写 state（零 carry /
    #   零 checksum / 非原子）+ `return 0` ⟹ 绕过单一出纳、抹掉跨轮键（与下方主重建路径的
    #   carry 纪律不一致）。修：快照 → 写 IDLE → 经 `_state_write` + `carry_over` 回填。
    _idle_cf="${STATE_FILE}.discover-carry.idle.$$"
    if [ -f "$STATE_FILE" ]; then
      cp -f "$STATE_FILE" "$_idle_cf" 2>/dev/null || {
        echo '{}' > "$_idle_cf"
        echo "WARN[discover-carry]: IDLE 快照 cp 失败（$STATE_FILE）⟹ 跨轮键回填无源" >&2
        echo "WARN[discover-carry]: idle carry snapshot cp failed" >> "$GK_DBG_LOG"
      }
    else
      echo '{}' > "$_idle_cf"
    fi
    cat > "$STATE_FILE" << 'EOFSTATE'
{"r_phase":null,"stage":"IDLE","branch":null,"worktree":null,"gate_data":{},"monitor_scores":{},"history":[]}
EOFSTATE
    GK_PY_CARRY="$(_gk_py_path "$_idle_cf")" _state_write "
import os
from gk_discover_carry import carry_over
try:
    _old=json.load(open(os.environ['GK_PY_CARRY'],encoding='utf-8'))
except Exception:
    _old={}
carry_over(_old,d)
"
    rm -f "$_idle_cf" 2>/dev/null || true
    echo "{\"ok\":true,\"status\":\"idle\",\"r_phase\":null,\"stage\":\"IDLE\",\"message\":\"No active R-phase. Ready for next R.\",\"target_repo\":\"${project_type}\",\"repo_hash\":\"${SKILL_REPO_HASH}\",\"repo_paths\":{\"gatekeeper\":\"${MAIN_REPO_WIN}\",\"skill\":\"${SKILL_DIR}\"}}"; return 0
  fi

  local _carry_f=""
  if [ -f "$STATE_FILE" ]; then
    # 2026-10-02（`ECC-01E84B0E87F5`）：carry 快照须在 phase 归档清空 gate_data **之前**取 ——
    #   否则 phase-changed 路径下 snapshot 已无 `ecc_findings`/`edit_budget`，carry 无从回填。
    _carry_f="${STATE_FILE}.discover-carry.$$"
    # ECC-A52B0EAB6C6D（2026-10-07 质询 6 臂）：cp 失败**禁静默**回退空对象（原式 `… || echo '{}'`
    #   可让保全在生产路径整体 no-op 且**零留痕**）⟹ 失败须留痕（stderr WARN + GK_DBG_LOG）；
    #   行为保持不阻断（对齐本仓「依赖不可用不得锁死序列」fail-soft 纪律）。
    if ! cp -f "$STATE_FILE" "$_carry_f" 2>/dev/null; then
      echo '{}' > "$_carry_f"
      echo "WARN[discover-carry]: 快照 cp 失败（$STATE_FILE → $_carry_f）⟹ 跨轮键回填无源，可能丢失" >&2
      echo "WARN[discover-carry]: carry snapshot cp failed ($STATE_FILE)" >> "$GK_DBG_LOG"
    fi
    local prev_phase prev_stage; prev_phase=$(json_val "$STATE_FILE" r_phase ""); prev_stage=$(json_val "$STATE_FILE" stage "")
    if [ "$prev_phase" = "$r_phase" ] && [ -n "$prev_stage" ]; then stage="$prev_stage"
    else
      stage="STAGE_0"
      # Phase changed — archive old R into history
      python3 "$SKILL_DIR/scripts/gk_discover_archive.py" archive "$STATE_FILE" "$_DEFAULT_STATE_FILE" "$_AUDIT_KEY_DIR" "$(date -Iseconds)" 2>/dev/null || true
    fi
  else
    if [ "$project_type" != "standard" ]; then
      : # stage already set by standing/analysis plan above
    else
      stage="STAGE_0"
    fi
  fi

  # I7: Read last_release_check BEFORE state rebuild (discover wipes gate_data)
  # T2 (2026-08-25): 主 state 归属预检 — 无 --plan 复位后、重建前读取旧主 state 归属；
  # 若被其他项目污染（如门卫 R7.1），在 discover 输出显式携带 state_ownership（不自动改，
  # 配合 gk_state_route T3 的候选描述，提示用 discover --plan 指定隔离 state）。
  local _owner_json="" _owner_field=""
  if [ -z "$plan_override" ]; then
    _owner_json=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-state 2>>"$GK_DBG_LOG" || echo '{}')
    if echo "$_owner_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test conflict 2>/dev/null; then
      _owner_field=",\"state_ownership\":$(echo "$_owner_json" | python3 "$SKILL_DIR/scripts/gk_views.py" conflict-view 2>/dev/null || echo '{"conflict":true}')"
    fi
  fi
  local old_rc; old_rc=$(python3 "$SKILL_DIR/scripts/gk_state.py" get gate_data.last_release_check --path "$STATE_FILE" --default 0 2>/dev/null || echo "0")
  # 2026-10-01（finding ECC-A135BE8837AF 修复）：重建前**整份快照** —— 下方 heredoc 只写
  #   {r_phase,stage,branch,worktree,main_repo,gate_data:{},monitor_scores,history} ⟹ 并发会话的
  #   `gate_data.edit_budget.sessions[*]`（额度盒）与顶层 `worktrees_extra`（活动写面允许集）被
  #   一并抹掉；hook 下次编辑按缺省**自动建盒 0/0** ⟹ 他会话被 Gate4 `edit_budget exhausted`
  #   死锁（2026-10-01 实测：并发会话 6a3e3469… 的 max32/used58/remaining2 被抹成 0/0/0）。
  #   ⚠ 保全**清单与判据**在单一事实源 `scripts/gk_discover_carry.py`（此处只做「快照 + 回填」，
  #     **不**复制白名单）；快照走**文件**（非 shell 内插）⟹ 值含 $ / 反引号 / 换行都不经 shell 展开。
  # 快照已在「state 存在」分支起取（先于 phase 归档）；此处仅兜底 state 缺失场景。
  _carry_f="${_carry_f:-${STATE_FILE}.discover-carry.$$}"
  [ -f "$_carry_f" ] || echo '{}' > "$_carry_f"
  # 2026-11-01（跨平台 ①D 修复）：**禁止 heredoc 手工拼 state JSON**。原写法
  #   cat > "$STATE_FILE" << EOFSTATE
  #   {"r_phase":"$r_phase",...,"main_repo":"$MAIN_REPO_WIN",...}
  #   EOFSTATE
  # 把四个**外部来源**的字符串直接嵌进 JSON 字符串体：
  #   · Windows 反斜杠路径（`<home>`）⟹ `\U` 非法转义（真因 A 同族）；
  #   · **CRLF 泄漏** —— 实测 `MAIN_REPO_WIN` 值为**裸 `\r`**（字节 152）⟹
  #     `json.loads` 抛 **`Invalid control character`** ⟹ **整份 state 不可读**
  #     ⟹ 所有读点 `{"error":"json_decode_error"}` ⟹ 质询链在入队后 57s 处全线中断。
  #     报错只说"解码失败"，真因是"写入时没剥 \r" —— 又一次**真因被伪装**。
  #   · `$history` 是命令替换产物（可能含换行）。
  # 修法 = **值经 env 传入 python，由 `json.dumps` 序列化**（本仓先例：`_budget_override_record`
  #   的「reason 经 env 传入（而非拼进 python 源码）⟹ 规避引号/换行注入」）。
  #   ⚠ 不能用 `gk_json.py build`：其 `_default_coerce` 把 `{}`/`[]` 当**字符串** ⟹
  #     `gate_data`/`monitor_scores`/`history` 会从对象退化成字符串（语义破坏）。
  #   ⚠ heredoc 用 `<<'PY'`（quoted）⟹ python 源码不经 shell 展开；值只走 env。
  _hist_json="$(python3 "$SKILL_DIR/scripts/gk_state.py" get history --path "$STATE_FILE" --json --default '[]' 2>/dev/null || echo '[]')"
  if GK_ST_R_PHASE="$r_phase" GK_ST_STAGE="$stage" GK_ST_BRANCH="$branch" \
     GK_ST_WORKTREE="$worktree" GK_ST_MAIN_REPO="$MAIN_REPO_WIN" \
     GK_ST_HISTORY="$_hist_json" \
     python3 - > "${STATE_FILE}.tmp.$$" 2>>"$GK_DBG_LOG" <<'PY'
import json, os, sys
def g(k, d=""):
    v = os.environ.get(k)
    return d if v is None else v
try:
    hist = json.loads(g("GK_ST_HISTORY", "[]"))
except Exception:
    hist = []
out = {
    "r_phase": g("GK_ST_R_PHASE"), "stage": g("GK_ST_STAGE"),
    "branch": g("GK_ST_BRANCH"), "worktree": g("GK_ST_WORKTREE"),
    "main_repo": g("GK_ST_MAIN_REPO"), "gate_data": {}, "monitor_scores": {},
    "history": hist,
}
sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
PY
  then
    mv -f "${STATE_FILE}.tmp.$$" "$STATE_FILE" 2>/dev/null || cp -f "${STATE_FILE}.tmp.$$" "$STATE_FILE" 2>/dev/null
  else
    # python 自身失败（不在 PATH / 语法错）⟹ 不静默：WARN + 保持原 state 不覆盖
    rm -f "${STATE_FILE}.tmp.$$" 2>/dev/null
    echo "WARN[state-rebuild]: state JSON 构造失败（python env 通道），保持原 state 未覆盖" >&2
    echo "WARN[state-rebuild]: state rebuild failed; state left untouched $GK_SID_TAG" >> "$GK_DBG_LOG"
  fi
  unset _hist_json
  # 保全回填：纯函数（`gk_discover_carry.carry_over`）+ **单一出纳** `_state_write`
  #   （flock + 原子写 + checksum）⟹ 不新增第二写者；保全失败绝不阻断 discover 主流程。
  GK_PY_CARRY="$(_gk_py_path "$_carry_f")" _state_write "
import os
from gk_discover_carry import carry_over as _carry
try:
    _old=json.load(open(os.environ['GK_PY_CARRY'],encoding='utf-8'))
except Exception:
    _old={}
_carry(_old,d)
"
  rm -f "$_carry_f" 2>/dev/null || true
  # Inject scheduler defaults into gate_data.scheduler
  # F-REV-83（2026-09-16）：**补 producer** —— `target_repo` 原**只进 stdout 不进 state**
  # （实测现存 state **全部无该键**：技能仓库 7 + dryrun worktree 2）⟹ 消费端
  # `_gx_repo_dir_for_current` 恒落兜底分支
  # （元数据中枢的指定从未落库）。此处与 `gate_data.project_type` **同处同源**落库；
  # ⚠ **仅在 plan META 显式给出时写**（缺 META ⟹ 写空串 = 保持"未指定"语义 ——
  # 禁把 `project_type` 当 repo 名污染该字段）。
  python3 "$SKILL_DIR/scripts/gk_state_ops.py" discover-scheduler "$STATE_FILE" "$SCHEDULER_MODE" "$SCHEDULER_MAX_LR" "$SCHEDULER_MIN_LR" "$SCHEDULER_TOTAL_STEPS" "${project_type}" "${old_rc:-0}" "${META_target_repo:-}" 2>/dev/null || true
  # --- I7: auto-trigger release-check for standing projects (external cycle watchdog) ---
  # meta-routing-protocol.md §4-7: release-check scans 8 tracked projects daily.
  # If standing and >24h since last check, auto-run with 10s timeout.
  if [ "$project_type" = "standing" ]; then
    local last_rc
    last_rc=$(python3 "$SKILL_DIR/scripts/gk_state.py" get gate_data.last_release_check --path "$STATE_FILE" --default 0 2>/dev/null || echo "0")
    local now; now=$(date +%s)
    if [ $(( now - ${last_rc:-0} )) -gt 86400 ] 2>/dev/null; then
      local rc_out; rc_out=$(timeout 15 bash "$0" release-check 2>/dev/null || echo '{"ok":false,"error":"timeout_or_unavailable"}')
      # F-REV-20（2026-09-10）：JSON 一律走 env —— 原 json.loads('''$rc_out''') 源码字面量内插，
      # 内容含反斜杠（如 C:\Users）时编译期 SyntaxError → 被 2>/dev/null 静默吞；解析失败保留原文
      # 并落 GK_DBG_LOG（非静默降级）。逻辑已收归 gk_state_ops.py release-check-record。
      RC_OUT="$rc_out" python3 "$SKILL_DIR/scripts/gk_state_ops.py" release-check-record "$STATE_FILE" 2>>"$GK_DBG_LOG" || true
    fi
  fi
  # ── v4.18: 裸跑检测 (T73) ──
  local warnings_json; warnings_json=$(_detect_bare_run_gatekeeper)
  # R5.8++: append project-type warnings — 并入 warnings 数组（原实现拼接
  # `"project":"..."` 裸键值对，与 bare_run 数组混用 → 输出 JSON 必非法。2026-08-03 修复）
  if [ -n "$warnings" ]; then
    warnings_json=$(WJ="$warnings_json" W="$warnings" python3 -c "
import json,os
base=os.environ.get('WJ','')
try:
    arr=json.loads(base) if base.strip() else []
except Exception:
    arr=[]
arr.append(os.environ.get('W',''))
print(json.dumps(arr))
" 2>>"$GK_DBG_LOG" || echo '["'"$warnings"'"]')
  fi
  local discover_target="${META_target_repo:-${project_type}}"
  # §17-4 A 步②：`state.worktree` 已定稿 ⟹ 同步 claim（供 D-a 回收闸 / D-b② 谓词对账；
  #   fail-soft / sid-gated / 主树排除 / 幂等，绝不改本命令行为与 rc）。
  _gk_state_wt_claim_sync "$worktree"
  if [ -n "$warnings_json" ]; then
    echo "{\"ok\":true,\"status\":\"active\",\"r_phase\":\"$r_phase\",\"stage\":\"$stage\",\"branch\":\"$branch\",\"project_type\":\"$project_type\",\"target_repo\":\"${discover_target}\",\"repo_hash\":\"${SKILL_REPO_HASH}\",\"repo_paths\":{\"gatekeeper\":\"${MAIN_REPO_WIN}\",\"skill\":\"${SKILL_DIR}\"},\"warnings\":$warnings_json$_owner_field$_bind_field}"
  else
    echo "{\"ok\":true,\"status\":\"active\",\"r_phase\":\"$r_phase\",\"stage\":\"$stage\",\"branch\":\"$branch\",\"project_type\":\"$project_type\",\"target_repo\":\"${discover_target}\",\"repo_hash\":\"${SKILL_REPO_HASH}\",\"repo_paths\":{\"gatekeeper\":\"${MAIN_REPO_WIN}\",\"skill\":\"${SKILL_DIR}\"}$_owner_field$_bind_field}"
  fi
  _state_checksum_write
}

# ── v4.18 T73: gatekeeper 裸跑检测 ──
_detect_bare_run_gatekeeper() {
  cd "$MAIN_REPO_WSL" 2>/dev/null || { echo ""; return; }
  local warnings=""
  # 检测 1: commit_shas 为空但 git log 有 R-phase 格式提交
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
  local r_commits; r_commits=$(git log -n 10 --oneline 2>/dev/null | "$RG" -c 'feat\(R|fix\(R' || echo "0")
  if [ "$r_commits" -gt 2 ] 2>/dev/null && [ -f "$STATE_FILE" ]; then
    local shas; shas=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --len gate_data.commit_shas --default 0 2>/dev/null)
    if [ "$shas" = "0" ]; then
      warnings=$(printf '%s["BARE RUN: git log has %s R-phase commits but commit_shas empty — governance skill likely bypassed. Run advance to re-sync."]' "${warnings:+,}" "$r_commits")
    fi
  fi
  # 检测 2: state 过期但 git 有新提交
  if [ -f "$STATE_FILE" ]; then
    local last_upd; last_upd=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get current.last_updated --default "" 2>/dev/null)
    if [ -n "$last_upd" ] && [ "$r_commits" -gt 0 ] 2>/dev/null; then
      local days_since; days_since=$(( ($(date +%s) - $(date -d "$last_upd" +%s 2>/dev/null || echo 0)) / 86400 ))
      if [ "$days_since" -ge 1 ] 2>/dev/null; then
        warnings=$(printf '%s["STATE STALE: last updated %s day(s) ago but git has %s R-phase commits."]' "${warnings:+,}" "$days_since" "$r_commits")
      fi
    fi
  fi
  if [ -n "$warnings" ]; then
    echo "[$warnings]"
  else
    echo ""
  fi
}

# ---------- SHA256 state integrity (bridge v4.16) ----------
# Refs: Bridge architecture v4.16 (state checksum as tamper detection)
#       bridge-cli.py _state_checksum_write/verify (Python pattern)
# R5.8: _state_checksum_verify now exits 1 on mismatch (was always 0)
# SECURITY NOTE (V5→V6, 2026-09-25 **选项 A**，用户裁定「唯一锁持有者 = python」)：
# 原注释称「加 flock 会增加复杂度与 WSL 兼容风险，故不加」—— 已被实测推翻（并发读-改-写
# 丢更新：`used=2` 而 `remaining` 只由 8→7）。原 bash `_with_state_lock()`
# （`flock -w 5` on `${STATE_FILE}.lock`）**已拆除**；锁资源不变（仍是 `<state>.lock`，
# fcntl.flock 与 flock(1) 是同一底层锁），但持有者改为 python 侧
# `gk_json_utils.state_lock`（可重入 + 5s 超时）—— python 侧 ~15 个写通道由此**全覆盖**，
# 而只锁 bash 只能覆盖 2 个入口。bash 侧一律经 `_state_write` / `_state_checksum_write`
# 的 python 载荷在锁内完成「读-改-写」。
# 判据见 scripts/test_gk_state_write_single_entry.py。
# [write_guard 裁决 2026-09-06 EXEMPT] 最低层写原语：dry_run 守卫由调用方承担，
# check 语义调用方（cmd_advance L3297/L3410）均已守卫——勿在本原语内机械包守卫（会阻断真实写入）。
_state_write() {
  # 2026-09-23（**ECC-60BBDCDB2F70 修复**）：原实现 `json.dump(d, open('$STATE_FILE','w'))`
  # 是**先截断再流式写**（本处注释却称 "Atomic write"）—— 进程中途被中断即留下**半截
  # state**：实测 2026-09-23 13:46 `.gatekeeper.state` 断在 `edit_budget.overrides[].reason`
  # 中途（27378/75913 B），hook Gate 1 随即拦掉**所有** Edit/Write，整条流水线阻塞。
  # 修法：改走 python 侧**单一出纳** `gk_json_utils.dump_state`（tmp + fsync +
  # `os.replace`，原子、无半写）；形态参数（indent=1 / ensure_ascii=False / newline='\n'）
  # 由该出纳统一持有 ⟹ bash 侧不再复制形态字面量（收敛，非新增写者）。
  # 2026-09-25（**选项 A**）：`_with_state_lock` 拆除后锁改由 python 侧持有 —— 本载荷在
  # `state_lock` 内完成「读-改-写」全程（`dump_state` 再取锁是**可重入**的，不自锁）。
  # ⚠ 载荷 `$1` **必须在行首**（不得缩进）⟹ 不能用 `with`（缩进会 IndentationError），
  #   故显式 `__enter__/__exit__`；进程退出即关 fd 释放锁 ⟹ 异常路径也不泄漏。
  # 2026-11-02（真因 D 第二轮）：state / scripts 路径**经 env 传入**（形态锚 = 解释器，
  #   见 `_gk_py_path`）。原内联 `'$STATE_FILE'` 在 MSYS bash + 原生 Windows python 下
  #   直接 FileNotFoundError ⟹ 所有经本出纳的写通道整段失效，且被 `2>/dev/null` 吞成静默。
  GK_PY_SCRIPTS="$(_gk_py_path "$SKILL_DIR/scripts")" \
  GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" \
  python3 -c "
import sys,json,hashlib,os
sys.path.insert(0,os.environ['GK_PY_SCRIPTS'])
from gk_json_utils import dump_state, state_lock
_lk=state_lock(os.environ['GK_PY_STATE']); _lk.__enter__()
d=json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'))
$1
# checksum 更新与原子落盘由 dump_state 一并完成
gd=json.dumps(d.get('gate_data',{}),sort_keys=True)
d['_checksum']=hashlib.sha256(gd.encode()).hexdigest()[:16]
dump_state(os.environ['GK_PY_STATE'], d)
_lk.__exit__(None, None, None)
" 2>/dev/null
}
# 2026-09-19 P5 §3 T5′ / 计划次序 S1-b（计量断链 ECC-F5FE1042A7BA 的配套，用户裁定方案 d）：
# edit_budget 覆盖留痕 —— 三条逃生舱路径（GATEKEEPER_EDIT_BUDGET / GK_BUDGET_OVERRIDE=1 /
# 人工 state-patch）本来**全是静默的**：本会话 state 里的 max:8 超出 scheduler.max_lr=4 的天花板
# ⟹ 必由人工 state-patch 抬出，而当时零留痕，只能靠撞墙次数反推。
# 2026-09-30 G4-e（REV-5 §13.3「分账收口」）：留痕**判据面**由内嵌 `edit_budget.overrides[]` 改为
#   旁挂 append-only 账本（见下 `_budget_log_append`）—— 前者被 `state-patch` 对 gate_data 顶层键的
#   整体替换**写一次砸一次**（实测 `overrides` 7→1）。`overrides[]` 由此**降级为只读遗留**
#   （本函数不再写它；阅读面统一以旁挂为准，`audit` / 熵第三支已如此）。
# ⚠ `reason` 属**自报字段** ⟹ 仅作审计叙述，**不得作为任何门禁判据**（P5 §5 纪律）。
# ⚠ 本助手**只记账**，不改变任何节点的可用额度。
# reason 经 env 传入（而非拼进 python 源码）⟹ 规避引号/换行注入。
# R1-b（2026-10-01）：**信用分旁挂账本**（跨会话累积；append-only + 封印）—— 与 `_budget_log_append`
#   同族、同层（**区外**）。提额/覆盖事件在**同一 choke point**（`_budget_override_record`）登记一条
#   `kind=bookkeeping delta=0` 的**中性记账**（只记「何时改了预算」，**不**代表审计事件；
#   `success/fail/overspend` 的赋值由审计署（§13.5c）后续回填）。写实现单源 = `scripts/gk_credit_ledger.py`。
#   2026-10-19（owner 方案 a）：原实现发 `kind=raise` ⟹ `reconcile` 把它当待审债，
#   224 条预算记账被机械报为 224 起未审债。现改发 `bookkeeping`（`reconcile` 不计债）；
#   历史 224 条由**签名基线** `<state>.credit-ledger.baseline.json` 划为 legacy。
# ⚠ 与 `_budget_log_append` 同层（区外，非保护区内）⟹ **零保护区改动**。
_credit_log_append() {  # <kind> <delta> <source> <reason>
  local _out _rc=0
  _out=$(python3 "$SKILL_DIR/scripts/gk_credit_ledger.py" append \
           --state "$STATE_FILE" --kind "${1:-raise}" --delta "${2:-0}" \
           --source "${3:-}" --reason "${4:-}" 2>&1) || _rc=$?
  if [ "$_rc" != "0" ]; then
    printf 'GATEKEEPER-WARN: [credit-ledger] 账本写入失败（fail-loud, rc=%s）：%s\n' "$_rc" "$_out" >&2
    return 1
  fi
  return 0
}

_budget_override_record() {  # <source> <reason>
  _budget_log_append "${1:-}" "${2:-}"
  # R1-b：同一 choke point 登记一条**中性记账**（`bookkeeping` / `delta=0`）；失败不阻断。
  _credit_log_append "bookkeeping" "0" "${1:-}" "${2:-}" || true
}

# REV-3 §12.7：提额**旁挂账本**（append-only，`<state>.budget-log.jsonl`）—— 熵第三支 / audit 的
# **唯一可靠测量面**。`overrides[]` 会被 `state-patch` 对 `gate_data` 顶层键的整体替换**砸掉**，
# 本文件只追加、永不被覆盖。与 `scripts/gk_advance.py::budget_log_append` 同口径（同后缀、同记录形状）。
# ⚠ 本函数与 `_budget_override_record` 同层（**区外**，非保护区内）⟹ 零保护区改动。
# 2026-09-30 G4-e（REV-5 §13.3）：**唯一写入面**（`overrides[]` 已降只读遗留）；并修 §12.7 规格漂移 ——
#   记录补 `from_max` / `to_max`（「提额幅度」可**复算**）与 `expires_at`（提额**有效期**，绑会话 TTL
#   `GK_SESSION_TTL`，默认 1800s）。`from_max` 取**链式**：上一条记录的 `to_max`（首条无前项 ⟹ `None`）。
_budget_log_append() {  # <source> <reason>
  # 2026-09-30 owner 裁定 C1–C4：读写**单源**归 `scripts/gk_budget_ledger.py`
  #   （C1 `kind` 就地过滤 / C2 封印 seal / C3 fail-loud / C4 坏行不计入）。
  # ⚠ C3 订正：原 `>/dev/null 2>&1 || true` 把写失败**静默吞掉**（P13）—— 现改为
  #   失败即 stderr 告警 + 落 `GK_DBG_LOG`（调用方仍可 `|| true` 不阻断，但**不再无声**）。
  local _out _rc=0
  _out=$(python3 "$SKILL_DIR/scripts/gk_budget_ledger.py" append \
           --state "$STATE_FILE" --source "${1:-}" --reason "${2:-}" \
           --ttl "${GK_SESSION_TTL:-1800}" 2>&1) || _rc=$?
  if [ "$_rc" != "0" ]; then
    printf 'GATEKEEPER-WARN: [budget-log] 账本写入失败（C3 fail-loud, rc=%s）：%s\n' "$_rc" "$_out" >&2
    printf '%s budget-ledger-append-failed rc=%s: %s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_rc" "$_out" >>"${GK_DBG_LOG:-/dev/null}" 2>/dev/null
    return 1
  fi
  return 0
}

# edit-log 写入单源（ED1/ED4，2026-10-08；承 §23.8.1）—— 委托 `gk_budget_ledger.py edit-append`，
#   消原保护区内**内联 printf** 的第二实现（6/6 臂收敛缺陷 ED1：写侧双实现 ⟹ 载体臂测死路径；
#   ED8：内联 `printf '%(%Y…)T'` 是**本地时区 + 字面 Z**，与模块 `_now_str` 的 UTC 双源）。
# fail-loud 同 C3 口径（`_budget_log_append`）：失败 stderr 告警 + 落 `GK_DBG_LOG`，调用方可不阻断但**不再无声**。
# ⚠ 本函数与 `_budget_log_append` 同层（**区外**）；只写 `<state>.edit-log.jsonl`，**不碰** remaining/used/billed_files。
_edit_log_append() {  # <result: allow|reject|override> <path> <node>
  [ -n "${STATE_FILE:-}" ] || return 0
  local _out _rc=0
  _out=$(python3 "$SKILL_DIR/scripts/gk_budget_ledger.py" edit-append \
           --state "$STATE_FILE" --session "${GK_SESSION_ID:-}" \
           --node "${3:-}" --path "${2:-}" --result "${1:-allow}" 2>&1) || _rc=$?
  if [ "$_rc" != "0" ]; then
    printf 'GATEKEEPER-WARN: [edit-log] 载体写入失败（ED4 fail-loud, rc=%s）：%s\n' "$_rc" "$_out" >&2
    printf '%s edit-log-append-failed rc=%s: %s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_rc" "$_out" >>"${GK_DBG_LOG:-/dev/null}" 2>/dev/null
    return 1
  fi
  return 0
}

# ── 节点编辑额度「agent 池 additive」注入（2026-09-23 用户裁定「梯度×2 + agent 池 additive」）──
# 依据设计 §4：「外包后主 agent 还要验收、收口、修 agent 修坏的地方，手改需求**不降反升**」——
# 派发 k 个 coder 即为主 agent 额外注入 k × current_lr 额度（**每个 coder 注入一份**），
# 使主 agent 不必再靠人工 `state-patch` 抬 max（那条路**绕过梯度**，且每次抬都往
# `overrides[]` 写噪声 —— 实测本节点 max 被抬到 6，高于梯度天花板 max_lr=4）。
# 常量与 `scripts/gk_advance.py` 的 `EDIT_BUDGET_PER_LR` / `EDIT_BUDGET_HARD_CAP` 同源，
# 漂移由 `scripts/test_gk_dispatch_autofill.py::test_budget_constants_match_advance` 机检。
# ⚠ 与 `_budget_override_record` 同层（**区外**，非保护区内）⟹ 零保护区改动。
# 2026-09-23（用户裁定「先提 PER_LR 额度」）：2 → 4。原 2 只有 2..8（lr 1..4），
#   实测本节点要靠人工抬 max 才够用；现 4..16 与硬顶 16 对齐（**硬顶不变**，仍封顶 16）。
# 2026-10-22（owner 裁定「基础额度翻倍」）：基线 4 → 8（lr=1 即 8，lr=2 起触硬顶 16）。
# 2026-10-23（owner 裁定 A+B+C）：基线 8 → 12、硬顶 16 → 24、外生上限 24 → 32。
#   依据：本机 cosine 长期停在 lr=1 ⟹ 每节点实付 8，而长 standing 节点实测碰 10–14 个文件 ⟹ 地板是瓶颈。
#   外部对照：SWE-agent 250 steps / OpenHands 500 iterations / Agents SDK 10 turns / LangGraph 25 steps。
#   ⚠ 本行须**逐字**匹配 `^_EDIT_BUDGET_PER_LR=(\d+)$`（机检正则），**禁加行尾注释**。
_EDIT_BUDGET_PER_LR=12
_EDIT_BUDGET_HARD_CAP=24
_grant_node_budget() {  # <source> <reason>
  local _lr
  _lr=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" \
        --get gate_data.scheduler.current_lr --default 1 2>/dev/null)
  case "$_lr" in ''|*[!0-9]*) _lr=1 ;; esac
  local _g=$(( _lr * _EDIT_BUDGET_PER_LR ))
  # ── D4（审计署 §21.8-a，2026-10-24）：额度兑换的**当日总量上限 + 冷却** ──────────
  #   缺口：原先只有「单次 ≤ 硬顶」，**次数/总量无上限、无冷却** ⟹ 反复 `--code-fix`
  #   可无限抬 max（实测 budget-log 已有 13 次、单日峰值 5 次、最小间隔 23s）。
  #   判据面 = budget-log 中 `source=code-fix` 的**当日**次数与额度；超出 ⟹ **不授予**
  #   （派发本身继续，只拒绝这次兑换，避免把「记账拒绝」放大成「派发失败」）。
  #   默认值依据（2026-10-24 实测 13 条记录）：单日峰值 5、最小间隔 23s、中位 2.7h。
  #   关：GK_CODE_FIX_CAP=0；调：GK_CODE_FIX_MAX_GRANTS / _TOTAL_CAP / _COOLDOWN_S。
  if [ "${GK_CODE_FIX_CAP:-1}" != "0" ]; then
    local _q="" _qrc=0
    _q=$(python3 "$SKILL_DIR/scripts/gk_budget_ledger.py" code-fix-quota \
           --state "$STATE_FILE" \
           --max-grants "${GK_CODE_FIX_MAX_GRANTS:-16}" \
           --total-cap "${GK_CODE_FIX_TOTAL_CAP:-192}" \
           --cooldown "${GK_CODE_FIX_COOLDOWN_S:-10}" \
           --add "$_g" 2>>"$GK_DBG_LOG") || _qrc=$?
    case "$_qrc:$_q" in
      0:*'"ok": false'*)
        local _why
        _why=$(printf '%s' "$_q" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field reason --default '?' 2>/dev/null || echo "?")
        printf 'GATEKEEPER-WARN: [D4] code-fix 额度兑换被拒（reason=%s）——本次不追加节点额度。调 GK_CODE_FIX_MAX_GRANTS/%s/_TOTAL_CAP/%s/_COOLDOWN_S/%s，关 GK_CODE_FIX_CAP=0\n' \
          "$_why" "${GK_CODE_FIX_MAX_GRANTS:-16}" "${GK_CODE_FIX_TOTAL_CAP:-192}" "${GK_CODE_FIX_COOLDOWN_S:-10}" >&2
        printf '%s codefix-denied reason=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_why" \
          >>"${GK_DBG_LOG:-/dev/null}" 2>/dev/null || true
        return 0 ;;
    esac
  fi
  # 走 `_state_write`（CLI 内部单一出纳：flock + 原子写 + checksum）而非 `state-patch`——
  # 后者会**额外**记一条 `source=state_patch` 覆盖留痕，与下面这条 `code-fix` 重复成噪声。
  _state_write "
gd=d.setdefault('gate_data',{}); eb=gd.setdefault('edit_budget',{})
# 2026-09-26（ECC-28DB1E33027A）：夹取**只向上、不向下** —— 原 min(cur+g, CAP) 形态会把
# 已被人抬到 CAP 之上的 max（用户 2026-09-24 裁定的 500）**夹回 16** ⟹ 后续编辑被 Gate4 拦死。
# 现式：≤CAP 者仍按梯度 additive；人工抬高者**保持不动**（永不降）。
# ⚠ 本段位于 _state_write 载荷内（bash 双引号区）⟹ **禁写 ASCII 反引号**：会被 bash 当命令
#   替换执行（同族 ECC-186B99627299）。机检臂 = test_cli_double_quoted_regions_have_no_backticks。
_cur=int(eb.get('max',0)); eb['max']=max(_cur,min(_cur+$_g,$_EDIT_BUDGET_HARD_CAP))
_rem=int(eb.get('remaining',0)); eb['remaining']=max(_rem,min(_rem+$_g,$_EDIT_BUDGET_HARD_CAP))
# 2026-09-25 会话隔离：额度授予**同时传播到各会话域**（否则已初始化的会话看不到这次追加）。
for _s in (eb.get('sessions') or {}).values():
    _m=int(_s.get('max',0) or 0); _s['max']=max(_m,min(_m+$_g,$_EDIT_BUDGET_HARD_CAP))
    _r=int(_s.get('remaining',0) or 0); _s['remaining']=max(_r,min(_r+$_g,$_EDIT_BUDGET_HARD_CAP))
" >/dev/null 2>&1 || true
  _budget_override_record "${1:-code-fix}" "${2:-}" >/dev/null 2>&1 || true
}
_state_checksum_write() {
  # 2026-09-23（**ECC-60BBDCDB2F70 修复**，与 `_state_write` 同根因）：原为
  # `json.dump(open('$STATE_FILE','w'))` 非原子写 ⟹ 同款半写风险。改走单一出纳 `dump_state`。
  # 2026-09-25（**选项 A**）：锁由 python 侧 `state_lock` 持有（同 `_state_write` 口径）。
  # 2026-09-26（**ECC-F0F0999A3970 区外等价加固**）：原为**无条件**重算 ⟹ 调用方**根本没改动**
  # 该 state 时（如 `cmd_finding` 带 `--domain`：python 只写域化 state、默认 state 一个字节没动）
  # 重算等价 no-op；但若默认 state **已被篡改**，重算会把 `_checksum` 改成与篡改内容相符的值 =
  # **洗白**（完整性旁路）。正常修法（`cmd_finding` 收尾改传目标 state / 删去）调用点在
  # `PROTECTED_REGION::gate` 内 ⟹ 不可改（实测全仓无授权通路）⟹ 改走区外，判据 = 「**本次 CLI
  # 调用是否改动过该 state**」：调用起点由本进程已运行秒数反推（`ps -o etimes= -p $$`），
  # 文件 mtime 早于起点 ⟹ 未改动 ⟹ 失配即篡改 ⟹ **拒写 + 留痕**（GK_DBG_LOG，不静默）；
  # ⚠ mtime 秒级粒度 ⟹ 判据留 **1s 容差**（`mt < inv-1`）：宁可放过「紧贴起点 1s 内写入」的
  #   极端样本，也不误拒任何调用方刚写过的 state（合法通路优先，误拒会留下陈旧 `_checksum`）。
  # checksum 已相符 ⟹ 零写盘；三处合法「直写后补算」（`cmd_discover` / subagent 落库 /
  # `cmd_adjudicate`）的 mtime 必 ≥ 起点 ⟹ 照旧重算（零回归）。
  local _ela _inv
  _ela=$(ps -o etimes= -p $$ 2>/dev/null | tr -d ' ')
  case "$_ela" in ''|*[!0-9]*) _ela=0 ;; esac
  _inv=$(( $(date +%s) - _ela ))
  GK_INVOKE_EPOCH="$_inv" \
  GK_PY_SCRIPTS="$(_gk_py_path "$SKILL_DIR/scripts")" \
  GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" \
  python3 -c "
import sys,json,hashlib,os
sys.path.insert(0,os.environ['GK_PY_SCRIPTS'])
from gk_json_utils import dump_state, state_lock
_lk=state_lock(os.environ['GK_PY_STATE']); _lk.__enter__()
d=json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'))
gd=json.dumps(d.get('gate_data',{}),sort_keys=True)
_new=hashlib.sha256(gd.encode()).hexdigest()[:16]
_old=str(d.get('_checksum','') or '')
_inv=int(os.environ.get('GK_INVOKE_EPOCH','0') or 0)
if _new==_old:
    pass
elif _inv and int(os.path.getmtime(os.environ['GK_PY_STATE']))<_inv-1:
    sys.stderr.write('[checksum] REFUSE 洗白未改动的 state（mtime<invoke）: new=%s old=%s\n' % (_new,_old))
else:
    d['_checksum']=_new
    dump_state(os.environ['GK_PY_STATE'], d)
_lk.__exit__(None, None, None)
" 2>>"${GK_DBG_LOG:-/dev/null}" || true
}

# ─── F-REV-92(a)：subagent **运行级看门狗**（deadline + 运行注册）────────────────────────
# 背景（读码 + 实测，2026-09-17 用户裁定「其他都同意」）：
#   ① 派发点是**裸命令替换**（<命令替换> 内 exec 解释器 + runner，见下方三处；⚠ **刻意不写派发串字面量** —— `test_subagent_runner_extract.py::TestCliCtxInjectGuard::test_preflight_blocks_before_dispatch` 以 `str.index()` 取**首次出现**判定「preflight 早于派发」，注释字面量会成更早命中而误判，本处首版即踩），
#      **无外层 `timeout`**；
#   ② `subagent_runner.py` 内**无全局看门狗**（`signal.alarm` / `asyncio.wait_for` /
#      deadline 全无），唯一界是**逐次**超时（`AsyncOpenAI(timeout=SUBAGENT_TIMEOUT)`
#      + 各 `subprocess.run(timeout=…)`）；
#   ③ 档位表 `SUBA_TIERS` tier3 = `max_turns 400 × timeout 600s` ⟹ **挂死上界 ≈ 66.7 小时**；
#   ④ **无运行注册** ⟹ 事后**无法判定**「上一轮是死了还是还在跑」；`flock` 只覆盖 state
#      与 key 目录，不覆盖 subagent 运行。
# 修法 = 两件：
#   **(a) 外层 deadline**：`timeout -k 30 "${SUBAGENT_MAX_RUNTIME:-3600}"` 包住**三处**派发点
#       （主 / DS 重试 / mimo 降级）。⚠ 必须带 `-k`：无 `-k` 时 SIGTERM 被忽略则 deadline
#       形同虚设。⚠ **已知局限（如实登记）**：subagent 默认解释器 `suagent_py311.sh` 经 WSL
#       interop `exec` **Windows** `python.exe`，WSL 侧只是 interop 桩 ⟹ 杀桩**未必**回收
#       Windows 侧进程（与 ⑰-7b 登记的 `timeout` 未加 `-k` 孤儿问题同族，未根治）。
#   **(b) 运行注册**：`${STATE_FILE}.subagent-run` 落 `PID|START|DEADLINE|ID|TIER`；下次派发前
#       检测**陈旧记录**（持有者 PID 已死 或 已过 deadline）⟹ WARN + `GK_DBG_LOG` 留痕，
#       判上一轮**异常终止**。⚠ 只用于**存活自校验**，**不进** monitor 的 JSON 输出契约
#       （避免 consumers / 严格 schema 被破坏）。⚠ 正常收尾必须注销，否则下次误报。
_gk_subagent_runfile() { echo "${STATE_FILE}.subagent-run"; }

_gk_subagent_watch_prev() {
  local f; f=$(_gk_subagent_runfile)
  [ -f "$f" ] || return 0
  local pid="" start="" dl="" sid="" tier=""
  IFS='|' read -r pid start dl sid tier < "$f" 2>/dev/null || { rm -f "$f" 2>/dev/null; return 0; }
  local now verdict=""
  now=$(date +%s 2>/dev/null || echo 0)
  if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
    verdict="pid_dead"
  elif [ -n "$dl" ] && [ "$dl" -gt 0 ] 2>/dev/null && [ "$now" -gt "$dl" ] 2>/dev/null; then
    verdict="deadline_exceeded"
  fi
  if [ -n "$verdict" ]; then
    echo "WARN[subagent-run]: 上一轮 subagent **异常终止**（$verdict — pid=$pid start=$start deadline=$dl id=$sid tier=$tier）；记录已清，本轮继续" >&2
    echo "[subagent-run] previous run abnormal ($verdict) pid=$pid start=$start deadline=$dl id=$sid tier=$tier $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
    rm -f "$f" 2>/dev/null
  fi
  return 0
}

_gk_subagent_watch_arm() {   # <subagent_id> <tier> <max_runtime_s>
  local sid="$1" tier="$2" max="${3:-0}" now dl=0
  now=$(date +%s 2>/dev/null || echo 0)
  if [ "${max:-0}" -gt 0 ] 2>/dev/null; then dl=$((now + max)); fi
  printf '%s|%s|%s|%s|%s\n' "$$" "$now" "$dl" "$sid" "$tier" > "$(_gk_subagent_runfile)" 2>/dev/null || true
}

_gk_subagent_watch_disarm() { rm -f "$(_gk_subagent_runfile)" 2>/dev/null || true; }

# ─── Context file writer — state summary for pre_tool_hook (方案B: **Context Projector**) ───
# 2026-10-01 正名（H3 设计第 6 条 / 待裁定 D3，依据 `audit --crossfull` L2 crossrev）：本段落
#   实为 **context 投影写盘器**（读 state → 写 `.gatekeeper.context.json`），**不是**事件总线；
#   原名「EventBus Context Injector」与 zthl 自研事件分发（`zthl/eventbus.py::SignalHub`）
#   同名不同物 ⟹ 按 H3 设计第 6 条正名为 **Context Projector**，新组件**避开** `EventBus` 命名。
# Writes .gatekeeper.context.json on every state change. pre_tool_hook reads this on every tool call
# and outputs to stderr if checksum changed. This replaces the need for /goal system message injection
# by pushing context through the hook pipeline instead.
_CONTEXT_FILE="${SKILL_DIR}/.gatekeeper.context.json"

_write_context_file() {
  python3 "$SKILL_DIR/scripts/gk_views.py" context-cache "$STATE_FILE" "$_CONTEXT_FILE" 2>/dev/null || true
}
# ─── 上下文注入判定（**唯一实现**）────────────────────────────────────────────
# F-REV-79（2026-09-16，用户裁定「质询 fail-closed 前置门：过时先 context --update（含重签），
# 仍不过则阻断派发」）：原判定链内联在 cmd_monitor 里 ⟹ 无法自愈后复验（要么直接阻断，要么
# 需要第二份判定 = 第二事实源）。提取为单点函数：自愈前置门与最终判定**共用**它。
# $1=ctx_file $2=ctx_sig → echo "ok"|"sig_invalid"|"sig_missing"|"ctx_missing_orphan_sig"|"ctx_missing"
# 进程内**可重入**的上下文发布锁（2026-10-30）
# 取锁单点：两处写者（`context --update` 发布段、`_context_resign` 重签）共用同一把 `<ctx>.lock`。
#   为什么要可重入：flock 按 **open-file-description** 计锁 —— 同进程若二次 `exec {fd}>` 再 flock，
#   拿到的是**另一个** OFD，内核不认「自己已持有」⟹ 内层阻塞到 `-w` 超时（自死锁）。
#   当前 update 链**不**进入 `_context_resign`（rotate 只在 cmd_advance / CLI 启动级），但两者
#   只需一次「rotate 内联进 `_sign_raw`」式的改动就会串起来 ⟹ 用 `_CTX_LOCK_FD` 做进程内守卫：
#   已持锁直接复用，内层不重复抢、不提前释放。
_ctx_lock_acquire() {
  local _f="$1" _t="${2:-20}"
  if [ -n "${_CTX_LOCK_FD:-}" ]; then return 0; fi
  command -v flock >/dev/null 2>&1 || return 0
  local _fd=""
  exec {_fd}>"${_f}.lock" 2>/dev/null || return 0
  flock -w "$_t" "$_fd" 2>/dev/null || true
  _CTX_LOCK_FD="$_fd"
}

_ctx_lock_release() {
  [ -n "${_CTX_LOCK_FD:-}" ] || return 0
  flock -u "$_CTX_LOCK_FD" 2>/dev/null || true
  eval "exec ${_CTX_LOCK_FD}>&-"
  _CTX_LOCK_FD=""
}

_ctx_inject_probe() {
  local ctx_file="$1" ctx_sig="$2"
  # 2026-10-30（签名竞态修复 ①）：**读者共享锁** —— 写者（`context --update` / `_context_resign`）
  #   持 `${ctx_file}.lock` 独占锁做「重建 + 重签 + 发布」⟹ 读者不会撞进「JSON 已换、.sig 仍旧」
  #   的窗口（历史病症：6 臂并发时全部判 sig_invalid 并各自重复自愈）。
  #   锁机制不可用（无 flock / fd 打不开）⟹ fail-open 按原样读：锁是防抖，不得成为新阻断点。
  local _pf_lk="${ctx_file}.lock" _pf_fd="" _r=""
  if command -v flock >/dev/null 2>&1; then
    exec {_pf_fd}>"$_pf_lk" 2>/dev/null || _pf_fd=""
    if [ -n "$_pf_fd" ]; then
      # **非阻塞**抢共享锁（2026-10-30）：原 `flock -s -w 5` 是**阻塞排队** —— 写者一连持有 5s
      #   时每个读者都陪着等满，探测是高频路径（每次派发前一次）⟹ 读者成了写者的放大器。
      #   写者持锁只在「发布」的毫秒级窗口内 ⟹ 非阻塞 + 一次 10ms 退避重试够用；
      #   仍失败（写者确实在发布）⟹ fail-open 读：这种情形下读到的可能是旧配对，但**不会挂死**。
      flock -s -n "$_pf_fd" 2>/dev/null || { sleep 0.01; flock -s -n "$_pf_fd" 2>/dev/null || true; }
    fi
  fi
  if [ -f "$ctx_file" ] && [ -f "$ctx_sig" ]; then
    local _t _v; _t=$(mktemp)
    cp "$ctx_file" "$_t"
    _v=$(openssl pkeyutl -verify -pubin -inkey "${_CONTEXT_PUB_KEY}" -rawin -in "$_t" -sigfile "$ctx_sig" 2>&1)
    rm -f "$_t"
    # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 /usr/bin/rg）
    if echo "$_v" | "$RG" -q "Verified"; then _r="ok"; else _r="sig_invalid"; fi
  elif [ -f "$ctx_sig" ]; then
    _r="ctx_missing_orphan_sig"
  elif [ -f "$ctx_file" ]; then
    _r="sig_missing"
  else
    _r="ctx_missing"
  fi
  if [ -n "$_pf_fd" ]; then flock -u "$_pf_fd" 2>/dev/null || true; eval "exec ${_pf_fd}>&-"; fi
  echo "$_r"
}
# ─── gitnexus 基线「先查，旧了才刷」单一源（2026-10-16，T7 / finding ECC-21AB384F03A9）────
# 两处消费（**禁第二实现**）：`_review_channel_preflight` 的 L3 基线门 + `apply-worktree --close-out` 收口环。
# 语义（owner 裁定）：先 `_gitnexus_baseline_status` **查询** —— current/reusable ⟹ **直接复用、不 analyze**
#   （避免反复重算，省时省硬件）；stale ⟹ 才 `_gx_analyze_embeddings` 自愈刷新（含残态修复 + 跨进程单飞）；
#   其它（unavailable 等）⟹ 不刷、原样返回。$1=repo dir；$2=日志标签（默认 gitnexus）。
# 输出 = 刷新后的 status（stdout 单行）；**不做** fail-closed 判定（调用方各按语义处置）。
_gitnexus_refresh_if_stale() {
  local _d="$1" _tag="${2:-gitnexus}" _st _re
  _st=$(_gitnexus_baseline_status "$_d")
  case "$_st" in
    current|reusable) printf '%s' "$_st"; return 0 ;;
    stale)
      # 2026-11-01（owner 裁定）：**握手取代二次判**。原实现 analyze 后又查一次 status，
      #   而 meta 落盘与查询之间存在竞态（实测 analyze 成功却仍返回 stale ⟹ 外层判 dispatch_blocked）。
      #   `_gx_analyze_embeddings` 返回 0 已内含「复验 current|reusable」⟹ 直接采信；
      #   仅在其失败时才回读 status（保留真实不可用信息）。
      if _gx_analyze_embeddings "$_d"; then
        echo "[$_tag] gitnexus baseline stale → 自愈刷新成功（握手确认）$(date -u +%FT%TZ)" >> "${GK_DBG_LOG:-/dev/null}"
        printf '%s' "current"; return 0
      fi
      echo "[$_tag] gitnexus baseline stale → 自愈未成功（回读 status）$(date -u +%FT%TZ)" >> "${GK_DBG_LOG:-/dev/null}"
      _re=$(_gitnexus_baseline_status "$_d")
      printf '%s' "$_re"; return 0 ;;
    *) printf '%s' "$_st"; return 0 ;;
  esac
}

# ─── 审查通道前置 helper（A/B/C/D，2026-09-04 SCR 收敛：六问安全网落地）────────
# channel ∈ {plan-refinement, crossrev}。由 cmd_monitor --subagent 的
# plan-refinement 角色（质询）或 --crossrev（交叉审查 L2 显式通道）触发。
# 依赖 env: CTX_INJECT_OK / CTX_INJECT_REASON（注入判定结果透传）。
# 返回: ok JSON exit 0 / error JSON exit 1（stdout 完整 JSON，不吞不追加）。
_review_channel_preflight() {
  local channel="$1"
  local inject_ok="${CTX_INJECT_OK:-true}"
  local inject_reason="${CTX_INJECT_REASON:-}"

  # ── D-lite: 组件 pin（source/version/output-contract + exit 2；无发行根故轻量不实例化五源 loader）──
  local pins_out; pins_out=$(python3 "${SKILL_DIR}/scripts/gk_review_pins.py" verify --channel "$channel" 2>>"$GK_DBG_LOG") || true
  local pins_ok; pins_ok=$(echo "$pins_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field ok --default None --default-invalid false 2>/dev/null || echo "false")
  if [ "$pins_ok" != "True" ]; then
    echo "{\"ok\":false,\"error\":\"REVIEW_PIN_FAIL\",\"channel\":\"$channel\",\"detail\":$(echo "$pins_out" | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin),ensure_ascii=False))" 2>/dev/null || echo '{}'),\"fix\":\"bash gatekeeper-cli.sh state 对照 scripts/gk_review_pins.py verify 明细\"}"
    return 1
  fi

  # ── A: 上下文签名新鲜（禁静默 skip——空白/机械性审查根因；失效/缺失阻断，GK_ALLOW_STALE_CTX=1 降级）──
  if [ "$inject_ok" != "true" ]; then
    if [ "${GK_ALLOW_STALE_CTX:-0}" = "1" ]; then
      echo "{\"warning\":\"context stale/unsigned/missing — degraded (GK_ALLOW_STALE_CTX=1)\",\"channel\":\"$channel\",\"reason\":\"${inject_reason:-unknown}\"}" >&2
      echo "[review-preflight] $channel ctx degrade allowed (GK_ALLOW_STALE_CTX=1) $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
    else
      # F-REV-24 (2026-09-11): ctx 缺失单列错误码（与 stale/unsigned 区分）；三态细分（R2 MoA 质询）
      # → ctx_missing / ctx_missing_orphan_sig 各带对应 fix 引导（运维动作不同）。
      local _a_err="CONTEXT_STALE_OR_UNSIGNED" _a_fix="bash gatekeeper-cli.sh context --update 后重试"
      case "$inject_reason" in
        ctx_missing_orphan_sig)
          _a_err="CONTEXT_MISSING_ORPHAN_SIG"
          _a_fix="删除孤儿 references/subagent-context.json.sig 后重试（或 bash gatekeeper-cli.sh context --update）" ;;
        ctx_missing)
          _a_err="CONTEXT_MISSING" ;;
      esac
      # R19-c（2026-09-22，L2 交叉审查 failed#4 同批修）：**判据必须指向真因**。
      #   原况：副本 `.keys` 继承失败后，用户只看到 `CONTEXT_STALE_OR_UNSIGNED` / `sig_invalid`
      #   （指向「ctx 过期」这一**错误方向**）⟹ R19 病象的成因被掩盖。现把前缀置的
      #   `GK_R19_KEYS_INHERIT_FAILED` 真因**附进同一 JSON 报文**，并给出对应 fix。
      local _a_hint="" _a_hint_fix=""
      if [ -n "${GK_R19_KEYS_INHERIT_FAILED:-}" ]; then
        _a_hint=",\"keys_inherit_failed\":\"${GK_R19_KEYS_INHERIT_FAILED}\""
        _a_hint_fix="（真因 = 副本 .keys 继承失败：先手工 ln -s <主工作树>/.keys .keys，或查 gk_dbg.log 的 [r19] 行）"
      fi
      echo "{\"ok\":false,\"error\":\"$_a_err\",\"channel\":\"$channel\",\"reason\":\"${inject_reason:-unknown}\",\"fix\":\"$_a_fix${_a_hint_fix}\"${_a_hint}}"
      return 1
    fi
  fi

  # ── B: L3 基线 status-fresh 复用（crossrev ∪ plan-refinement；current 复用增量基线，stale 才 analyze）──
  # 2026-10-05（用户令「计划质询之前强制检测 gitnexus 新鲜度」）：原仅 crossrev ⟹ 质询绕过基线门
  #   （node_guard 仅 advance 且默认 advisory）。现 plan-refinement 通道亦检。
  # 2026-11-02（owner 裁定，**语义变更**）：plan-refinement 由 fail-closed 改 **advisory** ——
  #   `stale`（索引落后于 HEAD）只告警放行；**只有 `unavailable`（根本没有索引）才阻断**。
  #   理由：持续提交的仓库里 `stale` 是常态，把它当阻断条件 ⟹ 并发质询永久卡死。
  #   crossrev 维持原 WARN（零回归）。
  if [ "$channel" = "crossrev" ] || [ "$channel" = "plan-refinement" ]; then
    # F-REV-77/78 收敛（2026-09-16）：状态判定改走**单点** `_gitnexus_baseline_status`
    # （内含 120s 超时 —— 原直调 `_run_gitnexus status` 在脏工作树下 ~25s 撞默认 30s 超时 →
    # 空输出 → 误判 unavailable）；且 `analyze` 现已失效 memo（F-REV-78）⟹ 下方复验取的是
    # **刷新后**真值（原实现读到缓存 stale → 恒 WARN 假警）。
    local _bl_dir gn_status _bl_ok=false
    _bl_dir=$(_gx_repo_dir_for_current)
    # T7（2026-10-16）：原为 `_gitnexus_refresh_if_stale`（stale ⟹ 自愈 analyze）。
    # 2026-11-02（owner 裁定「并发质询永久卡死」）：质询侧改**只读判定**，不再触发 analyze。
    #   实测代价：`_gitnexus_refresh_if_stale` 撞 stale 会走 `_gx_analyze_embeddings`
    #   ⟹ `analyze --embeddings`（本机 40min 级、写 ~300MB lbug）⟹ 每个计划、每次质询都付一遍，
    #   而持续提交的仓库里 stale 是常态 ⟹ 追不上、还把 C 盘打满（实测 2.3G 沙箱日志 + 883M 索引）。
    #   语义：质询要的是「有没有可用基线」这个**事实**，不是「基线必须最新」这个**目标**；
    #   刷新是运维动作（`context --update` / `apply-worktree --close-out` 各有入口），不该挂在
    #   每次质询的前置门里。
    gn_status=$(_gitnexus_baseline_status "$_bl_dir")
    { [ "$gn_status" = "current" ] || [ "$gn_status" = "reusable" ]; } && _bl_ok=true
    # 2026-11-02（owner 裁定）：**判据从 fail-closed 改 advisory** —— 只对 `unavailable` 阻断。
    # 病象：`stale` 曾被当阻断条件 ⟹ 门槛要求索引与 HEAD 精确同步 ⟹ 在任何**持续提交**的仓库里
    #   这是常态而非异常 ⟹ **并发质询永久卡死**（实测：主仓 HEAD `7aef9872`→`ab2f008c`→`ac0fb8c6`
    #   连推三次，每次自愈 analyze 要 1.5–5min，跑的过程中 HEAD 又变，永远追不上）。
    # 判据辨析（关键）：索引落后 = **图证据不完整**；图证据不完整 ≠ **不能质询**。
    #   基线图在质询里是**辅助证据**（node_guard / impact 之类），缺几条边最坏是某臂少引一处代码
    #   位置，不该让整轮跑不起来。真正的硬前提只有「根本没有可用索引」（`unavailable`）。
    # ⚠ 与 `GK_ALLOW_STALE_BASELINE=1` 的区别：那是**逐次豁免**（人肉逃生口）；本处是**改判据
    #   本身** —— 正常路径不再需要任何 env 开关。
    if ! $_bl_ok; then
      case "$gn_status" in
        unavailable)
          if [ "$channel" = "plan-refinement" ] && [ "${GK_ALLOW_STALE_BASELINE:-0}" != "1" ]; then
            echo "{\"ok\":false,\"error\":\"BASELINE_UNAVAILABLE\",\"channel\":\"plan-refinement\",\"status\":\"$gn_status\",\"hint\":\"该 repo 没有可用 gitnexus 索引（不是过期）——先跑一次 analyze 建基线；或 GK_ALLOW_STALE_BASELINE=1 显式降级\"}"
            return 1
          fi ;;
        *)
          # stale：**放行**，但必须留痕（报文 + dbg 日志），防「静默降级」再犯。
          echo "{\"warning\":\"baseline stale — degrade to advisory（图证据不完整，质询继续）\",\"channel\":\"$channel\",\"status\":\"$gn_status\"}" >&2
          echo "[review-preflight] $channel baseline=$gn_status → advisory 放行（索引落后于 HEAD，图证据不完整但非阻断）$(date -u +%FT%TZ)" >> "$GK_DBG_LOG" ;;
      esac
    fi
  fi

  # ── C: 节点绑定（crossrev 须在序列审查节点；GK_DEGRADE_REVIEW=1 显式降级）──
  if [ "$channel" = "crossrev" ]; then
    local cur_stage cur_rp
    cur_stage=$(json_val "$STATE_FILE" stage "IDLE")
    cur_rp=$(json_val "$STATE_FILE" r_phase "")
    # 2026-09-21（判据键修正 + 单源化）：原按 `gate_data.project_type` 分支 —— 该键是**活动
    # 计划的 META 声明**（单源 = `gk_route_center._META_FIELDS`），随活动计划切换而翻转
    # （0913 家族 META=standing；本会话 hook 计划 META=analysis）⟹ 同一条 `ECO-*` 常驻序列在
    # analysis 型活动计划下审查节点**恒不命中**，**即便 advance 到 ECO-AUDIT 也仍被拦**（实测：
    # `expected:"STAGE_3 (standard) 或 AUDIT-CROSSR"`）⟹ 正规路径被系统性堵死，逼出旁路
    # （`--isolate` 把副本 state 的 stage 改写成 AUDIT-CROSSR 的**自证式**满足 / GK_DEGRADE_REVIEW）。
    # 政策不变（"审查须在审查节点"）；键改为**序列命名空间**。判据本体**单源** =
    # `scripts/gk_review_nodes.py`（hook Gate 1b 同源消费），本处只做取数与分派。
    local c_ok=false c_expected="" _c_out
    _c_out=$(python3 -c "
import json,sys
sys.path.insert(0, sys.argv[2] + '/scripts')
from gk_review_nodes import review_node_ok
_d=json.load(open(sys.argv[1])); _gd=_d.get('gate_data') or {}
_r=review_node_ok(_d.get('stage','IDLE'), _d.get('r_phase',''), _gd.get('project_type',''))
print(('true' if _r['ok'] else 'false')+'|'+_r['expected'])
" "$STATE_FILE" "$SKILL_DIR" 2>>"$GK_DBG_LOG" || echo "false|")
    IFS='|' read -r c_ok c_expected <<< "$_c_out"
    # python 失败 → c_ok=false（fail-closed，拦）；expected 缺失 → 回落原文案
    [ -n "$c_expected" ] || c_expected="STAGE_3 (standard) 或 AUDIT-CROSSR"
    if ! $c_ok; then
      if [ "${GK_DEGRADE_REVIEW:-0}" = "1" ]; then
        echo "{\"warning\":\"cross-review degraded (GK_DEGRADE_REVIEW=1) — 非审查节点运行\",\"node_binding\":\"${cur_rp}/${cur_stage}\",\"expected\":\"$c_expected\"}" >&2
        echo "[review-preflight] crossrev node degrade rp=$cur_rp stage=$cur_stage $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
      else
        echo "{\"ok\":false,\"error\":\"CROSSREVIEW_NODE_BINDING\",\"channel\":\"crossrev\",\"current\":\"${cur_rp}/${cur_stage}\",\"expected\":\"$c_expected\",\"hint\":\"advance 到审查节点（standard STAGE_3 / standing ECO-VERIFY / audit AUDIT-CROSSR）再跑；或 GK_DEGRADE_REVIEW=1 显式降级\"}"
        return 1
      fi
    fi
  fi

  echo "{\"ok\":true,\"channel\":\"$channel\"}"
  return 0
}
# ─── gitnexus helper: direct node.exe call via WSL paths (bypasses PowerShell PATH issue) ───
# gitnexus node 定位单点（2026-09-07 ㊴ P1 单路径收敛，唯一探测实现）：
# PATH `command -v node` 优先 → Windows node.exe 候选 → WSL linux node 兜底。
# 消费方 = _run_gitnexus（bash spawner）与 _gx_subagent_gx_env（export GX_NODE/GX_JS）；
# 禁止在 python 侧/pdg_check/subagent_runner 再实现第二份探测（仅消费 CLI export）。
_gx_node_probe() {
  # $1 = mode: win（Windows python subagent，须 Windows node.exe）| wsl（默认，linux node 可执行）
  # 2026-09-09 修复（后R #1 availability 受限根因）：原实现 `command -v node` 无条件优先 →
  # 在 WSL 中恒命中 /usr/bin/node（linux）→ win 模式永远走不到 Windows node.exe 候选 →
  # _gx_subagent_gx_env win 分支恒 WARN（L1064 fail loudly）→ subagent gitnexus 工具不可用。
  local _mode="${1:-wsl}"
  # 2026-11-01（跨平台真因 F，owner 清单第 2 条）：**候选必须同目录双形态并列**。
  #   原实现只探 `/mnt/d/...`（**WSL 形态**）——在 Git Bash(MSYS) 里 `/mnt/d` **不存在**
  #   ⟹ 三个候选全落空 ⟹ 回落 `command -v node` ⟹ 命中 WorkBuddy 自带
  #   `/c/Users/HP/.workbuddy/binaries/node/versions/<v>/node`（**无 `.exe` 后缀**）。
  #   后果链（实测）：① 该形态既非 `*.exe` 也非 `/mnt/*` ⟹ `_run_gitnexus_raw` 判成 wsl 侧
  #   ⟹ 存储根取 POSIX `/mnt/c/.../.gitnexus-store/wsl` 交给 **Windows node** ⟹ node 按
  #   相对路径解析 ⟹ 落 `<cwd>/mnt/c/...` 的**假路径** ⟹ `status --json` 回
  #   `error:"not-indexed"` ⟹ 基线 `unavailable` ⟹ `BASELINE_STALE` 派发阻断；
  #   ② 用户口径要求用系统装的那份 node（`D:\Program Files\nodejs\node.exe`），不用 WorkBuddy 运行时。
  #   修：MSYS `/d/` 与 WSL `/mnt/d/` 同表并列；`.exe` 后缀显式补齐（`command -v` 在 MSYS 会剥后缀）。
  if [ "$_mode" = "win" ]; then
    local _p _pz
    for _p in \
      "/mnt/d/Program Files/nodejs/node.exe" "/d/Program Files/nodejs/node.exe" \
      "/mnt/c/Program Files/nodejs/node.exe" "/c/Program Files/nodejs/node.exe" \
      "/mnt/c/Program Files (x86)/nodejs/node.exe" "/c/Program Files (x86)/nodejs/node.exe"; do
      [ -x "$_p" ] && { echo "$_p"; return 0; }
    done
    # 兜底：PATH 里的 node —— 但**跳过 WorkBuddy 自带运行时**（owner 口径：用系统那份）；
    #   并把 MSYS 剥掉的 `.exe` 补回来（否则下游 `_gx_to_win_path` 产出无后缀的 Windows 路径）。
    _p=""; _p=$(command -v node 2>/dev/null || true)
    case "$_p" in
      */.workbuddy/binaries/*|*/WorkBuddy/resources/*) _p="" ;;
    esac
    if [ -n "$_p" ]; then
      case "$_p" in
        *.exe) ;;
        *) [ -x "${_p}.exe" ] && _p="${_p}.exe" ;;
      esac
      echo "$_p"; return 0
    fi
    # 最后兜底：连 WorkBuddy 运行时也收（但 `.exe` 后缀必须补齐 —— 否则下游把它判成 wsl 侧，
    #   存储根取 POSIX 形态交给 Windows node ⟹ 假路径 `not-indexed`；见上）。
    _p=$(command -v node 2>/dev/null || true)
    if [ -n "$_p" ]; then
      case "$_p" in
        *.exe) ;;
        *) [ -x "${_p}.exe" ] && _p="${_p}.exe" ;;
      esac
      echo "$_p"; return 0
    fi
    return 1
  fi
  local _node_cmd=""
  _node_cmd=$(command -v node || true)   # command -v 未命中零输出零 stderr（POSIX）→ 无需吞错
  if [ -n "$_node_cmd" ] && [ -x "$_node_cmd" ]; then
    echo "$_node_cmd"; return 0
  fi
  for _p in \
    "/mnt/d/Program Files/nodejs/node.exe" \
    "/mnt/c/Program Files/nodejs/node.exe" \
    "/mnt/c/Program Files (x86)/nodejs/node.exe"; do
    [ -x "$_p" ] && { echo "$_p"; return 0; }
  done
  # WSL linux node 兜底（Windows node 缺失场景，如 2026-09-07 d:/Program Files 路径实测不存在）
  if command -v node >/dev/null; then
    command -v node; return 0
  fi
  return 1
}
# P1 消费层 export（2026-09-08 实装，f0a3131 只 patch bash 侧 = 登记/代码错位收口）：
# 按消费方 python 运行环境形态注入 GX_NODE/GX_JS/GX_REPO —— 消费方只消费、不再自探测。
#   mode=win（Windows python311，suagent_py311.sh）：GX_NODE 转 Windows 形态（_gx_to_win_path 归一）+ GX_JS Windows 形态；
#   mode=wsl（WSL python3，audit --pdg/--pr）：GX_NODE 保持 /mnt 可执行形态 + GX_JS 仍 Windows 形态
#   （node.exe 是 Windows 二进制，js 参数恒需 Windows 形态）。
# F-REV-73（2026-09-16，用户裁定）：配对不变量 = **「node 面」与「gitnexus 包的 native
#   binding（JS 面）」必须同侧**。本机 gitnexus 只装 Windows 构建（@ladybugdb/core-win32-x64）
#   ⟹ node 须恒为 **Windows node.exe**；而 `_gx_node_probe wsl` 以 `command -v node` 优先命中
#   `/usr/bin/node`（linux v20.20.2）⟹ 混血执行报 `lbugjs.node: invalid ELF header`、输出恒空
#   （同 F-REV-72 根因；F-REV-72 修的是 bash 侧 `_run_gitnexus_raw` 取 node 的方式）。
#   ⟹ **两个 mode 一律取 win node**，mode 只决定 GX_NODE 的**路径形态**（见上）。
#   实测（2026-09-16）：`/mnt/d/Program Files/nodejs/node.exe` 存在且 `-x` 为真（Windows node v24.14.0）。
#   GX_REPO = 目标仓库名（单源 `_gx_repo_name_for_dir`），供 `gx_*` 工具去掉硬编码默认值。
# ─── 用户目录（WSL 形态；**不写死用户名**，2026-10-29 去硬编码）──────────────────
# `GK_USER_HOME` 显式胜；否则由主仓常量上溯三位派生（`<home>/Downloads/<workspace>/<repo>` ⟹ `<home>`）。
# 用途 = Windows 侧安装落点（npm 全局包 / python.exe / Temp）等此前写作 `/mnt/c/Users/<name>` 的字面量。
_user_home_wsl() {
  if [ -n "${GK_USER_HOME:-}" ]; then printf '%s' "$GK_USER_HOME"; return 0; fi
  local _h="$MAIN_REPO_WSL" _i=0
  while [ "$_i" -lt 3 ] && [ -n "$_h" ] && [ "$_h" != "/" ]; do
    _h=$(dirname "$_h"); _i=$((_i + 1))
  done
  case "$_h" in
    */Users/*) printf '%s' "$_h" ;;
    *) printf '%s' "${HOME:-/root}" ;;
  esac
}
# ─── 路径形态转换单一事实源 ───────────────────────────────────────────────────
# 2026-11-02：`_gx_to_win_path` / `_gk_py_form` / `_gk_py_path`（含设计注释）已**前移**到
#   启动块之前（见上方 SKILL_DIR 校验之后）—— 启动期 state 路由需要它们；此处不再重复定义
#   （第二份实现 = 形态分叉源）。
# 同上，**Windows 形态**（`C:\Users\<u>`；纯 bash 归一，Git Bash/WSL 双侧同结果）。
_user_home_win() {
  _gx_to_win_path "$(_user_home_wsl)"
}
_gx_subagent_gx_env() {
  local _mode="${1:-wsl}"
  # ⚠ 恒 win probe（**不**随 mode 变）—— 见上配对不变量；mode 只影响下方路径形态转换。
  local _node=""; _node=$(_gx_node_probe win) || true
  [ -n "$_node" ] || { unset GX_NODE GX_JS GX_REPO 2>/dev/null || true; return 1; }
  local _js_wsl; _js_wsl="$(_user_home_wsl)/AppData/Roaming/npm/node_modules/gitnexus/dist/cli/index.js"
  local _js_win=""; _js_win=$(_gx_to_win_path "$_js_wsl")
  [ -n "$_js_win" ] || {
    unset GX_NODE GX_JS GX_REPO 2>/dev/null || true
    echo "WARN[gx-env]: 解析 gitnexus 入口失败（$_js_wsl；wslpath 不可用）⟹ 图能力不可用" >&2
    return 1
  }
  local _is_win_node=false
  # 2026-11-01（跨平台 ①E 修复）：**补 MSYS 形态 `/[a-zA-Z]/*`**。
  #   原判据只认 `*.exe`（Windows 直接路径）与 `/mnt/*`（WSL 形态）⟹ MSYS/Git Bash 形态
  #   `/c/Users/HP/.workbuddy/binaries/node/versions/…/node` **两个都不匹配** ⟹ 被判成
  #   **linux node** ⟹ 走 fail-loud 分支 ⟹ `GX_NODE/GX_JS` 全置空 ⟹ 图能力不可用
  #   ⟹ `status` 输出恒空 ⟹ 基线判 `unavailable` ⟹ **`BASELINE_STALE` 阻断**（实测：
  #   plan-refinement 派发 `dispatch_blocked`，且报错把真因说成"node 是 linux 形态"）。
  #   实际该 node 是 **Windows 构建**（`status --json` 自报 `"platform":"win32"`）——
  #   又一次**真因被伪装**（报"linux node"，实为"路径形态没认出来"）。
  # ⚠ 不会误伤真 linux node：`/usr/bin/node` 的第三字符是 `s` 而非 `/` ⟹ 不匹配
  #   `/[a-zA-Z]/*`（该模式要求单字母盘符后紧跟 `/`）。
  # ⚠ 配对不变量（F-REV-73）不变：本机 gitnexus 包是 Windows 构建 ⟹ 只收 win node。
  # ⚠ 2026-11-01 续修（真因 F）：再补 **Windows 直接形态 `[A-Za-z]:*`** ——
  #   `_gx_node_probe win` 的 `command -v` 兜底会给出 `<home>/node`（**无 `.exe`**），
  #   该形态既非 `*.exe` 也非 `/mnt/*` ⟹ 仍被判 wsl 侧 ⟹ 存储根走 POSIX 分支 ⟹
  #   Windows node 按相对路径解析出 `<cwd>/mnt/c/...` 假路径 ⟹ `status` 回
  #   `error:"not-indexed"` ⟹ 基线 `unavailable`（实测已复现到缓存文件里的 storagePath）。
  #   即判据必须认「**路径形态**」而非「有没有 `.exe` 三个字母」。
  case "$_node" in
    *.exe|[A-Za-z]:*|/mnt/*|/[A-Za-z]/*) _is_win_node=true ;;
  esac
  if ! $_is_win_node; then
    # F-REV-73（2026-09-16，用户裁定）：**配对不变量 = 「node 面」与「gitnexus 包的 native
    #   binding（JS 面）」必须同侧**。本机只装了 **Windows 构建**（@ladybugdb/core-win32-x64）
    #   ⟹ 任何 **linux node** 组合必然 `lbugjs.node: invalid ELF header` ⟹ 输出恒空
    #   （与 F-REV-72 同根因：F-REV-72 修的是 bash 侧 `_run_gitnexus_raw` 的取 node 方式）。
    #   故**两个 mode 都只接受 win node**；旧 wsl 分支曾静默导出混血组合
    #   （`GX_NODE=/usr/bin/node` + `GX_JS=Windows 包`）——那正是恒空的那一组，现改为 fail-loud。
    unset GX_NODE GX_JS GX_REPO 2>/dev/null || true
    echo "WARN[gx-env]: node=$_node 为 linux 形态，而本机 gitnexus 包为 Windows 构建（@ladybugdb/core-win32-x64）⟹ 混血执行报 invalid ELF header、输出恒空；已置空（图能力不可用）。修复：装 Linux 侧 gitnexus 包，或用 suagent_py311.sh（Windows python）跑 subagent" >&2
    return 1
  fi
  if [ "$_mode" = "win" ]; then
    # Windows python 直执行 → node 需 Windows 形态
    GX_NODE=$(_gx_to_win_path "$_node")
  else
    # WSL python 经 interop 执行 → node 保持 /mnt 可执行形态（js 恒 Windows 形态）
    GX_NODE="$_node"
  fi
  GX_JS="$_js_win"
  # F-REV-73：repo 名同样**单源** —— 原 `gx_*` 工具签名里硬编码 `spz-gatekeeper-r-sequence`
  #   ⟹ 问「目标仓库」时恒查技能仓库（= F-REV-71 的子 agent 侧孪生）。空则不注入
  #   （python 侧 fail-loud，不自行兜底）。
  # 已有 GX_REPO（如 crossfull --isolate 的嵌套 CLI 调用已显式设定）→ 显式覆盖优先，不重算。
  local _gx_repo="${GX_REPO:-}"
  [ -n "$_gx_repo" ] || { _gx_repo=$(_gx_repo_name_for_dir "$(_gx_repo_dir_for_current)" 2>/dev/null) || true; }
  if [ -n "$_gx_repo" ]; then GX_REPO="$_gx_repo"; else unset GX_REPO 2>/dev/null || true; fi
  # A1（2026-10-28）：跨进程只读缓存的三要素之「repo 目录」——消费方 `gk_gitnexus` 用它算
  #   `git rev-parse HEAD`，缓存键 = repo + HEAD sha + argv；解析不出就不缓存（宁可不缓存，
  #   不返回陈旧图）。`GK_GX_CACHE=1` 只对**只读**子命令生效（analyze/publish 永不缓存）。
  local _gx_dir=""; _gx_dir=$(_gx_repo_dir_for_current 2>/dev/null) || true
  if [ -n "$_gx_dir" ]; then GX_REPO_DIR="$_gx_dir"; GK_GX_CACHE=1
  else unset GX_REPO_DIR 2>/dev/null || true; fi
  export GX_NODE GX_JS GX_REPO GX_REPO_DIR GK_GX_CACHE
}
# ── 进程级 memo（2026-09-14，用户裁定"加进程缓存"）─────────────────────────
# 根因：每次 _run_gitnexus 都 spawn 一个 node 进程。读类子命令（query/context/impact/
# detect-changes）会打开 .gitnexus 的 lbug 图库 → 生成 checkpoint intent/apply 锁对 + wal +
# shadow（实测 09-13 单日 691 对 / 464 checkpoint / 227 wal）；在 Trae 沙箱下这些删除被
# 重定向进回收站（per-tool-call churn 的主成分）。`status` 经实测**不开 DB**（只读索引元数据，
# lbug mtime 不变），缓存它省的是 node 启动开销。
# 语义：同一 CLI 进程内同 (子命令+参数, 目标仓库) 的**非改库**调用结果可复用——进程生命周期内
# 目标仓库不变，故复用安全。`analyze`/`publish` 改库 ⟹ **永不缓存**。
# 通道：memo 存 PID 键文件（bash 的 `$$` 在 `$( )` 子壳内保持主 shell PID ⟹ 可跨子壳传递
# 进程级状态）。>2h 的残留惰性清理，不无限堆积。
_GK_GX_MEMO_DIR="${TMPDIR:-/tmp}/gk-gx-memo"

_run_gitnexus() {
  local gx_args="$*"
  case "$gx_args" in
    analyze*|publish*)
      # F-REV-78（2026-09-16，本次读码发现）：改库后**必须失效本进程 memo** —— 否则同进程内后续
      # `status`/`query` 等读命令命中改库**前**的缓存。实测复现路径（preflight B）：
      # `status(stale) → analyze → status` 第二次读到缓存的 stale ⟹ **恒 WARN 假警**
      # （旧实现：改库只"不缓存自身"，无任何失效点）。失效面 = 本 PID 全部 memo 键。
      local _rc; _run_gitnexus_raw "$@"; _rc=$?
      rm -f "${_GK_GX_MEMO_DIR}/$$".* 2>/dev/null || true
      return $_rc ;;
  esac
  local _mk _mf
  _mk="$gx_args|$(_gx_repo_dir_for_current)"
  _mf="${_GK_GX_MEMO_DIR}/$$.$(printf '%s' "$_mk" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-96)"
  if [ -f "$_mf" ]; then cat "$_mf"; return 0; fi
  local _o; _o=$(_run_gitnexus_raw "$@")
  if mkdir -p "$_GK_GX_MEMO_DIR" 2>/dev/null; then
    printf '%s' "$_o" > "$_mf" 2>/dev/null || true
    find "$_GK_GX_MEMO_DIR" -maxdepth 1 -type f -mmin +120 -delete 2>/dev/null || true
  fi
  printf '%s' "$_o"
  return 0
}
# ─── gitnexus 外置存储根：按 **node 形态**分根（单一事实源）─────────────────────────
# 2026-11-01：抽成函数。原先这段分根逻辑只内联在 `_run_gitnexus_raw` 里 ⟹
#   `_gitnexus_baseline_status` 调 `fast-status` 时**拿不到**它（只传 shell 里的空 env）⟹
#   `fast-status` 的 `_meta_candidates` 只能看到 `<repo>/.gitnexus/meta.json`（外置存储下不存在）
#   ⟹ 恒 `unavailable` ⟹ 回退 `gitnexus status`（Windows 上 >120s 或直接崩）⟹ 基线判 `stale`/`unavailable`
#   ⟹ `BASELINE_STALE` 派发阻断。**这才是"自愈从未成功过"的真因**：自愈本身没坏，是它看不见索引。
# 语义：`GITNEXUS_STORAGE_ROOT` 显式胜；否则 `<GK_GITNEXUS_STORE_BASE|~/.gitnexus-store>` 下
#   按形态取 `win` / `wsl` 子根。⚠ 传的是**基根**，gitnexus 自己追加 `<reponame>-<hash>`。
_gx_store_root_for_node() {
  local _node="${1:-}"
  local _base="${GK_GITNEXUS_STORE_BASE:-$(_user_home_wsl)/.gitnexus-store}"
  local _sb=""
  if [[ "$_node" == *.exe ]] || [[ "$_node" == /mnt/* ]] \
     || [[ "$_node" == [A-Za-z]:* ]] || [[ "$_node" == /[A-Za-z]/* ]]; then
    # Windows node ⟹ Windows 反斜杠形态 + `\win` 根
    #   ⚠ 替换里必须**保留分隔符**（`\1:\\`）—— 只写 `\1:` 会吃掉 `/c/` 的尾斜杠 ⟹ `C:Users\...`
    _sb=$(printf '%s' "$_base" \
      | sed -e 's#^/mnt/\([a-zA-Z]\)/#\U\1:\\#' -e 's#^/\([a-zA-Z]\)/#\U\1:\\#' -e 's#/#\\#g')
    printf '%s' "${GITNEXUS_STORAGE_ROOT:-${_sb}\\win}"
  else
    # WSL/linux node ⟹ POSIX 形态 + `/wsl` 根（认 `C:\` / `C:/` / `/c/` 三种输入）
    _sb=$(printf '%s' "$_base" \
      | sed -e 's#\\#/#g' -e 's#^\([a-zA-Z]\):/#/x\1/#' -e 's#^/\([a-zA-Z]\)/#/mnt/\L\1/#' -e 's#/x\([a-zA-Z]\)/#/mnt/\L\1/#')
    printf '%s' "${GITNEXUS_STORAGE_ROOT:-${_sb}/wsl}"
  fi
}
_run_gitnexus_raw() {
  local gx_args="$*"
  local gx_out=""
  # node 定位 = _gx_node_probe 单点（P1 唯一探测，本函数不再内嵌第二份）
  # F-REV-72（2026-09-16，用户裁定）：**必须 win 模式** —— 本函数消费的 JS 面是**硬编码的
  #   Windows 份**（见下方 `_gx_js`），而 wsl 模式以 `command -v node` 命中 `/usr/bin/node`
  #   （linux v20.20.2）⟹ **混血执行**：`@ladybugdb` 只装 `core-win32-x64` ⟹ 凡需 native
  #   binding 的子命令（context/impact/query/detect-changes/analyze）报 `invalid ELF header`
  #   ⟹ **输出恒空**，且被 `2>/dev/null` 吞掉诊断 ⟹ **假绿**（实测：清 memo 后两次 `search`
  #   均落 0 字节 memo）。win 模式在 Windows node.exe 全缺失时**内部回退** linux node
  #   （见 `_gx_node_probe` L1291）⟹ 与旧行为等价，无回归。
  local _node_exe=""; _node_exe=$(_gx_node_probe win) || true
  local _gx_js; _gx_js="$(_user_home_wsl)/AppData/Roaming/npm/node_modules/gitnexus/dist/cli/index.js"
  # Determine project root and gitnexus repo name from state
  # （A2 单源化 2026-09-05）目录推导收敛到 _gx_repo_dir_for_current（GK_GX_DIR 显式覆盖 /
  # STATE target_repo → registry name↔path / skill·gatekeeper 语义 → SKILL_DIR·MAIN_REPO_WSL），
  # 不再在此内嵌第二份推导。未知 target_repo 名称先查 registry（新登记受治理项目可解析）。
  local _repo_dir; _repo_dir=$(_gx_repo_dir_for_current)
  # 2026-10-05（ECC-774A4BD638FB）：worktree（.git 为文件）归一主仓根 —— 防 gitnexus 报
  #   `Not a git repository` ⟹ status 恒 unavailable（见 _gx_worktree_main_root）。
  _repo_dir=$(_gx_worktree_main_root "$_repo_dir")
  # Direct node.exe via WSL paths — same as working command from WSL bash
  # node.exe is Windows binary: must convert WSL paths to Windows format via wslpath
  # --skip-git: gitnexus 1.6.9 仅 analyze/publish 支持（status/detect/context/impact/query 无此选项，
  # 传了必报 unknown option → stderr 被 2>/dev/null 吞 → 输出空 → 误判超时）。
  # 原实现对 analyze|status|detect 全加 --skip-git → status/detect 报错；2026-08-03 修正为仅 analyze。
  local _win_gx_js; _win_gx_js=$(_gx_to_win_path "$_gx_js")
  [ -n "$_win_gx_js" ] || {
    echo "unavailable: gitnexus 入口解析失败（$_gx_js；路径归一失败）" >&2
    echo ""
    return 1
  }
  local _skip_git=""
  case "$gx_args" in
    analyze*) _skip_git="--skip-git" ;;
  esac
  if [ -z "$_node_exe" ]; then
    echo "unavailable: node.exe not found in any known path" >&2
    echo ""
    return 1
  fi
  # NVIDIA ProgramData 路径受限（2026-08-31 复发确认：gitnexus 1.6.10 后技能仓库索引不可用）：
  # gitnexus analyze 身份缓存默认写 ProgramData 被拒 → 固化重定向到用户临时目录（2026-09-07 P1：按 node 类型选路径形态）
  local _gx_js_arg="$_win_gx_js"
  local _gx_identity_cache=""
  if [[ "$_node_exe" == *.exe ]] || [[ "$_node_exe" == /mnt/* ]] \
     || [[ "$_node_exe" == [A-Za-z]:* ]] || [[ "$_node_exe" == /[A-Za-z]/* ]]; then
    _gx_identity_cache="${GITNEXUS_ANALYZER_IDENTITY_CACHE_DIR:-$(_user_home_win)\\AppData\\Local\\Temp\\gk-gitnexus-identity}"
    mkdir -p "$(_user_home_wsl)/AppData/Local/Temp/gk-gitnexus-identity" 2>/dev/null || true
  else
    _gx_js_arg="$_gx_js"   # linux node 读 WSL 路径
    _gx_identity_cache="${GITNEXUS_ANALYZER_IDENTITY_CACHE_DIR:-/tmp/gk-gitnexus-identity}"
    mkdir -p "/tmp/gk-gitnexus-identity" 2>/dev/null || true
  fi
  # F-REV-84（2026-09-16，用户裁定「统一抬到 300s，对齐 python 侧」）：默认超时 **30 → 300**。
  # 依据（实测 + 读码）：`_run_gitnexus` 调用面有 **11+ 个必开 DB 的子命令**（context / impact /
  #   query / detect-changes / status —— 散布于 `cmd_monitor` 评分段 / `audit_extra` 红队站 /
  #   `cmd_context` / crossrev preflight / node_guard 注入等调用点），而 subagent 侧同一数据源
  #   （`subagent_runner._gitnexus_cmd`）早已是 **300 → 600 阶梯** ⟹ 同一仓库、同一命令，两侧
  #   口径差 **10-20 倍**，bash 主链在脏树/冷启/大仓下**静默空输出**（各调用点静默吞 stderr 诊断）
  #   = F-REV-77 同族。⚠ 行号一律不写（本项目 R-9 定案：注释去行号、改符号引用）。
  # ⚠ 单点：默认值**只此一处**（`GK_GX_STATUS_TIMEOUT` / ensure 的 analyze 为**显式覆盖**，见下）。
  # F-REV-88（2026-09-16，用户裁定「A+B 双修」）：`analyze`（含 `--embeddings`）走 onnxruntime-node，
  #   设备默认 `auto` 会探 CUDA/DML 执行提供器 → 加载 NVIDIA 驱动 → 触碰
  #   `C:\ProgramData\NVIDIA Corporation\Drs\nvAppTimestamps` ⟹ 沙箱判 `restricted` 拦停，且该拦截
  #   随 IDE 重启**复发**（运行时授权不持久 —— 详见 F-REV-89 沙箱 legacy 文件诊断）。此处显式钉
  #   `cpu` **断根**：CPU 路径不探 GPU 驱动。与沙箱白名单
  #   （`permission/global.json` → `resourceAuthorization.filesystem.readWrite`）互为冗余。
  #   ⚠ 只对 `analyze*` 注入：`GITNEXUS_EMBEDDING_DEVICE` 经 gitnexus `parseDevice` 校验，
  #   **空串即抛错**（非法值），故其余子命令**保持不设**（读命令非嵌入热路径，避免无谓降速）。
  #   ⚠ 不改变索引身份：`resolveEmbeddingIdentity` 只含 model/dimensions/provider、**不含 device**
  #   ⟹ 钉 cpu 不会触发全量重嵌入。
  # A1 收口（2026-10-28）：**spawn 委托** `scripts/gk_gitnexus.py run`（python 侧唯一 launcher）。
  #   本函数只保留**宿主侧编排**：node 定位（`_gx_node_probe win`）、js 路径（`_gx_js` + wslpath
  #   形态）、repo 目录（`_gx_repo_dir_for_current` + worktree 归一）、cwd 与 argv。
  #   策略面（identity cache 重定向 / analyze 钉 cpu / 超时语义）**不再有第二份实现** —— 旧写法
  #   在此再 spawn 一次 node，与 launcher 的 `_build_env` 双写同三条策略（漂移面）。
  #   rc 语义与旧实现一致：恒 0（失败文案走 stderr，调用方本就不判 rc）。
  #   ⚠ 2026-10-29 实测修：原引用 `$_SCRIPT_DIR`，但该变量在启动段（L94）已 `unset`，
  #     在 `set -u` 下任何 gitnexus 调用都炸 `unbound variable` ⟹ `cmd_monitor --subagent`
  #     恒 rc=1（6 臂派发全部 `dispatch_blocked`，且 reason 为空）。改用全局 `SKILL_DIR`。
  local _gx_launcher="$SKILL_DIR/scripts/gk_gitnexus.py"
  # ── 2026-11-01（跨平台 ①E 接线，trae 清单第 2/3 条）：gitnexus 存储根**按形态分根** ──
  # 病象（实测）：Windows 侧 CLI 跑 gitnexus 时**未设** `GITNEXUS_STORAGE_ROOT` ⟹ gitnexus
  #   回落 **repo-local `.gitnexus/`** ⟹ `status` 报 `error:"not-indexed"` ⟹ 质询链判
  #   `BASELINE_STALE` fail-closed 阻断（本 worktree 实测：主仓索引已建、worktree 侧恒 not-indexed）。
  #   同一仓在 WSL 侧建的索引落在 `/mnt/...`，Windows 侧 gitnexus 读不到 = **跨形态互斥**。
  # 修法 = **按形态分根**（不是平台判断锁死调用路径）：Windows 形态 → `win` 根，WSL 形态 → `wsl` 根。
  #   ⚠ 不硬编码用户路径 —— 根基由 env `GK_GITNEXUS_STORE_BASE` 提供，默认 = 用户主目录下
  #   `.gitnexus-store`（与既有 `_user_home_wsl()` 同源）；**用户可自定义**（对齐 R0.16 的
  #   「不硬编码、留可自定义配置」原则）。
  # 三个旋钮（实测依据）：
  #   · `GITNEXUS_MAX_FILE_SIZE` 默认 512KB ⟹ `gatekeeper-cli.sh`（821KB）被**跳过不索引**
  #     （analyze 日志实证：`effective threshold 2048KB (default 512KB)`）；
  #   · `GITNEXUS_WORKER_READY_TIMEOUT_MS` 默认过短 ⟹ worker 5s 即崩；
  #   · 存储根必须与形态一致（否则 not-indexed）。
  # 全部可用同名 env **覆盖**（`${VAR:-default}`），不夺用户控制权。
  # 存储根 = 单源 `_gx_store_root_for_node`（按 node 形态分根；`GITNEXUS_STORAGE_ROOT` 显式胜）
  local _gx_store_root=""
  _gx_store_root=$(_gx_store_root_for_node "$_node_exe")
  gx_out=$(
    GX_NODE="$_node_exe" GX_JS="$_gx_js_arg" GX_REPO_DIR="$_repo_dir" \
    GITNEXUS_ANALYZER_IDENTITY_CACHE_DIR="$_gx_identity_cache" \
    GITNEXUS_STORAGE_ROOT="$_gx_store_root" \
    GITNEXUS_WORKER_READY_TIMEOUT_MS="${GITNEXUS_WORKER_READY_TIMEOUT_MS:-30000}" \
    GITNEXUS_MAX_FILE_SIZE="${GITNEXUS_MAX_FILE_SIZE:-2048}" \
    python3 "$_gx_launcher" run --timeout "${GK_GX_TIMEOUT:-300}" --cwd "$_repo_dir" \
      -- $gx_args $_skip_git 2>/dev/null
  ) || true
  echo "$gx_out"
}
# ─── gitnexus registry/目标目录解析（A2/A3 共用；registry = gitnexus index/analyze 写入的全局注册表）───
# registry 位置：WSL $HOME 或 Windows 用户主目录（`_user_home_wsl` 派生，脚本 WSL 视图）下的 .gitnexus/registry.json。
_gx_registry_path() {
  local _c=""
  local _uh; _uh="$(_user_home_wsl)"
  local _uh_win; _uh_win=$(printf '%s' "$_uh" | sed 's#^/mnt/\([a-z]\)/#\U\1:/#')
  for _cand in "${HOME}/.gitnexus/registry.json" "${_uh}/.gitnexus/registry.json" "${_uh_win}/.gitnexus/registry.json"; do
    [ -f "$_cand" ] && { _c="$_cand"; break; }
  done
  echo "$_c"
}
# _gx_dir_for_repo_name <name> → gitnexus registry 名称精确匹配的目录（WSL 形态，posix 下自动 /mnt/<d>/ 转换）
# 用途（F-REV-39，2026-09-13）：`audit --crossfull --repo <name>` 的目标解析（与 state.target_repo 路由同源）。
# 未命中 → echo "" 且 rc=1（调用方 fail-loud，禁静默回退技能目录）。
_gx_dir_for_repo_name() {
  local _name="${1:-}" _reg=""
  [ -n "$_name" ] || return 1
  _reg="$(_gx_registry_path)"
  [ -n "$_reg" ] && [ -f "$_reg" ] || return 1
  GK_REG_FILE="$_reg" GK_REPO_NAME="$_name" python3 -c '
import json, os
try:
    d = json.load(open(os.environ["GK_REG_FILE"]))
except Exception:
    d = []
for e in d if isinstance(d, list) else []:
    if isinstance(e, dict) and e.get("name", "") == os.environ["GK_REPO_NAME"]:
        p = e.get("path", "").replace("\\", "/")
        if os.name == "posix" and len(p) >= 2 and p[1] == ":":
            p = "/mnt/" + p[0].lower() + p[2:]
        print(p); break
' 2>/dev/null
}
# _gx_repo_name_for_dir <dir> → gitnexus repo 名（registry name↔path 最长前缀匹配；未命中 fail-loud）
# 归一化：`\`→`/` + 小写 + 去尾斜杠；`/mnt/c/...` → `c:/...`，与 registry Windows 形态可比。
# 命中优先级：registry 最长前缀 → skill 目录特判；**两者皆不中即 fail-loud（rc=1 + 空名 + WARN）**
# （F-REV-73 前的兜底猜名 `spz_gatekeeper` 已删 —— 注册后它会静默查到另一个仓库）。
# 不覆盖 GK_DETECT_REPO 等调用点显式 env 覆盖。
_gx_repo_name_for_dir() {
  local dir="${1:-}"
  local reg name=""
  [ -n "$dir" ] || {
    echo "WARN[gx-repo]: _gx_repo_name_for_dir 收到空目录 ⟹ repo 名不可解析（fail-loud）" >&2
    return 1
  }
  reg=$(_gx_registry_path)
  if [ -n "$reg" ]; then
    name=$(GK_REG_FILE="$reg" GK_TARGET_DIR="$dir" python3 -c '
import json, os
def norm(p):
    p = p.replace("\\", "/").lower().rstrip("/")
    if p.startswith("/mnt/"):            # /mnt/c/... → c:/...
        p = p[5] + ":" + p[6:]
    return p
try:
    d = json.load(open(os.environ["GK_REG_FILE"]))
except Exception:
    d = []
if not isinstance(d, list):
    d = []
tn = norm(os.environ["GK_TARGET_DIR"])
best, bestlen = "", -1
for e in d:
    nm = e.get("name", "") if isinstance(e, dict) else ""
    p = e.get("path", "") if isinstance(e, dict) else ""
    if not nm or not p:
        continue
    pn = norm(p)
    if tn == pn or tn.startswith(pn + "/"):   # 目录在已索引仓库内/等于仓库根 → 最长前缀胜出
        if len(pn) > bestlen:
            best, bestlen = nm, len(pn)
print(best)
' 2>/dev/null)
  fi
  [ -n "$name" ] && { echo "$name"; return 0; }
  # F-REV-73（2026-09-16，用户裁定）：**兜底不再猜名**。
  #   历史语义：`*)` 猜 `spz_gatekeeper`（当时该名**不在 registry** ⟹ gitnexus 报
  #   `Repository not found` ⟹ 属「响亮失败」）。**注册 `spz_gatekeeper_project` 之后**该名成了
  #   真仓库 ⟹ 兜底变成「静默查到另一个仓库的图」—— 由响亮失败反转为**静默错答**。
  #   故改为 fail-loud：stdout 空 + rc=1 + stderr WARN（调用点即便 `2>/dev/null` 也看得见 WARN）。
  case "$dir" in
    "${SKILL_DIR}"*) echo "spz-gatekeeper-r-sequence"; return 0 ;;
  esac
  # ⚠ 消息内的反引号须转义（`\``）：未转义 = 命令替换，曾实测触发 `gitnexus analyze` 真执行并挂死
  echo "WARN[gx-repo]: 目录 '$dir' 未命中 gitnexus registry 且不在技能仓库内 ⟹ repo 名不可解析（已 fail-loud，不再回退猜名 spz_gatekeeper）；如需查询请先 \`gitnexus analyze\` 注册或用 GK_GX_DIR/GK_REPO_NAME 显式指定" >&2
  return 1
}
# _gx_repo_root_of <dir> → 该目录所属 git 仓库根（**归属判定**，非字符串猜测）：
#   ① registry 归属 → ② git `--git-common-dir` 反推主仓库根（**worktree / 子目录都能归属**）
#   → 均不中 ⟹ 空输出 + rc=1（调用方 fail-loud）。
# F-REV-83（2026-09-16）：本函数是「目录 → 仓库」的**唯一归属判定单点**。
# 【⑰-7 交叉审查清理】registry 分支**不得**自带 python —— 初版在此内联了一份「最长前缀 + 路径
#   归一化」python，与 `_gx_repo_name_for_dir` 构成**同规则第二实现**（两处 `norm()` 已异形：一份折
#   `/mnt/c/…`→`c:/…`、另一份折 `C:…`→`/mnt/c/…`）⟹ **双源漂移**，规则演化漏改一处即静默错答。
#   bomb 扫描（实测非读码）暴露其被「净额」掩盖：inline_python 219→219 实为**新增 1 块 + 删除 1 块**
#   （`_gx_repo_dir_for_current` 中与 `_gx_dir_for_repo_name` 逐字重复的 `_rp`）对冲。
#   现复用既有两个单点（`_gx_repo_name_for_dir` 目录→名 → `_gx_dir_for_repo_name` 名→目录），本函数
#   不再持有 registry python；等价性逐路径核对（子目录 / worktree / 非 git / 空参 × Win/posix 两形态）。
_gx_repo_root_of() {
  local d="${1:-}" root="" _nm=""
  [ -n "$d" ] && [ -d "$d" ] || return 1
  # registry 未命中在本函数是**中间态**（下接 git 归属），故按房内探针写法抑制
  # `_gx_repo_name_for_dir` 的 fail-loud WARN（stderr 丢弃）；本函数自己的失败由 rc=1 上报。
  _nm=$(_gx_repo_name_for_dir "$d" 2>/dev/null) || _nm=""
  if [ -n "$_nm" ]; then
    root=$(_gx_dir_for_repo_name "$_nm") || root=""
  fi
  [ -n "$root" ] && [ -d "$root" ] && { echo "$root"; return 0; }
  # git 权威：worktree 的 `.git` 是文件（内含 gitdir 指针），`--git-common-dir` 恒指主仓库 .git
  local _cd
  _cd=$(git -C "$d" rev-parse --git-common-dir 2>/dev/null) || return 1
  [ -n "$_cd" ] || return 1
  case "$_cd" in
    /*) : ;;
    *) _cd="$d/$_cd" ;;
  esac
  root=$(cd "$(dirname "$_cd")" 2>/dev/null && pwd) || return 1
  [ -n "$root" ] && { echo "$root"; return 0; }
  return 1
}
# _gx_repo_dir_for_current → 当前 gatekeeping 目标仓库目录（单一事实源，_run_gitnexus 消费）：
#   GK_GX_DIR 显式覆盖 → STATE target_repo 语义（skill/gatekeeper / registry 名精确匹配）
#   → **归属判定链**（state.worktree → 主仓库 → 当前目录，逐级须通过 `_gx_repo_root_of`）→ 均不中 fail-loud。
# F-REV-83（2026-09-16，用户质询「repo 为什么会查到其他仓库 / 该由元数据中枢指定」）—— 修前两处病：
#   ① 末枝 `echo "${MAIN_REPO_WSL:-$(pwd)}"` = 把**不可归属的目标静默替换成主仓库** ⟹ 该目录落在
#      技能仓库内 ⟹ `_gx_repo_name_for_dir` 的 registry 前缀**必命中技能仓库** ⟹ **静默错答**
#      （F-REV-73 的 fail-loud 在「名字解析」层，拦不住「目录归属判错」这一层）。
#   ② `skill` 语义用 `'.trae' in worktree` **字符串**判定 ⟹ 门卫仓库的 feature worktree
#      （`<home>/.trae/worktrees/spz_gatekeeper_project/feature/...`）**同样含 `.trae`**
#      ⟹ 被判成 skill ⟹ 恒查技能仓库的图（**⑰ 交叉审查实测**：现存 **9** 个 state（技能仓库 7 + dryrun worktree 2）**全部 rc=0 可归属**；其中 **2** 个属此形态 —— 修前均**错答为技能仓库**、修后**正确归属门卫仓库**）。
#   现语义：候选**必须通过归属验证**（registry 路径 / git 主仓库根）才被采用；猜名与静默回退**全删**。
# ─── 链接 worktree 归一（2026-10-05 · ECC-774A4BD638FB）──────────────────────
# 病根：链接 worktree 的 `.git` 是**文件**（内容 `gitdir: /mnt/c/...`）；gitnexus（Windows node
# + Windows git）读该 gitdir 失败 ⟹ 报 `Not a git repository` ⟹ `status` 恒 unavailable ⟹
# plan-refinement 的 `BASELINE_STALE` 结构性拦停（质询在 worktree 内被硬拦）。
# 修法 = 归一到**主仓根**（`.git` 为目录，两种 git 都认；worktree 内容 == 已提交的 master ⟹
# 语义等价）。只读、纯路径映射；非 worktree 原样返回（零回归）。
_gx_worktree_main_root() {  # <dir> → worktree 归一后的主仓根 / 原样
  local dir="$1" gd=""
  [ -n "$dir" ] || { echo ""; return 0; }
  [ -f "$dir/.git" ] || { echo "$dir"; return 0; }
  gd=$(git -C "$dir" rev-parse --git-common-dir 2>/dev/null) || { echo "$dir"; return 0; }
  case "$gd" in
    /*) : ;;
    *) gd="$dir/$gd" ;;
  esac
  ( cd "$(dirname "$gd")" 2>/dev/null && pwd ) || echo "$dir"
}

_gx_repo_dir_for_current() {
  local _tr="" _wt="" _d="" _cand=""
  [ -n "${GK_GX_DIR:-}" ] && { echo "$GK_GX_DIR"; return 0; }
  if [ -f "$STATE_FILE" ]; then
    # 一次读取（target_repo + worktree）；⚠ 不再从 worktree 字符串反推 target_repo（病②）
    _gx_pair=$(GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" python3 -c "
import json,os
try:
    d = json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'))
except Exception:
    d = {}
print(d.get('target_repo','') or '')
print(d.get('worktree','') or '')
" 2>/dev/null)
    { IFS= read -r _tr; IFS= read -r _wt; } <<< "$_gx_pair"
    case "$_tr" in
      skill) [ -n "$SKILL_DIR" ] && { echo "$SKILL_DIR"; return 0; } ;;
      gatekeeper) [ -n "$MAIN_REPO_WSL" ] && { echo "$MAIN_REPO_WSL"; return 0; } ;;
      "") ;;
      *)
        # 非内建语义：registry name 精确匹配（复用既有单点，禁第二份 python 匹配）
        _d=$(_gx_dir_for_repo_name "$_tr" 2>/dev/null) || true
        [ -n "$_d" ] && { echo "$_d"; return 0; }
        ;;
    esac
  fi
  for _cand in "$_wt" "${MAIN_REPO_WSL:-}" "$(pwd)"; do
    _d=$(_gx_repo_root_of "$_cand" 2>/dev/null) || continue
    [ -n "$_d" ] && { echo "$_d"; return 0; }
  done
  echo "WARN[gx-repo]: 目标仓库目录**不可归属**（state.worktree / 主仓库 / 当前目录均非受治理仓库）⟹ fail-loud（不再静默回退技能或主仓库，F-REV-83）；修法：\`GK_GX_DIR\` 显式指定，或对该仓库跑 \`gitnexus analyze\` 注册" >&2
  return 1
}
# ─── gitnexus 基线确保（A3）：复用既有 status 判定，同版本不重复 analyze ───
# 语义对齐 crossrev preflight B / `context --update`：
#   current|reusable → 复用既有基线（不重复 analyze）；stale/not indexed/不可用 → analyze
#   （analyze 自动 --skip-git）刷新后复查；失败仅 WARN，不阻断登记。
# 判定精度（2026-09-05 实证校准）：gitnexus 1.6.10 status 文本——
#   新鲜 = `Status: ✅ up-to-date`；未建索引 = `Repository not indexed. Run: gitnexus analyze`；
#   身份头恒含 `Current analyzer runner identity/Current commit` 字样 → **不能**用裸 `current` 判新鲜
#   （误判会把 stale 当 fresh → 永不重建 = 复用机制失效）；须锚定行首 `Status:` 行的 up-to-date。
_gitnexus_baseline_status() {   # <dir> → echo current|reusable|stale|unavailable
  local dir="$1" st
  # 2026-11-01（实测）：`gitnexus status` 在 Windows 上**恒定重算分析器身份摘要**
  #   （meta 记 dependencyRuntime.artifactCount=12280 个依赖产物；POSIX 所有权 API 缺失 ⟹
  #   身份缓存 fail-closed 永不命中）⟹ 原生 Windows 亦 >120s 不返回（query 同索引 985ms 正常）。
  #   首选**零 spawn** 的 `fast-status`（读索引自记 lastCommit + `git diff` 代码后缀），
  #   四态语义不变；只有它判不出（无 meta / 解析失败）才回退原 node status 路径。
  local _fast=""
  # ⚠ 2026-11-01（真因 G，实测）：**必须把外置存储根传进去**。原写 `${GITNEXUS_STORAGE_ROOT:-}`
  #   ⟹ 取的是 shell 里的值（通常为空；真正的分根结果在 `_run_gitnexus_raw` 局部变量里）⟹
  #   `fast_status._meta_candidates` 只看得见 `<repo>/.gitnexus/meta.json`（外置存储下不存在）
  #   ⟹ 恒 `unavailable` ⟹ 回退 `gitnexus status`（Windows 上 >120s 或崩溃）⟹ 基线恒 `stale`。
  local _sr=""
  _sr=$(_gx_store_root_for_node "$(_gx_node_probe win 2>/dev/null)")
  _fast=$(GITNEXUS_STORAGE_ROOT="$_sr" \
    python3 "$SKILL_DIR/scripts/gk_gitnexus.py" fast-status --cwd "$dir" 2>/dev/null | tr -d '\r' || true)
  case "$_fast" in
    current|reusable|stale) echo "$_fast"; return 0 ;;
  esac
  # F-REV-77（2026-09-16，本次实测发现）：`status` 要**比对工作树**（列出已修改文件）⟹ 脏工作树
  # 下**耗时 ~24.5s**（实测：本批 11 个未提交文件），而 `_run_gitnexus` 默认 `GK_GX_TIMEOUT=30`
  # ⟹ 一旦超时即**空输出** ⟹ 原实现落 `unavailable`（**误判**：索引其实存在且只是过期）。
  # 修：status 探测显式抬高超时。⚠ F-REV-84（2026-09-16）把默认值 120 → **300**：主链默认已
  # 统一到 300，若此处仍留 120 就是**唯一比默认更小**的调用点（脏树再大就退回误判面）；
  # 保留 `GK_GX_STATUS_TIMEOUT` 旋钮（可显式收紧）。
  # ⚠ 本函数只在**只读**判定路径使用；`_run_gitnexus` 的进程级 memo 保证同一 CLI 进程内只探一次。
  st=$(GK_GX_DIR="$dir" GK_GX_TIMEOUT="${GK_GX_STATUS_TIMEOUT:-300}" _run_gitnexus status --json 2>/dev/null || echo "")
  # 2026-10-30（实测修复，F-REV-1xx）：原实现用文本正则匹配**中文**关键词（`已过期` /
  #   `索引内容：N 个已修改`），但 gitnexus 1.6.12 的 status 文案是**英文**
  #   （`Status: ⚠️ stale (re-run gitnexus analyze)`），且工作区内容一致时**根本不打印
  #   `Index content` 行** ⟹ `reusable` 分支恒不可达（死代码）⟹ 每次 commit（哪怕只改
  #   markdown，实测 22 文件 0 代码改动）都落到兜底 `stale` ⟹ 无谓触发全量 analyze
  #   （实测单次 2132.5s ≈ 35 分钟）。
  #   修：改走官方 `status --json`（结构化，不随文案语言漂移）+ 代码文件差异判定。
  #   四态语义：incompleteReasons 非空 → stale（真需重建）；commit 相等 → current；
  #   commit 落后但 `git diff` 代码文件零改动（.py/.js/.ts/.tsx/.sh/.mjs/.cjs）→ reusable。
  local _st_verdict
  _st_verdict=$(printf '%s\n' "$st" | python3 -c '
import json, sys
raw = sys.stdin.read()
d = None
for line in reversed(raw.splitlines()):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        d = json.loads(line)
        break
    except Exception:
        continue
if d is None:
    print("unavailable")
    raise SystemExit
idx = d.get("index") or {}
cur = d.get("current") or {}
inc = idx.get("incompleteReasons") or []
if inc:
    print("stale")
    raise SystemExit
ic = (idx.get("commit") or "").strip()
cc = (cur.get("commit") or "").strip()
if not ic or not cc:
    print("unavailable")
    raise SystemExit
if ic == cc:
    print("current")
    raise SystemExit
print("commit_behind %s %s" % (ic, cc))
' 2>/dev/null || echo "unavailable")
  case "$_st_verdict" in
    current)     echo "current";     return 0 ;;
    stale)       echo "stale";       return 0 ;;
    unavailable) echo "unavailable"; return 0 ;;
    commit_behind\ *)
      local _ic _cc _ncode
      _ic=$(printf '%s' "$_st_verdict" | awk '{print $2}')
      _cc=$(printf '%s' "$_st_verdict" | awk '{print $3}')
      _ncode=$(git -C "$dir" diff --name-only "$_ic" "$_cc" -- '*.py' '*.js' '*.ts' '*.tsx' '*.sh' '*.mjs' '*.cjs' 2>/dev/null | wc -l | tr -d '[:space:]')
      if [ "${_ncode:-0}" -eq 0 ] 2>/dev/null; then
        echo "reusable"
      else
        echo "stale"
      fi
      return 0 ;;
    *) echo "unavailable"; return 0 ;;
  esac
}
_gx_analyze_embeddings() {  # <dir> → 0 = analyze 后 status 可复用（current|reusable）；非 0 = 仍不可复用
  # 语义搜索基线的**单一事实源**：凡走 `analyze --embeddings` 一律经此（禁各处直调）。
  # 2026-09-19 ECC-4BDBA3605F47 残留态自愈：lbug 里已存旧 CodeEmbedding 行时，新一遍
  #   「从头插」必撞主键 —— 实测 `CREATE (e:CodeEmbedding {id: ...})` 约束失败、
  #   `embeddingCheckpoint {nodesProcessed: 0, totalNodes: 2968}`、
  #   `incrementalInProgress {phase: load-graph}` 三者并存，且 gitnexus **永不自清**。
  #   ⟹ 无此重试则 analyze 恒失败、`context --update` 恒 unavailable（自激死锁）。
  #   `--drop-embeddings` 是 gitnexus 官方旗标（重建前丢弃既有嵌入），代价 = 一轮全量重嵌。
  # 不变式（2026-11-01 owner 裁定后）：**先试原命令**；只有**残态证据**（主键冲突 /
  #   incrementalInProgress / embeddingCheckpoint）才付 `--drop-embeddings` 全量重嵌代价；
  #   同一目录 30min 内只自愈一次（跨进程 marker）——「复验失败」本身**不**等于残态。
  local dir="${1:-}" _gx_st _gx_ok=1 _gx_lkfd=""
  [ -n "$dir" ] || dir="$(_gx_repo_dir_for_current)"
  if command -v flock >/dev/null 2>&1; then
    local _gx_lk="${TMPDIR:-/tmp}/gk-gx-refresh.$(printf '%s' "$dir" | tr -c 'A-Za-z0-9' '_').lock"
    exec {_gx_lkfd}>"$_gx_lk" 2>/dev/null || _gx_lkfd=""
    if [ -n "$_gx_lkfd" ]; then
      flock "$_gx_lkfd"
      _gx_st=$(_gitnexus_baseline_status "$dir")
      case "$_gx_st" in
        current|reusable) flock -u "$_gx_lkfd" 2>/dev/null || true; eval "exec ${_gx_lkfd}>&-"; return 0 ;;
      esac
    fi
  fi
  # 2026-11-01（实测，owner 裁定「复验失败 ≠ 残态」）：原实现**无条件**重试 `--drop-embeddings`
  #   （= 全量重嵌，本机 40min 级），且 6 臂/3 臂各自来一遍 ⟹「一次 stale = 一次全量」。
  #   收口两条：① 同一目录 30min 内只自愈一次（跨进程 marker，防每臂重复付账）；
  #   ② 只有**残态证据**（主键冲突 / incrementalInProgress / embeddingCheckpoint）才付全量重嵌。
  local _gx_heal_marker="${TMPDIR:-/tmp}/gk-gx-selfheal.$(printf '%s' "$dir" | tr -c 'A-Za-z0-9' '_')"
  if [ -f "$_gx_heal_marker" ]; then
    local _gx_age=$(( $(date +%s) - $(stat -c %Y "$_gx_heal_marker" 2>/dev/null || echo 0) ))
    if [ "$_gx_age" -lt 1800 ] 2>/dev/null; then
      echo "[gx-selfheal] 同目录 30min 内已自愈过（age=${_gx_age}s）→ 跳过重复 analyze $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
      [ -n "${_gx_lkfd:-}" ] && { flock -u "$_gx_lkfd" 2>/dev/null || true; eval "exec ${_gx_lkfd}>&-"; }
      return 1
    fi
  fi
  # ⚠ 2026-11-01（实测）：marker 原在 **analyze 之前** 落盘 ⟹ 一次 5 秒即失败的 analyze
  #   （如安全删除 shim 拦停）也会把 30min 冷静期点亮 ⟹ 之后 30 分钟**真 analyze 被跳过**
  #   ⟹ 日志只剩「同目录 30min 内已自愈过 → 跳过」⟹ 真因被完全掩盖（本会话实测）。
  #   修：成功 → 30min 冷静期（`$marker`）；失败 → 仅 5min（`$marker.fail`），失败不该锁死 30min。
  if [ -f "${_gx_heal_marker}.fail" ]; then
    local _gx_agef=$(( $(date +%s) - $(stat -c %Y "${_gx_heal_marker}.fail" 2>/dev/null || echo 0) ))
    if [ "$_gx_agef" -lt 300 ] 2>/dev/null; then
      echo "[gx-selfheal] 上次自愈失败仅 ${_gx_agef}s（<300s）→ 暂不重试 $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
      [ -n "${_gx_lkfd:-}" ] && { flock -u "$_gx_lkfd" 2>/dev/null || true; eval "exec ${_gx_lkfd}>&-"; }
      return 1
    fi
  fi
  local _gx_errf; _gx_errf=$(mktemp 2>/dev/null || echo /dev/null)
  GK_GX_DIR="$dir" GK_GX_TIMEOUT="${GK_GX_ANALYZE_TIMEOUT:-600}" \
    _run_gitnexus analyze --embeddings >"${GK_GX_KEEP_STDOUT:-/dev/null}" 2>"$_gx_errf" || true
  if [ "$_gx_errf" != "/dev/null" ] && [ -s "$_gx_errf" ]; then
    cat "$_gx_errf" >>"$GK_DBG_LOG" 2>/dev/null || true
  fi
  # 2026-09-21 R16/C2′：复验接受 `reusable`（内容一致即**可用**）—— 否则 R16 窗口下此处
  # 误判失败 ⟹ 白付 `--drop-embeddings` 全量重嵌（实测 366s 成功、8714 节点）。
  _gx_st=$(_gitnexus_baseline_status "$dir")
  if [ "$_gx_st" = "current" ] || [ "$_gx_st" = "reusable" ]; then
    _gx_ok=0
  elif grep -qiE "primary key|constraint|incrementalInProgress|embeddingCheckpoint|already exists|invalid ELF" "$_gx_errf" 2>/dev/null; then
    echo "[gx-selfheal] 检测到残态证据 → 重试 --drop-embeddings $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
    GK_GX_DIR="$dir" GK_GX_TIMEOUT="${GK_GX_ANALYZE_TIMEOUT:-600}" \
      _run_gitnexus analyze --embeddings --drop-embeddings >/dev/null 2>>"$GK_DBG_LOG" || true
    _gx_st=$(_gitnexus_baseline_status "$dir")
    { [ "$_gx_st" = "current" ] || [ "$_gx_st" = "reusable" ]; } && _gx_ok=0
  else
    echo "[gx-selfheal] 复验未过但**无残态证据** → 不付全量重嵌（status=$_gx_st）$(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
  fi
  [ "$_gx_errf" = "/dev/null" ] || rm -f "$_gx_errf" 2>/dev/null || true
  # 结果落 marker：成功 ⟹ 30min 冷静期；失败 ⟹ 只记 5min（见上方注释）
  if [ "$_gx_ok" = "0" ]; then
    : >"$_gx_heal_marker" 2>/dev/null || true
    rm -f "${_gx_heal_marker}.fail" 2>/dev/null || true
  else
    : >"${_gx_heal_marker}.fail" 2>/dev/null || true
  fi
  if [ -n "$_gx_lkfd" ]; then flock -u "$_gx_lkfd" 2>/dev/null || true; eval "exec ${_gx_lkfd}>&-"; fi
  return "$_gx_ok"
}
_gitnexus_ensure_baseline() {  # <dir> → echo 单行 JSON {gitnexus_baseline, detail[, warning]}；恒 exit 0
  local dir="${1:-}" st re
  if [ -z "$dir" ] || { [ ! -d "$dir/.git" ] && [ ! -f "$dir/.git" ]; }; then
    echo "{\"gitnexus_baseline\":\"skipped\",\"detail\":\"no git repo — 无可建基线目录\"}"
    return 0
  fi
  st=$(_gitnexus_baseline_status "$dir")
  # 2026-09-21 R16/L3：`reusable`（内容一致、仅 commit 落后）同属**可复用** ⟹ 不 analyze。
  # 输出值 = **真实态**（`current` 路径取值不变；`reusable` 不再被记成 current 而丢信息）。
  # 已核：唯一消费点 `cmd_register` 只按 `"failed"` 分支决策 ⟹ 零消费端破坏。
  if [ "$st" = "current" ] || [ "$st" = "reusable" ]; then
    echo "{\"gitnexus_baseline\":\"$st\",\"detail\":\"gitnexus status $st — 复用既有基线（内容一致），未重复 analyze\"}"
    return 0
  fi
  echo "[register] baseline stale/unavailable (status=$st) → analyze 刷新 $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
  # 新建索引首个 analyze 是**重操作**（1.6.10 全量建图；本机实测 69.9-122.6s）⟹ 显式 **600**
  # （F-REV-84：与 subagent 侧 300→600 阶梯的**上限**对齐。原值 180 是按"主链默认 30"留的余量，
  #  默认抬到 300 后 180 会**小于默认** ⟹ 必改，否则自动建索引反而更早超时）。
  # F-REV-95（2026-09-17，用户裁定）：与 `cmd_context --update` 的 analyze 共用**同一旋钮**
  #   `GK_GX_ANALYZE_TIMEOUT`（默认 600）—— 原先两处各自硬编码 600 / 走默认 300，口径不一致。
  # 2026-10-07（ECC-9FD1BEB74F82）：改走自愈单源（含 --drop-embeddings 残态修复 + 跨进程单飞）。
  _gx_analyze_embeddings "$dir" || true
  re=$(_gitnexus_baseline_status "$dir")
  if [ "$re" = "current" ] || [ "$re" = "reusable" ]; then
    echo "{\"gitnexus_baseline\":\"rebuilt\",\"detail\":\"analyze 后 status up-to-date — 基线已建\"}"
  else
    echo "{\"gitnexus_baseline\":\"failed\",\"detail\":\"analyze 后仍非 current（status=$re）— 登记不受阻\",\"warning\":true}"
  fi
  return 0
}
_state_checksum_verify() {
  # 2026-08-23 bomb 消解: 2>/dev/null → GK_DBG_LOG（checksum 验证失败静默 = 篡改检测失效）
  # 2026-09-25（选项 A）：`_with_state_lock` 已拆除；本检查**只读**（gk_gate_checksum.py 篡改即
  # BLOCK 且**不回写**）⟹ 无需取锁。
  python3 "${SKILL_DIR}/scripts/gk_gate_checksum.py" "$STATE_FILE" 2>>"$GK_DBG_LOG"
}

# ═══════════════════════════════════════════════════════════════
# Persistent Python Worker (eliminate per-call python3 spawn)
# ═══════════════════════════════════════════════════════════════
# 2026-10-28（A7）：原 bash 侧的 `_py_worker_*` / `_py3` **已整块删除**。删除理由是它们
#   **用了就是错的**，不是「没人用」：
#     ① `port=$(python3 worker …)` 的命令替换要等 worker 退出才返回 ⟹ 实测 rc=124 恒挂；
#     ② `trap '_py_worker_stop' EXIT` 把 worker 绑死在本 CLI 进程上 ⟹ 一次性调用零收益，
#        与「常驻省 spawn」的目标正好相反；
#     ③ 旧协议 = TCP `eval(code)` 且**无鉴权** ⟹ 本机任意进程可执行任意 Python。
#   ⟹ 承接方 = `scripts/gk_worker.py`（白名单 op + token 鉴权 + TTL 自退 + detached 启动）
#      与 `scripts/gk_worker_client.py`（detached 拉起 + pidfile 轮询 + token 读取）。
#   生产调用点**仍未接**（A7 裁定「不贸然接」：CLI 启动路径是 fail-closed 关键路径，
#   不宜再加一个可失败面）；接线留待 zthl-adapter §2.10 正式落地时统一设计。

# ---------- state ----------
cmd_state() {
  # Phase 7b (2026-08-23): state --clean-isolated — 残留隔离 state 治理。
  # 默认 dry 列表；--force 删除非当前使用的隔离 state（防误删活跃计划）。
  if [ "${1:-}" = "--clean-isolated" ]; then
    local _force=false _curr
    [ "${2:-}" = "--force" ] && _force=true
    _curr=$(realpath "$STATE_FILE" 2>/dev/null || echo "$STATE_FILE")
    local _found=false _removed=0
    for _iso in "$SKILL_DIR"/.gatekeeper.state.*; do
      [ -e "$_iso" ] || continue
      case "$_iso" in *.lock) continue ;; esac
      _found=true
      local _rp; _rp=$(realpath "$_iso" 2>/dev/null || echo "$_iso")
      if [ "$_rp" = "$_curr" ]; then
        echo "{\"isolated\":\"$_iso\",\"skip\":\"current state\"}"
      elif $_force; then
        rm -f "$_iso" 2>/dev/null && { _removed=$((_removed+1)); echo "{\"isolated\":\"$_iso\",\"removed\":true}"; }
      else
        echo "{\"isolated\":\"$_iso\",\"removed\":false,\"hint\":\"use --force to delete\"}"
      fi
    done
    if ! $_found; then
      echo '{"isolated":[],"message":"no isolated states found"}'
    else
      echo "{\"removed_total\":$_removed}"
    fi
    return 0
  fi
  # ② 形态盘点（只读，2026-10-02）：既有 `state` 命令的 --inventory 分支（禁新增 _CMD_REG）。
  #   默认扫 SKILL_DIR；可选位置参数 <root> 覆盖（测试/他仓盘点用）。零写盘。
  if [ "${1:-}" = "--inventory" ]; then
    local _inv_root="${2:-$SKILL_DIR}"
    [ -d "$_inv_root" ] || _inv_root="$SKILL_DIR"
    python3 - "$_inv_root" "$SKILL_DIR/scripts" <<'PYEOF' 2>>"$GK_DBG_LOG"
import os, sys, json
root, scripts = sys.argv[1], sys.argv[2]
sys.path.insert(0, scripts)
import gk_state_forms as gsf
import gk_finding as gf
states = []
for p in gsf.iter_live_states(root, extra_roots=gsf.worktree_state_roots(root)):
    form = gsf.state_form(p, skill_root=root)
    try:
        n = len(gf._read_findings_source(p, "base"))
    except Exception:
        n = 0
    try:
        wb = (gf.resolve_plan_state(p).get("would_be") or "")
    except Exception:
        wb = ""
    states.append({"path": p, "form": form,
                   "writable": form in gsf.WRITABLE_FORMS,
                   "findings": n, "would_be": wb})
print(json.dumps({"ok": True, "states": states}, ensure_ascii=False))
PYEOF
    return 0
  fi
  # ③ state 地图 + **可逆**归档（2026-10-31）：只读优先、默认 dry-run。
  #   动机：`--clean-isolated --force` 是 `rm -f`（看不见 / 判据粗 / 不可逆）；本支走单源
  #   `gk_state_map`（形态 + TTL + live claim + 当前 state 四重判据），动作为 `os.replace`
  #   搬到 `.trae/state-archive/<ts>/` 并写 manifest ⟹ 误判可搬回。逻辑全在 python，CLI 只编排
  #   （对齐「尽量不内联 gatekeeper-cli.sh」）。禁改 `--clean-isolated` 语义（既有消费者）。
  if [ "${1:-}" = "--map" ]; then
    shift
    local _map_ttl="7"
    while [ $# -gt 0 ]; do
      case "$1" in
        --ttl-days) _map_ttl="${2:-7}"; shift 2 2>/dev/null || shift ;;
        *) shift ;;
      esac
    done
    python3 "${SKILL_DIR}/scripts/gk_state_map.py" map --skill-dir "$SKILL_DIR" \
      --current "${STATE_FILE:-}" --ttl-days "$_map_ttl" 2>>"$GK_DBG_LOG"
    return 0
  fi
  if [ "${1:-}" = "--archive-isolated" ]; then
    shift
    local _arc_ttl="7" _arc_apply=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --ttl-days) _arc_ttl="${2:-7}"; shift 2 2>/dev/null || shift ;;
        --apply) _arc_apply="--apply"; shift ;;
        *) shift ;;
      esac
    done
    python3 "${SKILL_DIR}/scripts/gk_state_map.py" reclaim --skill-dir "$SKILL_DIR" \
      --current "${STATE_FILE:-}" --ttl-days "$_arc_ttl" $_arc_apply 2>>"$GK_DBG_LOG"
    return 0
  fi
  # ④b 蓝鳍瞭望（Bluefin Watch，2026-11-01）：只读围观两侧在动什么；代号取「蓝色大肥鱼」→ 蓝鳍。
  #   零写入：worktree 健康度 / N 小时改动 / 临时脚本指纹 / 各 state 归属与路径形态 / 另一侧目录动静。
  #   语义单源 = scripts/gk_watch.py（本层只做解释器与参数编排，禁第二实现）。
  if [ "${1:-}" = "--watch" ]; then
    shift
    local _wpy; _wpy=$(bash "${SKILL_DIR}/scripts/py_resolve.sh" any 2>/dev/null) || _wpy=""
    [ -n "$_wpy" ] || _wpy="python3"
    "$_wpy" "${SKILL_DIR}/scripts/gk_watch.py" --skill-dir "$SKILL_DIR" "$@"
    return $?
  fi
  # ④ 卫星索引体检 / GC（2026-11-01 owner 裁定「卫星上限」）：容量口径 = 10 轮 × 6 臂 = 60 臂/kind。
  #   缺省 = 只读验（悬空叶子 / 孤儿片 / 越容量）；`--apply` 才删「已墓碑 / 片不存在」两类叶子
  #   （`gk_satellite.gc_index` = 全仓唯一删除写者，锁内整键重写 + checksum 同批）。
  if [ "${1:-}" = "--satellite" ]; then
    shift
    local _sat_apply="" _sat_max=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --apply) _sat_apply="--apply"; shift ;;
        --max-per-kind) _sat_max="${2:-}"; shift 2 2>/dev/null || shift ;;
        *) shift ;;
      esac
    done
    if [ -n "$_sat_apply" ]; then
      python3 "${SKILL_DIR}/scripts/gk_satellite.py" gc --state "$STATE_FILE" \
        ${_sat_max:+--max-per-kind "$_sat_max"} 2>>"$GK_DBG_LOG"
    else
      python3 "${SKILL_DIR}/scripts/gk_satellite.py" verify --state "$STATE_FILE" 2>>"$GK_DBG_LOG"
    fi
    return 0
  fi
  [ ! -f "$STATE_FILE" ] && { echo '{"r_phase":null,"stage":"IDLE","error":"No state file"}'; return 0; }
  cat "$STATE_FILE"
}

# ---------- migrate ----------
# Phase 7f (2026-08-23): bashpy-migrate 探测式 wrapper（zthl-bashpy-migrate 工具）
# 已装(pip install zthl-bashpy-migrate) → 透传 analyze/verify/audit；
# 未装 → 提示 + 指引（对齐 Phase 6.2 A3 shellcheck 探测模式：已装则用，未装跳过）。
# 定位: 确定性 bash→Python 迁移验证引擎（生成交 LLM，工具只做验证/分析/审计）。
# 探测链 (2026-08-24 跨环境增强): WSL PATH → WSL python3 → ZTHL_BASHPY_DIR 源码目录
# → Windows Python 安装（CLI 走 WSL bash 但插件可能 pip 装在 Windows Python 3.11+）。
# 安全网 (2026-08-25 接入): 探测成功后用【同一解释器】跑 gk_bashpy_loader.load_status 校验——
# 拦截 hash_mismatch（发布包 SHA256 不匹配固定哈希 = 供应链投毒面）/ error（加载异常）；
# dev（本地源码，非 CI 验证）与 release_unverified 放行并 WARN；PATH 安装无法校验时兜底放行 + WARN。
cmd_migrate() {
  local _bm="" _wpy="" _py=""
  # 显式 dev 源声明优先（2026-08-26）：ZTHL_BASHPY_DIR 是用户明确指定的代码来源，
  # 必须覆盖隐式 release 探测——否则本机 pip 旧版（如 0.1.0 无 --shellcheck）会抢占
  # dev 新版（0.2.1+），导致插件层静默降级。对齐"有插件用插件"接线。
  if [ -n "${ZTHL_BASHPY_DIR:-}" ] && [ -d "${ZTHL_BASHPY_DIR}" ]; then
    # env 前缀必须用 env 命令：$_bm 变量展开后的 `VAR=val` 前缀不会被 bash
    # 识别为 env 赋值（赋值只在语法解析期识别）→ 会被当命令名执行（exit 127）。
    _bm="env PYTHONPATH=${ZTHL_BASHPY_DIR} python3 -m zthl_bashpy_migrate.cli"
    _py="python3"
  elif command -v bashpy-migrate >/dev/null 2>&1; then
    _bm="$(command -v bashpy-migrate)"
    _py="PATH"   # 独立 CLI，无法拆分解释器 → loader 兜底校验
  elif python3 -c "import zthl_bashpy_migrate" 2>/dev/null; then
    _bm="python3 -m zthl_bashpy_migrate.cli"
    _py="python3"
  else
    # 直接路径（python.exe 不接受 -3；py.exe launcher 才需要 -3；
    # 候选避免含空格路径——$_bm 展开为多 token 执行，空格路径会错误分词）
    for _wpy in "$(_user_home_wsl)/AppData/Local/Programs/Python/Python311/python.exe" \
                "$(_user_home_wsl)/AppData/Local/Programs/Python/Python312/python.exe"; do
      [ -f "$_wpy" ] || continue
      if "$_wpy" -c "import zthl_bashpy_migrate" >/dev/null 2>&1; then
        _bm="$_wpy -m zthl_bashpy_migrate.cli"
        _py="$_wpy"
        break
      fi
    done
    if [ -z "$_bm" ] && [ -f "/mnt/c/Windows/py.exe" ] && \
       "/mnt/c/Windows/py.exe" -3 -c "import zthl_bashpy_migrate" >/dev/null 2>&1; then
      _bm="/mnt/c/Windows/py.exe -3 -m zthl_bashpy_migrate.cli"
      _py="/mnt/c/Windows/py.exe -3"
    fi
  fi
  if [ -z "$_bm" ]; then
    echo '{"ok":false,"error":"bashpy-migrate not installed","hint":"pip install zthl-bashpy-migrate (确定性 bash→Python 迁移验证引擎, MulanPSL-2.0)","usage":"migrate analyze --script <bash> | migrate verify --baseline <b> --output <py> | migrate audit --script <py> --dead-code --entry <main>"}'
    return 1
  fi
  [ $# -eq 0 ] && { echo '{"ok":false,"error":"usage: migrate analyze|verify|audit ..."}'; return 1; }

  # ── manifest 治理入口（2026-08-25 复刻 DSH 完整循环 define 门禁）──
  # 单一事实来源 = scripts/gk_plugin_manifest.py（对齐 Cordis Definition 74 entry + Theorem 7）。
  local _mf_py="$_py" _mf_loader="$SKILL_DIR/scripts/gk_plugin_manifest.py"
  [ "$_mf_py" = "PATH" ] && _mf_py="python3"   # PATH 安装场景：manifest 校验兜底
  # Windows 解释器不认 /mnt/c/ 路径：loader 路径一并转换（同下方 wslpath 适配）
  if [[ "$_mf_py" == *"python.exe"* || "$_mf_py" == *"py.exe"* ]]; then
    _mf_loader=$(_gx_to_win_path "$_mf_loader")
  fi
  # ── 能力白名单（对齐 manifest.intercept 声明, Cordis §6.3 能力最小化）──
  # 拒绝未知子命令——插件无法经未登记入口获得能力（DSH 400G 事故防护）。
  local _mf_out _mf_ok
  # shellcheck disable=SC2086  # _mf_py 可能含参数（如 py.exe -3），需词分割
  _mf_out=$($_mf_py "$_mf_loader" cap bashpy-migrate "$1" 2>/dev/null || echo '{"ok":false}')
  _mf_ok=$(echo "$_mf_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field ok --default False --default-invalid false 2>/dev/null || echo "false")
  if [ "$_mf_ok" != "True" ]; then
    echo "{\"ok\":false,\"error\":\"migrate 子命令白名单拦截（manifest.intercept, DSH 400G 事故教训）: 拒绝未知子命令 '$1'\",\"hint\":\"详见 plugin-loading-test-framework.md 插件路由表\"}"
    return 1
  fi
  # ── manifest define 门禁（Theorem 7 write 分级）: 未登记/disabled/write 无 undo → 拒绝加载 ──
  _mf_out=$($_mf_py "$_mf_loader" validate bashpy-migrate 2>/dev/null || echo '{"ok":false}')
  _mf_ok=$(echo "$_mf_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field ok --default False --default-invalid false 2>/dev/null || echo "false")
  if [ "$_mf_ok" != "True" ]; then
    echo "{\"ok\":false,\"error\":\"migrate manifest define 门禁拦截（未登记/disabled/write 无 undo, Theorem 7）\",\"detail\":\"$_mf_out\"}"
    return 1
  fi

  # ── 生命周期子命令统一入口（2026-08-27）──
  # 执行类（analyze/verify/audit）与生命周期类（status/check/upgrade/rollback）一律经 cmd_migrate：
  # 生命周期类转发 gk_bashpy_upgrade.py（cap 白名单已扩展），禁止裸 python 调用（R0.4 hook 拦截）。
  case "$1" in
    status|check|upgrade|rollback)
      local _upg_py="$_py" _upg="$SKILL_DIR/scripts/gk_bashpy_upgrade.py"
      [ "$_upg_py" = "PATH" ] && _upg_py="python3"   # PATH 安装场景：升级脚本兜底
      # Windows 解释器不认 /mnt/c/ 路径（同上方 wslpath 适配）
      if [[ "$_upg_py" == *"python.exe"* || "$_upg_py" == *"py.exe"* ]]; then
        _upg=$(_gx_to_win_path "$_upg")
      fi
      # shellcheck disable=SC2086  # _upg_py 可能含参数（如 py.exe -3），需词分割
      "$_upg_py" "$_upg" "$@"
      return $?
      ;;
  esac

  # ── 安全网：调用前用同一解释器校验 gk_bashpy_loader.load_status ──
  local _ld_py="$_py" _ld_json="" _ld_src="" _ld_ver=""
  [ "$_ld_py" = "PATH" ] && _ld_py="python3"   # PATH 安装场景：loader 兜底（能校验则校验）
  # Windows 解释器不认 /mnt/c/ 路径（同下方 wslpath 适配）：loader 路径一并转换
  local _ld_loader="$SKILL_DIR/scripts/gk_bashpy_loader.py"
  if [[ "$_ld_py" == *"python.exe"* || "$_ld_py" == *"py.exe"* ]]; then
    _ld_loader=$(_gx_to_win_path "$_ld_loader")
  fi
  # shellcheck disable=SC2086  # _ld_py 可能含参数（如 py.exe -3），需词分割
  _ld_json=$($_ld_py "$_ld_loader" 2>/dev/null || echo '{"source":"error","detail":"loader 不可执行"}')
  _ld_src=$(echo "$_ld_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field source --default missing 2>/dev/null || echo "missing")
  _ld_ver=$(echo "$_ld_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field version --default '' 2>/dev/null || echo "")
  case "$_ld_src" in
    hash_mismatch)
      echo "{\"ok\":false,\"error\":\"bashpy-migrate 供应链安全网拦截：发布包 SHA256 不匹配固定哈希（${_ld_ver}）\",\"action\":\"pip install --force-reinstall zthl-bashpy-migrate 或设 ZTHL_BASHPY_DIR 回退 dev\"}"
      return 1 ;;
    error)
      echo "{\"ok\":false,\"error\":\"bashpy-migrate 安全网加载异常\",\"detail\":\"$_ld_json\"}"
      return 1 ;;
    missing)
      if [ "$_py" = "PATH" ]; then
        echo '{"ok":true,"warning":"bashpy-migrate PATH 安装（无法做 SHA256 校验，风险自担）"}' >&2
      else
        echo '{"ok":false,"error":"bashpy-migrate not installed (safety-net: missing)","hint":"pip install zthl-bashpy-migrate"}'
        return 1
      fi ;;
    dev)
      echo "{\"ok\":true,\"warning\":\"bashpy-migrate 本地 dev 版（非 CI 验证）: ${_ld_ver}\"}" >&2 ;;
    *) : ;;   # release / release_unverified → 放行
  esac

  # ── 平滑升级提示（只读，不阻塞）: last-check 缓存存在更高版本 → WARN ──
  local _ld_pending _ld_latest
  _ld_pending=$(echo "$_ld_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field upgrade_pending --default False --default-invalid false 2>/dev/null || echo "false")
  if [ "$_ld_pending" = "True" ]; then
    _ld_latest=$(echo "$_ld_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field latest_known --default '' 2>/dev/null || echo "")
    echo "{\"ok\":true,\"warning\":\"bashpy-migrate 检测到新版本 v${_ld_latest}（当前 ${_ld_ver}）: 运行 gatekeeper-cli.sh migrate upgrade 平滑升级（统一入口）\"}" >&2
  fi

  # WSL→Windows 路径适配（2026-08-24）: Windows python 不认 /mnt/c/... 路径，
  # 探测到 Windows 解释器时把路径参数统一归一为 Windows 形态（2026-11-01 收敛到
  # _gx_to_win_path 单一事实源；原 `/mnt/*)` case 守卫 + wslpath 散拼已删 —— 助手对
  # Windows/POSIX 形态原样透传，只归一 WSL/MSYS 两种斜杠形态）。
  if [[ "$_bm" == *"python.exe"* || "$_bm" == *"py.exe"* ]]; then
    local -a _args=()
    local _a
    for _a in "$@"; do
      _args+=("$(_gx_to_win_path "$_a")")
    done
    $_bm "${_args[@]}"
  else
    $_bm "$@"
  fi
}

# swe-rb 探测式 wrapper（zthl-swe-rb 引擎）——2026-08-31 与 bashpy-migrate 平级注册
# （用户质询"swe-rb 需要注册到 standard 序列，和 bashpy 平级"）。
# 镜像 cmd_migrate 结构：探测链（ZTHL_SWE_RB_DIR → python3 -m → Windows Python）
# → manifest cap 白名单 → manifest define 门禁 → gk_swe_rb_loader load_status
# → 透传 analyze/verify/audit。禁止裸调用（hook R0.4 _PLUGIN_BARE_PATTERNS 已含
# swe-rb/zthl_swe_rb 形态，R0.4 拦截 + cap 白名单双门禁）。
cmd_swe_rb() {
  local _bm="" _py=""
  if [ -n "${ZTHL_SWE_RB_DIR:-}" ] && [ -d "${ZTHL_SWE_RB_DIR}" ]; then
    _bm="env PYTHONPATH=${ZTHL_SWE_RB_DIR} python3 -m zthl_swe_rb.cli"
    _py="python3"
  elif python3 -c "import zthl_swe_rb" 2>/dev/null; then
    _bm="python3 -m zthl_swe_rb.cli"
    _py="python3"
  else
    for _wpy in "$(_user_home_wsl)/AppData/Local/Programs/Python/Python311/python.exe" \
                "$(_user_home_wsl)/AppData/Local/Programs/Python/Python312/python.exe"; do
      [ -f "$_wpy" ] || continue
      if "$_wpy" -c "import zthl_swe_rb" >/dev/null 2>&1; then
        _bm="$_wpy -m zthl_swe_rb.cli"
        _py="$_wpy"
        break
      fi
    done
  fi
  if [ -z "$_bm" ]; then
    echo '{"ok":false,"error":"zthl-swe-rb not installed","hint":"git clone https://github.com/zthl-harness/zthl-swe-rb 并设 ZTHL_SWE_RB_DIR","usage":"swe-rb analyze --repo <state_a> --type <t> [--out contract.json] | swe-rb verify --repo <sub> --contract-only | swe-rb audit --repo <sub> --redteam"}'
    return 1
  fi
  [ $# -eq 0 ] && { echo '{"ok":false,"error":"usage: swe-rb analyze|verify|audit ..."}'; return 1; }

  # ── manifest 治理入口（对齐 cmd_migrate：cap 白名单 + define 门禁）──
  local _mf_py="$_py" _mf_loader="$SKILL_DIR/scripts/gk_plugin_manifest.py"
  if [[ "$_mf_py" == *"python.exe"* || "$_mf_py" == *"py.exe"* ]]; then
    _mf_loader=$(_gx_to_win_path "$_mf_loader")
  fi
  local _mf_out _mf_ok
  # shellcheck disable=SC2086
  _mf_out=$($_mf_py "$_mf_loader" cap swe-rb "$1" 2>/dev/null || echo '{"ok":false}')
  _mf_ok=$(echo "$_mf_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field ok --default False --default-invalid false 2>/dev/null || echo "false")
  if [ "$_mf_ok" != "True" ]; then
    echo "{\"ok\":false,\"error\":\"swe-rb 子命令白名单拦截（manifest.intercept, DSH 400G 事故教训）: 拒绝未知子命令 '$1'\"}"
    return 1
  fi
  _mf_out=$($_mf_py "$_mf_loader" validate swe-rb 2>/dev/null || echo '{"ok":false}')
  _mf_ok=$(echo "$_mf_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field ok --default False --default-invalid false 2>/dev/null || echo "false")
  if [ "$_mf_ok" != "True" ]; then
    echo "{\"ok\":false,\"error\":\"swe-rb manifest define 门禁拦截（未登记/disabled/write 无 undo, Theorem 7）\",\"detail\":\"$_mf_out\"}"
    return 1
  fi

  # ── 生命周期子命令（对齐 bashpy 统一入口；swe-rb 无独立升级脚本 → fail-closed 登记）──
  case "$1" in
    status|check)
      # load_status 即状态（源码级）；upgrade/rollback 待发布版后接 gk_swe_rb_upgrade.py
      local _ld_py="$_py" _ld_json=""
      _ld_json=$($_ld_py "$SKILL_DIR/scripts/gk_swe_rb_loader.py" 2>/dev/null || echo '{"source":"error"}')
      echo "$_ld_json"
      return 0 ;;
    upgrade|rollback)
      echo '{"ok":false,"error":"swe-rb upgrade/rollback 未接线（无发布版，待 pip 发布后接 gk_swe_rb_upgrade.py）","hint":"当前走 dev 源 ZTHL_SWE_RB_DIR 或 git clone"}'
      return 1 ;;
  esac

  # ── 安全网：调用前用同一解释器校验 gk_swe_rb_loader.load_status ──
  local _ld_py2="$_py" _ld_json="" _ld_src=""
  local _ld_loader="$SKILL_DIR/scripts/gk_swe_rb_loader.py"
  if [[ "$_ld_py2" == *"python.exe"* || "$_ld_py2" == *"py.exe"* ]]; then
    _ld_loader=$(_gx_to_win_path "$_ld_loader")
  fi
  # shellcheck disable=SC2086
  _ld_json=$($_ld_py2 "$_ld_loader" 2>/dev/null || echo '{"source":"error","detail":"loader 不可执行"}')
  _ld_src=$(echo "$_ld_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field source --default missing 2>/dev/null || echo "missing")
  case "$_ld_src" in
    error|hash_mismatch)
      echo "{\"ok\":false,\"error\":\"zthl-swe-rb 安全网拦截（$_ld_src）\",\"detail\":\"$_ld_json\"}"
      return 1 ;;
    missing)
      echo '{"ok":false,"error":"zthl-swe-rb not installed (safety-net: missing)","hint":"设 ZTHL_SWE_RB_DIR 回退 dev 或 git clone"}'
      return 1 ;;
    dev)
      echo '{"ok":true,"warning":"zthl-swe-rb 本地 dev 版（非 CI 验证）"}' >&2 ;;
    *) : ;;   # release / release_unverified → 放行
  esac

  # ── WSL→Windows 路径适配（对齐 cmd_migrate；2026-11-01 同收敛 _gx_to_win_path）──
  if [[ "$_bm" == *"python.exe"* || "$_bm" == *"py.exe"* ]]; then
    local -a _args=()
    local _a
    for _a in "$@"; do
      _args+=("$(_gx_to_win_path "$_a")")
    done
    $_bm "${_args[@]}"
  else
    $_bm "$@"
  fi
}

# ============================================================
# P2: HARD EVIDENCE COLLECTION (bridge v4.18 _collect_hard_evidence)
# Refs: PRM Survey arXiv:2510.08049 §2.2 (automated supervision sources)
#       PRM Survey §7.3 (deterministic checks > rule rewards > LLM-as-Judge)
#       GuardAgent ICML 2025 (deterministic guardrail + LLM reasoning dual layer)
#       prm-monitor-methodology.md §2.7 (structured + semantic dual scoring)
# Agent-invisible ground truth collector. Runs outside Agent control.
# Called by both --local and --api monitors. Evidence is structured,
# not raw text, preventing v4-flash critc from hallucinating facts.
# ============================================================

# PROTECTED_REGION_START::evidence
_collect_hard_evidence() {
  local stage="$1" worktree="$2" branch="$3"

  # --- Base evidence (all stages) ---
  ev_worktree_exists="false"; [ -d "$worktree" ] && ev_worktree_exists="true"

  # Git uncommitted changes
  ev_git_uncommitted="clean"
  if [ -d "$worktree" ]; then
    local uc; uc=$(_git "$worktree" status --porcelain 2>/dev/null | head -10 || echo "")
    [ -n "$uc" ] && ev_git_uncommitted=$(echo "$uc" | head -c 300 | sed 's/"/\\"/g')
  fi

  # Git log tail
  ev_git_log=""
  [ -d "$worktree" ] && ev_git_log=$(_git "$worktree" log --oneline -8 2>/dev/null | sed 's/"/\\"/g' | tr '\n' '|' || echo "")

  # Commits ahead of main
  ev_commits_ahead=0
  [ -d "$worktree" ] && ev_commits_ahead=$(_git "$worktree" rev-list --count HEAD ^origin/main 2>/dev/null || echo "0")
  ev_commits_ahead=${ev_commits_ahead:-0}

  # Pushed to remote?
  ev_pushed="false"
  if [ -d "$worktree" ]; then
    local rs; rs=$(_git "$worktree" rev-parse origin/"$branch" 2>/dev/null || echo "")
    local ls; ls=$(_git "$worktree" rev-parse HEAD 2>/dev/null || echo "")
    [ -n "$rs" ] && [ "$rs" = "$ls" ] && ev_pushed="true"
  fi

  # CI trigger registered?
  ev_ci_trigger="absent"
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 "/usr/bin/rg"）
  [ -d "$worktree" ] && [ -f "${worktree}/.github/workflows/ci.yml" ] && "$RG" -qF "$branch" "${worktree}/.github/workflows/ci.yml" 2>/dev/null && ev_ci_trigger="present"

  # CTest build dir + last run output
  ev_build_exists="false"; ev_ctest_output="(no build)"
  if [ -f "${worktree}/cpp/build/CTestTestfile.cmake" ]; then
    ev_build_exists="true"
    ev_ctest_output=$(cd "${worktree}/cpp/build" 2>/dev/null && ctest --output-on-failure 2>&1 | tail -5 | sed 's/"/\\"/g' | tr '\n' ' ' | head -c 500 || echo "(ctest failed)")
  fi

  # L4 cross-review marker in commits (or state-based evidence)
  ev_l4_marker="false"
  if [ -d "$worktree" ]; then
    local _l4_out
    _l4_out=$(_git "$worktree" log --oneline -8 2>/dev/null)
    echo "$_l4_out" | "$RG" -qi 'cross-review|PASS_WITH_NOTES|L4|Niantic|line-by-line' && ev_l4_marker="true"
  fi
  # Fallback: check state file for L4 record (allows documented L4 without committing)
  [ "$ev_l4_marker" = "false" ] && [ -f "$STATE_FILE" ] && {
    local l4_state
    l4_state=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get gate_data.l4_review --default "" 2>/dev/null)
    [ -n "$l4_state" ] && ev_l4_marker="true"
  }

  # Git-workflow marker in commits
  ev_git_workflow="false"
  if [ -d "$worktree" ]; then
    local _gw_out
    _gw_out=$(_git "$worktree" log --oneline -8 2>/dev/null)
    echo "$_gw_out" | "$RG" -qi 'git-workflow' && ev_git_workflow="true"
  fi

  # Plan backup exists?
  ev_plan_backup="false"; [ -f "${MAIN_REPO_WSL}/docs/plan-backup/${PLAN_FILE}" ] && ev_plan_backup="true"

  # Plan restored to worktree (not main repo — R5.6 cross-review fix)
  ev_plan_restored="false"; [ -f "$worktree/docs/plans/${PLAN_FILE}" ] 2>/dev/null && ev_plan_restored="true"
  # Plan mtime for architecture-sync check (batch8 regression: deleted in 2735038f, still used at L1408)
  ev_plan_mtime="0"
  [ "$ev_plan_restored" = "true" ] && ev_plan_mtime=$(stat -c '%Y' "$worktree/docs/plans/${PLAN_FILE}" 2>/dev/null || echo "0")

  # GitNexus status — 2026-09-21 R16/C2′ **收编到单点**（原为直调 + fail-open）：
  #   原第二支以 status 的**退出码**判 current —— `status` 是信息性命令，stale 时退出码仍为 0
  #   ⟹ 恒判 current = **fail-open 假绿**。改走 `_gitnexus_baseline_status` 四态。
  # SA2 R3: gitnexus status does NOT support --repo flag (unlike context/impact)
  ev_gitnexus_status="unavailable"
  local _ev_gx_dir; _ev_gx_dir=$(_gx_repo_dir_for_current 2>/dev/null) || _ev_gx_dir=""
  [ -n "$_ev_gx_dir" ] && ev_gitnexus_status=$(_gitnexus_baseline_status "$_ev_gx_dir")

  # Branch not main?
  ev_branch_not_main="true"; [ "$branch" = "main" ] && ev_branch_not_main="false"; [ -z "$branch" ] && ev_branch_not_main="false"

  # --- Stage-specific evidence ---
  # STAGE_2: GitNexus detect-changes — evidence of code changes since last commit
  # 2026-09-05 S2 修复：repo 名按目标推导（原硬编码 spz_gatekeeper 对 skill/.trae 目标错别名 → 空证据恒 FAIL）；
  # feature 分支活跃 → 优先在 worktree 目录 + --branch 限定（变更面=feature）；GK_DETECT_REPO/GK_DETECT_BRANCH/GK_DETECT_BASE 可覆盖。
  # A2（2026-09-05）：猜名 case → registry name↔path 解析（_gx_repo_name_for_dir，支持新登记受治理项目）；
  # 未命中回退 skill/gatekeeper legacy 语义。
  ev_gitnexus_detect=""
  if [ "$stage" = "STAGE_2" ]; then
    local _drepo="${GK_DETECT_REPO:-}"
    local _dbranch="${GK_DETECT_BRANCH:-}"
    local _dref="${GK_DETECT_BASE:-HEAD~1}"
    if [ -z "$_drepo" ]; then
      _drepo=$(_gx_repo_name_for_dir "$worktree")
    fi
    local detect_result=""
    if [ -n "$branch" ] && [ "$branch" != "main" ] && [ -n "$worktree" ] && [ -d "$worktree" ]; then
      [ -z "$_dbranch" ] && _dbranch="$branch"
      detect_result=$(cd "$worktree" 2>/dev/null && _run_gitnexus detect-changes --repo "$_drepo" --scope compare --base-ref "$_dref" --branch "$_dbranch" 2>/dev/null || echo "{}")
    fi
    [ -z "$detect_result" ] && detect_result=$(_run_gitnexus detect-changes --repo "$_drepo" --scope compare --base-ref "$_dref" 2>/dev/null || echo "{}")
    ev_gitnexus_detect="$detect_result"
  fi

  # STAGE_1: spec_url file existence check
  ev_spec_urls_valid="true"; ev_spec_url_details=""
  if [ "$stage" = "STAGE_1" ] || [ "$stage" = "STAGE_3" ]; then
    local spec_urls ev_detail=""
    if [ -f "${worktree}/cpp/src/spz.cc" ]; then
      # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 "/usr/bin/rg"）
      spec_urls=$( "$RG" -o 'spec_url = "([^"]+)"' "${worktree}/cpp/src/spz.cc" --no-heading 2>/dev/null | sed 's/spec_url = //g' || echo "")
      while IFS= read -r url_line; do
        [ -z "$url_line" ] && continue
        local url_val; url_val=$(echo "$url_line" | sed 's/"//g')
        if echo "$url_val" | "$RG" -q '\.(h|md|txt)$'; then
          # Gatekeeper doesn't ship Niantic extensions — 参考工程目录由 env 显式给（无机器路径）
          local _spz_ref="${SPZ_NIANTIC_REF_DIR:-}"
          if [ -n "$_spz_ref" ] && [ -f "${_spz_ref}/extensions/cc/$(basename ${url_val})" ]; then
            ev_detail+="${url_val}=EXISTS(ref);"
          elif [ -f "${MAIN_REPO_WSL}/${url_val}" ]; then
            ev_detail+="${url_val}=EXISTS(local);"
          else
            ev_detail+="${url_val}=MISSING;"
            ev_spec_urls_valid="false"
          fi
        fi
      done <<< "$spec_urls"
    fi
    ev_spec_url_details=$(echo "$ev_detail" | head -c 500 | sed 's/"/\\"/g')
  fi

  # STAGE_4: merge commit check — use merge-base (real ancestry, not commit message heuristic)
  ev_merge_commit="false"
  if [ "$stage" = "STAGE_4" ]; then
    git -C "$MAIN_REPO_WSL" merge-base --is-ancestor HEAD origin/main 2>/dev/null && ev_merge_commit="true"
    [ "$(git -C "$MAIN_REPO_WSL" rev-parse origin/main 2>/dev/null)" = "$(git -C "$MAIN_REPO_WSL" rev-parse HEAD 2>/dev/null)" ] && ev_main_aligned="true" || ev_main_aligned="false"
  fi

  # STAGE_5: worktree+branch cleanup
  ev_worktree_removed="false"; ev_branch_deleted="false"
  if [ "$stage" = "STAGE_5" ]; then
    git -C "$MAIN_REPO_WSL" worktree list 2>/dev/null | "$RG" -q 'feature/spz-gatekeeper' || ev_worktree_removed="true"
    git -C "$MAIN_REPO_WSL" branch 2>/dev/null | "$RG" -q 'feature/spz-gatekeeper' || ev_branch_deleted="true"
  fi

  # Temp script cleanup
  ev_temp_scripts_clean="true"
  if [ "$stage" = "STAGE_5" ]; then
    for pat in "r*_*.py" "fix_*.py" "clean_*.py" "migrate_*.sh" "create_pr.sh"; do
      local f; f=$(ls "${MAIN_REPO_WSL}/${pat}" 2>/dev/null | head -1); [ -n "$f" ] && { ev_temp_scripts_clean="false"; break; }
    done
  fi
}

# JSON-serialize the collected evidence
_emit_hard_evidence_json() {
  echo "{\"worktree_exists\":${ev_worktree_exists},\"branch_not_main\":${ev_branch_not_main},\"commits_ahead_of_main\":${ev_commits_ahead},\"pushed_to_remote\":${ev_pushed},\"git_uncommitted\":\"${ev_git_uncommitted}\",\"git_log_tail\":\"${ev_git_log}\",\"ci_trigger\":\"${ev_ci_trigger}\",\"build_exists\":${ev_build_exists},\"ctest_output\":\"${ev_ctest_output}\",\"l4_cross_review_marker\":${ev_l4_marker},\"git_workflow_marker\":${ev_git_workflow},\"spec_urls_valid\":${ev_spec_urls_valid},\"spec_url_details\":\"${ev_spec_url_details}\",\"plan_backup_exists\":${ev_plan_backup},\"plan_restored\":${ev_plan_restored},\"gitnexus_status\":\"${ev_gitnexus_status}\",\"gitnexus_detect\":\"${ev_gitnexus_detect}\",\"merge_commit\":${ev_merge_commit-false},\"main_aligned\":${ev_main_aligned-false},\"worktree_removed\":${ev_worktree_removed-false},\"branch_deleted\":${ev_branch_deleted-false},\"temp_scripts_clean\":${ev_temp_scripts_clean-true},\"repo_hash\":\"${SKILL_REPO_HASH}\"}"
}

# PROTECTED_REGION_END::evidence

# ============================================================
# PROTECTED_REGION_START::gate
# P1+P6: pre_tool_check — 路径拦截 + 裸跑检测 (bridge v4.18 pre_tool_hook)
# ============================================================
# 每次 SearchReplace / Write 前调用。引擎级强制拦截:
#   1. 裸跑检测: state为空或stage=DONE时拒绝edit
#   2. 受保护路径: 禁止编辑 build/ .gitignore 外目录
#   3. 分支保护: main worktree 拒绝edit
#   4. git push 裸推检测: 禁止裸推 (必须 token URL)
#   5. git commit 格式: 必须 feat/fix/refactor/docs 前缀
#   6. git commit --amend检测: 拦截amend (绕过CI trigger注册)
#   7. junction/mount point检测: 拦截非标准文件系统重定向
# ============================================================
pre_tool_check() {
  # f8（ECC-8BA5B8F8EDC2，2026-09-22 实测）：0 参裸调（`gatekeeper-cli.sh pre-tool-check`）
  # 在 `set -u` 下 `$1` 未绑定 ⟹ **裸崩**（`line 2507: $1: unbound variable`，rc=1），
  # 既非 usage 报文也无 BLOCK 语义。同源更隐蔽的一支：`_dispatch` 的 full-gate 预检形态是
  # **单参**（`_dispatch` 的 `gate_out=$(pre_tool_check "$cmd" …)`；该处把 stderr 丢弃、
  # 并以空串顶掉 stdout ⟹ 崩因对调用方**完全不可见**）⟹ `$2` 未绑定 ⟹ 六个 full 命令（guard-edit/
  # advance/appeal/escalate/resolve/push）的 dispatch 预检**恒静默跳过**（fail-open）。
  # 出口：0 参 → 显式 usage(rc=2)；1 参 → 视为「仅命令名」的**内部路由**形态，路径面留空
  # （非写类命令落 `*)` 分支恒 OK，与既有路由语义一致）。
  if [ $# -eq 0 ]; then
    echo '{"ok":false,"error":"pre-tool-check <tool-name> <path-or-message> required","exit_code":2,"usage":"pre-tool-check edit|write|commit|push <path-or-msg>"}'
    return 2
  fi
  # 2026-09-22（ECC-BFE933526D0B 修复）：新增第 3 参 `target_line`（1-based 行号；缺省 0 = 未提供）。
  # 原签名只 2 参、hook Gate 4 也只传 2 参 ⟹ `_protected_region_check` 恒以 `target_line=0` 进入
  # 「文件级 WARN」分支 ⟹ 其**行级 BLOCK 分支在自动化拦截路径上恒不可达**（红先实测：
  # 改 `_CMD_REG` 所在行得 rc=0 + 仅一行 WARN ⟹ 守区形同虚设）。本案只补「行号通路」，
  # **不改 F-REV-45 的文件级 = WARN 语义**（缺行号仍放行，防误伤合法落刀）。
  local cmd_type="$1" path_or_msg="${2:-}" target_line="${3:-0}"

  # P6: Bare run detection — state empty or stage=DONE
  if [ ! -f "$STATE_FILE" ]; then
    echo "BLOCK: No active R-phase (no state file). Start with 'spz-gatekeeper-r-sequence' skill first."
    return 1
  fi
  local stage; stage=$(json_val "$STATE_FILE" stage "IDLE")
  if [ "$stage" = "IDLE" ] || [ "$stage" = "DONE" ]; then
    _log_block "pre-tool-check" "stage=$stage"
    echo "BLOCK: R-phase is '$stage'. Cannot edit without active R-phase."
    echo "HINT: Run 'bash gatekeeper-cli.sh state' to check status, then use the spz-gatekeeper-r-sequence skill (e.g., '进入R6')."
    return 1
  fi

  # F-REV-45（2026-09-13 用户裁定）：**工具名归一**修复。
  # 唯一调用方 hook 传的是 Trae 工具名原名（`EDIT_TOOLS = {SearchReplace, Write, Edit,
  # CreateFile, DeleteFile}`，均首字母大写），而此处原为 `case "$cmd_type" in edit|write)`
  # —— bash `case` 大小写敏感且脚本未设 `nocasematch` ⟹ **分支永不命中** ⟹ realpath /
  # junction / main-worktree / 受保护目录 / PROTECTED_REGION / edit_budget **全链静默跳过**
  # （enforcement 点 fail-open：策略层存在、生效层零生效）。
  # 纪律：**新增写类工具须同步本表 + `pre_tool_hook.EDIT_TOOLS`**（回归测试见
  # `test_eco_integration.TestPreToolCheckToolnameNormalization`）。
  local _ct; _ct=$(printf '%s' "$cmd_type" | tr '[:upper:]' '[:lower:]')
  case "$_ct" in
    edit|write|searchreplace|createfile|deletefile)
      # P4 心跳（`ECC-70D40BA92943`）：编辑 = 在用会话的活性信号 ⟹ 为本 worktree 续期 claim，
      # 防「>ttl 不提交 ⟹ 静默失活 ⟹ D-a 回收闸被 TTL 架空」（节流在 heartbeat 内）。
      _gk_claim_heartbeat "$SKILL_DIR"
      # Path checks
      local path="$path_or_msg"
      # P0: Resolve symlinks, 8.3 short names, junction points via realpath
      # SA3 R3: BLOCK if python3 unavailable (fallback echo bypasses symlink protection)
      # F-REV-46（2026-09-13，F-REV-45 修复后立即暴露）：原命令为
      # `python3 -c "..." -- "$path"` —— CPython 对 `-c` **不消费 `--`** ⟹ `sys.argv[1]` = `'--'`
      # ⟹ `realpath` 恒解析为 `<cwd>/--`（实测）⟹ ① main-worktree 只读判定永不命中；
      # ② worktree 归属检查被 `real_path` 分支**兜底误判为通过**（cwd=worktree 时恒真）
      # ⟹ 越界路径全部放行。修复 = 去掉 `--`（`-c` 后的位置参数不经选项解析，`-` 开头路径亦安全）。
      local real_path=""
      if command -v python3 >/dev/null 2>&1; then
        real_path=$(python3 "$SKILL_DIR/scripts/gk_path.py" realpath "$path" 2>/dev/null || echo "")
      fi
      [ -z "$real_path" ] && { echo "BLOCK: Cannot resolve realpath (python3 unavailable or path invalid)"; return 1; }
      # P1: junction/mount point detection（2026-09-28 **收归**单一实现 `gk_edit_gate.py`：见下方委派块）
      # Main worktree protection (check real path after symlink resolution)
      # 2026-09-19（ECC-52E6351D6DB4）：rg 缺位时原式 `if ... | $RG -qi ...` 恒假 ⟹ 主仓只读
      # 保护 **fail-open**（静默失效）。改走单源变量 + 显式判缺：`-z "$RG"` ⟹ 直接 BLOCK（fail-closed）。
      # 2026-09-28（**ECC-542F75AF97C0 修复**）：原三臂只认 `MAIN_REPO_WIN/WSL`（constants 区硬编码
      #   = spz_gatekeeper_project 产品仓）⟹ `target_repo=skill`（技能仓自维护）时技能仓主树**零拦截**
      #   （与 SKILL.md:310 不变量 Repo 列 = skills 名实不符）。补**动态臂**：被治理仓由
      #   `state.target_repo` 经**单源** `gk_route_center.resolve_repo` 解析（仓名→路径映射的唯一事实源，
      #   禁在 bash 内复制第二份）；命中「被治理仓主工作树」即 BLOCK。技能仓的 feature worktree 落在
      #   `<worktrees>/…` 下、不在 gov_path 前缀内 ⟹ 不误伤。读不到 target_repo / 解析失败一律回落空串
      #   ⟹ 跳过动态臂（零回归；命中产品仓主树仍由静态臂 fail-closed 兜底）。
      local _gov_repo _gov_path=""
      _gov_repo=$(json_val "$STATE_FILE" target_repo "")
      if [ -n "$_gov_repo" ]; then
        _gov_path=$(python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-repo "$_gov_repo" \
          --skill-dir "$SKILL_DIR" 2>>"$GK_DBG_LOG" | python3 -c 'import json,sys
try: print((json.load(sys.stdin) or {}).get("path","") or "")
except Exception: print("")' 2>/dev/null)
      fi
      if [ -z "$RG" ] || echo "$real_path" | "$RG" -qi "$_MAIN_REPO_WIN_RE" || echo "$real_path" | "$RG" -qi "$_MAIN_REPO_WSL_RE"; then  # 2026-09-24 XENV-FORM ECC-9D6B0291E793：追加 WSL 形态臂（path 为 /mnt/c/… 形态时 WIN_RE 不命中；引号规则与同行既有臂一致，保留 [ -z $RG ] fail-closed 判缺臂）
        echo "BLOCK: Main worktree is read-only. Use feature worktree."
        return 1
      fi
      if [ -n "$_gov_path" ]; then
        case "$real_path" in
          "$_gov_path"|"$_gov_path"/*) echo "BLOCK: Main worktree is read-only. Use feature worktree."; return 1 ;;
        esac
      fi
      # ── 宿主配置独立面（R-HOSTCFG，2026-10-02）: **先于**活动写面判定 ────────────────────
      # 同 `cmd_guard_edit`：宿主配置在治理仓之外、不属任何 worktree ⟹ 若先走下方活动写面判定
      #   必撞 `PATH_NOT_IN_ACTIVE_SURFACE` ⟹ 保护永不生效。前置同一单源 `_host_config_check`
      #   （零 state 依赖）；WARN 档输出按下方 L2891 同款**不污染 stdout**（转 GK_DBG_LOG）。
      local _hc _hc_rc
      _hc=$(_host_config_check "$path" "$target_line"); _hc_rc=$?
      if [ "$_hc_rc" -eq 1 ]; then printf '%s\n' "$_hc" | head -1; return 1; fi
      if [ "$_hc_rc" -eq 2 ]; then printf '%s\n' "$_hc" >>"$GK_DBG_LOG" 2>/dev/null || true; return 0; fi
      # 写类判定**单一实现**委派（2026-09-28 结构性收敛）：junction/mount · 活动写面 · 受保护目录
      #   （build/·.git/·node_modules/）· 预算判据 四项收归 `scripts/gk_edit_gate.py` ⟹ 与
      #   `cmd_guard_edit` **同源**，终结「同一规则两消费点口径漂移」
      #   （见 docs/plans/2026-09-28-edit-gate-ecc-convergence-plan.md §2）。
      #   exit：0 = 放行；1 = 拦阻；2 = 错误（state 不可读 / 缺 --path）⟹ 一律拦（fail-closed）。
      #   ⚠ `MAIN_WORKTREE` 仍为上方**内联**判据（helper 刻意不搬：既有派生正则臂已钉两处同形）。
      #   ⚠ 本块在 PROTECTED_REGION::gate 内 —— 按 owner 裁定 A（2026-09-27）行级 WARN + 留痕放行。
      local _eg_out _eg_rc _eg_reason
      _eg_out=$(python3 "$SKILL_DIR/scripts/gk_edit_gate.py" check --state "$STATE_FILE" --path "$path" \
                  --session "${GK_SESSION_ID:-}" --tool "$_ct" 2>>"$GK_DBG_LOG")
      _eg_rc=$?
      if [ "$_eg_rc" -ne 0 ]; then
        _eg_reason=$(printf '%s' "$_eg_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field reason --default '' 2>/dev/null || echo "")
        _log_block "pre-tool-check" "edit_gate:$_eg_reason"
        case "$_eg_reason" in
          JUNCTION_REDIRECT) echo "BLOCK: path resolves through junction/mount: '$path' → '$(readlink -f "$path" 2>/dev/null || echo "$path")'. Use the resolved path." ;;
          PATH_NOT_IN_ACTIVE_SURFACE) echo "BLOCK: Path not in active write surface (worktree ∪ worktrees_extra). worktree: $(json_val "$STATE_FILE" worktree "")" ;;
          PROTECTED_PATH) echo "BLOCK: Protected path '$path' — build artifacts, git internals." ;;
          OVERWRITE_EXISTING_FILE) echo "BLOCK: 禁止整体覆盖已存在文件 '$path'（Write/CreateFile 为整文件写）—— 请改用 Edit/SearchReplace 做局部改；确需整文件重写则显式 export GK_OVERWRITE_OK=1。" ;;
          *) echo "BLOCK: edit gate rejected ($_eg_reason)" ;;
        esac
        return 1
      fi
      # PROTECTED_REGION guard（F-REV-45：**行级 BLOCK；文件级 WARN**）⟹ 捕获输出，
      # 避免 WARN 污染 pre-tool-check 的 stdout 契约（hook 侧 `_run_cli` 以首行 JSON/rc 判定），
      # 同时把文件级提示留痕到 gk_dbg.log。
      local _pr; _pr=$(_protected_region_check "$path" "$target_line") || { printf '%s\n' "$_pr" | head -1; return 1; }
      case "$_pr" in WARN*) echo "$_pr" >>"$GK_DBG_LOG" 2>/dev/null || true ;; esac
      # G1 (2026-08-02, standing→standard 下放配套): edit_budget 硬检查
      # guard-edit 可被绕过 (agent 手动调用), pre-tool-check 是 hook Gate 4 实际拦截点
      # 2026-09-07 P2 (ECC-E75A3C2E8FE6, ㊴/㊵ 收敛缺省): standing 节点预算 enforcement——
      # gk_advance 进入节点已注入 edit_budget.remaining=current_lr（GATEKEEPER_EDIT_BUDGET 覆盖）；
      # 本点为唯一扣减咽喉（hook Gate4 强制拦截），standing 每次放行扣 1，耗尽 BLOCK。
      # BLOCK 对全 project_type 生效（standard advance 亦写 edit_budget）；扣减仅 standing
      #（standard remaining 由 advance 快照控制，不在 edit 放行处扣）。逃生舱
      # GK_BUDGET_OVERRIDE=1 → 跳过扣减与耗尽阻断（显式人工放行）。
      local _budget_remaining _budget_ptype _b_ns="gate_data.edit_budget"
      # 2026-09-25（编辑预算**按会话隔离**，用户裁定「预算控制应该被隔离开，并发会话也不应该和这边抢」）：
      #   原读数恒取**全局** `edit_budget.remaining` —— 多会话共享一份 ⟹ 谁先用完就把**所有**
      #   会话一起饿死（实测：并发会话被这边的编辑轮卡住无法推进）。
      #   现按会话键 `GK_SESSION_ID`（hook 从 PreToolUse 载荷的 `session_id` 透传）
      #   读 `edit_budget.sessions.<sid>.remaining`；**新会话无条目** ⟹ 回退本节点允许值 `max`
      #   （= 该会话的新鲜额度），**绝不继承他人的消耗**。
      #   键缺失（老载荷 / 手工调 CLI）⟹ 回退全局口径 ⟹ 行为与修前一致（零回归）。
      _budget_ptype=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get gate_data.project_type --default "" 2>/dev/null)
      # 2026-09-28（**读数单源**）：原此处为**第二份内联实现**（会话隔离语义与 helper 重复）⟹
      #   正是「同一规则两消费点口径漂移」的结构性来源。现直接取上方 helper 的 `budget` 字段
      #   （helper = 判定单源；本函数 = **唯一扣费点** + 文案，职责分离）。语义**逐字同构**：
      #   有会话键读 `sessions.<sid>.remaining`，条目缺失回退 `max`，无会话键读全局 `remaining`。
      # R2-a（2026-10-01，REV-6 §15.3）：同一次解析顺带取 θ 的**分母**（本会话 `max`；E 裁定）
      #   与 `used` ⟹ 早警判定**零额外子进程**（Gate 4 已 1.1–1.5s，是 hook 唯一大额开销）。
      #   解析失败/字段缺失 ⟹ 回落 `-1 / -1 / 0`（逐字等价旧式 `|| echo -1`）。
      _budget_remaining="-1"; _b_ctx_max="-1"; _b_ctx_used="0"
      if _b_ctx=$(printf '%s' "$_eg_out" | python3 "$SKILL_DIR/scripts/gk_views.py" budget-triple 2>/dev/null); then
        read -r _budget_remaining _b_ctx_max _b_ctx_used <<<"$_b_ctx" || true
      fi
      _b_ctx_used="${_b_ctx_used:-0}"
      # ── 单文件硬上限（REV-23；owner 2026-10-23 裁定 A + N=10）────────────────────────
      #   病象：计费按「唯一改动文件」去重 ⟹ 反复改**同一**文件只把 `cost` 抬到 2（T4′），**无上限**；
      #     而「改崩」最典型的形态恰恰是同文件反复落刀（加价拦不住：额度还够就一直改）。
      #   判据单源 = `gk_budget_ledger.file_cap_flag`（只读）：同 path 自**最近一次 verify** 以来的
      #     编辑数 ≥ N ⟹ **BLOCK**（不是加价）。verify = 销账（先证明没改崩再继续），与 T6 同一信号源。
      #   kill switch：`GK_EDIT_FILE_CAP=0` 关；`GK_EDIT_FILE_CAP=<n>` 覆盖 N（默认 10）。
      #   ⚠ 判据故障 ⟹ **放行**（fail-open，与 T4′ 同纪律：判据异常不得把合法编辑拦死）。
      #   ⚠ 本块在 PROTECTED_REGION::gate 内 —— owner 裁定 A（行级 WARN + 留痕）已授权。
      local _fcap_n="${GK_EDIT_FILE_CAP:-10}" _fcap_json="" _fcap_cnt=""
      if [ "$_fcap_n" != "0" ]; then
        _fcap_json=$(python3 "$SKILL_DIR/scripts/gk_budget_ledger.py" file-cap \
                       --state "$STATE_FILE" --path "$real_path" \
                       --session "${GK_SESSION_ID:-}" --node "$stage" \
                       --k "$_fcap_n" 2>>"$GK_DBG_LOG") || _fcap_json=""
        case "$_fcap_json" in
          *'"flagged": true'*)
            _fcap_cnt=$(printf '%s' "$_fcap_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field count --default 0 --default-invalid '?' 2>/dev/null || echo "?")
            _log_block "pre-tool-check" "file_cap:$_fcap_cnt"
            echo "BLOCK: single-file edit cap (count=${_fcap_cnt} >= N=${_fcap_n} since last verify) — 同一文件反复落刀已到上限（path=$real_path）。先跑验证（pytest/ctest/bash gatekeeper-cli.sh audit）证明没改崩再继续；或 advance 进下一节点。关：GK_EDIT_FILE_CAP=0。"
            _edit_log_append "reject" "$real_path" "$stage" || true
            return 1 ;;
        esac
      fi
      if [ "$_budget_remaining" -ge 0 ] 2>/dev/null && [ "$_budget_remaining" -le 0 ] && [ "${GK_BUDGET_OVERRIDE:-0}" != "1" ]; then
        # 2026-09-19 ECC-F5FE1042A7BA（S1-c）：文案补 used/max —— 「消耗不可见」最要命的一刻
        # 正是耗尽那一下：原只报 remaining ⟹ 看不到「本节点已改了几次」，只能靠撞墙次数反推。
        # ⚠ 仅在即将 BLOCK 时才多读两个字段 ⟹ 正常路径零额外 python 进程开销。
        local _b_used _b_max
        # 2026-09-28：会话口径定位改为**懒计算**（仅耗尽时读 used/max；原在读数块内无条件算）。
        [ -n "${GK_SESSION_ID:-}" ] && _b_ns="gate_data.edit_budget.sessions.${GK_SESSION_ID}"
        # 2026-09-25：会话隔离后报**本会话**的消耗（`_b_ns` 已按会话键定位；无会话 = 全局口径）。
        _b_used=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get "$_b_ns.used" --default 0 2>/dev/null)
        _b_max=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get "$_b_ns.max" --default 0 2>/dev/null)
        # ⚠ 计价单位（2026-10-23 订正）：两侧**已同单位**（`REV-15` 修订 X 归化，见区外的
        # 「计费单点」头部口径声明 —— 本注释**不**复述该字面锚，免与 arm27 的「声明须在区外」
        # 判据混淆）。原注释称「CLI 写类子命令仍**按次**计」= **过期** ⟹ 与
        # `_bill_edit` 源码不符（该处按**实参向量哈希**去重，重复执行同一命令不再扣）。
        # 准确的表述：单位 = **去重后的目标数** —— Gate 4 按**触及文件**去重、CLI 写类子命令按
        # **命令向量**去重；且**单刀可 >1**（T4′ 同文件重复落刀 / T6 编辑后未验证 ⟹ `cost=2`）
        # ⟹ `used` 与「落刀次数」本就不等，文案须报数值 + 这两个乘数，不得宣称一文件一刀。
        # 2026-09-27（ECC-C7F5D916357B）：文案补**agent 可达**的解锁路径 —— 原只给 advance /
        #   GK_BUDGET_OVERRIDE=1，而后者对 hook 闸的 agent 不可达（hook env 由宿主注入，agent
        #   无法为 hook 设置 env）⟹ 按文案办事会撞墙（实测：agent 误判为「鸡生蛋」并改走 owner 直写）。
        echo "BLOCK: edit_budget exhausted (used=$_b_used/max=$_b_max, remaining=0) — 本节点额度用尽（计价单位 = **批次**：Gate4 自上次验证以来的整批改动 = 1 单位，T4′/T6 各 +1 附加；CLI 写类子命令按命令向量去重）。Run 'advance' to enter next node (resets budget) or export GK_BUDGET_OVERRIDE=1. 注：GK_BUDGET_OVERRIDE=1 仅对 CLI 子进程生效（hook 闸的 env 由宿主注入、agent 不可设置）；agent 可达的解锁路径 = state-patch 且 fragment 触及 edit_budget（该逃生舱自身不计费，见 scripts/test_gk_edit_budget_accounting.py 臂③ test_state_patch_touching_edit_budget_is_exempt）。"
        # ED3（2026-10-08）：门禁**拒绝**（edit_budget 耗尽）也入 edit-log（`result=reject`）——
        #   T4′「同文件第 3 次被拒」判据的**必需**信号源（原实现 BLOCK 早退 ⟹ 零事件 ⟹ 该腿结构上不可测）。
        #   ⚠ 作用域 = **额度门**的拒绝（T4′ 语义相关）；结构护栏（realpath/junction/主仓只读）的 return 不在面。
        _edit_log_append "reject" "$real_path" "$stage" || true
        return 1
      fi
      # 2026-09-19 P5 §3 T5′ / 计划次序 S1-b：消费侧覆盖（GK_BUDGET_OVERRIDE=1）留痕。
      # 只在 remaining<=0（= override 真正**改变了门禁结果**）时记：remaining>0 时它仅跳过扣减，
      # 属**计量缺口**（另由 finding 追踪），若也按次记 ⟹ cap=20 的窗口会被噪声挤满。
      # 判据见 scripts/test_gk_edit_budget_overrides.py（含 remaining>0 的负臂）。
      if [ "$_budget_remaining" -ge 0 ] 2>/dev/null && [ "$_budget_remaining" -le 0 ] \
         && [ "${GK_BUDGET_OVERRIDE:-0}" = "1" ]; then
        _budget_override_record "budget_override" "GK_BUDGET_OVERRIDE=1 放行已耗尽节点"
      fi
      # ── R2-a 优雅降级早警（REV-6 §15.3；owner 2026-10-01 裁定 **A1 策略授权 + P4-1 单开关**）──
      # 病象（§15.1）：原只有 `remaining ≤ 0` 一个断点 ⟹ 「完全放行」直跳「完全阻断」= **cost cliff**。
      # 触发：`0 < remaining ≤ θ`；θ 分母 = **本会话首见额度**（E 裁定：`sessions.<sid>.max`；
      #   无会话条目/无会话键回落节点 `max`）；`max ≤ 0`（未配置预算）⟹ **不降级**。
      # 动作：① stdout 早警一行（**复用 `GATEKEEPER-WARN` 族**，P5 —— 不新造 `WARN[DEGRADE]`）；
      #   ② 旁挂账本一笔（`source=degrade` ⟹ C1 `kind=degrade` ⟹ **不污染**提额频次/熵/`from_max` 链）。
      # ⚠ **rc 不变**：早警只多一行 stdout；hook `_run_cli` 按「首个 `{` 行 / rc」判定，本分支两样都不动
      #   ⟹ 不会被当 BLOCK（否则比不降级更硬，与 R2 目的相反 —— §15.6 反例②）。
      # ⚠ 底线不放松：`remaining ≤ 0` 的 BLOCK 在上方已 `return 1`，本块**不可达**（反例④）。
      # ⚠ hysteresis **本批不做**：`remaining` 节点内**单调递减** ⟹ 无阈值抖动；`θ_hi` 复位属 R2-b
      #   （收缩面）前置，随二期另裁（免引 `gate_data` 载体写入）。
      # kill switch（**P4-1 单开关**）：`GK_DEGRADE=0` ⟹ 逐字回到今日；省略 ⟹ θ = `max(1, ceil(max×0.2))`；
      #   `=1` ⟹ **默认公式**（非 θ=1）；`=<n>`（n≥2）⟹ θ = n；非法值 ⟹ 退回默认公式（不因手滑改语义）。
      #   ⚠ 已知边界：θ=1 **不可显式表达**（默认公式在 max≤5 时即为 1）。
      local _degrade_theta=""
      case "${GK_DEGRADE:-}" in
        "") : ;;
        0)  _degrade_theta=0 ;;
        1)  : ;;
        *[!0-9]*) : ;;
        *)  _degrade_theta="${GK_DEGRADE}" ;;
      esac
      if [ -z "$_degrade_theta" ] && [ "${_b_ctx_max:--1}" -gt 0 ] 2>/dev/null; then
        _degrade_theta=$(( (${_b_ctx_max} + 4) / 5 ))      # ceil(max×0.2) == ceil(max/5)
        if [ "$_degrade_theta" -lt 1 ]; then _degrade_theta=1; fi
      fi
      if [ "${_degrade_theta:-0}" -gt 0 ] 2>/dev/null \
         && [ "$_budget_remaining" -ge 1 ] 2>/dev/null \
         && [ "$_budget_remaining" -le "${_degrade_theta:-0}" ] 2>/dev/null; then
        echo "GATEKEEPER-WARN: edit_budget degraded (remaining=$_budget_remaining ≤ θ=$_degrade_theta, used=${_b_ctx_used:-0}/max=${_b_ctx_max:--1}) — 建议收束改动面（R2-a 早警：本轮仍照常计费，未耗尽仍放行，底线 BLOCK 不变）"
        _budget_log_append "degrade" \
          "edit_budget low: remaining=$_budget_remaining theta=$_degrade_theta used=${_b_ctx_used:-0} max=${_b_ctx_max:--1}" || true
      fi
      # 2026-09-19 ECC-F5FE1042A7BA（S1-c）：原只写 remaining ⟹ `used` 恒 0、消耗不可见 ⟹ 补 `used`。
      # 2026-09-19 ECC-E05F3517A965（S1-c 后半，用户裁定本轮就改）：**standard 并轨** —— 原判据
      # `[ "$_budget_ptype" = "standing" ]` 把 standard 排除在外，而 standard 的 `used` 源自
      # `gate_data.edit_count`（`gk_advance._edit_budget` 读它）⟹ 不在此自增则 standard 预算形同虚设。
      # ⚠ 窗口语义（2026-09-19 定）：`edit_count` = **本 R-phase 累计**，由 `_edit_budget` 在 `r_phase`
      #   切换时归零 ⟹ 此处**不自持**归零。
      # 2026-09-23（**计价单位改为「触及文件数」**，用户裁定「把节点 edit_budget.max 与批次数解耦」）：
      #   原口径 = **一次放行扣 1**（「一刀 = 一单位」）⟹ 多文件批次被刀数掐死（**本轮实测**：一批
      #   5 文件 / 13 次工具调用把 `max=8` 打满，只能人工 `state-patch` 抬额度并污染 `overrides[]`）。
      #   现口径：`billed_files[]` 记本节点**已计费过的 `real_path`**，同一文件**重复落刀不再扣**；
      #   `max`/`remaining` 语义 = 「本节点允许 / 剩余可触及的**文件数**」。
      #   判据见 `scripts/test_gk_edit_budget_metering.py::test_same_file_is_billed_once`（红先）+
      #   `::test_second_distinct_file_is_billed`（负臂，守「去重 ≠ 免费」）。
      #   ⚠ 读-改-写**在同一次 `_state_write` 内**（payload 在 flock 内持 `d`）⟹ 去重**原子**，
      #     无「两个并发 edit 都以为自己首次触及」的 TOCTOU 窗口。
      #   ⚠ 路径经 env 传入（不拼进 python 源码）⟹ 规避引号/换行注入（同 `_budget_override_record`）。
      #   ⚠ `billed_files` FIFO cap=64：被挤出窗口的老条目**可能**被再计费一次（有界退让 ——
      #     宁可多扣不漏扣，对齐设计 §4「无 per-edit 明细 ⟹ cap 不翻倍」的下限保护）。
      if [ "$_budget_remaining" -ge 1 ] 2>/dev/null && [ "${GK_BUDGET_OVERRIDE:-0}" != "1" ]; then
        GK_BILL_PATH="$real_path" _state_write "
import os as _os
gd = d.setdefault('gate_data', {})
eb = gd.setdefault('edit_budget', {})
_p = _os.environ.get('GK_BILL_PATH', '') or ''
_sid = _os.environ.get('GK_SESSION_ID', '') or ''
# T4′（§25；owner 2026-10-08 裁定「先落 T4′ + 未验证主腿」）：窗口 N 内同一 path 的 spam 事件
#   计数 ≥ K ⟹ 本次编辑 cost=2（覆盖 dedup 的 1/0）。判据单源 = gk_budget_ledger.edit_spam_flag（只读）。
#   kill switch：GK_EDIT_LOG=0 关；GK_EDIT_LOG_N / GK_EDIT_LOG_K 覆盖窗口/阈值。
#   ⚠ 异常 ⟹ 回落 cost=1（fail-open，防判据故障把合法编辑误加价）。
#   ⚠ state 路径经 env（GK_PY_STATE，由 _state_write 统一注入，形态锚 = 解释器）；
#     调用行首**逐字不动** —— test_gk_edit_budget_metering 的 _bill_payload1 以该行为锚反推 payload。
_cost = 1
if _os.environ.get('GK_EDIT_LOG', '1') != '0':
    try:
        from gk_budget_ledger import edit_spam_flag as _esf
        _flag = _esf(_os.environ['GK_PY_STATE'], _p,
                     window=(_os.environ.get('GK_EDIT_LOG_N') or None),
                     k=(_os.environ.get('GK_EDIT_LOG_K') or None))
        if _flag.get('flagged'):
            _cost = 2
    except Exception:
        _cost = 1
# T6（§3 T6 / §25.8）：同一 (session,node) 内「未验证编辑」累计 ≥ K ⟹ 本节点后续编辑 cost=2
#   （跨文件散点 thrash；T4′ 只管同文件）。kill switch：GK_T6=0 关；GK_T6_K 覆盖阈值。
#   node 以字面量嵌入（= 本作用域 $stage，零额外子进程）；异常 ⟹ 保留既有 _cost（fail-open）。
if _cost == 1 and _os.environ.get('GK_T6', '1') != '0':
    try:
        from gk_budget_ledger import node_unverified_flag as _nuf
        if _nuf(_os.environ['GK_PY_STATE'], session=_sid, node='$stage',
                k=(_os.environ.get('GK_T6_K') or None)).get('flagged'):
            _cost = 2
    except Exception:
        pass
if _sid:
    # 2026-09-25 会话隔离：计数与去重台账都落**本会话域**；新会话自 'max' 起算新鲜额度。
    _s = eb.setdefault('sessions', {}).setdefault(_sid, {})
    _s.setdefault('max', eb.get('max', 0))
    _s.setdefault('used', 0)
    _s.setdefault('remaining', int(_s.get('max', 0) or 0))
    _bf = _s.setdefault('billed_files', [])
else:
    _s = None
    _bf = eb.setdefault('billed_files', [])
# 计费（REV-24，2026-10-23，owner 裁定「批次作计价单位」）：**批次 = 1 单位**。
#   批次边界 = verify（同 (session,node) 内自最近一次 verify 以来的**放行**编辑同属一批）⟹
#   本批**首刀**扣 1、后续刀 0；T4′/T6 命中不再当作「整价」而是**加价 +1**（spam 附加费）。
#   原口径（2026-09-23 起）= 每个唯一文件 1 单位 ⟹ 一个 5 文件轮次 = 5 单位，12 的地板被批次量
#   吃光（实测一轮 5 文件就耗尽）。判据单源 = gk_budget_ledger.batch_open（只读）。
#   billed_files 仍逐条记（**观测面**，如 gk_bill_observe 的来源反推），不再驱动扣减。
#   ⚠ 本载荷整体在**双引号**字符串内 ⟹ 注释里禁反引号、禁美元-括号：会被 shell 先行展开
#     （2026-10-24 实测：反引号包裹的 billed_files 被当命令执行，stderr 报 command not found）。
_deduct = 0
if _p:
    if _p not in _bf:
        _bf.append(_p)
        del _bf[:-64]
    _batch_first = True
    try:
        from gk_budget_ledger import batch_open as _bo
        _batch_first = _bo(_os.environ['GK_PY_STATE'], _sid, '$stage')
    except Exception:
        _batch_first = True           # 判据故障 ⟹ 按首刀（多扣 1，保守方向）
    if _batch_first:
        _deduct += 1
    if _cost == 2:
        _deduct += 1                  # T4′/T6 附加费（不再当整价）
if _deduct:
    if _s is None:
        eb['remaining'] = max(0, int(eb.get('remaining', 0)) - _deduct)
        eb['used'] = eb.get('used', 0) + _deduct
    else:
        _s['remaining'] = max(0, int(_s.get('remaining', 0)) - _deduct)
        _s['used'] = int(_s.get('used', 0) or 0) + _deduct
    gd['edit_count'] = gd.get('edit_count', 0) + _deduct
" >/dev/null 2>&1 || true
      fi
      # edit-log（T4′/T6 载体；owner 裁定 A 2026-10-08）：编辑级事件写入 —— 已**收归单源**（ED1/ED3/ED8）。
      # 载体 = 旁挂 append-only `<state>.edit-log.jsonl`（**不**参与 state-patch 整体替换）。
      # 只读旁挂：**不**碰 remaining/used/billed_files；seal 由区外侧在节点/审计边界低频重算（§23.3 对策①）。
      # 语义 = 「按节点重置额度」的同一节点口径（T6 分组用）；`ts`(UTC)/JSON 转义/`node_seq` 由
      #   `_edit_log_append` → `gk_budget_ledger.append_edit` **单源**生成（消原内联 printf 第二实现 + 本地时区双源）。
      # `result`：逃生舱放行记 `override`（ED3，原 `GK_BUDGET_OVERRIDE != 1` 作前提 ⟹ 逃生舱期零记录），
      #   常规放行记 `allow` ⟹ 每次编辑尝试**恰一条**事件。
      # ⚠ 本块在 PROTECTED_REGION::gate 内 —— 按 owner 裁定 A：**仅替换** append 分支实现，防线 BLOCK 语义一字不改。
      if [ "${GK_BUDGET_OVERRIDE:-0}" = "1" ]; then
        _edit_log_append "override" "$real_path" "$stage" || true
      else
        _edit_log_append "allow" "$real_path" "$stage" || true
      fi
      # r9-2 ②a（未审债 ⟹ **下一节点门可见**；`ECC-BCF60C185CBE`，owner 裁定 A，2026-10-01）：
      # 透传面 = `_eg_out`（本分支上方**已付**的那次 `gk_edit_gate.py check` 输出）⟹ **零边际子进程**。
      # 契约：首行 `OK` 保留（既有消费点按 rc / `OK` 判）；债面**另起一行**合法 JSON，
      # hook `_run_cli` 取**首条 `{` 行**。⚠ 必须带 `"ok":true` —— 否则 `_run_cli` 回该 JSON 而
      # Gate 4 读 `.get("ok")` 得假 ⟹ 反把放行改成拦阻（fail-closed 反噬）。
      # `_eg_out` 空（异常退路）⟹ 不打印（保持旧形态，防 `json.loads` 抛错把放行变拦阻）。
      echo "OK"
      [ -n "$_eg_out" ] && printf '{"ok":true,"edit_gate":%s}\n' "$_eg_out"
      ;;
    commit)
      local msg="$path_or_msg"
      # P1: detect git commit --amend (bypasses CI trigger registration)
      # Bridge R7.5教训: amend 会改写 commit SHA，CI trigger 失效
      # 2026-09-19（ECC-52E6351D6DB4）：与主仓只读保护同形 —— rg 缺位时原式恒假 ⟹ `--amend`
      # 检测 **fail-open**（可绕过 CI trigger 登记）。改走单源 + 判缺 fail-closed。
      if [ -z "$RG" ] || echo "$path_or_msg" | "$RG" -q "\-\-amend"; then
        echo "BLOCK: git commit --amend detected. This bypasses CI trigger registration. Use normal commit."
        return 1
      fi
      # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 /usr/bin/rg）
      if ! echo "$msg" | "$RG" -q '^(feat|fix|refactor|docs|test|chore|security)\(.*\):'; then
        echo "BLOCK: Commit message must use conventional format: feat(R#): description | fix(R#): ... | refactor(R#): ..."
        return 1
      fi
      echo "OK"
      ;;
    push)
      local url="$path_or_msg"
      if echo "$url" | "$RG" -q '^https://[^/@]+@github\.com/spz-ecosystem/spz_gatekeeper(\.git)?$'; then
        echo "OK"
      elif echo "$url" | "$RG" -qi 'origin|upstream'; then
        echo "BLOCK: Git push via origin/upstream requires token URL. Use: https://<TOKEN>@github.com/spz-ecosystem/spz_gatekeeper.git"
        return 1
      else
        echo "BLOCK: Git push must use token-authenticated URL."
        return 1
      fi
      ;;
    *)
      echo "OK"
      ;;
  esac
}

# ---------- guard-edit (bridge upgrade: CRITICAL_MODULE / CRITICAL_CONFIG) ----------
cmd_node_guard() {
  # 2026-09-01 L9 深检实装：node_guard CLI 统一入口（正本清源——ctx 由 CLI 编排注入，
  # agent 不再自证）。等价 gk_node_guard.py guard 的确定性检查 + state/磁盘自动注入。
  # 用法: node-guard <node> [--pid <id>] [--ctx '{...}'] [--check-only] [--source-docs <逗号分隔路径>]
  # source_docs（2026-09-04 补）：CLI 检查计划引用文档磁盘可读性 → 注入 ctx.source_docs=缺失清单
  # （空=齐备），agent 不自证。对齐 gk_node_guard.py guard ctx.source_docs 语义。
  # 2026-09-05 S9 修复：子命令透传——route-map/register/announce 直通 python（不再被误当节点名解析）。
  case "${1:-}" in
    route-map|register|announce)
      python3 "${SKILL_DIR}/scripts/gk_node_guard.py" "$@" 2>>"$GK_DBG_LOG"
      return $?
      ;;
    # S14（2026-09-05 交叉审查）：显式 guard 动词剥离——python 子命令形态
    # `guard --node X` 归一为 bash 简写形态 X（此前 guard 被当节点 → 误导性 UNKNOWN_NODE）。
    guard) shift || true ;;
  esac
  local node="" pid="" ctx_json="" check_only=false source_docs=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --node) node="${2:-}"; shift 2 2>/dev/null || shift ;;   # S14 归一：python 形态 --node X 亦接受
      --pid) pid="${2:-}"; shift 2 2>/dev/null || shift ;;
      --ctx) ctx_json="${2:-}"; shift 2 2>/dev/null || shift ;;
      --check-only) check_only=true; shift ;;
      --source-docs) source_docs="${2:-}"; shift 2 2>/dev/null || shift ;;
      *) [ -z "$node" ] && node="$1"; shift ;;   # bash 简写形态：首位置参数 = node
    esac
  done
  [ -z "$node" ] && { echo "{\"ok\":false,\"error\":\"node-guard <node> required — 注册节点见 gk_node_guard.py _ROUTES\"}"; return 1; }
  # source_docs 磁盘存在性检查 → 缺失清单（空=齐备）；与用户 ctx 合并（ctx 优先保留非 source_docs 键）
  local merged_ctx="$ctx_json"
  if [ -n "$source_docs" ]; then
    # F-REV-15 (2026-09-10)：委托 gk_node_guard.missing_source_docs（单一事实源）——相对路径按
    # 仓根（MAIN_REPO_WSL）解析，而非调用方 cwd（cmd_advance 不 cd → cwd 漂移会误判缺）。
    local _sd_out=""
    _sd_out=$(python3 "$SKILL_DIR/scripts/gk_node_guard.py" source-docs \
      --source-docs "$source_docs" --root "$MAIN_REPO_WSL" --ctx "$ctx_json" 2>>"$GK_DBG_LOG" || echo "")
    [ -n "$_sd_out" ] && merged_ctx="$_sd_out"
  fi
  # F-REV-76（2026-09-16，用户裁定）：基线状态由 CLI **单点注入** —— `_gitnexus_baseline_status`
  # （gitnexus status 单一事实源）→ ctx.baseline_status ∈ {current,stale,unavailable}。
  # 同时**撤销**「按 .gitnexus 实存注入 baseline=True」的存在性兜底（老索引/硬崩索引只要文件在
  # 就过门 = 假绿）。python 侧见 status 缺失即 fail-closed（不再有兜底可走）。
  local _bl_dir _bl_st=""
  _bl_dir=$(_gx_repo_dir_for_current)
  [ -n "$_bl_dir" ] && _bl_st=$(_gitnexus_baseline_status "$_bl_dir")
  if [ -n "$_bl_st" ]; then
    merged_ctx=$(GK_CTX="$merged_ctx" GK_BL_ST="$_bl_st" python3 -c '
import json, os
try:
    _ctx = json.loads(os.environ.get("GK_CTX") or "") or {}
except Exception:
    _ctx = {}
if not isinstance(_ctx, dict):
    _ctx = {}
_ctx["baseline_status"] = os.environ.get("GK_BL_ST", "")
print(json.dumps(_ctx, ensure_ascii=False))' 2>>"$GK_DBG_LOG" || echo "$merged_ctx")
  fi
  local guard_result guard_rc
  guard_result=$(python3 "${SKILL_DIR}/scripts/gk_node_guard.py" guard \
    --node "$node" --state-file "$STATE_FILE" --ctx "$merged_ctx" ${pid:+--pid "$pid"} 2>>"$GK_DBG_LOG")
  guard_rc=$?
  # guard 的 fail-closed = JSON ok:false + exit 2（stdout 已有完整 JSON，不吞不追加）
  if $check_only; then
    echo "{\"ok\":true,\"check_only\":true,\"guard\":$guard_result}"
    return 0
  fi
  # 完整模式：fail-closed 语义与 guard 一致（ok=false → exit 2）
  # S13（2026-09-05）：原恒 return 0 与注释契约不符——依赖退出码判读的调用方会漏拦截；
  # 改为透传 python guard 退出码（0=ok / 2=前置缺失 fail-closed / 其余=工具硬失败 fail-loud）。
  echo "$guard_result"
  return "$guard_rc"
}

# ---------- plan-lint（计划写入安全网 PW-SN 确定性机检）----------
# Refs: references/plan-writing-safety-net.md（七轨对位表机检列）
# 对计划文档做确定性机检：锚点可解 / 假设编号唯一 / 新开关全仓可查 / 消费者数
# 一致 / 判据含可执行命令 / 连续编号块唯一。级别 high|medium|info。
# 退出码：0=无 high/medium（info 不计）；1=有；2=用法错误。
# Usage: plan-lint <plan.md> [--json] [--stats] [--task-file <f>] [--source-docs a,b]（--stats = 只读计数：裸行锚段级分类 total/delivery/ledger + 锚类 reason 计数；恒 exit 0、既有 stdout 与退出码不变 ⟹ R-13；--task-file/--source-docs = PW-13 下发门预演（F3，2026-10-15）：交付前以「将下发的 task」预跑 gk_task_gate，前置暴露 novel_phrase / 语料不可读 / 状态域落错；缺省空 ⟹ 零 finding）
cmd_plan_lint() {
  [ $# -ge 1 ] || { echo '{"ok":false,"error":"plan-lint <plan.md> [--json] [--stats] [--task-file <f>] [--source-docs a,b] required"}'; return 2; }
  local out rc
  out=$(python3 "$SKILL_DIR/scripts/gk_plan_lint.py" "$@" 2>>"$GK_DBG_LOG")
  rc=$?
  printf '%s\n' "$out"
  return "$rc"
}

# ---------- anchor-rebase（行锚重钉：代码改写后把文档里的行锚按符号重新钉位）----------
# Refs: docs/plans/2026-09-20-skill-portability-ecc-plan.md §7（收口路径 1）
# 背景（2026-09-20 实测 + 用户裁定）：scripts/gk_anchor_rebase.py 原**没有 CLI 入口** ⟹ 按
# 「禁直连 scripts/gk_*.py，须走 CLI 统一入口」纪律无法调用，于是已记录的教训「代码落刀与锚刷
# 必须同批」反复做不到 —— 本批 rg 归口即净增 42 处漂移锚（受控 A/B：153 vs 111，ECC-C0813B077DEF）。
# 本命令即该纪律的**合规入口**：默认**只读预览**（每项 status=preview，不写任何文件）。
# ⚠ 仅 `--apply` 落刀，且它**会绕过 edit_budget**（既有缺口 ECC-1E6BFDD7A207）⟹ 属**显式人工
#   放行**动作：调用方须在 commit message / 计划文档中写明本批锚刷范围与判据，不得静默使用。
# Usage: anchor-rebase --docs <a.md,b.md> [--refs <f:1,f:2-9>] [--map <old=new,...>] [--apply]
cmd_anchor_rebase() {
  [ $# -ge 1 ] || { echo '{"ok":false,"error":"anchor-rebase --docs <a.md,b.md> [--refs ...] [--map ...] [--apply] required"}'; return 2; }
  local out rc
  out=$(python3 "$SKILL_DIR/scripts/gk_anchor_rebase.py" "$SKILL_DIR" "$@" 2>>"$GK_DBG_LOG")
  rc=$?
  printf '%s\n' "$out"
  return "$rc"
}

# ---------- model-probe（W2A 模型版本探针：钉 stride/相位周期，alias 不可作版本判据） ----------
# Refs: W2A §6.1 / §6.3(3) F1b（ECC-75F6A2BB7F2B）
cmd_model_probe() {
  # 模型版本探针（W2A §6.1 / §6.3(3) F1b；ECC-75F6A2BB7F2B）：
  #   判 stride / 相位周期 S 禁据 alias 推断（alias 可换后端不换名）⟹ 元数据层 + 行为层实测。
  #   resolved=false 为契约 fail-loud：下游须停并索真值，禁回落 S=2。
  if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ] || [ $# -eq 0 ]; then
    echo 'usage: gatekeeper-cli.sh model-probe [--meta <json>] [--series <json>] [--known-strides <json>] [--candidates <json>]'
    echo '  Resolve the true backend model version / phase stride S (alias is NOT a version discriminator).'
    echo '  Pure local (no API). resolved=false => fail-loud: do NOT assume S=2.'
    return 0
  fi
  local out rc
  out=$(python3 "$SKILL_DIR/scripts/gk_model_probe.py" "$@" 2>>"$GK_DBG_LOG")
  rc=$?
  printf '%s\n' "$out"
  return "$rc"
}

# ---------- phase-probe（相位扫描探针：密集 sweep × 每 stride 置换检验 + Bonferroni） ----------
# Refs: W2A P2 §6（一次密集 sweep）；ECC-42B4A6E15927
# 2026-11-04（导出面修复）：本命令属**排除面**（phase_probe 族不随公开包）。公开树里
#   原实现会裸派发到缺失脚本 ⟹ `rc=2` 且 **stdout 空**（stderr 被吞进 dbg log）——
#   用户无法区分"没装/坏了"。现补加载安全网同款具名出口（对齐 bashpy / paper-review）。
cmd_phase_probe() {
  # 相位探针（迁自论文仓实验脚本；ECC-42B4A6E15927；副本已冻结，以本仓为唯一事实源）：
  #   密集 sweep 填充长度 L=0..N-1，对**每个**候选 stride S 做置换检验 + Bonferroni 校正；
  #   `N_LENGTHS < 2S` 的 stride 标 UNDER-POWERED（不得读成真 null）；ONE sweep 服务所有 stride。
  #   默认 0 API：--dry-run 用合成臂自检统计量；--real 才委派 scripts/subagent_runner.py（联网）。
  if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ] || [ $# -eq 0 ]; then
    echo 'usage: gatekeeper-cli.sh phase-probe --dry-run | --real --group G1=<p1> [--group G2=<p2> ...] [--lengths N] [--length-step K] [--repeats M] [--mode prefix|inseq|both] [--outcome score|block] [--out <file>]'
    echo '  Dense phase sweep: phase-invariance p for every candidate stride (Bonferroni; under-powered flagged).'
    echo '  --dry-run = synthetic arm (no API). --real = delegate to scripts/subagent_runner.py (network).'
    return 0
  fi
  if [ ! -f "$SKILL_DIR/scripts/gk_phase_probe.py" ]; then
    echo '{"ok":false,"error":"PLUGIN_NOT_SHIPPED","feature":"phase-probe","source":"missing","detail":"phase 族（探针/格式/敏感度/混杂模拟/统计）均不随公开包（臂设计与稿件实验面属私仓）","hint":"需要该能力请在私仓运行；公开面无等价替代命令"}'
    return 2
  fi
  local out rc
  out=$(python3 "$SKILL_DIR/scripts/gk_phase_probe.py" "$@" 2>>"$GK_DBG_LOG")
  rc=$?
  printf '%s\n' "$out"
  return "$rc"
}

cmd_guard_edit() {
  local path="$1" target_line="${2:-0}"
  [ ! -f "$STATE_FILE" ] && { echo '{"allowed":false,"reason":"No state file"}'; return 1; }
  local stage; stage=$(json_val "$STATE_FILE" stage "IDLE")
  [ "$stage" = "IDLE" ] && { echo '{"allowed":false,"reason":"NO_ACTIVE_R_PHASE","hint":"Run bash gatekeeper-cli.sh state, then start a new R-phase via the spz-gatekeeper-r-sequence skill"}'; return 1; }

  # G2 (2026-08-02): state checksum verify — advance 入口已有 (L1906), guard-edit 补齐
  # 丢弃 stdout (gk_gate_checksum.py 会输出 {"ok":true,...}), 只取退出码避免污染 JSON 输出流
  if ! _state_checksum_verify >/dev/null 2>&1; then
    echo "{\"allowed\":false,\"reason\":\"STATE_FILE_TAMPERED\",\"hint\":\"State checksum mismatch — state may be tampered or corrupted. Run 'state' to inspect.\"}"
    return 1
  fi
  # MAIN_WORKTREE guard（2026-09-20 C3：正则改引用派生变量、并补 rg 缺位判缺臂 —— 与 pre_tool_check 同形，原缺该臂处为无遮蔽的独立 fail-open）
  if [ -z "$RG" ] || echo "$path" | "$RG" -qi "$_MAIN_REPO_WIN_RE" || echo "$path" | "$RG" -qi "$_MAIN_REPO_WSL_RE"; then  # 2026-09-24 XENV-FORM ECC-9D6B0291E793：追加 WSL 形态臂（同上，引号规则一致）
    local feature_path; feature_path=$(json_val "$STATE_FILE" worktree "")
    echo "{\"allowed\":false,\"reason\":\"MAIN_WORKTREE\",\"fix\":\"Convert to: ${feature_path}/<rest-of-path>\"}"; return 1
  fi
  # 2026-09-28（**ECC-542F75AF97C0 修复**）：动态臂（与 pre_tool_check 同源语义）—— 被治理仓由
  #   `state.target_repo` 经**单源** `gk_route_center.resolve_repo` 解析；命中「被治理仓主工作树」即拒。
  #   原静态臂只认 `MAIN_REPO_WIN/WSL`（产品仓）⟹ `target_repo=skill` 时技能仓主树**零拦截**。
  #   本函数原用裸 `$path`（未做 realpath）⟹ 动态臂自行 realpath（best-effort），归一两侧形态。
  local _gov_repo _gov_path=""
  _gov_repo=$(json_val "$STATE_FILE" target_repo "")
  if [ -n "$_gov_repo" ]; then
    _gov_path=$(python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-repo "$_gov_repo" \
      --skill-dir "$SKILL_DIR" 2>>"$GK_DBG_LOG" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field path --default '' --default-invalid '' --default-falsy '' 2>/dev/null)
  fi
  if [ -n "$_gov_path" ]; then
    local _gov_rp; _gov_rp=$(python3 "$SKILL_DIR/scripts/gk_path.py" realpath "$path" 2>/dev/null || echo "$path")
    case "$_gov_rp" in
      "$_gov_path"|"$_gov_path"/*)
        local feature_path; feature_path=$(json_val "$STATE_FILE" worktree "")
        echo "{\"allowed\":false,\"reason\":\"MAIN_WORKTREE\",\"fix\":\"Convert to: ${feature_path}/<rest-of-path>\"}"; return 1 ;;
    esac
  fi
  # ── 宿主配置独立面（R-HOSTCFG，2026-10-02）: **先于**活动写面判定 ────────────────────
  # 宿主配置在治理仓之外、**不属**任何 worktree ⟹ 若走下方 `gk_edit_gate.py check` 会先撞
  #   `PATH_NOT_IN_ACTIVE_SURFACE`（实测：mcp.json 被拒且读不到保护语义）⟹ 保护永不生效。
  #   故此处**前置**同一单源 `_host_config_check`：BLOCK 档拦、WARN 档放行 + 留痕，
  #   **不看** worktree / worktrees_extra（零 state 依赖）。
  local _hc _hc_rc
  _hc=$(_host_config_check "$path" "$target_line"); _hc_rc=$?
  if [ "$_hc_rc" -eq 1 ]; then
    echo "{\"allowed\":false,\"reason\":\"PROTECTED_REGION\",\"protection_status\":\"blocked\",\"detail\":\"$(printf '%s' "$_hc" | head -1)\"}"
    return 1
  elif [ "$_hc_rc" -eq 2 ]; then
    echo "{\"allowed\":true,\"reason\":\"HOST_CONFIG\",\"protection_status\":\"warn\",\"detail\":\"$(printf '%s' "$_hc" | head -1)\"}"
    return 0
  fi
  # 写类判定**单一实现**委派（2026-09-28 结构性收敛，见
  # docs/plans/2026-09-28-edit-gate-ecc-convergence-plan.md §2）：活动写面 / junction-mount /
  # 受保护目录（build/·.git/·node_modules/）/ stage=DONE / 预算耗尽 五项原为 `pre_tool_check`
  # **独有** ⟹ 同一规则两消费点口径漂移（用户实测：同一 feature worktree 路径本函数放行、
  # pre-tool-check 却 BLOCK）。现两侧统一委派 `scripts/gk_edit_gate.py check`。
  # exit 契约：0 = 放行；1 = 拦阻；2 = 错误（state 不可读 / 缺 --path）⟹ 一律按**拦阻**处置（fail-closed）。
  # ⚠ 本函数是**查询**：`--enforce-budget` 只**报**不扣（扣费唯一在 `pre_tool_check`）。
  # ⚠ `MAIN_WORKTREE` 仍由上方内联判据承担（与 pre_tool_check 同形，由 test_main_repo_guard 钉）。
  local _eg_out _eg_rc _eg_reason
  _eg_out=$(python3 "$SKILL_DIR/scripts/gk_edit_gate.py" check --state "$STATE_FILE" --path "$path" \
              --session "${GK_SESSION_ID:-}" --enforce-budget 2>>"$GK_DBG_LOG")
  _eg_rc=$?
  if [ "$_eg_rc" -ne 0 ]; then
    # ⚠ 输出**只**取 reason 标量：helper 的完整 JSON 落 `$GK_DBG_LOG` 供排查。
    #   原写法把 helper JSON 内联进 `"detail":${X:-{}}` —— bash 的 `${X:-{}}` 兜底花括号
    #   与字面 `}` 叠加 ⟹ **多一个右花括号 = 非法 JSON**（实测 `json.loads` 直接抛 ⟹
    #   调用方 `_cli_gate_ok` 只按 rc 判故无感，但任何按 JSON 解析的消费点会拿到空对象）。
    printf '%s\n' "[guard-edit] blocked rc=$_eg_rc: $_eg_out" >>"$GK_DBG_LOG" 2>/dev/null || true
    _eg_reason=$(printf '%s' "$_eg_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field reason --default '' 2>/dev/null || echo "")
    echo "{\"allowed\":false,\"reason\":\"${_eg_reason:-GATE_BLOCK}\",\"worktree\":\"$(json_val "$STATE_FILE" worktree "")\"}"
    return 1
  fi
  # PROTECTED_REGION guard — line-level when target_line, file-level otherwise
  local prot_detail="" protection_status="clear"
  if [ "$target_line" -ne 0 ] 2>/dev/null; then
    prot_detail=$(_protected_region_check "$path" "$target_line") || {
      echo "{\"allowed\":false,\"reason\":\"PROTECTED_REGION\",\"protection_status\":\"blocked\",\"detail\":\"$(echo "$prot_detail" | head -1)\"}"
      return 1
    }
    # 2026-09-27（owner 裁定 A）：行级命中 = WARN + 留痕**放行**（不再 BLOCK）⟹ 显式标注 warn（原为恒 clear）
    case "$prot_detail" in WARN*) protection_status="warn" ;; esac
  else
    prot_detail=$(_protected_region_check "$path") || { echo "{\"allowed\":false,\"reason\":\"PROTECTED_REGION\",\"protection_status\":\"blocked\"}"; return 1; }
    # F-REV-45（2026-09-13）：文件级（无 target_line）= WARN 留痕，放行但显式标注（不再是恒 BLOCK）
    case "$prot_detail" in WARN*) protection_status="warn" ;; esac
  fi

  local warning="" category=""

  # CRITICAL_MODULE detection (bridge pattern — edit must be followed by ctest)
  local bn; bn=$(basename "$path")
  case "$bn" in
    spz.cc|tlv.cc|spz.h|tlv.h|extension_validator.cc|extension_spec_registry.cc)
      warning="CRITICAL_MODULE — must run cmake --build + ctest after editing"
      category="CRITICAL_MODULE" ;;
    CMakeLists.txt|ci.yml)
      warning="CRITICAL_CONFIG — confirms to dependency freeze + CI trigger policy"
      category="CRITICAL_CONFIG" ;;
    *.md|*.txt|*.json|*.yaml|*.yml)
      category="docs/config" ;;
  esac

  # R5.8 SA2: gitnexus context 必须用 --repo 明确指定仓库
  # PowerShell CWD 与 bash CWD 独立，不加 --repo 可能查错索引或查空
  # F-REV-71（2026-09-16）：repo 名改由**单源推导**（`_gx_repo_name_for_dir`）—— 原硬编码
  #   `spz_gatekeeper` **不在 gitnexus registry**（实测 registry 只有 3 条，无该名）⟹ 任何
  #   调用必报 `Repository "spz_gatekeeper" not found` ⟹ 本段证据**恒空**（假绿）。
  local gn_context="" _gnrepo_ctx
  _gnrepo_ctx=$(_gx_repo_name_for_dir "$(_gx_repo_dir_for_current)")
  if echo "$path" | "$RG" -q '\.(cc|h|cpp|hpp)$'; then
    local sym; sym=$(basename "$path" | sed 's/\.[^.]*$//')
    gn_context=$(_run_gitnexus context --repo "$_gnrepo_ctx" "$sym" 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_views.py" gn-context-summary 2>/dev/null || echo "")
    [ -n "$gn_context" ] && warning="${warning} | gitnexus:${gn_context}"
  fi

  # P2 (2026-08-02, ECC-FINDING-20260802): 双前缀判定 — WSL /root/.config 或 Windows worktree (/mnt/c/.../.trae/worktrees)
  # G3 (2026-08-02): 输出 project_type — 消费端可用它区分 standard/standing 门禁语义
  local pt; pt=$(python3 "${SKILL_DIR}/scripts/gk_gate_project_type.py" "$STATE_FILE" 2>/dev/null || echo "standard")
  # 2026-11-01（开源可移植）：去用户名/仓库名硬编码，且改**内建 glob**（原 `"$RG" -q` 在 rg
  #   缺位时恒假 ⟹ 一律误标 `unknown`）。判据仍是「开发 worktree 树下的 feature/<branch>」。
  local _pth_norm="${path//\\//}"
  if [[ "$_pth_norm" == *"/superpowers/worktrees/"*"/feature/"* || "$_pth_norm" == *"/.trae/worktrees/"*"/feature/"* ]]; then
    [ -n "$category" ] && echo "{\"allowed\":true,\"path_type\":\"feature_worktree\",\"project_type\":\"$pt\",\"category\":\"$category\",\"warning\":\"$warning\",\"protection_status\":\"$protection_status\"}" || echo "{\"allowed\":true,\"path_type\":\"feature_worktree\",\"project_type\":\"$pt\",\"protection_status\":\"$protection_status\"}"
  else
    [ -n "$category" ] && echo "{\"allowed\":true,\"path_type\":\"unknown\",\"project_type\":\"$pt\",\"category\":\"$category\",\"warning\":\"$warning\",\"protection_status\":\"$protection_status\"}" || echo "{\"allowed\":true,\"path_type\":\"unknown\",\"project_type\":\"$pt\",\"warning\":\"Path not recognized\",\"protection_status\":\"$protection_status\"}"
  fi
}
# PROTECTED_REGION_END::gate

# ---------- PROTECTED REGION check (shared) ----------
# Refs: SkillOpt skill.py L18-28 (_is_in_slow_update_region)
#       SkillOpt slow_update.py L29-32 (SLOW_UPDATE_START/END markers)
#       SKILL.md Red Flags: guard-edit with PROTECTED_REGION
#       prm-monitor-methodology.md §8.1 (Protected Regions integration)
# SkillOpt pattern: declarative markers block edits to critical logic.
# Gatekeeper: 5 named regions (constants/evidence/gate/transition/appeal).
# Diff: SkillOpt checks text-in-region; Gatekeeper checks line-in-range.
# 2026-09-27（owner 裁定 A，见 `docs/plans/2026-09-27-owner-authorization-channel-plan.md`）：
# 保护区「行级命中」审计记录 —— append-only JSONL，路径 = `${STATE_FILE}.protected-edits.jsonl`。
# 失败静默（**不得**因留痕失败而阻断编辑）；`STATE_FILE` 未设 ⟹ 跳过。
_pe_record() {
  local f="$1" tl="$2" nm="$3" st="$4" en="$5"
  [ -n "$STATE_FILE" ] || return 0
  printf '{"ts":"%s","file":"%s","lines":"%s","region":"%s","span":"%s-%s","pid":%s}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$f" "$tl" "$nm" "$st" "$en" "$$" \
    >> "${STATE_FILE}.protected-edits.jsonl" 2>/dev/null || true
  return 0
}

# 宿主配置保留集 —— **单源** `case`（`_protected_region_check` 与两消费点的**前置**分支共用）。
# 按 **basename** 匹配（不分目录）—— 刻意「宁可多保护」：宿主配置文件在不同 AppData / 用户
#   目录形态下位置会变。
#   · `hooks.json` = **门禁本体**（Trae `PreToolUse` 注册表）⟹ **BLOCK**：被治理者不得自拆门禁
#     （改它 = 关掉本 hook = 治理自毁）。
#   · `mcp.json` / `settings.json` / `settings.json.bak_*` = 宿主配置（含明文 token / 行为开关 /
#     自动备份）⟹ **WARN + 强制留痕**（放行，可审计）。2026-09-29 owner 裁定「1 纳入加留痕」。
# 开关 `GK_HOST_PROTECT=0` ⟹ 整段跳过（回退面 = 变更前行为）。
# **返回码三态**（刻意区别于 `_protected_region_check` 的 rc≠0⟹拦 契约）：
#   0 = 非宿主配置（调用方继续其它判据）；1 = BLOCK 档；2 = WARN 档（**已** `_pe_record` 留痕）。
_host_config_check() {
  local file_path="$1" target_line="${2:-0}"
  [ "${GK_HOST_PROTECT:-1}" = "0" ] && return 0
  # 形态归一（2026-10-02 R-HOSTCFG）：hook 实测传的是 **Windows 形态** `C:\...\mcp.json`，而
  #   原式 `basename "$file_path"` 对反斜杠串退化为整串 ⟹ 保留集**永不命中**（仅 WSL 形态有效）。
  #   先把反斜杠折成正斜杠再取 basename ⟹ Windows / WSL 两形态通吃。
  local _hc_bn; _hc_bn=$(basename "${file_path//\\//}" | tr '[:upper:]' '[:lower:]')
  case "$_hc_bn" in
    hooks.json)
      echo "BLOCK: hooks.json 是门禁本体（Trae hook 注册表）—— 禁 agent 写；仅 owner 手工改。"
      return 1 ;;
    mcp.json|settings.json|settings.json.bak*)
      _pe_record "$file_path" "$target_line" "HOST-CONFIG" 0 0
      echo "WARN: $_hc_bn 是宿主配置（可能含明文 token / 行为开关）—— 已放行并留痕（region=HOST-CONFIG）。"
      return 2 ;;
  esac
  return 0
}

_protected_region_check() {
  local file_path="$1" target_line="${2:-0}"
  # ── 宿主配置保留集（2026-10-02 R-HOSTCFG：抽为单源 `_host_config_check`，供两消费点**前置**调用）──
  # 为何**前置**：宿主配置在治理仓之外、不属任何 worktree ⟹ 若先走活动写面判定必撞
  #   `PATH_NOT_IN_ACTIVE_SURFACE`（实测）⟹ 保护永不生效。故两消费点（`pre_tool_check` /
  #   `cmd_guard_edit`）均在本函数**之前**先调 `_host_config_check`；此处的调用是
  #   `_protected_region_check` 被**独立调用**时的兜底（保持「rc≠0 ⟹ 拦阻」契约不变）。
  local _hc _hc_rc
  _hc=$(_host_config_check "$file_path" "$target_line"); _hc_rc=$?
  if [ "$_hc_rc" -eq 1 ]; then printf '%s\n' "$_hc"; return 1; fi
  if [ "$_hc_rc" -eq 2 ]; then printf '%s\n' "$_hc"; return 0; fi
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG" + 缺位显式 fail-closed（原 /usr/bin/rg）
  if [ -z "$RG" ] || { echo "$file_path" | "$RG" -q "gatekeeper-cli.sh" && "$RG" -q "PROTECTED_REGION_START" "$SKILL_DIR/gatekeeper-cli.sh" 2>/dev/null; }; then
    # Extract all protected region line ranges
    local ranges; ranges=$(python3 "$SKILL_DIR/scripts/gk_source_scan.py" protected-regions "$SKILL_DIR/gatekeeper-cli.sh" 2>/dev/null || echo "")
    # 2026-09-23（R25 洞口补漏）：`target_line` 允许**逗号分隔多行**（整文件重写 = 多处差异行）。
    # 原式只做单值数值比较 + hook 只回「首个差异行」⟹「首行差异在区外、后续差异在区内」时
    # 逗号串整体非数字、区间比较双双失败 ⟹ fail-open（守区在最常见的重写形态上失效）。
    # 现逐行判，**任一行命中即 WARN + 留痕**；无任何有效行号时才退文件级 WARN（F-REV-45 语义不变）。
    local _tl _has_line=0
    while IFS= read -r _tl; do
      case "$_tl" in ''|0|*[!0-9]*) continue ;; esac
      _has_line=1
      [ -n "$ranges" ] || continue
      local start end name
      while IFS=: read -r start end name; do
        [ -z "$start" ] && continue
        if [ "$_tl" -ge "$start" ] 2>/dev/null && [ "$_tl" -le "$end" ] 2>/dev/null; then
          # 2026-09-27（owner 裁定 A，裁决记录 `ECC-D6115EC0C74D`）：行级 BLOCK → **行级 WARN + 强制留痕**。
          # 原「NO bypass channel」硬拦使每次落刀都需 owner 手敲配置；现放行但写审计（`_pe_record`），
          # 落刀仍须 commit + doc 留痕以保可追溯。文件级分支（无有效行号）语义不变（仍 WARN）。
          _pe_record "$file_path" "$_tl" "$name" "$start" "$end"
          echo "WARN: Line $_tl is in PROTECTED_REGION '$name' (L${start}-L${end}). Agent edit ALLOWED (owner ruling A, 2026-09-27) — recorded to <state>.protected-edits.jsonl; commit + doc trail required."
        fi
      done <<< "$ranges"
    done < <(printf '%s\n' "$target_line" | tr -c '0-9' '\n')
    # If no line number provided, use legacy file-level WARN
    # F-REV-45 语义（2026-09-13 用户裁定）+ owner 裁定 A（2026-09-27）：**文件级 = WARN；行级 = WARN + 留痕**。
    # 均不阻断（行级命中由 `_pe_record` 写审计 JSONL）。
    if [ "$_has_line" -eq 0 ]; then
      # 2026-10-13（`ECC-317C82A14DE8` ②）：**文件级命中亦留痕**。原仅 echo WARN 后 return 0 ⟹
      #   行号不可得时（MCP 写形态 / 宿主载荷键名不符）**静默无审计**，与「保护区写入必留痕」契约相悖
      #   （本会话实证：12:11 两次 gatekeeper-cli.sh 编辑，hook 日志仅 INVOKE→ALLOW，ledger 零条目）。
      _pe_record "$file_path" "0" "FILE-LEVEL" 0 0
      echo "WARN: gatekeeper-cli.sh 存在 PROTECTED_REGION 标记 — 未提供 target_line，文件级提示 **已留痕**（行级命中将 WARN + 行级留痕）"
      return 0
    fi
  fi
  return 0
}

# ---------- stage-detail ----------
cmd_stage_detail() {
  local stage="$1" ref_file=""
  case "$stage" in
    STAGE_0) ref_file="references/stage-0-start.md" ;; STAGE_1) ref_file="references/stage-1-code.md" ;;
    STAGE_2) ref_file="references/stage-2-ci.md" ;; STAGE_3) ref_file="references/stage-3-review.md" ;;
    STAGE_4) ref_file="references/stage-4-merge.md" ;; STAGE_5) ref_file="references/stage-5-retire.md" ;;
    *) echo "{\"error\":\"unknown stage\"}"; return 1 ;;
  esac
  [ -f "${SKILL_DIR}/${ref_file}" ] && echo "{\"stage\":\"$stage\",\"ref_file\":\"$ref_file\",\"lines\":$(wc -l < "${SKILL_DIR}/${ref_file}")}" || echo "{\"error\":\"ref not found\"}"
}

# ─── 子代理模型调用链（2026-10-31，owner 指令：L2 受限审查去 v4-flash 硬编码）──────────────
# 病象：subagent 派发行原样传 --api-model ${API_MODEL} ⟹ 模型恒 = `DS_MODEL_CRITIC`
#   （v4-flash 族）—— L2 `--crossrev` 受限审查因此与 actor 同族自审，且外部无覆盖位。
# 修法：与 subagent_runner 既有调用方（`gk_paper_review` / `gk_pc_sim`）**同一条链**：
#   `GK_SUBAGENT_API_MODEL` → 当前 provider 的 `API_MODEL` → `deepseek-flash`。
# 边界：仅 deepseek 车道吃 env —— MiMo 降级腿必须用 MiMo 自己的 critic 模型
#   （DS 侧模型名在 MiMo 端不存在，强塞会 400）。
# ⚠ 位置约束：必须放在 `# ---------- PRM MONITOR ...` 头部注释块**之前** ——
#   docgen 把「紧邻 cmd_monitor 的注释块」当 Purpose/Refs，插在中间会丢文档面（实测）。
_subagent_model_chain() {
  if [ "$PROVIDER" = "deepseek" ] && [ -n "${GK_SUBAGENT_API_MODEL:-}" ]; then
    printf '%s' "$GK_SUBAGENT_API_MODEL"
  else
    printf '%s' "${API_MODEL:-deepseek-flash}"
  fi
}

# ---------- PRM MONITOR: structural (--local) + semantic (--api → v4-flash) + alignment (--align → doc-code review) ----------
# Refs: --align = 委托 doc-align 插件（gk_doc_align.py 单一实现；F-REV-42 完成 2026-09-01 收敛）。0 API calls.
# Refs: --subagent --crossrev = L2 交叉审查显式通道（2026-09-04 L2/L3 换位）：preflight A 上下文签名新鲜/B L3 基线 status-fresh(stale 才 analyze)/C 审查节点绑定/D pin → gk_l3_prefetch 预取 detect-changes 摘要 → GK_L3_EVIDENCE env 注入 subagent（不可用 WARN 降级不阻断）。
# ----------

cmd_monitor() {
  local mode="--local" stage="" api_key="${API_KEY}" user_tools="" crossrev_flag=false role_override=""
  local task_file=""
  # G1（2026-10-03）：批身份派发侧接线（§18.1 判据三要素由**派发侧**显式给，非时间桶近似）。
  local batch_plan="" batch_narrow="" batch_epoch="" arm_group="" arm_delta=""
  # F4（2026-10-15）：通用进度探测（coder/质询 共用）—— `--watch <target>` 走共享模块
  #   `gk_dispatch_watch.py`（0-API 只读；接收裁决复用 gk_receive_check）。挂既有 monitor ⟹ 零新增 _CMD_REG。
  local watch_interval="" watch_iters="" watch_max="" watch_expect="" watch_kind=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --local) mode="--local"; shift ;;
      --api) mode="--api"; shift ;;
      --gitnexus) mode="--gitnexus"; shift ;;
      --align) mode="--align"; shift ;;
      --subagent) mode="--subagent"; shift ;;  # T43+++ constrained review agent
      # F4（2026-10-15）：通用进度探测 mode（与 --local/--api/--gitnexus/--align/--subagent 并列）。
      --watch) mode="--watch"; shift ;;
      --interval) watch_interval="${2:-}"; shift 2 2>/dev/null || shift ;;
      --iterations) watch_iters="${2:-}"; shift 2 2>/dev/null || shift ;;
      --max-wait) watch_max="${2:-}"; shift 2 2>/dev/null || shift ;;
      --expect) watch_expect="${2:-}"; shift 2 2>/dev/null || shift ;;
      --kind) watch_kind="${2:-}"; shift 2 2>/dev/null || shift ;;
      --crossrev) crossrev_flag=true; shift ;;  # C (2026-09-04): 交叉审查 L2 显式通道 → 节点绑定 + A/B/D 前置
      --role) role_override="${2:-}"; shift 2 2>/dev/null || shift ;;  # F-REV-11 C2 (2026-09-10): 显式角色覆盖（review 车道具名角色）
      --tools) user_tools="${2:-}"; shift 2 2>/dev/null || shift ;;  # explicit tool selection for --subagent
      --task-file) task_file="${2:-}"; shift 2 2>/dev/null || shift ;;  # L1 自动派发（2026-09-23）：窄任务经文件下发
      # G1（2026-10-03）：批身份注入 —— 编排方对**一次 MoA 批**取同一 `--batch-epoch`（如 date +%s），
      #   N 臂共享 ⟹ 同一 batch_id（治「同计划 10 分钟内两轮误并 / 一轮跨桶误分」）。禁第二实现：
      #   计算仍落 `gk_moa_aggregate.compute_batch_id`（payload 侧），此处只注入 env。
      --batch-plan) batch_plan="${2:-}"; shift 2 2>/dev/null || shift ;;
      --batch-narrow) batch_narrow="${2:-}"; shift 2 2>/dev/null || shift ;;
      --batch-epoch) batch_epoch="${2:-}"; shift 2 2>/dev/null || shift ;;
      # §18.3（2026-10-04）：组别身份注入 —— 编排方对**每个臂**给 G1（相同对）/G2（正交互补）/
      #   G3（污染组）；落 payload 的 entry.arm_group（聚合端只读不猜，禁聚合端按指纹反推）。
      --arm-group) arm_group="${2:-}"; shift 2 2>/dev/null || shift ;;
      # W2A-P2（2026-10-16）：**消融腿** per-arm 长度平移 Δ 注入 —— 编排方对**每个臂**给
      #   `i·Δ`（§6 口径 `L_i = L + i·Δ`；Δ=0 = 同相控制臂）；落 payload 的 entry.arm_delta
      #   （聚合端只读不猜，禁按指纹反推相位）。φ 由消费侧经 `gk_evidence.per_arm_phases` 派生。
      --arm-delta) arm_delta="${2:-}"; shift 2 2>/dev/null || shift ;;
      --api-key) api_key="${2:-}"; shift 2 2>/dev/null || shift ;;
      -*)  # ECC-310D65FD844A（2026-09-24 实测）：未知 flag 曾静默落 `*)` catch-all → 覆盖 `stage`，
           #     而 `--subagent` 模式下 `stage` **就是任务载体** ⟹ `monitor --subagent <任务> --tier 1`
           #     把任务静默换成 `1`（三份 sub-*.md 报告头「任务」字段均为 `1` 实证）。
           #     档位一律走 env `SUBAGENT_TIER`（`apply-worktree` 的 next 串即此形，见本函数 L7140 注），
           #     禁止在 monitor 上再造 `--tier` 第二通道；对齐 paper-review 未知参数的 fail-loud 惯例。
        echo "{\"ok\":false,\"error\":\"unknown flag: $1\",\"exit_code\":2,\"usage\":\"monitor [--local|--api|--gitnexus|--align|--subagent [--role R] [--tools T] [--task-file F] [--crossrev] [--batch-plan P] [--batch-narrow n1,n2] [--batch-epoch E] [--arm-group G1|G2|G3] [--api-key K]] | --watch <pr-*|12hex|worktree> [--kind auto|pipeline|aggregation|worktree] [--expect N] [--interval S] [--iterations N] [--max-wait S] | <stage>（档位用 env SUBAGENT_TIER）\"}"
        return 2 ;;
      *) stage="$1"; shift ;;
    esac
  done

  # T3/T12（2026-10-05，n4）：批身份/组别 flag **只在 `--subagent` 派发面**有意义 ——
  #   与其它 mode 同用会静默注入 env 而无消费方（`--arm-group` 曾可配 `--local` 误导）⟹ fail-loud。
  local _batch_flags=""
  [ -n "$batch_plan" ] && _batch_flags="${_batch_flags} --batch-plan"
  [ -n "$batch_narrow" ] && _batch_flags="${_batch_flags} --batch-narrow"
  [ -n "$batch_epoch" ] && _batch_flags="${_batch_flags} --batch-epoch"
  [ -n "$arm_group" ] && _batch_flags="${_batch_flags} --arm-group"
  [ -n "$arm_delta" ] && _batch_flags="${_batch_flags} --arm-delta"
  if [ -n "$_batch_flags" ] && [ "$mode" != "--subagent" ]; then
    echo "{\"ok\":false,\"error\":\"--arm-group/--batch-* 仅与 --subagent 同用（--arm-delta 同）\",\"mode\":\"$mode\",\"flags\":\"${_batch_flags# }\",\"exit_code\":2,\"usage\":\"monitor --subagent … --arm-group G1|G2|G3 --arm-delta N --batch-plan P --batch-narrow n1,n2 --batch-epoch E\"}"
    return 2
  fi

  # F4（2026-10-15）：watch **专属** flag 同用门（对齐上方 --arm-group/--batch-* 惯例，禁静默）。
  local _watch_flags=""
  [ -n "$watch_interval" ] && _watch_flags="${_watch_flags} --interval"
  [ -n "$watch_iters" ] && _watch_flags="${_watch_flags} --iterations"
  [ -n "$watch_max" ] && _watch_flags="${_watch_flags} --max-wait"
  [ -n "$watch_expect" ] && _watch_flags="${_watch_flags} --expect"
  [ -n "$watch_kind" ] && _watch_flags="${_watch_flags} --kind"
  if [ -n "$_watch_flags" ] && [ "$mode" != "--watch" ]; then
    echo "{\"ok\":false,\"error\":\"--interval/--iterations/--max-wait/--expect/--kind 仅与 --watch 同用\",\"mode\":\"$mode\",\"flags\":\"${_watch_flags# }\",\"exit_code\":2}"
    return 2
  fi

  # F4（2026-10-15）：通用进度探测出口（coder/质询 共用）—— 0-API 只读；接收裁决**复用**
  #   `gk_receive_check`（见共享模块 `gk_dispatch_watch.py`，**禁第二实现**）。挂既有 `monitor`
  #   ⟹ 零新增 `_CMD_REG`（`_CMD_REG` 在 PROTECTED_REGION::gate 内）。**不写 state / 不派发**。
  if [ "$mode" = "--watch" ]; then
    [ -n "$stage" ] || { echo '{"ok":false,"error":"watch target required","exit_code":2,"usage":"monitor --watch <pr-*|12hex|worktree> [--kind auto|pipeline|aggregation|worktree] [--expect N] [--interval S] [--iterations N] [--max-wait S]"}'; return 2; }
    local _w_out _w_rc
    _w_out=$(python3 "$SKILL_DIR/scripts/gk_dispatch_watch.py" \
      --state "$STATE_FILE" --target "$stage" \
      --kind "${watch_kind:-auto}" \
      --interval "${watch_interval:-10}" \
      --iterations "${watch_iters:-0}" \
      --max-wait "${watch_max:-1800}" \
      --expect "${watch_expect:-0}" \
      --skill-dir "$SKILL_DIR" 2>>"$GK_DBG_LOG")
    _w_rc=$?
    printf '%s\n' "$_w_out"
    return "$_w_rc"
  fi

  # G1（2026-10-03）：批身份 env 注入（仅非空时；空 ⟹ 落 payload 的 f(plan,桶) 兜底，零回归）。
  [ -n "$batch_plan" ] && export GK_BATCH_PLAN="$batch_plan"
  [ -n "$batch_narrow" ] && export GK_BATCH_NARROW="$batch_narrow"
  [ -n "$batch_epoch" ] && export GK_BATCH_EPOCH="$batch_epoch"
  # §18.3（2026-10-04）：组别 env 注入（仅非空时；空 ⟹ 落库 arm_group 空串 = UNKNOWN，不猜）。
  [ -n "$arm_group" ] && export GK_ARM_GROUP="$arm_group"
  # W2A-P2（2026-10-16）：消融腿 Δ env 注入（仅非空时；空 ⟹ 落库 arm_delta 空串 = UNKNOWN）。
  [ -n "$arm_delta" ] && export GK_ARM_DELTA="$arm_delta"

  # L1 自动派发（2026-09-23 用户裁定「next 可直接执行」）：窄任务从文件读入，**fail-loud**——
  # 原先 `next` 串尾部是字面量 `<narrow-task>`，须人工把长窄任务拼进命令行（引号/换行/中文标点
  # 全是雷；`cmd_apply_worktree --code-fix` 现自动写盘并回填此 flag）。三条拒绝：
  # ① 非 --subagent（否则文件内容会被当 **stage** 去查 schema，静默走错分支）
  # ② 文件不存在 ③ 文件为空 —— 均 exit 2，禁静默降级（对齐本命令既有的 fail-loud 惯例）。
  if [ -n "$task_file" ]; then
    [ "$mode" = "--subagent" ] || { echo "{\"ok\":false,\"error\":\"--task-file 仅与 --subagent 同用\",\"mode\":\"$mode\"}"; return 2; }
    [ -f "$task_file" ] || { echo "{\"ok\":false,\"error\":\"--task-file 不存在\",\"path\":\"$task_file\"}"; return 2; }
    stage=$(cat "$task_file" 2>/dev/null || echo "")
    [ -n "$stage" ] || { echo "{\"ok\":false,\"error\":\"--task-file 为空\",\"path\":\"$task_file\"}"; return 2; }
  fi

  # F-REV-11 C2 (2026-09-10)：--role 白名单校验（与 subagent_runner.ROLE_ALLOWED_REGIONS 同集；
  # 一致性由 test_subagent_runner_extract.TestCliMonitorRoleWiring 断言守护）——非法角色
  # fail-loud exit 2（禁静默降级：subagent_runner 对未知角色会回落 reporter 区，静默收敛不可接受）。
  if [ -n "$role_override" ]; then
    case "$role_override" in
      default|plan-refinement|scanner|exploiter|auditor|reporter|coder|venue-prior-art) ;;
      *) echo "{\"ok\":false,\"error\":\"unknown role '$role_override'\",\"valid\":\"default|plan-refinement|scanner|exploiter|auditor|reporter|coder|venue-prior-art\"}"; return 2 ;;
    esac
  fi

  # 2026-09-26（ECC-835E2928497D D 侧 · coder **加载安全网**，对齐
  # references/plugin-loading-test-framework.md §1）：`--role coder` 的唯一落刀能力 = `edit`
  #   → 入口 `gk_agent_family.load_family(<family>)`。族脚手架（references/agent-families/*.json）
  #   缺失/不可解析时，`load_family` 只在 coder **首次 edit 调用**才 FamilyError，且失败只回给
  #   agent ⟹ 表现「零落刀 + 报告像在分析」= §1 三失败模式的**漏加载静默**（协议红线：漏/误/错
  #   加载必须显式报告）。故设**派发前置闸**：位置 = 角色白名单之后、所有 `--subagent` 机制与
  #   **任何 LLM 派发之前**；脚手架不可加载 ⟹ `CODER_SCAFFOLD_MISSING` fail-loud（不静默降级）。
  #   ⚠ 只对 `--role coder` 生效（其余角色无 edit 能力，不受族脚手架约束 ⟹ 零回归）。
  if [ "$mode" = "--subagent" ] && [ "$role_override" = "coder" ]; then
    local _scaf_out _scaf_rc
    _scaf_out=$(python3 "${SKILL_DIR}/scripts/gk_agent_family.py" scaffold-status 2>&1); _scaf_rc=$?
    if [ "$_scaf_rc" -ne 0 ]; then
      local _scaf_json
      _scaf_json=$(printf '%s' "$_scaf_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --limit 400 2>/dev/null || echo '""')
      echo "{\"ok\":false,\"error\":\"CODER_SCAFFOLD_MISSING\",\"detail\":$_scaf_json,\"hint\":\"修 references/agent-families/（或 GK_AGENT_FAMILIES_DIR）后重派；派发前置闸按 plugin-loading §1 禁静默降级\"}"
      return 2
    fi
  fi

  [ -z "$stage" ] && [ "$mode" != "--align" ] && [ "$mode" != "--subagent" ] && { echo '{"error":"stage required"}'; return 1; }
  [ -z "$(_canon_schema_path "$stage" 2>/dev/null || true)" ] && [ "$mode" != "--gitnexus" ] && [ "$mode" != "--align" ] && [ "$mode" != "--subagent" ] && { echo "{\"error\":\"no schema for $stage\"}"; return 1; }

  local worktree branch cur_stage
  worktree=$(json_val "$STATE_FILE" worktree "" 2>/dev/null || echo "")
  branch=$(json_val "$STATE_FILE" branch "" 2>/dev/null || echo "")
  cur_stage=$(json_val "$STATE_FILE" stage "IDLE")

  if [ "$mode" = "--api" ]; then
    # bridge v4.18: auto-resolve key cross WSL boundary
    [ -z "$api_key" ] && { _resolve_api_key; api_key="$API_KEY"; }
    # W10 (2026-08-09): api-key 有效性预检 — 显式 --api-key 传错值 → 401（本次会话教训）
    if ! _validate_api_key "$api_key"; then
      echo '{"warning":"api-key invalid (W10), auto re-resolving","hint":"fix: remove --api-key or check its value"}' >&2
      API_KEY=""
      _resolve_api_key && api_key="$API_KEY"
    fi
    _monitor_api "$stage" "$api_key" "$worktree" "$branch"
    return $?
  fi

  if [ "$mode" = "--gitnexus" ]; then
    # GitNexus optimizer: run analyze + context + impact + query + detect-changes
    # via Windows Node.js (from WSL → powershell.exe). WSL Node v12 too old.
    local gn_raw gn_nodes gn_edges gn_clusters gn_flows
    local gn_context gn_impact gn_query gn_detect
    # 2026-11-01（owner 裁定「禁第二实现」）：原为裸 `_run_gitnexus analyze` ⟹ 绕过
    #   `_gx_analyze_embeddings` 的单飞/残态守卫（L2529 明文禁直调）。现收口到单一事实源，
    #   并经 GK_GX_KEEP_STDOUT 保留 stdout 供本处解析节点/边统计。
    local _gn_dir="${worktree:-$PWD}" _gn_outf
    _gn_outf=$(mktemp 2>/dev/null || echo /dev/null)
    GK_GX_KEEP_STDOUT="$_gn_outf" _gx_analyze_embeddings "$_gn_dir" >/dev/null 2>&1 || true
    gn_raw=$(cat "$_gn_outf" 2>/dev/null) || gn_raw=""
    [ "$_gn_outf" = "/dev/null" ] || rm -f "$_gn_outf" 2>/dev/null || true
    # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
    if echo "$gn_raw" | "$RG" -q "Repository indexed successfully"; then
      # Use Windows rg (has PCRE2) instead of WSL rg (no PCRE2)
      local _win_rg="/mnt/d/Program Files (x86)/Trae CN/resources/app/node_modules/@vscode/ripgrep/bin/rg.exe"
      [ ! -f "$_win_rg" ] && _win_rg="rg"  # fallback to whatever rg is available
      gn_nodes=$(echo "$gn_raw" | "$_win_rg" -oP '[\d,]+(?=\s+nodes)' 2>/dev/null | tr -d ',' || echo "unavailable")
      gn_edges=$(echo "$gn_raw" | "$_win_rg" -oP '[\d,]+(?=\s+edges)' 2>/dev/null | tr -d ',' || echo "unavailable")
      gn_clusters=$(echo "$gn_raw" | "$_win_rg" -oP '[\d,]+(?=\s+clusters)' 2>/dev/null | tr -d ',' || echo "unavailable")
      gn_flows=$(echo "$gn_raw" | "$_win_rg" -oP '[\d,]+(?=\s+flows)' 2>/dev/null | tr -d ',' || echo "unavailable")
    else
      gn_nodes="unavailable"; gn_edges="unavailable"; gn_clusters="unavailable"; gn_flows="unavailable"
    fi
    # F-REV-71（2026-09-16）：repo 名**单源推导**（与上方 `analyze`、下方 `detect-changes` 同源）
    #   原况：context 硬编码技能名、impact/query 硬编码 `spz_gatekeeper`（**不在 registry** ⟹ 恒空）。
    local _mrepo; _mrepo=$(_gx_repo_name_for_dir "$(_gx_repo_dir_for_current)")
    # context — 360° 调用图
    gn_context=$(_run_gitnexus context -r "$_mrepo" advance_dispatch 2>/dev/null | head -10 || echo "unavailable")
    # impact — 爆破半径
    gn_impact=$(_run_gitnexus impact -r "$_mrepo" advance_dispatch 2>/dev/null | head -10 || echo "unavailable")
    # query — 语义搜索
    gn_query=$(_run_gitnexus query -r "$_mrepo" "dead code|escape|bypass" 2>/dev/null | head -10 || echo "unavailable")
    # detect-changes — 变更符号级影响
    gn_detect=$(_run_gitnexus detect-changes --repo "$_mrepo" --scope compare --base-ref HEAD~1 2>/dev/null | head -10 || echo "unavailable")
    local gn_json="{\"nodes\":\"$gn_nodes\",\"edges\":\"$gn_edges\",\"clusters\":\"$gn_clusters\",\"flows\":\"$gn_flows\",\"context\":$(echo "$gn_context" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --strip 2>/dev/null || echo '\"\"'),\"impact\":$(echo "$gn_impact" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --strip 2>/dev/null || echo '\"\"'),\"query\":$(echo "$gn_query" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --strip 2>/dev/null || echo '\"\"'),\"detect\":$(echo "$gn_detect" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --strip 2>/dev/null || echo '\"\"'),\"stage\":\"$stage\",\"timestamp\":\"$(date -Iseconds)\"}"
    # f1（ECC-3D26D689A05F，2026-09-22 实测）：原为**裸 `json.dump` 直写** `$STATE_FILE` ——
    # 既不进 `_state_write` 单一写入口（**无 flock**，与并发写者抢写），也**不重算 `_checksum`**
    # ⟹ 下一个读者（self-check 的 checksum 校验）把「本命令自己刚写的 state」判成 TAMPERED
    # （隔离复现实测：该命令后 saved 校验和 ≠ 按 gate_data 重算的 canon 值，直到下一个写者
    # `monitor --local` 落盘才纠回）。出口 = 走 `_state_write`（flock + 原子写 + checksum 重算），
    # 且载荷经 **env** 传入（`$gn_json` 内含引号/反斜杠，不得拼进 python 源码）。
    GN_JSON="$gn_json" _state_write "
import json as _json, os as _os
d.setdefault('gate_data', {})['gitnexus'] = _json.loads(_os.environ.get('GN_JSON') or '{}')
" >/dev/null 2>&1 || true
    echo "$gn_json"
    return 0
  fi

  if [ "$mode" = "--align" ]; then
    # F-REV-42 H1（2026-09-13 更正；用户"这不是合并进 doc--align 了吗？这都是个独立插件了"）：
    # `--align` 原为**独立内联实现（11 项）**，但自 b6fe907（2026-09-01 "monitor --align 收敛"）
    # 起文档已统一指向 doc-align 插件（gk_doc_align.py = 升格实现），**代码却未同步** ⇒ 双源漂移。
    # 现**完成收敛**：直接委托 doc-align 插件（单一实现，含 check_doc_freshness/check_audit_docs_merged 等
    # 23 项），不再维护第二份检查器。L9 三态 + 自动 E2 register 已按其文档/家族名（MONITOR-LOCAL）
    # **原位归入 `monitor --local`**（见该分支 L9 段）。
    cmd_doc_align
    return $?
  fi

  # --- SUBAGENT MODE: constrained review agent (openai-agents SDK) ---
  # T43+++: shared infra (_resolve_provider_config + _resolve_api_key + fallback)
  # Python: configurable via SUAGENT_PYTHON env var (defaults to python3)
  #         e.g. export SUAGENT_PYTHON=<home>/.codex/venv/Scripts/python.exe
  # Activated: "研究/分析任务, 需要跨仓库搜索但不需要完整评分"
  # Output: {"conclusion":"...","evidence":[...],"confidence":"high|medium|low","tools_used":[...],"guardrail":"passed"}
  if [ "$mode" = "--subagent" ]; then
    local task="${stage:-}"
    [ -z "$task" ] && { echo '{"error":"--subagent requires a task argument"}' ; return 1; }
    [ -z "$api_key" ] && { _resolve_api_key; api_key="$API_KEY"; }
    # W10 (2026-08-09): api-key 有效性预检 — 显式 --api-key 传错值 → 401（本次会话教训）
    if ! _validate_api_key "$api_key"; then
      echo '{"warning":"api-key invalid (W10), auto re-resolving","hint":"fix: remove --api-key or check its value"}' >&2
      API_KEY=""
      _resolve_api_key && api_key="$API_KEY"
    fi
    _resolve_provider_config
    # 2026-09-08 F-REV-1 (ECC-8A07DDAD64ED): subagent 默认运行环境 = suagent_py311.sh
    # （python311 + openai-agents 0.22.x，实测 DeepSeek tool_calls 正常）；venv 0.17.6
    # 触发 400 请求体缺陷 → 不再裸默认 python3。SUAGENT_PYTHON 显式设置优先。
    local subagent_python="${SUAGENT_PYTHON:-}"
    if [ -z "$subagent_python" ]; then
      # 2026-09-23（ECC-6C0742C3BC90）：fix 档须与门禁 CLI **同源解释器**（`edit_gk` 用
      #   `os.path.realpath()` 解析 worktree 路径；Windows python311 只转命令行 `/mnt/*`，
      #   不转工具调用内路径 ⟹ `guard-edit` 恒拒）。
      # 2026-10-14（owner 裁定）：默认档切到**隔离 venv**（免受全局 site-packages 升级波及）。
      # 2026-11-01（公开前提）：**去绝对硬编码** —— 隔离 venv 是机器属性（他机无 `/opt/…`、
      #   Windows 侧另有同级 venv），写进源码 = 开源即炸。改委托 `scripts/py_resolve.sh`
      #   （env → 本机 pin `_accept_py.local` → 仓内 .venv → `GK_PY_GLOBS` 通配 → PATH），
      #   两台机器的 venv 由此**同级并列**，谁在位用谁。
      subagent_python=$(bash "${SKILL_DIR}/scripts/py_resolve.sh" subagent 2>/dev/null \
                        || bash "${SKILL_DIR}/scripts/py_resolve.sh" any 2>/dev/null || true)
      [ -n "$subagent_python" ] || subagent_python="python3"
    fi
    # A 沙箱接线（2026-10-16，owner 裁定「沙箱面向所有 subagent」「全接」）：把解释器包进
    #   `gk_sandbox`（单进程 mem/time/proc 硬上限），与 hub 准入（gk_hub_scheduler）互补。
    #   **单源**：仅改此变量，一处即覆盖全部 runner 调用点（下方 cmd_monitor 的三处派发）。
    #   真实解释器经 `GK_SUBAGENT_PY_REAL` 透传。
    #   逃生舱 `GK_SANDBOX_SUBAGENT=0` ⟹ 直连解释器（与 HEAD 逐字一致，零回归）。
    if [ "${GK_SANDBOX_SUBAGENT:-1}" != "0" ]; then
      if [ -x "${SKILL_DIR}/scripts/suagent_sandbox.sh" ]; then
        export GK_SUBAGENT_PY_REAL="$subagent_python"
        subagent_python="${SKILL_DIR}/scripts/suagent_sandbox.sh"
      elif [ "${GK_SANDBOX_FAIL_OPEN:-0}" != "1" ]; then
        # 2026-10-31：静默降级 → fail-closed（与 `_subagent_exec` 同判据）
        echo '{"ok":false,"error":"SANDBOX_WRAPPER_MISSING","hint":"scripts/suagent_sandbox.sh 不可执行；修脚本，或显式 GK_SANDBOX_SUBAGENT=0 / GK_SANDBOX_FAIL_OPEN=1"}' >&2
        return 2
      else
        echo "WARN[sandbox] wrapper missing → unsandboxed（GK_SANDBOX_FAIL_OPEN=1）" >> "$GK_DBG_LOG"
      fi
    fi
    # P1 消费层 export（2026-09-08，f0a3131/㊴ kept 实装）：探测唯一在 bash _gx_node_probe →
    # 注入 GX_NODE/GX_JS 供 subagent_runner 只消费（禁 python 自探测）。形态随运行环境：
    # suagent_py311.sh / *.exe = Windows python → win 形态；python3 = WSL → wsl 形态。
    # ⚠ 返回值 1 = 图能力不可用（fail-loud 已 WARN 到 stderr）⟹ 此处 `|| true` 保证不中断派发，
    #   但**不掩盖**：subagent 侧 `_gitnexus_cmd` 见 env 缺失即返回 [ERROR]（可留痕/可机检）。
    case "$subagent_python" in
      *.exe|*/suagent_py311.sh) _gx_subagent_gx_env win || true ;;
      *) _gx_subagent_gx_env wsl || true ;;
    esac
    # F-REV-91（2026-09-16，tier3 真实冒烟实测发现）：**WSL interop 只传递 `WSLENV` 白名单内的
    #   变量**给 Windows 进程；而 subagent 默认解释器 `suagent_py311.sh` 直接 `exec` Windows
    #   `python.exe` ⟹ 本处 bash 的 `export` 对 GX_*/GK_*/SUBAGENT_* **全被静默丢弃**。
    #   实测（Windows python 读回值）：普通 export → `GX_NODE` = None；并入白名单 → 可见。
    #   ⚠ 标志位语义与本能使然的直觉**相反**（同机实测矩阵）：裸名 `GXT` → 原值；
    #     `GXT/u` → **None（被丢弃）**；`GXT/p` → `D;\Program Files\…`（**路径被二次翻译而破坏**）；
    #     `GXT/w` → 原值。故此处**一律裸名**（值已是 Windows 形态，禁 `/p` 禁 `/u`）。
    #   同因还波及 `GATEKEEPER_HMAC_KEY`（= 既有 `unsigned_no_hmac` 症状）与 L0/L3/门 证据注入。
    #   ⚠ 只并入**当前非空**的键 —— 空串进白名单会让 runner 的 `os.environ.get(k, 默认)`
    #   见「存在但空」而**不回落到默认值**（如 `SUBAGENT_ID` 会变空串）。
    # ECC-AFC678CA168B（2026-09-28，用户指令「登记并修复」）：**WSLENV 并入循环原在此处 = 错位** ——
    #   它跑在所有待传变量赋值**之前**（SUBAGENT_ROLE 3593/3803、SUBAGENT_ID 仅以 env prefix 传递、
    #   GK_L0/L3/GATE_EVIDENCE 3739/3751/3769 均在其后），而循环用 `declare -p` 作存在性守卫
    #   ⟹ 这些键**永不入白名单** ⟹ Windows python（suagent_py311.sh → python.exe）侧全为 None。
    #   实测（忠实探针，跨 interop 边界）：SUBAGENT_ROLE=None / SUBAGENT_ID=None /
    #   GK_GATE_EVIDENCE_len=0 / GK_L3_EVIDENCE_len=0；WSLENV 仅含
    #   GX_NODE:GX_JS:GX_REPO:GATEKEEPER_HMAC_KEY。后果 = F-REV-91「半修」：crossfull postR/L2/红队
    #   LLM 车道 role 落 default → 读不到 gatekeeper-cli.sh（gate 区）→ 盲审 + 结论失真。
    #   现**下移至派发前**（见下方「派发前 env 收敛 + WSLENV 并入」段，含显式 export）。
    #   ⚠ 定位契约：test_eco_integration._WSLENV_BLOCK_RE 按 `    for _k in GX_NODE … \n    export WSLENV`
    #     定位该块 ⟹ 下移后缩进须保持 4 空格（改名/结构变更时本测试同批改）。
    # Named subagent modes — preset tools + max_turns
    # 4 RED subagents: scanner, exploiter, auditor, reporter
    # All use the full infrastructure from spz-gatekeeper-r-sequence skill flow
    # ── F-REV-100（2026-09-17 落刀）：per-role 工具清单**整体移除** ──
    # 工具面的**单一事实源** = runner 侧 `ROLE_TOOLS[role]`（次序 A：显式 --tools / 逃生位
    # > 角色表 > 档位阶梯）。原此处 6 处赋值（本默认值 + 4 个 RED case + crossrev/plan-refinement）
    # 在命名角色下**100% 不生效**（被 runner 的 `--tier` 无条件覆盖），却制造「看似已配权限」的假象
    # ⟹ 红队四角色拿不到 `state`/`audit`/… 反而拿到 `read_repo`/`json_*`。本处只留「用户显式覆盖口」。
    # 逃生位名**统一**为 `SUBAGENT_TOOLS`；旧名 `SUAGENT_TOOLS`（拼写缺 B）出 WARN 后按前者语义处理。
    if [ -n "${SUAGENT_TOOLS:-}" ]; then
      echo "[WARN] SUAGENT_TOOLS 已废弃（拼写缺 B）—— 请改用 SUBAGENT_TOOLS" >&2
      SUBAGENT_TOOLS="${SUBAGENT_TOOLS:-$SUAGENT_TOOLS}"
    fi
    local subagent_tools="${user_tools:-}"
    # ── 预算单源（2026-09-25 端到端实测裁定，ECC-A42C0B995E10）──────────────
    # 档位与预算的**唯一事实源** = runner `SUBA_TIERS[tier]`；CLI 侧只传 `--tier`
    # （角色 → tier 经 `export SUBAGENT_TIER`，见本函数下方 role case，含兜底臂）。
    # CLI 原先另存的三参（轮次 / L2 token 总预算 / L3 item 预算 = turns×工具调用合并）
    # 为**死参**：runner 的 tier 块无条件覆盖轮次、且在对应 env 未设时覆盖 token/item，
    # 而 CLI 从不 export 该 env ⟹ 三参与 runner 实际取值脱钩（实测 argv 传三参、
    # runner 产物 token_usage 仍为档位值）。故三参声明与下发整段删除，
    # 防「双源漂移 / 死参制造已配预算假象」复现（先例：F-REV-100 工具面同款收敛）。
    # 思考强度不调整：DS_REASONING_EFFORT 全开最大（用户确认），runner 侧 fallback 保持 high。
    local subagent_soft_ratio="${SUBAGENT_SOFT_RATIO:-0.8}"
    local subagent_mode_set=false
    case "$task" in
      red-scanner|RED-SCOPE)
        task="RED-SCOPE: 红队扫描 — run self-check, audit --state, gitnexus analyze/context/impact to map attack surface; 外部情报用 red_search/red_fetch（只读、禁下载、漏洞库须 GK_RED_INTEL_SANDBOX=1）"
        subagent_mode_set=true ;;
      red-exploiter|RED-EXPLOIT)
        task="RED-EXPLOIT: 红队渗透 — test escape paths: advance bypass, --force abuse, cross-plan injection, state tamper, guard-edit bypass; 情报研究用 red_search/red_fetch，任何复现实验只在 KVM 沙箱内跑"
        subagent_mode_set=true ;;
      red-auditor|RED-POSTEX)
        task="RED-POSTEX: 红队审计 — run reflect, self-check, audit --state replay, gitnexus query/detect-changes for dead code + optimizer gaps; 对照外部基线用 red_search/red_fetch（只读）"
        subagent_mode_set=true ;;
      red-reporter|RED-REPORT)
        task="RED-REPORT: 红队报告 — collect findings from state/gate_data, generate signed ECC-REDTEAM report via audit --report --type redteam"
        subagent_mode_set=true ;;
      *) ;;  # free-text task, use defaults
    esac
    # Validate tools against registry — 2026-08-07 与 subagent_runner.py TOOL_REGISTRY 同步
    # （补 read_bridge + gx_* 细分 + 门禁直通；两处名单须一致）
    # 2026-09-23（F7 基座 T7）：行尾追加 `,edit`（只增不改既有项）。本行**不在**任何
    # PROTECTED_REGION 内（实测 guard-edit 行级检查 allowed/clear）—— 与本区外的
    # `subagent_runner.TOOL_REGISTRY` 必须同批改，否则 self-check `tool_config` 对齐项红。
    local valid_tools="read,read_repo,gitnexus,gx_context,gx_impact,gx_query,gx_detect_changes,gx_trace,gx_guide,ci-diagnose,code_search,web_search,web_fetch,openreview_search,arxiv_search,red_search,red_fetch,read_doc,json_extract,json_read,json_write,state,self-check,advance,audit,guard-edit,reflect,edit"
    local IFS=','
    for t in $subagent_tools; do
      # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 /usr/bin/rg）
      echo ",$valid_tools," | "$RG" -q ",$t," || { echo "{\"error\":\"unknown tool: $t. Valid: $valid_tools\"}"; return 1; }
    done
    # B4 fix (2026-08-08): local IFS=',' 作用域覆盖整个 cmd_monitor 函数，
    # for 循环后未恢复 → 后续未加引号的 $mode_flag（含空格）按逗号分割失败，
    # '--mode plan-refinement' 变成单参数 → argparse 未知参数 → exit 2。
    IFS=$' \t\n'
    # （2026-09-25）free-text 轮次启发式（task_count × 10）已整体移除：
    # 轮次/预算单源 = runner 档位表（档位由上方 role case 的 `export SUBAGENT_TIER` 决定）。
    local subagent_runner="${SKILL_DIR}/scripts/subagent_runner.py"
    [ ! -f "$subagent_runner" ] && { echo '{"error":"subagent runner not found: '$subagent_runner'"}'; return 1; }

    # Verify context signature before injection (Ed25519, context key). Skip --inject-context if invalid.
    # 2026-08-12 调用点修复：subagent-context.json 由 _sign_raw 用 context 私钥签名（高频 24h 轮换），
    # 必须用 _CONTEXT_PUB_KEY 验证（与 context 显示命令 L5768 同逻辑）。
    # 不复用 _verify_raw——那是 audit 验证器（audit 公钥验 context 签名必然失败），
    # 且审计/上下文两套密钥必须保持隔离，不允许混用。
    local ctx_file="${SKILL_DIR}/references/subagent-context.json"
    local ctx_sig="${ctx_file}.sig"
    local inject_flag="" ctx_inject_ok=true ctx_inject_reason=""
    # F-REV-79（2026-09-16，用户裁定）：**自愈前置门** —— 判定失败时先自动 `context --update`
    # （含重签）再**复验**（同一单点判定 `_ctx_inject_probe`，不引入第二事实源）：
    #   过 → 正常注入（消除"阻断 + 请手动 context --update"的摩擦税）；
    #   不过 → 仍标 ctx_inject_ok=false（**fail-closed 语义不变**，交 preflight A 阻断）。
    # 只自愈**一次**（不循环）；GK_NO_CTX_SELFHEAL=1 可整体关闭（回到原直判行为）。
    local _probe; _probe=$(_ctx_inject_probe "$ctx_file" "$ctx_sig")
    # 2026-10-30（签名竞态修复 ②）：写者可能刚 publish 完 JSON、.sig 还在 rename 途中（毫秒级窗口）
    #   ⟹ 先退避 100ms **重探一次**，避免把瞬时窗口误判成「需要自愈」。
    if [ "$_probe" != "ok" ]; then
      sleep 0.1
      _probe=$(_ctx_inject_probe "$ctx_file" "$ctx_sig")
    fi
    if [ "$_probe" != "ok" ] && [ "${GK_NO_CTX_SELFHEAL:-0}" != "1" ]; then
      # ③ 单飞（2026-10-30）：6 臂并发时**只让一个臂**跑 update，其余等它完成后复验 ——
      #   原实现 6 臂各跑一次 update 并发写同一对文件 = 互相覆盖、`self-heal result: sig_invalid` 连爆。
      local _heal_fd="" _healer=1
      if command -v flock >/dev/null 2>&1; then
        exec {_heal_fd}>"${ctx_file}.heal" 2>/dev/null || _heal_fd=""
        if [ -n "$_heal_fd" ] && ! flock -n "$_heal_fd" 2>/dev/null; then _healer=0; fi
      fi
      if [ "$_healer" = "1" ]; then
        echo "[ctx-inject] self-heal ($_probe) → context --update $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
        bash "$SKILL_DIR/gatekeeper-cli.sh" context --update >>"$GK_DBG_LOG" 2>&1 || true
      else
        echo "[ctx-inject] self-heal wait ($_probe) — 另一臂正在 update $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
        local _w=0
        while [ "$_w" -lt 40 ]; do
          sleep 0.5; _w=$((_w + 1))
          _probe=$(_ctx_inject_probe "$ctx_file" "$ctx_sig")
          [ "$_probe" = "ok" ] && break
        done
      fi
      _probe=$(_ctx_inject_probe "$ctx_file" "$ctx_sig")
      echo "[ctx-inject] self-heal result: $_probe $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
      if [ -n "$_heal_fd" ]; then flock -u "$_heal_fd" 2>/dev/null || true; eval "exec ${_heal_fd}>&-"; fi
    fi
    if [ "$_probe" = "ok" ]; then
      inject_flag="--inject-context"
    else
      case "$_probe" in
        sig_invalid)
          # A1 (2026-09-04): 签名失效 → 显式 WARN + GK_DBG_LOG + fix 引导（禁静默 skip——空白/机械性审查根因之一）。
          ctx_inject_ok=false; ctx_inject_reason="sig_invalid"
          echo '{"warning":"context signature invalid — skipping context injection (A1 禁静默 skip)","severity":"review_block_candidate","ctx_file":"'"$ctx_file"'","fix":"bash gatekeeper-cli.sh context --update"}' >&2
          echo "[ctx-inject] invalid signature — skipping injection ($ctx_file) $(date -u +%FT%TZ)" >> "$GK_DBG_LOG" ;;
        sig_missing)
          # A1: 上下文文件未签名（注入面）→ 显式 WARN + 留痕（review 通道在 preflight 硬阻断）。
          ctx_inject_ok=false; ctx_inject_reason="sig_missing"
          echo '{"warning":"context file unsigned — skipping context injection (A1 禁静默 skip)","severity":"review_block_candidate","ctx_file":"'"$ctx_file"'","fix":"bash gatekeeper-cli.sh context --update"}' >&2
          echo "[ctx-inject] unsigned context file — skipping injection ($ctx_file) $(date -u +%FT%TZ)" >> "$GK_DBG_LOG" ;;
        ctx_missing_orphan_sig)
          # F-REV-24 细分（R2 MoA 质询 2026-09-11）：ctx 缺 + **孤儿 .sig**（无 ctx 的签名）→ 运维动作
          # 不同（清理孤儿签名 vs context --update），原 else 把两态压平共用 ctx_missing 致诊断信息损失。
          ctx_inject_ok=false; ctx_inject_reason="ctx_missing_orphan_sig"
          echo '{"warning":"context file missing but orphan .sig present — no context injection (F-REV-24)","severity":"review_block_candidate","ctx_file":"'"$ctx_file"'","ctx_sig":"'"$ctx_sig"'","fix":"删除孤儿 references/subagent-context.json.sig 或 bash gatekeeper-cli.sh context --update"}' >&2
          echo "[ctx-inject] ctx missing + orphan sig — no injection ($ctx_file) $(date -u +%FT%TZ)" >> "$GK_DBG_LOG" ;;
        *)
          # F-REV-24 (2026-09-11): ctx 文件**整体缺失**（且无孤儿签名）→ 此前两条分支都不命中 ⇒ 静默放行
          # （inject_flag 空、ctx_inject_ok 保持 true：既不注入也不阻断），与 A1"禁静默 skip"意图相悖；
          # 且该组合实测会让审查通道**无上下文注入仍照常下发**（另一会话占位任务误派发 ~166k token）。
          # 现显式标记 ctx_missing → preflight A 硬阻断（CONTEXT_MISSING；GK_ALLOW_STALE_CTX=1 仍可降级——
          # 注：该开关名只表 stale，现值收紧后亦授权 missing（语义扩容），见 plan F-REV-24 追记）。
          ctx_inject_ok=false; ctx_inject_reason="ctx_missing"
          echo '{"warning":"context file missing — no context injection (F-REV-24 禁静默放行)","severity":"review_block_candidate","ctx_file":"'"$ctx_file"'","fix":"bash gatekeeper-cli.sh context --update"}' >&2
          echo "[ctx-inject] context file missing — no injection ($ctx_file) $(date -u +%FT%TZ)" >> "$GK_DBG_LOG" ;;
      esac
    fi

    # Generate unique subagent_id for audit trail
    local subagent_id="sub-$(date +%s)-$$-${RANDOM}"
    # R5: Derive SUBAGENT_ROLE from task name + mode
    local subagent_role="default"
    if $subagent_mode_set; then
      case "$task" in
        RED-SCOPE:*) subagent_role="scanner" ;;
        RED-EXPLOIT:*) subagent_role="exploiter" ;;
        RED-POSTEX:*) subagent_role="auditor" ;;
        RED-REPORT:*) subagent_role="reporter" ;;
      esac
    fi
    # Plan-refinement subagents get plan-refinement role
    # F-REV-21 (2026-09-10)：cmd_plan_refinement 现已**显式**传 --role plan-refinement
    # （见其裁决下发出口）。
    # 2026-10-01（ECC-FAB556F786E5）：原「task 子串含 plan-refinement ⟹ **静默升级**为质询角色」
    #   有两处硬伤 —— ① **假阳**（任务文本偶然含该词即被升进高权通道）；② 更致命：审查通道门禁
    #   `_review_channel_preflight` 的 **arm 条件就是** `subagent_role == plan-refinement`
    #   ⟹「角色靠猜、门禁靠角色」= **循环**，猜错时门禁根本不举（实测臂 A：任务串写成
    #   「质询臂A(域化范围)：…」→ 落 default → verdicts/seven_dim 全空却仍套质询报告模板）。
    #   现改：**禁猜进质询通道** —— 命中该子串而**无显式 --role** ⟹ fail-loud，要求走统一入口
    #   `plan-refinement <plan> --task … → --adjudicate last --decision approve`（其下发出口
    #   显式带 --role plan-refinement）。
    # 2026-10-05（用户令「堵上裸跑质询裸窄任务通道」）：原「逃生 = 显式 `--role plan-refinement`」
    #   = **绕过统一入口的裸跑洞**（本轮两臂即裸任务下发 ⟹ moa-aggregate 归属失据、被过滤）。
    #   现**收回逃生**：显式 `--role plan-refinement` 必须是 pipeline 产出的 `full_task`
    #   （∈ gate_data.task_pipeline[]），否则 BARE_PLAN_REFINEMENT 拦截。
    #   single-source = `gk_task_gate.task_in_pipeline`（禁 bash 侧第二份解析）。
    # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
    if [ "$role_override" = "plan-refinement" ]; then
      local _san_ok
      # 2026-11-01（跨平台修复）：原 sys.path 用 bash 插值 SKILL_DIR（裸美元形态进 python 字符串）
      #   —— Git Bash(MSYS) 下 SKILL_DIR 是 /c/Users/... 形态，MSYS 只对 env 传递做 /c/→C:/ 转换、
      #   对字符串插值不转 ⟹ Windows python 收到非法路径 ⟹ ModuleNotFoundError: gk_task_gate
      #   ⟹ _san_ok=false ⟹ fail-closed BARE_PLAN_REFINEMENT（WSL 下 /mnt/c 合法 ⟹ 从未暴露）。
      #   改 env 单源（os.environ 取值，同 L5508/9377 既有惯例）：
      _san_ok=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" STATE_FILE="$(_gk_py_path "$STATE_FILE")" GK_PR_TASK="$task" python3 -c "
import os,sys
sys.path.insert(0, os.path.join(os.environ['SKILL_DIR'], 'scripts'))
from gk_task_gate import task_in_pipeline
print('true' if task_in_pipeline(os.environ.get('STATE_FILE',''), os.environ.get('GK_PR_TASK','')) else 'false')
" 2>>"$GK_DBG_LOG") || _san_ok="false"
      if [ "$_san_ok" != "true" ]; then
        echo "{\"ok\":false,\"error\":\"BARE_PLAN_REFINEMENT\",\"channel\":\"plan-refinement\",\"hint\":\"质询须走统一入口 plan-refinement <plan> --task … → --adjudicate last --decision approve（禁裸 --role plan-refinement）\"}"
        return 2
      fi
    elif [ -z "$role_override" ] && echo "$task" | "$RG" -q "plan-refinement"; then
      echo "{\"ok\":false,\"error\":\"REVIEW_ROLE_UNSPECIFIED\",\"channel\":\"plan-refinement\",\"hint\":\"疑似质询任务但未显式指定角色 —— 走统一入口 plan-refinement <plan> --task … → --adjudicate last --decision approve，或显式 --role plan-refinement\"}"
      return 2
    fi
    # F-REV-11 C2 (2026-09-10)：显式 --role 覆盖自动推导。L2 --crossrev / 后R 双独立此前
    # 既无 RED-* 前缀亦无 plan-refinement 标记 → 落 default（[evidence]）→ read_repo 读
    # gatekeeper-cli.sh 被 scope denied（C1 给 scanner/exploiter/auditor 加 gate 对这两条车道
    # 不生效）→ 具名角色 = 结构性闭合。
    [ -n "$role_override" ] && subagent_role="$role_override"
    # 2026-08-28 窄任务下发前投毒拦截（fail-closed）：清单是路由事实源，强注入信号
    # （忽略指令/角色伪装/跨租户）→ 阻断下发并报明细。深层投毒另需聚合器清洗（见 §4.9）。
    # 2026-08-28 追加 schema/复杂度校验（域 2）：格式违规/超限清单同样拒绝下发（防巨型清单污染）。
    if [ -f "$STATE_FILE" ]; then
      local _nt_poison; _nt_poison=$(python3 "${SKILL_DIR}/scripts/gk_route_center.py" resolve-narrow --state "$STATE_FILE" --check-poison 2>/dev/null || true)
      if [ -n "$_nt_poison" ] && echo "$_nt_poison" | grep -q '"poison": true'; then
        echo "{\"ok\":false,\"error\":\"narrow_tasks POISONED — dispatch blocked\",\"detail\":$_nt_poison,\"hint\":\"清理 gate_data.narrow_tasks[] 投毒条目后重试\"}" >&2
        return 1
      fi
      local _nt_schema; _nt_schema=$(python3 "${SKILL_DIR}/scripts/gk_route_center.py" resolve-narrow --state "$STATE_FILE" --check-schema 2>/dev/null || true)
      if [ -n "$_nt_schema" ] && echo "$_nt_schema" | grep -q '"schema_valid": false'; then
        # F-REV-51（2026-09-14）：hint 按 rule 分派。state_oversized 是**整文件累积**触发
        # （task_pipeline / subagent_history），与窄任务清单无关 ⟹ 原静态 hint「修正清单格式/
        # 复杂度」会把人引向错误方向（白改清单，真阻断源不动）。
        local _nt_hint="修正清单格式/复杂度（模板 §4.1 规范）后重试"
        if echo "$_nt_schema" | grep -q '"rule": "state_oversized"'; then
          _nt_hint="state 文件超限（非清单问题）：gate_data.task_pipeline / subagent_history 累积 → 归档或裁剪后重试（F-REV-51）"
        fi
        echo "{\"ok\":false,\"error\":\"narrow_tasks SCHEMA_VIOLATION — dispatch blocked\",\"detail\":$_nt_schema,\"hint\":\"$_nt_hint\"}" >&2
        return 1
      fi
    fi
    # 2026-08-28 窄任务→档位路由（模板 §4.1 配套）：gate_data.narrow_tasks[] 命中当前
    # 任务且条目声明 tier → 覆盖档位（SUBAGENT_TIER 透传 subagent_runner）。未命中/
    # 未声明 tier → 落角色默认档位。清单即下发路由的事实源，不再只是存在性检查。
    # 路由逻辑在元数据路由中枢 L5（gk_route_center.py resolve-narrow，2026-09-02 收编），此处仅消费。
    if [ -f "$STATE_FILE" ]; then
      local _nt_tier=""
      _nt_tier=$(python3 "${SKILL_DIR}/scripts/gk_route_center.py" resolve-narrow --state "$STATE_FILE" --task "$task" 2>/dev/null \
        | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field tier --default '' 2>/dev/null || echo "")
      if [ -n "$_nt_tier" ]; then
        export SUBAGENT_TIER="$_nt_tier"
        echo "{\"narrow_tasks_route\":\"tier=$_nt_tier — 窄任务清单命中当前任务\"}" >&2
      fi
    fi
    # 预算 profile（2026-08-15，按角色，用户确认档位：default 20K / RED 30K / exploiter+plan-refinement 50K）
    # 2026-08-28: 各角色映射档位（SUBAGENT_TIER 单一事实源），角色预设 token/item 仅作 env 兜底。
    case "$subagent_role" in
      plan-refinement)
        # 2026-08-15 工具扩权：完整计划质询协议需多源交叉审查（bridge 计划/参考项目/门卫 C++ 仓库/文档）。
        # 此前默认 search,read,gitnexus 无法 read_bridge/read_repo/read_doc → 协议跑不全。
        # 2026-08-27 提额（质询根因 A/B 实测）：180KB 大文档 × 1500 字符窗口 ≈ 120 次续读，
        # item_budget 250→600（eff_turns = 600//5 = 120）。
        # ⚠️ 二次修正：实测 total_tokens 109748 仍被 token_budget=50000 硬限截断（读 52% 即 budget 尽）
        # → token_budget 50000→120000（180KB ≈ 7 万 token 全文 + 评审余量）。
        # 2026-10-08（用户裁定「质询通道显式用 tier 4」）：tier 3 → **tier 4**。
        # 依据（本轮 §26 调查，实读非推断）：tier3 `token_budget` = 1,000,000（**成本当量**口径：
        #   `miss + hit×0.02 + completion×1.0`，见 subagent_runner._BudgetHooks.on_llm_end），
        #   而本轮单臂 plan-refinement 质询成本当量实测 **> 1,000,000**（raw 1.17–1.41M，当量亦超）
        #   ⟹ tier3 结构性低于真实成本 ⟹ 必 `budget_status=hard` 中途截停分析（结论不可信）。
        #   tier4 `token_budget` = 3,000,000（SUBA_TIERS[4]）⟹ 覆盖真实成本 + margin。
        # 与 SUBA_TIERS 单一事实源对齐；--tier 显式覆盖走 SUBAGENT_TIER（cmd_plan_refinement 透传）。
        # 窄任务清单机制（模板 §4）是根治：大文档拆 2-3 个窄任务，本提额为兼容单任务全读。
        export SUBAGENT_TIER="${SUBAGENT_TIER:-4}"
        # F-REV-100（2026-09-17）：原此处 `subagent_tools="search,read,read_bridge,read_repo,
        # gitnexus,gx_context,gx_impact,gx_query,gx_detect_changes,code_search,read_doc"`
        # **已移除** —— 工具面单一事实源 = runner `ROLE_TOOLS[plan-refinement]`（含上列全部，另补
        # `gx_trace`/`gx_guide`/`ci-diagnose`/`json_*` 与只读门禁直通 `state`/`self-check`/`audit`）。
        # 2026-09-25 预算单源：本臂仅定档位（tier 3），轮次/L2/L3 数额一律由 runner 档位表决定。
        ;;
      scanner)
        # 2026-08-28 角色→档位映射（用户质询：不同角色不同档位/预算/turns/超时）：
        # scanner = tier 3（light 只读枚举，但需读 gate 大文件）；reporter = tier 1（mini，降级——
        # 报告收集角色不承载重推理，走最低档）；exploiter = tier 3（heavy 攻击执行）。
        # SUBAGENT_TIER 若已被窄任务路由/显式覆盖则优先（${SUBAGENT_TIER:-N} 保底）。
        # 2026-10-17（owner 裁定「scanner t2→t3，其余保持」）：t2=200k 成本当量，与 auditor
        #   当年 t2→t4 的理由同构（RED-SCOPE 要读 gatekeeper-cli.sh ~575K 字符 + state 枚举攻击面）
        #   ⟹ 抬到 t3（1M），避免 `budget_status=hard` 中途截停分析。
        export SUBAGENT_TIER="${SUBAGENT_TIER:-3}"
        # 2026-09-25 预算单源：本臂仅定档位（2026-10-17 起 tier 3），轮次/L2/L3 数额由 runner 档位表决定。
        ;;
      auditor)
        # 2026-10-01（用户裁定「修 auditor 档位错配」）：auditor 从 tier2 **拆出并抬到 tier4**。
        # 依据（本轮实测 + 调用面）：auditor 承载三条**重审查**车道 —— L2 `--crossrev`、
        #   后R 五域审计（postR#1）、RED-POSTEX（role 映射 = auditor）；三者都要读 gate 区大文件
        #   （gatekeeper-cli.sh ~575K chars）⟹ tier2（200k 成本当量 / item 750）实测
        #   `budget_status=hard` 截停分析（crossrev 第二轮实证：242,496 > 200,000）。
        #   且 auditor(2) < default(4) 本身即错配：**审查面预算不应低于补位面**。
        export SUBAGENT_TIER="${SUBAGENT_TIER:-4}"
        # 2026-09-25 预算单源：本臂仅定档位（tier 4），轮次/L2/L3 数额由 runner 档位表决定。
        ;;
      reporter)
        export SUBAGENT_TIER="${SUBAGENT_TIER:-1}"
        # 2026-09-25 预算单源：本臂仅定档位（tier 1），轮次/L2/L3 数额由 runner 档位表决定。
        ;;
      exploiter)
        export SUBAGENT_TIER="${SUBAGENT_TIER:-3}"
        # 2026-09-25 预算单源：本臂仅定档位（tier 3），轮次/L2/L3 数额由 runner 档位表决定。
        ;;
      default)
        # 2026-08-28 收敛（用户质询定案）：default 定位 = standard 序列补位（W9 LLM 兜底 +
        # STAGE_2 CI 维护），非"通用杂活"——通用分析是主 agent（v4-pro）本职，default 冗余。
        # 档位 tier1 → tier3（standard 档）：工具含 ci-diagnose/gx_trace（batch8 19 项工具包规划
        # 落地，SUBA_TIERS tier3 白名单已补）；兜底任务 = 门禁 BLOCK/CI 失败后的 LLM 兜底分析。
        # 2026-10-01（用户裁定「default subagent 改成默认 tier4」）：tier3 → **tier4**
        #   （SUBA_TIERS[4] = 1.5M 成本当量 / item 4000 / 800 轮 / 80k 输出 / 900s）。
        export SUBAGENT_TIER="${SUBAGENT_TIER:-4}"
        # 2026-09-25 预算单源：本臂仅定档位（tier 4），轮次/L2/L3 数额由 runner 档位表决定。
        ;;
      coder)
        # fix 档位（`--tools` 含 `edit`）与 default 同档（tier 3 → 2026-10-01 tier 4）。
        export SUBAGENT_TIER="${SUBAGENT_TIER:-4}" ;;
      *)
        # 兜底臂（2026-09-25）：任何未登记角色 / roleless 派发一律 tier 3
        # → 2026-10-01（用户裁定）**tier 4**。
        # 必要性：tier=0（变量未导出）会让 runner **跳过** tier 块，反过来把已删的预算三参复活
        # ⟹ 单源破裂（症状：token_usage.cap 落回 runner 内建缺省值）。
        export SUBAGENT_TIER="${SUBAGENT_TIER:-4}" ;;
    esac
    # B2 fix (2026-08-08): CLI 必须传 --mode plan-refinement，否则 subagent_runner 的
    # args.mode 保持 "default"，plan-refinement 专用 SCR 审查 instructions 永不加载。
    local mode_flag=""
    if [ "$subagent_role" == "plan-refinement" ]; then
      mode_flag="--mode plan-refinement"
    fi
    # API key piped via stdin (not CLI arg) to keep it out of `ps`
    # B3 fix 配套 (2026-08-11): plan-refinement 复杂审查输出（7维评分+evidence）
    # 远超 runner 默认 SUBAGENT_MAX_TOKENS=800，thinking 下截断 → require_output
    # guardrail tripwire → 误判 subagent 失败。CLI 侧为 plan-refinement 提额。
    # 用 export 而非 `${VAR}` 展开：变量展开值不会被 bash 当作 env 前缀
    # （"SUBAGENT_MAX_TOKENS=4000: command not found" 教训）。
    # 2026-10-03（用户裁定「2000 硬截断很奇怪」）：**撤销** plan-refinement 的输出上限硬覆盖
    # （原钉死 16000，与 tier4 档位表 80000 不一致）—— 现由 `SUBA_TIERS[tier].max_output_tokens`
    # 单一事实源决定；显式设 env 仍可手动覆盖（保逃生位）。
    # ── 审查/质询通道前置（A/B/C/D，2026-09-04 SCR 收敛；stage-3-review 唯一入口注记）──
    # plan-refinement（质询）与 --crossrev（交叉审查 L2）→ 走 _review_channel_preflight：
    #   A context 签名新鲜（失效→显式阻断，GK_ALLOW_STALE_CTX=1 降级 WARN）
    #   B L3 基线 status-fresh 复用（crossrev，stale 才 analyze）
    #   C 节点绑定（crossrev 须在序列审查节点；GK_DEGRADE_REVIEW=1 降级）
    #   D 组件 pin（source/version/output-contract + exit 2，gk_review_pins.py）
    # ECC-FAB556F786E5（2026-10-01）：arm 条件改**显式** `role_override` —— 与「推断出的身份」解耦
    #   （原条件 = 被守卫对象自身，属循环依赖；子串推断路径已由上方 REVIEW_ROLE_UNSPECIFIED 关闭）。
    if [ "$role_override" = "plan-refinement" ] || $crossrev_flag; then
      local _rp_channel="plan-refinement"
      [ "$subagent_role" != "plan-refinement" ] && _rp_channel="crossrev"
      local _rp_res; _rp_res=$(CTX_INJECT_OK="$ctx_inject_ok" CTX_INJECT_REASON="${ctx_inject_reason:-}" _review_channel_preflight "$_rp_channel")
      local _rp_ok; _rp_ok=$(echo "$_rp_res" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field ok --default None --default-invalid false 2>/dev/null || echo "false")
      if [ "$_rp_ok" != "True" ]; then
        echo "$_rp_res"
        return 1
      fi
    fi
    # 2026-09-04 L2/L3 换位（代码级证据预取 v1）：crossrev（L2）在 preflight B（L3 基线
    # status-fresh/analyze）之后预取 gitnexus detect-changes 摘要 → GK_L3_EVIDENCE env
    # 注入 subagent（graph-anchored 预取，防 L2 整仓裸读）。不可用 → WARN 降级（仍可审查）。
    # repo/base 可经 GK_L3_REPO / GK_L3_BASE env 覆盖（默认技能仓库 HEAD~1）。
    local _l3ev=""
    if $crossrev_flag; then
      _l3ev=$(python3 "$SKILL_DIR/scripts/gk_l3_prefetch.py" --repo "${GK_L3_REPO:-spz-gatekeeper-r-sequence}" --base "${GK_L3_BASE:-HEAD~1}" 2>>"$GK_DBG_LOG" || echo '{"available":false}')
      local _l3ok; _l3ok=$(echo "$_l3ev" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field available --default None --default-invalid false 2>/dev/null || echo "false")
      if [ "$_l3ok" != "True" ]; then
        echo "WARN[L3-prefetch]: detect-changes 不可用 → L2 无图证据（降级为无预取）" >> "$GK_DBG_LOG"
        _l3ev=""
      fi
    fi
    # F-REV-11 C2 (2026-09-10)：gate 源码变更证据摘要（审计/红队/L2/后R 职责核心 = gate bash；
    # 单计算点在此，禁 python 侧第二实现）→ GK_GATE_EVIDENCE env 注入 subagent_runner。
    # 触发面 = --crossrev（L2）或显式 --role（后R/红队具名车道）；不可用 → 降级不阻断（对齐 _l3ev）。
    local _gtev=""
    if $crossrev_flag || [ -n "$role_override" ]; then
      _gtev=$(python3 "$SKILL_DIR/scripts/gk_gate_evidence.py" --repo-dir "$SKILL_DIR" --base "${GK_GATE_BASE:-HEAD~1}" 2>>"$GK_DBG_LOG" || echo '{"available":false}')
      local _gtok; _gtok=$(echo "$_gtev" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field available --default None --default-invalid false 2>/dev/null || echo "false")
      if [ "$_gtok" != "True" ]; then
        echo "WARN[gate-evidence]: 变更摘要不可用 → 无 gate 证据注入（降级不阻断）" >> "$GK_DBG_LOG"
        _gtev=""
      fi
    fi
    # F-REV-80（2026-09-16，用户裁定「加全量 L0 预取（含图证据）」）：**L0 全量预取** ——
    # L0-a（图/环境源）+ L0-b（自检/guard-edit）→ GK_L0_EVIDENCE env 注入 runner 尾块。
    # 触发面同 _gtev（--crossrev 或显式 --role，**含质询 plan-refinement**：根因之一是
    # 「质询自称五源验证、注入面却本就为空」）。单计算点在此；索引状态复用**已判定**的
    # `_gitnexus_baseline_status`（同进程 memo ⟹ 不重复 spawn）。不可用 → 降级不阻断。
    local _l0ev=""
    if $crossrev_flag || [ -n "$role_override" ]; then
      local _l0_dir _l0_st _l0_repo
      _l0_dir=$(_gx_repo_dir_for_current)
      _l0_st=$(_gitnexus_baseline_status "$_l0_dir")
      _l0_repo=""; _l0_repo=$(_gx_repo_name_for_dir "$_l0_dir" 2>/dev/null) || true
      _l0ev=$(GK_L0_MAIN_WORKTREE="${MAIN_REPO_WSL:-}" python3 "$SKILL_DIR/scripts/gk_l0_prefetch.py" \
        --repo "$_l0_repo" --repo-dir "$_l0_dir" \
        --base "${GK_L0_BASE:-HEAD~1}" --index-status "$_l0_st" \
        --skill-dir "$SKILL_DIR" --state-file "$STATE_FILE" 2>>"$GK_DBG_LOG" || echo '{"available":false}')
      local _l0ok; _l0ok=$(echo "$_l0ev" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field available --default None --default-invalid false 2>/dev/null || echo "false")
      if [ "$_l0ok" != "True" ]; then
        echo "WARN[L0-prefetch]: L0 预取不可用 → 无 L0 证据注入（降级不阻断）" >> "$GK_DBG_LOG"
        _l0ev=""
      fi
    fi
    # 缺陷4 修复（2026-09-13）：GATEKEEPER_HMAC_KEY 此前仅在 runner 直通路径（:5931 供给块）
      # 供给，monitor --subagent 派发路径缺失 → runner env 空 → 静默跳过签名（unsigned_no_hmac）。
      # 供给逻辑同 :5931-5949（.keys/subagent-hmac.key 首次生成 64-hex 后加载；无 key 不签名不报错）。
      if [ -z "${GATEKEEPER_HMAC_KEY:-}" ] && [ -n "${SKILL_DIR:-}" ]; then
        local _hmac_key_file="${SKILL_DIR}/.keys/subagent-hmac.key"
        if [ -f "$_hmac_key_file" ]; then
          GATEKEEPER_HMAC_KEY="$(head -1 "$_hmac_key_file" 2>/dev/null)"
        elif [ -d "${SKILL_DIR}/.keys" ]; then
          GATEKEEPER_HMAC_KEY="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(32))' 2>/dev/null)"
          if [ -n "$GATEKEEPER_HMAC_KEY" ]; then
            umask 177; echo "$GATEKEEPER_HMAC_KEY" > "$_hmac_key_file"; umask 022
            chmod 600 "$_hmac_key_file" 2>/dev/null
          fi
        fi
        # 2026-09-20（ECC-PLAN ①·宿主可用性）：原 `[ -n "$GATEKEEPER_HMAC_KEY" ]` —— 上面
        # if/elif **两条分支都不命中**时（`.keys` 目录不存在 = 非本机宿主）该变量**从未被赋值**
        # ⟹ `set -u` 下 unbound，函数体即刻中止。改 `${...:-}`（行为不变：仍只导出非空值）。
        # 同族副本 L6803（那份在**顶层**，unbound 会打死整 CLI 加载）；两处同批修。
        [ -n "${GATEKEEPER_HMAC_KEY:-}" ] && export GATEKEEPER_HMAC_KEY
      fi
      # F-REV-92(a)：先自校验**上一轮**是否异常终止（留痕），再注册本轮；派发套外层 deadline。
      _gk_subagent_watch_prev
      local _subagent_max_runtime="${SUBAGENT_MAX_RUNTIME:-3600}"
      _gk_subagent_watch_arm "$subagent_id" "${SUBAGENT_TIER:-0}" "$_subagent_max_runtime"
    # ── ECC-AFC678CA168B（2026-09-28）：**派发前 env 收敛 + WSLENV 并入（位置修正）** ──
    #   原并入循环在 3456-3477（早于本段全部赋值）⟹ `declare -p` 守卫使其恒跳过。现移到派发前，
    #   并先把本函数自算的键 export 成**真正的进程环境变量**（env prefix 只作用于单条命令、且不是
    #   shell 变量 ⟹ `declare -p` 看不见）。同因一并修复 GK_*_EVIDENCE（F-REV-11 C2 证据面，
    #   ECC-8D14BC1BDC47）与 SUBAGENT_ID（报告↔history 对账，ECC-241DB931377F）。
    #   空值仍跳过（保 F-REV-91「空串不进白名单」约束）；缩进保持 4 空格（测试定位契约）。
    export SUBAGENT_ID="$subagent_id" SUBAGENT_ROLE="$subagent_role"
    export GK_L0_EVIDENCE="${_l0ev:-}" GK_L3_EVIDENCE="${_l3ev:-}" GK_GATE_EVIDENCE="${_gtev:-}" \
           GK_WEB_EVIDENCE="${GK_WEB_EVIDENCE:-}"
    for _k in GX_NODE GX_JS GX_REPO SUBAGENT_ID SUBAGENT_ROLE GATEKEEPER_HMAC_KEY \
              GK_L0_EVIDENCE GK_L3_EVIDENCE GK_GATE_EVIDENCE GK_WEB_EVIDENCE SUBAGENT_IMAGES \
              SUBAGENT_TOKEN_BUDGET SUBAGENT_ITEM_BUDGET SUBAGENT_TOOLS \
              SUBAGENT_MAX_TOKENS SUBAGENT_TIMEOUT; do
      declare -p "$_k" >/dev/null 2>&1 || continue
      # 2026-10-10（ECC-3FD7DEAF6078 暴露）：`${!_k}` 是**间接展开**（把 `_k` 的**值**当变量名
      #   再取值）⟹ 目标变量「已 export 但未赋值」时（`export GX_NODE GX_JS GX_REPO` 在 GX_REPO
      #   解析不出仓库名时正是此态）→ `set -u` 下 **unbound variable 中止整个 cmd_monitor**，
      #   派发链在桩之前即死（实测 `GK_GX_DIR` 指向未索引目录 ⟹ rc=1 / 无输出）。
      #   `:-` 令该「声明未赋值」态归零跳过（与「值为空」同义），恢复文档承诺的
      #   「图能力不可用 → 降级不阻断」。
      [ -n "${!_k:-}" ] || continue
      case ":${WSLENV:-}:" in
        *":${_k}:"*|*":${_k}/"*) ;;
        *) WSLENV="${WSLENV:+$WSLENV:}${_k}" ;;
      esac
    done
    export WSLENV
      local subagent_out; subagent_out=$(echo "$api_key" | GK_L0_EVIDENCE="${_l0ev:-}" GK_L3_EVIDENCE="${_l3ev:-}" GK_GATE_EVIDENCE="${_gtev:-}" GK_WEB_EVIDENCE="${GK_WEB_EVIDENCE:-}" SUBAGENT_ID="$subagent_id" SUBAGENT_ROLE="$subagent_role" timeout -k 30 "$_subagent_max_runtime" $subagent_python "$subagent_runner" \
      --task "$task" \
      --tier "${SUBAGENT_TIER:-0}" \
      --tools "$subagent_tools" \
      --soft-ratio "$subagent_soft_ratio" \
      --api-base "${API_BASE}" \
      --api-model "$(_subagent_model_chain)" \
      --reasoning "${DS_REASONING_EFFORT}" \
      $mode_flag \
      $inject_flag \
      2>/tmp/gk_subagent_dbg.log)
    local exit_code=$?
    # B5 fix (2026-08-08): tripwire 等 guardrail 失败输出 error JSON 但 exit 0，
    # 原判定 `exit_code != 0 || 空输出` 不触发 → 无降级。补 error JSON 识别。
    # 2026-08-11 fix: 原 `rg -q '"error"'` 是文本匹配，agent 正常输出正文含 "error"
    # 字样（如 conclusion 提及）会误判失败 → 触发 MiMo fallback → 401。
    # 改为精确解析 JSON 顶层 error 字段。
    local subagent_failed=false
    if [ $exit_code -ne 0 ] || [ -z "$subagent_out" ]; then
      subagent_failed=true
    elif echo "$subagent_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test error --is str --first-line 2>/dev/null; then
      subagent_failed=true
    fi
    # 2026-10-31：**配置类失败**（runner `EXIT_CONFIG_ERROR=78` / `error_code=UNRESOLVED_OWN_USER`）
    #   不得走 DS 重试与 MiMo 降级 —— 换 provider 不会让白名单源出现（6 臂实测：重试仍空）；
    #   且必须让上层看到**非 0**，否则 `--adjudicate last-batch` 会回 `{"ok":true,"dispatched":…}`
    #   把 6 条记录消费成 approved（假成功、需人工重置）。
    if [ "$exit_code" = "78" ] || echo "$subagent_out" | "$RG" -q '"error_code": *"UNRESOLVED_OWN_USER"'; then
      [ -n "$subagent_out" ] && echo "$subagent_out"
      return 78
    fi
    if $subagent_failed; then
      # 2026-08-15: DS 重试优先 — 环境性瞬态失败（Trae sandbox 子进程被拦截 → 0 API 调用 →
      # guardrail tripwire）不该直接付出降级代价（MiMo 需 MIMO_API_KEY，缺失即报错）。
      # 先给 DS 一次完整重试。禁用: export SUBAGENT_DS_RETRY=0
      if [ "${SUBAGENT_DS_RETRY:-1}" = "1" ]; then
        local ds_retry_out; ds_retry_out=$(echo "$api_key" | SUBAGENT_ID="sub-$(date +%s)-$$-${RANDOM}" SUBAGENT_ROLE="$subagent_role" timeout -k 30 "$_subagent_max_runtime" $subagent_python "$subagent_runner" \
          --task "$task" \
          --tier "${SUBAGENT_TIER:-0}" \
          --tools "$subagent_tools" \
          --soft-ratio "$subagent_soft_ratio" \
          --api-base "${API_BASE}" \
          --api-model "$(_subagent_model_chain)" \
          --reasoning "${DS_REASONING_EFFORT}" \
          $mode_flag \
          $inject_flag \
          2>/tmp/gk_subagent_dbg.log)
        local ds_retry_exit=$?
        if [ $ds_retry_exit -eq 0 ] && [ -n "$ds_retry_out" ] && ! echo "$ds_retry_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test error --is str --first-line 2>/dev/null; then
          # DS 重试成功 → 采用重试结果，跳过降级链
          subagent_out="$ds_retry_out"
          subagent_failed=false
        fi
      fi
    fi
    if $subagent_failed; then
      if [ "$PROVIDER" != "mimo" ]; then
        # K1 kill switch（2026-09-23，plan-refinement sub-1790160203 收敛裁定）：GK_MIMO_DISABLED=1
        # 一键禁用 mimo 降级腿。此前 MiMo 车道唯一开关就是本 PROVIDER 判定，无禁用位；
        # 作为 10-21 v2.5 下线窗口的运维保险。J5 验收：置 GK_MIMO_DISABLED=1 时 subagent
        # 失败应报下方错误且不发起任何 MiMo 调用（failover 链在此跳过 mimo）。
        if [ "${GK_MIMO_DISABLED:-0}" = "1" ]; then
          echo '{"error":"subagent failed and GK_MIMO_DISABLED=1 — mimo fallback skipped","mode":"subagent","reason":"GK_MIMO_DISABLED"}' >&2
          [ -n "$subagent_out" ] && echo "$subagent_out" || echo '{"error":"subagent failed — all providers unavailable","mode":"subagent"}'
          return 1
        fi
        # MIMO fallback fix (2026-08-09): 原实现只换 --api-base/--api-model，
        # ① stdin 的 api_key 仍是 deepseek key → mimo API 401（用户观察到 fallback 失效）
        # ② API_BASE_MIMO 未定义 → 落到错误默认值 api.mimo.com/v1（真实是 api.xiaomimimo.com/v1）
        # 现与主 failover 链同模式：切 PROVIDER=mimo → _resolve_provider_config 刷新
        # API_BASE/API_MODEL/API_KEY → _resolve_api_key 重解析 mimo key。
        # 2026-08-11 fix（补全 L1936-1939 --api 模式同教训）：MIMO_API_KEY 缺失时
        # _resolve_api_key 的 mimo 分支会回退 DEEPSEEK_API_KEY → 用 DS key 打 MiMo API
        # → 实测 401 Invalid API Key（dbg_req_url=api.xiaomimimo.com）。此时必须跳过
        # fallback 并报明确错误，而不是拿错 key 打 MiMo。
        if [ -z "${MIMO_API_KEY:-}" ]; then
          echo '{"error":"subagent failed and MIMO_API_KEY not set — cannot fallback","mode":"subagent","reason":"MIMO_API_KEY missing, DS key is invalid for MiMo API"}' >&2
          [ -n "$subagent_out" ] && echo "$subagent_out" || echo '{"error":"subagent failed — all providers unavailable","mode":"subagent"}'
          return 1
        fi
        PROVIDER="mimo"
        _resolve_provider_config
        API_KEY=""  # 强制重解析，避免沿用 deepseek key
        _resolve_api_key && api_key="$API_KEY"
        # K2（2026-09-23，A1 落地，plan-refinement 裁定唯一修正点）：兜底车道原
        # --reasoning "low" 与 A1（MiMo 思考固定最大强度、不随车道降档）直接冲突；
        # 改与主车道同源（DS_REASONING_EFFORT）。runner 侧恒发 reasoning_effort
        # （subagent_runner.py:2323-2327），故不在 runner 侧改空值语义。
        subagent_out=$(echo "$api_key" | SUBAGENT_ID="sub-$(date +%s)-$$-${RANDOM}" SUBAGENT_ROLE="$subagent_role" timeout -k 30 "$_subagent_max_runtime" $subagent_python "$subagent_runner" \
          --task "$task" \
          --tier "${SUBAGENT_TIER:-0}" \
          --tools "$subagent_tools" \
          --soft-ratio "$subagent_soft_ratio" \
          --api-base "${API_BASE}" \
          --api-model "$(_subagent_model_chain)" \
          --reasoning "${DS_REASONING_EFFORT}" \
          $mode_flag \
          $inject_flag \
          2>/dev/null) || true
      fi
    fi
    # 2026-08-15: subagent 输出可见性 — 全量 ECC JSON + 可读双盲评分报告落盘
    # （主 agent 校验审核 + 用户直接评分，消除黑盒）。此前仅 stdout + subagent_history 截断摘要。
    if [ -n "$subagent_out" ]; then
      local sub_out_dir="${SKILL_DIR}/docs/analysis/subagent"
      mkdir -p "$sub_out_dir" 2>/dev/null
      local sub_out_file="${sub_out_dir}/${subagent_id}.json"
      local sub_report_file="${sub_out_dir}/${subagent_id}.md"
      if echo "$subagent_out" > "$sub_out_file" 2>/dev/null; then
        echo "$subagent_out" | python3 "${SKILL_DIR}/scripts/gk_subagent_report.py" > "$sub_report_file" 2>/dev/null || true
        echo "{\"output_file\":\"${sub_out_file}\",\"report_file\":\"${sub_report_file}\",\"note\":\"subagent full ECC + 双盲评分报告已落盘，供主 agent 审核与人类评分\"}" >&2
        # 2026-10-28（B：授权→产物）：把报告登记进派发账本 —— 优先绑定「已消费未绑定」的最近
        #   一张票据；CLI 直调 `monitor --subagent` 不经 Task 票据 ⟹ 自记账（origin=report）。
        #   失败不阻断派发（账本是对账面，非门禁面），但必须留痕。
        python3 "${SKILL_DIR}/scripts/gk_dispatch_ticket.py" record "$STATE_FILE" "$sub_report_file" \
          --session "${GK_SESSION_ID:-}" >>"${GK_DBG_LOG:-/dev/null}" 2>&1 || true
        # C4①（ECC-D9D2382BB535，2026-09-28）：落盘**校验** —— 可解析 ∧ 关键机检键非缺席。
        #   仅告警不阻断（非 ECC 输出本就会被下方 pydantic VALID 门拒），但**不得静默**。
        if ! GK_PY_OUT_FILE="$(_gk_py_path "$sub_out_file")" python3 -c "
import json,sys,os
d=json.load(open(os.environ['GK_PY_OUT_FILE'],encoding='utf-8'))
_m=[k for k in ('gx_status','verification','evidence_anchor') if k not in d]
if _m:
  print('MISSING:'+','.join(_m)); sys.exit(4)
" >>"${GK_DBG_LOG:-/dev/null}" 2>&1; then
          printf '[hist] ERROR DUMP_REPORT_INVALID sid=%s file=%s ts=%s\n' "$subagent_id" "$sub_out_file" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${GK_DBG_LOG:-/dev/null}" 2>&1 || true
          echo "{\"ok\":false,\"error\":\"DUMP_REPORT_INVALID\",\"subagent_id\":\"${subagent_id}\",\"file\":\"${sub_out_file}\"}" >&2
        fi
      fi
      echo "$subagent_out"
    else
      echo '{"error":"subagent failed — all providers unavailable","mode":"subagent"}'
    fi
    # Write subagent output to gate_data audit trail (④ Buffer, FIFO cap=20)
    # Validate with Pydantic schema before accepting — rejects malformed output
    if [ -n "$subagent_out" ] && echo "$subagent_out" | python3 -c "
import json,sys
from pydantic import BaseModel, Field
from typing import Literal, Optional
class E(BaseModel): file:str; lines:str; status:Literal['confirmed','suspect']; note:Optional[str]=None
class F(BaseModel): worked:list[str]=Field(default_factory=list); failed:list[str]=Field(default_factory=list); not_tried:list[str]=Field(default_factory=list)
class A(BaseModel): tool:str; path:str; reason:str; timestamp:str
class O(BaseModel): mode:str='subagent'; subagent_id:str; nonce:str; timestamp:str; task:str; conclusion:str; evidence:list[E]=Field(default_factory=list); findings:F=Field(default_factory=F); next_steps:list[str]=Field(default_factory=list); confidence:Literal['high','medium','low']='medium'; tools_used:list[str]=Field(default_factory=list); guardrail:str='passed'; turns:int=0; total_items:int=0; token_budget:Optional[int]=None; total_tokens:int=0; item_budget:Optional[int]=None; budget_status:str='ok'; hmac:Optional[str]=None; jwt_token:Optional[str]=None; access_violations:list[A]=Field(default_factory=list); overall_score:Optional[float]=None; verdicts:dict=Field(default_factory=dict); vocab_violations:list[dict]=Field(default_factory=list); seven_dim_score:dict=Field(default_factory=dict); challenges:list[str]=Field(default_factory=list); slashed:list[str]=Field(default_factory=list); kept:list[str]=Field(default_factory=list); agent_payload:dict=Field(default_factory=dict); gx_status:dict=Field(default_factory=dict); verification:dict=Field(default_factory=dict); evidence_anchor:dict=Field(default_factory=dict); agent_identity:dict=Field(default_factory=dict); token_usage:dict=Field(default_factory=dict); assertions:list[dict]=Field(default_factory=list); tool_call_count:int=0
d=json.loads(sys.stdin.read()); o=O(**d); print('VALID')
" 2>/dev/null | "$RG" -q 'VALID'; then
      # R1: HMAC verification (verify subagent output integrity)
      local hmac_valid="skip"
      if [ -n "${GATEKEEPER_HMAC_KEY:-}" ]; then
        hmac_valid=$(echo "$subagent_out" | SUBAGENT_ID="$subagent_id" GATEKEEPER_HMAC_KEY="$GATEKEEPER_HMAC_KEY" python3 -c "
import json,sys,hashlib,hmac
from pydantic import BaseModel, Field
from typing import Literal, Optional
class E(BaseModel): file:str; lines:str; status:Literal['confirmed','suspect']; note:Optional[str]=None
class F(BaseModel): worked:list[str]=Field(default_factory=list); failed:list[str]=Field(default_factory=list); not_tried:list[str]=Field(default_factory=list)
class A(BaseModel): tool:str; path:str; reason:str; timestamp:str
class O(BaseModel): mode:str='subagent'; subagent_id:str; nonce:str; timestamp:str; task:str; conclusion:str; evidence:list[E]=Field(default_factory=list); findings:F=Field(default_factory=F); next_steps:list[str]=Field(default_factory=list); confidence:Literal['high','medium','low']='medium'; tools_used:list[str]=Field(default_factory=list); guardrail:str='passed'; turns:int=0; total_items:int=0; token_budget:Optional[int]=None; total_tokens:int=0; item_budget:Optional[int]=None; budget_status:str='ok'; hmac:Optional[str]=None; jwt_token:Optional[str]=None; access_violations:list[A]=Field(default_factory=list); overall_score:Optional[float]=None; verdicts:dict=Field(default_factory=dict); vocab_violations:list[dict]=Field(default_factory=list); seven_dim_score:dict=Field(default_factory=dict); challenges:list[str]=Field(default_factory=list); slashed:list[str]=Field(default_factory=list); kept:list[str]=Field(default_factory=list); agent_payload:dict=Field(default_factory=dict); gx_status:dict=Field(default_factory=dict); verification:dict=Field(default_factory=dict); evidence_anchor:dict=Field(default_factory=dict); agent_identity:dict=Field(default_factory=dict); token_usage:dict=Field(default_factory=dict); assertions:list[dict]=Field(default_factory=list); tool_call_count:int=0
import os
# 2026-10-19 fix（W2A-L0 实测 dispatch_blocked 根因）：payload 必须用**原始键序**，
#   不能用 out.model_dump() 重排。runner 端 EccOutput 把 assertions/tool_call_count 声明在
#   agent_payload 之前并据此签名；CLI 侧 O() 原先把它们放在末尾 ⟹ 字段集相同、键序不同 ⟹
#   json.dumps 结果不同 ⟹ 六臂全部判 HMAC mismatch（tampered）⟹ subagent_history 零落库。
#   pydantic 仍用于结构校验；签名内容以磁盘上的原始 dict 为准（与签名端逐字同序）。
_raw=json.loads(sys.stdin.read())
out=O(**_raw)
sub_id=os.environ['SUBAGENT_ID']
master=os.environ['GATEKEEPER_HMAC_KEY']
# 2026-08-15 fix: 与 subagent_runner L94-98 签名算法同构 — 64-hex → bytes.fromhex，
# 不掺 SUBAGENT_ID 派生（runner L93 安全注释：sub_id 可预测，禁止派生）。
# 原实现 master.encode() + SHA256(SHA256(master+sub_id)+sub_id) 与签名端不同构 → 必然 mismatch
# → 所有 subagent 输出判 tampered → subagent_history 不写 → ECO-EDIT 门禁链断裂。
sk=bytes.fromhex(master) if len(master)==64 else master.encode()
# Recompute HMAC over payload (exclude hmac and jwt_token fields), preserving raw key order
data=dict(_raw); data.pop('hmac',None); data.pop('jwt_token',None)
expected=hmac.new(sk,json.dumps(data,separators=(',',':'),default=str).encode(),hashlib.sha256).hexdigest()
if out.hmac==expected: print('valid')
elif not out.hmac: print('no_hmac')
else: print('invalid')
" 2>/dev/null || echo "skip")
      fi
      [ "$hmac_valid" = "invalid" ] && { echo '{"ok":false,"error":"subagent HMAC mismatch — output tampered","subagent_id":"'"$subagent_id"'"}' >&2; return 1; }
      # 2026-10-31：**身份认证**（owner 指令「把身份认证补上」）。验签单源 =
      #   `gk_agent_identity.verify_ecc`（禁第二实现）。三态：
      #     · unsigned —— 未配 `GATEKEEPER_AGENT_KEY`（旧宿主），**不阻断**；
      #     · verified —— 签名可验、公钥与文件名同源；
      #     · invalid（含畸形/公钥缺失/验签失败）⟹ 按 **untrusted** 处置（与 HMAC mismatch 同档）。
      #   公钥目录缺省 `<skill>/.keys/agents`（`GATEKEEPER_AGENT_PUBKEY_DIR` 可覆盖）。
      local agent_id_status="unsigned"
      agent_id_status=$(echo "$subagent_out" | python3 "$SKILL_DIR/scripts/gk_agent_identity.py" verify \
        --pubkey-dir "${GATEKEEPER_AGENT_PUBKEY_DIR:-$SKILL_DIR/.keys/agents}" 2>/dev/null \
        | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field status --default unsigned 2>/dev/null \
        || echo "unsigned")
      [ -n "$agent_id_status" ] || agent_id_status="unsigned"
      [ "$agent_id_status" = "invalid" ] && { echo '{"ok":false,"error":"agent identity invalid — output untrusted","subagent_id":"'"$subagent_id"'"}' >&2; return 1; }
      export GK_AGENT_IDENTITY="$agent_id_status"
      # C3②（ECC-3BECE9FAD12A，2026-09-27）：把全量 ECC JSON / 双盲报告的落盘路径经 export 传给载荷
      #   （**不内联到下方派发行** —— 该行是既有 3 条红先臂的锚点，改形态会连带打断它们；
      #   路径在外层 sub_out_file / sub_report_file 计算，含 subagent_id）。
      export GK_OUTPUT_FILE="$sub_out_file" GK_REPORT_FILE="$sub_report_file"
      # 真因 D（2026-11-02）：python 侧路径形态以**解释器**为锚（见 `_gk_py_path` 段）。
      #   原状把 bash 形态 `/c/…` / `/mnt/c/…` 内联进 `sys.path` / `state_lock` / `open`
      #   ⟹ 原生 Windows python 直接 ImportError/FileNotFoundError ⟹ 整段落库未执行
      #   （HISTORY_WRITE_FAILED）。经 env 传入还顺带消灭 `\U` unicodeescape 家族。
      export GK_PY_SCRIPTS="$(_gk_py_path "$SKILL_DIR/scripts")" \
             GK_PY_STATE="$(_gk_py_path "$STATE_FILE")"
      echo "$subagent_out" | GK_TASK="$task" GK_HMAC_VALID="$hmac_valid" python3 -c "
import json,sys,os
sys.path.insert(0,os.environ['GK_PY_SCRIPTS'])
from gk_json_utils import dump_state, state_lock
from gk_subagent_report import normalize_evidence
out=json.loads(sys.stdin.read())
# ECC-4E6D7F42CA05（2026-09-27）：本块 = 「读 state → 改（subagent_history/subagent_last/
# _sealed_agent_score → 写 state」的 RMW，此前**全程无锁** ⟹ 并发臂完成时互相覆盖
# （subagent_history 条目静默丢失）。修法 = 取锁横跨读-写；dump_state 再取锁是**可重入**的、
# 不自锁。进程退出即关 fd 释放锁（含下方 JTI_REPLAY 的早退 sys.exit）。
_lk=state_lock(os.environ['GK_PY_STATE']); _lk.__enter__()
d=json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'))
gd=d.setdefault('gate_data',{})
hist=gd.setdefault('subagent_history',[])
# ECC 4-field structured summary
# ECC-74B7327230D8（2026-09-27）：原式 e.split(':') 遇 Windows 盘符路径（C:/…/x.py:13）
#   把**盘符冒号当分隔符** ⟹ file='C'、lines 塞全路径（行号/描述错位）；渲染侧又拼回原样 ⟹
#   症状被掩盖。归一下沉到 gk_subagent_report.normalize_evidence（按**首个「冒号+数字」**切）——
#   下沉到**已跟踪**模块的唯一动机 = 内联 python 不可单测（红先行为臂须可导入）；新建模块会被
#   red-first 沙箱软链回工作树 ⟹ 假绿。⚠ 注释内**禁 ASCII 反引号**（本 payload 在 bash 双引号区内，
#   反引号触发命令替换，实测 2026-09-27；守护臂 test_gk_eval_injection.cli_double_quoted_regions_have_no_backticks）。
evidence=normalize_evidence(out.get('evidence',[]))
findings=out.get('findings',{})
if isinstance(findings,str): findings={'worked':[findings],'failed':[],'not_tried':[]}
# 2026-10-19：模型常把 findings 三键留空（实测 11/11），而其结构化区段 kept/challenges
#   已有内容 ⟹ 回填 worked/failed（slashed 是"可砍掉"，不冒充 not_tried）。原字段不丢。
if not any((findings or {}).get(k) for k in ('worked','failed','not_tried')):
  findings={'worked':list(out.get('kept',[]) or [])[:5],
            'failed':list(out.get('challenges',[]) or [])[:5],
            'not_tried':[]}
# C4（ECC-D9D2382BB535，2026-09-28）：entry 只是「小摘要投影」，**全量机检字段外置**在
#   docs/analysis/subagent/<subagent_id>.json（C5 已证 304/304 配对；实测该 .json 含
#   gx_status/verification/evidence_anchor/token_usage/agent_payload 等）。三件：
#   ② machine_check 最小摘要（**由全量派生、禁独立计算**；超 _MACHINE_CHECK_MAX_BYTES 降级）；
#   ③ _ENTRY_KEYS = 投影键集**单源**（下方自检 entry 键 ⊆ 本集，防再丢面/误加面）。
#   ⚠ 注释内禁 ASCII 反引号（本 payload 在 bash 双引号区内 ⟹ 触发命令替换）。
_MACHINE_CHECK_MAX_BYTES=512
_ENTRY_KEYS=('task','subagent_id','conclusion','kept','slashed','challenges','evidence','findings',
             'next_steps','confidence','tools_used','seven_dim_score','overall_score','verdicts',
             'vocab_violations','budget_status','total_tokens','token_budget','total_items',
             'item_budget','hmac_status','output_file','report_file','machine_check',
             'access_violations','batch_id','tier','arm_group','arm_delta','arm_obs',
             'assertions','tool_call_count')
def _mc_field(x, key):
  return (x or {}).get(key, '') if isinstance(x, dict) else ''
# 2026-10-31（owner 裁定 A）：monitor --api 的分数只进 monitor_history（advisory），复盘面
#   原来看不见它 ⟹ 把最近一条投影进机检面（score/verdict/mode/ts），与 token/guardrail 同屏。
_mh=gd.get('monitor_history') or []
_mon=_mh[-1] if isinstance(_mh,list) and _mh else {}
if not isinstance(_mon,dict): _mon={}
_mon_last={'score': _mon.get('score'), 'verdict': _mon.get('verdict'),
           'mode': _mon.get('mode'), 'ts': _mon.get('ts')} if _mon else {}
_mc={'dump_ok': True,  # C4① 落盘校验结果（落盘段已 fail-loud；此处记状态位）
     'verification': _mc_field(out.get('verification'), 'status'),
     'evidence_anchor': _mc_field(out.get('evidence_anchor'), 'status'),
     'gx_status': _mc_field(out.get('gx_status'), 'verdict'),
     'token_usage_rounds': _mc_field(out.get('token_usage'), 'rounds'),
     'guardrail': out.get('guardrail',''), 'turns': out.get('turns',0), 'mode': out.get('mode',''),
     'nonce_len': len(str(out.get('nonce','') or '')), 'timestamp': out.get('timestamp',''),
     'monitor_last': _mon_last,
     # 2026-10-31：身份验签三态（外层已 fail-closed：invalid 不会到这里）
     'agent_identity': os.environ.get('GK_AGENT_IDENTITY','unsigned')}
if len(json.dumps(_mc,ensure_ascii=False).encode())>_MACHINE_CHECK_MAX_BYTES:
  _mc={'dump_ok': True, 'verification': _mc['verification'],
       'evidence_anchor': _mc['evidence_anchor'], 'gx_status': _mc['gx_status'],
       'monitor_last': _mon_last, 'agent_identity': _mc['agent_identity']}
# §18.1（2026-10-03，ECC-5538DD07B709 RC1/N1）：批身份随派发落库（与 tier 同批补，治 ECC-489C8AE274E6）。
#   批 = 一次 MoA 派发单元；各臂由派发侧给同一 plan/窄任务/纪元桶 ⟹ 同一 batch_id。
#   无计划作用域（如 RED-SCOPE）⟹ batch_id 空串（不凭空聚类无关臂）。
#   ⚠ 本 payload 在 bash 双引号区内 ⟹ 禁 ASCII 反引号（命令替换）**且禁 ASCII 双引号**
#   （ASCII 双引号会提前闭合 python3 -c 的引号，载荷被截断 → NameError → HISTORY_WRITE_FAILED；
#    本处曾用 backslash-n 的双引号字面量踩此坑，2026-10-03 实测由 crossfull 抓到；
#    守护臂见 test_gk_moa_batch_identity.py::test_history_payload_has_no_stray_double_quote）。
from gk_moa_aggregate import compute_batch_id, plan_key_from_task, merge_sealed_agent_score, arm_score, arm_observables
_b_plan = os.environ.get('GK_BATCH_PLAN','') or plan_key_from_task(out.get('task') or os.environ.get('GK_TASK',''))
_b_narrow = os.environ.get('GK_BATCH_NARROW','')
if not _b_narrow:
  _b_narrow = chr(10).join(sorted(str(x.get('id','')) for x in (gd.get('narrow_tasks') or []) if isinstance(x,dict)))
_b_epoch = os.environ.get('GK_BATCH_EPOCH','') or None
_batch_id = compute_batch_id(_b_plan, _b_narrow, _b_epoch) if (_b_plan or _b_narrow) else ''
# W2A-P2（2026-10-16）：**消融腿**观测量 —— §2 五件在**臂装配侧**产出（治 §14.7.1「仪器与结果变量
#   两条通道从未会合」）。Δ 经 env 「GK_ARM_DELTA」；φ/det_F1/cache 由 「arm_observables」 单源派生
#   （缺 S / 缺 gold / 缺 usage 各**具名拒估**，禁静默 0）。⚠ 本处禁 ASCII 双引号/反引号。
_D=os.environ.get('GK_ARM_DELTA','')
try:
  _Dn=int(str(_D).strip()) if str(_D).strip() else 0
except Exception:
  _Dn=0
_S=os.environ.get('GK_STRIDE','')
try:
  _Sn=int(str(_S).strip()) if str(_S).strip() else None
except Exception:
  _Sn=None
_gold=None
_rg=os.environ.get('GK_ARM_GOLD','')
if _rg:
  try: _gold=json.loads(_rg)
  except Exception: _gold=None
_obs=arm_observables(out, delta=_Dn, stride=_Sn, gold=_gold, provider=os.environ.get('GK_ARM_PROVIDER','') or 'deepseek')
entry={
  # F-REV-18 (2026-09-10): 原为 out.get('task','''\$task''')——任务文本被当 python 源码
  # 字面量内插。任务含 Windows 反斜杠路径（如 <home>）时 python 编译期即
  # SyntaxError（truncated \\UXXXXXXXX escape）→ 整块写回 heredoc 失败 → 被
  # '2>/dev/null || true' 静默吞掉 → subagent_history 不写 → ECO-EDIT→ECO-AUDIT
  # 门禁链断裂（与 L2865 注释自述的 tampered 断裂同路径、第二触发源）。
  # 修复：任务文本改经 env 传递（对齐 SUBAGENT_ID 模式），不再进入 python 源码。
  # F-REV-53（2026-09-14）：**去截断**。原 [:200] 使 task_fingerprint（F-REV-8 归属绑定）
  # 双向失效 —— standing 通道 task 前缀是固定 boilerplate（>200 字符），区分信息（词汇串）
  # 全在被截掉的尾部 ⟹ 实测 20/20 条同指纹（缺省锚=全留，绑定退化）；而 '--task' 传**全量
  # 原文**时指纹与存储副本不符（全排，MoA 零 references）。正解 = 去截断而非另落派生字段
  # （派生字段无法从记录重算 = 第二事实源）。展示侧仍有界（MoA 截 200/300）。
  'task':(out.get('task') or os.environ.get('GK_TASK','')),
  # 2026-08-28: ECC 字段上限由 runner 侧档位界限（_ECC_BOUNDS）权威裁切，聚合端保留有界全文，
  # 不再二次截断（MoA aggregator 消费此完整有界 ECC）。
  # 2026-09-08 dryrun 缺口3修复: 补 subagent_id/conclusion/kept/slashed/challenges — MoA
  # aggregator 溯源（trace.ids）与聚合裁决依赖这些字段；此前缺失致 trace.ids=['',''] +
  # conclusion 被误标 no_conclusion 可疑。
  'subagent_id': out.get('subagent_id',''),
  # F-REV-52（2026-09-14）：删二次截断。runner 侧已按 _ECC_BOUNDS[tier]['conclusion'] 权威
  # 裁切（tier3=2000 / tier4=3000），此处 [:500] 与之冲突、且与本段注释自述的「聚合端保留
  # 有界全文，不再二次截断」自相矛盾 ⇒ 实测 tier-3 臂结论 2000→500，丢 75%（F-REV-49 是
  # runner 侧恰好 2000，两者不同源，不可并案）。
  'conclusion': (out.get('conclusion') or ''),
  'kept': out.get('kept', [])[:5],
  'slashed': out.get('slashed', [])[:5],
  'challenges': out.get('challenges', [])[:5],
  'evidence':evidence,
  'findings':findings,
  'next_steps':out.get('next_steps',[]),
  'confidence':out.get('confidence',''),
  'tools_used':out.get('tools_used',[]),
  # 2026-10-19：结构化逐断言 + 实际工具调用轨迹（tools_used 是发放清单）。
  'assertions':out.get('assertions',[]),
  'tool_call_count':out.get('tool_call_count',0),
  # F-REV-52（2026-09-14）：7 维分原**只**落 '_sealed_agent_score'（单槽，下一臂即覆盖）
  # ⇒ 每臂评分不可回溯：本轮 arm1/arm2 的 7 维分已从 state 消失（只能从 CLI stdout 捞回）。
  # 补进 append-only 的 subagent_history ⟹ 随既有窗口 + 余烬全量转储留存。
  # T-c（2026-10-06，owner 裁定）：原注「不动 _sealed_agent_score 的单槽语义（覆盖即设计意图）」
  #   已作废 —— 单槽 = 单臂冒充 agent 侧 ⟹ 下方 P1-Seal #2 改为同批臂间 running mean。
  'seven_dim_score':out.get('seven_dim_score',{}) or {},
  'overall_score':out.get('overall_score') or arm_score(out),
  # F-REV-41 (2026-09-13): MoA 聚合器消费字段此前**未落库**（entry 白名单断链）⇒
  # gk_moa_aggregate._suspect_flags 的 vocab_violation / budget_* 永不触发、
  # hmac_status 恒 'verified_at_write'（实装但零生效假绿）。补齐聚合器读侧字段面 +
  # 落 HMAC 校验态（GK_HMAC_VALID ∈ valid|no_hmac|skip|invalid，由外层 bash 注入）。
  'verdicts':out.get('verdicts',{}) or {},
  'vocab_violations':out.get('vocab_violations',[]) or [],
  'budget_status':out.get('budget_status','ok'),
  'total_tokens':out.get('total_tokens',0),
  'token_budget':out.get('token_budget'),
  'total_items':out.get('total_items',0),
  'item_budget':out.get('item_budget'),
  'hmac_status':os.environ.get('GK_HMAC_VALID','skip'),
  # C3②（ECC-3BECE9FAD12A，2026-09-27）：落库条目补**指针** —— 指向全量 ECC JSON 与双盲
  #   评分报告的落盘文件（外层 sub_out_file / sub_report_file，经 env 传入，对齐 SUBAGENT_ID 模式）。
  #   此前 entry 只有摘要，主 agent 审核 / 人类评分须凭 subagent_id 去 docs/analysis/subagent/
  #   反查（隐式约定）。⚠ 注释内禁 ASCII 反引号（本 payload 在 bash 双引号区内，反引号触发命令替换）。
  'output_file':os.environ.get('GK_OUTPUT_FILE',''),
  'report_file':os.environ.get('GK_REPORT_FILE',''),
  'machine_check':_mc,
  # §18.1（2026-10-03）：批身份 + 档位（与 batch_id 同批补，治 ECC-489C8AE274E6）；
  #   tier 由外层 env SUBAGENT_TIER 注入（角色/窄任务路由的最终值）。
  'batch_id':_batch_id,
  'tier':os.environ.get('SUBAGENT_TIER',''),
  # §18.3（2026-10-04）：组别身份（G1 相同对 / G2 正交互补 / G3 污染组）—— 由派发侧编排方
  #   显式注入（实测聚合端**不可机检**：无此字段时窄任务指纹簇≠真组，且 template 注入不进
  #   _POISON_PATTERNS ⟹ 组③结构性不可见）。聚合端只读不猜。
  'arm_group':os.environ.get('GK_ARM_GROUP',''),
  # W2A-P2（2026-10-16）：消融腿 —— Δ（派发侧显式注入，聚合端只读不猜）+ 观测量（φ/det_F1/cache，
  #   由 §2 五件在**臂装配侧**产出，非事后从 verdicts 推）。
  'arm_delta':os.environ.get('GK_ARM_DELTA',''),
  'arm_obs':_obs
}
# Capture access violations for audit trail (crypto material access attempts)
avs=out.get('access_violations',[])
if avs:
  entry['access_violations']=[{'tool':a.get('tool',''),'path':a.get('path',''),'reason':a.get('reason',''),'timestamp':a.get('timestamp','')} for a in avs[:10]]
# C4③（ECC-D9D2382BB535）：投影键集**自检** —— entry 键必须 ⊆ 声明集 _ENTRY_KEYS
#   （防再丢面 / 误加面）；越集即 fail-loud（非零退出 → 外层 HISTORY_WRITE_FAILED 兜底）。
_extra=sorted(set(entry)-set(_ENTRY_KEYS))
if _extra:
  raise SystemExit('ENTRY_KEY_UNDECLARED: %s' % _extra)
# R3: JTI replay detection (Map + prune, inspired by ATH jti-replay.ts)
# 2026-09-22（R22 / 红队 C4 修复）：原实现 = **仅**「按过期惰性 prune」，两个缺口：
#   ① **无上限**：每次 subagent 落库都写一条 ⟹ 表随写入频率无界增长，与 state
#      262144 B 阈值耦合 —— 撞阈后本块 json.dump **整份写失败**，而下行以 || true
#      兜底 ⟹ jti 记录不落盘 ⟹ **静默 fail-open**（重放不再被拦），且病象呈现为
#      无关的'写失败'（判据指向错误方向）。
#   ② **缺 nonce 时静默跳过**（原 if nonce 双分支皆不执行）⟹ 零留痕 = 静默放弃防重放。
#   修法：prune-on-write（保留）+ **上限驱逐**（超 _JTI_MAX 按**最早过期**先删，即只删
#      最接近失效者 ⟹ 对「1h 内重放拦截」的削弱最小）+ 驱逐/缺 nonce **留痕**。
#      告警不可走 stderr（本块的 stderr 由收尾重定向汇入 GK_DBG_LOG、非直出用户面；
#      C3① 之前更是整段被吞）⟹ 直接追加日志。
import time as _t
now_s=_t.time()
_JTI_MAX=2000
jti_store=gd.setdefault('jti_store',{})
# Prune expired entries (prune-on-write)
expired=[k for k,v in jti_store.items() if v<now_s]
for k in expired: del jti_store[k]
_evicted=0
if len(jti_store)>_JTI_MAX:
  for k in sorted(jti_store,key=lambda x:jti_store[x])[:len(jti_store)-_JTI_MAX]:
    del jti_store[k]; _evicted+=1
nonce=out.get('nonce','')
if _evicted or not nonce:
  try:
    open(os.path.join(os.environ['GK_PY_SCRIPTS'],'gk_dbg.log'),'a',encoding='utf-8').write(
      '[jti] WARN %s pruned=%d evicted=%d size=%d nonce=%s %s\n'
      % ('nonce 缺失 → 本轮防重放未生效' if not nonce else '上限驱逐',
         len(expired), _evicted, len(jti_store), nonce or '<empty>',
         __import__('datetime').datetime.now().astimezone().isoformat()))
  except Exception:
    pass
if nonce and nonce in jti_store:
  print(json.dumps({'ok':False,'error':'JTI_REPLAY','nonce':nonce,'subagent_id':out.get('subagent_id','')}))
  sys.exit(0)
if nonce:
  jti_store[nonce]=now_s+3600  # 1h expiry (matches JWT exp)
hist.append(entry)
# t4(a)（2026-10-17，ECC-2E9DA8D90CB2）：**臂输出全量直接落卫星 history 片**，state 只留元数据。
#   原状：conclusion 全量内联，卫星片仅在 >96KB 溢出时才产生（主 state 非「只存元数据」）。
#   序：① 全量落片（in-tx 并入 gd 的 satellite_index，禁另起 state 写）→ ② **成功才**抹成
#   元数据投影（spilled / conclusion_len）；落片失败**保留全量**（fail-safe，禁静默丢结论）。
#   读侧 gk_moa_aggregate._satellite_history_union 按 subagent_id 用片内全量**原位替换**占位。
#   ⚠ 本 payload 在 bash 双引号区内 ⟹ 禁 ASCII 反引号 + 禁 ASCII 双引号。
try:
  import os as _os3
  sys.path.insert(0,_os3.environ['GK_PY_SCRIPTS'])
  import gk_satellite as _sat4
  _r4=_sat4.append(_os3.environ['GK_PY_STATE'],'history',[entry],
                   batch_id=(entry.get('batch_id') or 'history-live'),
                   arm=(entry.get('subagent_id') or 'state'), gd=gd)
  if _r4.get('ok'):
    entry['conclusion_len']=len(str(entry.get('conclusion') or ''))
    entry['spilled']=True
    entry.pop('conclusion',None)
  else:
    sys.stderr.write('HISTORY_SPILL_FAILED n=1: %s\n' % (_r4.get('error'),))
except Exception as _sx:
  sys.stderr.write('HISTORY_SPILL_FAILED n=1: %s\n' % (_sx,))
# F-REV-51/52（2026-09-14）：条数配额 → 字节配额。条数与 state 阈值（262144 B）**不同量纲**
# ⇒ 一改 conclusion 界（500→档位 2000）就会撞阈值 = F-REV-51 的病因。改为与阈值同量纲：
# 按序列化字节从**最旧**裁、保留最近（至少留 1 条）；条数上限保留为兜底。
# 先例：gk_narrow_route._NT_MAX_TOTAL_BYTES（清单侧同用字节配额）。
# 80KB 的预算依据（2026-09-14 实测）：file=gate_data 184,328 + 顶层/格式 32,200；
# 262,144 − 95,413（非 history 分量）− 64KB（narrow_tasks 自身设计上限，须预留）≈ 102KB
# ⟹ 取 80KB 留余量（≈10-11 臂 ≈3-4 轮 @3臂/轮）。实测 48KB 只能留 6 臂，窗口过窄。
# 2026-09-27（用户裁定「提配额+归档释放」）：80KB→96KB。背景=6 臂窗口（3 组×2）在 80KB 下
#   装不下第 6 臂（实测 5 臂 77,366 B，第 6 臂 ~15.9KB ⟹ 插入即被下方 pop(0) 当场淘汰，写回
#   ok 但零净增）；同批归档 gate_data.task_pipeline（13 条已决，−67.7KB）⟹ state 190,377 B，
#   余量足够容纳 96KB 的 history。
# 2026-10-26（owner 裁定「裁剪线抬到 128KB/196KB」）：96KB→128KB。
# 2026-11-02（owner 裁定「收紧 payload 配额」）：三腿各 **5% = 128KB**，合计 15%，
#   其余 85% 留给其它 key。依据：卫星片/冷侧车已承接 bulk；history 一窗只需
#   一轮（6 臂 × 16KB × 1.2 ≈ 118KB），不再按 10 轮 60 臂定价。
#   单源 = `gk_json_utils.HIST_MAX_BYTES`（本行为同值字面量，bash 不可 import；
#   漂移由 `scripts/test_gk_state_trim_lines.py` 逐值守）。
_HIST_MAX_BYTES=131072  # 128KB = STATE_SIZE_WALL * 5 // 100
# 逃生舱：「GK_STATE_TRIM_KB=196」把本腿裁剪线**显式覆盖**为 196KB（不改源码）
try:
  _kb=int(os.environ.get('GK_STATE_TRIM_KB') or 0)
  if _kb>0: _HIST_MAX_BYTES=_kb*1024
except Exception:  # noqa: BLE001 — 非法值回落到缺省
  pass
# C1②（ECC-0F1DAF8C787C，2026-09-28）：溢出条目**代数归档**（对齐 gk_finding.archive_closed 先例）
#   —— 原 hist.pop(0) 直接丢弃（不可回溯，与「提配额+归档释放」裁定相悖）；改为先把出窗条目
#   append 到旁挂 <state>.history-archive.jsonl（append-only，可回溯、不删），再出窗。
#   归档写失败**不阻断**（否则落库全失），但须留痕（stderr 由本段收尾重定向汇入 GK_DBG_LOG）。
#   ⚠ 变量名避开上方 JTI 的 _evicted（同名会串味）。
_hist_evicted=[]
while len(hist)>1 and len(json.dumps(hist,ensure_ascii=False).encode())>_HIST_MAX_BYTES:
  _hist_evicted.append(hist.pop(0))
if len(hist)>20:
  _hist_evicted+=hist[:-20]; hist[:]=hist[-20:]
if _hist_evicted:
  # P1 后续（c5 收敛，2026-10-06）：片写**收敛为调中枢** gk_satellite（禁第二直写者）。
  #   **按条入账**：每条以其**自身身份** (batch_id, arm=subagent_id) 落 per-arm 索引叶子
  #   （c5「片数==臂数」在**真实派发路径**成立；多条并成同一叶子会互相覆盖索引项）。
  #   本段在 dump_state **之前** ⟹ 索引**必须 in-tx 并入 gd**（传 gd），禁另起 state 写。
  try:
    import os as _os2
    sys.path.insert(0,_os2.environ['GK_PY_SCRIPTS'])
    import gk_satellite as _sat2
    for _e in _hist_evicted:
      if _e.get('spilled'):
        continue  # t4(a)：已在入库时全量落片 ⟹ 防同一条写两行
      _r2=_sat2.append(_os2.environ['GK_PY_STATE'],'history',[_e],
                       batch_id=(_e.get('batch_id') or 'history-overflow'),
                       arm=(_e.get('subagent_id') or 'state'), gd=gd)
      if not _r2.get('ok'):
        sys.stderr.write('HISTORY_ARCHIVE_FAILED n=1: %s\n' % (_r2.get('error'),))
  except Exception as _ax:
    sys.stderr.write('HISTORY_ARCHIVE_FAILED n=%d: %s\n' % (len(_hist_evicted), _ax))
gd['subagent_history']=hist
gd['subagent_last']=entry
# P1-Seal #2: plan-refinement output sealed to _sealed_agent_score
# Not written to monitor_scores — prevents human anchor bias during adjudicate
# T-c（2026-10-06，owner 裁定）：由**单槽覆盖**改为**同批臂间 running mean** ——
#   原实现令该槽 = 最后完成的那条臂（**单臂冒充 agent 侧**），adjudicate 的 divergence
#   基准随完成顺序漂移（实测本批 0.4471 = 某单臂 7 维均）。
#   merge_sealed_agent_score 保持返回形状不变（新增透明键 batch_id/arm_count/arm_ids）
#   ⟹ D10（gk_audit_state）/appeal/mediation 消费者零回归；单臂/跨批与旧语义逐字等价。
task_str=out.get('task','')
if 'plan-refinement' in task_str:
  import time as _ts
  gd['_sealed_agent_score']=merge_sealed_agent_score(
    gd.get('_sealed_agent_score') or {}, out, _batch_id, _ts.time())
if not dump_state(os.environ['GK_PY_STATE'], d):
  print(json.dumps({'ok':False,'error':'HISTORY_WRITE_FAILED','subagent_id':out.get('subagent_id','')}))
  sys.exit(3)
_lk.__exit__(None, None, None)
" 2>>"${GK_DBG_LOG:-/dev/null}" || {
  # C3①（ECC-3BECE9FAD12A，2026-09-27）：原收尾 = 丢弃 stderr + 兜底真值 —— 落库失败 / 载荷异常
  #   全被吞 ⟹ subagent_history 不写而无人知（ECO-EDIT→ECO-AUDIT 门禁链静默断裂）。改为 fail-loud：
  #   stderr 汇入调试日志 + 显式报错到 stderr + 非零返回（不再兜底成功）。
  printf '[hist] ERROR HISTORY_WRITE_FAILED sid=%s ts=%s\n' "$subagent_id" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${GK_DBG_LOG:-/dev/null}" 2>&1 || true
  echo "{\"ok\":false,\"error\":\"HISTORY_WRITE_FAILED\",\"subagent_id\":\"${subagent_id}\"}" >&2
  return 1
}
      # F-REV-93（2026-09-17，用户裁定「其他都同意」）：上方经 `dump_state`（原子写、锁内）落 `$STATE_FILE`
      #   （写 `subagent_history` / `subagent_last` / `_sealed_agent_score`），原先**其后无**
      #   `_state_checksum_write` ⟹ `_checksum` 停在上一版 `gate_data` 的摘要上 ⟹ 每次 subagent
      #   跑完 `self-check` 必报 `checksum_integrity FAIL`，且 `guard-edit` / `advance` 入口的
      #   `_state_checksum_verify` 有**误报 TAMPERED** 风险（会阻断后续写类子命令）。
      #   同型先例（均为"直写后补重算"）：`cron_scheduler` 直写 state、`register|close|verify`
      #   后补 —— 本处为**第三处漏点**（既有代码，非 ⑰-8 引入）。
      #   实测证据：`.gatekeeper.state` 的 mtime 与冒烟测结束时刻**逐秒一致**，且规范入口
      #   `bash gatekeeper-cli.sh self-check` 得 `checksum_integrity FAIL: saved=… computed=…`。
      #   ⚠ 必须在**同一分支内、写之后**调用（`_state_checksum_write` 现由 python `state_lock` 持锁）。
      _state_checksum_write
    fi
    # F-REV-92(a)：走到正常收尾 ⟹ 注销运行记录（否则下次派发会误判"上一轮异常终止"）。
    _gk_subagent_watch_disarm
    return 0
  fi

  # --- LOCAL MODE (structural, deterministic) ---
  local checks="[" total_req=0 passed=0

  # Collect hard evidence cross-validation
  _collect_hard_evidence "$stage" "$worktree" "$branch"
  local evidence; evidence=$(_emit_hard_evidence_json)

  # STAGE_0 (START — Worktree Setup + Plan Restore)
  if [ "$stage" = "STAGE_0" ]; then total_req=3
    [ "$ev_worktree_exists" = "true" ] && { checks+='{"item":"feature_worktree_exists","status":"PASS","score":1.0,"evidence":"'"$worktree"' exists"},'; passed=$((passed+1)); } || checks+='{"item":"feature_worktree_exists","status":"FAIL","score":0.0,"evidence":"no worktree"},';
    [ "$ev_branch_not_main" = "true" ] && [ -n "$branch" ] && { checks+='{"item":"branch_not_main","status":"PASS","score":1.0,"evidence":"'"$branch"'"},'; passed=$((passed+1)); } || checks+='{"item":"branch_not_main","status":"FAIL","score":0.0,"evidence":"main or null"},';
    [ "$ev_plan_restored" = "true" ] && { checks+='{"item":"plan_restored_to_worktree","status":"PASS","score":1.0,"evidence":"plan in worktree"},'; passed=$((passed+1)); } || checks+='{"item":"plan_restored_to_worktree","status":"FAIL","score":0.0,"evidence":"no plan in worktree"},';
  fi

  # STAGE_1 (CODE)
  if [ "$stage" = "STAGE_1" ]; then total_req=7
    [ "$ev_worktree_exists" = "true" ] && { checks+='{"item":"feature_worktree_exists","status":"PASS","score":1.0,"evidence":"'"$worktree"' exists"},'; passed=$((passed+1)); } || checks+='{"item":"feature_worktree_exists","status":"FAIL","score":0.0,"evidence":"no worktree"},';
    [ "$ev_branch_not_main" = "true" ] && [ -n "$branch" ] && { checks+='{"item":"branch_not_main","status":"PASS","score":1.0,"evidence":"'"$branch"'"},'; passed=$((passed+1)); } || checks+='{"item":"branch_not_main","status":"FAIL","score":0.0,"evidence":"main or null"},';
    # F-09: Check actual guard-edit record in gate_data (not just stage check)
    local ge_called; ge_called=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --gt gate_data.guard_edit_count 0 2>/dev/null)
    [ "$ge_called" = "yes" ] && { checks+='{"item":"guard_edit_called","status":"PASS","score":1.0,"evidence":"guard-edit recorded in gate_data"},'; passed=$((passed+1)); } || checks+='{"item":"guard_edit_called","status":"WARN","score":0.5,"evidence":"no guard-edit record — run guard-edit before coding"},';
    [ "$ev_build_exists" = "true" ] && { checks+='{"item":"compiled_and_tested","status":"PASS","score":1.0,"evidence":"build+ctest run"},'; passed=$((passed+1)); } || checks+='{"item":"compiled_and_tested","status":"FAIL","score":0.0,"evidence":"no build — run cmake+ctest"},';
    [ "${ev_commits_ahead}" -gt 0 ] 2>/dev/null && { checks+='{"item":"commits_ahead_of_main","status":"PASS","score":1.0,"evidence":"'"$ev_commits_ahead"' ahead"},'; passed=$((passed+1)); } || checks+='{"item":"commits_ahead_of_main","status":"FAIL","score":0.0,"evidence":"0 commits — nothing coded"},';
    [ "$ev_ci_trigger" = "present" ] && { checks+='{"item":"ci_trigger_registered","status":"PASS","score":1.0,"evidence":"branch in ci.yml"},'; passed=$((passed+1)); } || checks+='{"item":"ci_trigger_registered","status":"FAIL","score":0.0,"evidence":"not in ci.yml"},';
    [ "$ev_l4_marker" = "true" ] && { checks+='{"item":"l4_cross_review","status":"PASS","score":1.0,"evidence":"L4 marker (commits or state)"},'; passed=$((passed+1)); } || checks+='{"item":"l4_cross_review","status":"WARN","score":0.5,"evidence":"no L4 marker — push ONLY after L1-L4"},';
  fi

  # STAGE_2 (CI)
  if [ "$stage" = "STAGE_2" ]; then total_req=3
    [ "$ev_pushed" = "true" ] && { checks+='{"item":"pushed_to_remote","status":"PASS","score":1.0,"evidence":"SHA match"},'; passed=$((passed+1)); } || checks+='{"item":"pushed_to_remote","status":"FAIL","score":0.0,"evidence":"not pushed"},';
    # F-08: Check CI status from state file (not hardcoded)
    local ci_status; ci_status=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get gate_data.ci_status --default unknown 2>/dev/null)
    if [ "$ci_status" = "green" ]; then
      checks+='{"item":"ci_triggered","status":"PASS","score":1.0,"evidence":"CI green"},'; passed=$((passed+1))
      checks+='{"item":"all_platforms_green","status":"PASS","score":1.0,"evidence":"all platforms green"},'; passed=$((passed+1))
    elif [ "$ci_status" = "red" ]; then
      checks+='{"item":"ci_triggered","status":"PASS","score":1.0,"evidence":"CI triggered"},'; passed=$((passed+1))
      checks+='{"item":"all_platforms_green","status":"FAIL","score":0.0,"evidence":"CI red"},'
    else
      checks+='{"item":"ci_triggered","status":"ACTION","score":0.5,"evidence":"CI status unknown — check manually"},'
      checks+='{"item":"all_platforms_green","status":"ACTION","score":0.5,"evidence":"CI status unknown — check manually"},'
    fi
    if [ "$stage" = "STAGE_2" ]; then
      local dc_data; dc_data=$(echo "$evidence" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field gitnexus_detect --default '' 2>/dev/null || echo "")
      if [ -n "$dc_data" ] && [ "$dc_data" != "{}" ]; then
        checks+='{"item":"detect_changes_scope","status":"PASS","score":1.0,"evidence":"detect-changes data available"},'
        passed=$((passed+1))
      else
        if [ "${GK_ALLOW_NO_DETECT:-0}" = "1" ]; then
          checks+='{"item":"detect_changes_scope","status":"WARN","score":0.5,"evidence":"detect data unavailable — explicit degrade GK_ALLOW_NO_DETECT=1"},'
        else
          checks+='{"item":"detect_changes_scope","status":"FAIL","score":0.0,"evidence":"detect-changes data unavailable — 分支索引未就绪时先 gitnexus analyze（含 --branch）后重试，或 GK_ALLOW_NO_DETECT=1 显式降级"},'
        fi
      fi
      total_req=$((total_req+1))
    fi
  fi

  # STAGE_3 (REVIEW)
  if [ "$stage" = "STAGE_3" ]; then total_req=9
    local sc; sc=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get gate_data.sprint_contract --default "" 2>/dev/null)
    [ -n "$sc" ] && { checks+='{"item":"sprint_contract","status":"PASS","score":1.0,"evidence":"contract exists in gate_data"},'; passed=$((passed+1)); } || checks+='{"item":"sprint_contract","status":"FAIL","score":0.0,"evidence":"no sprint contract — declare scope+dimensions+failure_conditions BEFORE reviewing code"},';
    { [ "$ev_gitnexus_status" = "current" ] || [ "$ev_gitnexus_status" = "reusable" ]; } && { checks+='{"item":"l3_gitnexus_baseline","status":"PASS","score":1.0,"evidence":"gitnexus up to date"},'; passed=$((passed+1)); } || checks+='{"item":"l3_gitnexus_baseline","status":"FAIL","score":0.0,"evidence":"gitnexus stale"},';
    [ "$ev_l4_marker" = "true" ] && { checks+='{"item":"l4_niantic_reference","status":"PASS","score":1.0,"evidence":"L4 completed (commits or state)"},'; passed=$((passed+1)); } || checks+='{"item":"l4_niantic_reference","status":"FAIL","score":0.0,"evidence":"no L4 evidence"},';
    # F-07: l5_blind_spot — sc2034 (unused variables = potential bypasses)
    # 2026-08-26: 插件 shellcheck_scan 优先（确定性零依赖）；插件不可用回退外部 shellcheck。
    local sc2034_count sc_total sc_src
    local plugin_sc; plugin_sc=$(_plugin_sc_counts)
    if [ -n "$plugin_sc" ]; then
      sc2034_count=$(echo "$plugin_sc" | awk '{print $1}')
      sc_total=$(echo "$plugin_sc" | awk '{print $2}')
      sc_src="plugin"
    else
      # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
      sc2034_count=$(shellcheck --severity=warning "$SKILL_DIR/gatekeeper-cli.sh" 2>/dev/null | "$RG" -c 'SC2034' || true)
      sc_total=$(shellcheck --severity=warning "$SKILL_DIR/gatekeeper-cli.sh" 2>/dev/null | "$RG" -c 'SC[0-9]' || true)
      sc_src="shellcheck"
    fi
    sc2034_count=${sc2034_count:-0}
    sc_total=${sc_total:-0}
    [ "$sc2034_count" -eq 0 ] && { checks+='{"item":"l5_blind_spot","status":"PASS","score":1.0,"evidence":"no unused variables (sc2034, '"$sc_src"')"},'; passed=$((passed+1)); } || checks+='{"item":"l5_blind_spot","status":"WARN","score":0.5,"evidence":"'"$sc2034_count"' unused variables detected (sc2034, '"$sc_src"')"},';
    [ "$ev_plan_restored" = "true" ] && [ "$ev_plan_mtime" != "0" ] && { checks+='{"item":"l6_architecture_sync","status":"PASS","score":1.0,"evidence":"plan synced"},'; passed=$((passed+1)); } || checks+='{"item":"l6_architecture_sync","status":"WARN","score":0.5,"evidence":"plan not synced"},';
    [ "$ev_plan_backup" = "true" ] && { checks+='{"item":"plan_backup_synced","status":"PASS","score":1.0,"evidence":"backup exists"},'; passed=$((passed+1)); } || checks+='{"item":"plan_backup_synced","status":"FAIL","score":0.0,"evidence":"no backup"},';
    # F-06: dead_code_gate1 — sc 规则总警告数（插件 shellcheck_scan 或回退 shellcheck）
    [ "$sc_total" -le 5 ] && { checks+='{"item":"dead_code_gate1","status":"PASS","score":1.0,"evidence":"sc warnings: '"$sc_total"' (threshold 5, '"$sc_src"')"},'; passed=$((passed+1)); } || checks+='{"item":"dead_code_gate1","status":"WARN","score":0.5,"evidence":"sc warnings: '"$sc_total"' exceed threshold ('"$sc_src"')"},';
    # F-06: dead_code_gate2 — detect unreferenced function definitions
    local defined_funcs referenced_funcs unref_count
    # 2026-08-13 同批修复：rg -oE 组合短标志中 -E=--encoding（扩展正则默认开启），去掉 E。
    # 2026-08-20 盲区修复：referenced 提取排除定义行（rg -v '^fn()'），
    #   消除"定义行自引用 → unref 恒 0 → gate2 永远 PASS"的失效 bug。
    # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
    defined_funcs=$( "$RG" -o '^[a-z_][a-zA-Z0-9_]*\(\)' "$SKILL_DIR/gatekeeper-cli.sh" 2>/dev/null | sed 's/()//' | sort -u || echo "")
    referenced_funcs=$( "$RG" -v '^[a-z_][a-zA-Z0-9_]*\(\)' "$SKILL_DIR/gatekeeper-cli.sh" 2>/dev/null | "$RG" -o '\b[a-z_][a-zA-Z0-9_]*\b' | sort -u || echo "")
    unref_count=0
    while IFS= read -r fn; do
      [ -z "$fn" ] && continue
      echo "$referenced_funcs" | "$RG" -qxF "$fn" || unref_count=$((unref_count+1))
    done <<< "$defined_funcs"
    [ "$unref_count" -eq 0 ] && { checks+='{"item":"dead_code_gate2","status":"PASS","score":1.0,"evidence":"'"$unref_count"' unreferenced functions"},'; passed=$((passed+1)); } || checks+='{"item":"dead_code_gate2","status":"WARN","score":0.5,"evidence":"'"$unref_count"' unreferenced functions detected"},';
    # F-06: dead_code_gate3 — large inline python3 -c blocks (maintenance risk)
    local big_py_blocks
    big_py_blocks=$(python3 "$SKILL_DIR/scripts/gk_source_scan.py" large-inline-blocks "$SKILL_DIR/gatekeeper-cli.sh" 2>/dev/null || echo 0)
    big_py_blocks=${big_py_blocks:-0}
    [ "$big_py_blocks" -le 5 ] && { checks+='{"item":"dead_code_gate3","status":"PASS","score":1.0,"evidence":"'"$big_py_blocks"' large inline blocks (>40 lines, threshold 5)"},'; passed=$((passed+1)); } || checks+='{"item":"dead_code_gate3","status":"WARN","score":0.5,"evidence":"'"$big_py_blocks"' large inline blocks exceed threshold"},';
    # F-08: python_lint — ruff check --select F on scripts/*.py（2026-08-26 接入门禁）
    # 外部 binary 为可选增强：未装 → PASS（不阻断）；已装 → 0 findings PASS / >0 WARN（不稀释 score）
    local _py_findings=0
    if command -v ruff &>/dev/null; then
      _py_findings=$(ruff check --select F "$SKILL_DIR"/scripts/*.py 2>/dev/null | wc -l || true)
      _py_findings=${_py_findings:-0}
      [ "$_py_findings" -eq 0 ] && { checks+='{"item":"python_lint","status":"PASS","score":1.0,"evidence":"ruff: 0 F findings on scripts/*.py"},'; passed=$((passed+1)); } || checks+='{"item":"python_lint","status":"WARN","score":0.5,"evidence":"ruff: '"$_py_findings"' F findings on scripts/*.py"},';
    else
      # 2026-11-01（假绿修）：依赖缺失 ≠ 通过 ⟹ SKIP 且**不计入 total**（原 PASS/1.0 白送分）。
      checks+='{"item":"python_lint","status":"SKIP","score":0.0,"evidence":"ruff not installed — 未评估（不计入 passed/total）"},';
      total_req=$((total_req-1));
    fi
  fi

  # STAGE_4 (MERGE)
  if [ "$stage" = "STAGE_4" ]; then total_req=7
    [ "$ev_plan_backup" = "true" ] && { checks+='{"item":"pre_pr_backup","status":"PASS","score":1.0,"evidence":"backup exists"},'; passed=$((passed+1)); } || checks+='{"item":"pre_pr_backup","status":"FAIL","score":0.0,"evidence":"no backup"},';
    [ "$ev_merge_commit" = "true" ] && { checks+='{"item":"pr_merged","status":"PASS","score":1.0,"evidence":"merge commit found"},'; passed=$((passed+1)); } || checks+='{"item":"pr_merged","status":"FAIL","score":0.0,"evidence":"no merge commit"},';
    [ "$ev_main_aligned" = "true" ] && { checks+='{"item":"main_aligned","status":"PASS","score":1.0,"evidence":"origin==local"},'; passed=$((passed+1)); } || checks+='{"item":"main_aligned","status":"FAIL","score":0.0,"evidence":"not aligned"},';
    [ "$ev_plan_restored" = "true" ] && { checks+='{"item":"plan_restored","status":"PASS","score":1.0,"evidence":"plan in docs"},'; passed=$((passed+1)); } || checks+='{"item":"plan_restored","status":"FAIL","score":0.0,"evidence":"plan missing"},';
    { [ "$ev_gitnexus_status" = "current" ] || [ "$ev_gitnexus_status" = "reusable" ]; } && { checks+='{"item":"gitnexus_post_r","status":"PASS","score":1.0,"evidence":"index current"},'; passed=$((passed+1)); } || checks+='{"item":"gitnexus_post_r","status":"FAIL","score":0.0,"evidence":"index stale"},';
    # 2026-11-01（假绿修）：原两条**无条件 PASS**（README: "PR invariant met" / "not yet time"），
    #   完全不读事实 ⟹ 改为 SKIP 且不计入 total（真正查 PR 内容需 PR 元数据源，留待独立任务）。
    checks+='{"item":"no_plan_in_pr","status":"SKIP","score":0.0,"evidence":"未评估（缺 PR 元数据来源）"},';
    checks+='{"item":"no_changelog","status":"SKIP","score":0.0,"evidence":"未评估（缺变更日志来源）"},';
    total_req=$((total_req-2));
  fi

  # STAGE_5 (RETIRE)
  if [ "$stage" = "STAGE_5" ]; then total_req=6
    [ "$ev_plan_backup" = "true" ] && { checks+='{"item":"final_backup","status":"PASS","score":1.0,"evidence":"backup present"},'; passed=$((passed+1)); } || checks+='{"item":"final_backup","status":"FAIL","score":0.0,"evidence":"missing"},';
    [ "$ev_worktree_removed" = "true" ] && { checks+='{"item":"worktree_removed","status":"PASS","score":1.0,"evidence":"clean"},'; passed=$((passed+1)); } || checks+='{"item":"worktree_removed","status":"FAIL","score":0.0,"evidence":"worktree still exists"},';
    [ "$ev_branch_deleted" = "true" ] && { checks+='{"item":"branch_deleted","status":"PASS","score":1.0,"evidence":"deleted"},'; passed=$((passed+1)); } || checks+='{"item":"branch_deleted","status":"FAIL","score":0.0,"evidence":"branch still exists"},';
    [ "$cur_stage" = "DONE" ] && { checks+='{"item":"cli_advance_done","status":"PASS","score":1.0,"evidence":"DONE"},'; passed=$((passed+1)); } || checks+='{"item":"cli_advance_done","status":"WARN","score":0.5,"evidence":"'"$cur_stage"' not DONE"},';
    [ "$ev_temp_scripts_clean" = "true" ] && { checks+='{"item":"temp_scripts_cleaned","status":"PASS","score":1.0,"evidence":"clean"},'; passed=$((passed+1)); } || checks+='{"item":"temp_scripts_cleaned","status":"WARN","score":0.5,"evidence":"temp files remain"},';
    # P2: GitNexus status — verify index is current before retirement
    # 2026-09-21 R16/C2′：收编到单点，并消灭原 fail-open —— 原写法是"文本不含 stale 即 PASS"
    # ⟹ 探测失败（unavailable）也报 PASS「index current」= **未验证却报绿**。
    # 现：stale → FAIL（真过期）；unavailable → **WARN**（未验证，不阻断退休）；
    # current|reusable → PASS。与同文件 `cmd_self_check` / ECO 支口径一致。
    local _retire_dir _gn_retire="unavailable"
    _retire_dir=$(_gx_repo_dir_for_current 2>/dev/null) || _retire_dir=""
    [ -n "$_retire_dir" ] && _gn_retire=$(_gitnexus_baseline_status "$_retire_dir")
    case "$_gn_retire" in
      current|reusable)
        checks+='{"item":"gitnexus_pre_retire","status":"PASS","score":1.0,"evidence":"gitnexus index '"$_gn_retire"'"},'; passed=$((passed+1)) ;;
      stale)
        checks+='{"item":"gitnexus_pre_retire","status":"FAIL","score":0.0,"evidence":"gitnexus index stale — run gitnexus analyze"},' ;;
      *)
        checks+='{"item":"gitnexus_pre_retire","status":"WARN","score":0.5,"evidence":"gitnexus status unavailable — 未验证（探测失败）"},' ;;
    esac
  elif echo "$stage" | "$RG" -q '^ECO-'; then
    # ECO phases scored separately: agent via monitor --subagent plan-refinement,
    # human via adjudicate --verdicts F1-F7. This is a lightweight infra health check.
    total_req=2
    # 2026-09-21 R16/C2′：收编到单点（原直调 + 文本匹配）；`reusable` = 内容一致 ⟹ 基建健康 PASS。
    local _eco_dir _eco_gx="unavailable"
    _eco_dir=$(_gx_repo_dir_for_current 2>/dev/null) || _eco_dir=""
    [ -n "$_eco_dir" ] && _eco_gx=$(_gitnexus_baseline_status "$_eco_dir")
    case "$_eco_gx" in
      current|reusable)
        checks+='{"item":"gitnexus_current","status":"PASS","score":1.0,"evidence":"index '"$_eco_gx"'"},'; passed=$((passed+1)) ;;
      *)
        checks+='{"item":"gitnexus_current","status":"WARN","score":0.5,"evidence":"gitnexus '"$_eco_gx"' — run analyze"},' ;;
    esac
    local eco_phase_progress; eco_phase_progress=$(GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" python3 -c "
import json,os; d=json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'))
ec=d.get('gate_data',{}).get('eco_completions',{})
print(len(ec))
" 2>/dev/null || echo "0")
    [ "$eco_phase_progress" -gt 0 ] 2>/dev/null && { checks+='{"item":"eco_advances_recorded","status":"PASS","score":1.0,"evidence":"ECO phases advancing"},'; passed=$((passed+1)); } ||
      checks+='{"item":"eco_advances_recorded","status":"WARN","score":0.5,"evidence":"no ECO advances — standing plan active?"},'
    # 2026-08-28 T7.12(B)+1 实装（batch8 覆盖缺口补项）：--local ECO 分支由 2 项基建健康
    # 扩展为每阶段质量项（基线/审查产物/收敛方案/质询报告/文档同步），确定性 0 API。
    case "$stage" in
      ECO-RESEARCH|ECO-SCAN|ECO-READ)
        total_req=3
        # 基线完整：代码库地图（subagent-context.json 签名载体）存在
        if [ -s "${SKILL_DIR}/references/subagent-context.json" ]; then
          checks+='{"item":"codebase_map","status":"PASS","score":1.0,"evidence":"subagent-context.json present"},'; passed=$((passed+1));
        else
          checks+='{"item":"codebase_map","status":"WARN","score":0.5,"evidence":"subagent-context.json missing — run context --update"},';
        fi
        # 审查产物：subagent 分析留痕 —— **union 读面**（主 state ⊕ 卫星 history 片，
        #   卫星计划对齐：写侧溢出已落片，只读 live 会误报空历史）；读失败 fail-loud 进 WARN。
        local eco_read_art
        eco_read_art=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --history-len 2>>"$GK_DBG_LOG")
        if ! [[ "$eco_read_art" =~ ^[0-9]+$ ]]; then
          checks+='{"item":"analysis_artifact","status":"WARN","score":0.5,"evidence":"history unreadable — see GK_DBG_LOG"},'
        elif [ "$eco_read_art" -gt 0 ]; then
          checks+='{"item":"analysis_artifact","status":"PASS","score":1.0,"evidence":"subagent analysis recorded"},'; passed=$((passed+1));
        else
          checks+='{"item":"analysis_artifact","status":"WARN","score":0.5,"evidence":"no analysis artifact — run monitor --subagent"},'
        fi ;;
      ECO-EDIT)
        total_req=3
        # 收敛方案：人类裁决/让步记录（human_calibration_log 非空）
        local eco_edit_conv; eco_edit_conv=$(python3 "$SKILL_DIR/scripts/gk_state.py" get gate_data.human_calibration_log --path "$STATE_FILE" --as yes:no 2>/dev/null || echo "no")
        [ "$eco_edit_conv" = "yes" ] && { checks+='{"item":"converged_plan","status":"PASS","score":1.0,"evidence":"human calibration recorded"},'; passed=$((passed+1)); } ||
          checks+='{"item":"converged_plan","status":"WARN","score":0.5,"evidence":"no calibration/concession record"},'; ;;
      ECO-VERIFY|ECO-AUDIT)
        total_req=3
        # 质询报告：ECC 分析产物存在
        local eco_audit_rep; eco_audit_rep=$(ls "${SKILL_DIR}"/references/ecc-*.md 2>/dev/null | head -1)
        [ -n "$eco_audit_rep" ] && { checks+='{"item":"challenge_report","status":"PASS","score":1.0,"evidence":"ECC analysis present"},'; passed=$((passed+1)); } ||
          checks+='{"item":"challenge_report","status":"WARN","score":0.5,"evidence":"no ecc-*.md — audit report pending"},'; ;;
      ECO-DOC)
        total_req=3
        # 文档同步：docgen/doc-align 产物可验证（cli-protocol 由 docgen 生成）
        if [ -s "${SKILL_DIR}/references/cli-protocol.md" ]; then
          checks+='{"item":"doc_sync","status":"PASS","score":1.0,"evidence":"cli-protocol present (docgen output)"},'; passed=$((passed+1));
        else
          checks+='{"item":"doc_sync","status":"WARN","score":0.5,"evidence":"cli-protocol missing — run docgen"},';
        fi ;;
    esac
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
  elif echo "$stage" | "$RG" -q '^ECC-'; then
    total_req=2
    # F-23: ECC monitor — check actual analysis doc and adjudication record
    local ecc_doc; ecc_doc=$(ls "${MAIN_REPO_WSL}"/references/ecc-*.md 2>/dev/null | head -1)
    [ -n "$ecc_doc" ] && { checks+='{"item":"analysis_doc_exists","status":"PASS","score":1.0,"evidence":"ECC analysis document present"},'; passed=$((passed+1)); } || checks+='{"item":"analysis_doc_exists","status":"FAIL","score":0.0,"evidence":"no ecc-*.md found"},';
    local ecc_adj; ecc_adj=$(GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" python3 -c "import json,os;d=json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'));cl=d.get('gate_data',{}).get('human_calibration_log',[]);print('yes' if any(e.get('stage','').startswith('ECC-') for e in cl) else 'no')" 2>/dev/null || echo "no")
    [ "$ecc_adj" = "yes" ] && { checks+='{"item":"adjudication_recorded","status":"PASS","score":1.0,"evidence":"Human calibration logged for ECC"},'; passed=$((passed+1)); } || checks+='{"item":"adjudication_recorded","status":"FAIL","score":0.0,"evidence":"no ECC adjudication record"},';
  fi

  # 2026-08-15: monitor --local 扩展 — bash 静态漏洞模式检测（wsl 引用/插值污染/三引号注入/错键/非注册 --tools）
  # 确定性、~100ms 单文件扫描；FAIL（LLM 注入等）计入 score 拉低，WARN（内部数据三引号设计债）标记不阻断。
  # 注意: 结果经临时文件传递而非 bash 变量/管道——JSON detail 含 $(_get_achievements_config) 等字面量，
  # bash 的 $(...) 命令替换 / echo 二次展开会破坏 JSON（2026-08-15 实测教训，同三引号注入修复模式）。
  local bs_tmp; bs_tmp=$(mktemp)
  # 2026-08-23 bomb 消解: 2>/dev/null → GK_DBG_LOG（扫描器崩溃不能静默降级为"0 issues"假干净）
  python3 "${SKILL_DIR}/scripts/gk_bash_static_scan.py" --json --skill-dir "${SKILL_DIR}" > "$bs_tmp" 2>>"$GK_DBG_LOG" \
    || echo '{"issues":0,"checks":[]}' > "$bs_tmp"
  local bs_fails; bs_fails=$(GK_PY_FILE="$(_gk_py_path "$bs_tmp")" python3 -c "import json,os;d=json.load(open(os.environ['GK_PY_FILE']));print(sum(1 for c in d.get('checks',[]) if c['status']=='FAIL'))" 2>>"$GK_DBG_LOG" || echo 0)
  local bs_warns; bs_warns=$(GK_PY_FILE="$(_gk_py_path "$bs_tmp")" python3 -c "import json,os;d=json.load(open(os.environ['GK_PY_FILE']));print(sum(1 for c in d.get('checks',[]) if c['status']=='WARN'))" 2>>"$GK_DBG_LOG" || echo 0)
  rm -f "$bs_tmp"
  if [ "${bs_fails:-0}" -gt 0 ] 2>/dev/null; then
    # FAIL（LLM 注入等）→ 仅标记 + 自动进 violations（_monitor_finalize 提取 FAIL 项）；不稀释 score
    checks+='{"item":"bash_static","status":"FAIL","score":0.0,"evidence":"'"$bs_fails"' FAIL static vuln patterns (LLM 注入等)"},'
  elif [ "${bs_warns:-0}" -gt 0 ] 2>/dev/null; then
    # WARN（内部数据三引号设计债）→ 仅标记（与现有 WARN 项语义一致，不稀释 score 不阻断）
    checks+='{"item":"bash_static","status":"WARN","score":0.5,"evidence":"'"$bs_warns"' WARN static patterns (内部数据三引号设计债)"},'
  else
    checks+='{"item":"bash_static","status":"PASS","score":1.0,"evidence":"no static vuln patterns"},'; passed=$((passed+1));
  fi

  # 2026-09-02: monitor 强化 — hook 工具越权/提权绕过监控（防线② 行为偏离检测）
  # 检测面 = state gate_data.hook_block_log（pre_tool_hook block() 持久化被禁意图）。
  # TTL 窗口内存在提权绕过（kind=escalation: Edit/Write 被 BLOCK 后经 RunCommand 直写同文件）
  # → 必检 FAIL 计入 total_req（拉低 score → advance 拦截）；仅普通 BLOCK → WARN 标记不阻断。
  local hook_snap; hook_snap=$(GK_PY_SCRIPTS="$(_gk_py_path "$SKILL_DIR/scripts")" GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" python3 -c "import sys,json,os;sys.path.insert(0,os.environ['GK_PY_SCRIPTS']);import pre_tool_hook as h;print(json.dumps(h._block_log_snapshot(os.environ['GK_PY_STATE'])))" 2>>"$GK_DBG_LOG" || echo '{"blocks":0,"escalations":0,"chains":[]}')
  local hook_esc hook_blk
  hook_esc=$(echo "$hook_snap" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field escalations --default 0 2>>"$GK_DBG_LOG" || echo 0)
  hook_blk=$(echo "$hook_snap" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field blocks --default 0 2>>"$GK_DBG_LOG" || echo 0)
  if [ "${hook_esc:-0}" -gt 0 ] 2>/dev/null; then
    total_req=$((total_req+1))
    checks+='{"item":"hook_escalation","status":"FAIL","score":0.0,"evidence":"'"$hook_esc"' 次工具提权绕过（编辑被 BLOCK 后经 RunCommand 直写同文件）— 行为偏离，advance 拦截"},'
  elif [ "${hook_blk:-0}" -gt 0 ] 2>/dev/null; then
    checks+='{"item":"hook_block_trace","status":"WARN","score":0.5,"evidence":"'"$hook_blk"' 次工具 BLOCK（TTL 窗口内，无提权链）"},'
  else
    checks+='{"item":"hook_block_trace","status":"PASS","score":1.0,"evidence":"no hook block/escalation in window"},'; passed=$((passed+1));
  fi

  # ── 2026-09-21 用户裁定：【提问挂起 kill 闸】= monitor --local 的拦截 ──
  # 裁定逐字：「kill 应该是 monitor--local 的拦截，纪律表是摆设」「提问静默期间开始跑睡眠，
  # 提问半小时没动静就暂停主进程」。⟹ 分工契约：**记录侧**在 pre_tool_hook（Gate 9 配套，
  # 放行的提问落 `.gatekeeper.ask-hold`，下一次工具调用结算进 `.gatekeeper.ask-hold.log`）；
  # **判杀侧**唯此一项，判据单源 = `pre_tool_hook._ask_hold_snapshot`（不造第二份读实现）。
  #   · 停留 ≥ 1800s（半小时）⟹ 判 FAIL 且**计入 total_req** ⟹ score 被拉低
  #     ⟹ verdict=BLOCKED ⟹ advance 被拦 = 「暂停主进程」的机制化落法（不进纪律表）。
  #   · 24h 窗口外的陈旧台账不重复判杀（防永久锁死）。
  #   · 逃生舱 GK_ASK_HOLD_KILL=0 → 放行（显式人工放行，与 edit_budget 逃生舱同调）。
  total_req=$((total_req+1))
  local _ah_snap _ah_hit _ah_ev
  _ah_snap=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 -c "import json, os, sys
sys.path.insert(0, os.path.join(os.environ['SKILL_DIR'], 'scripts'))
import pre_tool_hook as h
print(json.dumps(h._ask_hold_snapshot(os.environ['SKILL_DIR']), ensure_ascii=False))" 2>>"$GK_DBG_LOG" || echo '{"pending_s":0,"max_s":0,"violations":[]}')
  _ah_hit=$(printf '%s' "$_ah_snap" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field violations --len --default-invalid 0 2>>"$GK_DBG_LOG" || echo 0)
  _ah_ev=$(printf '%s' "$_ah_snap" | python3 "$SKILL_DIR/scripts/gk_views.py" violations-summary 2>>"$GK_DBG_LOG" || echo "violations=0")
  if [ "${GK_ASK_HOLD_KILL:-1}" = "0" ]; then
    checks+='{"item":"ask_hold_kill","status":"PASS","score":1.0,"evidence":"disabled by GK_ASK_HOLD_KILL=0 ('"$_ah_ev"')"},'; passed=$((passed+1));
  elif [ "${_ah_hit:-0}" -gt 0 ] 2>/dev/null; then
    checks+='{"item":"ask_hold_kill","status":"FAIL","score":0.0,"evidence":"提问挂起超阈值未响应（半小时）—— '"$_ah_ev"' ⟹ 暂停主进程：勿静默继续，问题落待办或等用户在线"},'
  else
    checks+='{"item":"ask_hold_kill","status":"PASS","score":1.0,"evidence":"'"$_ah_ev"' — 无超阈提问挂起"},'; passed=$((passed+1));
  fi

  # L9 安全网（2026-08-26；F-REV-42 归位 2026-09-13）：`--align` 收敛入 doc-align 后，
  # L9 三态按其文档/家族名（MONITOR-LOCAL）**原位归入 `--local`**，单源调用权威实现
  # gk_self_check.check_l9_*（self-check #14-16）。语义 = 诊断项（不入 total_req/score，
  # 与旧 --align 一致）；FAIL 项经 _monitor_finalize 进 violations（可见留痕）+ 触发自动 E2。
  # + 2026-09-28 s4（`ECC-03F2EB7D6607`）：并入 `sc.check_ecc_form` = ECC 写入规范的**机械
  #   （A 类）只读体检**（「monitor 监管 ecc 按规范写入」）。走**同一 rows 通路** ⟹ FAIL 复用
  #   下方既有 L9 auto-E2（**零新增写入者**，N4 合规；监管 ≠ 写入者）。
  local _l9_line _l9_fail_names=""
  while IFS= read -r _l9_line; do
    [ -n "$_l9_line" ] || continue
    checks+="$_l9_line,"
    case "$_l9_line" in
      *'"status":"FAIL"'*)
        _l9_fail_names="${_l9_fail_names:+$_l9_fail_names,}$(printf '%s' "$_l9_line" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("item",""))' 2>/dev/null)";;
    esac
  done <<< "$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" STATE_FILE="$(_gk_py_path "$STATE_FILE")" GK_PY_SD="$(_gk_py_path "$SKILL_DIR")" GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" python3 -c "
import json, os, sys
sys.path.insert(0, os.path.join(os.environ['GK_PY_SD'], 'scripts'))
try:
    import gk_self_check as sc
    rows = [sc.check_l9_runtime_safenet(os.environ['GK_PY_SD']),
            sc.check_l9_gatechain_prereq(os.environ['GK_PY_STATE']),
            sc.check_l9_entropy_appeal(os.environ['GK_PY_STATE']),
            sc.check_ecc_form(os.environ['GK_PY_STATE'])]
except Exception as e:
    rows = [{'check': 'l9_runtime_safenet', 'status': 'WARN',
             'detail': 'gk_self_check 调用异常: ' + type(e).__name__ + ': ' + str(e)}]
for r in rows:
    st = r.get('status', 'WARN')
    o = {'item': r.get('check', ''), 'status': st, 'evidence': r.get('detail', '')}
    if st in ('PASS', 'WARN', 'FAIL'):
        o['score'] = {'PASS': 1.0, 'WARN': 0.5, 'FAIL': 0.0}[st]
    print(json.dumps(o, ensure_ascii=False))
" 2>>"$GK_DBG_LOG" || echo '{"item":"l9_runtime_safenet","status":"WARN","score":0.5,"evidence":"l9 单源调用异常"}')"
  # ── ㉕(b) (2026-09-06 实装): monitor L9 视图 FAIL → 自动 E2 register ──
  # family=MONITOR-LOCAL, cover_layers=L9 → finding-journal(C8)→余烬→replay(C10) 闭环。
  # register 幂等（同标题不重复登记，见 gk_finding.register L174-176）；GK_L9_AUTO_E2=0 可关闭。
  if [ "${GK_L9_AUTO_E2:-1}" = "1" ] && [ -n "$_l9_fail_names" ]; then
    local _l9_ctx; _l9_ctx="$(json_val "$STATE_FILE" stage 'IDLE')/$(json_val "$STATE_FILE" r_phase '')"
    STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_finding.py" register "$STATE_FILE" \
      "L9 gate FAIL (monitor @ $_l9_ctx): $_l9_fail_names" monitor \
      --family MONITOR-LOCAL --cover-layers L9 >/dev/null 2>>"$GK_DBG_LOG" || true
  fi

  _monitor_finalize "$stage" "$mode" "$total_req" "$passed" "$checks"
}

# --- monitor finalize (shared by local + api) ---
# [write_guard 裁决 2026-09-06 EXEMPT] 写 monitor_scores 为命令契约：cmd_monitor 无 --check 变体；
# advance 自动调用位于 L3297 dry_run=false 守卫内——守卫在调用方，函数内不重复包。
_monitor_finalize() {
  local stage="$1" mode="$2" total_req="$3" passed="$4" checks="$5"

  local violations="[" fc=0
  # extract FAIL items via python3
  local fail_items; fail_items=$(echo "$checks" | python3 "$SKILL_DIR/scripts/gk_views.py" monitor-fail-items 2>/dev/null)
  while IFS= read -r it; do
    [ -n "$it" ] && { violations+="$it,"; ((fc++)); }
  done <<< "$fail_items"
  violations="${violations%,}]"

  local score=0; [ "$total_req" -gt 0 ] && score=$(python3 "$SKILL_DIR/scripts/gk_num.py" ratio "$passed" "$total_req" 2>/dev/null || echo "0.0")
  # score ≤ 0.5 → BLOCKED (conservative, per "Cut the Overcredit" ICLR 2026:
  # FPR >> FNR impact. 0.5 itself is "PRM uncertain" — don't gamble.)
  local verdict="PASS"; python3 "$SKILL_DIR/scripts/gk_num.py" gt "$score" 0.5 2>/dev/null || verdict="BLOCKED"

  [ -f "$STATE_FILE" ] && _state_write "d.setdefault('monitor_scores',{})['$stage']={'score':${score},'verdict':'${verdict}','passed':${passed},'total':${total_req}}"

  echo "{\"stage\":\"$stage\",\"mode\":\"$mode\",\"score\":$score,\"verdict\":\"$verdict\",\"passed\":$passed,\"total\":$total_req,\"violations\":$violations,\"checks\":${checks%,}]}"
}

# --- API MODE: v4-flash actor-critic (Principle 1: separation) ---
# [write_guard 裁决 2026-09-06 EXEMPT] 同 _monitor_finalize：仅 cmd_monitor 真实调用/advance L3297 守卫内；
# 无 --check 变体，函数内无 dry_run 变量可守卫（引未定义变量会误阻断写入）。
_monitor_api() {
  local stage="$1" api_key="$2" worktree="$3" branch="$4"
  # 2026-10-31（owner 裁定 A）：**主路径 = 审计署决策后端**（与 `gk_audit_outcome` 同一端点
  #   `/v1/systemone`、同一 typed-choice 协议），分数只作 advisory（不进门禁）。
  #   · 未配 `GK_AUDIT_OUTCOME_ENDPOINT` ⟹ 只回 `advisory=endpoint_unset`（不联网、不伪造分数）。
  #   · 旧 PRM 车道（v4-flash + FAILOVER_CHAIN）降为逃生舱 `GK_MONITOR_API_LEGACY=1`（默认关），
  #     **标注：逐步移除（sunset）** —— 其模型来自常量 `DS_MODEL_CRITIC`（v4-flash 族）+ 固定
  #     FAILOVER_CHAIN（硬编码、不可按端点配置）；校准读数攒够或 30 天窗口结束即删除。
  #     理由：同族自评不可校准、生产零记录（`monitor_history=0`）；转正须先与人类裁决配对。
  if [ "${GK_MONITOR_API_LEGACY:-0}" != "1" ]; then
    local _md_out _md_rc
    _md_out=$(python3 "$SKILL_DIR/scripts/gk_monitor_decision.py" run \
      --stage "$stage" --worktree "$worktree" --branch "$branch" \
      --endpoint "${GK_AUDIT_OUTCOME_ENDPOINT:-}" 2>>"${GK_DBG_LOG:-/dev/null}")
    _md_rc=$?
    [ -n "$_md_out" ] && echo "$_md_out"
    return $_md_rc
  fi
  [ -z "$api_key" ] && { echo '{"error":"--api-key required. Set GATEKEEPER_API_KEY env var or pass --api-key KEY"}'; return 1; }

  # Resolve provider config (DeepSeek vs MiMo)
  _resolve_provider_config

  local schema; schema=$(cat "$(_canon_schema_path "$stage" 2>/dev/null)" 2>/dev/null)
  local state; state=$(cat "$STATE_FILE" 2>/dev/null)

  # Collect hard evidence via standalone function (bridge P2 pattern)
  _collect_hard_evidence "$stage" "$worktree" "$branch"
  local evidence; evidence=$(_emit_hard_evidence_json)

  local system_prompt="You are a Process Reward Model (PRM) for the SPZ Gatekeeper R-sequence pipeline. Given a GATE SCHEMA and EXECUTION STATE + HARD EVIDENCE, score how well the agent satisfied each requirement. Output ONLY JSON: {\"overall_score\":0.0-1.0,\"checks\":[{\"item\":\"...\",\"status\":\"PASS|FAIL|UNCERTAIN|CONTRADICTION\",\"score\":0.0-1.0,\"evidence\":\"file:line_range\"}],\"violations\":[\"...\"],\"contradictions\":[\"state says X but evidence shows Y — mark CONTRADICTION\"],\"next_action\":\"...\",\"reasoning\":\"...\"}. Rules: PASS=1.0, FAIL=0.0, UNCERTAIN=0.5, CONTRADICTION=0.0. CONTRADICTION means the state file (written by agent) claims something that hard evidence disproves. Example: state says ctest passed but evidence shows build_exists=false. Mark CONTRADICTION, not FAIL. CRITICAL: commits_ahead_of_main=0 → no new code, FAIL compile+commit requirements. ci_trigger=absent → FAIL CI. build_exists=false → FAIL compile. l4_marker=false → FAIL cross-review. spec_urls_valid=false → FAIL spec_url (file doesn't exist in Niantic reference). git_workflow_marker=false → WARN (push via git-workflow required). Evidence is ground truth. State file may lie — trust evidence. RELOCATION: Every evidence field MUST be 'file:line_range' format (e.g. 'gatekeeper-cli.sh:647-748'). Never output just a filename without line numbers."

  local user_prompt="GATE SCHEMA: $schema\n\nSTATE FILE: $state\n\nHARD EVIDENCE: $evidence\n\n"

  # T34: GitNexus analysis injection — baseline + per-symbol impact
  # Refs: PRM Survey arXiv:2510.08049 §2.2 (formal verification as evidence)
  #       SkillOpt §3.4 (code graph as optimization signal)
  #       prm-monitor-methodology.md §8.3 (Gatekeeper integration pattern)
  local gn_context; gn_context=$(python3 "$SKILL_DIR/scripts/gk_views.py" gitnexus-baseline "$STATE_FILE" 2>/dev/null || echo "")
  [ -n "$gn_context" ] && user_prompt="${user_prompt}GITNEXUS BASELINE: $gn_context\n\n"

  # T34: GitNexus context — inject call chain context for modified files
  # F-REV-71（2026-09-16）：repo 名**单源推导**（原硬编码 `spz_gatekeeper` 不在 registry ⟹ 恒空）；
  #   在进入循环前解析一次（避免 `read sym` 子壳内每符号 spawn 一次 python）。
  local gn_context_files="" _gnrepo_t34
  _gnrepo_t34=$(_gx_repo_name_for_dir "$(_gx_repo_dir_for_current)")
  if [ -d "$worktree" ] && [ -n "$stage" ]; then
    gn_context_files=$(_git "$worktree" diff --name-only HEAD~1..HEAD 2>/dev/null | \
    sed 's/.*\///' | sed 's/\.[^.]*$//' | head -3 | while read sym; do
      [ -z "$sym" ] && continue
      # R5.8 SA2: gitnexus context 明确指定仓库 — 防止 PowerShell CWD 偏移
      local ctx; ctx=$(_run_gitnexus context --repo "$_gnrepo_t34" "$sym" 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_views.py" gn-context-summary-sym "$sym" 2>/dev/null || echo "")
      [ -n "$ctx" ] && echo "$ctx"
    done)
  fi
  [ -n "$gn_context_files" ] && user_prompt="${user_prompt}GITNEXUS CONTEXT: ${gn_context_files}\n\n"

  # P1: Per-symbol impact for STAGE_3/4 (check modified symbols in worktree)
  # F-REV-71（2026-09-16）：repo 名**单源推导**（原硬编码 `spz_gatekeeper` 不在 registry ⟹ 恒空）；
  #   进循环前解析一次（同 T34）。
  local gn_impact="" _gnrepo_p1
  _gnrepo_p1=$(_gx_repo_name_for_dir "$(_gx_repo_dir_for_current)")
  if [ -d "$worktree" ] && { [ "$stage" = "STAGE_3" ] || [ "$stage" = "STAGE_4" ]; }; then
    gn_impact=$(_git "$worktree" diff --name-only HEAD~1..HEAD 2>/dev/null | \
    sed 's/.*\///' | sed 's/\.[^.]*$//' | head -5 | while read sym; do
      [ -z "$sym" ] && continue
      # R5.8 SA2: gitnexus impact 明确指定仓库 — 防止 PowerShell CWD 偏移
      # shellcheck disable=SC2140,SC2206
      _run_gitnexus impact --repo "$_gnrepo_p1" "$sym" 2>/dev/null | \
      python3 "$SKILL_DIR/scripts/gk_views.py" gn-impact-line 2>/dev/null
    done | tr '\n' '; ')
    [ -n "$gn_impact" ] && user_prompt="${user_prompt}GITNEXUS IMPACT: ${gn_impact}\n\n"
  fi

  user_prompt="${user_prompt}Score this gate. Output only JSON."

  # T43+++v2: retry-before-fallback chain (Bridge engine.py pattern)
   local resp content failover_chain failover_i provider_saved="$PROVIDER"
  # shellcheck disable=SC2206
  failover_chain=(${GK_FAILOVER_CHAIN//,/ })
  for failover_i in "${!failover_chain[@]}"; do
    local fb="${failover_chain[$failover_i]}"
    case "$fb" in
      # failover key fix (2026-08-09): 原 `[ -z "$api_key" ] && _resolve_api_key`
      # 中 api_key 是必填函数参数（非空）→ mimo 分支永远不重解析 key，
      # curl 用 deepseek key 打 mimo API → 401。改为强制 API_KEY="" 再重解析。
      deepseek) PROVIDER="deepseek"; _resolve_provider_config; API_KEY=""; _resolve_api_key; api_key="$API_KEY" ;;
      mimo)     PROVIDER="mimo";     _resolve_provider_config; API_KEY=""; _resolve_api_key; api_key="$API_KEY" ;;
      ollama|local) PROVIDER="deepseek" ; break ;;  # local: fall through to error below
    esac

    # Retry up to 2 times per provider (Bridge MODEL_RETRY.max_retries=2)
    local retry=0 content=""
    while [ $retry -lt 2 ]; do
      # Rebuild req_body for current provider
      if [ "$PROVIDER" = "mimo" ]; then
        SYSTEM_PROMPT="$system_prompt" USER_PROMPT="$user_prompt" req_body=$(python3 "$SKILL_DIR/scripts/gk_req_body.py" "$API_MODEL" 2>/dev/null)
      else
        SYSTEM_PROMPT="$system_prompt" USER_PROMPT="$user_prompt" req_body=$(python3 "$SKILL_DIR/scripts/gk_req_body.py" "$API_MODEL" "$DS_REASONING_EFFORT" 2>/dev/null)
      fi
      resp=$(curl -s --max-time 60 -X POST "${API_BASE}/chat/completions" \
        -H "Authorization: Bearer ${api_key}" \
        -H "Content-Type: application/json" \
        -d "$req_body" 2>/dev/null)
      content=$(echo "$resp" | python3 "$SKILL_DIR/scripts/gk_json.py" get choices.0.message.content 2>/dev/null)
      [ -n "$content" ] && break 2  # success → exit both loops
      retry=$((retry + 1))
    done
    # If this provider failed, check if error is retryable before falling to next
    if [ $retry -ge 2 ] && ! _is_retryable "$resp"; then
      break  # non-retryable error (e.g. 400) → stop, don't try next provider
    fi
  done
  PROVIDER="$provider_saved"; _resolve_provider_config  # restore original provider

  [ -z "$content" ] && { echo "{\"error\":\"all providers failed\",\"failover_chain\":\"${GK_FAILOVER_CHAIN}\"}"; return 1; }

  # A7（2026-09-06 ㉔，与 cmd_appeal 同款 schema 守卫）：裁判输出缺 overall_score（坏 JSON/schema
  # 漂移）不得按哨兵 -1 判 BLOCKED 落盘——显式 MONITOR_RESPONSE_INVALID + RETRYABLE，未落记录
  # （防 A7 假否决相邻族：合法 JSON 缺字段被当实质 -1 否决消费）。
  if ! echo "$content" | "$RG" -q '"overall_score"'; then
    echo '{"ok":false,"error":"MONITOR_RESPONSE_INVALID","reason":"裁判输出缺 overall_score 字段（schema 漂移/坏 JSON）","action":"RETRYABLE","hint":"LLM 输出违约 — 未落记录，重试或登记模型问题"}'
    return 1
  fi

  local score; score=$(echo "$content" 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_json.py" get overall_score -1 2>/dev/null)
  # Normalize score to 0-1 scale (MiMo uses 0-100, DeepSeek uses 0-1)
  if [ -n "$score" ] && [ "$score" != "-1" ]; then
    score=$(python3 "$SKILL_DIR/scripts/gk_num.py" norm "$score" 2>/dev/null || echo "0")
  fi
  local violations; violations=$(echo "$content" 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_json.py" get violations 2>/dev/null || echo '[]')
  local next_action; next_action=$(echo "$content" 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_json.py" get next_action 2>/dev/null || echo "")
  local reasoning; reasoning=$(echo "$content" 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_json.py" get reasoning 2>/dev/null || echo "")

  # Fallback if parsing completely failed
  [ -z "$score" ] && score="0"
  [ -z "$violations" ] && violations='[]'

  local verdict="PASS"; python3 "$SKILL_DIR/scripts/gk_num.py" gt "${score:-0}" 0.5 2>/dev/null || verdict="BLOCKED"

  # Write FULL monitor output to dedicated file (agent-invisible), mirroring bridge's
  # .bridge_monitor_out_tmp.json pattern. Agent only sees score+verdict+violations.
  # SECURITY NOTE (V7): This file contains full LLM reasoning content (chain-of-thought,
  # model self-critique, etc.) which may leak internal evaluation logic. It MUST NOT be
  # committed to git. The file is ephemeral and overwritten each monitor invocation.
  # Add .gatekeeper_monitor_api_tmp.json to .gitignore if a global gitignore is used.
  local monitor_out="${MAIN_REPO_WSL}/.gatekeeper_monitor_api_tmp.json"
  echo "$content" | python3 "$SKILL_DIR/scripts/gk_views.py" monitor-dump "$monitor_out" "$stage" "${PROVIDER}" "${API_MODEL}" "${score:-0}" "${verdict}" "$(date -Iseconds)" 2>/dev/null || true

  [ -f "$STATE_FILE" ] && _state_write "d.setdefault('monitor_scores',{})['$stage']={'score':${score:-0},'verdict':'${verdict}','provider':'${PROVIDER}','model':'${API_MODEL}','reasoning':'${DS_REASONING_EFFORT}','next_action':'${next_action}','reasoning':'${reasoning}'}"

  # Agent-visible: only summary, no checks details. Full dump at $monitor_out.
  echo "{\"stage\":\"$stage\",\"mode\":\"--api\",\"provider\":\"${PROVIDER}\",\"model\":\"${API_MODEL}\",\"score\":${score:-0},\"verdict\":\"$verdict\",\"violations\":$violations,\"next_action\":\"$next_action\",\"reasoning\":\"$reasoning\",\"_full_dump\":\"$monitor_out\"}"
}

# ============================================================
# ADVANCE — structural gates + PRM active blocking
# ============================================================
# PROTECTED_REGION_START::transition
cmd_advance() {
  local to_stage="" dry_run=false run_monitor=true force=false
  while [ $# -gt 0 ]; do case "$1" in
    --check) dry_run=true; shift ;; --force) force=true; shift ;; --monitor) run_monitor=true; shift ;; *) to_stage="$1"; shift ;; esac; done

  [ -z "$to_stage" ] && { echo '{"error":"to_stage required"}'; return 1; }
  [ ! -f "$STATE_FILE" ] && { echo '{"allowed":false,"reason":"No state file"}'; return 1; }

  # Auto-rotate expired keys (context=1d, audit=30d) — CLI 启动级已覆盖, 此处双保险
  _key_rotate_if_expired

  local current_stage branch worktree ptype
  current_stage=$(json_val "$STATE_FILE" stage "IDLE")
  branch=$(json_val "$STATE_FILE" branch "")
  worktree=$(json_val "$STATE_FILE" worktree "")
  ptype=$(python3 "${SKILL_DIR}/scripts/gk_gate_project_type.py" "$STATE_FILE" 2>/dev/null || echo "standard")

  # ── 环境证据收集（standard 分支 structural gates；bash 侧唯一来源）──
  local env_json="{}"
  if [ "$ptype" = "standard" ]; then
    env_json=$(_collect_advance_env "$current_stage" "$to_stage" "$worktree" "$branch")
  fi

  # ── PRM Monitor（standard CRITICAL 转换 + standing 全部转换；结果注入 gk_advance.py）──
  local monitor_json="null"
  if $run_monitor && ! $force && [ "$dry_run" = "false" ]; then
    local _should_monitor=false
    if [ "$ptype" = "standard" ]; then
      case "${current_stage}→${to_stage}" in
        "STAGE_0→STAGE_1"|"STAGE_1→STAGE_2"|"STAGE_2→STAGE_3"|"STAGE_3→STAGE_4"|"STAGE_4→STAGE_5"|"STAGE_5→DONE") _should_monitor=true ;;
      esac
    elif [ "$ptype" = "standing" ]; then
      # Phase 7a (2026-08-23): standing 分支 PRM Monitor 主动阻断（原零 monitor 调用，仅 R4 熵兜底）
      _should_monitor=true
    fi
    if $_should_monitor; then
        local _monitor_mode="--local"
        # R4: Entropy-driven monitor mode override (>0.3 → force API)
        # Phase 7a 修正 (2026-08-23): 统一走 gk_gate_entropy.py（计划 L488 明确要求），
        # 内联 heredoc 只有 rejected_edits 分支 → standing(ECO-*) 熵恒 0.0 永不触发 --api。
        # 权威实现: ECO-* → human_calibration_log, 其他 → rejected_edits + access_violations。
        # stderr 诊断走 GK_DBG_LOG（熵计算输入可观测, 2026-08-23 交叉审查 #1）
        local _er; _er=$(python3 "${SKILL_DIR}/scripts/gk_gate_entropy.py" "$STATE_FILE" "$current_stage" 2>>"$GK_DBG_LOG" || echo "0.0")
        # 2026-10-31（§9.2 单源落点）：阈值不再写字面量 —— 读 `gk_econ_params.T_API`
        #   （与 `_raise_entropy` / `_entropy_enforced` 同源；owner 已签 §8 #4）。
        #   本行在 PROTECTED_REGION::transition 内 ⟹ 改的是**取值来源**，语义保持 0.3 等价。
        local _t_api; _t_api=$(GK_PY_SD="$(_gk_py_path "$SKILL_DIR")" python3 -c "import sys,os; sys.path.insert(0, os.path.join(os.environ['GK_PY_SD'], 'scripts')); import gk_econ_params as e; print(e.T_API)" 2>/dev/null || echo "0.3")
        if python3 "$SKILL_DIR/scripts/gk_num.py" gt "${_er}" "${_t_api:-0.3}" 2>/dev/null; then
          _monitor_mode="--api"
        fi
        _resolve_api_key
        # T7.12(B)+2 (2026-08-28 实装)：--api 语义评分覆盖 ECO 阶段关键交付点
        # （ECO-AUDIT 质询密封 / ECO-DOC 文档交付）——原仅 CRITICAL_STAGES + 熵>0.3 触发，
        # standing 高频但关键转换也应有语义评分机会；其余 ECO 转换仍走 --local（成本可控）。
        local _need_api=false
        if echo "$CRITICAL_STAGES" | "$RG" -qw "$current_stage" 2>/dev/null; then _need_api=true; fi
        # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
        if [ "$ptype" = "standing" ] && echo "$to_stage" | "$RG" -qw "ECO-VERIFY|ECO-AUDIT|ECO-DOC" 2>/dev/null; then _need_api=true; fi
        # 2026-09-04 修复（用户质询：advance 内部 monitor 0.5 vs CLI 1.0 不一致 → --force 不该出现）：
        # 根因 = --api 失败（error JSON + exit≠0）与 --local 输出串入同一命令替换 → 两行非单 JSON →
        # json.load 失败 → 静默兜底 score=0.5 → PRM_MONITOR_BLOCKED（仅 →ECO-AUDIT/ECO-DOC 命中）。
        # 修复 = local/api 分变量互不混流；api 失败落 GK_DBG_LOG（fail-loud）回退 local；
        # 两侧均不可用 → 显式错误退出（不再静默 0.5 逼 --force）。
        local _local_json _api_json=""
        _local_json=$(cmd_monitor --local "$current_stage" 2>>"$GK_DBG_LOG")
        if $_need_api && [ -n "${API_KEY:-}" ]; then
          _api_json=$(cmd_monitor --api "$current_stage" --api-key "$API_KEY" 2>>"$GK_DBG_LOG")
          if echo "$_api_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test error --not-is str 2>/dev/null; then
            echo "[advance] api monitor unavailable → local fallback ($(echo "$_api_json" | head -c 160)) $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
            _api_json=""
          fi
        fi
        if [ -n "$_api_json" ]; then _monitor_mode="--api"; else _monitor_mode="--local"; fi
        monitor_json="${_api_json:-$_local_json}"
        if ! echo "$monitor_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" valid 2>/dev/null; then
          echo "[advance] PRM monitor unusable (local+api) — blocking fail-loud (was silent 0.5) $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
          echo '{"error":"PRM monitor unavailable — see gk_dbg.log","score":0.0,"verdict":"BLOCKED","mode":"local"}'
          return 1
        fi
        monitor_json=$(echo "$monitor_json" | python3 -c "import sys,json;d=json.load(sys.stdin);d['mode']='${_monitor_mode#--}';print(json.dumps(d))" 2>/dev/null)
    fi
  fi

  # ── check-changes / remote（hint 注入；bash 侧收集）──
  local cc_json="{}" remote_json="unknown"
  cc_json=$(bash "$0" check-changes --type doc --threshold 2 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_views.py" doc-code-summary 2>/dev/null || echo "{}")
  remote_json=$(cd "$MAIN_REPO_WSL" 2>/dev/null && git remote -v 2>/dev/null | head -4 | paste -sd '; ' - || echo "unknown")

  # ── 2026-09-05 S12 / 2026-09-10 F-REV-13：G 谓词接入状态机（全序列前置执行 node_guard.guard）──
  # L9 编排注入（正本清源，2026-09-01 纪律）：ctx 由 cmd_node_guard 统一入口委托 python guard
  # 自 state/磁盘自动推导（context_file/baseline/narrow_tasks），advance **不手写 ctx**——
  # 手写 = 第二推导/第二事实源（曾用 bash heredoc 传 MAIN_REPO_WSL/.gitnexus + source_docs=[]，
  # 2026-09-05 用户质询撤销：双事实源 + 调用点造假绿输入，违背 fail-closed）。
  # 2026-09-10 P1 更新：source_docs 未声明 → 归 info 跳过（自动路径无源，不再恒判缺）；
  # 计划 META 声明 source_docs → 自动接源校验磁盘可读性。默认 advisory（注入结果 JSON + GK_DBG_LOG，
  # 不阻断）；GK_GUARD_STRICT=1 → 硬门禁（missing → BLOCK，未注册节点 skip）。
  local guard_out="" _guard_json=""
  # F-REV-13 (2026-09-10)：G 谓词从 standard 泛化到全部序列（standing ECO-* / audit AUDIT-* /
  # red RED-*），闭合"非 standard 序列 advance 无 node_guard 前置门禁"缺口（此前 if ptype=standard
  # → 三条序列的节点前置产物无人校验）；未注册节点（ECC-* 等）→ 判定 skip，交 advance 自身注册校验。
  # P1 接源同源：META source_docs → --source-docs（未声明 → guard 归 info）。
  if [ -n "$to_stage" ]; then
    # F-REV-14 (2026-09-10)：META 源 = state 绑定计划（计划指针 plan 字段 / 隔离 state 文件名后缀），
    # 非硬编码 PLAN_FILE——此前"state 指向 R7 计划、META 读 R 对齐计划"脱钩 → 隔离 state 下
    # META source_docs 恒空、本前置等价 no-op（接源管道接上但源侧永无数据）。委托路由中枢
    # resolve-bound-plan（唯一事实源），未绑定 → 保持原 PLAN_FILE。
    local _bound_plan _saved_plan="$PLAN_FILE"
    _bound_plan=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" STATE_FILE="$(_gk_py_path "$STATE_FILE")" PLAN_POINTER="${_PLAN_POINTER:-}" \
      python3 "$SKILL_DIR/scripts/gk_route_center.py" resolve-bound-plan 2>>"$GK_DBG_LOG" \
      | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field plan_file --default '' 2>/dev/null || echo "")
    [ -n "$_bound_plan" ] && PLAN_FILE="$_bound_plan"
    _read_plan_metadata
    PLAN_FILE="$_saved_plan"
    local _sd_arg=""
    [ -n "${META_source_docs:-}" ] && _sd_arg="--source-docs $META_source_docs"
    # shellcheck disable=SC2086  # 计划声明路径清单（逗号分隔单参数，路径不含空格）
    guard_out=$(cmd_node_guard "$to_stage" $_sd_arg)
    if [ -n "$guard_out" ] && [ "${GK_GUARD_STRICT:-0}" = "1" ]; then
      local _gverdict
      _gverdict=$(echo "$guard_out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('ok' if d.get('ok') is True else ('skip' if str(d.get('error','')).startswith('UNKNOWN_NODE') else 'block'))
" 2>/dev/null || echo "block")
      if [ "$_gverdict" = "block" ]; then
        # allowed=false 对齐 cmd_advance 其他拒绝分支的 JSON 契约（advance 成功/拒绝均以 allowed 判读）
        echo "{\"ok\":false,\"allowed\":false,\"error\":\"node_guard_precondition\",\"guard\":$guard_out,\"hint\":\"GK_GUARD_STRICT=1 硬门禁 — 补齐 missing（窄任务/源文档/context/baseline）后重试，或 GK_GUARD_STRICT=0 降级 advisory\"}"
        return 1
      fi
    fi
    # F-REV-13 (2026-09-10)：guard 摘要统一构建（advisory 可见性）——standard / non-standard / dry-run
    # 三条输出路径共用同一份 _guard_json，避免三处重复（原仅 standard 非 dry-run 注入）。
    if [ -n "$guard_out" ]; then
      _guard_json=$(echo "$guard_out" | python3 -c "import sys,json;d=json.load(sys.stdin);n=d.get('node');print(',\"node_guard\":'+json.dumps({'ok':d.get('ok'),'node':(n.get('id') if isinstance(n,dict) else None),'missing':d.get('missing',[]),'info':d.get('info',[])},ensure_ascii=False))" 2>/dev/null || echo "")
    fi
  fi

  # ── 调用 gk_advance.py（状态机核心：判定 + 状态写入，Phase 7 迁移）──
  local _adv_args=""
  $dry_run && _adv_args="$_adv_args --check"
  $force && _adv_args="$_adv_args --force"
  local result
  result=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 "$SKILL_DIR/scripts/gk_advance.py" "$to_stage" $_adv_args --env-json "$env_json" --monitor-json "$monitor_json" --cc-json "$cc_json" --remote-json "$remote_json" 2>>"$GK_DBG_LOG" || echo '{"error":"gk_advance_py_failed"}')

  local _allowed _ok
  _allowed=$(echo "$result" | python3 "$SKILL_DIR/scripts/gk_json.py" get allowed false 2>/dev/null || echo "False")
  _ok=$(echo "$result" | python3 "$SKILL_DIR/scripts/gk_json.py" get ok false 2>/dev/null || echo "False")

  if [ "$_allowed" = "False" ] && [ "$_ok" = "False" ]; then
    $force && echo '{"warning":"FORCE mode — PRM monitor bypassed"}' >&2
    # F-REV-16 (2026-09-10)：拒绝路径同样注入 guard 摘要——F-REV-13 声明"标准/非标准/dry-run 三路径统一"
    # 漏了这条 gk_advance 拒绝的 early return → 被拒时前置状态完全不可见（advisory 可见性断裂）。
    if [ -n "${_guard_json:-}" ]; then
      echo "$(printf '%s' "$result" | sed 's/}$//')${_guard_json}}"
    else
      echo "$result"
    fi
    return 1
  fi

  if [ "$ptype" = "standard" ]; then
    if [ "$dry_run" = "false" ]; then
      # ── standard 成功路径：bash 外围写入（state 已由 gk_advance.py 写入）──
      local retrospect_json="" cur_score=0.5
      _write_gate_data "$current_stage" "$worktree" "$branch"
      if [ "$to_stage" = "DONE" ]; then retrospect_json=$(_generate_retrospect "$current_stage"); fi
      cur_score=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get "monitor_scores.$current_stage.score" --default 0.5 2>/dev/null)
      # best 增量更新（2026-08-25 迁移自内联 python，r_phase 脚本内自动提取，消除 rg 依赖）
      python3 "$SKILL_DIR/scripts/gk_state_patch.py" update-best "$STATE_FILE" "$cur_score" "$to_stage" "" "$(date -Iseconds)" >/dev/null 2>&1 || true
      _write_context_file
      local ach_unlocked; ach_unlocked=$(_check_achievements)
      local ach_json="" ach_output=""
      if [ "$ach_unlocked" != "[]" ]; then
        ach_json=$(python3 "$SKILL_DIR/scripts/gk_state_patch.py" append-achievements "$STATE_FILE" "$ach_unlocked" "$(_get_achievements_config)" 2>/dev/null)
      fi
      [ -n "$ach_json" ] && ach_output=",\"achievements\":$ach_json" && ach_output="${ach_output},\"encouragement\":\"$(_encouragement achievement $(echo "$ach_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field '' --join '; ' --subkey label --default-invalid '新成就解锁' 2>/dev/null))\""
      local _done_extra=""
      [ -n "$retrospect_json" ] && _done_extra=",\"retrospect\":$retrospect_json"
      # S12 advisory：guard 摘要已在 guard 块统一构建（_guard_json，F-REV-13 重构去重）
      # 2026-08-27 序列节点安全网：车站播报（当前站 + 下一站预报 + 进入门禁 + checklist）注入 standard 成功路径
      # S14（2026-09-05）：announce 改走 cmd_node_guard 统一入口（收敛"直调 python vs 入口透传"双通道）
      local _station_json=""
      _station_json=$(cmd_node_guard announce --node "$to_stage" --current "$current_stage" 2>/dev/null || echo "")
      if [ -n "$_station_json" ] && echo "$_station_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" valid 2>/dev/null; then
        _station_json=",\"station\":$(printf '%s' "$_station_json" | python3 "$SKILL_DIR/scripts/gk_views.py" station-projection 2>/dev/null)"
      else
        _station_json=""
      fi
      # 合并：result（Python 判定 JSON）+ bash 外围字段
      echo "$(printf '%s' "$result" | sed 's/}$//')${_done_extra}${ach_output}${_guard_json}${_station_json},\"best\":{\"score\":${cur_score},\"stage\":\"${to_stage}\"}}"
    else
      # F-REV-13：standard dry-run（--check）同样注入 guard 摘要（前置状态在 check 下可见）
      if [ -n "${_guard_json:-}" ]; then
        echo "$(printf '%s' "$result" | sed 's/}$//')${_guard_json}}"
      else
        echo "$result"
      fi
    fi
    return 0
  fi

  # ── non-standard 成功路径：I9 / auto-audit / audit_result / red_* / achievements ──
  # dry_run（--check）零副作用契约：state 写入类（I9/achievements/context）跳过；
  # 只读证据收集（audit_result/auto-audit）保留（与 standard dry-run 输出对齐）。
  local i9_output="" auto_audit_output="" audit_extra=""
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
  if [ "$dry_run" = "false" ] && { [ "$to_stage" = "ECO-DOC" ] || echo "$to_stage" | "$RG" -qi "RED-REPORT"; }; then
    local red_result; red_result=$(python3 "${SKILL_DIR}/scripts/_red_attacks.py" all 2>/dev/null || echo '{}')
    local ecc_count; ecc_count=$(echo "$red_result" | python3 "$SKILL_DIR/scripts/gk_json.py" get findings 0 2>/dev/null || echo "0")
    if [ "$ecc_count" -gt 0 ]; then
      # F8（ECC-7F497B4805F5，2026-09-18 用户裁定 A3 ①）：去重键由**可变的** `evidence_hash`
      # 改为 `id`（同 id upsert）。原实现在此内联去重，而 `_red_attacks.site_digest` 令
      # evidence_hash 随仓库变化 ⟹ 同 id 每次重扫都再入账（实测 subagent_history ×5 /
      # RECUR-DEVSOURCE ×2）。现委托台账 owner `gk_finding.upsert_red_findings`
      # （单源、pytest 直测；`first_added` 不回溯 + 内容变才推进 `last_modified`，
      # 并回报 duplicate_ids 使存量重复**可见**）。
      # ── T1（2026-10-05，F-REV-63 深修）：写点与读点**同源**（取数中枢 `_conv_state_path`）──
      #   病灶（F-REV-63）：finding 写点绑 base `$STATE_FILE`，而取数中枢 `_conv_state_path`
      #   解析**域 state** ⟹ findings 账与 journal **异源** ⟹ `MU_BACKCAST_NEGATIVE`。
      #   修法 = 写点改走同一中枢（域解析结果）；解析失败 ⟹ **fail-closed**（禁静默回 base，
      #   否则异源复发）。回退开关 `GK_FREV63_WRITE_SRC=legacy` ⟹ 显式绑回 `$STATE_FILE`（零回归）。
      if [ "${GK_FREV63_WRITE_SRC:-central}" = "legacy" ]; then
        _CONV_STATE=""                       # 显式回退：空 ⟹ 下游取 $STATE_FILE
      elif _conv_state_path && [ -n "$_CONV_STATE" ]; then
        :                                    # 采用域 state（与读点同源）
      else
        # F-REV-13/16 不变式：guard 块**之后**的每个出口都不得静默丢 guard 摘要 ——
        #   本支是 F-REV-63 写点取数失败（fail-closed），仍须带 `_guard_json`（空则退化为原 JSON）。
        echo "$(printf '%s' "{\"ok\":false,\"error\":\"red_ledger_state_route_failed\",\"detail\":\"写点取数中枢解析失败（${_CONV_ERR:-STATE_ROUTE_FAILED}）；fail-closed 禁静默回 base，可用 GK_FREV63_WRITE_SRC=legacy 回退\"}" | sed 's/}$//')${_guard_json}}"
        return 1
      fi
      local red_ledger
      red_ledger=$(RED_RESULT="$red_result" GK_RED_STATE="$(_gk_py_path "${_CONV_STATE:-$STATE_FILE}")" GK_PY_SD="$(_gk_py_path "$SKILL_DIR")" python3 -c "
import json,os,sys
sys.path.insert(0,os.path.join(os.environ['GK_PY_SD'],'scripts'))
from gk_finding import upsert_red_findings
new=json.loads(os.environ.get('RED_RESULT','') or '{}').get('ecc_findings',[])
print(json.dumps(upsert_red_findings(os.environ.get('GK_RED_STATE',''), new), ensure_ascii=False))
" 2>/dev/null || echo '{\"ok\":false,\"error\":\"red ledger upsert failed\"}')
      i9_output=",\"i9_redteam\":{\"findings\":$ecc_count,\"ledger\":$red_ledger}"
    fi
  fi
  # audit 子命令有副作用（写 gate_data.audit_state_result 等）→ dry_run 跳过
  if [ "$dry_run" = "false" ] && [ "$ptype" = "standing" ]; then
    local _aa; _aa=$(bash "$0" audit --state 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_views.py" audit-summary-view 2>/dev/null || echo "")
    [ -n "$_aa" ] && auto_audit_output=",\"auto_audit\":$_aa"
  fi
  if [ "$dry_run" = "false" ]; then
    case "$to_stage" in
    AUDIT-STATE) audit_extra=",\"audit_result\":$(bash "$0" audit --state 2>/dev/null || echo '{}')" ;;
    AUDIT-MEMORY) audit_extra=",\"audit_result\":$(bash "$0" audit --memory 2>/dev/null || echo '{}')" ;;
    AUDIT-CROSSR) audit_extra=",\"audit_result\":$(bash "$0" audit --crossr 2>/dev/null || echo '{}')" ;;
    AUDIT-REPORT) audit_extra=",\"audit_result\":$(bash "$0" audit --report 2>/dev/null || echo '{}')" ;;
    RED-SCOPE) audit_extra=",\"red_scope\":$(bash "$0" self-check --tests skip 2>/dev/null || echo '{}')" ;;
    # 2026-09-22（R22/C1 红队发现修复）：原 4 阶段注入的是**假证据** ——
    #   RED-SURFACE 直接内联字面量 `{"cached":true,"from":"ECO-SCAN baseline"}`（不是扫描结果，
    #   却读作"已有缓存基线"）；CONSTRAINTS/EXPLOIT/POSTEX 用 `audit --state` +
    #   **硬编码 repo 名 `spz-gatekeeper-r-sequence`** 的 ad-hoc 拼接。而 `_red_attacks.py`
    #   对这四相**均有真实实现**（surface/constraints/exploit/postex，2026-08-31 扩阶段时漏接线）
    #   ⟹ 红队序列上层"14 阶段齐全"、下四层证据空洞（假绿）。现与 RED-HINT… 同形接线。
    RED-SURFACE) audit_extra=",\"red_surface\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" surface 2>/dev/null || echo '{}')" ;;
    RED-CONSTRAINTS) audit_extra=",\"red_constraints\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" constraints 2>/dev/null || echo '{}')" ;;
    RED-EXPLOIT) audit_extra=",\"red_exploit\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" exploit 2>/dev/null || echo '{}')" ;;
    RED-POSTEX) audit_extra=",\"red_postex\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" postex 2>/dev/null || echo '{}')" ;;
    RED-REPORT) audit_extra=",\"red_report\":$(bash "$0" audit --report --type redteam 2>/dev/null || echo '{}')" ;;
    RED-PY) audit_extra=",\"red_py_complete\":true" ;;
    # 2026-08-31 双层 SN 对齐：audit 序列红队分发 7→14 阶段补齐（RED-HINT/HOOK/POISON/REGISTRY/GHOST/COVERAGE/DIFF）
    # 原仅 7 阶段注入（SCOPE/SURFACE/CONSTRAINTS/EXPLOIT/POSTEX/REPORT/PY）——新增 7 阶段证据缺失 =
    # 红队序列双层（node_guard red route 14 vs audit 序列分发 7）不对齐，红队审查证据盲区。
    RED-HINT) audit_extra=",\"red_hint\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" hint 2>/dev/null || echo '{}')" ;;
    RED-HOOK) audit_extra=",\"red_hook\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" hook 2>/dev/null || echo '{}')" ;;
    RED-POISON) audit_extra=",\"red_poison\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" poison 2>/dev/null || echo '{}')" ;;
    RED-REGISTRY) audit_extra=",\"red_registry\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" registry 2>/dev/null || echo '{}')" ;;
    RED-GHOST) audit_extra=",\"red_ghost\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" ghost 2>/dev/null || echo '{}')" ;;
    RED-COVERAGE) audit_extra=",\"red_coverage\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" coverage 2>/dev/null || echo '{}')" ;;
    RED-DIFF) audit_extra=",\"red_diff\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" diff 2>/dev/null || echo '{}')" ;;
    RED-INTEGRITY) audit_extra=",\"red_integrity\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" integrity 2>/dev/null || echo '{}')" ;;
    # A9（2026-10-28）：RED-AIG 车道 —— 不可信样本只在 KVM 沙箱内交给 AI-Infra-Guard。
    # 无宿主直跑分支；AIG_BIN / GK_KVM_IMAGE 未配时返回 info/high 结构化 finding（不静默跳过）。
    RED-AIG) audit_extra=",\"red_aig\":$(python3 \"${SKILL_DIR}/scripts/_red_attacks.py\" aig 2>/dev/null || echo '{}')" ;;
  esac
  fi
  local ach_unlocked="" ach_json="" ach_output=""
  if [ "$dry_run" = "false" ]; then
    ach_unlocked=$(_check_achievements)
    if [ "$ach_unlocked" != "[]" ]; then
      ach_json=$(python3 "$SKILL_DIR/scripts/gk_state_patch.py" append-achievements "$STATE_FILE" "$ach_unlocked" "$(_get_achievements_config)" 2>/dev/null)
    fi
    [ -n "$ach_json" ] && ach_output=",\"achievements\":$ach_json" && ach_output="${ach_output},\"encouragement\":\"$(_encouragement achievement $(echo "$ach_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field '' --join '; ' --subkey label --default-invalid '新成就解锁' 2>/dev/null))\""
    _write_context_file
  fi
  # S12 / F-REV-13 (2026-09-10) advisory：guard 摘要已在 guard 块统一构建（_guard_json），此处直接拼接
  echo "$(printf '%s' "$result" | sed 's/}$//')${audit_extra}${i9_output}${auto_audit_output}${ach_output}${_guard_json}}"
  return 0
}

# ── Phase 7: 环境证据收集（standard 分支 structural gates 的 bash 侧来源）──
_collect_advance_env() {
  local cur="$1" to="$2" wt="$3" br="$4"
  local j="{}"
  case "${cur}→${to}" in
    "STAGE_0→STAGE_1")
      local _wt_exists="false" _wt_reg="false"
      [ -d "$wt" ] && _wt_exists="true"
      git -C "$MAIN_REPO_WSL" worktree list 2>/dev/null | "$RG" -q "$wt" && _wt_reg="true"
      local _rp; _rp=$(json_val "$STATE_FILE" r_phase "" 2>/dev/null || echo "")
      local _rp_in="false"
      if [ -n "$_rp" ] && echo "$wt" | "$RG" -qi "$_rp" >/dev/null 2>&1; then _rp_in="true"; fi
      j=$(python3 "$SKILL_DIR/scripts/gk_json.py" build worktree_exists=$_wt_exists wt_registered=$_wt_reg r_phase_in_path=$_rp_in) ;;
    "STAGE_1→STAGE_2")
      local _uncommitted _stash _ci _detect
      _uncommitted=$(cd "$wt" 2>/dev/null && git status --porcelain 2>/dev/null | head -1 || echo "worktree_missing")
      _stash=$(cd "$wt" 2>/dev/null && git stash list 2>/dev/null | wc -l || echo "worktree_dead")
      _ci=0
      [ -n "$br" ] && _ci=$(cd "$wt" 2>/dev/null && "$RG" -cF "$br" .github/workflows/ci.yml 2>/dev/null | head -1 | tr -d ' \r\n' || echo "0")
      _ci=${_ci:-0}
      local _detect_out; _detect_out=$(_run_gitnexus detect-changes --repo "$(_gx_repo_name_for_dir "$wt")" --scope compare 2>/dev/null || echo "")
      _detect=0
      if [ -n "$_detect_out" ]; then _detect=$(echo "$_detect_out" | python3 "$SKILL_DIR/scripts/gk_json.py" count changes 2>/dev/null || echo "0"); fi
      j=$(python3 "$SKILL_DIR/scripts/gk_json.py" build worktree_exists=$([ -d "$wt" ] && echo true || echo false) uncommitted="$_uncommitted" stash_count=$_stash ci_trigger=$_ci detect_changes=$_detect) ;;
    "STAGE_2→STAGE_3")
      local _diff; _diff=$(cd "$wt" 2>/dev/null && git diff --name-only HEAD~1..HEAD 2>/dev/null | head -1 || echo "")
      j=$(python3 "$SKILL_DIR/scripts/gk_json.py" build diff_files="$_diff") ;;
    "STAGE_3→STAGE_4")
      local _pb="false"; [ -f "${MAIN_REPO_WSL}/docs/plan-backup/${PLAN_FILE}" ] && _pb="true"
      j=$(python3 "$SKILL_DIR/scripts/gk_json.py" build plan_backup_exists=$_pb) ;;
    "STAGE_4→STAGE_5")
      # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 /usr/bin/rg + bare rg）
      local _merge="false" _gnup="false"
      if [ -n "$br" ] && git -C "$MAIN_REPO_WSL" merge-base --is-ancestor "$br" origin/main 2>/dev/null; then _merge="true"; fi
      # 2026-09-21 R16/C2′：收编到单点；`reusable`（内容一致）算 up-to-date。
      case "$(_gitnexus_baseline_status "$MAIN_REPO_WSL")" in current|reusable) _gnup="true" ;; esac
      # 2026-10-31（T9 前置；standard 计划 §9.1 实测 + 11877 臂 CONDITIONAL-BLOCKED）：
      #   补产 `plan_backup_exists`。**本改动零行为变更** —— 现状 `_structural_gates` 的
      #   `STAGE_4→STAGE_5`（gk_advance.py:643-647）只查 merge_check / gn_up_to_date，
      #   **不读**本键（读它的 `:649` 属 `STAGE_5→DONE`）⟹ 多产一个暂无人消费的键。
      #   必要性：T9 把 `STAGE_5→DONE` 的该门并入 4→5 后，4→5 将开始读它；若 bash 侧仍不产
      #   ⟹ `env.get(...,False)` 恒 False ⟹ **4→5 恒 FAIL**（单测因 `_ok_env` 手造 True 而全绿）。
      #   语义：与 `STAGE_3→STAGE_4`（本函数 :5919 分支）逐字同源 —— 同一备份路径判定，不分段。
      local _pb="false"; [ -f "${MAIN_REPO_WSL}/docs/plan-backup/${PLAN_FILE}" ] && _pb="true"
      j=$(python3 "$SKILL_DIR/scripts/gk_json.py" build merge_check=$_merge gn_up_to_date=$_gnup plan_backup_exists=$_pb) ;;
    "STAGE_5→DONE")
      # 2026-10-31（T9 去重）：原 `_gnstale` producer 已删 —— 唯一消费点
      #   `gk_advance.py` 的 `STAGE_5→DONE` 分支原先读 `gn_stale` 只发一条 WARN，与
      #   `STAGE_4→STAGE_5` 的 `gn_up_to_date` 是**同一检查**（§9.1 `gitnexus_fresh` ×3）。
      #   4→5 刚检过，且 STAGE_5 的职责是「gitnexus analyze 终态」（只会变 fresh）⟹ 纯重复。
      #   语义未丢：仍由 4→5 的 `gn_up_to_date` 承载。
      local _pb="false"
      [ -f "${MAIN_REPO_WSL}/docs/plan-backup/${PLAN_FILE}" ] && _pb="true"
      j=$(python3 "$SKILL_DIR/scripts/gk_json.py" build plan_backup_exists=$_pb) ;;
  esac
  echo "$j"
}

# T31: Generate retrospect on DONE — compare current R with previous retrospect
_generate_retrospect() {
  # shellcheck disable=SC2034  # last_stage 是函数签名契约, 当前未使用但 future retrospect 可能需要
  local last_stage="$1"
  local r_phase; r_phase=$(json_val "$STATE_FILE" r_phase "unknown")
  local retrospect_dir="${MAIN_REPO_WSL}/docs/plan-backup"
  local retrospect_file="${retrospect_dir}/retrospect-${r_phase,,}-$(date +%Y%m%d).md"

  # Read current state data
  local monitor_scores rejected_edits edit_count
  monitor_scores=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --dump monitor_scores --default "{}" 2>/dev/null || echo "{}")
  rejected_edits=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --dump gate_data.rejected_edits --default "[]" 2>/dev/null || echo "[]")
  edit_count=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get gate_data.edit_count --default 0 2>/dev/null)

  # Find previous retrospect
  local prev_retrospect="(no previous retrospect)"
  local prev_file; prev_file=$(ls -t "${retrospect_dir}"/retrospect-*.md 2>/dev/null | head -1)
  [ -n "$prev_file" ] && prev_retrospect=$(head -20 "$prev_file" 2>/dev/null || echo "(read error)")

  # Generate retrospect markdown
  cat > "$retrospect_file" << EOFRETRO
# ${r_phase} Retrospective ($(date +%Y-%m-%d))

## monitor_scores
\`\`\`json
${monitor_scores}
\`\`\`

## rejected_edits (last 10)
\`\`\`json
${rejected_edits}
\`\`\`

## edit_budget
- total edits: ${edit_count}
- budget max: 4

## previous_retrospect (first 20 lines)
${prev_retrospect}
EOFRETRO

  echo "{\"file\":\"${retrospect_file}\",\"edit_count\":${edit_count},\"rejected_count\":$(echo "$rejected_edits" | python3 -c "import sys,json;print(len(json.loads(sys.stdin.read())))" 2>/dev/null || echo 0)}"
}

# --- write stage-specific gate_data (bridge pattern: structured audit trail) ---
# [write_guard 裁决 2026-09-06 EXEMPT] 唯一调用方 = cmd_advance L3413，已在 L3410 `[ "$dry_run" = "false" ]`
# 守卫内——守卫在调用点不在函数内；函数自身无 check 语义（标准推进成功路径的 gate_data 批量落盘）。
_write_gate_data() {
  local stage="$1" worktree="$2"
  local gd_update=""
  # Always collect commit SHAs for bare-run detection
  local new_shas
  new_shas=$(cd "$MAIN_REPO_WSL" 2>/dev/null && git log --oneline -5 --no-decorate 2>/dev/null | head -5 | awk '{print $1}' | tr '\n' ' ' || echo "")
  gd_update="\"commit_shas\":\"${new_shas% }\""  # Always written, fixes bare-run detection
  case "$stage" in
    STAGE_1) gd_update+=",\"ctest_passed\":$( [ -f "${worktree}/cpp/build/CTestTestfile.cmake" ] && echo true || echo false), \"ci_trigger_registered\":$( [ -d "$worktree" ] && [ -f "${worktree}/.github/workflows/ci.yml" ] && "$RG" -qF "$branch" "${worktree}/.github/workflows/ci.yml" 2>/dev/null && echo true || echo false)" ;;
    STAGE_2) 
      local ci_pushed; ci_pushed=$(cd "$MAIN_REPO_WSL" 2>/dev/null && git log --oneline origin/"$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"..HEAD 2>/dev/null | wc -l || echo 0)
      local ci_clean; ci_clean=$(cd "$MAIN_REPO_WSL" 2>/dev/null && git status --porcelain 2>/dev/null | wc -l || echo 1)
      [ "$ci_pushed" -eq 0 ] && [ "$ci_clean" -eq 0 ] && gd_update+=",\"ci_green\":true" || gd_update+=",\"ci_green\":false" ;;
    STAGE_3)
      # 2026-09-21 R16/C2′：原实现把 `gitnexus status` 的**彩色文本 stdout 当 JSON 解析**
      # ⟹ 解析必失败 ⟹ 四维**恒空**（静默降级）。改直接取单点四态；形状保持（4 维留空 +
      # 新增 baseline_status）。已核 `gk_audit_state.py` replay 只检 `"nodes" in gb` ⟹ 加键安全。
      local gb_json="" _gd_st="unavailable"
      _gd_st=$(_gitnexus_baseline_status "$MAIN_REPO_WSL")
      gb_json=$(printf '{"nodes":"","edges":"","clusters":"","flows":"","baseline_status":"%s"}' "$_gd_st")
      gd_update+=",\"gitnexus_baseline\":$gb_json, \"plan_synced\":$( [ -f "${MAIN_REPO_WSL}/docs/plans/${PLAN_FILE}" ] && echo true || echo false)" ;;
    STAGE_4)
      local pr_num; pr_num=$(git -C "$MAIN_REPO_WSL" log --oneline -1 2>/dev/null | "$RG" -o '#[0-9]+' | head -1 | tr -d '#' || echo "")
      gd_update+=",\"pr_number\":\"$pr_num\"" ;;
    STAGE_5)
      local branch_name; branch_name=$(cd "$MAIN_REPO_WSL" 2>/dev/null && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
      local branch_exists="true"
      # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
      git branch --list "$branch_name" 2>/dev/null | "$RG" -q . || branch_exists="false"
      [ "$branch_exists" = "false" ] && gd_update+=",\"branch_cleaned\":true" || gd_update+=",\"branch_cleaned\":false" ;;
  esac
  # gate_data 批量写入（2026-08-25 迁移自内联 python；checksum 由 gk_state._write_state 单一事实重算）
  # S7/S8（2026-09-05）：改走 cmd_state_patch 统一写入入口（gate_data 写入类证据单一通道）
  [ -n "$gd_update" ] && cmd_state_patch "$gd_update" >/dev/null 2>&1 || true
}

# ============================================================
# APPEAL — 一次性上诉 (bridge v4.16: appeal → 终裁 → 永久记录)
# ============================================================
# 仅当 agent 认为 monitor 判错时可调用。每个 gate 只能 appeal 一次。
# 驳回 → gate 入 appeal_denied_gates → 永久拦截。仅 --force 可覆盖。
# ============================================================

# PROTECTED_REGION_END::transition

# ---------- appeal ----------
# PROTECTED_REGION_START::appeal
cmd_appeal() {
  local gate="$1" notes="${2:-}"
  [ -z "$gate" ] && { echo '{"error":"appeal <stage> <notes> required"}'; return 1; }
  [ ! -f "$STATE_FILE" ] && { echo '{"error":"No state file"}'; return 1; }

  # ── bash 薄壳（2026-09-06 bashpy 改造）：域逻辑单源 = scripts/gk_appeal.py ──
  # D3 foreign guard / A7 sentinel 迁移 / 粘性否决检查 / mediation / 记录写回 / schema 守卫
  # 全部收拢 python 核心（其 JSON 已对齐 legacy 契约：allowed/reason/error/ok 兼容）。
  # bash 仅保留：env/密钥解析（WSL 边界）+ 环境就绪守卫 + 委托 + JSON 透传 + fail-closed。

  # 环境与密钥读取（WSL 边界解析）
  local api_key="${API_KEY}" worktree branch
  worktree=$(json_val "$STATE_FILE" worktree "" 2>/dev/null || echo "")
  branch=$(json_val "$STATE_FILE" branch "" 2>/dev/null || echo "")

  # bridge v4.18: auto-resolve key cross WSL boundary
  [ -z "$api_key" ] && { _resolve_api_key; api_key="$API_KEY"; }

  # A7（2026-09-05）：环境就绪安全网——API_BASE/API_KEY 缺失属环境故障，**不是实质否决**：
  # 明确错误码 + 引导 + action=RETRYABLE，不落任何记录（对照 paper-review loader 五源分流先例）。
  if [ -z "${API_BASE:-}" ]; then
    echo '{"ok":false,"error":"APPEAL_ENV_UNAVAILABLE","reason":"API_BASE 未设置（WSL provider env 缺失）","action":"RETRYABLE","hint":"设置 API_BASE（DS: https://api.deepseek.com / MIMO: https://api.xiaomimimo.com/v1）+ DEEPSEEK_API_KEY 或 GATEKEEPER_API_KEY 后重试 — 环境问题非实质否决，未落记录"}'
    return 1
  fi
  if [ -z "$api_key" ]; then
    echo '{"ok":false,"error":"APPEAL_ENV_UNAVAILABLE","reason":"API_KEY 未设置且自动解析失败","action":"RETRYABLE","hint":"设置 DEEPSEEK_API_KEY/GATEKEEPER_API_KEY 后重试 — 环境问题非实质否决，未落记录"}'
    return 1
  fi

  # ── 委托 python 核心（域逻辑单源）────────────────────────────
  # 显式传 --base/--model（防未 export env 丢失）；python 继承 API_BASE/API_MODEL 语义，
  # 失败一律 A7 规范码 RETRYABLE 且不落记录（不烧唯一 appeal 机会）。
  # F-REV-9 C1（2026-09-08）：appeal 判据 = 进入判据（防 Catch-22）——传当前阶段 + transition
  # env（_collect_advance_env 单源：cur→gate 对应 case 产出，如 STAGE_3→STAGE_4 = plan_backup_exists）；
  # python 核心复用 gk_advance._structural_gates 核验"进入 {gate} 的门禁"，完成态 schema 降级背景。
  local _cur_st _tx_env
  _cur_st=$(json_val "$STATE_FILE" stage "IDLE" 2>/dev/null || echo "IDLE")
  _tx_env=$(_collect_advance_env "$_cur_st" "$gate" "$worktree" "$branch" 2>/dev/null || echo "{}")
  [ -z "$_tx_env" ] && _tx_env="{}"
  local _ap_out _ap_rc
  _ap_out=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_appeal.py" \
    --gate "$gate" --notes "$notes" --api-key "$api_key" \
    --worktree "$worktree" --branch "$branch" --path "$STATE_FILE" \
    --base "${API_BASE:-}" --model "${API_MODEL:-deepseek-flash}" \
    --current-stage "$_cur_st" --env-json "$_tx_env" 2>>"$GK_DBG_LOG")
  _ap_rc=$?
  if [ $_ap_rc -ne 0 ]; then
    # python 核心错误 JSON（APPEAL_DENIED_PERMANENTLY/ALREADY_APPEALED/FOREIGN_*/A7 RETRYABLE）
    # 已对齐 legacy 契约（allowed/reason）→ 直接透传；空/非 JSON（核心崩溃）→ fail-closed 兜底。
    if echo "$_ap_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" valid 2>/dev/null; then
      echo "$_ap_out"
    else
      echo '{"allowed":false,"reason":"APPEAL_CORE_UNAVAILABLE","detail":"python 核心未返回可解析 JSON — 见 GK_DBG_LOG，未落记录"}'
    fi
    return 1
  fi
  echo "$_ap_out"
}

# ============================================================
# ESCALATE — 人类上报 (bridge v4.16: appeal DENIED → escalate)
# ============================================================
# 仅在 appeal 被驳回后可触发。生成 Markdown 报告供人类审查。
# ============================================================

# PROTECTED_REGION_END::appeal

# ---------- escalate ----------
cmd_escalate() {
  local gate="$1" reason="${2:-}"
  [ -z "$gate" ] && { echo '{"error":"escalate <stage> <reason> required"}'; return 1; }
  [ ! -f "$STATE_FILE" ] && { echo '{"error":"No state file"}'; return 1; }

  # D3: Foreign content guard — detect cross-tenant contamination in escalate reason
  local _own_user="${USERNAME:-${USER:-HP}}"
  local foreign_hit
  local _tmp_reason; _tmp_reason=$(mktemp)
  printf '%s' "$reason" > "$_tmp_reason"
  foreign_hit=$(python3 "$SKILL_DIR/scripts/gk_foreign_scan.py" "$_tmp_reason" "$_own_user" 2>/dev/null || echo "clean")
  rm -f "$_tmp_reason"
  if [ "$foreign_hit" != "clean" ]; then
    echo "{\"ok\":false,\"error\":\"FOREIGN_CONTENT_DETECTED\",\"detail\":\"$foreign_hit\",\"action\":\"BLOCKED\"}"
    return 1
  fi

  # Check: was this gate's appeal denied?
  # 2026-08-31 修复: 与 cmd_appeal 写入对齐 —— appeal_denied_gates 在顶层，
  # 原查 gate_data.appeal_denied_gates（嵌套）永不命中 → 误报 APPEAL_NOT_DENIED。
  local denied; denied=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --contains appeal_denied_gates "$gate" 2>/dev/null)
  [ "$denied" != "yes" ] && { echo "{\"allowed\":false,\"reason\":\"APPEAL_NOT_DENIED\",\"detail\":\"Gate $gate has not been denied on appeal. Appeal must be denied BEFORE escalating.\"}"; return 1; }

  local report="${MAIN_REPO_WSL}/.gatekeeper_escalation_${gate}_$(date +%Y%m%d_%H%M).md"

  cat > "$report" << EOFREPORT
# Gatekeeper Escalation Report — ${gate}

**Generated**: $(date -Iseconds)
**Reason**: ${reason}

## State Snapshot
\`\`\`json
$(cat "$STATE_FILE" 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_json.py" pretty 2>/dev/null)
\`\`\`

## Gate Data
\`\`\`json
$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --dump gate_data 2>/dev/null)
\`\`\`

## Appeal Record
$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --dump "appeal_records.$gate" 2>/dev/null)

## Git Diff (uncommitted + recent)
\`\`\`
$(git -C "$MAIN_REPO_WSL" diff --stat 2>/dev/null || echo "(no changes)")
\`\`\`

## Git Log (last 10)
\`\`\`
$(git -C "$MAIN_REPO_WSL" log --oneline -10 2>/dev/null)
\`\`\`

## Monitor Full Output (if available)
\`\`\`json
$(cat "${MAIN_REPO_WSL}/.gatekeeper_monitor_api_tmp.json" 2>/dev/null | python3 "$SKILL_DIR/scripts/gk_json.py" pretty 3000 2>/dev/null || echo "(no API monitor output)")
\`\`\`

---
**Action required**: Human review of escalated PRM monitor decision.
EOFREPORT

  echo "{\"escalated\":true,\"gate\":\"$gate\",\"report\":\"$report\",\"action\":\"Review the report and decide whether to --force advance or implement the fix manually.\"}"
}

# ---------- resolve (human final resolution after appeal/escalate) ----------
cmd_resolve() {
  local gate="${1:-}" resolution="${2:-}" reason="${3:-}"
  [ -z "$gate" ] && { echo '{"ok":false,"error":"resolve <gate> <resolution> [reason]. resolution: force_advance|manual_fix|dismiss"}'; return 1; }
  [ -z "$resolution" ] && { echo '{"ok":false,"error":"resolution required: force_advance|manual_fix|dismiss"}'; return 1; }
  case "$resolution" in
    force_advance|manual_fix|dismiss) ;;
    *) echo '{"ok":false,"error":"resolution must be force_advance|manual_fix|dismiss"}'; return 1 ;;
  esac
  # D3: Foreign content guard — detect cross-tenant contamination in resolve reason
  local _own_user="${USERNAME:-${USER:-HP}}"
  local foreign_hit
  local _tmp_reason; _tmp_reason=$(mktemp)
  printf '%s' "$reason" > "$_tmp_reason"
  foreign_hit=$(python3 "$SKILL_DIR/scripts/gk_foreign_scan.py" "$_tmp_reason" "$_own_user" 2>/dev/null || echo "clean")
  if [ "$foreign_hit" != "clean" ]; then
    rm -f "$_tmp_reason"
    echo "{\"ok\":false,\"error\":\"FOREIGN_CONTENT_DETECTED\",\"detail\":\"$foreign_hit\",\"action\":\"BLOCKED\"}"
    return 1
  fi
  # G-09: Validate gate parameter
  # 2026-08-13 修复：rg -qE 是 grep 语法误用——ripgrep 的 -E 是 --encoding 别名（扩展正则默认开启），
  # 导致 gate 校验永远失败（"Unknown gate"）。改为 rg -q。
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
  if ! echo "$gate" | "$RG" -q '^(ECO-RESEARCH|ECO-VERIFY|ECO-AUDIT|ECO-EDIT|ECO-SCAN|ECO-READ|ECO-DOC|ECC-.*)$'; then
    rm -f "$_tmp_reason"
    echo "{\"ok\":false,\"error\":\"Unknown gate: $gate\",\"known_gates\":[\"ECO-RESEARCH\",\"ECO-EDIT\",\"ECO-VERIFY\",\"ECO-DOC\",\"ECO-SCAN\",\"ECO-READ\",\"ECO-AUDIT\",\"ECC-ANALYSIS\"]}"
    return 1
  fi
  # G-18: Block resolve when appeal was permanently denied (fail-closed)
  # 2026-08-31 修复: appeal_denied_gates 在顶层（cmd_appeal 写入段），原查嵌套路径永不命中。
  local _appeal_denied; _appeal_denied=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --contains appeal_denied_gates "$gate" 2>/dev/null)
  [ -z "$_appeal_denied" ] && _appeal_denied="yes"  # Python failed → deny (fail-closed)
  if [ "$_appeal_denied" = "yes" ]; then
    rm -f "$_tmp_reason"
    echo "{\"ok\":false,\"error\":\"APPEAL_DENIED_PERMANENTLY\",\"detail\":\"Gate $gate appeal was denied. Resolve blocked — use --force to override or re-evaluate.\",\"action\":\"BLOCKED\"}"
    return 1
  fi
  # G-17: Block resolve when appeal_required exists — must use appeal (LLM mediation) first
  # 2026-10-31（X1 多源）：判据单源 = scripts/gk_gate_appeal.py。原 `gk_state_query --get
  #   gate_data.appeal_required` 是第二实现，看不到 `gate_data.appeal_blocks` 的新阻断源 ⟹ fail-open。
  local _appeal_gates; _appeal_gates=$(python3 "$SKILL_DIR/scripts/gk_gate_appeal.py" --blocking "$STATE_FILE" 2>/dev/null)
  if [ -n "$_appeal_gates" ] && [ "$resolution" = "force_advance" ]; then
    rm -f "$_tmp_reason"
    echo "{\"ok\":false,\"error\":\"APPEAL_REQUIRED_BEFORE_RESOLVE\",\"detail\":\"Gate $_appeal_gates has appeal_required flag. Use 'appeal <gate> <notes>' first (LLM mediation). resolve force_advance cannot bypass quality gates.\",\"action\":\"BLOCKED\"}"
    return 1
  fi
  # G-10: reason already written to _tmp_reason; will be read by Python below
  python3 "$SKILL_DIR/scripts/gk_state_ops.py" resolve-record "$STATE_FILE" "$gate" "$resolution" "$_tmp_reason" 2>/dev/null || echo '{"ok":false,"error":"resolve failed"}'
  rm -f "$_tmp_reason"
  # Sign resolution with audit Ed25519 key (ghost attack defense)
  # 2026-08-13 修复：显式走 audit 线（_sign_raw 第 2 参）。此前默认 context 私钥与设计
  # （flywheel L1136 复用 audit key）错配，且 context 24h 轮换导致长期记录 7 天后永久无法验签。
  # 写入后自验 fail-fast（防止签名写坏但 audit 才发现）；落 ed25519_hash 供自哈希防损坏。
  local _res_data; _res_data=$(python3 "$SKILL_DIR/scripts/gk_state_patch.py" subset "$STATE_FILE" human_resolutions "$gate" "ed25519_sig,ed25519_hash" 2>/dev/null || echo "")
  if [ -n "$_res_data" ] && [ -f "$_AUDIT_PRIV_KEY" ]; then
    local _tmp_res; _tmp_res=$(mktemp)
    echo "$_res_data" > "$_tmp_res"
    local _sig; _sig=$(_sign_raw "$_tmp_res" audit 2>/dev/null || echo "")
    local _sig_b64 _sig_hash
    _sig_b64=$(echo "$_sig" | python3 "$SKILL_DIR/scripts/gk_json.py" get sig 2>/dev/null)
    _sig_hash=$(echo "$_sig" | python3 "$SKILL_DIR/scripts/gk_json.py" get hash 2>/dev/null)
    rm -f "$_tmp_res"
    if [ -n "$_sig_b64" ]; then
      python3 "$SKILL_DIR/scripts/gk_crypto_cli.py" set-resolution-sig "$STATE_FILE" "$gate" "$_sig_b64" "$_sig_hash" 2>/dev/null || true
      # 防御插桩 [DBG-RESOLVE-2026-08-13]：自验签名，失败即阻断写入（fail-fast）
      local _self_ok; _self_ok=$(_verify_resolution_sig "$gate" 2>/dev/null || echo '{"ok":false}')
      if ! echo "$_self_ok" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test ok 2>/dev/null; then
        echo "{\"ok\":false,\"error\":\"resolve signature self-verify failed: $_self_ok\"}"; return 1
      fi
    fi
  fi
}

# ---------- replay (D8: decision replay from advance log) ----------
# C10 (2026-09-05): replay --ember [phase] = ember 快照回判（archived finding reconcile + A3 seal 验签），
# 归口 §12 决策重放统一入口；无 --ember = legacy advance_log 决策重放（_replay.py，不变）。
cmd_replay() {
  local _mode="legacy" _phase=""
  if [ "${1:-}" = "--ember" ]; then
    _mode="ember"; _phase="${2:-}"
  fi
  if [ "$_mode" = "ember" ]; then
    python3 "${SKILL_DIR}/scripts/gk_ember_replay.py" reconcile --state-file "$STATE_FILE" ${_phase:+--phase "$_phase"} --audit-key-dir "${_AUDIT_KEY_DIR:-}" 2>/dev/null || echo '{"ok":false,"error":"ember replay failed"}'
    return 0
  fi
  python3 "${SKILL_DIR}/scripts/_replay.py" "$STATE_FILE" 2>/dev/null || echo '{"ok":false,"error":"replay failed"}'
}

# ---------- ember (C10: get_state_history 同构只读面, 2026-09-05) ----------
# 只读命令：list = 倒序列余烬快照 / get = 单份元数据 / verify = A3 seal 验签。
# reconcile 归口 cmd_replay --ember（§12 决策重放统一入口，本命令不重复引擎）。
# 2026-09-25（**L2 自动触发落刀**，`ECC-3802B43E4EF9`）：新增 **burn** 子命令 = 「让余烬系统
#   **处理** state 体积」的确定性入口 —— 归口到既有配额归档通道 `gk_finding.archive_closed`
#   （`cmd_finding archive-closed`，**禁第二实现**；同一 state 解析链 + 同一锁/checksum 通道）：
#   预算足 ⟹ `archived=0` **零写盘**；越线 ⟹ 按汇总预算把**最旧 closed** 台账烧成旁挂余烬
#   `<state>.finding-archive.jsonl`（可回溯）+ `purged_fids` 代际声明（`reconcile` 单列 purged）。
#   病根（实测）：该通道当天已实现且 CLI 已暴露，但**无任何自动触发**（相位切换的 ember 快照只在
#   `discover` 且相位真变化时写）⟹ state 名义上受余烬管理、实际十几天增长**从未被处理过**
#   （margin 实测只剩 1.3%）⟹ 只能靠人工调配额。本入口 + cron 作业 `ember-burn`（每小时对齐
#   tick 相位）= 把「被墙逼着跑」改成「系统定期处理」。
#   ⚠ `_CMD_REG[ember]` 的 `side_effects` 字段保持空（**注册表在 PROTECTED_REGION::gate 内，禁改**）
#   ⟹ `burn` 的 state 写不计入 edit_budget 计费面（登记见计划档 §4.13.14 D）。
cmd_ember() {
  local _sub="${1:-list}"
  shift 2>/dev/null || true
  if [ "$_sub" = "burn" ]; then
    cmd_finding archive-closed "$@"
    return $?
  fi
  python3 "${SKILL_DIR}/scripts/gk_ember_replay.py" "$_sub" --state-file "$STATE_FILE" "$@" --audit-key-dir "${_AUDIT_KEY_DIR:-}" 2>/dev/null || echo "{\"ok\":false,\"error\":\"ember $_sub failed\"}"
}

# ---------- pr-score (C9: PR-SCORE 双盲评分锚定, 2026-09-06) ----------
# plan-refinement 双盲评分（plan-refinement SKILL.md 8.2 角色 2：F1-F7 + 7 维）锚定：
# seal = score.json → 独立快照 .prscore-<plan>.json + plan `<!-- PR-SCORE -->` 区块 + A3 audit key 签名
# verify = 快照 seal 验签 + 区块存在性与关键字段一致性（防"双盲评分产物事后可改无锚"）
# list = plan 同目录快照只读面。plan 定位：--plan 全路径或 docs/plans/ 下名称。
cmd_pr_score() {
  local _sub="${1:-}"
  if [ -z "$_sub" ]; then
    echo '{"ok":false,"error":"pr-score <seal|verify|list> required"}'
    return 1
  fi
  shift 2>/dev/null || true
  local _plan="" _args=()
  while [ $# -gt 0 ]; do
    if [ "$1" = "--plan" ] && [ -n "$2" ]; then
      local cand="$2"
      [ -f "$cand" ] && _plan="$cand"
      [ -z "$_plan" ] && [ -f "${SKILL_DIR}/docs/plans/${cand}" ] && _plan="${SKILL_DIR}/docs/plans/${cand}"
      [ -z "$_plan" ] && [ -f "${SKILL_DIR}/docs/plans/${cand}.md" ] && _plan="${SKILL_DIR}/docs/plans/${cand}.md"
      shift 2
      continue
    fi
    _args+=("$1")
    shift
  done
  if [ -z "$_plan" ]; then
    echo '{"ok":false,"error":"--plan 文档未定位（给定路径或 docs/plans/ 下）"}'
    return 1
  fi
  python3 "${SKILL_DIR}/scripts/gk_pr_score.py" "$_sub" --plan "$_plan" "${_args[@]}" 2>/dev/null \
    || echo "{\"ok\":false,\"error\":\"pr-score $_sub failed\"}"
}

# ---------- cron (application-level scheduler) ----------
# [write_guard 裁决 2026-09-06 EXEMPT] 状态写入仅于 health 子命令（L4077 显式簿记，release-check 调度器实跑）；
# list/status 只读子命令零写入；无 --check 变体。
cmd_cron() {
  local action="${1:-list}"
  shift 2>/dev/null
  case "$action" in
    list)
      python3 "${SKILL_DIR}/scripts/cron_jobs.py" list 2>/dev/null ;;
    create)
      local name="${1:-}" schedule="${2:-}" prompt="${3:-}" script="" no_agent="false"
      # 2026-08-27: --script/--no-agent 透传（doc-align 定期任务 = no_agent + script 确定性执行）
      local _rest=()
      while [ $# -gt 0 ]; do
        case "$1" in
          --script) script="${2:-}"; shift 2 2>/dev/null || shift ;;
          --no-agent) no_agent="true"; shift ;;
          --) shift; break ;;
          *) _rest+=("$1"); shift ;;
        esac
      done
      # 兼容原签名: cron create <name> <schedule> <prompt> [--script S --no-agent]
      if [ ${#_rest[@]} -ge 1 ] && [ -z "$name" ] && [ $# -gt 0 ]; then :; fi
      [ -z "$name" ] && [ -n "${_rest[0]:-}" ] && name="${_rest[0]}" && schedule="${_rest[1]:-}" && prompt="${_rest[2]:-}"
      [ -z "$name" ] && { echo '{"ok":false,"error":"Usage: cron create <name> <schedule> <prompt> [--script S --no-agent]"}'; return 1; }
      [ -z "$schedule" ] && { echo '{"ok":false,"error":"Schedule required (e.g. 0 9 * * *, every 2h, 30m)"}'; return 1; }
      [ -z "$prompt" ] && [ "$no_agent" != "true" ] && { echo '{"ok":false,"error":"Prompt required"}'; return 1; }
      [ -z "$prompt" ] && prompt="(no_agent script job)"
      local _na_flag=""; [ "$no_agent" = "true" ] && _na_flag="--no-agent"
      python3 "${SKILL_DIR}/scripts/cron_jobs.py" create "$name" "$schedule" "$prompt" --script "$script" $_na_flag ;;
    remove)
      local job_id="${1:-}"
      [ -z "$job_id" ] && { echo '{"ok":false,"error":"Usage: cron remove <job_id>"}'; return 1; }
      python3 "${SKILL_DIR}/scripts/cron_jobs.py" remove "$job_id" ;;
    enable|disable)
      local job_id="${1:-}"
      [ -z "$job_id" ] && { echo '{"ok":false,"error":"Usage: cron enable/disable <job_id>"}'; return 1; }
      local _en="enable"; [ "$action" = "disable" ] && _en="disable"
      python3 "${SKILL_DIR}/scripts/cron_jobs.py" "$_en" "$job_id" ;;
    tick)
      python3 "${SKILL_DIR}/scripts/cron_scheduler.py" --once --verbose 2>/dev/null || echo '{"ok":false,"error":"tick failed"}'
      ;;
    start)
      echo '{"ok":true,"message":"Starting cron scheduler (background)"}'
      # Cross-platform: use Python subprocess instead of nohup (Windows compat)
      GK_PY_SD="$(_gk_py_path "$SKILL_DIR")" python3 -c "
import subprocess,os,sys
log=open(os.path.join(os.environ['GK_PY_SD'],'scripts','cron.log'),'a')
p=subprocess.Popen([sys.executable,os.path.join(os.environ['GK_PY_SD'],'scripts','cron_scheduler.py'),'--interval','60'],
    stdout=log,stderr=log,stdin=subprocess.DEVNULL,
    start_new_session=True,cwd=os.environ['GK_PY_SD'])
print('{\"ok\":true,\"pid\":%d}' % p.pid)
" 2>/dev/null || echo '{"ok":false,"error":"Failed to start cron scheduler"}'
      ;;
    status)
      python3 "${SKILL_DIR}/scripts/cron_jobs.py" status ;;
    run)
      local job_id="${1:-}"
      [ -z "$job_id" ] && { echo '{"ok":false,"error":"Usage: cron run <job_id>"}'; return 1; }
      # 2026-09-01 修复：script+no_agent job 直接执行脚本（此前一律走 subagent，无视
      # no_agent 配置——external-ref 等纯脚本 job 被错误地交给 LLM）。
      local job_meta
      job_meta=$(python3 "${SKILL_DIR}/scripts/cron_jobs.py" get "$job_id" 2>/dev/null)
      local job_script job_no_agent job_prompt
      job_script=$(echo "$job_meta" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field script --default '' 2>/dev/null)
      job_no_agent=$(echo "$job_meta" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field no_agent --bool-tf --default-invalid '' 2>/dev/null)
      job_prompt=$(echo "$job_meta" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field prompt --default '' 2>/dev/null)
      if [ -n "$job_script" ] && [ "$job_no_agent" = "true" ]; then
        [ -f "${SKILL_DIR}/$job_script" ] || { echo "{\"ok\":false,\"error\":\"script not found: $job_script\"}"; return 1; }
        # 与 cron_scheduler._run_job 同源：按扩展名派发（.py → python3；其余 → bash）。
        case "$job_script" in
          *.py) python3 "${SKILL_DIR}/$job_script" 2>/dev/null || echo '{"ok":false,"error":"script run failed"}' ;;
          *)    bash "${SKILL_DIR}/$job_script" 2>/dev/null || echo '{"ok":false,"error":"script run failed"}' ;;
        esac
        return 0
      fi
      # Phase 7c B3 (2026-08-21): 调度器注入的 CRON_PROMPT 权威优先（含 context_from 跨作业拼接），
      # 修复数据管道静默丢失（cron_scheduler.py 设了 env 但此前从未被读取）。
      # 空守卫只作用于存储 prompt 路径——CRON_PROMPT 存在时跳过存储读取。
      local prompt=""
      if [ -n "${CRON_PROMPT:-}" ]; then
        prompt="$CRON_PROMPT"
      elif [ -n "$job_prompt" ]; then
        prompt="$job_prompt"
      else
        prompt=$(python3 "${SKILL_DIR}/scripts/cron_jobs.py" prompt "$job_id" 2>/dev/null)
        [ -z "$prompt" ] && { echo '{"ok":false,"error":"Job not found or empty prompt"}'; return 1; }
      fi
      _resolve_api_key
      _resolve_provider_config
      _subagent_exec "${SKILL_DIR}/scripts/subagent_runner.py" --task "$prompt" --mode default \
        --api-key "$API_KEY" --api-base "$API_BASE" --api-model "$API_MODEL" \
        --reasoning "$DS_REASONING_EFFORT" --max-turns 10 2>/dev/null || echo '{"ok":false,"error":"agent run failed"}'
      ;;
    trigger)
      local ref="${1:-}"
      [ -z "$ref" ] && { echo '{"ok":false,"error":"Usage: cron trigger <id|name>"}'; return 1; }
      python3 "${SKILL_DIR}/scripts/cron_jobs.py" trigger "$ref" ;;
    edit)
      local ref="${1:-}" field="${2:-}" value="${3:-}"
      [ -z "$ref" ] && { echo '{"ok":false,"error":"Usage: cron edit <id|name> <field> <value>"}'; return 1; }
      [ -z "$field" ] && { echo '{"ok":false,"error":"Field required (schedule/prompt/name/deliver/workdir)"}'; return 1; }
      python3 "${SKILL_DIR}/scripts/cron_jobs.py" edit "$ref" "$field" "$value" ;;
    health)
      # Phase 7c (2026-08-21): 调度器状态投影——checksum-aware + plan 指针感知写入。
      # 修复 cron_scheduler 直写 state 不重算 _checksum → 下次 advance/guard-edit 报 TAMPERED 的 bug；
      # 并顺带修复写死默认 state 忽略 plan 指针的错位问题（STATE_FILE 由 CLI 启动时解析）。
      # Usage: cron health <release-check-json-file>
      local rc_file="${1:-}"
      [ -f "$STATE_FILE" ] || { echo '{"ok":false,"error":"No state file"}'; return 1; }
      [ ! -f "$rc_file" ] && { echo '{"ok":false,"error":"report file required: cron health <json-file>"}'; return 1; }
      GK_PY_RC="$(_gk_py_path "$rc_file")" _state_write "d.setdefault('gate_data',{})['cron_health']={'last_tick_at':'$(date -u +%Y-%m-%dT%H:%M:%SZ)','last_tick_ok':True,'source':'cron'}; d.setdefault('gate_data',{})['_latest_release_check']=json.load(open(os.environ['GK_PY_RC']))" 2>/dev/null || true
      local ptype; ptype=$(python3 "${SKILL_DIR}/scripts/gk_gate_project_type.py" "$STATE_FILE" 2>/dev/null || echo "standard")
      echo "{\"ok\":true,\"state_file\":\"$STATE_FILE\",\"project_type\":\"$ptype\"}"
      ;;
    *) echo '{"ok":false,"error":"Usage: cron [list|create|remove|enable|disable|tick|start|status|run|trigger|edit|health]"}' ;;
  esac
}

# ---------- set-key (standardized API key management) ----------
cmd_set_key() {
  local provider="${1:-}" key="${2:-}" _kf="" _file_ok=false

  # 2026-11-02（开源包可用性）：`set-key status` = 只读面，报来源与掩码，**不回显完整 key**。
  if [ "$provider" = "status" ] || [ "$provider" = "--status" ]; then
    local _src="unset" _mask=""
    _kf=$(_gk_key_file "$PROVIDER")
    _mask=$(_gk_key_file_read "$PROVIDER") || _mask=""
    if [ -n "$_mask" ]; then _src="file"; else _mask=""; fi
    if [ "$_src" = "unset" ] && \
       [ -n "${GATEKEEPER_API_KEY:-}${DEEPSEEK_API_KEY:-}${MIMO_API_KEY:-}" ]; then
      _src="env"
    fi
    _mask=$(python3 "$SKILL_DIR/scripts/gk_api_key.py" mask --provider "$PROVIDER" \
              --skill-dir "$SKILL_DIR" 2>/dev/null || true)
    python3 -c 'import json,sys
print(json.dumps({"ok": True, "provider": sys.argv[1], "key_source": sys.argv[2],
                  "key_file": sys.argv[3], "masked": sys.argv[4]}, ensure_ascii=False))' \
      "$PROVIDER" "$_src" "$_kf" "$_mask"
    return 0
  fi

  case "$provider" in
    deepseek|mimo) ;;
    *)
      echo '{"error":"Usage: set-key <deepseek|mimo> <key> | set-key status","providers":["deepseek","mimo"]}'
      return 1
      ;;
  esac

  [ -z "$key" ] && { echo '{"error":"key argument required","usage":"set-key deepseek sk-xxx OR set-key mimo tp-xxx"}'; return 1; }

  local env_var
  if [ "$provider" = "mimo" ]; then
    env_var="MIMO_API_KEY"
  else
    env_var="DEEPSEEK_API_KEY"
  fi

  # 持久化（跨平台，2026-11-02）：`.keys/<provider>` 以 0600 写入 —— 这是 Linux/macOS 上
  #   唯一重启后仍生效的入口；路径单源 = `scripts/gk_api_key.py`（`$GATEKEEPER_KEY_FILE` 可覆盖）。
  _kf=$(_gk_key_file "$provider")
  mkdir -p "$(dirname "$_kf")" 2>/dev/null || true
  if ( umask 077; printf '%s\n' "$key" > "$_kf" ) 2>/dev/null; then
    chmod 600 "$_kf" 2>/dev/null || true
    _file_ok=true
  fi

  # Set for current session (WSL)
  export "${env_var}=${key}"

  # Persist to Windows User environment (cross-session) —— best-effort；非 Windows 自动跳过。
  local _ps_exe=""
  if [ -x "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" ]; then
    _ps_exe="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
  elif command -v powershell.exe >/dev/null 2>&1; then
    _ps_exe="powershell.exe"
  fi
  local _note="Key set for current session; persisted to key file (cross-platform)."
  if [ -n "$_ps_exe" ]; then
    local safe_key; safe_key=$(printf '%s' "$key" | sed "s/'/''/g")
    "$_ps_exe" -NoProfile -Command "[System.Environment]::SetEnvironmentVariable('${env_var}', '${safe_key}', 'User')" 2>/dev/null \
      && _note="Key set for current session + key file + Windows User env (restart IDE for Process scope)."
  fi
  python3 -c 'import json,sys
print(json.dumps({"ok": True, "provider": sys.argv[1], "env_var": sys.argv[2],
                  "key_file": sys.argv[3], "file_persisted": sys.argv[4] == "1",
                  "session_env": True, "note": sys.argv[5]}, ensure_ascii=False))' \
    "$provider" "$env_var" "$_kf" "$( [ "$_file_ok" = true ] && echo 1 || echo 0 )" "$_note"
}

# 2026-11-04（方案 C：**不锁单一平台**）：主仓命中判定收成**单源**。
#   病象（实测）：`_main_repo_resolve` 解析失败时 `_MAIN_REPO_*_RE` 为空，而
#   `rg -qi ""` **命中一切** ⟹ 任何路径都被判成主仓 ⟹ `MAIN_WORKTREE` 假拦
#   （跨平台调用/换机后 python 解析不到主仓即全量误拦）。
#   判据：RG 缺位 ⟹ fail-closed(0)；两形态正则**各自非空才判**，任一命中 ⟹ 0。
_main_repo_hit() {
  local _p="${1:-}"
  [ -z "$RG" ] && return 0
  if [ -n "$_MAIN_REPO_WIN_RE" ] && printf '%s' "$_p" | "$RG" -qi "$_MAIN_REPO_WIN_RE"; then
    return 0
  fi
  if [ -n "$_MAIN_REPO_WSL_RE" ] && printf '%s' "$_p" | "$RG" -qi "$_MAIN_REPO_WSL_RE"; then
    return 0
  fi
  return 1
}

# 2026-11-04（方案 C：**不锁单一平台**）：主仓命中判定收成**单源**。
#   病象（实测）：`_main_repo_resolve` 解析失败时 `_MAIN_REPO_*_RE` 为空，而
#   `rg -qi ""` **命中一切** ⟹ 任何路径都被判成主仓 ⟹ `MAIN_WORKTREE` 假拦
#   （跨平台调用/换机后 python 解析不到主仓即全量误拦）。
#   判据：RG 缺位 ⟹ fail-closed(0)；两形态正则**各自非空才判**，任一命中 ⟹ 0。
_main_repo_hit() {
  local _p="${1:-}"
  [ -z "$RG" ] && return 0
  if [ -n "$_MAIN_REPO_WIN_RE" ] && printf '%s' "$_p" | "$RG" -qi "$_MAIN_REPO_WIN_RE"; then
    return 0
  fi
  if [ -n "$_MAIN_REPO_WSL_RE" ] && printf '%s' "$_p" | "$RG" -qi "$_MAIN_REPO_WSL_RE"; then
    return 0
  fi
  return 1
}

# ---------- balance (DeepSeek API balance query, MiMo 无此 endpoint) ----------
# 2026-11-04（用户：「余额检查命令需要改造一下，需要用于随机或者定期。检查是否存在 token
#   异常消耗 / 缓存命中突然崩溃？subagent 那边应该已经有类似的东西了？」）：
#   `--audit` 与上一快照比（余额速率/归零），`--usage FILE` 复用 `gk_cache_observe`（subagent
#   逐调用归因）判缓存崩溃/失效点，`--record` 落本机台账，`--jitter N` 把采样时刻随机化。
#   默认（不带新 flag）输出**逐字不变** —— 加性变更，不影响既有消费者。
cmd_balance() {
  local _json=0 _record=0 _audit=0 _usage="" _jitter="0" _strict=0 _hist="" _ji=0
  while [ $# -gt 0 ]; do
    case "${1:-}" in
      --json) _json=1 ;;
      --record) _record=1 ;;
      --audit) _audit=1 ;;
      --usage) _usage="${2:-}"; shift ;;
      --jitter) _jitter="${2:-0}"; shift ;;
      --strict) _strict=1 ;;
      --history) _hist="${2:-}"; shift ;;
    esac
    shift
  done
  local api_key="${API_KEY}"
  [ -z "$api_key" ] && { _resolve_api_key; api_key="$API_KEY"; }
  [ -z "$api_key" ] && { echo '{"error":"API key not set"}'; return 1; }

  # Balance only works with DeepSeek — MiMo API has no balance endpoint
  local balance_url="https://api.deepseek.com/user/balance"
  if [ "$PROVIDER" = "mimo" ]; then
    echo '{"warning":"MiMo API has no balance endpoint","provider":"mimo","hint":"Check https://platform.xiaomimimo.com/#/console/usage for usage"}'
    # Still try DeepSeek balance with fallback key
    balance_url="https://api.deepseek.com/user/balance"
  fi

  # 随机抖动：打散采样时刻（避免每次都在同一缓存窗口/限流点取数）。
  # ⚠ 纯 bash（2026-11-04）：原实现用内联解释器做 jitter ⟹ 新增第 97 个**内联载荷**，
  #   触发公开面 `--max-payload 96` 棘轮。改用 `$RANDOM`（0..32767 上限），零新载荷。
  case "$_jitter" in
    ''|0|0.0|0.00) : ;;
    *)
      _ji="${_jitter%%.*}"
      case "$_ji" in ''|*[!0-9]*) _ji=0 ;; esac
      [ "$_ji" -gt 32767 ] && _ji=32767
      [ "$_ji" -gt 0 ] && sleep "$(( RANDOM % (_ji + 1) ))"
      ;;
  esac

  local resp; resp=$(curl -s --max-time 30 -X GET "$balance_url" \
    -H "Accept: application/json" \
    -H "Authorization: Bearer ${api_key}" 2>/dev/null)

  [ -z "$resp" ] && { echo '{"error":"balance API call failed"}'; return 1; }

  if [ "$_json" = "1" ] || [ "$_record" = "1" ] || [ "$_audit" = "1" ] \
     || [ -n "$_usage" ] || [ "$_strict" = "1" ] || [ -n "$_hist" ]; then
    local _args=(--stdin)
    [ "$_record" = "1" ] && _args+=(--record)
    [ "$_audit" = "1" ] && _args+=(--audit)
    [ "$_strict" = "1" ] && _args+=(--strict)
    [ -n "$_usage" ] && _args+=(--usage "$_usage")
    [ -n "$_hist" ] && _args+=(--history "$_hist")
    [ "$_json" = "1" ] && _args+=(--json)
    printf '%s' "$resp" | python3 "${SKILL_DIR}/scripts/gk_balance_audit.py" "${_args[@]}"
    return $?
  fi

  echo "$resp" | python3 "${SKILL_DIR}/scripts/balance_format.py" 2>/dev/null
}

# ---------- self-check (system diagnostics) ----------
# Checks state file integrity, provider connectivity, gitnexus status, subagent env.
# Usage: self-check [--tests quick|full|skip] [--full|--quick|--skip-tests] [--repair-worktree]
#   `--tests`（2026-11-01）：测试腿**显式分档** —— quick（缺省，22 文件子集 + 缓存）/
#   full（全量 575+ 文件，CI / 发布前用）/ skip（只要环境面，最快）。
#   `--repair-worktree`（2026-11-01）：第 39 项 `state.proj.worktree` 不一致时**原地修复**
#   （worktree 复制 state 后必做，否则启动期归属扫描会纠正到主树当时阶段并致域路由 MISMATCH）。
#   等价 env `GK_SELFCHECK_TESTS=quick|full|skip`（子进程强制 skip 防套娃）。
# Phase 3.5e: Python checks extracted to scripts/gk_self_check.py
cmd_self_check() {
  local issues=0 checks="" _sc_tests=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --tests) _sc_tests="${2:-}"; shift 2 2>/dev/null || shift ;;
      --full) _sc_tests="full"; shift ;;
      --quick) _sc_tests="quick"; shift ;;
      --skip-tests) _sc_tests="skip"; shift ;;
      --repair-worktree) export GK_SELFCHECK_REPAIR_WORKTREE=1; shift ;;
      *) shift ;;                     # 保留既有宽容（旧调用方可能带无关参数）
    esac
  done
  case "$_sc_tests" in
    quick|full|skip) export GK_SELFCHECK_TESTS="$_sc_tests" ;;
    "") : ;;
    *) echo '{"ok":false,"error":"self-check --tests 只接受 quick|full|skip"}' >&2; return 2 ;;
  esac

  # ---- Python-backed checks via gk_self_check.py ----
  # R2（2026-09-05）：聚合器掩蔽分流——原 `|| echo 空 JSON` 把"issues>0 合法 FAIL 退出 1"与
  # "python 崩溃"混为一谈：run_all 只要有任何 FAIL（如 WSL 下 pytest 缺失）就整包被兜底丢弃，
  # python 19 项检查在可见 self-check 永不显形（A4 根因）。修复 = 只在本命令自身 python3
  # 不可解析/崩溃时兜底；退出码非 0 但输出可解析 = 真实发现，原样并入 issues。
  # 解释器单源（2026-11-01，二修）：不再写死任何个人 venv 绝对路径（公开包别人的机器上没有，
  #   且 Windows 侧同级 venv 无法并列）。走 `scripts/py_resolve.sh pytest` —— 只挑**真能
  #   import pytest** 的候选（quick/full 才真跑）；一个都没有时回落 any 解释器，
  #   `check_tests` 会显式 SKIP 并给出原因（不静默当绿）。
  local _sc_py; _sc_py=$(bash "${SKILL_DIR}/scripts/py_resolve.sh" pytest 2>/dev/null || true)
  [ -n "$_sc_py" ] || _sc_py=$(_subagent_py_real)
  local sc_out; sc_out=$("$_sc_py" "${SKILL_DIR}/scripts/gk_self_check.py" \
    --state-file "$STATE_FILE" \
    --skill-dir "$SKILL_DIR" \
    --key-meta "${_KEY_META:-}" \
    --key-integrity "${_KEY_INTEGRITY:-}" \
    --audit-key-dir "${_AUDIT_KEY_DIR:-}" 2>/dev/null)
  local _sc_rc=$?
  if ! echo "$sc_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test checks --is list >/dev/null 2>&1; then
    sc_out='{"ok":true,"issues":0,"checks":[{"check":"python_aggregator","status":"WARN","detail":"gk_self_check.run_all 崩溃或不可解析(rc='"$_sc_rc"') — python 19 项未并入，见 gk_dbg.log"}]}'
  fi

  # Merge Python check results
  local py_issues; py_issues=$(echo "$sc_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field issues --default 0 2>/dev/null || echo 0)
  issues=$((issues + py_issues))

  # Extract Python check results — 动态提取（2026-08-15 RED-PY-BASH 修复）：
  # 原硬编码白名单易漂移（曾漏 gitnexus；新增 python 检查需手动加循环项 → 静默丢输出）。
  # 现自动取 python 输出全部 check（**含 gitnexus** —— 2026-11-01 起判定由 python 元数据面产出，
  #   原「排除 gitnexus 由 bash 统一生成」的双写契约已删除，见下方 0 段注释）。
  local py_checks; py_checks=$(echo "$sc_out" | python3 "$SKILL_DIR/scripts/gk_views.py" selfcheck-py-checks 2>/dev/null)
  [ -n "$py_checks" ] && checks+="${py_checks},"

  # ---- Bash-native checks ----
  # 0. gitnexus — **已删除 bash 探针**（2026-11-01 提速 + 去伪红）：
  #   原走 `_gitnexus_baseline_status`（`gitnexus status --json`，默认 300s / 自检 10s）——
  #   本机实测该子命令**挂起**（90s 无进展、user CPU≈0）⟹ 只产出 `unavailable` WARN（伪红）
  #   且单点吃掉 10s+。判定改由 python 侧 `check_gitnexus`（读 `.gitnexus` 元数据、0 子进程、
  #   毫秒级）产出，经 `gk_views selfcheck-py-checks` 透传（不再排除 gitnexus）。
  # 3. Tool config consistency (2026-08-09) — TOOL_REGISTRY/valid_tools/SCOPE_PATH_MAP
  #    守护"单一数据源+自动派生"机制；self-check 已被 ECO/AUDIT/RED hint 引用，零新增流程节点
  local cfg_out; cfg_out=$(python3 "${SKILL_DIR}/scripts/check_tool_cfg.py" 2>/dev/null || echo '{"ok":false,"issues":1,"checks":[]}')
  local cfg_issues; cfg_issues=$(echo "$cfg_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field issues --default 0 2>/dev/null || echo 0)
  issues=$((issues + cfg_issues))
  local cfg_cjson; cfg_cjson=$(echo "$cfg_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field checks --first-json --default-invalid '' 2>/dev/null)
  [ -n "$cfg_cjson" ] && checks+="${cfg_cjson},"
  # 4. Subagent python
  if command -v python3 >/dev/null 2>&1; then
    checks+="{\"check\":\"subagent_python\",\"status\":\"PASS\"},"
  else
    checks+="{\"check\":\"subagent_python\",\"status\":\"FAIL\"},"
    issues=$((issues+1))
  fi
  # 5. Context injection readiness (subagent-context.json + .sig)
  local ctx_file="${SKILL_DIR}/references/subagent-context.json"
  local sig_file="${ctx_file}.sig"
  if [ -f "$ctx_file" ] && [ -f "$sig_file" ]; then
    local ctx_verify; ctx_verify=$(openssl pkeyutl -verify -pubin -inkey "${_CONTEXT_PUB_KEY}" -rawin -in "$ctx_file" -sigfile "$sig_file" 2>&1)
   # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
   if ! echo "$ctx_verify" | "$RG" -q "Verified"; then
     # Fallback: try audit key (context signed before rotation)
     ctx_verify=$(openssl pkeyutl -verify -pubin -inkey "${_AUDIT_PUB_KEY}" -rawin -in "$ctx_file" -sigfile "$sig_file" 2>&1)
   fi
   if echo "$ctx_verify" | "$RG" -q "Verified"; then
     checks+='{"check":"context_injection","status":"PASS","detail":"context signed + verified"},'
   else
     checks+='{"check":"context_injection","status":"WARN","detail":"context signature stale. Run: context --update"},'
   fi
  else
    checks+='{"check":"context_injection","status":"WARN","detail":"context not initialized. Run: context --update"},'
  fi

  # 12. Environment variable integrity check (API_KEY 判定走 _resolve_api_key 全链; SUBAGENT_ROLE, NODE)
  local env_issues=0 env_details=""
  # Check API key — 2026-09-06 修复: 旧逻辑只看 WSL env（bash-only）→ 忽略 PowerShell
  # User/Process 边界回退 → 有 key 却报 API_KEY=MISSING 的荒唐误报（key 其实在 Windows 环境）。
  # 现改走 _resolve_api_key（GATEKEEPER→DEEPSEEK→PowerShell User→Process 同链），自检判定
  # 与 CLI 实际可跑条件严格一致；_validate_api_key（W10）过滤空/含空白/过短 key。
  local _api_check="MISSING"
  if _resolve_api_key && [ -n "$API_KEY" ]; then
    if _validate_api_key "$API_KEY"; then
      _api_check="SET"
    else
      _api_check="INVALID"
    fi
  fi
  case "$_api_check" in
    SET)     env_details+="API_KEY=OK($PROVIDER)" ;;
    INVALID) env_issues=$((env_issues+1)); env_details+="API_KEY=INVALID(W10 校验失败: 空/空白/过短)" ;;
    *)       env_issues=$((env_issues+1)); env_details+="API_KEY=MISSING(local-only monitor)" ;;
  esac
  # Check SUBAGENT_ROLE override (warn if set — potential escalation vector)
  if [ -n "${SUBAGENT_ROLE:-}" ]; then
    env_issues=$((env_issues+1)); env_details+=" | SUBAGENT_ROLE=OVERRIDDEN(${SUBAGENT_ROLE})"
  fi
  # Check node + project-local gitnexus runner (2026-08-20: 原硬编码 /mnt/d/Program Files/nodejs/node.exe
  # 与 R-T5.6 的 .gitnexus/run.cjs 项目本地 runner 不一致 → node.exe 缺失误报 WARN 但 gitnexus 实际正常)
  if [ -f "${SKILL_DIR}/.gitnexus/run.cjs" ] && command -v node >/dev/null 2>&1; then
    env_details+=" | NODE=OK(run.cjs)"
  else
    env_issues=$((env_issues+1)); env_details+=" | NODE=MISSING(run.cjs/node)"
  fi
  if [ "$env_issues" -eq 0 ]; then
    checks+="{\"check\":\"env_integrity\",\"status\":\"PASS\",\"detail\":\"$env_details\"},"
  else
    checks+="{\"check\":\"env_integrity\",\"status\":\"WARN\",\"issues\":$env_issues,\"detail\":\"$env_details\"},"
  fi

  # 13. rg 误用安全网（2026-08-13）：ripgrep 的 -E=--encoding（非 grep 的 extended，扩展正则默认开启），
  #     rg -qE 是 grep 语法误用曾导致 resolve gate 校验永远"Unknown gate"。静态扫描防回归。
  #     2026-08-13 二轮补漏：组合短标志同样误用（rg -qiE / rg -oE —— -E 会把 pattern 当 encoding 参数吃掉，
  #     报 unknown encoding），扫描模式扩展为 rg -<字母>*E 任意组合。
  # 字符类 [q]/[E] 破坏自指（本行不含字面模式，否则 rg -l 会命中自己）
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg；内层模式串保持原样）
  local rg_misuse; rg_misuse=$("$RG" -l "rg -[a-z]*[E] '|rg -[a-z]*[E] \"" "$SKILL_DIR"/gatekeeper-cli.sh "$SKILL_DIR"/scripts/*.sh 2>/dev/null | head -3)
  if [ -z "$rg_misuse" ]; then
    checks+='{"check":"rg_usage","status":"PASS","detail":"no rg -E/-qE misuse (rg -E=--encoding, ext regex default)"},'
  else
    checks+="{\"check\":\"rg_usage\",\"status\":\"FAIL\",\"detail\":\"rg -E misuse in: $rg_misuse\"},"
    issues=$((issues+1))
  fi

  # 14. heredoc 静默失败检测（2026-08-13）：python heredoc 异常曾因 2>/dev/null 被吞（如 divergence=None 崩溃），
  #     现关键路径 stderr 追加到 GK_DBG_LOG，此处检查最近是否有 python 错误。
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
  local _dbg_errs; _dbg_errs=$(tail -20 "$GK_DBG_LOG" 2>/dev/null | "$RG" -c 'Traceback|Error' || echo 0)
  if [ "${_dbg_errs:-0}" = "0" ]; then
    checks+='{"check":"heredoc_errors","status":"PASS","detail":"no recent python heredoc errors in gk_dbg.log"},'
  else
    checks+="{\"check\":\"heredoc_errors\",\"status\":\"WARN\",\"detail\":\"${_dbg_errs} recent errors in gk_dbg.log — see $(basename "$GK_DBG_LOG")\"},"
  fi

  # 15. audit 联动（2026-08-20）：引用 audit --state 持久化的 audit_state_result 摘要，审计↔自检闭环。
  #     未运行 → INFO；已运行且 matches>0 → PASS（明细带 matches/total）。
  local _audit_link; _audit_link=$(python3 "$SKILL_DIR/scripts/gk_views.py" audit-link "$STATE_FILE" 2>/dev/null || echo "NOT_RUN")
  if [ "$_audit_link" = "NOT_RUN" ]; then
    checks+='{"check":"audit_link","status":"INFO","detail":"audit --state 未运行 — 无摘要可引用"},'
  elif [ "$_audit_link" = "audit_state matches=0/0" ]; then
    checks+='{"check":"audit_link","status":"WARN","detail":"audit_state_result 异常 matches=0/0"},'
  else
    checks+="{\"check\":\"audit_link\",\"status\":\"PASS\",\"detail\":\"$_audit_link\"},"
  fi

  # 16. git-workflow 插件加载安全网（2026-08-30，git-workflow 插件化 → 纳入本机自检）：
  #     git-workflow 是独立技能仓库（bash 技能类），经 gk_gitworkflow_loader 五源分流
  #     （builtin/dev/tampered/missing/error，多入口 SHA256 pin + manifest 对账）。
  #     builtin → PASS；dev → WARN（未 pin/未登记治理缺口）；missing → WARN（脚本缺失）；
  #     tampered/error → FAIL（fail-closed：误加载拦截，禁用）。
  #     loader 缺失 = git-workflow 技能未安装 → INFO（非本技能强制依赖，不报错）。
  local gw_loader="${SKILL_DIR}/../git-workflow/scripts/gk_gitworkflow_loader.py"
  if [ -f "$gw_loader" ]; then
    local gw_out; gw_out=$(python3 "$gw_loader" check 2>/dev/null || echo '{"source":"error"}')
    local gw_src; gw_src=$(echo "$gw_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field source --default error 2>/dev/null || echo "error")
    case "$gw_src" in
      builtin)
        checks+='{"check":"gitworkflow_loader","status":"PASS","detail":"git-workflow builtin (SHA256 pins + manifest verified)"},' ;;
      dev)
        checks+='{"check":"gitworkflow_loader","status":"WARN","detail":"git-workflow dev (unpinned scripts or manifest gap)"},' ;;
      missing)
        checks+='{"check":"gitworkflow_loader","status":"WARN","detail":"git-workflow core scripts missing (漏加载)"},' ;;
      tampered|error)
        checks+="{\"check\":\"gitworkflow_loader\",\"status\":\"FAIL\",\"detail\":\"git-workflow $gw_src (fail-closed — 误加载拦截)\"},"
        issues=$((issues+1)) ;;
      *)
        checks+='{"check":"gitworkflow_loader","status":"INFO","detail":"git-workflow loader unusable"},' ;;
    esac
  else
    checks+='{"check":"gitworkflow_loader","status":"INFO","detail":"git-workflow skill not installed (loader absent)"},'
  fi

  # 注：sequence_node_safety / governed_baseline / tenant_isolation 三项 2026-09-05 曾以 bash-native
  # 单发独立显形（掩蔽 workaround）；R2 根修后 python 聚合器（gk_self_check.run_all #17-19）已并入上方
  # py_checks，此处不再单发（防双写重复），崩溃兜底由 python_aggregator WARN 显式承载。

  # 去除尾逗号（checks 每元素拼接带 ','，尾部残留 → JSON 非法，2026-08-03 修复）
  checks="${checks%,}"
  echo "{\"ok\":true,\"issues\":$issues,\"checks\":[$checks]}"
}

# ---------- main router ----------
cmd="${1:-}"; shift 2>/dev/null || true

# ---------- doc-align (document deterministic alignment engine) ----------
# Refs: bashpy 同档 — 0 API 静态扫描；论文框架漂移 / CLI 命令数 / 双源 L 层 / 优化器状态登记
# Usage: doc-align [--papers-dir P] [--review-skill-dir R] [--json]
# 唯一调用公式：doc-align（脚本恒输出 JSON，--json 为兼容 no-op）。未知参数 → exit 2 + usage。
cmd_doc_align() {
  local papers_dir="${PAPERS_DIR:-}" review_skill_dir="${REVIEW_SKILL_DIR:-}"
  local ecc_review_pkg="" ecc_review_roots="" summary=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --papers-dir) papers_dir="${2:-}"; shift 2 2>/dev/null || shift ;;
      --review-skill-dir) review_skill_dir="${2:-}"; shift 2 2>/dev/null || shift ;;
      # 2026-09-26（ECC-1FA6B6E7D15C A 侧）：转发 ECC 证据包**逐锚复核**入口。
      # 形态约束：`_CMD_REG` 在 `PROTECTED_REGION::gate` 内（禁改）⟹ **不新增命令**，
      #   只在既有 `doc-align` 上开分支（同 `state-patch` 先例，见本文件 L6684 注）。
      #   本函数体**不在**任何 PROTECTED_REGION 内 ⟹ 可落刀。
      --ecc-review) ecc_review_pkg="${2:-}"; shift 2 2>/dev/null || shift ;;
      --roots) ecc_review_roots="${2:-}"; shift 2 2>/dev/null || shift ;;
      --json) shift ;;  # no-op：gk_doc_align.py 恒输出 JSON（兼容统一调用公式）
      # 2026-10-12（ECC-F2BDAFB8899C）：人读视图（每检查一行）—— 全量 JSON 逾 1.7 万行不可一次读完。
      --summary) summary="1"; shift ;;
      *)
        echo "{\"ok\":false,\"error\":\"unknown arg: $1\",\"exit_code\":2,\"usage\":\"doc-align [--papers-dir P] [--review-skill-dir R] [--ecc-review <pkg.md>] [--roots a,b] [--json] [--summary]\",\"next\":\"bash gatekeeper-cli.sh help doc-align\"}"
        return 2 ;;
    esac
  done
  if [ -n "$ecc_review_pkg" ]; then
    # 转发包复核：0 API 确定性；--roots 为**逗号分隔**的附加扫描根（仓外计划/证据包所在仓）。
    local _er_rc
    if [ -n "$ecc_review_roots" ]; then
      python3 "${SKILL_DIR}/scripts/gk_ecc_review.py" "$ecc_review_pkg" --roots "$ecc_review_roots"
    else
      python3 "${SKILL_DIR}/scripts/gk_ecc_review.py" "$ecc_review_pkg"
    fi
    _er_rc=$?
    [ "$_er_rc" -le 1 ] && return 0 || return "$_er_rc"
  fi
  if [ -n "$summary" ]; then
    PAPERS_DIR="$papers_dir" REVIEW_SKILL_DIR="$review_skill_dir" \
      python3 "${SKILL_DIR}/scripts/gk_doc_align.py" --summary
  else
    PAPERS_DIR="$papers_dir" REVIEW_SKILL_DIR="$review_skill_dir" \
      python3 "${SKILL_DIR}/scripts/gk_doc_align.py"
  fi
}

# ---------- paper-review (论文写作投稿前置模拟评审插件 — 2026-08-28，域 7 专项；投稿前自检，非同行审稿) ----------
# Refs: 多会议评审准则档案（按 venue 归档，档案随私仓保留）—— 轨道政策
# 单一事实源内置于 gk_paper_review.py。产出"添加/补充什么才能提高接收概率"的缺口清单 + 接收概率。
# --local 0 API 确定性缺口扫描；--subagent 深度评审（自动解析 GATEKEEPER_API_KEY/DEEPSEEK_API_KEY）。
# Usage: paper-review --venue <venue-id> [--track <track-id>] --papers-dir <dir> [--local|--subagent|--pc-sim [--pc-role R] [--pc-ac-from JSON] [--pc-extreme] [--pc-rebuttal FILE] [--pc-out PREFIX]]
# 唯一调用公式见 usage；未知参数 → exit 2 + usage。
cmd_paper_review() {
  local venue="" track="" papers_dir="" mode="" camera_ready="" repo="" status=""
  local pc_role="" pc_ac_from="" pc_extreme="" pc_rebuttal="" pc_out=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --venue) venue="${2:-}"; shift 2 2>/dev/null || shift ;;
      --track) track="${2:-}"; shift 2 2>/dev/null || shift ;;
      --papers-dir) papers_dir="${2:-}"; shift 2 2>/dev/null || shift ;;
      --repo) repo="${2:-}"; shift 2 2>/dev/null || shift ;;
      --local) mode="--local"; shift ;;
      --subagent) mode="--subagent"; shift ;;
      # 2026-10-21：PC 定向模拟（评审组成口径，见 scripts/gk_pc_sim.py）。
      # 与 --subagent 互斥：前者按「准则簇」补缺口，后者按「评审人」估判定。
      --pc-sim) mode="--pc-sim"; shift ;;
      --pc-role) pc_role="${2:-}"; shift 2 2>/dev/null || shift ;;
      --pc-ac-from) pc_ac_from="${2:-}"; shift 2 2>/dev/null || shift ;;
      # 2026-10-23：极端轮次（污染台账口径）从 CLI 露出——此前只存在于脚本 argparse，
      # 技能入口不可见 ⟹ 极端测试的机制等于没沉淀进插件。
      --pc-extreme) pc_extreme="--extreme"; shift ;;
      --pc-rebuttal) pc_rebuttal="${2:-}"; shift 2 2>/dev/null || shift ;;
      --pc-out) pc_out="${2:-}"; shift 2 2>/dev/null || shift ;;
      --camera-ready) camera_ready="--camera-ready"; shift ;;
      --status) status="1"; shift ;;
      *)
        echo "{\"ok\":false,\"error\":\"unknown arg: $1\",\"exit_code\":2,\"usage\":\"paper-review --venue fse|www [--track T] --papers-dir <dir> [--repo ALIAS] [--local|--subagent|--pc-sim] [--pc-role R] [--pc-ac-from JSON] [--pc-extreme] [--pc-rebuttal FILE] [--pc-out PREFIX] [--camera-ready] [--status]\",\"next\":\"bash gatekeeper-cli.sh help paper-review\"}"
        return 2 ;;
    esac
  done
  # 2026-10-21（用户质询"为啥那么久/没接探针"）：--status 只读 .progress.jsonl，不需要 dir/API key。
  if [ "$status" = "1" ]; then
    local _sargs=(--status)
    [ -n "$venue" ] && _sargs+=(--venue "$venue")
    [ -n "$track" ] && _sargs+=(--track "$track")
    GK_PAPER_REVIEW_VIA_CLI=1 python3 "${SKILL_DIR}/scripts/gk_paper_review.py" "${_sargs[@]}"
    return $?
  fi
  if [ -z "$venue" ] || [ -z "$papers_dir" ]; then
    echo '{"ok":false,"error":"usage: paper-review --venue fse|www [--track T] --papers-dir <dir> [--local|--subagent|--pc-sim] [--status]","exit_code":1}'
    return 1
  fi
  # 基础加载安全网（2026-08-29 bashpy 协议统一应用）：漏/误/错加载 → exit 2 + 明确错误码
  local load_json load_src
  load_json=$(python3 "${SKILL_DIR}/scripts/gk_paper_review_loader.py" 2>/dev/null)
  load_src=$(echo "$load_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field source --default missing 2>/dev/null || echo "missing")
  case "$load_src" in
    builtin|dev) : ;;
    tampered|missing|error)
      echo "{\"ok\":false,\"error\":\"paper-review 加载安全网拦截: source=$load_src（$(echo "$load_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field detail --default '' 2>/dev/null)）\",\"exit_code\":2,\"usage\":\"paper-review --venue fse|www [--track T] --papers-dir <dir> [--local|--subagent]\"}"
      return 2 ;;
  esac
  [ -z "$mode" ] && mode="--local"
  # --pc-role/--pc-ac-from/--pc-extreme/--pc-rebuttal/--pc-out 只在 --pc-sim 派发面
  # 有意义（与 monitor 的 flag 同用门同款：禁静默）。
  if [ "$mode" != "--pc-sim" ] && { [ -n "$pc_role" ] || [ -n "$pc_ac_from" ] \
      || [ -n "$pc_extreme" ] || [ -n "$pc_rebuttal" ] || [ -n "$pc_out" ]; }; then
    echo '{"ok":false,"error":"--pc-role/--pc-ac-from/--pc-extreme/--pc-rebuttal/--pc-out 仅与 --pc-sim 同用","exit_code":2,"usage":"paper-review --venue www --track T --papers-dir <dir> --pc-sim [--pc-role R] [--pc-ac-from JSON] [--pc-extreme] [--pc-rebuttal FILE] [--pc-out PREFIX]"}'
    return 2
  fi
  local args=(--venue "$venue" --papers-dir "$papers_dir" "$mode")
  [ -n "$track" ] && args+=(--track "$track")
  [ -n "$camera_ready" ] && args+=("$camera_ready")
  [ -n "$repo" ] && args+=(--repo "$repo")
  # 2026-10-21：PC 定向模拟派发（0 state 写入；key 解析与 --subagent 同源）
  if [ "$mode" = "--pc-sim" ]; then
    API_KEY=""
    _resolve_api_key || { echo '{"ok":false,"error":"PC 模拟需要 API key（GATEKEEPER_API_KEY / DEEPSEEK_API_KEY）","exit_code":2,"usage":"paper-review --venue www --papers-dir <dir> --pc-sim"}'; return 2; }
    _validate_api_key "$API_KEY" || { echo '{"ok":false,"error":"API key 无效（空/含空白/过短）","exit_code":2}'; return 2; }
    _resolve_provider_config
    local pcargs=(--venue "$venue" --papers-dir "$papers_dir")
    [ -n "$track" ] && pcargs+=(--track "$track")
    [ -n "$repo" ] && pcargs+=(--repo "$repo")
    [ -n "$pc_role" ] && pcargs+=(--role "$pc_role")
    [ -n "$pc_ac_from" ] && pcargs+=(--ac-from "$pc_ac_from")
    [ -n "$pc_extreme" ] && pcargs+=("$pc_extreme")
    [ -n "$pc_rebuttal" ] && pcargs+=(--rebuttal-file "$pc_rebuttal")
    [ -n "$pc_out" ] && pcargs+=(--out "$pc_out")
    [ -n "$camera_ready" ] && pcargs+=("$camera_ready")
    GK_SUBAGENT_API_KEY="$API_KEY" GK_SUBAGENT_API_BASE="$API_BASE" GK_SUBAGENT_API_MODEL="$API_MODEL" \
      python3 "${SKILL_DIR}/scripts/gk_pc_sim.py" "${pcargs[@]}"
    return $?
  fi
  if [ "$mode" = "--subagent" ]; then
    # 深度评审基础加载安全网：key 缺失 → exit 2 + 明确错误码与正确调用方式
    API_KEY=""
    _resolve_api_key || { echo '{"ok":false,"error":"subagent 深度评审需要 API key（GATEKEEPER_API_KEY / DEEPSEEK_API_KEY）","exit_code":2,"usage":"paper-review --venue fse|www --papers-dir <dir> --subagent"}'; return 2; }
    _validate_api_key "$API_KEY" || { echo '{"ok":false,"error":"API key 无效（空/含空白/过短）","exit_code":2}'; return 2; }
    _resolve_provider_config
    # 2026-08-29 安全网漏洞修复（用户质询"目录被清空=危险命令拦截失败？加载安全网失效了？"）：
    # 加载安全网此前只在 CLI 侧校验脚本状态，直接 `python gk_paper_review.py` 绕过 CLI 时
    # 安全网不运行。CLI 设置 GK_PAPER_REVIEW_VIA_CLI=1 标记唯一正确调用方式，
    # gk_paper_review.main() 入口对缺失标记 fail-closed（exit 2 + 提示唯一调用方式）。
    GK_SUBAGENT_API_KEY="$API_KEY" GK_SUBAGENT_API_BASE="$API_BASE" GK_SUBAGENT_API_MODEL="$API_MODEL" \
      GK_PAPER_REVIEW_CACHE="${GK_PAPER_REVIEW_CACHE:-1}" \
      GK_PAPER_REVIEW_VIA_CLI=1 python3 "${SKILL_DIR}/scripts/gk_paper_review.py" "${args[@]}"
    return $?
  fi
  GK_PAPER_REVIEW_CACHE="${GK_PAPER_REVIEW_CACHE:-1}" \
    GK_PAPER_REVIEW_VIA_CLI=1 python3 "${SKILL_DIR}/scripts/gk_paper_review.py" "${args[@]}"
}

# ---------- help (命令调用公式唯一入口 — 2026-08-28) ----------
# Usage: help [cmd] — 输出 references/cli-protocol.md 的全部/单命令调用公式（单一事实源）。
# 所有命令的基础加载安全网：未知命令/参数错误 → exit 2 + 指向本命令获取唯一调用公式。
cmd_help() {
  local target="${1:-}"
  local proto="${SKILL_DIR}/references/cli-protocol.md"
  if [ ! -f "$proto" ]; then
    echo '{"ok":false,"error":"cli-protocol.md not found — run docgen --check first"}'
    return 1
  fi
  if [ -n "$target" ]; then
    # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 /usr/bin/rg）
    "$RG" -n -A3 "\|.*\b$target\b" "$proto" 2>/dev/null | head -12
  else
    "$RG" -n "Usage:|^##" "$proto" 2>/dev/null | head -80
  fi
}

# ---------- project-register（治理范围注册表自动化入库门禁 — 域 5）----------
# Refs: 2026-08-28-security-hardening-assessment.md §5.2（自动化管控流程）。
# 把 .gatekeeper.scopes.json 的手动编辑改为受控命令：输入合规检测 → 原子登记
# （flock+checksum）→ REPO_ROOTS 联动声明（--read-repo）→ audit_log 审计留痕。
# Usage: project-register register <marker> --state <path> [--type main|worktree|plugin]
#                                  [--note <text>] [--read-repo <alias>]
#        project-register list
#        project-register remove <marker>
cmd_project_register() {
  local out rc
  out=$(python3 "${SKILL_DIR}/scripts/gk_project_register.py" "$@")
  rc=$?
  # A3（2026-09-05）：register 成功 → 对新登记项目 state 父目录做 gitnexus 基线确保。
  # 复用既有基线检测（_gitnexus_ensure_baseline → gitnexus status current|up-to-date|已是最新
  # = 同版本复用、不重复 analyze；stale/缺失才 analyze）——失败仅 WARN 不阻断登记（输出 JSON 附
  # gitnexus_baseline 字段 + stderr 提示），对齐 gatekeeper 登记门禁"登记不因外部索引失败而回滚"。
  if [ $rc -eq 0 ] && [ "${1:-}" = "register" ]; then
    local _sf _gxb
    _sf=$(printf '%s' "$out" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("entry",{}).get("state_file",""))' 2>/dev/null || echo "")
    if [ -n "$_sf" ]; then
      _gxb=$(_gitnexus_ensure_baseline "$(dirname "$_sf")")
    else
      _gxb='{"gitnexus_baseline":"skipped","detail":"state_file 不可解析 — 基线确保跳过"}'
    fi
    # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 /usr/bin/rg）
    if echo "$_gxb" | "$RG" -q '"failed"'; then
      echo "{\"warning\":\"gitnexus baseline ensure failed — 登记已完成，索引待环境就绪后手动 analyze\",\"gitnexus_baseline\":$_gxb}" >&2
    fi
    printf '%s' "$out" | python3 -c '
import sys, json
d = json.load(sys.stdin)
d["gitnexus_baseline"] = json.loads(sys.argv[1])
print(json.dumps(d, ensure_ascii=False, indent=2))
' "$_gxb"
    return 0
  fi
  printf '%s\n' "$out"
  return "$rc"
}

# ---------- moa-aggregate (MoA 聚合器 — ECC references → 主 agent 聚合输入) ----------
# Refs: zthl-harness-adapter-plan governance/moa/（Hermes MoA 同构，Reference-Aggregator）。
# subagent ECC 报告 = reference（有界字段随档位 _ECC_BOUNDS 缩放）；主 agent = aggregator。
# 本命令 = 聚合前治理：投毒清洗（pre_check）+ 溯源（audit）+ 聚合引用块生成（inject）。
# Usage: moa-aggregate [--state FILE] [--recent N] [--role ROLE] [--task T] [--allow-cross-task] [--fresh N] [--md]
# F-REV-8 归属约束（2026-09-11）：默认只聚合**同一任务指纹**的 references（缺省拒跨任务聚合）；
# --task T 显式指定锚定任务；--allow-cross-task 显式放开（trace 记 cross_task_allowed）。
# 唯一调用公式见 usage；未知参数 → exit 2 + usage。
cmd_moa_aggregate() {
  local state_file="${STATE_FILE:-}" recent=0 role="" task="" md_flag=false cross_task=false fresh=""
  # 2026-09-23（B2 / `ECC-BAB89429DFD1`）：`--accept`（MoA 聚合**验收**单入口）+ `--worktrees`
  #   由本白名单转发 —— 实现落在 `scripts/gk_moa_aggregate.py`（Python-only，族
  #   `F-MoA-accept-aggregation` 的 coder 落点）；此处只是参数编排，**禁第二实现**。
  local accept_flag=false worktrees=""
  # T7（2026-10-16，finding ECC-21AB384F03A9）：补转发 `accept` 的 3 个 **py 侧已有、CLI 却缺**的 flag
  #   —— 尤其 `--full-regression`（合并树全量回归）经 CLI 此前**不可达** ⟹ 早期"验收单入口"实际打不通。
  local full_regression=false accept_files="" accept_timeout=""
  # ECC-4C1E8A27B9D3（2026-09-24）：`--html <path>` —— MoA 聚合后的**双盲人评页**出口
  #   （自足 HTML / 读完即弃；实现落 `gk_moa_aggregate.render_html`，此处只转发，禁第二实现）。
  local html_out="" html_given=false out_file="" no_open_flag=false plan=""
  # §18.1（2026-10-03，ECC-5538DD07B709 RC1/N1）：`--batch <id>` 精确取批 + `--allow-cross-batch`
  #   显式放开跨批比较（缺省按批分节不混票）。实现落 gk_moa_aggregate，此处只转发，禁第二实现。
  local batch="" cross_batch=false
  # Infra-1c（2026-10-05，ECC-1F540718AEE5）：聚合落 finding / 跨轮收敛比对 —— 白名单转发，
  #   实现落 gk_moa_aggregate（禁第二实现）。
  local emit_finding=false no_emit_finding=false convergence=false mu=""
  # 2026-11-02：臂数断言（防 6 臂被 task_bound 剪成 1 臂仍当成功）；实现落 gk_moa_aggregate.apply_expect。
  local expect_n=""
  # 2026-11-02：与 --expect 同用的有界自动补救（仅归属/批边界；可疑件不自动放宽）。
  local auto_remediate=false
  # D（2026-10-09，owner 裁定「点提交自动跑三步并交给我」）：`--serve`/`--port` 白名单转发 ——
  #   一次性回环服务（页面提交 ⟹ 自动跑三步链 ⟹ 回执）；实现落 `gk_moa_aggregate.serve`，此处只编排。
  local serve_flag=false port=""
  # §5（2026-10-11，ECC-143409BC4A8C）：`--covert-scan` 白名单转发 —— T4 隐蔽事件通道 warden
  #   三轴扫描（实现落 gk_covert_warden.py，经 gk_moa_aggregate 挂进聚合封套；禁第二实现）。
  local covert_scan=false
  # A8-①（2026-10-11，ECC-8B2C819EDE7D）：`--strict-independence` 白名单转发 —— opt-in 独立度硬门
  #   （n_eff < n_eff_min 时强制 abstain；实现落 gk_moa_aggregate，此处只编排，禁第二实现）。
  local strict_independence=false
  # T1（2026-10-14，ECC-PLAN `2026-10-14-moa-chain-automation-plan.md` §3-T1）：链骨架白名单转发
  #   （实现落 `gk_moa_aggregate.chain`，此处只编排，**禁第二实现**；**挂既有命令 ⇒ 零新增 _CMD_REG**）。
  local chain_flag=false
  # T2（2026-10-14，C 计划 §3-T2）：P/L/M 分组独立出口（挂既有 moa-aggregate，零新增 _CMD_REG）。
  local group_flag=false
  # T4（2026-10-14，C 计划 §3-T4）：链尾 HTML 自动导出 opt-out。
  local no_html_flag=false
  # T15（2026-10-29，user 裁定「链头入参」）：`--from-plan` / `--arms-per-group` 白名单转发 ——
  #   链头 = plan-lint(PW-SN) 机检门 → 派臂（委托 plan-refinement --run）→ 聚合 → HTML；
  #   实现落 `gk_moa_aggregate.chain_head` / `chain`，此处只编排，**禁第二实现**。
  local from_plan="" arms_per_group=""
  # T5（2026-10-15，C 计划 §3-T5）：链尾散文接收（`-`=stdin）→ 自动 from-prose 并入台账。
  local prose_file=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --state) state_file="${2:-}"; shift 2 2>/dev/null || shift ;;
      --recent) recent="${2:-}"; shift 2 2>/dev/null || shift ;;
      --role) role="${2:-}"; shift 2 2>/dev/null || shift ;;
      --task) task="${2:-}"; shift 2 2>/dev/null || shift ;;
      # §18（2026-10-02）：`--plan <计划路径子串>` 白名单转发 —— 实现落 `gk_moa_aggregate`
      #   （`mode=plan_bound`，6 臂 3 组按计划锚聚齐）；此处只是参数编排，**禁第二实现**。
      --plan) plan="${2:-}"; shift 2 2>/dev/null || shift ;;
      # §18.1（2026-10-03）：批锚 / 跨批放开 —— 白名单转发，实现落 `gk_moa_aggregate`。
      --batch) batch="${2:-}"; shift 2 2>/dev/null || shift ;;
      --allow-cross-batch) cross_batch=true; shift ;;
      --allow-cross-task) cross_task=true; shift ;;
      # 2026-09-28（用户裁定「加新鲜度判断避免聚合到过时产物」）：`--fresh <秒>` 由本白名单
      #   转发 —— 实现落 `gk_moa_aggregate`（产物 mtime 判据）；此处只是参数编排，**禁第二实现**。
      --fresh) fresh="${2:-}"; shift 2 2>/dev/null || shift ;;
      --md) md_flag=true; shift ;;
      --accept) accept_flag=true; shift ;;
      --full-regression) full_regression=true; shift ;;
      --accept-files) accept_files="${2:-}"; shift 2 2>/dev/null || shift ;;
      --accept-timeout) accept_timeout="${2:-}"; shift 2 2>/dev/null || shift ;;
      --worktrees) worktrees="${2:-}"; shift 2 2>/dev/null || shift ;;
      --html) html_out="${2:-}"; html_given=true; shift 2 2>/dev/null || shift ;;
      # `--out`（2026-09-24 补白名单）：python 侧**早已支持**落档，CLI 却未转发 ⟹
      # `--html` 模式下 stdout 只出 envelope（单一 JSON），聚合正文就只有靠它才能留档
      # （原提示指向一个调用方给不了的 flag = 死路提示）。
      --out) out_file="${2:-}"; shift 2 2>/dev/null || shift ;;
      # 2026-09-24（用户裁定「HTML 需要自动打开」）：`--no-open` 由本白名单转发 ——
      #   默认行为 = 写盘后自动在宿主浏览器打开（实现落 `gk_moa_aggregate._should_open` /
      #   `_open_in_browser`）；pytest 运行中天然惰性，故测试面无需改动。禁第二实现。
      --no-open) no_open_flag=true; shift ;;
      # D（2026-10-09）：`--serve`/`--port` 白名单转发（须与 `--html` 同用）。
      --serve) serve_flag=true; shift ;;
      --port) port="${2:-}"; shift 2 2>/dev/null || shift ;;
      --emit-finding) emit_finding=true; shift ;;
      # 2026-10-14（ECC-50A0C5A3F2A8，用户令「不能抑制」）：`--no-emit-finding` 由 opt-out **升级为保护锁**
      #   —— 本处仍转发，但 python 侧（`gk_moa_aggregate`）对其实施 fail-loud（rc=2），**不再能掐掉**自动 finding。
      --no-emit-finding) no_emit_finding=true; shift ;;
      --convergence) convergence=true; shift ;;
      --mu) mu="${2:-}"; shift 2 2>/dev/null || shift ;;
      # 2026-11-02：`--expect N` 白名单转发（实际 references 数不符 ⟹ rc=1）。
      --expect) expect_n="${2:-}"; shift 2 2>/dev/null || shift ;;
      --auto-remediate) auto_remediate=true; shift ;;
      # §5（2026-10-11，ECC-143409BC4A8C）：`--covert-scan` 白名单转发（无值 flag）。
      --covert-scan) covert_scan=true; shift ;;
      # A8-①（2026-10-11，ECC-8B2C819EDE7D）：`--strict-independence` 白名单转发（无值 flag）。
      --strict-independence) strict_independence=true; shift ;;
      --chain) chain_flag=true; shift ;;
      # T15（2026-10-29）：链头入参（从计划文本起跑；须与 --chain 同用）。
      --from-plan) from_plan="${2:-}"; shift 2 2>/dev/null || shift ;;
      --arms-per-group) arms_per_group="${2:-}"; shift 2 2>/dev/null || shift ;;
      # T2（2026-10-14，C 计划 §3-T2）：P/L/M 分组独立出口。
      --group) group_flag=true; shift ;;
      # T4（2026-10-14，C 计划 §3-T4）：链尾 HTML 自动导出 opt-out（与 --chain 同用）。
      --no-html) no_html_flag=true; shift ;;
      # T5（2026-10-15，C 计划 §3-T5）：链尾散文接收（`-`=stdin）→ 自动 from-prose 并入台账。
      --prose) prose_file="${2:-}"; shift 2 2>/dev/null || shift ;;
      *)
        echo "{\"ok\":false,\"error\":\"unknown arg: $1\",\"exit_code\":2,\"usage\":\"moa-aggregate [--state FILE] [--recent N] [--role ROLE] [--task T] [--plan P] [--batch ID] [--allow-cross-task] [--allow-cross-batch] [--fresh N] [--md] [--out FILE] [--accept] [--worktrees a,b,...] [--full-regression] [--accept-files F,..] [--html OUT.html] [--no-open] [--serve] [--port N] [--emit-finding] [--convergence] [--mu N,N,...] [--expect N] [--auto-remediate] [--covert-scan] [--strict-independence] [--chain] [--from-plan PLAN] [--arms-per-group K] [--group] [--no-html] [--prose FILE]\",\"next\":\"bash gatekeeper-cli.sh help moa-aggregate\"}"
        return 2 ;;
    esac
  done
  # 缺值/吃参 fail-loud：`--html` 落尾或后跟另一 flag 时 `$2` 会拿到空串或下一个 flag
  #   （后者更坏 —— 该 flag 被静默吞掉）⟹ 显式拒绝，禁静默走错分支（同本仓 fail-loud 纪律）。
  if $html_given; then
    case "$html_out" in
      ""|-*) echo "{\"ok\":false,\"error\":\"--html 需要一个非空输出路径（且不得以 - 开头）\",\"exit_code\":2}"
             return 2 ;;
    esac
  fi
  local args=()
  [ -n "$state_file" ] && args+=(--state "$state_file")
  [ -n "$recent" ] && [ "$recent" != "0" ] && args+=(--recent "$recent")
  [ -n "$role" ] && args+=(--role "$role")
  [ -n "$task" ] && args+=(--task "$task")
  [ -n "$plan" ] && args+=(--plan "$plan")
  [ -n "$batch" ] && args+=(--batch "$batch")
  $cross_batch && args+=(--allow-cross-batch)
  $cross_task && args+=(--allow-cross-task)
  [ -n "$fresh" ] && [ "$fresh" != "0" ] && args+=(--fresh "$fresh")
  $md_flag && args+=(--md)
  $accept_flag && args+=(--accept)
  [ -n "$worktrees" ] && args+=(--worktrees "$worktrees")
  $full_regression && args+=(--full-regression)
  [ -n "$accept_files" ] && args+=(--accept-files "$accept_files")
  [ -n "$accept_timeout" ] && args+=(--accept-timeout "$accept_timeout")
  [ -n "$out_file" ] && args+=(--out "$out_file")
  $html_given && args+=(--html "$html_out")
  $no_open_flag && args+=(--no-open)
  $serve_flag && args+=(--serve)
  [ -n "$port" ] && args+=(--port "$port")
  $emit_finding && args+=(--emit-finding)
  $no_emit_finding && args+=(--no-emit-finding)
  $convergence && args+=(--convergence)
  [ -n "$mu" ] && args+=(--mu "$mu")
  [ -n "$expect_n" ] && [ "$expect_n" != "0" ] && args+=(--expect "$expect_n")
  $auto_remediate && args+=(--auto-remediate)
  # §5（2026-10-11，ECC-143409BC4A8C）：covert warden 三轴扫描并入聚合封套。
  $covert_scan && args+=(--covert-scan)
  # A8-①（2026-10-11，ECC-8B2C819EDE7D）：opt-in 独立度硬门转发。
  $strict_independence && args+=(--strict-independence)
  $chain_flag && args+=(--chain)
  # T15（2026-10-29）：链头入参白名单转发（实现落 gk_moa_aggregate，禁第二实现）。
  [ -n "$from_plan" ] && args+=(--from-plan "$from_plan")
  [ -n "$arms_per_group" ] && args+=(--arms-per-group "$arms_per_group")
  $group_flag && args+=(--group)
  $no_html_flag && args+=(--no-html)
  # T5（2026-10-15，C 计划 §3-T5）：链尾散文（`-`=stdin）白名单转发（挂既有命令，零新增 _CMD_REG）。
  [ -n "$prose_file" ] && args+=(--prose "$prose_file")
  # S9（2026-10-06）：图表后端改 **ECharts**（vendor `assets/echarts.min.js`，渲染端只读静态文件）
  #   ⟹ 与解释器无关（原「探测装 plotly 的解释器」的 env 覆盖口已随之删除）。
  local _py="python3"
  "$_py" "${SKILL_DIR}/scripts/gk_moa_aggregate.py" "${args[@]}"
}

# ---------- docgen (auto-generate command reference) ----------
# Refs: Self-referential — generates cli-protocol.md from code annotations.
# Usage: docgen [--check]  (--check = exit 1 if output differs from current file)
cmd_docgen() {
  local check_mode=false
  [ "${1:-}" = "--check" ] && check_mode=true

  local gen_script="$SKILL_DIR/.docgen.py"
  cat > "$gen_script" << 'PYEOF'
import re, os, sys
from datetime import datetime

script_path = os.environ.get('SKILL_DIR', '') + '/gatekeeper-cli.sh'
if not os.path.exists(script_path):
    print('{"error":"gatekeeper-cli.sh not found"}')
    sys.exit(1)

with open(script_path) as f:
    lines = f.readlines()

# 2026-09-20 修复（实测，非推测）：命令的**调用键**是 _CMD_REG 的注册键（含连字符），
# 不是函数名去 cmd_ 前缀（`cmd_paper_review` 的键是 `paper-review`）。原实现按函数名
# 派生 ⟹ 21/48 命令的 Usage 公式被印成**不可达**形态（`paper_review`）。
alias_by_func = {}
for _line in lines:
    _m = re.match(r'_CMD_REG\[([^\]]+)\]="([^|]+)\|', _line)
    if _m:
        alias_by_func[_m.group(2)] = _m.group(1)

commands = []
for i, line in enumerate(lines):
    m = re.match(r'^(cmd_\w+)\(\)', line)
    if not m:
        m2 = re.match(r'^(pre_tool_check)\(\)', line)
        if m2:
            func_name = m2.group(1)
        else:
            continue
    else:
        func_name = m.group(1)

    header = []
    j = i - 1
    # 2026-09-20 修复：原条件 `while j >= 0 and lines[j].strip() in ('', '') or lines[j].startswith('#')`
    # 因 and/or 优先级 = `(j >= 0 and blank) or startswith('#')` ⟹ j 到 -1 后 lines[-1]
    # **负索引回绕**到文件尾，把尾部注释吃成本命令的表头（尾部含 `Refs:` 即被当引用，已实测复现）。
    while j >= 0 and (lines[j].strip() == '' or lines[j].startswith('#')):
        if lines[j].startswith('#'):
            header.append(lines[j])
        j -= 1
    header.reverse()

    refs = []
    purpose = ''
    banner = ''
    plain = ''
    # 2026-09-20 修复（实测）：原实现取「def 前**最后一条** `#` 行」作 Purpose
    # ⟹ `# Usage:` 注记行被当 Purpose（实测 6 条），真实用途被覆盖。改判据：
    #   banner 描述（`# ---- xxx ----`）优先；否则第一条普通注释行；
    #   `# Usage:` / `# Refs:` 注记行**不参与** Purpose。
    for h in header:
        s = h.rstrip('\n')
        if 'Refs:' in s:
            refs.append(s.split('Refs:', 1)[1].strip())
            continue
        if s.startswith('# Usage:'):
            continue
        m3 = re.match(r'^#\s*-{5,}\s*(.+?)\s*-{5,}\s*$', s)
        if m3:
            if not banner:
                banner = m3.group(1)
            continue
        if s.startswith('# ') and not plain:
            plain = s[2:].strip()
    purpose = banner or plain

    sig = ''
    k = i + 1
    while k < len(lines) and not lines[k].strip().startswith('local '):
        k += 1
    if k < len(lines):
        sig = lines[k].strip().replace('local ', '').rstrip(';')

    commands.append((func_name, purpose, sig, refs))

lines_out = []
lines_out.append('# CLI Protocol — Gatekeeper Command Reference & PRM Monitor')
lines_out.append('')
lines_out.append('**Auto-generated by docgen**. Source of truth: code annotations.')
lines_out.append('**Refs**: prm-monitor-methodology.md, SKILL.md (routing)')
lines_out.append('')
lines_out.append('> 文档是 CLI 的输出, 不是输入 — CLI 是 Agent ↔ 文件系统的确定性裁判。')
lines_out.append('')
# 2026-09-04 确定性修复：原 `**Generated**: {datetime.now()}` 每次漂移 → docgen --check
# 逐字节比对恒 fail。改静态标记（可复现输出；生成时间不入档）。
lines_out.append('**Generated**: docgen deterministic output (2026-09-04)')
lines_out.append(f'**Commands**: {len(commands)}')
lines_out.append('')
lines_out.append('| # | Command | Purpose | Signature | Refs |')
lines_out.append('|---|---------|---------|-----------|------|')

for idx, (name, purp, sig, refs) in enumerate(sorted(commands), 1):
    p = (purp[:60] if purp else name.replace('cmd_','').replace('_',' '))
    s = sig[:40] if sig else '-'
    r = '; '.join(refs)[:80] if refs else '-'
    lines_out.append(f'| {idx} | `{name}` | {p} | `{s}` | {r} |')

lines_out.append('')
lines_out.append('## Detail')
for name, purp, sig, refs in sorted(commands):
    # 2026-09-20 修复：alias 取 _CMD_REG 注册键（原按函数名派生 ⟹ 21/48 不可达）
    alias = alias_by_func.get(name, name.replace('cmd_', ''))
    lines_out.append(f'\n### {name}')
    if sig:
        lines_out.append(f'**Usage**: `gatekeeper-cli.sh {alias} <args>`')
    if purp:
        lines_out.append(f'**Purpose**: {purp}')
    if refs:
        lines_out.append('**Refs**:')
        for r in refs:
            lines_out.append(f'- {r}')

output = '\n'.join(lines_out)

check = os.environ.get('DOCGEN_CHECK', 'false')
if check == 'true':
    ref_path = os.environ.get('SKILL_DIR', '') + '/references/cli-protocol.md'
    if os.path.exists(ref_path):
        with open(ref_path) as f:
            existing = f.read()
        if output.strip() == existing.strip():
            sys.exit(0)
        else:
            print('DOC_DRIFT: cli-protocol.md out of sync')
            sys.exit(1)
    else:
        print('WARN: cli-protocol.md not found')
        sys.exit(0)
else:
    print(output)
PYEOF

  local output
  output=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" DOCGEN_CHECK="$([ "$check_mode" = true ] && echo 'true' || echo 'false')" python3 "$gen_script" 2>&1)
  local rc=$?
  rm -f "$gen_script"
  [ $rc -ne 0 ] && [ "$check_mode" = false ] && { echo "$output"; return 1; }
  [ $rc -ne 0 ] && [ "$check_mode" = true ] && { echo "$output"; return 1; }

  if ! $check_mode; then
    local ref_path="$SKILL_DIR/references/cli-protocol.md"
    echo "$output" > "$ref_path"
    local lc; lc=$(echo "$output" | wc -l)
    echo "{\"ok\":true,\"file\":\"${ref_path}\",\"size\":${lc}}"
  fi
}

# ---------- reflect (T41) ----------
# Refs: SkillOpt arXiv:2605.23904 §3.5 (rejected edits as negative feedback)
#       SkillOpt §3.6 (Epoch-Wise Slow/Meta Update = longitudinal improvement)
#       prm-monitor-methodology.md §8.4 (rejected_edits closed loop)
# Diff: SkillOpt reflect uses LLM optimizer model (chat_optimizer);
#       Gatekeeper reflects via structured JSON output for agent consumption
# Status: Dynamic reflection via DeepSeek v4-flash API (T41)
cmd_reflect() {
  local stage="${1:-}"
  [ -z "$stage" ] && { echo '{"error":"reflect <stage> required"}'; return 1; }
  [ ! -f "$STATE_FILE" ] && { echo '{"error":"No state file"}'; return 1; }

  local rejected; rejected=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --tail gate_data.rejected_edits 5 --indent 2 2>/dev/null || echo '[]')

  local best; best=$(python3 "$SKILL_DIR/scripts/gk_state.py" get gate_data.best --path "$STATE_FILE" --json --indent 2 --default '{}' 2>/dev/null || echo '{}')

  local human_cal; human_cal=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --tail gate_data.human_calibration_log 5 --indent 2 2>/dev/null || echo '[]')

  # Read cross-R history for longitudinal analysis
  local cross_r_context
  cross_r_context=$(python3 "$SKILL_DIR/scripts/gk_views.py" cross-r-context "$STATE_FILE" 2>/dev/null || echo "")

  local api_key="${API_KEY}"
  [ -z "$api_key" ] && { _resolve_api_key; api_key="$API_KEY"; }

  if [ -z "$api_key" ]; then
    echo "{\"rejected_edits\":$rejected,\"best\":$best,\"human_calibration\":$human_cal,\"guidance\":\"Analyze rejected edits against best snapshot. Focus on patterns: which violations repeat? Which stage has most rejections?\",\"mode\":\"static\"}"
    return 0
  fi

  _resolve_provider_config

  local system_prompt="You are a code review optimizer for the SPZ Gatekeeper R-sequence pipeline. Analyze rejected edits, best snapshot, and human calibration log to provide actionable improvement guidance. Output ONLY JSON: {\"pattern_analysis\":\"...\",\"stage_ranking\":\"...\",\"recommendations\":[\"...\"],\"summary\":\"...\"}"

  local user_prompt="STAGE: $stage\n\nREJECTED EDITS (last 5): $rejected\n\nBEST SNAPSHOT: $best${cross_r_context:+\n\n$cross_r_context}\n\nHUMAN CALIBRATION (last 5): $human_cal\nProvide:\n1. Pattern analysis — which violations repeat across rejected edits?\n2. Stage ranking — which stage has most rejections?\n3. Specific improvement recommendations for next attempts\n\nOutput only JSON."

  local req_body
  if [ "$PROVIDER" = "mimo" ]; then
    SYSTEM_PROMPT="$system_prompt" USER_PROMPT="$user_prompt" req_body=$(python3 "$SKILL_DIR/scripts/gk_req_body.py" "$API_MODEL" 2>/dev/null)
  else
    SYSTEM_PROMPT="$system_prompt" USER_PROMPT="$user_prompt" req_body=$(python3 "$SKILL_DIR/scripts/gk_req_body.py" "$API_MODEL" "$DS_REASONING_EFFORT" 2>/dev/null)
  fi

  local resp; resp=$(curl -s --max-time 120 -X POST "${API_BASE}/chat/completions" \
    -H "Authorization: Bearer ${api_key}" \
    -H "Content-Type: application/json" \
    -d "$req_body" 2>/dev/null)

  local guidance; guidance=$(printf '%s' "$resp" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field choices.0.message.content --default '' --default-invalid '' --default-falsy '' 2>/dev/null || echo '')

  if [ -z "$guidance" ]; then
    echo "{\"rejected_edits\":$rejected,\"best\":$best,\"human_calibration\":$human_cal,\"guidance\":\"Analyze rejected edits against best snapshot. Focus on patterns: which violations repeat? Which stage has most rejections?\",\"mode\":\"static\",\"fallback_reason\":\"API call failed\"}"
    return 0
  fi

  # Persist analysis to gate_data.rejected_patterns + clear needs_analysis
  # 2026-08-15: guidance 来自 LLM（不可信）——原 json.loads('''$guidance''') 三引号注入；
  # 改 env 传递 + try/except 保留原文（同 audit --crossr/--report 修复模式）。
  REFLECT_GUIDANCE="$guidance" python3 "$SKILL_DIR/scripts/gk_state_ops.py" reflect-persist "$STATE_FILE" "$stage" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>/dev/null || true

  echo "{\"rejected_edits\":$rejected,\"best\":$best,\"guidance\":$(echo "$guidance" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape 2>/dev/null),\"mode\":\"dynamic\",\"provider\":\"${PROVIDER}\",\"model\":\"${API_MODEL}\"}"
}

# ---------- cmd_check-changes (文档变更触发器: 统计未提交/未推送改动) ----------
# 用法: gatekeeper-cli.sh check-changes [--threshold <N>] [--repo <path>] [--type doc|code|all]
# 输出 JSON: {doc_changes, code_changes, unpushed_commits, push_needed, entropy_rate, ...}
# 被以下模块调用:
#   - advance hint gates (文档预算监视器)
#   - entropy monitor (熵率高于阈值 + 文档堆积 → 推文档释放压力)
#   - cmd_push status (与 previous_push_failures 并列)
cmd_check_changes() {
  local threshold=2 repo="" type="all"
  while [ $# -gt 0 ]; do
    case "$1" in
      --threshold) threshold="${2:-}"; shift 2 2>/dev/null || shift ;;
      --repo) repo="${2:-}"; shift 2 2>/dev/null || shift ;;
      --type) type="${2:-}"; shift 2 2>/dev/null || shift ;;
      *) break ;;
    esac
  done
  [ -z "$repo" ] && repo="${MAIN_REPO_WSL:-.}"
  cd "$repo" 2>/dev/null || { echo '{"ok":false,"error":"Cannot access repo: '"$repo"'"}'; return 1; }

  # 1. Uncommitted changes (git diff --name-only HEAD)
  local all_uncommitted; all_uncommitted=$(git diff --name-only HEAD 2>/dev/null || echo "")
  local doc_count=0 code_count=0
  local doc_list="" code_list=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    # Doc patterns: docs/ references/ *.md AGENTS.md CLAUDE.md SKILL.md
    # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
    if echo "$f" | "$RG" -qi '^(docs/|references/|.*\.md$|AGENTS\.md|CLAUDE\.md|SKILL\.md)'; then
      doc_count=$((doc_count + 1))
      doc_list="${doc_list}\"${f}\","
    else
      code_count=$((code_count + 1))
      code_list="${code_list}\"${f}\","
    fi
  done <<< "$all_uncommitted"
  # Trim trailing commas
  doc_list="${doc_list%,}"; code_list="${code_list%,}"

  # 2. Unpushed commits (git log origin/main..HEAD)
  local unpushed=0 unpushed_log=""
  unpushed=$(git rev-list --count origin/main..HEAD 2>/dev/null || echo "0")
  local unpushed_commits=0
  [ "$unpushed" -ge 0 ] 2>/dev/null && unpushed_commits=$unpushed
  if [ "$unpushed_commits" -gt 0 ]; then
    unpushed_log=$(git log --oneline origin/main..HEAD 2>/dev/null | head -5)
  fi

  # 3. Entropy rate from state (read-only, non-fatal if missing)
  local entropy="null"
  [ -f "${STATE_FILE:-}" ] && entropy=$(python3 "$SKILL_DIR/scripts/gk_state.py" get gate_data.entropy_rate --path "$STATE_FILE" --default null 2>/dev/null || echo "null")

  # 4. Push failures from state
  local push_fail_count=0
  [ -f "${STATE_FILE:-}" ] && push_fail_count=$(GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" python3 -c "
import json,os
try:
    d=json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'))
    pf=d.get('gate_data',{}).get('push_failures',[])
    print(len(pf))
except: print(0)
" 2>/dev/null || echo "0")

  # 5. Determine push_needed
  local push_needed=false
  local trigger_doc=false trigger_commit=false
  [ "$doc_count" -ge "$threshold" ] && trigger_doc=true
  [ "$unpushed_commits" -gt 0 ] && trigger_commit=true
  [ "$type" = "all" ] && { $trigger_doc || $trigger_commit; } && push_needed=true
  [ "$type" = "doc" ] && $trigger_doc && push_needed=true
  [ "$type" = "code" ] && $trigger_commit && push_needed=true

  # 6. Output JSON
  cat <<ENDJSON
{"ok":true,"doc_changes":$doc_count,"code_changes":$code_count,"total_uncommitted":$((doc_count + code_count)),"unpushed_commits":$unpushed_commits,"doc_changes":[$doc_list],"code_changes":[$code_list],"unpushed_log":$(echo "$unpushed_log" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --limit 500 2>/dev/null || echo '""'),"doc_threshold":$threshold,"push_needed":$push_needed,"entropy_rate":$entropy,"push_failures_count":$push_fail_count}
ENDJSON
}

# ---------- cmd_push (git push 封装: 3 阶段强制门禁) ----------
# 阶段 1: status → 返回远程状态 JSON, 不执行任何操作
# 阶段 2: confirm → 校验 token + 执行推送 (必须先执行 status)
# 用法: gatekeeper-cli.sh push status  [--repo <path>] [--remote <name>] [--branch <name>]
#       gatekeeper-cli.sh push confirm [--repo <path>] [--remote <name>] [--branch <name>] [--timeout <s>] [--push-user <user>] [<token>]
#       --push-user / env GK_PUSH_USER：Gitee/atomgit 系需 user:token 形态（缺省 token-only，兼容 GitHub）

# ─── F8.1: 远端验证门禁 ───
# [write_guard 裁决 2026-09-06 EXEMPT] 纯读函数（remote get-url + 白名单匹配，零写入）——bomb 扫描器误归属
# （把兄弟 cmd_push 的 _state_write 记到本函数名下）；无需守卫。
# 白名单的 JSON 视图（错误回包用；空表 ⟹ `[]`，不写死字面量副本）
_remote_allow_json() {
  local out="" p
  for p in "${_ALLOWED_REMOTE_PATTERNS[@]}"; do
    p="${p//\"/}"
    out+="\"${p}\","
  done
  printf '[%s]' "${out%,}"
}

_verify_remote() {
  local repo="${1:-.}"
  local remote="${2:-origin}"
  local url; url=$(cd "$repo" 2>/dev/null && git remote get-url "$remote" 2>/dev/null || echo "")
  [ -z "$url" ] && { echo '{"ok":false,"error":"remote_verify_failed","detail":"Cannot get URL for remote '"$remote"'"'; return 1; }
  # 2026-11-01：匹配改**内建 glob**（原 `"$RG" -qi` 在 rg 缺位时恒假 ⟹ 安全门 fail-open）。
  local _url_lc _p_lc pattern
  _url_lc=$(printf '%s' "$url" | tr '[:upper:]' '[:lower:]')
  for pattern in "${_ALLOWED_REMOTE_PATTERNS[@]}"; do
    _p_lc=$(printf '%s' "$pattern" | tr '[:upper:]' '[:lower:]')
    case "$_url_lc" in
      *"$_p_lc"*)
        echo "{\"ok\":true,\"remote\":\"$remote\",\"url\":\"$url\",\"matched\":\"$pattern\"}"
        return 0 ;;
    esac
  done
  echo '{"ok":false,"error":"remote_not_allowed","remote":"'"$remote"'","url":"'"$url"'","allowed_patterns":'"$(_remote_allow_json)"',"hint":"Set git remote to an allowed host/prefix, or widen the gate with GK_PUSH_REMOTE_ALLOW=<host/prefix>[,...]"}'
  return 1
}

# [write_guard 裁决 2026-09-06 EXEMPT] _state_write 仅于真实 push 三次失败后（L5085 落 push_failures 供
# 确定性重试门禁）；status 只读动作不可达写入；push 无 --check 变体。
# ─── 直推 main 的显式授权判据（2026-11-03 集成修复）────────────────────────────
# 病象：原实现对**任意**被委托仓的 main/master 一律拒绝，且文案硬写 “This repo uses PR
#   workflow” —— 把本门禁仓的策略套到旁路仓（实测 git-workflow 仓历史全是直推 main，被误伤）。
# 现判据三选一（均**显式**、可审计）：
#   ① `push auth-main` 写的一次性授权文件（原语义，保留）；
#   ② 本次调用带 `--allow-main`（调用方显式透传，不写盘）；
#   ③ env `GK_PUSH_ALLOW_MAIN`（逗号/冒号分隔）命中目标仓**绝对路径前缀**或**仓目录名**。
_push_allow_main_match() {
  local _ra="$1" _pat
  [ -n "${GK_PUSH_ALLOW_MAIN:-}" ] || return 1
  while IFS= read -r _pat; do
    [ -n "$_pat" ] || continue
    case "$_ra" in
      "$_pat"|"$_pat"/*) return 0 ;;
    esac
    [ "$(basename "$_ra")" = "$_pat" ] && return 0
  done < <(printf '%s\n' "${GK_PUSH_ALLOW_MAIN}" | tr ',:' '\n')
  return 1
}

cmd_push() {
  local action="" repo="" remote="origin" branch="" timeout=10 push_url="" token="" push_user="${GK_PUSH_USER:-}" allow_main=0
  # 2026-10-10（finding ECC-6056478D1353 · 摩擦①）：action 只认**非 flag** 首参 —— 原式
  #   `action="$1"` 会把 `push --repo X` 的 `--repo` 当 action 吃掉 ⟹ repo 回落 MAIN_REPO_WSL、
  #   其余 flag 全丢（实测）。改后 `push --repo X` = 省略 action（走 status 分支）。
  if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then action="$1"; shift; fi

  while [ $# -gt 0 ]; do
    case "$1" in
      --repo) repo="${2:-}"; shift 2 2>/dev/null || shift ;;
      --remote) remote="${2:-}"; shift 2 2>/dev/null || shift ;;
      --branch) branch="${2:-}"; shift 2 2>/dev/null || shift ;;
      --timeout) timeout="${2:-}"; shift 2 2>/dev/null || shift ;;
      --push-url) push_url="${2:-}"; shift 2 2>/dev/null || shift ;;
      --push-user) push_user="${2:-}"; shift 2 2>/dev/null || shift ;;
      --allow-main) allow_main=1; shift ;;
      *) break ;;
    esac
  done

  [ -z "$repo" ] && repo="${MAIN_REPO_WSL:-.}"
  [ -z "$branch" ] && branch=$(cd "$repo" 2>/dev/null && git branch --show-current 2>/dev/null || echo "main")
  [ -z "$push_url" ] && push_url=$(cd "$repo" 2>/dev/null && git remote get-url "$remote" 2>/dev/null)

  cd "$repo" 2>/dev/null || { echo '{"ok":false,"error":"Cannot access repo: '"$repo"'"}'; return 1; }

  # ─── Phase -1: auth-main → 临时授权直接推送 main (非必要不得使用) ───
  if [ "$action" = "auth-main" ]; then
    local auth_file="${STATE_FILE%/*}/.push-main-auth.json"
    local expires; expires=$(date -d '+10 minutes' +%s 2>/dev/null || python3 -c "import time;print(int(time.time())+600)" 2>/dev/null)
    echo "{\"expires\":$expires,\"reason\":\"manual_override\",\"created\":\"$(date -Iseconds 2>/dev/null)\"}" > "$auth_file"
    echo "{\"ok\":true,\"phase\":\"auth-main\",\"expires_at\":$expires,\"ttl_minutes\":10,\"warning\":\"Direct push to main authorized for 10 minutes. Use only when PR workflow is unavailable.\"}"
    return 0
  fi

  # ─── Phase 0: 强制 status check ───
  if [ "$action" != "confirm" ]; then
    # F8.1: 远端白名单验证
    local vr; vr=$(_verify_remote "$repo" "$remote" 2>/dev/null)
    if ! echo "$vr" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test ok 2>/dev/null; then
      echo "$vr"
      return 1
    fi
    # 获取本地/远端状态 (不推送)
    local local_sha=$(git rev-parse --short "$branch" 2>/dev/null || echo "")
    local behind=0 ahead=0 has_remote=true remote_default="" remote_commits=""
    local remote_head_sha="" has_token=true token_source=""

    # Remote state (timeout 5: WSL network may hang)
    if timeout 5 git ls-remote --exit-code "$remote" "$branch" &>/dev/null; then
      remote_head_sha=$(timeout 5 git ls-remote "$remote" "$branch" 2>/dev/null | cut -f1 | cut -c1-7)
      behind=$(git rev-list --count "${local_sha}..${remote_head_sha}" 2>/dev/null || echo 0)
      ahead=$(git rev-list --count "${remote_head_sha}..${local_sha}" 2>/dev/null || echo 0)
      remote_default=$(git symbolic-ref refs/remotes/"$remote"/HEAD 2>/dev/null | sed "s|refs/remotes/$remote/||" || echo "")
    else
      has_remote=false
    fi

    # Local commits to be pushed (if any)
    local commit_log=""
    if [ "$ahead" -gt 0 ]; then
      commit_log=$(git log --oneline "${remote_head_sha}..${local_sha}" 2>/dev/null | head -5)
    fi

    # Token availability (check only, no resolution)
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      token_source="GITHUB_TOKEN"
    elif gh auth token &>/dev/null; then
      token_source="gh_auth"
    else
      has_token=false
      token_source="none"
    fi

    # F-15: Previous push failures from state
    local _status_push_failures=""
    if [ -f "${STATE_FILE:-}" ]; then
      _status_push_failures=$(GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" python3 -c "
import json,sys,os
s=json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'))
pf=s.get('gate_data',{}).get('push_failures',[])
if pf:
    print(json.dumps({'count':len(pf),'last_error':pf[-1].get('error',''),'last_attempt':pf[-1].get('timestamp','')}))
else:
    print('')
" 2>/dev/null || echo "")
    fi
    [ -n "$_status_push_failures" ] && _status_push_failures=",\"previous_push_failures\":$_status_push_failures"

    # F-15: check-changes snapshot (doc/code granularity for status)
    local _status_cc=""
    local _status_cc_out; _status_cc_out=$(bash "$0" check-changes --type all --threshold 2 --repo "$repo" 2>/dev/null || echo '{"ok":false}')
    if echo "$_status_cc_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test ok 2>/dev/null; then
      _status_cc=",\"check_changes\":$(echo "$_status_cc_out" | python3 "$SKILL_DIR/scripts/gk_views.py" push-check-summary 2>/dev/null || echo '{}')"
    fi

    # Status JSON
    cat <<ENDJSON
{"ok":true,"phase":"status","repo":"$(pwd)","remote":"$remote","branch":"$branch","local_sha":"$local_sha","remote_head":"$remote_head_sha","ahead":$ahead,"behind":$behind,"has_remote":$has_remote,"has_token":$has_token,"token_source":"$token_source","commits_pending":$([ "$ahead" -gt 0 ] && echo "true" || echo "false"),"commit_log":$(echo "$commit_log" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --limit 1000 2>/dev/null || echo '""'),"needs_confirmation":true$_status_push_failures$_status_cc,"next_action":"Run: gatekeeper-cli.sh push confirm --repo $repo --remote $remote --branch $branch"}
ENDJSON
    return 0
  fi

  # ─── Phase 1: confirm → 校验 token + 推送 ───
  # Stage gate：**只对本门禁仓生效**（2026-11-03 集成修复）。
  #   原实现对任意 `--repo` 都要求活跃 R-phase ⟹ 旁路仓（如 git-workflow）在门禁 IDLE 时
  #   永远推不上去，且报错与「推送」无关，属策略越界。判定用 `MAIN_REPO_WSL`（启动期解析）；
  #   解析不到时 **fail-closed**（按本仓处理 ⟹ 保留 stage 闸）。
  local _is_own_repo=0
  if [ -n "${MAIN_REPO_WSL:-}" ] && [ -d "${MAIN_REPO_WSL:-}" ] \
     && [ "$(cd "$repo" 2>/dev/null && pwd -P)" = "$(cd "$MAIN_REPO_WSL" 2>/dev/null && pwd -P)" ]; then
    _is_own_repo=1
  fi
  # stage 值**照常读取**（下游 L4 交叉审查提示要用），但**只有本门禁仓**用它做闸
  local _cur_stage
  _cur_stage=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get stage --default IDLE 2>/dev/null)
  if [ "$_is_own_repo" = "1" ]; then
    if [ "$_cur_stage" = "IDLE" ] || [ "$_cur_stage" = "DONE" ]; then
      _log_block "push" "confirm rejected: stage=$_cur_stage"
      echo "{\"ok\":false,\"phase\":\"confirm\",\"error\":\"Push requires active R-phase (current stage: $_cur_stage). Start with spz-gatekeeper-r-sequence skill first.\"}"
      return 1
    fi
  fi

  # Main branch guard：直推 main/master 需**显式**授权（三选一，见 `_push_allow_main_match` 头注）。
  #   2026-11-03：原实现无条件拒绝 + 硬写 “This repo uses PR workflow” ⟹ 对旁路仓误伤且归因错误。
  if [ "$branch" = "main" ] || [ "$branch" = "master" ]; then
    local auth_file="${STATE_FILE%/*}/.push-main-auth.json" auth_valid=false
    if [ -f "$auth_file" ]; then
      local now; now=$(date +%s 2>/dev/null || python3 -c "import time;print(int(time.time()))" 2>/dev/null || echo "0")
      local expires; expires=$(python3 "$SKILL_DIR/scripts/gk_json_utils.py" field expires --file "$auth_file" --default 0 2>/dev/null || echo "0")
      [ "$now" -lt "$expires" ] && auth_valid=true
    fi
    local _ra; _ra="$(pwd -P)"
    if ! $auth_valid && [ "$allow_main" != "1" ] && ! _push_allow_main_match "$_ra"; then
      rm -f "$auth_file" 2>/dev/null
      echo "{\"ok\":false,\"phase\":\"confirm\",\"error\":\"Direct push to '$branch' blocked by policy\",\"repo\":\"$_ra\",\"hint\":\"Authorize one of: (a) gatekeeper-cli.sh push auth-main (10 min, one-shot); (b) pass --allow-main (explicit, per call); (c) add repo path/name to GK_PUSH_ALLOW_MAIN\"}"
      return 1
    fi
    # 一次性授权文件只在**实际被使用**时消费；--allow-main / env 放行不消耗它
    [ "$auth_valid" = true ] && rm -f "$auth_file" 2>/dev/null
  fi

  # Branch conflict guard: check if local is behind remote before pushing
  local _push_behind=0 _push_remote_sha=""
  if timeout 5 git ls-remote --exit-code "$remote" "$branch" &>/dev/null; then
    _push_remote_sha=$(timeout 5 git ls-remote "$remote" "$branch" 2>/dev/null | cut -f1 | cut -c1-7)
    _push_behind=$(git rev-list --count "HEAD..${_push_remote_sha}" 2>/dev/null || echo 0)
  fi
  if [ "$_push_behind" -gt 0 ]; then
    echo "{\"ok\":false,\"phase\":\"confirm\",\"error\":\"Push blocked: branch '$branch' is $_push_behind commit(s) behind remote. Run 'git pull --rebase origin $branch' first.\"}"
    return 1
  fi

  # Token resolution (4 sources)
  [ $# -gt 0 ] && token="$1" && shift
  [ -z "$token" ] && token="${GITHUB_TOKEN:-}"
  if [ -z "$token" ]; then
    token=$(gh auth token 2>/dev/null || true)
  fi
  if [ -z "$token" ]; then
    local gh_config="${HOME}/.config/gh/hosts.yml"
    # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
    [ -f "$gh_config" ] && token=$( "$RG" 'oauth_token:' "$gh_config" 2>/dev/null | head -1 | sed 's/.*oauth_token: *//')
  fi

  if [ -z "$token" ]; then
    echo '{"ok":false,"phase":"confirm","error":"No GitHub token available. Run: gh auth login  or  set GITHUB_TOKEN env var"}'
    return 1
  fi

  # Construct token URL（2026-09-28：改走纯函数助手 _push_auth_url.sh —— 原实现恒 token-only 形态，
  #   对 atomgit/Gitee 系报 `could not read Password`（token 被当用户名）⟹ 直推失败；需 user:token。
  #   见 scripts/_push_auth_url.sh 头注 + 红先 scripts/test_gk_push_auth_url.py）。
  if [ -f "$SKILL_DIR/scripts/_push_auth_url.sh" ]; then
    . "$SKILL_DIR/scripts/_push_auth_url.sh"
  fi
  if ! command -v _push_auth_url >/dev/null 2>&1; then
    echo '{"ok":false,"phase":"confirm","error":"push_url_helper_missing","detail":"scripts/_push_auth_url.sh 不可用"}'
    return 1
  fi
  push_url=$(_push_auth_url "$push_url" "$token" "$push_user")

  [ -z "$push_url" ] && { echo '{"ok":false,"phase":"confirm","error":"No remote URL configured"}'; return 1; }

  # ─── git-workflow 强制提醒钩子 ───
  # SKILL.md 要求: "每个 R 新 token → 强制 INVOKE git-workflow（push + PR创建均走 git-workflow）"
  # 此处不阻塞推送（CLI 无法 INVOKE skill），但输出醒目警告
  # 2026-08-30 防循环哨兵：git-workflow push 委托本 cmd_push 时置 GIT_WORKFLOW_DELEGATING=1，
  # 已处于委托链中 → 跳过提醒（防 cmd_push→提醒→git-workflow→委托→提醒 环路）。
  if [ "${GIT_WORKFLOW_DELEGATING:-0}" != "1" ]; then
    local _gw_remote_type=""
    if echo "$push_url" | "$RG" -qi '(gitcode|atomgit)\.'; then
      _gw_remote_type="skill-repo"
      echo "⚠️  WARNING [git-workflow]: Remote appears to be a skill repo (gitcode/atomgit)." >&2
      echo "    Raw push embeds token in URL — use git-workflow skill for proper token rotation." >&2
      echo "    See: SKILL.md → Push/PR → INVOKE git-workflow" >&2
    fi
    if echo "$push_url" | "$RG" -qi '(pull|pr|merge|feature/)'; then
      _gw_remote_type="pr-related"
      echo "⚠️  WARNING [git-workflow]: This push may be PR-related." >&2
      echo "    Use git-workflow skill to create/update PRs with proper token rotation." >&2
      echo "    See: SKILL.md → Push/PR → INVOKE git-workflow" >&2
    fi
    if [ -z "$_gw_remote_type" ]; then
      echo "ℹ️  NOTE [git-workflow]: Consider using git-workflow skill for this push (token rotation + PR support)." >&2
      echo "    See: SKILL.md → Push/PR → INVOKE git-workflow" >&2
    fi
    echo "" >&2
  fi

  # F-14: L4 cross-review check before push
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
  local l4_marker; l4_marker=$(git log -5 --format="%B" 2>/dev/null | "$RG" -c "L4\|cross.review\|niantic" || echo "0")
  if [ "$l4_marker" -eq 0 ] && [ "$_cur_stage" != "DONE" ]; then
    echo "⚠️  WARNING: No L4 cross-review evidence in recent commits. Consider running L1-L7 review before push." >&2
  fi

  # Execute push with retry
  local attempt=1 max_attempts=3 last_output=""
  while [ $attempt -le $max_attempts ]; do
    last_output=$(timeout "$timeout" git push "$push_url" "$branch" 2>&1) && {
      # 2026-10-10（finding ECC-6056478D1353 · 摩擦②）：`git push <url> <branch>` **不写**
      #   `refs/remotes/<remote>/<branch>` ⟹ 本地 status / branch -vv 与远端脱节（须手动补刷）。
      #   补刷单点：把远端 ref 钉到**刚推成功的本地 sha**（best-effort，不改推送语义）。
      local _pushed_sha; _pushed_sha=$(git rev-parse "$branch" 2>/dev/null || echo "")
      if [ -n "$_pushed_sha" ]; then
        git update-ref "refs/remotes/$remote/$branch" "$_pushed_sha" 2>/dev/null || true
      fi
      echo "{\"ok\":true,\"phase\":\"confirm\",\"branch\":\"$branch\",\"remote\":\"$remote\",\"attempt\":$attempt}"
      return 0
    }
    local ec=$?
    [ $ec -eq 124 ] && last_output="TIMEOUT: push exceeded ${timeout}s"
    [ $attempt -lt $max_attempts ] && sleep 5
    attempt=$((attempt + 1))
  done

  # Non-fast-forward detection → suggest PR
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
  if echo "$last_output" | "$RG" -qi "non-fast\|fetch first\|protected"; then
    local feature_branch="feature/push-$(date +%Y%m%d-%H%M%S)"
    echo "{\"ok\":false,\"phase\":\"confirm\",\"error\":\"Non-fast-forward / branch protected\",\"suggestion\":\"Create a PR: git checkout -b $feature_branch && git push origin $feature_branch && gh pr create --base $branch --head $feature_branch --fill\",\"output\":$(echo "$last_output" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --limit 500 2>/dev/null || echo '""')}"
    return 1
  fi

  # F-15: Record push failure to state for deterministic retry gate
  local _push_err_escaped; _push_err_escaped=$(echo "$last_output" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --limit 500 2>/dev/null || echo '""')
  local _push_ts; _push_ts=$(python3 -c "import datetime;print(datetime.datetime.now(datetime.timezone.utc).isoformat())" 2>/dev/null || echo "unknown")
  [ -f "${STATE_FILE:-}" ] && _state_write "d.setdefault('gate_data',{}).setdefault('push_failures',[]).append({'timestamp':'$_push_ts','error':'Push failed after ${max_attempts} attempts','output':$_push_err_escaped,'branch':'$branch','remote':'$remote'})"

  echo "{\"ok\":false,\"phase\":\"confirm\",\"error\":\"Push failed after ${max_attempts} attempts\",\"output\":$_push_err_escaped}"
  return 1
}

# ---------- ci-diagnose (轻量: 仅 list + fetch, 无 LLM) ----------
# LLM 诊断层已砍掉(token/时间/资源节省), 由 ci-diagnostician subagent 接管
# list:  1 curl + 1 python3 parse → table (~0.3s)
# fetch: 1 curl jobs + 1 python3 download → /tmp/ci_logs/ (~1-5s, 无 API 费)
# Usage: ci-diagnose list [COUNT]       — show recent CI runs
#        ci-diagnose fetch <run-id>     — fetch logs to /tmp/ci_logs/
cmd_ci_diagnose() {
  local run_id="" gh_token="${GITHUB_TOKEN:-${GH_TOKEN:-}}" subcmd=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --token) gh_token="${2:-}"; shift 2 2>/dev/null || shift ;;
      -*) echo "{\"error\":\"Unknown flag: $1\"}" >&2; return 1 ;;
      *) [ -z "$subcmd" ] && subcmd="$1"; shift ;;
    esac
  done

  [ -z "$gh_token" ] && { echo '{"error":"GitHub token required. Set GITHUB_TOKEN env var or pass --token TOKEN"}'; return 1; }

  local repo owner repo_name
  repo=$(git -C "$MAIN_REPO_WSL" remote get-url origin 2>/dev/null || echo "")
  if [ -n "$repo" ]; then
    repo=$(echo "$repo" | sed 's|https\?://[^/]*/||; s|\.git$||; s|git@[^:]*:||')
    owner=$(echo "$repo" | cut -d'/' -f1)
    repo_name=$(echo "$repo" | cut -d'/' -f2)
  fi
  [ -z "$owner" ] || [ -z "$repo_name" ] && { echo '{"error":"Cannot determine repo from git remote origin"}'; return 1; }
  local gh_api="https://api.github.com/repos/${owner}/${repo_name}"
  local auth_header="Authorization: token ${gh_token}"

  # --- list subcommand: show recent CI runs (lightweight, no Python) ---
  if [ "$subcmd" = "list" ]; then
    local count="${2:-5}"
    local resp
    resp=$(curl -sf --max-time 30 -H "$auth_header" -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "${gh_api}/actions/runs?per_page=${count}" 2>&1) || {
      echo '{"error":"Failed to fetch CI runs"}'; return 1
    }
    # Single call for JSON parse + table format (rg not suitable for JSON)
    python3 "$SKILL_DIR/scripts/gk_views.py" ci-runs-table "$count" <<< "$resp"
    return 0
  fi

  # --- fetch subcommand: download failed job logs to /tmp/ci_logs/ (no LLM) ---
  if [ "$subcmd" = "fetch" ]; then
    run_id="$2"
    [ -z "$run_id" ] && { echo '{"error":"Usage: ci-diagnose fetch <RUN_ID> [--token TOKEN]"}'; return 1; }
    local log_dir="/tmp/ci_logs/${run_id}"
    mkdir -p "$log_dir" 2>/dev/null || { echo "{\"error\":\"Cannot create $log_dir\"}"; return 1; }

    # Get jobs — pipe JSON to python3 via stdin (safe, no shell escaping)
    local jobs_json
    jobs_json=$(curl -s --max-time 30 -H "$auth_header" "${gh_api}/actions/runs/${run_id}/jobs" 2>/dev/null)
    [ -z "$jobs_json" ] && { echo "{\"error\":\"No jobs data for run $run_id\"}"; return 1; }

    python3 -c "
import json, sys, urllib.request, os

data = json.loads(sys.stdin.read())
jobs = [j for j in data.get('jobs', []) if j.get('conclusion') == 'failure']
if not jobs:
    print(json.dumps({'ok': True, 'dir': '$log_dir', 'jobs': 0, 'msg': 'No failed jobs'}))
    sys.exit(0)

token = '$gh_token'
log_base = 'https://api.github.com/repos/${owner}/${repo_name}/actions/jobs/'
downloaded = []
for j in jobs:
    jname = j.get('name', 'unknown').replace('/', '_').replace(' ', '_')
    jid = j.get('id', '')
    log_url = log_base + str(jid) + '/logs'
    out_path = os.path.join('$log_dir', jname + '.log')
    req = urllib.request.Request(log_url, headers={'Authorization': 'token ' + token})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(raw[-50000:])  # last 50KB
        downloaded.append({'job': jname, 'bytes': len(raw[-50000:]), 'path': out_path})
    except Exception as e:
        downloaded.append({'job': jname, 'error': str(e)})

print(json.dumps({'ok': True, 'dir': '$log_dir', 'jobs': len(jobs), 'downloaded': downloaded}))
" <<< "$jobs_json" 2>/dev/null || echo '{"error":"Python fetch failed"}'
    return 0
  fi

  # --- unknown subcommand ---
  echo '{"error":"Usage: ci-diagnose list [COUNT]  or  ci-diagnose fetch <RUN_ID> [--token TOKEN]"}'
  return 1
}

# ─── state-patch — gate_data 统一证据写入（S7/S8 2026-09-05 实装）───
# Usage: state-patch '<json-fragment>'
# 统一入口：gate_data 写入类证据（含内部 _write_gate_data）统一经此，checksum 由
# gk_state 单一事实重算；fragment 支持片段/完整对象两种形态（容错外花括号，
# S7 2026-09-05），解析失败给 guidance 不静默。gate 级 none + state_write 副作用标记。
cmd_state_patch() {
  # 2026-09-23（ECC-089658238011 / ECC-A91DC4562198）：**顶层键设值通路**。
  # 背景：`update-gate-data` 只写 `gate_data` 内部；顶层键（如 `worktree`）此前**无任何
  #   CLI 通路** —— 唯一会重写它的是 `cmd_discover`，而 discover 会**归档并清空 gate_data**
  #   ⟹ `apply-worktree` 无法把 worktree 落到被 `pre_tool_check` 强制消费的字段
  #   （「隔离只产不消」的一半根因）。
  # 形态约束：`_CMD_REG` 命令注册表在 `PROTECTED_REGION::gate` 内（禁改）⟹ **不新增命令**，
  #   只在既有 `state-patch` 上开分支；本函数体不在任何 PROTECTED_REGION 内。
  # 写入面：`gk_state_patch.py set-top`（拒绝 `gate_data`/`_` 前缀键/非法 JSON，fail-loud）。
  if [ "${1:-}" = "--set-top" ]; then
    local _stk="${2:-}" _stv="${3:-}"
    [ -z "$_stk" ] && { echo '{"ok":false,"error":"state-patch --set-top <key> <json-value> required","usage":"state-patch --set-top worktree '\''\"/path/to/wt\"'\''"}'; return 1; }
    [ ! -f "$STATE_FILE" ] && { echo '{"ok":false,"error":"No state file"}'; return 1; }
    local _sto _strc
    _sto=$(python3 "$SKILL_DIR/scripts/gk_state_patch.py" set-top "$STATE_FILE" "$_stk" "$_stv" 2>>"$GK_DBG_LOG")
    _strc=$?
    echo "$_sto"
    return "$_strc"
  fi
  # 2026-10-01：`--del-top <key>` —— 顶层键**删除**（清顶层误写残留的**正规通路**；对称 `--set-top`）。
  #   背景：`--set-top` 只有设值、无删除 ⟹ 误写出的顶层键（如漏 `gate_data.` 前缀造出的顶层
  #   `edit_budget`）无正规通路可清 ⟹ 本分支补该删除面（写实现单源 = `gk_state_patch.py del-top`）。
  if [ "${1:-}" = "--del-top" ]; then
    local _dtk="${2:-}"
    [ -z "$_dtk" ] && { echo '{"ok":false,"error":"state-patch --del-top <key> required"}'; return 1; }
    [ ! -f "$STATE_FILE" ] && { echo '{"ok":false,"error":"No state file"}'; return 1; }
    local _dto _dtrc
    _dto=$(python3 "$SKILL_DIR/scripts/gk_state_patch.py" del-top "$STATE_FILE" "$_dtk" 2>>"$GK_DBG_LOG")
    _dtrc=$?
    echo "$_dto"
    return "$_dtrc"
  fi
  # 2026-09-30 G4-a/G4-b（治 state 面 lost-update）：**叶子级写 / 只追加**通路。
  #   背景：`state-patch <fragment>` 是 `gate_data.update()` 浅合并 ⟹ 调用方「锁外读整份 →
  #   回写整份」会 last-writer-wins（实测：并发会话额度互打到 0、`overrides` 10→3–4）。
  #   本二 flag = 锁内**定点**写，调用方无需再算整值。实现单源 = `gk_state_patch.py
  #   set-nested|append-list`（禁第二实现）。计划 §1.3-G4 / §5。
  if [ "${1:-}" = "--set-nested" ] || [ "${1:-}" = "--append-list" ]; then
    local _g4cmd="${1#--}" _g4path="${2:-}" _g4val="${3:-}"
    if [ -z "$_g4path" ] || [ -z "$_g4val" ]; then
      echo "{\"ok\":false,\"error\":\"state-patch --${_g4cmd} <a.b.c> <json> required\"}"; return 1
    fi
    [ ! -f "$STATE_FILE" ] && { echo '{"ok":false,"error":"No state file"}'; return 1; }
    local _g4out="" _g4rc=0
    _g4out=$(python3 "$SKILL_DIR/scripts/gk_state_patch.py" "$_g4cmd" "$STATE_FILE" "$_g4path" "$_g4val" 2>>"$GK_DBG_LOG")
    _g4rc=$?
    # 留痕口径同 fragment 通道：**仅**触及 edit_budget 时记一条（且路径面不含 overrides
    # ⟹ 与 `_budget_override_record` 自身的 append-list 写不构成递归）。
    if [ "$_g4rc" -eq 0 ] && printf '%s' "$_g4path" | "$RG" -q "edit_budget"; then
      _budget_override_record "state_patch_set_nested" "state-patch --${_g4cmd} ${_g4path}"
    fi
    echo "$_g4out"
    return "$_g4rc"
  fi
  # §17-2：域桶 `gate_data.wt_domain[<token>][]` 的**唯一写通路**（对齐 `--set-nested` 先例）。
  #   背景：state 去具体化 —— 活动 worktree 由**域化解析**承载（token ← env `GK_SESSION_ID`，
  #   读侧 `gk_route_center.active_roots`）。写实现单源 = `gk_state_patch.py wt-domain`
  #   （token 经 `gk_finding._DOMAIN_TOKEN_RE` 校验，fail-loud；set-nested/update-gate-data 触达该路径均拒）。
  if [ "${1:-}" = "--wt-domain" ]; then
    local _wdop="${2:-}" _wdtok="${3:-}" _wdpath="${4:-}"
    if [ -z "$_wdop" ] || [ -z "$_wdtok" ] || [ -z "$_wdpath" ]; then
      echo '{"ok":false,"error":"state-patch --wt-domain <bind|unbind> <token> <path> [--dry-run] required"}'; return 1
    fi
    [ ! -f "$STATE_FILE" ] && { echo '{"ok":false,"error":"No state file"}'; return 1; }
    local _wdout _wdrc
    if [ "${5:-}" = "--dry-run" ]; then
      _wdout=$(python3 "$SKILL_DIR/scripts/gk_state_patch.py" wt-domain "$STATE_FILE" "$_wdop" "$_wdtok" "$_wdpath" --dry-run 2>>"$GK_DBG_LOG")
    else
      _wdout=$(python3 "$SKILL_DIR/scripts/gk_state_patch.py" wt-domain "$STATE_FILE" "$_wdop" "$_wdtok" "$_wdpath" 2>>"$GK_DBG_LOG")
    fi
    _wdrc=$?
    echo "$_wdout"
    return "$_wdrc"
  fi
  # 2026-10-05（ECC-44BF078E791C）：窄任务清单**生产者**分支 —— 从 JSON（裸数组或
  #   {"narrow_tasks":[...]}）校验后**替换**写入 `gate_data.narrow_tasks[]`（此前只有消费者
  #   route/check-schema/check-poison，无生产者）。实现单源 = `gk_narrow_route.py --register`
  #   （validate_entries / poison_hits / gk_state_patch 写通路）；本分支仅参数编排，**禁第二实现**。
  #   形态约束：`_CMD_REG` 在 PROTECTED_REGION::gate 内且 `test_gk_state_forms` 钉「条目数不变」
  #   ⟹ **不新增命令**，在既有 `state-patch` 上开分支（同 `--set-nested` / `--wt-domain` 先例）。
  if [ "${1:-}" = "--narrow-register" ]; then
    local _nrf="${2:-}"
    if [ -z "$_nrf" ]; then
      echo '{"registered":false,"error":"state-patch --narrow-register <json-file> required","exit_code":2,"usage":"state-patch --narrow-register <json-file>"}'
      return 2
    fi
    [ -f "$_nrf" ] || { echo "{\"registered\":false,\"error\":\"register file not found: $_nrf\",\"exit_code\":2}"; return 2; }
    [ -f "$STATE_FILE" ] || { echo '{"registered":false,"error":"No state file"}'; return 2; }
    local _nro _nrr
    _nro=$(python3 "$SKILL_DIR/scripts/gk_narrow_route.py" --state "$STATE_FILE" --register "$_nrf" 2>>"$GK_DBG_LOG")
    _nrr=$?
    echo "$_nro"
    return "$_nrr"
  fi
  if [ "${1:-}" = "--narrow-check-groups" ]; then
    # 只读重放：对 state 内已登记的窄任务清单执行三组语义约束（G1 相同对 /
    #   G2 正交互补 / G3 污染），违规 exit 4。实现单源 = `gk_narrow_route.py --check-groups`。
    [ -f "$STATE_FILE" ] || { echo '{"mode":"legacy","ok":false,"error":"No state file"}'; return 2; }
    local _ncgo _ncgr
    _ncgo=$(python3 "$SKILL_DIR/scripts/gk_narrow_route.py" --state "$STATE_FILE" --check-groups 2>>"$GK_DBG_LOG")
    _ncgr=$?
    echo "$_ncgo"
    return "$_ncgr"
  fi
  # 2026-10-27（方案 B）：Task 派发**单次票据**的签发/校验通路。
  #   背景：Gate 0 的关键词黑名单不是完备集（「质询」类自然语言恒可绕过）⟹ 判据改为
  #   默认拒绝 + 可验证凭据（HMAC + 查询哈希 + 过期 + 单次消费）。
  #   形态约束同 `--set-nested` / `--narrow-register` 先例：`_CMD_REG` 在 PROTECTED_REGION::gate
  #   内（禁改）⟹ **不新增命令**，在既有 `state-patch` 上开分支。
  #   实现单源 = `gk_dispatch_ticket.py`（本分支仅参数编排，禁第二实现）。
  if [ "${1:-}" = "--dispatch-issue" ]; then
    local _diq="${2:-}" _dittl="300" _disess="${GK_SESSION_ID:-}" _dinode=""
    [ -z "$_diq" ] && { echo '{"ok":false,"error":"state-patch --dispatch-issue <query|@file|sha256> [--ttl N] [--session S] [--node N] required"}'; return 1; }
    [ -f "$STATE_FILE" ] || { echo '{"ok":false,"error":"No state file"}'; return 1; }
    shift 2 2>/dev/null || true
    while [ $# -gt 0 ]; do
      case "${1:-}" in
        --ttl) _dittl="${2:-300}"; shift 2 2>/dev/null || shift ;;
        --session) _disess="${2:-}"; shift 2 2>/dev/null || shift ;;
        --node) _dinode="${2:-}"; shift 2 2>/dev/null || shift ;;
        *) echo "{\"ok\":false,\"error\":\"unknown arg: ${1:-}\"}"; return 1 ;;
      esac
    done
    local _diout _dirc
    _diout=$(python3 "$SKILL_DIR/scripts/gk_dispatch_ticket.py" issue "$STATE_FILE" "$_diq" \
      --ttl "$_dittl" --session "$_disess" --node "$_dinode" 2>>"$GK_DBG_LOG")
    _dirc=$?
    echo "$_diout"
    return "$_dirc"
  fi
  if [ "${1:-}" = "--dispatch-verify" ]; then
    local _dvtk="${2:-}" _dvq="${3:-}" _dvsess="${GK_SESSION_ID:-}"
    if [ -z "$_dvtk" ] || [ -z "$_dvq" ]; then
      echo '{"ok":false,"error":"state-patch --dispatch-verify <ticket> <query|@file|sha256> [--session S] required"}'
      return 1
    fi
    [ -f "$STATE_FILE" ] || { echo '{"ok":false,"error":"No state file"}'; return 1; }
    shift 3 2>/dev/null || true
    while [ $# -gt 0 ]; do
      case "${1:-}" in
        --session) _dvsess="${2:-}"; shift 2 2>/dev/null || shift ;;
        *) echo "{\"ok\":false,\"error\":\"unknown arg: ${1:-}\"}"; return 1 ;;
      esac
    done
    local _dvout _dvrc
    _dvout=$(python3 "$SKILL_DIR/scripts/gk_dispatch_ticket.py" verify "$STATE_FILE" "$_dvtk" "$_dvq" \
      --session "$_dvsess" 2>>"$GK_DBG_LOG")
    _dvrc=$?
    echo "$_dvout"
    return "$_dvrc"
  fi
  local fragment="$1"
  [ -z "$fragment" ] && { echo '{"ok":false,"error":"state-patch <fragment> required","usage":"state-patch '\''\"ci_status\":\"green\"'\''"}'; return 1; }
  [ ! -f "$STATE_FILE" ] && { echo '{"ok":false,"error":"No state file"}'; return 1; }
  local out rc
  out=$(python3 "$SKILL_DIR/scripts/gk_state_patch.py" update-gate-data "$STATE_FILE" "$fragment" 2>>"$GK_DBG_LOG")
  rc=$?
  # 2026-09-19 P5 §3 T5′ / 计划次序 S1-b：人工 state-patch 是三条覆盖路径里**最静默**的一条
  #（本会话 state 的 max:8 即由此而来、当时零留痕）⟹ 仅在 fragment 触及 edit_budget 时记，
  # 避免「凡 patch 必记」的噪声口径（判据含负臂）。本命令是**通用** patch 通道，不专为额度服务。
  # 2026-09-30 G4-d：留痕判据从**子串嗅探**改为**解析后键**（`fragment` 的顶层键是否真含
  #   `edit_budget`）。旧实现 `printf '%s' "$fragment" | rg -q "edit_budget"` 会被**文本巧合**
  #   触发（`{"note":"edit_budget"}` 对额度毫无作用却写一条 override）——「是否计费」与
  #   「是否留痕」是两件事，前者已由 `_BILL_EXEMPT_CMDS` 按通道判定（§13.2）。
  # 2026-10-04：`@<file>` fragment ⟹ 记留痕前先解析（否则路径串里看不到 `edit_budget` 键；
  #   与 `gk_state_patch.py::_resolve_at_file` 同一 `@` 约定，argv 只留 ASCII 路径）。
  local _rec_frag="$fragment"
  case "$_rec_frag" in @*) [ -f "${_rec_frag#@}" ] && _rec_frag="$(cat -- "${_rec_frag#@}")" ;; esac
  if [ "$rc" -eq 0 ] && printf '%s' "$_rec_frag" | python3 -c "
import sys, json
raw = sys.stdin.read().strip()
try:
    obj = json.loads(raw) if raw.startswith('{') else json.loads('{' + raw.lstrip(',').strip() + '}')
except Exception:
    obj = {}
sys.exit(0 if isinstance(obj, dict) and 'edit_budget' in obj else 1)
" 2>/dev/null; then
    _budget_override_record "state_patch" "state-patch fragment: $(printf '%s' "$_rec_frag" | head -c 200)"
  fi
  echo "$out"
  return "$rc"
}

# ─── ci-status (delegate to project's scripts/ci-status.sh) ───
# Usage: ci-status [TOKEN] [COUNT] | ci-status --record <green|red|unknown>
cmd_ci_status() {
  # S8（2026-09-05）：--record <green|red|unknown> — CI 真实结果的显式确认写入通道
  # （先跑 ci-status 看真实 runs，确证后回写 gate_data.ci_status；不自动解析表格防近似造假绿）。
  if [ "${1:-}" = "--record" ]; then
    local val="${2:-}"
    case "$val" in
      green|red|unknown) ;;
      *) echo '{"ok":false,"error":"ci-status --record <green|red|unknown>","usage":"先 ci-status 确证真实结果再显式回写"}'; return 1 ;;
    esac
    cmd_state_patch "\"ci_status\":\"$val\""
    return $?
  fi
  local ws; ws=$(json_val "$STATE_FILE" worktree "" 2>/dev/null || echo "")
  local script="${ws:-$MAIN_REPO_WSL}/scripts/ci-status.sh"
  [ ! -f "$script" ] && { echo '{"ok":false,"error":"ci-status.sh not found in project scripts"}'; return 1; }
  bash "$script" "$@"
}

# ─── pre-check (WASM pre-check: delegate to project's wasm-pre-check.sh) ───
# Usage: pre-check wasm [--skip-build] [--skip-smoke] [--strict] [--auto-fix]
cmd_pre_check() {
  local subcmd="$1"; shift
  case "$subcmd" in
    wasm)
      local ws
      ws=$(json_val "$STATE_FILE" worktree "" 2>/dev/null || echo "")
      local script_dir="${ws:-$MAIN_REPO_WSL}/scripts/wasm-pre-check.sh"
      [ ! -f "$script_dir" ] && { echo '{"ok":false,"error":"wasm-pre-check.sh not found in project scripts"}'; return 1; }
      bash "$script_dir" "$@"
      ;;
    convergence)
      # Infra-2（2026-10-05）：`--loop` ⟹ **质询轮次循环早停**（编排层 `gk_convergence_evaluator.py`；
      #   正本 references/convergence-evaluator.md §5）。**不新增 `_CMD_REG` 命令**（承计划 §4）。
      #   ⚠ 该模式**不依赖 state 路由**（可只给 `--mu` 出 verdict）；`--emit-finding` 须显式
      #   传 `--state` + `--plan`（state 取 `_conv_state_path` 解析结果）。
      if [ "${1:-}" = "--loop" ]; then
        shift
        python3 "${SKILL_DIR}/scripts/gk_convergence_evaluator.py" loop "$@"
        return $?
      fi
      # n4-L1（2026-10-05）：`--show-state` —— 打印**解析到的 state + 归因**，终结取数黑箱
      #   （F-REV-63 排查靠它：看清"读到哪个 state、为何"，而非静默读错账）。
      if [ "${1:-}" = "--show-state" ]; then
        if ! _conv_state_path; then
          echo "{\"ok\":false,\"error\":\"${_CONV_ERR:-STATE_ROUTE_FAILED}\",\"base_state\":\"${STATE_FILE}\"}"
          return 1
        fi
        echo "{\"ok\":true,\"resolved_state\":\"${_CONV_STATE}\",\"base_state\":\"${STATE_FILE}\"}"
        return 0
      fi
      # 子计划2 §3 判据 4：无 state ⟹ {"ok":false,"error":"no_active_plan"}（不 panic）
      # A6-T2 ①（2026-09-15，判据 J18/J20）：取数锚改走**中枢**；error ⟹ fail-closed。
      if ! _conv_state_path; then
        echo "{\"ok\":false,\"error\":\"${_CONV_ERR:-STATE_ROUTE_FAILED}\",\"channel\":\"state-routing\"}"
        return 1
      fi
      if [ ! -f "$_CONV_STATE" ]; then
        echo '{"ok":false,"error":"no_active_plan"}'
        return 1
      fi
      python3 "${SKILL_DIR}/scripts/gk_convergence_estimator.py" evaluate "$_CONV_STATE"
      ;;
    "")
      echo '{"ok":false,"error":"Usage: pre-check wasm [...] | pre-check convergence"}'
      return 1
      ;;
    *)
      echo "{\"ok\":false,\"error\":\"Unknown pre-check target: $subcmd. Valid: wasm|convergence\"}"
      return 1
      ;;
  esac
}

# ─── t-star: T* 冻结登记（子计划2 §1-C3 前提门的 producer；机器可读落点 = gate_data.t_star）───
# F-REV-57（2026-09-14）：此前该落点**未定义** ⟹ T_NOT_FROZEN 无 producer ⟹ T4 门恒不启用（幻影门）。
# 冻结语义 = **此后不改**（改串须 --force，且按 §2.2 冲突规则须作废采集窗口）。
# Usage: t-star freeze --strings "串1|串2|串3" [--source <plan>] [--force]
#        t-star show
cmd_t_star() {
  local subcmd="$1"; shift 2>/dev/null || true
  case "$subcmd" in
    freeze) python3 "${SKILL_DIR}/scripts/gk_convergence_estimator.py" freeze "$STATE_FILE" "$@" ;;
    show)   python3 "${SKILL_DIR}/scripts/gk_convergence_estimator.py" show "$STATE_FILE" ;;
    *) echo '{"ok":false,"error":"Usage: t-star freeze --strings <a|b|c> [--source <plan>] [--force] | t-star show"}'; return 1 ;;
  esac
}

# ─── workers: s5.5 自适应并发度（核数/内存→worker；**单一源** = gk_hub_scheduler.adaptive_workers）───
# 供 gitnexus 增量分析 / subagent 扇出 / audit-depth / moa-integrity / phase-probe 等查询（禁各自再算）。
# ⚠ 例外（据实化，2026-10-16，finding ECC-3DF26C21C3CB）：`scripts/_accept_cli.sh` **不**查询本单源，自算
#   `nproc×2`（cap 12）—— 它是有意的**超订**（隐藏 coder 子进程 fork/exec 延迟，`_accept_cli.sh:29-45` 有
#   实测论据），且属**快循环**（显式子集秒级）⟹ 禁为查单源再加 CLI 子进程（单次 CLI 调用孵 ~10 次 execve）。
#   别处**一律**走本单源；仅 accept 保留其专用超订口径（非"第二实现"，是性能敏感例外）。
# Usage: gatekeeper-cli.sh workers [--n N] [--cap N]
cmd_workers() {
  python3 "${SKILL_DIR}/scripts/gk_hub_scheduler.py" workers "$@" 2>>"$GK_DBG_LOG"
}

# ─── commit (encoding-safe commit via temp file, bypass WSL sandbox mojibake) ───
# Bridge r3-v1 L3 pattern: git commit -F <file> avoids passing non-ASCII through CLI.
# Usage: gatekeeper-cli.sh commit -m "message"
#        gatekeeper-cli.sh commit --repo <path> -m "message"
# ─── commit (提交面**单一入口**：锁预检 → 破 stat 缓存 → 只 add 显式路径 → 暂存面校验 → 提交 → HEAD 复核) ───
# 2026-09-25（事故驱动 = `ECC-E5364D7993C8` / `ECC-3802B43E4EF9` 同批）：原实现只做 `git commit -F`
# （消息编码安全），三个**流程缺陷**全裸着 ——
#   ① **撕裂读入历史**：`git add` 的**那一次读取**若坏（CIFS / 并发写），进索引的 blob 就坏；而此后
#      `git status`/`git diff`/`git diff-files` 全走**索引 stat 缓存**（size+mtime 命中即不重算 hash）
#      ⟹ 竟然报 clean ⟹ 损坏内容进历史（实测 `65974a8`：`gatekeeper-cli.sh` 2968-2977 两段粘连、
#      `bash -n` 直接 syntax error，唯 `git archive HEAD` 型测试暴露）。
#   ② **孤儿锁**：提交进程被杀（工具宿主复用终端 / 超时 / 会话中断）⟹ `.git/index.lock` 留存 ⟹ 后续
#      提交恒失败（当日两次：16:09 / 18:40，均 0 字节且**无** git 进程）。
#   ③ **无单一入口**：谁 add、add 什么、提交前校准，全靠 agent 自觉（`git add -A` 还会夹带并发会话文件）。
# 本入口按序消除：锁预检（孤儿 ⟹ `mv` 归档到 `.gk-trash`（**非删除**）；活锁 ⟹ fail-loud **不抢**）→
#   `git update-index --really-refresh`（**破缓存致盲**）→ 只 add **显式路径** →
#   `gk_commit_verify --mode staged`（blob ↔ 工作树**逐字节** + `.sh/.py/.json` **解析面**；不过则
#   **不提交** ⟹ 损坏挡在历史之外）→ 提交 → `--mode rev HEAD` 复核（兜住"校验后又被撕裂"的窗口）。
# 用法: commit -m <msg> [--add <path>...] [--repo skill|gatekeeper|<path>] [--verify-only [--rev <rev>]]
#        [--refresh <path>...]   # drvfs **安全**刷新（`ECC-FAA686AB1791`/`ECC-C2BE2C56A7BD`）：
#                                # 两路读不一致 ⟹ 拒绝回写（防把 Windows 侧编辑回滚）；禁裸 `cp` 往返
_gk_repo_label() {   # --repo 别名（与 META `target_repo: skill|gatekeeper` 同词表）
  case "$1" in
    skill) printf '%s' "$SKILL_DIR" ;;
    gatekeeper) printf '%s' "$MAIN_REPO_WSL" ;;
    *) printf '%s' "$1" ;;
  esac
}

_gk_trash_dir() {    # 回收落点**单源**（`gk_route_center.trash_dir`）；禁第二份路径推算
  GK_PY_SD="$(_gk_py_path "$SKILL_DIR")" python3 -c "import sys,os;sys.path.insert(0,os.path.join(os.environ['GK_PY_SD'],'scripts'));import gk_route_center as r;print(r.trash_dir(os.environ['GK_PY_SD']))" 2>/dev/null \
    || printf '%s' "${SKILL_DIR%/*}/../.gk-trash"
}

_gk_commit_lock_preflight() {   # <repo>：孤儿锁归档（非删除）/ 活锁 fail-loud（不抢）
  # 设计 L（2026-09-30，R-CONC-GIT §2）：锁语义**唯一实现**已迁 `scripts/gk_git_lease.py::preflight`
  #   —— 本函数降为**薄包装**：判据 / 文案 / rc 由其**原样返回**（行为逐字保持；对照网 = 既有
  #   `scripts/test_gk_commit_guard.py` 的孤儿/活锁臂）。⚠ 禁在本处新增任何拒绝条件。
  # stderr 直通调用方（孤儿归档的 `WARN[commit]: …` 仍可见），stdout 原样透传。
  local _out _rc
  _out=$(python3 "$SKILL_DIR/scripts/gk_git_lease.py" preflight "$1" --trash "$(_gk_trash_dir)")
  _rc=$?
  [ -n "$_out" ] && printf '%s\n' "$_out"
  return "$_rc"
}

# 设计 L：lease **释放**（临界段出口）。`release` 只删**自己创建**的锁；孤儿归档走 `_archive` 另一路。
_gk_lease_release() {  # <lock_path>
  [ -n "${1:-}" ] || return 0
  python3 "$SKILL_DIR/scripts/gk_git_lease.py" release --lock "$1" >/dev/null 2>&1 || true
}

# ── 设计 D（2026-09-30，R-CONC-GIT §3）：运行时刻 declare = **write-claims 台账**接线 ──────
# **登记点①「写哪本账」裁定**：**主 repo 单本账** `<主 worktree>/.gatekeeper.write-claims.jsonl`
#   —— 跨 worktree 共享可见；且落点**区外 append-only** ⟹ `discover` 清空 `gate_data` 不连带清空。
#   `GK_WRITE_CLAIMS_PATH` 非空 ⟹ 覆盖（应急/测试开关）。
_gk_claims_repo() {
  local _m
  _m=$(git -C "$SKILL_DIR" worktree list --porcelain 2>/dev/null | python3 -c '
import sys
for ln in sys.stdin:
    if ln.startswith("worktree "):
        print(ln.split(" ", 1)[1].strip()); break
' 2>/dev/null)
  printf '%s' "${_m:-$SKILL_DIR}"
}

# best-effort：登记失败**不得**影响派发/提交主流程（但仍落 `gk_dbg.log` 留痕，禁静默）。
_gk_claim_register() {  # <sid> <worktree> <family> <source> <comma-paths>
  python3 "$SKILL_DIR/scripts/gk_write_claims.py" append \
    --repo "$(_gk_claims_repo)" --sid "${1:-}" --worktree "${2:-}" --family "${3:-}" \
    --source "${4:-dispatch}" --paths "${5:-}" >>"$GK_DBG_LOG" 2>&1 || true
}

# §17-4 A 步②：写面写点（`discover`）登记 `state.worktree` 的 claim（fail-soft / sid-gated /
#   主树排除 / 幂等，语义单源在 `gk_write_claims.sync_state_worktree`）。best-effort：
#   台账同步**绝不**影响 discover 主流程（`|| true`）。
_gk_state_wt_claim_sync() {  # <worktree>
  python3 "$SKILL_DIR/scripts/gk_write_claims.py" sync-state-worktree \
    --repo "$(_gk_claims_repo)" --sid "${GK_SESSION_ID:-}" --worktree "${1:-}" \
    >>"$GK_DBG_LOG" 2>&1 || true
}

# P4（§16，2026-10-02）：**续期**本会话 claim ⟹ 长任务周期性提交即维持占用
#   （防超 `GK_CLAIM_TTL_S` 静默失活 ⟹ D-a 回收闸被架空；6 臂质询硬项）。best-effort。
_gk_claim_renew() {  # <sid>
  python3 "$SKILL_DIR/scripts/gk_write_claims.py" renew \
    --repo "$(_gk_claims_repo)" --sid "${1:-}" --source reconcile >>"$GK_DBG_LOG" 2>&1 || true
}
# 写后对账（提交面）：**只 WARN 不阻断**（`lease-warns-never-blocks`）⟹ 恒 `return 0`。
# ⚠ 诊断串落 `$GK_DBG_LOG`（**不得**进 stdout/stderr）：CLI 的对外契约 = stdout **单一 JSON**，
#   实测把对账 JSON 打到 stderr 会污染 `stdout+stderr` 合并流的「最后一行 JSON」判据
#   （`test_gk_commit_guard` / `test_gk_git_lease` 的既有臂**批量假红**）⟹ 走本仓诊断日志惯例。
_gk_claim_reconcile() {  # <sid> <comma-changed>
  _gk_claim_renew "${1:-}"   # P4：提交前续期，防长任务超 TTL 静默失活
  python3 "$SKILL_DIR/scripts/gk_write_claims.py" reconcile \
    --repo "$(_gk_claims_repo)" --sid "${1:-}" --changed "${2:-}" \
    --worktree "${3:-}" \
    --expected-auto --state "$STATE_FILE" >>"$GK_DBG_LOG" 2>&1 || true
  return 0
}
_gk_claim_heartbeat() {  # <worktree>
  # `ECC-70D40BA92943`：判活锚 = **活动**（编辑）而非仅提交。节流在 heartbeat 内（ttl*0.5）
  #   ⟹ 多数编辑调用零写盘、不涨台账；输出全落 GK_DBG_LOG，不污染 pre-tool-check 的 stdout 契约。
  python3 "$SKILL_DIR/scripts/gk_write_claims.py" heartbeat \
    --repo "$(_gk_claims_repo)" --worktree "${1:-}" >>"$GK_DBG_LOG" 2>&1 || true
  return 0
}

cmd_commit() {
  local msg="" repo="" worktree="" verify_only=0 verify_rev=""
  local -a add_paths=() refresh_paths=()

  while [ $# -gt 0 ]; do
    case "$1" in
      -m) msg="${2:-}"; shift 2 2>/dev/null || shift ;;
      --repo) repo="$(_gk_repo_label "${2:-}")"; shift 2 2>/dev/null || shift ;;
      --add) shift; while [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; do add_paths+=("$1"); shift; done ;;
      --refresh) shift; while [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; do refresh_paths+=("$1"); shift; done ;;
      --verify-only) verify_only=1; shift ;;
      --rev) verify_rev="${2:-}"; shift 2 2>/dev/null || shift ;;
      *) break ;;
    esac
  done
  # Remaining args become message if -m not given
  [ -z "$msg" ] && msg="$*"

  # Resolve repo path: --repo（含别名）> --add 默认技能仓 > state.worktree > MAIN_REPO_WSL
  if [ -z "$repo" ]; then
    if [ ${#add_paths[@]} -gt 0 ]; then
      repo="$SKILL_DIR"          # 本工作流 add 的都是技能仓文件；跨仓须显式 --repo
    elif [ -f "$STATE_FILE" ]; then
      worktree=$(json_val "$STATE_FILE" worktree "" 2>/dev/null || echo "")
      [ -n "$worktree" ] && repo="$worktree"
    fi
  fi
  [ -z "$repo" ] && repo="$MAIN_REPO_WSL"
  [ ! -d "$repo" ] && { echo "{\"ok\":false,\"error\":\"repo not found: $repo\"}"; return 1; }

  # ── drvfs 安全刷新（`ECC-FAA686AB1791`/`ECC-C2BE2C56A7BD`）：不提交/不校验 ────────────
  #    两路读（git 路径 vs read 路径）**不一致** ⟹ 拒绝回写（防把 Windows 侧编辑回滚）；禁裸 cp 往返。
  if [ ${#refresh_paths[@]} -gt 0 ]; then
    python3 "$SKILL_DIR/scripts/gk_commit_verify.py" --repo "$repo" --refresh "${refresh_paths[@]}"
    return $?
  fi

  # ── 只校验不提交（事后审计面 / 事故复盘面）──
  if [ "$verify_only" = "1" ]; then
    if [ -n "$verify_rev" ]; then
      python3 "$SKILL_DIR/scripts/gk_commit_verify.py" --repo "$repo" --mode rev --rev "$verify_rev"
    else
      python3 "$SKILL_DIR/scripts/gk_commit_verify.py" --repo "$repo" --mode staged
    fi
    return $?
  fi

  [ -z "$msg" ] && { echo '{"ok":false,"error":"commit message required. Usage: commit -m \"message\" [--add <path>...] [--repo skill|<path>]"}'; return 1; }

  # ① 锁预检（孤儿 ⟹ 归档；活锁 ⟹ 不抢）
  _gk_commit_lock_preflight "$repo" || return 1
  # ①a 设计 §2（merge **降级为检出**，2026-09-30）：**检出**未完成 merge 态 ⟹ 留痕 + 提示串行合并；
  #     **不拒**（冲突收尾本身就是 `git commit -F`；做成拒绝会阻断收尾）。一期**不做** `cmd_merge`。
  if [ -e "$repo/.git/MERGE_HEAD" ]; then
    echo "WARN[commit]: 检出未完成 merge 态（MERGE_HEAD 存在）⟹ 本次提交可能在收尾冲突；合并请**串行**（设计 §11.3-3：单队列 git merge --no-ff）" >&2
  fi
  # ①b 设计 L（2026-09-30，R-CONC-GIT §2）：repo 级写 **lease** —— 临界段前**自己创建**、各出口释放。
  #     kill switch `GK_GIT_LEASE=0` ⟹ 完全跳过（应急；行为与本批前**逐字一致**）。
  local _lease_lk=""
  if [ "${GK_GIT_LEASE:-1}" != "0" ]; then
    local _lout _lrc=0
    _lout=$(python3 "$SKILL_DIR/scripts/gk_git_lease.py" acquire "$repo" --sid "${GK_SESSION_ID:-}" --trash "$(_gk_trash_dir)" 2>>"$GK_DBG_LOG") || _lrc=$?
    if [ "$_lrc" != "0" ]; then
      printf '%s\n' "$_lout"
      return "$_lrc"
    fi
    _lease_lk=$(LEASE_OUT="$_lout" python3 "$SKILL_DIR/scripts/gk_json_utils.py" field lock --env LEASE_OUT --default '' 2>/dev/null)
  fi
  # ② 破索引 stat 缓存致盲（事故根因层：缓存命中 ⟹ git 不重算 hash ⟹ 撕裂读隐形）
  git -C "$repo" update-index --really-refresh >/dev/null 2>&1 || true
  # ③ 只 add **显式路径**（禁 `-A`/`.` 夹带并发会话的在改文件）
  if [ ${#add_paths[@]} -gt 0 ]; then
    git -C "$repo" add -- "${add_paths[@]}" >/dev/null 2>&1 \
      || { _gk_lease_release "$_lease_lk"; echo "{\"ok\":false,\"error\":\"git add 失败: ${add_paths[*]}\"}"; return 1; }
  fi
  # ④ 暂存面校验：blob ↔ 工作树逐字节 + 解析面；坏 ⟹ **不提交**（损坏不进历史）
  #    注：rc=1（有坏项）**仍**输出合法 JSON ⟹ 不可用 `|| echo` 兜底（会拼接出第二份 JSON 破坏解析）
  local _v1 _v1rc _v1ok
  _v1=$(python3 "$SKILL_DIR/scripts/gk_commit_verify.py" --repo "$repo" --mode staged 2>/dev/null); _v1rc=$?
  if [ "$_v1rc" -eq 2 ] || [ -z "$_v1" ]; then
    _v1='{"ok":false,"bad":[{"path":"?","reason":"gk_commit_verify 环境/参数错（rc='"$_v1rc"'）"}]}'
  fi
  _v1ok=$(printf '%s' "$_v1" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test ok --as 1:0 2>/dev/null || echo 0)
  if [ "$_v1ok" != "1" ]; then
    _gk_lease_release "$_lease_lk"
    echo "{\"ok\":false,\"error\":\"COMMIT_VERIFY_FAILED(staged): 暂存面校验不过 ⟹ 已**阻止提交**（损坏不进历史）\",\"verify\":$_v1}"
    return 1
  fi

  # ④b 设计 D 写后对账（2026-09-30）：暂存面路径 vs live claims ⟹ 不一致落 `anomaly`（**不阻断**）。
  local _staged
  _staged=$(git -C "$repo" diff --cached --name-only 2>/dev/null | tr '\n' ',')
  _gk_claim_reconcile "${GK_SESSION_ID:-}" "${_staged%,}" "$repo"

  # Write message to temp file via Python (bypass sandbox encoding truncation)
  local msg_file
  msg_file=$(python3 -c "import tempfile;print(tempfile.mkstemp(suffix='.txt',prefix='gk_commit_')[1])" 2>/dev/null || echo "/tmp/gk_commit_$$.txt")
  printf '%s' "$msg" | python3 "$SKILL_DIR/scripts/gk_io.py" write-text "$msg_file" 2>/dev/null || { _gk_lease_release "$_lease_lk"; echo '{"ok":false,"error":"failed to write commit message"}'; return 1; }

  # git commit -F reads from file, no CLI encoding issues
  local out; out=$(git -C "$repo" commit -F "$msg_file" 2>&1); local rc=$?
  rm -f "$msg_file" 2>/dev/null

  if [ $rc -ne 0 ]; then
    _gk_lease_release "$_lease_lk"
    echo "{\"ok\":false,\"error\":$(echo "$out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --strip 2>/dev/null || echo '\"\"'),\"exit_code\":$rc}"
    return $rc
  fi

  # ⑤ 提交后复核（HEAD 面）：兜住"校验通过后、提交前"又被撕裂的窗口
  local sha; sha=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo "unknown")
  local _v2 _v2rc _v2ok
  _v2=$(python3 "$SKILL_DIR/scripts/gk_commit_verify.py" --repo "$repo" --mode rev --rev HEAD 2>/dev/null); _v2rc=$?
  if [ "$_v2rc" -eq 2 ] || [ -z "$_v2" ]; then
    _v2='{"ok":false,"bad":[{"path":"?","reason":"gk_commit_verify 环境/参数错（rc='"$_v2rc"'）"}]}'
  fi
  _v2ok=$(printf '%s' "$_v2" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" test ok --as 1:0 2>/dev/null || echo 0)
  if [ "$_v2ok" != "1" ]; then
    _gk_lease_release "$_lease_lk"
    echo "{\"ok\":false,\"commit\":\"$sha\",\"error\":\"COMMIT_VERIFY_FAILED(rev HEAD): 坏项已进历史 ⟹ 人工处置 = git -C $repo reset --soft HEAD^ 后重提（**禁 amend**）\",\"verify\":$_v2}"
    return 1
  fi
  local _vn
  _vn=$(printf '%s' "$_v2" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field checked --len --default-invalid 0 2>/dev/null || echo 0)
  _gk_lease_release "$_lease_lk"
  echo "{\"ok\":true,\"commit\":\"$sha\",\"verified\":$_vn,\"message\":$(echo "$out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape --strip 2>/dev/null || echo '\"\"')}"
  return 0
}

# ─── search (T43+: repo-routed search with precise context loading) ───
# Design: agent says "search X in gatekeeper", CLI auto-routes + precise load + hash verify
# Usage: gatekeeper-cli.sh search <pattern> --repo <gatekeeper|skill> [--file <glob>] [--line <N>] [--context <N>]
cmd_search() {
  local pattern="" repo="" file_pattern="" line_range="" context_lines=5

  while [ $# -gt 0 ]; do
    case "$1" in
      --repo) repo="${2:-}"; shift 2 2>/dev/null || shift ;;
      --file) file_pattern="${2:-}"; shift 2 2>/dev/null || shift ;;
      --line) line_range="${2:-}"; shift 2 2>/dev/null || shift ;;
      --context) context_lines="${2:-}"; shift 2 2>/dev/null || shift ;;
      -*) shift ;;
      *) [ -z "$pattern" ] && pattern="$1"; shift ;;
    esac
  done

  [ -z "$pattern" ] && { echo '{"error":"Usage: search <pattern> --repo <gatekeeper|skill> [--file <glob>] [--line <N>]"}'; return 1; }

  # Read plan metadata for routing
  _read_plan_metadata
  [ -z "$repo" ] && repo="${META_target_repo:-gatekeeper}"

  # 步骤 1（路由）：repo 名 → 绝对路径。**路由单一事实源 = gk_route_center 五层链**
  #   （L1 plan → L2 repo → L3 worktree → L4 域 → L5 narrow），本命令不再自持层级判定。
  local search_path
  search_path=$(_resolve_repo_path "$repo") || { echo "{\"error\":\"unknown repo: ${repo}\"}"; return 1; }
  [ ! -d "$search_path" ] && { echo "{\"error\":\"repo path not found: ${search_path}\"}"; return 1; }

  # 步骤 2：元数据交叉校验（plan META.target_repo vs --repo）
  if [ -n "$META_target_repo" ] && [ "$repo" != "$META_target_repo" ] && [ "$repo" != "both" ]; then
    echo "{\"warning\":\"repo '${repo}' differs from META target_repo '${META_target_repo}'\",\"route\":\"${search_path}\"}"
  fi

  # 步骤 3：身份校验（repo_hash；skill/gatekeeper 各一）
  local expected_hash=""
  case "$repo" in
    gatekeeper) expected_hash="15309a63" ;;
    skill)      expected_hash="${SKILL_REPO_HASH}" ;;
  esac

  # 步骤 4：检索（gitnexus 语义 → rg 文本兜底；bridge 无索引 ⟹ 直接 rg）
  local results gn_available=false
  local gn_repo
  # F-REV-71（2026-09-16）：repo 名改由**单源推导**（复用上方 Layer 1 已解析的 `search_path`）
  #   —— 原 gatekeeper 分支硬编码 `spz_gatekeeper`（**不在 registry** ⟹ 恒报找不到 ⟹ 静默退化为 rg）。
  case "$repo" in
    gatekeeper|skill) gn_repo=$(_gx_repo_name_for_dir "$search_path") ;;
    bridge)     gn_repo="" ;;  # bridge 无 gitnexus 索引，退化为 rg 文本搜索
    both)       gn_repo="" ;;
  esac

  # Try gitnexus semantic search first
  if [ -n "$gn_repo" ]; then
    local gn_out
    gn_out=$(_run_gitnexus query -r $gn_repo $pattern 2>/dev/null || echo "")
    if [ -n "$gn_out" ] && echo "$gn_out" | python3 "$SKILL_DIR/scripts/gk_views.py" gn-has-results 2>/dev/null; then
      gn_available=true
      # Extract structured results: symbol name + file:line
      results=$(echo "$gn_out" | python3 "$SKILL_DIR/scripts/gk_views.py" gn-query-results 2>/dev/null || echo "")
    fi
  fi

  # Fallback: rg text search
  if [ "$gn_available" = "false" ] || [ -z "$results" ]; then
    local rg_args=(-n --no-heading)
    [ -n "$file_pattern" ] && rg_args+=(--glob "$file_pattern")
    # bridge repo: plan docs are gitignored by design, add --no-ignore to find them
    if [ "$repo" = "bridge" ]; then
      rg_args+=(--no-ignore)
    fi
    if [ "$repo" = "both" ]; then
      local gk_results sk_results
      gk_results=$(cd "$(_resolve_repo_path gatekeeper)" 2>/dev/null && "$RG" "${rg_args[@]}" "$pattern" . 2>/dev/null | head -20 || echo "")
      sk_results=$(cd "$(_resolve_repo_path skill)" 2>/dev/null && "$RG" "${rg_args[@]}" "$pattern" . 2>/dev/null | head -20 || echo "")
      results=""
      [ -n "$gk_results" ] && results+="$(echo "$gk_results" | sed "s|^|[gatekeeper:${expected_hash:-15309a63}] |")"
      [ -n "$sk_results" ] && { [ -n "$results" ] && results+=$'\n'; results+="$(echo "$sk_results" | sed "s|^|[skill:${SKILL_REPO_HASH}] |")"; }
    else
      results=$(cd "$search_path" 2>/dev/null && "$RG" "${rg_args[@]}" "$pattern" . 2>/dev/null | head -30 || echo "")
    fi
  fi

  local match_count=0
  [ -n "$results" ] && match_count=$(echo "$results" | wc -l)

  # If --line specified, show surrounding context (precise context loading)
  if [ -n "$line_range" ] && [ -n "$results" ]; then
    local target_file target_line
    target_file=$(echo "$results" | head -1 | sed 's/:.*//')
    target_line=$(echo "$results" | head -1 | sed 's/^[^:]*:\([0-9]*\):.*/\1/')
    if [ -n "$target_file" ] && [ -f "${search_path}/${target_file}" ]; then
      local ctx_start=$((target_line - context_lines))
      [ $ctx_start -lt 1 ] && ctx_start=1
      local ctx_end=$((target_line + context_lines))
      local file_content
      file_content=$(sed -n "${ctx_start},${ctx_end}p" "${search_path}/${target_file}" 2>/dev/null | cat -n)
      results=$results$'\n'"--- context (${ctx_start}-${ctx_end}) of ${target_file} ---"$'\n'"$file_content"
    fi
  fi

  echo "{\"repo\":\"${repo}\",\"path\":\"${search_path}\",\"repo_hash\":\"${expected_hash:-${SKILL_REPO_HASH}}\",\"pattern\":\"${pattern}\",\"matches\":${match_count},\"results\":$(echo "${results:-}" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" escape 2>/dev/null || echo '""')}"
}

# ── release-check: GitHub release version scanner ──
# Refs: MPR Standing Plan §场景1 — 外部参考项目冲击分析
# Usage: release-check [--timeout <seconds>]
# Stage: any (works in IDLE/standing/active-r)
# Output: JSON { ok, projects[] } — each project: name, repo_url,
#         current_version, latest_version, category, has_update
cmd_release_check() {
  local timeout=10
  while [ $# -gt 0 ]; do
    case "$1" in
      --timeout) timeout="${2:-}"; shift 2 2>/dev/null || shift ;;
      *) break ;;
    esac
  done

  # ── 项目定义: name|api_url|current_version|category|display_url ──
  # 直接依赖
  local -a projects=(
    "gitnexus|https://api.github.com/repos/abhigyanpatwari/GitNexus/releases/latest|v1.6.6|direct|github.com/abhigyanpatwari/GitNexus"
    "codex|https://api.github.com/repos/khulnasoft/codex/releases/latest|unknown|direct|github.com/khulnasoft/codex"
    "ripgrep|https://api.github.com/repos/BurntSushi/ripgrep/releases/latest|unknown|direct|github.com/BurntSushi/ripgrep"
    "zthl-bashpy-migrate|https://api.github.com/repos/zthl-harness/zthl-bashpy-migrate/releases/latest|v0.2.3|plugin|github.com/zthl-harness/zthl-bashpy-migrate"
  )
  # 参考项目
  local -a refs=(
    "ECC|https://api.github.com/repos/affaan-m/ECC/releases/latest|v2.0.0-rc.1|reference|github.com/affaan-m/ECC"
    "SkillOpt|https://api.github.com/repos/yang-lab/SkillOpt/releases/latest|unknown|reference|github.com/yang-lab/SkillOpt"
    "SafeHarness|https://api.github.com/repos/lin-lab/SafeHarness/releases/latest|unknown|reference|github.com/lin-lab/SafeHarness"
    "OpenCodeReview|https://api.github.com/repos/alibaba/opencode-review/releases/latest|v1.1.18|reference|github.com/alibaba/opencode-review"
    "agent-reach|https://api.github.com/repos/Panniantong/Agent-Reach/releases/latest|unknown|reference|github.com/Panniantong/Agent-Reach"
  )

  local items=""

  # 合并两个列表
  for entry in "${projects[@]}" "${refs[@]}"; do
    IFS='|' read -r name api_url current_version category display_url <<< "$entry"

    local latest_version="$current_version"
    local resp
    resp=$(curl -s --max-time "$timeout" \
      -H "Accept: application/vnd.github.v3+json" \
      "$api_url" 2>/dev/null || echo "")

    if [ -n "$resp" ]; then
      local fetched
      fetched=$(echo "$resp" | python3 "$SKILL_DIR/scripts/gk_views.py" release-tag 2>/dev/null || echo "")
      [ -n "$fetched" ] && latest_version="$fetched"
    fi

    local has_update
    if [ "$current_version" = "unknown" ] || [ "$current_version" = "$latest_version" ]; then
      has_update=false
    else
      has_update=true
    fi

    items+="${items:+,}{\"name\":\"$name\",\"repo_url\":\"$display_url\",\"current_version\":\"$current_version\",\"latest_version\":\"$latest_version\",\"category\":\"$category\",\"has_update\":$has_update}"
  done

  echo "{\"ok\":true,\"projects\":[$items]}"
}

# ─── apply-worktree: worktree 申请—分发入口（F7/R9 子集，2026-09-22）───
# 用户公理 A2：coding agent 须「向元数据路由申请 worktree」，禁止自行挑选目录。
# 单一事实源 = gk_route_center.apply_worktree（白名单 + 归一化复用，禁第二实现）。
# Usage: apply-worktree <finding-id> --family <F>
#        apply-worktree --plan <plan-file> [--dry-run]   ← 计划驱动建树（feature/<plan-stem>）
#        apply-worktree --code-fix --finding <fid> [--family F] [--tier N] [--dry-run] [--state P]
#
# 2026-09-23（F7 基座 T8，**路线 A**，用户裁定）：编码代理编排放**不新注册命令** ——
# `_CMD_REG` 在 `PROTECTED_REGION::gate` 内（SKILL.md T48b「agent 无法修改注册表绕过门禁」），
# 故 code-fix 编排作为本命令的 `--code-fix` 模式挂在**区外**的既有函数体上（零保护区改动）。
# 族判定/窄任务编译的单一事实源 = `gk_agent_family.py resolve`（本函数只做参数编排，不复制判定）。
cmd_apply_worktree() {
  local fid="" family="" codefix="0" tier="" dry="0" state_override="" state_flag_given="0" batch="0" session="" reclaim="0" reclaim_apply="0" reclaim_tmp="0" tmp_days="7" reclaim_trash="0" trash_days="3" bind_mode="" path_arg="" main_repo_arg="" receive_check_wt="" release_claim="" reclaim_all="0" sat_reclaim="" sat_backfill="" finding_spill="" reclaim_branches="0" plan_arg=""
  # T7（2026-10-16，finding ECC-21AB384F03A9）：处置链闭环出口参数（`--close-out`）。
  local closeout="0" closeout_wts="" accept_files="" full_regression="0" no_gitnexus="0" no_reclaim="0"
  case "${1:-}" in
    --code-fix) codefix="1"; shift ;;
    --plan) plan_arg="${2:-}"; shift 2 2>/dev/null || shift ;;   # 计划驱动建树单一入口（2026-10-28）
    --close-out) closeout="1"; shift ;;
    --batch) batch="1"; shift ;;
    --satellite-reclaim) sat_reclaim="1"; shift ;;
    --satellite-backfill) sat_backfill="1"; shift ;;
    --finding-spill) finding_spill="1"; shift ;;
    --session) session="${2:-}"; shift 2 2>/dev/null || shift ;;
    --bind) bind_mode="bind"; shift ;;
    --unbind) bind_mode="unbind"; shift ;;
    --receive-check) receive_check_wt="${2:-}"; shift 2 2>/dev/null || shift ;;
    --reclaim) reclaim="1"; shift ;;
    --tmp) reclaim_tmp="1"; shift ;;
    --trash) reclaim_trash="1"; shift ;;
    --release-claim) release_claim="${2:-}"; shift 2 2>/dev/null || shift ;;
    --all) reclaim_all="1"; shift ;;
    --branches) reclaim_branches="1"; shift ;;
    *) fid="${1:-}"; shift 2>/dev/null || true ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --close-out) closeout="1"; shift ;;
      --worktrees) closeout_wts="${2:-}"; shift 2 2>/dev/null || shift ;;
      --accept-files) accept_files="${2:-}"; shift 2 2>/dev/null || shift ;;
      --full-regression) full_regression="1"; shift ;;
      --no-gitnexus) no_gitnexus="1"; shift ;;
      --no-reclaim) no_reclaim="1"; shift ;;
      --family) family="${2:-}"; shift 2 2>/dev/null || shift ;;
      --plan) plan_arg="${2:-}"; shift 2 2>/dev/null || shift ;;
      --satellite-reclaim) sat_reclaim="1"; shift ;;
      --satellite-backfill) sat_backfill="1"; shift ;;
      --finding-spill) finding_spill="1"; shift ;;
      --main-repo) main_repo_arg="${2:-}"; shift 2 2>/dev/null || shift ;;
      --code-fix) codefix="1"; shift ;;
      --batch) batch="1"; shift ;;
      --session) session="${2:-}"; shift 2 2>/dev/null || shift ;;
      --bind) bind_mode="bind"; shift ;;
      --unbind) bind_mode="unbind"; shift ;;
      --path) path_arg="${2:-}"; shift 2 2>/dev/null || shift ;;
      --receive-check) receive_check_wt="${2:-}"; shift 2 2>/dev/null || shift ;;
      --release-claim) release_claim="${2:-}"; shift 2 2>/dev/null || shift ;;
      --reclaim) reclaim="1"; shift ;;
      --tmp) reclaim_tmp="1"; shift ;;
      --trash) reclaim_trash="1"; shift ;;
      --all) reclaim_all="1"; shift ;;
      --tmp-days) tmp_days="${2:-7}"; shift 2 2>/dev/null || shift ;;
      --trash-days) trash_days="${2:-3}"; shift 2 2>/dev/null || shift ;;
      --apply) reclaim_apply="1"; shift ;;
      --finding) fid="${2:-}"; shift 2 2>/dev/null || shift ;;
      --tier) tier="${2:-}"; shift 2 2>/dev/null || shift ;;
      --state) state_override="${2:-}"; state_flag_given="1"; shift 2 2>/dev/null || shift ;;
      --dry-run) dry="1"; shift ;;
      *) echo "{\"ok\":false,\"error\":\"unknown arg: $1\",\"usage\":\"apply-worktree <finding-id> --family <F> | apply-worktree [--code-fix] --finding <fid[,…]> [--batch] [--family F] [--tier N] [--dry-run] [--state P] | apply-worktree --session <name> [--state P] | apply-worktree --bind|--unbind --path <dir> [--state P] [--dry-run] | apply-worktree --reclaim [--tmp|--trash] [--tmp-days N] [--trash-days N] [--path <dir>] [--apply] [--all] | apply-worktree --release-claim <sid>\",\"next\":\"bash gatekeeper-cli.sh help apply-worktree\"}"; return 2 ;;
    esac
  done
  # ── sanctioned 手动 release 出口（write-claims 台账；仅**追加** released 终态行）（2026-10-06）──────
  #   动机：`gk_write_claims.release` 是设计内的终态出口（`state ∈ {live,renewed}` 之外唯一收口），
  #   但**无 CLI 面** —— 直跑 `scripts/gk_*.py` 被加载安全网拦（绕开 CLI 门禁/留痕）⟹ 悬空 / 测试
  #   残留 / 会话提前终结的 claim 只能干等 TTL（默认 3600s）自然失活，回收面与对账面在窗口内持续
  #   误报（zombie / 误 held）。本模式挂既有 `apply-worktree`（与 `--reclaim` 同属 claims 面），
  #   **不新注册命令**（`_CMD_REG` 在 PROTECTED_REGION::gate 内）。语义单源 = 中枢
  #   `gk_write_claims.release`（禁第二实现）；best-effort 语义**不适用** —— 本入口是显式人工动作，
  #   台账不可用即 fail-loud（回 rc≠0），不静默成功。
  if [ -n "$release_claim" ]; then
    python3 "${SKILL_DIR}/scripts/gk_write_claims.py" release \
      --repo "$(_gk_claims_repo)" --sid "$release_claim" --source "manual-release"
    return $?
  fi
  # ── 接收侧**纯检测**分支（2026-10-03，计划 DRAFT-8 §2.2/§2.3/T2）：`--receive-check <wt>` ─────────
  # 纪律：**只读**（不写 state / 不建 worktree / 不派发）；检测单源 = `scripts/gk_receive_check.py`
  #   （**禁第二实现**）；留痕 = 回包字段（`surface_review` / `skipped`）。判据 = 脚本自带的臂 ①–⑰。
  #   `--diff-filter` / rc 表 / 优先级链 / `hook_live_from` 派生全在该脚本内单点。
  # ⚠ DRAFT-16（P1 收口，6 臂 MoA）：补 `--main-repo` 透传 —— 原式**独缺**该参（同函数 L7919 已捕获
  #   `main_repo_arg`，:8132/:8270 亦有消费先例）⟹ `--receive-check --main-repo <外部仓>` 静默按技能仓判定
  #   （越界 rc=2 误报 / 错基线 clean）。`${main_repo_arg:-$SKILL_DIR}` 缺省逐字零回归。
  if [ -n "$receive_check_wt" ]; then
    python3 "${SKILL_DIR}/scripts/gk_receive_check.py" \
      --wt "$receive_check_wt" \
      --main-repo "${main_repo_arg:-$SKILL_DIR}" \
      --state-file "${state_override:-$STATE_FILE}" \
      --skill-dir "$SKILL_DIR"
    return $?
  fi
  # ── RC1 活动写面允许集写入面（2026-09-27，`ECC-D21AFB35DC1E`）──────────────────────────
  # `--bind|--unbind --path <dir>` = `state.worktrees_extra[]` 的**唯一写通路**
  #   （`state-patch --set-top worktrees_extra` 已被 `_TOP_DENY` fail-loud 拒绝 ⟹ 无旁路）。
  # 单一事实源 = `scripts/gk_state_patch.py worktrees-extra`（持 state_lock / 原子写 / 重算 checksum /
  #   **幂等** / `--dry-run` 零写盘）；本函数只做参数编排（**禁第二实现**）。
  # 落点**区外**、零保护区改动。`--bind` 要求路径**存在**（fail-loud，防写入无效允许集）；
  #   `--unbind` 允许悬空（目录可能已删，仍需解绑 —— 回退面）。
  if [ -n "$bind_mode" ]; then
    [ -n "$path_arg" ] || { echo '{"ok":false,"error":"--bind/--unbind 需要 --path <dir>","usage":"apply-worktree --bind|--unbind --path <dir> [--state P] [--dry-run]"}'; return 2; }
    if [ "$bind_mode" = "bind" ] && [ ! -d "$path_arg" ]; then
      echo "{\"ok\":false,\"error\":\"--bind 路径不存在（fail-loud，防写入无效允许集）\",\"path\":\"$path_arg\"}"; return 1
    fi
    local -a _we_args=()
    [ "$dry" = "1" ] && _we_args+=(--dry-run)
    python3 "$SKILL_DIR/scripts/gk_state_patch.py" worktrees-extra \
      "${state_override:-$STATE_FILE}" "$bind_mode" "$path_arg" "${_we_args[@]}" 2>>"$GK_DBG_LOG"
    return $?
  fi
  # ── 卫星片回收**生产入口**（T1，`ECC-2A298C57FF7E`）──────────────────────────
  #   动机：`gk_satellite.reclaim` 此前**零生产调用点**（回收器够不到片 = 幻影门，卫星计划 §4.2）。
  #   形态：`apply-worktree --satellite-reclaim [--apply]`；默认 dry-run（只报），`--apply` 真打墓碑。
  #   语义单源 = `gk_satellite.reclaim`（本层只做参数编排，**禁第二实现**）。
  if [ -n "$sat_reclaim" ]; then
    _sat_dry="1"; [ "$reclaim_apply" = "1" ] && _sat_dry="0"
    local -a _sat_rd=(); [ "$_sat_dry" = "1" ] && _sat_rd+=(--dry-run)
    python3 "$SKILL_DIR/scripts/gk_satellite.py" reclaim --state "${state_override:-$STATE_FILE}" "${_sat_rd[@]}" 2>>"${GK_DBG_LOG:-/dev/null}"
    return $?
  fi
  # ── 卫星存量片 TTL **回填**生产入口（T5，`ECC-F3AB40FD6CD7`）────────────────────
  #   动机：T2 前生产叶子 `ttl_s` 恒 0 ⟹ 存量片不进回收判据；一次性补齐（幂等）。
  if [ -n "$sat_backfill" ]; then
    _sat_dry="1"; [ "$reclaim_apply" = "1" ] && _sat_dry="0"
    local -a _sat_bf=(); [ "$_sat_dry" = "1" ] && _sat_bf+=(--dry-run)
    python3 "$SKILL_DIR/scripts/gk_satellite.py" backfill-ttl --state "${state_override:-$STATE_FILE}" "${_sat_bf[@]}" 2>>"${GK_DBG_LOG:-/dev/null}"
    return $?
  fi
  # ── ecc_findings 越线**强制 spillover**生产入口（B，`ECC-DB9EF1F34C0E`）──────────────
  #   动机：清墙原只能靠下一次 register 隐式触发（不可控/不可复现）。
  #   形态：`apply-worktree --finding-spill [--apply]`；默认 dry-run（只报），`--apply` 真移。
  #   语义单源 = `gk_finding.spillover_open`（本层只做参数编排，**禁第二实现**）。
  if [ -n "$finding_spill" ]; then
    _sp_dry="1"; [ "$reclaim_apply" = "1" ] && _sp_dry="0"
    GK_SP_DRY="$_sp_dry" STATE_FILE="${state_override:-$STATE_FILE}" \
      python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" spillover 2>>"${GK_DBG_LOG:-/dev/null}"
    return $?
  fi
  # ── worktree 根自解析（2026-09-25，用户裁定：「GATEKEEPER_WORKTREE_ROOT 在 code-fix 路径没有
  #   自解析（session 分支有）——显式补 env 解决」）──────────────────────────────────────
  # 背景：`gk_route_center.apply_worktree` 要求该 env **显式**给出（且须落在开发 worktree 根白名单内），
  #   缺则 fail-loud `GATEKEEPER_WORKTREE_ROOT 未设置`。实测（2026-09-25）**plain 与 `--code-fix`
  #   两条路径都撞**该错：原实现只在 `--session` 分支补自解析 —— 而 `--code-fix` 的建 worktree 走
  #   **子进程自调**（本函数 `bash gatekeeper-cli.sh apply-worktree …`）、plain 走本函数尾部
  #   ⟹ 那两条路径**没有**这层兜底（env 未设即整链失败）。故**上提到模式分派之前**：单点、
  #   `--session`/`--code-fix`/plain 三路共用；`--session` 分支内的副本**随之删除**（禁第二实现）。
  # 取值由 `scripts/gk_apply_worktree_cli.py route-root` 从**单点常量**派生（bash 侧不另抄字面量）；
  #   `gk_worktree_reclaim.py` 的自分支（`if not root`）用的正是**同一个**单源常量 ⟹ 回收链行为不变
  #   （其内部兜底退化为 no-op）。
  # 仅当 env 为空时才派生（显式传入优先；与设计 §6 开关表「省略 ⟹ 默认值」一致）。
  # ⚠ 载荷**不得在列 0 出现 `}`**：`test_agent_cli_wiring._code_fix_seg()` 按「下一个列 0 的 `}`」取
  #   函数边界（与长度解耦）⟹ 列 0 的花括号会把函数体**截断**，使既有 code-fix 臂全部假红。
  if [ -z "${GATEKEEPER_WORKTREE_ROOT:-}" ]; then
    GATEKEEPER_WORKTREE_ROOT=$(python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" route-root 2>>"$GK_DBG_LOG")
    export GATEKEEPER_WORKTREE_ROOT
  fi
  # ── --plan：计划驱动建树**单一入口**（2026-10-28，owner「把手动绕路的方式堵上」）──────────
  # 病象（实测）：计划建树**没有正路** —— `discover --plan` 只**探测**已有树（探不到回落
  #   `$SKILL_DIR`），`apply-worktree` 只有 finding / code-fix / bind 模式 ⟹ agent 手搓
  #   `git worktree add` 造野树（写面未登记 ⟹ Edit 被 Gate 3 拦）⟹ 又用 `cp` 搬文件。
  # 本模式 = 一条命令的正路，三段**全部委托既有单源**（禁第二实现）：
  #   ① 建/复用树 = `gk_route_center.py apply-worktree-plan`（白名单 + 委托 git-workflow + 后置校验）
  #   ② 域 state + plan 指针 = `cmd_discover --plan <p> --build-state`
  #   ③ 写面 = `state-patch set-top`（`state.worktree` / `branch`，state-patch 是单一出纳）
  if [ -n "$plan_arg" ]; then
    [ -n "$state_override" ] && { echo '{"ok":false,"error":"--plan 与 --state 互斥（域 state 由 discover --plan 绑定）"}'; return 2; }
    local _pj _pwt _pbr _pf _pst _pdet _pdj _prc
    local -a _pa=(apply-worktree-plan --plan-file "$plan_arg" \
                    --main-repo "${main_repo_arg:-$SKILL_DIR}" --skill-dir "$SKILL_DIR")
    [ "$dry" = "1" ] && _pa+=(--dry-run)
    _pj=$(python3 "$SKILL_DIR/scripts/gk_route_center.py" "${_pa[@]}" 2>>"$GK_DBG_LOG") \
      || { echo "{\"ok\":false,\"error\":\"PLAN_WORKTREE_FAILED\",\"detail\":${_pj:-null}}"; return 1; }
    if [ "$dry" = "1" ]; then printf '%s\n' "$_pj"; return 0; fi
    _pwt=$(printf '%s' "$_pj" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field worktree 2>/dev/null)
    _pbr=$(printf '%s' "$_pj" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field branch 2>/dev/null)
    _pf=$(printf '%s' "$_pj" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field plan_file 2>/dev/null)
    [ -z "$_pwt" ] && { echo "{\"ok\":false,\"error\":\"PLAN_WORKTREE_EMPTY\",\"detail\":${_pj:-null}}"; return 1; }
    # ② 域 state + plan 指针（单源 = cmd_discover；`--build-state` 建骨架，缺则 fail-closed）
    _pdj=$(cmd_discover --plan "$_pf" --build-state 2>>"$GK_DBG_LOG"); _prc=$?
    [ "$_prc" = "0" ] || { echo "{\"ok\":false,\"error\":\"PLAN_STATE_BIND_FAILED\",\"detail\":${_pdj:-null}}"; return 1; }
    _pst=$(printf '%s' "$_pdj" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field state_file 2>/dev/null)
    [ -z "$_pst" ] && _pst="$STATE_FILE"
    # discover 的**探测值**（诊断面：用来证明它按目录约定认回了同一棵树；不一致不静默）
    _pdet=$(json_val "$_pst" worktree "" 2>/dev/null || echo "")
    # ③ 写面钉死为本次建/复用的树（`state.worktree` 是 Gate 3/4 的强制面主值）
    python3 "$SKILL_DIR/scripts/gk_state_patch.py" set-top "$_pst" worktree "\"$_pwt\"" >>"$GK_DBG_LOG" 2>&1 || true
    [ -n "$_pbr" ] && python3 "$SKILL_DIR/scripts/gk_state_patch.py" set-top "$_pst" branch "\"$_pbr\"" >>"$GK_DBG_LOG" 2>&1 || true
    PJ="$_pj" PSTATE="$_pst" PDET="$_pdet" python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" plan-merge
    return 0
  fi
  # ── worktree 回收链（2026-09-24 用户裁定「同意建议」；finding `ECC-35AC08DA96F0`）──────
  # 语义：`--reclaim` = 扫描 → **归档前置** → 回收。**默认 dry-run**（只报告），`--apply` 才落刀
  #   （对齐本仓 `audit --apply` 惯例）。
  # 动机：创建侧已自动化（本函数 `--code-fix`/`--batch`/`--session` → git-workflow
  #   `worktree create`），回收侧却**无调用点** + `git worktree prune` 被判「删除动作须用户
  #   裁定」⟹ 只产不消（实测 15 个堆积）；且**无归档前置** ⟹ 未提交内容随目录静默丢失
  #   （mimo/xenv 遗留实证）。
  # 落点**区外**（与 code-fix/batch/session 同层）⟹ 零保护区改动；**禁第二实现** —— 扫描 /
  #   归档 / 回收的单一事实源 = `scripts/gk_worktree_reclaim.py`，本函数只做参数编排。
  if [ "$reclaim" = "1" ]; then
    local -a _rc_args=()
    [ "$reclaim_apply" = "1" ] && _rc_args+=(--apply)
    # 2026-10-06（finding `ECC-2B04C5B10464`）：`--all` = **显式授权全量回收**。core 侧对
    #   「`apply` 且无 `--path` 且未授权」**拒绝**（`FULL_SWEEP_REFUSED`，零写）—— 治「一次无
    #   `--path` 的 `--apply` 全量扫删掉在用会话 worktree」的事故面（白名单原为 opt-in）。
    [ "$reclaim_all" = "1" ] && export GK_RECLAIM_ALLOW_FULL=1
    # 2026-10-01（并发多会话现场）：**路径白名单**透传 —— 只回收 `--path` 指定路径，其余一律
    #   进 skipped（原语义 = 本仓**全部** agent worktree ⟹ `--apply` 会删掉**并发会话正在用的**
    #   工作区，实测 dry-run 同时列出 b3f2421a/73a535fe）。判据在脚本内（单一事实源），本行只编排；
    #   空 `--path` = 原全量语义（零回归）。
    [ -n "$path_arg" ] && _rc_args+=(--path "$path_arg")
    # B-2（2026-10-16，owner 裁定「回收含 worktree→分支」）：`--branches` 透传 —— 回收 worktree
    #   后按 `_is_merged_clean` 判据回收其分支（opt-in；未并入/有残留 ⟹ fail-closed 保留）。
    [ "$reclaim_branches" = "1" ] && _rc_args+=(--branches)
    if [ "$reclaim_tmp" = "1" ]; then
      # `/tmp` 子模式（2026-09-24 用户裁定「3 是不是更好」）：`/tmp` 是**全局共享**区，
      # 故**只清本仓可归因且超龄**的残留 —— 双条件判定与在用白名单都在脚本内（单一事实源）。
      python3 "$SKILL_DIR/scripts/gk_worktree_reclaim.py" tmp --days "$tmp_days" "${_rc_args[@]}" 2>>"$GK_DBG_LOG"
    elif [ "$reclaim_trash" = "1" ]; then
      # 隔离区子模式（2026-09-24 用户裁定「2」，finding `ECC-AAB70D5DCF11`）：回收区此前**只进
      #   不出** —— hook 把每条递归删除改写成「搬进 .gk-trash」，却全无清空通路 ⟹ 单调增长
      #   （实测 321M），并发会话的「删除」永远无法完成。本支就是缺的那一半：龄期门 +
      #   RESTORE-MAP 自洽校验（不自洽即拒删）都判在脚本内（单一事实源）。
      python3 "$SKILL_DIR/scripts/gk_worktree_reclaim.py" trash --repo "$SKILL_DIR" --days "$trash_days" "${_rc_args[@]}" 2>>"$GK_DBG_LOG"
    else
      # RC1-S4（2026-09-27）：同批清**悬空允许集** —— 把本域 state 交给回收链，
      #   在回收之后解绑 `worktrees_extra[]` 中目录已不存在的条目（单一写通路，见 reclaim 尾段）。
      python3 "$SKILL_DIR/scripts/gk_worktree_reclaim.py" --repo "$SKILL_DIR" --state "${state_override:-$STATE_FILE}" "${_rc_args[@]}" 2>>"$GK_DBG_LOG"
    fi
    return $?
  fi
  # ── P4 批量派发（2026-09-23 用户裁定「实装 P4」）──────────────────────────────
  # 语义：`--batch --finding a,b,…` = 一次申请 N 个 worktree + 回 **N 条可直接执行的 next**
  # （设计 §11.2 路线 A：不新注册命令、零保护区改动）。
  # **禁第二实现**：每个 fid 的族判定/建 worktree/窄任务重编译/额度追加**全部**复用本函数的
  # 单发路径（递归自调）—— 批量层只做「上限门 + 互斥门 + 回封套」。
  # 上限：k ≤ `GK_SUBAGENT_K_MAX`（默认 **2**；用户裁定「k=2 起步」——本机空闲内存 ~2.7 GB，
  # 并发 coder + pytest -n auto + Trae 已接近换页阈值，禁超发）。
  # 互斥门：同批各族 `allowed_paths` **两两 disjoint**（设计 §11.3 硬约束 1）——重叠即拒，
  # 否则两个 coder 会写同一文件、制造合并冲突。
  if [ "$batch" = "1" ]; then
    local _k_max="${GK_SUBAGENT_K_MAX:-2}" _fids=() _f _one _tf
    IFS=',' read -r -a _fids <<<"$fid"
    [ "${#_fids[@]}" -eq 0 ] || [ -z "${_fids[0]}" ] && { echo '{"ok":false,"error":"--batch 需要 --finding a,b,…"}'; return 2; }
    if [ "${#_fids[@]}" -gt "$_k_max" ]; then
      echo "{\"ok\":false,\"error\":\"batch 请求数超过并发上限\",\"requested\":${#_fids[@]},\"k_max\":$_k_max,\"hint\":\"用户裁定 k=2 起步（本机空闲内存 ~2.7G）；调 GK_SUBAGENT_K_MAX 前须先证内存充裕\"}"
      return 2
    fi
    _tf=$(mktemp)
    for _f in "${_fids[@]}"; do
      # ⚠ 2026-09-23 功能臂实测踩坑：原写 `${dry:+--dry-run}` —— `dry` 默认是字符串 `"0"`，
      #   `${var:+...}` 判的是**非空**而非真值 ⟹ **恒**展开 ⟹ 批量层永远走 dry-run、从不真派发
      #   （回包长相与族判定输出同形，不看 `worktree` 字段根本发现不了）。改用数组按值显式拼。
      local -a _sub=(cmd_apply_worktree --code-fix --finding "$_f" --state "${state_override:-$STATE_FILE}")
      [ -n "$family" ] && _sub+=(--family "$family")
      [ -n "$tier" ] && _sub+=(--tier "$tier")
      [ "$dry" = "1" ] && _sub+=(--dry-run)
      _one=$("${_sub[@]}")
      printf '%s\n' "$_one" >>"$_tf"
    done
    python3 - "$_tf" "$_k_max" <<'PY'
import json
import sys

rows, bad = [], []
with open(sys.argv[1], encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except ValueError:
            bad.append({"raw": line[:200]})
            continue
        (rows if o.get("ok") else bad).append(o)

# 互斥门（设计 §11.3-1）：同批各族 allowed_paths 两两 disjoint。
paths = {}
collide = []
for r in rows:
    for p in (r.get("allowed_paths") or []):
        if p in paths:
            collide.append({"path": p, "a": paths[p], "b": r.get("finding")})
        paths[p] = r.get("finding")
if collide:
    print(json.dumps({"ok": False, "error": "同批族间 allowed_paths 重叠（禁并发写同一文件）",
                      "collisions": collide, "dispatches": rows},
                     ensure_ascii=False))
    sys.exit(0)

print(json.dumps({
    "ok": not bad,
    "count": len(rows),
    "k_max": int(sys.argv[2]),
    "dispatches": rows,
    "failed": bad,
    "next_all": [r.get("next", "") for r in rows],
    "headsup": ("同批并发上限 %s；合并**必须串行**（设计 §11.3-3：单队列 git merge --no-ff，"
                "禁并发 merge；冲突即 git merge --abort + 该族回退派发）。"
                "CM1（设计 P）：**命中共享热点（如 gatekeeper-cli.sh）的族须单独先派**，"
                "勿与其它族同批（仅规程提示，无机械强制）" % sys.argv[2]),
}, ensure_ascii=False))
PY
    rm -f "$_tf"
    return 0
  fi
  # ── 会话级隔离（2026-09-23 用户裁定 + 2026-09-27 序④-A v5「甲」收敛）────────────────
  # 用户裁定：「为了加速我会并行跑几个会话，并行会话需要可以申请独立 worktree 独立域化 state
  #   且编辑预算不共享不冲突」。
  # 与 `--code-fix` 的**区别**（三条）：不绑 finding/族、**不**调 `_grant_node_budget`
  #   （不追加主节点额度）、不产出窄任务。只做「建/复用 worktree + bind 承接」，回 `state_file` 与 `next`。
  # 甲（**单 state + 计数分片，废副本**，owner 2026-09-27 裁定；组3 6 臂审查后落刀面闭合）：
  #   ❌ 不再 `cp` base state 到 worktree、不再对副本 `set-top` —— 会话 worktree **直接归主树 state**。
  #   ✅ 预算隔离改走**已实装**的 `edit_budget.sessions.<sid>`（`--session <name>` 仅人可读标签；
  #      计数分片由 hook 透传的真实 sid 自动生效）。
  #   ✅ 迁移步内**幂等归档**旧副本残留（有 diff 才入旁挂 / 无 diff 直接删）→ 再 bind 该 worktree。
  # 门禁侧为何**自动**生效（无需设 env）：`pre_tool_hook` 的 EDIT_TOOLS 面按**目标路径**解析
  #   state（`_resolve_state_by_target_path`），其 `_skill_roots` 已含
  #   `<SKILL_DIR>.parent.parent/worktrees/<SKILL_DIR.name>` ⟹ `agent/session/**` 归**主树** state
  #   （A1 实测）；且 `_run_cli` 已透传 STATE_FILE ⟹ Gate 4 同源。
  if [ -n "$session" ]; then
    case "$session" in
      *[!A-Za-z0-9._-]*|.*|*..*)
        echo "{\"ok\":false,\"error\":\"非法 session 名（仅 [A-Za-z0-9._-]，禁前导点 / '..' / 路径分隔符）\",\"got\":\"$session\"}"
        return 2 ;;
    esac
    local _s_st="${state_override:-$STATE_FILE}" _s_json _s_wt _s_branch _s_max
    # 源 state 兜底：从 **worktree** 里跑本命令时，`SKILL_DIR/.gatekeeper.state` 可能不存在
    # （worktree 无自带 state）⟹ 原样复制会得到空壳、`max=0` ⟹ 会话拿到**零预算**却看不出原因。
    # 故先退到默认 state；两者都缺 ⟹ **fail-loud**（绝不静默发一个 0 预算的会话）。
    [ -f "$_s_st" ] || _s_st="$_DEFAULT_STATE_FILE"
    [ -f "$_s_st" ] || { echo "{\"ok\":false,\"error\":\"源 state 不存在（无域化基线可复制）\",\"resolved\":\"$state_override$STATE_FILE\",\"default\":\"$_DEFAULT_STATE_FILE\"}"; return 1; }
    # 根默认（2026-09-25 上提）：`GATEKEEPER_WORKTREE_ROOT` 自解析已**上提到模式分派之前**
    # （本函数开头：`--session`/`--code-fix`/plain 三路共用同一单点）⟹ 此处**不再重复**
    # （禁第二实现）；显式传入的 env 仍优先（上提块只在空值时派生）。
    _s_json=$(python3 "$SKILL_DIR/scripts/gk_route_center.py" apply-worktree \
        --finding "session-${session}" --family session \
        --main-repo "${main_repo_arg:-$SKILL_DIR}" --skill-dir "$SKILL_DIR" 2>>"$GK_DBG_LOG") \
      || { echo "{\"ok\":false,\"error\":\"会话 worktree 申请失败\",\"raw\":${_s_json:-null}}"; return 1; }
    _s_wt=$(printf '%s' "$_s_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field worktree 2>/dev/null)
    _s_branch=$(printf '%s' "$_s_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field branch 2>/dev/null)
    [ -z "$_s_wt" ] && { echo "{\"ok\":false,\"error\":\"会话 worktree 未返回 worktree\",\"raw\":$_s_json}"; return 1; }
    # ① 幂等归档（A5 口径：有 diff 才入旁挂 / 无 diff 直接删）—— 旁挂命名族在 python 侧单源。
    #    helper = gk_state_patch.cmd_session_state_archive（可测；禁 bash 内联不可测实现）。
    python3 "$SKILL_DIR/scripts/gk_state_patch.py" session-state-archive \
        "$_s_st" "$_s_wt/.gatekeeper.state" --session "$session" --worktree "$_s_wt" >>"$GK_DBG_LOG" 2>&1 || true
    # ② bind 承接（唯一写通路）：把该 worktree 登记进**主 state** 的 worktrees_extra[]。
    python3 "$SKILL_DIR/scripts/gk_state_patch.py" worktrees-extra "$_s_st" bind "$_s_wt" >>"$GK_DBG_LOG" 2>&1 || true
    _s_max=$(STATE_FILE="$_s_st" python3 "$SKILL_DIR/scripts/gk_state_query.py" \
        --get gate_data.edit_budget.max --default 0 2>/dev/null)
    # 设计 D 登记点①（2026-09-30）：会话 worktree 派发成功 ⟹ 记一条 claim（paths = 该 worktree 目录）。
    _gk_claim_register "$session" "$_s_wt" "session" "session" "$_s_wt"
    echo "{\"ok\":true,\"session\":\"$session\",\"worktree\":\"$_s_wt\",\"branch\":\"$_s_branch\",\"state_file\":\"$_s_st\",\"bound_worktrees_extra\":true,\"budget\":{\"isolation\":\"per-session\",\"max\":${_s_max:-0}},\"note\":\"会话 worktree 归**主树 state**（hook 按 _resolve_state_by_target_path 自动治理，无需设 env）；编辑预算按会话分片 gate_data.edit_budget.sessions.<sid>（--session <name> 仅人可读标签）；CLI 命令请前置 STATE_FILE=$_s_st\",\"next\":\"STATE_FILE=$_s_st bash $SKILL_DIR/gatekeeper-cli.sh state\"}"
    return 0
  fi
  # ── T7 处置链闭环出口（--close-out，2026-10-16，finding ECC-21AB384F03A9 / C 计划 §3 T7）─────
  #   语义：coder 落刀后的**收口单入口** —— 串联 验收 → **关单** → gitnexus（先查旧才刷）→ 回收。
  #   各环复用单一源（**禁第二实现**）：`accept_reports`（含合并树 --full-regression，经 cmd_moa_aggregate）
  #     / `cmd_finding close` / `_gitnexus_refresh_if_stale` / `gk_worktree_reclaim`。
  #   **B-1 时序（2026-10-16，owner 裁定「accept → close → 回收」）**：关单**前移到回收之前** ——
  #     关单须在 worktree/分支**仍在**时完成（`commit:<sha>` 类证据分支回收后可能不可达 ⟹ `_accept_gate` 拒）。
  #     关单自身过机检硬门 `_accept_gate`（合法 verify source）+ `_guard_precheck` ⟹ **无需额外人工复核**。
  #     逃生舱 `GK_CLOSEOUT_NO_CLOSE=1` ⟹ 退回「只产 next」（与 HEAD 逐字一致，零回归）。
  #   落点区外、零新增 _CMD_REG。
  if [ "$closeout" = "1" ]; then
    local _co_st="${state_override:-$STATE_FILE}" _co_acc _co_x _co_rc _co_gx="skipped" _co_cl='{"auto_closed":false}'
    local -a _co_a=(--state "$_co_st" --accept --worktrees "$closeout_wts")
    [ -n "$accept_files" ] && _co_a+=(--accept-files "$accept_files")
    [ "$full_regression" = "1" ] && _co_a+=(--full-regression)
    _co_acc=$(cmd_moa_aggregate "${_co_a[@]}" 2>>"$GK_DBG_LOG") || _co_acc='{"ok":false,"error":"accept failed"}'
    # ── B-1：关单（**回收之前**）────────────────────────────────────────────────────────────────
    local _co_verdict
    _co_verdict=$(ACCEPT_JSON="$_co_acc" python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" closeout-verdict 2>>"$GK_DBG_LOG") || _co_verdict="unknown"
    if [ "${GK_CLOSEOUT_NO_CLOSE:-0}" != "1" ] && [ "$_co_verdict" = "pass" ] && [ -n "$fid" ]; then
      local _co_prev_st="${STATE_FILE:-}" _co_ok=true _cid
      # 真因 C 边界③（2026-11-02）：`_co_st` 可能来自 `--state` 参数（Windows 形态）⟹ 归一
      STATE_FILE="$(_gk_fwd "$_co_st")"
      for _cid in $(printf '%s' "$fid" | tr ',' ' '); do
        [ -n "$_cid" ] || continue
        cmd_finding close "$_cid" --verify-source tests:accept-pass >>"$GK_DBG_LOG" 2>&1 || _co_ok=false
      done
      STATE_FILE="$(_gk_fwd "$_co_prev_st")"
      _co_cl="{\"auto_closed\": $_co_ok, \"all_ok\": $_co_ok}"
    fi
    if [ "$no_gitnexus" != "1" ]; then
      # 守卫：`_gx_repo_dir_for_current` 对**不可归属**的 state（缺 target_repo/worktree 且候选目录全不命中）
      #   会 fail-loud 返回 1（空目录）；此时**不**调 helper（其 `gitnexus status` 探测默认超时 300s）
      #   ⟹ 空 ⟹ 如实 `skipped:no_repo`（未刷新，附因）。
      local _co_dir
      _co_dir=$(_gx_repo_dir_for_current 2>/dev/null) || _co_dir=""
      if [ -n "$_co_dir" ]; then
        _co_gx=$(_gitnexus_refresh_if_stale "$_co_dir" "close-out")
      else
        _co_gx="skipped:no_repo"
      fi
    fi
    _co_rc='{"skipped":true}'
    if [ "$no_reclaim" != "1" ]; then
      local -a _co_r=(--repo "$SKILL_DIR" --state "$_co_st")
      [ "$reclaim_apply" = "1" ] && _co_r+=(--apply)
      [ "$reclaim_branches" = "1" ] && _co_r+=(--branches)
      _co_rc=$(python3 "$SKILL_DIR/scripts/gk_worktree_reclaim.py" "${_co_r[@]}" 2>>"$GK_DBG_LOG") || _co_rc='{"ok":false,"error":"reclaim failed"}'
    fi
    _co_x=$(ACCEPT_JSON="$_co_acc" FIDS="$fid" CLOSE_JSON="$_co_cl" python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" closeout-next 2>>"$GK_DBG_LOG") || _co_x='{"verdict":"unknown"}'
    ACCEPT_JSON="$_co_acc" CLOSEOUT_JSON="$_co_x" RECLAIM_JSON="$_co_rc" GX_STATUS="$_co_gx" \
      python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" closeout-aggregate 2>>"$GK_DBG_LOG"
    return $?
  fi
  [ -z "$fid" ] && { echo '{"ok":false,"error":"apply-worktree <finding-id> required"}'; return 2; }
  if [ "$codefix" = "1" ]; then
    # 2026-10-30（环境坑加固）：`--state` 是**显式**参数面 —— 给出但为空 / 指向不存在文件时
    #   **禁**回落默认 state（回落 = 在错误台账上判族 / 派发，症状伪装成「族判定失败」）。
    #   现场：调用方 `--state "$ST"` 因外壳吞变量退化为 `--state ''` ⟹ 全程读写默认 state。
    if [ "$state_flag_given" = "1" ] && [ -z "$state_override" ]; then
      echo '{"ok":false,"error":"STATE_PATH_EMPTY","finding":"'"$fid"'","hint":"--state 显式给出但为空（常见成因：调用方变量未展开/被外壳吞掉）；拒绝回落默认 state"}'
      return 2
    fi
    if [ "$state_flag_given" = "1" ] && [ ! -f "$state_override" ]; then
      echo '{"ok":false,"error":"STATE_PATH_NOT_FOUND","finding":"'"$fid"'","state":"'"$state_override"'","hint":"--state 指向不存在的文件；拒绝回落默认 state（会读写错台账）"}'
      return 2
    fi
    local _st="${state_override:-$STATE_FILE}" _fam_json _fam_rc _fam_err _fam_tail
    # ── T6 下发点回环预检（2026-10-15，finding ECC-AC7004852D8C / C 计划 §3）────────────────────
    #   动机（owner 裁定）：「ecc 生成 → 下发」时间窗内会发生漂移（行锚漂移最常见；设计变更最麻烦），
    #   多会话高并发推进尤甚 ⟹ **强制回环**。判据单一源 = `gk_finding._guard_precheck`
    #   （register/verify/close/reopen/amend-title/archive 已内建，**唯独下发点缺失**）⟹ 本落点补齐。
    #   命中 ⟹ fail-loud 拒派发（在族判定 / 建 worktree **之前**，省白建）；逃生舱 = env GK_FINDING_PRECHECK=0。
    local _pc_json _pc_rc _pc_err _pc_tail
    # 2026-10-27（U3 归因）：预检失败分支原只回 `ECC_PRECHECK_DRIFT` + 结构化 precheck，
    #   **不带 `rc` / `stderr_tail`** ⟹ 预检内部非预期异常（如 state 形态非法引发的
    #   `AttributeError: 'str' object has no attribute 'get'`）真因只在 gk_dbg.log，
    #   与下方「族判定失败」分支同族病象（`ECC-786B05E46C61`）。此处按同构补齐：
    #   stderr 先落临时文件 ⟹ ① 追加 gk_dbg.log 留痕 ② 回包带 rc + JSON 转义 stderr_tail。
    _pc_err=$(mktemp)
    _pc_json=$(python3 "$SKILL_DIR/scripts/gk_finding.py" precheck "$_st" "$fid" 2>"$_pc_err"); _pc_rc=$?
    if [ "$_pc_rc" -ne 0 ]; then
      cat "$_pc_err" >>"$GK_DBG_LOG" 2>/dev/null || true
      _pc_tail=$(tail -c 300 "$_pc_err" 2>/dev/null | tr '\n' ' ')
      # 预检自身可能把非预期异常**压成结构化错误**（stdout 的 `error` / `error_class`），
      #   stderr 为空 ⟹ 此时从结构化回包拼真因（`<类名>: <文案>`），保证诊断面非空。
      if [ -z "$_pc_tail" ]; then
        _pc_tail=$(printf '%s' "$_pc_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" precheck-tail 2>/dev/null || true)
      fi
      rm -f "$_pc_err"
      echo "{\"ok\":false,\"error\":\"ECC_PRECHECK_DRIFT\",\"rc\":${_pc_rc:-1},\"finding\":\"$fid\",\"precheck\":${_pc_json:-null},\"stderr_tail\":$(printf '%s' "$_pc_tail" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-escape 2>/dev/null || echo '\"\"'),\"hint\":\"下发前回环预检命中漂移（判据单一源 gk_finding._guard_precheck）：先 amend-anchors/amend-title 修锚再派发；确需放行置 env GK_FINDING_PRECHECK=0\"}"
      return 1
    fi
    rm -f "$_pc_err"
    # 2026-09-23（**ECC-786B05E46C61 修复**）：原实现把 stderr 直接 2>>GK_DBG_LOG 后只回
    # `detail:${_fam_json:-null}` —— `detail` 取的是 **stdout**，而非 `FamilyError` 的
    # traceback 只落 stderr ⟹ 回包恒 `detail:null`，故障面看起来像「无族命中」（实测：
    # 族模板字面花括号触发 KeyError 时即此形态），真因只有翻 gk_dbg.log 才能看到。
    # 修法：stderr 先落临时文件，失败时 ① 追加进 gk_dbg.log（留痕不丢）② 回包带 `rc` +
    # JSON 转义的 `stderr_tail` ⟹ 诊断面**结构性可得**，不再依赖操作者记得翻日志。
    _fam_err=$(mktemp)
    _fam_json=$(python3 "$SKILL_DIR/scripts/gk_agent_family.py" resolve "$fid" \
        ${family:+--family "$family"} --state "$_st" 2>"$_fam_err")
    _fam_rc=$?
    if [ "$_fam_rc" -ne 0 ] || [ -z "$_fam_json" ]; then
      cat "$_fam_err" >>"$GK_DBG_LOG" 2>/dev/null || true
      _fam_tail=$(tail -c 300 "$_fam_err" 2>/dev/null | tr '\n' ' ')
      rm -f "$_fam_err"
      echo "{\"ok\":false,\"error\":\"族判定失败\",\"rc\":${_fam_rc:-1},\"detail\":${_fam_json:-null},\"stderr_tail\":$(printf '%s' "$_fam_tail" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-escape 2>/dev/null || echo '\"\"')}"
      return 1
    fi
    rm -f "$_fam_err"
    # 2026-10-15（加载安全网失效根因 · 手动 --family 旁路）：`--family F` 是**人工覆盖**，原实现无条件
    #   采信 ⟹ 与 finding 无关的族被静默采纳、coder 被派去做**无关落刀**（实测：强塞 F-ECC-PLAND，
    #   按 raw-车道 finding 却去 `scripts/gk_doc_align.py` 实现 `check_plan_landing_drift`）。修：显式
    #   `--family` 时**必须**与自动判定一致（无命中或判成别族 ⟹ `FAMILY_MISMATCH` fail-loud，禁静默）。
    if [ -n "$family" ]; then
      # 2026-11-03 ECC-CC0F58BCC0C8：自动判定失败不得吞成 auto=<none>。
      #   原 `resolve ... || true` + `json-field family 2>/dev/null || echo ""` 把
      #   FAMILY_ANCHOR_MISMATCH / 族判定失败 统一退化成 <none> ⟹ 真因不可见。
      local _auto_json _auto_fam _auto_rc _auto_err _auto_err_j
      _auto_json=$(python3 "$SKILL_DIR/scripts/gk_agent_family.py" resolve "$fid" --state "$_st" 2>>"$GK_DBG_LOG")
      _auto_rc=$?
      _auto_fam=$(printf '%s' "$_auto_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field family 2>>"$GK_DBG_LOG") || _auto_fam=""
      _auto_err=$(printf '%s' "$_auto_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field error 2>>"$GK_DBG_LOG") || _auto_err=""
      _auto_err_j=$(printf '%s' "$_auto_err" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-escape 2>>"$GK_DBG_LOG") || _auto_err_j=""
      [ -n "$_auto_err_j" ] || _auto_err_j='""'
      if [ "$_auto_fam" != "$family" ]; then
        echo "{\"ok\":false,\"error\":\"FAMILY_MISMATCH\",\"finding\":\"$fid\",\"given\":\"$family\",\"auto\":\"${_auto_fam:-<none>}\",\"auto_rc\":${_auto_rc:-0},\"auto_error\":${_auto_err_j},\"hint\":\"--family 是人工覆盖，必须与自动族判定一致；无命中须先登记 references/agent-families/F-*.json 且其 match.any 命中该 finding（禁强塞无关族）\"}"
        return 1
      fi
    fi
    # --dry-run：只回族判定 + 窄任务串（不申请 worktree、不派发）
    # 2026-09-23（L1 自动派发）：**显式标注不可派发**。dry-run 在**建 worktree 之前**编译
    # 窄任务 ⟹ `worktree:` 行为空 ⟹ 直接拿它派发会把落刀打回调用方 cwd（实测 = 主树，
    # 即 `ECC-D398E70B7E72` 事故的源头）。原实现只回裸 resolve 输出，全靠操作者记得这一条。
    if [ "$dry" = "1" ]; then
      printf '%s' "$_fam_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" codefix-dry
      return 0
    fi
    local _fam_name _wt_json _wt
    _fam_name=$(printf '%s' "$_fam_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field family 2>/dev/null)
    [ -z "$_fam_name" ] && { echo "{\"ok\":false,\"error\":\"族判定未返回 family\"}"; return 1; }
    _wt_json=$(bash "$SKILL_DIR/gatekeeper-cli.sh" apply-worktree "$fid" --family "$_fam_name" 2>>"$GK_DBG_LOG") \
        || { echo '{"ok":false,"error":"apply-worktree 失败"}'; return 1; }
    _wt=$(printf '%s' "$_wt_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field worktree 2>/dev/null)
    [ -z "$_wt" ] && { echo "{\"ok\":false,\"error\":\"apply-worktree 未返回 worktree\",\"raw\":$_wt_json}"; return 1; }
    # ── 2026-09-23（**ECC-089658238011**，B：per-coder 隔离闭环）────────────────────
    # 根因（P3 第 3 次真派发实测）：单一全局 `state.worktree` **同时**充当「技能自维护活动面」
    #   与「coder 落刀面」。写门禁（`pre_tool_hook` Gate 3 / CLI `pre_tool_check`）**只认**
    #   `state.worktree`，而它指向技能目录 ⟹ 派发侧只能把 worktree 塞进窄任务文本（软提示），
    #   coder 想写自己的 worktree 反被
    #   `BLOCK: Path not in active worktree. Target worktree: <技能目录>` 拒回，
    #   最终落刀进**主树**（实测主树 dirty 3→7，gatekeeper-cli.sh / gk_moa_aggregate.py 被改）。
    # 修法：为每个 coder 建**worktree 本地 state**（其 `worktree` = 本 agent worktree），派发串以
    #   `STATE_FILE=` 指向它 ⟹ 门禁面与落刀面**同源**；**主 state 一字不改**（原注释「不写
    #   state.worktree 以免污染主门禁取证面」的顾虑被**保留**，而非绕过）。
    # 落点 = `<wt>/.gatekeeper.state`：命中 `.gitignore` 的 `.gatekeeper.state*` ⟹ 运行期产物。
    local _wt_state="$_wt/.gatekeeper.state" _wt_branch
    _wt_branch=$(printf '%s' "$_wt_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field branch 2>/dev/null)
    cp "$_st" "$_wt_state" 2>/dev/null || printf '{"gate_data":{}}\n' >"$_wt_state"
    python3 "$SKILL_DIR/scripts/gk_state_patch.py" set-top "$_wt_state" worktree "\"$_wt\"" >>"$GK_DBG_LOG" 2>&1 || true
    [ -n "$_wt_branch" ] && python3 "$SKILL_DIR/scripts/gk_state_patch.py" set-top "$_wt_state" branch "\"$_wt_branch\"" >>"$GK_DBG_LOG" 2>&1 || true
    # 2026-09-23（**ECC-8BE02C8CBB5F 修复**）：建完 worktree 后**重新编译**窄任务并注入其路径。
    # 依据：`gk_agent_edit.apply_edit(worktree, rel_path, ...)` **以 worktree 为根**做路径拼接与
    # 逃逸预检 ⟹ 该路径是隔离的**唯一入口**。原实现在建 worktree **之前**编译窄任务、且调
    # `resolve` 时不带 `--worktree` ⟹ 窄任务串 `worktree:` 行**恒为空**（dry-run 实测
    # `worktree: \n`），subagent 只能退到 CLI cwd（技能主树）作业 —— worktree 白建、隔离失效。
    # ⚠ **不**改写 `state.worktree`：该字段被 advance/audit/self-check 等**主门禁视图**消费，
    #    改成 agent 的临时 worktree 会污染主门禁取证面 ⟹ 本 finding 初判的「不写 state」一项**撤销**。
    local _nt_json _nt
    _nt_json=$(python3 "$SKILL_DIR/scripts/gk_agent_family.py" resolve "$fid" \
        --family "$_fam_name" --state "$_st" --worktree "$_wt" 2>>"$GK_DBG_LOG")
    _nt=$(printf '%s' "${_nt_json:-}" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field narrow_task 2>/dev/null)
    [ -z "$_nt" ] && { echo "{\"ok\":false,\"error\":\"窄任务重编译失败\",\"raw\":${_nt_json:-null}}"; return 1; }
    # 档位：`cmd_monitor` 参数表**无** `--tier` 分支（只认 `SUBAGENT_TIER` env / 窄任务清单路由）
    # ⟹ 回显串改 env 前缀形态。`STATE_FILE=` 前缀把派发固定在与族判定**同一** state
    #（否则 `--state` 只影响族判定，派发侧 `cmd_monitor` 仍读活动 state ⟹ 两面不一致）。
    local _tier="${tier:-}"
    [ -z "$_tier" ] && _tier=$(printf '%s' "$_fam_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field tier 2>/dev/null)
    [ -z "$_tier" ] && _tier=3
    local _nt_esc
    _nt_esc=$(printf '%s' "$_nt" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-escape)
    # 2026-09-23（**L1 自动派发**，用户裁定「next 可直接执行」）：窄任务落 `--task-file`。
    # 原 `next` 串尾部是**字面量占位符** `<narrow-task>` ⟹ 必须人工把 5~10 KB 窄任务拼进
    # 命令行（引号/换行/中文标点全是雷；实测此步即事故高发点）。现由 CLI **瞬时自动填空**：
    # 窄任务（**已注入 worktree 的版本**）写入 state 旁路目录，`next` 串里只出现文件路径。
    # 目录用 `"$STATE_FILE".dispatch` —— 被 `.gitignore` 的 `.gatekeeper.state*` 覆盖
    # （目录名同前缀）⟹ 运行期产物，不入库。
    local _task_dir="${_st}.dispatch" _task_file
    mkdir -p "$_task_dir" 2>/dev/null || true
    _task_file="$_task_dir/${fid}.task.txt"
    printf '%s\n' "$_nt" >"$_task_file"
    # 落刀后**为主 agent 追加节点额度**（agent 池 additive，见 `_grant_node_budget`）。
    # 理由：coder 落刀**不**吃主 agent 的 `edit_budget`（F2：`GK_BUDGET_OVERRIDE=1` 声明
    # 「门禁探测非用户编辑」）⟹ 若不追加，主 agent 的「验收 + 收口 + 修 coder 修坏的地方」
    # 这段真实手改需求会被本节点 max 卡死（本会话实测撞顶 3 次）。
    _grant_node_budget "code-fix" "apply-worktree --code-fix 派发 ${fid}（族 ${_fam_name}）⟹ 为主 agent 追加节点额度"
    # 2026-09-23（**ECC-591BA1B918B4 修复**）：fix 档位工具面**不得**写死 `--tools edit`。
    # 原串只给 `edit` ⟹ agent 无 read/search 无法定位 `_log_block()` 内容、无 state 看配额
    # （实测 subagent turns=1，自述「本次审查无读/搜工具（仅 edit）」空手而归）。
    # 正确集合 = `subagent_runner._FIX_TIER_TOOLS`（fix 档位 = 只读档位 + edit，最小权限、
    # 不含任何其它位移能力）；两处**同串**，漂移由
    # `test_agent_cli_wiring.py::test_code_fix_tools_match_runner_fix_tier` 机检。
    local _fix_tools="read,read_repo,code_search,read_doc,json_extract,json_read,json_write,state,guard-edit,edit"
    # ECC-591BA1B918B4 配套（region 面）：`--role coder` —— 「能落刀就得能读它改的代码」。
    # 实测不带角色落 `default`（仅 evidence 区）⟹ agent 的 read 全被
    # `scope denied: gate/transition not in effective_regions={'evidence'}` 拒，拿不到待改
    # 函数逐字原文 ⟹ 零落刀。coder 的 region = evidence+transition+gate（见
    # subagent_runner.ROLE_ALLOWED_REGIONS；两处名单同集由
    # test_subagent_runner_extract::TestCliMonitorRoleWiring::test_role_whitelist_matches_runner 守护）。
    # 2026-09-23（P4）：回显补 `allowed_paths` —— 批量层要据此做「同批两两 disjoint」互斥门
    # （设计 §11.3-1）；单发路径自身不消费它，属**零成本**透出（数据已在 `_fam_json` 里）。
    local _ap_esc
    _ap_esc=$(printf '%s' "$_fam_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-field-raw allowed_paths '[]' 2>/dev/null || echo '[]')
    # 设计 D 登记点①（2026-09-30）：coder 派发成功 ⟹ 记一条 claim（paths = 族的 allowed_paths）。
    #   设计 P（CM1）：`headsup` 串同步补「命中共享热点的族须单独先派」（**只文案，不加机械强制**）。
    _gk_claim_register "$fid" "$_wt" "$_fam_name" "dispatch" \
      "$(printf '%s' "$_fam_json" | python3 "$SKILL_DIR/scripts/gk_apply_worktree_cli.py" json-list-join allowed_paths 2>/dev/null)"
    # 2026-10-17（W2A-P2 消融观测）：coder 也是 subagent ⟹ 纳入 `arm_obs`（落库段通用，不区分角色）。
    #   但要让它有**相位/打分**，须透传 `GK_STRIDE` / `GK_ARM_GOLD`；此处按**引用**透传
    #   （`\$` 保持字面量），由调用方 shell 求值 —— 避免把任意 gold JSON 内插进本 echo 的 JSON 串
    #   破坏结构。未设 ⟹ 空 ⟹ 下游具名 UNKNOWN（零回归）。
    echo "{\"ok\":true,\"finding\":\"$fid\",\"family\":\"$_fam_name\",\"worktree\":\"$_wt\",\"tier\":\"$_tier\",\"state_file\":\"$_wt_state\",\"allowed_paths\":$_ap_esc,\"narrow_task\":$_nt_esc,\"narrow_task_file\":\"$_task_file\",\"next\":\"STATE_FILE=$_wt_state SUBAGENT_TIER=$_tier GK_STRIDE=\$GK_STRIDE GK_ARM_GOLD=\$GK_ARM_GOLD bash $SKILL_DIR/gatekeeper-cli.sh monitor --subagent --role coder --tools $_fix_tools --task-file $_task_file\"}"
    return 0
  fi
  [ -z "$family" ] && { echo '{"ok":false,"error":"--family <F> required"}'; return 2; }
  python3 "$SKILL_DIR/scripts/gk_route_center.py" apply-worktree \
    --finding "$fid" --family "$family" --main-repo "${main_repo_arg:-$SKILL_DIR}" --skill-dir "$SKILL_DIR" \
    2>>"$GK_DBG_LOG" || echo '{"ok":false,"error":"apply-worktree failed"}'
}

# ─── cmd_plan_refinement: 计划质询统一入口（2026-08-26，轨道 B 确定性门禁）───
# 2026-08-27 全名化：命令名 plan-refine → plan-refinement（与 Skill 名统一，消除歧义投毒点）。
# 简写名 plan-refine 已移出 _CMD_REG → dispatch 未知命令拦截（天然投毒点关闭）。
# plan-refinement <target> [--task "自定义任务"] [--source-docs a,b,c] [--check-only]
#                 [--acknowledge-injected "A,B"] [--list-pending]
#                 [--adjudicate <id> --decision approve|fix|drop [--note "…"]]
# 统一入口：主 agent 不再"裸读 SKILL.md 跑质询"，一律经 CLI：
#   1. preflight 前置产物检查（计划存在 / META / 源文档 / subagent 点检 / **adjudicate 密封**（G4-c））
#   2. L2 入站数据管道节点（F-REV-21，2026-09-10）：--task 过 provenance/leading/poison/有界
#      检查 → 阻断则拒绝；通过则**只写入 gate_data.task_pipeline[] 的 pending 记录，不下发**
#   3. --adjudicate <id> --decision approve → 取回 full_task 交 cmd_monitor --subagent 下发
#   4. --check-only: 只跑 preflight，不启动 subagent（纯只读）
#
# 硬门禁依据（F-REV-21）：--task 是**入站内容**（下发给 subagent 的自然语言），R0.2/R0.3
# hook 是**出站命令门**——两者不在同一条链，故入站侧须独立设节点。事故形态：agent 把
# 「新增 MCP 兜底模式」写进 --task → subagent 去文档找 MCP → 报"全文无 MCP 字样" →
# 主 agent 反诬文档缺陷；同轮还把答案写成检查项（结论泄漏）→ 3 份高收敛非独立证据。
# 计划质询统一入口：preflight + L2 入站门 + 裁决下发（--check-only 纯只读）。
# F6（2026-10-15）：`--run` 链尾 —— enqueue 完成后接力：
#   ① 内部 `cmd_plan_refinement --adjudicate last-batch --decision approve`（**复用**统一入口，禁第二实现）；
#   ② 缺省 `cmd_moa_aggregate --plan <plan> --recent N`（N = 刚入队臂数，**禁手抄**；`--no-aggregate` opt-out）；
#   ③ 输出**单一 JSON 封套**（禁伪拼接 JSON —— 实现为一次性 `json.dumps`）。
# 2026-10-27（owner 令「加 chain 透传」）：`--run --chain` ⟹ 聚合按 `moa-aggregate --chain` 跑
#   （批锚自解析→聚合→ecc-finding→P/L/M→熔断只读→HTML→prose→integrity 全链）。**默认关**
#   （宿主裁定 2026-10-16：`--chain` 不挂 plan-refinement，两条血脉共用 moa-aggregate 一个载体）。
_plan_refine_run_tail() {
  local target="$1" sub_out="$2" n="$3" no_agg="$4" agg_out="$5" chain="$6"
  local _adj_json="null" _adj_rc=0 _adj_out
  _adj_out=$(cmd_plan_refinement "$target" --adjudicate last-batch --decision approve 2>>"$GK_DBG_LOG") || _adj_rc=$?
  [ -n "$_adj_out" ] && _adj_json="$_adj_out"
  local _agg_json="null" _agg_rc=0
  if [ "$no_agg" != "true" ]; then
    local _aargs=(--state "$STATE_FILE" --plan "$target" --recent "$n")
    [ "$chain" = "true" ] && _aargs+=(--chain)
    [ -n "$agg_out" ] && _aargs+=(--out "$agg_out")
    local _agg_out
    _agg_out=$(cmd_moa_aggregate "${_aargs[@]}" 2>>"$GK_DBG_LOG") || _agg_rc=$?
    [ -n "$_agg_out" ] && _agg_json="$_agg_out"
  fi
  # 2026-10-27（E2BIG 实测）：`_adj_json` 含 6 臂 full_task，直接作 argv 传 `python3 -c`
  # 触发 `Argument list too long`（本轮 plan-refinement --run 尾部即此崩，聚合封套整条丢失）。
  # 改走临时文件：python 侧只收路径，argv 恒定小串；出口用法（单次 json.dumps）不变。
  local _pt1 _pt2 _pt3
  _pt1=$(mktemp) && _pt2=$(mktemp) && _pt3=$(mktemp)
  # 守卫（2026-10-27）：装配失败 / 临时文件不可用 ⟹ **fail-loud**（JSON 封套 + rc=3）。
  # 原实现尾句是 `rm -f`，会把 python 的非零退出吞成 rc=0 + stdout 空 ⟹ 「跑成功但没结果」静默丢据。
  if [ -z "$_pt1" ] || [ -z "$_pt2" ] || [ -z "$_pt3" ]; then
    printf '{"ok":false,"run":true,"error":"TMPFILE_UNAVAILABLE","exit_code":3,"aggregate_rc":%s}\n' "${_agg_rc:-0}"
    return 3
  fi
  printf '%s' "$sub_out" >"$_pt1"; printf '%s' "$_adj_json" >"$_pt2"; printf '%s' "$_agg_json" >"$_pt3"
  local _env_out="" _env_rc=0
  _env_out=$(python3 -c '
import json, sys
def _j(x):
    x = open(x, encoding="utf-8").read().strip() if x else ""
    if not x:
        return None
    try:
        return json.loads(x)
    except Exception:
        return {"_raw": x[:4000]}
e, a, g = _j(sys.argv[1]), _j(sys.argv[2]), _j(sys.argv[3])
print(json.dumps({"ok": bool(e and e.get("ok") and a and a.get("ok")), "run": True,
                  "enqueue": e, "adjudicate": a, "aggregate": g,
                  "adjudicate_rc": int(sys.argv[4]), "aggregate_rc": int(sys.argv[5])},
                 ensure_ascii=False))
' "$_pt1" "$_pt2" "$_pt3" "$_adj_rc" "$_agg_rc") || _env_rc=$?
  rm -f "$_pt1" "$_pt2" "$_pt3"
  if [ "$_env_rc" -ne 0 ] || [ -z "$_env_out" ]; then
    printf '{"ok":false,"run":true,"error":"ENVELOPE_ASSEMBLY_FAILED","exit_code":3,"python_rc":%s,"adjudicate_rc":%s,"aggregate_rc":%s}\n' \
      "$_env_rc" "$_adj_rc" "$_agg_rc"
    return 3
  fi
  printf '%s\n' "$_env_out"
}

cmd_plan_refinement() {
  local target="" task="" source_docs="" check_only=false tier="" task_from_plan=false
  local adjudicate_id="" decision="" note="" list_pending=false acknowledge=""
  local arms_per_group=""
  # W2A-P2（2026-10-16）：消融腿 —— 逐臂长度平移基数 Δ（§6 `L_i = L + i·Δ`；缺省 0 = 同相控制臂）。
  local arm_delta_base=""
  # F6（2026-10-15）：`--run` 单入口（enqueue → adjudicate → 缺省 moa-aggregate）；旧用法逐字保留。
  local run_mode=false no_aggregate=false aggregate_out=""
  # 2026-10-27：`--chain` 透传（仅 `--run` 可用；默认关 ⟹ 零行为回归）。
  local chain_flag=false
  # W2A 金字塔（2026-10-18）：证据共享拓扑 —— L0=臂各自检索；L1/L2/L3=主 agent
  #   预取/构造证据集经 GK_WEB_EVIDENCE 注入（**非**跨进程实时通信）。
  local evidence_sharing="" web_evidence_file=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --task) task="${2:-}"; shift 2 2>/dev/null || shift ;;
      --task-from-plan) task_from_plan=true; shift ;;
      --source-docs) source_docs="${2:-}"; shift 2 2>/dev/null || shift ;;
      --check-only) check_only=true; shift ;;
      --tier) tier="${2:-}"; shift 2 2>/dev/null || shift ;;
      # T1（2026-10-05，n4）：每组臂数 K（入队条数 = 3×K；缺省 env GK_PLAN_REFINE_ARMS_PER_GROUP=2）。
      --arms-per-group) arms_per_group="${2:-}"; shift 2 2>/dev/null || shift ;;
      # W2A-P2（2026-10-16）：消融腿 —— 逐臂 Δ 基数（臂 i 落 `i·base`）；缺省 0（零回归）。
      --arm-delta-base) arm_delta_base="${2:-}"; shift 2 2>/dev/null || shift ;;
      # F6（2026-10-15）：单入口 `--run` + 聚合开关。
      # W2A 金字塔：证据共享层级 + 主 agent 预取证据文件（L1-L3 必填）。
      --evidence-sharing) evidence_sharing="${2:-}"; shift 2 2>/dev/null || shift ;;
      --web-evidence) web_evidence_file="${2:-}"; shift 2 2>/dev/null || shift ;;
      --run) run_mode=true; shift ;;
      --no-aggregate) no_aggregate=true; shift ;;
      --chain) chain_flag=true; shift ;;
      --aggregate-out) aggregate_out="${2:-}"; shift 2 2>/dev/null || shift ;;
      --adjudicate) adjudicate_id="${2:-}"; shift 2 2>/dev/null || shift ;;
      --decision) decision="${2:-}"; shift 2 2>/dev/null || shift ;;
      --note) note="${2:-}"; shift 2 2>/dev/null || shift ;;
      --list-pending) list_pending=true; shift ;;
      --acknowledge-injected) acknowledge="${2:-}"; shift 2 2>/dev/null || shift ;;
      *) target="$1"; shift ;;
    esac
  done

  # ── SAFE-TERMINATION GATE（2026-10-30；默认关 = 只显示不拦截）──
  #   触发面：`--no-aggregate` 会跳过链尾（MoA 聚合 → ECC finding → P/L/M）。
  #   默认（GK_SAFE_TERMINATION≠1）：stderr 显示 skipped，不改变行为；
  #   开启（GK_SAFE_TERMINATION=1）：直接拦截 rc=2，禁止静默跳步。
  if $no_aggregate; then
    local _st_skipped="moa-aggregate(ecc-finding/P-L-M)"
    printf '{"gate":"safe_termination","visible":true,"default":"off","skipped":"%s","hint":"--no-aggregate 只出 references；设 GK_SAFE_TERMINATION=1 可拦截"}\n' "$_st_skipped" >&2
    if [ "${GK_SAFE_TERMINATION:-0}" = "1" ]; then
      printf '{"ok":false,"error":"safe_termination_gate: --no-aggregate 被拦截（GK_SAFE_TERMINATION=1）","skipped":"%s","exit_code":2}\n' "$_st_skipped"
      exit 2
    fi
  fi

  # ── F6（2026-10-15）`--run` 前置门（fail-loud，禁静默；置于所有下游分支之前）──
  #   ① 聚合开关仅 `--run` 可用；② `--run` 与其它相位（裁决/只读检查/列队）互斥；③ `--run` 须有 task。
  if $no_aggregate || [ -n "$aggregate_out" ] || $chain_flag; then
    $run_mode || { echo '{"ok":false,"error":"--no-aggregate/--aggregate-out/--chain 仅与 --run 同用","exit_code":2}'; return 2; }
  fi
  if $run_mode && { [ -n "$adjudicate_id" ] || $check_only || $list_pending; }; then
    echo '{"ok":false,"error":"--run 与 --adjudicate/--check-only/--list-pending 互斥（不同相位）","exit_code":2}'; return 2
  fi
  if $run_mode && [ -z "$task" ] && ! $task_from_plan; then
    echo '{"ok":false,"error":"--run 需要 --task 或 --task-from-plan","exit_code":2}'; return 2
  fi

  # ── W2A 金字塔（2026-10-18）：证据共享拓扑校验/注入 ────────────────────────────
  #   口径（计划 §3/§5）：L0 = 臂各自 web_search/web_fetch；L1-L3 = 主 agent 预取/构造
  #   证据集，经 `GK_WEB_EVIDENCE` 注入到每个臂（同一份渲染契约 `gk_evidence.render_snippet`）。
  #   这是 **evidence-sharing topology**，不是跨进程实时通信；L1 scout / L2 curated /
  #   L3 union 的差别由 `--web-evidence` 文件的内容决定，CLI 只做确定性校验与下发。
  case "${evidence_sharing:-}" in
    ""|L0|L1|L2|L3) ;;
    *) echo '{"ok":false,"error":"--evidence-sharing 须为 L0|L1|L2|L3","exit_code":2}'; return 2 ;;
  esac
  if [ "$evidence_sharing" = "L0" ]; then
    unset GK_WEB_EVIDENCE
    unset GK_EVIDENCE_SHARING 2>/dev/null || true
  elif [ -n "$evidence_sharing" ]; then
    if [ -z "$web_evidence_file" ] || [ ! -f "$web_evidence_file" ]; then
      echo '{"ok":false,"error":"--evidence-sharing L1|L2|L3 需要 --web-evidence <json-file>","exit_code":2}'
      return 2
    fi
    local _wev_json
    # 2026-11-01（跨平台修复）：sys.path 原为 bash 插值 SKILL_DIR（裸美元形态进 python 字符串）
    #   ⟹ MSYS /c/ 路径不被 Windows python 识别（env 传递才转换）⟹ ModuleNotFoundError
    #   ⟹ 证据校验误报。改 env 单源（同 BARE 守卫修法）。
    _wev_json=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 -c "
import json, os, sys
sys.path.insert(0, os.path.join(os.environ['SKILL_DIR'], 'scripts'))
import gk_evidence as E
try:
    recs = E.loads(open(sys.argv[1], encoding='utf-8').read())
except Exception as e:
    sys.stderr.write('web-evidence parse: %s\n' % (e,)); raise SystemExit(2)
if not recs:
    sys.stderr.write('web-evidence empty\n'); raise SystemExit(2)
print(json.dumps(recs, ensure_ascii=False))
" "$web_evidence_file" 2>>"$GK_DBG_LOG") || {
      echo '{"ok":false,"error":"--web-evidence 不是合法非空证据数组","exit_code":2}'
      return 2
    }
    export GK_WEB_EVIDENCE="$_wev_json"
    export GK_EVIDENCE_SHARING="$evidence_sharing"
    echo "INFO[plan-refinement]: evidence-sharing=$evidence_sharing evidence_file=$web_evidence_file" >> "$GK_DBG_LOG"
  fi

  # ── state 路由（2026-10-17，`ECC-0DBB2CBB5461`）：**计划参数即路由源** ─────────────
  #   病象：本函数全程用 CLI **启动期** `$STATE_FILE`（未设 env `GK_PLAN_FILE` 时恒 base）⟹
  #     窄任务登记在域 state 却报 `narrow_tasks_insufficient`、批次写进 base（跨计划污染）；
  #     而 `GK_PLAN_FILE` 路由本身是通的 ⟹ 缺口只在「计划参数未参与路由」。
  #   修法：`<plan>` 声明 `META.state_domain` 且域 state 存在 ⟹ 本轮读/写/派发全部落域 state。
  #   单源：`gk_route_center.meta_state_domain`（读 META）+ `gk_finding.resolve_domain_state`
  #     （域路径解析，fail-closed，含双形态别名归一）。沿用既有 kill switch
  #     `GK_STATE_DOMAIN_ROUTE`（与 CLI 启动期 L4 1b 步同一开关）—— **不新造开关**。
  #   域声明但域 state 缺失 ⟹ **保留 base** + WARN 落 `GK_DBG_LOG`（不静默改道，也不打断
  #     尚未域化的存量计划；留痕可审计）。
  if [ -n "$target" ] && [ "${GK_STATE_DOMAIN_ROUTE:-1}" != "0" ]; then
    local _pr_plan="" _pr_dom_state=""
    for _c in "$target" "${SKILL_DIR}/docs/plans/${target}" "${SKILL_DIR}/docs/plans/${target}.md"; do
      [ -f "$_c" ] && { _pr_plan="$_c"; break; }
    done
    if [ -n "$_pr_plan" ]; then
      _pr_dom_state=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" STATE_FILE="$(_gk_py_path "$STATE_FILE")" PR_PLAN="$_pr_plan" \
        python3 -c "
import os, sys
sys.path.insert(0, os.path.join(os.environ['SKILL_DIR'], 'scripts'))
import gk_route_center as R
import gk_finding as F
plan = os.environ.get('PR_PLAN') or ''
dom = ''
try:
    dom = R.meta_state_domain(plan, os.environ['SKILL_DIR'])
except Exception as e:
    sys.stderr.write('WARN[pr-route] meta_state_domain: %s\n' % (e,))
if not dom:
    raise SystemExit(0)
try:
    print(F.resolve_domain_state(os.environ['STATE_FILE'], dom))
except Exception as e:
    sys.stderr.write('WARN[pr-route] resolve_domain_state(%s): %s\n' % (dom, e))
" 2>>"$GK_DBG_LOG" || true)
      if [ -n "$_pr_dom_state" ] && [ -f "$_pr_dom_state" ] && [ "$_pr_dom_state" != "$STATE_FILE" ]; then
        # 真因 C 边界④（2026-11-02）：`resolve_domain_state` 由 python 返回（可能是 `C:\…`）⟹ 归一
        STATE_FILE="$(_gk_fwd "$_pr_dom_state")"
        export STATE_FILE
        STATE_FILE_EXPLICIT=1
        export STATE_FILE_EXPLICIT
        # ── 环境一致性（2026-11-01 实锤，诊断域 skill.w2a-3v-diag 正规链现场）──
        #   病灶：本块只改 STATE_FILE（域落点），未同步 GK_PLAN_FILE（域**来源**）⟹
        #   下游取数中枢 `_conv_state_path` 的 `GK_PLAN_FILE="${GK_PLAN_FILE:-$PLAN_FILE}"`
        #   仍取 CLI 启动期默认 PLAN_FILE（L565 硬编码，文件常已不存在）⟹ resolve_plan
        #   走 5 层金字塔搜索按 mtime **命中撞库计划**（现场 2026-10-31-standard-t2-t6-roadmap）
        #   ⟹ 派生 domain ≠ 已路由域 state ⟹ FINDING_DOMAIN_MISMATCH → STATE_DOMAIN_MISMATCH
        #   fail-closed（T4 收敛门 L9815 等正规链必挂；手工复现传对 GK_PLAN_FILE 恒绿）。
        #   修法：域落点与域来源**同源**——路由成功即 export 已解析的真实计划路径
        #   `_pr_plan`（非 target 裸名，防再次金字塔撞库）。仅本成功支生效 ⟹
        #   「域声明但域 state 缺失 ⟹ 保留 base」的存量语义零变化。
        GK_PLAN_FILE="$_pr_plan"
        export GK_PLAN_FILE
        PLAN_FILE="$_pr_plan"
        export PLAN_FILE
        echo "INFO[plan-refinement]: state_domain route -> $STATE_FILE (plan=$_pr_plan)" >> "$GK_DBG_LOG"
      fi
    fi
  fi

  # ── Preflight: 定位计划文档（WSL 形态）──
  #   2026-10-21（`ECC-81883BA000AB`）：本块从入队段**前移**到队列/裁决段之前 ——
  #   窄任务 sidecar（`<plan>.narrow.json`）必须在**入队**（submit）与**派发**（fan-out）
  #   两个消费点都可见；若留在入队段，`--adjudicate last-batch` 的 fan-out 拿不到 sidecar
  #   ⟹ 退回读 state 全局清单（跨计划污染）。
  # 2026-10-05（计划质询加载安全网修正）：逐候选**留痕** `_plan_tried`，未知路径时回显
  #   「已试候选」清单（引导清晰 + 拦截高效），并让阻断面**只**给可操作指引（消噪音摩擦）。
  local plan_path="" _plan_tried=""
  _plan_try() { _plan_tried="${_plan_tried}${_plan_tried:+,}$1"; [ -z "$plan_path" ] && [ -f "$1" ] && plan_path="$1"; return 0; }
  _plan_try "$target"
  _plan_try "${SKILL_DIR}/docs/plans/${target}"
  _plan_try "${SKILL_DIR}/docs/plans/${target}.md"
  # 2026-10-15（C 计划 §8·worktree 漂移）：方案 A 已定「技能仓的 git worktree 与主树是**同一治理对象**」，
  #   但**未合并**的计划只存在于 linked worktree ⟹ 从主树调 CLI 时上述候选恒空（实测：同一条
  #   `plan-refinement <名>` 在主树 `preflight blocked: plan_doc/meta missing` / 在 worktree 命中 ——
  #   **同一命令随 cwd 分裂**）。补 **worktree 候选**：
  #   单源 = `git worktree list --porcelain`（git 权威视图，非第二份路径推算）；
  #   `GK_PLAN_WORKTREE_ROOTS`（冒号分隔）= 测试/隔离注入（对齐 `STATE_FILE` 的 env 覆盖惯例）。
  local _wt_roots="${GK_PLAN_WORKTREE_ROOTS:-}" _wt _old_ifs
  if [ -z "$_wt_roots" ]; then
    _wt_roots=$(git -C "$SKILL_DIR" worktree list --porcelain 2>/dev/null \
                  | awk '/^worktree /{print substr($0,10)}' | tr '\n' ':')
  fi
  _old_ifs="$IFS"; IFS=':'
  for _wt in $_wt_roots; do
    [ -n "$_wt" ] || continue
    [ "$_wt" = "$SKILL_DIR" ] && continue   # 去重（SKILL_DIR 候选已在前 2 条）
    _plan_try "${_wt}/docs/plans/${target}"
    _plan_try "${_wt}/docs/plans/${target}.md"
  done
  IFS="$_old_ifs"
  _plan_try "${MAIN_REPO_WSL}/docs/plans/${target}"
  _plan_try "${MAIN_REPO_WSL}/docs/plans/${target}.md"
  # 窄任务 sidecar（`ECC-81883BA000AB`）：`plan.md` ⟹ `plan.narrow.json`（也接受 `plan.md.narrow.json`）。
  # 存在 ⟹ 入队/派发都**只**读它；不存在 ⟹ 按 plan 归属过滤 state 全局清单（未声明归属即排除）。
  local _narrow_sidecar=""
  if [ -n "$plan_path" ]; then
    if [ -f "${plan_path%.md}.narrow.json" ]; then
      _narrow_sidecar="${plan_path%.md}.narrow.json"
    elif [ -f "${plan_path}.narrow.json" ]; then
      _narrow_sidecar="${plan_path}.narrow.json"
    fi
  fi

  # ── L2 管道节点：队列视图（纯只读）──
  if $list_pending; then
    python3 "${SKILL_DIR}/scripts/gk_task_gate.py" list --state "$STATE_FILE" 2>>"$GK_DBG_LOG"
    return $?
  fi

  # ── L2 管道节点：裁决出口（唯一的下发路径）──
  if [ -n "$adjudicate_id" ]; then
    case "$decision" in
      approve|fix|drop) ;;
      *) echo '{"ok":false,"error":"--adjudicate 须配 --decision approve|fix|drop"}'; return 1 ;;
    esac
    # 2026-11-01（实测，owner 质问「链是不是白做了」）：**相位级 --adjudicate approve 会跳过链尾**
    #   （`_plan_refine_run_tail` 只在 `--run` 分支调用 ⟹ moa-aggregate → ecc-finding → P/L/M 全不跑，
    #   而 stdout 只回一句 dispatched，调用方无从得知）。与 `--no-aggregate` 同族「静默跳步」，
    #   故沿用**同一可见性闸**（GK_SAFE_TERMINATION=1 可拦截）：默认 stderr 显式列出 skipped。
    if [ "$decision" = "approve" ] && ! $run_mode && ! $no_aggregate; then
      if [ "${GK_SAFE_TERMINATION:-0}" = "1" ]; then
        echo '{"ok":false,"error":"safe_termination_gate: 相位级 --adjudicate approve 会跳过聚合链尾","skipped":"moa-aggregate(ecc-finding/P-L-M)","exit_code":2,"fix":"改用 plan-refinement <plan> --run（单入口：enqueue→adjudicate→aggregate）"}'
        return 2
      fi
      printf '{"gate":"safe_termination","visible":true,"default":"off","skipped":"moa-aggregate(ecc-finding/P-L-M)","reason":"phase-level --adjudicate approve（非 --run）","fix":"补跑 moa-aggregate 或下次用 --run"}\n' >&2
    fi
    # T9（2026-10-05，n4）：批级消解出口 —— `--adjudicate last-batch` 取整批**显式 id**
    #   （M1：原只取队尾单条）；旧 `last`/显式 id 逐字不变（零回归，§4-R9）。
    local _adj_ids="" _adj_prep_id="$adjudicate_id"
    if [ "$adjudicate_id" = "last-batch" ]; then
      _adj_ids=$(python3 "${SKILL_DIR}/scripts/gk_task_gate.py" resolve-ids \
        --state "$STATE_FILE" --id last-batch 2>>"$GK_DBG_LOG" | python3 -c '
import sys, json
try:
    print("\n".join(json.load(sys.stdin).get("ids", [])))
except Exception:
    pass
' 2>>"$GK_DBG_LOG" | tr -d '\r') || true   # CRLF 净化（2026-11-01）：Windows python print=\r\n，$() 不剥 \r ⟹ id 尾粘 \r ⟹ 逐臂 prepare 必挂
      if [ -z "$_adj_ids" ]; then
        echo '{"ok":false,"error":"no_pending_batch","detail":"last-batch 未解析到任何 pending（先按 3×K 入队）"}'
        return 1
      fi
      _adj_prep_id=$(printf '%s\n' "$_adj_ids" | tail -1)
    fi
    local _adj_rc=0 _adj_out=""
    # F-REV-22（2026-09-11 用户定案）：approve **先校验后下发、下发成功才落状态**。
    # 原实现先写 status=approved 再下发 → 下发的 review-channel preflight 一挡
    # （如 CONTEXT_STALE_OR_UNSIGNED），记录已被消费成 approved 却从未派发（滞留）。
    # 现 approve 走 --prepare（只校验+返回载荷，不落盘）→ 下发成功才 commit 定格；
    # 失败则记录留 pending，修好可重试或 --decision drop。
    local _prep=""
    [ "$decision" = "approve" ] && _prep="--prepare"
    _adj_out=$(python3 "${SKILL_DIR}/scripts/gk_task_gate.py" adjudicate \
      --state "$STATE_FILE" --id "$_adj_prep_id" --decision "$decision" --note "$note" $_prep \
      2>>"$GK_DBG_LOG") || _adj_rc=$?
    # F-REV-20 禁静默失败：解析/写盘失败原会变成"看起来没记录"→ 必须显式拒绝
    # ECC-<pipe-ctx>（2026-09-27 实测）：原式在 rc≠0 时**丢弃** `gk_task_gate adjudicate`
    #   已产出的**富错误**（`phase_mismatch` + record/current context + 可操作 `hint`），
    #   只回一句「记录未落地」⟹ 现场无从判断（实测：会话指针漂移到 isolate state 致
    #   `project_type standing→analysis`，rc=1 无提示）。修法 = **失败时**非空输出原样透传
    #   （它本身已是 {"ok":false,"error":…} 契约），仅**空输出**回兜底；approve 成功仍走下发。
    if [ "$_adj_rc" != "0" ]; then
      if [ -n "$_adj_out" ]; then
        printf '%s\n' "$_adj_out"
      else
        echo "{\"ok\":false,\"error\":\"adjudicate_failed\",\"rc\":${_adj_rc:-1},\"detail\":\"gk_task_gate adjudicate **无输出**（环境/参数错），记录未落地，禁止当已裁决\"}"
      fi
      return "${_adj_rc:-1}"
    fi
    [ -z "$_adj_out" ] && { echo '{"ok":false,"error":"adjudicate_failed","rc":0,"detail":"gk_task_gate adjudicate rc=0 但**无输出**（异常），记录未落地"}'; return 1; }
    if [ "$decision" != "approve" ]; then
      printf '%s\n' "$_adj_out"
      return 0
    fi
    # approve → 取回 full_task + tier 下发（唯一出口）；成功后才 commit 定格（F-REV-22）
    local _ft="" _tier="" _ft_rc=0
    _ft=$(ADJ_OUT="$_adj_out" python3 "$SKILL_DIR/scripts/gk_json_utils.py" field full_task --env ADJ_OUT --default '' 2>>"$GK_DBG_LOG") || _ft_rc=$?
    if [ "$_ft_rc" != "0" ] || [ -z "$_ft" ]; then
      echo '{"ok":false,"error":"adjudicate_prepare_but_full_task_unreadable","detail":"记录保持 pending（未下发）"}'
      return 1
    fi
    _tier=$(ADJ_OUT="$_adj_out" python3 "$SKILL_DIR/scripts/gk_json_utils.py" field tier --env ADJ_OUT --default-falsy '' 2>>"$GK_DBG_LOG" | tr -d '\r') || true   # CRLF 净化（2026-11-01）：tier 带 \r 污染 SUBAGENT_TIER 下游路由
    [ -n "$_tier" ] && export SUBAGENT_TIER="$_tier"
    # 角色显式传（不再依赖 task 子串推断；子串推断保留为无 --role 时的兜底）
    # ── T2（2026-10-05，n4 组 fan-out）：按批下发 3×K 臂 ─────────────────────────
    #   批级共享 `--batch-narrow`（= 单一 `--task` 逐字相同 ⟹ 同一 batch_id，消 R3'' 分叉）
    #   + 逐臂 `--arm-group G#`；`--batch-plan`/`--batch-epoch` 亦一次批内一致。
    #   回退开关 `GK_PLAN_REFINE_GROUP=0` ⟹ 旧单臂（零回归）；K=`GK_PLAN_REFINE_ARMS_PER_GROUP`（默认 2）。
    #   ⚠ 逐臂 rc 经**文件**回传（`&`+`wait` 取不到各臂 rc；且 N9 禁消费端并流）。
    #   ⚠ T1（入队 3×K pending）/ T9（batch 级 resolve）为**后续**任务；本步先通 fan-out 面。
    local _disp_rc=0 _arm_reason=""
    if [ "${GK_PLAN_REFINE_GROUP:-1}" = "0" ]; then
      cmd_monitor --subagent "$_ft" --role plan-refinement
      _disp_rc=$?
    else
      # T1 消费端（2026-10-05）：**逐臂取各自 full_task**（入队时已按 3 组×K 嵌入组任务，
      #   见 `gk_task_gate.submit --expand-groups`）；组别按**批内入队序** index//K 还原
      #   （前 K=G1 / 次 K=G2 / 末 K=G3，与 narrow_tasks[] 顺序映射同源）。
      #   原实现 6 臂共用单条 `_ft` ⟹ 组别只是标签、各臂跑**同一**窄任务（流程 bug 现场，
      #   即 `gate_data.narrow_tasks[]` 悬空：登记了却无消费方）。
      #   `--batch-narrow` 仍**全批共享**（disp-plan §3：3 组窄任务并集），保 batch_id 不分叉。
      local _K="${GK_PLAN_REFINE_ARMS_PER_GROUP:-2}"
      # W2A-P2（2026-10-16）：消融腿 —— 逐臂长度平移基数（§6 `L_i = L + i·Δ`；0 = 同相控制臂）。
      local _delta_base="${arm_delta_base:-0}"
      local _bplan="" _bnarrow="" _bepoch _tmp_arm_dir
      _bepoch="$(date +%s)"
      # 2026-10-08（ECC-0A7EBDA60149 邻接·bash_static P8 收口）：变量名落 `$_tmp` 家族
      #   —— 与 `gk_bash_static_scan._P8_TMP_EXEMPT`（CLI 内部临时目录白名单）同源；本目录确为
      #   `mktemp -d` 产物 ⟹ 命名即声明意图，非「改名绕过扫描器」（原 `$_arm_dir` 不匹配白名单
      #   被误报为裸 `rm -rf`；扫描器**语义不变**，仅变量名对齐既有豁免口径）。
      _tmp_arm_dir="$(mktemp -d "${TMPDIR:-/tmp}/gkpfa.XXXXXX")"
      local -a _arm_fts=() _arm_grps=()
      local _arm_id_list="$_adj_ids"
      [ -z "$_arm_id_list" ] && _arm_id_list="$_adj_prep_id"
      local _aid _idx=0 _aout _aft
      for _aid in $_arm_id_list; do
        _aout=$(python3 "${SKILL_DIR}/scripts/gk_task_gate.py" adjudicate \
          --state "$STATE_FILE" --id "$_aid" --decision approve --note "$note" --prepare \
          2>>"$GK_DBG_LOG") || { echo "{\"ok\":false,\"error\":\"arm_prepare_failed\",\"id\":\"$_aid\"}"; rm -rf "$_tmp_arm_dir"; return 1; }
        _aft=$(ADJ_OUT="$_aout" python3 -c 'import json,os;print(json.loads(os.environ.get("ADJ_OUT","") or "{}").get("full_task",""))' 2>>"$GK_DBG_LOG" | tr -d '\r') || _aft=""   # CRLF 净化（2026-11-01）：full_task 尾粘 \r ⟹ task_in_pipeline 精确匹配恒失败 ⟹ BARE_PLAN_REFINEMENT（同段 _bplan/_ag/_bnarrow 已净化，本处漏网）
        if [ -z "$_aft" ]; then
          echo "{\"ok\":false,\"error\":\"arm_full_task_unreadable\",\"id\":\"$_aid\"}"
          rm -rf "$_tmp_arm_dir"; return 1
        fi
        [ -z "$_bplan" ] && _bplan=$(ADJ_OUT="$_aout" python3 -c 'import json,os;print(str(((json.loads(os.environ.get("ADJ_OUT","") or "{}").get("record") or {}).get("target") or "")))' 2>>"$GK_DBG_LOG" | tr -d '\r')   # CRLF 净化（2026-11-01）：batch-plan 带 \r ⟹ plan 归属错配
        _arm_fts+=("$_aft")
        # 组别**单源** = full_task 内嵌标记（入队时由 `_group_expand_records` 写入）。
        # 原 `G$((_idx/_K+1))` 假设 `_adj_ids` 与入队序一致；L0 实跑中 n3 因此被标成 G2
        # ⟹ 仅在没有标记（无清单/显式回退）时才用下标兜底。
        _ag=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" FULL_TASK="$_aft" python3 -c 'import os,sys
sys.path.insert(0, os.path.join(os.environ["SKILL_DIR"], "scripts"))
from gk_task_gate import group_label_of_full_task
print(group_label_of_full_task(os.environ.get("FULL_TASK", "")))' 2>>"$GK_DBG_LOG" | tr -d '\r') || _ag=""   # CRLF 净化（2026-11-01）：G1\r 污染 --arm-group/临时文件名
        _arm_grps+=("${_ag:-G$(( _idx / _K + 1 ))}")
        _idx=$((_idx + 1))
      done
      # batch-narrow = 3 组窄任务**并集**（全批逐字相同 ⟹ 同一 batch_id；disp-plan §3）
      # 2026-10-21（`ECC-81883BA000AB`）：与入队端**同源** —— sidecar 优先；无 sidecar 按 plan 归属过滤。
      _bnarrow=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" GK_K="$_K" GK_NARROW_SIDECAR="$_narrow_sidecar" \
        GK_NARROW_SCOPE="$plan_path" SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 -c '
import json,os,sys
sys.path.insert(0, os.path.join(os.environ["SKILL_DIR"], "scripts"))
import gk_task_gate as G
try:
    sc = os.environ.get("GK_NARROW_SIDECAR") or ""
    if sc:
        nt = G.load_narrow_tasks_file(sc)
    else:
        d = json.load(open(os.environ["STATE_FILE"], encoding="utf-8"))
        nt = G.narrow_tasks_for_scope(d.get("gate_data", {}).get("narrow_tasks") or [],
                                      os.environ.get("GK_NARROW_SCOPE") or "")
    nt = nt[:3*int(os.environ.get("GK_K","2"))]
    print(",".join(str(e.get("task") or e.get("name") or "") for e in nt if isinstance(e,dict)))
except Exception:
    print("")
' 2>>"$GK_DBG_LOG" | tr -d '\r') || _bnarrow=""   # CRLF 净化（2026-11-01）：\r 混入共享 --batch-narrow ⟹ 批指纹分叉/臂题面污染
      local _i _fa
      for _i in "${!_arm_fts[@]}"; do
        _fa="${_tmp_arm_dir}/${_arm_grps[$_i]}-${_i}"
        ( cmd_monitor --subagent "${_arm_fts[$_i]}" --role plan-refinement \
            --batch-plan "$_bplan" --batch-narrow "$_bnarrow" --batch-epoch "$_bepoch" \
            --arm-group "${_arm_grps[$_i]}" --arm-delta "$(( _i * _delta_base ))" \
            >"${_fa}.out" 2>"${_fa}.err"; printf '%s' "$?" >"${_fa}.rc" ) &
      done
      wait
      local _rcf _arm_rc
      for _rcf in "${_tmp_arm_dir}"/*.rc; do
        [ -f "$_rcf" ] || continue
        _arm_rc="$(cat "$_rcf")"
        if [ "$_arm_rc" != "0" ]; then
          _disp_rc="$_arm_rc"
          # 叠盾（2026-10-07，ECC-9FD1BEB74F82）：真因须**可达** —— 在 rm -rf 之前取逐臂 stderr/stdout 摘要
          _arm_reason="$( { cat "${_rcf%.rc}.err" 2>/dev/null; cat "${_rcf%.rc}.out" 2>/dev/null; } | tail -c 600 | tr '\n' ' ' | tr -d '"\\' )"
          break
        fi
      done
      rm -rf "$_tmp_arm_dir"
    fi
    if [ "$_disp_rc" != "0" ]; then
      echo "{\"ok\":false,\"error\":\"dispatch_blocked\",\"id\":\"$adjudicate_id\",\"rc\":${_disp_rc:-1},\"reason\":\"${_arm_reason}\",\"detail\":\"下发未成功 → 记录保持 pending（修复后重试，或 --decision drop）\"}"
      return "$_disp_rc"
    fi
    # ECC-<pipe-ctx>（2026-09-27 实测）：原 `>/dev/null` 把 `gk_task_gate commit` 的真因
    #   （如 state 漂移 ⟹ `no pending task`）**丢弃** ⟹ 只剩「已派发但未定格」的笼统警告。
    #   修法 = 捕获 stdout 并作为 JSON 字符串字段回传（真因可达；双份派发风险可判）。
    local _cmt_rc=0 _cmt_out="" _cmt_out_json='""'
    # T9（2026-10-05，n4）：批 ⟹ 逐臂**显式 id** 定格（R7/R10：每 id 恰消费一次、无僵尸）；
    #   单 ⟹ 原单条（`last`/显式 id 逐字不变，零回归）。
    local _cid _cmt_ids="$adjudicate_id"
    [ -n "$_adj_ids" ] && _cmt_ids="$_adj_ids"
    for _cid in $_cmt_ids; do
      _cmt_rc=0 _cmt_out=""
      _cmt_out=$(python3 "${SKILL_DIR}/scripts/gk_task_gate.py" commit \
        --state "$STATE_FILE" --id "$_cid" --decision approve --note "$note" \
        2>>"$GK_DBG_LOG") || _cmt_rc=$?
      [ -n "$_cmt_out" ] && _cmt_out_json=$(printf '%s' "$_cmt_out" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""')
      if [ "$_cmt_rc" != "0" ]; then
        echo "{\"ok\":false,\"warning\":\"dispatch_ok_but_commit_failed\",\"id\":\"$_cid\",\"rc\":${_cmt_rc:-1},\"commit_out\":${_cmt_out_json},\"detail\":\"subagent 已派发但记录未定格 → 有重复派发风险，请核对 task_pipeline\"}"
        return 1
      fi
    done
    # 2026-10-08（ECC-64F4D0BF14F1）：成功路径原**静默**（零 stdout）⟹ 结果不可观测
    #   （实测被误判为「静默失败 / fail-open」）。失败路径已有 `dispatch_blocked` ⟹ 成功侧**对称补回执**。
    echo "{\"ok\":true,\"dispatched\":\"$adjudicate_id\",\"mode\":\"batch\"}"
    return 0
  fi

  [ -z "$target" ] && { echo '{"ok":false,"error":"plan-refinement <target> required — 计划文档路径或名称"}'; return 1; }
  # 2026-08-27 梯度路由：--tier 指定档位（1-4）→ SUBAGENT_TIER 透传 subagent_runner；
  # 未指定 → 用 SUBAGENT_TIER env 或默认 0（按角色，plan-refinement 角色 = tier 3 中间档）
  [ -n "$tier" ] && export SUBAGENT_TIER="$tier"

  # （计划文档定位与窄任务 sidecar 解析已前移到队列/裁决段之前 —— 见上方 `plan_path` / `_narrow_sidecar`。）

  # ── Q4③（hook-xenv §15.3-Q4，F7/F4 裁决）：登记动作 = **工具生成 --task + 人核** ──
  # 落点点名：本函数既有 submit（:7384「通过则只写 pending 不下发」）是**唯一**登记出口；
  # 本 flag 只做「从计划文档**提取**质询目标行」喂给同一出口 ⟹ 不构成第二张登记表。
  # 提取规则 = 命中「质询目标 … 逐字一致」行，取 `）**：` 之后全文（= canonical --task 串，
  # 与手工 `--task` 逐字节等值 ⟹ 入队条目逐字段等值 = §15.3 判别臂）。
  # 提取失败/空串 ⟹ **fail-loud**（禁静默空 task 入队）；与 `--task` 并用 ⟹ 拒（禁双源）。
  if $task_from_plan; then
    [ -n "$plan_path" ] || { echo '{"ok":false,"error":"--task-from-plan 需要可定位的 <PLAN>"}'; return 1; }
    [ -z "$task" ] || { echo '{"ok":false,"error":"--task-from-plan 与 --task 互斥（工具生成 vs 人手拼串，禁双源）"}'; return 2; }
    task=$(python3 -c '
import io, sys
for ln in io.open(sys.argv[1], encoding="utf-8"):
    if ("质询目标" in ln) and ("逐字一致" in ln) and ("）**：" in ln):
        print(ln.split("）**：", 1)[1].strip())
        break
' "$plan_path" 2>>"$GK_DBG_LOG")
    [ -n "$task" ] || { echo '{"ok":false,"error":"--task-from-plan 未在计划中命中质询目标行（提取器 fail-loud，禁静默空 task）"}'; return 1; }
  fi

  # 前置产物缺失清单（列表，python 侧序列化为 JSON）
  local missing_items=""
  [ -z "$plan_path" ] && missing_items="${missing_items}${missing_items:+,}plan_doc"
  local has_meta="false"
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 /usr/bin/rg）
  if [ -n "$plan_path" ] && "$RG" -q "<!-- META" "$plan_path" 2>/dev/null; then
    has_meta="true"
  else
    [ -n "$plan_path" ] && missing_items="${missing_items}${missing_items:+,}meta"
  fi
  # 源文档存在性
  local bad_docs=""
  if [ -n "$source_docs" ]; then
    local IFS=','
    for d in $source_docs; do
      [ ! -f "$d" ] && bad_docs="${bad_docs:+$bad_docs,}$d"
    done
    IFS=$' \t\n'
    [ -n "$bad_docs" ] && missing_items="${missing_items}${missing_items:+,}source_docs"
  fi
  # subagent 点检历史（最近一条是否 plan-refinement）—— **union 读面**（主 state ⊕ 卫星 history 片）；
  #   读失败 fail-loud（ckpt=unreadable ⟹ 进 missing），禁 `2>/dev/null` 静默当空历史。
  local last_task="" ckpt="absent"
  if ! last_task=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --history-last-task --max 120 2>>"$GK_DBG_LOG"); then
    ckpt="unreadable"
  else
    case "$last_task" in *plan-refinement*) ckpt="present" ;; esac
  fi
  # ── G4-c（2026-09-30，R-CONC-GIT §1.3-G4c）：把「三步分工」后两步的**门禁证据**纳入 missing 面 ──
  # 病灶（实测）：preflight 自述检查四项（计划存在 / META / 源文档 / **subagent 点检**），
  #   但 `missing[]` 只装前三项 ⟹ `checkpoint:absent` 时 **`missing: []` = 假绿灯**
  #   （下游「进相位前查前置」据此放行，而质询链其实未闭合）。
  # 修法：`subagent_pointcheck` 与 `adjudicate_seal` 一并入 `missing[]`；**不阻断**
  #   （阻断面仍只有 plan_doc/meta）⟹ 对齐本仓「依赖不可用不得锁死序列」fail-soft 纪律。
  # ⚠ `adjudicate_seal` 为**存在性**校验（`gk_adjudicate.py` 的 entry 不含计划路径字段 ⟹ 归属须人工核对）。
  local adjudicate_seal="absent"
  adjudicate_seal=$(GK_PY_STATE="$(_gk_py_path "$STATE_FILE")" python3 -c "
import json,os
try:
    d=json.load(open(os.environ['GK_PY_STATE'],encoding='utf-8'))
    cl=d.get('gate_data',{}).get('human_calibration_log') or []
    print('present' if any((e.get('verdicts_json') or e.get('decision')) for e in cl) else 'absent')
except Exception:
    print('absent')
" 2>/dev/null)
  [ "$ckpt" != "present" ] && missing_items="${missing_items}${missing_items:+,}subagent_pointcheck"
  [ "$adjudicate_seal" = "absent" ] && missing_items="${missing_items}${missing_items:+,}adjudicate_seal"
  # ── Preflight 软告警（WARN，**不阻断**；2026-09-14 用户定案）──────────────
  # ① api_key_missing：密钥判空（0 成本，始终判定）
  # ② balance_unavailable / balance_low:<v>：余额探测（仅 DeepSeek 有 /user/balance endpoint）
  # 开关（本处消费=本处定义，故省略即启用、净新增仅 1 次 ≤8s 只读 curl）：
  #   GK_PREFLIGHT_BALANCE=0 ⟹ 跳过余额探测；GK_BALANCE_MIN_CNY 默认 2.0（≈1 轮质询成本下界）
  # ⚠ 只写 preflight.warnings[]，**不改** blocked/ok 与退出码 —— 余额依赖网络/密钥，
  #   阻断会被"查不到余额"锁死序列（对齐本仓「依赖不可用不得锁死序列」fail-soft 纪律）。
  _resolve_provider_config
  _resolve_api_key
  local _bal="" _bal_enabled=1
  { [ "${GK_PREFLIGHT_BALANCE:-1}" = "0" ] || [ "$PROVIDER" = "mimo" ] || [ -z "$API_KEY" ]; } && _bal_enabled=0
  if [ "$_bal_enabled" = "1" ]; then
    local _bal_resp
    _bal_resp=$(curl -s --max-time 8 -X GET "https://api.deepseek.com/user/balance" \
      -H "Accept: application/json" -H "Authorization: Bearer ${API_KEY}" 2>/dev/null)
    _bal=$(BAL_RESP="$_bal_resp" python3 "$SKILL_DIR/scripts/gk_views.py" balance 2>>"$GK_DBG_LOG")
  fi
  local pf_warn_json
  pf_warn_json=$(python3 "${SKILL_DIR}/scripts/gk_preflight_warn.py" \
    --key-present "$([ -n "$API_KEY" ] && echo 1 || echo 0)" \
    --balance-enabled "$_bal_enabled" --balance "$_bal" \
    --min-cny "${GK_BALANCE_MIN_CNY:-2.0}" 2>>"$GK_DBG_LOG")
  [ -z "$pf_warn_json" ] && pf_warn_json="[]"
  # 组装 preflight JSON
  # 2026-10-05（加载安全网）：**阻断面优先** —— `plan_doc` 缺失时**只**给该可操作指引
  #   （附「已试候选」），屏蔽其后 moot 项提示（消噪音）；非阻断时方逐项给指引。
  local hint=""
  if [ -z "$plan_path" ]; then
    hint="计划文档不存在 → 已试候选：[${_plan_tried}]；先 writing-plans 再质询（本项阻断，其余暂不评）；"
  else
    case "$missing_items" in
      *meta*) hint="${hint}META 缺失 → F8 SUSPECTED（对照 r-phase-meta-template.md）；" ;;
    esac
    if [ "$has_meta" = "true" ]; then
      case "$missing_items" in
        *source_docs*) hint="${hint}源文档不可读 → 先 Read 再断言（铁律: 假设必须有源文件证据）；" ;;
      esac
      case "$missing_items" in
        *subagent_pointcheck*) hint="${hint}无 subagent 点检实体（subagent_history 末条非 plan-refinement）→ 先跑 plan-refinement <plan> --task；" ;;
      esac
      case "$missing_items" in
        *adjudicate_seal*) hint="${hint}无 adjudicate 密封（human_calibration_log 空）→ 质询后须 adjudicate --verdicts ... --decision ...（**存在性**校验，计划归属请人工核对）；" ;;
      esac
    fi
  fi
  # ── PW-SN 写侧机检（2026-10-29，堵「安全网可被跳过」）──────────────────────────────
  #   病史（实测）：`plan-lint` 自 2026-09-14 实装起**只是手动命令** —— hook 无计划写门、
  #   本 preflight 也不调它 ⟹ 质询可以对 high/medium 未清零的计划开跑，写侧安全网形同虚设。
  #   本条接进**质询前置**：high/medium 非 0 ⟹ 阻断（对齐 PW-SN §7「交付门」）。
  #   逃生舱 `GK_PLAN_LINT_GATE=0`（显式，留痕到 GK_DBG_LOG）；解释器/脚本不可用 ⟹ 同样阻断
  #   （fail-closed：判据不可用不等于通过）。
  local pl_rc=0 pl_json="{}" pl_skipped="false"
  if [ -n "$plan_path" ] && [ "${GK_PLAN_LINT_GATE:-1}" != "0" ]; then
    pl_json=$(python3 "$SKILL_DIR/scripts/gk_plan_lint.py" "$plan_path" --json-compact 2>>"$GK_DBG_LOG") || pl_rc=$?
    if [ -z "$pl_json" ]; then
      pl_json="{}"
      [ "$pl_rc" = "0" ] && pl_rc=2
    fi
  else
    pl_skipped="true"
    echo "[plan-lint] skipped (GK_PLAN_LINT_GATE=0) plan=$plan_path" >> "$GK_DBG_LOG"
  fi
  local missing_json; missing_json=$(python3 -c "import json,sys;print(json.dumps(sys.argv[1].split(',') if sys.argv[1] else []))" "$missing_items" 2>/dev/null || echo "[]")
  local preflight_json="{\"target\":\"$target\",\"plan_path\":\"$plan_path\",\"has_meta\":$has_meta,\"checkpoint\":\"$ckpt\",\"adjudicate_seal\":\"$adjudicate_seal\",\"missing\":$missing_json,\"warnings\":$pf_warn_json,\"plan_lint\":$pl_json,\"plan_lint_skipped\":$pl_skipped,\"hint\":\"$hint\"}"

  # ── plan_doc / meta 缺失 → 阻塞（质询对象无效，禁止带缺开始）──
  if [ -z "$plan_path" ] || [ "$has_meta" != "true" ]; then
    echo "{\"ok\":false,\"error\":\"preflight blocked: plan_doc/meta missing\",\"preflight\":$preflight_json}"
    return 1
  fi

  # ── PW-SN 机检未过 → 阻塞（high/medium 未清零 = 交付门未过，见 references/plan-writing-safety-net.md §7）──
  if [ "$pl_skipped" != "true" ] && [ "$pl_rc" != "0" ]; then
    echo "{\"ok\":false,\"error\":\"preflight blocked: plan_lint high/medium\",\"preflight\":$preflight_json}"
    return 1
  fi

  # ── --check-only: 只读 preflight ──
  if $check_only; then
    echo "{\"ok\":true,\"check_only\":true,\"preflight\":$preflight_json}"
    return 0
  fi

  # ── 组装任务（下发路径改经 L2 管道节点，见函数尾；cmd_monitor 侧角色改显式 --role）──
  local full_task="plan-refinement: $target"
  [ -n "$task" ] && full_task="${full_task} — ${task}"
  [ -n "$source_docs" ] && full_task="${full_task} | source_docs=${source_docs}"
  # ── ③ E1-E4 证据注入任务模式（2026-09-06，references/e1e4-evaluator-matrix.md §2）──
  # 质询对象 = 审查层矩阵（--task 含标记 "审查层矩阵"/"E1-E4"，或目标文档 basename
  # e1e4-evaluator-matrix.md）→ preflight 预取确定性证据摘要（doc-align 状态行 +
  # round-log + E2 EVAL-MATRIX finding），以 file:line 形式注入 task 文本前
  # （对齐 subagent_runner evidence 契约 subagent_runner.py:1222-1231）。
  # 判定/构建单一事实源 = scripts/gk_doc_align.py（is_eval_matrix_object /
  # build_preflight_evidence）；未命中 → stdout 为空、task 零改动
  # （向后兼容）；证据源失败 → N/A 行降级不阻塞。禁新建 _CMD_REG 命令（A4）。
  local pr_evidence=""
  # 2026-09-13 D1 修复（第四轮质询 sub-cdfdc15e1ab0 挑战采纳）：standing 通道派发接线——
  # 此前此处不传 --channel、不设 env，e1e4 谓词不命中 standing 计划 → 证据注入零生效
  # （"代码存在性≠生效性"假绿）。通道推导：env GATEKEEPER_PREFLIGHT_CHANNEL（回退开关，
  # 最高优先）> gate_data.project_type=standing → standing；否则留空交 auto（2026-11-03：
  # E1-E4 标记 → e1e4；408 帧 → system；其余 e1e4 未命中零注入）。
  local _pr_channel=""
  local _pr_ptype=""
  _pr_ptype=$(python3 "$SKILL_DIR/scripts/gk_state.py" get gate_data.project_type --path "$STATE_FILE" --default '' --default-falsy '' 2>>"$GK_DBG_LOG") || true
  [ "$_pr_ptype" = "standing" ] && _pr_channel="standing"
  [ -n "${GATEKEEPER_PREFLIGHT_CHANNEL:-}" ] && _pr_channel="${GATEKEEPER_PREFLIGHT_CHANNEL}"
  # 2026-11-03：channel 留空 = auto（gk_doc_align 内按 project_type / E1-E4 标记 / 408 帧选择：
  # standing → standing；E1-E4 → e1e4；408 → system 四轴；其余 e1e4 且未命中零注入）。
  pr_evidence=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "${SKILL_DIR}/scripts/gk_doc_align.py" \
    preflight-evidence --task-text "$full_task" --plan-path "$plan_path" \
    --state-file "$STATE_FILE" --project-type "$_pr_ptype" --channel "$_pr_channel" 2>>"$GK_DBG_LOG") || true
  if [ -n "$pr_evidence" ]; then
    full_task="${pr_evidence}"$'\n\n'"${full_task}"
    echo "[ev-inject] preflight 证据注入 channel=${_pr_channel:-auto}（$(printf '%s' "$pr_evidence" | wc -l) 行）$(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
  fi

  # ── T4 收敛前置门（子计划2 §2-T4；F-REV-57 实装，2026-09-14）─────────────────
  # 定序（D5 裁定）：**T4 → L2 入站门**（判据 5/6 中 CONVERGENCE_BUDGET_EXCEEDED 优先于 provenance_injected）。
  # 三态：
  #   ① T* 未冻结 / N*=∞ ⟹ WARN CONV_GATE_WARN_NO_FREEZE（判据 5 例外：**不静默拒一切**，防序列自锁）
  #   ② 评估器依赖不可用 ⟹ WARN CONV_GATE_UNAVAILABLE（判据 8 fail-soft：依赖不可用不得锁死序列）
  #   ③ N*_hi > GK_CONV_MAX_ROUNDS ⟹ BLOCK CONVERGENCE_BUDGET_EXCEEDED，**仅** GK_CONV_GATE=1
  # 默认 GK_CONV_GATE=0（opt-in 不阻断）⟹ 同场景降级 blocked:false + warning CONV_GATE_WARN（判据 6）。
  local conv_warning="" conv_json=""
  # A6-T2 ①（2026-09-15，判据 J18/J20）：取数锚改走**中枢** `_conv_state_path`
  # （= resolve-state），error ⟹ **fail-closed**（禁静默回 base）。
  if ! _conv_state_path; then
    echo "{\"ok\":false,\"blocked\":true,\"error\":\"${_CONV_ERR:-STATE_ROUTE_FAILED}\",\"convergence\":{\"action\":\"fail_closed\",\"error\":\"${_CONV_ERR:-STATE_ROUTE_FAILED}\"},\"channel\":\"state-routing\",\"fix\":\"建域化 state，或 GK_STATE_DOMAIN_ROUTE=0 关闭域解析\"}"
    return 1
  fi
  if [ -f "$_CONV_STATE" ]; then
    conv_json=$(python3 "${SKILL_DIR}/scripts/gk_convergence_estimator.py" gate "$_CONV_STATE" 2>>"$GK_DBG_LOG") || conv_json=""
  fi
  [ -z "$conv_json" ] && conv_json='{"action":"warn","warning":"CONV_GATE_UNAVAILABLE","error":"estimator_unavailable"}'
  # F-REV-59 修复（2026-09-14）：本 case 用**精确子串**匹配 estimator stdout。
  # 原写 `*'"action":"block"'*`（无空格）而 estimator 当时输出 `"action": "block"`（带空格）
  # ⟹ **全分支不命中**、T4 门静默空转（连 WARN 都不出，函数层 15 例全绿掩盖）。
  # 双保险：① estimator `_emit` 改紧凑分隔符（契约）；② 此处再 `tr -d ' '` 归一，
  # 任一格式都能命中。契约守卫测试 = test_cli_gate_stdout_matches_bash_contract。
  local conv_flat; conv_flat=$(printf '%s' "$conv_json" | tr -d ' ')
  case "$conv_flat" in
    *'"action":"block"'*)
      if [ "${GK_CONV_GATE:-0}" = "1" ]; then
        echo "{\"ok\":false,\"blocked\":true,\"error\":\"CONVERGENCE_BUDGET_EXCEEDED\",\"convergence\":$conv_json}"
        return 1
      fi
      conv_warning="CONV_GATE_WARN"
      ;;
    *'"action":"warn"'*)
      case "$conv_flat" in
        *CONV_GATE_WARN_NO_FREEZE*) conv_warning="CONV_GATE_WARN_NO_FREEZE" ;;
        *) conv_warning="CONV_GATE_UNAVAILABLE" ;;
      esac
      ;;
  esac

  # ── 档位「自动换挡」消费（2026-10-08，finding `ECC-46C8BF837715`；§27.1）──────────────
  # 病象：评估器 `tier_recommendation`（含 η_tier **启动前预测**）原为**零消费者**死输出。
  # 现**显式消费**：`action=raise` ⟹ ① 可见 WARN（stderr，不污染 stdout JSON 契约）；
  #   ② **自动换挡**（tier = min(最高档, 当前+1)，留痕 `GK_DBG_LOG`）。
  #   默认 1（**自动开**，2026-10-08 用户裁定）；`GK_AUTO_TIER=0` 显式关闭 ⟹ 退化为只告警（opt-out）。
  local _tr_action _tr_pred
  _tr_action=$(printf '%s' "$conv_json" | python3 "$SKILL_DIR/scripts/gk_views.py" tier-action 2>/dev/null || echo "")
  if [ "$_tr_action" = "raise" ]; then
    _tr_pred=$(printf '%s' "$conv_json" | python3 "$SKILL_DIR/scripts/gk_views.py" tier-prediction 2>/dev/null || echo "")
    local _tier_max; _tier_max=$(python3 "$SKILL_DIR/scripts/gk_suba_tiers.py" max-tier 2>/dev/null || echo 4)
    case "$_tier_max" in ''|*[!0-9]*) _tier_max=4 ;; esac
    local _cur_tier="${SUBAGENT_TIER:-3}"
    case "$_cur_tier" in ''|*[!0-9]*) _cur_tier=3 ;; esac
    if [ "${GK_AUTO_TIER:-1}" != "0" ] && [ "$_cur_tier" -lt "$_tier_max" ]; then
      local _new_tier=$(( _cur_tier + 1 ))
      export SUBAGENT_TIER="$_new_tier"
      printf '%s tier-auto-shift %s -> %s (%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$_cur_tier" "$_new_tier" "$_tr_pred" >>"$GK_DBG_LOG" 2>/dev/null || true
      echo "GATEKEEPER-WARN: [tier-auto-shift] 收敛评估器建议升档 ⟹ 自动换挡 $_cur_tier → $_new_tier（$_tr_pred）" >&2
    else
      echo "GATEKEEPER-WARN: [tier-recommendation] 收敛评估器建议升档（raise；$_tr_pred）—— 已在最高档或 GK_AUTO_TIER=0，请人工 --tier 落档" >&2
    fi
  fi

  # ── L2 入站数据管道节点（F-REV-21）：四项检查 → pending 入队；**不在此处下发** ──
  # ① provenance（--task 的专名须在 target ∪ source_docs 可证）→ 命中即阻断（可 --acknowledge-injected 显式豁免）
  # ② leading（①…②… 枚举 + 断言谓词 + 括号答案提示）→ 标记，交裁决点强制显形
  # ③ poison / ④ 有界（复用 gk_narrow_route 词表与上限）
  # 检查对象 = 原始 --task（不含 preflight 证据：证据是机器从 target 派生的，非 agent 断言）。
  local _gate_rc=0 _gate_out=""
  _gate_out=$(python3 "${SKILL_DIR}/scripts/gk_task_gate.py" check \
    --task "$task" --target "$plan_path" --source-docs "$source_docs" \
    --acknowledge "$acknowledge" --emit-record \
    --target-name "$target" --full-task "$full_task" --tier "$tier" \
    --state "$STATE_FILE" \
    2>>"$GK_DBG_LOG") || _gate_rc=$?
  if [ -z "$_gate_out" ]; then
    echo '{"ok":false,"error":"task_gate_failed","detail":"gk_task_gate check 无输出（禁止静默放行）"}'
    return 1
  fi
  if [ "$_gate_rc" = "2" ]; then
    # 阻断面 = provenance_injected / novel_phrase_ungrounded（一切未知长串）/ leading_question /
    # poison_marker / schema_violation。豁免**逐项转录**（禁通配）→ gate.acknowledge_hint 可直接粘贴。
    echo "{\"ok\":false,\"blocked\":true,\"gate\":$_gate_out,\"hint\":\"读 gate.block_reasons；确认无危险内容后用 --acknowledge-injected <gate.acknowledge_hint> 豁免（逐项转录），或改写 --task 去掉未落地长串\"}"
    return 2
  fi
  if [ "$_gate_rc" != "0" ]; then
    echo "{\"ok\":false,\"error\":\"task_gate_failed\",\"detail\":\"rc=$_gate_rc\",\"gate\":$_gate_out}"
    return 1
  fi

  # 入队（持 state 锁；记录经 stdin 传递，不走 shell 字面量内插——F-REV-20 纪律）
  # T1（2026-10-05，n4）：一次入队 **3×K** 条 pending（MoA 3 组×K 臂的承载面；§2-T1）。
  #   K = `--arms-per-group` | `GK_PLAN_REFINE_ARMS_PER_GROUP` | 2；`GK_PLAN_REFINE_GROUP=0`
  #   ⟹ 单条（旧单臂路径零回归）。id 加盐唯一 + 批级 `batch` 键由 submit --count 落（§3）。
  local _pr_apg="${arms_per_group:-${GK_PLAN_REFINE_ARMS_PER_GROUP:-2}}"
  case "$_pr_apg" in ''|*[!0-9]*) _pr_apg=2 ;; esac
  [ "$_pr_apg" -lt 1 ] 2>/dev/null && _pr_apg=1
  local _n_records=$((3 * _pr_apg))
  [ "${GK_PLAN_REFINE_GROUP:-1}" = "0" ] && _n_records=1
  local _sub_rc=0 _sub_out=""
  # 2026-09-25（选项 A）：`_with_state_lock` 已拆除 —— `gk_task_gate.save_state` 走
  # `gk_json_utils.dump_state`（内置锁）⟹ 无需外层 bash 锁。
  # T1 消费端（2026-10-05）：批入队（`_n_records>1`）时传 `--expand-groups --k`，
  #   令 submit 从 `gate_data.narrow_tasks[]` 逐臂嵌入组任务（见 gk_task_gate._group_expand_records）；
  #   条目不足 ⟹ submit 回退同名复制（`group_tasks:false`，旧语义零回归，输出可见）。
  # 2026-10-21（`ECC-81883BA000AB`）：窄任务来源**绑定本计划** —— sidecar 存在 ⟹ 只读 sidecar；
  #   否则按 `--narrow-scope <plan>` 过滤全局清单（未声明归属的旧条目一律排除 ⟹ fail-closed）。
  #   ⚠ 禁用数组下标拼接（plan 路径可含空格）：用 bash 数组逐项传参。
  local -a _sub_args=(--state "$STATE_FILE" --count "$_n_records")
  if [ "$_n_records" -gt 1 ]; then
    _sub_args+=(--expand-groups --k "$_pr_apg")
    if [ -n "$_narrow_sidecar" ]; then
      _sub_args+=(--narrow-tasks-file "$_narrow_sidecar")
    elif [ -n "$plan_path" ]; then
      _sub_args+=(--narrow-scope "$plan_path")
    fi
  fi
  _sub_out=$(printf '%s' "$_gate_out" | python3 "${SKILL_DIR}/scripts/gk_task_gate.py" submit "${_sub_args[@]}" 2>>"$GK_DBG_LOG") || _sub_rc=$?
  if [ "$_sub_rc" != "0" ] || [ -z "$_sub_out" ]; then
    # T10：submit 越双墙时回 `pipeline_over_wall`+`over`轴+`hint`（rc≠0 且 stdout 非空）⟹
    #   透传该结构化原因（否则被通用文案吞掉，调用方看不到「pending 越墙」与出口指引）。
    if [ -n "$_sub_out" ]; then
      printf '%s\n' "$_sub_out"
    else
      echo "{\"ok\":false,\"error\":\"task_pipeline_submit_failed\",\"detail\":\"rc=$_sub_rc（记录未入队，禁止当已排期）\"}"
    fi
    return 1
  fi
  # ── 豁免惩罚（2026-10-05，用户令「给豁免加惩罚机制」）──────────────────────────
  #   `--acknowledge-injected` 逐项豁免 L2 门的阻断项，此前**零代价** ⟹ 可**整表豁免**无痛绕过入站门
  #   （本轮实测：一次转录 18 项即抹平 leading_question / novel_phrase_ungrounded）。现给豁免定价：
  #   每豁免 1 项 = 信用分 **−1**（kind=exempt，计入旁挂信用账本；append-only + 封印，跨会话累积，
  #   audit 可见）。空 acknowledge ⟹ 不计费（零回归）。写失败 WARN 不阻断（对齐账本调用面纪律）。
  local _ack_n=0 _exempt_field=""
  if [ -n "$acknowledge" ]; then
    _ack_n=$(printf '%s' "$_gate_out" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field acknowledged --len-list --default-invalid 0 2>>"$GK_DBG_LOG") || _ack_n=0
    if [ "${_ack_n:-0}" -gt 0 ]; then
      _credit_log_append "exempt" "-${_ack_n}" "plan-refinement" "acknowledge_injected: ${_ack_n} 项（${target}）" || true
      _exempt_field=",\"exempt_penalty\":-${_ack_n}"
    fi
  fi
  local _conv_field=""
  [ -n "$conv_warning" ] && _conv_field=",\"warning\":\"$conv_warning\",\"convergence\":$conv_json"
  # F6（2026-10-15）：`--run` 单入口 —— enqueue 完成后**接力** adjudicate +（缺省）moa-aggregate，
  #   免主 agent 手动逐步拼命令（§14.7 F-D「手动拼接摩擦」另一半）。旧路径（无 `--run`）逐字不变。
  if $run_mode; then
    _plan_refine_run_tail "$target" "$_sub_out" "$_n_records" "$no_aggregate" "$aggregate_out" "$chain_flag"
    return $?
  fi
  echo "{\"ok\":true,\"pending\":true,\"gate\":$_gate_out,\"submit\":$_sub_out$_conv_field$_exempt_field,\"next\":\"plan-refinement <plan> --run（单入口：enqueue→adjudicate→aggregate）；只要下发可用 --adjudicate last --decision approve（会跳过聚合链尾）\"}"
  return 0
}

# ─── 命令注册表 (PROTECTED_REGION::gate) ───
# 格式: func|gate_level|stage_constraint|side_effects
# gate:   full (advance gate + guard-edit) / partial (pre_tool_check) / none (只读)
# stage:  any / active-r / idle-only
# side:   git_push / state_write / permission_escalation / empty
# PROTECTED_REGION_START::gate
declare -A _CMD_REG
_CMD_REG[discover]="cmd_discover|none|any|"
_CMD_REG[state]="cmd_state|none|any|"
_CMD_REG[migrate]="cmd_migrate|partial|any|"
_CMD_REG[swe-rb]="cmd_swe_rb|partial|any|state_write"
_CMD_REG[guard-edit]="cmd_guard_edit|full|any|"
_CMD_REG[pre-tool-check]="pre_tool_check|partial|any|"
_CMD_REG[advance]="cmd_advance|full|active-r|state_write"
_CMD_REG[node-guard]="cmd_node_guard|none|any|"
_CMD_REG[monitor]="cmd_monitor|partial|any|"
_CMD_REG[stage-detail]="cmd_stage_detail|none|any|"
_CMD_REG[balance]="cmd_balance|none|any|"
_CMD_REG[self-check]="cmd_self_check|none|any|"
_CMD_REG[calibrate]="cmd_calibrate|none|any|"
_CMD_REG[doc-align]="cmd_doc_align|none|any|"
_CMD_REG[paper-review]="cmd_paper_review|partial|any|state_write"
_CMD_REG[help]="cmd_help|none|any|"
_CMD_REG[moa-aggregate]="cmd_moa_aggregate|none|any|"
_CMD_REG[set-key]="cmd_set_key|none|any|key_write"
_CMD_REG[docgen]="cmd_docgen|none|any|state_write"
_CMD_REG[reflect]="cmd_reflect|partial|active-r|"
_CMD_REG[appeal]="cmd_appeal|full|active-r|permission_escalation"
_CMD_REG[escalate]="cmd_escalate|full|active-r|permission_escalation"
_CMD_REG[resolve]="cmd_resolve|full|active-r|state_write"
_CMD_REG[replay]="cmd_replay|none|any|"
_CMD_REG[ember]="cmd_ember|none|any|"
_CMD_REG[pr-score]="cmd_pr_score|partial|any|state_write"
_CMD_REG[cron]="cmd_cron|none|any|state_write"
_CMD_REG[push]="cmd_push|full|any|git_push"
_CMD_REG[ci-status]="cmd_ci_status|none|any|"
_CMD_REG[state-patch]="cmd_state_patch|none|any|state_write"
_CMD_REG[ci-diagnose]="cmd_ci_diagnose|none|any|"
_CMD_REG[check-changes]="cmd_check_changes|none|any|"
_CMD_REG[apply-worktree]="cmd_apply_worktree|partial|any|state_write"
_CMD_REG[pre-check]="cmd_pre_check|none|any|"
_CMD_REG[t-star]="cmd_t_star|none|any|state_write"
_CMD_REG[workers]="cmd_workers|none|any|"
_CMD_REG[commit]="cmd_commit|none|active-r|git_write"
_CMD_REG[search]="cmd_search|none|any|"
_CMD_REG[release-check]="cmd_release_check|none|any|"
_CMD_REG[plan-refinement]="cmd_plan_refinement|partial|any|state_write"
_CMD_REG[plan-lint]="cmd_plan_lint|none|any|"
_CMD_REG[anchor-rebase]="cmd_anchor_rebase|none|any|state_write"
_CMD_REG[model-probe]="cmd_model_probe|none|any|"
_CMD_REG[phase-probe]="cmd_phase_probe|none|any|"
_CMD_REG[adjudicate]="cmd_adjudicate|none|any|state_write"
_CMD_REG[project-register]="cmd_project_register|partial|any|state_write"
_CMD_REG[audit]="cmd_audit|none|any|state_write"
_CMD_REG[finding]="cmd_finding|none|any|state_write"
_CMD_REG[achievements]="cmd_achievements|none|any|state_write"
_CMD_REG[context]="cmd_context|none|any|state_write"
_CMD_REG[trace]="cmd_trace|none|any|"
_CMD_REG[attribution]="cmd_attribution|none|any|"

# ── audit: 审计重放命令 ──
# Runs audit checks on current state, history, and ECC documents
# Usage: audit [--state|--docs|--memory|--crossr|--coverage [--base <ref>]|--crossfull [--base <ref>] [--repo <name>] [--state <path>] [--isolate]
#               |--pdg [--symbol <fn>] [--repo <name>] [--supply]|--pr --base <ref> [--symbol <fn>]
#               |--red <phase>|--hint|--self|--hook|--report [--type <type>] [--force]]
#               [--verify <path>] [--init-keys] [--key rotate|revoke|destroy|export-pub|fingerprint|status] [--all]
# Audit types: financial (财务报表), compliance (合规), performance (绩效)
# R7: Two independent key pairs — context (high-freq) + audit (low-freq)
# 2026-09-20（ECC-PLAN ①·宿主形态）：原为宿主机绝对路径字面量 —— 换宿主（macOS / 通用 Linux /
# Windows Git-Bash）或换安装位置后，`.keys` 指向**不存在的目录** ⟹ 连带下方 L6803 的 unbound。
# 改由 SKILL_DIR 派生（L62-69 已保证非空；`install.sh` 部署面随之自动正确）。
_AUDIT_KEY_DIR="${SKILL_DIR}/.keys"
_CONTEXT_PRIV_KEY="${_AUDIT_KEY_DIR}/context_ed25519.pem"
_CONTEXT_PUB_KEY="${_AUDIT_KEY_DIR}/context_ed25519.pub"
_AUDIT_PRIV_KEY="${_AUDIT_KEY_DIR}/audit_ed25519.pem"
_AUDIT_PUB_KEY="${_AUDIT_KEY_DIR}/audit_ed25519.pub"
_KEY_META="${_AUDIT_KEY_DIR}/key-meta.json"
_KEY_INTEGRITY="${_AUDIT_KEY_DIR}/.key-integrity.sha256"
_AUDIT_TYPES='{"state":"financial","memory":"compliance","crossr":"performance","report":"performance","redteam":"redteam"}'

# ── subagent 签名密钥供给（2026-08-15，HMAC_KEY=MISSING 根因修复）──
# 此前 GATEKEEPER_HMAC_KEY 仅被消费（L1608/runner L94）从不供给：
# 文档记载的 "salted SHA256 fallback" 已因可预测性被移除（2026-08-12 加固），
# 但无替代供给机制 → env 缺失时 subagent 输出静默跳过签名。
# 现与 Ed25519 密钥族同模式：.keys/subagent-hmac.key 首次生成 64-hex，之后加载。
# 文件不存在/生成失败 → 维持原行为（不签名、不报错），不引入可预测 fallback。
_HMAC_KEY_FILE="${_AUDIT_KEY_DIR}/subagent-hmac.key"
if [ -z "${GATEKEEPER_HMAC_KEY:-}" ]; then
  if [ -f "$_HMAC_KEY_FILE" ]; then
    GATEKEEPER_HMAC_KEY="$(head -1 "$_HMAC_KEY_FILE" 2>/dev/null)"
  elif [ -d "$_AUDIT_KEY_DIR" ]; then
    GATEKEEPER_HMAC_KEY="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(32))' 2>/dev/null)"
    if [ -n "$GATEKEEPER_HMAC_KEY" ]; then
      umask 177; echo "$GATEKEEPER_HMAC_KEY" > "$_HMAC_KEY_FILE"; umask 022
      chmod 600 "$_HMAC_KEY_FILE" 2>/dev/null
    fi
  fi
  # 2026-09-20（ECC-PLAN ①·宿主可用性）：原 `[ -n "$GATEKEEPER_HMAC_KEY" ]` —— 上面 if/elif
  # **两条分支都不命中**时（`.keys` 目录不存在）该变量**从未被赋值** ⟹ `set -u` 下 unbound。
  # 本处为**顶层**语句 ⟹ 不是「函数体中止」而是**整 CLI 加载期 exit 1**（已实测：临时探针脚本
  # 复现同形，报 `GATEKEEPER_HMAC_KEY: unbound variable` 且其后语句不再执行）。
  # 同族副本 L3261（函数内）同批修。
  [ -n "${GATEKEEPER_HMAC_KEY:-}" ] && export GATEKEEPER_HMAC_KEY
fi

# A1+A2 fix: Verify key-meta.json integrity + pubkey fingerprint match
# Returns 'ok' if valid, error message otherwise
_verify_key_integrity() {
  [ ! -f "$_KEY_META" ] && { echo "ok"; return 0; }  # no meta yet
  [ ! -f "$_KEY_INTEGRITY" ] && { echo "tampered:integrity_file_missing"; return 1; }
  local expected; expected=$(head -1 "$_KEY_INTEGRITY" 2>/dev/null)
  local actual; actual=$(sha256sum "$_KEY_META" 2>/dev/null | awk '{print $1}')
  [ "$expected" = "$actual" ] || { echo "tampered:key-meta.json modified (sha256 mismatch)"; return 1; }
  # A2: Verify pubkey fingerprints match key-meta.json records
  python3 << 'PYEOF'
import json, os, hashlib, sys
meta_file = os.environ.get('_KEY_META','')
if not os.path.exists(meta_file): sys.exit(0)
meta = json.load(open(meta_file))
for ktype in ['context_ed25519', 'audit_ed25519']:
    pub_path = os.environ.get('_AUDIT_KEY_DIR','') + '/' + ktype.replace('_ed25519','') + '_ed25519.pub'
    if os.path.exists(pub_path):
        fp = hashlib.sha256(open(pub_path,'rb').read()).hexdigest()
        expected_fp = meta.get(ktype,{}).get('fingerprint','')
        if expected_fp and fp != expected_fp:
            print(f'tampered:{ktype} pubkey replaced')
            sys.exit(1)
PYEOF
  [ $? -eq 0 ] && echo "ok" || echo "tampered:pubkey_fingerprint_mismatch"
}

# A1: Update integrity hash after key-meta.json modification
_update_key_integrity() {
  [ ! -f "$_KEY_META" ] && return 0
  local _kh
  _kh=$(sha256sum "$_KEY_META" 2>/dev/null | awk '{print $1}')
  [ -z "$_kh" ] && return 1
  printf '%s\n' "$_kh" > "$_KEY_INTEGRITY"
  return 0
}

# 轮转盲区修复 (2026-08-21): 过期检测从 cmd_advance 提升为 CLI 级启动检查。
# 原设计轮转只挂在 cmd_advance → 长期不 advance 则错过过期检测（context=1d / audit=30d）。
# 现任何命令调用都会先处理过期密钥；cmd_advance 保留调用作为双保险。
# 幂等性：仅在 key-meta 存在且确有密钥过期时才触发；rotate 后再次调用无事发生。
_key_rotate_if_expired() {
  [ -f "$_KEY_META" ] || return 0
  local _expired; _expired=$(GK_PY_META="$(_gk_py_path "$_KEY_META")" python3 -c "
import json,datetime,os
meta=json.load(open(os.environ['GK_PY_META']))
now=datetime.datetime.utcnow()
for ktype,info in meta.items():
    exp=info.get('expires','')
    if exp:
        try:
            exp_dt=datetime.datetime.fromisoformat(exp.replace('Z',''))
            if now>exp_dt: print(ktype); break
        except: pass
" 2>/dev/null || echo "")
  [ -n "$_expired" ] || return 0
  # 2026-08-13: 显式传 auto 标记自动轮换（BP.08.04 生命周期审计可追溯来源）
  # 2026-11-02（只读命令副作用修复）：原只静默 stderr ⟹ 内部 rotate 的 stdout
  #   （openssl `Signature Verified Successfully`）直接混进调用方输出，实测把
  #   `finding status` 的 JSON 契约打断（首字符不是 `{`）。改为**双流静默**，
  #   轮换结果只落 debug log。轮换本身**保留**：2026-08-21「轮转盲区」修复依赖它，
  #   去掉会让长期不 advance 的环境永不轮换（密钥过期仍继续用）。
  if bash "$0" audit --key rotate "$_expired" auto >/dev/null 2>&1; then
    echo "[key-rotate] auto rotate $_expired ok $(date -u +%FT%TZ)" >> "$GK_DBG_LOG" 2>/dev/null || true
  else
    echo "[key-rotate] auto rotate $_expired FAILED $(date -u +%FT%TZ)" >> "$GK_DBG_LOG" 2>/dev/null || true
  fi
  # 2026-09-10: rotate 后自动重签 context（防"轮换→签名 stale 每日复发"链，见 _context_resign）
  _context_resign
  # CapiscIO: destroy .bak files older than 7 days (grace period expired)
  find "$_AUDIT_KEY_DIR" -name "*.bak" -mtime +7 -exec rm -f {} \; 2>/dev/null
}

# ── context 签名自动重签（2026-09-10）─────────────────────────────────────────
# 根因链：context 私钥 24h 自动轮换（_key_rotate_if_expired）→ 但 context 文件签名只由人工
# `context --update` 刷新 → 每次轮换后签名立即 stale：
#   ① gk_node_guard._context_signature_fresh → sig_stale_after_key_rotation → 序列节点安全网
#      codebase_map 前置谓词 fail-closed（实测 2026-09-10 STAGE_3 guard ok:false）；
#   ② gatekeeper-cli.sh L969 CONTEXT_STALE_OR_UNSIGNED → L2 --crossrev 车道降级/阻断。
# 处置：轮换后仅重签现有 ctx 文件（复用 _sign_raw context 线），不触发 gitnexus analyze
# （非 --update 全量）；无 ctx 文件/无密钥 → 静默 no-op（新装环境不引入伪 sig）。
_context_resign() {
  local ctx_file="$SKILL_DIR/references/subagent-context.json"
  [ -f "$ctx_file" ] || return 0
  # 2026-10-30（签名竞态修复 ①）：重签同样走独占锁 + 原子发布，避免与并发 update/读者交错。
  # 取锁必须复用 `_ctx_lock_acquire`（可重入单点）：rotate 由 cmd_advance / CLI 启动级触发时
  #   不持锁，但一旦调用方已持锁（如 update 内联 rotate），就地 `exec {fd}>` 复核是**新 OFD**
  #   ⟹ 会阻塞到 `-w` 超时；可重入助手让内层直接复用外层锁。
  local _cr_had="${_CTX_LOCK_FD:-}"
  _ctx_lock_acquire "$ctx_file" 20
  local sig_result; sig_result=$(_sign_raw "$ctx_file" 2>/dev/null || echo "")
  if [ -n "$sig_result" ]; then
    local _sig_tmp="${ctx_file}.sig.tmp.$$"
    echo "$sig_result" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field sig --b64 2>/dev/null > "$_sig_tmp"
    mv -f "$_sig_tmp" "${ctx_file}.sig" 2>/dev/null || rm -f "$_sig_tmp"
    if [ -s "${ctx_file}.sig" ]; then
      echo "[key-rotate] context 自动重签完成（防 rotate 后签名 stale）$(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
    fi
  fi
  if [ -z "$_cr_had" ]; then _ctx_lock_release; fi
}

_audit_sign() {
  local content="$1"
  local tmpf; tmpf=$(mktemp)
  echo -n "$content" > "$tmpf"
  python3 "$SKILL_DIR/scripts/gk_crypto_cli.py" audit-sign "$_AUDIT_PRIV_KEY" "$tmpf" 2>/dev/null || echo '{"hash":"","signature":""}'
  rm -f "$tmpf"
}

# Sign a raw file (no markdown wrapper). Returns {"sig":"<base64>","hash":"<hex>"}
# 2026-08-13 参数化：key_type ∈ {context, audit}，默认 context。
#   - context = 24h 高频轮换，用于 subagent-context.json 注入签名（高频、短期）
#   - audit = 30d 低频轮换，用于 human_resolutions 终裁记录（低频、长期存证，NIST SP 800-57 密钥用途分离）
#   移除静默 fallback（fail-loud）：R7 拆分后缺 key 直接报错，避免"签完不知道用的哪把钥"导致验证端错配
_sign_raw() {
  local file_path="$1" key_type="${2:-context}"
  [ ! -f "$file_path" ] && { echo '{"error":"file not found"}'; return 1; }
  local key="${_CONTEXT_PRIV_KEY}"
  [ "$key_type" = "audit" ] && key="${_AUDIT_PRIV_KEY}"
  [ ! -f "$key" ] && { echo "{\"error\":\"no ${key_type} signing key. Run: gatekeeper-cli.sh audit --init-keys\"}"; return 1; }
  python3 "$SKILL_DIR/scripts/gk_crypto_cli.py" sign-raw "$key" "$file_path" 2>/dev/null || echo '{"error":"sign failed"}'
}

# Verify a raw file signature. Returns {"ok":true} or {"ok":false,"error":"..."}
# 2026-08-13 参数化第 4 参 pubkey_path（默认 audit 公钥）：
#   R7 拆分密钥时 _sign_raw 切到 context 私钥但本函数仍硬编码 audit 公钥 → 56e1549 错配，
#   作者 e836fcc 用 openssl 绕过（context 显示路径）。参数化后 context 线可显式传 _CONTEXT_PUB_KEY，
#   消灭死代码 + 杜绝"签名切密钥、验证没同步"再发生。
_verify_raw() {
  local file_path="$1" sig_b64="$2" expected_hash="${3:-}" pubkey_path="${4:-$_AUDIT_PUB_KEY}"
  [ ! -f "$file_path" ] && { echo '{"ok":false,"error":"file not found"}'; return 1; }
  python3 "$SKILL_DIR/scripts/gk_crypto_cli.py" verify-raw "$file_path" "$sig_b64" "$expected_hash" "$pubkey_path" 2>/dev/null || echo '{"ok":false,"error":"verify failed"}'
}

# 验证 human_resolutions 终裁记录签名（ghost attack defense 真验签）
# 2026-08-13 新增：audit --state 此前只查 ed25519_sig 存在性（可伪造），本函数做密码学真验签。
# 兼容策略：audit 公钥优先（新规范），失败回退 context 公钥（56e1549 前后残留旧记录，WARN 级 context_legacy）。
# 字节契约：签名对象 = 规范化 JSON + 尾换行（签名端 echo > tmp 追加 \n，见 cmd_resolve）；两种形态都尝试。
_verify_resolution_sig() {
  local gate="$1"
  python3 "$SKILL_DIR/scripts/gk_crypto_cli.py" verify-resolution "$STATE_FILE" "$gate" "$_AUDIT_PUB_KEY" "$_CONTEXT_PUB_KEY" 2>/dev/null || echo '{"ok":false,"error":"verify_resolution_failed"}'
}

# ── finding: ECC-FINDING 闭环协议（技能自维护防裸跑，2026-08-20, R-T8.2）──
# 用法: finding register <title> <source> | verify <id> <ok> | close <id> <verify_source> | status
#       | from-prose <散文文件> | score <findings.json>   （S4/S5，2026-10-06）
#       | stale [--ttl-days N] [--apply]   （2026-11-01：TTL 标 stale + 锚文件被 diff 触及 ⟹ reopen；
#                                          默认只报不写，--apply 才落盘）
#       | dup-check <title> [--family <族>] [--anchor <锚>]... [--tau ..] [--exclude-id ..]
#         （2026-10-26 §2.3-A：写前同类同族候选**只读**面；register 另支持 --merge-into/--dup-ack）
# source: crossr/red/manual/audit。登记后 hook Gate 8 放行技能仓库写操作。
cmd_finding() {
  local fcmd="${1:-status}"; shift || true
  # S4/S5（2026-10-06）：散文→ecc-findings / findings→批级裁定分。**挂在既有 `finding` 命令下**
  #   （不加新 `_CMD_REG` 条目 —— 守 `test_gk_state_forms::test_no_new_cmd_reg_entry_added` 不变量）。
  case "$fcmd" in
    from-prose) python3 "$SKILL_DIR/scripts/gk_prose_findings.py" "$@"; return $? ;;
    score)      python3 "$SKILL_DIR/scripts/gk_finding_score.py" "$@"; return $? ;;
  esac
  # 2026-09-07 批①-5 (ECC-E75A3C2E8FE6 相邻缺陷): gk_finding.save_findings 直写 state
  # 不重算 _checksum → 每次 register/close/verify 后 state checksum 失配（guard-edit/advance
  # 入口 _state_checksum_verify 会误报 TAMPERED）。写类子命令后补 checksum 重算（flock 内）。
  local _fout; _fout=$(python3 "$SKILL_DIR/scripts/gk_finding.py" "$fcmd" "$STATE_FILE" "$@" 2>>"$GK_DBG_LOG" \
    || echo '{"ok":false,"error":"finding cmd failed"}')
  case "$fcmd" in
    register|close|verify|reopen|release-approve|release-reject|declassify|stale) _state_checksum_write ;;
  esac
  echo "$_fout"
}

# [write_guard 裁决 2026-09-06 EXEMPT] 写入仅于持久化域 --state/--docs（by-design：结果落盘供 RED 消费）；
# 只读域（--hook/--red/--self/--hint/--memory/--crossr/--coverage）零写入；audit 无 --check 变体。
cmd_audit() {
  local scope="${1:-state}"
  # F-REV-75（2026-09-16，用户裁定「同根因修」）：gitnexus 环境**单点注入** —— 本函数下
  # `--pdg`（L3 PDG/污点）与 `--pr`（L10 PR 审查）两分支的 python 脚本原各自硬编码
  # `/mnt/d/Program Files/nodejs/node.exe`（正是技能自身禁令 L1275 点名的「第二份探测」）。
  # 改为消费 GX_NODE/GX_JS/GX_REPO（`_gx_node_probe` 单点产物）。返回值 1 = 图能力不可用
  # （fail-loud 已 WARN 到 stderr）⟹ `|| true` 不中断审计，但**不掩盖**：脚本侧见 env 缺失
  # 即输出 [ERROR]（可留痕/可机检）。
  case "$scope" in
    --pdg|pdg|--pr|pr) _gx_subagent_gx_env wsl || true ;;
  esac
  case "$scope" in
    --state|state)
      # ── Runtime evidence collection ──
      # Phase 4a (2026-08-19): 迁移到 scripts/gk_audit_state.py — 17 项确定性检查
      # (2026-09-02 hook_block_log 意图记忆可审计性 +1: state 15→16→17)
      # 复用 gk_state.py 读 state (含 SHA256 checksum warning); 输出契约与旧 heredoc 一致
      # (batch8 R-T6 Phase 4a: cmd_audit bash heredoc L4952-5115 → 独立 Python)
      local _tmp_state; _tmp_state=$(mktemp)
      # 2026-08-13: 真验签所需公钥路径传给脚本（脚本内无法调 bash 函数，走环境变量）
      export _AUDIT_PUB_KEY _CONTEXT_PUB_KEY
      # 2026-08-13: stderr 追加到 GK_DBG_LOG（此前 2>/dev/null 吞错→heredoc 异常静默失败输出空 JSON，如 divergence=None 崩溃）；
      # 失败时把最近日志尾部嵌入错误 JSON 便于诊断
      local state_data; state_data=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 "$SKILL_DIR/scripts/gk_audit_state.py" --state 2>>"$GK_DBG_LOG" || echo "{\"state_checks\":[],\"audit_summary\":{\"total_fields\":0,\"heredoc_error\":\"$(tail -3 "$GK_DBG_LOG" 2>/dev/null | tr '\n' ' ' | head -c 200)\"}}")
      # Persist state result for RED report consumption
      # 2026-08-20 (交叉审查): 原 `['audit_state_result']=$state_data` 字面量嵌入——JSON 的
      # true/false/null 非合法 Python 字面量 → NameError → 被 `|| true` 吞 → 持久化恒失败，
      # redteam 报告 Finding 1 恒空。改: state_data 落临时文件 + _state_write（内置 flock +
      # checksum 重算，规避直写导致 _checksum 失配误报篡改 + audit --all 并行写竞争）。
      echo "$state_data" > "$_tmp_state"
      GK_PY_TMP="$(_gk_py_path "$_tmp_state")" _state_write "d.setdefault('gate_data',{})['audit_state_result']=json.load(open(os.environ['GK_PY_TMP']))"
      rm -f "$_tmp_state"
      # 2026-10-28（B3b）：签发登记 sidecar（审计署登记双读）。失败不阻断本次审计，
      # 但下游 dual_read 会因摘要缺失/过期而拒 ⟹ fail-loud 在消费侧。
      python3 "${SKILL_DIR}/scripts/gk_audit_registry.py" register --state "$STATE_FILE" \
        ${_AUDIT_KEY_DIR:+--key-dir "$_AUDIT_KEY_DIR"} --source audit_state \
        >>"${GK_DBG_LOG:-/dev/null}" 2>&1 || echo "[audit-registry] WARN register(audit_state) failed" >>"${GK_DBG_LOG:-/dev/null}"
      # 2026-10-29（E18/B1）：审计证据 → finding 台账闭环。match=false 逐项登记
      # （source=audit / release_state=provisional / root_key 幂等）；失败不阻断审计本身。
      local _audit_fnd; _audit_fnd=$(python3 "$SKILL_DIR/scripts/gk_audit_findings.py" \
        "$STATE_FILE" 2>>"$GK_DBG_LOG" || echo '{"ok":false,"error":"adapter failed"}')
      echo "{\"ok\":true,\"audit_mode\":\"state\",\"result\":$state_data,\"findings\":$_audit_fnd}" ;;
    --docs|docs)
      # Document alignment audit: 4 deterministic checks, 0 API calls
      # Phase 4b (2026-08-20): 迁移到 scripts/gk_audit_docs.py — 与 --state 同构:
      # 路径参数化 (原 heredoc 硬编码 /mnt/c/...) + 持久化走 _state_write
      # (原 `['audit_docs_result']=$docs_result` 字面量嵌入——JSON 含引号破坏 python -c, 同 --state 修复)
      local _tmp_docs; _tmp_docs=$(mktemp)
      local docs_result; docs_result=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 "$SKILL_DIR/scripts/gk_audit_docs.py" 2>>"$GK_DBG_LOG" || echo "{\"docs_checks\":[],\"summary\":{\"total\":0,\"matches\":0,\"failures\":1,\"heredoc_error\":\"$(tail -3 "$GK_DBG_LOG" 2>/dev/null | tr '\n' ' ' | head -c 200)\"}}")
      # Persist docs result for RED report consumption (2026-08-20: 改 _state_write, 同 --state)
      echo "$docs_result" > "$_tmp_docs"
      GK_PY_TMP="$(_gk_py_path "$_tmp_docs")" _state_write "d.setdefault('gate_data',{})['audit_docs_result']=json.load(open(os.environ['GK_PY_TMP']))"
      rm -f "$_tmp_docs"
      # 2026-10-28（B3b）：签发登记 sidecar（同 --state）。
      python3 "${SKILL_DIR}/scripts/gk_audit_registry.py" register --state "$STATE_FILE" \
        ${_AUDIT_KEY_DIR:+--key-dir "$_AUDIT_KEY_DIR"} --source audit_docs \
        >>"${GK_DBG_LOG:-/dev/null}" 2>&1 || echo "[audit-registry] WARN register(audit_docs) failed" >>"${GK_DBG_LOG:-/dev/null}"
      # 2026-10-29（E18/B1）：同 --state 的 finding 闭环（docs 失败项一并入册）。
      local _audit_fnd; _audit_fnd=$(python3 "$SKILL_DIR/scripts/gk_audit_findings.py" \
        "$STATE_FILE" 2>>"$GK_DBG_LOG" || echo '{"ok":false,"error":"adapter failed"}')
      echo "{\"ok\":true,\"audit_mode\":\"docs\",\"result\":$docs_result,\"findings\":$_audit_fnd}" ;;
    --hint|--self|--hook|--red|hint|self|hook|red)
      # Phase 4c-4f (2026-08-20): CLI 接线 — gk_audit_state.py 扩展检查链
      # (check_hint/check_self/check_hook/check_red 已在 Phase 4a 实现, run_all 可调)
      local _amode="${1#--}"; shift || true
      local _aresult; _aresult=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 "$SKILL_DIR/scripts/gk_audit_state.py" "--$_amode" 2>>"$GK_DBG_LOG" || echo "{\"error\":\"$(tail -3 "$GK_DBG_LOG" 2>/dev/null | tr '\n' ' ' | head -c 200)\"}")
      echo "{\"ok\":true,\"audit_mode\":\"$_amode\",\"result\":$_aresult}" ;;
    --memory|memory)
      # R-T6 Phase 4b 补课 (2026-08-23): 原 bash heredoc (L4628-4650, 硬编码 ECC 路径)
      # 迁移为独立 gk_audit_memory.py — 输出契约不变 (history_count/ecc_files_found/
      # calibration_trend/calibration_samples/history_entries), SKILL_DIR 参数化
      local result; result=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 "$SKILL_DIR/scripts/gk_audit_memory.py" 2>>"$GK_DBG_LOG" || echo "{\"history_count\":0,\"ecc_files_found\":0,\"calibration_trend\":\"stable\",\"calibration_samples\":0,\"history_entries\":[],\"error\":\"$(tail -3 "$GK_DBG_LOG" 2>/dev/null | tr '\n' ' ' | head -c 200)\"}")
      # 2026-10-28（E2 覆盖率）：原只 echo ⟹ `audit_memory_result` 被 deny 集合声明为
      #   「审计侧单一写者落库」却**零生产者**（判据侧永远读不到）。补真落盘，写法与
      #   --state/--docs 同构（临时文件 + `_state_write`，flock + checksum 重算）。
      local _tmp_mem; _tmp_mem=$(mktemp)
      echo "$result" > "$_tmp_mem"
      GK_PY_TMP="$(_gk_py_path "$_tmp_mem")" _state_write "d.setdefault('gate_data',{})['audit_memory_result']=json.load(open(os.environ['GK_PY_TMP']))"
      rm -f "$_tmp_mem"
      # 2026-10-28（B3b）：签发登记 sidecar。memory/crossr **不进**双读 required 域，
      # 但登记表按「当前存在的证据域」记账（后续升 required 时无需重跑登记）。
      python3 "${SKILL_DIR}/scripts/gk_audit_registry.py" register --state "$STATE_FILE" \
        ${_AUDIT_KEY_DIR:+--key-dir "$_AUDIT_KEY_DIR"} --source audit_memory \
        >>"${GK_DBG_LOG:-/dev/null}" 2>&1 || echo "[audit-registry] WARN register(audit_memory) failed" >>"${GK_DBG_LOG:-/dev/null}"
      echo "{\"ok\":true,\"audit_mode\":\"memory\",\"result\":$result}" ;;
    --egress|egress)
      # Q3e 残项（2026-10-11，ECC-DF7FC6860957）：egress JSONL **只读审计**摘要（总数/ok/by_host/by_via/failures）。
      # 委托单源 gk_evidence.summarize_egress（禁第二实现）；不新增命令（_CMD_REG 在 PROTECTED_REGION::gate 内），
      # 只在区外函数体开分支（同 state-patch/calibrate 先例）。
      local _eres; _eres=$(python3 "$SKILL_DIR/scripts/gk_evidence.py" summarize-egress 2>>"$GK_DBG_LOG" || echo '{"error":"egress_audit_failed"}')
      echo "{\"ok\":true,\"audit_mode\":\"egress\",\"result\":$_eres}" ;;
    --crossr|crossr)
      # R-T6 Phase 5 (2026-08-20): 核心分析迁移至 gk_audit_crossr.py
      # （GITSCAN env 合并 git 并发检测，替代原 heredoc + 二次 python3 -c 合并）
      # 2026-09-01: L1 扩展实装 — GWSCAN env 追加 git-workflow 全量检测
      # （gk_git_workflow_check.py：protected/detached/merge/dirty/unpushed/stale/worktree/hooks/loader）
      local gitscan; gitscan=$(python3 "${SKILL_DIR}/scripts/gk_git_concurrency_check.py" "$SKILL_DIR" 2>>"$GK_DBG_LOG" || echo '{"ok":false}')
      local gwscan; gwscan=$(python3 "${SKILL_DIR}/scripts/gk_git_workflow_check.py" "$SKILL_DIR" 2>>"$GK_DBG_LOG" || echo '{"ok":false}')
      local result; result=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" GITSCAN="$gitscan" GWSCAN="$gwscan" SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 "$SKILL_DIR/scripts/gk_audit_crossr.py" 2>>"$GK_DBG_LOG" || echo "{\"rejected_count\":0,\"rejection_convergence\":\"stable\",\"error\":\"$(tail -3 "$GK_DBG_LOG" 2>/dev/null | tr '\n' ' ' | head -c 200)\"}")
      # 2026-10-28（E2 覆盖率）：补真落盘（同 --memory 注释）。**只落确定性结果** ——
      #   下面的 `llm_analysis` 是 LLM 注解（非确定性面），不进证据键。
      local _tmp_crossr; _tmp_crossr=$(mktemp)
      echo "$result" > "$_tmp_crossr"
      GK_PY_TMP="$(_gk_py_path "$_tmp_crossr")" _state_write "d.setdefault('gate_data',{})['audit_crossr_result']=json.load(open(os.environ['GK_PY_TMP']))"
      rm -f "$_tmp_crossr"
      # 2026-10-28（B3b）：签发登记 sidecar（只记确定性证据摘要，LLM 注解不入账）。
      python3 "${SKILL_DIR}/scripts/gk_audit_registry.py" register --state "$STATE_FILE" \
        ${_AUDIT_KEY_DIR:+--key-dir "$_AUDIT_KEY_DIR"} --source audit_crossr \
        >>"${GK_DBG_LOG:-/dev/null}" 2>&1 || echo "[audit-registry] WARN register(audit_crossr) failed" >>"${GK_DBG_LOG:-/dev/null}"
      # LLM analysis for cross-R patterns via subagent_runner (unified security layer)
      # 2026-09-09：GK_NO_LLM=1（audit --crossfull 串行器置位）→ 跳过内嵌 LLM——
      # L2/后R subagent 车道由统一启动器标记手动单触发，不随确定性车道每次白烧。
      local api_key="${API_KEY}"
      [ -z "$api_key" ] && { _resolve_api_key; api_key="$API_KEY"; }
      if [ -n "$api_key" ] && [ -z "${GK_NO_LLM:-}" ]; then
        _resolve_provider_config
        # 2026-08-15 fix: --max-turns 3 太紧 — subagent 3 轮内完不成分析 → "Max turns exceeded"
        # → conclusion 缺失 → llm_analysis 静默为空（曾致 LLM 分析从未激活）。
        # 2026-08-15 二修: 改为下限 50（SUBAGENT_MAX_TURNS 可配置，默认与 runner 一致），
        # 避免复杂分析再撞轮数上限。SUBAGENT_MAX_TOKENS 用 export 防 env 前缀解析陷阱。
        export SUBAGENT_MAX_TOKENS="${SUBAGENT_MAX_TOKENS:-4000}"
        # 2026-10-31（ECC 落盘缺口，`gk_ecc_sink`）：原式把 runner 输出**直管进** field
        #   conclusion ⟹ 整份 EccOutput 丢弃（无文件/无卫星片/无索引 ⟹ 不可复盘、MoA 不可见）。
        #   改为先留原文 → 经中枢落盘（与质询同构）→ 再抽 conclusion。落盘失败只留痕不阻断。
        local llm_raw; llm_raw=$(_subagent_exec "${SKILL_DIR}/scripts/subagent_runner.py" \
          --task "Analyze cross-R audit data. Output JSON: {\"pattern_assessment\":\"converging|diverging|stable\",\"recurring_issues\":[\"...\"],\"recommendations\":[\"...\"],\"summary\":\"...\"}. DATA: $result" \
          --mode auditor --api-key "$api_key" --api-base "$API_BASE" --api-model "$API_MODEL" \
          --reasoning "$DS_REASONING_EFFORT" --max-turns "${SUBAGENT_MAX_TURNS:-50}" 2>/dev/null || echo "")
        if [ -n "$llm_raw" ]; then
          printf '%s' "$llm_raw" | python3 "${SKILL_DIR}/scripts/gk_ecc_sink.py" persist \
            --state "$STATE_FILE" --domain audit --batch "crossr-$(date +%Y%m%dT%H%M%S)-$$" \
            --arm crossr --md >>"${GK_DBG_LOG:-/dev/null}" 2>&1 \
            || echo "[ecc-sink] WARN audit --crossr 落盘失败" >>"${GK_DBG_LOG:-/dev/null}"
        fi
        local llm_analysis; llm_analysis=$(printf '%s' "$llm_raw" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field conclusion --default '' 2>/dev/null || echo "")
        [ -n "$llm_analysis" ] && result=$(echo "$result" | LLM_ANALYSIS="$llm_analysis" python3 "$SKILL_DIR/scripts/gk_views.py" llm-analysis-merge 2>/dev/null || echo "$result")
      fi
      echo "{\"ok\":true,\"audit_mode\":\"crossr\",\"result\":$result}" ;;
    --pdg|pdg)
      # 2026-09-01 L3/L5 扩展实装：PDG 程序依赖图 + 污点分析统一入口
      # （gk_gitnexus_pdg_check.py：CDG/REACHING_DEF 死代码第二关 + TAINTED/TAINT_PATH 污点补 hook 盲区）
      # 依赖：仓库已 `node .gitnexus/run.cjs analyze --pdg` 建层（gitnexus.json pdg 字段）。
      # 用法：audit --pdg [--symbol <fn>] [--limit <n>] [--repo <name>] [--supply]
      # F-REV-75：`pdg_repo` 默认值**去硬编码**（原写死 spz-gatekeeper-r-sequence = F-REV-71 族）——
      # 省略即由脚本消费 GX_REPO（单源 `_gx_repo_name_for_dir`）；仍空则脚本 fail-loud。
      local pdg_symbol="" pdg_repo="" pdg_limit="50" pdg_supply=""
      while [ $# -gt 0 ]; do
        case "$1" in
          --symbol) pdg_symbol="${2:-}"; shift 2 2>/dev/null || shift ;;
          --limit) pdg_limit="${2:-}"; shift 2 2>/dev/null || shift ;;
          --repo) pdg_repo="${2:-}"; shift 2 2>/dev/null || shift ;;
          --supply) pdg_supply="--supply"; shift ;;
          *) shift ;;
        esac
      done
      local pdg_result; pdg_result=$(python3 "${SKILL_DIR}/scripts/gk_gitnexus_pdg_check.py" \
        ${pdg_symbol:+--symbol "$pdg_symbol"} --limit "$pdg_limit" ${pdg_repo:+--repo "$pdg_repo"} $pdg_supply 2>>"$GK_DBG_LOG" \
        || echo "{\"ok\":false,\"pdg_layer\":false,\"error\":\"$(tail -3 "$GK_DBG_LOG" 2>/dev/null | tr '\n' ' ' | head -c 200)\"}")
      echo "{\"ok\":true,\"audit_mode\":\"pdg\",\"result\":$pdg_result}" ;;
    --pr|pr)
      # 2026-09-01 L10 扩展实装：PR 级审查（gitnexus-pr-review 本地等价）
      # （gk_pr_review_check.py：detect-changes compare → 变更符号/受影响流程/风险等级）
      # 用法：audit --pr --base <ref> [--symbol <fn>] [--repo <name>] [--limit <n>]
      # F-REV-75：`pr_repo` 默认值**去硬编码**（同 --pdg 分支，原写死 = F-REV-71 族）。
      local pr_base="" pr_symbol="" pr_repo="" pr_limit="50"
      while [ $# -gt 0 ]; do
        case "$1" in
          --base) pr_base="${2:-}"; shift 2 2>/dev/null || shift ;;
          --symbol) pr_symbol="${2:-}"; shift 2 2>/dev/null || shift ;;
          --repo) pr_repo="${2:-}"; shift 2 2>/dev/null || shift ;;
          --limit) pr_limit="${2:-}"; shift 2 2>/dev/null || shift ;;
          *) shift ;;
        esac
      done
      if [ -z "$pr_base" ]; then
        echo "{\"ok\":false,\"audit_mode\":\"pr\",\"error\":\"audit --pr --base <ref> required（对比基准，如 HEAD~1）\"}"
        return 1
      fi
      local pr_result; pr_result=$(python3 "${SKILL_DIR}/scripts/gk_pr_review_check.py" \
        --base "$pr_base" ${pr_repo:+--repo "$pr_repo"} --limit "$pr_limit" \
        ${pr_symbol:+--symbol "$pr_symbol"} 2>>"$GK_DBG_LOG" \
        || echo "{\"ok\":false,\"error\":\"$(tail -3 "$GK_DBG_LOG" 2>/dev/null | tr '\n' ' ' | head -c 200)\"}")
      echo "{\"ok\":true,\"audit_mode\":\"pr\",\"result\":$pr_result}" ;;
    --coverage|coverage)
      # E1 变更面证据探针（2026-09-06 实装，§15.1 P2 → §15.6 ㉕③ 落点：质询前置证据命令）。
      # 只产变更面事实（文件面 git diff + 符号面 gitnexus detect-changes → 组件分类 →
      # 层需求映射 + NO-DETECT 标注），收敛/层扩展决策交 plan-refinement 质询子集。
      # 用法：audit --coverage [<scope>|--base <ref>] [--repo <name>] [--repo-dir <dir>] [--no-symbols]
      # A4 合规：无新 _CMD_REG 命令（扩展既有 audit）。
      # F-REV-75：`cov_repo` 默认值**去硬编码**（原写死 spz-gatekeeper-r-sequence = F-REV-71 族）
      # —— 省略即由脚本消费 GX_REPO（单源 `_gx_repo_name_for_dir`）。
      local cov_base="HEAD~1" cov_repo="" cov_dir="" cov_no_sym="" cov_pos=""
      while [ $# -gt 0 ]; do
        case "$1" in
          --base) cov_base="${2:-}"; shift 2 2>/dev/null || shift ;;
          --repo) cov_repo="${2:-}"; shift 2 2>/dev/null || shift ;;
          --repo-dir) cov_dir="${2:-}"; shift 2 2>/dev/null || shift ;;
          --no-symbols) cov_no_sym="--no-symbols"; shift ;;
          -*) shift ;;                      # scope 自身（--coverage）等跳过
          *) cov_pos="$1"; shift ;;         # 位置参数 = scope（如 HEAD~3）
        esac
      done
      [ -n "$cov_pos" ] && cov_base="$cov_pos"
      [ -z "$cov_dir" ] && cov_dir=$(_gx_repo_dir_for_current)
      [ -z "$cov_dir" ] && cov_dir="$SKILL_DIR"
      local cov_result; cov_result=$(GK_COV_DIR="$cov_dir" python3 "${SKILL_DIR}/scripts/gk_audit_coverage.py" \
        --base "$cov_base" ${cov_repo:+--repo "$cov_repo"} $cov_no_sym 2>>"$GK_DBG_LOG" \
        || echo "{\"ok\":false,\"probe\":\"E1-coverage\",\"error\":\"$(tail -3 "$GK_DBG_LOG" 2>/dev/null | tr '\n' ' ' | head -c 200)\"}")
      echo "{\"ok\":true,\"audit_mode\":\"coverage\",\"result\":$cov_result}" ;;
    --crossfull|crossfull)
      # ── 统一启动器：runbook 0-13 全量串行执行器（2026-09-09 实装，2026-09-09 补全 LLM 车道）──
      # 治本根因（用户质询"交叉审查每轮都有遗漏"）：runbook = 文本契约依赖 agent 逐 step
      # 自律执行 → LLM step omission 必然复发。audit --crossfull = 一条命令串行实跑：
      #   确定性车道：E1 coverage → L1 crossr → L3 pdg(taint) → L6 doc-align → L7 audit-hook →
      #               L8 self-check → L9 monitor --local → L10 audit-red → L10b bomb
      #   LLM 车道：  L2 monitor --subagent --crossrev（code-to-spec）→ 后R 双独立互斥 ×2
      #               （auditor 五域审计 / exploiter 攻击链，串行 = 互斥调度，双报告齐全才 advance）
      #   MANUAL 注记：L4 版本表 / L5 RedFlags / node-guard / 计划质询 / step13 处置（无 CLI 数据源
      #               或需人工/参数 → 诚实标注，防"全量=自动已跑"误判）
      # 语义：GK_NO_LLM=1 → 子命令内嵌 LLM（crossr）跳过；LLM 车道步去 GK_NO_LLM 实跑；
      #   GK_CROSSFULL_SUBAGENT=0 → 整条 LLM 车道 SKIP（快速确定性模式）；
      #   pdg_layer=false → L3 WARN(层缺) + L5 TAINTED NOT-RUN 联动（不静默）；
      #   L2/后R 输出提取 conclusion+confidence；受限/失败 → WARN(受限) 显式标注。
      # 用法：audit --crossfull [<base>|--base <ref>] [--repo <name>] [--state <path>] [--isolate]
      #   （缺省 base=HEAD~10 近 10 commit；--repo = 目标仓库名（gitnexus registry）；--state = 独立 state；
      #    --isolate = 独立 worktree + 独立 state（F-REV-30），前置调 register（F-REV-39））
      local _cf_base="HEAD~10" _cf_repo="" _cf_state="" _cf_isolate=0
      while [ $# -gt 0 ]; do
        case "$1" in
          --base) _cf_base="${2:-}"; shift 2 2>/dev/null || shift ;;
          --repo) _cf_repo="${2:-}"; shift 2 2>/dev/null || shift ;;
          --state) _cf_state="${2:-}"; shift 2 2>/dev/null || shift ;;
          --isolate) _cf_isolate=1; shift ;;
          -*) shift ;;
          *) _cf_base="$1"; shift ;;
        esac
      done
      # ── 目标解析（F-REV-39，2026-09-13）：--repo 名 → 目录；未命中 fail-loud（禁静默回退技能目录）──
      local _cf_dir=""
      local _cf_skill_dir="$SKILL_DIR" _cf_cwd="$SKILL_DIR" _cf_state_eff="$STATE_FILE" _cf_target_is_skill=1
      if [ -n "$_cf_repo" ]; then
        _cf_dir="$(_gx_dir_for_repo_name "$_cf_repo")"
        if [ -z "$_cf_dir" ]; then
          echo '{"ok":false,"error":"unknown_repo","detail":"'"$_cf_repo"' 未在 gitnexus registry — 先 project-register register（A3 建基线）"}'
          return 2
        fi
        export GK_GX_DIR="$_cf_dir"
        _cf_target_is_skill=0
      fi
      # ── 隔离（F-REV-30，2026-09-13）：独立 worktree + 独立 state；前置调 register（单源，不复制注册逻辑）──
      if [ "$_cf_isolate" = "1" ]; then
        local _cf_iso_src="${_cf_dir:-$SKILL_DIR}"
        if [ ! -e "$_cf_iso_src/.git" ]; then
          echo '{"ok":false,"error":"isolate_requires_git","detail":"'"$_cf_iso_src"' 非 git 仓 — 无法建隔离 worktree（可改用 --state 指定独立 state）"}'
          return 2
        fi
        # 隔离根：`GATEKEEPER_WORKTREE_ROOT` 优先；否则取**单源** `DEV_WORKTREE_ROOTS[0]`
        # （`gk_apply_worktree_cli.py route-root`，禁第二份机器路径）；仍空 ⟹ 宿主 temp。
        local _cf_wt_root="${GATEKEEPER_WORKTREE_ROOT:-}"
        if [ -z "$_cf_wt_root" ]; then
          local _cf_root0
          _cf_root0=$(python3 "${SKILL_DIR}/scripts/gk_apply_worktree_cli.py" route-root 2>/dev/null || true)
          if [ -n "$_cf_root0" ]; then
            _cf_wt_root="${_cf_root0%/}/$(basename "$SKILL_DIR")/dryrun"
          else
            _cf_wt_root="${TMPDIR:-/tmp}/gk-crossfull-wt"
          fi
        fi
        local _cf_ts; _cf_ts=$(date +%Y%m%d-%H%M%S)
        local _cf_wt="${_cf_wt_root}/crossfull-${_cf_ts}"
        mkdir -p "$_cf_wt_root" 2>/dev/null || true
        if ! git -C "$_cf_iso_src" worktree add --detach "$_cf_wt" "$_cf_base" >/dev/null 2>>"$GK_DBG_LOG"; then
          echo '{"ok":false,"error":"worktree_add_failed","detail":"'"$_cf_wt"'"}'
          return 2
        fi
        # 2026-09-21（隔离面继承）：隔离 worktree 须继承**身份/密钥面** —— `.keys/` 被
        # `.gitignore:19` 排除、不入 HEAD 树（实测 `git ls-tree -r HEAD -- .keys` 为空）⟹
        # 嵌套 CLI 的 `SKILL_DIR` = 本 worktree（脚本目录派生，外部 env 不生效）⟹
        # `_CONTEXT_PUB_KEY` = `<wt>/.keys/context_ed25519.pub` 指空 ⟹ `_ctx_inject_probe` 恒
        # `sig_invalid` ⟹ preflight A 硬阻断；且自愈门（`context --update` 重签）需 `<wt>/.keys/
        # context_ed25519.pem`，**同缺**，必然失败 ⟹ 失败以 L2=`WARN(受限)` 呈现而 crossfull 整体
        # **rc=0**（**假绿** —— 比显式失败更坏）。
        # 纪律：继承「身份/密钥/治理范围」面，**隔离「状态」面**（state 仍走 `_cf_state_eff`）。
        # 软链而非复制 ⟹ 密钥单源（宿主 `.keys` 为唯一事实源），worktree 移除即消失。
        if [ -d "$_cf_iso_src/.keys" ] && [ ! -e "$_cf_wt/.keys" ]; then
          if ln -s "$_cf_iso_src/.keys" "$_cf_wt/.keys" 2>>"$GK_DBG_LOG"; then
            echo "[crossfull] isolate .keys inherited <- $_cf_iso_src/.keys $(date -u +%FT%TZ)" >> "$GK_DBG_LOG"
          else
            echo '{"ok":false,"error":"isolate_keys_inherit_failed","detail":"'"$_cf_wt"'/.keys — 隔离态将 sig_invalid（假绿风险），拒绝继续"}'
            return 2
          fi
        fi
        if [ -n "$_cf_repo" ]; then
          bash "$SKILL_DIR/gatekeeper-cli.sh" project-register register "$_cf_repo" \
            --state "${_cf_state:-${_cf_iso_src}/.gatekeeper.state}" \
            --note "crossfull --isolate 自动注册（F-REV-30/39）" >/dev/null 2>>"$GK_DBG_LOG" || true
        fi
        _cf_state_eff="${_cf_state:-${_cf_wt_root}/crossfull-${_cf_ts}.state}"
        # P0-2 负向断言（2026-09-13）：本段只应写副本 state，父 state 必须只读
        #（原设计拟调 _state_checksum_write，其硬绑 $STATE_FILE → 会改写父 state，已取消）
        _cf_src_sum=$(sha256sum "$STATE_FILE" 2>/dev/null | cut -c1-16)
        # 隔离 state 须描述隔离 worktree（否则 gk_state_route 判"state 归属冲突"并纠正 → 与 cwd 不一致）；
        # P0-2（2026-09-13）节点绑定对齐 preflight C 白名单：standing → ECO-VERIFY（A4 合并前为
        #   ECO-AUDIT，旧名由 gk_node_guard.canon_eco 归一），非 standing → AUDIT-CROSSR
        #（project_type 在 gate_data 下、顶层为 None）—— 逻辑已收归 gk_state_ops.py crossfull-copy。
        python3 "$SKILL_DIR/scripts/gk_state_ops.py" crossfull-copy "$STATE_FILE" "$_cf_state_eff" "$_cf_wt" 2>>"$GK_DBG_LOG" || true
        _cf_src_sum2=$(sha256sum "$STATE_FILE" 2>/dev/null | cut -c1-16)
        if [ "$_cf_src_sum" != "$_cf_src_sum2" ]; then
          echo "WARN: [crossfull] 父 state 在副本写入段被改动（${_cf_src_sum} → ${_cf_src_sum2}）— 本段应只读父 state" >>"$GK_DBG_LOG"
        fi
        _cf_cwd="$_cf_wt"
        _cf_skill_dir="$_cf_wt"
        export GK_CF_ISOLATED=1 GK_CF_WORKTREE="$_cf_wt"
      fi
      [ -n "$_cf_state" ] && _cf_state_eff="$_cf_state"
      export GK_NO_LLM=1
      SKILL_DIR="$_cf_skill_dir" STATE_FILE="$_cf_state_eff" GK_DBG_LOG="$GK_DBG_LOG" \
        GK_CF_CWD="$_cf_cwd" GK_CF_TARGET_IS_SKILL="$_cf_target_is_skill" \
        python3 - "$_cf_base" <<'CROSSFULL_PY'
import hashlib, json, os, subprocess, sys
cli = os.path.join(os.environ["SKILL_DIR"], "gatekeeper-cli.sh")
dbg = os.environ.get("GK_DBG_LOG", os.devnull)
env = dict(os.environ, GK_NO_LLM="1")
base = sys.argv[1]

def run(args, timeout=1800, no_llm=True):
    """no_llm=True → 子命令内嵌 LLM 跳过（确定性步）；LLM 车道步（L2/后R）no_llm=False（去 GK_NO_LLM）。"""
    err = ""
    _run_env = dict(env)
    if not no_llm:
        _run_env.pop("GK_NO_LLM", None)
    try:
        p = subprocess.run(["bash", cli] + args, capture_output=True, text=True,
                           timeout=timeout, env=_run_env,
                           cwd=os.environ.get("GK_CF_CWD") or os.environ["SKILL_DIR"])
        out, err, rc = p.stdout, p.stderr, p.returncode
    except Exception as e:
        out, err, rc = "", str(e), 1
    with open(dbg, "a", encoding="utf-8", errors="replace") as f:
        f.write("crossfull %s -> rc=%d\n" % (" ".join(args), rc))
    return rc, out, err

def val(out, keys, default=None):
    try:
        d = json.loads(out)
    except Exception:
        return default
    for k in keys:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return default
    return d

def ws_fingerprint():
    """LLM 车道**读取面**（GK_CF_CWD）的工作树一致性指纹（ECC-130ECB1ABCA4，2026-09-28）。

    判据**单源** = scripts/gk_git_concurrency_check.py --ws-fingerprint（禁第二份实现）。
    不可用（非 git 仓/git 缺失）→ None，调用方须显式标 NOT-RUN，**不得**当成"一致"。
    ⚠ 本 docstring 位于 bash 双引号/heredoc 区内 ⟹ **禁写 ASCII 反引号**
      （族 ECC-186B99627299；本处曾因此被 test_cli_double_quoted_regions_have_no_backticks
      判红 —— 2026-09-28 由全量回归抓出并修，见 §十三-K）。
    """
    repo = os.environ.get("GK_CF_CWD") or os.environ["SKILL_DIR"]
    try:
        p = subprocess.run([sys.executable, os.path.join(os.environ["SKILL_DIR"], "scripts",
                           "gk_git_concurrency_check.py"), "--ws-fingerprint", repo],
                           capture_output=True, text=True, timeout=300)
        return json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip() else None
    except Exception:
        return None

steps = []
def step(sid, name, args, keys):
    rc, out, err = run(args)
    v = val(out, keys)
    if rc != 0 or (rc == 0 and not out.strip() and err.strip()):
        st = "FAIL"; detail = (err or out).strip().splitlines()[-1][:110] if (err or out).strip() else "no output"
    elif v is False or v is None and not out.strip():
        st = "FAIL"; detail = (err or "no output").strip()[:110]
    else:
        st = "OK"
        detail = str(v)[:110] if v is not None else out.strip().splitlines()[0][:110] if out.strip() else "OK"
        if isinstance(v, (dict, list)):
            detail = json.dumps(v, ensure_ascii=False)[:110]
    steps.append({"id": sid, "name": name, "status": st, "detail": detail})
    print("[%s] %-21s %s  %s" % (sid, name, st, detail), flush=True)

# 非技能目标（--repo）→ 技能专属步显式 SKIP（不静默、不计 FAIL）—— F-REV-39（2026-09-13）：
# 串行器步骤集面向技能自身（doc-align/self-check/audit-hook/bomb 均为技能面）；
# 对非技能仓库这些步不适用，须显式标注而非产 FAIL 噪音。
_non_skill = os.environ.get("GK_CF_TARGET_IS_SKILL", "1") == "0"

def skip_nonskill(sid, name, why):
    if not _non_skill:
        return False
    steps.append({"id": sid, "name": name, "status": "SKIP",
                  "detail": "non-skill target：%s 不适用" % why})
    print("[%s] %-21s SKIP  non-skill target" % (sid, name), flush=True)
    return True

# ── P0-3 shadow register（2026-09-13）：postR/L2 产物「本应收录」清单（**只产不写**）──
# 治 D3「postR 产物黑洞」：本段原只取 conclusion/confidence ⟹ ecc_findings 恒空、step13 恒 MANUAL。
# 契约复用（防第二事实源）：抽取面 = EccOutput.evidence(file/lines/status/note)；
#   verdict 词表 = gk_adjudicate 逐域契约（PASS / 非 PASS）；去重 = 显式 sha256 指纹
#   （**不用** gk_finding.reconcile —— 其为 state↔journal 代际对账，语义不同）。
# shadow 首发：不写 journal、不写 state（转正判据 = shadow 自身数据，见计划 §2 P0-3）。
_shadow, _shadow_stat = [], {}

def shadow_extract(sid, family, cover_layers, out):
    """抽「本应收录」候选 → _shadow（family/cover_layers 必填、显式指纹去重）。

    cover_layers = 该步自身车道承载的审查层（shadow 期占位，转正前由计划质询子集复核）。
    返回 (新增, 重复跳过)；输出非 JSON / 无 evidence / 无定位锚 → 不计入（不产低质条目）。
    """
    try:
        d = json.loads(out)
    except Exception:
        return 0, 0
    if not isinstance(d, dict):
        return 0, 0
    ev = d.get("evidence")
    ev = ev if isinstance(ev, list) else []
    added = dup = 0
    for e in ev:
        if not isinstance(e, dict):
            continue
        _file, _lines = str(e.get("file", "")), str(e.get("lines", ""))
        _note = str(e.get("note", "") or "")
        if not _file:                      # 无定位锚 → 低质候选，不收（治"清单非空但劣质"）
            continue
        fp = hashlib.sha256(("%s|%s|%s|%s" % (_file, _lines, _note[:80], family))
                            .encode("utf-8")).hexdigest()[:16]
        if any(s["fingerprint"] == fp for s in _shadow):
            dup += 1
            continue
        _st = str(e.get("status", "suspect")).lower()
        _shadow.append({
            "fingerprint": fp,
            "source": "crossr",                       # register 合法 source（非 red/review ⟹ cover 自愿）
            "family": family,                         # 必填（P0-3 ④）
            "cover_layers": list(cover_layers),       # 必填（P0-3 ④）
            "gap": False,
            "verdict": "PASS" if _st == "confirmed" else "FAIL",   # 复用 gk_adjudicate 词表
            "evidence_status": _st,
            "title": "%s:%s — %s" % (_file, _lines, (_note or str(d.get("conclusion", "")))[:80]),
            "confidence": d.get("confidence", ""),
            "step": sid,
        })
        added += 1
    _shadow_stat[sid] = {"added": added, "deduped": dup,
                         "evidence_total": len(ev), "family": family}
    return added, dup

# monitor --local 需要 stage 参数（从当前 state 自动注入，免手动传）
_stage = ""
try:
    _sf = os.environ.get("STATE_FILE") or os.path.join(os.environ["SKILL_DIR"], ".gatekeeper.state")
    with open(_sf, encoding="utf-8") as _f:
        _stage = json.load(_f).get("stage", "")
except Exception:
    _stage = ""
_monitor_args = ["monitor", "--local"] + ([_stage] if _stage else [])
# 2026-09-21（R6a 拆硬编码）：L2 任务面**不再写死**。来源优先级（单源，与 L5 中枢同源）：
#   ① GK_CROSSFULL_L2_TASKS（env，';' 分隔）—— 显式注入（可携带本阶段候选假设）
#   ② gate_data.narrow_tasks[].task —— **同一份清单**即 L5 `resolve-narrow` 的事实源，同时
#      满足 node_guard「narrow_tasks[] 非空」前置（消除"门禁要清单、编排器却不吃清单"的分叉）
#   ③ _L2_TASK_DEFAULT —— 本文件**唯一**出现处的兜底；来源为 default 时 L2 记
#      WARN(默认任务)，使「未注入」可见，而非静默跑默认串
_L2_TASK_DEFAULT = ("L2 code-to-spec 审查: 近 %s commit 变更面（audit --crossfull 确定性车道结果见各步输出）")
_L2_MAX_TASKS = 3


def _l2_tasks(base):
    """L2 任务面单源取任务 → (任务列表, 来源标签)。"""
    env = [t.strip() for t in os.environ.get("GK_CROSSFULL_L2_TASKS", "").split(";") if t.strip()]
    if env:
        return env[:_L2_MAX_TASKS], "injected"
    try:
        with open(_sf, encoding="utf-8") as _f:
            _nt = json.load(_f).get("gate_data", {}).get("narrow_tasks") or []
        ts = [str(e.get("task", "")).strip() for e in _nt if isinstance(e, dict)]
        ts = [t for t in ts if t]
        if ts:
            return ts[:_L2_MAX_TASKS], "narrow_tasks"
    except Exception:
        pass
    return [_L2_TASK_DEFAULT % base], "default"

step("E1",  "coverage",      ["audit","--coverage","--base",base], ["result","probe","files"])
step("L1",  "crossr",        ["audit","--crossr"],                 ["result","rejected_count"])
# L3 pdg 特判：pdg_layer=false = 确定性命令工作正常但层缺失 → WARN(降级) 非 FAIL（不静默，L5 联动 NOT-RUN）
_r3c, _r3o, _r3e = run(["audit","--pdg"])
if _r3c != 0:
    _st3 = "FAIL"; _d3 = (_r3e or _r3o).strip().splitlines()[-1][:110] if (_r3e or _r3o).strip() else "no output"
elif '"pdg_layer": false' in _r3o:
    _st3 = "WARN(层缺)"
    try:
        _d3 = json.loads(_r3o).get("result", {}).get("recommendation", "pdg_layer=false")[:110]
    except Exception:
        _d3 = "pdg_layer=false"
else:
    _st3 = "OK"; _d3 = "pdg_layer=true"
steps.append({"id": "L3", "name": "pdg-layer", "status": _st3, "detail": _d3})
print("[L3] pdg-layer          %s  %s" % (_st3, _d3), flush=True)
# ── LLM 车道**读取面**取前快照（判据/断言见文末「工作树一致性断言」段，@ECC-130ECB1ABCA4）──
_ws_pre = ws_fingerprint()
# L2 code-to-spec（runbook step 3；受限 agent ×N，--crossrev 显式通道；
# 节点绑定由 preflight C 判定（R5 已修：判据键 = 序列命名空间）；任务面由 _l2_tasks 单源供给；
# GK_CROSSFULL_SUBAGENT=0 可跳过 LLM 车道）
if os.environ.get("GK_CROSSFULL_SUBAGENT", "1") != "0":
    _l2ts, _l2src = _l2_tasks(base)
    _l2ok, _l2dets, _l2anch = 0, [], []
    for _t in _l2ts:
        _l2rc, _l2o, _l2e = run(["monitor", "--subagent", "--crossrev", "--role", "auditor", _t],
                                no_llm=False)
        if _l2rc == 0 and '"conclusion"' in _l2o:
            _l2ok += 1
            try:
                _l2j = json.loads(_l2o)
                _l2dets.append(str(_l2j.get("conclusion", ""))[:70]
                               + " conf=" + str(_l2j.get("confidence", "")))
                # F-REV-97 消费端（2026-09-22，红队 C2 修复）：evidence 定位锚机检结果
                # 由此前**无消费方**的 runner 自述字段升级为**步态判据** —— 缺锚即降级留痕。
                # 这闭合了红队实测的缺口：「门禁产出契约只有 result/gap，锚点质量零校验」
                # 与 instructions 的锚点要求之间缺失的**强制校验环**。
                _ea = _l2j.get("evidence_anchor") or {}
                if _ea.get("status") == "incomplete":
                    _l2anch.append("锚缺: " + ",".join(
                        str(x) for x in (_ea.get("unanchored") or [])[:3]))
            except Exception:
                _l2dets.append(_l2o.strip().splitlines()[0][:90] if _l2o.strip() else "ok")
            # P0-3 shadow：L2 车道承载 L2 code-to-spec 层（逐任务登记，替代原单次登记）
            _sn, _sd = shadow_extract("L2", "code-to-spec", ["L2"], _l2o)
            print("[L2] shadow-register   +%d 候选（去重跳过 %d）" % (_sn, _sd), flush=True)
        else:
            _l2dets.append("失败: " + ((_l2e or _l2o).strip().splitlines()[-1][:90]
                                     if (_l2e or _l2o).strip() else "no output"))
    if _l2ok == len(_l2ts):
        _l2st = "WARN(默认任务)" if _l2src == "default" else "OK"
    elif _l2ok:
        _l2st = "WARN(部分)"
    else:
        _l2st = "FAIL"
    # F-REV-97（红队 C2）：锚缺是最强降级信号，但**不掩盖**更严重的 FAIL/部分失败
    if _l2anch and _l2st == "OK":
        _l2st = "WARN(锚缺)"
    _l2dt = "src=%s %d/%d | " % (_l2src, _l2ok, len(_l2ts)) + " ; ".join(_l2dets + _l2anch)
else:
    _l2st = "SKIP"; _l2dt = "GK_CROSSFULL_SUBAGENT=0"
steps.append({"id": "L2", "name": "crossrev(LLM)", "status": _l2st, "detail": _l2dt})
print("[L2] crossrev(LLM)      %s  %s" % (_l2st, _l2dt), flush=True)
# L5 恒产独立步（P0-4，2026-09-13）：不依赖 PDG 层 —— L3=OK 时同样产 L5（治 D2「L5 缺位」）
_l3st = next((s["status"] for s in steps if s["id"] == "L3"), "UNKNOWN")
if _l3st == "OK":
    _l5st, _l5d = "OK", "pdg_layer=true — 经 pdg 层已在位"
else:
    _l5st, _l5d = "NOT-RUN", "pdg_layer=false — 先 node .gitnexus/run.cjs analyze --pdg 重建层"
steps.append({"id": "L5", "name": "TAINTED(经pdg)", "status": _l5st, "detail": _l5d})
print("[L5] TAINTED(经pdg)    %s  %s" % (_l5st, _l5d), flush=True)
if not skip_nonskill("L6", "doc-align", "技能文档/脚本面"):
    step("L6",  "doc-align",     ["doc-align"],                        ["issues"])
if not skip_nonskill("L7", "audit-hook", "技能 hook 配置面"):
    step("L7",  "audit-hook",    ["audit","--hook"],                   ["result","issues"])
if not skip_nonskill("L8", "self-check", "技能自检面"):
    step("L8",  "self-check",    ["self-check", "--tests", "quick"],   ["issues"])
step("L9",  "monitor-local", _monitor_args,                        ["score","verdict"])
step("L10", "red",           ["audit","--red"],                    ["result","gap"])
if not skip_nonskill("L10b", "bomb", "技能脚本扫描面"):
    step("L10b","bomb",          ["migrate","audit","--script", cli, "--bomb"], ["bomb_scan","total"])
# ── 后R 双独立（runbook step 12；互斥调度串行 ×2，双报告齐全才 advance）──
if os.environ.get("GK_CROSSFULL_SUBAGENT", "1") != "0":
    for _rid, _rname, _rtask, _rfam, _rlay, _rrole in (
        ("postR#1", "auditor 审计", "audit --all 五域 + 偏差分析: 近 %s commit 变更面" % base,
         "postR-five-domain", ["L1", "L3", "L6", "L8", "L10"], "auditor"),
        ("postR#2", "exploiter 红队", "基于 L10 findings 攻击链分析(利用/绕过/投毒面): 近 %s commit 变更面" % base,
         "postR-attack-chain", ["L10"], "exploiter")):
        _rr, _ro, _re = run(["monitor", "--subagent", "--role", _rrole, _rtask], no_llm=False)
        if _rr == 0 and '"conclusion"' in _ro:
            try:
                _rj = json.loads(_ro); _rs = "OK"; _rd = str(_rj.get("conclusion", ""))[:90] + " conf=" + str(_rj.get("confidence", ""))
            except Exception:
                _rs = "OK"; _rd = _ro.strip().splitlines()[0][:110] if _ro.strip() else "ok"
        else:
            _rs = "WARN(受限)"; _rd = (_re or _ro).strip().splitlines()[-1][:110] if (_re or _ro).strip() else "no output"
        steps.append({"id": _rid, "name": _rname, "status": _rs, "detail": _rd})
        print("[%s] %-21s %s  %s" % (_rid, _rname, _rs, _rd), flush=True)
        # P0-3 shadow：后R 双独立各自车道层（auditor 五域 / exploiter 攻击链）
        if _rs == "OK":
            _sn, _sd = shadow_extract(_rid, _rfam, _rlay, _ro)
            print("[%s] shadow-register   +%d 候选（去重跳过 %d）" % (_rid, _sn, _sd), flush=True)
else:
    for _rid, _rname in (("postR#1", "auditor 审计"), ("postR#2", "exploiter 红队")):
        steps.append({"id": _rid, "name": _rname, "status": "SKIP", "detail": "GK_CROSSFULL_SUBAGENT=0"})
        print("[%s] %-21s SKIP  GK_CROSSFULL_SUBAGENT=0" % (_rid, _rname), flush=True)
# ── 工作树一致性断言（`ECC-130ECB1ABCA4`，2026-09-28）──────────────────────────────
# 病灶（用户 2026-09-28 报告 + 读码定位）：本 runner 的 LLM 车道（L2 `--crossrev` / 后R 双独立）
# 以 `cwd=GK_CF_CWD` = **活动工作树** 运行（非 `--isolate` 时）；车道期间若有**并发编辑**
# （另一会话 / 编辑器 / agent 自身）⟹ L2 **读到半写/撕裂内容**，而本段原有并发断言**只覆盖父
# state**（见隔离段 `_cf_src_sum`），**工作树零断言** ⟹ 结论静默失真 = 本仓自认最坏的"假绿"。
# 修法（判据单源，禁第二份实现）：车道**前后各取一次** `--ws-fingerprint`，不等即
#   ① 打 loud 行 ② 把 L2 步降级为 `WARN(并发写)` ③ JSON 落 `worktree_fingerprint.changed_files`。
_ws_a, _ws_b = _ws_pre, ws_fingerprint()
_ws_info = {"before": (_ws_a or {}).get("fingerprint"), "after": (_ws_b or {}).get("fingerprint"),
            "changed_files": [], "consistent": None}
if _ws_a and _ws_b:
    _ba = {f["path"]: f["blob"] for f in _ws_a.get("files", [])}
    _bb = {f["path"]: f["blob"] for f in _ws_b.get("files", [])}
    _ws_ch = sorted(set(_ba) ^ set(_bb)) or sorted(
        p for p in (set(_ba) & set(_bb)) if _ba[p] != _bb[p])
    _ws_info["consistent"] = not _ws_ch
    _ws_info["changed_files"] = _ws_ch
    if _ws_ch:
        print("[WSc] worktree-consistency WARN  车道期间工作树被并发改动 %d 文件：%s ⟹ "
              "L2/后R 可能读到半写/撕裂快照" % (len(_ws_ch), ", ".join(_ws_ch[:5])), flush=True)
        for _s in steps:
            if _s["id"] == "L2" and _s["status"].startswith("OK"):
                _s["status"] = "WARN(并发写)"
                _s["detail"] = "工作树一致性断言不通过（车道期间被并发改动）| " + _s["detail"]
    else:
        print("[WSc] worktree-consistency OK    车道期间工作树未变（fp=%s）"
              % _ws_a.get("fingerprint"), flush=True)
else:
    print("[WSc] worktree-consistency NOT-RUN 指纹不可用（非 git 仓 / git 缺失）⟹ "
          "本段**无**一致性证据（不得读作一致）", flush=True)

# ── MANUAL 注记（无 CLI 数据源/需人工/需参数的 runbook 步——诚实标注非自动，防"全量=自动已跑"误判）──
for _mid, _mname, _mnote in (
    ("L4", "版本表人工", "requesting-code-review L4 YAML（上游依赖版本表 + external_shocks）数据源非 CLI — 人工对照"),
    ("L5R", "RedFlags 人工", "project_rules Red Flags 逐条人工核对（TAINTED 机械部分见 L5 联动）"),
    ("L9g", "node-guard", "node-guard <node> [--check-only] 需节点上下文参数 — 人工/按节点触发"),
    ("step11", "计划质询", "plan-refinement <plan> --task <质询> 需 plan+窄任务参数，非通用自动（单轮上限含质询 1 次）"),
    ("step13", "处置", "findings → E2 register(family/cover_layers) → journal → 余烬 → replay；修复后重跑受影响层")):
    steps.append({"id": _mid, "name": _mname, "status": "MANUAL", "detail": _mnote[:110]})
    print("[%s] %-21s MANUAL  %s" % (_mid, _mname, _mnote[:100]), flush=True)
print("---")
print(json.dumps({"ok": True, "audit_mode": "crossfull", "crossfull": {
    "base": base, "steps": steps,
    "target_is_skill": not _non_skill,
    "isolated": bool(os.environ.get("GK_CF_ISOLATED")),
    "worktree": os.environ.get("GK_CF_WORKTREE", ""),
    # ECC-130ECB1ABCA4（2026-09-28）：LLM 车道读取面的工作树一致性断言 ——
    # consistent=False ⟹ 车道期间被并发改动，L2/后R 结论可能是半写/撕裂读的产物（不可读作 OK）
    "worktree_fingerprint": _ws_info,
    # P0-3 shadow（2026-09-13）：postR/L2「本应收录」清单 + 逐步统计
    #（**只产不写**：不落 journal/state；显式指纹去重；family/cover_layers 必填）
    "shadow_findings": _shadow,
    "shadow_stat": _shadow_stat,
    "note": "runbook 0-13 全量：确定性车道(E1/L1/L3/L6/L7/L8/L9/L10/L10b) + LLM 车道(L2 --crossrev / 后R 双独立互斥) 串行实跑；"
            "GK_CROSSFULL_SUBAGENT=0 可跳过 LLM 车道；L4/L5人工/质询/处置 = MANUAL 标注非自动；"
            "P0-3 shadow_findings = 只产不写的应交收录清单（转正判据 = shadow 自身数据）；"
            "--repo <name> 目标化（技能专属步 SKIP）/ --state 独立 state / --isolate 独立 worktree+state（F-REV-30/39）。"}}, ensure_ascii=False))
CROSSFULL_PY
      ;;
    --report|report)
      local audit_type="performance" no_sign=false
       # Parse --type and --force (was --no-sign, now requires --force for emergencies)
       while [ $# -ge 2 ]; do
         case "${2:-}" in
           --type) audit_type="${3:-performance}"; shift 2 ;;
           --force) no_sign=true; shift ;;  # --no-sign renamed to --force, only for emergencies
           *) break ;;
         esac
       done
      # 6b: audit type validation
      case "$audit_type" in
        financial|compliance|performance|redteam) ;;
        *) echo "{\"ok\":false,\"error\":\"Invalid audit type. Valid: financial, compliance, performance, redteam\"}"; return 1 ;;
      esac
      # 6c: audit_id with PID + random component for uniqueness under concurrency
      local audit_id; audit_id="AUDIT-$(date +%Y%m%d)-$(date +%s | sha256sum | head -c 6)-$$-$(openssl rand -hex 2 2>/dev/null || echo "00")"
      local result; result=$(python3 "$SKILL_DIR/scripts/gk_views.py" audit-summary "$audit_id" "$audit_type" "$STATE_FILE" 2>/dev/null || echo '{}')
      # LLM generates the audit report
      local api_key="${API_KEY}"
      [ -z "$api_key" ] && { _resolve_api_key; api_key="$API_KEY"; }
      local report_content=""
      if [ "$audit_type" = "redteam" ]; then
        # Red team report: industry standard 6-section + ATT&CK mapping + per-finding evidence hash
        local rt_findings; rt_findings=$(python3 "$SKILL_DIR/scripts/gk_views.py" redteam-findings "$STATE_FILE" 2>/dev/null || echo '{"findings":[],"severity_counts":{},"total_findings":0,"mitre_mappings":[]}')
        local rt_summary; rt_summary=$(echo "$rt_findings" | python3 "$SKILL_DIR/scripts/gk_views.py" redteam-summary "$audit_id" "$STATE_FILE" 2>/dev/null || echo '{}')
        # shellcheck disable=SC2288,SC1083
        local rt_data; rt_data=$(echo "$rt_findings" | python3 "$SKILL_DIR/scripts/gk_views.py" redteam-report "$audit_id" "$STATE_FILE" 2>/dev/null || echo "# ECC-REDTEAM: $audit_id\\n\\nReport generation failed")
        report_content="$rt_data"
      elif [ -n "$api_key" ]; then
        _resolve_provider_config
        # I1: Use subagent_runner.py instead of raw curl for audit report generation
        local _tmp_audit_data; _tmp_audit_data=$(mktemp)
        echo "$result" > "$_tmp_audit_data"
        local _subagent_result; _subagent_result=$(_subagent_exec "${SKILL_DIR}/scripts/subagent_runner.py" \
          --task "Generate a structured audit report from this data: $(cat "$_tmp_audit_data" | head -c 4000)" \
          --mode auditor --tools state,read \
          --api-key "$api_key" --api-base "$API_BASE" --api-model "$API_MODEL" \
          --reasoning "$DS_REASONING_EFFORT" --max-turns 3 2>/dev/null || echo "")
        rm -f "$_tmp_audit_data"
        # 2026-10-31（ECC 落盘缺口，`gk_ecc_sink`）：报告生成臂的**原始 EccOutput** 此前只被
        #   用来拼正文，整份丢弃 ⟹ 与质询通道不对称（无文件/无片/无索引）。改为同构落盘；
        #   失败只留痕不阻断报告签发（报告 md + 签名仍是权威产物）。
        if [ -n "$_subagent_result" ]; then
          printf '%s' "$_subagent_result" | python3 "${SKILL_DIR}/scripts/gk_ecc_sink.py" persist \
            --state "$STATE_FILE" --domain audit --batch "$audit_id" --arm report --md \
            >>"${GK_DBG_LOG:-/dev/null}" 2>&1 \
            || echo "[ecc-sink] WARN audit --report 落盘失败" >>"${GK_DBG_LOG:-/dev/null}"
        fi
        if [ -n "$_subagent_result" ]; then
          # 2026-08-15: 修复 report 正文提取 —— ① --tools evidence,constants 不在 TOOL_REGISTRY → 工具集为空；
          # ② get('output'/'content') 错键（runner 顶层只发 conclusion）；③ json.loads('''$var''') 三引号注入
          # （_subagent_result 来自 LLM，不可信）。统一走 env 传递 + conclusion 键 + try/except 保留原文。
          report_content=$(SUBAGENT_RESULT="$_subagent_result" RESULT_DATA="$result" python3 "$SKILL_DIR/scripts/gk_views.py" audit-report-assemble "$audit_id" "$audit_type" "$(date +%Y-%m-%d)" 2>/dev/null || echo "# ECC-AUDIT: $audit_id\n\nReport generation failed")
        else
          report_content="# ECC-AUDIT: $audit_id\n## §2 Summary\n$(echo "$result" | python3 -m json.tool 2>/dev/null || echo "$result")"
        fi
      else
        report_content="# ECC-AUDIT: $audit_id\n## §1 Header\n- Audit ID: $audit_id\n- Audit Type: $audit_type\n- Date: $(date +%Y-%m-%d)\n\n## §2 Summary\n$(echo "$result" | python3 -m json.tool 2>/dev/null || echo "$result")"
      fi
      # Refuse to sign if no data: need history_count > 0 OR audit --state was called
      local history_count; history_count=$(echo "$result" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field history_count --default 0 2>/dev/null || echo "0")
      # 2026-09-07 ECC-35E1926F483D: standing 序列无 standard AUDIT-STATE 相位（advance AUDIT-STATE
      # 才写 audit_phases_completed），但五域证据（audit_state_result 等）已落盘 = 等价的证据已收集
      # 判据——standing 上禁止裸跑 audit --report 会误锁 seal 收口。
      # 2026-10-01（finding ECC-DD4FF260119F）：判据**上收 python**（`gk_node_guard.report_evidence_ok`
      # 单一事实源）—— 原内联式写死 `project_type=='standing'`，致**非 standard/standing 的新路线**
      # （如 `zthl-adapter`；其本就没有 standard 的 AUDIT-STATE 相位）即便五域证据已落盘也恒被判无证据
      # ⟹ `audit --all` 的 report 域恒失败。按 owner 令「尽量不内联 gatekeeper-cli.sh」：此处只调用、
      # 不复刻规则（零双轨）。新语义 = AUDIT-STATE 相位 OR (非 standard ∧ 五域证据落盘)。
      # 2026-11-01（跨平台修复）：sys.path 与 STATE_FILE 原均为 bash 插值 ⟹ MSYS /c/ 绝对路径
      #   不被 Windows python 识别（env 传递才做 /c/→C:/ 转换）⟹ ModuleNotFoundError / 打不开
      #   state ⟹ report_evidence_ok 误判 no ⟹ seal 收口误锁。改 env 单源（同 BARE 守卫修法）。
      local audit_state_done; audit_state_done=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 -c "
import json,os,sys
sys.path.insert(0, os.path.join(os.environ['SKILL_DIR'], 'scripts'))
from gk_node_guard import report_evidence_ok
try:
    s=json.load(open(os.environ['STATE_FILE'],encoding='utf-8'))
except Exception:
    s={}
print('yes' if report_evidence_ok(s) else 'no')
" 2>/dev/null || echo "no")
      if [ "$history_count" -le 0 ] && [ "$audit_state_done" != "yes" ] && [ "$audit_type" != "redteam" ]; then
        # 2026-08-15 fix: 原错误信息 "audit --state was never called" 误导——裸跑 audit --state
        # 命令不会写 audit_phases_completed，判定依赖的是 advance AUDIT-STATE 阶段标记。
        # 2026-09-07 ECC-35E1926F483D 补充: standing 序列无需 advance AUDIT-STATE。
        # 2026-10-28（E2）：证据判据由 `any`（单域）收紧为 all-of（有生产者两域
        #   audit_state_result + audit_docs_result）⟹ 提示同步为 `audit --state --docs`。
        echo "{\"ok\":false,\"error\":\"Cannot sign audit report: history_count=0 and no audit evidence on disk (AUDIT-STATE phase not completed / produced-domain evidence absent). Run audit --state --docs before audit --report.\"}"
        return 1
      fi
      # Write report with hash and signature
      local report_date; report_date=$(date +%Y%m%d)
      # 2026-10-29（E18/B3）：路径由 SKILL_DIR 派生（原写死安装目录 ⟹ worktree/副本审计
      #   必然写回主仓 references，报告与产物归属分叉）。
      local report_path="${SKILL_DIR}/references/ecc-audit-${report_date}.md"
      local content_hash="" content_sig=""
      # Write to temp first to ensure sign + disk content match exactly
      local tmp_report; tmp_report=$(mktemp)
      cat > "$tmp_report" <<< "$report_content"
      if ! $no_sign && [ -f "$_AUDIT_PRIV_KEY" ]; then
        local sig_json; sig_json=$(_audit_sign "$(cat "$tmp_report")")
        content_hash=$(echo "$sig_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field hash --default '' 2>/dev/null)
        content_sig=$(echo "$sig_json" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field signature --default '' 2>/dev/null)
      fi
      # Append hash + signature to report
      if [ -n "$content_hash" ]; then
        cp "$tmp_report" "$report_path"
        echo "" >> "$report_path"
        echo "## §9 Integrity" >> "$report_path"
        echo "- Content SHA256: \`$content_hash\`" >> "$report_path"
        echo "- Signature (Ed25519): \`$content_sig\`" >> "$report_path"
        local pubkey_b64; pubkey_b64=$(openssl pkey -in "$_AUDIT_PUB_KEY" -pubin 2>/dev/null | base64 -w0 2>/dev/null || echo "")
        echo "- Public Key (embedded): \`$pubkey_b64\`" >> "$report_path"
      else
        cp "$tmp_report" "$report_path"
        [ "$no_sign" = "false" ] && echo "" >> "$report_path" && echo "*Report not signed — no Ed25519 key found. Run audit --init-keys.*" >> "$report_path"
      fi
      rm -f "$tmp_report"
      # 2026-10-29（E18/B3）：报告可机读侧车 `<state>.audit-report.json`（唯一写者 =
      #   gk_audit_report.py）。失败不阻断报告签发，仅留痕（md + 签名仍是权威产物）。
      python3 "$SKILL_DIR/scripts/gk_audit_report.py" write "$STATE_FILE" \
        --audit-id "$audit_id" --type "$audit_type" \
        --content-hash "$content_hash" --report-path "$report_path" \
        >>"${GK_DBG_LOG:-/dev/null}" 2>&1 || echo "[audit-report] WARN sidecar write failed" >>"${GK_DBG_LOG:-/dev/null}"
      result=$(echo "$result" | python3 -c "import sys,json;d=json.loads(sys.stdin.read());d['audit_id']='$audit_id';d['audit_type']='$audit_type';d['content_hash']='$content_hash';d['report_path']='$report_path';print(json.dumps(d))" 2>/dev/null || echo "$result")
      echo "{\"ok\":true,\"audit_mode\":\"report\",\"audit_id\":\"$audit_id\",\"audit_type\":\"$audit_type\",\"content_hash\":\"$content_hash\",\"report_path\":\"$report_path\",\"result\":$result}" ;;
    --verify|verify)
      local target_path="${2}"
      if [ ! -f "$target_path" ]; then
        echo "{\"ok\":false,\"error\":\"File not found: $target_path\"}"
        return 1
      fi
      # 6a: Path validation — verify target is within skill directory
      local verify_path; verify_path=$(realpath "$target_path" 2>/dev/null || echo "")
      local skill_dir; skill_dir=$(realpath "$SKILL_DIR" 2>/dev/null)
      if [[ "$verify_path" != "$skill_dir"* ]] && [[ "$verify_path" != "$skill_dir/references/"* ]]; then
        echo '{"ok":false,"error":"Verify path must be within skill directory"}'
        return 1
      fi
      local verify_result; verify_result=$(python3 -c '
import re
with open("'"$target_path"'") as f: content = f.read()
m = re.search(r"Content SHA256: `([a-f0-9]+)`", content)
m2 = re.search(r"Signature \(Ed25519\): `(.+)`", content)
if not m or not m2:
    print(json.dumps({"ok":False,"error":"No hash or signature found in report"}))
    exit(0)
stored_hash = m.group(1)
stored_sig = m2.group(1)
clean_content = re.sub(r"## §9 Integrity.*?(?=\Z|\n#)", "", content, flags=re.DOTALL).strip()
import hashlib
computed = hashlib.sha256(clean_content.encode()).hexdigest()
hash_match = computed == stored_hash
import json; print(json.dumps({"ok":True,"hash_match":hash_match,"stored_hash":stored_hash,"computed_hash":computed}))
' 2>/dev/null || echo '{"ok":false,"error":"Verification parse failed"}')
      local hash_match; hash_match=$(echo "$verify_result" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field hash_match --default False --default-invalid '' 2>/dev/null)
      if [ "$hash_match" = "True" ]; then
        local sig_valid
        # Try embedded public key from report first
        sig_valid=$(python3 -c '
import base64,hashlib,re,sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_pem_public_key
with open("'"$target_path"'") as f: content = f.read()
pubkey_m = re.search(r"Public Key \(embedded\): `(.+)`", content)
if not pubkey_m:
    pubkey_m = re.search(r"Public Key: `(.+)`", content)
if pubkey_m:
    try:
        pubkey_pem = base64.b64decode(pubkey_m.group(1))
        pub = load_pem_public_key(pubkey_pem)
    except:
        sys.exit(3)
else:
    sys.exit(4)
m = re.search(r"Signature \(Ed25519\): `(.+)`", content)
sig_b64 = m.group(1) if m else ""
m2 = re.search(r"Content SHA256: `([a-f0-9]+)`", content)
stored_hash = m2.group(1) if m2 else ""
clean = re.sub(r"## §9 Integrity.*", "", content, flags=re.DOTALL).strip()
computed = hashlib.sha256(clean.encode()).hexdigest()
if computed != stored_hash:
    sys.exit(2)
try:
    pub.verify(base64.b64decode(sig_b64), clean.encode())
    print("true")
except:
    print("false")
' 2>/dev/null || echo "false")
        # Fallback: try filesystem key if embedded key not available
        if [ "$sig_valid" != "true" ] && [ -f "$_AUDIT_PUB_KEY" ]; then
          sig_valid=$(python3 -c '
import base64,hashlib,re,sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_pem_public_key
with open("'"$target_path"'") as f: content = f.read()
with open("'"$_AUDIT_PUB_KEY"'","rb") as f:
    pub = load_pem_public_key(f.read())
m = re.search(r"Signature \(Ed25519\): `(.+)`", content)
sig_b64 = m.group(1) if m else ""
m2 = re.search(r"Content SHA256: `([a-f0-9]+)`", content)
stored_hash = m2.group(1) if m2 else ""
clean = re.sub(r"## §9 Integrity.*", "", content, flags=re.DOTALL).strip()
computed = hashlib.sha256(clean.encode()).hexdigest()
if computed != stored_hash:
    sys.exit(2)
try:
    pub.verify(base64.b64decode(sig_b64), clean.encode())
    print("true")
except:
    print("false")
' 2>/dev/null || echo "false")
        fi
        # 2026-08-13 外部锚核对（修复 self-referential 风险）：内嵌公钥自证可被整体伪造
        # （攻击者改内容+重算hash+自签+替换内嵌公钥即可通过，fallback 永不触发）。
        # 金标准（DeepInspect/ai-audit-trail/零信任 BP.08）要求信任锚在记录之外——
        # 校验内嵌公钥 ∈ {当前 audit 公钥, 7 天内 .bak 公钥} 集合。
        local _anchor="unchecked" _sig_final="$sig_valid"
        if [ "$sig_valid" = "true" ]; then
          local _embedded_fp
          _embedded_fp=$(GK_PY_TARGET="$(_gk_py_path "$target_path")" python3 -c "
import base64,re,sys,hashlib,os
content=open(os.environ['GK_PY_TARGET']).read()
m=re.search(r'Public Key \(embedded\): \`(.+)\`',content)
if not m: m=re.search(r'Public Key: \`(.+)\`',content)
if not m: sys.exit(1)
print(hashlib.sha256(base64.b64decode(m.group(1))).hexdigest())
" 2>/dev/null || echo "")
          if [ -n "$_embedded_fp" ]; then
            _anchor="mismatch"
            if [ -f "$_AUDIT_PUB_KEY" ]; then
              local _audit_fp; _audit_fp=$(sha256sum "$_AUDIT_PUB_KEY" 2>/dev/null | awk '{print $1}')
              [ "$_embedded_fp" = "$_audit_fp" ] && _anchor="ok:current"
            fi
            if [ "$_anchor" = "mismatch" ]; then
              local _bak
              for _bak in "$_AUDIT_KEY_DIR"/audit_ed25519.pub.*.bak; do
                [ -f "$_bak" ] || continue
                local _bak_fp; _bak_fp=$(sha256sum "$_bak" 2>/dev/null | awk '{print $1}')
                [ "$_embedded_fp" = "$_bak_fp" ] && { _anchor="ok:bak:$(basename "$_bak")"; break; }
              done
            fi
            [ "$_anchor" = "mismatch" ] && _sig_final="untrusted_anchor"
            [ "$_anchor" = "unchecked" ] && { _anchor="no_embedded_key"; _sig_final="untrusted_anchor"; }
          else
            _anchor="no_embedded_key"; _sig_final="untrusted_anchor"
          fi
        elif [ "$sig_valid" = "false" ] && [ ! -f "$_AUDIT_PUB_KEY" ]; then
          _anchor="no_trust_anchor"
        fi
        verify_result=$(echo "$verify_result" | python3 -c "import sys,json;d=json.loads(sys.stdin.read());d['signature_valid']='$_sig_final';d['anchor']='$_anchor';print(json.dumps(d))" 2>/dev/null || echo "$verify_result")
      elif [ "$hash_match" = "True" ] && [ ! -f "$_AUDIT_PUB_KEY" ]; then
        verify_result=$(echo "$verify_result" | python3 -c "import sys,json;d=json.loads(sys.stdin.read());d['signature_valid']='no_pubkey';print(json.dumps(d))" 2>/dev/null || echo "$verify_result")
      fi
      echo "{\"ok\":true,\"audit_mode\":\"verify\",\"file\":\"$target_path\",\"result\":$verify_result}" ;;
    --init-keys|init-keys)
      mkdir -p "$_AUDIT_KEY_DIR" 2>/dev/null
      if [ -f "$_AUDIT_PRIV_KEY" ] && [ -f "$_CONTEXT_PRIV_KEY" ]; then
        echo "{\"ok\":false,\"error\":\"Keys already exist at $_AUDIT_KEY_DIR. Use 'key rotate' or delete manually.\"}"
      else
        # A8: Serialize init-keys with mkdir-based atomic lock
         local lockfile="${_AUDIT_KEY_DIR}/.init-lock"
         if ! mkdir "$lockfile" 2>/dev/null; then
           # Another init-keys in progress, wait briefly and re-check
           sleep 1
           if [ -f "$_AUDIT_PRIV_KEY" ] && [ -f "$_CONTEXT_PRIV_KEY" ]; then
             echo "{\"ok\":false,\"error\":\"Keys already exist at $_AUDIT_KEY_DIR. Use 'key rotate' or delete manually.\"}"
             return 0
           fi
           mkdir "$lockfile" 2>/dev/null || { echo '{"ok":false,"error":"init-keys lock failed (concurrent init)"}'; return 1; }
         fi
         # shellcheck disable=SC2064
         trap "rmdir '${_AUDIT_KEY_DIR}/.init-lock' 2>/dev/null" EXIT
        # R7: Generate two independent key pairs
        [ ! -f "$_AUDIT_PRIV_KEY" ] && { openssl genpkey -algorithm ED25519 -out "$_AUDIT_PRIV_KEY" 2>/dev/null; openssl pkey -in "$_AUDIT_PRIV_KEY" -pubout -out "$_AUDIT_PUB_KEY" 2>/dev/null; }
        [ ! -f "$_CONTEXT_PRIV_KEY" ] && { openssl genpkey -algorithm ED25519 -out "$_CONTEXT_PRIV_KEY" 2>/dev/null; openssl pkey -in "$_CONTEXT_PRIV_KEY" -pubout -out "$_CONTEXT_PUB_KEY" 2>/dev/null; }
        chmod 600 "$_AUDIT_PRIV_KEY" "$_CONTEXT_PRIV_KEY" 2>/dev/null
        # R7: Write key-meta.json with expiration tracking (heredoc, no bash injection)
        export _KEY_META _AUDIT_KEY_DIR
        python3 << 'PYEOF'
import json, time, os
meta_file = os.environ.get('_KEY_META', '')
meta = {
    'audit_ed25519': {
        'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'expires': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 30*86400)),
        'status': 'pre-activation', 'rotation_days': 30,
        'fingerprint': ''
    },
    'context_ed25519': {
        'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'expires': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 1*86400)),
        'status': 'pre-activation', 'rotation_days': 1,
        'fingerprint': ''
    }
}
with open(meta_file, 'w') as f: json.dump(meta, f, indent=2)
PYEOF
        # A1: Generate integrity hash for key-meta.json
        _update_key_integrity
        # A2: Store pubkey fingerprints in key-meta
        python3 << 'PYEOF'
import json, hashlib, os
meta = json.load(open(os.environ.get('_KEY_META','')))
for ktype in ['context_ed25519', 'audit_ed25519']:
    pubkey_path = os.environ.get('_AUDIT_KEY_DIR','') + '/' + ktype.replace('_ed25519','') + '_ed25519.pub'
    if os.path.exists(pubkey_path):
        meta[ktype]['fingerprint'] = hashlib.sha256(open(pubkey_path, 'rb').read()).hexdigest()
with open(os.environ.get('_KEY_META',''), 'w') as f: json.dump(meta, f, indent=2)
PYEOF
        _update_key_integrity
        rmdir "${_AUDIT_KEY_DIR}/.init-lock" 2>/dev/null  # release init lock
        trap - EXIT
        echo "{\"ok\":true,\"audit_mode\":\"init-keys\",\"audit_key\":\"$_AUDIT_PRIV_KEY\",\"context_key\":\"$_CONTEXT_PRIV_KEY\",\"meta\":\"$_KEY_META\"}"
      fi ;;
    --key)
      shift; local key_action="${1:-}"
      # R7/G6: NIST SP 800-57 state transition validator
      # Valid transitions: pre-activation→active→deactivated, active→compromised→destroyed, deactivated→destroyed
      _validate_key_state_transition() {
        local key_type="$1" new_state="$2"
        python3 << 'PYEOF'
import json, os, sys
meta_file = os.environ.get('_KEY_META', '')
if not os.path.exists(meta_file):
    print('ok')  # no meta yet, allow
    sys.exit(0)
meta = json.load(open(meta_file))
key = os.environ.get('_KEY_TYPE', '') + '_ed25519'
current = meta.get(key, {}).get('status', 'pre-activation')
new = os.environ.get('_NEW_STATE', 'active')
VALID = {
    'pre-activation': ['active', 'deactivated', 'destroyed'],
    'active': ['deactivated', 'compromised'],
    'deactivated': ['destroyed'],
    'compromised': ['destroyed', 'deactivated'],
    'revoked': ['destroyed'],
    'destroyed': [],
}
if new in VALID.get(current, []):
    print('ok')
else:
    print(f'INVALID: {current} -> {new} not allowed')
PYEOF
      }
      case "$key_action" in
        rotate)
          # R7: CapiscIO overlapping rotation — gen new key FIRST, test it, then retire old
          local key_type="${2:-context}"
          # 2026-08-13: trigger 区分来源（auto=cmd_advance 自动轮换 / manual=手动），供 BP.08.04 生命周期审计追溯
          local trigger="${3:-manual}"
          # Strip trailing _ed25519 suffixes (e.g. context_ed25519 → context)
          key_type="${key_type%_ed25519}"
          local priv="${_CONTEXT_PRIV_KEY}"; local pub="${_CONTEXT_PUB_KEY}"
          [ "$key_type" = "audit" ] && { priv="${_AUDIT_PRIV_KEY}"; pub="${_AUDIT_PUB_KEY}"; }
          local ts; ts=$(date +%Y%m%d_%H%M%S)
          [ ! -f "$priv" ] && { echo "{\"ok\":false,\"error\":\"No existing ${key_type}_ed25519 key to rotate. Run: audit --init-keys\"}"; return 1; }
          # A2: Verify current pubkey fingerprint matches key-meta before rotation
          if [ -f "$_KEY_INTEGRITY" ]; then
            local integ; integ=$(_verify_key_integrity)
            [ "$integ" != "ok" ] && { echo "{\"ok\":false,\"error\":\"KEY INTEGRITY COMPROMISED: $integ\"}"; return 1; }
          fi
          # G6: Validate state transition — only active/pre-activation keys can rotate
          export _KEY_TYPE="$key_type" _NEW_STATE="deactivated"
          local st_check; st_check=$(_validate_key_state_transition "$key_type" "deactivated")
          [ "$st_check" != "ok" ] && { echo "{\"ok\":false,\"error\":\"Cannot rotate: $st_check\"}"; return 1; }
          # G1: Generate new key FIRST (to temp), then atomically swap
          local tmp_priv="${priv}.new"; local tmp_pub="${pub}.new"
          openssl genpkey -algorithm ED25519 -out "$tmp_priv" 2>/dev/null || { echo '{"ok":false,"error":"keygen failed"}'; return 1; }
          openssl pkey -in "$tmp_priv" -pubout -out "$tmp_pub" 2>/dev/null || { rm -f "$tmp_priv"; echo '{"ok":false,"error":"pubkey extraction failed"}'; return 1; }
          chmod 600 "$tmp_priv" 2>/dev/null
          # Verify new key works (sign+verify smoke test with Ed25519-compatible syntax)
          echo -n "rotation-test" > /tmp/_rotate_test_in.bin
          openssl pkeyutl -sign -inkey "$tmp_priv" -rawin -in /tmp/_rotate_test_in.bin -out /tmp/_rotate_test.sig 2>/dev/null
          openssl pkeyutl -verify -pubin -inkey "$tmp_pub" -rawin -in /tmp/_rotate_test_in.bin -sigfile /tmp/_rotate_test.sig 2>/dev/null || { rm -f "$tmp_priv" "$tmp_pub" /tmp/_rotate_test.sig /tmp/_rotate_test_in.bin; echo '{"ok":false,"error":"new key verification failed"}'; return 1; }
          rm -f /tmp/_rotate_test.sig /tmp/_rotate_test_in.bin
          # G4: Serialize key ops with flock to prevent TOCTOU
          local lockfile="${_AUDIT_KEY_DIR}/.key.lock"
          touch "$lockfile" 2>/dev/null
          exec 9>"$lockfile"
          flock -w 5 9 || { rm -f "$tmp_priv" "$tmp_pub"; echo '{"ok":false,"error":"lock timeout"}'; return 1; }
          # Atomically replace old with new (mv on same FS is atomic)
          mv "$priv" "${priv}.${ts}.bak" 2>/dev/null
          mv "$pub" "${pub}.${ts}.bak" 2>/dev/null
          mv "$tmp_priv" "$priv" 2>/dev/null
          mv "$tmp_pub" "$pub" 2>/dev/null
          # Update key-meta
          local rdays=1; [ "$key_type" = "audit" ] && rdays=30
          export _KEY_META key_type rdays ts pub
          python3 << 'PYEOF'
import json, time, os, hashlib
meta_file = os.environ.get('_KEY_META', '')
expires_sec = time.time() + int(os.environ.get('rdays', '1')) * 86400
meta = json.load(open(meta_file)) if os.path.exists(meta_file) else {}
key_type = os.environ.get('key_type', 'context')
# Compute new pubkey fingerprint
pub_path = os.environ.get('pub', '')
new_fp = ''
if os.path.exists(pub_path):
    new_fp = hashlib.sha256(open(pub_path, 'rb').read()).hexdigest()
meta[key_type + '_ed25519'] = {
    'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'expires': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(expires_sec)),
    'status': 'active',
    'rotated_from': os.environ.get('ts', ''),
    'rotation_days': int(os.environ.get('rdays', '1')),
    'fingerprint': new_fp
}
with open(meta_file, 'w') as f: json.dump(meta, f, indent=2)
PYEOF
          # A1: Update integrity hash
          _update_key_integrity
          # Release lock after atomic swap + key-meta update
          exec 9>&-
          # Re-sign context if context key rotated（净 0 行：改调单点 `_context_resign` —— 原就地 `_sign_raw "$ctx_file" > /dev/null` 是 **no-op**：`_sign_raw` 只把 base64 JSON 打到 stdout、从不落盘，且该 JSON 直写 .sig 亦错形态（.sig 是 64B 裸签名）⟹ 每次轮换后 .sig 恒 stale。2026-09-20 实证：cron `key-rotate-check` 08:49:09 轮换后 .sig 仍停在 09-19、对新 pub 验签失败、对上一代 .bak pub 验签成功，并把 `node-guard ECO-READ` 的「代码库地图」打成 missing。守护：scripts/test_context_resign_on_rotate.py）
          [ "$key_type" = "context" ] && _context_resign
          # T7.3 (2026-08-13): record rotation event to gate_data.key_rotation_log[] — batch8 T7.3 计划要求，此前缺失
          _state_write "d.setdefault('gate_data',{}).setdefault('key_rotation_log',[]).append({'key_type':'$key_type','rotated_at':'$(date -u +%Y-%m-%dT%H:%M:%SZ)','backup':'${priv}.${ts}.bak','trigger':'$trigger'})" 2>/dev/null || true
          # CapiscIO: destroy .bak older than 7 days (grace period expired) — 手动 rotate 同样清理（此前只在 cmd_advance 过期触发时清理）
          find "$_AUDIT_KEY_DIR" -name "*.bak" -mtime +7 -exec rm -f {} \; 2>/dev/null
          echo "{\"ok\":true,\"action\":\"rotate\",\"key_type\":\"${key_type}_ed25519\",\"backup\":\"${priv}.${ts}.bak\"}" ;;
        revoke)
          local key_type="${2:-context}"
          local priv="${_CONTEXT_PRIV_KEY}"
          [ "$key_type" = "audit" ] && priv="${_AUDIT_PRIV_KEY}"
          # G6: Validate state transition for revoke
          export _KEY_TYPE="$key_type" _NEW_STATE="revoked"
          local st_check; st_check=$(_validate_key_state_transition "$key_type" "revoked")
          [ "$st_check" != "ok" ] && { echo "{\"ok\":false,\"error\":\"Cannot revoke: $st_check\"}"; return 1; }
          if [ ! -f "$priv" ]; then
            echo "{\"ok\":false,\"error\":\"${key_type}_ed25519 key not found\"}"
          else
            # R7: Mark revoked in key-meta, shred private key (G2 NIST-compliant destruction)
            mkdir -p "$_AUDIT_KEY_DIR/.revoked" 2>/dev/null
            local ts; ts=$(date +%Y%m%d_%H%M%S)
            # Move pub key (non-sensitive), shred priv key (sensitive)
            local pub="${_CONTEXT_PUB_KEY}"; [ "$key_type" = "audit" ] && pub="${_AUDIT_PUB_KEY}"
            [ -f "$pub" ] && mv "$pub" "$_AUDIT_KEY_DIR/.revoked/${key_type}_ed25519.pub.${ts}" 2>/dev/null
            # G2: shred private key before removing (NIST SP 800-57 §Destroyed)
            shred -u "$priv" 2>/dev/null || rm -f "$priv"  # fallback if shred unavailable
            # G7: Scan for .keys/ access violations in gate_data
            local compromise_evidence=""
            local gd="${SKILL_DIR}/state/gate_data.json"
            if [ -f "$gd" ]; then
              export _GD_FILE="$gd"
              local violations; violations=$(python3 << 'PYEOF'
import json, os
gd_file = os.environ.get('_GD_FILE', '')
if os.path.exists(gd_file):
    violations = json.load(open(gd_file)).get('_ACCESS_VIOLATIONS', [])
    keys_hits = [v for v in violations if '.keys/' in str(v.get('path',''))]
    print(len(keys_hits))
else:
    print(0)
PYEOF
)
              [ "$violations" != "0" ] && compromise_evidence=", \"compromise_evidence\":${violations}_violations_found"
            fi
            export _KEY_META key_type
            python3 << 'PYEOF'
import json, time, os
meta_file = os.environ.get('_KEY_META', '')
meta = json.load(open(meta_file)) if os.path.exists(meta_file) else {}
key_type = os.environ.get('key_type', 'context')
meta[key_type + '_ed25519'] = {
    'status': 'revoked',
    'revoked_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
}
with open(meta_file, 'w') as f: json.dump(meta, f, indent=2)
PYEOF
            # A1: Update integrity hash
            _update_key_integrity
            # 2026-08-13: revoke 事件留痕（BP.08.04 密钥生命周期审计——revoke/destroy 此前不留日志）
            _state_write "d.setdefault('gate_data',{}).setdefault('key_rotation_log',[]).append({'key_type':'$key_type','action':'revoke','revoked_at':'$(date -u +%Y-%m-%dT%H:%M:%SZ)','moved_to':'${_AUDIT_KEY_DIR}/.revoked/${key_type}_ed25519.pub.${ts}'${compromise_evidence}})" 2>/dev/null || true
            echo "{\"ok\":true,\"action\":\"revoke\",\"key_type\":\"${key_type}_ed25519\",\"revoked_at\":\"$ts\"}"
          fi ;;
        status)
          # A1: Check integrity before showing status
          local integ; integ=$(_verify_key_integrity)
          if [ "$integ" != "ok" ]; then
            echo "{\"ok\":false,\"error\":\"KEY INTEGRITY COMPROMISED: $integ\"}"
          elif [ -f "$_KEY_META" ]; then
            # 2026-08-13: 追加密钥生命周期事件摘要（BP.08.04 审计密码实施运行——rotate/revoke/destroy 事件尾部）
            local _kl_tail; _kl_tail=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --tail gate_data.key_rotation_log 3 2>/dev/null || echo '[]')
            cat "$_KEY_META" | KL_TAIL="$_kl_tail" python3 "$SKILL_DIR/scripts/gk_views.py" key-meta-tail 2>>"$GK_DBG_LOG" || cat "$_KEY_META"
          else
            echo '{"error":"no key-meta.json found"}'
          fi ;;
        destroy)
          # R7/G2: NIST-compliant key destruction — shred old .bak keys
          local key_type="${2:-context}"
          # G6: Validate state transition for destroy (only deactivated/revoked/compromised can be destroyed)
          export _KEY_TYPE="$key_type" _NEW_STATE="destroyed"
          local st_check; st_check=$(_validate_key_state_transition "$key_type" "destroyed")
          [ "$st_check" != "ok" ] && { echo "{\"ok\":false,\"error\":\"Cannot destroy: $st_check. Destroy only .bak/revoked keys.\"}"; return 1; }
          local pattern="${_CONTEXT_PRIV_KEY}"; [ "$key_type" = "audit" ] && pattern="${_AUDIT_PRIV_KEY}"
          local count=0
          for f in "${pattern}".*.bak "$_AUDIT_KEY_DIR/.revoked/${key_type}_ed25519.pem."*; do
            [ -f "$f" ] || continue
            shred -u "$f" 2>/dev/null || rm -f "$f"
            count=$((count + 1))
          done
          # 2026-08-13: destroy 事件留痕（BP.08.04 密钥生命周期审计——销毁环节此前不可审计）
          _state_write "d.setdefault('gate_data',{}).setdefault('key_rotation_log',[]).append({'key_type':'$key_type','action':'destroy','destroyed_at':'$(date -u +%Y-%m-%dT%H:%M:%SZ)','files_shredded':$count})" 2>/dev/null || true
          echo "{\"ok\":true,\"action\":\"destroy\",\"key_type\":\"${key_type}_ed25519\",\"files_shredded\":$count}" ;;
        export-pub)
          # R7/G5: Export public key for distribution (NIST SP 800-57 §Distribution)
          local key_type="${2:-context}"
          local pub="${_CONTEXT_PUB_KEY}"; [ "$key_type" = "audit" ] && pub="${_AUDIT_PUB_KEY}"
          [ ! -f "$pub" ] && { echo "{\"ok\":false,\"error\":\"${key_type}_ed25519 public key not found\"}"; return 1; }
          local fp; fp=$(sha256sum "$pub" 2>/dev/null | cut -d' ' -f1) || fp=$(sha256sum "$pub" 2>/dev/null | awk '{print $1}') || fp=""
          echo "{\"ok\":true,\"key_type\":\"${key_type}_ed25519\",\"public_key\":\"$(cat "$pub" | tr -d '\n')\",\"fingerprint_sha256\":\"$fp\"}" ;;
        fingerprint)
          # R7/G5: Show key fingerprints for partner verification
          local key_type="${2:-}"
          if [ -n "$key_type" ]; then
            local pub="${_CONTEXT_PUB_KEY}"; [ "$key_type" = "audit" ] && pub="${_AUDIT_PUB_KEY}"
            [ ! -f "$pub" ] && { echo "{\"ok\":false,\"error\":\"${key_type}_ed25519 public key not found\"}"; return 1; }
            local fp; fp=$(sha256sum "$pub" 2>/dev/null | cut -d' ' -f1) || fp=$(sha256sum "$pub" 2>/dev/null | awk '{print $1}') || fp=""
            echo "{\"ok\":true,\"fingerprint\":{\"${key_type}_ed25519\":\"$fp\"}}"
          else
            # Show all fingerprints
            # 2026-09-22 R19：**空集不得报成功** —— 红先臂 `keys_absent_source_fail_loud` 实测修前为
            #   `rc=0` + `{"ok":true,"fingerprints":{}}`（**假绿**：调用方据 `ok:true` 会误判密钥就绪）。
            #   `missing` 为**增量字段**（对既有消费者无破坏），部分缺失时如实列出而不静默。
            local _body="" _missing=""
            for t in context audit; do
              local pub="${_CONTEXT_PUB_KEY}"; [ "$t" = "audit" ] && pub="${_AUDIT_PUB_KEY}"
              if [ -f "$pub" ]; then
                local fp; fp=$(sha256sum "$pub" 2>/dev/null | cut -d' ' -f1) || fp=""
                _body="${_body}${_body:+,}\"${t}_ed25519\":\"$fp\""
              else
                _missing="${_missing}${_missing:+,}\"${t}_ed25519\""
              fi
            done
            if [ -z "$_body" ]; then
              echo "{\"ok\":false,\"error\":\"keys_not_found\",\"missing\":[${_missing}],\"key_dir\":\"${_AUDIT_KEY_DIR}\",\"fix\":\"副本应由主副本继承 .keys（R19 自动继承）或先初始化密钥\"}"
              return 1
            fi
            echo "{\"ok\":true,\"fingerprints\":{${_body}},\"missing\":[${_missing}]}"
          fi ;;
        *) echo "{\"ok\":false,\"error\":\"Usage: key rotate|revoke|destroy|export-pub|fingerprint|status [context|audit]\"}" ;;
      esac ;;
    --all|all|"")
      # I1: Unified audit — run all sub-commands (Batch 9 Phase 2: parallel)
      # ECO.15: Add 120s timeout per subprocess to prevent hangs (missing API key, slow network)
      local all_results="{}"
      local _tmp_audit_dir; _tmp_audit_dir=$(mktemp -d)
      local _AUDIT_TIMEOUT=120
      _audit_timed_run() {
        local tout="$1"; shift
        "$@" &
        local pid=$!
        local elapsed=0
        while kill -0 "$pid" 2>/dev/null && [ "$elapsed" -lt "$tout" ]; do
          sleep 2; elapsed=$((elapsed + 2))
        done
        if kill -0 "$pid" 2>/dev/null; then
          kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 1
        fi
        wait "$pid" 2>/dev/null; return 0
      }
      # 2026-11-03 ECC-7131658C9F77：域结果读取单源 —— 空/坏 JSON 必须给出具名失败
      # （rc + stderr 尾 + 字节数），禁止用 2>/dev/null 把域错误吞成 "load-failed: line 1"。
      _audit_read_result() {
        local _d="$1"
        local _f="$_tmp_audit_dir/${_d}.json"
        local _rf="$_tmp_audit_dir/${_d}.rc"
        local _ef="$_tmp_audit_dir/${_d}.err"
        local _bytes=0 _rc=-1 _tail=""
        [ -f "$_f" ] && _bytes=$(wc -c < "$_f" | tr -d ' ')
        [ -f "$_rf" ] && _rc=$(cat "$_rf")
        [ -s "$_ef" ] && _tail=$(tail -c 300 "$_ef" | tr '\n' ' ')
        if [ "${_bytes:-0}" -gt 0 ] && python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "$_f" >/dev/null 2>&1; then
          cat "$_f"
        else
          python3 -c 'import json,sys;d=sys.argv;print(json.dumps({"ok":False,"error":"empty_or_invalid_result","domain":d[1],"rc":int(d[2]) if d[2].lstrip("-").isdigit() else -1,"bytes":int(d[3]) if d[3].isdigit() else 0,"stderr_tail":d[4][:300]}))' "$_d" "$_rc" "${_bytes:-0}" "$_tail"
        fi
      }
      # Serial audit domains (2026-09-07 ECC-F78E1B1EF083: 并行 spawn 致聚合 parse failed——
      # 子审计竞态（flock/_state_write 与嵌套 CLI 并发）；改串行保证逐域 JSON 完整落盘)
      # 2026-09-07 audit --all serialization: each domain bounded by _AUDIT_TIMEOUT individually
      for _ad in state docs memory crossr depth; do
        _audit_timed_run $_AUDIT_TIMEOUT bash "$0" audit --$_ad > "$_tmp_audit_dir/$_ad.json" 2> "$_tmp_audit_dir/$_ad.err"
        echo $? > "$_tmp_audit_dir/$_ad.rc"
      done
      # Report with timeout (may call API via subagent_runner)
      local r_result
      if _audit_timed_run $_AUDIT_TIMEOUT bash "$0" audit --report --type performance > "$_tmp_audit_dir/report.json" 2> "$_tmp_audit_dir/report.err"; then
        echo 0 > "$_tmp_audit_dir/report.rc"
      else
        echo $? > "$_tmp_audit_dir/report.rc"
      fi
      r_result=$(_audit_read_result report)
      # Read parallel results
      local s_result; s_result=$(_audit_read_result state)
      local d_result; d_result=$(_audit_read_result docs)
      local m_result; m_result=$(_audit_read_result memory)
      local c_result; c_result=$(_audit_read_result crossr)
      local dp_result; dp_result=$(_audit_read_result depth)
      # 2026-08-20: 聚合改用 sys.argv 传参（原 '''...''' 三引号嵌入会把 JSON 内 \n/\t 转义
      # 二次解释为真实控制字符 → JSONDecodeError "Invalid control character"；含单引号内容同样破坏三引号串）
      # 2026-09-07 ECC-F78E1B1EF083 根治: argv 传文件内容在 report/depth 大 JSON 时超 ARG_MAX(每参~128K)→parse 失败；
      # 改传文件路径由 python 直读（路径 argv 恒小），逐文件容错不整体失败
      all_results=$(python3 -c '
import json, sys
def load(p):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception as e:
        return {"ok": False, "error": "load-failed: %s" % str(e)}
# 2026-09-19 ECC-350134A03D8F（F-REV-103 建议①）：原在此把顶层 ok **硬编码为常量真值** ⟹ 六域
#   全失败时顶层仍报成功（静默假成功），而 gk_node_guard.audit_all_recorded 只认 ``--all``
#   这一路径的返回值语义 ⟹ 门禁形同虚设。现改为**六域 all-of 派生**：先算出发布面
#   （state/docs 解包 result，其余原样），再由发布面自身收集失败域 ⟹ 顶层 ok 与 failed_domains
#   由**构造**保证一致，不存在「自报与事实不符」的第二真值。
sp = sys.argv[1:7]
s, d, m, c, r, dp = [load(p) for p in sp]
st = s.get("result", s) if isinstance(s, dict) else s
dc = d.get("result", d) if isinstance(d, dict) else d
res = {"state": st, "docs": dc, "memory": m, "crossr": c, "depth": dp, "report": r}
failed = sorted(k for k, v in res.items() if isinstance(v, dict) and v.get("ok") is False)
res["ok"] = not failed
res["audit_mode"] = "all"
res["failed_domains"] = failed
print(json.dumps(res))
' "$_tmp_audit_dir/state.json" "$_tmp_audit_dir/docs.json" "$_tmp_audit_dir/memory.json" "$_tmp_audit_dir/crossr.json" "$_tmp_audit_dir/report.json" "$_tmp_audit_dir/depth.json" 2>>"$GK_DBG_LOG" || echo '{"ok":false,"error":"unified audit parse failed"}')
      # 2026-08-23 bomb-inventory dangerous_command 豁免: mktemp -d 临时目录清理（CLI 内部 _tmp_* 白名单语义）
      # 加固（防 E2E rm -rf 自删教训复现）: 空变量/非临时前缀不删
      # 2026-09-19 ECC-9F0E3847E481（根因）/ ECC-350134A03D8F（症状，F-REV-103）：本清理块原置于
      #   **上方 python 聚合之前**，而聚合是「按文件路径重读」（sys.argv[1:7]）⟹ 目录已被删 ⟹
      #   六域恒 `load-failed: [Errno 2] ... /tmp/tmp.XXXX/<域>.json`，且顶层仍报 `ok:true`
      #   （静默假成功）。修法 = 移到聚合**之后**（此处）。回归门 =
      #   scripts/test_gk_audit_all_aggregation.py（判据① 行为面 ENOENT-free；判据② 行序不变量）。
      if [ -n "$_tmp_audit_dir" ] && [[ "$_tmp_audit_dir" == /tmp/* ]]; then
        rm -rf "$_tmp_audit_dir"
      fi
      # 2026-10-29（E18/B4）：`audit --all` 聚合结果落库 —— 原只 echo ⟹ 五域证据有、
      #   聚合无（下游无法复核「最近一次全量审计」）。写法同 state/docs（_state_write 单出纳）。
      local _tmp_all; _tmp_all=$(mktemp)
      echo "$all_results" > "$_tmp_all"
      GK_PY_TMP="$(_gk_py_path "$_tmp_all")" _state_write "d.setdefault('gate_data',{})['audit_all_result']=json.load(open(os.environ['GK_PY_TMP']))"
      rm -f "$_tmp_all"
      python3 "${SKILL_DIR}/scripts/gk_audit_registry.py" register --state "$STATE_FILE" \
        ${_AUDIT_KEY_DIR:+--key-dir "$_AUDIT_KEY_DIR"} --source audit_all \
        >>"${GK_DBG_LOG:-/dev/null}" 2>&1 || echo "[audit-registry] WARN register(audit_all) failed" >>"${GK_DBG_LOG:-/dev/null}"
      echo "$all_results" ;;
    --depth|depth)
      # Batch 9: GitNexus integration — dead code 3-gate + detect-changes
      local target="${1:-}"
      local depth_result="{}"
      # Gate 1: gitnexus context（A2：repo 名按当前目标 registry 解析，替代硬编码 spz_gatekeeper）
      local gn_context=""
      if [ -n "$target" ]; then
        gn_context=$(_run_gitnexus context -r "$(_gx_repo_name_for_dir "$(_gx_repo_dir_for_current)")" $target 2>/dev/null || echo "unavailable")
      fi
      # Gate 2: detect-changes (if in active R-phase)
      local gn_detect=""
      local r_phase; r_phase=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get r_phase --default "" 2>/dev/null)
      if [ -n "$r_phase" ] && [ "$r_phase" != "IDLE" ] && [ "$r_phase" != "DONE" ]; then
        gn_detect=$(_run_gitnexus detect-changes --repo "$(_gx_repo_name_for_dir "$(_gx_repo_dir_for_current)")" --scope compare 2>/dev/null || echo "unavailable")
      fi
      # Gate 3: production entry point scan
      local prod_scan=""
      if [ -n "$target" ]; then
        local incoming; incoming=$(echo "$gn_context" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field incoming --keys-join ',' --default-invalid '' 2>/dev/null || echo "")
        if [ -n "$incoming" ]; then
          local has_prod=false
          for entry in $(echo "$incoming" | tr ',' ' '); do
            case "$entry" in
              test_*.cc|*_test.cc) ;; # test self-cycle, skip (must be before *.cc)
              main.cc|wasm_main.cc|spz.cc|*.cc) has_prod=true ;;
            esac
          done
          prod_scan="$has_prod"
        fi
      fi
      depth_result=$(GN_CTX="$gn_context" GN_DET="$gn_detect" GN_TARGET="$target" GN_PROD="$prod_scan" python3 "$SKILL_DIR/scripts/gk_views.py" depth-result 2>>"$GK_DBG_LOG" || echo '{"ok":false,"error":"depth analysis failed"}')
      # R-T6 Phase 6 (2026-08-20): 追加 Python/脚本级死代码检测（gk_audit_depth.py）
      local py_depth; py_depth=$(SKILL_DIR="$(_gk_py_path "$SKILL_DIR")" python3 "$SKILL_DIR/scripts/gk_audit_depth.py" 2>>"$GK_DBG_LOG" || echo '{}')
      depth_result=$(echo "$depth_result" | PY_DEPTH="$py_depth" python3 "$SKILL_DIR/scripts/gk_views.py" depth-merge 2>>"$GK_DBG_LOG" || echo "$depth_result")
      echo "$depth_result" ;;
    *) echo "{\"ok\":false,\"error\":\"Usage: audit [--state|--docs|--memory|--crossr|--coverage [--base <ref>]|--crossfull [--base <ref>] [--repo <name>] [--state <path>] [--isolate]|--pdg [--symbol <fn>] [--repo <name>] [--supply]|--pr --base <ref> [--symbol <fn>]|--depth <symbol>] [--red <phase>|--hint|--self|--hook] [--report [--type <type>] [--force]] [--verify <path>] [--init-keys] [--key rotate|revoke|destroy|export-pub|fingerprint|status] [--all]}\"}" ;;
  esac
}

# ── 子 agent 上下文管理 ──
# gatekeeper-cli.sh context [--update]
# --update: 从 codebase 扫描重建 subagent-context.json
cmd_context() {
  local ctx_file="$SKILL_DIR/references/subagent-context.json"
  case "${1:-}" in
    --update)
      # gitnexus 语义地图层（2026-08-11）：代码库地图由 gitnexus 生成（analyze 语义索引），
      # 替代"硬编码行号即地图"的认知。subagent 自带 gx_query/gx_context/gx_impact 工具，
      # 此处只保证索引新鲜 + 注入地图指引，地图本体由 subagent 用 gx_* 动态下钻。
      # 自修复 (2026-08-21): status 检测从"退出码"改为"输出文本"（对齐 L1404/L1981 模式）。
      # gitnexus status 是信息性命令——stale 时退出码仍为 0 → 原逻辑永不触发重建；
      # 且 TRAE 沙箱下 analyze 成功也退出码 1（NVIDIA nvAppTimestamps 文件被拦）→ && 判定失效。
      # 重建后复查 status 文本判定成功，不依赖退出码。
      # F-REV-77/78 收敛（2026-09-16）：状态判定走**单点** `_gitnexus_baseline_status`（内含
      # 120s 超时）—— 原直调 `_run_gitnexus status` 在脏工作树下 ~25s 撞默认 30s 超时 → 空输出
      # → **恒判非 current** → 每次 `context --update` 都白跑 `analyze --embeddings`（~260s）；
      # analyze 后复验则因 memo 已失效（F-REV-78）取到**真值**（原先读到缓存 stale →
      # GK_GN_STATUS 恒 unavailable，即便重建成功）。
      local _gn_status="unavailable" _gn_dir
      _gn_dir=$(_gx_repo_dir_for_current)
      if [ "$(_gitnexus_baseline_status "$_gn_dir")" = "current" ]; then
        _gn_status="current"
      else
        # F-REV-95（2026-09-17，用户裁定）：**analyze 超时 300 → 600**（旋钮 `GK_GX_ANALYZE_TIMEOUT`）。
        #   原走 `_run_gitnexus_raw` 的**默认 300**，而 `_gitnexus_ensure_baseline` 的 analyze 早已
        #   显式 600 ⟹ 同一个 `analyze --embeddings` 两条路径口径不一致。实测 analyze（3969 节点
        #   嵌入）260s 起步，冷启 / 大改必然越 300s ⟹ 被 `timeout` **强杀**，在 gitnexus 侧留下
        #   `incrementalInProgress` + `embeddingCheckpoint.kind="interrupted"`（**gitnexus 永不自动
        #   清除**）⟹ `gitnexus status` 恒 `stale` ⟹ 下一轮 `context --update` 又白跑一次 analyze
        #   （**自激循环**：越杀越 stale、越 stale 越跑）。同时 `lbug.wal` 残留 + `lbug.shadow` 缺失
        #   （正常收尾三 sidecar 应全消失）⟹ 向量索引 DDL 未落主文件 → `code_embedding_idx` 报缺失。
        #   ⚠ 单点：与 `_gitnexus_ensure_baseline` 共用同一旋钮，禁各自硬编码。
        # 2026-09-19 ECC-4BDBA3605F47：原此处直调 `analyze --embeddings`（无残留自愈）⟹
        #   残留态下恒失败、`context --update` 恒 unavailable。改为经单一事实源
        #   `_gx_analyze_embeddings`（内置 `--drop-embeddings` 重试臂）。
        if _gx_analyze_embeddings "$_gn_dir"; then
          _gn_status="rebuilt"
        fi
      fi
      export GK_GN_STATUS="$_gn_status"
      # F-REV-90（2026-09-16，用户指令「细化首次添加时间与最后一次改动时间，而不是低效回滚」）：
      # `_red_attacks.py` 以 `GK_RED_LEDGER` 指向的**上一轮上下文文件**为时间戳账本 ——
      # 注入点必须在下方覆盖写**之前**（同一文件，此刻仍是上一轮内容）⟹ 同内容重扫时
      # `first_added`/`last_modified` 逐字节不变（`context --update` 幂等），无需回滚。
      export GK_RED_LEDGER="$ctx_file"
      # 2026-10-30（签名竞态修复 ①）：写者**独占锁**覆盖「重建 + 重签 + 发布」整段；
      #   读者 `_ctx_inject_probe` 取共享锁 ⟹ 「新 JSON + 旧 .sig」不再对读者可见。
      #   `-w 20`（`_ctx_lock_acquire` 默认）：拿不到锁**也继续**（锁是防抖，不能把 update
      #   变成新的挂死点）；可重入 ⟹ 与本进程内层发布段共用同一把锁。
      local _cu_had="${_CTX_LOCK_FD:-}"
      _ctx_lock_acquire "$ctx_file" 20
      if ! python3 "$SKILL_DIR/scripts/gk_context_build.py" build "$SKILL_DIR" "$STATE_FILE" "$ctx_file" 2>/dev/null; then
        [ -z "$_cu_had" ] && _ctx_lock_release
        echo '{"ok":false,"error":"context update failed"}'
        return 1
      fi
      # Sign context file with Ed25519 —— **context key**（`_sign_raw` 默认 key_type=context
      # ⟹ `_CONTEXT_PRIV_KEY`；注入侧 `_context_signature_fresh` 用 `_CONTEXT_PUB_KEY` 验证，
      # 两侧**必须同源**）。⚠ 原注释写「uses audit key」是**误导**（若真用 audit key，注入侧
      # 必报 invalid signature）—— 2026-09-16 读码核实并订正。
      local sig_result; sig_result=$(_sign_raw "$ctx_file" 2>/dev/null || echo '{"error":"sign failed"}')
      local sig_file="${ctx_file}.sig"
      # .sig 同样 tmp+rename（原直接 `> "$sig_file"` 会把 .sig 先截断成 0 字节）
      local _sig_tmp="${sig_file}.tmp.$$"
      echo "$sig_result" | python3 "$SKILL_DIR/scripts/gk_json_utils.py" field sig --b64 2>/dev/null > "$_sig_tmp"
      mv -f "$_sig_tmp" "$sig_file" 2>/dev/null || rm -f "$_sig_tmp"
      [ -s "$sig_file" ] && echo "{\"ok\":true,\"signed\":true,\"files\":$(python3 "$SKILL_DIR/scripts/gk_json_utils.py" field files --len --file "$ctx_file" 2>/dev/null || echo 0)}" || echo '{"ok":false,"error":"context sign failed"}'
      [ -z "$_cu_had" ] && _ctx_lock_release
      ;;
    *)
      # A5: Verify context Ed25519 signature before displaying
      if [ -f "$ctx_file" ]; then
        local sig_file="${ctx_file}.sig"
        if [ -f "$sig_file" ]; then
          # Use Ed25519 verify via openssl pkeyutl (same as _verify_raw)
          local tmpctx; tmpctx=$(mktemp)
          cp "$ctx_file" "$tmpctx"
          local ctx_hash; ctx_hash=$(sha256sum "$ctx_file" | awk '{print $1}')
          local verify_ok; verify_ok=$(openssl pkeyutl -verify -pubin -inkey "${_CONTEXT_PUB_KEY}" -rawin -in "$tmpctx" -sigfile "$sig_file" 2>&1)
          rm -f "$tmpctx"
          # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
          if echo "$verify_ok" | "$RG" -q "Verified"; then
            GK_PY_CTX="$(_gk_py_path "$ctx_file")" python3 -c "import json,os;print(json.dumps(json.load(open(os.environ['GK_PY_CTX'])),indent=2,ensure_ascii=False))" 2>/dev/null || echo '{"error":"read failed"}'
          else
            echo "{\"ok\":false,\"error\":\"context signature INVALID — file may be tampered. Run: gatekeeper-cli.sh context --update\"}"
          fi
        else
          echo '{"ok":false,"error":"no context signature found. Run: gatekeeper-cli.sh context --update"}'
        fi
      else
        echo '{"ok":false,"error":"context file not found. Run: gatekeeper-cli.sh context --update"}'
      fi
      ;;
  esac
}

# ── R6 两路归因: IFR 因果链 + LOO logprobs ──
cmd_trace() {
  local target="${1:-advance}"
  [ ! -f "$STATE_FILE" ] && { echo '{"ok":false,"error":"No state file. Start an ECO phase first."}'; return 1; }
  python3 -c "
import json, os
sf = '$STATE_FILE'
d = json.load(open(sf))
eco = d.get('gate_data',{}).get('eco_completions',{})
entropy = d.get('gate_data',{}).get('entropy_rate','N/A')
chain = []
for phase, info in sorted(eco.items())[-10:]:
    chain.append({'phase': phase, 'completed': info.get('completed_at',''), 'to': info.get('transitioned_to',''), 'entropy': entropy})
print(json.dumps({'ok':True,'target':'$target','chain_len':len(chain),'chain':chain}, indent=2, ensure_ascii=False))
" 2>/dev/null || echo '{"ok":false,"error":"trace parsing failed"}'
}

cmd_attribution() {
  local input_file="${1:-}"
  [ -z "$input_file" ] && { echo '{"ok":false,"error":"Usage: attribution <prompt_file>"}'; return 1; }
  [ ! -f "$input_file" ] && { echo "{\"ok\":false,\"error\":\"prompt file not found: $input_file\"}"; return 1; }
  local api_key="${GATEKEEPER_API_KEY:-${DEEPSEEK_API_KEY:-}}"
  # 2026-09-10 F-REV-17（对齐 DSH 单一 route + model id 透传）：base/model 走 provider 单源解析——
  # 原实现硬编码 `https://api.deepseek.com/v1/chat/completions` + V3 旧名模型 = **第二事实源**
  # 绕过 DS_* 常量（换模型/换网关需改代码）。现统一消费 API_BASE/API_MODEL（env 可覆盖）。
  _resolve_provider_config
  [ -z "$api_key" ] && { _resolve_api_key; api_key="${API_KEY:-}"; }
  [ -z "$api_key" ] && { echo '{"ok":false,"error":"No API key. Set \$GATEKEEPER_API_KEY"}'; return 1; }
  local prompt; prompt=$(cat "$input_file" 2>/dev/null | head -c 8000)
  [ -z "$prompt" ] && { echo '{"ok":false,"error":"Empty prompt file"}'; return 1; }
  # Call DeepSeek with logprobs for LOO attribution
  local _at_base="${API_BASE:-https://api.deepseek.com}" _at_model="${API_MODEL:-deepseek-flash}"
  # B9f（2026-10-28）：prompt 转义改走 CLI（stdin 传原文）——旧式 shell 内插 `'$prompt'`
  #   在 prompt 含撇号时 SyntaxError ⟹ `|| echo '""'` 静默变空 content（顺带修此缺陷）。
  local _at_prompt_json
  _at_prompt_json=$(printf '%s' "$prompt" | python3 "$SKILL_DIR/scripts/gk_views.py" attribution-prompt 2>/dev/null || echo '""')
  local resp; resp=$(curl -s --max-time 120 -X POST "${_at_base%/}/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $api_key" \
    -d "{\"model\":\"${_at_model}\",\"messages\":[{\"role\":\"user\",\"content\":${_at_prompt_json}}],\"max_tokens\":256,\"temperature\":0,\"logprobs\":true,\"top_logprobs\":3}" 2>/dev/null)
  # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
  if echo "$resp" | "$RG" -q '"error"'; then
    echo "{\"ok\":false,\"error\":\"API call failed\"}"
    return 1
  fi
  python3 "$SKILL_DIR/scripts/gk_views.py" attribution-report <<< "$resp" 2>/dev/null || echo '{"ok":false,"error":"logprobs parsing failed"}'
}

# ── 人类成就系统 (bridge-r-phase R7.9 T80 移植) ──
# 4 个成就: first_blood, sharpshooter, comeback, graduate
# 用户可在 state 中自定义成就标签和描述
_ACHIEVEMENT_DEFAULTS='
{"eco-first-cycle":{"label":"First ECO Cycle","msg":"Completed your first ECO cycle."},
 "eco-10-cycles":{"label":"Veteran","msg":"Completed 10 ECO cycles."},
 "ecc-impact-done":{"label":"Impact Analyst","msg":"Completed an ECC impact analysis."},
 "redteam-first-find":{"label":"Bug Hunter","msg":"Red team found its first vulnerability."},
 "redteam-clean":{"label":"Iron Defense","msg":"Red team found zero vulnerabilities."},
 "key-rotate-first":{"label":"Key Master","msg":"First automatic key rotation completed."},
 "cron-100-runs":{"label":"Automation Hero","msg":"Cron jobs executed 100 times."},
 "audit-perfect":{"label":"Perfect Audit","msg":"Audit passed all checks."},
 "human-review-first":{"label":"Human Touch","msg":"First human review completed."},
 "resolve-first":{"label":"Arbiter","msg":"First human resolution recorded."}}'

_get_achievements_config() {
  ACH_DEFAULTS="$_ACHIEVEMENT_DEFAULTS" python3 "$SKILL_DIR/scripts/gk_views.py" achievements-config "$STATE_FILE" 2>/dev/null || echo "$_ACHIEVEMENT_DEFAULTS"
}

_check_achievements() {
  python3 "$SKILL_DIR/scripts/gk_views.py" achievements-check "$STATE_FILE" 2>/dev/null || echo "[]"
}

_encouragement() {
  local event_type="$1" detail="$2"
  if [ "$event_type" = "interrupt" ]; then
    echo "中断: ${detail}。这不是失败——是系统在问题累积前抓住了计划偏差。检查证据后重新开始。"
  elif [ "$event_type" = "achievement" ]; then
    echo "成就解锁: ${detail}"
  fi
}

# ── cmd_achievements: 列出/查看成就状态 ──
cmd_achievements() {
  local raw
  raw=$(_get_achievements_config)
  local unlocked
  unlocked=$(_check_achievements)
  ACH_RAW="$raw" ACH_UNLOCKED="$unlocked" python3 "$SKILL_DIR/scripts/gk_views.py" achievements-record "$STATE_FILE"
}

# ── adjudicate: 裁决记录工具 + 人类评分交叉验证 ──
# Refs: MPR Standing Plan §ECO-EDIT — 人类 PASS/WARN/BLOCKED 打分 + ⑨ Human Optimizer
# Usage: adjudicate --verdicts '{"F1":"PASS","F2":"WARN",...}' --score <0.0-1.0> [--decision "text"]
#                  [--impact <path>] [--stage <name>] [--verdicts-file <json>] [--concessions-file <json>]
#                  [--concessions '{"F2":"…"}'] [--blind] [--checklist '[…]'] [--change-items N]
#                  [--constraint-level <c>] [--ts <ISO8601>] [--json-compact]
# Stage: any (works in standing/analysis modes)
# 功能: 记录人类裁判裁决 + 对比 monitor 评分；R17-T2 后 = 薄调用 gk_adjudicate.py（输出信封「旧键+新键」
#       + `entry` 回传），state 落盘收归本处 `_state_write` 单点。
cmd_adjudicate() {
  # R17-T2（2026-09-28）：**真 argv 薄调用** —— 单一事实源 = scripts/gk_adjudicate.py
  #   （原内联 A2–A11/A14 已删；A12 的 checksum 写点保留下方唯一一行）。
  # 契约面：输出信封「保留旧键 + 新增键」（A13/R7 owner 裁定 2026-09-28）；`entry` 由文件版回传、
  #   本处只做 append+cap=50（R17-R6，禁 CLI 重建）；state 落盘收归 `_state_write` 单点；
  #   `--ts` 生产路径单点声明（R8）；rc→JSON 信封由文件版承担（R9 契约表）。
  local _a _has_ts=false
  for _a in "$@"; do [ "$_a" = "--ts" ] && _has_ts=true; done
  local -a _tail=(--path "$STATE_FILE")
  # R8 单点：仅当调用方未显式给 --ts 时由本处注入（parity 臂可覆盖以定源）
  [ "$_has_ts" = false ] && _tail+=(--ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
  local _out _rc
  _out=$(python3 "$SKILL_DIR/scripts/gk_adjudicate.py" "$@" "${_tail[@]}" 2>/dev/null)
  _rc=$?
  if [ "$_rc" -ne 0 ]; then
    # 失败面：文件版已产 JSON 信封即原样透传（rc 逐值保真）；无输出（异常）补显式信封（禁静默）
    if [ -n "$_out" ]; then printf '%s\n' "$_out"; else
      echo "{\"ok\":false,\"error\":\"adjudicate_python_failure\",\"exit_code\":$_rc}"
    fi
    return "$_rc"
  fi
  # R17-R6 写盘收归 CLI 单点：entry 由文件版回传 → append + cap=50（`_state_write` 自带 flock/原子/checksum）
  ADJ_ENTRY=$(printf '%s' "$_out" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin).get("entry") or {},ensure_ascii=False))' 2>/dev/null) \
  _state_write "
import os as _os, json as _json
_e=_json.loads(_os.environ.get('ADJ_ENTRY','') or '{}')
if _e:
    cl=d.setdefault('gate_data',{}).setdefault('human_calibration_log',[])
    cl.append(_e)
    del cl[:-50]
" 2>/dev/null || true
  [ -f "$STATE_FILE" ] && _state_checksum_write
  printf '%s\n' "$_out"
}

_dispatch() {
  local cmd="$1"; shift
  local entry="${_CMD_REG[$cmd]:-}"

  if [ -z "$entry" ]; then
    local valid_cmds=""
    for k in "${!_CMD_REG[@]}"; do valid_cmds="${valid_cmds:+$valid_cmds,}$k"; done
    echo "{\"ok\":false,\"error\":\"Unknown command: $cmd. Not registered. Valid commands: [$valid_cmds]\",\"exit_code\":2,\"usage\":\"run 'gatekeeper-cli.sh help [cmd]' for the unique call formula of any command\",\"next\":\"bash gatekeeper-cli.sh help\"}"
    return 2
  fi

  IFS='|' read -r fn gate_level stage_constraint side_effects <<< "$entry"

  # stage gate: active-r 约束
  if [ "$stage_constraint" = "active-r" ]; then
    local cur_stage
    cur_stage=$(STATE_FILE="$(_gk_py_path "$STATE_FILE")" python3 "$SKILL_DIR/scripts/gk_state_query.py" --get stage --default IDLE 2>/dev/null)
    if [ "$cur_stage" = "IDLE" ] || [ "$cur_stage" = "DONE" ]; then
      _log_block "$cmd" "command router rejected: stage=$cur_stage"
      echo "{\"ok\":false,\"error\":\"Command $cmd requires active R-phase (current stage: $cur_stage). Start with spz-gatekeeper-r-sequence skill first.\"}"
      return 1
    fi
  fi

  # gate_level gate: full=always pre_tool_check, partial=only with side_effects, none=skip
  local should_check=false
  case "$gate_level" in
    full) should_check=true ;;
    partial) [ -n "$side_effects" ] && should_check=true ;;
    none) ;; # skip
  esac
  if $should_check; then
    local gate_out
    gate_out=$(pre_tool_check "$cmd" 2>/dev/null || echo "")
    # 2026-09-20（ECC-PLAN ②·归口）：rg 单源 "$RG"（原 bare rg）
    if echo "$gate_out" | "$RG" -q '"allowed":false'; then
      echo "{\"ok\":false,\"error\":\"pre_tool_check blocked $cmd\",\"detail\":$gate_out}"
      return 1
    fi
  fi

  "$fn" "$@"
}
# PROTECTED_REGION_END::gate

# ─── 计费单点（ECC-1E6BFDD7A207 · Q14 裁定 B，2026-09-23）─────────────────────
# BILL_UNITS_DECL path1=batches path2=files_dedup counter=edit_budget.remaining
# ↑ **机器可读的计费口径声明**（`ECC-CB8579F9D826` 的**区外等价加固**）。两套扣减实现**共享同一
#   额度**（`remaining`/`used`/`edit_count`）。**2026-10-05 归化（`REV-15` §21.3 修订 X）**：原 ② 按
#   **调用次数**计（`path2=calls`）⟹ 与 ① 单位不同；现将 ② 向 ① **归化**（补**身份去重**）⟹
#   `path2=files_dedup`（命令向量去重）。
#   **2026-10-23 `REV-24`（owner 裁定「批次作计价单位」）**：① 由 `files_dedup` 改为 **`batches`** ——
#   Gate4 自上次 verify 以来的整批改动 = 1 单位（T4′/T6 各 +1 附加）。两通道**维度主动分化**：
#   ① 管「一批改动收束了几轮」、② 管「CLI 命令向量重复」。声明 = 契约，`arm36` 已**重述**为
#   「两条实现的反推值必须逐字等于本行声明」，任一侧静默漂移仍会红。
#   口径（正典 `2026-09-21-review-runtime-subplan.md` §4.12.4 Q14）：`edit_budget` =
# 「agent **经门禁观察点**的写动作次数」。观察点两处，**但扣减实现是两套**（2026-09-24 勘误
# `ECC-CB8579F9D826`：原注释称「同调本单点 / 扣减+留痕唯一实现」= over-claim，与源码不符）：
#   ① `pre_tool_check` 的 EDIT_TOOLS 面（hook Gate4 拦截点；`edit|write|searchreplace|…`）
#      —— **在 `PROTECTED_REGION::gate` 之内** ⟹ 独立内联实现（`billed_files[]` 仅作观测面；
#      扣减按 **批次** —— `batch_open()` 判定本刀是否本批首刀）；
#   ② 下方调度尾部：`_dispatch` 分派的**写类**子命令（`_CMD_REG` 的 `side_effects` ∈
#      {state_write, git_write, key_write}）—— 这是 Q14 裁定 B **新纳入**的覆盖面，
#      由本函数 `_bill_edit` 承担。**2026-10-05 归化前**：按**调用次数**计（`path2=calls`）；
#      **归化后**：补**身份去重**（`billed_files[]`，身份 = 实参向量哈希）⟹ `files_dedup`。
# ⚠ **维度分化是有意的**（`REV-24` 2026-10-23 owner 裁定）：① = 批次、② = 命令向量去重；
#   共享同一个 `remaining` 计数器 ⟹ 任一侧改口径必须同步本声明（arm27 反推比对 + arm36 钉）。
# 必须**不**计（否则误计/自噬）：
#   ⓐ 门禁**内部**调用 —— 判别面是「**不经 `_dispatch`**」（`_log_block`→`_state_write`、
#      `advance` 内部写、`_budget_override_record`）；故**禁**把计费挂进 `_state_write` 本体。
#   ⓑ `GK_BUDGET_OVERRIDE=1` 放行（跳过扣减与耗尽阻断）。
#   ⓒ `state-patch` 且 fragment 触及 `edit_budget` 的**逃生舱自身**（否则 `remaining=0` 时
#      连重置它自己都会被扣）—— 该判定由**调用方**（调度尾部）承担，本单点不复制它。
# ⚠ 算法一字不改：`remaining-1` / `used+1` / `edit_count+1`；`edit_count` = 本 R-phase 累计，
#   归零由 `_edit_budget` 在 `r_phase` 切换时做 ⟹ 本处**不自持**归零。
# ⚠ 本函数**不**做耗尽阻断（BLOCK）—— 阻断面仍在 `pre_tool_check` 的既有分支（语义不变）。
_bill_edit() {
  local _why="${1:-edit}"; shift || true
  # `REV-15` §21.3 修订 X（2026-10-05 · 归化）：原 ② 按**调用次数**计（无去重台账）⟹ 与 ①（hook
  #   Gate4，按 `billed_files` 去重）**两套单位**共享同一 `remaining`。现补**身份去重** —— 身份 =
  #   `sha256(cmd + NUL 连接的各实参)[:12]`（**实参向量哈希**，owner 2026-10-05 裁定口径），经 env
  #   `GK_BILL_ID` 传入 payload（**不**拼进 python 源码 ⟹ 规避引号/换行注入，同 `GK_BILL_PATH`）。
  local _bid
  _bid=$(printf '%s\0' "$_why" "$@" | sha256sum | cut -c1-12)
  # ⓑ 显式人工放行：既不扣减也不阻断
  [ "${GK_BUDGET_OVERRIDE:-0}" = "1" ] && return 0
  [ -f "${STATE_FILE:-}" ] || return 0
  # 2026-09-23（**并发会话堵漏**，设计稿 §11.7-4 的落地）：原实现在**锁外**读 `remaining`
  #   （`gk_state_query.py`）却在锁内写**绝对值** `eb['remaining']=$_nr` ⟹ 两个并发写者
  #   各读 N、各写 N-1 = **丢一次扣减**（额度 fail-open）。实测（真两进程并发，修前）：
  #   `used=2` 而 `remaining` 只由 8→7 —— 两笔都记了账、只扣了一次。
  #   修法 = 把「读 remaining + 判 >=1 + 相对减 + `used`/`edit_count` 自增」**整体搬进
  #   `_state_write` 的锁内 payload**（与 hook 侧 `pre_tool_check` L2730 同一原子口径）⟹
  #   读-改-写全程持 flock，无 TOCTOU 窗口；且**判据只剩一处**（不再有锁外快路径预检，
  #   防两处判据漂移）。payload 末行 print 扣减后的 remaining，仅供下方调试日志。
  local _nr
  _nr=$(GK_BILL_ID="$_bid" _state_write "
import os as _os
gd=d.setdefault('gate_data',{}); eb=gd.setdefault('edit_budget',{})
# 2026-09-25 会话隔离：有会话键 → 扣本会话域；无键 → 全局口径（与修前一致）。
_sid=_os.environ.get('GK_SESSION_ID','') or ''
if _sid:
    _box=eb.setdefault('sessions',{}).setdefault(_sid,{})
    _box.setdefault('max',eb.get('max',0)); _box.setdefault('used',0)
    _box.setdefault('remaining',int(_box.get('max',0) or 0))
else:
    _box=eb
# 2026-10-05 归化（REV-15 修订 X）：身份去重 —— 同一身份（实参向量哈希）只计一次。
_bid=_os.environ.get('GK_BILL_ID','') or ''
_bf=_box.setdefault('billed_files',[])
if _bid and _bid not in _bf:
    _bf.append(_bid)
    del _bf[:-64]
    _r=int(_box.get('remaining',0) or 0)
    if _r>=1:
        _box['remaining']=_r-1
        _box['used']=int(_box.get('used',0) or 0)+1
        gd['edit_count']=int(gd.get('edit_count',0) or 0)+1
        print(_r-1)
    else:
        print(_r)
else:
    print(int(_box.get('remaining',0) or 0))
" 2>/dev/null | tail -n 1)
  # 留痕（**不**改 state schema）：`used`/`edit_count` 即 state 侧消耗可见性；本行仅调试日志
  [ -n "${GK_DBG_LOG:-}" ] && echo "[bill_edit] $_why -> remaining=${_nr:-?}" >>"$GK_DBG_LOG" 2>/dev/null
  return 0
}

# ─── 统一调度 ───
# Phase 7b (2026-08-23): 会话绑定 WARN — 非 discover 命令跟随 plan 指针时告警，
# 提示隔离 state 来源（discover 写入）；discover（无 --plan）可清除指针返回默认。
if [ "${_PP_FOLLOWED:-false}" = "true" ] && [ "$cmd" != "discover" ]; then
  echo "WARN[plan-pointer]: following isolate state set by discover — run 'discover' (no --plan) to return to default" >&2
  echo "WARN[plan-pointer]: following isolate state set by discover" >> "$GK_DBG_LOG"
fi
# 密钥过期启动检查（轮转盲区修复 2026-08-21）：任何命令先处理过期密钥，不 advance 也轮转。
# audit 命令自身管理密钥生命周期（--key rotate 等），跳过避免双重轮转；
# cron 调度器子进程（cron run）由作业自身处理，跳过避免递归。
case "$cmd" in
  audit|cron) : ;;
  *) _key_rotate_if_expired ;;
esac
# ── 计费面 ②（ECC-1E6BFDD7A207 · Q14 裁定 B）：`_dispatch` 分派的**写类**子命令计入 edit_budget ──
# 判别面 = `_CMD_REG[$cmd]` 的 `side_effects`（数据驱动，取该注册串末字段 `##*|`）∈
# {state_write, git_write, key_write}。**不另立清单** ⟹ 新增写类子命令自动纳入、无第二事实源。
# 排除：ⓐ 门禁内部调用（不经本行 ⟹ 天然不计）；ⓑ `GK_BUDGET_OVERRIDE=1`（`_bill_edit` 内判）；
#       ⓒ `state-patch` 且 fragment 触及 `edit_budget` 的逃生舱自身（否则 remaining=0 时
#          连重置它自己都会被扣）；ⓓ **零副作用形态**（见下方 `_bill_is_noop_invoke`）。
#   ⓔ **已知缺口（未修，`ECC-4BE775BC003B`）**：`--state <p>` **不改变计费落点** —— 本判据面读
#      `${STATE_FILE:-}`，而 `--state` 只在 `cmd_*` 内部生效（**晚于**本块）⟹ 用 `--state` 隔离的
#      调用仍扣**默认** state 额度（实测：`test_gk_apply_worktree_errors.py` 三臂中两臂带 `--state`
#      仍扣满 3 = 臂数）⟹ 「用 `--state` 隔离」是**假隔离**。修法待裁：须红先臂 + 可能改本判据面
#      （**语义变更 ⟹ 禁裸落刀**）。
#       扣减**先于** `_dispatch` ⟹ 不夺走 dispatch 的退出码
#          （本块之后恒以 `_dispatch` 的 rc 作为脚本退出码，原契约不变）。
# ── ⓓ 零副作用形态**不计费**（`ECC-0530B31DF9F1` 的「假计费」切片，2026-09-26）─────────
# 病象（本机实测 2026-09-26：沙箱技能根 + HEAD 版 CLI + `edit_budget.max=8/remaining=8`）：
#   · `apply-worktree --code-fix --dry-run …` ⟹ `remaining` **8→7** —— 而该形态在 `cmd_apply_worktree`
#     里于**建 worktree 之前**就 return（其「--dry-run：只回族判定 + 窄任务串（不申请 worktree、
#     不派发）」注释即零副作用契约）⟹ **假计费**。
#   · `apply-worktree --reclaim` ⟹ 同样 **8→7** —— 该子模式**缺省即 dry-run**（只报告；`--apply`
#     才落刀，单一事实源 = `scripts/gk_worktree_reclaim.py`）⟹ 同族假计费。
#   · 对照 `state-patch '{"…"}'`（真写 state）⟹ 8→7 —— **应当**计费（本豁免不得动摇它）。
# 口径依据：`edit_budget` 计的是「agent **经门禁观察点**的**写**动作」（见「计费单点」头部）⟹
#   没有写就没有可计之物。**只豁免有据的显式形态**（实测 / 代码路径可证），**不**放宽到命令级 ——
#   否则整类命令免费 = 额度失效。
# ⚠ `advance --check` **不在**豁免面：本次未取到「成功路径零副作用」的实测证据（沙箱内守卫恒拒 ⟹
#   未进入写面，但不足以为成功路径背书）⟹ 另登记 finding，待证据齐备再裁。
_bill_is_noop_invoke() {
  case "${1:-}" in
    apply-worktree)
      case " $* " in
        *" --dry-run "*)
          # ⚠ `--dry-run` **仅**对 `--code-fix` 生效：plain 路径**解析**该旗标却不消费 ⟹ 仍真建 worktree
          case " $* " in *" --code-fix "*) return 0 ;; esac ;;
      esac
      # `--reclaim`：只在**不带** `--apply` 时零副作用（带 `--apply` = 真回收，必须计费）
      case " $* " in
        *" --reclaim "*) case " $* " in *" --apply "*) : ;; *) return 0 ;; esac ;;
      esac
      # `--receive-check`（2026-10-03，计划 DRAFT-8 §2.2/T2/rev 15）：`cmd_apply_worktree` 在该分支
      #   **只调 `gk_receive_check.py` 并 return**（不写 state / 不建 worktree / 不派发）⟹ **零副作用**
      #   ⟹ 不计费。仍遵 P9「只豁免**显式命名形态**，不放宽整命令」。
      case " $* " in *" --receive-check "*) return 0 ;; esac ;;
    commit)
      # `--verify-only`：`cmd_commit` 在该分支**校验后直接 return**，从不进入提交段
      case " $* " in *" --verify-only "*) return 0 ;; esac ;;
    advance)
      # `--check` = dry-run（`ECC-033715F5215A` 取证，2026-09-26）：**零 state 写** ——
      #   python 侧 `gk_advance.py` 的 6 处 `_write_state` 全在 `if not dry_run:` 下，且成功路径在
      #   `if dry_run: return {check_only:True,…}` **早退**（终写不可达）；`_monitor_eval` 见 dry_run
      #   即返回 None（不写 `rejected_edits`）；`_edit_budget` 的额度/调度变更亦 `not dry_run`。
      #   bash 侧 `cmd_advance` 的 4 个写块（red ledger / auto-audit / audit_extra / achievements+context）
      #   全在 `[ "$dry_run" = "false" ]` 下。
      # ⟹ 与 `--dry-run` 同族：**不计费**。判据由 `test_arm34`（行为）+ `test_arm35`（写点守卫下限）钉住。
      case " $* " in *" --check "*) return 0 ;; esac ;;
    plan-refinement)
      # 形态级豁免（F-PROC-2，owner 2026-09-30 授权；P9「豁免通道须显式列举零副作用形态」的首个实例）：
      #   `--check-only`（只跑 preflight，纯只读）/ `--list-pending`（队列视图，纯只读）**零副作用** ⟹ 不计费；
      #   `--task`（真写 `gate_data.task_pipeline[]`）/ `--adjudicate`（下发 subagent）= 真副作用 ⟹ **仍计费**。
      #   ⚠ 只豁免**显式命名形态**，**不**放宽整命令（否则整类命令免费 = 额度失效，违 P9 判据）。
      case " $* " in
        *" --task "*|*" --adjudicate "*) : ;;
        *" --check-only "*|*" --list-pending "*) return 0 ;;
      esac ;;
  esac
  return 1
}
# ── 2026-10-23 交易凭证（**区外**，零保护区改动）：`used` 前后差额 → `<state>.budget-log.jsonl`
#    的 `kind=charge` 行。动机（owner 裁定「按顺序做」）：Gate 4 / `_bill_edit` 只改余额、
#    **不开票** ⟹ 审计拿不到交易流，只能从 `used` 反推。计费实现位于 `PROTECTED_REGION::gate`
#    内**不可改** ⟹ 在区外用「整次调用前后的快照差额」复原 `cost`；扣款口径、扣减点、计费单位
#    **一律不变**（本块只读快照 + 追加旁挂账本，绝不改 state）。
#    ⚠ 快照必须包住**整次调用**：`_bill_edit` 在 `_dispatch` **之前**扣（下方计费块），只包
#      `_dispatch` 会漏掉整条 CLI 计费通道。
#    ⚠ 取快照的口径按「同一域」比对（`session` / `global`）：会话条目在**首笔扣款时**才被创建，
#      跨域差额（b0 读全局、b1 读新会话域）是伪差值 ⟹ **不记，绝不猜**。
_budget_snap() {  # → "<domain> <used> <remaining>"；不可用 → "- - -"
  STATE_FILE="${STATE_FILE:-}" GK_SESSION_ID="${GK_SESSION_ID:-}" python3 - <<'PY' 2>/dev/null || echo "- - -"
import json, os, sys
sys.stdout.reconfigure(newline="\n")   # CRLF 净化（2026-11-01）：Windows print=\r\n ⟹ $() 捕获尾粘 \r 污染账单三字段串
p = os.environ.get("STATE_FILE") or ""
sid = os.environ.get("GK_SESSION_ID") or ""
try:
    d = json.load(open(p, encoding="utf-8"))
except Exception:
    print("- - -"); raise SystemExit
eb = (d.get("gate_data") or {}).get("edit_budget") or {}
box = (eb.get("sessions") or {}).get(sid) if sid else None
if sid:
    # 有会话键 ⟹ **一律**按会话域报（`session`），条目未建时按扣减点的同一 `setdefault` 口径
    #   预演（`max=eb.max / used=0 / remaining=max`；见 Gate 4 与 `_bill_edit` 的 `_s.setdefault`）。
    #   否则「新会话首笔扣款」会跨域（b0 全局、b1 新会话域）而被当伪差值丢掉 ⟹ 首刀无票。
    if isinstance(box, dict):
        print("session", int(box.get("used", 0) or 0), int(box.get("remaining", 0) or 0))
    else:
        print("session", 0, int(eb.get("max", 0) or 0))
else:
    print("global", int(eb.get("used", 0) or 0), int(eb.get("remaining", 0) or 0))
PY
}
_bill_args="$*"
_bill_b0=""
# 只读命令零额外开销：仅 Gate 4 计费点（`pre-tool-check`）先取；CLI 计费块命中时再补取。
case "$cmd" in pre-tool-check) _bill_b0=$(_budget_snap) ;; esac
_gk_bill_se="${_CMD_REG[$cmd]:-}"
_gk_bill_se="${_gk_bill_se##*|}"
# 2026-09-30 G4-d（REV-5 §13.2）：计费豁免**按通道**（命令白名单），**不再按内容**。
#   依据：Fed 日内信贷「有抵押免费 / 无抵押收费」—— 可对账的**记账**（finding / state 维护 /
#   审计 / 计划校验）是银行自己的账本，不占工程额度；**工程动作**（commit / push /
#   apply-worktree / advance）照旧计费。旧实现 = 子串嗅探 `case "$*" in *edit_budget*)`
#   ⟹ **免密提款**（fragment `{"note":"edit_budget"}` 也能免），且把「是否计费」与
#   「是否留痕」两件事混成一个判据。判据见 scripts/test_gk_bill_channel.py。
_BILL_EXEMPT_CMDS=" finding state-patch self-check audit plan-lint doc-align state-query "
_gk_bill_exempt=0
case "$_BILL_EXEMPT_CMDS" in *" $cmd "*) _gk_bill_exempt=1 ;; esac
if [ -n "$_gk_bill_se" ] && [ "$_gk_bill_exempt" = "0" ] && ! _bill_is_noop_invoke "$cmd" "$@"; then
  case "$_gk_bill_se" in
    state_write|git_write|key_write) [ -n "$_bill_b0" ] || _bill_b0=$(_budget_snap); _bill_edit "$cmd" "$@" ;;
  esac
fi
# ── 2026-10-23 交易凭证（后置半）：整次调用跑完 ⟹ 再取一次快照，差额即本笔 `cost`。
#    前半（`_budget_snap` 定义 + `_bill_b0`）在**计费块之前**（见上），两半合起来才覆盖
#    `_bill_edit`＋`pre-tool-check`（Gate 4）两个扣减点。
_dispatch "$cmd" "$@"
_bill_rc=$?
if [ -n "$_bill_b0" ]; then
  _bill_b1=$(_budget_snap)
  read -r _bill_d0 _bill_u0 _bill_r0 <<<"$_bill_b0" || true
  read -r _bill_d1 _bill_u1 _bill_r1 <<<"$_bill_b1" || true
  case "${_bill_d0:-}:${_bill_d1:-}" in
    session:session|global:global)
      # 非数字（`-` / 空）⟹ 不记，绝不猜（沿用本文件 `[ .. -ge 0 ] 2>/dev/null` 的判据式）
      if [ "${_bill_u0:-x}" -ge 0 ] 2>/dev/null && [ "${_bill_u1:-x}" -ge 0 ] 2>/dev/null; then
        _bill_d=$(( _bill_u1 - _bill_u0 ))
        if [ "$_bill_d" -gt 0 ]; then
          GK_CHARGE_COST="$_bill_d" _budget_log_append "charge" \
            "cmd=$cmd args=$_bill_args cost=$_bill_d used=$_bill_u0->$_bill_u1 remaining=${_bill_r1:-?}" || true
        fi
      fi ;;
    *) : ;;                    # 不可用 / 跨域（b0 全局、b1 新会话域）⟹ 伪差值，不记
  esac
fi
exit "$_bill_rc"
