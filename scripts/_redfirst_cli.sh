#!/bin/bash
# _redfirst_cli.sh — red-first 复现器（PW-SN §2.2 步①，2026-09-15 REV-5 / 四轮质询 G6+G9）
# =============================================================================
# 机理：`test_gk_route_center.TestL4DomainRoute._sandbox` 以「SCRIPT_DIR 软链 scripts/ +
# 实拷 `SCRIPT_DIR/../gatekeeper-cli.sh`」建沙箱 ⟹ 复制一份技能根**镜像**，把 CLI 换成
# `<rev>` 版（默认即"上一版实装"），即可在同一批用例上断言**必红**。
# 关键约束：被测测试文件必须**实拷贝**——软链会被 `Path(__file__).resolve()` 还原回真目录，
# 从而又用回工作树里的 CLI（red-first 静默失效；REV-5 首版运行即踩此坑）。
#
# Usage: bash scripts/_redfirst_cli.sh <git-rev> <test-file-rel> "<pytest -k 表达式>" \
#          [--expect=red|green]
#   e.g. bash scripts/_redfirst_cli.sh HEAD scripts/test_gk_route_center.py \
#          "j5b or j9 or j11 or j13 or j14"
#        bash scripts/_redfirst_cli.sh <rev> scripts/test_gk_route_center.py \
#          "j5b or j11 or j13 or j15 or j16 or j17 and not j14b" --expect=red
#        （R-14：把计划里的"必红"从**自报**变**可断言**；`-k` 选中集即用例清单）
# Exit: 0 = 期望满足（**未给 --expect 时恒 0**，保持 REV-5 契约「不看用例红绿」）；
#       1 = 期望不满足（red 出现假绿 / green 出现假红）；2 = 环境 / 取版 / 参数失败。
# 解释器：$REDFIRST_PY（缺省走**单源** `scripts/gk_accept_py.py`：env `ACCEPT_PY` →
# `scripts/_accept_py.local`（本机私有）→ `python3`）——2026-09-16 R-16 D-1 的语义保留：
# red-first 必须与生产面**同解释器版本**（本机 venv 绑定由 `_accept_py.local` 承担，
# 公开 clone 无该文件时回落系统 python3）。
set -uo pipefail
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
_REG="${REDFIRST_REGISTRY:-$SKILL_DIR/references/red-arm-templates.json}"
# `PY` 与 `SKILL_DIR` 一并提前（2026-09-23 实测）：`--affected --run` 在 mode 分支内就要用它，
# 而原赋值位置在其**之后** ⟹ `set -u` 下 `PY: unbound variable`（首版实测撞到，已修）。
PY="${REDFIRST_PY:-$(python3 "$SKILL_DIR/scripts/gk_accept_py.py" 2>/dev/null || echo python3)}"

# ─── 登记表驱动入口（2026-09-23，ECC-9FE17481B8F6；用户裁定「登记表驱动入口」）───
# 把「红先工作法三条」从**文本提示**变**机械入口**，堵掉「手工拼 -k / 手工挑测试文件」这条路：
#   ① 一条命令出判定 —— `--finding <id>`：测试文件与 `-k` 由登记表给出（禁拼）；
#   ② 形态臂先行 —— 缺省只跑 `shape_k`（源码切片，~0.1s/例）；`--phase=full` 才跑判别力全臂；
#   ③ 受影响文件选中集 —— `--affected`：由 `git diff` 推出受影响的测试文件（替掉全量回归）。
# 安全网 —— `--check`：登记表 ↔ 测试文件 ↔ 用例名**三方对账**，任何漂移 fail-loud(exit 2)。
# 登记表 = `references/red-arm-templates.json` 的 `finding_arms`（单一事实源，禁第二份名单）。
_resolve() {  # <mode:finding|affected|check> <reg> <skill_dir> [finding-id] [shape|full]
  python3 -c '
import json, os, re, subprocess, sys
mode, reg_path, skill_dir = sys.argv[1], sys.argv[2], sys.argv[3]
rest = sys.argv[4:]
def die(m):
    sys.stderr.write("[red-first] FATAL: %s\n" % m)
    raise SystemExit(2)
try:
    reg = json.load(open(reg_path, encoding="utf-8"))
except Exception as e:
    die("登记表不可读 %s: %s" % (reg_path, e))
arms = reg.get("finding_arms") or []
def names_of(tf):
    try:
        src = open(os.path.join(skill_dir, tf), encoding="utf-8").read()
    except Exception as e:
        die("test_file 不可读 %s: %s" % (tf, e))
    return set(re.findall(r"(?m)^\s*def (test_\w+)", src))
def drift(a):
    tf = a.get("test_file") or ""
    ns = names_of(tf)
    out = []
    for key in ("finding", "test_file", "shape_k", "full_k", "expect"):
        if not a.get(key):
            out.append("缺字段 %s" % key)
    for key in ("shape_k", "full_k"):
        for tok in re.findall(r"[A-Za-z_]\w*", a.get(key) or ""):
            if tok in ("or", "and", "not"):
                continue
            if not any(tok in n for n in ns):
                out.append("%s 的用例 %r 不在 %s（无任何 test_* 名含该串）" % (key, tok, tf))
    return out
if mode == "check":
    if not arms:
        die("登记表 finding_arms 为空 —— 红先纪律没有登记面")
    bad = 0
    for a in arms:
        for d in drift(a):
            sys.stderr.write("[red-first] DRIFT %s: %s\n" % (a.get("finding") or "?", d))
            bad += 1
    sys.stdout.write("[red-first] --check: %d 条 finding 臂台账，漂移 %d 项\n" % (len(arms), bad))
    raise SystemExit(2 if bad else 0)
if mode == "affected":
    p = subprocess.run(["git", "diff", "--name-only", "HEAD"], capture_output=True, text=True)
    seen = []
    for f in (p.stdout or "").splitlines():
        f = f.strip()
        if not (f.startswith("scripts/") and f.endswith(".py")):
            continue
        base = f[len("scripts/"):-3]
        cand = f if base.startswith("test_") else ("scripts/test_%s.py" % base)
        if cand not in seen and os.path.isfile(os.path.join(skill_dir, cand)):
            seen.append(cand)
    if not seen:
        sys.stderr.write("[red-first] git diff 未推出受影响的测试文件\n")
        die("勿回退全量回归 —— 先把改动限定在有测试面的文件上")
    for c in seen:
        sys.stdout.write("%s\t\n" % c)
    raise SystemExit(0)
fid = rest[0] if rest else ""
phase = rest[1] if len(rest) > 1 else "shape"
hit = [a for a in arms if a.get("finding") == fid]
if not hit:
    die("finding %r 未登记红先臂（禁「我跑过了」自证）；已登记: %s"
        % (fid, ", ".join(x.get("finding") or "?" for x in arms)))
a = hit[0]
d = drift(a)
if d:
    die("登记表漂移: " + "; ".join(d))
sys.stdout.write("%s\t%s\n" % (a["test_file"], a["shape_k"] if phase == "shape" else a["full_k"]))
' "$@"
}
case "${1:-}" in
  --check)    shift; _resolve check "$_REG" "$SKILL_DIR"; exit $? ;;
  --affected)
    shift
    _AFF=$(_resolve affected "$_REG" "$SKILL_DIR") || exit 2
    _AF=$(printf '%s\n' "$_AFF" | cut -f1)
    if [ "${1:-}" = "--run" ]; then
      # 2026-09-23（用户裁定「能并行的测试全部并行」）：受影响文件**一次**喂给 `pytest -n auto`
      #   （xdist 已在配好的隔离 venv，无需装包），替掉「N 个文件 N 次冷启」。
      #   两处**刻意不并行**：① `--finding/--expect` 判据面（单文件 + `-k`，xdist 启动开销 > 收益）；
      #   ② **复核面** —— xdist 有分块漂移假阳性（`ECC-2C6363430A3B`）⟹ 真回归必须串行复跑确认，
      #      本模式只做**并发首跑**，不替代 `_accept_cli.sh` 的串行复核。
      #   `REDFIRST_N` 可覆盖（本机空闲内存有限，必要时 `REDFIRST_N=2`）。
      #   默认 = **硬件自适应基数 × 2（上限 12）**（2026-10-29，user 令「把硬件自适应接进去」）：
      #     基数单一源 = `gk_hub_scheduler.adaptive_workers`（可见核/affinity + 空闲内存闸）；
      #     ×2 为实测 plateau 的超订因子（`-n auto`(=5) 250s / `-n 8` 211s / `-n 12` 206s
      #     / `-n 15` 211s / `-n 20` 214s ⟹ plateau ≈210s，失败集逐项相同）。
      _BASE_N=""
      if [ -z "${REDFIRST_N:-}" ]; then
        # 用 `python3`（**非** `$PY`）：探测 stdlib-only；`$PY` 可能是自测替身。
        _BASE_N="$(PYTHONPATH="$SKILL_DIR/scripts" python3 -c 'import gk_hub_scheduler as H; print(H.adaptive_workers(1000))' 2>/dev/null || true)"
      fi
      case "$_BASE_N" in ''|*[!0-9]*) _BASE_N="$(nproc 2>/dev/null || echo 4)" ;; esac
      _DEF_N=$(( _BASE_N * 2 )); [ "$_DEF_N" -gt 12 ] && _DEF_N=12; [ "$_DEF_N" -lt 1 ] && _DEF_N=1
      _N="${REDFIRST_N:-$_DEF_N}"
      echo "[red-first] --affected --run（**并行首跑，非复核**）: $(printf '%s\n' "$_AF" | wc -l) 个文件，-n $_N"
      # `--dist loadfile`（**确定层**，2026-09-24，`ECC-2C6363430A3B`）：默认 `--dist load`
      #   按**用例**分配 worker ⟹ 同文件用例拆散、异文件用例交错进同一进程 ⟹ 跨文件模块级
      #   状态泄漏（bootstrap 写 `subagent_runner` 全局）暴露为「并行红 / 串行绿」的分块漂移。
      #   `loadfile` 让**同文件恒同 worker** ⟹ 分配可复现，与 `_accept_cli.sh` 同策略。
      # shellcheck disable=SC2086
      PYTHONDONTWRITEBYTECODE=1 "$PY" -m pytest $_AF -q --tb=line \
        -p no:cacheprovider -n "$_N" --dist loadfile
      exit $?
    fi
    printf '%s\n' "$_AF"
    exit 0
    ;;
  --finding)
    shift
    _FID="${1:?usage: --finding <id> [--phase=shape|full] [--expect=red|green]}"; shift
    _PHASE="shape"
    case "${1:-}" in --phase=*) _PHASE="${1#--phase=}"; shift ;; esac
    case "$_PHASE" in shape|full) : ;; *) echo "[red-first] FATAL: --phase 只接受 shape|full" >&2; exit 2 ;; esac
    _LINE=$(_resolve finding "$_REG" "$SKILL_DIR" "$_FID" "$_PHASE") || exit 2
    _TF="${_LINE%%$'\t'*}"; _K="${_LINE#*$'\t'}"
    echo "[red-first] finding=$_FID phase=$_PHASE test=$_TF k=\"$_K\""
    # 复用既有已验通路（rev 默认 HEAD；其余参数原样透传，如 --expect=red）
    exec bash "$0" "${REDFIRST_REV:-HEAD}" "$_TF" "$_K" "${1:-}"
    ;;
esac

REV="${1:?usage: _redfirst_cli.sh <git-rev> <test-file-rel> <pytest -k expr> [--expect=red|green]}"
TESTFILE="${2:?}"
KEXPR="${3:?}"
case "${4:-}" in
  "")             EXPECT="none" ;;
  --expect=red)   EXPECT="red" ;;
  --expect=green) EXPECT="green" ;;
  *) echo "FATAL: 未知第 4 参 '${4}'（只接受 --expect=red / --expect=green）"; exit 2 ;;
esac
# `PY` 已在文件头（mode 分支之前）定义，主流程与 `--affected --run` 共用同一份。
cd "$SKILL_DIR" || exit 2
# 2026-09-23（**沙箱耗时**，实测驱动）：`git archive` **从 `/mnt/c` 读对象**是唯一大额
#   —— 实测分解：`git archive|tar` **1.48 s** / pytest 冷启 **0.66 s** / 被测臂本体 **0.04 s**。
#   故沙箱树按 **rev 的 commit sha** 缓存：首跑建，之后**零抽取**，每次只刷新覆盖层
#   （被测文件实拷贝 + rev 未跟踪脚本软链）。
#   **不换沙箱**：`/tmp` 已是 WSL 原生 ext4（最快落点），瓶颈在**源侧** CIFS/9p 读仓对象；
#   换到别处只会把 1.48 s 换成更慢。
_RFC="${REDFIRST_CACHE:-/tmp/gk-redfirst-cache}"
_RF_SHA=$(git rev-parse "$REV" 2>/dev/null) || { echo "FATAL: git rev-parse $REV 失败"; exit 2; }
RF="$_RFC/$_RF_SHA"
if [ ! -f "$RF/gatekeeper-cli.sh" ]; then
  mkdir -p "$RF/scripts"
  git archive "$REV" scripts 2>/dev/null | tar -x -C "$RF" \
    || { echo "FATAL: git archive $REV scripts 失败"; exit 2; }
  git show "$REV:gatekeeper-cli.sh" > "$RF/gatekeeper-cli.sh" \
    || { echo "FATAL: git show $REV:gatekeeper-cli.sh 失败"; exit 2; }
  # 2026-11-09：红先臂若消费 `references/red-arm-templates.json`（模版登记表/生成器族），
  #   sandbox 必须带 **rev 版登记表** —— 否则 `$RF/references` 缺席 ⟹ 红/绿都 ERROR（判据无效）。
  #   按 sha 缓存，rev 不变 ⟹ 只取一次；公开树无该文件时容错（不阻断其它形态）。
  mkdir -p "$RF/references"
  git show "$REV:references/red-arm-templates.json" > "$RF/references/red-arm-templates.json" \
    2>/dev/null || true
fi
_TB=$(basename "$TESTFILE")
# 覆盖层（每次都刷）
# ⚠ 被测文件必须**实拷贝**（见头部契约：软链会被 `Path(__file__).resolve()` 还原回真目录）；
#   且先确认缓存里它不是软链，否则 `cp` 会顺着链接**写穿**到工作树。
if [ -L "$RF/scripts/$_TB" ]; then echo "FATAL: 缓存内被测文件是 symlink（red-first 会失效）"; exit 2; fi
cp "$TESTFILE" "$RF/scripts/$_TB"
# rev **未跟踪**（本批新增）的脚本 ⟹ archive 不含 ⟹ 从工作树补软链（等价于原 `else` 分支）。
for f in scripts/*.py; do
  b=$(basename "$f")
  [ "$b" = "$_TB" ] && continue
  [ -e "$RF/scripts/$b" ] && continue
  ln -sf "$SKILL_DIR/$f" "$RF/scripts/$b"
done
echo "[red-first] rev=$REV cli_sha=$(sha256sum "$RF/gatekeeper-cli.sh" | cut -c1-12) py=$PY expect=$EXPECT sandbox=$RF"
# `PYTHONDONTWRITEBYTECODE` + `-p no:cacheprovider`：沙箱在 `/tmp` / CIFS 上，省掉 .pyc 与
# `.pytest_cache` 的落盘往返（纯提速，不改判据）。
OUT=$(PYTHONDONTWRITEBYTECODE=1 "$PY" -m pytest "$RF/scripts/$_TB" -q --tb=no -rfE \
      -p no:cacheprovider -k "$KEXPR" 2>&1)
printf '%s\n' "$OUT" | tail -30
SUM=$(printf '%s\n' "$OUT" | grep -E '[0-9]+ (passed|failed|error|errors)' | tail -1)
_n() { printf '%s' "$SUM" | grep -oE "[0-9]+ $1" | head -1 | cut -d' ' -f1; }
P=$(_n passed); F=$(_n failed); E=$(_n 'errors?')
case "$EXPECT" in
  none)
    echo "[red-first] 判读：FAILED = 判据对 $REV 版实现有判别力（预期）；全 passed = 判据对 $REV 无判别力（须重写判据）。"
    ;;
  red)
    if [ "${F:-0}" -gt 0 ] && [ "${P:-0}" -eq 0 ] && [ "${E:-0}" -eq 0 ]; then
      echo "[red-first] EXPECT=red 满足：选中集 ${F} 例全红（passed=0 errors=0）⟹ 判据对 $REV 有判别力"
    else
      echo "[red-first] EXPECT=red **不满足**：passed=${P:-0} failed=${F:-0} errors=${E:-0} ⟹ 判据对 $REV **无**判别力（假绿），须重写判据"
      exit 1
    fi
    ;;
  green)
    if [ "${F:-0}" -eq 0 ] && [ "${E:-0}" -eq 0 ] && [ "${P:-0}" -gt 0 ]; then
      echo "[red-first] EXPECT=green 满足：选中集 ${P} 例全绿（failed=0 errors=0）"
    else
      echo "[red-first] EXPECT=green **不满足**：passed=${P:-0} failed=${F:-0} errors=${E:-0} ⟹ 判据对 $REV 过度约束（假红），须重写判据"
      exit 1
    fi
    ;;
esac
