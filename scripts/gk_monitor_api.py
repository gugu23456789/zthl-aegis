#!/usr/bin/env python3
"""
Gatekeeper Monitor API -- LLM API 统一入口
==========================================
Extracted from gatekeeper-cli.sh _monitor_api() (L1480-1610).
Full alignment: failover chain, retry, GitNexus injection, hard evidence, schema, score normalization.

Usage:
  python3 scripts/gk_monitor_api.py --stage STAGE_0 --api-key KEY [--provider deepseek|mimo]

Exit codes:
  0 = OK (JSON output with result)
  1 = Error (JSON output with error field)
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from gk_state import _read_state, DEFAULT_STATE_FILE
from gk_json_utils import update_state

# Provider configs (from gatekeeper-cli.sh PROTECTED_REGION::constants)
# 2026-10-02（**模型可换**，与 bash 侧对称）：base/model/effort 改 env 覆盖 —— 模型保质期 ~3 个月
#   （旧模型退役 / 更便宜更好的上线），降级链目标 = 兜底防爆 ⟹ 换代应**只改配置不改代码**。
#   默认值 = 本模块既有值（**不变**）；覆盖键与 bash 同源：
#     DEEPSEEK_BASE_URL / GK_CRITIC_MODEL / GK_REASONING_EFFORT / MIMO_BASE_URL / GK_MIMO_CRITIC_MODEL。
#   ⚠ 本模块**当前未接线**（bash `_monitor_api` 不调用它）⟹ 本次 env 化**无运行时影响**，属收编前置；
#     原为「硬编码第二份」（bash 改 env 到不了这里）——现与 bash 同 env 作用域。
#   ⚠ 默认值分歧登记（本批**不**对齐，防未评估的行为变更）：本模块 DS reasoning default = "high"，
#     bash `DS_REASONING_EFFORT` default = "max"（既有分歧，收编时另裁）。
_DS_BASE_DEFAULT = "https://api.deepseek.com/v1"
_DS_MODEL_DEFAULT = "deepseek-flash"
_DS_EFFORT_DEFAULT = "high"
_MIMO_BASE_DEFAULT = "https://api.xiaomimimo.com/v1"
_MIMO_MODEL_DEFAULT = "mimo-v2.6-flash"

PROVIDERS = {
    "deepseek": {
        "base": os.environ.get("DEEPSEEK_BASE_URL", _DS_BASE_DEFAULT),
        "model": os.environ.get("GK_CRITIC_MODEL", _DS_MODEL_DEFAULT),
        "reasoning_effort": os.environ.get("GK_REASONING_EFFORT", _DS_EFFORT_DEFAULT),
    },
    "mimo": {
        # 2026-09-22 (P0): 域名修复 api.mimo.ai → api.xiaomimimo.com（旧域名失效 = failover 第二跳死）；
        # 模型 mimo-chat → mimo-v2.6-flash（v2.5 系列 2026-10-21 下线）。MiMo 不用 reasoning_effort
        # （payload 侧 L255 仅对 deepseek 注入），死字段已移除。实测 2026-09-22 九探针全绿。
        "base": os.environ.get("MIMO_BASE_URL", _MIMO_BASE_DEFAULT),
        "model": os.environ.get("GK_MIMO_CRITIC_MODEL", _MIMO_MODEL_DEFAULT),
    },
}

# Failover chain —— **机制合并**（2026-10-02，G5；读**同一 env 作用域**，与 bash 同源同接口）。
# 单源 = `gatekeeper-cli.sh::GK_FAILOVER_CHAIN`（bash 侧已 `export` ⟹ 任意子进程可继承）；本模块
#   从环境读取同一键 ⟹ 宿主/环境改一处即两实现同变（原为**硬编码第二实现**：改不了）。
# 默认串**逐字**与 bash 默认一致，且由 `scripts/test_gk_monitor_parity.py` 机检守护（禁单侧漂移）；
#   standalone（非 bash 子进程）无 env 时回落默认，保证可用。
FAILOVER_CHAIN = [p.strip() for p in
                  os.environ.get("GK_FAILOVER_CHAIN", "deepseek,mimo,local").split(",")
                  if p.strip()]


def _is_retryable(status_code: int) -> bool:
    """Filter which errors trigger failover (gatekeeper-cli.sh _is_retryable L144-148).
    Only network/timeout/5xx errors are retryable. 400-level are NOT.

    2026-10-10（ECC-5E433392C5C7）：**402 Payment Required（DS 欠费 / Insufficient Balance）**
    是例外 —— 它不是请求缺陷，而是「本 provider 这条腿已不可用，换下一条腿（MiMo）」的
    显式信号 ⟹ 必须视为可重试（否则 `stop_chain` 停在 DS，永远降不到 MiMo）。
    其余 4xx（400 语义错 / 401 鉴权）仍**不可重试**（换 provider 也是错 key/错请求，不付降级代价）。"""
    return status_code >= 500 or status_code == 0 or status_code == 402  # 0 = network error


# ── H1a（2026-09-28）：降级链「ms 级切换 + 安全防护加固」（落点=技能仓 scripts/）────────────
# 现状缺口（读码实测）：
#   ① 首跳「连不上」（域名失效/DNS 死）时，原实现要**白等 read 超时 60s × 2 次重试**才换跳
#      ⟹ 一次降级可达 ~2 分钟，**非 ms 级**。真实事故参照：`api.mimo.ai` 域名失效（见 PROVIDERS 注）。
#   ② 无**跨进程**健康记忆：CLI 每次调用都是新进程 ⟹ 每次都重新撞同一死域。
#   ③ 安全面：base URL 无白名单、跟随重定向、响应体无上限、错误串可能回显凭据。
# 修法：连接/读**双超时** + 连接类失败**立即降级**（不再同跳重试）+ **断路器**（失败阈值 → TTL 内
#       O(1) 零网络跳过）+ base 白名单 + 禁重定向 + 响应体上限 + 错误脱敏。
# 对齐 Bridge（`engine.py` 的 `_check_circuit`/`_record_failure`/`_failover_candidates`）语义；
# 差异：Bridge 在**进程内**，本仓需**落盘 TTL 缓存**（因 CLI 每次新进程）。
FAILOVER_CONNECT_TIMEOUT = float(os.environ.get("GK_FAILOVER_CONNECT_TIMEOUT", "3"))
FAILOVER_READ_TIMEOUT = float(os.environ.get("GK_FAILOVER_READ_TIMEOUT", "60"))
FAILOVER_BREAKER_FAILS = int(os.environ.get("GK_FAILOVER_BREAKER_FAILS", "2"))
FAILOVER_BREAKER_TTL = float(os.environ.get("GK_FAILOVER_BREAKER_TTL", "60"))
FAILOVER_MAX_RESP_BYTES = int(os.environ.get("GK_FAILOVER_MAX_RESP_BYTES", str(2 * 1024 * 1024)))
# base URL 白名单（单一事实源 = PROVIDERS）——防域名投毒 / SSRF / 误改 base
ALLOWED_BASES = frozenset(p["base"] for p in PROVIDERS.values())


def _breaker_path(state_path: str) -> Path:
    """断路器缓存路径（与 state 同目录；`.gitignore` 已覆盖）。纯运行时健康缓存，**非事实源**。"""
    return Path(state_path).parent / ".gatekeeper.failover.json"


def _breaker_read(state_path: str) -> dict:
    try:
        data = json.loads(_breaker_path(state_path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}   # best-effort：缓存损坏不得影响主流程


def _breaker_write(state_path: str, data: dict) -> None:
    """原子写（tmp + os.replace）；任何失败静默（纯缓存，不进主判据）。"""
    p = _breaker_path(state_path)
    try:
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
    except OSError:
        pass


def _breaker_allows(state_path: str, fb: str) -> tuple:
    """(allow, reason)。open 且未过 TTL → (False, …) ⟹ 调用方**零网络**跳过（ms 级）；
    TTL 过期 → half-open 放行一次探测。"""
    ent = _breaker_read(state_path).get(fb) or {}
    until = float(ent.get("open_until", 0) or 0)
    if until > time.time():
        return False, f"circuit open, retry in {round(until - time.time(), 1)}s (fails={ent.get('fails')})"
    return True, ""


def _breaker_record_fail(state_path: str, fb: str) -> None:
    data = _breaker_read(state_path)
    fails = int((data.get(fb) or {}).get("fails", 0) or 0) + 1
    data[fb] = {
        "fails": fails,
        "last_fail_at": round(time.time(), 3),
        "open_until": round(time.time() + FAILOVER_BREAKER_TTL, 3) if fails >= FAILOVER_BREAKER_FAILS else 0,
    }
    _breaker_write(state_path, data)


def _breaker_record_ok(state_path: str, fb: str) -> None:
    data = _breaker_read(state_path)
    if data.pop(fb, None) is not None:
        _breaker_write(state_path, data)


def _ensure_allowed_base(config: dict) -> None:
    """安全：base URL 必须落在 PROVIDERS 单源白名单内（防域名投毒 / SSRF / 误改 base）。"""
    if config.get("base") not in ALLOWED_BASES:
        raise ValueError(f"unsafe base url rejected: {config.get('base')!r} (not in allowlist)")


def _redact(msg: str, api_key: str) -> str:
    """安全：错误信息脱敏（绝不回显 api key / Bearer 凭据）。"""
    out = str(msg)
    if api_key:
        out = out.replace(api_key, "***")
    return re.sub(r"(Bearer\s+)\S+", r"\1***", out)

# Schema directory
SCHEMA_DIR = Path(__file__).parent.parent / "monitor-schemas"


def _collect_hard_evidence(stage: str, worktree: str, branch: str, state_path: str) -> dict:
    """Collect hard evidence (from gatekeeper-cli.sh _collect_hard_evidence L591-730)."""
    evidence = {}

    # commits_ahead_of_main
    if worktree and Path(worktree).exists():
        try:
            result = subprocess.run(
                ["git", "-C", worktree, "rev-list", "--count", "HEAD", "^origin/main"],
                capture_output=True, text=True, timeout=10
            )
            evidence["commits_ahead"] = int(result.stdout.strip()) if result.returncode == 0 else 0
        except (subprocess.TimeoutExpired, ValueError):
            evidence["commits_ahead"] = 0
    else:
        evidence["commits_ahead"] = 0

    # ci_trigger
    if worktree and Path(worktree).exists():
        ci_file = Path(worktree) / ".github" / "workflows" / "ci.yml"
        if ci_file.exists():
            try:
                content = ci_file.read_text(encoding="utf-8")
                evidence["ci_trigger"] = "present" if branch in content else "absent"
            except Exception:
                evidence["ci_trigger"] = "absent"
        else:
            evidence["ci_trigger"] = "absent"
    else:
        evidence["ci_trigger"] = "absent"

    # build_exists
    if worktree:
        build_file = Path(worktree) / "cpp" / "build" / "CTestTestfile.cmake"
        evidence["build_exists"] = build_file.exists()
    else:
        evidence["build_exists"] = False

    # l4_marker (cross-review marker)
    evidence["l4_marker"] = False  # Would need git log analysis

    # git_workflow_marker
    evidence["git_workflow_marker"] = False  # Would need git log analysis

    # 2026-09-02: hook 工具越权/提权绕过证据（防线② 行为偏离 → api 评审硬证据）
    # state gate_data.hook_block_log 快照（TTL 窗口）：escalation>0 → PRM 应判 FAIL/审计
    hook_ev = {"hook_blocks": 0, "hook_escalations": 0, "hook_chains": []}
    try:
        import sys as _sys
        from pathlib import Path as _P
        _sys.path.insert(0, str(_P(__file__).resolve().parent))
        import pre_tool_hook as _h
        hook_ev = _h._block_log_snapshot(state_path)
    except Exception:
        pass
    evidence["hook_blocks"] = hook_ev.get("blocks", 0)
    evidence["hook_escalations"] = hook_ev.get("escalations", 0)
    evidence["hook_chains"] = hook_ev.get("chains", [])

    return evidence


def _inject_gitnexus(state_path: str, worktree: str, stage: str) -> str:
    """Inject GitNexus context (from gatekeeper-cli.sh L1498-1552)."""
    parts = []

    # Layer 1: GitNexus baseline from state
    state = _read_state(state_path)
    gn = state.get("gate_data", {}).get("gitnexus", {})
    nodes = gn.get("nodes", "")
    if nodes and nodes != "unavailable":
        parts.append(f"GITNEXUS BASELINE: {json.dumps({k: gn.get(k) for k in ['nodes', 'edges', 'clusters', 'flows', 'stage', 'timestamp']})}")

    # Layer 2: GitNexus context for modified files
    if worktree and Path(worktree).exists():
        try:
            result = subprocess.run(
                ["git", "-C", worktree, "diff", "--name-only", "HEAD~1..HEAD"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                files = result.stdout.strip().split("\n")[:3]
                for f in files:
                    if not f:
                        continue
                    sym = Path(f).stem
                    # Call gitnexus context via powershell (R5.8 SA2: --repo required)
                    try:
                        ctx_result = subprocess.run(
                            ["powershell.exe", "-Command", f"gitnexus context --repo spz_gatekeeper {sym}"],
                            capture_output=True, text=True, timeout=30
                        )
                        if ctx_result.returncode == 0:
                            ctx = json.loads(ctx_result.stdout)
                            callers = ctx.get("incoming", {})
                            callees = ctx.get("outgoing", {})
                            parts.append(f"GITNEXUS CONTEXT: {sym}: calls={len(callees)} called_by={len(callers)}")
                    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
                        pass
        except (subprocess.TimeoutExpired, Exception):
            pass

    # Layer 3: GitNexus impact for STAGE_3/4
    if stage in ("STAGE_3", "STAGE_4") and worktree and Path(worktree).exists():
        try:
            result = subprocess.run(
                ["git", "-C", worktree, "diff", "--name-only", "HEAD~1..HEAD"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                files = result.stdout.strip().split("\n")[:5]
                impacts = []
                for f in files:
                    if not f:
                        continue
                    sym = Path(f).stem
                    try:
                        impact_result = subprocess.run(
                            ["powershell.exe", "-Command", f"gitnexus impact --repo spz_gatekeeper {sym}"],
                            capture_output=True, text=True, timeout=30
                        )
                        if impact_result.returncode == 0:
                            d = json.loads(impact_result.stdout)
                            target = d.get("target", {}).get("name", "")
                            count = d.get("impactedCount", 0)
                            risk = d.get("risk", "")
                            impacts.append(f"{target} impact={count} risk={risk}")
                    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
                        pass
                if impacts:
                    parts.append(f"GITNEXUS IMPACT: {'; '.join(impacts)}")
        except (subprocess.TimeoutExpired, Exception):
            pass

    return "\n\n".join(parts) if parts else ""


def monitor_api(
    stage: str,
    api_key: str,
    provider: str = "deepseek",
    worktree: str = "",
    branch: str = "",
    state_path: str = DEFAULT_STATE_FILE,
) -> dict:
    """Execute monitor API call with failover chain and retry."""
    if not api_key:
        return {"error": "--api-key required. Set GATEKEEPER_API_KEY env var", "ok": False}

    # Read state
    state = _read_state(state_path)
    if "error" in state:
        return {"error": state["error"], "ok": False}

    # Read schema
    schema_file = SCHEMA_DIR / f"{stage}.json"
    schema = ""
    if schema_file.exists():
        schema = schema_file.read_text(encoding="utf-8")

    # Collect hard evidence
    evidence = _collect_hard_evidence(stage, worktree, branch, state_path)

    # Build system prompt (exact copy from L1494)
    system_prompt = """You are a Process Reward Model (PRM) for the SPZ Gatekeeper R-sequence pipeline. Given a GATE SCHEMA and EXECUTION STATE + HARD EVIDENCE, score how well the agent satisfied each requirement. Output ONLY JSON: {"overall_score":0.0-1.0,"checks":[{"item":"...","status":"PASS|FAIL|UNCERTAIN|CONTRADICTION","score":0.0-1.0,"evidence":"file:line_range"}],"violations":["..."],"contradictions":["state says X but evidence shows Y — mark CONTRADICTION"],"next_action":"...","reasoning":"..."}. Rules: PASS=1.0, FAIL=0.0, UNCERTAIN=0.5, CONTRADICTION=0.0. CONTRADICTION means the state file (written by agent) claims something that hard evidence disproves. Example: state says ctest passed but evidence shows build_exists=false. Mark CONTRADICTION, not FAIL. CRITICAL: commits_ahead_of_main=0 → no new code, FAIL compile+commit requirements. ci_trigger=absent → FAIL CI. build_exists=false → FAIL compile. l4_marker=false → FAIL cross-review. spec_urls_valid=false → FAIL spec_url (file doesn't exist in Niantic reference). git_workflow_marker=false → WARN (push via git-workflow required). Evidence is ground truth. State file may lie — trust evidence. RELOCATION: Every evidence field MUST be 'file:line_range' format (e.g. 'gatekeeper-cli.sh:647-748'). Never output just a filename without line numbers."""

    # Build user prompt (from L1496)
    user_prompt = f"GATE SCHEMA: {schema}\n\nSTATE FILE: {json.dumps(state)}\n\nHARD EVIDENCE: {json.dumps(evidence)}\n\n"

    # GitNexus injection (from L1498-1552)
    gn_context = _inject_gitnexus(state_path, worktree, stage)
    if gn_context:
        user_prompt += f"{gn_context}\n\n"

    user_prompt += "Score this gate. Output only JSON."

    # ── H1a（2026-09-28）：降级链 = 断路器 + 双超时 + 白名单 + 禁重定向 + 体量上限 ─────────
    last_error = None
    # 2026-09-28（G5 同族·单侧硬缺陷修复，与 master `dffb6d0` 同语义）：**熔断须停整条链**。
    #   原实现把 `break` 落在**内层** `for retry` 体内 ⟹ 只退重试循环，外层 `for fb` 仍换下一个
    #   provider —— 与它自己的注释「don't try next provider」以及 bash 侧（`break` 在**外层**
    #   failover 循环体内，实测 gatekeeper-cli.sh `_monitor_api` 的
    #   `if [ $retry -ge 2 ] && ! _is_retryable "$resp" ]` 之后）**行为不一致** ⟹ 双源语义漂移。
    #   修法：显式 `stop_chain` 标志，命中不可重试错误即退**外层**（与 bash 同语义）。
    stop_chain = False
    for fb in FAILOVER_CHAIN:
        if stop_chain:
            break
        if fb not in PROVIDERS:
            if fb == "local":
                # LOCAL PROVIDER (占位): 无本地模型时不可用，直通fallthrough到error
                continue
            continue
        # 断路器：open 且未过 TTL ⟹ **零网络**跳过（ms 级切换的关键；原实现无此面）
        _ok, _why = _breaker_allows(state_path, fb)
        if not _ok:
            last_error = f"skip {fb}: {_why}"
            continue
        config = PROVIDERS[fb]
        # 安全：base URL 必须落在 PROVIDERS 单源白名单（防域名投毒 / SSRF）
        try:
            _ensure_allowed_base(config)
        except ValueError as _e:
            last_error = _redact(str(_e), api_key)
            continue

        # Retry up to 2 times per provider (Bridge MODEL_RETRY.max_retries=2)
        for retry in range(2):
            try:
                payload = {
                    "model": config["model"],
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.0,
                    "max_tokens": 2000,
                }

                # Add reasoning_effort for DeepSeek
                if fb == "deepseek":
                    payload["reasoning_effort"] = config["reasoning_effort"]

                # Add response_format for MiMo
                if fb == "mimo":
                    payload["response_format"] = {"type": "json_object"}

                resp = requests.post(
                    f"{config['base']}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    # H1a：连接/读**双超时**（连接短 ⟹ 死域快速失败）；禁重定向（防劫持到白名单外域）
                    timeout=(FAILOVER_CONNECT_TIMEOUT, FAILOVER_READ_TIMEOUT),
                    allow_redirects=False,
                )
                # H1a 安全：响应体上限（防超大响应 DoS）
                _blen = len(resp.content or b"")
                if _blen > FAILOVER_MAX_RESP_BYTES:
                    _breaker_record_fail(state_path, fb)
                    last_error = f"{fb}: response too large ({_blen}B > {FAILOVER_MAX_RESP_BYTES}B)"
                    break
                resp.raise_for_status()
                result = resp.json()
                content = result.get("choices", [{}])[0].get("message", {}).get("content", "")

                if content:
                    # Parse response
                    try:
                        parsed = json.loads(content)
                        # A7（2026-09-06 ㉔，cmd_appeal/gk_appeal 同款守卫）：裁判输出缺 overall_score
                        # （坏 JSON/schema 漂移）不得按哨兵 -1 判 BLOCKED 落盘 → 该 provider 响应无效，
                        # 走失败链 continue（未落记录，防 A7 假否决相邻族复发）。
                        if "overall_score" not in parsed or not isinstance(
                                parsed.get("overall_score"), (int, float)):
                            last_error = f"invalid response from {fb}: missing overall_score"
                            continue
                        # H1a：本跳产出有效裁判 ⟹ 清除断路器计数（恢复健康）
                        _breaker_record_ok(state_path, fb)
                        score = parsed.get("overall_score", -1)

                        # Normalize score (MiMo 0-100 → 0-1)
                        if score > 1:
                            score = round(score / 100, 2)
                        else:
                            score = round(score, 2)

                        violations = parsed.get("violations", [])
                        next_action = parsed.get("next_action", "")
                        reasoning = parsed.get("reasoning", "")
                        checks = parsed.get("checks", [])

                        verdict = "PASS" if score > 0.5 else "BLOCKED"

                        # Write full output to temp file (agent-invisible)
                        monitor_out = Path(state_path).parent / ".gatekeeper_monitor_api_tmp.json"
                        full_output = {
                            **parsed,
                            "_meta": {
                                "stage": stage,
                                "provider": fb,
                                "model": config["model"],
                                "score": score,
                                "verdict": verdict,
                                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            }
                        }
                        with open(monitor_out, "w", encoding="utf-8") as f:
                            json.dump(full_output, f, indent=2, ensure_ascii=False)

                        # Write monitor_scores to state (bash L1629)
                        # 2026-09-25（ECC-567E8C847F16 / 选项 A）：改**锁内重放**（`update_state`）
                        # —— 原「read → 改 → write」非原子；本增量只写本 stage 的判读结果，
                        # 与读到的 state 内容无关 ⟹ 可安全原子重放（保序：写前取锁）。
                        def _ms_mut(d):
                            ms = d.setdefault("gate_data", {}).setdefault("monitor_scores", {})
                            ms[stage] = {
                                "score": score,
                                "verdict": verdict,
                                "provider": fb,
                                "model": config["model"],
                                "reasoning": reasoning,
                                "next_action": next_action,
                                "checks": checks,
                            }
                            d["monitor_scores"] = ms
                            return d
                        update_state(state_path, _ms_mut)

                        return {
                            "ok": True,
                            "score": score,
                            "verdict": verdict,
                            "violations": violations,
                            "next_action": next_action,
                            "reasoning": reasoning,
                            "provider": fb,
                            "model": config["model"],
                            "mode": "--api",
                            "stage": stage,
                            "_full_dump": parsed,
                        }

                    except json.JSONDecodeError:
                        last_error = "invalid JSON response from LLM"
                        continue

            except (requests.exceptions.ConnectTimeout,
                    requests.exceptions.ConnectionError) as e:
                # H1a：**连接类**失败（域名失效 / DNS 死 / 拒连）⟹ 记失败 + **立即降级**。
                # 原实现会在此白等 `timeout=60` × 2 次重试 ⟹ 一次降级 ~2 分钟，非 ms 级。
                _breaker_record_fail(state_path, fb)
                last_error = _redact(f"connect failed on {fb}: {e}", api_key)
                break
            except requests.exceptions.Timeout as e:
                # H1a：已连上但读超时 ⟹ 记失败并降级（同跳重试只会让延迟翻倍）
                _breaker_record_fail(state_path, fb)
                last_error = _redact(f"read timeout on {fb}: {e}", api_key)
                break
            except requests.exceptions.RequestException as e:
                # H1a：错误串脱敏（原实现直出 str(e)，可能带凭据）
                status_code = getattr(getattr(e, "response", None), "status_code", 0)
                _breaker_record_fail(state_path, fb)
                last_error = _redact(f"API error on {fb}: {e}", api_key)
                # 不可重试错误（如 4xx）→ **停整条降级链**（与 bash `_monitor_api` 同语义：
                #   `break  # non-retryable` 位于**外层** provider 循环体内）⟹ 不换下一个 provider。
                if not _is_retryable(status_code):
                    stop_chain = True
                    break
                continue

    return {"error": f"all providers failed: {last_error}", "ok": False}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Gatekeeper Monitor API")
    parser.add_argument("--stage", required=True, help="Stage name")
    parser.add_argument("--api-key", required=True, help="API key")
    parser.add_argument("--provider", default="deepseek", help="Provider (deepseek|mimo)")
    parser.add_argument("--worktree", default="", help="Worktree path")
    parser.add_argument("--branch", default="", help="Branch name")
    parser.add_argument("--path", default=DEFAULT_STATE_FILE, help="State file path")

    args = parser.parse_args()

    result = monitor_api(
        stage=args.stage,
        api_key=args.api_key,
        provider=args.provider,
        worktree=args.worktree,
        branch=args.branch,
        state_path=args.path,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if result.get("ok", False) else 1)


if __name__ == "__main__":
    main()
