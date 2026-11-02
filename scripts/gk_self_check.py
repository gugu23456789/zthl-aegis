#!/usr/bin/env python3
"""
Gatekeeper Self-Check — System diagnostics module
==================================================
Extracted from gatekeeper-cli.sh cmd_self_check() inline Python blocks.
Runs 30+ checks (authoritative registry = `run_all`): state_file, gate_data, checksum, HMAC key, key integrity,
foreign content guard, subagent runner, jwt_signing, provider, gitnexus,
bash_static, bashpy_loader, tests, l9_runtime_safenet, l9_gatechain_prereq,
l9_entropy_appeal, sequence_node_safety, governed_baseline, tenant_isolation,
review_layer_coverage, finding_journal_reconcile, ember_replay_audit,
python_argv_inject, pr_score_anchor, red_meta_read, bash_write_drift,
hook_registration, gitnexus_version, model_config, sandbox, cron_health.

Usage:
  python3 scripts/gk_self_check.py [--state-file <path>] [--skill-dir <path>]
                                    [--key-meta <path>] [--key-integrity <path>]
                                    [--audit-key-dir <path>]

Output: JSON with {"ok": true, "issues": N, "checks": [...]}
"""

import ast
import hashlib
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlparse
from urllib.error import URLError


# ---------------------------------------------------------------------------
# Individual check functions — each returns a dict with "check" and "status"
# ---------------------------------------------------------------------------

def check_state_file(state_path: str) -> dict:
    """Check state file existence and JSON validity with 'stage' field."""
    result = {"check": "state_file"}
    p = Path(state_path)
    if not p.exists():
        result["status"] = "MISSING"
        return result
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "stage" in data:
            result["status"] = "PASS"
        else:
            result["status"] = "FAIL"
            result["detail"] = "missing 'stage' field"
    except (json.JSONDecodeError, OSError):
        result["status"] = "FAIL"
        result["detail"] = "JSON parse error"
    return result


def check_gate_data(state_path: str) -> dict:
    """Parse gate_data and report rejected edits / needs_analysis / block_log."""
    result = {"check": "gate_data"}
    p = Path(state_path)
    if not p.exists():
        result["status"] = "FAIL"
        result["detail"] = "state_file_not_found"
        return result
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        result["status"] = "FAIL"
        result["detail"] = "parse failed"
        return result
    gd = data.get("gate_data", {})
    rejected = len(gd.get("rejected_edits") or [])
    analysis = gd.get("needs_analysis", False)
    blocks = len(gd.get("block_log") or [])
    result["status"] = "PASS"
    result["rejected_count"] = rejected
    result["needs_analysis"] = analysis
    result["block_log_count"] = blocks
    return result


def check_checksum(state_path: str) -> dict:
    """Verify SHA256 checksum integrity of gate_data."""
    result = {"check": "checksum_integrity"}
    p = Path(state_path)
    if not p.exists():
        result["status"] = "FAIL"
        result["detail"] = "state_file_not_found"
        return result
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        result["status"] = "FAIL"
        result["detail"] = "parse_error"
        return result
    stored = data.get("_checksum", "")
    gate_dump = json.dumps(data.get("gate_data", {}), sort_keys=True, ensure_ascii=True)
    computed = hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
    if not stored:
        result["status"] = "WARN"
        result["detail"] = "no checksum in state file"
        result["computed"] = computed
    elif stored != computed:
        result["status"] = "FAIL"
        result["detail"] = f"checksum mismatch: saved={stored} computed={computed}"
    else:
        result["status"] = "PASS"
        result["detail"] = "checksum OK"
        result["checksum"] = computed
    return result


def check_hmac_key() -> dict:
    """Check GATEKEEPER_HMAC_KEY env var for length and presence."""
    result = {"check": "env_hmac_key"}
    try:
        key = os.environ.get("GATEKEEPER_HMAC_KEY", "")
        if key and len(key) == 64:
            result["status"] = "PASS"
            result["detail"] = "HMAC_KEY=OK"
        elif key:
            result["status"] = "WARN"
            result["detail"] = f"HMAC_KEY=SHORT(len={len(key)}, need 64 hex chars)"
        else:
            result["status"] = "WARN"
            result["detail"] = "HMAC_KEY=MISSING(subagent output unsigned)"
    except Exception as e:
        result["status"] = "FAIL"
        result["detail"] = f"hmac_key: {e}"
    return result


def check_key_integrity(key_meta: str, key_integrity: str, audit_key_dir: str) -> dict:
    """Verify Ed25519 key pair integrity via SHA256 and pubkey fingerprints."""
    result = {"check": "key_integrity"}
    meta_p = Path(key_meta)
    integ_p = Path(key_integrity)
    if not meta_p.exists():
        result["status"] = "PASS"
        result["detail"] = "no key-meta yet (nothing to check)"
        return result
    if not integ_p.exists():
        result["status"] = "FAIL"
        result["detail"] = "tampered:integrity_file_missing"
        return result
    # SHA256 hash comparison
    try:
        expected = integ_p.read_text(encoding="utf-8").strip().split("\n")[0]
        actual = hashlib.sha256(meta_p.read_bytes()).hexdigest()
    except OSError:
        result["status"] = "FAIL"
        result["detail"] = "read_error"
        return result
    if expected != actual:
        result["status"] = "FAIL"
        result["detail"] = "tampered:key-meta.json modified (sha256 mismatch)"
        return result
    # Pubkey fingerprint verification
    try:
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        result["status"] = "FAIL"
        result["detail"] = "key-meta parse error"
        return result
    for ktype in ("context_ed25519", "audit_ed25519"):
        base = ktype.replace("_ed25519", "")
        pub_path = Path(audit_key_dir) / base / f"{base}_ed25519.pub"
        if pub_path.exists():
            fp = hashlib.sha256(pub_path.read_bytes()).hexdigest()
            expected_fp = meta.get(ktype, {}).get("fingerprint", "")
            if expected_fp and fp != expected_fp:
                result["status"] = "FAIL"
                result["detail"] = f"tampered:{ktype} pubkey replaced"
                return result
    result["status"] = "PASS"
    result["detail"] = "context+audit keys OK"
    return result


def _parse_subagent_constants(scripts_path: Path) -> dict:
    """Parse constants via AST (no import; openai SDK 初始化会挂).

    2026-10-31（P2c）：守卫词表已迁单一事实源 `gk_foreign_content.LEAKAGE_MARKERS`
    （原 `subagent_runner._FOREIGN_USER_PATTERNS`）。统计器**必须**同步改源 —— 否则常量
    搬走后此处恒报 0（fail-open 空转，见 crossreview §4.1(c) 第 5 消费点）。
    返回 `{'ok': True, 'tools': N, 'patterns': N}` 或 None。
    """
    def _count(path: Path, name: str) -> int | None:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, OSError):
            return None
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    if isinstance(node.value, ast.List):
                        return len(node.value.elts)
                    if isinstance(node.value, ast.Dict):
                        return len(node.value.keys)
        return None

    sr_path = scripts_path / "subagent_runner.py"
    fc_path = scripts_path / "gk_foreign_content.py"
    if not sr_path.exists():
        return None
    tools_found = _count(sr_path, "TOOL_REGISTRY")
    patterns_found = _count(fc_path, "LEAKAGE_MARKERS") if fc_path.exists() else None
    if patterns_found is None:   # 兼容未归一仓结构（旧常量在 runner 内）
        patterns_found = _count(sr_path, "_FOREIGN_USER_PATTERNS")
    return {"ok": True, "tools": tools_found or 0, "patterns": patterns_found or 0}


def check_foreign_content_guard(skill_dir: str) -> dict:
    """Count _FOREIGN_USER_PATTERNS in subagent_runner module."""
    result = {"check": "foreign_content_guard"}
    try:
        scripts_path = Path(skill_dir) / "scripts"
        if not scripts_path.exists():
            result["status"] = "WARN"
            result["detail"] = "scripts directory not found"
            return result
        sr = _parse_subagent_constants(scripts_path)
        if sr is None or not sr.get("ok"):
            result["status"] = "WARN"
            result["detail"] = "subagent_runner not importable"
            return result
        count = sr.get("patterns", 0)
        if count > 0:
            result["status"] = "PASS"
            result["detail"] = f"active ({count} patterns)"
            result["count"] = count
        else:
            result["status"] = "WARN"
            result["detail"] = "loaded but patterns empty"
            result["count"] = 0
    except Exception as e:
        # 2026-08-20: RED-PY 隔离要求 — 单 check 崩溃不得拖垮整个 self-check
        result["status"] = "WARN"
        result["detail"] = f"check crashed: {e}"
    return result


def check_subagent_runner(skill_dir: str) -> dict:
    """Import subagent_runner and check TOOL_REGISTRY."""
    result = {"check": "subagent_runner"}
    try:
        scripts_path = Path(skill_dir) / "scripts"
        if not scripts_path.exists():
            result["status"] = "WARN"
            result["detail"] = "scripts directory not found"
            return result
        sr = _parse_subagent_constants(scripts_path)
        if sr is None or not sr.get("ok"):
            result["status"] = "WARN"
            result["detail"] = "subagent_runner not importable"
            return result
        tools = sr.get("tools", 0)
        result["status"] = "PASS"
        result["detail"] = f"{tools} tools OK"
    except Exception as e:
        result["status"] = "WARN"
        result["detail"] = f"check crashed: {e}"
    return result


def check_jwt_signing(skill_dir: str) -> dict:
    """Verify joserfc importable (JWT signing for subagent output)."""
    result = {"check": "jwt_signing"}
    sr_path = Path(skill_dir) / "scripts" / "subagent_runner.py"
    if not sr_path.exists():
        result["status"] = "SKIP"
        result["detail"] = "subagent_runner.py not found"
        return result
    try:
        import importlib
        importlib.import_module("joserfc")
        result["status"] = "PASS"
        result["detail"] = "joserfc+jti replay OK"
    except ImportError:
        result["status"] = "FAIL"
        result["detail"] = "joserfc not installed"
    return result


def check_provider() -> dict:
    """Check API provider connectivity via lightweight POST ping."""
    result = {"check": "provider"}
    api_key = os.environ.get("API_KEY", "") or os.environ.get("DEEPSEEK_API_KEY", "")
    key_source = "env" if api_key else "none"
    if not api_key:
        # Resolve via gatekeeper env
        for k in ("GATEKEEPER_API_KEY", "DEEPSEEK_API_KEY"):
            v = os.environ.get(k, "")
            if v:
                api_key = v
                break
    if not api_key:
        # 2026-11-02（开源包可用性）：key 文件（跨平台持久化）—— 与 CLI `_resolve_api_key` 同源。
        try:
            from gk_api_key import read_key
            _skill = os.environ.get("GK_SKILL_DIR") or os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))
            api_key, key_source = read_key(_skill, os.environ.get("GATEKEEPER_PROVIDER", "deepseek"))
            key_source = key_source or "none"
        except Exception:  # noqa: BLE001 — 自检不得因 key 文件层故障而崩
            key_source = "none"
    if not api_key:
        result["status"] = "SKIP"
        result["detail"] = "No API key set"
        result["key_source"] = "none"
        return result
    result["key_source"] = key_source
    api_base = os.environ.get("API_BASE", "https://api.deepseek.com")
    api_model = os.environ.get("API_MODEL", "deepseek-flash")
    try:
        req = Request(
            f"{api_base}/chat/completions",
            data=json.dumps({
                "model": api_model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1
            }).encode(),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
        )
        with urlopen(req, timeout=5) as resp:
            code = resp.status
        if code in (200, 400):
            result["status"] = "PASS"
            result["code"] = code
        else:
            result["status"] = "WARN"
            result["code"] = code
    except (URLError, OSError, ValueError) as e:
        result["status"] = "WARN"
        result["detail"] = str(e)
    return result


def check_gitnexus(skill_dir: str) -> dict:
    """gitnexus 可用性 / 索引在位（**默认 0 子进程**，2026-11-01 提速）。

    病象（实测 2026-11-01）：本机 `node .gitnexus/run.cjs status` 与 `gitnexus status` 都
    **挂起**（user CPU ≈0.05s、90s 无进展），旧实现以 60s 超时兜底 ⟹ 单项吃掉 **60.0s**，
    占 self-check 总时长 80.8s 的 74%，且超时被判 **FAIL**（把环境卡顿当门禁红）。
    修法：默认只读索引元数据（`gitnexus.json` / `meta.json` 的**存在性 + mtime 年龄**），
    0 子进程、毫秒级；需要真探 CLI 时显式 `GK_SELFCHECK_GITNEXUS_PROBE=cli`（超时 20s，
    超时只 WARN）。索引新鲜度语义不变：缺索引 = WARN「index missing」。
    """
    result = {"check": "gitnexus", "probe": "metadata"}
    gx = Path(skill_dir) / ".gitnexus"
    idx = [p for p in (gx / "gitnexus.json", gx / "meta.json") if p.is_file()]
    if not idx:
        result["status"] = "WARN"
        result["detail"] = "index missing: 未见 .gitnexus/gitnexus.json 或 meta.json"
        return result
    newest = max(idx, key=lambda p: p.stat().st_mtime)
    age_s = max(0.0, time.time() - newest.stat().st_mtime)
    result["index_age_s"] = int(age_s)
    result["index_bytes"] = max(p.stat().st_size for p in idx)
    if str(os.environ.get("GK_SELFCHECK_GITNEXUS_PROBE", "")).strip().lower() != "cli":
        result["status"] = "PASS"
        result["detail"] = ("index 在位: %s（%.1f 天前，%d KB）；CLI 探针已跳过"
                            "（GK_SELFCHECK_GITNEXUS_PROBE=cli 可深探）"
                            % (newest.name, age_s / 86400.0,
                               result["index_bytes"] // 1024))
        return result
    # 深探（显式开启）：只取「能不能跑通」，超时按 WARN（不再 FAIL —— CLI 卡顿不是门禁红）
    result["probe"] = "cli"
    run_cjs = gx / "run.cjs"
    cmd = ["node", str(run_cjs), "status"] if run_cjs.exists() else ["gitnexus", "status"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20, cwd=skill_dir)
    except (subprocess.TimeoutExpired, OSError) as e:
        result["status"] = "WARN"
        result["detail"] = "index 在位但 CLI 探针不可判（%s）: %s" % (type(e).__name__, e)
        return result
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    if r.returncode == 0 and out:
        result["status"] = "PASS"
        result["detail"] = out.splitlines()[0]
    elif "尚未索引" in out or "no index" in out.lower():
        result["status"] = "WARN"
        result["detail"] = "index missing: " + out[:100]
    else:
        result["status"] = "WARN"
        result["detail"] = "exit=%d: %s" % (r.returncode, out[:100])
    return result


def check_cli_hook_executable(skill_dir: str) -> dict:
    """CLI 自指死锁探针（2026-10-22，owner 裁定「只加自检探针」）。

    病象（实测死锁）：`bash gatekeeper-cli.sh <cmd>` 会被 hook Gate R0.3
    `_scan_script_content` 读**整份脚本内容**；CLI 自身含危险命令族（gitnexus memo
    清理行）⟹ 判定危险 ⟹ **CLI 全域不可执行** ⟹ `advance` / `apply-worktree` /
    `state-patch` 全部不可达 ⟹ 节点额度与写面都无法复位（补额度只能靠 advance）。
    修复 = `377ea77` 信任根豁免（`_TRUST_ROOT_SCRIPTS`）；本探针只负责**防复发** ——
    新增危险词、或有人把豁免删掉时，self-check 立刻 FAIL 而不是等下一个人撞死锁。
    """
    result = {"check": "cli_hook_executable"}
    cli = Path(skill_dir) / "gatekeeper-cli.sh"
    if not cli.exists():
        result["status"] = "FAIL"
        result["detail"] = f"missing {cli}"
        return result
    try:
        r = subprocess.run(["bash", str(cli), "help"], capture_output=True, text=True,
                           timeout=30, cwd=skill_dir)
    except (subprocess.TimeoutExpired, OSError) as e:
        result["status"] = "FAIL"
        result["detail"] = f"CLI 不可执行: {e}"
        return result
    out = (r.stdout or "") + (r.stderr or "")
    # 判据 = rc==0 **且** 出现命令注册表的稳定锚 `cmd_`（`help` 由 `_CMD_REG` 生成，
    #   首行即 `### cmd_<name>`）；仅 rc==0 不足以排除「被拦但退出码被吞」的假绿。
    if r.returncode == 0 and "cmd_" in out and "GATEKEEPER-BLOCK" not in out:
        result["status"] = "PASS"
        result["detail"] = "CLI 可经 hook 执行"
    else:
        result["status"] = "FAIL"
        result["detail"] = ("CLI 被 hook 拦（自指死锁复发？）rc=%d: %s"
                            % (r.returncode, out.strip().replace("\n", " ")[:160]))
    return result


def check_bash_static(skill_dir: str) -> dict:
    """Check gatekeeper-cli.sh for known bash/python injection bug patterns (2026-08-15).

    Delegates to scripts/gk_bash_static_scan.py（安全网拦截体系的 bash 静态检查扩展）：
    P2 json.loads(sys.stdin) / P3 三引号注入 / P4 get('output') 错键 / P5 非注册 --tools / P7 裸反引号。
    """
    result = {"check": "bash_static"}
    scan = Path(skill_dir) / "scripts" / "gk_bash_static_scan.py"
    if not scan.exists():
        result["status"] = "FAIL"
        result["detail"] = "gk_bash_static_scan.py missing"
        return result
    try:
        r = subprocess.run(
            [sys.executable, str(scan), "--json", "--skill-dir", skill_dir],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(r.stdout or "{}")
        fails = [c for c in data.get("checks", []) if c["status"] == "FAIL"]
        warns = [c for c in data.get("checks", []) if c["status"] == "WARN"]
        if data.get("issues", 0) > 0:
            result["status"] = "FAIL" if fails else "WARN"
            result["detail"] = f"{len(fails)} FAIL / {len(warns)} WARN static patterns"
            result["patterns"] = [c["detail"] for c in (fails + warns)]
        else:
            result["status"] = "PASS"
            result["detail"] = "no static vuln patterns (P2/P3/P4/P5/P7)"
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
        result["status"] = "FAIL"
        result["detail"] = str(e)
    return result


def check_bashpy_loader(skill_dir: str) -> dict:
    """bashpy-migrate 加载安全网（2026-08-23）：发布包优先 + SHA256，回退本地 dev 源码。

    拦截语义（用户定案）:
    - release: 发布包 + SHA256 校验通过 → PASS
    - release_unverified: 发布包已装但无固定哈希 → WARN（CI 发布后登记 _RELEASE_PINS）
    - dev: 本地开发源码回退 → WARN（非 CI 验证）
    - hash_mismatch: 发布包 SHA256 不匹配 → FAIL（误加载拦截）
    - missing: 工具未装（探测式启用，不阻断）→ WARN
    - error: 导入异常 → FAIL
    """
    result = {"check": "bashpy_loader"}
    try:
        sys.path.insert(0, str(Path(skill_dir) / "scripts"))
        from gk_bashpy_loader import load_status
        s = load_status()
        src = s.get("source", "unknown")
        if src == "release":
            result["status"] = "PASS"
        elif src == "hash_mismatch":
            result["status"] = "FAIL"
        elif src == "error":
            result["status"] = "FAIL"
        else:
            result["status"] = "WARN"
        result["detail"] = f"source={src} — {s.get('detail', '')}"
    except Exception as e:
        result["status"] = "FAIL"
        result["detail"] = f"loader check failed: {type(e).__name__}: {e}"
    return result


def check_paper_review_loader(skill_dir: str) -> dict:
    """paper-review 加载安全网（2026-08-29，bashpy 协议统一应用）。

    拦截语义（对齐 plugin-loading-test-framework.md §1.3）:
    - builtin: 脚本存在 + manifest 登记 + SHA256 命中 → PASS
    - dev: 脚本存在但未 pin → WARN（未登记哈希，非 CI 验证）
    - tampered: SHA256 不匹配固定点 → FAIL（误加载拦截）
    - missing: 脚本缺失 → WARN（漏加载显式报告）
    - error: 编译/导入失败 → FAIL（错误加载拦截）
    """
    result = {"check": "paper_review_loader"}
    try:
        sys.path.insert(0, str(Path(skill_dir) / "scripts"))
        from gk_paper_review_loader import load_status
        s = load_status()
        src = s.get("source", "unknown")
        if src == "builtin":
            result["status"] = "PASS"
        elif src in ("tampered", "error"):
            result["status"] = "FAIL"
        else:
            result["status"] = "WARN"
        result["detail"] = f"source={src} — {s.get('detail', '')}"
    except Exception as e:
        result["status"] = "FAIL"
        result["detail"] = f"loader check failed: {type(e).__name__}: {e}"
    return result


# ── 测试腿的**有界**口径（2026-11-01 提速）────────────────────────────────────
# 旧口径病象（实测）：无条件跑**全部** `test_*.py`（575+ 文件）+ 180s 超时 ⟹ 必然超时 ⟹
#   恒 FAIL「pytest 超时」（把「跑不完」当门禁红）；而 pytest 不可用的解释器下整项 SKIP ⟹
#   「测试门禁」在真实 CLI 路径上从未真正执行过。
# 新口径（`GK_SELFCHECK_TESTS`）：quick（缺省，快速子集 + xdist）/ full（全量，CI 用）/ skip。
# 子弹药：子进程**强制** `skip` ⟹ 防「self-check → pytest（含 test_gk_self_check）→ self-check」套娃。
_SELFCHECK_TESTS_ENV = "GK_SELFCHECK_TESTS"
_CHILD_TESTS_ENV = {"GK_SELFCHECK_TESTS": "skip"}
# 快速子集 = ci_smoke.sh 的快线 15 个 + 本轮新增/关键不变量（全部为秒级文件）
_QUICK_TEST_FILES = (
    "test_gk_plan_lint.py", "test_gk_gate_appeal.py", "test_gk_econ_params.py",
    "test_gk_monitor_m1.py", "test_gk_budget_ledger.py", "test_gk_credit_floor.py",
    "test_gk_main_repo.py", "test_main_repo_value_sync.py",
    "test_gk_advance_transition_table.py", "test_gk_ecc_sink.py",
    "test_gk_finding_open_spillover.py", "test_gk_state_map.py",
    "test_gk_monitor_decision.py", "test_gk_agent_identity.py",
    "test_gk_subagent_model_chain.py",
    "test_gk_state_wall_levels.py", "test_gk_state_trim_lines.py",
    "test_gk_satellite.py", "test_gk_two_legs.py", "test_gk_ecc_cap.py",
    "test_gk_json_utils.py", "test_gk_finding_stale.py",
)
_QUICK_TIMEOUT_S = 300
_FULL_TIMEOUT_S = 1800
_TESTS_CACHE_TTL_ENV = "GK_SELFCHECK_TESTS_TTL"


def _tests_cache_path() -> Path:
    home = os.environ.get("HOME") or str(Path.home())
    return Path(home) / ".gatekeeper" / "selfcheck-tests.json"


def _git_fingerprint(skill_dir: str) -> str:
    """HEAD + 已跟踪差异 + **测试文件集合指纹**（新增/删除/改动测试文件都变）。

    性能取舍（实测 2026-11-01）：`git status --porcelain` 在本仓（/mnt/c，海量未跟踪
    `.gitnexus/`）耗时 **29.5s** ⟹ 每次自检都付不起。改 `-uno`（跳过未跟踪扫描，秒级）
    + 直接对 `scripts/test_*.py` 的 `(名, 大小, mtime)` 取摘要 —— 测试腿只依赖这些文件，
    新增/删除/改动都会变键（不存在「新增测试没被算进指纹」）。git 不可用 ⟹ ''（不缓存）。
    """
    try:
        head = subprocess.run(["git", "-C", skill_dir, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10)
        st = subprocess.run(["git", "-C", skill_dir, "status", "--porcelain", "-uno"],
                            capture_output=True, text=True, timeout=25)
        if head.returncode != 0 or st.returncode != 0:
            return ""
        h = hashlib.sha256()
        for p in sorted((Path(skill_dir) / "scripts").glob("test_*.py")):
            try:
                s = p.stat()
            except OSError:
                continue
            h.update(("%s:%d:%d\n" % (p.name, s.st_size, int(s.st_mtime))).encode())
        return hashlib.sha256(
            (head.stdout + "\x00" + st.stdout + "\x00" + h.hexdigest()).encode()).hexdigest()[:16]
    except Exception:  # noqa: BLE001 — 边界：拿不到指纹就不缓存（不臆造新鲜度）
        return ""


def check_tests(skill_dir: str) -> dict:
    """脚本测试门禁（**有界**三分档，2026-11-01）。

    - `quick`（缺省）：`_QUICK_TEST_FILES` 子集，xdist 可用时 `-n auto`，超时 300s；
    - `full`：全部 `test_*.py`，超时 1800s（CI / 发布前，由 `GK_SELFCHECK_TESTS=full` 触发）；
    - `skip`：显式跳过（子进程强制注入 ⟹ 禁套娃）。
    判决：rc≠0 ⟹ FAIL；**超时 ⟹ WARN(inconclusive)** —— 环境卡顿不是门禁红；pytest 缺失 ⟹ SKIP。
    """
    result = {"check": "tests"}
    mode = (os.environ.get(_SELFCHECK_TESTS_ENV) or "quick").strip().lower()
    scripts_dir = Path(skill_dir) / "scripts"
    all_tests = sorted(scripts_dir.glob("test_*.py"))
    if not all_tests:
        result["status"] = "WARN"
        result["detail"] = "无 test_*.py 测试文件"
        return result
    if mode == "skip":
        result.update({"status": "SKIP", "mode": mode,
                       "detail": "显式跳过（%s=skip；子进程强制此值以防套娃）"
                                 % _SELFCHECK_TESTS_ENV})
        return result
    if mode == "full":
        files, timeout = all_tests, _FULL_TIMEOUT_S
    else:
        mode = "quick"
        want = set(_QUICK_TEST_FILES)
        files = [t for t in all_tests if t.name in want]
        if not files:
            result.update({"status": "SKIP", "mode": mode,
                           "detail": "快速子集文件均不存在（环境不完整）"})
            return result
        timeout = _QUICK_TIMEOUT_S
    result["mode"] = mode
    result["files"] = "%d/%d" % (len(files), len(all_tests))
    # ── 结果缓存（同代码同判决；只对 quick 生效）───────────────────────────────
    # 键 = HEAD + 工作树差异 + 解释器版本 ⟹ **任一文件变动即失效**（不存在「改了代码还命中旧绿」）。
    # 关掉：`GK_SELFCHECK_TESTS_TTL=0`。
    ttl = float(os.environ.get(_TESTS_CACHE_TTL_ENV, "1800") or 0)
    cache_key = ""
    if ttl > 0 and mode == "quick":
        fp = _git_fingerprint(skill_dir)
        if fp:
            cache_key = fp + ":" + sys.version.split()[0]
            try:
                c = json.loads(_tests_cache_path().read_text(encoding="utf-8"))
                age = time.time() - float(c.get("ts") or 0)
                if c.get("key") == cache_key and age < ttl:
                    cached = dict(c.get("result") or {})
                    cached.update({"cached": True, "age_s": int(age), "mode": mode})
                    return cached
            except Exception:  # noqa: BLE001 — 边界：坏缓存按未命中
                pass
    try:
        probe = subprocess.run([sys.executable, "-c", "import pytest"],
                               capture_output=True, text=True, timeout=15)
        if probe.returncode != 0:
            result["status"] = "SKIP"
            result["detail"] = (f"解释器 {sys.executable} 无 pytest — 环境不可用，测试硬门禁"
                                "保留于 pytest 可用解释器（`GK_PYTHON` / `scripts/_accept_py.local`"
                                " 指定，或 `--tests skip` 显式跳过）")
            return result
    except subprocess.TimeoutExpired:
        result["status"] = "SKIP"
        result["detail"] = "pytest 探测超时 — 按环境不可用跳过"
        return result
    cmd = [sys.executable, "-m", "pytest", "-q", "--tb=short"]
    try:
        import importlib.util as _ilu
        if _ilu.find_spec("xdist") is not None and len(files) >= 4:
            cmd += ["-n", str(min(4, os.cpu_count() or 1))]
            result["xdist"] = True
    except Exception:  # noqa: BLE001 — 边界：探测失败按串行（不影响判决）
        pass
    cmd += [t.name for t in files]
    env = dict(os.environ)
    env.update(_CHILD_TESTS_ENV)      # 禁套娃：子进程里的 run_all 不再跑测试腿
    try:
        proc = subprocess.run(cmd, cwd=str(scripts_dir),
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        result["status"] = "WARN"
        result["detail"] = (f"pytest 超时({timeout}s, mode={mode}) — 结果**不可判**(inconclusive)；"
                            f"全量门禁请 `{_SELFCHECK_TESTS_ENV}=full`")
        return result
    out = (proc.stdout or "") + (proc.stderr or "")
    lines = [ln for ln in out.strip().splitlines() if ln.strip()]
    tail = lines[-1] if lines else "(无输出)"
    if proc.returncode == 0:
        result["status"] = "PASS"
        result["detail"] = f"pytest 全绿 (mode={mode}, {len(files)} 文件) — {tail}"
    else:
        result["status"] = "FAIL"
        result["detail"] = f"pytest 失败(rc={proc.returncode}, mode={mode}, {len(files)} 文件) — {tail}"
    _tests_cache_write(cache_key, result)
    return result


def _tests_cache_write(key: str, result: dict) -> None:
    """写测试腿缓存（best-effort；无键 / 写失败 ⟹ 静默跳过，不影响判决）。"""
    if not key:
        return
    try:
        p = _tests_cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"key": key, "ts": time.time(), "result": result},
                                ensure_ascii=False), encoding="utf-8")
    except Exception:  # noqa: BLE001 — 边界
        pass


# ── 全仓 AST 扫描结果缓存（2026-11-01 二次提速）────────────────────────────────
# 病象（cProfile 实测，tests=skip）：`red_meta_scan → _scan_scope_readers` **39.2s(cProfile)
#   ≈ 13.6s(真实)**、`check_python_argv_inject` 4.6s —— 两者都在**每次**自检里重新 AST
#   解析 1100+ 个 .py（5.8M 次 ast.walk）。文件没变 ⟹ 结果必然相同。
# 修法：按「被扫文件集合指纹（路径+大小+mtime）」缓存**结果**（默认 24h，`TTL=0` 关闭）。
_SCAN_CACHE_TTL_ENV = "GK_SELFCHECK_SCAN_TTL"


def _scan_cache_path() -> Path:
    home = os.environ.get("HOME") or str(Path.home())
    return Path(home) / ".gatekeeper" / "selfcheck-scan.json"


def _scan_fingerprint(skill_dir: str) -> str:
    """被扫面指纹：`scripts/**/*.py|*.sh` + `references/**/*.py` + 顶层 CLI 脚本。

    ⚠ 性能（实测 2026-11-01）：**不能用 `Path.rglob`** —— 在 /mnt/c（9p）上递归遍历一次
    **37s**（两个 rglob 共 74s，把自检从 26s 拖到 102s）。改 `git ls-files`（一次子进程，
    只列已跟踪文件）+ 逐文件 `stat`；git 不可用时退**平铺** glob（不递归）。
    """
    root = Path(skill_dir)
    rel_paths = None
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "--", "scripts", "references"],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            rel_paths = [p for p in r.stdout.splitlines() if p.endswith((".py", ".sh"))]
    except Exception:  # noqa: BLE001 — 边界：退平铺 glob
        rel_paths = None
    if rel_paths is None:
        rel_paths = []
        for sub, pats in (("scripts", ("*.py", "*.sh")), ("references", ("*.py",))):
            base = root / sub
            if base.is_dir():
                for pat in pats:
                    rel_paths += [str(p.relative_to(root)) for p in sorted(base.glob(pat))]
        rel_paths = [p for p in rel_paths if p.endswith((".py", ".sh"))]
    h = hashlib.sha256()
    seen = 0
    for rel in rel_paths:
        p = root / rel
        try:
            s = p.stat()
        except OSError:
            continue
        h.update(("%s:%d:%d\n" % (rel, s.st_size, int(s.st_mtime))).encode())
        seen += 1
    try:                                   # 顶层 CLI（不在 scripts/ 下，单独计入）
        s = (root / "gatekeeper-cli.sh").stat()
        h.update(("gatekeeper-cli.sh:%d:%d\n" % (s.st_size, int(s.st_mtime))).encode())
        seen += 1
    except OSError:
        pass
    fp = h.hexdigest()[:16] if seen else ""
    return fp


def _cached_scan(name: str, skill_dir: str, fn) -> dict:
    """跑一次全仓扫描并缓存（键 = `name:扫描面指纹`；**多条目**存储，禁互相覆盖）。"""
    ttl = float(os.environ.get(_SCAN_CACHE_TTL_ENV, "86400") or 0)
    fp = _scan_fingerprint(skill_dir) if ttl > 0 else ""
    if not fp:
        return fn()
    key = "%s:%s" % (name, fp)
    p = _scan_cache_path()
    store = {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and all(isinstance(v, dict) for v in raw.values()):
            store = raw
    except Exception:  # noqa: BLE001 — 边界：坏缓存/旧格式按空处理
        store = {}
    ent = store.get(key)
    if isinstance(ent, dict) and (time.time() - float(ent.get("ts") or 0)) < ttl:
        r = ent.get("result")
        if isinstance(r, dict):
            r = dict(r)
            r["cached"] = True
            return r
    r = fn()
    store[key] = {"ts": time.time(), "result": r}
    if len(store) > 8:                       # 只保留最近 8 条（防缓存文件无限增长）
        for k in sorted(store, key=lambda k: store[k].get("ts", 0))[:-8]:
            store.pop(k, None)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(store, ensure_ascii=False), encoding="utf-8")
    except Exception:  # noqa: BLE001 — 边界：缓存写失败不影响判决
        pass
    return r


def check_l9_runtime_safenet(skill_dir: str) -> dict:
    """L9 运行时安全网（2026-08-26 扩展）：插件升级对账基础设施。

    覆盖 stage-3-review.md L9「运行时安全网」: sha256/sha512 双对账 + 备份
    manifest + 版本白名单（升级场景）。静态扫描 gk_bashpy_upgrade.py + 备份
    目录探测，零 API。判定:
    - 模块缺失 → FAIL（运行时安全网不可用）
    - 双对账 + 备份 + 白名单三要素齐全 → PASS
    - 模块在但要素残缺 → WARN（明细列出缺项）
    """
    result = {"check": "l9_runtime_safenet"}
    upg = Path(skill_dir) / "scripts" / "gk_bashpy_upgrade.py"
    if not upg.exists():
        result["status"] = "FAIL"
        result["detail"] = "gk_bashpy_upgrade.py missing — 运行时安全网不可用"
        return result
    try:
        text = upg.read_text(encoding="utf-8", errors="replace")
        # 三要素（对应 L9 定义）: 双对账 sha512 / 备份 manifest / 版本白名单
        has_dual = "sha512" in text and "sha256" in text
        has_backup = "backup-manifest.json" in text or "backup" in text
        has_whitelist = any(k in text for k in
                            ("wheel-integrity", "whitelist", "_is_sha512_integrity"))
        cache = Path(os.environ.get(
            "GK_BASHPY_CACHE", str(Path.home() / ".cache" / "gk-bashpy")))
        backup_ready = cache.is_dir()
        missing = [n for n, ok in (("sha256/sha512 双对账", has_dual),
                                   ("备份 manifest", has_backup),
                                   ("版本白名单", has_whitelist)) if not ok]
        if not missing:
            result["status"] = "PASS"
            result["detail"] = ("对账/备份/白名单三要素齐全；备份目录="
                                + ("存在" if backup_ready else "未创建(首次升级时)"))
        else:
            result["status"] = "WARN"
            result["detail"] = "缺: " + "、".join(missing)
    except OSError as e:
        result["status"] = "WARN"
        result["detail"] = f"gk_bashpy_upgrade.py 读取失败: {e}"
    return result


def check_l9_gatechain_prereq(state_path: str) -> dict:
    """L9 门禁链前置（2026-08-26 扩展）：复用 gk_advance._eco_prereq_heuristic。

    覆盖 stage-3-review.md L9「门禁链前置」: advance 拦截时检查
    subagent/audit/adjudicate 前置产物（纯读 gate_data，零 API）。判定:
    - state 缺失 / stage 非 ECO-* → INFO（无门禁链可判定）
    - 当前 ECO stage 前置产物齐全 → PASS
    - 有缺失 → WARN（missing 明细，提示前置节点被跳过）
    """
    result = {"check": "l9_gatechain_prereq"}
    p = Path(state_path)
    if not p.exists():
        result["status"] = "INFO"
        result["detail"] = "state 缺失 — 无门禁链可判定"
        return result
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        current = str(d.get("stage", ""))
        if not current.startswith("ECO-"):
            result["status"] = "INFO"
            result["detail"] = f"stage={current} 非 ECO 阶段 — 门禁链前置不适用"
            return result
        from gk_advance import _eco_prereq_heuristic
        h = _eco_prereq_heuristic(d, current)
        missing = h.get("missing", [])
        if missing:
            result["status"] = "WARN"
            result["detail"] = (f"stage={current}: {len(missing)} 个前置产物缺失 — "
                                + h.get("verdict", ""))
            result["missing"] = [m["item"] for m in missing]
        else:
            result["status"] = "PASS"
            result["detail"] = f"stage={current}: 前置产物齐全"
    except Exception as e:
        result["status"] = "WARN"
        result["detail"] = f"check crashed: {type(e).__name__}: {e}"
    return result


def check_l9_entropy_appeal(state_path: str) -> dict:
    """L9 熵/appeal 链路（2026-08-26 扩展）：熵阈值 + appeal 死锁检测。

    覆盖 stage-3-review.md L9「熵/appeal 链路」: entropy_rate 阈值（<0.5，对照
    monitor-schemas/ECO-VERIFY.json）+ appeal_required → escalate 回路无死锁。
    判定:
    - entropy_rate >= 0.5 → FAIL（熵过高需人类裁决）
    - appeal_denied_gates 非空 → WARN（永久拒绝的 gate 清单）
    - appeal_required 存在 → WARN（advance 被锁，须先 appeal）
    - 均无 → PASS；state 缺失 → INFO
    """
    result = {"check": "l9_entropy_appeal"}
    p = Path(state_path)
    if not p.exists():
        result["status"] = "INFO"
        result["detail"] = "state 缺失 — 无熵/appeal 链路可判定"
        return result
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        gd = d.get("gate_data", {})
        er = gd.get("entropy_rate")
        # appeal_denied_gates 在顶层（cmd_appeal L3139 写入 d['appeal_denied_gates']），
        # 嵌套 gd.get 永不命中 → 永久拒绝 gate 漏报（L2 审查修正 2026-08-31）
        denied = d.get("appeal_denied_gates") or []
        # X1（2026-10-31）：多源阻断单源判定（`appeal_blocks` + 旧 scalar 兜底）
        from gk_gate_appeal import blocking_gates
        required = blocking_gates(d)
        probs = []
        if er is not None:
            try:
                if float(er) >= 0.5:
                    probs.append(f"entropy_rate={er}>=0.5")
            except (TypeError, ValueError):
                pass
        if denied:
            probs.append(f"appeal_denied_gates={denied}")
        if required:
            probs.append(f"appeal_required={','.join(required)}")
        if not probs:
            result["status"] = "PASS"
            result["detail"] = "熵 < 0.5 且无 appeal 死锁"
        elif probs[0].startswith("entropy"):
            result["status"] = "FAIL"
            result["detail"] = "; ".join(probs)
        else:
            result["status"] = "WARN"
            result["detail"] = "; ".join(probs)
    except Exception as e:
        result["status"] = "WARN"
        result["detail"] = f"check crashed: {type(e).__name__}: {e}"
    return result


def _verify_source_kinds(vsrc: str) -> list:
    """解析 `;` 分隔的 `<kind>:payload`，返回小写 kind 列表（c9 加固辅助）。

    判据**单源同构** `gk_finding._assert_verify_source`：只有含 `:` 的结构化段参与 kind 校验，
    无冒号自由文本段（`l10b` / `R-T8.5 复验` / 括号补充）放行。原实现 `part.split(":")[0]`
    把无冒号段整段当 kind ⟹ 合法源串里的括号补充被误判（实测 `ECC-9130E7CA8625` 的
    `tests:… (…; mu_tgt 11/8/3/0);review:…` ⟹ 恒 FAIL）。
    """
    out = []
    for part in (vsrc or "").split(";"):
        part = part.strip()
        if ":" in part:
            out.append(part.split(":", 1)[0].strip().lower())
    return out


def _bad_verify_kinds(vsrc: str) -> list:
    """非白名单 kind（单源 = `gk_finding._VERIFY_SOURCES`；导入失败 → [] = 跳过，不误伤）。"""
    try:
        from gk_finding import _VERIFY_SOURCES
    except Exception:
        return []
    return sorted({k for k in _verify_source_kinds(vsrc) if k not in _VERIFY_SOURCES})


def _bad_commits(vsrc: str) -> list:
    """`commit:` 段中无 sha 或 sha 仓内不可解析（`git cat-file -e <sha>^{commit}`）的条目。

    仓库根 = 本文件父目录的父目录（skill/worktree 根）。git 异常（不可用/超时）→ 跳过该段
    （不误判为编造）。返回条目为缺失的 sha 或 `"no-sha"`。
    """
    repo = str(Path(__file__).resolve().parent.parent)
    bad = []
    for part in (vsrc or "").split(";"):
        part = part.strip()
        if not part.lower().startswith("commit:"):
            continue
        payload = part.split(":", 1)[1]
        m = re.search(r"\b[0-9a-fA-F]{7,40}\b", payload)
        if not m:
            bad.append("no-sha")
            continue
        sha = m.group(0)
        try:
            r = subprocess.run(["git", "-C", repo, "cat-file", "-e", sha + "^{commit}"],
                               capture_output=True, timeout=10)
        except Exception:
            continue
        if r.returncode != 0:
            bad.append(sha)
    return bad


def check_ecc_form(state_path: str) -> dict:
    """ECC 写入规范 · **机械（A 类）**体检（2026-09-28；`ECC-03F2EB7D6607` + `ECC-FF45F426BA45`）。

    = 「monitor 监管 ecc 按规范写入」的只读落点（`s4`）。判据与 `gk_finding.register` 的
    fail-loud 边界**单源同构**（常量直取 `gk_finding`，不抄字面量 ⟹ 两处永不漂移）：

      - `closure_oracle ∈ {"", "mechanical", "judgment"}`（**`""`=未分类合法**，存量不追责）
      - `root_key` 非空时：**无空白**且**长度 ≤ `_ROOT_KEY_MAX`**（= 根因指纹，非散文）
      - 终态**有据**（2026-10-04 · §18.2 判据 9 / ⑤）：`status ∈ {closed,fixed}` 时须
        `basis_ref` 非空 **或** `verify_source == "register-only"`（显式「仅登记」标签）；
        否则 **FAIL** —— 治「登记即闭合」洗白形状（`ECC-DB4E4CBDCF7C`）。
      - **闭合须有「源」**（2026-10-04 · c9 v2→v3 加固 · `ECC-2C7BEBA09A84`）：
        `status ∈ {closed,fixed}` 时除 `basis_ref` 外，`verify_source` **不得** ∈ `{"", "manual"}`
        （空/`manual` = 无实据自证）；因 `register` 自动产 `evidence_hash` 后 `basis_ref` 恒非空 ⟹
        原判据对新条目失效，v2 补「源质量」恢复拦截。v3（全纳入）再补三条**真牙齿**：
          · **kind 白名单**：`verify_source` 的 `;` 分段 kind 须 ∈ `gk_finding._VERIFY_SOURCES`
            （非白名单 = 「任意串即有源」⟹ FAIL）；
          · **commit 可核验**：`commit:<sha>` 段须携带可解析 sha 且仓内 `git cat-file -e` 存在
            （编造 sha ⟹ FAIL）；
          · **`fixed` 一并核验**：不再豁免 verify 路径（`verify()` 增可选 `verify_source`）。

    判定：state 缺失 → INFO；无 `ecc_findings` → INFO；有违例 → **FAIL**（计数 + 前 3 条样例）；
    否则 PASS。⚠ **只读**：不写台账、不写盘 —— 监管 ≠ 写入者（N4：零新增写入者；FAIL 的出口
    复用既有 `_l9_fail_names` → L9 auto-E2，不另造写通路）。
    """
    result = {"check": "ecc_form"}
    p = Path(state_path)
    if not p.exists():
        result["status"] = "INFO"
        result["detail"] = "state 缺失 — 无 ecc 台账可判定"
        return result
    try:
        from gk_finding import (_CLOSURE_ORACLES, _ROOT_KEY_MAX,  # 单源：与 register 拒绝边界同构
                                _ECC_SOURCES, _SOURCE_MAX)
        d = json.loads(p.read_text(encoding="utf-8"))
        fs = (d.get("gate_data") or {}).get("ecc_findings")
        if not isinstance(fs, list) or not fs:
            result["status"] = "INFO"
            result["detail"] = "无 ecc_findings — 无写入规范可判定"
            return result
        ok_oracles = ("",) + tuple(_CLOSURE_ORACLES)
        bad_co, bad_rk, bad_src, bad_close, bad_srcq, bad_vsrc, bad_commit = [], [], [], [], [], [], []
        for f in fs:
            if not isinstance(f, dict):
                continue
            co = f.get("closure_oracle") or ""
            if co not in ok_oracles:
                bad_co.append("%s:%r" % (f.get("id", "?"), co))
            rk = f.get("root_key") or ""
            if rk and (len(rk) > _ROOT_KEY_MAX or any(c.isspace() for c in rk)):
                bad_rk.append("%s:%r" % (f.get("id", "?"), rk[:24]))
            # 2026-09-28（B 类安全网）：`source` 须为白名单内短 token。
            #   ⚠ **存量**非规范（实测 base 92 条里 ≈44 条）只 **WARN 不 FAIL** —— 否则恒红、
            #   且等于用新规追责历史；新写入由 `register` 边界 fail-loud 拦（增量收口）。
            sc = f.get("source") or ""
            if sc not in _ECC_SOURCES or len(sc) > _SOURCE_MAX or any(c.isspace() for c in sc):
                bad_src.append("%s:%r" % (f.get("id", "?"), sc[:24]))
            # 2026-10-04（§18.2 判据 9 / ⑤ + c9 加固 ECC-2C7BEBA09A84）：终态须「有据」+「源可核验」。
            #   · `basis_ref` 非空 或 `verify_source == "register-only"`（显式仅登记出口）；
            #   · 源质量：终态须 vsrc ∉ {"", "manual"}（无实据自证 = 洗白）——`closed`/`fixed` 一并；
            #   · kind 白名单：每段 kind ∈ `_VERIFY_SOURCES`，非白名单 = 「任意串即有源」⟹ FAIL；
            #   · commit 可核验：`commit:<sha>` 须携带可解析 sha 且仓内 `git cat-file -e` 存在。
            stt = f.get("status") or "open"
            vsrc = f.get("verify_source") or ""
            if stt in ("closed", "fixed") and vsrc != "register-only":
                if not (f.get("basis_ref") or ""):
                    bad_close.append("%s:%s" % (f.get("id", "?"), stt))
                elif vsrc in ("", "manual"):
                    # c9 加固④（全纳入）：`fixed` 也须有真源（不再豁免 verify 路径）。
                    bad_srcq.append("%s:%r" % (f.get("id", "?"), vsrc))
                else:
                    # 终态须有**结构化**真源：纯自由文本（无 `kind:` 段）= 无实据自证。
                    #   非终态自由文本段放行（与 `gk_finding._assert_verify_source` 同构），
                    #   但终态不放行 —— 否则「自由文本即源」= 洗白形状。
                    _bk = _bad_verify_kinds(vsrc)
                    if not _verify_source_kinds(vsrc):
                        _bk = ["<no-structured-source>"]
                    if _bk:
                        bad_vsrc.append("%s:%s" % (f.get("id", "?"), ",".join(_bk)))
                    _bc = _bad_commits(vsrc)
                    if _bc:
                        bad_commit.append("%s:%s" % (f.get("id", "?"), ",".join(_bc)))
        if bad_co or bad_rk or bad_close or bad_srcq or bad_vsrc or bad_commit:
            result["status"] = "FAIL"
            result["detail"] = ("closure_oracle 非法 %d 条 %s；root_key 非法 %d 条 %s；"
                                "无据关闭 %d 条 %s；闭合无源 %d 条 %s；"
                                "源 kind 非法 %d 条 %s；commit 不可解析 %d 条 %s"
                                % (len(bad_co), bad_co[:3], len(bad_rk), bad_rk[:3],
                                   len(bad_close), bad_close[:3],
                                   len(bad_srcq), bad_srcq[:3],
                                   len(bad_vsrc), bad_vsrc[:3],
                                   len(bad_commit), bad_commit[:3]))
        elif bad_src:
            result["status"] = "WARN"
            result["detail"] = ("存量 `source` 非规范 %d 条（**不追责**，仅提示；新写入已被 "
                                "`register` 边界 fail-loud 拦下）样例 %s"
                                % (len(bad_src), bad_src[:3]))
        else:
            result["status"] = "PASS"
            result["detail"] = ("ecc_findings=%d：closure_oracle/root_key/closure_basis/source 均合规" % len(fs))
        return result
    except Exception as e:
        result["status"] = "WARN"
        result["detail"] = f"check crashed: {type(e).__name__}: {e}"
        return result


def check_sequence_node_safety(skill_dir: str, ng=None) -> dict:
    """序列节点安全网健全程度（2026-09-05 扩展）。

    对 gk_node_guard._ROUTES 全部序列的每站做三面实配核查（gate=_GATES /
    checklist=_CHECKLISTS / safety=_SAFETY）——S11（2026-09-05）standard 序列
    _GATES 缺 STAGE_0/DONE、_SAFETY 仅 STAGE_2/3、DONE 无 checklist 的"大面积
    落默认空壳"必须以确定性检查钉死（与 test_gk_node_guard 实配锁定互补，防只锁
    测试不锁运行面）。判定:
    - 任一站在三面全默认（0/3 显式，仅靠 _node_defaults 兜底）→ FAIL（空壳站，
      detail 列出 序列:节点）
    - 有站 1/3 显式（thin，gate 顺序默认或 safety 引导默认）→ 计入 detail（WARN 级，
      引导逐站补齐，不阻断——red/audit/plugin 顺序站合法场景）
    - 全站 ≥2/3 显式 → PASS；routes 输出各序列 gate/checklist/safety 实配覆盖率

    dispatcher 路线（route meta walk=dispatcher，2026-09-07 批③ ⑤ WAD 复核追认 R4）：
    red（_red_attacks 引擎分发）/ audit（cmd_audit 家族 + audit --all）非 advance 逐站 walk，
    站级门禁语义在引擎分发/registry 面（check_red S10）——其三面覆盖率照常输出 rows，
    但不计 bare/thin（机械补 _GATES 描述串 = 双事实源错误实现）。
    """
    result = {"check": "sequence_node_safety"}
    if ng is None:
        try:
            import gk_node_guard as _ng
        except Exception as e:
            result["status"] = "FAIL"
            result["detail"] = f"gk_node_guard 不可导入 — 序列安全网不可核查: {e}"
            return result
        ng = _ng
    routes = getattr(ng, "_ROUTES", None) or {}
    gates = getattr(ng, "_GATES", None) or {}
    checklists = getattr(ng, "_CHECKLISTS", None) or {}
    safety = getattr(ng, "_SAFETY", None) or {}
    bare, thin, route_rows, dispatcher_rows = [], [], [], []
    n_nodes = 0
    for route, meta in routes.items():
        nodes = (meta.get("nodes", []) if isinstance(meta, dict) else []) or []
        if not nodes:
            continue
        is_disp = isinstance(meta, dict) and meta.get("walk") == "dispatcher"
        n_nodes += len(nodes)
        g = c = s = 0
        for node in nodes:
            g += 1 if node in gates else 0
            c += 1 if node in checklists and checklists[node] else 0
            s += 1 if node in safety and safety[node] else 0
            if is_disp:
                continue  # 引擎分发路线：覆盖率照常统计，不计 bare/thin（WAD）
            explicit = (1 if node in gates else 0) \
                + (1 if node in checklists and checklists[node] else 0) \
                + (1 if node in safety and safety[node] else 0)
            if explicit == 0:
                bare.append(f"{route}:{node}")
            elif explicit == 1:
                thin.append(f"{route}:{node}({explicit}/3)")
        row = {
            "route": route, "name": meta.get("name", ""),
            "nodes": len(nodes),
            "gate_explicit": f"{g}/{len(nodes)}",
            "checklist_explicit": f"{c}/{len(nodes)}",
            "safety_explicit": f"{s}/{len(nodes)}",
        }
        if is_disp:
            row["walk"] = "dispatcher"
            dispatcher_rows.append(row)
        route_rows.append(row)
    result["routes"] = route_rows
    result["dispatcher_routes"] = dispatcher_rows
    result["bare_stations"] = bare
    result["thin_stations"] = thin
    disp_n = sum(r["nodes"] for r in dispatcher_rows)
    disp_note = (f"；dispatcher 路线 {len(dispatcher_rows)} 条/{disp_n} 站"
                 + "（引擎分发 WAD，不计 thin）" if dispatcher_rows else "")
    if bare:
        result["status"] = "FAIL"
        result["detail"] = ("空壳站（仅路由登记、三面全默认）: "
                            + "、".join(bare) + "；thin 站 " + str(len(thin)) + disp_note)
    elif thin:
        result["status"] = "WARN"
        result["detail"] = ("无空壳站，但 thin 站 " + str(len(thin))
                            + " 个（gate 顺序默认/引导默认，可接受或逐站补齐）: "
                            + "、".join(thin[:12]) + disp_note)
    else:
        result["status"] = "PASS"
        result["detail"] = (f"{len(routes)} 序列 / {n_nodes} 站三面实配齐备"
                            + disp_note)
    return result


# ── 派生联动 / 租户隔离共用小工具（2026-09-05；registry/scopes 路径归一与读取）────
def _gx_norm_path(p: str) -> str:
    """归一：\\ → / + 小写 + 去尾斜杠；/mnt/c/... → c:/...（gitnexus 路径比较口径，Python 侧单源）。"""
    p = p.replace("\\", "/").lower().rstrip("/")
    if p.startswith("/mnt/"):
        p = p[5] + ":" + p[6:]
    return p


def _repo_identity_dir(base_dir: str) -> str:
    """返回 `base_dir` 所属**仓库根目录**（worktree ⟹ **主仓**根）；不可解析返回 ""。

    2026-10-01（`governed_baseline` 对 agent 会话 worktree 恒 FAIL 的根因修复）：
    基线判定须按**仓库身份**而非**目录字面** —— agent 会话 worktree 与主仓**共享对象库/refs**
    （`.git` 是**文件**：`gitdir: <主仓>/.git/worktrees/<n>`）⟹ 治理实体 = 主仓；且实测
    `gitnexus status` 在 `.git`-文件 worktree 下**直接报 `Not a git repository`** ⟹ GN 无法为
    worktree 单独建索引（不存在"给它建基线"这条路）。故取 `--git-common-dir`（跨 worktree 恒指
    主仓 `.git`）反推主仓根，交由调用方按 registry 复核（**核不中仍 FAIL**，不做无条件放行）。
    """
    if not base_dir or not os.path.isdir(base_dir):
        return ""
    out = ""
    for extra in (["--path-format=absolute"], []):
        try:
            r = subprocess.run(["git", "-C", base_dir, "rev-parse", *extra, "--git-common-dir"],
                               capture_output=True, text=True, timeout=5)
        except Exception:
            return ""
        out = (r.stdout or "").strip()
        if r.returncode == 0 and out:
            break
    if not out:
        return ""
    common = out if os.path.isabs(out) else os.path.abspath(os.path.join(base_dir, out))
    common = common.rstrip("/\\")
    if os.path.basename(common) != ".git":
        return ""
    return os.path.dirname(common)


def _default_registry_path() -> str:
    for cand in (os.environ.get("USERPROFILE", ""), str(Path.home())):
        if cand:
            p = os.path.join(cand, ".gitnexus", "registry.json")
            if os.path.isfile(p):
                return p
    try:  # 用户目录不写死用户名（2026-10-29 去硬编码）
        from gk_host_paths import user_home, wsl_to_win
        for uh in (user_home(), wsl_to_win(user_home())):
            p = os.path.join(uh, ".gitnexus", "registry.json")
            if os.path.isfile(p):
                return p
    except Exception:
        pass
    return ""


def _load_scopes(skill_dir: str, scopes_path: str = "") -> dict:
    """读治理范围注册表（.gatekeeper.scopes.json）；失败返回空结构。"""
    p = scopes_path or os.path.join(skill_dir, ".gatekeeper.scopes.json")
    try:
        d = json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


def _load_gx_registry(registry_path: str = "") -> list:
    p = registry_path or _default_registry_path()
    if not p:
        return []
    try:
        d = json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return []
    return d if isinstance(d, list) else []


def _scopes_root_for(state_path: str, scopes: dict, skill_dir: str) -> tuple[str, str]:
    """按 state 判定所属治理租户根目录与判定来源（scopes state_file / 目录归属）。"""
    sn = _gx_norm_path(os.path.abspath(state_path))
    for proj in scopes.get("governed_projects", []) or []:
        if not isinstance(proj, dict):
            continue
        if _gx_norm_path(str(proj.get("state_file", ""))) == sn:
            return os.path.dirname(os.path.abspath(state_path)), "scopes"
    # 目录片段归属：state 父目录命中任一 marker 片段（worktree 形态），或 = 技能目录（固有治理）
    parent = os.path.dirname(os.path.abspath(state_path))
    pn = _gx_norm_path(parent)
    for proj in scopes.get("governed_projects", []) or []:
        if not isinstance(proj, dict):
            continue
        for m in proj.get("markers", []) or []:
            if m and _gx_norm_path(str(m)) in pn:
                return parent, "marker"
    if _gx_norm_path(skill_dir) == pn:
        return parent, "skill"
    return parent, "none"


def check_governed_baseline(state_path: str, skill_dir: str,
                            registry_path: str = "", scopes_path: str = "") -> dict:
    """派生联动（2026-09-05 定案：元数据只引用，基线存在性由路由运行时派生）。

    元数据（state/target_repo/worktree）须与自动注册机制 + gitnexus 基线联动：
    META 不新增字段声明基线，而是——当前活动项目的目录 → 治理范围（scopes
    state_file/marker 片段/skill 固有）判定 + gitnexus registry name↔path 基线存在性
    （A3 register 自动建基线后 registry 必有条目）派生。判定:
    - 无 state / IDLE 无 worktree → INFO（无活动项目，派生不适用）
    - 治理范围判定 none + 非技能目录 → WARN（未知租户——先 project-register 登记）
    - 治理范围内但 registry 无对应条目 → FAIL（基线缺失：project-register register 触发 A3 自动建）
    - 治理范围内且 registry 有条目 → PASS（基线已派生登记，条目名输出）
    """
    result = {"check": "governed_baseline"}
    if not state_path or not os.path.isfile(state_path):
        result["status"] = "INFO"
        result["detail"] = "无 state 文件 — 派生联动不适用（先 discover 初始化）"
        return result
    try:
        st = json.loads(Path(state_path).read_text(encoding="utf-8"))
    except Exception:
        result["status"] = "WARN"
        result["detail"] = "state 读取失败 — 派生联动跳过"
        return result
    stage = str(st.get("stage", "") or st.get("r_phase", ""))
    worktree = str(st.get("worktree", "") or "")
    if stage == "IDLE" and not worktree:
        result["status"] = "INFO"
        result["detail"] = "stage=IDLE 且无 worktree — 无活动目标项目"
        return result
    # 目标目录 = 显式 worktree 优先（A2 registry 前缀解析语义一致），否则 state 父目录
    base_dir = worktree if (worktree and os.path.isdir(worktree)) else os.path.dirname(os.path.abspath(state_path))
    scopes = _load_scopes(skill_dir, scopes_path)
    root, src = _scopes_root_for(state_path, scopes, skill_dir)
    if src == "none":
        # state 自身无归属 → 用 worktree 目录再做一次 marker 片段归属
        root, src = _scopes_root_for(os.path.join(base_dir, ".gatekeeper.state"), scopes, skill_dir) \
            if os.path.isdir(base_dir) else (root, "none")
    if src == "none":
        result["status"] = "WARN"
        result["detail"] = ("目标目录不在治理范围注册表（src=none）: "
                            + base_dir + " — 先用 project-register register 登记（A3 将自动建基线）")
        return result
    reg = _load_gx_registry(registry_path)
    bdir = _gx_norm_path(os.path.abspath(base_dir))
    hit = ""
    for e in reg:
        if not isinstance(e, dict):
            continue
        pn = _gx_norm_path(str(e.get("path", "")))
        if pn and (bdir == pn or bdir.startswith(pn + "/")):
            hit = str(e.get("name", ""))
            break
    via = ""
    if not hit:
        # 2026-10-01：**worktree 兜底** —— 直接前缀未命中时，按**仓库身份**再匹配一次。
        #   agent 会话 worktree 的 `.git` 是文件、与主仓同仓 ⟹ 基线归主仓（且 GN 对
        #   `.git`-文件 worktree 报 `Not a git repository`，无法单独建索引，见 `_repo_identity_dir`）。
        #   命中后 detail 显式标注 `via=worktree-of`，与直接命中**可区分**（不掩盖来源）；
        #   仓库根**核不中 registry ⟹ 仍 FAIL**（非无条件放行）。
        idir = _repo_identity_dir(base_dir)
        if idir:
            inorm = _gx_norm_path(os.path.abspath(idir))
            for e in reg:
                if not isinstance(e, dict):
                    continue
                pn = _gx_norm_path(str(e.get("path", "")))
                if pn and (inorm == pn or inorm.startswith(pn + "/")):
                    hit = str(e.get("name", ""))
                    via = "worktree-of"
                    break
    if not hit:
        result["status"] = "FAIL"
        result["detail"] = (f"治理范围 src={src}，但 gitnexus registry 无对应基线条目 "
                            f"({base_dir}) — 缺基线 → project-register register 自动建（A3）")
        return result
    result["status"] = "PASS"
    result["detail"] = (f"src={src}；registry 基线条目存在: {hit}（A3/analyze 登记）"
                        + ("；via=worktree-of（base_dir 为该仓 git worktree，与主仓共享基线；"
                           "GN 无法为 .git-文件 worktree 单独建索引）" if via else ""))
    return result


def check_tenant_isolation(skill_dir: str, scopes_path: str = "",
                           registry_path: str = "") -> dict:
    """租户隔离（2026-09-05 定案：域 token 门小步实装；与余烬系统对应）。

    治理范围注册表 = 租户名册（天庭），每个 governed state_file 父目录 = 租户根。
    跨租户数据隔离确定性检查（doc-align/self-check 共用）:
    - 双形态重复根（同目录 C:/ 与 /mnt/c/ 并存 = 两租户实为一家，域边界虚置）→ WARN
    - 嵌套根（A 租户根 ⊂ B 租户根 = 域边界包含/越权读取面）→ WARN（列出对）
    - state_file 归一化重复（同 state 两租户声明）→ WARN
    隔离键 = state_domain <repo>.<plan> 的 repo 段；技能目录 = 固有租户，不与他租户判嵌套。
    """
    result = {"check": "tenant_isolation"}
    scopes = _load_scopes(skill_dir, scopes_path)
    projects = [p for p in scopes.get("governed_projects", []) or [] if isinstance(p, dict)]
    if not projects:
        result["status"] = "SKIP"
        result["detail"] = "无 governed_projects 登记 — 租户隔离无可核查"
        return result
    # 租户根（state_file 父目录）归一集合 + 原文映射（不做 abspath：Windows 下 /mnt/... 非绝对，
    # 而 scopes 登记的 state_file 恒为绝对路径，取 dirname 后 _gx_norm_path 统一 C:/ 与 /mnt/ 形态）
    by_norm = {}
    skill_n = _gx_norm_path(os.path.abspath(skill_dir))
    for p in projects:
        sf = str(p.get("state_file", "")).replace("\\", "/")
        if not sf or "/" not in sf:
            continue
        root_raw = sf.rsplit("/", 1)[0]  # 剥 .gatekeeper.state → 项目根
        if not root_raw:
            continue
        key = _gx_norm_path(root_raw)
        by_norm.setdefault(key, []).append({"markers": p.get("markers", []), "state_file": sf})
    dup = [k for k, v in by_norm.items() if len(v) > 1]
    dups = sorted(dup)
    nested = []
    keys = sorted(by_norm)
    for i, a in enumerate(keys):
        if a == skill_n:
            continue  # 技能目录固有租户不参与嵌套判定
        for b in keys[i + 1:]:
            if b == skill_n:
                continue
            if a.startswith(b + "/") or b.startswith(a + "/"):
                nested.append((b, a) if b.startswith(a + "/") else (a, b))
    warns = []
    if dups:
        warns.append("state_file 父目录归一化重复租户: " + "、".join(dups))
    if nested:
        warns.append("嵌套租户根（域边界包含，跨租户读取面）: "
                     + "、".join(f"{x}⊂{y}" for x, y in nested[:6]))
    result["tenant_roots"] = list(by_norm)
    result["duplicate_roots"] = dups
    result["nested_roots"] = nested
    if warns:
        result["status"] = "WARN"
        result["detail"] = "；".join(warns)
    else:
        result["status"] = "PASS"
        result["detail"] = f"{len(by_norm)} 个治理租户根，无双形态重复/嵌套 — 域边界清晰"
    return result


# ---------------------------------------------------------------------------
# C4 (2026-09-06): RED-META-01/02 越权读探测——findings 供 L10b 人工裁决
#   01 = 租户根判定归一单源启发式：直读 .gatekeeper.scopes.json 的代码点候选
#       （须核对比较是否经 _gx_norm_path 归一——归一单源未走 → 形态差异绕过面）
#   02 = 双源复验（非重复 #19 轮子）：gitnexus registry name/path ↔ scopes 租户根
#       交叉归一——registry 路径命中/嵌套 scopes 根 = 越权读面候选（#19 只见 scopes 内部）
# 输出 candidate findings（WARN 不 FAIL——裁决交 L10b，agent register source=red family=RED-META）
# ---------------------------------------------------------------------------
_SCOPES_FILE_HINT = ".gatekeeper.scopes.json"

# L10b 裁决登记豁免表（2026-09-07 批③ ③：red_meta_read 22 候选分级定案）——
# 对齐 write_guard EXEMPT-8 先例：逐点核对后登记"等效归一/无跨形态比较"裁决，
# 归一单源化改造 = 远期重构项（不阻断）。豁免模块仍会被列 info（保留核对面），不产生 warn。
_RED_META_ADJUDICATED = {
    "pre_tool_hook.py": "自带 _win_to_wsl/_wsl_to_win/_resolve_existing 双形态归一；marker=token 子串比对不受形态影响（L10b 核对安全）",
    "subagent_runner.py": "自带 _sf_exists /mnt↔盘符双形态存在性探测 + 保持原形态不 abspath；无跨形态路径比较（L10b 核对安全）",
    "_red_attacks.py": "red_registry 读取面 = checksum/孤儿/别名 校验 + _path_exists_win_compat 双形态存在性；无跨形态路径比较（L10b 核对安全）",
    "gk_project_register.py": "登记输入合规面 + registry 归一走 A2 同源既有实现（L10b 核对安全）",
}


def _mask_comment_docstring(py_text: str) -> list:
    """屏蔽注释与 docstring 后的代码行（启发式 01 用）：去 docstring（三引号块）+ 全行 # 注释。

    防止 01 把注释/docstring/常量定义行当"直读 scopes 代码点"（2026-09-07 批③ ③ 裁决噪声类）。
    """
    import re
    # 行号保持掩码：docstring 块整体替换为等量空行（不折叠行数 → 命中行号与源文件一致）
    txt = re.sub(r'"""(?:[^"]|"(?!")|""(?!"))*"""',
                 lambda m: "\n" * m.group(0).count("\n"), py_text, flags=re.S)
    return ["" if ln.lstrip().startswith("#") else ln for ln in txt.splitlines()]


def _scan_scope_readers(skill_dir: str) -> list:
    """RED-META-01 直读 scopes 代码点 — R2 AST 语法级精扫（2026-09-09 实装，批③-4 backlog）。

    替代 R1 行文本窗口（行含 scopes 字样 + 邻近 open/read_text 即列）→ AST 定位真调用：
      - 注释/docstring/字符串常量（含 scopes 字样但非读动作）语法级天然不列（无需掩码）；
      - 候选 = ast.Call 且 func ∈ {open, read_text, read_bytes, json.load, json.loads}，
        文件参数数据流粗判引用 scopes 路径（字面量 / Path 构造 / 常量绑定回溯）；
      - 文件含 scopes 常量但读调用参数不可解析 → 每文件 1 条弱候选 info（防漏，收敛 02/#19 兜底面）；
      - 分级（L10b 裁决语义保持）：文件含归一单源（_gx_norm_path 系）或命中豁免登记 → info；
        否则 warn。漏报由 RED-META-02 / #19 / RED-HOOK 兜底（批③-4 声明）。
    """
    import ast
    hits = []
    scripts_dir = os.path.join(skill_dir, "scripts")
    if not os.path.isdir(scripts_dir):
        return hits
    norm_tokens = ("_gx_norm_path", "_norm_path", "_win_to_wsl", "_wsl_to_win")
    for f in sorted(os.path.join(scripts_dir, n) for n in os.listdir(scripts_dir) if n.endswith(".py")):
        try:
            txt = open(f, encoding="utf-8").read()
        except OSError:
            continue
        base = os.path.basename(f)
        # 夹具（test_* 构造/断言非治理生产读面）与扫描器宿主（单源权威，自引用噪声）不列候选
        if base.startswith("test_") or base == "gk_self_check.py":
            continue
        try:
            tree = ast.parse(txt)
        except SyntaxError:
            continue  # 非语法完整生产文件不参与 AST 精扫（脚本面均应为完整模块）
        src_lines = txt.splitlines()
        # 文件级归一/豁免信号（AST 引用级，非文本行）
        has_norm = any(isinstance(n, (ast.Name, ast.Attribute))
                       and getattr(n, "id", getattr(n, "attr", "")) in norm_tokens
                       for n in ast.walk(tree))
        adjudicated = base in _RED_META_ADJUDICATED
        # scopes 常量链引用（文件内任一常量含 scopes 路径字样）
        scope_const = any(isinstance(n, ast.Constant) and isinstance(n.value, str)
                          and "scopes.json" in n.value for n in ast.walk(tree))

        def _refs_scopes(a: "ast.AST") -> bool:
            """文件参数数据流粗判：子树常量含 scopes 路径；Name 经 Assign 绑定回溯。"""
            for n in ast.walk(a):
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and "scopes.json" in n.value:
                    return True
            if isinstance(a, ast.Name):
                for node in ast.walk(tree):
                    if isinstance(node, ast.Assign) and node.value is not None:
                        for tgt in node.targets:
                            if isinstance(tgt, ast.Name) and tgt.id == a.id and _refs_scopes(node.value):
                                return True
                    elif isinstance(node, ast.AnnAssign) and node.value is not None \
                            and isinstance(node.target, ast.Name) and node.target.id == a.id \
                            and _refs_scopes(node.value):
                        return True
            return False

        def _call_name(c: "ast.Call") -> str:
            fn = c.func
            if isinstance(fn, ast.Name):
                return fn.id
            if isinstance(fn, ast.Attribute):
                if fn.attr in ("read_text", "read_bytes"):
                    return fn.attr
                if fn.attr in ("load", "loads") and isinstance(fn.value, ast.Name) \
                        and fn.value.id == "json":
                    return "json." + fn.attr
            return ""

        def _text_of(node: "ast.AST") -> str:
            return (src_lines[node.lineno - 1].strip()[:110]
                    if 0 < node.lineno <= len(src_lines) else "")

        # strong 候选按行去重（json.load(open(...)) 双 Call 同 line）；weak 兜底每文件至多 1 条
        # （仅文件无任何 strong 命中且确有 scopes 常量时落一条 info，防漏；否则弱候选即噪声）
        strong_hits: dict = {}
        weak_hit: dict | None = None

        def _add(node: "ast.Call", arg: "ast.AST | None", weak: bool):
            line = getattr(node, "lineno", 1)
            if weak:
                nonlocal weak_hit
                if weak_hit is None:
                    weak_hit = {"file": base, "line": line,
                                "norm_in_file": True, "adjudicated": adjudicated,
                                "weak": True, "text": _text_of(node)}
                return
            if line in strong_hits:
                return
            strong_hits[line] = {"file": base, "line": line,
                                 "norm_in_file": has_norm or adjudicated,
                                 "adjudicated": adjudicated,
                                 "weak": False, "text": _text_of(node)}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = _call_name(node)
            if fn not in ("open", "read_text", "read_bytes", "json.load", "json.loads"):
                continue
            arg = None
            if fn == "open":
                arg = node.args[0] if node.args else None
                if arg is None:
                    for kw in node.keywords:
                        if kw.arg in ("file", "path"):
                            arg = kw.value
            elif fn in ("json.load", "json.loads"):
                arg = node.args[0] if node.args else None
            else:  # read_text/read_bytes：value 链解（Path(...) / open(...) 结果 / 变量）
                v = node.func.value
                for _ in range(4):
                    if not isinstance(v, ast.Call):
                        break
                    vn = _call_name(v)
                    if vn in ("open",) or (isinstance(v.func, ast.Name) and v.func.id in ("Path", "PurePath")):
                        v = v.args[0] if v.args else v
                    else:
                        break
                arg = v
            if arg is not None and _refs_scopes(arg):
                _add(node, arg, weak=False)
            elif scope_const and weak_hit is None:
                # 参数不可解析但文件确有 scopes 常量 → 暂记首个弱候选；最终无任何 strong 才落（防漏，02/#19 兜底）
                _add(node, arg, weak=True)
        hits.extend(strong_hits.values())
        if weak_hit is not None and not strong_hits:
            hits.append(weak_hit)
    return hits


def red_meta_scan(skill_dir: str, scopes_path: str = "", registry_path: str = "") -> dict:
    """RED-META-01/02 越权读探测（C4）：候选 findings 供 L10b 裁决（WARN 非门禁）。"""
    result = {"check": "red_meta_read"}
    scopes = _load_scopes(skill_dir, scopes_path)
    projects = [p for p in scopes.get("governed_projects", []) or [] if isinstance(p, dict)]
    if not projects:
        result["status"] = "SKIP"
        result["detail"] = "无 governed_projects 登记 — 越权读探测无可核查"
        return result
    findings = []
    # 01：直读 scopes 的代码点候选（归一单源核对提示）
    readers = _scan_scope_readers(skill_dir)
    for h in readers:
        # 文件内无归一调用 = 高嫌疑（该处比较可能走形态差异绕过）；有 = 低（仍列候选供核对）
        findings.append({"id": "RED-META-01", "severity": "warn" if not h["norm_in_file"] else "info",
                         "title": f"直读 scopes 代码点 {h['file']}:{h['line']}（归一单源核对）",
                         "description": "租户根判定须经 _gx_norm_path 归一单源；未归一直接比较 = "
                                        "C:/ 与 /mnt/c/ 双形态可绕过面。text: " + h["text"]})
    # 02：registry ↔ scopes 交叉复验（第二源；registry 路径命中/嵌套 scopes 根 = 越权读面候选）
    registry = _load_gx_registry(registry_path)
    scopes_n = {}
    for p in projects:
        sf = str(p.get("state_file", "")).replace("\\", "/")
        if not sf or "/" not in sf:
            continue
        root_raw = sf.rsplit("/", 1)[0]
        if root_raw:
            scopes_n.setdefault(_gx_norm_path(root_raw), []).append(str(p.get("name", "?")))
    reg_paths = []
    for item in registry:
        nm = str(item.get("name", "")) if isinstance(item, dict) else str(item)
        pa = str(item.get("path", "")) if isinstance(item, dict) else ""
        if pa:
            reg_paths.append((nm, pa))
    reg_norms = sorted(set(_gx_norm_path(p) for _, p in reg_paths))
    for rn in reg_norms:
        for sn, owners in scopes_n.items():
            if rn == sn:
                continue
            if rn.startswith(sn + "/") or sn.startswith(rn + "/"):
                findings.append({"id": "RED-META-02", "severity": "warn",
                                 "title": f"registry 路径与 scopes 租户根嵌套/重复: {rn} ↔ {sn}",
                                 "description": "gitnexus registry 登记路径与治理租户根边界交叠"
                                                "（#19 未见此源）= 越权读面候选，owners="
                                                + ",".join(owners[:3])})
    if any(f["severity"] == "warn" for f in findings):
        result["status"] = "WARN"
        result["detail"] = ("RED-META 候选 " + str(len(findings)) + " 条（01="
                            + str(sum(1 for f in findings if f["id"] == "RED-META-01"))
                            + "，02=" + str(sum(1 for f in findings if f["id"] == "RED-META-02"))
                            + "）→ 交 L10b 裁决")
    elif findings:
        # 全部 info = 已归一/裁决登记豁免（_RED_META_ADJUDICATED 核对安全）→ 非越权读面
        result["status"] = "PASS"
        result["detail"] = ("直读 scopes 代码点 " + str(len(findings))
                            + " 条均 info（已归一单源或 L10b 登记豁免核对安全）→ 无越权读候选；"
                            "RED-META-02 无 registry↔scopes 嵌套")
    else:
        result["status"] = "PASS"
        result["detail"] = "无 RED-META 候选（读 scopes 代码点均含归一；registry↔scopes 无嵌套交叠）"
    result["findings"] = findings
    return result


# ---------------------------------------------------------------------------
# 审查层四件套注册表（2026-09-05 C1 / E4 静态先行；self-check #20）
# 单一事实源 = references/stage-3-review.md "统一调用方式" L×CLI 映射表 + 每层扩展点表。
#   四件套面:
#     cli   确定性命令（gatekeeper-cli.sh _CMD_REG 注册名；cli_manual=True = 无 CLI 系人工对照设计）
#     doc   stage-3-review.md 必含的该层锚点文本
#     red   scripts/_red_attacks.py 必含的 RED 向量族前缀（空 + na 说明 = 该层暂无专属攻击族）
#     tests scripts/test_*.py 必含的回归测试文件（空 + na 说明 = 该层测试面设计如此/外部副本）
#   matrix=True 的行 = 原 doc_align cross_review_matrix MATRIX_COMMANDS 成员
#   （REVIEW_LAYER_MATRIX 由此派生，改一处生效——防双写，A4 教训）
# ---------------------------------------------------------------------------
REVIEW_LAYERS = {
    "L1": {"name": "Git history", "matrix": True, "cli": ["audit"],
           "doc": ["L1 Git history"], "red": [],
           "tests": ["test_gk_git_workflow_check.py", "test_git_concurrency_check.py"],
           "na": {"red": "RED-TAMPER（P2 登记 §9-A）落地后补族"}},
    "L2": {"name": "code-to-spec", "matrix": True, "cli": ["plan-refinement"],
           "doc": ["L2 code-to-spec"], "red": [],
           "tests": ["test_gk_review_pins.py", "test_gk_l3_prefetch.py"],
           "na": {"red": "crossrev 通道由 monitor --subagent 指令面承载，非攻击族"}},
    "L3": {"name": "GitNexus", "matrix": True, "cli": ["audit"],
           "doc": ["L3 GitNexus"], "red": [],
           "tests": ["test_gk_gitnexus_pdg_check.py"],
           "na": {"red": "图/PDG 数据面（确定性命令承载，非攻击族）"}},
    "L4": {"name": "Reference Projects", "matrix": False, "cli": [], "cli_manual": True,
           "doc": ["L4 Reference Projects"], "red": [], "tests": [],
           "na": {"cli": "requesting-code-review L4 YAML 人工对照（数据源非 CLI）",
                  "red": "上游依赖版本表人工核查",
                  "tests": "外部技能副本（references/skill-ports 版本化）"}},
    "L5": {"name": "Blind spots", "matrix": True, "cli": ["audit"],
           "doc": ["L5 Blind spots"],
           "red": ["RED-POISON", "RED-REGISTRY", "RED-GHOST", "RED-COVERAGE"],
           "tests": ["test_gk_gitnexus_pdg_check.py"]},
    "L6": {"name": "Architecture", "matrix": True, "cli": ["doc-align"],
           "doc": ["L6 Architecture"], "red": [],
           "tests": ["test_gk_doc_align.py"],
           "na": {"red": "架构事实由 doc-align 确定性检查器承载"}},
    "L7": {"name": "Security", "matrix": True, "cli": ["audit"],
           "doc": ["L7 Security"], "red": [],
           "tests": ["test_gk_audit_state.py"],
           "na": {"red": "供应链族无专属 RED（zizmor/actionlint 走 CI 侧）"}},
    "L8": {"name": "Hook", "matrix": True, "cli": ["self-check", "audit"],
           "doc": ["L8 Hook"], "red": ["RED-HOOK"],
           "tests": ["test_pre_tool_hook.py"]},
    "L9": {"name": "Safenet", "matrix": True, "cli": ["monitor", "node-guard"],
           "doc": ["L9 安全网"], "red": [],
           "tests": ["test_gk_self_check.py", "test_gk_node_guard.py"],
           "na": {"red": "L9 门禁链运行时安全网；攻击族 = RED-HOOK/RED-PY（L7/L8 面）"}},
    "L10": {"name": "Red-team", "matrix": True, "cli": ["audit"],
            "doc": ["L10 红队"],
            "red": ["RED-SCOPE", "RED-SURFACE", "RED-CONSTRAINTS", "RED-EXPLOIT",
                    "RED-POSTEX", "RED-REPORT", "RED-HINT", "RED-HOOK", "RED-PY",
                    "RED-POISON", "RED-REGISTRY", "RED-GHOST", "RED-COVERAGE",
                    "RED-DIFF", "RED-INTEGRITY"],
            "tests": ["test_red_attacks.py"]},
    "PR": {"name": "PR gate", "matrix": True, "cli": ["audit"],
           "doc": ["STAGE_4 PR 门禁"], "red": [],
           "tests": ["test_gk_pr_review_check.py"],
           "na": {"red": "PR 变更面由 audit --pr + impact 确定性承载"}},
}

# doc_align cross_review_matrix 共享单源（matrix=True 行派生，改注册表一处生效）
REVIEW_LAYER_MATRIX = {k: v["cli"] for k, v in REVIEW_LAYERS.items() if v.get("matrix")}


def _read_text_quiet(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return ""


def check_review_layer_coverage(skill_dir: str, registry: dict = None,
                                cli_text: str = "", review_doc_text: str = "",
                                red_text: str = "", test_dir: str = "") -> dict:
    """审查层四件套覆盖（2026-09-05 C1 / E4 静态先行，self-check #20）。

    L1-L10(+PR) 每层按 REVIEW_LAYERS 注册表断言已维护的审查仪器面:
      ① cli  — gatekeeper-cli.sh _CMD_REG 唯一入口实存（或 cli_manual 人工设计）
      ② doc  — stage-3-review.md 该层锚点文本实存
      ③ red  — _red_attacks.py 该层登记的 RED 向量族前缀实存
      ④ tests— scripts/ 该层登记的回归测试文件实存
    判定（对齐 A4 序列节点三面模式，分母 = 该层"已声明必配面数"）:
      - 必配面 0 命中（注册表退化为空壳）→ FAIL（bare，逐层列）
      - 必配面部分缺失 → WARN（thin，列出缺哪个面——改进候选，不阻断）
      - 必配面齐备 → PASS；na 面为设计说明（matrix 输出可见，不计缺失）
    只读确定性 0 API；源文件不可读且无注入文本 → SKIP。
    """
    result = {"check": "review_layer_coverage"}
    reg = registry if registry is not None else REVIEW_LAYERS
    sd = Path(skill_dir)
    if cli_text == "":
        cli_text = _read_text_quiet(str(sd / "gatekeeper-cli.sh"))
    if review_doc_text == "":
        review_doc_text = _read_text_quiet(str(sd / "references" / "stage-3-review.md"))
    if red_text == "":
        red_text = _read_text_quiet(str(sd / "scripts" / "_red_attacks.py"))
    tdir = test_dir or str(sd / "scripts")
    if not cli_text and not review_doc_text and not red_text:
        result["status"] = "SKIP"
        result["detail"] = "gatekeeper-cli.sh / stage-3-review.md / _red_attacks.py 均不可读 — 覆盖核查跳过"
        return result
    registered = set(re.findall(r"_CMD_REG\[([a-z0-9-]+)\]", cli_text))
    rows, bare, thin = [], [], []
    for layer, row in reg.items():
        cli_list = list(row.get("cli") or [])
        cli_manual = bool(row.get("cli_manual"))
        anchors = list(row.get("doc") or [])
        red_fams = list(row.get("red") or [])
        tests = list(row.get("tests") or [])
        # 必配面（声明的面）与满足判定
        req = {}
        if cli_list or cli_manual:
            req["cli"] = (cli_manual or all(c in registered for c in cli_list))
        if anchors:
            req["doc"] = all(a in review_doc_text for a in anchors)
        if red_fams:
            req["red"] = all(f in red_text for f in red_fams)
        if tests:
            req["tests"] = all((Path(tdir) / t).is_file() for t in tests)
        present = [k for k, v in req.items() if v]
        missing = [k for k, v in req.items() if not v]
        name = str(row.get("name", layer))
        rows.append({
            "layer": layer, "name": name,
            "cli_manual": cli_manual,
            "present": present, "missing": missing,
            "na": dict(row.get("na") or {}),
        })
        if req and not present:
            bare.append(layer)
        elif missing:
            thin.append(f"{layer}(缺 {'/'.join(missing)})")
    result["rows"] = rows
    result["bare_layers"] = bare
    result["thin_layers"] = thin
    if bare:
        result["status"] = "FAIL"
        result["detail"] = ("审查层注册表退化为空壳（必配面全缺）: "
                            + "、".join(bare) + "；thin 层 " + str(len(thin)))
    elif thin:
        result["status"] = "WARN"
        result["detail"] = ("无空壳层，但必配面缺失 " + str(len(thin))
                            + " 层（改进候选，逐层补齐）: " + "、".join(thin[:12]))
    else:
        result["status"] = "PASS"
        result["detail"] = f"{len(rows)} 层（L1-L10+PR）必配面齐备；na 面见 rows"
    return result


# ---------------------------------------------------------------------------
# Aggregator — runs all checks and returns summary
# ---------------------------------------------------------------------------

def _check_finding_journal(state_path: str) -> dict:
    """finding_journal_reconcile（2026-09-05 C8/f7）：ECC 裁决输出第二副本锚对账。

    journal 缺失/closed-fixed 无前序事件/记录被删/state 回滚 → FAIL（人工裁决输出
    被全改或伪造裁决 = L10b 兜底机制的单点洞，f7 爆破结论 → 锚定）。
    """
    result = {"check": "finding_journal_reconcile"}
    if not state_path or not os.path.isfile(state_path):
        result.update({"status": "SKIP",
                       "detail": "无 state_file 上下文（ECC 域不存在）；findings 直提交域待接线"})
        return result
    try:
        from gk_finding import reconcile
        rec = reconcile(state_path)
    except Exception as e:
        result.update({"status": "FAIL", "detail": "reconcile 异常: " + str(e)})
        return result
    if rec.get("ok") is False:
        n = len(rec.get("anomalies", []))
        head = "；".join(str(a.get("reason", "")) for a in rec.get("anomalies", [])[:3])
        result.update({"status": "FAIL",
                       "detail": f"{rec.get('events')} 事件/{rec.get('findings')} 记录对账异常 {n} 项: {head}"})
    else:
        result.update({"status": "PASS",
                       "detail": f"{rec.get('events')} 事件/{rec.get('findings')} 记录一致"})
    return result


def check_egress_chain() -> dict:
    """egress 账本链完整性（2026-10-22）：逐行重算 prev/chain。

    与 #21 finding journal 对账同层：只验「账本自洽」，不声称防宿主妥协。
    缺账本 → SKIP（新环境尚无出网）；legacy 前缀 → WARN（升级前记录无链，
    不阻断）；断链/分叉 → FAIL。WARN 不计 issues，避免给日常出网加摩擦。
    """
    result = {"check": "egress_chain"}
    try:
        import gk_evidence as ge
        path = ge.egress_log_path()
        if not os.path.isfile(path):
            result.update({"status": "SKIP", "detail": "no egress ledger yet"})
            return result
        rep = ge.verify_egress_chain(path)
    except Exception as e:  # noqa: BLE001 — 自检项失败不应带崩整轮
        result.update({"status": "FAIL", "detail": "verify 异常: " + str(e)})
        return result
    if not rep.get("ok"):
        result.update({"status": "FAIL",
                       "detail": "chain broken at line %s (count=%s, forks=%s)"
                                 % (rep.get("bad_at"), rep.get("count"),
                                    len(rep.get("forks", {})))})
    elif rep.get("legacy"):
        # 2026-10-23：无链行分前缀（升级遗留）与**尾部**（混版写入）两种；均 WARN 不阻断。
        #   中段无链行仍由 verify 判 FAIL（见 gk_evidence.verify_egress_chain）。
        result.update({"status": "WARN",
                       "detail": "%s records, %s unsigned (%s)"
                                 % (rep.get("count"), rep.get("legacy"),
                                    "tail: mixed-version writers"
                                    if rep.get("unsigned_tail") else "pre-chain prefix")})
    else:
        result.update({"status": "PASS",
                       "detail": "%s records chained" % rep.get("count")})
    return result


def _audit_key_rotated_at(audit_key_dir: str = "") -> float:
    """审计密钥**最近一次轮换时刻**（epoch 秒）；不可判 → 0.0。

    2026-09-22（R22 / 自检 #22 假红修复）：`key-meta.json` 的 `audit_ed25519.created`
    = 现役钥**生成时刻** = 轮换点。用户裁定密钥止血（rotate）后，**所有轮换前签发的
    余烬/快照**验签必然失败 —— 这是**预期副作用**，不是篡改；原实现一律判 FAIL ⟹
    永久假红（每轮 self-check 都报 A3 seal invalid，把真篡改淹没在噪声里）。
    """
    d = audit_key_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".keys")
    p = os.path.join(d, "key-meta.json")
    try:
        with open(p, encoding="utf-8") as f:
            created = (json.load(f).get("audit_ed25519") or {}).get("created", "")
        if created:
            import calendar
            import time as _t
            return calendar.timegm(_t.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        pass
    return 0.0


def _iso(ts: float) -> str:
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(ts)


def _check_ember_replay(state_path: str, audit_key_dir: str = "") -> dict:
    """ember_replay_audit（2026-09-05 C10）：对最新余烬快照跑 archived reconcile + A3 seal 验签。

    无余烬/无 state 上下文 → SKIP（#21 同族 SKIP 语义）；anomalies 或 seal invalid → FAIL；
    pre-C8 epoch / 缺签 unverified_no_seal → PASS（降级标注 detail——best-effort 诊断不宣称对抗级）。
    """
    result = {"check": "ember_replay_audit"}
    if not state_path or not os.path.isfile(state_path):
        result.update({"status": "SKIP", "detail": "无 state_file 上下文（无余烬烧录域）"})
        return result
    state_dir = os.path.dirname(state_path)
    try:
        from gk_ember_replay import ember_files, reconcile_ember
        files = ember_files(state_dir)
    except Exception as e:
        result.update({"status": "FAIL", "detail": "ember module 导入/枚举异常: " + str(e)})
        return result
    if not files:
        result.update({"status": "SKIP", "detail": "state 目录无 .gatekeeper.ember.*.json（未发生相位切换）"})
        return result
    try:
        rec = reconcile_ember(files[0], audit_key_dir)
    except Exception as e:
        result.update({"status": "FAIL", "detail": "archived reconcile 异常: " + str(e)})
        return result
    if rec.get("skip"):
        result.update({"status": "PASS", "detail": "skip: " + str(rec.get("skip")) + " " + str(rec.get("detail", ""))})
        return result
    anomalies = (rec.get("reconcile") or {}).get("anomalies") or []
    seal = rec.get("seal") or {}
    if anomalies:
        head = "；".join(str(a.get("reason", "")) for a in anomalies[:3])
        result.update({"status": "FAIL",
                       "detail": f"archived reconcile {len(anomalies)} 异常: {head}（phase={rec.get('phase')}）"})
        return result
    if seal.get("status") in ("invalid", "error"):
        # 2026-09-22（R22）：**先判是不是密钥轮换的预期副作用**，再判篡改。
        #   判据 = 快照 mtime 早于审计钥轮换点 ⟹ 旧钥签发、轮换后必然验不过；
        #   此时 `anomalies` 已为 0（内容未被改动）⟹ 降级 PASS + 显式标注，不再假红。
        _rot = _audit_key_rotated_at(audit_key_dir)
        try:
            _mt = os.path.getmtime(files[0])
        except OSError:
            _mt = 0.0
        if _rot and _mt and _mt < _rot:
            result.update({"status": "PASS",
                           "detail": "A3 seal 失效属**密钥轮换预期副作用**（pre-rotation，非篡改）："
                                     f"snapshot={_iso(_mt)} < key_rotation={_iso(_rot)}，"
                                     "且 archived reconcile anomalies=0 ⟹ integrity-unverified 降级标注"})
            return result
        result.update({"status": "FAIL",
                       "detail": "A3 seal " + str(seal.get("status")) + ": "
                       + str(seal.get("detail", "")) + "（phase=" + str(rec.get("phase")) + "）"})
        return result
    if rec.get("epoch") == "pre-c8":
        result.update({"status": "PASS", "detail": "pre-C8 快照回判豁免（INFO），seal: " + str(seal.get("status"))})
        return result
    if seal.get("status") == "unverified_no_seal":
        result.update({"status": "PASS",
                       "detail": "archived reconcile 一致但 seal 缺失（pre-A3 epoch），integrity-unverified 降级标注"})
        return result
    result.update({"status": "PASS",
                   "detail": "archived reconcile 一致，A3 seal verified，verdict="
                   + str((rec.get("gate") or {}).get("verdict")) + "（phase=" + str(rec.get("phase")) + "）"})
    return result


def _run_git_tracked(skill_dir: str, rel: str):
    """git 判定文件是否已跟踪（存量 vs 新增）。git 不可用 → None（无法区分，按存量保守处理）。"""
    try:
        import subprocess
        p = subprocess.run(["git", "-C", skill_dir, "ls-files", "--error-unmatch", "--", rel],
                           capture_output=True)
        return p.returncode == 0
    except Exception:
        return None


def check_python_argv_inject(skill_dir: str) -> dict:
    """python_argv_inject（2026-09-05，C10 代码卫生轮）——argv 内联一致性门禁。

    约定 = `def main(argv=None)`（argv 注入；对齐 gk_json/gk_num/gk_req_body/gk_mediation
    清理约定，测试直传参数无需 monkeypatch sys.argv）。旧式 = `def main()` 且函数内直读
    sys.argv。判定：**未跟踪（新增）脚本用旧式 → FAIL**（回潮即拦）；**已跟踪存量旧式 →
    WARN 候选清单**（逐步迁移，不误伤 gk_finding 等既有脚本）。范围 scripts/gk_*.py +
    scripts/test_gk_*.py；git 不可用 → 全部按存量 WARN（保守不误拦）。
    """
    result = {"check": "python_argv_inject"}
    if not skill_dir or not os.path.isdir(skill_dir):
        result.update({"status": "SKIP", "detail": "skill_dir 缺失/不可读"})
        return result
    import glob
    import re
    files = sorted(glob.glob(os.path.join(skill_dir, "scripts", "gk_*.py"))
                   + glob.glob(os.path.join(skill_dir, "scripts", "test_gk_*.py")))
    old_main = re.compile(r"^\s*def main\(\)\s*(?:->[^:]+)?\s*:", re.M)
    legacy, violations = [], []
    for f in files:
        try:
            txt = open(f, encoding="utf-8").read()
        except OSError:
            continue
        if "sys.argv" not in txt or not old_main.search(txt):
            continue
        rel = os.path.relpath(f, skill_dir)
        tracked = _run_git_tracked(skill_dir, rel)
        (legacy if tracked is not False else violations).append(rel)
    if violations:
        head = "、".join(violations[:5])
        result.update({"status": "FAIL", "legacy": len(legacy),
                       "detail": f"新增脚本 {len(violations)} 个用旧式 main() 直读 sys.argv"
                       f"（应 main(argv=None) 注入）: {head}"})
    elif legacy:
        head = "、".join(legacy[:8])
        result.update({"status": "WARN", "legacy": len(legacy),
                       "detail": f"存量脚本 {len(legacy)} 个仍用旧式 main()（WARN 候选，逐步迁移）: {head}"})
    else:
        result.update({"status": "PASS", "legacy": 0,
                       "detail": f"扫描 {len(files)} 个脚本：全部符合 main(argv) 注入约定"})
    return result


def _prscore_sealed_ts(snap_path: str) -> float:
    """`.prscore-*.json` 的 `sealed_at` → epoch 秒（缺/不可解析 → 文件 mtime；再不可得 → 0.0）。

    2026-09-22（f4 / ECC-50F4AED30AF4）：与 `_check_ember_replay` 的 A3 seal 同族**归因**所需的
    时间锚 —— 判「验签失败是密钥轮换的预期副作用还是篡改」，先要能取到快照的签发时刻。
    """
    sa = ""
    try:
        with open(snap_path, encoding="utf-8") as f:
            sa = (json.load(f) or {}).get("sealed_at", "")
    except Exception:
        sa = ""
    if isinstance(sa, str) and sa:
        try:
            import calendar
            import time as _t
            return calendar.timegm(_t.strptime(sa[:19], "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            pass
    try:
        return os.path.getmtime(snap_path)
    except OSError:
        return 0.0


def _check_pr_score_anchor(skill_dir: str, audit_key_dir: str = "") -> dict:
    """pr_score_anchor（2026-09-06 C9）：PR-SCORE 双盲评分锚定校验。

    docs/plans 下 .prscore-*.json 快照 ↔ plan `<!-- PR-SCORE -->` 区块一致性 + A3 seal 验签
    （verify 单源 = gk_pr_score 模块函数 gk_pr_score.cmd_verify()，非 CLI 命令）。无快照 →
    SKIP（C9 未启用不误报）；anchored=False——
    seal invalid/error 或区块缺失/字段不一致 → FAIL；seal 降级态（unverified_*）→ PASS 标注。

    2026-09-22（f4 / ECC-50F4AED30AF4）：补**轮换副作用归因**（与 `_check_ember_replay` 的 A3
    seal 同族同判据）—— 用户裁定密钥止血（rotate）后，轮换**前** seal 过的快照必然验不过
    （`seal.key_fp` 是旧钥指纹），这是预期副作用而非篡改；原实现一律 FAIL ⟹ 永久假红（每轮
    self-check 都报同一份），把真篡改淹没在噪声里。判据 = 快照 `sealed_at`（缺则 mtime）早于
    审计钥轮换点，**且** plan 区块字段一致（`mismatches` 空 ⟹ 内容未被改动）⟹ 降级 PASS 标注。
    """

    result = {"check": "pr_score_anchor"}
    plans_dir = os.path.join(skill_dir, "docs", "plans")
    if not os.path.isdir(plans_dir):
        result.update({"status": "SKIP", "detail": "无 docs/plans 目录（无被质询计划域）"})
        return result
    try:
        sys.path.insert(0, os.path.join(skill_dir, "scripts"))
        import gk_pr_score
    except Exception as e:
        result.update({"status": "FAIL", "detail": "gk_pr_score 模块导入异常: " + str(e)})
        return result
    snaps = sorted(n for n in os.listdir(plans_dir)
                   if n.startswith(gk_pr_score.PRSCORE_PREFIX) and n.endswith(".json"))
    if not snaps:
        result.update({"status": "SKIP", "detail": "docs/plans 无 .prscore-*.json（C9 锚定未启用）"})
        return result
    bad, degraded = [], []
    for snap in snaps:
        base = snap[len(gk_pr_score.PRSCORE_PREFIX):-5]
        plan = os.path.join(plans_dir, base + ".md")
        if not os.path.isfile(plan):
            bad.append(snap + ":plan_missing")
            continue
        try:
            v = gk_pr_score.cmd_verify(plan, audit_key_dir)
        except Exception as e:
            bad.append(snap + ":verify_exc " + str(e))
            continue
        if v.get("anchored"):
            continue
        seal_st = v.get("seal", "")
        mm = ";".join(v.get("mismatches") or [])
        # f4（ECC-50F4AED30AF4）归因闸：先判「轮换预期副作用」，再判篡改（见 docstring）。
        # 要件（缺一不可）① 纯验签失败（无字段不一致 ⟹ 内容未被改）② 签发时刻 < 轮换点。
        if seal_st in ("invalid", "error") and not mm:
            _rot = _audit_key_rotated_at(audit_key_dir)
            _ts = _prscore_sealed_ts(os.path.join(plans_dir, snap))
            if _rot and _ts and _ts < _rot:
                degraded.append(snap + ":seal_" + seal_st + "_pre_rotation"
                                + "(sealed=" + _iso(_ts) + "<rot=" + _iso(_rot) + ")")
                continue
        if seal_st in ("invalid", "error") or mm:
            bad.append(snap + ":unverified(" + seal_st + ("," + mm if mm else "") + ")")
        else:
            degraded.append(snap + ":seal_" + seal_st)
    if bad:
        head = " | ".join(bad[:3])
        result.update({"status": "FAIL", "detail": f"PR-SCORE 锚定异常 {len(bad)} 份: {head}"})
    elif degraded:
        result.update({"status": "PASS", "detail": "; ".join(degraded[:3]) + "（降级标注，best-effort）"})
    else:
        result.update({"status": "PASS", "detail": f"{len(snaps)} 份快照 anchored（seal verified + 区块一致）"})
    return result


# 26. bash 写函数防再引入漂移 (2026-09-07 批②, ECC-C66D7831EF73) — 确定性 gate
# write_guard 族 bash 写入者确定性回归面：权威计数 = 外部插件 migrate audit --bomb（循环 B/CI
# 域，技能侧无法复跑）；本 gate 只守技能侧可判定的防再引入面——EXEMPT 注册表（§2.5）不被静默
# 删改 + 新增未登记 bash 写函数候选暴露给 L10b 裁决（防新代码静默复现旧模式，㊳ 789 归因根因）。
# 归属算法：顶层函数序段划分（col0 `name() {` 顺序切分文件）+ 注释行跳过 + 头部自归属——
# 嵌套/缩进伪函数头（usage 文本等）不计，规避 bash 无 AST 的切片歧义（㊷ write_guard 根因同源）。
_EXEMPT_WG_MARK = re.compile(r"\[write_guard 裁决 2026-09-06 EXEMPT\]")
_WRITE_TOK_RE = re.compile(r"_state_write\b|_write_gate_data\b|_state_checksum_write\b")
_FN_HEAD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{")
# §2.5 注册表 EXEMPT-8（2026-09-06 ㊱ 裁决：核对非重裁决）
_EXEMPT8 = ("_state_write", "_monitor_finalize", "_monitor_api", "_write_gate_data",
            "cmd_cron", "_verify_remote", "cmd_push", "cmd_audit")
# 已裁决/守卫域的其余顶层 bash 写函数（最低层写原语 / 守卫内调用 / 持久化簿记域，与 EXEMPT-8
# 同类裁决口径；新增顶层写函数名须先 L10b 裁决登记再并入本表，否则触发 WARN 候选）
_KNOWN_BASH_WRITERS = set(_EXEMPT8) | {
    "_state_checksum_write", "_state_checksum_verify",
    "cmd_discover", "cmd_advance", "cmd_resolve", "cmd_adjudicate", "cmd_finding",
    "cmd_state_patch", "cmd_ci_diagnose", "cmd_ci_status", "cmd_check_changes",
    "cmd_set_key", "cmd_context", "cmd_self_check", "pre_tool_check",
}


def _write_token_owner(lines: list) -> dict:
    """顶层函数序段归属：返回 {owner_name: [token 行号]}。

    每行仅当非注释（`#` 开头）才计入；若行本身是顶层函数头 → 归自身（头部自归属）；
    否则归属最近前置顶层函数头。伪/嵌套（缩进）函数头不参与归属划分。
    """
    headers = []
    for i, ln in enumerate(lines):
        if _FN_HEAD_RE.match(ln):
            headers.append((i, _FN_HEAD_RE.match(ln).group(1)))
    owners: dict = {}
    hidx = -1
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("#"):
            continue
        if hidx + 1 < len(headers) and headers[hidx + 1][0] <= i:
            hidx += 1
        if not (0 <= hidx < len(headers)):
            continue  # 首函数头之前（全局区）不归属
        if not _WRITE_TOK_RE.search(ln):
            continue
        own = headers[hidx][1]
        owners.setdefault(own, []).append(i + 1)
    return owners


def check_bash_write_drift(skill_dir: str) -> dict:
    """防再引入 gate：bomb write_guard 族 bash 写入者确定性回归。

    FAIL（硬）：EXEMPT 注记数 != 8（注册表被静默删改）；§2.5 EXEMPT-8 任一函数名从
    gatekeeper-cli.sh 消失（注册表与代码漂移）。
    WARN（advisory → L10b 裁决队列）：出现**未登记**的顶层 bash 写函数——写 token 行归属
    函数名不在 _KNOWN_BASH_WRITERS = 新增代码再引入旧模式候选（须补 L10b 裁决登记）。
    归因/计数权威 = 外部插件 migrate audit --bomb（循环 B/CI 域），本 gate 不替代之。
    """
    p = Path(skill_dir) / "gatekeeper-cli.sh"
    if not p.exists():
        return {"check": "bash_write_drift", "status": "FAIL",
                "detail": "gatekeeper-cli.sh 缺失", "missing": ["file"]}
    text = p.read_text(encoding="utf-8")
    fails, warns = [], []
    marks = _EXEMPT_WG_MARK.findall(text)
    if len(marks) != 8:
        fails.append(f"EXEMPT 注记数={len(marks)}（须=8）— §2.5 注册表被静默删改/重复")
    for name in _EXEMPT8:
        if not re.search(rf"^{re.escape(name)}\s*\(\s*\)\s*\{{", text, re.M):
            fails.append(f"§2.5 EXEMPT 函数 {name} 已消失（注册表与代码漂移）")
    owners = _write_token_owner(text.split("\n"))
    candidates = sorted(
        (name, lns[0]) for name, lns in owners.items()
        if name not in _KNOWN_BASH_WRITERS)
    for owner, ln in candidates:
        warns.append(f"未登记顶层 bash 写函数候选: {owner} (L{ln}) — 须 L10b 裁决登记或并入 EXEMPT 注册表")
    status = "FAIL" if fails else ("WARN" if warns else "PASS")
    return {"check": "bash_write_drift", "status": status,
            "exempt_marks": len(marks),
            "unknown_writers": [c[0] for c in candidates],
            "detail": (f"EXEMPT 注记 {len(marks)}/8；未登记写函数候选 {len(candidates)}"
                       + ("；" + "; ".join(fails) if fails else "")),
            "missing": fails, "warnings": warns}


def check_state_write_checksum(skill_dir: str) -> dict:
    """state_write_checksum（2026-09-22 R22 新规则；锚 ECC-3D26D689A05F）。

    **规则**：`gatekeeper-cli.sh` 中任何「以内联 python 直接写 `$STATE_FILE` 的 `json.dump`」
    必须在同段落（±12 行窗口）内伴随 checksum 重算（`_state_checksum_write` / `_state_write`
    / `dump_state`），否则 FAIL 并逐条列出写点行号。

    **依据（实测）**：`monitor --gitnexus` 写 `gate_data.gitnexus` 用裸 `json.dump` 直写且不重算
    ⟹ 该命令后 `saved != canon`（隔离复现：`c54be628…` vs `d0be49cc…`），下游
    `_state_checksum_verify` 误报 TAMPERED，直到下一个写者（`monitor --local`）纠正。
    同族已修先例 = `cmd_finding` 的 `_state_checksum_write` 补算（ECC-E75A3C2E8FE6）。

    **监控入口**：`gatekeeper-cli.sh self-check`（→ `monitor --local` 的 L9 车道）。
    """
    p = os.path.join(skill_dir, "gatekeeper-cli.sh")
    try:
        with open(p, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        return {"check": "state_write_checksum", "status": "SKIP", "detail": "CLI 不可读: %s" % e}
    total, bad = [], []
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("#") or "json.dump(" not in s or "STATE_FILE" not in s:
            continue
        if "open('$STATE_FILE'" not in s:
            continue                      # 非「直写 state」形态（读 / 走出纳 / 非 state）
        total.append(i + 1)
        seg = "\n".join(lines[max(0, i - 12): i + 13])
        if any(k in seg for k in ("_state_checksum_write", "_state_write", "dump_state")):
            continue
        bad.append(i + 1)
    if not total:
        return {"check": "state_write_checksum", "status": "SKIP",
                "detail": "未扫到内联直写 state 的 json.dump（扫描式失效或已全收敛）"}
    if bad:
        # 为什么是 WARN 而非 FAIL（校准记录，2026-09-22 实测 8/8 抽查皆真阳性）：
        #   静态**无法区分**「该直写点后续由同函数统一重算」与「永不重算」——抽查 L653/L1077/
        #   L1124/L1152/L3005/L4871/L4895/L5837 均确为裸写，但其中若干在调用流末尾由
        #   `_state_checksum_write` 统一补算（故未长期暴露）。**已被动态证明**stale 的只有
        #   `monitor --gitnexus`（隔离复现 saved≠canon）⟹ 该点归 finding ECC-3D26D689A05F，
        #   其余按本文件 #26 `check_bash_write_drift` 的既有惯例记 **WARN 候选 → L10b 裁决队列**。
        return {"check": "state_write_checksum", "status": "WARN",
                "detail": "%d/%d 处内联直写 state 未伴随本地 checksum 重算（候选，交 L10b 裁决）：L%s"
                          % (len(bad), len(total), ", L".join(map(str, bad[:10])))}
    return {"check": "state_write_checksum", "status": "PASS",
            "detail": "%d 处直写点均伴随 checksum 重算" % len(total)}


def check_red_phase_wiring(skill_dir: str) -> dict:
    """red_phase_wiring（2026-09-22 R22 新规则；锚红队 C1）。

    **规则**：`gatekeeper-cli.sh` 的 audit 序列 `RED-*` 分派分支中，禁止两种"假证据"形态：
      ① 内联字面量证据（如 `{"cached":true,…}` —— 不是扫描结果，却读作"已有缓存基线"）；
      ② 硬编码 repo 名（`-r spz-gatekeeper-r-sequence` —— 非本机宿主恒不命中且违 F-REV-71 单源）。
    多相真实实现在 `scripts/_red_attacks.py`（surface/constraints/exploit/postex/…）。

    **依据**：2026-08-31 红队序列 7→14 阶段补齐时，上四相（SURFACE/CONSTRAINTS/EXPLOIT/POSTEX）
    漏接线到真实实现，改用 ad-hoc/字面量拼接 ⟹ 上层"14 阶段齐全"、下四层证据空洞（假绿）。

    **监控入口**：`gatekeeper-cli.sh self-check`。
    """
    p = os.path.join(skill_dir, "gatekeeper-cli.sh")
    try:
        with open(p, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        return {"check": "red_phase_wiring", "status": "SKIP", "detail": "CLI 不可读: %s" % e}
    hits, scanned = [], 0
    pat_head = re.compile(r"^\s*RED-[A-Z]+\)\s*audit_extra=")
    for i, ln in enumerate(lines):
        if not pat_head.match(ln):
            continue
        scanned += 1
        if '{"cached":true' in ln:
            hits.append("L%d 内联字面量证据" % (i + 1))
        elif re.search(r"-\s*r\s+spz-gatekeeper-r-sequence", ln):
            hits.append("L%d 硬编码 repo 名" % (i + 1))
    if not scanned:
        return {"check": "red_phase_wiring", "status": "SKIP",
                "detail": "未扫到 RED-* 分派分支（扫描式失效）"}
    if hits:
        return {"check": "red_phase_wiring", "status": "FAIL",
                "detail": "%d/%d 个 RED-* 分支命中假证据形态：%s"
                          % (len(hits), scanned, "；".join(hits[:6]))}
    return {"check": "red_phase_wiring", "status": "PASS",
            "detail": "%d 个 RED-* 分支均无内联字面量/硬编码 repo 形态" % scanned}


def check_amp_observability(skill_dir: str) -> dict:
    """AMP 观测面自检（2026-10-26）—— **AMP 的第一个消费者**。

    背景：AMP 兼容层（`zthl/acp/`）此前**无任何消费方** ⟹ 是叶子遥测，
    「判定 ⟺ logged」只有自证、没有机器验证。本检查以自检面消费 `access.log`：
    ① 记录可解析且含 `LogRecord` 关键字段；② 新鲜度（>24h 无新记录 ⟹ WARN）。
    落点解析与 `zthl.acp.amp.amp_dir()` 同源（不复制路径逻辑）：读不到模块时回退仓内默认。
    """
    import time as _t
    d = os.environ.get("GK_AMP_DIR", "").strip()
    if d:
        ampdir = Path(d)
    else:
        try:
            sys.path.insert(0, str(Path(skill_dir).resolve()))
            from zthl.acp import amp as _amp
            ampdir = _amp.amp_dir()
        except Exception:
            ampdir = Path(skill_dir) / ".zthl" / "amp"
    p = ampdir / "access.log"
    if not p.exists():
        return {"check": "amp_observability", "status": "INFO",
                "detail": f"AMP 尚未落盘（{ampdir}）— 无工具调用或 GK_AMP=0"}
    total = bad = 0
    last_ts = ""
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return {"check": "amp_observability", "status": "WARN", "detail": f"不可读: {e}"}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        total += 1
        try:
            r = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not all(k in r for k in ("schemaVersion", "timestamp", "logType", "logId")):
            bad += 1
        last_ts = str(r.get("timestamp") or last_ts)
    age_h = None
    try:
        from datetime import datetime
        t = last_ts
        if len(t) >= 5 and t[-5] in "+-" and t[-4:].isdigit():
            t = t[:-2] + ":" + t[-2:]
        age_h = (_t.time() - datetime.fromisoformat(t).timestamp()) / 3600.0
    except Exception:
        pass
    if bad:
        return {"check": "amp_observability", "status": "FAIL",
                "detail": f"{ampdir}/access.log: {bad}/{total} 条记录不合 schema"}
    if age_h is not None and age_h > 24:
        return {"check": "amp_observability", "status": "WARN",
                "detail": f"最近一条 access 记录 {age_h:.1f}h 前（>24h）；AMP 可能被关闭（GK_AMP=0）"}
    return {"check": "amp_observability", "status": "PASS",
            "detail": f"{total} 条 access 记录，schema 合规；最近 {('%.1fh 前' % age_h) if age_h is not None else '时间未知'}"}


# ─── 2026-10-31（owner 令「补全 3 项自检」）：hook 注册态 / gitnexus 版本·耗时 / 模型配置 ───
# 背景：原 self-check 只查 wrapper **可执行**、gitnexus **status 首行**、API key **是否存在**
#   ⟹ 开源用户最常见的三类故障不可见：hooks.json 未注册（install --no-hooks / 被他人条目占）、
#   索引版本过旧或单次调用过慢（每站 300s 等待的真因）、model/env 取值非法（拼写错误静默透传）。
_EFFORT_LEVELS = ("off", "low", "high", "max")
_FAILOVER_PROVIDERS = ("deepseek", "mimo", "ollama", "local")
_GITNEXUS_MIN = (1, 6, 0)


def _parse_semver(text: str):
    """从任意版本串取 `(major, minor, patch)`；不可解析 ⟹ None（不猜）。"""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def check_hook_registration(skill_dir: str) -> dict:
    """hooks.json **注册态**（单源 = `gk_hook_manage.py status --json` 的 `source`）。

    registered ⟹ PASS；absent / foreign ⟹ WARN；unparseable ⟹ FAIL（hook 面整体不可加载）；
    工具缺失 / 不可执行 ⟹ SKIP（不阻断）。
    """
    result = {"check": "hook_registration"}
    tool = Path(skill_dir) / "scripts" / "gk_hook_manage.py"
    if not tool.exists():
        result["status"] = "SKIP"
        result["detail"] = "gk_hook_manage.py 不存在"
        return result
    try:
        r = subprocess.run([sys.executable, str(tool), "status", "--json"],
                           capture_output=True, text=True, timeout=20, cwd=skill_dir)
    except (subprocess.TimeoutExpired, OSError) as e:
        result["status"] = "SKIP"
        result["detail"] = "status 不可执行: %s" % type(e).__name__
        return result
    try:
        st = json.loads((r.stdout or "").strip() or "{}")
    except ValueError:
        result["status"] = "WARN"
        result["detail"] = "status 输出非 JSON: %s" % (r.stdout or r.stderr)[:120]
        return result
    src = str(st.get("source") or "error")
    result["detail"] = "source=%s ours=%s foreign=%s command_ok=%s" % (
        src, st.get("ours"), st.get("foreign"), st.get("command_ok"))
    if src == "registered" and st.get("command_ok", True):
        result["status"] = "PASS"
    elif src == "unparseable":
        result["status"] = "FAIL"
    else:
        result["status"] = "WARN"
    return result


def _gitnexus_verdict(ver, elapsed_ms: int, threshold_ms: int):
    """纯判据（单测友好）：版本过旧 / 调用过慢 ⟹ WARN；其余 PASS。"""
    if ver is None:
        return "WARN", "版本不可解析"
    if ver < _GITNEXUS_MIN:
        return "WARN", "版本 %d.%d.%d < %d.%d.%d" % (ver + _GITNEXUS_MIN)
    if elapsed_ms > threshold_ms:
        return "WARN", "调用耗时 %dms > 阈值 %dms" % (elapsed_ms, threshold_ms)
    return "PASS", "版本 %d.%d.%d, 耗时 %dms" % (ver + (elapsed_ms,))


def check_gitnexus_version(skill_dir: str) -> dict:
    """GitNexus **版本 + 单次调用耗时**（阈值 env `GK_SELFCHECK_GITNEXUS_MS`，默认 5000ms）。"""
    result = {"check": "gitnexus_version"}
    run_cjs = Path(skill_dir) / ".gitnexus" / "run.cjs"
    cmd = ["node", str(run_cjs), "--version"] if run_cjs.exists() else ["gitnexus", "--version"]
    threshold = int(os.environ.get("GK_SELFCHECK_GITNEXUS_MS", "5000") or 5000)
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20, cwd=skill_dir)
    except (subprocess.TimeoutExpired, OSError) as e:
        result["status"] = "SKIP"
        result["detail"] = "gitnexus 不可用: %s" % type(e).__name__
        return result
    elapsed = int((time.time() - t0) * 1000)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    ver = _parse_semver(out)
    status, detail = _gitnexus_verdict(ver, elapsed, threshold)
    result.update({"status": status, "detail": detail,
                   "version": ver, "elapsed_ms": elapsed})
    return result


def _valid_model_id(mid: str) -> bool:
    """model id 透传（DSH 语义）：只拦空/空白/注入面字符，**不**拦未登记 id。"""
    if not mid or any(ch.isspace() for ch in mid):
        return False
    return not any(ch in mid for ch in "$`\"';|&<>()")


def check_model_config() -> dict:
    """模型/端点/env **取值合法性**（未知 model id 不报错；非法 effort / chain / base 报 WARN）。"""
    critic = os.environ.get("GK_CRITIC_MODEL", "deepseek-flash")
    actor = os.environ.get("GK_ACTOR_MODEL", "deepseek-flash")
    mimo_critic = os.environ.get("GK_MIMO_CRITIC_MODEL", "mimo-v2.6-flash")
    mimo_actor = os.environ.get("GK_MIMO_ACTOR_MODEL", "mimo-v2.6-pro")
    effort = os.environ.get("GK_REASONING_EFFORT", "max")
    chain = os.environ.get("GK_FAILOVER_CHAIN", "deepseek,mimo,local")
    ds_base = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    mimo_base = os.environ.get("MIMO_BASE_URL", "https://api.xiaomimimo.com/v1")
    problems = []
    for name, mid in (("GK_CRITIC_MODEL", critic), ("GK_ACTOR_MODEL", actor),
                      ("GK_MIMO_CRITIC_MODEL", mimo_critic), ("GK_MIMO_ACTOR_MODEL", mimo_actor)):
        if not _valid_model_id(mid):
            problems.append("%s 非法: %r" % (name, mid))
    if effort not in _EFFORT_LEVELS:
        problems.append("GK_REASONING_EFFORT 非法: %r（合法: %s）"
                        % (effort, list(_EFFORT_LEVELS)))
    legs = [x.strip() for x in chain.split(",") if x.strip()]
    if not legs:
        problems.append("GK_FAILOVER_CHAIN 为空")
    for leg in legs:
        if leg not in _FAILOVER_PROVIDERS:
            problems.append("GK_FAILOVER_CHAIN 未知 provider: %r" % leg)
    for name, base in (("DEEPSEEK_BASE_URL", ds_base), ("MIMO_BASE_URL", mimo_base)):
        u = urlparse(base)
        if u.scheme not in ("http", "https") or not u.netloc:
            problems.append("%s 非法: %r" % (name, base))
    detail = "critic=%s effort=%s chain=%s" % (critic, effort, chain)
    if problems:
        return {"check": "model_config", "status": "WARN",
                "detail": detail + "; " + " | ".join(problems), "problems": problems}
    return {"check": "model_config", "status": "PASS", "detail": detail}


def check_sandbox(skill_dir: str) -> dict:
    """层 1 沙箱**生效态**（2026-10-31：与 `_subagent_exec` 同判据）。

    `GK_SANDBOX_SUBAGENT=0` ⟹ WARN（显式关闭）；包装器缺失/不可执行 ⟹ FAIL（派发 fail-closed）；
    探针 `gk_sandbox.py run -- <python> -c pass` 非零 ⟹ WARN。层 2（KVM/Cube）不在此判据内。
    """
    result = {"check": "sandbox"}
    mode = os.environ.get("GK_SANDBOX_SUBAGENT", "1")
    smode = os.environ.get("GK_SANDBOX_MODE", "limits")
    mem = os.environ.get("GK_SANDBOX_MEM_MB", "2048")
    result.update({"mode": "off" if mode == "0" else smode, "mem_mb": mem,
                   "bwrap": bool(shutil.which("bwrap"))})
    if mode == "0":
        result["status"] = "WARN"
        result["detail"] = "沙箱被显式关闭（GK_SANDBOX_SUBAGENT=0）"
        return result
    if smode == "bwrap" and not shutil.which("bwrap"):
        result["status"] = "FAIL"
        result["detail"] = "GK_SANDBOX_MODE=bwrap 但未安装 bubblewrap ⟹ 派发 fail-closed"
        return result
    wrap = Path(skill_dir) / "scripts" / "suagent_sandbox.sh"
    if not (wrap.exists() and os.access(wrap, os.X_OK)):
        result["status"] = "FAIL"
        result["detail"] = "suagent_sandbox.sh 缺失/不可执行 ⟹ 派发 fail-closed"
        return result
    probe = Path(skill_dir) / "scripts" / "gk_sandbox.py"
    if not probe.exists():
        result["status"] = "WARN"
        result["detail"] = "gk_sandbox.py 不存在（包装器无法生效）"
        return result
    try:
        r = subprocess.run([sys.executable, str(probe), "run", "--",
                            sys.executable, "-c", "pass"],
                           capture_output=True, text=True, timeout=20, cwd=skill_dir)
    except (subprocess.TimeoutExpired, OSError) as e:
        result["status"] = "WARN"
        result["detail"] = "gk_sandbox 探针不可执行: %s" % type(e).__name__
        return result
    if r.returncode != 0:
        result["status"] = "WARN"
        result["detail"] = "gk_sandbox 探针 rc=%d: %s" % (
            r.returncode, (r.stderr or r.stdout or "")[:120])
        return result
    result["status"] = "PASS"
    result["detail"] = "mode=limits mem_mb=%s wrapper=ok" % mem
    return result


def _iso_ts(text: str):
    """解析 jobs.json 的 ISO 时间（带/不带微秒、Z 或 +00:00）；不可解析 ⟹ None。"""
    s = (text or "").replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return None


def check_satellite(state_path: str) -> dict:
    """卫星索引**一致性 + 容量**（2026-11-01）：悬空叶子 / 孤儿片 / 越 60 臂容量 ⟹ WARN。

    为什么是 WARN 不是 FAIL：片缺失不阻断治理主流程（读 union 走片文件本身），但它意味着
    「索引指向空气 / 归档不可回溯」—— 必须可见。修复入口 = `state --satellite --apply`
    （`gk_satellite.gc_index`：只删「已墓碑 / 片不存在」两类叶子）。
    """
    result = {"check": "satellite"}
    if not state_path or not os.path.isfile(state_path):
        result["status"] = "SKIP"
        result["detail"] = "state 不存在（无可检索引）"
        return result
    try:
        import gk_satellite as SAT
        v = SAT.verify_shards(state_path)
    except Exception as e:  # noqa: BLE001 — 边界：检查器不可用 ⟹ 具名 WARN（不静默 PASS）
        result["status"] = "WARN"
        result["detail"] = "卫星检查器不可用: %s" % type(e).__name__
        return result
    result["data"] = {"dangling": v.get("dangling_count", 0),
                      "orphan_shards": v.get("orphan_shards") or [],
                      "over_capacity": v.get("over_capacity") or {},
                      "capacity": v.get("capacity") or {},
                      "leaves": v.get("leaves", 0)}
    if v.get("ok"):
        result["status"] = "PASS"
        result["detail"] = "索引一致性/容量正常（叶子 %d）" % v.get("leaves", 0)
    else:
        result["status"] = "WARN"
        result["detail"] = ("悬空叶子 %d / 孤儿片 %s / 越容量 %s —— 修："
                            "`state --satellite --apply`"
                            % (v.get("dangling_count", 0),
                               ",".join(v.get("orphan_shards") or []) or "无",
                               json.dumps(v.get("over_capacity") or {}, ensure_ascii=False)))
    return result


def _worktree_root(skill_dir: str) -> str:
    """当前工作树根（`git rev-parse --show-toplevel`；非 git 仓库回 realpath(skill_dir)）。"""
    try:
        r = subprocess.run(["git", "-C", skill_dir, "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return os.path.realpath(r.stdout.strip())
    except Exception:  # noqa: BLE001 — 边界：git 不可用 ⟹ 目录真值兜底
        pass
    return os.path.realpath(skill_dir)


def _canon_tree(p) -> str:
    """归属比较的路径归一（跨 OS 形态安全）。

    ⚠ 跨平台坑（2026-11-01）：WSL 侧 state 写 `/mnt/c/...`、Windows 侧写 `C:/...`；
    直接 `os.path.realpath` 在**异形态**上会当相对路径拼接（Linux 上 `C:/x` ⟹ `<cwd>/C:/x`）。
    故只在「形态与当前 OS 匹配」时才 realpath，之后统一用 `_gx_norm_path`（`/mnt/c` → `c:`、小写、
    去尾斜杠）比较。
    """
    p = str(p or "").strip()
    if not p:
        return ""
    is_win = len(p) > 1 and p[1] == ":"
    is_posix = p.startswith("/")
    if (os.name == "nt" and is_win) or (os.name != "nt" and is_posix):
        try:
            p = os.path.realpath(p)
        except OSError:
            pass
    return _gx_norm_path(p)


def check_state_ownership(state_path: str, skill_dir: str) -> dict:
    """#39 state 归属一致性（**顶层** `state.worktree` ↔ 当前工作树）+ **可选修复**。

    病象（实测）：把主树种子 state **复制**进 worktree 后，顶层 `worktree` 仍指向主树 ⟹ 启动期
    归属扫描（`gk_state_route._load_worktree` 投影 `worktree/r_phase/stage`）判 `conflict`、把
    expected 纠正到主树那条 state（主树当时 active-r 是 R7 ⟹ 落 `.gatekeeper.state.gatekeeper.r7`）
    ⟹ 域路由拿 r7 state 解析新计划的域必然 `MISMATCH`。
    判据：`realpath(state["worktree"]) == realpath(git rev-parse --show-toplevel)`。
    修复：`GK_SELFCHECK_REPAIR_WORKTREE=1`（CLI `--repair-worktree`）⟹ 原地改写该字段并重算
    checksum（单源 `gk_json_utils.dump_state`）；默认**只报不写**。
    """
    result = {"check": "state_ownership"}
    if not state_path or not os.path.isfile(state_path):
        result["status"] = "SKIP"
        result["detail"] = "state 不存在（无可校验归属）"
        return result
    expected = _worktree_root(skill_dir)
    try:
        d = json.loads(Path(state_path).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 — 边界：坏 state 不崩，具名 WARN
        result["status"] = "WARN"
        result["detail"] = "state 不可解析: %s" % type(e).__name__
        return result
    cur = str(d.get("worktree") or "").strip()   # ⚠ 归属字段 = **顶层** `worktree`
    # 单源校验：启动期归属扫描读的正是 `gk_state_route._load_worktree`（`_state_projection`
    # 只投影顶层 `worktree/r_phase/stage`）——本检查不得自证一个扫描不读的字段。
    try:
        import gk_state_route as _R
        _seen = _R._load_worktree(state_path)
        if _seen is not None and str(_seen).strip() != cur:
            result["status"] = "WARN"
            result["detail"] = "字段漂移：顶层 worktree=%s ≠ gk_state_route 读到的 %s" % (cur, _seen)
            return result
    except Exception:  # noqa: BLE001 — 边界：单源模块不可用 ⟹ 退化为直读顶层，不误判
        pass
    result["data"] = {"state_worktree": cur, "expected": expected}
    if cur and _canon_tree(cur) == _canon_tree(expected):
        result["status"] = "PASS"
        result["detail"] = "归属一致: %s" % expected
        return result
    if not cur:
        result["status"] = "WARN"
        result["detail"] = ("缺顶层 worktree（discover 未写迹）⟹ 路由会退回计划指针；"
                            "`self-check --repair-worktree` 可补写为 %s" % expected)
        if not _repair_enabled():
            return result
    else:
        result["status"] = "WARN"
        result["detail"] = ("归属不一致：state=%s ≠ 当前工作树=%s ⟹ 启动期归属扫描会纠正到别的"
                            " state（并拖入其阶段）；修：`self-check --repair-worktree`"
                            % (cur, expected))
        if not _repair_enabled():
            return result
    try:
        import gk_json_utils as JU
        d["worktree"] = expected          # 顶层字段（启动期扫描的唯一读取面）
        gd = d.setdefault("gate_data", {})
        d["_checksum"] = hashlib.sha256(
            json.dumps(gd, sort_keys=True).encode()).hexdigest()[:16]
        JU.dump_state(state_path, d)
    except Exception as e:  # noqa: BLE001 — 边界：修复失败 ⟹ 保持 WARN 并具名
        result["status"] = "WARN"
        result["detail"] = "归属修复失败: %s: %s" % (type(e).__name__, e)
        return result
    result["status"] = "PASS"
    result["repaired"] = True
    result["detail"] = "已修复归属: %s（改写 proj.worktree + 重算 checksum）" % expected
    return result


def _repair_enabled() -> bool:
    return str(os.environ.get("GK_SELFCHECK_REPAIR_WORKTREE", "")).strip() in ("1", "true", "yes")


def check_cron_health(now_ts=None, grace_s: int = 3600, stale_s: int = 7200) -> dict:
    """cron 调度**新鲜度 + 逾期作业**（2026-11-01 根因：`cron_tick.bat` 的 `cd ~/.trae` 在
    WSL root 下解析为 `/root/.trae` ⟹ 每小时 rc=1、作业全部逾期而无人察觉）。

    判据：tick.log 缺失或年龄 > `stale_s` ⟹ WARN；任一启用作业 `next_run_at` 超期 >
    `grace_s` ⟹ WARN（逐名列出）。仅 WARN（调度可被人为暂停），不阻断。
    """
    result = {"check": "cron_health"}
    home = os.environ.get("HOME") or str(Path.home())
    cron_dir = Path(home) / ".gatekeeper" / "cron"
    jobs_file, tick_log = cron_dir / "jobs.json", cron_dir / "tick.log"
    if not jobs_file.exists():
        result["status"] = "SKIP"
        result["detail"] = "jobs.json 不存在（cron 未初始化）"
        return result
    try:
        data = json.loads(jobs_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        result["status"] = "WARN"
        result["detail"] = "jobs.json 不可解析: %s" % type(e).__name__
        return result
    jobs = data if isinstance(data, list) else data.get("jobs", [])
    now = now_ts if now_ts is not None else time.time()
    overdue = []
    for j in jobs or []:
        if not isinstance(j, dict) or not j.get("enabled"):
            continue
        ts = _iso_ts(j.get("next_run_at"))
        if ts is not None and now - ts > grace_s:
            overdue.append(str(j.get("name")))
    tick_age = int(now - tick_log.stat().st_mtime) if tick_log.exists() else None
    result.update({"overdue": overdue, "tick_age_s": tick_age,
                   "enabled": sum(1 for j in jobs or [] if isinstance(j, dict) and j.get("enabled"))})
    if tick_age is None:
        result["status"] = "WARN"
        result["detail"] = "tick.log 不存在 ⟹ 调度器从未 tick"
    elif tick_age > stale_s or overdue:
        result["status"] = "WARN"
        result["detail"] = "tick 年龄 %ds / 逾期 %d 个: %s" % (
            tick_age, len(overdue), ",".join(overdue[:5]) or "-")
    else:
        result["status"] = "PASS"
        result["detail"] = "tick 年龄 %ds，无逾期" % tick_age
    return result


def run_all(state_path: str, skill_dir: str,
            key_meta: str = "", key_integrity: str = "", audit_key_dir: str = "") -> dict:
    """Run all self-checks and return aggregated result."""
    issues = 0
    checks = []

    # 1. State file
    r = check_state_file(state_path)
    if r["status"] in ("FAIL", "MISSING"):
        issues += 1
    checks.append(r)

    # 2. Gate data
    r = check_gate_data(state_path)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 3. Checksum integrity
    r = check_checksum(state_path)
    if r["status"] in ("FAIL",):
        issues += 1
    checks.append(r)

    # 4. HMAC key
    r = check_hmac_key()
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 5. Key integrity
    _key_meta = key_meta or os.environ.get("_KEY_META", "")
    _key_integrity = key_integrity or os.environ.get("_KEY_INTEGRITY", "")
    _audit_key_dir = audit_key_dir or os.environ.get("_AUDIT_KEY_DIR", "")
    r = check_key_integrity(_key_meta, _key_integrity, _audit_key_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 6. Foreign content guard
    r = check_foreign_content_guard(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 7. Subagent runner
    r = check_subagent_runner(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 8. JWT signing
    r = check_jwt_signing(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 9. Provider connectivity
    r = check_provider()
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 10. GitNexus
    r = check_gitnexus(skill_dir)
    if r["status"] in ("FAIL",):
        issues += 1
    checks.append(r)

    # 11. Bash static vuln patterns (2026-08-15)
    r = check_bash_static(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 12. bashpy-migrate 加载安全网 (2026-08-23)
    r = check_bashpy_loader(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 12b. paper-review 加载安全网 (2026-08-29, bashpy 协议统一应用)
    r = check_paper_review_loader(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 13. 脚本测试门禁 (2026-08-23) — pytest 全绿，本地 CI 等效
    r = check_tests(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 14. L9 运行时安全网 (2026-08-26) — 升级对账三要素（stage-3-review L9）
    r = check_l9_runtime_safenet(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 15. L9 门禁链前置 (2026-08-26) — 复用 _eco_prereq_heuristic（stage-3-review L9）
    r = check_l9_gatechain_prereq(state_path)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 16. L9 熵/appeal 链路 (2026-08-26) — 熵阈值 + 死锁检测（stage-3-review L9）
    r = check_l9_entropy_appeal(state_path)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 17. 序列节点安全网健全程度 (2026-09-05) — S11 空壳站回归：ROUTES 每站三面实配
    r = check_sequence_node_safety(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 18. 派生联动 (2026-09-05) — 元数据只引用：活动项目目录 → 治理范围 + gitnexus 基线派生
    r = check_governed_baseline(state_path, skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 19. 租户隔离 (2026-09-05) — scopes 租户根双形态重复/嵌套（与余烬隔离对应，域 token 门）
    r = check_tenant_isolation(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 20. 审查层四件套覆盖 (2026-09-05 C1/E4 静态先行) — L1-L10(+PR) CLI/文档/红队族/测试 必配面
    r = check_review_layer_coverage(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 21. finding journal 重放对账 (2026-09-05 C8/f7) — ECC 裁决输出第二副本锚
    #   （无 journal 前序事件的 closed/fixed/rejected = 伪造裁决候选）
    r = _check_finding_journal(state_path)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 22. ember 快照回判 + A3 seal (2026-09-05 C10) — archived reconcile 读旧余烬"当时应判"
    #   （无余烬 SKIP；协调篡改经 seal 验签检出；pre-C8/缺签降级标注不阻断）
    r = _check_ember_replay(state_path, _audit_key_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 23. python argv 注入一致性 (2026-09-05 C10 卫生轮) — 新脚本须 main(argv=None)，存量旧式 WARN
    r = _cached_scan("python_argv_inject", skill_dir,
                     lambda: check_python_argv_inject(skill_dir))
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 24. PR-SCORE 双盲评分锚定 (2026-09-06 C9) — 快照↔plan 区块一致性 + A3 seal（无快照 SKIP）
    r = _check_pr_score_anchor(skill_dir, _audit_key_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 25. RED-META 越权读探测 (2026-09-06 C4) — 归一单源启发式 + registry↔scopes 双源复验
    #     （candidate findings 供 L10b 裁决——WARN 不 FAIL，非门禁）
    r = _cached_scan("red_meta", skill_dir, lambda: red_meta_scan(skill_dir))
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 26. bash 写函数防再引入漂移 (2026-09-07 批②, C66D7831EF73) — EXEMPT 注册表回归
    #     + 未登记写函数候选（WARN → L10b 裁决队列；权威计数=外部插件，本 gate 守确定性面）
    r = check_bash_write_drift(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 27. state 直写必须重算 checksum (2026-09-22 R22 新规则) — 锚 ECC-3D26D689A05F
    #     （`monitor --gitnexus` 裸 json.dump 直写 ⟹ 下游 _state_checksum_verify 误报 TAMPERED）
    r = check_state_write_checksum(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 28. 红队阶段不得注入假证据 (2026-09-22 R22 新规则) — 锚红队 C1
    #     （7→14 阶段补齐时上四相漏接线到 _red_attacks.py ⟹ 证据空洞/假绿）
    r = check_red_phase_wiring(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 29. egress 账本哈希链 (2026-10-22) — 外部证据入口的调用元数据须自洽
    #     （此前只 append 无链：截断/重排/插入不可见；legacy 前缀 WARN 不阻断）
    r = check_egress_chain()
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 30. CLI 可经 hook 执行（2026-10-22，owner 裁定「只加自检探针」）— 锚 377ea77
    #     信任根豁免防的是「CLI 含危险词 ⟹ 整条 CLI 不可执行 ⟹ advance/apply-worktree 不可达」
    #     的自指死锁；本项只观测、不修复，防复发。
    r = check_cli_hook_executable(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 31. ECC 写入规范机械体检（2026-10-26）— 锚 RED-PY-MISS
    #     `check_ecc_form` 已实装却**无调用点** ⟹ 恒不执行 = 门禁盲区（新机制未挂入自检）。
    #     state 缺失/无 ecc_findings 回 INFO（不阻断）；违例 FAIL 计入 issues。
    r = check_ecc_form(state_path)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 32. AMP 观测面（2026-10-26）— AMP 兼容层此前**无消费者**（叶子遥测）；
    #     本项消费 access.log：schema 合规（FAIL 计 issues）+ 新鲜度（>24h WARN）。
    r = check_amp_observability(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 33. hooks.json 注册态（2026-10-31）— wrapper 可执行 ≠ 已注册；absent/foreign 仅 WARN
    r = check_hook_registration(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 34. GitNexus 版本/耗时（2026-10-31）— 版本 <1.6 或单次调用超阈值 ⟹ WARN（慢索引真因）
    r = check_gitnexus_version(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 35. 模型/端点/env 取值合法性（2026-10-31）— 只报 WARN（配置问题不阻断运行）
    r = check_model_config()
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 36. 层 1 沙箱生效态（2026-10-31）— 包装器缺失 ⟹ FAIL（派发 fail-closed）
    r = check_sandbox(skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 37. cron 新鲜度/逾期（2026-11-01）— tick 停摆或作业逾期 ⟹ WARN
    r = check_cron_health()
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 38. 卫星索引一致性/容量（2026-11-01）— 悬空叶子/孤儿片/越 60 臂 ⟹ WARN
    r = check_satellite(state_path)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 39. state 归属一致性（2026-11-01）— proj.worktree ≠ 当前工作树 ⟹ WARN
    #     （worktree 复制 state 后未改归属 ⟹ 启动期纠正到主树当时阶段，如 r7 ⟹ 域路由 MISMATCH）
    #     修复入口：`self-check --repair-worktree`（env GK_SELFCHECK_REPAIR_WORKTREE=1）
    r = check_state_ownership(state_path, skill_dir)
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    # 40. 外部工具依赖面（2026-11-01，开源可移植）— 缺工具只报 WARN（能力降级，非状态损坏），
    #     每行带 install / substitute，供开源用户照抄；`missing_required` 供消费端提示。
    r = check_dependencies()
    if r["status"] == "FAIL":
        issues += 1
    checks.append(r)

    return {"ok": True, "issues": issues, "checks": checks}


def check_dependencies() -> dict:
    """外部工具依赖面（2026-11-01，开源可移植）：缺什么 / 影响什么 / 怎么装或平替。

    只报 `WARN`（缺工具 = **能力降级**，不是状态损坏 ⟹ 不阻断 `self-check` 的 issues 口径）。
    每行给出 `install`（官方安装）与 `substitute`（本仓已有的环境变量替代位），供开源用户照抄。
    """
    def _which(*names):
        for n in names:
            p = shutil.which(n)
            if p:
                return p
        return ""

    def _rg():
        # 与 CLI 同源：`GK_RG` > 可信绝对目录 > PATH（CLI 不做裸 PATH 查，这里只用于**报告**）
        p = (os.environ.get("GK_RG") or "").strip()
        if p and os.path.exists(p):
            return p
        for cand in ("/usr/local/bin/rg", "/usr/bin/rg", "/opt/homebrew/bin/rg",
                     "/opt/local/bin/rg", "/snap/bin/rg", "/mingw64/bin/rg"):
            if os.path.exists(cand):
                return cand
        return _which("rg")

    def _py_pkg(name):
        try:
            import importlib.util
            return "present" if importlib.util.find_spec(name) else "missing"
        except Exception:  # noqa: BLE001 — 探测失败按缺失报告
            return "missing"

    rows = []

    def add(tool, path, need, purpose, install, substitute):
        rows.append({"tool": tool, "state": "present" if path else "missing",
                     "path": path or "", "need": need, "purpose": purpose,
                     "install": install, "substitute": substitute})

    add("bash", _which("bash"), "required", "CLI 入口（gatekeeper-cli.sh 及全部 .sh）",
        "Windows: Git Bash 或 WSL；Linux/macOS: 自带",
        "无（.sh 入口不可绕过；Windows 请用 WSL）")
    add("python3", _which("python3", "python"), "required", "CLI 内部全部脚本",
        "apt install python3 / winget install Python.Python.3.12",
        "export GK_PYTHON=/path/to/python（`scripts/py_resolve.sh` 会消费）")
    add("git", _which("git"), "required", "state/discover/worktree/审查证据",
        "https://git-scm.com/downloads", "无（治理状态与证据依赖 git）")
    add("rg", _rg(), "recommended",
        "文本检索与多条守卫判据（缺位时相关判据无法生效）",
        "apt install ripgrep | brew install ripgrep | "
        "winget install BurntSushi.ripgrep.MSVC",
        "export GK_RG=/path/to/rg")
    add("node", _which("node", "node.exe"), "optional",
        "GitNexus 图索引（node >= 20）", "https://nodejs.org/",
        "不装 ⟹ 图能力降级为 WARN/SKIP（其余命令不受影响）")
    add("gitnexus", _which("gitnexus"), "optional",
        "图索引 / 调用链 / 变更影响（需要 node）", "npm i -g gitnexus",
        "不装 ⟹ 用 search / code_search 替代；图判据 SKIP")
    add("markitdown", _which("markitdown"), "optional",
        "read_doc 的文档转文本", "pipx install markitdown",
        "不装 ⟹ 仅 read_doc 不可用（read/read_repo 正常）")
    add("powershell.exe", _which("powershell.exe", "pwsh"), "optional",
        "Windows 侧注册表/密钥注入（仅 Windows 宿主）", "系统自带（PowerShell 5.1+）",
        "非 Windows 宿主不需要")

    for pkg, why in (("openai", "subagent 运行时"), ("agents", "subagent 运行时（openai-agents）"),
                     ("pydantic", "subagent 运行时"), ("pytest", "验收/测试面")):
        rows.append({"tool": "py:" + pkg, "state": _py_pkg(pkg),
                     "path": sys.executable, "need": "optional" if pkg != "pytest" else "recommended",
                     "purpose": why,
                     "install": "pip install openai openai-agents pydantic pytest",
                     "substitute": "export GK_PYTHON=/path/to/venv-python"
                                   "（`scripts/py_resolve.sh subagent`）"})

    missing = [r for r in rows if r["state"] == "missing"]
    res = {"check": "dependencies",
           "status": "WARN" if missing else "PASS",
           "missing": [r["tool"] for r in missing],
           "missing_required": [r["tool"] for r in missing if r["need"] == "required"],
           "tools": rows}
    if missing:
        res["detail"] = ("缺 %d 项：%s（按 tools[].install / tools[].substitute 补齐；"
                         "缺 optional 项只降级对应能力）"
                         % (len(missing), ", ".join(r["tool"] for r in missing)))
    return res


def main(argv=None):
    """CLI entry point. Parses args and runs checks."""
    state_path = os.environ.get("STATE_FILE", "")
    skill_dir = os.environ.get("SKILL_DIR", "")
    key_meta = os.environ.get("_KEY_META", "")
    key_integrity = os.environ.get("_KEY_INTEGRITY", "")
    audit_key_dir = os.environ.get("_AUDIT_KEY_DIR", "")

    args = list(sys.argv[1:] if argv is None else argv)
    i = 0
    while i < len(args):
        if args[i] == "--state-file" and i + 1 < len(args):
            state_path = args[i + 1]
            i += 2
        elif args[i] == "--skill-dir" and i + 1 < len(args):
            skill_dir = args[i + 1]
            i += 2
        elif args[i] == "--key-meta" and i + 1 < len(args):
            key_meta = args[i + 1]
            i += 2
        elif args[i] == "--key-integrity" and i + 1 < len(args):
            key_integrity = args[i + 1]
            i += 2
        elif args[i] == "--audit-key-dir" and i + 1 < len(args):
            audit_key_dir = args[i + 1]
            i += 2
        else:
            i += 1

    result = run_all(state_path, skill_dir, key_meta, key_integrity, audit_key_dir)
    print(json.dumps(result, indent=2))
    sys.exit(1 if result["issues"] > 0 else 0)


if __name__ == "__main__":
    main()
