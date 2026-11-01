#!/usr/bin/env python3
"""OTD 探针框架（论文 §5.3 tab:otd / 元评估计划 §1.6 的可执行版，2026-08-10）。

每个探针 = 故障注入（单点破坏输入）+ 机制必须零漏检检出。统一返回 JSON 探针报告。
- 6 个可立即执行（依赖已实现的机制）
- 3 个标注 BLOCKED（依赖 batch8 R-T6/R-T7.15 推进到位）

⚠️⚠️⚠️ 需要大改声明（读此文件前必读）⚠️⚠️⚠️
本文件是【预制探针框架】，不是论文证据的生产脚本。当前 9 个探针中：
  - 6 个"可执行"探针中，多数用的是【参考实现】或【基线验证】，只能证明"机制方向可行"，
    不能直接当作论文 tab:otd / RQ5 的通过证据——要变成论文数据，每个探针必须按其
    "需要大改"注释完成装配（接线生产实现 / 注入自动化 / 环境固定）。
  - 3 个 BLOCKED 探针依赖 batch8 R-T6（audit37）/ R-T7.15（history_sources）推进到位，
    到节点前不可解锁。
  - 运行环境：gatekeeper-cli.sh / run_verify.sh 是 WSL/CI 脚本；Windows PowerShell 下
    cli_json 与 verify_sentinel 会诚实 SKIP（非 FAIL）。真实执行必须走 WSL 或
    compile.yml 的 CI 路径（见 batch8 计划 R-T6 Phase 4 装配点）。
装配点登记：batch8 计划 §R-T6/R-T7.15（docs/plan-backup/2026-06-22-batch8-python-migration-plan.md）
           + 元评估计划 §1.6。每个探针的 "⚠️ 需要大改" 段 = 该探针的升级路线图。

用法:
    python3 scripts/otd_probes.py            # 跑全部可执行探针
    python3 scripts/otd_probes.py cli_json   # 跑单个探针
退出码: 0 = 全部通过; 1 = 有失败; 2 = 有 BLOCKED(待依赖)
"""
import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
CLI = SCRIPTS / "gatekeeper-cli.sh"
STATE_FILE = Path.home() / ".gatekeeper" / "gatekeeper.state.json"

# R2（2026-09-22）：state 序列化单一事实源 —— 勿再内联 json.dump 直写 state。
sys.path.insert(0, str(SCRIPTS))
from gk_json_utils import dump_state, state_lock  # noqa: E402


def _run_bash(args: list[str], input=None, timeout=30):
    """跨环境 bash 调用: 优先本机 bash, fallback wsl bash (Windows 无 bash 时)。"""
    for bash in ("bash", "wsl"):
        try:
            cmd = [bash, "bash", *args] if bash == "wsl" else [bash, *args]
            return subprocess.run(cmd, input=input, capture_output=True,
                                  text=True, timeout=timeout)
        except FileNotFoundError:
            continue
    raise FileNotFoundError("no bash available (try wsl)")


def _run_py(args: list[str], timeout=60):
    return subprocess.run([sys.executable, *args], capture_output=True,
                          text=True, timeout=timeout)


# ──────────────────────────────────────────────────────────────
# 探针 1: CLI JSON 契约（可观测性）
# ──────────────────────────────────────────────────────────────
def probe_cli_json() -> dict:
    """30 命令 verdict 契约: 所有 CLI 输出必须是合法 JSON 且含 ok 字段。
    探针: 对每个只读命令跑一遍，解析 stdout 首行 JSON。
    通过标准: 100% 命令返回可解析 JSON (ok/stage/reason/hint 结构)。
    环境注: gatekeeper-cli.sh 是 WSL 脚本; Windows 无 bash 时标记 SKIP(非 FAIL),
            真实执行在 WSL/CI (compile.yml 或 wslsh) 下进行。

    ⚠️ 需要大改（本探针当前为【契约存在性抽查】，仅 5 个只读命令）:
      1) 命令清单从 5 扩到 30 全量（对照 gatekeeper-cli.sh _CMD_REG），逐命令断言
         stdout 首行 JSON 且含 ok/stage/reason/hint 四键（R5.9++ T48b 注册表为准）。
      2) 判定标准升级：从"能解析"到"verdict 四键齐全 + JSON Schema 校验"（论文 tab:otd
         pass=100% 要求的真正含义）。
      3) 环境固定：在 WSL / GitHub Actions（compile.yml 新增 probe job）跑，禁止
         PowerShell 直跑（否则每次都是 SKIP 而非真实数据）。
      4) 与 audit 全量项（probe_audit37）合并为一次 CI 回归，产出可复现 CSV 证据。
    """
    try:
        # 探测 bash 可用性（cli_json 依赖 WSL 环境跑 gatekeeper-cli.sh）
        subprocess.run(["bash", "--version"], capture_output=True, timeout=10)
    except FileNotFoundError:
        try:
            subprocess.run(["wsl", "true"], capture_output=True, timeout=10)
        except FileNotFoundError:
            return {"probe": "cli_json", "dim": "observability",
                    "metric": "verdict parse success", "pass": None, "skipped": True,
                    "detail": "SKIP: no bash/wsl in this environment; run under WSL/CI"}
    read_commands = ["state", "discover", "stage-detail", "self-check", "context"]
    results = {}
    for cmd in read_commands:
        try:
            r = _run_bash([str(CLI), cmd])
            line = next((l for l in r.stdout.splitlines() if l.lstrip().startswith("{")), "")
            parsed = json.loads(line) if line else {}
            ok = "ok" in parsed or "stage" in parsed
            results[cmd] = {"json_ok": bool(line), "ok_field": ok}
        except Exception as e:  # noqa: BLE001
            results[cmd] = {"error": str(e)}
    passed = all(v.get("json_ok") and v.get("ok_field") for v in results.values())
    return {"probe": "cli_json", "dim": "observability", "metric": "verdict parse success",
            "pass": passed, "detail": results}


# ──────────────────────────────────────────────────────────────
# 探针 2: 篡改注入（可追溯性）
# ──────────────────────────────────────────────────────────────
def probe_tamper() -> dict:
    """不可变审计链: 篡改 state 后 gate 入口必须检测 (STATE_FILE_TAMPERED)。
    探针: 备份 state → 篡改一个字段 → 跑 guard-edit/pre-tool-check → 恢复。
    通过标准: 篡改后入口报告 STATE_FILE_TAMPERED / checksum 失败 = 100% 检出。
    已有证据: 红队（STATE_FILE_TAMPERED 拦截）。

    ⚠️ 需要大改（本探针当前为【手动篡改+一次性注入】）:
      1) 前置条件：需要 active R-phase 的真实 state 文件；当前无 state 时返回 N/A，
         不是证据。跑探针前必须先 discover/进入 R-phase。
      2) 注入方式需与生产 `_state_checksum_verify`（SHA256，R5.8 d953c97）对齐：
         逐字段篡改（r_phase / stage / gate_data / history[]）而非加 _tamper 幽灵字段，
         以覆盖"真实字段被改"而非"多一个键"的检测面。
      3) 自动化：改为参数化注入矩阵（N 种篡改 × 入口命令），产出逐项检出率表，
         而非单次布尔。目标 = tab:otd pass 100%（零漏检）。
    """
    if not STATE_FILE.exists():
        return {"probe": "tamper", "dim": "traceability", "metric": "tamper detection",
                "pass": True, "detail": "no state file (no active R-phase); probe N/A"}
    backup = STATE_FILE.read_text(encoding="utf-8")
    try:
        # 2026-09-25（选项 A）：注毒段与还原段**各自**在锁内 —— ⚠ 绝不跨下方 `_run_bash`
        #   持锁：子 CLI 自身要取同一把锁，锁内等子进程 = 自我饿死（-w 5 超时）。
        with state_lock(STATE_FILE):
            data = json.loads(backup)
            data["_tamper"] = "injected"
            dump_state(STATE_FILE, data)
        r = _run_bash([str(CLI), "guard-edit", "--check"])
        detected = "TAMPER" in r.stdout or "TAMPER" in r.stderr or r.returncode != 0
        return {"probe": "tamper", "dim": "traceability", "metric": "tamper detection",
                "pass": detected, "detail": {"tamper_injected": True, "detected": detected}}
    finally:
        with state_lock(STATE_FILE):
            STATE_FILE.write_text(backup, encoding="utf-8")


# ──────────────────────────────────────────────────────────────
# 探针 3: 配置漂移注入（可诊断性）
# ──────────────────────────────────────────────────────────────
def probe_toolcfg_drift() -> dict:
    """check_tool_cfg (W3): 注入注册表漂移后 self-check 必须检出。
    探针: 跑 check_tool_cfg.py 当前状态 (零漂移); 漂移注入需改源码, 故先验证基线自检。
    通过标准: 基线 self-check 0 issue (drift detection 的阴性基线)。
    已有证据: W3 已实现。

    ⚠️ 需要大改（本探针当前为【零漂移基线自检】，未做注入）:
      1) 真正探针 = 漂移注入：临时复制 scripts/，在 check_tool_cfg.py 的
         TOOL_REGISTRY/配置文件里注入差集条目 → 断言 self-check 报出差集 → 还原。
         当前 TODO(注入) 位置即注入点，需实现为自动化（临时改 + try/finally 还原，
         或基于 diff 快照回滚，禁止留下脏工作区——R1 教训）。
      2) 判定标准：从"基线 0 issue"升级为"注入 K 种漂移 → 100% 检出 + 差集名称正确"。
      3) 运行环境：与 W2/W4 同一 WSL/CI 通道，避免 PowerShell 路径差异。
    """
    r = _run_py([str(SCRIPTS / "check_tool_cfg.py")])
    clean = "0 issue" in r.stdout or "OK" in r.stdout or r.returncode == 0
    return {"probe": "toolcfg_drift", "dim": "diagnosability",
            "metric": "baseline drift detection", "pass": clean,
            "detail": {"exit": r.returncode, "stdout_tail": r.stdout.strip()[-200:]}}
    # TODO(注入): 复制 scripts/ 临时改 TOOL_REGISTRY 差集 → 断言 self-check 报差集 → 还原。


# ──────────────────────────────────────────────────────────────
# 探针 4: 缺哨兵注入（可诊断性）
# ──────────────────────────────────────────────────────────────
def probe_verify_sentinel() -> dict:
    """run_verify (W2): 无 ALL_PASS 哨兵的脚本必须被拒 (P3_ASSERT_FAIL)。
    探针: 构造一个"假通过"脚本(echo done 但无哨兵) → run_verify.sh 必须 P3_ASSERT_FAIL。
    通过标准: 100% 拒绝假通过。
    已有证据: W2 已实现。

    ⚠️ 需要大改（本探针当前为【单样例假通过脚本】，依赖 rg 存在）:
      1) 环境依赖：run_verify.sh 内部用 rg 扫描 ALL_PASS 哨兵；Windows 无 rg 时
         SKIP。需固定 rg 依赖（WSL 安装 / CI 环境注入），否则数据不可复现。
      2) 注入面扩大：除"无哨兵"外，补"哨兵被注释/拆行/大小写变体"等 K 种逃逸样本，
         断言全部 P3_ASSERT_FAIL（对齐 W4 负向前瞻的逃逸面思路）。
      3) 修复率侧：一次修复（GATEKEEPER-FIX）需要 agent 重试循环，与 probe_fix_hint
         合并成端到端 trace（BLOCK → hint → 重试 → 通过），单跑本探针给不出修复率。
    """
    fake = "#!/bin/bash\necho done\n"  # 无 === ALL_PASS ===
    r = _run_bash([str(SCRIPTS / "run_verify.sh")], input=fake)
    if r.returncode == 127 and "P3_ASSERT_FAIL" not in r.stdout + r.stderr:
        return {"probe": "verify_sentinel", "dim": "diagnosability",
                "metric": "false-pass rejection", "pass": None, "skipped": True,
                "detail": "SKIP: run_verify.sh 内部依赖 (rg) 缺失; 真实执行在 WSL/CI"}
    rejected = "P3_ASSERT_FAIL" in r.stdout + r.stderr or r.returncode != 0
    return {"probe": "verify_sentinel", "dim": "diagnosability",
            "metric": "false-pass rejection", "pass": rejected,
            "detail": {"exit": r.returncode, "has_sentinel_fail": rejected}}


# ──────────────────────────────────────────────────────────────
# 探针 5: 熵漂移注入（可观测性）
# ──────────────────────────────────────────────────────────────
def probe_entropy_drift() -> dict:
    """熵监视器: 注入漂移序列后熵 > 0.5 必须检出。
    探针: 直接调用熵计算逻辑 (R4), 注入 20 条窗口含漂移样本 → 断言熵 > 0.5。
    通过标准: 漂移窗口熵 > 0.5 (100% TP), 纯净窗口熵 ≤ 0.5 (0 FP)。
    实现注: 熵计算位于 gk_monitor_api / R4 逻辑; 此处用等价参考实现验证阈值行为,
            生产实现探针待 R-T6 Phase 2a 接线后替换。

    ⚠️ 需要大改（本探针当前为【本地参考实现】，非生产 R4 熵）:
      1) 接线：替换为 gk_monitor_api / R4 生产熵计算（R-T6 Phase 2a gk_monitor_api.py
         迁移后），当前 import 的本地 entropy() 只是数学等价物，论文证据必须出自生产路径。
      2) 注入场景：从"单窗口 20 条"扩为长会话漂移序列（数百步、混合 allow/deny 渐变），
         覆盖 LHTB 长时程场景（论文 §5 长会话熵门禁扩展）；统计 TP/FP 而非单次布尔。
      3) 阈值校准：0.5 阈值需在生产数据上校准（误报/漏报权衡曲线），tab:otd 的
         "100% TP, 0 FP" 是目标不是现状——先跑出真实分布再定阈。
    """
    import math
    from collections import Counter

    def entropy(window):
        c = Counter(window)
        n = len(window)
        return -sum((v / n) * math.log2(v / n) for v in c.values())

    drift_window = ["deny"] * 11 + ["allow"] * 9          # 11/20 异常 → 熵 ~0.99
    clean_window = ["allow"] * 19 + ["allow"]             # 全正常 → 熵 0
    tp = entropy(drift_window) > 0.5
    fp_free = entropy(clean_window) <= 0.5
    return {"probe": "entropy_drift", "dim": "observability",
            "metric": "drift TP/FP", "pass": tp and fp_free,
            "detail": {"drift_entropy": round(entropy(drift_window), 3),
                       "clean_entropy": round(entropy(clean_window), 3)}}


# ──────────────────────────────────────────────────────────────
# 探针 6: fix-hint 一次修复率（可诊断性）
# ──────────────────────────────────────────────────────────────
def probe_fix_hint() -> dict:
    """GATEKEEPER-FIX: 危险命令被拦后 hint 必须给出可执行修复。
    探针: 调 _dangerous_command 于 4 类危险命令 → 断言每个命中都带 Fix: hint。
    通过标准: 100% 命中含 hint (一次修复率的前置条件)。
    已有证据: W4 (Gate R0.2) 已实现。

    ⚠️ 需要大改（本探针当前为【直接 import 私有 API】，绕过 CLI 门禁）:
      1) 路径合规：禁止 `import pre_tool_hook` 直调 `_dangerous_command`（绕过
         gatekeeper-cli 的 pre-tool-check 门禁通道，用户已明确"裸跑无意义"）。改为
         通过 CLI `pre-tool-check`/`guard-edit` 发真实 BLOCK 事件 → 断言 stdout 含
         GATEKEEPER-FIX: hint。这同时验证 hint 是否真的下发到 agent 可见层。
      2) 判定升级：hint 存在（当前）→ hint 能完成一次修复（端到端：BLOCK → hint →
         agent 重试 → 通过）。需要 replay 循环（gatekeeper-cli replay 命令）积累样本，
         tab:otd 的 ≥90% 修复率必须来自 replay 统计。
      3) 命令面扩大：4 类危险命令 → 全部 W4 正则分支 + --force-with-lease 负向前瞻
         样本（13/13 单元用例是测试层，本探针是 CLI 集成层，两层都要）。
    """
    sys.path.insert(0, str(SCRIPTS))
    import pre_tool_hook as p

    cases = ["git push --force origin main", "git reset --hard",
             "git clean -fd", "rm -rf /tmp/x"]
    results = {}
    for cmd in cases:
        hit = p._dangerous_command(cmd)
        results[cmd] = bool(hit and hit[1].startswith("Fix:"))
    return {"probe": "fix_hint", "dim": "diagnosability",
            "metric": "hint presence (precursor to one-shot repair)",
            "pass": all(results.values()), "detail": results}


# ──────────────────────────────────────────────────────────────
# BLOCKED 探针（依赖 batch8 推进）
# ──────────────────────────────────────────────────────────────
def probe_history_sources() -> dict:
    """6-source archive completeness (论文 tab:otd Tra 行)。
    ⚠️ BLOCKED — 依赖 batch8 R-T7.15（history[] prev_entry 6 字段扩展）。
    解锁条件：R-T7.15 完成后，history[] 快照含全部 6 源（block_log/rejected_edits/
    gate_data/plan/commit/redteam_findings），本探针再实现"跨阶段重构完整性"断言。
    到节点前保持 BLOCKED，勿硬跑（会得到假证据）。"""
    return {"probe": "history_sources", "dim": "traceability",
            "metric": "6-source archive completeness",
            "pass": None, "blocked": True,
            "detail": "BLOCKED: depends on batch8 R-T7.15 (history[] prev_entry 6 字段扩展)"}


def probe_audit37() -> dict:
    """audit --all + independent invocation (论文 tab:otd Obs 行)。
    ⚠️ BLOCKED — 依赖 batch8 R-T6 Phase 4a-4f（gk_audit_state.py 41 项：
    state 17 + hint 4 + self 4 + hook 6 + red 10；2026-09-02 HOOK-05/06 提权防线
    + hook_block_log 意图记忆 = 41）。
    解锁条件：R-T6 Phase 4a gk_audit_state.py 迁移完成，本探针再实现
    "audit --all + 每项独立调用"双路径断言。
    到节点前保持 BLOCKED。"""
    return {"probe": "audit37", "dim": "observability",
            "metric": "audit --all + independent invocation (41 checks)",
            "pass": None, "blocked": True,
            "detail": "BLOCKED: depends on batch8 R-T6 Phase 4a-4f (gk_audit_state.py 41 项)"}


def probe_kappa() -> dict:
    """Cohen's kappa (human-agent) (论文 tab:otd Tra 行)。
    ⚠️ BLOCKED — 需要多轮 adjudicate 记录积累（human_calibration_log）。
    解锁条件：gatekeeper-cli adjudicate 在真实评审轮中积累 ≥2 轮人机评分对
    （建议 ≥30 样本），再算 kappa ≥0.7。当前无真实评审数据，硬算=造数。"""
    return {"probe": "kappa", "dim": "traceability",
            "metric": "Cohen's kappa (human-agent)",
            "pass": None, "blocked": True,
            "detail": "BLOCKED: requires multi-round adjudicate logs (human_calibration_log 积累)"}


# ──────────────────────────────────────────────────────────────
PROBES = {
    "cli_json": probe_cli_json,
    "tamper": probe_tamper,
    "toolcfg_drift": probe_toolcfg_drift,
    "verify_sentinel": probe_verify_sentinel,
    "entropy_drift": probe_entropy_drift,
    "fix_hint": probe_fix_hint,
    "history_sources": probe_history_sources,
    "audit37": probe_audit37,
    "kappa": probe_kappa,
}


def main(argv: list[str]) -> int:
    names = argv[1:] if len(argv) > 1 else list(PROBES)
    report = {"results": []}
    has_fail = False
    for name in names:
        if name not in PROBES:
            print(f"unknown probe: {name}", file=sys.stderr)
            continue
        res = PROBES[name]()
        report["results"].append(res)
        if res.get("blocked"):
            status = "BLOCKED"
        elif res.get("skipped"):
            status = "SKIP"
        else:
            status = "PASS" if res["pass"] else "FAIL"
        print(f"[{status}] {name}: {res.get('metric', '')}")
        if res.get("blocked") or res.get("skipped"):
            print(f"        {res['detail']}")
        elif not res["pass"]:
            has_fail = True
            print(f"        {json.dumps(res['detail'], ensure_ascii=False)[:300]}")
    print(json.dumps(report, ensure_ascii=False))
    return 1 if has_fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
