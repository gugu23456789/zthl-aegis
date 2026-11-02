#!/usr/bin/env python3
"""
gk_finding.py — ECC-FINDING 闭环协议状态机 (batch8 R-T8.2, 2026-08-20)
=======================================================================
技能自维护防裸跑的核心机制：缺陷发现 → 登记(open) → 修复(fixed)
→ 复验(verified/rejected) → 关闭(closed) + 回流元数据。

状态机: open → in_progress → fixed → verified → closed
                └→ rejected（复验失败，退回 open）

闭环 = 缺陷发现即登记，修复后复验（RED/crossr/manual），关闭时写
`verify_source` 回流元数据（供 R-T8.5 自动复验框架消费）。

数据落点: state.gate_data.ecc_findings[]（与 I9 RED-REPORT auto-writeback 同一数组）

用法: python3 gk_finding.py <cmd> <state_file> [args]
  ⚠ `<state_file>` 是**第一个位置参数**（`main()`: `cmd, state_file = args[0], args[1]`）；
    下述各子命令签名均**省略**了它 —— 实际调用形如
    `gk_finding.py close <state_file> <id> tests:...`，写成 `close <id>` 会把 id 当 state 路径。
  cmd: register <title> [source] [--family <族>] [--cover-layers L5,L9] [--gap true|false] [--domain <repo>.<plan>]
       # source: crossr/red/review/manual/audit（默认 manual）；red/review 须带 --cover-layers（C2/E2）
       # --repo <仓根|token>：跨仓归属 token（缺省由 close/verify 的 commit:<sha> 派生）
       verify <id> <true|false> [--verify-source <来源>] [--domain <repo>.<plan>]
       close <id> [verify_source] [--verify-source <来源>] [--ack-accept] [--domain <repo>.<plan>]   # 缺省 verify_source=manual
       reopen <id> [reason] [--reason <文本>] [--domain <repo>.<plan>]   # 重开终态 finding（status→open + journal 留痕）
       stale [--ttl-days <n>] [--apply]   # 时效巡检：TTL 超期标 stale；锚文件被 diff 触及 ⟹ reopen（默认只报不写）
       amend-title <id> --suffix <文本> [--note <文本>] [--domain <repo>.<plan>]   # R25: **追加**更正子句（不改写历史；幂等）
       status
       family [--domain <repo>.<plan>]       # 只读：按缺陷族（family）聚合台账（红队分族总览）
       check [--title <标题>] [--root-key <根因指纹>] [--anchors a,b,...] [--domain <repo>.<plan>]
                                     # ECC-43C982F794B8: **只读**写前检查（报命中既有 finding + 跨域重复；零写盘）
       reconcile                     # C8/f7: journal 重放对账 state vs 独立第二副本锚
       epoch [--ts <iso>] [--reason <文本>]   # F-REV-23: 打代际标记（reconcile 只对标记后对账）
 域纪律（ECC-C98BDE1D2B3B）：写类子命令（register/verify/close/amend-title）可带 `--domain <repo>.<plan>`
 走域化 state；声明域后**不静默回退**默认 state（目标不存在即拒绝）——防跨仓 finding 互相污染。
 解析纪律（2026-09-05）：子命令统一位置参数 + --flag；缺参/未知 --参数/非法 bool/多余位置参数
  → 显式 usage 错误（{"ok":false,"error":...} exit 1），不静默忽略（防拼写错误被吞）。
输出: stdout JSON {"ok":true,...}；错误 {"ok":false,"error":...} exit 1。
"""
import hashlib
import hmac
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# R2（2026-09-22）：state 序列化单一事实源 —— 勿再内联 json.dump 直写 state。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gk_json_utils import (dump_state, state_lock, ser_bytes,  # noqa: E402
                           state_size_report, STATE_SIZE_WALL, STATE_SIZE_RESERVE,
                           WALL_TRIM_PCT)

DEFAULT_SKILL = Path(__file__).resolve().parent.parent

# C2/E2：要求登记缺陷族"应拦审查层"的来源（其余来源按需自愿登记）
_COVER_REQUIRED_SOURCES = ("red", "review")

# ── ECC 写入规范（A 类 · 机械可闭合拦截；ECC-03F2EB7D6607 / ECC-FF45F426BA45，2026-09-27）──
# 缺口（实测）：`closure_oracle` 落刀时为**自由文本**（零校验）⟹ 标签可任意书写 = 不可机检
#   = 等于没判据（`--api` 语义判据 / `--local` 结构判据都无从对表）。
# 纪律：**机械可判**的写入规范在此 fail-loud 拒写（`{"ok":false}` exit 1，经 main() 边界统一转）；
#   **判断类**内容（principal/resolution 等）**不**校验 —— 留给 owner（见 ECC-FF45F426BA45 的
#   「机器填事实 / 人填判断」边界）。本处 = **唯一**校验点（单源），register/merge 两路都过。
_CLOSURE_ORACLES = ("mechanical", "judgment")   # "" = 未分类（合法）
_ROOT_KEY_MAX = 64                              # 根因指纹长度上限（超长即非指纹、是散文）

# ── ECC `source` 写入规范（B 类安全网；2026-09-28，规范正本 references/ecc-write-spec.md）──
# 现场（实测 base state 92 条）：`source` 曾**零校验** ⟹ 整段时间线/探针说明被灌入
#   （规范值仅 manual 37 / red 7 / review 4 / 空 15，其余 ≈29 条为散文；含 `R25.9` / `user`）
#   ⟹ 机器无法按来源分面统计（「散乱状态」的结构性成因）。
# 纪律：`source` 只接受**短 token**（≤`_SOURCE_MAX` 且无空白）；白名单外的新来源须**显式登记**
#   到 `_ECC_SOURCES`（单一登记点；不静默接受）。**长文本出处**走 `source_note` 字段
#   （`--source-file` 通道）—— 两者显式分离，`source` 永不再承载散文。
_SOURCE_MAX = 32
# 2026-10-16（`ECC-E844E67E64A5`）：新增 `prose` —— 散文结论（`gk_prose_findings.convert`）
#   原硬编码 `review`，与 **MoA 聚合 finding 同源** ⟹ 来源分面统计不可分（散文是人写结论，
#   非审查层 finding ⟹ 亦**不再**因缺 `cover_layers` 被标 `gap`）。
_ECC_SOURCES = ("manual", "crossr", "crossrev", "red", "review", "audit", "monitor",
                "prose", "subagent-promoted")   # 登记点：新增来源只改这一行
_DEFAULT_SOURCE = "manual"
_FROM_REPORT_SOURCE = "subagent-promoted"
# `--from-report` 的**允许抽取字段**白名单（其余键一律**丢弃** ⟹ 禁整份 subagent 报告入册）
_REPORT_ALLOWED = ("title", "summary", "family", "anchors", "facets", "root_key",
                   "closure_oracle", "cover_layers")

# 审计 finding 适配器（E18，2026-10-29）：`severity` / `owner` 为**可选**结构化字段（缺省空串，
# 存量 400+ 条不回填 = 不扩写状态）。severity = 严重度单源白名单（**只升不降**，同 root_key
# 合并时升档）；owner = 责任域 token（如 `skill.<plan>`），禁空白禁散文（同 source 纪律）。
_SEVERITIES = ("info", "low", "medium", "high", "critical")   # 序 = 严重度递增
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITIES)}
_OWNER_MAX = 120

# ── ECC 闭合「源」写入规范（c9 加固；2026-10-04 · ECC-2C7BEBA09A84 / BLUE-FAT-FISH-IDLE-GATE）──
# 缺口：`close()` 的 `verify_source` **零校验**（任意串，含 `register-only`）⟹ c9「闭合无源」可绕。
# 纪律：`verify_source` = `;` 分隔的 `<kind>[:<payload>]`，`kind ∈ _VERIFY_SOURCES`（单一登记点）；
#   `manual` = 显式「无源」标记（c9 对 `closed`/`fixed` 判 FAIL）；`register-only` = 显式「仅登记」
#   合法出口。写入边界 fail-loud ⟹ 任意串不再能冒充「有源」。
_VERIFY_SOURCES = ("manual", "commit", "tests", "arm", "review", "crossr", "red",
                   "monitor", "register-only")


def _assert_verify_source(vsrc: str) -> None:
    """`close()`/`verify()` 写入边界的 `verify_source` 形态门（单源 = `_VERIFY_SOURCES`）。

    仅校验**结构化段**（`kind:payload` 形态，含 `:`）：其 `kind` 须 ∈ `_VERIFY_SOURCES`，否则拒写。
    **无冒号的自由文本段**（历史「回流元数据」用法，如 `l10b`/`R-T8.5 复验`）放行 —— 其可核验性
    由 c9（审计门）对终态判定。空串合法（显式无源 → c9 对终态判 FAIL）。
    """
    for part in (vsrc or "").split(";"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        kind = part.split(":", 1)[0].strip().lower()
        if kind not in _VERIFY_SOURCES:
            raise ValueError("verify_source 非法 kind: %r（合法: %s；见 gk_finding._VERIFY_SOURCES）"
                             % (kind, " | ".join(_VERIFY_SOURCES)))


# ── 关单**验收**对偶门（accept gate，2026-10-13 · ECC-89CDA3AEC7B5）──────────────
# 对偶于 register 的 `route_hard` 预检（准入硬门）：close 侧补「验收硬门」——`verify_source`
#   须承载**可核验证据**，否则终态汇点禁行（治「close 只校形态、不核验证据真实性 / 不要求有据」）。
# 仅 **CLI 手工面**强制（`accept_hard=True`）；内部/测试调用（缺省 `accept_hard=False`）不受约束
#   ⟹ 零回归。逃生舱 `--ack-accept`（= 对偶于 register 的 `--ack-drift`），放行即 journal `accept_ack`。
# **跨仓默认**（owner 2026-10-15 令「ECC-finding 全过程必须默认支持跨仓」）：`commit:<sha>` 在
#   **候选仓集合**（非单仓）任一可解析即通过 —— `_candidate_repos()`：env `GK_FINDING_REPOS`
#   → 技能仓 → state 所在仓 → CWD 所在仓 → 技能仓的**同级仓**。单仓假设 = 漂移源（跨仓 sha 被
#   误判为伪源）⟹ 默认多仓。
_ACCEPT_KINDS = ("commit", "arm", "tests", "review", "crossr", "red", "monitor")


def _accept_segments(vsrc: str) -> list:
    out = []
    for part in (vsrc or "").split(";"):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            k, p = part.split(":", 1)
            out.append((k.strip().lower(), p.strip()))
        else:
            out.append(("", part))
    return out


def _repo_root(start: str) -> str:
    """自 `start` 向上找首个含 `.git` 的仓根（无则 ''）。"""
    try:
        p = Path(start).resolve()
    except Exception:  # noqa: BLE001
        return ""
    for anc in [p] + list(p.parents):
        if (anc / ".git").exists():
            return str(anc)
    return ""


def _candidate_repos(state_file: str) -> list:
    """**跨仓候选仓根**（去重保序）——`ECC-FINDING` 全过程默认支持跨仓的输入面。

    优先级：env `GK_FINDING_REPOS`（`:`/`;` 分隔，显式追加）→ 技能仓 → state 所在仓 →
    CWD 所在仓 → 技能仓的**同级仓**（`DEFAULT_SKILL.parent/*/.git`）。

    `GK_FINDING_ISOLATE=1` ⟹ **只认 base 与同目录**（返回空表）：单目录语义的单元测试必须打开，
    否则 tmp state 会经 `DEFAULT_SKILL` 读到主树实账（实测：`writable_duplicates` 被实账 12 条
    污染，`principal` 的 `root_causes` 由 1 变 13）。生产默认不设 ⟹ 跨仓口径不变。
    """
    if os.environ.get("GK_FINDING_ISOLATE") == "1":
        return []
    cands = []

    def _add(p):
        p = str(p or "").strip()
        if p and p not in cands:
            cands.append(p)

    for p in re.split(r"[:;]", os.environ.get("GK_FINDING_REPOS", "")):
        _add(p)
    _add(str(DEFAULT_SKILL))
    _add(_repo_root(os.path.dirname(os.path.abspath(state_file))))
    try:
        _add(_repo_root(os.getcwd()))
    except Exception:  # noqa: BLE001
        pass
    try:
        for d in sorted(Path(DEFAULT_SKILL).parent.iterdir()):
            if (d / ".git").exists():
                _add(str(d))
    except Exception:  # noqa: BLE001
        pass
    return cands


def _commit_resolvable(sha: str, repos=None) -> bool:
    """sha 在**候选仓任一处**可解析 ⟹ True（跨仓默认）。"""
    import subprocess
    sha = (sha or "").strip()
    if not sha:
        return False
    for repo in (repos or [str(DEFAULT_SKILL)]):
        try:
            r = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "--quiet",
                                sha + "^{commit}"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=15)
            if r.returncode == 0:
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _accept_gate(state_file: str, fid: str, verify_source: str, accept_ack=None) -> None:
    """关单**验收硬门**（对偶于 `register` 的 `route_hard`）：`verify_source` 须承载可核验证据。

    - 无任何 `kind ∈ _ACCEPT_KINDS` 的证据段（`manual`/空/自由文本）⟹ fail-loud（先补 `verify` 或写证据）
    - 含 `commit:<sha>` 段但 sha 在**候选仓**（默认多仓，`_candidate_repos`）均不可解析 ⟹ fail-loud（伪源）
    - `accept_ack=True`（CLI `--ack-accept`）⟹ 放行 + journal `accept_ack`（逐 fid 一条，带 fid、禁带 to）
    - 开关 env `GK_FINDING_ACCEPT=0` ⟹ SKIP（默认 1 = 强制）
    """
    if str(os.environ.get("GK_FINDING_ACCEPT", "1")).strip() == "0":
        return
    if accept_ack is None:
        accept_ack = str(os.environ.get("GK_FINDING_ACK_ACCEPT", "")).strip() not in ("", "0", "false")
    segs = _accept_segments(verify_source)
    ev = [(k, p) for (k, p) in segs if k in _ACCEPT_KINDS]
    problems = []
    if not ev:
        problems.append("无证据段：verify_source=%r 不含 %s 之一（manual/空/自由文本不作证据）"
                        % (verify_source, "/".join(_ACCEPT_KINDS)))
    repos = _candidate_repos(state_file)
    for k, p in ev:
        if k == "commit" and not _commit_resolvable(p, repos):
            problems.append("commit:%s 在候选仓不可解析（伪源；候选=%d 仓）" % (p, len(repos)))
    if not problems:
        return
    if accept_ack:
        _append_journal(state_file, {"event": "accept_ack", "fid": fid, "ts": _now(),
                                     "problems": problems})
        return
    raise ValueError(
        "ECC_CLOSE_ACCEPT_FAIL: " + "; ".join(problems)
        + " —— 关单须承载可核验证据（先 `verify`，或 `--verify-source` 写 `commit:<真实sha>`/"
          "`arm:`/`tests:`）；确需无据关单请 `--ack-accept` 显式放行（记 accept_ack 留痕）")


# ── 释放批准链（release approval；B 阶段 2026-10-06）─────────────────────────────
# 缺口：`emit_aggregate_finding` 产的 finding **直接可用** ⟹ 无「可下发实装」硬门；且 MoA 聚合
#   finding 与人类评审 finding **分家**（无复合）。
# 修法（owner 2026-10-06 裁「复合 + 释放批准 / 硬门」）：
#   · **独立字段** `release_state ∈ {none,provisional,release_approved,release_rejected}`
#     —— **不动**既有 status 机（open→in_progress→fixed→verified→closed）；聚合 finding 落 `provisional`。
#   · 人评 = **唯一写通路**（`release-approve`/`release-reject`）；放行即**复合**（人评 overlay
#     并入**同一条** finding，不新起镜像）。
#   · **硬门** = `release_set()`：未 `release_approved` **不得**进「可下发实装」集。
#   · **P-meta 可污染通道**（对齐审计署计划 §2.1）：人评自身可被污染 ⟹ 双盲 `divergence` 超阈时
#     **禁自动放行**（须 `--final-ruling` 显式人类终裁）。
_RELEASE_STATES = ("none", "provisional", "release_approved", "release_rejected")
_RELEASE_DIVERGENCE_MAX = 0.2   # 与 `gk_audit_state.adjudicate_records` 的 divergence ≤0.2 同源

# ── T5-a/T5-d：溯源 / 能力硬门 + 二阶（记忆）校验（XSPI 强化，2026-10-06）─────────
# 依据（机制正本 references/xspi-defense.md）：检测（正则/ML）**不是**安全边界，**容器化**才是
#   （CaMeL / Design-Patterns arXiv:2506.08837）；且「记忆写入 = 不可信输入事件」（AgentPoison/
#   SpAIware）⟹ 不可信内容须打 taint，**未 declassify 不得到达后果性汇点**（release/close/verify）。
# 纪律：taint 由**摄取边界**显式赋值（聚合/散文 finding = untrusted）；缺省 trusted ⟹ 零回归。
_PROVENANCE = ("trusted", "untrusted")
_QUARANTINE_FACET = "provenance:untrusted"

# C8/f7：ECC 裁决契约绑定 — mutation 追加写入独立第二副本锚（journal），
# reconcile 重放对账 state.ecc_findings 状态机（防"L10b 裁决输出被全部篡改无痕"）
_JOURNAL_SUFFIX = ".finding-journal.jsonl"

# F-REV-23（2026-09-11）：journal 跨 state 代际存活 ⇒ 引入显式 **epoch 代际标记**。
# reconcile 只对「最近一次 epoch 之后」的事件对账；epoch 之前的属前代，不误报「记录被删」。
# 纪律：**不自动推断代际**（按 live findings 最早 register ts 反推会掩盖"最旧记录被删"），
# 只认显式 epoch —— 谁轮换 state 谁负责打点；静默清洗仍会 FAIL（检测能力不退化）。
_EPOCH_EVENT = "epoch"

# ── ECC-FINDING 跨仓污染守卫（ECC-C98BDE1D2B3B，2026-09-11）──
# 缺陷归属域 token 形态 `<repo>.<plan>`（对齐 META.state_domain / A2-D5 域化命名前向接口），
# 域化 state 文件 = 同目录 `.gatekeeper.state.<token>`。
# 纪律：声明域后 **绝不静默回退** 默认 state —— 目标不存在即 fail-closed 拒绝；
# 否则跨仓 finding 会静默落进技能默认 `.gatekeeper.state`（现场：4 条门卫域混入技能域）。
#
# ── 现状 / 缺口登记（2026-09-26 只读取证，**不改语义**）──────────────────────────────
# · **已修**：声明域 → fail-closed（`resolve_domain_state`/`FINDING_DOMAIN_STATE_MISSING`）。
# · **缺口①（opt-in 静默）**：**未声明域** ⟹ 静默落默认 state，**无提示**（`domain_bound=false`
#   仅是调用期返回字段，非持久键）。现场：本计划名下并存 base 113 条 vs plan-basename 域 138 条。
# · **缺口②（无枚举面）**：无「按域枚举 findings」的只读面 ⟹ 单查 base 会**误判不在册**
#   （2026-09-26 实测误判 4 条：`ECC-7FF005759CE2`/`ECC-1E6BFDD7A207`/`ECC-1765B3E4DF55`/
#   `ECC-F5FE1042A7BA` 实在孤儿域）。归并/冻结须先有「base/孤儿域/旁挂 archive 三源对账臂」。
# · 纪律（用户 2026-09-26 裁定）：**正本 = base**；孤儿域**冻结不删**；引用 finding 前**须双查**。
# · 锚：`ECC-46C22B11AD85`（RC3）/ `ECC-4D6978F042BA` / §4.13.30 一、五。
_STATE_PREFIX = ".gatekeeper.state"
_DOMAIN_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _state_file_domain(state_file: str) -> str:
    """state 文件名携带的域 token（默认 `.gatekeeper.state` → ''；`.gatekeeper.state.a.b` → 'a.b'）。"""
    name = Path(state_file).name
    if not name.startswith(_STATE_PREFIX):
        return ""
    return name[len(_STATE_PREFIX):].lstrip(".")


def _domain_alias_candidates(token: str) -> list:
    """§17-1①（2026-10-03）：域 token 的**别名候选**（双形态归一）。

    现场：同计划并存 `.gatekeeper.state.<plan>`（无 repo 段）与
    `.gatekeeper.state.skill.<plan>`（带 `skill.` 段），`_DOMAIN_TOKEN_RE` 两形态皆合法。
    归一 = **仅**围绕计划指针的既定 repo 段 `skill.` 换形（**不**做任意「去首段」——
    否则异 repo 同基名 `gatekeeper.r7`/`spz2glb.r7`/`r7` 会被误并）。
    """
    if token.startswith("skill."):
        cand = token[len("skill."):]
    else:
        cand = "skill." + token
    return [cand] if cand and _DOMAIN_TOKEN_RE.match(cand) else []


def resolve_domain_state_ex(state_file: str, domain: str) -> dict:
    """`resolve_domain_state` 的**带别名诊断**形态（§17-1①，`ECC-55339EF8A5C6` (b)）。

    返回 `{"path", "alias_from", "alias_to"}`；`alias_*` 非空 ⟹ 命中**别名读映射**
    （目标形态缺失而另一形态存在 ⟹ 读到存在者；**不建/不迁/不改物理文件**）。
    fail-closed 语义与 `resolve_domain_state` 逐字一致（非法 token / 域不符 / 两形态皆缺 → raise）。
    """
    token = (domain or "").strip()
    if not token:
        raise ValueError("--domain 空值（usage: " + _usage_error("register") + "）")
    if not _DOMAIN_TOKEN_RE.match(token):
        raise ValueError("--domain 非法 token " + repr(token)
                         + "（形态 <repo>.<plan>，禁 / 、反斜杠、.. 与前导点）")
    cur = _state_file_domain(state_file)
    if cur and cur != token:
        raise ValueError("FINDING_DOMAIN_MISMATCH: 目标 state 域=" + cur + " 与 --domain=" + token
                         + " 不一致（禁止跨仓写同一 ledger）")
    target = str(Path(state_file).with_name(_STATE_PREFIX + "." + token))
    # 2026-10-19（复审 BLOCK）：旁挂产物（`.credit-ledger.baseline.json` 等）**不是**活体域
    #   state；`os.path.isfile` 会把已存在的 sidecar 判为域 ⟹ `--domain` 写入即毁基线/封印。
    if not _is_live_ledger_name(os.path.basename(target)):
        raise ValueError("FINDING_DOMAIN_ARTIFACT: --domain 指向旁挂产物而非活体域 state: "
                         + repr(token))
    if os.path.isfile(target):
        return {"path": target, "alias_from": "", "alias_to": ""}
    # §17-1①：目标缺失 → 试别名（双形态归一）；命中即读映射，不建/不迁。
    for cand in _domain_alias_candidates(token):
        alt = str(Path(state_file).with_name(_STATE_PREFIX + "." + cand))
        if not _is_live_ledger_name(os.path.basename(alt)):
            continue
        if os.path.isfile(alt):
            return {"path": alt, "alias_from": token, "alias_to": cand}
    raise ValueError("FINDING_DOMAIN_STATE_MISSING: 域化 state 不存在 " + target
                     + "（声明域不静默回退默认 state；先建域化 state 或走 discover --plan 绑定）")


def resolve_domain_state(state_file: str, domain: str) -> str:
    """`--domain <token>` → 域化 state 路径（fail-closed，ECC-C98BDE1D2B3B）。

    - token 须匹配 `^[A-Za-z0-9][A-Za-z0-9._-]*$`（拒绝 / \\ .. 与前导点 → 防路径逃逸）
    - 与传入 state 已携带的域不符 → FINDING_DOMAIN_MISMATCH
    - 目标域化 state 不存在 → FINDING_DOMAIN_STATE_MISSING（**不静默回退默认 state**）
    - §17-1①（2026-10-03）：目标缺失而**另一形态**（`skill.<plan>` ↔ `<plan>`）存在 ⟹ 别名读映射
      （非静默：向 stderr 记 `WARN [domain-alias]`）；两形态皆缺仍 fail-closed。
    """
    r = resolve_domain_state_ex(state_file, domain)
    if r.get("alias_from"):
        sys.stderr.write("WARN [domain-alias] %s → %s（双形态域 state 读映射，§17-1①）\n"
                         % (r["alias_from"], r["alias_to"]))
    return r["path"]


def dual_form_domains(state_file: str) -> list:
    """§17-1③（2026-10-03）：**只读**检测「同计划双形态域 state 并存」。

    在传入 state **同级**目录枚举 `.gatekeeper.state.*`，按基名（**仅**剥 `skill.` 前缀）分组；
    同基名 ≥2 种形态 ⟹ 报 1 条 `{base, forms[]}`。**纯读**（零写 state/文件）。
    异 repo 同基名（`gatekeeper.r7`/`spz2glb.r7`/`r7`）**不**归并 ⟹ 不误报。
    """
    d = Path(state_file).parent
    forms: dict = {}
    for p in sorted(d.glob(_STATE_PREFIX + ".*")):
        name = p.name
        if not _is_live_ledger_name(name):   # [ECC-A48A8204B877] 过滤单源（原内联，漏 bak-* 等标记）
            continue
        tok = name[len(_STATE_PREFIX):].lstrip(".")
        base = tok[len("skill."):] if tok.startswith("skill.") else tok
        forms.setdefault(base, []).append(tok)
    return [{"base": b, "forms": sorted(v)} for b, v in sorted(forms.items()) if len(v) > 1]


def _iter_sources(state_file: str) -> list:
    """只读遍历 (源标签, findings)：传入 state 自身 + 同级**活体**域 state（`.gatekeeper.state.*`）。

    [ECC-A48A8204B877] 过滤**单源** = `_is_live_ledger_name` —— 原为**内联**过滤
    （`endswith((".lock",".seal",".tmp")) or ".jsonl" in name`）⟹ **漏** `bak-*`/`corrupt-*`/
    `pre-budget` 等产物标记 ⟹ 备份被当域读（实测 `bak-compact-20261005T161823Z` 造成 33 对假跨域双源）。
    """
    out = []
    paths = [Path(state_file)] + [p for p in sorted(Path(state_file).parent.glob(_STATE_PREFIX + ".*"))
                                  if _is_live_ledger_name(p.name)]
    for p in paths:
        name = p.name
        s = _read_state(str(p))
        gd = s.get("gate_data") if isinstance(s, dict) else None
        if not isinstance(gd, dict):
            continue
        fs = [f for f in (gd.get("ecc_findings") or []) if isinstance(f, dict)]
        if fs:
            out.append((name[len(_STATE_PREFIX):].lstrip("."), fs))
    return out


def cross_domain_dups(state_file: str) -> list:
    """§G2（2026-10-03）：**只读**跨域重复登记检测（同 `root_key` 跨源）。

    病象：同缺陷在**不同域 state** 各自登记（id 不同、domain 不同）⟹ 一域已 close、另一域仍
    open（实测 `ECC-9D69CA476E5C` open @review-runtime vs `ECC-E2AE7C65A71D` closed @base）。
    **机械键 = 非空 `root_key`**（跨源同 key ⟹ 同根因）。`root_key` 空者**不可机检**（须人工/
    语义 dedup）⟹ 本面**只覆盖有 key 的面**，无 key **不报**（是「未判」非「无重复」，禁误读为干净）。
    """
    by_key: dict = {}
    for src, fs in _iter_sources(state_file):
        for f in fs:
            k = str(f.get("root_key") or "").strip()
            if not k:
                continue
            by_key.setdefault(k, []).append(
                {"source": src, "id": f.get("id"), "status": f.get("status")})
    return [{"root_key": k, "members": v} for k, v in sorted(by_key.items())
            if len({m["source"] for m in v}) > 1]


# ── 只读写前检查面（`ECC-43C982F794B8`，2026-10-14 用户令「读取检查然后写入」）──────────
# 缺口：`register` 只在**锁内**按 `root_key` 静默合并；`cross_domain_dups` 只读检测虽在，却**未接入
#   写前核验** ⟹ 调用方写前**无从**知道「是否已有同根因/同锚登记」。本函数 = 补上对外**只读**面
#   （写侧合并逻辑一字不改）：命中即逐条回报 `id`/`status`/`matched_by`，并顺带回 `cross_domain_dups`。
# 纪律：**只读**（不取锁、不写盘、不重算 checksum）—— 读面 = `load_findings_union`（含 finding 溢出片）。
def check(state_file: str, *, title: str = "", root_key: str = "",
          anchors=None) -> dict:
    """**只读**写前检查：报出与 (title / root_key / anchors) 命中的既有 finding。

    命中判据（任一即命中，逐条记 `matched_by`）：`root_key` 全等 / `title` 全等 / `anchors` 有交集。
    返回 `{"ok":True,"matches":[...],"cross_domain_dups":[...],"checked":{...}}`。**不写盘**。
    """
    rk = (root_key or "").strip()
    tt = (title or "").strip()
    want = [str(a) for a in (anchors or []) if str(a).strip()]
    matches = []
    for f in load_findings_union(state_file):
        if not isinstance(f, dict):
            continue
        hit = []
        if rk and str(f.get("root_key") or "").strip() == rk:
            hit.append("root_key")
        if tt and str(f.get("title") or "") == tt:
            hit.append("title")
        if want:
            inter = sorted(set(map(str, f.get("anchors") or [])).intersection(want))
            if inter:
                hit.append("anchors:" + ",".join(inter))
        if hit:
            matches.append({"id": f.get("id"), "status": f.get("status"),
                            "title": f.get("title"), "root_key": f.get("root_key"),
                            "matched_by": hit})
    return {"ok": True, "matches": matches,
            "cross_domain_dups": cross_domain_dups(state_file),
            "checked": {"root_key": rk, "title": tt, "anchors": want}}


def _write_checksum(state_file: str) -> None:
    """写后重算 `_checksum`（与 gatekeeper-cli.sh `_state_checksum_write` 同算法：
    gate_data 规范化 sha256[:16]）。收敛 ECC-9F21304266C5 同族缺口——写 state 的多入口
    未收敛到统一重算，落盘后 checksum 失配即被 `_state_checksum_verify` 误报 TAMPERED。
    2026-09-25（选项 A）：读-改-写整体持 `state_lock`（唯一锁持有者 = python）。
    """
    with state_lock(state_file):
        s = _read_state(state_file)
        if not s:
            return
        gd = json.dumps(s.get("gate_data", {}), sort_keys=True)
        want = hashlib.sha256(gd.encode()).hexdigest()[:16]
        if s.get("_checksum") == want:
            return                       # 已正确 ⟹ 零写（防 >95% 水位的等量写被拦）
        s["_checksum"] = want
        dump_state(state_file, s)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_state(state_file: str) -> dict:
    try:
        return json.loads(Path(state_file).read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_findings(state_file: str) -> list:
    s = _read_state(state_file)
    return s.setdefault("gate_data", {}).setdefault("ecc_findings", [])


def save_findings(state_file: str, findings: list) -> None:
    # 2026-09-25（选项 A）：读-改-写整体持 `state_lock`（否则并发 register/close 相互覆盖）。
    with state_lock(state_file):
        s = _read_state(state_file)
        gd = s.setdefault("gate_data", {})
        gd["ecc_findings"] = findings
        # 2026-11-02（写崩修复）：checksum 与台账**同一次写**落盘。
        #   原实现先 `save_findings` 再 `_write_checksum` 二次写；后者只改 checksum，
        #   体积不缩 ⟹ 在 >95% 水位被 `_wall_guard` 拦（实测 archive_closed 收缩到
        #   2,600,777 B 后，第二次写 2,600,811 B 被拒）⟹ 修复动作被自己的收尾写阻断。
        s["_checksum"] = hashlib.sha256(
            json.dumps(gd, sort_keys=True).encode()).hexdigest()[:16]
        dump_state(state_file, s)


def spillover_open(state_file: str, max_open: int = 0, *, dry_run: bool = False) -> dict:
    """`ecc_findings` **open 侧溢出出口**（卫星计划 §4 遗漏⑤ · `ECC-43D22663EFB5`）。

    病象：`archive_closed` **只动 closed** ⟹ `open` 集**无回收出口**、单调增长 ⟹ 撑爆主 state
    （实测 `ecc_findings` 90,884 B = 主 state 33.3%，是越 256KB 硬墙的最大单键）。
    处置：open 条数越 `ECC_MAX_OPEN` ⟹ 把**最旧**的 `n_over` 条移出主台账、append 到 finding 卫星片
    （`<state>.finding-archive.jsonl`，经中枢 `gk_satellite.append`，**禁第二直写者**）+ 打 epoch
    `purged_fids`（reconcile 单源认可）；**读侧 `load_findings_union` 透明 union 回读** ⟹ 单源口径不变。
    ⚠ 越线时 `register` **须仍成功**（先溢出再落盘，**禁自锁**）；本函数只挪 `open`，不碰 closed/fixed。
    ⚠ `max_open<=0` ⟹ 由 `gk_json_utils.ECC_MAX_OPEN` 派生（单源）；**同时**按 `ECC_MAX_BYTES`
      （**主判据**，`ECC-6E9040979A70`）溢出 —— 越线是**体积**问题、非清空台账 ⟹ **保留 ≥1 条**。
    """
    import gk_json_utils as JU
    cap_open = int(max_open or 0) or int(getattr(JU, "ECC_MAX_OPEN", 0) or 0)
    cap_bytes = int(getattr(JU, "ECC_MAX_BYTES", 0) or 0)
    findings = load_findings(state_file)
    if not findings:
        return {"ok": True, "spilled": 0, "capped": False, "open": 0, "bytes": 0}

    def _sz(lst):
        return len(json.dumps(lst, ensure_ascii=False).encode("utf-8"))

    def _old(f):
        return str(f.get("created_at") or f.get("first_added") or "")

    opens = [f for f in findings if isinstance(f, dict) and f.get("status") == "open"]
    over_open = max(0, len(opens) - cap_open) if cap_open > 0 else 0
    need_bytes = cap_bytes > 0 and _sz(findings) > cap_bytes
    if over_open <= 0 and not need_bytes:
        return {"ok": True, "spilled": 0, "capped": False,
                "open": len(opens), "bytes": _sz(findings)}
    removed = []
    if over_open > 0:   # ① open-count 轴：open 最旧优先
        removed = sorted(opens, key=_old)[:over_open]
    rm_ids = {id(f) for f in removed}
    remaining = [f for f in findings if id(f) not in rm_ids]
    # ② byte 轴（**主判据**，`ECC-6E9040979A70`）：仍越线 ⟹ 续移「open 优先、再 closed/fixed」最旧，
    #    但**保留 ≥1 条**（体积问题不该清空台账；单条即超 cap 时停在此 floor 并如实上报）。
    if cap_bytes > 0:
        while len(remaining) > 1 and _sz(remaining) > cap_bytes:
            nxt = sorted(remaining, key=lambda f: (
                0 if f.get("status") == "open" else 1, _old(f)))[0]
            removed.append(nxt)
            remaining = [f for f in remaining if f is not nxt]
    if not removed:
        return {"ok": True, "spilled": 0, "capped": False,
                "open": len(opens), "bytes": _sz(findings)}
    if dry_run:   # 安全网（`ECC-DB9EF1F34C0E`）：显式入口默认只报不移（state 逐字不变）
        return {"ok": True, "capped": True, "dry_run": True, "spilled": len(removed),
                "spilled_ids": sorted(str(f.get("id")) for f in removed if f.get("id")),
                "open": sum(1 for f in remaining if f.get("status") == "open"),
                "bytes": _sz(remaining)}
    save_findings(state_file, remaining)
    _write_checksum(state_file)
    try:
        import gk_satellite as _SAT
        _reg = _SAT.append(state_file, "finding", removed,
                           batch_id="finding-spillover", arm=_archive_gen_token())
        if not _reg.get("ok"):
            sys.stderr.write("FINDING_SPILLOVER_FAILED n=%d: %s\n"
                             % (len(removed), _reg.get("error")))
    except Exception as _sx:  # noqa: BLE001 — 边界：中枢不可用 ⟹ 不阻断溢出主流程（stderr 留痕）
        sys.stderr.write("FINDING_SPILLOVER_FAILED n=%d: %s\n" % (len(removed), _sx))
    epoch(state_file, ts=_gen_start_or_earliest(_journal_events(state_file)),
          reason="ecc_findings open/byte 溢出（遗漏⑤）",
          purged_fids=[str(f.get("id")) for f in removed if f.get("id")])
    return {"ok": True, "capped": True, "spilled": len(removed),
            "spilled_ids": sorted(str(f.get("id")) for f in removed if f.get("id")),
            "open": sum(1 for f in remaining if f.get("status") == "open"),
            "bytes": _sz(remaining)}


def load_findings_union(state_file: str) -> list:
    """**读侧 union**（单源口径不变）：主台账 + 本 state 的 finding 溢出片（`*.finding-archive.jsonl`）。

    ⚠ **只读视图** —— 写路径（`register`/`close`/…）**一律**用 `load_findings`（**main-only**），
    否则 union 回写会把溢出片条目**复制回主台账**（F-REV-63 `MU_BACKCAST_NEGATIVE`）。
    按 `id` 去重，**主台账优先**（同 id 以主账状态为准）；缺片 / 坏片不崩（防御式只读）。
    """
    out, seen = [], set()
    for f in load_findings(state_file):
        if isinstance(f, dict):
            fid = f.get("id")
            if fid:
                if fid in seen:
                    continue
                seen.add(fid)
            out.append(f)
    arch = _archive_path(state_file)
    if os.path.isfile(arch):
        for f in _read_findings_source(arch, "archive"):
            if not isinstance(f, dict):
                continue
            fid = f.get("id")
            if fid:
                if fid in seen:
                    continue
                seen.add(fid)
            out.append(f)
    return out


# ── 跨仓 finding 的 `<repo_token>` 索引投影（2026-11-01）──────────────────────────────
# 缺口：跨仓审查/红队的 finding 全落调用方 state ⟹「某仓有多少 open / 多少 stale」只能全台账
#   人肉分桶；而另建一组「卫星库」= 又一份要同步的真相源（用户裁定：**不新建库**）。
# 处置：finding 自带 `repo_token`（显式 `--repo` 优先；否则由 `verify_source=commit:<sha>`
#   解析出的仓根目录名归一），`gate_data.finding_repo_index[<token>]` = **只读投影**（计数，
#   不存 fid 列表 ⟹ 不涨 state 体积）。读面 = `finding status` 的 `repo_index` 字段。
_REPO_INDEX_KEY = "finding_repo_index"
_REPO_TOKEN_MAX = 64                       # token 形态与 source/owner 同纪律：短、无空白
_UNATTRIBUTED = "_unattributed"            # 无 repo_token ⟹ 显式可见（不臆造归属）


def _repo_token(repo_root: str) -> str:
    """仓根 → token（目录名；`C:\\a\\b` / `/a/b` 双形态经归一）。空 → ''。"""
    p = str(repo_root or "").strip().replace("\\", "/")
    if not p:
        return ""
    try:
        return Path(p).name.strip()
    except Exception:  # noqa: BLE001 — 边界：非法路径形态 ⟹ 视为未归属
        return ""


def _resolve_commit_repo(sha: str, repos=None) -> str:
    """`sha` 在**候选仓**中首个可解析者 → 仓根（不可解析 → ''）。"""
    import subprocess
    sha = (sha or "").strip()
    if not sha:
        return ""
    for repo in (repos or [str(DEFAULT_SKILL)]):
        try:
            r = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "--quiet",
                                sha + "^{commit}"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=15)
            if r.returncode == 0:
                return str(repo)
        except Exception:  # noqa: BLE001 — 边界：单仓不可用不阻断其余候选
            continue
    return ""


def _commit_from_verify_source(vsrc: str) -> str:
    """`verify_source` 里的**首个** `commit:<sha>`（无 → ''）。"""
    for k, p in _accept_segments(vsrc):
        if k == "commit" and p:
            return p
    return ""


def _norm_repo_token(repo: str, explicit: str = "") -> str:
    """`--repo` 入参归一：**已存在目录** ⟹ 取目录名；否则按 token 原样（须过形态门）。

    非法形态（超长 / 含空白）⟹ fail-loud（同 `source`/`owner` 纪律：短 token，禁散文）。
    """
    t = (explicit or "").strip()
    if not t:
        return _repo_token(repo)
    cand = t.replace("\\", "/")
    try:
        if os.path.isdir(t) or os.path.isdir(cand):
            return _repo_token(cand)
    except Exception:  # noqa: BLE001
        pass
    if len(t) > _REPO_TOKEN_MAX or any(c.isspace() for c in t) or "/" in cand or ":" in cand:
        raise ValueError("--repo 非法: %r（须为**已存在**仓根目录，或 ≤%d 字无空白 token）"
                         % (explicit, _REPO_TOKEN_MAX))
    return t


def _attr_repo_token(state_file: str, f: dict, vsrc: str = "") -> str:
    """给 finding 补 `repo_token`（已有则不动；缺省时由 `verify_source=commit:<sha>` 派生）。

    派生失败（无 commit 段 / sha 不可解析）⟹ 返回 '' 且**不写字段**（归 `_unattributed`，
    不臆造归属）。只在**写路径**调用（register/close/verify）⟹ 无 git 往返成本在只读面上。
    """
    cur = str(f.get("repo_token") or "").strip()
    if cur:
        return cur
    sha = _commit_from_verify_source(vsrc or str(f.get("verify_source") or ""))
    if not sha:
        return ""
    tok = _repo_token(_resolve_commit_repo(sha, _candidate_repos(state_file)))
    if tok:
        f["repo_token"] = tok
    return tok


def _project_repo_index(findings) -> dict:
    """纯函数投影：`ecc_findings` → `{<token>: {total, open, closed, stale, updated_at}}`。"""
    idx: dict = {}
    now = _now()
    for f in (findings or []):
        if not isinstance(f, dict):
            continue
        tok = str(f.get("repo_token") or "").strip() or _UNATTRIBUTED
        e = idx.setdefault(tok, {"total": 0, "open": 0, "closed": 0, "stale": 0,
                                 "updated_at": now})
        e["total"] += 1
        st = str(f.get("status") or "open")
        if st == "open":
            e["open"] += 1
        elif st in ("closed", "verified"):
            e["closed"] += 1
        if f.get("stale"):
            e["stale"] += 1
    return idx


def _refresh_repo_index(state_file: str) -> dict:
    """重算 `gate_data.finding_repo_index`（**投影**，非第二真相源）。

    单源 = `ecc_findings[].repo_token`（写路径维护；本函数**不做** git 解析 ⟹ 常数级）。
    每 token：`{total, open, closed, stale, updated_at}`；无 token 者归 `_unattributed`。
    持 `state_lock` 重读后**只写该键**并同批重算 `_checksum`（同 `_write_checksum` 算法单源）。
    """
    with state_lock(state_file):
        s = _read_state(state_file)
        if not s:
            return {}
        gd = s.setdefault("gate_data", {})
        idx = _project_repo_index(gd.get("ecc_findings") or [])
        gd[_REPO_INDEX_KEY] = idx
        s["_checksum"] = hashlib.sha256(json.dumps(gd, sort_keys=True).encode()).hexdigest()[:16]
        dump_state(state_file, s)
    return idx


# ── RED 引擎台账 upsert（F8 / ECC-7F497B4805F5，2026-09-18）──
# 现场：`gatekeeper-cli.sh` 的 `RED_RESULT` 直写段按 `evidence_hash` 去重，而
#   `_red_attacks` 的 `site_digest` 把**全部命中站点**（file:line）滚动 sha256 吞进 evidence
#   （设计意图：第 9+ 处被篡改时不被"样例有损"吞掉）⟹ **仓库一变 hash 就变**，同 id 必然再入账
#   ⟹ 实测 `RED-EXPLOIT-subagent_history` ×5 / `RED-RECUR-DEVSOURCE` ×2（32 记录 / 27 唯一 id）。
# 处置（A3 ①，用户裁定）：去重键改 **id**，同 id 走 upsert ——
#   `first_added` 不回溯（保留最早）；内容变（`evidence_hash` 变）才推进 `last_modified`
#   （对齐 `_red_attacks.red_report` 的 F-REV-90 双语义：first_added 永不改写 / last_modified 内容变才改写）。
def upsert_red_findings(state_file: str, new: list) -> dict:
    """RED 引擎 finding 台账 upsert（键 = `id`）。返回 added/updated/unchanged/duplicate_ids。

    - 同 id 且 `evidence_hash` 相同 ⟹ `unchanged`（**不写盘**，重放幂等）；但若新记录携带
      旧记录**缺失**的派生元数据（如 `root_key`）⟹ 补写并计 `updated`（不推 `last_modified`、
      不入状态机 journal —— 状态未变，见 2026-10-26 注释）
    - 同 id 且 hash 不同 ⟹ 合并更新：新记录为准 + 旧记录里新记录缺的字段保留；
      `first_added` 取旧值、`last_modified` 取新值
    - 无 `id` 的记录**跳过**（不留脏记录）
    - `duplicate_ids` = 写入后**仍存在多条**的 id（存量异常可见化；清理须显式授权，本函数不删）

    **2026-09-25 修复（`ECC-685DDE20F8AB`）—— 本通路也必须入 journal**：
    病象（实测）：本函数只走 `save_findings` + `_write_checksum`，**不写 finding journal**
    ⟹ RED 引擎把**已 close** 的 fid 重新 upsert 成 `status=open`（RED 记录自带 `status:"open"`）
    时，journal 末事件仍是 `to=closed` ⟹ `finding reconcile` 恒报「state 被回滚」（实测 6 条：
    `RED-CONSTRAINTS-01/02`、`RED-MIGRATE-INLINE/SWALLOW/DANGER/FD`）；且**无自愈通道** —— 同
    hash 重放走 `unchanged` 分支、既不落盘也不留痕 ⟹ 缺口永不闭合。
    规则（单一判据，只为闭合 `reconcile_pair` 的两类失配而写）：
      ① `added` 必留锚（新记录无任何前序事件）；② `updated` 必留痕（真变更）；
      ③ **「重开」自愈** —— journal 末事件为终态而 state=`open` 时补记（覆盖同 hash 重放）。
      ⚠ 只修「终态 → `open`」**这一向**（RED 引擎已知合法转换：F8 实测「仓库一变
      `evidence_hash` 就变 ⟹ 同 id 必再入账」）；**反向不修** —— state=终态而 journal 无锚 =
      「伪造裁决候选」，必须保持 fail-loud，**不得把该信号洗掉**。
    """
    findings = load_findings(state_file)
    # 处置前强制回环闸（**降级放行**，§2.4-a）：upsert 属**写面**；RED 自动化面无交互出口 ⟹
    #   命中 drifted 的 fid **逐条跳过**（本轮不 upsert，下次重放再试），余者照写；不硬阻断。
    _pass = _precheck_degrade(state_file, [f.get("id") for f in (new or []) if f.get("id")])
    idx = {}
    for i, f in enumerate(findings):
        idx.setdefault(f.get("id"), i)
    added = updated = unchanged = 0
    _touched = []                       # ① ②：真新增 / 真变更的 (fid, 旧 status) —— 必留痕
    for f in (new or []):
        fid = f.get("id")
        if not fid:
            continue
        if str(fid) not in _pass:          # 降级：drifted fid 跳过本轮写入
            continue
        i = idx.get(fid)
        if i is None:
            findings.append(dict(f))
            idx[fid] = len(findings) - 1
            added += 1
            _touched.append((fid, ""))
            continue
        old = findings[i]
        if old.get("evidence_hash") == f.get("evidence_hash"):
            # 同内容重放：若新记录携带旧记录**缺失**的派生元数据（如 root_key，schema 演进），
            # 补写该字段 —— 否则新族键永远进不了台账（evidence_hash 不含它 ⟹ 恒走本分支）。
            # 只补缺失键：不推 first_added/last_modified（内容未变），也不入状态机 journal。
            gaps = {k: v for k, v in f.items() if k not in old and v is not None}
            if gaps:
                old.update(gaps)
                findings[i] = old
                updated += 1
            else:
                unchanged += 1
            continue
        merged = dict(old)
        merged.update({k: v for k, v in f.items() if v is not None})
        merged["first_added"] = old.get("first_added") or f.get("first_added")
        merged["last_modified"] = f.get("last_modified") or old.get("last_modified")
        findings[i] = merged
        updated += 1
        _touched.append((fid, old.get("status", "open")))
    if added or updated:
        save_findings(state_file, findings)
        _write_checksum(state_file)

    # ── 对账锚入账（单一判据；见 docstring ①②③）；state 先落盘、再补锚（对齐 register/close 次序）──
    _evs_by_fid = {}
    for _e in _journal_events(state_file):
        if _e.get("event") != _EPOCH_EVENT and _e.get("fid"):
            _evs_by_fid.setdefault(str(_e["fid"]), []).append(_e)
    _TERMINAL = ("closed", "fixed", "rejected")
    _st_by_fid = {str(f.get("id")): f.get("status", "open") for f in findings if f.get("id")}
    _journaled = set()
    for fid, _from in _touched:                                       # ① ②
        _append_journal(state_file, {"ts": _now(), "event": "upsert", "fid": fid,
                                     "from": _from,
                                     "to": _st_by_fid.get(str(fid), "open"),
                                     "source": "red_engine"})
        _journaled.add(str(fid))
    for fid, st in _st_by_fid.items():                                # ③ 重开自愈
        if st != "open" or fid in _journaled:
            continue
        _last_to = next((e.get("to") for e in reversed(_evs_by_fid.get(fid) or [])
                         if e.get("to")), None)
        if _last_to in _TERMINAL:
            _append_journal(state_file, {"ts": _now(), "event": "upsert", "fid": fid,
                                         "from": _last_to, "to": "open",
                                         "source": "red_engine:reopen_repair"})
            _journaled.add(fid)
    counts = {}
    for f in findings:
        fid = f.get("id")
        if fid:
            counts[fid] = counts.get(fid, 0) + 1
    return {"ok": True, "added": added, "updated": updated, "unchanged": unchanged,
            "total": len(findings), "unique": len(counts),
            "duplicate_ids": sorted(k for k, v in counts.items() if v > 1),
            "journaled": len(_journaled)}


def prune_duplicates(state_file: str) -> dict:
    """台账**存量**同 id 重复清理（保留**首条**），写 journal 留痕。返回 pruned/duplicate_ids。

    背景（2026-09-19 实测）：`upsert_red_findings` 的 docstring 明写「清理须显式授权，
    本函数**不删**」，而 `close()` 只改**第一条**匹配 ⟹ 同 id 多条的存量记录
    （实测 `RED-EXPLOIT-subagent_history` 5 条 / `RED-RECUR-DEVSOURCE` 2 条，均为早年按
    `evidence_hash` 去重的病灶产物）**既关不掉也删不掉**。本函数补该路径。

    语义（三条都可机检，判据见 `test_gk_finding.py`）：
      - **保留首条**（不取最先 closed 的那条）—— 首条是 `first_added` 最早的载体；
      - **可复算**：返回 `pruned` / `duplicate_ids`，非重复项**顺序不变**；
      - **留痕**：每个被剔除的 id 写一条 `prune_duplicate` journal 事件（对齐 close/verify）。
    ⚠ 同 id **内容已合并**的场景（F8 的 upsert 结果）不该走本函数 —— upsert 已把新内容并进
    首条，余下的才是真脏记录。无 `id` 的记录**不参与**去重（保留原位）。
    """
    findings = load_findings(state_file)
    # 处置前强制回环闸（**降级放行**，§2.4-a）：prune 属**写面**（删重复条目）；内部面无交互
    #   出口 ⟹ 命中 drifted 的 fid **逐条跳过**（保留其重复，不删），余者照删；不硬阻断。
    _cnt = {}
    for _f in findings:
        if _f.get("id"):
            _cnt[_f["id"]] = _cnt.get(_f["id"], 0) + 1
    _pass = _precheck_degrade(state_file, [k for k, v in _cnt.items() if v > 1])
    seen, kept, dup_ids, dropped = set(), [], [], 0
    for f in findings:
        fid = f.get("id")
        if fid and fid in seen:
            if str(fid) not in _pass:       # 降级：drifted fid 跳过（不清重复）
                kept.append(f)
                continue
            dup_ids.append(fid)
            dropped += 1
            continue
        if fid:
            seen.add(fid)
        kept.append(f)
    if dropped:
        save_findings(state_file, kept)
        _write_checksum(state_file)
        for fid in sorted(set(dup_ids)):
            _append_journal(state_file, {"ts": _now(), "event": "prune_duplicate",
                                         "fid": fid, "dropped": dup_ids.count(fid),
                                         "kept": "first"})
    return {"ok": True, "pruned": dropped, "duplicate_ids": sorted(set(dup_ids)),
            "total": len(kept), "unique": len(seen)}


def _journal_path(state_file: str) -> str:
    """裁决日志（第二副本锚）路径：独立于 state 文件的 .finding-journal.jsonl。"""
    return state_file + _JOURNAL_SUFFIX


def _journal_key():
    """journal 事件签名密钥（HMAC-SHA256，C 接线 2026-10-16）。缺失 ⟹ `b""`（降级，不冒充已签）。

    取值优先级：`GK_JOURNAL_KEY` → `GATEKEEPER_HMAC_KEY`（既有单源，CLI 供给）。**不新建密钥文件**
    （避免触碰 `.keys/` 与轮换纪律）；无钥时事件仍入链但 `sig=""`/`sig_alg="none"`（显式可观测）。
    """
    for _name in ("GK_JOURNAL_KEY", "GATEKEEPER_HMAC_KEY"):
        v = os.environ.get(_name, "")
        if v:
            try:
                return bytes.fromhex(v) if len(v) == 64 else v.encode()
            except ValueError:
                return v.encode()
    return b""


def _journal_prev_hash(path: str) -> str:
    """上一行（最后一条非空）原始文本的 sha256 hex；文件缺失/空 ⟹ `""`（链头）。"""
    try:
        with open(path, "rb") as jf:
            data = jf.read()
    except OSError:
        return ""
    lines = [ln for ln in data.split(b"\n") if ln.strip()]
    if not lines:
        return ""
    return hashlib.sha256(lines[-1]).hexdigest()


def _journal_canon(rec: dict) -> str:
    """签名/验签共用的**规范串**（`sort_keys` + 紧凑分隔，**排除 `sig` 自身**）。"""
    return json.dumps({k: rec[k] for k in rec if k != "sig"}, sort_keys=True,
                      ensure_ascii=False, separators=(",", ":"))


def _append_journal(state_file: str, entry: dict) -> None:
    """append-only 入账；写入失败不阻断主流程（journal 缺失由 reconcile 显式暴露，不静默吞）。

    **C 接线（2026-10-16，owner 裁定「事件级签名 + 哈希链」）**：每行 = `{**entry, journal_v:2,
    prev:<上一行 sha256>, sig:<HMAC(prev+canonical)>, sig_alg:…}`。
      · `prev` = **哈希链**（改/删/插任一行 ⟹ 后续每次 `prev` 失配 ⟹ 断链可机检）；
      · `sig`  = **事件真实性**（需密钥；对称 HMAC —— 提供完整性/防篡改，非公开可验证的不可否认）。
    无钥 ⟹ `sig=""`/`sig_alg="none"`（**显式降级**，不冒充已签）。向后兼容：旧行为（仅写 entry）
    升级为带链字段；读取方按 `journal_v` 缺省视为 legacy（见 `verify_journal`）。
    """
    path = _journal_path(state_file)
    prev = _journal_prev_hash(path)
    key = _journal_key()
    rec = dict(entry)
    rec["journal_v"] = 2
    rec["prev"] = prev
    if key:
        rec["sig_alg"] = "hmac-sha256"          # ⚠ 须在算 canonical **之前**置位（否则 append/verify 规范串不等）
        rec["sig"] = hmac.new(key, (prev + _journal_canon(rec)).encode("utf-8"),
                              hashlib.sha256).hexdigest()
    else:
        rec["sig"] = ""
        rec["sig_alg"] = "none"
    try:
        with open(path, "a", encoding="utf-8") as jf:
            jf.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def verify_journal(state_file: str) -> dict:
    """只读**验链 + 验签**（C 接线）。返回 `{ok,total,signed,legacy,degraded,broken[]}`。

    `broken[].reason` ∈ {invalid_json, chain_break, bad_sig}；**legacy（无 `journal_v`）不计断裂**
    （向后兼容，单独计数 `legacy`）。`ok=False` ⟹ 存在篡改/断链/坏签，**fail-loud**。
    """
    path = _journal_path(state_file)
    try:
        with open(path, encoding="utf-8") as jf:
            raw_lines = [ln.rstrip("\n") for ln in jf]
    except OSError:
        return {"ok": False, "error": "JOURNAL_MISSING", "total": 0, "signed": 0,
                "legacy": 0, "degraded": not _journal_key(), "broken": []}
    key = _journal_key()
    prev, total, signed, legacy, broken = "", 0, 0, 0, []
    for idx, ln in enumerate(raw_lines):
        if not ln.strip():
            continue
        total += 1
        try:
            rec = json.loads(ln)
        except ValueError:
            broken.append({"line": idx, "reason": "invalid_json"})
            prev = hashlib.sha256(ln.encode("utf-8")).hexdigest()
            continue
        if rec.get("journal_v") == 2:
            if rec.get("prev") != prev:
                broken.append({"line": idx, "reason": "chain_break"})
            if rec.get("sig"):
                signed += 1
                if key:
                    exp = hmac.new(key, (prev + _journal_canon(rec)).encode("utf-8"),
                                   hashlib.sha256).hexdigest()
                    if rec["sig"] != exp:
                        broken.append({"line": idx, "reason": "bad_sig"})
        else:
            legacy += 1
        prev = hashlib.sha256(ln.encode("utf-8")).hexdigest()
    return {"ok": not broken, "total": total, "signed": signed, "legacy": legacy,
            "degraded": (not key), "broken": broken}


def _journal_events(state_file: str) -> list:
    path = _journal_path(state_file)
    events = []
    try:
        with open(path, encoding="utf-8") as jf:
            for line in jf:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    except (OSError, ValueError):
        return events  # 缺失/损坏：交由 reconcile 判定（损坏=潜在清洗信号，由调用方读 event 计数为 0 暴露）
    return events


def reconcile_pair(findings: list, events: list, gen_start: str = "") -> dict:
    """ECC 裁决状态机对账核心（单源；C8 live reconcile 与 C10 archived ember replay 共用，防双写）。

    anomalies（四形态）：
      - journal 缺失但 findings 有（全量清洗/输出被全改无对账证据）
      - closed/fixed/rejected 无任何前序 journal 事件（伪造裁决）
      - journal 末事件为 closed/fixed 但 state=open（state 被回滚）
      - journal 有记录但 findings 无此 finding（记录被删）

    archived 口径（C10）：调用方先按 fid ∈ findings 做相位作用域过滤（跨相位合法 closure
    不误报残留），再传本函数；返回 {"ok","events","findings","anomalies"}。

    gen_start（F-REV-23，2026-09-11）：**代际过滤** —— 只对 `ts >= gen_start` 的事件对账。
    背景：journal 是 append-only 且**跨 state 代际存活**（文件名 = `<state>.finding-journal.jsonl`），
    state 代际更替（重建/轮换）后前代 fid 仍留在 journal ⇒ 原逻辑恒报「记录被删」（实测 15 项）。
    gen_start = 最近一次显式 epoch 标记的 ts（见 `epoch()`）；**空串 = 不过滤**（向后兼容，
    archived replay 传空以保持其相位作用域原语义）。epoch 标记自身不计入事件账。

    purged（F7 / ECC-0D66677798EE，2026-09-18）：任一代际标记可用 `purged_fids` **显式声明出域/清洗**
    的 fid ⟹ 这些 fid 从「journal 有事件但 state 无此 finding（记录被删）」类**排除**，单列于
    `purged` 供审计。**未声明**者仍照报（检测能力不退化：静默清洗依旧暴露）。
    背景：2026-09-11 域隔离迁移的 10 条纯技能域记录在后续一次未留痕台账重置中消失，journal
    只剩逐条 `reanchor` ⟹ 对账器无法区分「声明出域」与「真丢失」，只能永久 FAIL 10 项。
    """
    evs_src = [e for e in events if e.get("event") != _EPOCH_EVENT]
    if gen_start:
        evs_src = [e for e in evs_src if str(e.get("ts", "")) >= gen_start]
    purged = set()
    for e in events:
        if e.get("event") == _EPOCH_EVENT:
            purged.update(str(x) for x in (e.get("purged_fids") or []) if str(x))
    live = {f["id"]: f for f in findings if "id" in f}
    by_id = {}
    for e in evs_src:
        by_id.setdefault(e.get("fid", ""), []).append(e)
    anomalies = []
    if not events and live:
        anomalies.append({"fid": "*", "status": "",
                          "reason": f"journal 缺失（state 有 {len(live)} 条 finding，无 {_JOURNAL_SUFFIX} 对账锚）"})
    for fid, f in live.items():
        evs = by_id.get(fid, [])
        st = f.get("status", "open")
        if st in ("closed", "fixed", "rejected") and not any(e.get("to") == st for e in evs):
            anomalies.append({"fid": fid, "status": st,
                              "reason": "无 journal 前序事件（" + st + " 无对账锚 = 伪造裁决候选）"})
        # 判据 = **最后一个带 `to` 的事件**（非「末事件」）：`precheck_ack` 等**非状态转移**事件
        #   尾插后，`evs[-1]` 无 `to` ⟹ 会**掩蔽**回滚检测（恒不报）；故取最新状态转移事件。
        _last_to = next((e.get("to") for e in reversed(evs) if "to" in e), None)
        if st == "open" and evs and _last_to in ("closed", "fixed", "rejected"):
            anomalies.append({"fid": fid, "status": st,
                              "reason": "journal 末事件=" + str(_last_to) + " 但 state=open（state 被回滚）"})
    for fid, evs in by_id.items():
        if fid not in live and evs:
            if fid in purged:
                continue   # epoch 显式声明的出域/清洗 ⟹ 已解释，不计异常（单列于 purged）
            anomalies.append({"fid": fid, "status": "",
                              "reason": "journal 存在 " + str(len(evs)) + " 事件但 state 无此 finding（记录被删）"})
    return {"ok": not anomalies, "events": len(evs_src), "raw_events": len(events),
            "findings": len(live), "anomalies": anomalies, "purged": sorted(purged)}


def _last_epoch(events: list) -> str:
    """最近一次 epoch 代际标记的 ts（无 → 空串 = 不过滤，向后兼容）。"""
    ts = ""
    for e in events:
        if e.get("event") == _EPOCH_EVENT and e.get("ts"):
            ts = str(e["ts"])
    return ts


def epoch(state_file: str, ts: str = "", reason: str = "", purged_fids=None) -> dict:
    """打一个**代际标记**（F-REV-23）：journal 里 append `{"event":"epoch"}`。
    state 代际更替（重建/轮换/归档）后调用，使 reconcile 只对标记**之后**的事件对账。
    `ts` 可显式指定代际起点（回填历史边界）；缺省 = 现在。

    `purged_fids`（F7 / ECC-0D66677798EE，2026-09-18）：显式声明**出域/清洗**的 fid ⟹
    `reconcile_pair` 把它们从「记录被删」异常类排除并单列 `purged`。
    ⚠ **回填历史出域必须复用原 gen_start 的 ts**（缺省 `_now()` 会把代际起点推到今天，
    把前代事件整体踢出对账 scope = 顺手关掉那段的对账能力）。
    """
    at = ts or _now()
    pf = [str(x) for x in (purged_fids or []) if str(x)]
    entry = {"ts": at, "event": _EPOCH_EVENT, "reason": reason}
    if pf:
        entry["purged_fids"] = pf
    _append_journal(state_file, entry)
    return {"ok": True, "epoch": at, "reason": reason, "purged_fids": pf,
            "journal_path": _journal_path(state_file)}


def reconcile(state_file: str) -> dict:
    """finding_journal_reconcile（C8/f7）：live journal 重放对账 state.ecc_findings。

    委托 reconcile_pair（单源）；archived 版本 = gk_ember_replay.reconcile_ember。
    F-REV-23：以最近一次 epoch 标记的 ts 作 gen_start（代际过滤），避免前代 fid 误报。
    """
    if not os.path.isfile(state_file):
        return {"check": "finding_journal_reconcile", "ok": True,
                "detail": "state_file_not_found", "journal_path": _journal_path(state_file)}
    findings = load_findings(state_file)
    events = _journal_events(state_file)
    gen = _last_epoch(events)
    r = reconcile_pair(findings, events, gen_start=gen)
    return {"check": "finding_journal_reconcile", "ok": r["ok"],
            "journal_path": _journal_path(state_file), "gen_start": gen,
            "events": r["events"], "raw_events": r["raw_events"],
            "findings": r["findings"], "anomalies": r["anomalies"],
            "purged": r["purged"]}


def _split_layers(v) -> list:
    """cover_layers 入参归一：字符串（, 或 ; 分隔）或 list → 干净 str 列表。"""
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    return [x.strip() for x in str(v).replace(";", ",").split(",") if x.strip()]


def _valid_layer_set():
    """合法审查层集（单源 = gk_self_check.REVIEW_LAYERS，C1/E4）；不可导入 → None（跳过校验）。"""
    try:
        from gk_self_check import REVIEW_LAYERS
        return set(REVIEW_LAYERS)
    except Exception:
        return None


def _uniq_str(xs):
    """字符串列表去重（保序、去首尾空白、丢空串）—— anchors/facets 的单一归一化点。"""
    out, seen = [], set()
    for x in (xs or []):
        s = str(x).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _extend_unique(rec: dict, key: str, xs) -> None:
    """把 xs 并入 rec[key]（去重保序）—— root_key 合并路径（ECC-BA7224C3B2A2）的唯一入口。"""
    rec[key] = _uniq_str(list(rec.get(key) or []) + list(xs or []))


# ④ 同配额替换（2026-10-10，ECC-81F6D83D153B）：`assess_findings` 的**单次评估**产物（分类 / 载体 /
#   度量）在 `root_key` 合并（= 同 (plan,batch) **重跑**）时须**后写覆盖**，而非 `_extend_unique`
#   式**叠加** —— 实测 `ECC-9186B25360D6` 出现两个 `classification:`（infra-defect + plan-error）
#   与 `refs:6`+`refs:2`（`ECC-6A8E27475130` 同型 `refs:2`+`refs:8`）⟹ 下游
#   `gk_moa_aggregate._facet_value("refs")` 取**首个** = 读错批号、丢另一轮。
#   标量命名空间 = 后写覆盖；其余（`provenance:` 标记 / 自由文本 facet / `relevance:` 等）保持并入。
_SCALAR_FACET_NS = ("classification", "carrier", "refs", "clusters", "weight", "class-tie",
                    # 2026-10-10（ECC-0BA041A4284E）：MoA 聚合 finding 的**身份 facet**
                    #   （batch/plan/cross-batch）同为标量 —— 同 root_key 重跑须后写覆盖，禁叠加。
                    "batch", "plan", "cross-batch")


def _merge_facets(rec: dict, xs) -> None:
    """facets 合并：**标量命名空间后写覆盖**（禁叠加），其余去重保序并入（`_uniq_str` 归一）。"""
    old = [str(x).strip() for x in (rec.get("facets") or []) if str(x).strip()]
    new = [str(x).strip() for x in (xs or []) if str(x).strip()]
    new_ns = {s.split(":", 1)[0] for s in new if ":" in s} & set(_SCALAR_FACET_NS)
    keep = [s for s in old
            if not (":" in s and s.split(":", 1)[0] in new_ns)]
    rec["facets"] = _uniq_str(keep + new)


# 派生标题刷新（2026-10-10，ECC-60BF82183364）：**自动生成、含易变计数**的标题（如
#   `MoA聚合批裁决: batch=… n=… clusters=… suspect=… <class>`）在同 `root_key` **重跑**时须刷为
#   最新 —— 否则 title 与 facets 口径分叉（facets 已后写覆盖；实测 `ECC-6A8E27475130`
#   title `n=2 clusters=1 unknown` vs facets `refs:8 / infra-defect`）= 人读被误导。
#   **仅**前缀命中的派生标题参与刷新；人工/策展标题一律不动（防覆盖）。历史不丢：merge 路径
#   已把**每次新标题**记入 journal（`{"event":"merge",…,"title":<new>}`，L1112-1114）⟹ title 可刷新。
_DERIVED_TITLE_PREFIXES = ("MoA聚合批裁决: ",)


def _is_derived_title(t) -> bool:
    s = str(t or "")
    return any(s.startswith(p) for p in _DERIVED_TITLE_PREFIXES)


def _refresh_derived_title(rec: dict, new_title: str) -> bool:
    """同 root_key 重跑时把**派生标题**刷为最新（防 title↔facets 分叉）；非派生标题不动。

    返回是否刷新。要求**新旧标题同为派生**（防「人工标题 + 派生标题」混用 root_key 时误覆盖人工侧）。
    """
    if (new_title and _is_derived_title(new_title) and _is_derived_title(rec.get("title"))
            and rec.get("title") != new_title):
        rec["title"] = new_title
        return True
    return False


def _gate_writable(state_file: str) -> None:
    """② 写门（D3 opt-in）：写类入口**进入前**校验形态 + opt-in（单源 = `gk_state_forms`）。

    形态 ∈ `WRITABLE_FORMS`（`base`/`domain`）；写 `domain` 形态时，若**有计划上下文**
    （env `GK_PLAN_FILE`）则须该计划已声明 `META.state_domain`，否则 fail-loud
    `STATE_FORM_NOT_OPTED_IN`。无计划上下文 ⟹ 仅形态门（零回归，兼容既有 `--domain` 写）。
    """
    import gk_state_forms as _gsf
    _pf = os.environ.get("GK_PLAN_FILE", "") or ""
    # ECC-D652357E13AB：`resolve_plan_state` 返回 **dict**（见本模块同名单源），原
    #   `.declared_domain` 属性访问 ⟹ 只要进程导出 `GK_PLAN_FILE` 即 `AttributeError`
    #   （阻断 finding 注册 / `moa-aggregate` 的 emit）。改**按键取值**。
    _pd = (resolve_plan_state(state_file, _pf) or {}).get("declared_domain") if _pf else None
    _gsf.assert_writable_form(state_file, plan_declared=_pd)


def _evidence_hash(title: str, root_key: str, family: str, anchors) -> str:
    """finding 内容指纹（确定性、可复算）：`title + root_key + family + 锚(排序去重)`。

    P1（2026-10-04）：**单一算法源** —— `register` 新建与 merge 回填共用（防两式漂移）。
    """
    return hashlib.sha256("\x00".join([
        title or "", root_key or "", family or "",
        ",".join(sorted(_uniq_str(anchors))),
    ]).encode("utf-8")).hexdigest()[:16]


def _scan_taint(text: str) -> list:
    """T5-d **写入时**污点扫描：复用 `gk_moa_aggregate.poison_labels`（单源词表 + 多候选面）。

    检测面不可用（导入失败）⟹ 返回 `[]`（**fail-open**：不在登记处硬阻断；后果性汇点仍有硬门）。
    """
    try:
        from gk_moa_aggregate import poison_labels
    except Exception:  # noqa: BLE001
        return []
    try:
        return poison_labels(text)
    except Exception:  # noqa: BLE001
        return []


def _sink_blocked(f: dict) -> bool:
    """T5-a 能力硬门判据：**不可信来源且未 declassify** ⟹ 后果性汇点（release/close/verify）禁行。"""
    return str(f.get("provenance", "trusted")) == "untrusted" and not f.get("declassified")


def _declassify_inplace(f: dict) -> None:
    """就地解密（置 declassified + facet）；不动 provenance（保 taint 可追溯）。"""
    f["declassified"] = True
    _extend_unique(f, "facets", ["declassified"])


def _guard_precheck(state_file: str, fids, ack=None) -> None:
    """**处置前强制回环闸**（Plan-2 / ECC-6E2F2261410D）：写入口**前置**的「锚判决」硬门。

    动机（owner 裁定）：预检是**处理每条 ECC 前的必要流程**，不区分处置方 ⟹ 闸落在**写入口内**
    （不依赖调用方自觉）。判决引擎 = `gk_ecc_review.classify_anchor(..., "existence")`
    （**单一源**，与 `scan_title_anchors` 同一引擎，禁第二套）；标题面 = `_live_title`
    （刷锚段按序代入后）；锚提取 = `gk_ecc_review.extract_anchors`（A v2，含字面值）；根 = **候选仓集合**
    （`_candidate_repos`：env `GK_FINDING_REPOS` → 技能仓 → state 所在仓 → CWD 所在仓 → 同级仓；
    **跨仓默认** `ECC-ECDB1C9C2B1D`；技能仓经 `DEFAULT_SKILL` 模块全局逐调用取 ⟹ 可被测试 monkeypatch）。

    - **按 fid 过滤**：只扫 `fids` 命中的 finding（`scan_title_anchors` 无 fid 形参 ⟹ 其返回体
      无法直接复用；本处复用其**判决引擎与三个单源**，**不**扫全台账、**不**越权扫无关 fid）。
    - 命中 ⟹ `raise ValueError("ECC_PRECHECK_DRIFT: <fid> 锚 <anchor> <verdict>（detail）")`。
    - `ack=True`（CLI `--ack-drift` 由 `main` **显式透传**）⟹ **放行 + journal 记 `precheck_ack`**
      （逐 fid 一条）。schema = `{"event":"precheck_ack","fid":<fid>,"ts":<ISO>,"drift":[…]}`
      —— **必带 `fid`**（缺则 `reconcile_pair` 归入 `""` ⟹ 永久假 FAIL「记录被删」）、
      **禁带 `to`**（非状态转移事件，会与 `reconcile_pair` 的 `to==st` / 末事件判据串扰）。
      `ack=None` 时回退 env `GK_FINDING_ACK_DRIFT`（仅供外部手动放行；CLI **不再**置该 env）。
    - 开关：env `GK_FINDING_PRECHECK=0` ⟹ SKIP（默认 `1` = 强制）。
    - **覆盖边界（§9-7 方案 B，2026-10-07）**：本闸只覆盖 **`gk_finding` 模块内的写入口**；`ecc_findings`
      的两条**模块外整份替换**写者（`gk_discover_carry.carry_over` / `gk_state_patch.cmd_update_gate_data`）
      **不受闸约束**（显式已知边界，见各自 docstring）。
    - `fids` 空 / state 不存在 / 无锚 / 无漂移 ⟹ **零动作**（纯读，不建文件、不写盘）。
    """
    if str(os.environ.get("GK_FINDING_PRECHECK", "1")).strip() == "0":
        return
    if ack is None:
        ack = str(os.environ.get("GK_FINDING_ACK_DRIFT", "")).strip() not in ("", "0", "false")
    drifted = _scan_drift(state_file, fids)
    if not drifted:
        return
    if ack:
        _journal_precheck_ack(state_file, drifted)
        return
    raise ValueError("ECC_PRECHECK_DRIFT: " + "; ".join(
        "%s 锚 %s %s（%s）" % (d["fid"], d["anchor"], d["verdict"], d["detail"])
        for d in drifted))


def _drift_detail(v: dict, hi: int, missing_text: str = "仓内不可解析") -> str:
    """drifted 项 detail 渲染（existence 面 · A v2 的四类非 `ok` 判决）。

    `line_over_eof` 的 `<hi> > EOF <n>` **逐字保持** A v1；`file_missing` 文案由调用面给
    （`_scan_drift` =「候选仓内不可解析」，`scan_title_anchors` =「仓内不可解析」）。
    """
    verdict = v.get("verdict")
    if verdict == "file_missing":
        return missing_text
    if verdict == "line_over_eof":
        return "%d > EOF %s" % (hi, v.get("eof"))
    if verdict == "line_drift":
        return "字面值 `%s` 漂至 :%s" % (v.get("literal"), v.get("suggested_line"))
    if verdict == "literal_missing":
        return "字面值 `%s` 全文无命中" % v.get("literal")
    return str(verdict)


def _scan_drift(state_file: str, fids) -> list:
    """对 `fids` 命中的 finding 跑**锚判决单一源**，返回 drifted 明细（只读：不写盘、不抛）。

    抽为独立函数（Plan-2 修正）：`_guard_precheck`（硬门）与 `_precheck_degrade`（降级放行）
    共用**同一次扫描**，避免逐 fid 重建仓索引（N 次 `_build_index`）。
    """
    wanted = {str(x) for x in (fids or []) if str(x)}
    if not wanted or not os.path.isfile(state_file):
        return []
    from gk_plan_lint import _lazy_index, _resolve_path
    import gk_ecc_review   # 函数级（禁置顶 from-import）：装载期零耦合 + monkeypatch 可见
    # **跨仓默认**（`ECC-ECDB1C9C2B1D` / owner 2026-10-15「ecc-finding 全过程必须默认支持跨仓」）：
    #   锚在**候选仓集合**（`_candidate_repos`，禁第二份仓枚举）任一仓内可解析 ⟹ 视为**不漂移**。
    #   单仓口径会令**他仓锚**在技能仓查不到 ⟹ 静默报漂移（假红）或静默零动作（不保护）。
    roots = _candidate_repos(state_file) or [str(DEFAULT_SKILL)]
    idx = {r: _lazy_index(r) for r in roots}   # §9-6：惰性 —— 直连锚 ⟹ 不走全仓 walk（仅 basename 兜底才建）
    drifted = []
    for f in load_findings(state_file):
        fid = str(f.get("id") or "")
        if fid not in wanted:
            continue
        # A v2：字面值自**标题行**抽取 —— 复用 B 面 `extract_anchors`（`iter_anchor_refs` +
        #   `_literals` 单一源），不再硬填 `literals: []`。
        for a in gk_ecc_review.extract_anchors(_live_title(f.get("title") or "")):
            ok, first, resolved = False, None, None
            for r in roots:
                v = gk_ecc_review.classify_anchor(a, _resolve_path(a["rel"], r, idx[r]),
                                                  "existence")
                if first is None:
                    first = v
                verdict = v.get("verdict")
                if verdict in ("ok", "hit"):   # A v2：hit = 字面值命中 ⟹ 不漂移
                    ok = True
                    break
                # 记「文件**确在某候选仓**」的判决（比 file_missing 更有信息量，供 detail 用）
                if verdict != "file_missing" and resolved is None:
                    resolved = v
            if ok:
                continue
            v = resolved or first or {"verdict": "file_missing"}
            drifted.append({"fid": fid, "anchor": a["ref"], "rel": a["rel"],
                            "verdict": v.get("verdict"),
                            "detail": _drift_detail(v, a["hi"], "候选仓内不可解析")})
    return drifted


def _journal_precheck_ack(state_file: str, drifted: list) -> None:
    """逐 drifted fid 记 `precheck_ack`（schema 见 `_guard_precheck`：必带 fid、禁带 to）。"""
    for fid in sorted({d["fid"] for d in drifted}):
        _append_journal(state_file, {"event": "precheck_ack", "fid": fid, "ts": _now(),
                                     "drift": [d for d in drifted if d["fid"] == fid]})


def _precheck_degrade(state_file: str, fids) -> set:
    """**降级放行**（Plan-2 §2.4-a）：**内部 / 自动化面**（`prune_duplicates` /
    `upsert_red_findings`）的闸出口 —— 无交互出口，硬阻断会锁死 RED 管线 / 存量清理 ⟹ **不 raise**。

    逐 fid 判决：命中 drifted 者记 `precheck_ack` 并**从放行集剔除**（「逐条跳过该 fid」），
    其余照常处置（「放行其余」）。返回**可继续处置**的 fid 集合（str）。
    开关 `GK_FINDING_PRECHECK=0` ⟹ 全放行（与硬门同开关）。
    """
    allf = {str(x) for x in (fids or []) if str(x)}
    if str(os.environ.get("GK_FINDING_PRECHECK", "1")).strip() == "0":
        return allf
    drifted = _scan_drift(state_file, fids)
    if drifted:
        _journal_precheck_ack(state_file, drifted)
    return allf - {d["fid"] for d in drifted}


# ── finding 归属路由硬门（档 1，2026-10-09 · ECC-0319B418F9A7）──────────────
# 病象：`register` 写 CLI 解析到的 `STATE_FILE`（启动块跟随计划指针），**不按 finding 的归属计划
#   路由** ⟹ 在 Y 计划活跃时登记 X 计划的 finding 必落错 state（本会话复发 2 次：`ECC-E34434E64B82`
#   误落 base、`ECC-2418DB9463A2` 误落额度银行计划 state）。
# 判据（单源）：finding 的**裸计划锚**（`docs/plans/<X>.md`，**全匹配**；不含 MoA 的 `plan:` 前缀式）
#   ⟹ `resolve_plan_state` 读计划 META `state_domain` → 归属 state；声明域 + 目标 state 存在 +
#   ≠ 当前 `STATE_FILE` ⟹ 漂移。无计划锚（技能级 finding）/ 计划未声明域 / 目标 state 未建 ⟹ 零动作。
# 落点：硬门只落 **CLI 手工面**（`main()` 的 register 分支 `route_hard=True`）；模块内/自动化调用
#   默认 `route_hard=False`（跳过，防误伤 MoA / prose / estimator 管线，对齐 `_precheck_degrade` 先例）。
_ROUTE_DRIFT_RE = re.compile(r"^docs/plans/[A-Za-z0-9._\-]+\.md(?::\d+(?:-\d+)?)?$")


def _route_drift_list(state_file: str, anchors) -> list:
    """归属漂移明细（只读；空 ⟹ 无漂移）。

    对 finding 的**裸计划锚**逐个求「本计划应落哪套 state」（`resolve_plan_state` 单源）；
    声明域 + 目标 state 存在 + ≠ 当前 state ⟹ 记 `{anchor, plan, target}`。
    """
    sdir = os.path.dirname(os.path.abspath(state_file))
    out = []
    for a in (anchors or []):
        rel = str(a or "").strip()
        if not _ROUTE_DRIFT_RE.match(rel):
            continue
        rel = rel.split(":", 1)[0]              # 去行号锚：`docs/plans/x.md:120`
        plan_file = os.path.join(sdir, rel)
        if not os.path.isfile(plan_file):
            continue
        try:
            rp = resolve_plan_state(state_file, plan_file)
        except Exception:  # noqa: BLE001 — 判定单源异常 ⟹ 不臆造漂移
            continue
        tgt = str(rp.get("target") or "")
        if (rp.get("basis") == "declared" and rp.get("target_exists") and tgt
                and os.path.abspath(tgt) != os.path.abspath(state_file)):
            out.append({"anchor": rel, "plan": plan_file, "target": tgt})
    return out


def _journal_route_drift(state_file: str, fid: str, drifts: list) -> None:
    """记 `route_drift` ack 事件（**必带 `fid`**：缺则 `reconcile_pair` 归入 '' ⟹ 永久假 FAIL；
    **禁带 `to`**：非状态转移事件，会与 reconcile 的 `to==st` 判据串扰）。"""
    _append_journal(state_file, {"event": "route_drift", "fid": fid, "ts": _now(),
                                 "drifts": [{"anchor": d["anchor"], "target": d["target"]}
                                            for d in drifts]})


def _bump_severity(rec: dict, sev: str) -> None:
    """severity **只升不降**（空值不动；存量无该字段 ⟹ 首次写入即升档）。"""
    if not sev:
        return
    cur = (rec.get("severity") or "").strip().lower()
    if not cur or _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(cur, -1):
        rec["severity"] = sev


def register(state_file: str, title: str, source: str,
             family: str = "", cover_layers=None, gap=None,
             root_key: str = "", anchors=None, facets=None,
             closure_oracle: str = "", source_note: str = "",
             release_state: str = "none", provenance: str = "trusted",
             severity: str = "", owner: str = "",
             repo_token: str = "",
             ack=None, route_hard: bool = False,
             merge_into: str = "", dup_ack: str = "") -> dict:
    """登记 open finding；C2/E2：记录带 family / cover_layers / gap（缺陷族审查层覆盖断言）。

    - source ∈ {red, review} 且 cover_layers 空 → gap=True + cover_warnings 提示（不阻断）
    - cover_layers 值须 ∈ 已登记审查层（REVIEW_LAYERS 单源）；非法值告警不阻断
    - gap 显式传入时以显式为准
    - ECC-4E6D7F42CA05（2026-09-27）：读-改-写**整体**持 `state_lock` —— 原 `load_findings`
      在锁外、`save_findings` 又写调用方传入的旧 list ⟹ 并发 register 丢更新（实测 8 并发仅
      2 条落盘）。现整段锁内完成「读 → 幂等判 → 追加 → 落盘」。
    - ECC-BA7224C3B2A2 / ECC-FF45F426BA45（2026-09-27）：新增 root_key/anchors/facets/
      closure_oracle。幂等判据升为**双档** —— 有 `root_key` 时按**根因指纹**合并（异措辞同根因
      不再各建一条镜像）：命中即 append anchors/facets（去重）+ 可选更新 closure_oracle +
      journal `merge`；**无 root_key 时逐字保持 title 全等**（向后兼容）。目的 = 让「发现面 N
      （并发多源）」收敛到「裁决面 1（单一台账）」；anchor/facet 只由本函数归一（单源）。
    """
    _gate_writable(state_file)
    rk = (root_key or "").strip()
    co = (closure_oracle or "").strip().lower()   # 单一 canon（大小写归一，非拒写）
    if co and co not in _CLOSURE_ORACLES:
        raise ValueError("closure_oracle 非法: %r（合法值: %s；留空=未分类）"
                         % (closure_oracle, " | ".join(_CLOSURE_ORACLES)))
    if rk and (len(rk) > _ROOT_KEY_MAX or any(c.isspace() for c in rk)):
        raise ValueError("root_key 非法: %r（根因指纹不得含空白且长度 ≤%d）"
                         % (root_key, _ROOT_KEY_MAX))
    rstate = (release_state or "none").strip()
    if rstate not in _RELEASE_STATES:
        raise ValueError("release_state 非法: %r（合法: %s；见 gk_finding._RELEASE_STATES）"
                         % (release_state, " | ".join(_RELEASE_STATES)))
    prov = (provenance or "trusted").strip()
    if prov not in _PROVENANCE:
        raise ValueError("provenance 非法: %r（合法: %s；见 gk_finding._PROVENANCE）"
                         % (provenance, " | ".join(_PROVENANCE)))
    sev = (severity or "").strip().lower()
    if sev and sev not in _SEVERITY_RANK:
        raise ValueError("severity 非法: %r（合法: %s；留空=未定级）"
                         % (severity, " | ".join(_SEVERITIES)))
    own = (owner or "").strip()
    if own and (len(own) > _OWNER_MAX or any(ch.isspace() for ch in own)):
        raise ValueError("owner 非法: %r（责任域 token，禁空白且 ≤%d；长说明请走 source_note）"
                         % (owner, _OWNER_MAX))
    # 跨仓归属 token（2026-11-01）：显式 `--repo` 优先（目录 ⟹ 取目录名），否则留空
    #   （留空者由 close/verify 的 `commit:<sha>` 派生；两者都无 ⟹ 归 `_unattributed`）。
    tok = _norm_repo_token("", repo_token)
    # T5-d（2026-10-06）：**写入时**污点扫描（记忆写入 = 不可信输入事件 ⟹ 不在读时才发现）。
    taint = _scan_taint((title or "") + "\n" + (source_note or "") + "\n" + (family or ""))
    # `source` 写入规范（B 类安全网）：短 token + 白名单；**长文本出处**走 `source_note`。
    src = (source or "").strip()
    if not src:
        raise ValueError("source 不能为空（合法: %s；规范正本 references/ecc-write-spec.md）"
                         % " | ".join(_ECC_SOURCES))
    if len(src) > _SOURCE_MAX or any(c.isspace() for c in src):
        raise ValueError("source 非法: %r（须为 ≤%d 字且**无空白**的 token；长文本出处请走 "
                         "--source-file ⟹ 落 `source_note`，见 references/ecc-write-spec.md）"
                         % (source, _SOURCE_MAX))
    if src not in _ECC_SOURCES:
        raise ValueError("source 不在白名单: %r（合法: %s；新增来源须登记 "
                         "`gk_finding._ECC_SOURCES` 单一行）"
                         % (source, " | ".join(_ECC_SOURCES)))
    note = (source_note or "").strip()
    # 归属路由硬门（档 1 · ECC-0319B418F9A7）：仅 CLI 手工面（route_hard）拦**跨计划登记**；
    # 无计划锚（技能级 finding）/ 计划未声明域 / 目标 state 未建 ⟹ 零动作（不误伤）。
    drifts = _route_drift_list(state_file, anchors) if route_hard else []
    if drifts and not ack:
        raise ValueError("ECC_FINDING_ROUTE_DRIFT: " + "; ".join(
            "锚 %s 归属 state=%s ≠ 当前 %s" % (d["anchor"], d["target"], state_file)
            for d in drifts)
            + " —— 计划属 finding 请带 `--domain <repo>.<plan>` 落归属 state；"
              "确属本 state 时 `--ack-drift` 显式放行（记 route_drift 留痕）")
    merged = None
    _dups = []
    with state_lock(state_file):
        findings = load_findings(state_file)
        if merge_into:
            # 显式合并目标（OSS 前置计划 §2.3-B）：目标不存在 ⟹ fail-loud（禁静默降级为新建）
            for f in findings:
                if f.get("id") == merge_into:
                    merged = f
                    break
            if merged is None:
                raise ValueError("merge_into 目标不存在: %r（本 state 无该 id；"
                                 "请用 finding dup-check 取候选 id）" % merge_into)
        else:
            for f in findings:
                if rk and f.get("root_key") == rk:
                    merged = f
                    break
                if not rk and f.get("title") == title:
                    return f  # 幂等：同标题不重复登记（既有记录不回填新字段）
        if merged is not None:
            _extend_unique(merged, "anchors", anchors)
            # ECC-81F6D83D153B：facets 走**标量命名空间后写覆盖**（禁叠加 classification/refs/…）
            _merge_facets(merged, facets)
            # ECC-60BF82183364：派生标题（MoA聚合批裁决 计数标题）随重跑刷新，防 title↔facets 分叉
            _refresh_derived_title(merged, title)
            # 释放态**不回退**：存量已裁（approved/rejected）⟹ 不动；仅缺省补 `rstate`
            merged.setdefault("release_state", rstate)
            # E18：severity 只升不降；owner 缺省补（已有责任域不被后来者覆盖）
            _bump_severity(merged, sev)
            if own:
                merged.setdefault("owner", own)
            if tok:
                merged.setdefault("repo_token", tok)
            # T5-a/T5-d：taint **只升不降**（untrusted 覆盖 trusted；declassified 保留）；污点并集
            merged.setdefault("provenance", prov)
            merged.setdefault("declassified", False)
            if prov == "untrusted":
                merged["provenance"] = "untrusted"
                _extend_unique(merged, "facets", [_QUARANTINE_FACET])
            if taint:
                _extend_unique(merged, "taint", taint)
            # E24（2026-10-30）：merge 时**刷新** `source_note`（证据摘要随重跑更新）。
            #   原实现只在新建分支写该字段 ⟹ 同 root_key 的审计证据文本永久停在首登记那次
            #   （实测 `ECC-9BAE656572A1` 的 note 仍是旧 `replay=check open findings…`，
            #   与当前 replay 矛盾 = 台账内的「过时记录」）。空 note 不覆盖（禁抹掉旧证据）。
            #   ⚠ 污点面无需重扫：`taint` 在进入锁前由 `title+source_note+family` 同批算出
            #   （见 `_scan_taint` 调用点），并已在上方 `_extend_unique` 并入（只升不降）
            #   ⟹ 新文本的污点标记天然随本次合并进入，不存在「换文案绕过标记」。
            if note:
                merged["source_note"] = note
            if co:
                merged["closure_oracle"] = co
            # P1 补（2026-10-04）：merge 分支**回填** `evidence_hash` —— 存量 finding（注册早于
            #   「register 产指纹」修复）无该字段 ⟹ `close`/`verify` 的 `basis_ref`（= evidence_hash）
            #   恒空 ⟹ c9「终态须有据」对存量条目**结构性不可满足**（只能退 `register-only`）。
            #   缺则按**合并后**字段同式重算（单一算法源 `_evidence_hash`）；已有则不动（防失效）。
            if not (merged.get("evidence_hash") or ""):
                merged["evidence_hash"] = _evidence_hash(
                    merged.get("title", ""), merged.get("root_key", ""),
                    merged.get("family", ""), merged.get("anchors") or [])
            merged["last_modified"] = _now()
            save_findings(state_file, findings)
        else:
            # F-REV-23 自锚：state 代际初启（findings 空）且无 epoch → 先打代际标记，
            # 使后续 reconcile 只对「本代际内」事件对账（防前代 fid 残留误报「记录被删」）。
            if not findings and not _last_epoch(_journal_events(state_file)):
                _append_journal(state_file, {"ts": _now(), "event": _EPOCH_EVENT,
                                             "reason": "auto: state 代际初启（首个 finding）"})
            layers = _split_layers(cover_layers)
            warnings = []
            valid = _valid_layer_set()
            if valid is not None:
                bad = sorted(x for x in layers if x not in valid)
                if bad:
                    warnings.append("cover_layers 非已登记审查层: " + ",".join(bad)
                                    + "（合法: L1-L10/PR，见 REVIEW_LAYERS 单源）")
            if src in _COVER_REQUIRED_SOURCES and not layers:
                warnings.append("source=" + src + " 未登记 cover_layers — 缺陷族缺审查层覆盖断言"
                                "（gap），须登记应拦审查层（L1-L10/PR）")
            g = bool(gap) if gap is not None else (src in _COVER_REQUIRED_SOURCES and not layers)
            # P1（2026-10-04）：手动路径也产 `evidence_hash`（内容指纹、确定性）—— 原**仅**
            #   引擎路径（`_red_attacks`）自产 ⟹ `verify`/`close` 的 `basis_ref`（= evidence_hash）
            #   对手动 finding 恒空 ⟹ c9「终态须有据」对 register 路径**结构性不可满足**。
            #   指纹 = title + root_key + family + 锚（排序去重）；同内容 ⟹ 同指纹（幂等可复算）。
            _eh = _evidence_hash(title, rk, family, anchors)
            f = {
                "id": "ECC-" + uuid.uuid4().hex[:12].upper(),
                "title": title,
                "source": src,
                "status": "open",
                "created_at": _now(),
                "family": family or "",
                "cover_layers": layers,
                "gap": g,
                "cover_warnings": warnings,
                "root_key": rk,
                "anchors": _uniq_str(anchors),
                "facets": _uniq_str(facets),
                "closure_oracle": co,
                "source_note": note,
                "evidence_hash": _eh,
                "release_state": rstate,
                "severity": sev,
                "owner": own,
                **({"repo_token": tok} if tok else {}),
                "provenance": prov,
                "declassified": False,
                "taint": taint,
                "quarantined": bool(taint) and prov == "untrusted",
            }
            findings.append(f)
            save_findings(state_file, findings)
            # §2.3-B（2026-10-26）：写前候选**只提示**（不拒写、不合并）。未给 `dup_ack` 时算候选；
            #   命中 ⟹ journal `dup_suspect`（**无 from/to** ⟹ 不与 reconcile 状态机串扰）+ 回包带列表。
            if not dup_ack:
                try:
                    _dups = dup_candidates(state_file, title, family, anchors, facets,
                                           exclude_id=f["id"])["candidates"]
                except Exception:  # noqa: BLE001 — 边界：候选面不可用 ⟹ 不阻断登记
                    _dups = []
                if _dups:
                    _append_journal(state_file, {"ts": f["created_at"], "event": "dup_suspect",
                                                 "fid": f["id"],
                                                 "candidates": [x["id"] for x in _dups]})
            # [遗漏⑤·ECC-43D22663EFB5] open 越线 ⟹ 就地溢出（同锁内，`state_lock` 可重入）；
            #   越线时 register **仍成功**（先溢出再落盘，**禁自锁**）。best-effort：溢出失败不阻断登记。
            try:
                spillover_open(state_file)
            except Exception as _spx:  # noqa: BLE001 — 边界：溢出 best-effort，不阻断 register
                sys.stderr.write("SPILLOVER_FAILED: %s\n" % _spx)
    _write_checksum(state_file)  # ⚠ 仍在锁外（同文件双 flock 会 state lock timeout，见 P0-1）
    _refresh_repo_index(state_file)   # 跨仓索引投影（2026-11-01；计数随每次写刷新）
    if merged is not None:
        _append_journal(state_file, {"ts": _now(), "event": "merge", "fid": merged["id"],
                                     "root_key": rk, "source": source, "title": title})
        if drifts and ack:
            _journal_route_drift(state_file, merged["id"], drifts)
        return merged
    _append_journal(state_file, {"ts": f["created_at"], "event": "register", "fid": f["id"],
                                 "from": "", "to": "open", "source": source, "title": title})
    if drifts and ack:
        _journal_route_drift(state_file, f["id"], drifts)
    # §2.3-B：候选只在**回包**带出（不落记录字段 ⟹ 不扩 schema、不涨 state）
    return dict(f, dup_candidates=_dups) if _dups else f


def verify(state_file: str, fid: str, ok: bool, verify_source: str = "",
           ack: bool = False, *, declassify: bool = False) -> dict:
    """复验 finding：ok → `fixed` / 否则 `rejected`。

    c9 加固（2026-10-04 · 全纳入）：`fixed` 也须承载「源」——`ok=True` 时可带 `verify_source`
    （白名单形态，见 `_assert_verify_source`）⟹ c9 对 `fixed` 一并核验 kind/commit。
    Plan-2（2026-10-06）：处置前**强制回环闸** —— 写前置定序 = `_gate_writable` →
    `_assert_single_source` → `_guard_precheck` → 写；`ack=True` ⟹ 放行 + journal `precheck_ack`。
    """
    _gate_writable(state_file)
    _assert_single_source(state_file, fid, "verify")
    _guard_precheck(state_file, [fid], ack=ack)
    if verify_source:
        _assert_verify_source(verify_source)
    findings = load_findings(state_file)
    for f in findings:
        if f["id"] == fid:
            # T5-a：不可信来源未 declassify ⟹ 复验汇点禁行（除非显式解密）
            if _sink_blocked(f):
                if declassify:
                    _declassify_inplace(f)
                else:
                    raise ValueError(
                        "verify 被 T5-a 溯源硬门拒：finding %s 来源不可信（provenance=untrusted）"
                        "且未 declassify ⟹ 须 declassify=True 或先 `finding declassify`" % f["id"])
            from_status = f.get("status", "open")
            f["status"] = "fixed" if ok else "rejected"
            f["verified_at"] = _now()
            f["basis_ref"] = f.get("evidence_hash", "")
            if ok and verify_source:
                f["verify_source"] = verify_source
            _attr_repo_token(state_file, f, verify_source if ok else "")
            # rejected 状态保留可观测（审计链可见复验失败）；重新登记/修复时 register 去重幂等处理。
            save_findings(state_file, findings)
            _write_checksum(state_file)
            _refresh_repo_index(state_file)
            _append_journal(state_file, {"ts": f["verified_at"], "event": "verify", "fid": f["id"],
                                         "from": from_status, "to": f["status"], "ok": ok,
                                         "verify_source": f.get("verify_source", ""),
                                         "basis_ref": f["basis_ref"]})
            return f
    raise KeyError(f"finding {fid} not found")


def close(state_file: str, fid: str, verify_source: str, ack: bool = False, *,
          declassify: bool = False, accept_hard: bool = False, accept_ack=None) -> dict:
    """关闭 finding（终态 `closed`）；写入边界校验 `verify_source` 形态（c9）。

    Plan-2：处置前强制回环闸（定序同 `verify`）；T5-a：不可信来源未 declassify ⟹ 终态汇点禁行。
    """
    _gate_writable(state_file)
    _assert_single_source(state_file, fid, "close")
    _guard_precheck(state_file, [fid], ack=ack)
    _assert_verify_source(verify_source)
    if accept_hard:
        _accept_gate(state_file, fid, verify_source, accept_ack)
    findings = load_findings(state_file)
    for f in findings:
        if f["id"] == fid:
            # T5-a：不可信来源未 declassify ⟹ 终态汇点禁行（除非显式解密）
            if _sink_blocked(f):
                if declassify:
                    _declassify_inplace(f)
                else:
                    raise ValueError(
                        "close 被 T5-a 溯源硬门拒：finding %s 来源不可信（provenance=untrusted）"
                        "且未 declassify ⟹ 须 declassify=True 或先 `finding declassify`" % f["id"])
            from_status = f.get("status", "open")
            f["status"] = "closed"
            f["verify_source"] = verify_source
            f["closed_at"] = _now()
            f["basis_ref"] = f.get("evidence_hash", "")
            _attr_repo_token(state_file, f, verify_source)
            save_findings(state_file, findings)
            _write_checksum(state_file)
            _refresh_repo_index(state_file)
            _append_journal(state_file, {"ts": f["closed_at"], "event": "close", "fid": f["id"],
                                         "from": from_status, "to": "closed",
                                         "verify_source": verify_source, "basis_ref": f["basis_ref"]})
            return f
    raise KeyError(f"finding {fid} not found")


def reopen(state_file: str, fid: str, reason: str = "", ack: bool = False) -> dict:
    """重开一条**终态**（closed/fixed/rejected）finding：status → open + journal 留痕。

    用途：误关（如把伞形 finding 当载体关掉）或缺陷回归时把台账拉回真实态。与 `close` 镜像，
    但**必须**补 journal —— `reconcile_pair` 的判据「state=`open` 而 journal 末事件
    `to ∈ {closed,fixed,rejected}`」= 「state 被回滚」anomaly ⟹ 只改 state 不补记会立刻造出
    一条**假 anomaly**（`upsert_red_findings` 的 ③ 重开自愈只在 RED upsert 时被动补记，
    不构成按需通路）。故本函数 = 「改 status + 补 `to=open` 事件 + 重算 checksum」三件同批。
    Plan-2：处置前强制回环闸（定序同 `verify`）。

    - 已是 `open` ⟹ **幂等 no-op**（零写盘、零 journal，返回 `noop:true`）
    - 清 `verify_source`/`closed_at`/`verified_at`（历史仍在 journal，可回溯；不回写）
    - checksum 重算走 `_write_checksum`（与 `close` 同路径）
    """
    _gate_writable(state_file)
    _assert_single_source(state_file, fid, "reopen")
    _guard_precheck(state_file, [fid], ack=ack)
    findings = load_findings(state_file)
    for f in findings:
        if f["id"] == fid:
            from_status = f.get("status", "open")
            if from_status == "open":
                return dict(f, noop=True)
            f["status"] = "open"
            for k in ("verify_source", "closed_at", "verified_at"):
                f.pop(k, None)
            f["basis_ref"] = f.get("evidence_hash", "")
            save_findings(state_file, findings)
            _write_checksum(state_file)
            _refresh_repo_index(state_file)
            _append_journal(state_file, {"ts": _now(), "event": "reopen", "fid": f["id"],
                                         "from": from_status, "to": "open",
                                         "reason": reason or "manual"})
            return f
    raise KeyError(f"finding {fid} not found")


# ── 台账时效巡检（TTL 标 stale + 锚文件被 diff 触及 ⟹ 自动 reopen，2026-11-01）────────
# 缺口（用户裁定「diff 触及自动 reopen + TTL」）：finding 一旦进终态就**永不回看**——
#   ① 修复被后续提交回退，台账仍显示 `closed`（**假绿**）；
#   ② `open` 条目可以无限期躺着，「陈年未处置」在状态视图里不可见（与 stale 同义）。
# 判据（两条，皆为**机械可判**）：② TTL 超期 ⟹ 打 `stale` 标记（**不改 status**：stale 是
#   可见性标记，不是状态机转移）；① 终态 finding 的 `verify_source=commit:<sha>` 之后，
#   该 finding 的**锚文件**在同仓被 `git diff --name-only <sha>`（含未提交改动）触及 ⟹
#   `reopen`（journal 记 `reason=anchor_changed`，与手工 reopen 同形态 ⟹ reconcile 不误报）。
# 纪律：默认**只报不写**（同 `spillover_open` 的安全网形态）；`apply=True` 才落盘。
_STALE_TERMINAL = ("fixed", "verified", "closed")
_STALE_REASON_TTL = "ttl_expired"
_STALE_REASON_ANCHOR = "anchor_changed"
# 锚里形如 `<命名空间>:<值>` 的前缀（非文件路径）
_ANCHOR_NAMESPACES = ("batch", "plan", "commit", "arm", "tests", "review", "crossr",
                      "red", "monitor", "embed", "state", "doc")


def _parse_ts(v):
    """ISO ts → aware datetime（不可解析 → None；`Z` 与无 tz 形态都归一为 UTC）。"""
    s = str(v or "").strip()
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001 — 边界：坏时间戳 ⇒ 由调用方计 no_timestamp
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def _last_touch(f) -> str:
    """finding 的最近活动时刻（取 `last_modified`/`verified_at`/`closed_at`/`created_at` 最大者）。"""
    best, best_d = "", None
    for k in ("last_modified", "verified_at", "closed_at", "created_at", "first_added"):
        d = _parse_ts(f.get(k))
        if d is not None and (best_d is None or d > best_d):
            best, best_d = str(f.get(k)), d
    return best


def _tracked_files(repo: str):
    """`git ls-tree -r --name-only HEAD` → set（不可用 → None，调用方按空集处理）。"""
    import subprocess
    try:
        r = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "--name-only", "HEAD"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        if r.returncode != 0:
            return None
        return {ln for ln in r.stdout.decode("utf-8", "replace").splitlines() if ln}
    except Exception:  # noqa: BLE001 — 边界：git 不可用 ⇒ 退磁盘存在性判定
        return None


def _changed_since(repo: str, base: str):
    """`git diff --name-only <base>`（base vs 工作树，含未提交改动）→ set；失败 → None。"""
    import subprocess
    try:
        r = subprocess.run(["git", "-C", repo, "diff", "--name-only", base],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
        if r.returncode != 0:
            return None
        return {ln for ln in r.stdout.decode("utf-8", "replace").splitlines() if ln}
    except Exception:  # noqa: BLE001
        return None


def _anchor_files(f, repo: str, tracked) -> list:
    """finding 的 `anchors` 归一为**仓内相对路径**（`git ls-tree` 集合优先、磁盘兜底）。

    非路径锚（`L10`/`§4.13`/`batch:...`/`ECC-...`）跳过 —— 「文件被改」判据对它们无意义。
    """
    out = []
    for a in (f.get("anchors") or []):
        s = str(a or "").strip().replace("\\", "/")
        if not s or s.startswith("§"):
            continue
        p = s
        if ":" in s:
            ns = s.split(":", 1)[0].strip().lower()
            if ns in _ANCHOR_NAMESPACES:
                continue
            p = s.split(":", 1)[0].strip()   # `path.py:123` ⟹ `path.py`
        if re.match(r"^[A-Za-z]{1,4}\d", p):   # L10 / R7 / F08 形态（层号/序号，非路径）
            continue
        if p.startswith("./"):
            p = p[2:]
        if not p or not ("/" in p or "." in p):
            continue
        cands = [p]
        if "/" not in p and tracked:
            cands += [t for t in sorted(tracked) if t.endswith("/" + p)]
        hit = next((c for c in cands if tracked and c in tracked), "")
        if not hit and os.path.isfile(os.path.join(repo, p)):
            hit = p
        if hit and hit not in out:
            out.append(hit)
    return out


def stale_scan(state_file: str, ttl_days: int = 14, *, apply: bool = False,
               now_ts: str = "") -> dict:
    """台账**时效巡检**：TTL 超期 ⟹ 标 `stale`；锚文件被 diff 触及 ⟹ `reopen`。

    返回（stdout JSON 形态的 python dict）：
      `stale[]`   = 超期 open 条目（`age_days`/`last_touch`/`already_stale`）
      `reopened[]`= 判定应重开的终态条目（`from`/`commit`/`repo_token`/`touched[]`）
      `skipped[]` = 判不了的条目（`no_commit_anchor` / `commit_unresolvable` / `no_file_anchor`
                    / `diff_failed` / `no_timestamp`）—— **显式可见，不静默当干净**
      `blocked[]` = apply 时被 `_guard_precheck` 拦下的 fid（锚漂移 ⟹ 不自动重开，需人工）
    `apply=False`（默认）**零写盘**；`apply=True` 才落 status/stale/journal/索引。
    """
    ttl = int(ttl_days)
    if ttl <= 0:
        raise ValueError("--ttl-days 需正整数（得到 %r）" % ttl_days)
    now = _parse_ts(now_ts) or datetime.now(timezone.utc)
    findings = load_findings(state_file)
    repos = _candidate_repos(state_file)
    out = {"ok": True, "apply": bool(apply), "ttl_days": ttl, "now": now.isoformat(),
           "scanned": len(findings), "stale": [], "reopened": [], "skipped": [],
           "blocked": [], "applied": {"reopened": 0, "stale": 0}}
    reopen_ids, stale_ids, stale_age = [], [], {}
    _repo_cache, _tracked_cache, _diff_cache = {}, {}, {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or "")
        if not fid:
            continue
        st = str(f.get("status") or "open")
        if st == "open":
            touch = _last_touch(f)
            d = _parse_ts(touch)
            if d is None:
                out["skipped"].append({"id": fid, "why": "no_timestamp"})
                continue
            age = (now - d).total_seconds() / 86400.0
            if age < ttl:
                continue
            out["stale"].append({"id": fid, "status": st, "age_days": round(age, 2),
                                 "last_touch": touch, "already_stale": bool(f.get("stale"))})
            stale_age[fid] = round(age, 2)
            if not f.get("stale"):
                stale_ids.append(fid)
            continue
        if st not in _STALE_TERMINAL:
            out["skipped"].append({"id": fid, "why": "status_not_scanned", "status": st})
            continue
        sha = _commit_from_verify_source(f.get("verify_source", ""))
        if not sha:
            out["skipped"].append({"id": fid, "why": "no_commit_anchor"})
            continue
        if sha not in _repo_cache:
            _repo_cache[sha] = _resolve_commit_repo(sha, repos)
        repo = _repo_cache[sha]
        if not repo:
            out["skipped"].append({"id": fid, "why": "commit_unresolvable", "commit": sha})
            continue
        if repo not in _tracked_cache:
            _tracked_cache[repo] = _tracked_files(repo) or set()
        anchors = _anchor_files(f, repo, _tracked_cache[repo])
        if not anchors:
            out["skipped"].append({"id": fid, "why": "no_file_anchor", "commit": sha})
            continue
        key = (repo, sha)
        if key not in _diff_cache:
            _diff_cache[key] = _changed_since(repo, sha)
        changed = _diff_cache[key]
        if changed is None:
            out["skipped"].append({"id": fid, "why": "diff_failed", "commit": sha})
            continue
        touched = [a for a in anchors if a in changed]
        if not touched:
            continue
        out["reopened"].append({"id": fid, "from": st, "reason": _STALE_REASON_ANCHOR,
                                "commit": sha, "repo_token": _repo_token(repo),
                                "touched": touched})
        reopen_ids.append(fid)
    if not apply or not (reopen_ids or stale_ids):
        return out
    _gate_writable(state_file)
    # 逐 fid 走回环闸（单 fid 粒度 ⟹ 漂移条目**单独**拦下，不拖累其余；不静默放行）
    _ok = []
    for fid in reopen_ids:
        try:
            _guard_precheck(state_file, [fid])
            _ok.append(fid)
        except ValueError as e:  # noqa: BLE001 — 逐条拦下，明细回包
            out["blocked"].append({"id": fid, "why": str(e)})
    reopen_ids = _ok
    if not (reopen_ids or stale_ids):
        return out
    now_iso = now.isoformat()
    findings = load_findings(state_file)   # 判定与落盘之间可能有并发写 ⟹ 重读后再改
    byid = {str(f.get("id")): f for f in findings if isinstance(f, dict) and f.get("id")}
    events = []
    for fid in reopen_ids:
        f = byid.get(fid)
        if not f or str(f.get("status") or "") == "open":
            continue
        from_status = str(f.get("status") or "")
        f["status"] = "open"
        for k in ("verify_source", "closed_at", "verified_at",
                  "stale", "stale_since", "stale_days", "stale_reason"):
            f.pop(k, None)
        f["basis_ref"] = f.get("evidence_hash", "")
        f["last_modified"] = now_iso
        f["reopened_at"] = now_iso
        events.append({"ts": now_iso, "event": "reopen", "fid": fid,
                       "from": from_status, "to": "open", "reason": _STALE_REASON_ANCHOR})
        out["applied"]["reopened"] += 1
    for fid in stale_ids:
        f = byid.get(fid)
        if not f or str(f.get("status") or "") != "open":
            continue
        f["stale"] = True
        f["stale_since"] = str(f.get("stale_since") or now_iso)
        f["stale_reason"] = _STALE_REASON_TTL
        f["stale_days"] = stale_age.get(fid, f.get("stale_days", 0))
        events.append({"ts": now_iso, "event": "stale", "fid": fid,
                       "reason": _STALE_REASON_TTL, "age_days": f["stale_days"]})
        out["applied"]["stale"] += 1
    save_findings(state_file, findings)
    _write_checksum(state_file)
    for ev in events:
        _append_journal(state_file, ev)
    _refresh_repo_index(state_file)
    return out


def set_release_state(state_file: str, fid: str, release_state: str, *,
                      by: str = "", note: str = "", divergence=None,
                      final_ruling: bool = False, declassify: bool = False) -> dict:
    """写 finding 的**释放批准态**（人评唯一写通路；独立于 status 机）。

    - `release_state ∈ _RELEASE_STATES`；非法 ⟹ fail-loud。
    - **P-meta 硬门**：`release_approved` 且 `divergence > _RELEASE_DIVERGENCE_MAX` 且非
      `final_ruling` ⟹ **拒写**（人评自身可污染 ⟹ 超阈须显式人类终裁）。
    - **T5-a 溯源硬门**：来源 `untrusted` 且未 declassify ⟹ `release_approved` **拒写**；
      须 `declassify=True`（显式解密）或 `final_ruling=True`（人类终裁 = 最强解密）。
    - **复合（overlay）**：`by`/`note` 并入 finding（人评叠加到聚合 finding **同一**记录）。
    - 写盘同 `close` 路径：`save_findings` + `_write_checksum` + `_append_journal`。
    """
    _gate_writable(state_file)
    if release_state not in _RELEASE_STATES:
        raise ValueError("release_state 非法: %r（合法: %s）"
                         % (release_state, " | ".join(_RELEASE_STATES)))
    if (release_state == "release_approved" and divergence is not None
            and float(divergence) > _RELEASE_DIVERGENCE_MAX and not final_ruling):
        raise ValueError(
            "release_approved 被 P-meta 硬门拒：divergence=%.3f > %.2f 且未给 --final-ruling"
            "（人评自身可污染 ⟹ 超阈须显式人类终裁）"
            % (float(divergence), _RELEASE_DIVERGENCE_MAX))
    _assert_single_source(state_file, fid, "release")
    findings = load_findings(state_file)
    for f in findings:
        if f["id"] == fid:
            # T5-a：不可信来源未 declassify ⟹ 后果性汇点禁行（除非显式解密 / 人类终裁）
            if release_state == "release_approved" and _sink_blocked(f):
                if declassify or final_ruling:
                    _declassify_inplace(f)
                else:
                    raise ValueError(
                        "release_approved 被 T5-a 溯源硬门拒：finding %s 来源不可信"
                        "（provenance=untrusted）且未 declassify ⟹ 须 --declassify 或 --final-ruling"
                        % f["id"])
            prev = f.get("release_state", "none")
            f["release_state"] = release_state
            f["released_at"] = _now()
            if by:
                f["released_by"] = by
            if note:
                f["release_note"] = note
            _extend_unique(f, "facets", ["release:" + release_state])
            save_findings(state_file, findings)
            _write_checksum(state_file)
            _append_journal(state_file, {"ts": f["released_at"], "event": "release",
                                         "fid": f["id"], "from": prev, "to": release_state,
                                         "by": by, "divergence": divergence,
                                         "final_ruling": bool(final_ruling),
                                         "declassified": bool(f.get("declassified"))})
            return f
    raise KeyError(f"finding {fid} not found")


def declassify(state_file: str, fid: str, *, by: str = "", note: str = "") -> dict:
    """人评把**不可信** finding **解密**（去 T5-a 汇点门）：置 `declassified=True` + 留痕。

    - 独立于 release/close：可与任一汇点动作串联（先解密，后 close/release）。
    - `provenance` **不变**（保 taint 可追溯）；幂等（已解密 ⟹ 仍置位、补 by/note）。
    """
    _gate_writable(state_file)
    _assert_single_source(state_file, fid, "declassify")
    findings = load_findings(state_file)
    for f in findings:
        if f["id"] == fid:
            _declassify_inplace(f)
            if by:
                f["declassified_by"] = by
            if note:
                f["declassified_note"] = note
            save_findings(state_file, findings)
            _write_checksum(state_file)
            _append_journal(state_file, {"ts": _now(), "event": "declassify",
                                         "fid": f["id"], "by": by})
            return f
    raise KeyError(f"finding {fid} not found")


def release_set(state_file: str) -> dict:
    """**硬门**（消费方唯一入口）：可下发实装集 = `release_state == release_approved`。

    返回 `{"approved":[...], "pending":[...], "rejected":[...], "blocked":[...]}`；
    `pending` = provisional 未裁；`blocked` = 已 `release_approved` 但**被 T5-a 溯源硬门拦**
    （来源不可信且未 declassify）—— 即使误置 release_state 也不得下发（**双层防御**）。
    下发/实装路径**须**以 `approved` 为准 —— 未批准者**不得**下发（硬门）。
    """
    out = {"approved": [], "pending": [], "rejected": [], "blocked": []}
    for f in load_findings(state_file):
        rs = f.get("release_state", "none")
        if rs == "release_approved":
            (out["blocked"] if _sink_blocked(f) else out["approved"]).append(f["id"])
        elif rs == "release_rejected":
            out["rejected"].append(f["id"])
        elif rs == "provisional":
            out["pending"].append(f["id"])
    return out


def amend_title(state_file: str, fid: str, suffix: str, note: str = "", *,
                _skip_precheck: bool = False, ack: bool = False) -> dict:
    """给 finding 标题**追加**更正子句（R25 用途：标题内行号锚漂移）。

    纪律（2026-09-23 用户裁定「修复漂移锚」）：
      · **不改写历史** —— 登记时的行号是当时的证据 ⟹ 只**追加**带日期的更正后缀，原文一字不动；
      · 幂等（后缀已在标题中 → 跳过，不重复追加）；
      · 存量同 id 多条时**全部**追加（避免"改了第一条、第二条仍误导"的部分状态）；
      · 写盘与 `close` 同路径：`save_findings` + `_write_checksum`（重算，防 TAMPERED 误报）
        + `_append_journal` 入账（第二副本锚，可 `reconcile` 复算）。
    Plan-2（2026-10-06）：处置前**强制回环闸**（定序 = `_gate_writable` → `_assert_single_source`
    → `_guard_precheck` → 写），但 **remedy 不自锁**（⛔ 硬约束）：`amend_anchors` 的刷锚重钉
    （suffix 本身即 `[刷锚 …] <old> → <new>`）就是漂移的**撤销动作** ⟹ 两条豁免通道：
    ① 显式 `_skip_precheck=True`；② suffix 命中 `_RE_REANCHOR`（刷锚段形态，`amend_anchors` 走此路）。
    """
    if not (suffix or "").strip():
        raise ValueError("amend-title 需要非空 --suffix")
    _gate_writable(state_file)
    _assert_single_source(state_file, fid, "amend-title")
    if _skip_precheck or _RE_REANCHOR.search(suffix or ""):
        pass          # remedy 通道：闸不得拦「纠偏动作」本身（否则漂移永不可修）
    else:
        _guard_precheck(state_file, [fid], ack=ack)
    findings = load_findings(state_file)
    amended = already = 0
    for f in findings:
        if f.get("id") != fid:
            continue
        t = f.get("title") or ""
        if suffix in t:
            already += 1
            continue
        f["title"] = (t + " " + suffix).strip()
        f["title_amended_at"] = _now()
        amended += 1
    if amended == 0 and already == 0:
        raise KeyError(f"finding {fid} not found")
    if amended:
        save_findings(state_file, findings)
        _write_checksum(state_file)
        _append_journal(state_file, {"ts": _now(), "event": "amend-title", "fid": fid,
                                     "amended": amended, "suffix_head": suffix[:80],
                                     "note": (note or "")[:120]})
    return {"id": fid, "amended": amended, "already": already}


# ── 刷锚段「顺序代入」语义（2026-10-06；锚判决单一源引擎 A 面）────────────────────────
# 病象：`amend_anchors` 对漂移标题**追加** `[刷锚 <date>] <old> → <new>`（append-only，不改写
#   历史），而 `scan_title_anchors` 只扫**原文** ⟹ 重钉**永不生效**（旧锚永久报漂移 = 检测端
#   与执行端脱钩）。
# 纪律（三步，缺一即错解）：
#   ① **按出现序**收集 (old → new) 有序对（对**原文**收集；`old`/`new` = 任意非空白 token，
#      **禁**假设仅 `file.ext:NNN` 形态）；
#   ② 删**全部**刷锚段 ⟹ 得主体 `body_0`；
#   ③ `t := body_0`，按段序把 `t` 中 `old_i` 的**锚边界出现**替换为 `new_i`（先 `re.escape`；
#      两侧统一加锚 token 边界：左 `(?<![\w./:\[\]-])` / 右 `(?![\w./:\[\]-])`）——
#      **禁**裸 `str.replace`：`real.py:1` 会误吃 `real.py:10`、`:1` 会误吃区间 `:1-5`
#      （前缀/后缀误改写）。
#   · 链式（`a→b→c`）依序代入 ⟹ 收敛为**最终**锚（中间锚与旧锚均不残留）。
_RE_REANCHOR = re.compile(r"\[刷锚\s+[\d-]+\]\s*(\S+)\s*→\s*(\S+)")
_ANCHOR_BOUND_L = r"(?<![\w./:\[\]-])"
_ANCHOR_BOUND_R = r"(?![\w./:\[\]-])"


def _live_title(title: str) -> str:
    """标题的**生效锚面**：刷锚段按出现序代入后的标题（纯函数，零 IO）。

    无刷锚段 ⟹ 与入参**逐字恒等**（零行为变化）；有段 ⟹ 删段得主体 + 顺序代入（见上方三步）。
    """
    t = str(title or "")
    pairs = [(m.group(1), m.group(2)) for m in _RE_REANCHOR.finditer(t)]
    if not pairs:
        return t
    body = _RE_REANCHOR.sub("", t)
    for old, new in pairs:
        body = re.sub(_ANCHOR_BOUND_L + re.escape(old) + _ANCHOR_BOUND_R,
                      lambda _m, _n=new: _n, body)
    return body


def scan_title_anchors(state_file: str, repo: str = "") -> dict:
    """finding **标题**内行锚漂移检测（只读）—— `amend-title` 的**检测端**（R25 对偶，形态 A）。

    病象：`ecc_findings[].title` 常内嵌行号锚（如 `subagent_runner.py:2556-2558`），代码一动即
    漂移，但**全仓无检测器扫标题**（`gk_doc_align.check_anchor_existence` 只扫 `docs/plans/*.md`）
    ⟹ `amend-title` 是孤岛、只能人工手调。

    复用（**单一事实源，禁第二套**）：标题面 = `_live_title`（刷锚段代入后）；锚提取 + 字面值 =
    `gk_ecc_review.extract_anchors`（内含 `iter_anchor_refs` + `_literals`）；路径解析 =
    `gk_plan_lint._lazy_index` + `_resolve_path`
    （仓内相对路径优先，否则 basename 索引 —— §9-6 惰性：直连命中则不建整索引）；**判决 = `gk_ecc_review.classify_anchor(..., "existence")`**
    —— 与转发包复核 `classify`（`mode="content"`）**同一判决引擎**，`existence` 面逐字保持本项目
    原判据（EOF 操作数 = `hi`、计数 = 逐行迭代、读失败 fail-soft）。
    ⚠ `import gk_ecc_review` 置于**函数体内**（装载期零耦合；模块级早绑会让 monkeypatch 不可见）。
    判据 v2（A v2，2026-10-07 折入本计划；与 `check_anchor_existence` 的 file_missing /
    line_over_eof 同族）：
      · file_missing    — 被引文件在仓内不可解析；
      · line_over_eof   — 行号（区间取右端）> 文件 EOF（`detail` 逐字保持 `<hi> > EOF <n>`）；
      · line_drift      — 标题行反引号字面值在文件内命中但不在锚区间；
      · literal_missing — 字面值全文无命中。
    字面值自**标题行**抽取（复用 `gk_ecc_review.extract_anchors` = `iter_anchor_refs` + `_literals`
    单一源）；**无字面值仍 `ok`**（A v1 口径逐字保持 ⟹ 闸不泛滥）。
    **纯读**（零写 state/文档）。
    返回 {"anchors_total", "findings_scanned", "drifted": [{fid, anchor, rel, verdict, detail}]}；
    `anchors_total` 按 `_live_title` 口径计（刷锚标记与其取代的旧锚**不计**）。
    """
    from gk_plan_lint import _lazy_index, _resolve_path
    import gk_ecc_review   # 函数级（禁置顶 from-import）：装载期零耦合 + monkeypatch 可见
    root = repo or str(DEFAULT_SKILL)
    index = _lazy_index(root)   # §9-6：惰性 —— 直连锚 ⟹ 不走全仓 walk（仅 basename 兜底才建）
    findings = load_findings(state_file)
    drifted, total = [], 0
    for f in findings:
        fid = str(f.get("id") or "")
        # A v2：字面值自**标题行**抽取（复用 B 面 `extract_anchors`；单一源）。
        for a in gk_ecc_review.extract_anchors(_live_title(f.get("title") or "")):
            total += 1
            v = gk_ecc_review.classify_anchor(a, _resolve_path(a["rel"], root, index),
                                              "existence")
            verdict = v.get("verdict")
            if verdict in ("ok", "hit"):   # A v2：hit = 字面值命中 ⟹ 不漂移
                continue
            drifted.append({"fid": fid, "anchor": a["ref"], "rel": a["rel"],
                            "verdict": verdict, "detail": _drift_detail(v, a["hi"])})
    return {"anchors_total": total, "findings_scanned": len(findings), "drifted": drifted}


def amend_anchors(state_file: str, mapping: dict, apply: bool = False, note: str = "") -> dict:
    """finding 标题行锚**重钉**（append-only）—— `amend-title` 的**执行端**（形态 B）。

    `mapping` = `{old_anchor: new_anchor}`（**显式核实对**；同 `gk_anchor_rebase.py --map` 纪律：
    本函数**不替你判对错**，只按给定清单精确追加）。对每条 finding：`title` 含 `old` ⟹ 以
    `amend_title` 追加 `[刷锚 YYYY-MM-DD] <old> → <new>`（**不改写历史**、幂等 —— 同 suffix 已在则跳过）。

    ⚠ **为何不自动规划**：finding 标题多为**裸锚**（无绑定符号）⟹ `anchor_rebase_plan` 的「最近命中」
    对裸锚不可信（与 plan 侧 `--refs` 纪律同因）⟹ 新值须人工核实后经 `mapping` 给入。
    `apply=False` = **预览**（零写）。返回 {"planned", "applied", "already", "not_found", "dry_run"}。
    """
    findings = load_findings(state_file)
    date = _now()[:10]
    planned, not_found = [], []
    for old, new in mapping.items():
        hits = [f for f in findings if old in str(f.get("title") or "")]
        if not hits:
            not_found.append(old)
        for f in hits:
            planned.append({"fid": f.get("id"), "old": old, "new": new,
                            "suffix": f"[刷锚 {date}] {old} → {new}"})
    if not apply:
        return {"planned": planned, "applied": 0, "already": 0,
                "not_found": not_found, "dry_run": True}
    applied = already = 0
    for p in planned:
        r = amend_title(state_file, p["fid"], p["suffix"], note)
        applied += int(r.get("amended", 0))
        already += int(r.get("already", 0))
    return {"planned": planned, "applied": applied, "already": already,
            "not_found": not_found, "dry_run": False}


def status(state_file: str) -> dict:
    # 2026-10-31（遗漏⑤ 读侧收口）：**读**走 union（主台账 ⊕ finding 溢出片）——
    #   只读 main 会把已溢出条目当「不存在」（读分裂，`MU_BACKCAST_NEGATIVE` 同族）。
    findings = load_findings_union(state_file)
    counts = {}
    for f in findings:
        st = f.get("status", "open")
        counts[st] = counts.get(st, 0) + 1
    return counts


def _parse_bool(v, name):
    s = str(v).strip().lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no"):
        return False
    raise ValueError(f"{name} 需为 true/false/1/0/yes/no（收到: {v!r}）")


def _read_payload_file(path, flag):
    """读 payload 文件（`--title-file` / `--source-file` 通道，2026-09-23 R26 接口化改造）。

    动因：长文本走命令行要同时避让**三重** —— ① shell 引号；② `gatekeeper-cli.sh` 外层
    那一趟 `$VAR`/`$( )` 展开；③ 门禁 R0.2 对文本里危险字面量的拦截。实测连续撞门两次
    （`register 位置参数过多` + R0.2 拦危险字面量）⟹ 把转义负担从人挪到**接口**。
    纪律：不可读 → fail-loud（**绝不**静默降级成默认值）；只去首尾空白，正文内换行原样保留。
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except Exception as e:  # noqa: BLE001 — CLI 边界：统一转显式 usage 错误，不裸抛
        raise ValueError(f"{flag} 文件不可读: {path}（{e}）")
    return raw.strip()


def _load_report_payload(path):
    """`--from-report` 的**允许字段**抽取（2026-09-28，规范正本 references/ecc-write-spec.md）。

    subagent 报告（`docs/analysis/subagent/*.json`；`subagent_runner.EccOutput` 形态）是**易失的
    单次调用输出**，与持久台账 `ECC-FINDING` 是**两类东西**。本通道只允许**显式提升**：
    从报告里抽 `_REPORT_ALLOWED` 白名单内的字段（别名 `summary`→`title`），其余键
    （`conclusion` / `evidence` / `next_steps` / `data` / `jwt_token` / `hmac` …）**一律丢弃**
    ⟹ 结构性保证「整份 subagent 报告不得入册」。附 `_note`（文件名 + sha256[:16]）留痕来源。
    非对象 / 不可读 / 非 JSON → fail-loud（ValueError，绝不静默降级）。
    """
    try:
        raw = Path(path).read_bytes()
    except Exception as e:  # noqa: BLE001 — CLI 边界：显式失败
        raise ValueError(f"--from-report 文件不可读: {path}（{e}）")
    try:
        d = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"--from-report 非合法 JSON: {path}（{e}）")
    if not isinstance(d, dict):
        raise ValueError("--from-report 须为 JSON **对象**（subagent 报告形态）")

    def _list(v):
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
        return [str(v)] if v and str(v).strip() else []

    out = {}
    for k in _REPORT_ALLOWED:
        if k in d and d[k]:
            out[k] = _list(d[k]) if k in ("anchors", "facets", "cover_layers") else d[k]
    if not out.get("title") and d.get("summary"):
        out["title"] = str(d["summary"])
    out["_note"] = "promoted from %s sha256=%s" % (Path(path).name,
                                                   hashlib.sha256(raw).hexdigest()[:16])
    return out


def _usage_error(cmd):
    msgs = {
        "register": "finding register <title> [source] [--title-file <path>] [--source-file <path>] [--from-report <path>] [--family <族>] [--cover-layers L1,L9] [--gap true|false] [--root-key <根因指纹>] [--anchor <锚>]... [--facet <侧面>]... [--closure-oracle <mechanical|judgment>] [--repo <仓根|token>] [--merge-into <fid>] [--dup-ack <理由>] [--domain <repo>.<plan>]",
        "dup-check": "finding dup-check <title> [--family <族>] [--anchor <锚>]... [--facet <侧面>]... [--tau <0..1>] [--limit <n>] [--exclude-id <fid>] [--domain <repo>.<plan>]",
        "verify": "finding verify <id> <true|false> [--verify-source <来源>] [--domain <repo>.<plan>]",
        "close": "finding close <id> [verify_source] [--verify-source <来源>] [--ack-accept] [--domain <repo>.<plan>]",
        "reopen": "finding reopen <id> [reason] [--reason <文本>] [--domain <repo>.<plan>]",
        "release-approve": "finding release-approve <id> [--by <名>] [--note <文本>] [--divergence <0..1>] [--final-ruling] [--declassify] [--domain <repo>.<plan>]",
        "release-reject": "finding release-reject <id> [--by <名>] [--note <文本>] [--domain <repo>.<plan>]",
        "declassify": "finding declassify <id> [--by <名>] [--note <文本>] [--domain <repo>.<plan>]",
        "status": "finding status [--domain <repo>.<plan>]",
        "family": "finding family [--domain <repo>.<plan>]",
        "check": "finding check [--title <标题>] [--root-key <根因指纹>] [--anchors a,b,...] [--domain <repo>.<plan>]",
        "ledger": "finding ledger [--plan <path>] [--domain <repo>.<plan>]",
        "principal": "finding principal [--plan <path>] [--tau <0..1>] [--embeddings <契约jsonl>|--no-embeddings] [--emb-tau <0..1>] [--domain <repo>.<plan>]",
        "embed": "finding embed [--model <id>] [--out <path>] [--from-vectors <json>] [--dry-run] [--domain <repo>.<plan>]",
        "conflicts": "finding conflicts [--converge] [--apply] [--dedupe]",
        "reconcile": "finding reconcile [--domain <repo>.<plan>]",
        "amend-title": "finding amend-title <id> --suffix <text> [--note <text>] [--domain <repo>.<plan>]",
        "anchor-drift": "finding anchor-drift [--repo <dir>] [--domain <repo>.<plan>]",
        "amend-anchors": "finding amend-anchors --map <old=new,...> [--apply] [--note <text>] [--domain <repo>.<plan>]",
        "epoch": "finding epoch [--ts <iso>] [--reason <text>] [--purged <fid,fid,...>] [--domain <repo>.<plan>]",
        "archive-closed": "finding archive-closed [--target-total <bytes>] [--keep-closed <n>] [--dry-run] [--domain <repo>.<plan>]",
        "precheck": "finding precheck <fid> [--domain <repo>.<plan>]",
        "journal-verify": "finding journal-verify [--domain <repo>.<plan>]",
        "stale": "finding stale [--ttl-days <n>] [--apply] [--now <iso>] [--domain <repo>.<plan>]",
    }
    # 2026-10-29（E22）：`main()` 的**第一个位置参数是 `state_file`**
    #   （`cmd, state_file = args[0], args[1]`），而上方文案只写子命令参数 ⟹
    #   照抄 `close <id>` 会把 finding id 当成 state 路径（本日实测连错三次：
    #   第一次 `close <id> <vsrc>` → vsrc 被当状态文件；随后两次 `--verify-source` 亦然）。
    #   故在此**单点**把 `<state_file>` 插进每条文案（子命令表不改，防二源漂移）。
    if not cmd:
        return "usage: finding <cmd> <state_file> [args]"
    tail = msgs.get(cmd)
    if tail is None:
        return "usage: finding %s <state_file> [args]" % cmd
    prefix = "finding " + cmd
    return "usage: " + tail.replace(prefix, prefix + " <state_file>", 1)


def _int_arg(v: str, flag: str) -> int:
    """整数参数解析（缺参/非整数 → 显式 usage 错误，不静默取 0）。"""
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ValueError("%s 需整数（得到 %r）" % (flag, v))


try:  # [P2 修 · ECC-65129D205C9A] 片名**单源**：从卫星中枢 `KIND_SUFFIX` 派生
    #   （原为独立字面量 + 注释式对齐 = 二源漂移风险，改名时中枢静默漂移）。
    from gk_satellite import KIND_SUFFIX as _SAT_KIND_SUFFIX
    _ARCHIVE_SUFFIX = _SAT_KIND_SUFFIX["finding"]
except Exception:  # noqa: BLE001 — 装载期兜底（保既有行为，不新增失败面）
    _ARCHIVE_SUFFIX = ".finding-archive.jsonl"


def _archive_path(state_file: str) -> str:
    """代数归档旁挂（append-only JSONL，可回溯被移出 state 的 closed 条目）。"""
    return state_file + _ARCHIVE_SUFFIX


def _archive_gen_token() -> str:
    """归档**代数标签**（卫星 per-arm 索引叶子用；须匹配中枢 `_SEG_RE` `^[A-Za-z0-9][A-Za-z0-9-]*$`）。

    取 UTC 秒级时间戳（全字母数字）—— 一代际一叶子，与 `epoch(purged_fids)` 的代际语义同轴。

    2026-10-31（遗漏⑤ 实测）：秒级标签在**同一秒内两次溢出**时撞同一叶子 ⟹ 中枢
    `cmd_set_nested` 拒「目标已是容器」的整键替换（G4）⟹ **片已落、索引未登记**
    （`FINDING_SPILLOVER_FAILED … 索引登记失败（片已落）`，回收器够不到该批）。
    修法 = 标签尾部加 6 位随机后缀（仍匹配 SEG_RE），保「一代际一叶子」语义不撞键。
    """
    return (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-" + uuid.uuid4().hex[:6])


def _gen_start_or_earliest(events: list) -> str:
    """归档打 epoch 时的代际起点：有历史 epoch 就**复用**（不推后代际）；否则取 journal
    最早事件 ts（等价「不过滤」）。

    ⚠ 缺省 `_now()` 会把代际起点推到今天 ⟹ 前代事件整体踢出对账 scope；对**仍 live 的
    closed 条目**反而会**新造**「无 journal 前序事件（伪造裁决候选）」异常 —— 即归档动作
    制造出假异常。故必须走本函数。
    """
    gs = _last_epoch(events)
    if gs:
        return gs
    ts = [str(e.get("ts")) for e in events if e.get("ts")]
    return min(ts) if ts else _now()


def archive_closed(state_file: str, target_total: int = 0, keep_closed: int = 0,
                   dry_run: bool = False, ack: bool = False) -> dict:
    """`ecc_findings` **配额驱动的代数归档**（L2，2026-09-25 · `ECC-75DAED1C537C`）。

    背景（实测）：`ecc_findings` 是 state 里**唯一无任何配额**且**单调增长**的分量
    （117 条 95,940 B = 全文件 39.6%；closed 45 条 = 该台账 45.6%），而其余配额各自独立
    定价、无人汇总 ⟹ 它膨胀即吃掉他人预留（见 runtime 子计划 §4.13.9-E）。

    语义（四条都可机检，判据见 `test_gk_finding.py::TestArchiveClosedQuota`）：
      - **配额由汇总预算派生**（不另拍数）：`target_total`（缺省 = **`WALL_TRIM_PCT` 90% 水位**，
        不是 `WALL − RESERVE`）减去**其余分量实测字节**（≈ `canon_bytes − ser_bytes(findings)`）
        ⟹ 得 `ecc_findings` 可用预算；`keep_closed` = 至少保留的 closed 条数。
        取 90% 而非 99.4%：95% 是**写入口拦截线**，若只裁到 `WALL − RESERVE`，归档虽成功但
        state 仍在 95% 以上 ⟹ 下一次普通写立刻被墙闸拦 ⟹ 修复动作没有真正闭环。
      - **只动 `closed`**：`open`/`fixed`/`rejected` **一律不碰**（未闭环/待复核 = 治理信息，
        不得因体积被裁）。
      - 从**最旧** closed 起移出（`closed_at` → `last_modified` → `first_added` 回退），直到
        ≤ 预算 或 closed 仅剩 `keep_closed` 条；移出条目 **append 到旁挂
        `<state>.finding-archive.jsonl`**（可回溯）。
      - 对移出 id 打 epoch 声明 `purged_fids`（`reconcile_pair` 已支持该机制，单列 `purged`
        供审计），且 **ts 复用当前 gen_start**（`_gen_start_or_earliest`）—— 不得推后代际起点。
      - `dry_run=True` **零写盘**（不改 state、不写旁挂、不写 journal）。
    ⚠ `shortfall > 0` = 「裁光 closed 仍超预算」⟹ 预算被**其余分量**吃掉，须另裁他键；本函数
    **不越权**动非 closed 项，只如实上抛（fail-loud）。
    """
    if not dry_run:
        _gate_writable(state_file)
    findings = load_findings(state_file)
    rep = state_size_report(state_file)
    budget = (target_total or (STATE_SIZE_WALL * WALL_TRIM_PCT // 100)) \
        - (rep.get("canon_bytes", 0) - ser_bytes(findings))
    cand = sorted((f for f in findings if f.get("status") == "closed"),
                  key=lambda f: str(f.get("closed_at") or f.get("last_modified")
                                    or f.get("first_added") or ""))
    removed, remaining = [], list(findings)
    for f in cand:
        if len([x for x in remaining if x.get("status") == "closed"]) <= keep_closed:
            break
        if ser_bytes(remaining) <= budget:
            break
        remaining = [x for x in remaining if x is not f]
        removed.append(f)
    before, after = ser_bytes(findings), ser_bytes(remaining)
    out = {"ok": True, "budget": budget, "before_bytes": before, "after_bytes": after,
           "archived": len(removed),
           "archived_ids": sorted(str(f.get("id")) for f in removed if f.get("id")),
           "kept_closed": len([x for x in remaining if x.get("status") == "closed"]),
           "shortfall": max(0, after - budget), "dry_run": bool(dry_run)}
    if not removed or dry_run:
        return out
    # 处置前强制回环闸（Plan-2 / ECC-6E2F2261410D）：归档亦属**处置**（移出 closed 条目 = 写台账）
    #   与其余写面同门；粒度 = **待归档 fids**（§2.4-a），出口 = `--ack-drift`（`main` 咽喉点
    #   透传 `ack=True`）。`dry_run` / 无移出已在上方早返回 ⟹ 此处**必有写**，
    #   故闸随后即落盘（纯读；无漂移 ⟹ 零动作）。
    _guard_precheck(state_file, [str(f.get("id")) for f in removed if f.get("id")], ack=ack)
    # 落盘次序：state 先、旁挂次、代际锚最后（对齐 register/close 的「锚在末」次序）
    save_findings(state_file, remaining)
    _write_checksum(state_file)
    # [ECC-65129D205C9A / 卫星计划 §8/§10] **生产者接线（禁第二直写者）**：片写**收敛为调中枢**
    #   `gk_satellite.append`（片唯一写者 = 中枢）。原实现 `open(_archive_path(state_file), "a")`
    #   是**第二直写者**（绕开中枢 ⟹ 无判活锚 / 无 per-arm 索引叶子 / 静态「零直写」臂可被证伪）。
    #   best-effort（对齐原 `except OSError: pass`）：片写失败**不阻断**归档（否则 state 已裁、
    #   片未落 = 数据丢失），但**留痕**（stderr 由 CLI 汇入 GK_DBG_LOG）。
    try:
        import gk_satellite as _SAT
        _reg = _SAT.append(state_file, "finding", removed,
                           batch_id="finding-closed", arm=_archive_gen_token())
        if not _reg.get("ok"):
            sys.stderr.write("FINDING_ARCHIVE_FAILED n=%d: %s\n"
                             % (len(removed), _reg.get("error")))
    except Exception as _ax:  # noqa: BLE001 — 边界：中枢不可用 ⟹ 不阻断归档主流程
        sys.stderr.write("FINDING_ARCHIVE_FAILED n=%d: %s\n" % (len(removed), _ax))
    epoch(state_file, ts=_gen_start_or_earliest(_journal_events(state_file)),
          reason="ecc_findings 配额归档（L2）",
          purged_fids=[str(f.get("id")) for f in removed if f.get("id")])
    return out


# ══════════ 域 ledger 枚举 + 「本计划应落哪套 state」单点（RC3′，`ECC-46C22B11AD85`）══════════
# 动机（2026-09-26 实测，§4.13.30 一/五）：同一计划名下**并存多套台账**（base 113 条 vs
#   plan-basename 域 138 条，id 交集仅 21、6 条同 id 状态相反），而仓内**无任何只读面**能同时
#   看见它们 ⟹ 单查 base 即误判「不在册」（实测误判 4 条）。归并/冻结须以**只读三源对账**为前置。
# 判据（**只读，零写盘**）：枚举 state 同目录的 base + 全部 `.gatekeeper.state.*` 域 state +
#   各自 `*.finding-archive.jsonl`，给 per-source 计数 + id 交集 + **状态冲突清单**；并可对某计划
#   给出「应落哪套 state」的**单点判定**（声明域 → 域 state；未声明 → base，附可推导域提示）。
# 非活体产物（同目录旁挂，**不是** ledger）：后缀 / 标记双判据（现场实测，见 `_is_live_ledger_name`）。
# ⚠ 后缀须对**全名**判（`.gatekeeper.state.lock` 的 token 是 `lock`，不带点 ⟹ 只判 token 会漏收）。
# 2026-10-01（`ECC-8F359340A5B9`）：补 `.seal` —— **产物命名体系漂移**的落点：账本**模块名**用
#   下划线（`gk_credit_ledger` / `gk_budget_ledger`）、**产物名**用连字符（`.credit-ledger.jsonl`
#   / `.budget-log.jsonl`），而后缀排除清单在此**手抄第二份** ⟹ 后加的封印（两模块的
#   `SEAL_SUFFIX` = `<产物>.jsonl.seal`）漏登记：`.jsonl` 收录了、`.jsonl.seal` 没有 ⟹ 封印被
#   当**活体域 ledger**（`--domain credit-ledger.jsonl.seal` 可解析 ⟹ 写入即毁封印）。
#   抗漂移判据（机检）= `scripts/test_gk_finding_ledger_artifact_filter.py::test_arm2`：
#   断言两模块声明的 `SUFFIX`/`SEAL_SUFFIX` **全部**被本清单覆盖（单源判据，禁再漏）。
_LEDGER_ARTIFACT_SUFFIXES = (".tmp", ".bak", ".json", ".jsonl", ".lock", ".orig", ".swp", ".seal")
_LEDGER_ARTIFACT_MARKERS = ("bak-", "corrupt-", ".subagent-history", "pre-budget")


def _is_live_ledger_name(name: str) -> bool:
    """文件名是否是一个**活体**域 ledger（`.gatekeeper.state.<token>`）。

    现场（2026-09-26 实测）：state 同目录不止活体域 —— 还混着备份/临时/归档旁挂
    （`.bak-*` / `*.tmp` / `corrupt-*` / `*.pre-budget*.bak` / `*.finding-journal.jsonl` /
    `*.subagent-history.archive-*.json`）⟹ 它们**不是** ledger，读进来会**虚报计数**
    （首版实测：archive 竟被当域、journal 与 `.lock` 各成 0 条「域」）；更糟的是
    `.gatekeeper.state.<…>.subagent-history.archive-*.json` 顶层是 **JSON list**，
    `load_findings` 在它上面直接 `'list' object has no attribute 'setdefault'` 崩。
    判据（收紧，宁漏不误收）：**全名**不带产物后缀，且 token 合 `_DOMAIN_TOKEN_RE`、不带产物标记。
    """
    if not name.startswith(_STATE_PREFIX + "."):
        return False
    if name.endswith(_LEDGER_ARTIFACT_SUFFIXES):
        return False
    tok = name[len(_STATE_PREFIX):].lstrip(".")
    if not tok or not _DOMAIN_TOKEN_RE.match(tok):
        return False
    return not any(m in tok for m in _LEDGER_ARTIFACT_MARKERS)


def _live_ledger_paths_in(d: str) -> list:
    """某目录内的**活体** finding ledger 路径（base `.gatekeeper.state` + 域 `.gatekeeper.state.<token>`）。

    只读；目录缺失 ⟹ `[]`。域名收紧 = `_is_live_ledger_name`（备份/临时/归档旁挂一律不收）。
    """
    out = []
    try:
        b = os.path.join(d, _STATE_PREFIX)
        if os.path.isfile(b):
            out.append(os.path.abspath(b))
        for n in sorted(os.listdir(d)):
            if _is_live_ledger_name(n):
                out.append(os.path.abspath(os.path.join(d, n)))
    except OSError:
        pass
    return out


def _ledger_sources(state_file: str) -> list:
    """三源枚举 `[(path, domain, kind)]`，kind ∈ {base, domain, archive}（**跨仓**，只读）。

    源 = base（`state_file` 自身）+ **同目录**活体域 ledger + **候选仓**（`_candidate_repos`：
    env `GK_FINDING_REPOS` / 技能仓 / state 所在仓 / CWD 所在仓 / 同级仓）**各自目录**下的活体
    ledger —— **跨仓默认**（`ECC-ECDB1C9C2B1D` / owner 2026-10-15「ecc-finding 全过程必须默认
    支持跨仓」）；单目录口径会令**他仓 ledger** 不在全域对账面内 ⟹ 真跨仓「双源漂移」检测不到。
    `_is_live_ledger_name` 收紧：备份/临时/归档旁挂一律不收；archive = 每个源的
    `<...>.finding-archive.jsonl`（若存在）。
    """
    base = os.path.abspath(state_file)
    d = os.path.dirname(base) or "."
    cand = [base]
    for p in _live_ledger_paths_in(d):
        if p != base:
            cand.append(p)
    for repo in _candidate_repos(state_file):
        rd = os.path.abspath(repo) if repo else ""
        if not rd or rd == os.path.abspath(d):
            continue
        cand.extend(_live_ledger_paths_in(rd))
    out, seen = [], set()
    for p in cand:
        ap = os.path.abspath(p)
        if ap in seen or not os.path.isfile(ap):
            continue
        seen.add(ap)
        out.append((ap, _state_file_domain(ap), "base" if ap == base else "domain"))
    for ap, dom, _k in list(out):
        arch = _archive_path(ap)
        if os.path.isfile(arch):
            out.append((arch, dom, "archive"))
    return out


def _read_findings_source(path: str, kind: str) -> list:
    """读一个源的 findings（archive = JSONL 逐行；其余 = state 的 `ecc_findings`）。

    **防御式只读**（不用 `load_findings`：后者会在缺 `gate_data` 时**改内存 dict**，且对
    顶层非 dict 的文件直接崩 —— 现场有顶层为 list 的旁挂）。任何不可解析/形态不符 → `[]`。
    """
    if kind == "archive":
        out = []
        try:
            with open(path, encoding="utf-8") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln:
                        item = json.loads(ln)
                        if isinstance(item, dict):
                            out.append(item)
        except (OSError, ValueError):
            return []
        return out
    try:
        s = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — 边界：坏文件不崩，返回空（计数照实为 0）
        return []
    gd = s.get("gate_data") if isinstance(s, dict) else None
    if isinstance(gd, dict) and isinstance(gd.get("ecc_findings"), list):
        return gd["ecc_findings"]
    return []


def resolve_plan_state(state_file: str, plan_file: str = "", skill_dir: str = "") -> dict:
    """「**本计划应落哪套 state**」单点判定（只读）—— 收敛「落哪套无单点裁决」缺口。

    次序（**全部复用既有单源**，不另立第二套判定）：
      · 声明域（`gk_route_center.meta_state_domain` 读 META）→ 目标 = `<dir>/.gatekeeper.state.<token>`；
      · 未声明 → 目标 = **base**（`basis="base"`），并附**可推导域**（`derive_state_domain`）提示
        `would_be` —— 这正是「声明 opt-in」下的实际落点，供作者驱动声明。
    ⚠ **只读**：不建域 state、不改 base；`target_exists=false` 时照实上报（不臆造）。
    """
    base = os.path.abspath(state_file)
    sdir = os.path.dirname(base) or "."
    declared = derived = ""
    try:
        import gk_route_center as rc
        declared = rc.meta_state_domain(plan_file, skill_dir)
        if not declared and plan_file:
            meta = (rc.resolve_plan(plan_file, skill_dir).get("meta") or {})
            derived = rc.derive_state_domain(meta, plan_file)
    except Exception:  # noqa: BLE001 — 边界：拿不到路由源就照实回 base（不臆造域）
        pass
    token = declared or ""
    target = (os.path.join(sdir, _STATE_PREFIX + "." + token) if token else base)
    would_be = (os.path.join(sdir, _STATE_PREFIX + "." + derived)
                if derived and not declared else "")
    return {"ok": True, "plan": os.path.abspath(plan_file) if plan_file else "",
            "declared_domain": declared, "derived_domain": derived,
            "basis": "declared" if declared else "base",
            "target": target, "target_exists": os.path.isfile(target),
            "would_be": would_be}


def _src_key(p: str, state_file: str) -> str:
    """跨源去重键（`ledger.shared_ids` / `conflicts.by_source` 的键）。

    治「**两仓同名 `.gatekeeper.state` 并键**」（`ECC-ECDB1C9C2B1D`）：**同目录**源仍用 basename
    （原形，零回归）；**异目录**（真跨仓）源用相对 base 目录的路径（唯一、可读）⟹ 跨仓同 fid 的
    两源不再被压成一键（否则 `shared_ids`/`conflicts` **恒漏报**）。
    """
    ap = os.path.abspath(p)
    bd = os.path.dirname(os.path.abspath(state_file)) or "."
    if os.path.dirname(ap) == bd:
        return os.path.basename(ap)
    try:
        return os.path.relpath(ap, bd)
    except ValueError:  # 跨盘符等 relpath 失败 ⟹ 绝对路径兜底（仍唯一）
        return ap


def ledger(state_file: str, plan_file: str = "", skill_dir: str = "") -> dict:
    """按域枚举 findings（只读三源对账）+ 可选「本计划应落哪套 state」单点判定。

    返回 `{ok, base, sources[], ids_total, shared_ids[], conflicts[], plan_target?}`：
      · `sources[]` 每项 `{path, domain, kind, total, by_status}`（计数**可复算**）；
      · `shared_ids` = 出现在 ≥2 源的 id；`conflicts` = 同 id 在源间**状态不一致**者（带 `by_source`）。
    ⚠ 只读：枚举与判定均零写盘。
    """
    sources, id_status = [], {}
    for p, dom, kind in _ledger_sources(state_file):
        fs = _read_findings_source(p, kind)
        by = {}
        for f in fs:
            st = f.get("status", "open")
            by[st] = by.get(st, 0) + 1
        sources.append({"path": p, "domain": dom, "kind": kind,
                        "total": len(fs), "by_status": by})
        for f in fs:
            fid = f.get("id")
            if fid:
                id_status.setdefault(fid, {})[_src_key(p, state_file)] = f.get("status", "open")
    conflicts = [{"id": fid, "by_source": m}
                 for fid, m in sorted(id_status.items()) if len(set(m.values())) > 1]
    out = {"ok": True, "base": os.path.abspath(state_file),
           "sources": sources, "ids_total": len(id_status),
           "shared_ids": sorted(fid for fid, m in id_status.items() if len(m) > 1),
           "conflicts": conflicts}
    if plan_file:
        out["plan_target"] = resolve_plan_state(state_file, plan_file, skill_dir)
    return out


def status_map(state_file: str) -> dict:
    """**全源** `{fid: status}`（只读）—— 供 `gk_plan_lint.check_dep_gate` 等**只读消费者**
    复用「枚举域化源 + 读 status」单源；**禁**各自直读裸 JSON（`ECC-57A1D39ABB4E`）。

    同 id 出现在多源且状态不一致时取**非 closed 优先**（保守：一处 closed 不得掩盖他处 open）。
    """
    out = {}
    for p, _dom, kind in _ledger_sources(state_file):
        for f in _read_findings_source(p, kind):
            fid = f.get("id")
            if not fid:
                continue
            st = f.get("status", "open")
            if fid not in out or (out[fid] == "closed" and st != "closed"):
                out[fid] = st
    return out


# ══════════ 台账级「主要矛盾」提取器（principal；`ECC-02710BDFAC8E`）══════════
# 缺口（2026-10-10 用户裁定）：ECC 的 `principal` 此前只有**形式判据**
#   （`monitor-schemas/ECC-WRITE.json::principal_singular_if_present`：principal **若给出**则恰 1 条），
#   **无**「吃台账 → 吐主要矛盾」的**函数** ⟹ MoA 页只能对挑战**计数**（质询挑战 121 / 保留 122 / 应砍 106），
#   无法把 100+ 条**塌缩**为根因组（RC）⟹ fan-out 无法降维（修 100+ 要派 100+ coder = 鸡生蛋）。
# 本函数 = 该**函数**（确定性、零 LLM、只读）：复用既有件，不新增第二实现 ——
#   · 全源合并 = `_ledger_sources`/`_entries_by_id` + `_pick_winner`（finding 面既有）；
#   · 锚集 Jaccard 聚类 = `gk_moa_aggregate._jaccard`/`_avg_linkage`（**聚合 RC** 既有；惰性 import 防循环）；
#   · carrier = 读既有 `carrier:P/L/M` facet（`assess_findings` 已产）。
# 排序口径（用户裁）：`score = Σ_{open 成员} severity`；severity 缺失 ⟹ 按 carrier 兜底（默认 1.0）。
_SEVERITY_WEIGHT = {"critical": 8.0, "high": 4.0, "medium": 2.0, "low": 1.0, "info": 0.5}
_CARRIER_SEVERITY = {"M": 4.0, "L": 4.0, "P": 2.0}
# 聚类键**排除**的标量/测量 facet（非根因标签；与 `_SCALAR_FACET_NS` 同族）
_CLUSTER_FACET_EXCLUDE = ("classification", "carrier", "refs", "clusters", "weight",
                          "class-tie", "batch", "plan", "cross-batch", "stale", "declassified")


def _finding_severity(f: dict) -> float:
    """严重度权重（确定性）：显式 `severity` 优先 → `carrier:` facet 兜底 → 默认 1.0。"""
    sev = str(f.get("severity") or "").strip().lower()
    if sev in _SEVERITY_WEIGHT:
        return _SEVERITY_WEIGHT[sev]
    for x in (f.get("facets") or []):
        s = str(x)
        if s.startswith("carrier:"):
            c = s.split(":", 1)[1].strip().upper()
            if c in _CARRIER_SEVERITY:
                return _CARRIER_SEVERITY[c]
    return 1.0


# title 词提取（召回加强；2026-10-10 `ECC-7F6AC6625A45`）：ASCII 词(len≥2) + 中文 **bigram**
#   （中文按双字滑窗，避免单字噪声；停用词仅去最高频功能词）
_TITLE_ASCII_RE = re.compile(r"[a-z0-9_]{2,}")
_TITLE_CJK_RE = re.compile(r"[\u4e00-\u9fff]")
_TITLE_STOP = frozenset((
    "the", "and", "for", "with", "not", "but", "all", "any", "null", "none", "true", "false",
    "finding", "ecc", "bug", "test", "arm", "def", "get", "set", "use",
))


def _title_tokens(s: str) -> set:
    """title → 词集：ASCII 词（len≥2、去停用）+ 中文 bigram（滑窗）。"""
    low = str(s or "").lower()
    toks = {t for t in _TITLE_ASCII_RE.findall(low) if t not in _TITLE_STOP}
    cjk = _TITLE_CJK_RE.findall(low)
    toks |= {"".join(cjk[i:i + 2]) for i in range(len(cjk) - 1)}
    return toks


def _finding_cluster_tokens(f: dict) -> set:
    """`root_key` 缺省时的聚类键：**锚集**(`a:`) + 非标量 facet(`f:`) + **title 词**(`t:`)。

    2026-10-10（`ECC-7F6AC6625A45`）：原先只吃 anchors ⟹ 550 条中 548 成孤项（召回太弱）。
    加 title 词提召回；窄 τ=0.6 仍约束精度（散词重合不足以过阈）。
    """
    toks = set()
    for a in (f.get("anchors") or []):
        s = str(a).strip().lower()
        if s:
            toks.add("a:" + s)
    for x in (f.get("facets") or []):
        s = str(x).strip().lower()
        if not s or s.split(":", 1)[0] in _CLUSTER_FACET_EXCLUDE:
            continue
        toks.add("f:" + s)
    for t in _title_tokens(f.get("title") or ""):
        toks.add("t:" + t)
    return toks


# ── 写前「同类同族」候选（OSS 前置计划 §2.3-A，2026-10-26）────────────────────
# 病象：`register` 写前**只有** root_key 命中合并 + 无 root_key 时精确标题幂等 ⟹ 并发两会话
#   （如 audit --bomb 与交叉审查收口）把同一根因各记一条 = 两条 open（μ_n 被抬高）。
# 纪律（§2.5）：**只提示、不自动并** —— 缺省静默合并会让被审 agent 移动自己停止检验的分母，
#   与论文 §3「签名是冻结的外部输入」冲突。合并只走调用方显式 `merge_into`。
_DUP_TAU = 0.6


def dup_candidates(state_file: str, title: str, family: str = "", anchors=None,
                   facets=None, tau: float = _DUP_TAU, limit: int = 5,
                   exclude_id: str = "") -> dict:
    """**只读**候选面：返回与「本条待登记内容」相似的在账 open finding（不改任何文件）。

    - 相似度单源 = `_finding_cluster_tokens`（锚 `a:` + 非标量 facet `f:` + 标题词 `t:`）
      的 Jaccard（实现单源 = `gk_moa_aggregate._jaccard`，**禁第二实现**）；
    - 族过滤：本条 `family` 非空时只比同族（族空 ⟹ 不做硬过滤并标 `family_unfiltered`）；
    - 只在账 **open** 记录参与（终态不提示，防「重复已关」噪音）；
    - 空候选 = `[]` + `ok:true`；读取失败 ⟹ `ok:false` + 具名 `error`（**不拿空列表冒充**）。
    """
    from gk_moa_aggregate import _jaccard   # 惰性 import（防顶层循环）

    probe = {"title": title or "", "family": family or "",
             "anchors": list(anchors or []), "facets": list(facets or [])}
    pt = _finding_cluster_tokens(probe)
    if not pt:
        return {"ok": True, "candidates": [], "tau": tau,
                "stats": {"open": 0, "compared": 0, "family_unfiltered": not bool(str(family or "").strip())}}
    fam = str(family or "").strip()
    try:
        recs = load_findings_union(state_file)
    except Exception as e:  # noqa: BLE001 — 边界：读取不可用 ⟹ 具名 error（禁假绿）
        return {"ok": False, "error": type(e).__name__, "candidates": [], "tau": tau}
    _an = {str(a) for a in (anchors or [])}
    out, compared = [], 0
    for f in recs:
        if not isinstance(f, dict) or str(f.get("status", "open")) in _TERMINAL_STATES:
            continue
        if exclude_id and str(f.get("id") or "") == exclude_id:
            continue  # 登记后自查时排除刚落的这一条（否则恒 1.0 自匹配）
        cf = str(f.get("family") or "").strip()
        if fam and cf and cf != fam:
            continue
        compared += 1
        ct = _finding_cluster_tokens(f)
        if not ct:
            continue
        sc = _jaccard(pt, ct)
        if sc < tau:
            continue
        out.append({"id": f.get("id"), "title": f.get("title", ""),
                    "status": f.get("status", "open"), "score": round(sc, 4),
                    "family_match": bool(fam and cf == fam),
                    "shared_anchors": sorted(_an & {str(a) for a in (f.get("anchors") or [])})})
    out.sort(key=lambda x: (-x["score"], str(x.get("id") or "")))
    return {"ok": True, "candidates": out[:max(1, int(limit))], "tau": tau,
            "stats": {"open": compared, "matched": len(out),
                      "family_unfiltered": not bool(fam)}}


# ── embedding 粗筛（2026-10-10 `ECC-FAF2A8F0A0DF`，用户裁定 ③-A）───────────────
# 旁挂契约 `<state>.finding-embeddings.jsonl`（每行 {"id":..,"vec":[..]}；不进 git）。
# 中文 finding 标题的**语义近重复**（措辞不同、token 不重叠）Jaccard 恒 0 ⟹ 靠向量召回。
# A/B：`bge-small-zh-v1.5`（中文）P@1=79.2%/gap=0.130 ≫ `arctic-embed-xs`（英文）60.4%/0.079。
# 角色 = **粗筛召回**（与 Jaccard 取并集）；**主判据仍是 root_key/锚集**；缺失则 fail-open。
_EMB_TAU_DEFAULT = 0.66   # A/B 校准（bge 同主题 0.675 / 异主题 0.545，取中间偏召回）


def _load_embeddings(path: str) -> dict:
    """读旁挂向量契约 `<state>.finding-embeddings.jsonl` → `{fid: [float,...]}`。

    fail-open（用户裁定 ③-A）：文件缺失/坏行一律跳过，返回已解析部分（不抛）。
    """
    out = {}
    if not path or not os.path.exists(path):
        return out
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:  # noqa: BLE001 — 坏行跳过（fail-open）
                    continue
                fid = str(rec.get("id") or "").strip()
                vec = rec.get("vec")
                if fid and isinstance(vec, list) and vec:
                    try:
                        out[fid] = [float(x) for x in vec]
                    except (TypeError, ValueError):
                        continue
    except OSError:
        return {}
    return out


def _cosine(a, b) -> float:
    """余弦相似度（纯 python；维度不等取短，模零返 0）。"""
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    dot = na = nb = 0.0
    for i in range(n):
        dot += a[i] * b[i]
        na += a[i] * a[i]
        nb += b[i] * b[i]
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / ((na ** 0.5) * (nb ** 0.5))


# ── 相似度 BLAS/GEMM 路径（`ECC-5B314A80DD49`，2026-10-11）─────────────────────
# 病象：`principal` ② 阶段纯 Python 双层循环算两两余弦（`_cosine` 每对 d 维 ×3 次解释器循环）
#   ⟹ `O(n²·d)`，n 跨线（≳3–5k）即成瓶颈。修法：numpy 可用时一次 `V @ V.T`（BLAS GEMM）出对集；
#   numpy 缺席则**回退**逐对 `_cosine`（零回归）。两路径**逐位等价**（同 `emb_tau` 判据）。
_NUMPY_CACHE: list = []   # [] = 未探测；[None] = 不可用；[mod] = numpy 模块（惰性单点）


def _get_numpy():
    """惰性探测 numpy（缺席 ⟹ None；调用方回退纯 Python）。单点缓存（测试可替身）。"""
    if not _NUMPY_CACHE:
        try:
            import numpy as _n
            _NUMPY_CACHE.append(_n)
        except Exception:  # noqa: BLE001 — numpy 非硬依赖，缺席即回退纯 Python
            _NUMPY_CACHE.append(None)
    return _NUMPY_CACHE[0]


def _emb_links_numpy(ids, emb, emb_tau):
    """BLAS 路径：返回满足 `cos>=emb_tau` 的下标对集 `{(i,j)|i<j}`；不可用/不适用 ⟹ **None**（回退）。

    适用条件（任一不满足即 None，保持与逐对 `_cosine` **同语义**）：numpy 可用；`ids` 每条都有向量；
    向量等长且非空。返回 None 时调用方走原逐对路径（逐位等价，零回归）。
    """
    np = _get_numpy()
    if np is None or not ids:
        return None
    rows = []
    for fid in ids:
        v = emb.get(fid)
        if not v:
            return None                      # 有缺向量 ⟹ 回退（旧路径只连「双方都有向量」的对）
        rows.append(v)
    d = len(rows[0])
    if d == 0 or any(len(r) != d for r in rows):
        return None                          # 长度不齐 ⟹ 回退（`_cosine` 取短，语义不同）
    X = np.asarray([[float(x) for x in r] for r in rows], dtype=np.float64)
    nrm = np.sqrt((X * X).sum(axis=1))
    nz = nrm > 0.0
    Xn = np.zeros_like(X)
    Xn[nz] = X[nz] / nrm[nz, None]
    S = Xn @ Xn.T                            # 一次 GEMM：n×n 相似度
    iu, ju = np.triu_indices(len(rows), k=1)
    m = S[iu, ju] >= emb_tau
    return set(zip(iu[m].tolist(), ju[m].tolist()))


# ── 相似度矩阵向量化 + LSH 候选（`ECC-5B314A80DD49` 续，2026-10-11）──────────────
# 上一刀只把「两两余弦」搬上 BLAS，但 ② 的 `for i/for j` 仍在 Python 里逐对跑 `_jaccard`
# （O(n²) 解释器迭代），且 `sim` 是 Python list-of-lists（~32 B/格 ⟹ n=10k 约 3.2 GB）。
# 本刀补齐三件：① **Jaccard 向量化**（token 位矩阵 `M@M.T` 出交集，去 Python 双层）；
# ② **`sim` 改 numpy**（float64 8 B/格 ⟹ 4× 省内存；`_avg_linkage` 的 `sim[i][j]` 索引天然兼容）；
# ③ **LSH 候选**（余弦超平面 + token MinHash；n≥阈值只算候选对，把 n² 降到 ~|C|）。
_LSH_N_DEFAULT = int(os.environ.get("GK_PRINCIPAL_LSH_N", "1"))       # n≥此值启用 LSH 候选
# 用户裁定（2026-10-11）：**LSH 常态启用**（默认 1）。真台账并集 n=554 实测 LSH 召回 99.2%
#   （orphans 248 vs 精确 249、emb_links 5723 vs 5770）⟹ 可接受的近似；若要退回稠密精确路径，
#   设 env `GK_PRINCIPAL_LSH_N` 为 >n 的值即可。
_LSH_BANDS = int(os.environ.get("GK_PRINCIPAL_LSH_BANDS", "16"))      # band 数
_LSH_ROWS = int(os.environ.get("GK_PRINCIPAL_LSH_ROWS", "4"))         # 每 band 行数（k=bands*rows）
_LSH_SEED = int(os.environ.get("GK_PRINCIPAL_LSH_SEED", "20261011"))  # 固定 seed ⟹ 确定性


def _token_bitmatrix(sigs, np):
    """token 集列表 → `(M: n×V float64 0/1, sizes: n)`；Jaccard 向量化的底座。"""
    vocab = {}
    for s in sigs:
        for t in s:
            if t not in vocab:
                vocab[t] = len(vocab)
    M = np.zeros((len(sigs), max(len(vocab), 1)), dtype=np.float64)
    for i, s in enumerate(sigs):
        for t in s:
            M[i, vocab[t]] = 1.0
    return M, M.sum(axis=1)


def _jaccard_matrix_numpy(sigs, np):
    """向量化 Jaccard：`inter=M@M.T`（BLAS）、`union=s_i+s_j−inter`。数值与 `_jaccard` 等价。"""
    M, sizes = _token_bitmatrix(sigs, np)
    inter = M @ M.T
    union = sizes[:, None] + sizes[None, :] - inter
    safe = np.where(union > 0.0, union, 1.0)
    jac = np.where(union > 0.0, inter / safe, 0.0)
    np.fill_diagonal(jac, 0.0)
    return jac


def _emb_pairs_numpy(ids, emb, emb_tau, np):
    """「有向量」子集的 cos 近邻对（映射回原下标）；缺向量的行不参与（与旧逐对路径同语义）。

    等长向量走 BLAS `Vn@Vn.T`；长度不齐退回逐对 `_cosine`（取短语义）。**不再整段落空**。
    """
    sub = [(i, emb.get(fid)) for i, fid in enumerate(ids) if emb.get(fid)]
    if not sub:
        return set()
    d0 = len(sub[0][1])
    if d0 == 0 or any(len(v) != d0 for _i, v in sub):
        pairs = set()
        for a in range(len(sub)):
            for b in range(a + 1, len(sub)):
                if _cosine(sub[a][1], sub[b][1]) >= emb_tau:
                    pairs.add((sub[a][0], sub[b][0]))
        return pairs
    X = np.asarray([[float(x) for x in v] for _i, v in sub], dtype=np.float64)
    nrm = np.sqrt((X * X).sum(axis=1))
    nz = nrm > 0
    Xn = np.zeros_like(X)
    Xn[nz] = X[nz] / nrm[nz, None]
    S = Xn @ Xn.T
    iu, ju = np.triu_indices(len(sub), k=1)
    m = S[iu, ju] >= emb_tau
    idx = [i for i, _v in sub]
    return {(idx[a], idx[b]) for a, b in zip(iu[m].tolist(), ju[m].tolist())}


def _sim_matrix_numpy(ids, sigs, emb, emb_tau, np):
    """稠密精确路径：向量化 Jaccard ⊕ embedding must-link。返回 `(sim float64 n×n, emb_links)`。"""
    jac = _jaccard_matrix_numpy(sigs, np)
    pairs = _emb_pairs_numpy(ids, emb, emb_tau, np)   # 有向量的子集（缺向量行不参与）
    if pairs:
        pr = sorted(pairs)
        idx = np.fromiter((x for p in pr for x in p), dtype=int,
                          count=2 * len(pr)).reshape(len(pr), 2)
        jac[idx[:, 0], idx[:, 1]] = 1.0
        jac[idx[:, 1], idx[:, 0]] = 1.0
    return jac, len(pairs)


def _lsh_candidates(ids, sigs, emb, np):
    """LSH 候选对（余弦超平面 + token MinHash，banding）。返回上三角 `{(i,j)|i<j}`；确定性。

    余弦族**只对有向量的行**建桶（缺向量的行不参与该族，但仍由 MinHash 族覆盖），
    避免「个别缺向量 ⟹ 整族跳过」的整段失能（真台账实测 554 条中 2 条缺向量）。
    """
    n = len(ids)
    rng = np.random.default_rng(_LSH_SEED)
    k = _LSH_BANDS * _LSH_ROWS
    cand = set()

    def _bucket(packed, idxs):
        for b in range(_LSH_BANDS):
            blk = packed[:, b * _LSH_ROWS:(b + 1) * _LSH_ROWS]
            buckets = {}
            for r in range(len(idxs)):
                buckets.setdefault(blk[r].tobytes(), []).append(idxs[r])
            for grp in buckets.values():
                for a in range(len(grp)):
                    for c in range(a + 1, len(grp)):
                        i, j = grp[a], grp[c]
                        cand.add((i, j) if i < j else (j, i))

    with_v = [(i, emb.get(fid)) for i, fid in enumerate(ids) if emb.get(fid)]
    if with_v:
        d0 = len(with_v[0][1])
        if d0 > 0 and all(len(v) == d0 for _i, v in with_v):
            X = np.asarray([[float(x) for x in v] for _i, v in with_v], dtype=np.float64)
            nrm = np.sqrt((X * X).sum(axis=1))
            nz = nrm > 0
            Xn = np.zeros_like(X)
            Xn[nz] = X[nz] / nrm[nz, None]
            H = (Xn @ rng.standard_normal((d0, k))) > 0.0
            _bucket(H, [i for i, _v in with_v])

    vocab = {}
    for s in sigs:
        for t in s:
            if t not in vocab:
                vocab[t] = len(vocab) + 1
    if vocab:
        P = 2147483647                              # 2^31−1（a*h+b < 2^47 ⟹ int64 不溢出）
        aa = rng.integers(1, P, size=k)
        bb = rng.integers(0, P, size=k)
        sig = np.full((n, k), -1.0, dtype=np.float64)
        for i, s in enumerate(sigs):
            if not s:
                continue
            h = np.array([vocab[t] for t in s], dtype=np.int64)[:, None]
            sig[i, :] = ((aa * h + bb) % P).min(axis=0)
        _bucket(sig, list(range(n)))
    return cand


def _sim_matrix_lsh(ids, sigs, emb, emb_tau, np):
    """LSH 候选路径：**仅候选对**算真值 sim（其余 0）。返回 `(sim float64 n×n, emb_links, |cand|)`。

    近似（漏配率由 `_LSH_BANDS/_LSH_ROWS` 控制）；仅当 n≥`_LSH_N_DEFAULT` 时启用。
    """
    from gk_moa_aggregate import _jaccard
    n = len(ids)
    cand = _lsh_candidates(ids, sigs, emb, np)
    sim = np.zeros((n, n), dtype=np.float64)
    emb_links = 0
    for (i, j) in cand:
        s = _jaccard(sigs[i], sigs[j])
        vi, vj = emb.get(ids[i]), emb.get(ids[j])
        if vi and vj and _cosine(vi, vj) >= emb_tau:
            s = 1.0
            emb_links += 1
        sim[i, j] = sim[j, i] = s
    return sim, emb_links, len(cand)


def principal(state_file: str, plan_file: str = "", tau: float = 0.6,
              embeddings_file=None, emb_tau: float = _EMB_TAU_DEFAULT) -> dict:
    """**台账级主要矛盾提取器**（只读、确定性、零 LLM）。

    契约（用户 2026-10-10 裁定）：
      · 输入 = finding ledger **全源合并**（base + 活体域 state + archive），同 id 按 `_pick_winner` 取权威；
      · 聚类键 = `root_key` 优先（**仅 n≥2 的组**精确成组；单例交给余项聚类）
        **并**锚集 Jaccard（平均连接凝聚 τ）**并** embedding 粗筛（`ECC-FAF2A8F0A0DF`
        ③-A：`cos>=emb_tau` 的对强制直连，并集召回）；
      · 排序 = 簇内 `open` 数 × severity（severity 缺失按 carrier 兜底，默认 1.0）。

    `embeddings_file`：`None`=自动探测 `<state_file>.finding-embeddings.jsonl`；`""`=关闭；
    路径=用该契约文件。文件缺失 ⟹ **fail-open** 退回纯 Jaccard（现况不变）。

    输出 `{ok, principal, root_causes[], orphans[], stats}`：
      · `principal` = **恰 1**，且**只从根因组（size≥2）中选**（2026-10-10 `ECC-7F6AC6625A45`：
        单例/孤项**不得**当主矛盾；无合格 RC ⟹ `None` = fail-loud）；平局取 open 多者，再取 key 字典序；
      · `root_causes[]` = 每个根因组（size≥2）的溶解清单（members）+ score/open/carrier；
      · `orphans[]` = **未归并孤项**（单例；单列，不充数）。
    """
    from collections import Counter
    from gk_moa_aggregate import _jaccard, _avg_linkage   # 惰性 import（防顶层循环）

    merged = {fid: _pick_winner(ents)[2]
              for fid, ents in _entries_by_id(state_file).items()}
    # relevance:out = 不可验证/不可冒充缺陷；保留台账审计，但不进 RC/orphan 计数。
    merged = {fid: f for fid, f in merged.items()
              if "relevance:out" not in (f.get("facets") or [])}

    def _open(f):
        return str(f.get("status", "open")) not in _TERMINAL_STATES

    def _score(f):
        return _finding_severity(f) if _open(f) else 0.0

    # ① root_key 精确成组（非空者）。只预分组 n≥2 的组；单例交给 ②。
    #    否则 `convert` 给每条散文标题生成的唯一 root_key 会把跨措辞同根因永久隔成孤项。
    groups, by_rk = [], {}
    for fid, f in merged.items():
        rk = str(f.get("root_key") or "").strip()
        if not rk:
            continue
        by_rk.setdefault(rk, []).append(fid)
    grouped = set()
    for rk, members in by_rk.items():
        if len(members) < 2:
            continue
        groups.append({"key": "root_key:" + rk, "members": members})
        grouped.update(members)

    # ② 余项 → 锚集 Jaccard（平均连接凝聚）+ embedding 粗筛（并集召回，`ECC-FAF2A8F0A0DF`）
    emb_path = (state_file + ".finding-embeddings.jsonl") if embeddings_file is None \
        else str(embeddings_file)
    emb = _load_embeddings(emb_path) if emb_path else {}
    emb_links = 0
    rest = [(fid, merged[fid]) for fid in merged if fid not in grouped]
    if rest:
        ids = [fid for fid, _f in rest]
        sigs = [_finding_cluster_tokens(f) for _fid, f in rest]
        n = len(rest)
        np_ = _get_numpy()
        sim = None
        if np_ is not None and n >= _LSH_N_DEFAULT:
            # ③ LSH 候选路径（大 n；仅候选对算真值；近似，漏配率由 bands/rows 控制）
            sim, emb_links, _nc = _sim_matrix_lsh(ids, sigs, emb, emb_tau, np_)
        elif np_ is not None:
            # ①② 向量化稠密精确路径（Jaccard 位矩阵 GEMM + numpy sim）
            sim, emb_links = _sim_matrix_numpy(ids, sigs, emb, emb_tau, np_)
        if sim is None:
            # 回退：numpy 缺席 ⟹ 原纯 Python 双层路径
            npl = _emb_links_numpy(ids, emb, emb_tau)
            sim = [[0.0] * n for _ in range(n)]
            for i in range(n):
                for j in range(i + 1, n):
                    s = _jaccard(sigs[i], sigs[j])
                    if npl is not None:
                        if (i, j) in npl:
                            s = 1.0   # 向量近邻 ⟹ 强制直连（must-link；粗筛召回，与 Jaccard 取并集）
                            emb_links += 1
                    else:
                        vi, vj = emb.get(ids[i]), emb.get(ids[j])
                        if vi and vj and _cosine(vi, vj) >= emb_tau:
                            s = 1.0
                            emb_links += 1
                    sim[i][j] = sim[j][i] = s
        for idxs in _avg_linkage(sim, n, tau):
            groups.append({"key": "anchors", "members": [ids[i] for i in idxs]})

    # ③ 打分 + 排序（score↓ → open↓ → key 字典序；确定性，不依赖遍历顺序）
    rcs = []
    for g in groups:
        fs = [merged[m] for m in g["members"]]
        carriers = Counter()
        for f in fs:
            for x in (f.get("facets") or []):
                s = str(x)
                if s.startswith("carrier:"):
                    carriers[s.split(":", 1)[1].strip().upper()] += 1
        rcs.append({
            "key": g["key"],
            "score": round(sum(_score(f) for f in fs), 4),
            "open": sum(1 for f in fs if _open(f)),
            "n": len(fs),
            "carrier": (carriers.most_common(1)[0][0] if carriers else ""),
            "members": sorted(g["members"]),
            "title": str(fs[0].get("title") or "") if fs else "",
        })
    rcs.sort(key=lambda r: (-r["score"], -r["open"], r["key"]))
    # principal **只能是根因组**（n≥2）且 score>0；单例孤项一律不作主矛盾（fail-loud）
    _principal = next((r for r in rcs if r["n"] > 1 and r["score"] > 0), None)
    orphans = sorted(r["members"][0] for r in rcs if r["n"] == 1)
    return {
        "ok": True,
        "principal": _principal,
        "root_causes": [r for r in rcs if r["n"] > 1],
        "orphans": orphans,
        "stats": {"total": len(merged),
                  "root_causes": sum(1 for r in rcs if r["n"] > 1),
                  "orphans": len(orphans), "tau": tau,
                  "emb_source": emb_path, "emb_vectors": len(emb), "emb_links": emb_links},
    }


def family_view(state_file: str) -> dict:
    """**family 级聚合视图**（只读、确定性、零写盘）。

    输入 = finding ledger **全源合并**（`_entries_by_id` + `_pick_winner`，与 `principal` 同源）；
    按 `family` 分桶（空/缺失 ⟹ `(unassigned)`），每桶给 `total/open/terminal/gap/
    severity_max/status/cover_layers/members`。排序 = open↓ → total↓ → family 字典序。
    """
    from collections import Counter

    merged = {fid: _pick_winner(ents)[2]
              for fid, ents in _entries_by_id(state_file).items()}
    buckets = {}
    for fid, f in merged.items():
        fam = str(f.get("family") or "").strip() or "(unassigned)"
        b = buckets.setdefault(fam, {"total": 0, "open": 0, "terminal": 0, "gap": 0,
                                     "severity_max": 0.0, "status": Counter(),
                                     "cover_layers": set(), "members": []})
        st = str(f.get("status", "open"))
        b["total"] += 1
        b["status"][st] += 1
        if st in _TERMINAL_STATES:
            b["terminal"] += 1
        else:
            b["open"] += 1
        if f.get("gap") is True:
            b["gap"] += 1
        b["severity_max"] = max(b["severity_max"], _finding_severity(f))
        for layer in (f.get("cover_layers") or []):
            s = str(layer).strip()
            if s:
                b["cover_layers"].add(s)
        b["members"].append(fid)

    fams = [{
        "family": fam,
        "total": b["total"],
        "open": b["open"],
        "terminal": b["terminal"],
        "gap": b["gap"],
        "severity_max": round(b["severity_max"], 4),
        "status": dict(sorted(b["status"].items())),
        "cover_layers": sorted(b["cover_layers"]),
        "members": sorted(b["members"]),
    } for fam, b in buckets.items()]
    fams.sort(key=lambda x: (-x["open"], -x["total"], x["family"]))
    return {
        "ok": True,
        "families": fams,
        "stats": {"total": len(merged), "families": len(fams),
                  "open": sum(x["open"] for x in fams),
                  "gap": sum(x["gap"] for x in fams)},
    }


# ══════════ 跨源联邦冲突收敛（元数据中枢·全序列打通②/③ 实现缺口；`ECC-95175BA03B50`）══════════
# 病象（实测 2026-09-28）：`ledger` 报 5 条**同 id 跨源状态冲突** —— 三源（base + 活体域 state +
#   archive）各自可写同一 id，**无单一权威、无裁决** ⟹ 正是「全序列打通②命名族 4→1 / ③单一
#   resolve_state」未落地的直接后果（user 裁「收进元数据中枢」）。
# 本模块补：① 确定性**裁决**（策略见 `_pick_winner`）② 可选**收敛**（把权威状态对齐到所有可写源）
#   ③ **禁多源可写**（`_assert_single_source`：写前置唯一性门，fail-loud）④ 可选**归位**（`--dedupe`
#   **只清真镜像**；代际分歧只报不删）。
# 实测修正（2026-09-28，user 裁「只清真镜像，分歧仅登记 + 写门硬拒」）：
#   · **权威只在可写源内裁** —— 原 `_pick_winner(items)` 连 archive 一起裁，而 archive 只读 ⟹
#     `--dedupe` 会把**基态的活体条目**删掉（127 条 shared 里 102 条是 base↔archive 对）＝数据丢失。
#   · **只删真镜像**（同 id 跨可写源且指纹全等）—— 存量 25 条可写重复**内容并不同**（同 id 不同代际，
#     如 base "9 PROTECTED_REGIONs" vs 域 "1 PROTECTED_REGIONs"）⟹ 按胜者删镜像会丢一代记录。
_TERMINAL_STATES = ("closed", "fixed", "rejected")


def _entries_by_id(state_file: str) -> dict:
    """`{fid: [(path, kind, entry)]}` —— 联邦视图（**只读**；复用 ledger 的三源枚举，不另立第二套）。"""
    out: dict = {}
    for p, _dom, kind in _ledger_sources(state_file):
        for f in _read_findings_source(p, kind):
            fid = f.get("id")
            if fid:
                out.setdefault(fid, []).append((p, kind, f))
    return out


def _assert_single_source(state_file: str, fid: str, op: str) -> None:
    """**禁多源可写**（全序列打通②/③ 本体）：id 级写前置**唯一性门**（fail-loud）。

    若 `fid` 同现于 ≥2 个**可写**源（base/domain；archive 只读不计）⟹ 拒绝 —— 否则「改了一源、
    另一源仍留旧值」的分叉会持续。归位入口 = `finding conflicts --dedupe --apply`（保留胜者那份）。
    """
    srcs = sorted({p for (p, kind, _e) in _entries_by_id(state_file).get(fid, [])
                   if kind != "archive"})
    if len(srcs) > 1:
        raise ValueError(
            "FINDING_MULTI_SOURCE: " + op + " 拒绝写 id " + fid + "（同现于 " + str(len(srcs))
            + " 个可写源，单一权威未定）⟹ 先跑 finding conflicts --dedupe --apply 归位；源="
            + "; ".join(os.path.basename(p) for p in srcs))


def _pick_winner(entries: list):
    """确定性裁决（user 裁「终态优先 + 最近时间 + base 兜底」）。

    排序键 = `(终态, 时间戳, base优先, 路径)` 取**最大**：
      · 终态（closed/fixed/rejected）= 1 > 非终态（open）= 0 —— 已修的结论不被镜像的旧 open 覆盖；
      · 时间戳 = closed_at || verified_at || created_at（空串最小）；
      · 同终态同时间 ⟹ base 优先；仍并列 ⟹ 路径字典序（**确定性**，不依赖遍历顺序）。
    """
    def _key(it):
        _p, kind, e = it
        st = e.get("status", "open")
        term = 1 if st in _TERMINAL_STATES else 0
        ts = e.get("closed_at") or e.get("verified_at") or e.get("created_at") or ""
        return (term, ts, 1 if kind == "base" else 0, _p)
    return max(entries, key=_key)


# 镜像判据（2026-09-28 实测修正）：**只清「真镜像」** —— 同 id 跨可写源且**同内容**（全字段
#   归一后全等）才算重复的副本，可安全删其一。内容不同者 = **不同代际**（实测 title 不同，如
#   base "9 PROTECTED_REGIONs" vs 域 "1 PROTECTED_REGIONs"）⟹ **只报不删**（人工裁决），
#   否则「按胜者删镜像」会**系统性删掉域那份、丢一代记录**（closed_at 已被收敛对齐，最近时间
#   裁决信号退化 ⟹ 胜者恒定取 base）。`last_modified` 是 upsert/merge 的易变字段，不计入镜像。
_MIRROR_IGNORE_FIELDS = ("last_modified",)


def _mirror_fingerprint(e: dict) -> str:
    """条目的**镜像指纹**（全字段归一；剔除易变字段）。"""
    return json.dumps({k: v for k, v in e.items() if k not in _MIRROR_IGNORE_FIELDS},
                      sort_keys=True, ensure_ascii=False)


def _writable_is_mirror(writable: list) -> bool:
    """≥2 个可写源持有同 id 且**指纹全等**（真镜像）⟹ 可删镜像；否则 = 代际分歧（只报不删）。"""
    return len(writable) >= 2 and len({_mirror_fingerprint(e) for (_p, _k, e) in writable}) == 1


def _align_terminal(e: dict, w_e: dict) -> None:
    """终态闭合元数据对齐（2026-10-08）：把 `e` 对齐到权威 `w_e`，并**保证合规**。

    病象：`conflicts --converge --apply` 原只写 `status`/`closed_at`/`verify_source`，**不写
    `basis_ref`** ⟹ 目标源若原为 `open` 会被对齐成**「无据关闭」**（monitor `ecc_form` 判据 9
    `bad_close` FAIL）——即 converge 自己制造不合规终态。
    修法：①补写 `basis_ref`（胜者有则用胜者，否则回落该条 `evidence_hash`）；②若对齐后仍不合规
    （`basis_ref` 空 **或** `verify_source` 的 `;` 分段 kind 不全在 `_VERIFY_SOURCES` 白名单、
    或 ∈ {"", "manual"}）则回落 `register-only`（c9 的显式「仅登记」出口）。
    """
    if w_e.get("closed_at"):
        e["closed_at"] = w_e["closed_at"]
    if w_e.get("verify_source"):
        e["verify_source"] = w_e["verify_source"]
    if w_e.get("basis_ref"):
        e["basis_ref"] = w_e["basis_ref"]
    elif not (e.get("basis_ref") or ""):
        e["basis_ref"] = e.get("evidence_hash") or w_e.get("evidence_hash") or ""
    _vsrc = e.get("verify_source") or ""
    if _vsrc != "register-only":
        _kinds = [p.strip().split(":", 1)[0].strip().lower()
                  for p in _vsrc.split(";") if p.strip()]
        _vs_ok = bool(_vsrc) and _vsrc != "manual" and all(k in _VERIFY_SOURCES for k in _kinds)
        if not (e.get("basis_ref") or "") or not _vs_ok:
            e["verify_source"] = "register-only"


def conflicts(state_file: str, converge: bool = False, apply: bool = False,
              dedupe: bool = False, ack: bool = False) -> dict:
    """跨源**重复/冲突**视图 + 可选**归位**（单一权威 = 全序列打通②/③ 本体）。

    覆盖面 = `ledger.shared_ids`（同 id 同现于 ≥2 源者，**含同态重复与 base↔archive 对**），
    非仅状态不一致者。每条附 `kind` ∈ {mirror, divergent, archive-only}：
      · `mirror` = ≥2 个**可写**源持有且**指纹全等**（真镜像，可安全删镜像）；
      · `divergent` = ≥2 个可写源但内容不同（**不同代际** ⟹ 只报不删，人工裁决）；
      · `archive-only` = 除 archive 外仅 1 个可写源（archive 只读，**不构成可写重复**）。

    - 默认：只报（每条附 `conflict` 标志 + `by_source` + `winner` + `kind`）。
    - `converge=True`：按 `_pick_winner`（**只在可写源内**裁，archive 不得当选）算权威，报拟动
      （**dry-run，零写盘**）。
    - `apply=True`（须与 `converge` 同用）：
        · `dedupe=False` ⟹ **对齐**：把权威 `status`（+ 终态的 `closed_at`/`verify_source`）写进每个
          持有该 id 的**可写**源；archive 只读。
        · `dedupe=True` ⟹ **只清「真镜像」**（`kind=mirror`）：保留**胜者**那份，其余可写源的同 id
          条目**移除**（journal 记全量快照 ⟹ 可回溯/可复原）。**分歧（divergent）只报不删** ——
          实测同 id 跨源内容不同（如 base "9 PROTECTED_REGIONs" vs 域 "1 …"）⟹ 删镜像会丢一代记录。
          **不会回退**（胜者 = 终态优先，已 close 不被旧 open 覆盖）。
    **幂等**：无改动 ⟹ 不写（`converged`/`deduped` 只计真改动）。

    ⚠ **闸粒度边界（§9-7 方案 B，2026-10-07）**：写闸只按**读面 `shared_ids`** 过滤（`converge and apply`
    时对 `shared_ids` 全集合跑一次 `_guard_precheck`）；**不**逐可写源复检 —— 若某源里同 id 的标题锚
    漂移而异于读面判据，闸可能不覆盖（**显式声明的已知边界**）。archive 只读，不在写面。
    """
    ents = _entries_by_id(state_file)
    led = ledger(state_file)
    if converge and apply:
        # 处置前强制回环闸（Plan-2 / ECC-6E2F2261410D）：`conflicts` **不属只读**（`--apply` 会写
        #   多源）⟹ 与其余写面同门；只对**将要动的 fid**（= `shared_ids` 全集）过滤，禁全台账扫。
        #   dry-run（未 `--apply`）零写盘 ⟹ 不设闸（只读面不设闸，与 `ledger`/`status` 同）。
        _guard_precheck(state_file, list(led.get("shared_ids", [])), ack=ack)
    out = {"ok": True, "conflicts": [], "converged": 0, "deduped": 0, "applied": bool(apply),
           "policy": "terminal-first+recency+base-tiebreak" + ("+dedupe" if dedupe else "")}
    for fid in led.get("shared_ids", []):
        items = ents.get(fid, [])
        if len(items) < 2:
            continue
        writable = [(p, k, e) for (p, k, e) in items if k != "archive"]
        by_source = {_src_key(p, state_file): e.get("status", "open") for p, _k, e in items}
        # 权威**只在可写源内**裁（archive 只读，不得当选）—— 2026-09-28 实测：base↔archive 对
        #   若让 archive 当选，`--dedupe` 会把 base 那份删掉（数据丢失）。
        w = _pick_winner(writable) if writable else _pick_winner(items)
        w_e, w_st = w[2], w[2].get("status", "open")
        mirror = _writable_is_mirror(writable)
        actions = [{"source": p, "kind": k, "from": e.get("status", "open"), "to": w_st}
                   for (p, k, e) in writable if e.get("status", "open") != w_st]
        out["conflicts"].append({
            "id": fid, "conflict": len(set(by_source.values())) > 1, "by_source": by_source,
            "winner": {"status": w_st, "source": w[0]}, "actions": actions, "mirror": mirror,
            "kind": ("mirror" if mirror else "divergent") if len(writable) > 1 else "archive-only"})
        if not (converge and apply):
            continue
        if dedupe and mirror:                     # 只清「真镜像」；代际分歧只报不删（人工裁决）
            for p, k, e in writable:
                if (p, k) == (w[0], w[1]):
                    continue                     # 保留唯一权威（胜者那份）
                fs = load_findings(p)
                fs[:] = [x for x in fs if x.get("id") != fid]
                save_findings(p, fs)
                _write_checksum(p)
                _append_journal(p, {"ts": _now(), "event": "conflict_dedupe", "fid": fid,
                                    "kept": w[0], "removed_entry": e,
                                    "policy": "keep-winner-remove-mirrors"})
                out["deduped"] += 1
        elif actions:
            for act in actions:
                p = act["source"]
                fs = load_findings(p)
                for e in fs:
                    if e.get("id") == fid:
                        e["status"] = w_st
                        if w_st in _TERMINAL_STATES:
                            _align_terminal(e, w_e)
                save_findings(p, fs)
                _write_checksum(p)
                _append_journal(p, {"ts": _now(), "event": "conflict_converge", "fid": fid,
                                    "from": act["from"], "to": w_st, "authority": w[0],
                                    "policy": "terminal-first+recency+base-tiebreak"})
                out["converged"] += 1
        if converge and apply and w_st in _TERMINAL_STATES and not (dedupe and mirror):
            # 一致性**修复**（2026-10-08）：状态已对齐但目标源闭合**不合规**（缺 `basis_ref` 或
            #   `verify_source` kind 非白名单）⟹ 补写（幂等）—— 让被旧版 converge 对齐出的
            #   「无据关闭」**自愈**（`_align_terminal` 只写终态元数据，不改业务字段）。
            for p, k, e in writable:
                if e.get("status") != w_st:
                    continue
                _probe = dict(e)
                _align_terminal(_probe, w_e)
                if _probe == e:
                    continue
                fs = load_findings(p)
                for x in fs:
                    if x.get("id") == fid:
                        _align_terminal(x, w_e)
                save_findings(p, fs)
                _write_checksum(p)
                _append_journal(p, {"ts": _now(), "event": "conflict_converge_repair",
                                    "fid": fid, "target": p,
                                    "policy": "terminal-basis-ref-repair"})
                out["converged"] += 1
    return out


def writable_duplicates(state_file: str) -> list:
    """同 id 同现于 ≥2 个**可写**源（base/domain；archive 只读不计）的 id 列表（只读）。

    = 单一权威不变量（全序列打通②/③）的**可观测面**（含真镜像与代际分歧）。归位入口 =
    `finding conflicts --dedupe --apply`（只清真镜像；分歧只报不删，人工裁决）。
    """
    return sorted(fid for fid, items in _entries_by_id(state_file).items()
                  if len({_p for (_p, k, _e) in items if k != "archive"}) > 1)


def writable_mirrors(state_file: str) -> list:
    """同 id 同现于 ≥2 个**可写**源且**指纹全等**（真镜像）的 id 列表（只读）。

    = 单一权威不变量（全序列打通②/③）的**机检判据**（硬门禁）；`--dedupe --apply` 应清空它。
    内容不同的「代际分歧」**不**入此列（它们须人工裁决，见 `conflicts` 的 `kind=divergent`）。
    """
    out = []
    for fid, items in _entries_by_id(state_file).items():
        if _writable_is_mirror([it for it in items if it[1] != "archive"]):
            out.append(fid)
    return sorted(out)


def main(argv=None):
    """CLI 入口。子命令统一解析：位置参数 + --flag；缺参/未知参数 → 显式 usage 错误（不静默）。"""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print(json.dumps({"error": _usage_error("")}))
        sys.exit(1)
    cmd, state_file = args[0], args[1]
    # `--ack-drift`（处置前回环闸的**显式放行**）：**单一咽喉点**解析 —— 凡命中即从 argv 摘除
    #   （六写面各自的「未知参数」解析器不再撞门：verify/close/reopen/amend-title/conflicts/
    #   archive-closed），并**显式透传** `ack=<flag>` 到六个 dispatch（§2.4-d「六分支透传 ack=True」）。
    #   ⛔ **不**经由 env：进程内不复位会令后续**无** `--ack-drift` 的调用被过放行（Plan-2 修正）。
    #   放行留痕 = journal `precheck_ack`（见 `_guard_precheck`）。
    ack_drift = "--ack-drift" in args
    if ack_drift:
        args = [a for a in args if a != "--ack-drift"]
    domain = None  # None=未声明域；''=声明了但空值（→ 拒绝，不静默回退）
    try:
        if cmd == "register":
            title, source = "", "manual"
            family, cover_layers, gap = "", None, None
            title_file, source_file = "", ""
            root_key, closure_oracle = "", ""
            source_note, from_report = "", ""
            merge_into, dup_ack = "", ""
            repo_tok = ""
            anchors, facets = [], []
            pos = []
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--title-file":
                    if i + 1 >= len(rest):
                        raise ValueError("--title-file 缺值（" + _usage_error("register") + "）")
                    title_file, i = rest[i + 1], i + 2
                elif a == "--source-file":
                    if i + 1 >= len(rest):
                        raise ValueError("--source-file 缺值（" + _usage_error("register") + "）")
                    source_file, i = rest[i + 1], i + 2
                elif a == "--family":
                    if i + 1 >= len(rest):
                        raise ValueError("--family 缺值（" + _usage_error("register") + "）")
                    family, i = rest[i + 1], i + 2
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("register") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a == "--cover-layers":
                    if i + 1 >= len(rest):
                        raise ValueError("--cover-layers 缺值（" + _usage_error("register") + "）")
                    cover_layers, i = rest[i + 1], i + 2
                elif a == "--root-key":
                    if i + 1 >= len(rest):
                        raise ValueError("--root-key 缺值（" + _usage_error("register") + "）")
                    root_key, i = rest[i + 1], i + 2
                elif a == "--anchor":
                    if i + 1 >= len(rest):
                        raise ValueError("--anchor 缺值（" + _usage_error("register") + "）")
                    anchors.append(rest[i + 1])
                    i += 2
                elif a == "--facet":
                    if i + 1 >= len(rest):
                        raise ValueError("--facet 缺值（" + _usage_error("register") + "）")
                    facets.append(rest[i + 1])
                    i += 2
                elif a == "--closure-oracle":
                    if i + 1 >= len(rest):
                        raise ValueError("--closure-oracle 缺值（" + _usage_error("register") + "）")
                    closure_oracle, i = rest[i + 1], i + 2
                elif a == "--gap":
                    if i + 1 >= len(rest):
                        raise ValueError("--gap 缺值（" + _usage_error("register") + "）")
                    gap, i = _parse_bool(rest[i + 1], "--gap"), i + 2
                elif a == "--from-report":
                    if i + 1 >= len(rest):
                        raise ValueError("--from-report 缺值（" + _usage_error("register") + "）")
                    from_report, i = rest[i + 1], i + 2
                elif a == "--merge-into":
                    if i + 1 >= len(rest):
                        raise ValueError("--merge-into 缺值（" + _usage_error("register") + "）")
                    merge_into, i = rest[i + 1], i + 2
                elif a == "--dup-ack":
                    if i + 1 >= len(rest):
                        raise ValueError("--dup-ack 缺值（" + _usage_error("register") + "）")
                    dup_ack, i = rest[i + 1], i + 2
                elif a == "--repo":
                    if i + 1 >= len(rest):
                        raise ValueError("--repo 缺值（" + _usage_error("register") + "）")
                    repo_tok, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"未知参数 {a}（" + _usage_error("register") + "）")
                else:
                    pos.append(a)
                    i += 1
            if len(pos) > 2:
                raise ValueError("register 位置参数过多（" + _usage_error("register") + "）")
            # 文件通道与**同槽位**位置参数互斥（防「既给文件又给位置」时静默取其一）
            if title_file and pos:
                raise ValueError("--title-file 与位置参数 <title> 互斥（给了文件就不要再给位置标题）（"
                                 + _usage_error("register") + "）")
            # 2026-09-28：`--source-file` **不再**与位置 `[source]` 互斥 —— 两者语义已分离
            #   （`source` = 短 token；`--source-file` = 长文本出处 ⟹ `source_note`）。
            if title_file:
                title = _read_payload_file(title_file, "--title-file")
            elif pos:
                title = pos[0]
            if len(pos) > 1:
                source = pos[1]
            if source_file:
                # 长文本出处 → `source_note`（**不**再污染 `source` token；见 ecc-write-spec.md）
                source_note = _read_payload_file(source_file, "--source-file")
                if not source_note:
                    raise ValueError("--source-file 内容为空（传了空文件；请写非空出处文本或去掉该参数）（"
                                     + _usage_error("register") + "）")
            if from_report:
                # 显式**提升**通道：只抽允许字段；`source` 固定 `subagent-promoted`
                rep = _load_report_payload(from_report)
                title = title or rep.get("title", "")
                family = family or rep.get("family", "")
                anchors = list(anchors) + list(rep.get("anchors", []))
                facets = list(facets) + list(rep.get("facets", []))
                root_key = root_key or rep.get("root_key", "")
                closure_oracle = closure_oracle or rep.get("closure_oracle", "")
                if not cover_layers and rep.get("cover_layers"):
                    cover_layers = ",".join(rep["cover_layers"]) \
                        if isinstance(rep["cover_layers"], list) else rep["cover_layers"]
                source = _FROM_REPORT_SOURCE if source in ("", _DEFAULT_SOURCE) else source
                source_note = source_note or rep.get("_note", "")
            if not title:
                raise ValueError("register 缺 title（" + _usage_error("register") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = register(state_file, title, source,
                           family=family, cover_layers=cover_layers, gap=gap,
                           root_key=root_key, anchors=anchors, facets=facets,
                           closure_oracle=closure_oracle, source_note=source_note,
                           repo_token=repo_tok,
                           ack=ack_drift, route_hard=True,
                           merge_into=merge_into, dup_ack=dup_ack)
        elif cmd == "check":
            # 只读写前检查面（`ECC-43C982F794B8`）：报命中既有 finding + 跨域重复；零写盘。
            ck_title, ck_root, ck_anchors = "", "", []
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a in ("--title", "--root-key", "--anchors", "--domain"):
                    if i + 1 >= len(rest):
                        raise ValueError(a + " 缺值（" + _usage_error("check") + "）")
                    if a == "--title":
                        ck_title = rest[i + 1]
                    elif a == "--root-key":
                        ck_root = rest[i + 1]
                    elif a == "--anchors":
                        ck_anchors = [x for x in rest[i + 1].split(",") if x.strip()]
                    else:
                        domain = rest[i + 1]
                    i += 2
                else:
                    raise ValueError("未知参数 %r（%s）" % (a, _usage_error("check")))
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = check(state_file, title=ck_title, root_key=ck_root, anchors=ck_anchors)
        elif cmd == "dup-check":
            # OSS 前置计划 §2.3-A（2026-10-26）：写前「同类同族」候选的**只读** CLI 面。
            #   单一源 = `dup_candidates`（禁第二实现）；零写盘（连 journal 都不写）。
            dc_title, dc_family, dc_excl = "", "", ""
            dc_anchors, dc_facets = [], []
            dc_tau, dc_limit = _DUP_TAU, 5
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a in ("--family", "--domain", "--exclude-id", "--tau", "--limit"):
                    if i + 1 >= len(rest):
                        raise ValueError(a + " 缺值（" + _usage_error("dup-check") + "）")
                    if a == "--family":
                        dc_family = rest[i + 1]
                    elif a == "--exclude-id":
                        dc_excl = rest[i + 1]
                    elif a == "--tau":
                        dc_tau = float(rest[i + 1])
                    elif a == "--limit":
                        dc_limit = _int_arg(rest[i + 1], "--limit")
                    else:
                        domain = rest[i + 1]
                    i += 2
                elif a in ("--anchor", "--facet"):
                    if i + 1 >= len(rest):
                        raise ValueError(a + " 缺值（" + _usage_error("dup-check") + "）")
                    (dc_anchors if a == "--anchor" else dc_facets).append(rest[i + 1])
                    i += 2
                elif a.startswith("--"):
                    raise ValueError("未知参数 %r（%s）" % (a, _usage_error("dup-check")))
                else:
                    if dc_title:
                        raise ValueError("dup-check 位置参数过多（" + _usage_error("dup-check") + "）")
                    dc_title, i = a, i + 1
            if not dc_title:
                raise ValueError("dup-check 缺 title（" + _usage_error("dup-check") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = dup_candidates(state_file, dc_title, dc_family, dc_anchors, dc_facets,
                                 tau=dc_tau, limit=dc_limit, exclude_id=dc_excl)
        elif cmd == "precheck":
            # T6（2026-10-15，ECC-AC7004852D8C）：**下发点回环预检**只读暴露面 —— 供 CLI
            #   `apply-worktree --code-fix`（coder 派发入口）在族判定/建 worktree **之前**调用。
            #   判据单一源 = `_guard_precheck`（禁第二实现）；`_scan_drift` 仅取结构化明细
            #   （同一判决引擎，只读）。`ack` 恒 False ⟹ 预检**不设放行口**（逃生舱 = env
            #   `GK_FINDING_PRECHECK=0`）。命中 ⟹ rc=1 + `ECC_PRECHECK_DRIFT` + drift 明细。
            pc_fid = ""
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("precheck") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"precheck 不支持参数 {a}（" + _usage_error("precheck") + "）")
                else:
                    pc_fid, i = a, i + 1
            if not pc_fid:
                raise ValueError("precheck 需要 <fid>（" + _usage_error("precheck") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            try:
                _guard_precheck(state_file, [pc_fid], ack=False)
            except ValueError:
                print(json.dumps({"ok": False, "error": "ECC_PRECHECK_DRIFT",
                                  "finding": pc_fid,
                                  "drift": _scan_drift(state_file, [pc_fid])},
                                 ensure_ascii=False))
                sys.exit(1)
            out = {"ok": True, "finding": pc_fid}
        elif cmd == "verify":
            pos, vsrc = [], ""
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("verify") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a == "--verify-source":
                    if i + 1 >= len(rest):
                        raise ValueError("--verify-source 缺值（" + _usage_error("verify") + "）")
                    vsrc, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"verify 不支持参数 {a}（" + _usage_error("verify") + "）")
                else:
                    pos.append(a)
                    i += 1
            if len(pos) < 2:
                raise ValueError("verify 需要 <id> <true|false>（" + _usage_error("verify") + "）")
            if len(pos) > 2:
                raise ValueError("verify 位置参数过多（" + _usage_error("verify") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = verify(state_file, pos[0], _parse_bool(pos[1], "ok"),
                         verify_source=vsrc, ack=ack_drift)
        elif cmd == "close":
            pos, vsrc, accept_ack = [], "", None
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--verify-source":
                    if i + 1 >= len(rest):
                        raise ValueError("--verify-source 缺值（" + _usage_error("close") + "）")
                    vsrc, i = rest[i + 1], i + 2
                elif a == "--ack-accept":
                    accept_ack = True
                    i += 1
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("close") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"未知参数 {a}（" + _usage_error("close") + "）")
                else:
                    pos.append(a)
                    i += 1
            if not pos:
                raise ValueError("close 需要 <id>（" + _usage_error("close") + "）")
            if len(pos) > 2:
                raise ValueError("close 位置参数过多（" + _usage_error("close") + "）")
            fid = pos[0]
            if len(pos) == 2:
                vsrc = pos[1]  # 向后兼容：finding close <id> <verify_source>
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = close(state_file, fid, vsrc or "manual", ack=ack_drift,
                        accept_hard=True, accept_ack=accept_ack)
        elif cmd == "reopen":
            pos, reason = [], ""
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--reason":
                    if i + 1 >= len(rest):
                        raise ValueError("--reason 缺值（" + _usage_error("reopen") + "）")
                    reason, i = rest[i + 1], i + 2
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("reopen") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"未知参数 {a}（" + _usage_error("reopen") + "）")
                else:
                    pos.append(a)
                    i += 1
            if not pos:
                raise ValueError("reopen 需要 <id>（" + _usage_error("reopen") + "）")
            if len(pos) > 2:
                raise ValueError("reopen 位置参数过多（" + _usage_error("reopen") + "）")
            fid = pos[0]
            if len(pos) == 2:
                reason = pos[1]  # 向后兼容：finding reopen <id> <reason>
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = reopen(state_file, fid, reason, ack=ack_drift)
        elif cmd in ("release-approve", "release-reject"):
            pos, by, note, div, final, decl = [], "", "", None, False, False
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a in ("--by", "--note", "--divergence"):
                    if i + 1 >= len(rest):
                        raise ValueError(a + " 缺值（" + _usage_error(cmd) + "）")
                    if a == "--by":
                        by, i = rest[i + 1], i + 2
                    elif a == "--note":
                        note, i = rest[i + 1], i + 2
                    else:
                        try:
                            div = float(rest[i + 1])
                        except (TypeError, ValueError):
                            raise ValueError("--divergence 需浮点（得到 %r）" % rest[i + 1])
                        i += 2
                elif a == "--final-ruling":
                    final, i = True, i + 1
                elif a == "--declassify":
                    decl, i = True, i + 1
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error(cmd) + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"{cmd} 不支持参数 {a}（" + _usage_error(cmd) + "）")
                else:
                    pos.append(a)
                    i += 1
            if not pos:
                raise ValueError(cmd + " 需要 <id>（" + _usage_error(cmd) + "）")
            if len(pos) > 1:
                raise ValueError(cmd + " 位置参数过多（" + _usage_error(cmd) + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = set_release_state(
                state_file, pos[0],
                "release_approved" if cmd == "release-approve" else "release_rejected",
                by=by, note=note, divergence=div, final_ruling=final, declassify=decl)
        elif cmd == "declassify":
            pos, by, note = [], "", ""
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a in ("--by", "--note"):
                    if i + 1 >= len(rest):
                        raise ValueError(a + " 缺值（" + _usage_error("declassify") + "）")
                    if a == "--by":
                        by, i = rest[i + 1], i + 2
                    else:
                        note, i = rest[i + 1], i + 2
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("declassify") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"declassify 不支持参数 {a}（" + _usage_error("declassify") + "）")
                else:
                    pos.append(a)
                    i += 1
            if not pos:
                raise ValueError("declassify 需要 <id>（" + _usage_error("declassify") + "）")
            if len(pos) > 1:
                raise ValueError("declassify 位置参数过多（" + _usage_error("declassify") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = declassify(state_file, pos[0], by=by, note=note)
        elif cmd == "amend-title":
            pos, suffix, note = [], "", ""
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a in ("--suffix", "--note"):
                    if i + 1 >= len(rest):
                        raise ValueError(a + " 缺值（" + _usage_error("amend-title") + "）")
                    if a == "--suffix":
                        suffix, i = rest[i + 1], i + 2
                    else:
                        note, i = rest[i + 1], i + 2
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("amend-title") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"未知参数 {a}（" + _usage_error("amend-title") + "）")
                else:
                    pos.append(a)
                    i += 1
            if not pos:
                raise ValueError("amend-title 需要 <id>（" + _usage_error("amend-title") + "）")
            if len(pos) > 1:
                raise ValueError("amend-title 位置参数过多（" + _usage_error("amend-title") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = amend_title(state_file, pos[0], suffix, note, ack=ack_drift)
        elif cmd == "anchor-drift":
            # 形态 A（2026-10-03）：标题行锚漂移**只读**扫描（amend-title 检测端）。
            repo, rest = "", args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--repo":
                    if i + 1 >= len(rest):
                        raise ValueError("--repo 缺值（" + _usage_error("anchor-drift") + "）")
                    repo, i = rest[i + 1], i + 2
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("anchor-drift") + "）")
                    domain, i = rest[i + 1], i + 2
                else:
                    raise ValueError(f"anchor-drift 不支持参数 {a}（" + _usage_error("anchor-drift") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = scan_title_anchors(state_file, repo)
        elif cmd == "amend-anchors":
            # 形态 B（2026-10-03）：标题重钉**执行端**（append-only；--apply 才写）。
            mapping, apply, note, rest = {}, False, "", args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--map":
                    if i + 1 >= len(rest):
                        raise ValueError("--map 缺值（" + _usage_error("amend-anchors") + "）")
                    for kv in rest[i + 1].split(","):
                        if not kv.strip():
                            continue
                        if "=" not in kv:
                            raise ValueError(f"--map 项缺 =（{kv!r}）")
                        k, v = kv.split("=", 1)
                        mapping[k.strip()] = v.strip()
                    i += 2
                elif a == "--apply":
                    apply, i = True, i + 1
                elif a == "--note":
                    if i + 1 >= len(rest):
                        raise ValueError("--note 缺值（" + _usage_error("amend-anchors") + "）")
                    note, i = rest[i + 1], i + 2
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("amend-anchors") + "）")
                    domain, i = rest[i + 1], i + 2
                else:
                    raise ValueError(f"amend-anchors 不支持参数 {a}（" + _usage_error("amend-anchors") + "）")
            if not mapping:
                raise ValueError("amend-anchors 需要 --map <old=new,...>（" + _usage_error("amend-anchors") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = amend_anchors(state_file, mapping, apply, note)
        elif cmd == "stale":
            # 台账时效巡检（2026-11-01）：TTL 超期 → 标 stale；锚文件被 diff 触及 → reopen。
            #   默认**只报不写**（安全网形态，同 `spillover_open`）；`--apply` 才落盘。
            st_ttl, st_apply, st_now = 14, False, ""
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a in ("--ttl-days", "--now", "--domain"):
                    if i + 1 >= len(rest):
                        raise ValueError(a + " 缺值（" + _usage_error("stale") + "）")
                    if a == "--ttl-days":
                        st_ttl = _int_arg(rest[i + 1], "--ttl-days")
                    elif a == "--now":
                        st_now = rest[i + 1]
                    else:
                        domain = rest[i + 1]
                    i += 2
                elif a == "--apply":
                    st_apply, i = True, i + 1
                else:
                    raise ValueError(f"stale 不支持参数 {a}（" + _usage_error("stale") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = stale_scan(state_file, st_ttl, apply=st_apply, now_ts=st_now)
        elif cmd == "status":
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("status") + "）")
                    domain, i = rest[i + 1], i + 2
                else:
                    raise ValueError(f"status 不支持参数 {a}（" + _usage_error("status") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = status(state_file)
            # §17-1③（2026-10-03）：只读双形态检测 —— 同计划两形态域 state 并存 ⟹ 非静默告警
            #   （挂在既有 status 输出的 `dual_form` 字段，**不新增子命令** ⟹ _CMD_REG 条数不变）。
            if isinstance(out, dict):
                out["dual_form"] = dual_form_domains(state_file)
                # §G2（2026-10-03）：跨域重复登记（同 root_key 跨源）只读检测（非静默）。
                out["cross_domain_dup"] = cross_domain_dups(state_file)
                # 2026-11-01：跨仓索引（**只读现算**，不依赖落盘投影是否最新；不写盘）。
                out["repo_index"] = _project_repo_index(load_findings_union(state_file))
        elif cmd == "journal-verify":
            # C 接线（2026-10-16，owner 裁定「事件级签名 + 哈希链」）：只读验链 + 验签（不新增 _CMD_REG）。
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("journal-verify") + "）")
                    domain, i = rest[i + 1], i + 2
                else:
                    raise ValueError(f"journal-verify 不支持参数 {a}（"
                                     + _usage_error("journal-verify") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = verify_journal(state_file)
        elif cmd == "prune-duplicates":
            # 存量同 id 重复清理（保留首条 + journal 留痕）—— 补 `upsert_red_findings`
            # docstring「清理须显式授权，本函数不删」留下的清理缺口；`--domain` 可指定域化 state。
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("prune-duplicates") + "）")
                    domain, i = rest[i + 1], i + 2
                else:
                    raise ValueError("prune-duplicates 不支持参数 " + a
                                     + "（" + _usage_error("prune-duplicates") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = prune_duplicates(state_file)
        elif cmd == "archive-closed":
            # `ecc_findings` 配额驱动的代数归档（L2）—— 只动 closed；移出项走旁挂 + epoch 声明。
            rest = args[2:]
            i = 0
            target, keep_closed, dry = 0, 0, False
            while i < len(rest):
                a = rest[i]
                if a == "--target-total":
                    if i + 1 >= len(rest):
                        raise ValueError("--target-total 缺值（" + _usage_error("archive-closed") + "）")
                    target, i = _int_arg(rest[i + 1], "--target-total"), i + 2
                elif a == "--keep-closed":
                    if i + 1 >= len(rest):
                        raise ValueError("--keep-closed 缺值（" + _usage_error("archive-closed") + "）")
                    keep_closed, i = _int_arg(rest[i + 1], "--keep-closed"), i + 2
                elif a == "--dry-run":
                    dry, i = True, i + 1
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("archive-closed") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"未知参数 {a}（" + _usage_error("archive-closed") + "）")
                else:
                    raise ValueError("archive-closed 不支持位置参数（"
                                     + _usage_error("archive-closed") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = archive_closed(state_file, target_total=target,
                                 keep_closed=keep_closed, dry_run=dry)
        elif cmd == "epoch":
            ts, reason, purged = "", "", None
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--ts":
                    if i + 1 >= len(rest):
                        raise ValueError("--ts 缺值（" + _usage_error("epoch") + "）")
                    ts, i = rest[i + 1], i + 2
                elif a == "--reason":
                    if i + 1 >= len(rest):
                        raise ValueError("--reason 缺值（" + _usage_error("epoch") + "）")
                    reason, i = rest[i + 1], i + 2
                elif a == "--purged":
                    if i + 1 >= len(rest):
                        raise ValueError("--purged 缺值（" + _usage_error("epoch") + "）")
                    # 逗号分隔 fid 列表（F7：显式声明出域/清洗）
                    purged = [x.strip() for x in rest[i + 1].split(",") if x.strip()]
                    i += 2
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("epoch") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"未知参数 {a}（" + _usage_error("epoch") + "）")
                else:
                    raise ValueError("epoch 不支持位置参数（" + _usage_error("epoch") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = epoch(state_file, ts, reason, purged_fids=purged)
        elif cmd == "reconcile":
            rest = args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("reconcile") + "）")
                    domain, i = rest[i + 1], i + 2
                else:
                    raise ValueError(f"reconcile 不支持参数 {a}（" + _usage_error("reconcile") + "）")
            # §18.2 判据 c3（2026-10-04）：declared-but-unresolved（指针 stale/dangling）⟹
            #   禁静默读 base；显式报错并停止（对齐既有 failure path 的 sys.exit(1)）。
            from gk_state_route import read_point_pointer_error
            _rp_err = read_point_pointer_error()
            if _rp_err:
                print(json.dumps(_rp_err, ensure_ascii=False))
                sys.exit(1)
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = reconcile(state_file)
        elif cmd == "ledger":
            # RC3′（只读）：三源枚举 + 可选「本计划应落哪套 state」单点判定（零写盘）。
            rest, plan = args[2:], ""
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--plan":
                    if i + 1 >= len(rest):
                        raise ValueError("--plan 缺值（" + _usage_error("ledger") + "）")
                    plan, i = rest[i + 1], i + 2
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("ledger") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"ledger 不支持参数 {a}（" + _usage_error("ledger") + "）")
                else:
                    raise ValueError("ledger 不支持位置参数（" + _usage_error("ledger") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = ledger(state_file, plan_file=plan)
        elif cmd == "family":
            # family 级聚合视图（只读，零写盘）：红队 finding 按缺陷族聚账。
            rest, domain = args[2:], None
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("family") + "）")
                    domain, i = rest[i + 1], i + 2
                else:
                    raise ValueError(f"family 不支持参数 {a}（" + _usage_error("family") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = family_view(state_file)
        elif cmd == "conflicts":
            # 跨源联邦冲突收敛（`ECC-95175BA03B50`）：默认只报；--converge 算权威（dry-run）；
            # --apply 才把权威对齐到所有可写源（幂等）。
            rest, converge, apply = args[2:], False, False
            dedupe = False
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--converge":
                    converge, i = True, i + 1
                elif a == "--apply":
                    apply, i = True, i + 1
                elif a == "--dedupe":
                    dedupe, i = True, i + 1
                elif a.startswith("--"):
                    raise ValueError(f"conflicts 不支持参数 {a}（" + _usage_error("conflicts") + "）")
                else:
                    raise ValueError("conflicts 不支持位置参数（" + _usage_error("conflicts") + "）")
            if apply and not converge:
                raise ValueError("--apply 须与 --converge 同用（" + _usage_error("conflicts") + "）")
            out = conflicts(state_file, converge=converge, apply=apply, dedupe=dedupe,
                            ack=ack_drift)
        elif cmd == "embed":
            # 离线嵌入 producer（`ECC-FAF2A8F0A0DF` ③-A）：委托 gk_finding_embed（保持 CLI
            #   统一入口，不裸跑 scripts/gk_*.py）。读台账 (id,title) → 本地 bge 嵌入 → 写旁挂契约。
            import gk_finding_embed
            emodel, eout, edry, efrom, rest = "", "", False, "", args[2:]
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--model" and i + 1 < len(rest):
                    emodel, i = rest[i + 1], i + 2
                elif a == "--out" and i + 1 < len(rest):
                    eout, i = rest[i + 1], i + 2
                elif a == "--from-vectors" and i + 1 < len(rest):
                    efrom, i = rest[i + 1], i + 2
                elif a == "--dry-run":
                    edry, i = True, i + 1
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("embed") + "）")
                    domain, i = rest[i + 1], i + 2
                else:
                    raise ValueError(f"embed 不支持参数 {a}（" + _usage_error("embed") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = gk_finding_embed.run(state_file, model=emodel or None, out=eout, dry=edry,
                                       from_vectors=efrom)
        elif cmd == "principal":
            # 台账级主要矛盾提取器（`ECC-02710BDFAC8E`）：只读；全源合并 → root_key/锚集聚类 →
            #   open×severity 排序 → principal 恰 1 + RC 溶解清单 + 未归并孤项。
            rest, plan, tau, emb_file, emb_tau = args[2:], "", 0.6, None, _EMB_TAU_DEFAULT
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--plan":
                    if i + 1 >= len(rest):
                        raise ValueError("--plan 缺值（" + _usage_error("principal") + "）")
                    plan, i = rest[i + 1], i + 2
                elif a == "--tau":
                    if i + 1 >= len(rest):
                        raise ValueError("--tau 缺值（" + _usage_error("principal") + "）")
                    tau, i = float(rest[i + 1]), i + 2
                elif a == "--embeddings":
                    if i + 1 >= len(rest):
                        raise ValueError("--embeddings 缺值（" + _usage_error("principal") + "）")
                    emb_file, i = rest[i + 1], i + 2
                elif a == "--emb-tau":
                    if i + 1 >= len(rest):
                        raise ValueError("--emb-tau 缺值（" + _usage_error("principal") + "）")
                    emb_tau, i = float(rest[i + 1]), i + 2
                elif a == "--no-embeddings":
                    emb_file, i = "", i + 1
                elif a == "--domain":
                    if i + 1 >= len(rest):
                        raise ValueError("--domain 缺值（" + _usage_error("principal") + "）")
                    domain, i = rest[i + 1], i + 2
                elif a.startswith("--"):
                    raise ValueError(f"principal 不支持参数 {a}（" + _usage_error("principal") + "）")
                else:
                    raise ValueError("principal 不支持位置参数（" + _usage_error("principal") + "）")
            if domain is not None:
                state_file = resolve_domain_state(state_file, domain)
            out = principal(state_file, plan_file=plan, tau=tau,
                            embeddings_file=emb_file, emb_tau=emb_tau)
        else:
            raise ValueError(f"unknown cmd {cmd}（" + _usage_error(cmd) + "）")
        result = out if cmd in ("reconcile", "epoch", "ledger", "family", "conflicts", "principal", "embed", "check", "precheck", "dup-check", "stale") else {"ok": True}
        if cmd not in ("reconcile", "epoch", "ledger", "family", "conflicts", "principal", "embed", "check", "precheck", "dup-check", "stale"):
            if isinstance(out, dict) and "id" in out:
                result["finding"] = out
            else:
                result["status"] = out
        # 域绑定可观测（ECC-C98BDE1D2B3B）：未带 --domain 的调用 domain_bound=false，
        # 便于审计发现"未归属域"的 finding（潜在跨仓污染候选）。
        result["domain_bound"] = domain is not None
        if domain:
            result["domain"] = domain
            result["state_file"] = state_file
        print(json.dumps(result, ensure_ascii=False))
    except SystemExit:
        raise
    except Exception as e:
        msg = str(e)
        # 2026-10-27（U3 归因，诊断面）：补**加性**字段 `error_class`。
        #   病象：预检等路径上的非预期异常（如 state 形态非法 ⟹ `AttributeError: 'str' object
        #   has no attribute 'get'`）被本处理器压成**纯文本** `error`，异常类名丢失 ⟹ 上游
        #   `apply-worktree` 只能回空 `stderr_tail`，真因不可观测（ECC-786B05E46C61 同族）。
        #   `error` 文案与 rc 逐字不变（旧消费者零影响）；新字段仅供诊断拼接。
        out = {"ok": False, "error": msg, "error_class": type(e).__name__}
        # ── 加载安全网·阻断响应自引导（ECC-73F9BD85C30F）────────────────────────────
        # 缺口（实测事故）：`--plan`（真名 `--plan-file`）这类**未知 flag** 只回
        #   `未知参数 --plan（...）`，**无合法集回显** ⟹ 调用面只能靠人记得先 `help finding`、
        #   记得真名。现对「未知 flag / 未知子命令」这类**调用形态**错误补三要素
        #   （正本 = references/plugin-loading-test-framework.md §5）：
        #   · usage   = 本子命令唯一调用公式（`_usage_error` 单源，不另写一份文案）
        #   · allowed = 该子命令**真实** flag 集（下表逐条回源本文件解析循环；`--domain` 通用）
        #   · next    = 可执行出口（`help finding` → references/cli-protocol.md 唯一事实源）
        # **纯加性**：`error` 文案 / rc=1 逐字不变；且**仅**调用形态错误带新字段（其余错误面
        #   out 逐字同旧，零回归）。旧消费者忽略新字段。
        _sub = str(args[0]) if args else ""
        _sub_flags = {
            "register": ["--title-file", "--source-file", "--family", "--domain",
                         "--cover-layers", "--root-key", "--anchor", "--facet",
                         "--closure-oracle", "--gap", "--from-report", "--repo",
                         "--merge-into", "--dup-ack"],
            "dup-check": ["--family", "--anchor", "--facet", "--tau", "--limit",
                          "--exclude-id", "--domain"],
            "verify": ["--domain", "--verify-source"],
            "close": ["--verify-source", "--domain"],
            "reopen": ["--reason", "--domain"],
            "release-approve": ["--by", "--note", "--divergence", "--final-ruling", "--declassify", "--domain"],
            "release-reject": ["--by", "--note", "--domain"],
            "declassify": ["--by", "--note", "--domain"],
            "amend-title": ["--suffix", "--note", "--domain"],
            "anchor-drift": ["--repo", "--domain"],
            "amend-anchors": ["--map", "--apply", "--note", "--domain"],
            "status": ["--domain"],
            "prune-duplicates": ["--domain"],
            "archive-closed": ["--target-total", "--keep-closed", "--dry-run", "--domain"],
            "epoch": ["--ts", "--reason", "--purged", "--domain"],
            "reconcile": ["--domain"],
            "ledger": ["--plan", "--domain"],
            "family": ["--domain"],
            "principal": ["--plan", "--tau", "--embeddings", "--no-embeddings", "--emb-tau", "--domain"],
            "embed": ["--model", "--out", "--from-vectors", "--dry-run", "--domain"],
            "conflicts": ["--converge", "--apply", "--dedupe"],
            "precheck": ["--domain"],
            "stale": ["--ttl-days", "--apply", "--now", "--domain"],
            "journal-verify": ["--domain"],
        }
        if ("未知参数" in msg or "不支持参数" in msg
                or msg.startswith("unknown cmd")):
            out["allowed"] = _sub_flags.get(_sub, [])
            out["usage"] = _usage_error(_sub)
            out["next"] = "bash gatekeeper-cli.sh help finding"
        print(json.dumps(out))
        sys.exit(1)


if __name__ == "__main__":
    main()
