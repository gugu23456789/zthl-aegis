"""族定义（数据）加载 + 族判定 + 窄任务编译 —— 编码代理切片（F7 基座）。

设计依据 docs/plans/2026-09-22-coding-agent-slice-design.md §2：
族定义落成数据（一类一 agent = 一份 JSON），本模块只做「读数据 + 判定 + 组装」，
不含任何编辑能力（编辑在 gk_agent_edit.py）。
"""
import json
import os
import re
import sys

# 族定义必填键（缺任一或值为 None → FamilyError，fail-loud，不静默降级）
REQUIRED_KEYS = ("family", "match", "tier", "edit_quota", "allowed_paths",
                 "forbidden_paths", "narrow_task_template", "test_first",
                 "verify_cmd", "affected_tests")

DEFAULT_FAMILIES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "references", "agent-families")


class FamilyError(Exception):
    """族定义加载/校验失败（fail-loud）。"""


def _families_dir(d):
    # 2026-09-26（ECC-835E2928497D）：`GK_AGENT_FAMILIES_DIR` 可覆盖（与既有
    # GATEKEEPER_STATE_ROOTS / GK_ANCHOR_REBASE_ROOTS 同族的配置口）；未设 ⟹ 逐字不变。
    return d or os.environ.get("GK_AGENT_FAMILIES_DIR") or DEFAULT_FAMILIES_DIR


def load_family(family_id: str, families_dir: str = "") -> dict:
    """按 id 载入族定义并校验必填键；未知 id / 缺键 / 空值 / JSON 坏 → FamilyError。"""
    path = os.path.join(_families_dir(families_dir), family_id + ".json")
    if not os.path.isfile(path):
        raise FamilyError("族定义不存在: " + path)
    try:
        with open(path, encoding="utf-8") as f:
            fam = json.load(f)
    except Exception as e:  # noqa: BLE001 — 边界，fail-loud
        raise FamilyError("族定义解析失败 %s: %s" % (path, e))
    if not isinstance(fam, dict):
        raise FamilyError("族定义必须是 JSON 对象: " + path)
    for k in REQUIRED_KEYS:
        # 2026-09-22 红先（test_load_family_missing_required_key_fails_loud）：
        # 「键存在但值为 None」必须与「键缺失」同判 —— 否则 None 会一路静默传到
        # 下游（如 match.any 解引用即 AttributeError，报错点远离真因）。
        if k not in fam or fam[k] is None:
            raise FamilyError("族定义缺必填键 %r: %s" % (k, path))
    if fam.get("family") != family_id:
        raise FamilyError("族定义 family 字段与文件名不符: %s" % path)
    return fam


def list_families(families_dir: str = "") -> list:
    """列出全部族 id（排序，稳定）。"""
    d = _families_dir(families_dir)
    if not os.path.isdir(d):
        return []
    return sorted(n[:-5] for n in os.listdir(d) if n.endswith(".json"))


# 三失败模式严重度（source 取最重者；对齐 plugin-loading §1 拦截语义）
_SCAFFOLD_RANK = {"missing": 0, "tampered": 1, "error": 2}


def scaffold_status(families_dir: str = "") -> dict:
    """coder 落刀脚手架健康度（三失败模式显式，**禁静默**）—— 对齐
    `references/plugin-loading-test-framework.md` §1。

    2026-09-26（ECC-835E2928497D）：`--role coder` 的唯一落刀能力 = `edit` → 入口
    `load_family(<family>)`。族脚手架缺失/不可解析时，`load_family` 只在 coder **首次 edit
    调用**才 `FamilyError`（且失败只回给 agent）⟹ 表现「零落刀 + 报告像在分析」= §1 的
    **漏加载静默**。本函数把该脚手架的加载态**显式**化，供派发前置闸消费。

    分流（`source` 取最重者）：
      `missing`  漏加载：族目录不存在 / 目录内 0 个族定义
      `error`    错误加载：族 JSON 解析失败
      `tampered` 误加载：`family` 字段与文件名不符 / 缺必填键 / 必填键值为 None
      `ready`    全绿
    `errors` 逐条给出**路径级**真因（不只报个数）。
    """
    d = _families_dir(families_dir)
    errors, source, fams = [], "", []
    if not os.path.isdir(d):
        errors.append("族目录不存在: " + d)
        source = "missing"
    else:
        fams = sorted(n[:-5] for n in os.listdir(d) if n.endswith(".json"))
        if not fams:
            errors.append("族目录内无族定义（0 个 *.json）: " + d)
            source = "missing"
        for fid in fams:
            try:
                load_family(fid, d)
            except FamilyError as e:
                msg = str(e)
                errors.append(msg)
                cls = "error" if "解析失败" in msg else "tampered"
                if _SCAFFOLD_RANK[cls] > _SCAFFOLD_RANK.get(source, -1):
                    source = cls
    ok = not errors
    return {
        "ok": ok,
        "source": "ready" if ok else source,
        "detail": ("脚手架就绪：%d 族" % len(fams)) if ok else "；".join(errors[:3]),
        "families": fams,
        "errors": errors,
    }


def _finding_text(finding: dict) -> str:
    """族判定/落点预检共用的命中面（id/title/description/source）。"""
    return " ".join(str((finding or {}).get(k) or "")
                    for k in ("id", "title", "description", "source"))


def _matched_keywords(fam: dict, text: str) -> list:
    """该族 `match.any` 中命中 `text` 的关键词（保序）。"""
    kws = ((fam.get("match") or {}).get("any") or [])
    return [k for k in kws if k and re.search(re.escape(k), text, re.I)]


def classify(finding: dict, families_dir: str = "") -> str:
    """按各族的 match.any 关键词命中判定族；首个命中者胜；无命中 → ""（不受理）。

    规则命中面 = finding 的 id/title/description/source 拼接（与 R25 聚类口径一致）。

    2026-09-26（`ECC-68A8EDFA4E40` 类级加固）：族可声明 `generic_tokens` —— 该表内的**泛词**
    单独命中**不构成路由依据**。现场实测：F3a 的 `json.dump` 是任何 state 直写站点都会出现的
    词 ⟹ 提到它的 finding 一律落 F3a，而 F3a 模板**锁死落点** `_log_block()` ⟹ 派发后 coder
    「按错落点落刀」（8 条 F3a 命中里 7 条靠它、其中 6 条**仅**靠它，且多数不属 F3a 的类）。
    命中集 ⊆ 泛词表 ⟹ 视同未命中，继续试下一族；全族皆然 ⟹ "" = **fail-loud 不受理**（不猜测）。
    """
    text = _finding_text(finding)
    for fid in list_families(families_dir):
        fam = load_family(fid, families_dir)
        hits = _matched_keywords(fam, text)
        if not hits:
            continue
        generic = {str(t).strip().lower() for t in (fam.get("generic_tokens") or []) if str(t).strip()}
        if generic and {str(h).strip().lower() for h in hits} <= generic:
            continue
        return fid
    return ""


def _red_arm_guidance() -> str:
    """红先臂「**禁手写**」引导块 —— id 与占位符**实时取自登记表**（经 `gk_red_arm_gen`）。

    2026-09-23（用户裁定「先接完 gk_red_arm_gen 的派发流」）：发生器此前已可用，但派发串
    （本函数产物）**不提它** ⟹ coder 仍按老路手写臂 —— 而手写正是发生器本来要消掉的三种
    浪费（措辞/骨架漂移、漏「HEAD 必红」对照行、负臂缺席）。现在接进派发串：
      · **同源**：id 与 placeholders 从 `references/red-arm-templates.json` 读，登记表一变
        派发串自动跟着变（负臂 `test_narrow_task_tracks_registry_ids` 钉住此性质）；
      · **fail-loud**：登记表不可读 ⟹ 抛 `FamilyError`。宁可不派发，也不派一个「无臂骨架」
        的任务（否则 coder 又回到手写）。
    """
    try:
        import gk_red_arm_gen as gen
        reg = gen.load_registry()
    except Exception as e:  # noqa: BLE001 — 派发边界，fail-loud 不裸抛
        raise FamilyError("红先模版登记表不可读（派发串无法给出臂骨架）: %s" % e)
    lines = ["红先臂（**禁手写**；骨架一律由登记表发生器给出，防措辞/骨架漂移）:",
             "  · 选型: python3 scripts/gk_red_arm_gen.py list"]
    for t in reg.get("templates") or []:
        tid = str(t.get("id") or "")
        phs = " ".join("%s=<值>" % str(p).strip("{}") for p in (t.get("placeholders") or []))
        lines.append("  · %s → python3 scripts/gk_red_arm_gen.py render %s %s" % (tid, tid, phs))
    lines.append("  · 渲染后**不得有 {…} 残留**（发生器会拒绝半成品）；"
                 "「HEAD 计数 ⟹ 必红」对照行与**负臂**必须一并给出。")
    return "\n".join(lines)


def _family_may_edit_tests(allowed_paths) -> bool:
    """该族是否**允许 coder 改测试文件**（结构性信号：`allowed_paths` 里有没有 `test_*.py`）。

    这是区分「可改自有测试」型与「source-only」型的**唯一机械判据**（不新增 schema / 不需逐族手标）。
    只按**文件名形态**判（`test_*.py`），不看目录层级。
    """
    for p in (allowed_paths or []):
        b = os.path.basename(str(p).replace("\\", "/"))
        if b.startswith("test_") and b.endswith(".py"):
            return True
    return False


def arm_allowed_extra(fam: dict, finding_id: str) -> list:
    """**设计 A（2026-09-30）**：该 finding 的红先臂文件 → 并入 coder 有效 `allowed_paths`。

    病象（用户实测「apply-worktree 经常因为**不包含对应个别测试文件**导致失败」）：
    族 `allowed_paths` 是**静态**清单（每族通常只一个测试文件），而「这个 finding 的臂写在哪个
    文件」是**按 finding**登记在 `references/red-arm-templates.json::finding_arms[].test_file`
    ⟹ 二者**系统性错配** ⟹ coder 落 `gk_agent_edit.apply_edit` 闸② 时被判
    `blocked_by: "allowed_paths"` ⟹ 改不动自己的臂。

    **单一事实源** = 红先臂登记表（**禁**在族 JSON 里再手抄一份 ⟹ 那正是流程摩擦）。

    ── **门（关键）**：族分**两类设计**（实测）────────────────────────────────────────
      · **可改自有测试**型（`allowed_paths` **已含测试文件**，如 F3b / XENV-FORM /
        F-MoA-accept-aggregation）⟹ **并入**该 finding 的臂文件（A 只在这类生效）；
      · **source-only**型（`allowed_paths` **不含**任何测试文件，模板自陈「**禁止改任何测试文件**
        （红先臂由主 agent 写）—— 你只负责落刀」；实测 F7 / F-cli-dispatch-budget-single-source /
        F-MoA-full-regression）⟹ **一律 no-op**。
    门的依据：**显式禁令优先于本推演** —— 这些族的 forbidden 表**不**列自家臂文件（它列的是**他族**
    测试，防跨族覆盖），故单看 `forbidden_paths` **不足以**判出「source-only」；而「allowed 里
    有没有测试文件」是**结构性**信号，不引入新 schema、不需逐族手标（零流程摩擦）。

    其余 no-op：未登记/空值 ⟹ `[]`；已在该族 `allowed_paths` ⟹ `[]`；命中 `forbidden_paths`
    ⟹ `[]`（显式禁令优先）；登记表不可读 ⟹ `[]`（**best-effort，不阻断派发**）。
    """
    fid = str(finding_id or "")
    if not fid:
        return []
    allowed = list(fam.get("allowed_paths") or [])
    if not _family_may_edit_tests(allowed):
        return []
    try:
        import gk_red_arm_gen as gen
        tf = gen.finding_test_file(fid)
    except Exception:  # noqa: BLE001 — 边界：取数失败不得阻断派发
        return []
    if not tf:
        return []
    from gk_agent_edit import _within   # 复用**同一份**路径判定语义（禁第二实现）
    if _within(tf, fam.get("forbidden_paths")):
        return []
    if _within(tf, allowed):
        return []
    return [tf]


def compile_narrow_task(fam: dict, finding: dict, worktree: str, quota: int,
                        allowed=None) -> str:
    """把族模板 + finding 锚 + worktree + 配额组装成极严窄任务串（A3：压改动范围到最小）。

    `allowed`：有效 `allowed_paths`（缺省 = 族原值）—— 设计 A 把「该 finding 的臂文件」并入后
    经此传入，使**窄任务串、回包、台账**三面同源（否则 coder 被告知的面与实际闸判定面不一致）。
    """
    anchor = "%s — %s" % ((finding or {}).get("id", "?"),
                          (finding or {}).get("title", ""))
    # 2026-09-23（跨族共因 ⑤，实测）：原用 `str.format(anchor=…, verify_cmd=…)` ⟹ 模板里的
    # **字面花括号**被当占位符 —— F3b 模板含 `side_effects ∈ {state_write, git_write, key_write}`
    # ⟹ `KeyError`，`apply-worktree --code-fix` 在族判定处**静默失败**（CLI 只回
    # `族判定失败 detail=null`，真因仅落 gk_dbg.log），派发链全断。编译函数为 10 族共用 ⟹
    # 任一族的模板写 `{a, b}` 都会炸。改为**定点替换两个已知占位符**，其余花括号原样保留。
    body = str(fam.get("narrow_task_template") or "")
    body = (body.replace("{anchor}", anchor)
                .replace("{verify_cmd}", str(fam.get("verify_cmd", ""))))
    _allowed = [str(x) for x in (allowed if allowed is not None
                                 else (fam.get("allowed_paths") or []))]
    return "\n".join([
        body,
        "",
        "worktree: " + worktree,
        # 2026-09-23（ECC-591BA1B918B4 附带缺口）：`edit_gk(worktree, path, old_str, new_str,
        # family_id, used, allowed)` **要求 agent 传 family_id**，而窄任务原串不含族名 ⟹ agent
        # 无从得知、只能猜（`apply_edit` 用它做 allowed/forbidden 白名单判定）。此处显式给出。
        "family: " + str(fam.get("family") or ""),
        "edit 配额（超出即 BLOCK）: " + str(quota),
        "allowed_paths: " + ", ".join(_allowed),
        "forbidden_paths: " + ", ".join(fam.get("forbidden_paths") or []),
        "红先测试（必须先看它失败）: " + str(fam.get("test_first") or ""),
        _red_arm_guidance(),
        "仅允许改动 allowed_paths 内文件；禁止改动 forbidden_paths 内任何文件。",
    ])


def _find_finding(state_file: str, finding_id: str):
    """从本 state 的 finding 台账取记录（**读侧 union**：主台账 ⊕ 溢出片）；找不到 → None。

    `ECC-3B8AAE201343` 遗漏⑤：溢出到 `<state>.finding-archive.jsonl` 的 finding 若只查主台账，
    族模板就会「找不到 finding」而放行（`have_state=False` 使落点预检静默 no-op）。
    """
    import gk_finding as _gf
    for cand in _gf.load_findings_union(state_file):
        if str((cand or {}).get("id") or "") == finding_id:
            return cand
    return None


def _check_anchor(fam: dict, finding: dict, finding_id: str,
                  explicit: bool, have_state: bool) -> None:
    """派发边界**落点一致性预检**（`ECC-68A8EDFA4E40` 类级加固）。

    族模板若**锁死落点**（声明 `anchor_symbols`），则 finding 文本必须至少命中其中一个符号；
    否则该 finding 的**病象不在本族锁定的落点内** ⟹ 派发出去就是「按错落点落刀」（现场：
    coder 被指去改 `_log_block()`，而病象在 monitor 报告落库块）。

    三条 no-op（零回归）：`anchor_symbols` 未声明（不锁单点落点）/ `explicit`（调用方显式给
    `--family` = 人工担责，跳过）/ `have_state` 假（只有 id、无 finding 记录 ⟹ 无证据可判）。
    """
    syms = [str(s) for s in (fam.get("anchor_symbols") or []) if str(s).strip()]
    if not syms or explicit or not have_state:
        return
    text = _finding_text(finding)
    if any(re.search(re.escape(s), text, re.I) for s in syms):
        return
    raise FamilyError(
        "族↔finding 落点错配（FAMILY_ANCHOR_MISMATCH）：族 %s 的窄任务书**锁死落点** %s，而 "
        "finding %s 的文本里找不到其中任何一个 ⟹ 病象不在本族落点内，按此模板派发会**改错函数**。"
        "处置：① 若病象确在别处（多站点/属他族）—— 为它**扩族或开新族**；② 若确属本族且落点无误 "
        "—— 用 `--family %s` **显式指定**（显式 = 人工担责，跳过本预检）。"
        % (fam.get("family"), syms, finding_id, fam.get("family")))


def resolve(finding_id: str, family_id: str = "", state_file: str = "",
            families_dir: str = "", worktree: str = "") -> dict:
    """族判定 + 窄任务编译（**单一事实源**，供 CLI `apply-worktree --code-fix` 消费）。

    - `state_file` 非空 → 从 `gate_data.ecc_findings[]` 取该 finding 记录（判定命中面含
      title/description）；留空则退化为「仅 id」记录（命中面变窄，可用 `family_id` 显式指定绕过）。
    - 族：`family_id` 显式优先，否则 `classify()`；无命中 → `FamilyError`（不受理，fail-loud）。
    - `worktree` 仅用于窄任务串组装（`--dry-run` 可留空）。
    - **设计 A（2026-09-30）**：返回/窄任务/回包的 `allowed_paths` = 族清单 **∪ 本 finding 的
      红先臂文件**（见 `arm_allowed_extra`；`GK_ARM_ALLOWED=0` 关闭）。三面同源，故 CLI 回包与
      台账 claim 自动带上它，`--batch` 两两 disjoint 门随之覆盖。
    """
    if state_file:
        if not os.path.isfile(state_file):
            raise FamilyError("state 文件不存在: " + state_file)
        finding = _find_finding(state_file, finding_id)
        if finding is None:
            raise FamilyError(
                "finding 不存在于该 state 的 gate_data.ecc_findings[]: %s（state=%s）⟹ 该 id "
                "属别的 state 域，请用 --state 指向其所在域" % (finding_id, state_file))
    else:
        finding = {"id": finding_id}
    fid = family_id or classify(finding, families_dir)
    if not fid:
        raise FamilyError("无族命中（各 match.any 全未命中；或**仅**命中泛词 `generic_tokens`）: " + finding_id)
    fam = load_family(fid, families_dir)
    _check_anchor(fam, finding, finding_id, explicit=bool(family_id), have_state=bool(state_file))
    quota = int(fam.get("edit_quota") or 0)
    # **设计 A（2026-09-30）**：有效 `allowed_paths` = 族清单 ∪ 本 finding 的红先臂文件。
    #   `GK_ARM_ALLOWED=0` ⟹ 退回族原值（kill switch，零回归）。
    allowed = list(fam.get("allowed_paths") or [])
    if os.environ.get("GK_ARM_ALLOWED", "1") != "0":
        for _p in arm_allowed_extra(fam, finding_id):
            if _p not in allowed:
                allowed.append(_p)
    return {
        "ok": True,
        "finding": finding_id,
        "family": fid,
        "quota": quota,
        "tier": fam.get("tier"),
        "narrow_task": compile_narrow_task(fam, finding, worktree, quota, allowed=allowed),
        "test_first": fam.get("test_first"),
        "verify_cmd": fam.get("verify_cmd"),
        "affected_tests": fam.get("affected_tests"),
        "allowed_paths": allowed,
        "forbidden_paths": fam.get("forbidden_paths"),
    }


def validate_family(data: dict) -> dict:
    """族定义写时 lint（ECC-6C36BAF3D0FB）：REQUIRED_KEYS 之外的**内容条款**前置 ——
    §8.3 判据自检、{anchor}/{verify_cmd} 占位符、allowed_paths/test_first/verify_cmd 非空。
    返回 {"ok", "errors", "warnings"}；errors 非空 = 不可登记（fail-loud，勿静默降级）。"""
    errors, warnings = [], []
    for k in REQUIRED_KEYS:
        v = data.get(k)
        if v is None or (isinstance(v, (str, list, dict)) and not v):
            errors.append("必填键缺失或为空: %s" % k)
    tpl = str(data.get("narrow_task_template") or "")
    if "判据自检" not in tpl:
        errors.append("narrow_task_template 缺「判据自检」条款（设计 §8.3）")
    if "{anchor}" not in tpl:
        errors.append("narrow_task_template 缺占位符 {anchor}（finding id 传不进任务书，compile 定点替换依赖）")
    if "{verify_cmd}" not in tpl:
        warnings.append("narrow_task_template 缺占位符 {verify_cmd}（compile 对缺席 no-op；存量族 F3a/F3b 即此形态，coder 亦无法跑命令）")
    if not (data.get("allowed_paths") or []):
        errors.append("allowed_paths 为空（无落刀面）")
    if not (data.get("test_first") or ""):
        errors.append("test_first 为空（红先纪律承载）")
    if not (data.get("verify_cmd") or ""):
        errors.append("verify_cmd 为空（验收闸承载）")
    if "禁止" not in tpl and "禁 " not in tpl:
        warnings.append("模板未含禁止性措辞（forbidden_paths 之外的行为边界建议模板内明示）")
    # 2026-09-26（ECC-68A8EDFA4E40 类级加固）：泛词表 / 锁死落点符号表的形态与自洽。
    gts = data.get("generic_tokens")
    if gts:
        if not isinstance(gts, list) or not all(isinstance(x, str) and x.strip() for x in gts):
            errors.append("generic_tokens 必须是**非空字符串**的列表")
        else:
            anys = {str(x).strip().lower() for x in ((data.get("match") or {}).get("any") or [])}
            extra = [str(x) for x in gts if str(x).strip().lower() not in anys]
            if extra:
                errors.append("generic_tokens 必须是 match.any 的**子集**"
                              "（否则该词永不参与判定，声明即失效）: %s" % extra)
    syms = data.get("anchor_symbols")
    if syms is not None and (not isinstance(syms, list)
                             or not all(isinstance(x, str) and x.strip() for x in syms)):
        errors.append("anchor_symbols 必须是**非空字符串**的列表（或省略）")
    # 2026-09-26（`ECC-1D1C893060AF`）：模板**不得断言未实测的结构性事实** —— 最典型载体 =
    # **裸行号锚**：派发时早已漂移（实测 F3b 模板曾写 `≈L2500–2872` / `L2872 与 L9357`，时过即错），
    # 而 coder 会**按错前提行事**（同一族两次同向误判的根因）。
    # 机检代理判据 = 模板内禁 `L<≥3 位数字>`（保留 `L1/L2/L3` 档位/层次名不受影响）；
    # 结构事实一律改**符号锚**（`PROTECTED_REGION::gate` / `PROTECTED_REGION_END::gate`）+ 要求 coder
    # 实跑核对（`rg -n 'PROTECTED_REGION' …`）。
    # ⚠ 已知边界（如实登记）：本判据只覆盖 `L<n>` 形态；`file.py:<n>` 形态（XENV-FORM / F-ecc-review
    # 模板里的既有背景描述）不在本切片面内。
    bare_lines = sorted(set(re.findall(r"L\d{3,}", tpl)))
    if bare_lines:
        errors.append("narrow_task_template 含**裸行号锚** %s ⟹ 属「未实测的结构性事实」（行号必漂移、"
                      "coder 会按错前提行事）；请改符号锚 + 要求 coder 实跑核对（ECC-1D1C893060AF）"
                      % bare_lines)
    return {"ok": not errors, "errors": errors, "warnings": warnings}


def main(argv: list[str]) -> int:
    """`resolve <fid> [--family F] [--state P] [--worktree W]` | `list` |
    `scaffold-status [--families-dir D]` | `validate <file.json>`。"""
    if not argv:
        print(json.dumps({"ok": False, "error": "usage: resolve <fid> [--family F] "
                                                 "[--state P] [--worktree W] | list | "
                                                 "scaffold-status [--families-dir D] | validate <file.json>"},
                         ensure_ascii=False))
        return 2
    if argv[0] == "list":
        print(json.dumps({"ok": True, "families": list_families()}, ensure_ascii=False))
        return 0
    if argv[0] == "scaffold-status":
        # 派发前置闸消费面（ECC-835E2928497D）：ok=False ⟹ rc=1，CLI 据此 fail-loud
        # `CODER_SCAFFOLD_MISSING`（禁静默降级；对齐 plugin-loading §1 拦截语义）。
        d, i = "", 1
        while i < len(argv):
            if argv[i] == "--families-dir" and i + 1 < len(argv):
                d = argv[i + 1]; i += 2
            else:
                print(json.dumps({"ok": False, "error": "unknown arg: " + argv[i],
                                  "usage": "scaffold-status [--families-dir D]"},
                                 ensure_ascii=False))
                return 2
        st = scaffold_status(d)
        print(json.dumps(st, ensure_ascii=False))
        return 0 if st["ok"] else 1
    if argv[0] == "validate":
        if len(argv) < 2:
            print(json.dumps({"ok": False, "error": "validate <family.json> required"},
                             ensure_ascii=False))
            return 2
        try:
            with open(argv[1], encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            print(json.dumps({"ok": False, "error": "族文件读取/解析失败: %s" % e},
                             ensure_ascii=False))
            return 1
        r = validate_family(data)
        print(json.dumps(r, ensure_ascii=False))
        return 0 if r["ok"] else 1
    if argv[0] != "resolve":
        print(json.dumps({"ok": False, "error": "unknown subcommand: " + argv[0]},
                         ensure_ascii=False))
        return 2
    args = argv[1:]
    fid = args[0] if args and not args[0].startswith("--") else ""
    opts: dict = {}
    i = 1 if fid else 0
    while i < len(args):
        k = args[i]
        if k in ("--family", "--state", "--worktree") and i + 1 < len(args):
            opts[k[2:]] = args[i + 1]
            i += 2
        else:
            print(json.dumps({"ok": False, "error": "unknown arg: " + k,
                              "usage": "resolve <fid> [--family F] [--state P] [--worktree W]"},
                             ensure_ascii=False))
            return 2
    if not fid:
        print(json.dumps({"ok": False, "error": "resolve <fid> required"}, ensure_ascii=False))
        return 2
    try:
        out = resolve(fid, opts.get("family", ""), opts.get("state", ""),
                      worktree=opts.get("worktree", ""))
    except FamilyError as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        return 1
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
