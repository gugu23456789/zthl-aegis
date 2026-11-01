"""F7 基座：族定义加载 / 族判定 / 窄任务编译（red-first）。"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_agent_family as af


def _write_family(tmp_path, fid, **over):
    fam = {
        "family": fid,
        "match": {"any": ["CHECKSUM", "checksum"]},
        "tier": 3,
        "edit_quota": 3,
        "allowed_paths": ["gatekeeper-cli.sh", "scripts/"],
        "forbidden_paths": ["docs/"],
        "narrow_task_template": "只改 {anchor}，禁止其它改动。验收：{verify_cmd}",
        "test_first": "scripts/test_gk_agent_edit.py::test_red_first",
        "verify_cmd": "pytest scripts/test_x.py -q",
        "affected_tests": ["scripts/test_x.py"],
    }
    fam.update(over)
    d = tmp_path / "agent-families"
    d.mkdir(exist_ok=True)
    (d / (fid + ".json")).write_text(json.dumps(fam, ensure_ascii=False), encoding="utf-8")
    return str(d)


def test_load_family_returns_mapping(tmp_path):
    d = _write_family(tmp_path, "F3-state-write-integrity")
    fam = af.load_family("F3-state-write-integrity", d)
    assert fam["family"] == "F3-state-write-integrity"
    assert fam["tier"] == 3


def test_load_family_missing_required_key_fails_loud(tmp_path):
    d = _write_family(tmp_path, "F9-bad", match=None)
    with pytest.raises(af.FamilyError) as e:
        af.load_family("F9-bad", d)
    assert "match" in str(e.value)


def test_load_family_unknown_id_fails_loud(tmp_path):
    d = _write_family(tmp_path, "F3-state-write-integrity")
    with pytest.raises(af.FamilyError):
        af.load_family("NoSuchFamily", d)


def test_classify_picks_first_matching_family(tmp_path):
    d = _write_family(tmp_path, "F3-state-write-integrity")
    fid = af.classify({"id": "ECC-X", "title": "checksum 未重算"}, d)
    assert fid == "F3-state-write-integrity"


# ── 派发串接上红先臂发生器（2026-09-23 用户裁定「先接完 gk_red_arm_gen 的派发流」）──

def _narrow(tmp_path):
    d = _write_family(tmp_path, "F3-state-write-integrity")
    fam = af.load_family("F3-state-write-integrity", d)
    return af.compile_narrow_task(fam, {"id": "ECC-X", "title": "t"}, "/w", 3)


def test_narrow_task_embeds_red_arm_guidance(tmp_path):
    """派发串必须**点名发生器**并禁止手写（原来完全没提 ⟹ coder 只能手写）。"""
    s = _narrow(tmp_path)
    assert "gk_red_arm_gen.py" in s, "派发串未接入发生器"
    assert "禁手写" in s


def test_narrow_task_tracks_registry_ids(tmp_path, monkeypatch):
    """**同源臂**：登记表增一个模版 ⟹ 派发串自动跟着出现（证明实时读表，不是硬编码名单）。"""
    import gk_red_arm_gen as gen
    reg = json.loads(json.dumps(gen.load_registry()))          # 深拷贝，勿动真表
    reg["templates"].append({"id": "zz-probe-arm", "placeholders": ["alpha"],
                             "body": "assert {alpha}"})
    monkeypatch.setattr(gen, "load_registry", lambda *a, **k: reg)
    s = _narrow(tmp_path)
    assert "zz-probe-arm" in s and "alpha=<值>" in s, s


def test_narrow_task_fails_loud_when_registry_unreadable(tmp_path, monkeypatch):
    """**负臂**：登记表不可读 ⟹ FamilyError（宁可不派发，也不派一个「无臂骨架」的任务）。"""
    import gk_red_arm_gen as gen

    def _boom(*a, **k):
        raise ValueError("登记表缺失")

    monkeypatch.setattr(gen, "load_registry", _boom)
    with pytest.raises(af.FamilyError):
        _narrow(tmp_path)


def test_classify_excluded_family_returns_empty(tmp_path):
    d = _write_family(tmp_path, "F3-state-write-integrity")
    assert af.classify({"id": "ECC-Y", "title": "无关标题"}, d) == ""


def test_compile_narrow_task_contains_paths_quota_and_verify(tmp_path):
    d = _write_family(tmp_path, "F3-state-write-integrity")
    fam = af.load_family("F3-state-write-integrity", d)
    task = af.compile_narrow_task(fam, {"id": "ECC-Z", "title": "checksum 未重算"},
                                  worktree="/tmp/wt", quota=3)
    assert "/tmp/wt" in task and "3" in task
    assert "gatekeeper-cli.sh" in task and "docs/" in task
    assert fam["verify_cmd"] in task


F3_SUBFAMILIES = ("F3a-state-write-convergence", "F3b-edit-budget-accounting")


def test_real_f3_subfamily_files_are_valid():
    """真实族数据文件（2026-09-23 F3 拆分后的两个子族）必须能通过 load_family 校验（防手写 JSON 漂移）。"""
    for fid in F3_SUBFAMILIES:
        fam = af.load_family(fid)  # 用默认目录
        assert fam["family"] == fid
        assert fam["edit_quota"] == 3
        # 2026-09-23 A1（用户裁定「强化档位 4」，替代新增 fix 专用档）：F3 两子族的预算档位
        # 由 3 抬到 4（token_budget 1M / max_turns 800 / max_output_tokens 80k / timeout 900s），
        # 解 C1「单次派发 669,009 tokens 撞 tier3 的 500k 顶（turns 仅用 10/400）」。
        assert fam["tier"] == 4
        assert fam["test_first"]
        assert fam["verify_cmd"]
        assert fam["affected_tests"]


def test_f3_subfamilies_are_file_level_disjoint():
    """两子族必须**文件级互斥**（防并行 worktree 分支互相覆盖 = 「打架」）：
    各方独占的测试文件必须出现在对方的 forbidden_paths；且 allowed_paths 除共用的
    `gatekeeper-cli.sh` 外不得交叉。"""
    a = af.load_family("F3a-state-write-convergence")
    b = af.load_family("F3b-edit-budget-accounting")
    assert "scripts/test_gk_edit_budget_accounting.py" in a["forbidden_paths"]
    assert "scripts/test_gk_state_write_single_entry.py" in b["forbidden_paths"]
    assert set(a["allowed_paths"]) - {"gatekeeper-cli.sh"} == set()
    assert set(b["allowed_paths"]) - {"gatekeeper-cli.sh"} == {"scripts/test_gk_edit_budget_accounting.py"}
    # 2026-09-24 去重（用户裁定「避免又引入重复实现」）：原此处另有两条
    # `allowed_paths ∩ 他族 affected_tests` 判据 —— 已由**N 族泛化臂**
    # `test_no_family_allowed_paths_invade_others_affected_tests` 统一覆盖（对**全部**族对施加
    # 同一判据，覆盖面严格更强）⟹ 本臂只保留 F3 两族的**专属契约**（他族不适用），
    # 避免同一判据在两处维护（改一处忘一处 = 静默退化）。


def test_every_family_template_demands_judgement_selfcheck():
    """设计 §8.3 强制要求 ①：每个族的 `narrow_task_template` 必须含**判据自检**要求。

    动机（实测，非推测）：F3b 首版正臂「**红了但红得不对**」—— 载荷里的 `"` 被 shell 截断，
    子命令根本没跑到（假红）；F3a 一轮内两次踩「判据**注释盲**」（把注释文本当代码站点：
    `_inline_sites` 净持平 13→13、`cli_state_dump_lines` 使 `arm1` 假红）。二者同源 =
    「判据本身没有自检」⟹ 必须让 coder 被要求点出此类缺陷（但**仍须先落刀**，见
    `subagent_runner.ROLE_INSTRUCTIONS["coder"]`）。本臂防「新族模板漏写该要求」的静默退化。
    """
    d = af.DEFAULT_FAMILIES_DIR
    names = sorted(n for n in os.listdir(d) if n.endswith(".json"))
    assert names, "未扫到任何族数据文件 —— 本臂失去判别力"
    missing = [n for n in names
               if "判据自检" not in json.loads(
                   open(os.path.join(d, n), encoding="utf-8").read()).get(
                       "narrow_task_template", "")]
    assert not missing, f"族模板缺「判据自检」要求（设计 §8.3）：{missing}"


def test_f3_members_route_to_the_right_subfamily():
    """族判定实测：各成员按 id/title 路由到正确族。

    2026-09-23 第三族开族（`ECC-792E2215ABC4`，用户裁定「落机制 + 开第三族」）：
    **读侧**成员 `ECC-81B0861B3349` 原口径 = 「两族均不受理（空串 = fail-loud）」，
    现改为路由到 **`F18-state-read-convergence`**（R18 读侧收敛族）⟹ 本臂随之更新；
    另补一条负臂：与任何族关键词都不沾的 finding 仍须 fail-loud 回空串（防族判定过宽）。
    """
    a, b = "F3a-state-write-convergence", "F3b-edit-budget-accounting"
    assert af.classify({"id": "ECC-9F21304266C5",
                        "title": "_log_block() 直写 state 不重算 _checksum"}) == a
    assert af.classify({"id": "ECC-3FE14977FC55",
                        "title": "state 序列化形态依赖最后写者所在副本"}) == a
    assert af.classify({"id": "ECC-1E6BFDD7A207",
                        "title": "edit_budget 只覆盖 Edit 工具调用（脚本直写文件不计）"}) == b
    assert af.classify({"id": "ECC-81B0861B3349",
                        "title": "gatekeeper.state 解析手动重复(30+ 内联 json.load)"}) == \
        "F18-state-read-convergence"
    # 负臂：与任何族关键词都不沾的 finding 仍须回空串（fail-loud，防族判定过宽）
    assert af.classify({"id": "ECC-000000000000",
                        "title": "与本仓任何族关键词无关的占位缺陷"}) == ""


def test_narrow_task_carries_family_id_and_worktree():
    """窄任务串必须显式给出 `family:` 与 `worktree:` —— 二者都是 `edit_gk` 的**必填参数**
    （`edit_gk(worktree, path, old_str, new_str, family_id, used, allowed)`）。

    现场（ECC-591BA1B918B4 附带缺口，2026-09-23）：原 `compile_narrow_task` 只给 worktree，
    **不给族名** ⟹ agent 无从得知 `family_id`、只能猜，而 `gk_agent_edit.apply_edit` 用它做
    allowed/forbidden 白名单判定 ⟹ 猜错即被 `forbidden_paths`/`allowed_paths` 闸拒。
    """
    fam = af.load_family("F3a-state-write-convergence")
    nt = af.compile_narrow_task(fam, {"id": "ECC-X", "title": "t"}, "/wt/agent-x", 3)
    assert "family: F3a-state-write-convergence" in nt
    assert "worktree: /wt/agent-x" in nt
    assert "edit 配额（超出即 BLOCK）: 3" in nt


def test_compile_narrow_task_tolerates_literal_braces(tmp_path):
    """⑤ 跨族共因（2026-09-23 实测，F3b 派发链全断）：族模板里的**字面花括号**被 `.format()`
    当占位符 ⟹ `KeyError: 'state_write, git_write, key_write'`。

    现场：`apply-worktree --code-fix --finding ECC-1E6BFDD7A207 … --dry-run` 回
    `{"ok":false,"error":"族判定失败","detail":null}` —— 真因（KeyError 栈）只落在
    `scripts/gk_dbg.log`，CLI 把**非 FamilyError 异常**吞成 detail=null ⟹ 表面像「无族命中」。
    该判据是**编译函数**级共因（10 族共用同一 `compile_narrow_task`）⟹ 任何模板写
    `{a, b}` 都会炸断派发链。本臂钉住：字面花括号须**原样保留**且编译成功。
    """
    tmpl = ("只改 {anchor}。**排除面**：`side_effects` 不含 {state_write, git_write, key_write}。"
            "验收：{verify_cmd}")
    d = _write_family(tmp_path, "Fx-literal-brace", narrow_task_template=tmpl)
    fam = af.load_family("Fx-literal-brace", d)
    nt = af.compile_narrow_task(fam, {"id": "ECC-B", "title": "t"}, "/wt/b", 3)
    assert "{state_write, git_write, key_write}" in nt, "字面花括号被 format 吃掉或被替换"
    assert "ECC-B" in nt and fam["verify_cmd"] in nt, "真占位符未被替换"


def test_real_family_templates_compile_without_keyerror():
    """每个**真实**族数据文件的模板都必须能编译 —— ⑤ 的防回退臂（本臂即当初应捕获 F3b 断链的臂）。"""
    d = af.DEFAULT_FAMILIES_DIR
    names = sorted(n for n in os.listdir(d) if n.endswith(".json"))
    assert names, "未扫到任何族数据文件 —— 本臂失去判别力"
    for n in names:
        fam = af.load_family(n[:-5], d)
        nt = af.compile_narrow_task(fam, {"id": "ECC-T", "title": "t"}, "/wt/t",
                                    fam["edit_quota"])
        assert "ECC-T" in nt, f"{n} 模板编译产物缺 anchor"


def test_family_files_carry_no_absolute_home_path():
    """机检（**红先**）：族定义**不得**含家目录绝对路径。

    ⚠ 2026-09-23（**ECC-8D46F2B1C0A4**）：`verify_cmd` 会被 `compile_narrow_task` 编进**任务文本**，
    而任务文本要过 `foreign_content_guard`（白名单 = `_OWN_USER`）。路径里的 `Users/HP` 一旦撞上
    `_OWN_USER` 解析退化（WSL 下 `USER=root` 兜底）⟹ **自家**路径被判成**外租户** ⟹
    `BLOCKED: cross-tenant contamination (Users/HP)` 拦死整条 coder 车道（实测 P3：2/2 coder
    产出空报告）。⟹ 族定义一律走 cwd 相对形态（`cd "$PWD"`），把触发面归零 —— 这也是
    「同一模板早上能过、下午被拦」那类间歇故障的根治面。
    """
    d = af.DEFAULT_FAMILIES_DIR
    names = sorted(n for n in os.listdir(d) if n.endswith(".json"))
    assert names, "未扫到任何族数据文件 —— 本臂失去判别力"
    bad = []
    for n in names:
        raw = open(os.path.join(d, n), encoding="utf-8").read()
        for pat in ("/mnt/c/Users/", "C:\\Users\\", "C:/Users/"):
            if pat in raw:
                bad.append(f"{n}:{pat}")
    assert not bad, "族定义含家目录绝对路径（会触发 foreign_content_guard 白名单误判）：" + "; ".join(bad)


# ─── N 族泛化不变式（2026-09-24 用户裁定「先补测试，交叉审查验证是否存在更多重复」）──────
# 动机（实测）：原 `test_f3_subfamilies_are_file_level_disjoint` **写死 F3a/F3b 两族**；
# 第三族 F18 与第四族 F-MoA 加入后**静态数据层无任何守护**。设计 §11.3-1 明说「泛化为任意
# N 族样本」—— 运行期互斥门已泛化（CLI `--batch` 的 `collisions` 门），但那是**同批**运行期
# 判据，且只覆盖 `--batch` 路径（单发 `--code-fix` 完全不查）⟹ 族数据写错要等真派发才暴露。

def _family_pairs():
    """全部族**有序两两组合**（含反向）。返回 `[(a_id, a_fam, b_id, b_fam), ...]`。"""
    fams = [(n, af.load_family(n)) for n in af.list_families()]
    return [(a, fa, b, fb) for a, fa in fams for b, fb in fams if a != b]


def _invasion_violations(pairs):
    """族 `allowed_paths` 侵入他族 `affected_tests` 的违例清单（**判据核心，可单测**）。

    **豁免（2026-09-28，`ECC-81B66A7B0E40`）**：命中项若在**他族** `forbidden_paths` 中 ⟹
    该族**无权修改**该文件 ⟹ 它只能「**用它**验收」，不能「**修绿它**」⟹ 属合法
    **verify-only 依赖**，不构成本条要防的「互相覆盖」。

    为什么这不算放宽判据（防「为过测而简化」）—— 本条要防的病是**双向**的：
    `affected_tests` 是**该族的验收基线**（`verify_cmd` 跑的就是它），一族的可改文件落在他族
    验收文件上 ⟹ 两族**各自**「修绿」同一文件，后落刀者覆盖先落刀者的验收语义（互相背书 /
    判据漂移）。该病**以「后者可改该文件」为前提**；若在他族 `forbidden_paths` 中，前提不成立
    （后者改不动）⟹ 该重叠**不可能**产生互相覆盖。故本函数只报「既在他族验收面、又**可被该族
    改动**」的重叠 —— 判据更精确（收窄到真实可发生的病），非更松。
    """
    out = []
    for a, fa, b, fb in pairs:
        forb = set(fb.get("forbidden_paths") or [])
        hit = sorted((set(fa.get("allowed_paths") or []) & set(fb.get("affected_tests") or [])) - forb)
        if hit:
            out.append("%s.allowed_paths ∩ %s.affected_tests = %s" % (a, b, hit))
    return out


def test_no_family_allowed_paths_invade_others_affected_tests():
    """设计 §11.3-1 N 族泛化：任一族 `allowed_paths` 不得侵入**他族** `affected_tests`。

    ⚠ **verify-only 豁免**：若侵入项在他族 `forbidden_paths` 中 ⟹ 该族无权改该文件 ⟹ 不构成本条
    所防的「互相覆盖」（判据与理由见 `_invasion_violations` 的 docstring）。

    同族不检（族**可以**改自己的验收文件）。
    """
    bad = _invasion_violations(_family_pairs())
    assert not bad, "族 allowed_paths 侵入他族验收面（验收互相覆盖）：\n  " + "\n  ".join(bad)


def test_invasion_guard_exempts_forbidden_verify_only():
    """臂（红先）：命中项在他族 `forbidden_paths` ⟹ **豁免**（verify-only 依赖，非重叠）。"""
    pairs = [("A", {"allowed_paths": ["t.py"]},
              "B", {"affected_tests": ["t.py"], "forbidden_paths": ["t.py"]})]
    assert _invasion_violations(pairs) == [], "verify-only 依赖被误报为验收面重叠"


def test_invasion_guard_still_catches_modifiable_overlap():
    """臂（红先 · 守强度）：命中项**不在**他族 `forbidden_paths` ⟹ 仍须报（可改动 = 真重叠）。"""
    pairs = [("A", {"allowed_paths": ["t.py"]},
              "B", {"affected_tests": ["t.py"], "forbidden_paths": []})]
    assert _invasion_violations(pairs) != [], "可改动的验收面重叠被漏报（判据被放宽过头）"


def test_family_match_keywords_are_not_shared_across_families():
    """同一关键词不得出现在**两个**族的 `match.any` 里。

    为什么：`classify()` 是**首个命中者胜**（按 `list_families()` 的文件名排序遍历）⟹
    关键词重复时 finding 归属退化为「依赖族文件名的字典序」，**加族 / 改名都会静默改路由**。

    形态说明：现状 4 族关键词全体不交 ⟹ 本臂是**守护臂**（防未来加族时静默退化）。
    """
    owner = {}
    dup = []
    for n in af.list_families():
        for kw in (af.load_family(n).get("match") or {}).get("any") or []:
            k = str(kw).strip().lower()
            if k in owner and owner[k] != n:
                dup.append("%r: %s ↔ %s" % (k, owner[k], n))
            owner[k] = n
    assert not dup, "关键词跨族重复 ⟹ classify 路由不确定：\n  " + "\n  ".join(dup)


def test_validate_family_catches_judgement_selfcheck_gap():
    """ECC-6C36BAF3D0FB：写时 lint 必须抓「判据自检」缺失（把迟到 1F 前置化）。"""
    import gk_agent_family as F
    base = {"family": "T", "match": {"any": ["x"]}, "tier": 4, "edit_quota": 3,
            "allowed_paths": ["a.py"], "forbidden_paths": ["b/"],
            "narrow_task_template": "修 {anchor}，禁止越界。{verify_cmd} 判据自检：有",
            "test_first": "t.py", "verify_cmd": "pytest t.py",
            "affected_tests": ["t.py"]}
    assert F.validate_family(base)["ok"] is True
    bad = dict(base)
    bad["narrow_task_template"] = "修 {anchor}。{verify_cmd}"
    r = F.validate_family(bad)
    assert r["ok"] is False and any("判据自检" in e for e in r["errors"]), r
    bad2 = dict(base)
    bad2["narrow_task_template"] = "修 {anchor}。判据自检：有"
    r2 = F.validate_family(bad2)
    assert r2["ok"] is True, r2  # {verify_cmd} 缺席降级为 warning（存量 F3a/F3b 形态）
    assert any("{verify_cmd}" in w for w in r2["warnings"]), r2


# ─── ECC-68A8EDFA4E40（族↔finding 错配）类级加固：泛词不得单独路由 + 派发边界落点预检 ──────
# 病象（P3 隔离 e2e 实测）：F3a 模板**锁死落点** `_log_block()`，而 `match.any` 里的泛词
# `json.dump` 把「病象在 monitor 报告落库块」的 finding 也路由到 F3a ⟹ coder 按错落点落刀。
# 两层修法：① 判定层——泛词**单独**命中不构成路由依据；② 派发层——族锁死落点符号必须能在
# finding 文本里找到，否则 fail-loud（"宁可不派发，也不派一个改错函数的任务"）。

def test_generic_token_alone_does_not_route(tmp_path):
    """族声明的 `generic_tokens`（泛词）：**只**靠它命中不得判定该族。"""
    d = _write_family(tmp_path, "F-generic", generic_tokens=["CHECKSUM"])
    assert af.classify({"id": "ECC-G1", "title": "checksum 未重算"}, d) == "", \
        "只靠泛词命中即路由 ⟹ generic_tokens 形同虚设"


def test_generic_token_plus_specific_still_routes(tmp_path):
    """负臂：泛词与**特异词**同时命中 ⟹ 仍须路由（泛词是「不得单独依据」，不是黑名单）。"""
    d = _write_family(tmp_path, "F-generic2", match={"any": ["checksum", "特异锚"]},
                      generic_tokens=["checksum"])
    assert af.classify({"id": "ECC-G2", "title": "特异锚 未收敛"}, d) == "F-generic2"


# red-first 沙箱只含 `scripts/` + CLI（**无** `references/`）⟹ 依赖**真族数据**的臂在沙箱
# skip、在 accept 面必判（先例：arm69 对 `SKILL.md`）；**机制**一律用合成族（tmp）判。
_HAVE_REAL_FAMILIES = os.path.isdir(af.DEFAULT_FAMILIES_DIR)


def _anchor_state(tmp_path, title):
    st = tmp_path / "state.json"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": [
        {"id": "ECC-M1", "title": title, "source": "manual"}]}}, ensure_ascii=False),
        encoding="utf-8")
    return str(st)


def test_resolve_refuses_on_family_anchor_mismatch(tmp_path, monkeypatch):
    """派发边界预检：族锁死落点符号不出现在 finding 文本 ⟹ `resolve` fail-loud。

    预检落在 `resolve`（派发边界）而非 `classify`（关键词契约）⟹ 既有 classify 语义与既有
    `test_f3_members_route_to_the_right_subfamily` 臂均不受影响。`_red_arm_guidance` 被替换
    ⟹ 本臂不依赖 `references/red-arm-templates.json`（沙箱可判）。
    """
    d = _write_family(tmp_path, "F-anchored", match={"any": ["直写 state"]},
                      anchor_symbols=["_log_block"])
    st = _anchor_state(tmp_path, "直写 state 未收敛（monitor 落库块）")
    monkeypatch.setattr(af, "_red_arm_guidance", lambda: "红先臂：见登记表")
    with pytest.raises(af.FamilyError) as e:
        af.resolve("ECC-M1", state_file=st, families_dir=d)
    assert "FAMILY_ANCHOR_MISMATCH" in str(e.value), str(e.value)


def test_resolve_allows_when_anchor_present(tmp_path, monkeypatch):
    """负臂：finding 文本含本族锁死落点符号 ⟹ 预检放行（不误拦正路）。"""
    d = _write_family(tmp_path, "F-anchored", match={"any": ["直写 state"]},
                      anchor_symbols=["_log_block"])
    st = _anchor_state(tmp_path, "_log_block() 直写 state 未收敛")
    monkeypatch.setattr(af, "_red_arm_guidance", lambda: "红先臂：见登记表")
    out = af.resolve("ECC-M1", state_file=st, families_dir=d)
    assert out["ok"] is True and out["family"] == "F-anchored"


def test_family_without_anchor_symbols_is_not_blocked(tmp_path, monkeypatch):
    """负臂（**零回归**）：未声明 `anchor_symbols` 的族 ⟹ 预检 no-op（不锁单点落点即不设限）。"""
    d = _write_family(tmp_path, "F-plain", match={"any": ["直写 state"]})
    st = _anchor_state(tmp_path, "直写 state 未收敛（随便哪处）")
    monkeypatch.setattr(af, "_red_arm_guidance", lambda: "红先臂：见登记表")
    out = af.resolve("ECC-M1", state_file=st, families_dir=d)
    assert out["ok"] is True and out["family"] == "F-plain"


def test_real_f3a_json_dump_alone_does_not_route():
    """真实 F3a **数据面**：只提到 `json.dump` 的 finding 不得路由到 F3a（现役唯一泛词）。

    ⚠ 沙箱无 `references/` ⟹ skip；accept 面必判。
    """
    if not _HAVE_REAL_FAMILIES:
        pytest.skip("red-first 沙箱无 references/agent-families（accept 面必判）")
    assert af.classify({"id": "ECC-X", "title": "monitor 落库块 json.dump 写失败"}) == "", \
        "F3a 的泛词仍在单独路由（ECC-68A8EDFA4E40 未修）"
    # 负臂：命中**特异**词仍须路由（剔泛词不得误伤 F3a 正路）
    assert af.classify({"id": "ECC-Y", "title": "_log_block() 直写 state 不重算 _checksum"}) == \
        "F3a-state-write-convergence"


def test_validate_family_rejects_generic_token_outside_match_any():
    """写时 lint：`generic_tokens` 必须是 `match.any` 子集（否则该词永不参与判定 = 声明即失效）。"""
    base = {"family": "T", "match": {"any": ["x"]}, "tier": 4, "edit_quota": 3,
            "allowed_paths": ["a.py"], "forbidden_paths": ["b/"],
            "narrow_task_template": "修 {anchor}，禁止越界。{verify_cmd} 判据自检：有",
            "test_first": "t.py", "verify_cmd": "pytest t.py", "affected_tests": ["t.py"]}
    bad = dict(base)
    bad["generic_tokens"] = ["不在 any 里"]
    r = af.validate_family(bad)
    assert r["ok"] is False and any("generic_tokens" in e for e in r["errors"]), r


def test_real_families_pass_validate_family():
    """守护臂：**真实**族文件须整体过写时 lint（含新键 `generic_tokens`/`anchor_symbols` 自洽）。

    ⚠ 沙箱无 `references/` ⟹ skip；accept 面必判。
    """
    if not _HAVE_REAL_FAMILIES:
        pytest.skip("red-first 沙箱无 references/agent-families（accept 面必判）")
    names = sorted(n for n in os.listdir(af.DEFAULT_FAMILIES_DIR) if n.endswith(".json"))
    assert names, "未扫到任何族数据文件 —— 本臂失去判别力"
    bad = {}
    for n in names:
        res = af.validate_family(af.load_family(n[:-5]))
        if not res["ok"]:
            bad[n] = res["errors"]
    assert not bad, "族定义未过 validate_family：%s" % bad


def test_validate_family_rejects_bare_line_anchor_in_template():
    """模板**不得断言未实测的结构性事实**：裸行号锚（`L<≥3 位>`）必漂移 ⟹ 写时抑制。

    `ECC-1D1C893060AF`：F3b 模板曾写 `≈L2500–2872` / `L2872 与 L9357` —— 派发时早已漂移，
    coder 按错前提行事（同一族两次同向误判的根因）。结构事实改**符号锚** + 要求 coder 实跑核对。
    """
    base = {"family": "T", "match": {"any": ["x"]}, "tier": 4, "edit_quota": 3,
            "allowed_paths": ["a.py"], "forbidden_paths": ["b/"],
            "narrow_task_template": "修 {anchor}，禁止越界。{verify_cmd} 判据自检：有",
            "test_first": "t.py", "verify_cmd": "pytest t.py", "affected_tests": ["t.py"]}
    bad = dict(base)
    bad["narrow_task_template"] = (
        "修 {anchor}。计费段在 `PROTECTED_REGION::gate` 内（该区 ≈L2500–2872），禁止越界。"
        "{verify_cmd} 判据自检：有")
    r = af.validate_family(bad)
    assert r["ok"] is False and any("裸行号锚" in e for e in r["errors"]), r
    # 负臂：档位 / 层次名（`L1`/`L3`）与符号锚不受影响
    good = dict(base)
    good["narrow_task_template"] = (
        "修 {anchor}。覆盖 L1/L3 面，落点见 `PROTECTED_REGION_END::gate` 之后，禁止越界。"
        "{verify_cmd} 判据自检：有")
    assert af.validate_family(good)["ok"] is True, af.validate_family(good)
