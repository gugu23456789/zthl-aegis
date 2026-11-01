#!/usr/bin/env python3
"""gk_plugin_manifest.py — 插件 manifest 注册表 + 生命周期（复刻 DSH/Cordis 完整循环，2026-08-25）。

对齐 Cordis 论文（cordis-paper.pdf）:
- **Definition 74（declarative configuration）**: entry 六字段
  `id / url / isolate / intercept / config / disabled` —— 管理方登记的插件声明。
- **Theorem 7（recover 不变性）**: 合法插件必须满足 `recover(track(f,g)) = recover`（卸载后
  回到加载前状态）。代码级强制 = **write 分级**:
  - `write: false`（探测式, f = id, 免逆）→ Theorem 7 平凡成立；
  - `write: true`（可写插件）→ **必须声明 `undo` 卸载回滚钩子**，否则拒绝加载。
  （DSH 400G 事故 = 插件执行无逆写效应、违反 Theorem 7 的实例。）
- **DSH 自进化完整循环**: `define(登记) → run(加载+快照) → stop(回滚) → undefine(注销)`。

与 gk_bashpy_loader.py 的关系: loader 管"能否加载 + 加载哪个源"（SHA256 pin 安全网），
本模块管"该插件是否被允许加载 + 生命周期 + 卸载回滚"（manifest 治理层）。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_host_paths import user_home as _user_home, win_abs_to_wsl  # noqa: E402

PKG = "zthl_bashpy_migrate"
# dev 源目录（环境变量优先 + 已知路径回退，Windows/WSL 双形态）。
# 2026-08-29: 补 CCF-A-Skills（prompt-based skill，Downloads 参考项目）——
# 修正 manifest 声明 dev:${CCF_A_SKILLS_DIR} 但环境变量未设导致 dev 源不可解析的配置缺口。
# 2026-10-29 去硬编码：默认根由**用户目录**派生（`gk_host_paths.user_home`，不写死用户名）；
# 两形态（`<home>/…` 与 `/mnt/c/Users/…`）由 `win_abs_to_wsl` 单源归一。
_HOME = _user_home()
_DEV_SOURCE_DIRS = (
    os.environ.get("ZTHL_BASHPY_DIR", ""),
    os.environ.get("CCF_A_SKILLS_DIR", ""),
    os.path.join(_HOME, "zthl-bashpy-migrate"),
    win_abs_to_wsl(os.path.join(_HOME, "zthl-bashpy-migrate")),
    os.path.join(_HOME, "Downloads", "CCF-A-Skills"),
    win_abs_to_wsl(os.path.join(_HOME, "Downloads", "CCF-A-Skills")),
)
GK_DBG_LOG = Path(__file__).resolve().parent / "gk_dbg.log"

# ── 插件 manifest 注册表（对齐 Definition 74 entry）─────────────────────────
# id        稳定标识（路由键，对齐 entry.id 的 reconciliation key）
# name/url  源（发布包名 / dev 目录）
# isolate   隔离注解：True = 需沙箱执行边界（对齐 §6.3；当前探测式全 False，预留）
# intercept 能力白名单（对齐 §6.3 能力最小化 + Definition 74 intercept 注解）
# config    版本 pin 引用（对齐 entry.config：绑定组件形成 effect function apply）
# disabled  管理性关闭（对齐 entry.disabled）
# write     False=探测式只读（f=id, 免逆）; True=可写（必须提供 undo）
# undo      write=True 的卸载回滚钩子（"module:func" 或可调用）；write=False 应为 None
MANIFESTS = {
    "bashpy-migrate": {
        "id": "bashpy-migrate",
        "name": "zthl-bashpy-migrate",
        "url": ("pip:zthl-bashpy-migrate | dev:${ZTHL_BASHPY_DIR} "
                "| npm:@zthl-harness/dsh-bashpy-migrate@0.2.3"),
        "isolate": False,
        "intercept": ("analyze", "verify", "audit",
                      # 生命周期子命令（2026-08-27 统一入口：cmd_migrate 转发 gk_bashpy_upgrade.py，
                      # 禁止裸 python 调用——R0.4 hook 拦截 + cap 白名单双门禁）
                      "status", "check", "upgrade", "rollback"),
        "config": {"pin_table": "_RELEASE_PINS", "dev_env": "ZTHL_BASHPY_DIR",
                   "entry": "zthl_bashpy_migrate.audit:bomb_scan",
                   # DSH npm 包装器登记（2026-08-26）：本地 tarball sha512
                   # （scripts/npm-bundle.sh 产出 npm-integrity.json），DSH 加载时对账——
                   # 零公共 registry 投毒面（对齐 §4.4 npm pin 预留）。
                   "integrity": ("sha512-422dcb92511bf7035798d58b6a9b06d73847adeb3fb78ea1e6e4adfa6dea1b8646b4708d5944c0c03c2fb11f01abe6961086c3c9488c50a365f33a6c2682537b")},
        "disabled": False,
        "write": False,
        "undo": None,
    },
    "swe-rb": {
        "id": "swe-rb",
        "name": "zthl-swe-rb",
        "url": ("pip:zthl-swe-rb | dev:${ZTHL_SWE_RB_DIR} "),
        "isolate": False,
        # 2026-08-31 骨架登记：SWE-RB 重构契约验证引擎（analyze/verify/audit），
        # 与 bashpy-migrate 同型统一安全网/注册/守护/类型格式；能力名 contract/
        # behaviour/redteam 与 bashpy 同名不同 pid（cap 白名单按 pid 区分）。
        # 信息边界（防 benchmark 卡 bug）：契约只来自 State A，tests/ 树与
        # 评分手册信息永不进入（analyze _SKIP_DIRS 含 tests/）。
        "intercept": ("analyze", "verify", "audit",
                      "status", "check", "upgrade", "rollback"),
        "config": {"dev_env": "ZTHL_SWE_RB_DIR",
                   "entry": "zthl_swe_rb.audit:redteam_scan",
                   "loader": "gk_swe_rb_loader.py",
                   "taxonomy_ref": "zthl-swe-rb/docs/refactoring-taxonomy.md"},
        "disabled": False,
        "write": False,
        "undo": None,
    },
    "paper-review": {
        "id": "paper-review",
        "name": "gk_paper_review",
        "url": "builtin:${SKILL_DIR}/scripts/gk_paper_review.py",
        "isolate": False,
        "intercept": ("paper-review",),   # 唯一入口 = CLI 命令（gatekeeper-cli.sh cmd_paper_review）
        "config": {"entry": "gk_paper_review:main",
                   # 评审准则单一事实源 = `references/paper-venues/<venue>.json`
                   # （2026-10-27 起下沉为档案；脚本只留引擎 + 校验）。多会议准则按 venue 归档，
                   # 轨道政策随各会议 CFP 固化后版本化（档案随私仓保留）。
                   "policy_ref": "<venue-policy>",
                   # 专业评审技能对接（2026-08-29）：CCF-A-Skills ccf-reviewer（拒稿点/补实验点/
                   # 写作漏洞）+ ccf-citation（related work taxonomy / missing citation risk list）。
                   # --subagent 评审 prompt 可引用其 reviewer_taxonomy/claim_evidence_matrix 深化。
                   "skill_ref": "ccf-a-skills",
                   "dep": "markitdown(pipx, ~/.local/bin — read_doc_gk 转换用)"},
        "disabled": False,
        "write": False,
        "undo": None,
    },
    "ccf-a-skills": {
        "id": "ccf-a-skills",
        "name": "CCF-A-Skills (kay-kuo, MIT)",
        "url": ("dev:${CCF_A_SKILLS_DIR} "
                "| git:https://github.com/kay-kuo/CCF-A-Skills.git"),
        "isolate": False,
        "intercept": ("ccf-reader", "ccf-writing", "ccf-figure-table", "ccf-citation",
                      "ccf-reviewer", "ccf-rebuttal", "ccf-presentation"),
        "config": {"dev_env": "CCF_A_SKILLS_DIR",
                   "entry": "ccf-reviewer:SKILL.md + ccf-citation:SKILL.md（paper-review skill_ref）",
                   "policy_ref": "CCF-A 评审政策（_shared/ reviewer_taxonomy + claim_evidence_matrix + evidence_policy + venue_profiles）",
                   "dep": "无（prompt-based skill，零运行时依赖）",
                   "shared": "_shared/（ccf_principles / output_schemas / reproducibility_checklist）"},
        "disabled": False,
        "write": False,
        "undo": None,
    },
    "gitnexus-skills": {
        "id": "gitnexus-skills",
        "name": "gitnexus bundled skills (npm 包 gitnexus 自带 12 份)",
        # 2026-09-17 登记（F-REV-101，用户裁定「101 可以」）。与 ccf-a-skills 同为**外部内容源**，
        # 但性质不同：CCF-A 是 prompt-based skill（登记的是**能力**）；本项是 npm 包 gitnexus
        # **自带的文档**（登记的是**内容源 + 消费方 + 能力面**）。
        # 消费方 = `subagent_runner:gx_guide_gk`（按需拉取官方 skill 全文）；其 topic 白名单
        # `_GX_SKILLS_TOPICS` 与本项 `intercept` **必须等值** —— 由 test_gk_plugin_manifest
        # 的 TestGitnexusSkillsRegistration 强制（防"声明 vs 实际"两处事实源漂移，
        # 同 TOOL_REGISTRY ↔ valid_tools 的既有守护模式）。
        # ⚠ **供应链 pin 缺口（显式登记，不静默）**：技能内容随 npm 包 gitnexus 分发，
        # 本机无法离线取得 tarball sha512 ⟹ 本项**未**登记 config.integrity（故 url **刻意
        # 不写 `npm:` 段** —— 写了会被 validate 的门禁正确拒绝，不规避门禁）。
        # 包级版本 pin 现归属 `<home>\.codex\state\reference-versions.yaml`（工具版本面）；
        # 若要在**本 manifest** 落 tarball pin，须联网取 npm `dist.integrity` 后补登记。
        "url": "dev:${GX_SKILLS_DIR} | pkg:gitnexus/skills (GX_JS 上溯 package.json 推导)",
        "isolate": False,
        "intercept": ("guide", "cli", "exploring", "debugging", "impact-analysis",
                      "refactoring", "pdg-query", "taint-analysis",
                      "plan", "review", "work", "lfg"),
        "config": {"dev_env": "GX_SKILLS_DIR",
                   "entry": "subagent_runner:gx_guide_gk",
                   "topics_source": "subagent_runner._GX_SKILLS_TOPICS（等值由测试强制）",
                   "dep": "npm 包 gitnexus（版本 pin 见 reference-versions.yaml）",
                   "pinning_gap": "npm tarball sha512 未登记（需联网取 npm dist.integrity 后补）"},
        "disabled": False,
        "write": False,
        "undo": None,
    },
    "git-workflow": {
        "id": "git-workflow",
        "name": "git-workflow (umbrella skill, MulanPSL-2.0, v2.1.0)",
        "url": "builtin:${SKILL_DIR}/../git-workflow/scripts/git-workflow.sh",
        "isolate": False,
        # 2026-08-30 技能加载安全网登记（加载安全网模版第三次应用，用户质询"分析 spz-gatekeeper 与
        # git-workflow 链接委托关系；git-workflow 升级标准技能加载安全网模式"）：
        # intercept = 七模块对外能力白名单（check_capability 入口用）；config.loader 指向技能侧
        # gk_gitworkflow_loader.py（SHA256 pin 五源分流，tampered → fail-closed exit 2）。
        # 委托关系（整理登记）：spz-gatekeeper SKILL.md Push/PR **强制 INVOKE git-workflow**
        # （token 轮换 + PR）；git-workflow push 反向委托 spz-gatekeeper cmd_push（F8.1 远端白名单
        # 门禁，GIT_WORKFLOW_DELEGATING=1 防循环哨兵）；git-workflow → github-push 子模块
        # （重试+限速）。双向委托经本登记纳入治理闭环。
        "intercept": ("push", "branch", "worktree", "release", "security", "cleanup",
                      "history", "selfcheck", "version"),
        "config": {"entry": "git-workflow.sh:main",
                   "loader": "git-workflow/scripts/gk_gitworkflow_loader.py",
                   "version": "2.1.0.post1",
                   "delegate": "spz-gatekeeper-r-sequence cmd_push (F8.1, 防循环哨兵 GIT_WORKFLOW_DELEGATING)",
                   "dep": "github-push 子模块（可选，重试+限速）"},
        "disabled": False,
        "write": False,
        "undo": None,
    },
}

_ACTIVE = {}  # pid -> {"snapshot": {...}}  运行时登记（undefine 注销）

_NPM_URL_PREFIX = "npm:"


def _dbg(msg: str) -> None:
    """GK_DBG_LOG 追加（可调试插桩）: 生命周期决策可审计。"""
    try:
        with open(GK_DBG_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{Path(__file__).name}] {msg}\n")
    except OSError:
        pass


def get_manifest(pid: str) -> dict | None:
    """按 id 取 manifest；未知 id 返回 None。"""
    return MANIFESTS.get(pid)


def validate_manifest(pid: str) -> dict:
    """manifest 自洽校验（define 门禁，Theorem 7 代码级强制）。

    返回 {"ok": bool, "pid": str, "errors": [...]}。
    - 未知 id → 拒绝（未登记插件无法获得能力，对齐 Cordis §6.3 能力最小化）
    - disabled → 拒绝（管理性关闭优先于一切）
    - write:true 且 undo 缺失 → 拒绝（无逆写效应 = DSH 400G 事故模式）
    """
    m = get_manifest(pid)
    if m is None:
        _dbg(f"validate[{pid}]: unknown plugin")
        return {"ok": False, "pid": pid, "errors": ["unknown plugin (未登记入口无法获得能力)"]}
    errors = []
    if m.get("disabled"):
        errors.append("plugin administratively disabled")
    if m.get("write") and not m.get("undo"):
        errors.append("write plugin requires undo (Theorem 7 recover 不变性: 无逆写效应 = DSH 400G 事故模式)")
    # 供应链 pin（npm 段）: url 任一 | 段以 npm: 开头 → 必须登记 config.integrity
    # （本地 tarball sha512 / pnpm lockfile integrity 哈希，对齐 Python 侧 _RELEASE_PINS
    # 的 SHA256 pin 语义 + §4.4 DSH 生态 npm pin 预留）。不登记 = 供应链不可信 → 拒绝加载。
    for seg in str(m.get("url", "")).split("|"):
        if seg.strip().startswith(_NPM_URL_PREFIX) and not (m.get("config") or {}).get("integrity"):
            errors.append("npm plugin requires config.integrity (tarball sha512, 供应链 pin)")
            break
    if errors:
        _dbg(f"validate[{pid}]: BLOCKED {errors}")
        return {"ok": False, "pid": pid, "errors": errors}
    _dbg(f"validate[{pid}]: PASS (write={m.get('write', False)})")
    return {"ok": True, "pid": pid, "errors": []}


def check_capability(pid: str, capability: str) -> dict:
    """能力白名单检查（intercept 注解的运行时强制）。

    调用点在把请求分发到插件前必须调用 —— 拒绝 manifest 白名单外的能力
    （对齐 Cordis §6.3 sandbox 能力最小化：插件无法经未登记入口获得能力）。
    """
    m = get_manifest(pid)
    if m is None:
        return {"ok": False, "pid": pid, "capability": capability,
                "error": "unknown plugin"}
    if capability not in m.get("intercept", ()):
        return {"ok": False, "pid": pid, "capability": capability,
                "error": f"capability '{capability}' not in whitelist {list(m['intercept'])}"}
    return {"ok": True, "pid": pid, "capability": capability}


def _inject_dev_dirs() -> list:
    """把 manifest 的 dev 源目录加入 sys.path（幂等）。返回本次实际注入的目录。"""
    injected = []
    for d in _DEV_SOURCE_DIRS:
        if d and Path(d).is_dir() and d not in sys.path:
            sys.path.insert(0, d)
            injected.append(d)
    return injected


def load_plugin(pid: str) -> dict:
    """define + run: 校验 manifest → 记录快照 → 登记 _ACTIVE。

    快照 = 加载前的 sys.path 视图（卸载时恢复），对应 track 记录逆 g 的最小实现：
    对探测式插件（write=false）加载副作用仅 dev 源 sys.path 注入，快照即恢复依据。
    """
    v = validate_manifest(pid)
    if not v["ok"]:
        return {"ok": False, "pid": pid, "error": "; ".join(v["errors"]),
                "action": "manifest BLOCKED（define 门禁未过）"}
    m = get_manifest(pid)
    snapshot = {"sys_path": tuple(sys.path), "injected": []}
    if not m.get("isolate"):
        snapshot["injected"] = _inject_dev_dirs()
    if pid in _ACTIVE:
        _dbg(f"load[{pid}]: already active (idempotent, snapshot kept)")
        return {"ok": True, "pid": pid, "status": "already_active",
                "manifest": m, "snapshot": snapshot}
    _ACTIVE[pid] = {"snapshot": snapshot}
    _dbg(f"load[{pid}]: define+run done, snapshot={snapshot}")
    return {"ok": True, "pid": pid, "status": "active",
            "manifest": m, "snapshot": snapshot}


def unload_plugin(pid: str) -> dict:
    """stop + undefine: 回滚快照（恢复 sys.path）→ 注销 _ACTIVE。

    - 幂等：未登记也返回 ok（note 说明），不报错。
    - 只读插件（write=false）：回滚 = 撤销 dev 源注入（f=id 的逆平凡成立）。
    - 可写插件（write=true）：本函数只回滚 sys.path 快照；业务 undo 钩子由
      调用点在写操作完成后显式执行（manifest.undo 声明其位置）。
    """
    rec = _ACTIVE.get(pid)
    if rec is None:
        return {"ok": True, "pid": pid, "reverted": False,
                "note": "not active (idempotent unload)"}
    snapshot = rec["snapshot"]
    for d in snapshot.get("injected", []):
        if d in sys.path:
            sys.path.remove(d)
    _ACTIVE.pop(pid, None)
    _dbg(f"unload[{pid}]: recover done, removed injected={snapshot.get('injected')}")
    return {"ok": True, "pid": pid, "reverted": True,
            "removed_from_sys_path": snapshot.get("injected")}


def list_manifests() -> list:
    """全部登记插件摘要（CLI list 用）。"""
    return [{"id": m["id"], "write": m.get("write", False),
             "intercept": list(m.get("intercept", ())),
             "disabled": m.get("disabled", False)}
            for m in MANIFESTS.values()]


def main(argv: list[str]) -> int:
    """CLI 入口（gatekeeper-cli.sh 接入用）: list / validate <pid> / load <pid> / unload <pid> / cap <pid> <cap>"""
    if not argv:
        print(__doc__.splitlines()[0])
        return 1
    cmd, rest = argv[0], argv[1:]
    if cmd == "list":
        print(json.dumps(list_manifests(), ensure_ascii=False, indent=2))
        return 0
    if cmd == "validate" and rest:
        out = validate_manifest(rest[0])
    elif cmd == "load" and rest:
        out = load_plugin(rest[0])
    elif cmd == "unload" and rest:
        out = unload_plugin(rest[0])
    elif cmd == "cap" and len(rest) >= 2:
        out = check_capability(rest[0], rest[1])
    else:
        print('{"ok":false,"error":"usage: list | validate <pid> | load <pid> | unload <pid> | cap <pid> <cap>"}')
        return 1
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok", False) else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
