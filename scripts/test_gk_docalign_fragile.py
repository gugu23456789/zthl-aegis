#!/usr/bin/env python3
"""doc-align 脆弱点收口 **红先臂**（`ECC-439C8B7CF048`，2026-10-13）。

三处脆弱点（2026-10-13 实测，非推测）：
  ① **docgen 产物对账缺失**：`docgen --check` 报 `DOC_DRIFT`（cli-protocol.md 被 `0fcbe84` 手工
     追加 2 行、`3c18f67` 手改 `**Commands**` 50→51，两次都未重跑 docgen），而 doc-align 的命令数
     四项检查**全 PASS** ⟹ 「doc-align 绿 / docgen 红」两面分裂，无任何门禁把两者绑定。
  ② **命令数三口径分裂**：测试 `src.count("_CMD_REG[")`=56（含 2 注释 + 3 读取）/ doc-align
     `_count_cmd_reg`（正则 `[a-z-]+`，仅赋值行）=51 / docgen（`cmd_\\w+` 函数 + 硬编码
     `pre_tool_check`）=51；且 `[a-z-]+` 一旦遇数字/大写命令名即**静默漏计**。
  ③ **`--summary` 截断**：`detail[:137]+"..."` 把多条目清单**从中间斩断**（papers_framework_drift
     的 7 项、comment_code_mismatch 的多文件），可操作信息丢失。

红跑沙箱只取 `scripts/`（**无 `references/`**）⟹ 依赖 `references/cli-protocol.md` 的守卫臂在沙箱内
恒真空绿，故**不入 `-k`**（见 `test_docgen_sync_guard_*`），真判别力在 accept / 主树。
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

SKILL_DIR = Path(__file__).resolve().parent.parent
CLI = SKILL_DIR / "gatekeeper-cli.sh"
STATE_FORMS = Path(__file__).resolve().parent / "test_gk_state_forms.py"


# ── ② D3：计数口径须容纳数字/大写命令名 ──────────────────────────────
def test_frag_counter_tolerates_digit_and_upper_names():
    """红先 ②a（D3）：`gk_doc_align._count_cmd_reg` 须认得数字/大写命令名。

    HEAD 的 `[a-z-]+` 对 `_CMD_REG[stage2]="…"` 命中 **0** ⟹ 命令名一旦含数字即**静默漏计**，
    而 docgen 用独立枚举、文档由 docgen 生成，二者会同错 ⟹ **无检查会发现**。
    """
    import gk_doc_align as D
    assert D._count_cmd_reg('_CMD_REG[stage2]="cmd_x|none|any|"') == 1, \
        "含【数字】的命令名被 `_count_cmd_reg` 静默漏计"
    assert D._count_cmd_reg('_CMD_REG[Probe]="cmd_y|none|any|"') == 1, \
        "含【大写】的命令名被 `_count_cmd_reg` 静默漏计"
    assert D._count_cmd_reg(CLI.read_text(encoding="utf-8")) >= 51


# ── ② D2：state_forms 常量与 doc-align 计数同源 ──────────────────────
def test_frag_state_forms_constant_single_source():
    """红先 ②b（D2）：`test_gk_state_forms.EXPECTED_CMD_REG_COUNT` 须与 doc-align 的
    `_count_cmd_reg`（赋值行口径）**同源**，且该测试不得再数子串 `_CMD_REG[`。

    HEAD：常量=**56**（`src.count("_CMD_REG[")` 子串口径，含注释/读取）vs `_count_cmd_reg`=**51**
    ⟹ 三口径分裂，正是 `54→56` 漂移能被藏住的机制。
    """
    import gk_doc_align as D
    src = STATE_FORMS.read_text(encoding="utf-8")
    m = re.search(r"(?m)^EXPECTED_CMD_REG_COUNT\s*=\s*(\d+)", src)
    assert m, "缺 EXPECTED_CMD_REG_COUNT 常量"
    actual = D._count_cmd_reg(CLI.read_text(encoding="utf-8"))
    assert int(m.group(1)) == actual, \
        "常量与 doc-align 计数不同源：常量=%s vs _count_cmd_reg=%s" % (m.group(1), actual)
    assert "_count_cmd_reg" in src, \
        "该测试未复用 doc-align 的单一计数口径（仍手写子串口径 `src.count(\"_CMD_REG[\")`）"


# ── ③ D7：summary 不得截断多条目清单 ────────────────────────────────
def test_frag_summary_lists_all_items():
    """红先 ③（D7）：`gk_doc_align.summarize` 不得把多条目 detail **从中间截断**。

    HEAD：`detail[:137]+"..."` ⟹ 8 个条目的清单被斩；修后须**全部条目**都在输出里。
    """
    import gk_doc_align as D
    items = ["ITEM%02d_XXXXXXXXXXXXXXXX" % i for i in range(8)]   # ≥200 字，确保 HEAD 的 [:137] 会截
    detail = "架构事实未反映: " + ", ".join(items)
    out = D.summarize({"issues": 0, "checks": [{"check": "c", "status": "WARN", "detail": detail}]})
    missing = [it for it in items if it not in out]
    assert not missing, "多条目 detail 被截断，丢失：%s" % missing
    assert max(len(l) for l in out.splitlines()) < 400, "换行后单行仍过长"


# ── ① D1：docgen 产物对账（**非红守卫臂**，沙箱内真空绿 ⟹ 不入 -k）──────
def test_docgen_sync_guard_check_passes():
    """守卫臂（**非红**）：`bash gatekeeper-cli.sh docgen --check` 须 rc=0
    （`references/cli-protocol.md` == docgen 产物）。

    ⚠ 红跑沙箱只取 `scripts/`（无 `references/`）⟹ 沙箱内恒「not found → rc 0」= 真空绿；
    真判别力在 accept / 主树（`references/` 在位）。故 **不入选红先集**。
    """
    from test_gk_edit_budget_metering import _wsl
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh docgen --check' % _wsl(SKILL_DIR)],
        capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, "docgen --check 报漂移：%s" % ((r.stdout + r.stderr)[:300])


# ── D1-b：probe 命令须有 docgen 可识别表头 banner（`ECC-FF16D8C2E5C7`，**保护区内落刀**）──
def test_frag_probe_cmd_has_docgen_banner():
    """红先（`ECC-FF16D8C2E5C7`）：`cmd_model_probe` / `cmd_phase_probe` 上方须有 docgen 可识别的
    表头 banner（`^# -{5,} <purpose> -{5,}$`），否则 docgen 提取不到 Purpose ⟹ 文档退化为
    `model probe` / `phase probe`（这正是 `0fcbe84` 手改文档、docgen --check 报漂移的根因）。

    落点 `cmd_model_probe` / `cmd_phase_probe` 在 **`PROTECTED_REGION::gate` 内** ⟹ 按 2026-09-27
    owner 裁定 A：行级 WARN + 强制留痕放行（commit/文档双留痕见同批 commit，主语带 `[PROTECTED-EDIT]`）。
    """
    import re as _re
    src = CLI.read_text(encoding="utf-8")
    for fn in ("cmd_model_probe", "cmd_phase_probe"):
        m = _re.search(r"(?m)^" + fn + r"\(\) \{", src)
        assert m, "缺函数 %s" % fn
        before = src[: m.start()].rstrip("\n").split("\n")[-5:]
        assert any(_re.match(r"^#\s*-{5,}\s*\S.*\s*-{5,}\s*$", ln) for ln in before), (
            "%s 上方缺 docgen 可识别 banner（Purpose 会退化成 '%s'）"
            % (fn, fn.replace("cmd_", "").replace("_", " ")))


# ── D8（`ECC-092EC2A72A3F`）：comment_code_mismatch 的系统假阳性收口 ──────────
def test_frag_comment_checker_skips_builtin_method_crossmodule(tmp_path):
    """红先（`ECC-092EC2A72A3F`）：`check_comment_code_mismatch` 的 ③（反引号 `name()`）与
    ②（`cmd_*`）**不得**把下列四类当「注释引用缺失」：

      · **内置函数** —— `str()` / `compile()` / `id()`（`dir(builtins)`）；
      · **方法调用** —— 本文件出现 `.<name>(`（如 `obj.exists()` 里的 `exists`）；
      · **跨模块 def** —— 本仓 `scripts/*.py` **别处**定义（`claim_ttl_s` 在 `gk_git_lease.py`）；
      · **CLI 内非命令 token** —— `case` 值 / 旗标（`cmd_target_mismatch` 是 `reason` 值）。

    HEAD 实测产 **16 项**（15 假 + 1 真 `cmd_code_fix`）—— 系统性假阳性把该闸的信噪比压到 1/16。
    """
    import gk_doc_align as D
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "other_mod.py").write_text(
        "def claim_ttl_s():\n    return 1\n\n\ndef cmd_set_nested(a, b):\n    return {}\n",
        encoding="utf-8")
    (tmp_path / "scripts" / "x.py").write_text(
        '"""refs: `str()` builtin / `exists()` method / `claim_ttl_s()` cross-module '
        '/ `cmd_set_nested` python-func."""\n'
        "p = obj.exists()\n", encoding="utf-8")
    (tmp_path / "gatekeeper-cli.sh").write_text(
        "cmd_foo() { :; }\n# reason=cmd_target_mismatch\n", encoding="utf-8")
    r = D.check_comment_code_mismatch(str(tmp_path))
    probs = [p for p in (r.get("problems") or []) if p.startswith("x.py")]
    assert not probs, "误报内置/方法/跨模块引用：%s" % probs
