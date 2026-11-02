"""`gk_suba_tiers`（η_tier 单源实算）+ 收敛评估器「启动前预测」红先臂。

finding `ECC-46C8BF837715`（2026-10-08）：档位 3↔4 自动换挡半成品 ——
  ① η_tier 原只作**常数**活在计划文档（且已漂移：表记 3→4 `g_token=2.0×`，实网 = `3.0×`）；
  ② `tier_recommendation` **零消费者**（死输出）；
  ③ 无「升档是否划算」的**启动前预测**。

落刀前红：`gk_suba_tiers` 模块不存在（`ImportError`）、`_tier_rec` 无 `state_file` 形参
（传 3 参 ⟹ `TypeError`）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gk_suba_tiers as T  # noqa: E402
import gk_convergence_estimator as E  # noqa: E402


# ───────── η_tier 实算（单源 = live SUBA_TIERS）─────────
def test_tier_gain_34_matches_live_suba_tiers():
    """3→4 增益 = **live `SUBA_TIERS` 比值**（非文档常数表）—— 逐维钉死。

    文档 §8.19.2 记 `g_token=2.0×`（2026-09-14 快照）；现网 `1,000,000 → 3,000,000` ⟹ **3.0×**
    （2026-09-26 仅 tier4 ×1.5 破坏对称）⟹ 本臂即「常数漂移」的机检锚。
    """
    g = T.tier_gain(3, 4)
    assert g["g_token"] == 3.0, g
    assert g["g_item"] == 2.0, g
    assert g["g_turns"] == 2.0, g
    assert g["g_out"] == 2.0, g
    assert g["g_timeout"] == 1.5, g
    assert g["g_file"] == 1.0, g          # 30MB 饱和 ⟹ 该维无增益
    assert T.TIER_GAIN_34 == g, "TIER_GAIN_34 应与 tier_gain(3,4) 逐字一致（禁第二实现）"


def test_tier_gain_is_derived_not_hardcoded():
    """单源臂：改动 `SUBA_TIERS` 的值 ⟹ `tier_gain` 随动（证「实算」而非抄常数）。"""
    import copy
    saved = copy.deepcopy(T.SUBA_TIERS[4])
    try:
        T.SUBA_TIERS[4]["token_budget"] = 4_000_000     # 3 → 4 应为 4.0×
        assert T.tier_gain(3, 4)["g_token"] == 4.0, "tier_gain 未随 SUBA_TIERS 实算（抄了常数）"
    finally:
        T.SUBA_TIERS[4].clear()
        T.SUBA_TIERS[4].update(saved)


def test_tier_gain_unknown_tier_raises():
    """fail-loud 臂：未知档位 ⟹ `KeyError`（禁静默返回）。"""
    for bad in ((0, 4), (4, 5)):
        try:
            T.tier_gain(*bad)
        except KeyError:
            continue
        raise AssertionError("未知档位 %r 应抛 KeyError" % (bad,))


# ───────── 收敛评估器「启动前预测」─────────
def _state(tmp_path, budget_status):
    st = tmp_path / ("s_%s.json" % (budget_status or "none"))
    hist = [{"budget_status": budget_status}] if budget_status is not None else []
    st.write_text(json.dumps({"gate_data": {"subagent_history": hist}}), encoding="utf-8")
    return str(st)


def test_tier_rec_predicts_raise_on_budget_hard(tmp_path):
    """启动前预测（主臂）：上一次运行 `budget_status=hard` ⟹ 本档被 cap 截停 ⟹ `raise`。"""
    rec = E._tier_rec({"ok": True, "infinite": False, "n_star_hi": 1}, 3, _state(tmp_path, "hard"))
    assert rec["action"] == "raise", rec
    assert rec["reason"] == "LAST_RUN_BUDGET_HARD", rec
    p = rec["prediction"]
    assert p["predicted_raise_pays"] is True and p["last_budget_status"] == "hard", p
    assert p["eta_tier"]["g_token"] == 3.0, "预测未用实算 η_tier：%r" % (p,)


def test_tier_rec_holds_without_budget_stop(tmp_path):
    """负臂：`budget_status=ok` ⟹ 不误升（`hold`，预测 pays=False）。"""
    rec = E._tier_rec({"ok": True, "infinite": False, "n_star_hi": 1}, 3, _state(tmp_path, "ok"))
    assert rec["action"] == "hold", rec
    assert rec["prediction"]["predicted_raise_pays"] is False, rec


def test_tier_rec_item_exceeded_and_at_top(tmp_path):
    """边界臂：`item_exceeded` ⟹ 升档有据；已处最高档 ⟹ `at_top` 且不再要求升档。"""
    rec = E._tier_rec({"ok": True, "infinite": False, "n_star_hi": 1}, 3, _state(tmp_path, "item_exceeded"))
    assert rec["action"] == "raise" and rec["prediction"]["predicted_raise_pays"] is True, rec
    top = E._tier_rec({"ok": True, "infinite": False, "n_star_hi": 1}, 3,
                      _state(tmp_path, "hard"), current_tier=4)
    assert top["action"] == "hold", top
    assert top["prediction"]["at_top"] is True and top["prediction"]["predicted_raise_pays"] is False, top


def test_tier_rec_unknown_unchanged(tmp_path):
    """零回归臂：评估器不可用 ⟹ 仍 `unknown`（不因新逻辑改变既有三态）。"""
    rec = E._tier_rec({"ok": False, "error": "X"}, 3, _state(tmp_path, "hard"))
    assert rec["action"] == "unknown", rec


def test_gate_tier_recommendation_carries_prediction(tmp_path):
    """接线臂：`gate()` 的 `tier_recommendation` 现携带 `prediction`（消费面可见）。"""
    st = _state(tmp_path, "hard")
    out = E.gate(st)
    tr = out.get("tier_recommendation") or {}
    assert "prediction" in tr or tr.get("action") == "unknown", tr


# ══════════ 类级守卫：`SUBA_TIERS`「源码解析读取点」台账（`ECC-D59A6171817B`，2026-10-12）══════════
# 2026-10-08（`3f2807b` / `ECC-46C8BF837715`）把 `SUBA_TIERS` 从 `subagent_runner.py` 迁到本模块
# （即 `gk_suba_tiers.py`），但**只搬定义、未穷举旧读取点** ⟹ 留下「陈旧读取点」（表面像「多源」，
# 实则定义始终只有一处）。本类 = **读取点台账**：凡以「解析源码」方式取 `SUBA_TIERS` 的读取点，
# 其目标**必须** = 本模块；新增读取点须在本文件登记（否则本台账不替它兜底）。
#
# 旧家名构造为**拼接串**（不写字面量）—— 防本守卫文件自身被判成读取点。
_OLD_HOME = "subagent_runner" + ".py"


def test_stale_reader_inv_suba_tiers_single_definition():
    """不变量（非红）：`SUBA_TIERS` 的**赋值定义**只允许在本模块；旧家不得再有（防迁回 / 双源复活）。"""
    import ast as _ast

    def _defines(src: str) -> bool:
        return any(isinstance(n, _ast.Assign)
                   and any(isinstance(t, _ast.Name) and t.id == "SUBA_TIERS" for t in n.targets)
                   for n in _ast.walk(_ast.parse(src)))

    assert _defines((SCRIPTS / "gk_suba_tiers.py").read_text(encoding="utf-8")), \
        "真家 gk_suba_tiers.py 未定义 SUBA_TIERS（结构变了？）"
    assert not _defines((SCRIPTS / _OLD_HOME).read_text(encoding="utf-8")), (
        f"旧家 {_OLD_HOME} 又出现 SUBA_TIERS 赋值 ⟹ 双源复活（唯一事实源 = gk_suba_tiers.py）")


def test_stale_reader_red1_red_attacks_load_tiers_hits_home():
    """读取点①（**红先**）：`_red_attacks._load_tiers()` 须命中真家（非空 dict）。

    指旧家 ⟹ 返回 `None` ⟹ `red_ghost()` 发 `RED-GHOST-ERR/SUBA_TIERS 不可解析` ⟹
    **预算域越界（DoS）校验整段被跳过**（静默失效，无臂报错 —— 最隐蔽）。
    """
    import importlib
    ra = importlib.import_module("_red_attacks")
    assert ra._load_tiers(), (
        "`_red_attacks._load_tiers()` 未命中 SUBA_TIERS ⟹ 仍指旧家 ⟹ RED-GHOST 预算域校验静默失效")


def test_stale_reader_red2_dispatch_budget_runner_hits_home():
    """读取点②（**红先**）：`test_gk_dispatch_budget_single_source.RUNNER` 须指真家。"""
    import importlib
    db = importlib.import_module("test_gk_dispatch_budget_single_source")
    assert Path(db.TIERS_SRC).name == "gk_suba_tiers.py", \
        f"dispatch-budget 读取点仍指旧家：{db.TIERS_SRC}"


def test_stale_reader_reg_node_guard_fixture_hits_home():
    """读取点③（**非红**回归）：`test_gk_node_guard.py::TestSubagentTiers` 夹具须读真家。"""
    ng = (SCRIPTS / "test_gk_node_guard.py").read_text(encoding="utf-8")
    seg = ng[ng.index("class TestSubagentTiers"):ng.index("def test_four_tiers")]
    assert '"gk_suba_tiers.py"' in seg, "node-guard 夹具未指真家"
    assert ('"' + _OLD_HOME + '"') not in seg, "node-guard 夹具仍读旧家"

