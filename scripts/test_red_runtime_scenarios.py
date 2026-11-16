"""红队运行时**场景层剧本**臂（6 条，2026-11-11，红先）。

红先对照（HEAD 即 `445a8807`）：
  `git show HEAD:scripts/red_runtime/scenarios.py` → **不存在** ⟹ 本文件 ImportError（必红）；
  `python3 -c "import json;d=json.load(open('references/red-vectors.json'));print(sum(v.get('kind')=='runtime' for v in d['vectors']))"` → **0**。

判据（对齐 E1/E3/E4，不放宽）：
  · 每条剧本经 `runner.run_scenario` 在 `/tmp` 沙盘根执行，`invariant=exit_zero` ⟹ 防住才 PASS；
  · 登记表 `kind:"runtime"` 与 `scenarios.SCENARIOS` **双向差集为空**（禁孤儿/漏登记）；
  · 每条含正控（合法动作必须成功）——探针内部已断言，防判定器恒真。
"""
import json
import sys
import uuid
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

from red_runtime import runner, scenarios  # noqa: E402

LIMITS = {"mem_mb": 1024, "timeout_s": 180, "max_proc": 16}


def _runtime_registered():
    data = json.loads((ROOT / "references" / "red-vectors.json").read_text(encoding="utf-8"))
    return [v for v in (data.get("vectors") or []) if v.get("kind") == "runtime"]


def test_registry_and_impl_are_bijective():
    """登记表 ↔ 实现必须一一对应（缺一 = 有机制没落地 / 有剧本没登记）。"""
    registered = {v["id"] for v in _runtime_registered()}
    implemented = {s["id"] for s in scenarios.SCENARIOS}
    assert registered == implemented, {
        "registered_not_implemented": sorted(registered - implemented),
        "implemented_not_registered": sorted(implemented - registered),
    }


@pytest.mark.parametrize("sid", [s["id"] for s in scenarios.SCENARIOS])
def test_scenario_defense_holds(sid):
    """按 `SCENARIOS` 声明顺序逐条跑：防住 ⟹ exit_zero ⟹ PASS。"""
    root = "/tmp/gk-red-scen-%s-%s" % (sid, uuid.uuid4().hex[:8])
    rep = runner.run_scenario(scenarios.build(sid, root), root=root, limits=LIMITS)
    # `ok` 只表示"报告已生成"（恒 True）；**判定必须看 verdict**（2026-11-11 实测：
    #   原臂只看 ok ⟹ 探针 exit 1 的 FAIL 也被判 PASS，E4 形同虚设）。
    assert rep.get("verdict") == "PASS", json.dumps(rep, ensure_ascii=False)[:1500]
    assert rep.get("ok") is True, json.dumps(rep, ensure_ascii=False)[:1500]
    # 证据面必须落盘（可复盘）
    ev = Path(rep.get("evidence") or "")
    assert ev.is_file() and ev.stat().st_size > 0, rep


def test_all_scenarios_run_in_declared_order():
    """顺序臂：全部剧本按 `SCENARIOS` 顺序串行跑，逐条 PASS（禁「只跑通一条就算」）。"""
    seen = []
    for sc in scenarios.SCENARIOS:
        root = "/tmp/gk-red-order-%s-%s" % (sc["id"], uuid.uuid4().hex[:8])
        rep = runner.run_scenario(scenarios.build(sc["id"], root), root=root, limits=LIMITS)
        seen.append((sc["id"], rep.get("verdict") == "PASS"))   # 只看 ok 会把 FAIL 当 PASS
    assert all(ok for _, ok in seen), seen
    assert [s for s, _ in seen] == [s["id"] for s in scenarios.SCENARIOS]
