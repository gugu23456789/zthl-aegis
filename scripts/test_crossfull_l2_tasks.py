#!/usr/bin/env python3
"""R6a 红先：crossfull 的 L2 任务面**拆硬编码 → 单源取任务**（2026-09-21）。

缺陷（实测 + 读码）：`audit --crossfull` 的 L2 crossrev 任务串**写死在编排器里**
（gatekeeper-cli.sh `"L2 code-to-spec 审查: 近 %s commit 变更面…"`）⟹
  ① 编排器有自己的私有任务面，**既不读注入、也不读 `gate_data.narrow_tasks[]`**；
  ② 而 `narrow_tasks[]` 是 L5 元数据路由中枢（`gk_route_center.resolve_narrow`）**下发路由的
     事实源**，同时是 `advance → ECO-AUDIT` 的 node_guard 前置（要求非空）——于是出现
     "**门禁要清单、编排器却不吃清单**"的分叉；
  ③ 结果：审查任务面与"该审什么"无关，且无法把候选假设带进审查。

测法（同 R3/R5 的**片段抽取**）：从 CLI 抽出真实 `_l2_tasks` 片段 → 子进程跑 → 断言。
不跑 crossfull、不派 subagent ⟹ 零 API、零落盘。

四臂：
  1 注入优先  GK_CROSSFULL_L2_TASKS="a;b;c;d" → 取前 3 条，src=injected
  2 清单次之  无 env + narrow_tasks=[t1,t2]  → 逐字取清单 task，src=narrow_tasks
  3 兜底      无 env + 无清单                → src=default，且串内已格式化 base
  4 空清单    无 env + narrow_tasks=[]       → src=default（**不得**静默当 OK）
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLI = HERE.parent / "gatekeeper-cli.sh"

_RE = re.compile(
    r'(_L2_TASK_DEFAULT = \(.*?\n    return \[_L2_TASK_DEFAULT % base\], "default"\n)', re.S)


def _frag() -> str:
    txt = CLI.read_text(encoding="utf-8", errors="replace")
    m = _RE.search(txt)
    assert m, "CLI 中找不到 _l2_tasks 单源取任务片段（R6a 未接线？）"
    return m.group(1)


def _run(state_path: Path, env_extra: dict) -> dict:
    harness = ("import json,os\n_sf=%r\n%s\n_ts,_src=_l2_tasks('BASETAG')\n"
               "print(json.dumps({'ts':_ts,'src':_src}))\n" % (str(state_path), _frag()))
    env = dict(os.environ)
    env.pop("GK_CROSSFULL_L2_TASKS", None)
    env.update(env_extra)
    r = subprocess.run([sys.executable, "-c", harness], capture_output=True, text=True,
                       env=env, timeout=60)
    assert r.returncode == 0, r.stderr[-400:]
    return json.loads(r.stdout)


def _state(tmp_path: Path, nt) -> Path:
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"gate_data": {"narrow_tasks": nt}}, ensure_ascii=False),
                 encoding="utf-8")
    return p


class TestL2TaskSingleSource:
    def test_arm1_injected_wins_and_caps(self, tmp_path):
        out = _run(_state(tmp_path, [{"task": "from_list"}]), {"GK_CROSSFULL_L2_TASKS": "a;b;c;d"})
        assert out["src"] == "injected", out
        assert out["ts"] == ["a", "b", "c"], out  # 上限 3，防成本失控

    def test_arm2_narrow_tasks_second(self, tmp_path):
        out = _run(_state(tmp_path, [{"task": "t1"}, {"id": "x", "task": "t2"}]), {})
        assert out["src"] == "narrow_tasks", out
        assert out["ts"] == ["t1", "t2"], out  # 逐字取清单 task（与 L5 同源）

    def test_arm3_default_fallback(self, tmp_path):
        out = _run(_state(tmp_path, []), {})
        assert out["src"] == "default", out
        assert len(out["ts"]) == 1 and "BASETAG" in out["ts"][0], out

    def test_arm4_empty_list_not_silently_ok(self, tmp_path):
        out = _run(_state(tmp_path, []), {"GK_CROSSFULL_L2_TASKS": "   "})
        assert out["src"] == "default", out  # 空白注入 = 未注入，不得当 injected

    def test_wiring_call_site_uses_source(self):
        """接线断言：L2 调用点改吃来源（循环变量），**不再内联**任务串字面量。"""
        txt = CLI.read_text(encoding="utf-8", errors="replace")
        assert '"--role", "auditor", _t]' in txt, "L2 调用点未改为来源供给"
        assert txt.count("L2 code-to-spec 审查: 近") == 1, "任务串字面量须**单源**（仅兜底常量一处）"
