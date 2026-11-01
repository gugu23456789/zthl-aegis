#!/usr/bin/env python3
"""`gk_crossfull_two_phase` 的机检臂（2026-10-26）。

守什么：
  1. 只认**确定性车道**的 FAIL（L2/后R 的 FAIL 不得触发早停）；
  2. 确定性红 ⟹ **不启动**阶段 2（省一轮 LLM 车道）；
  3. 确定性绿 ⟹ 阶段 2 必跑；
  4. `--force` 可强制跑全量（诊断）；
  5. 输出里没有 crossfull JSON ⟹ fail-loud（不得静默当绿）。
"""
import json
import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_crossfull_two_phase as T  # noqa: E402


def _payload(steps):
    return {"ok": True, "audit_mode": "crossfull",
            "crossfull": {"base": "x", "steps": steps}}


def test_parse_ignores_progress_lines():
    out = "noise\n[L1] ok\n" + json.dumps(_payload([{"id": "L1", "status": "OK"}])) + "\n"
    p = T.parse_crossfull(out)
    assert p and p["audit_mode"] == "crossfull"


def test_parse_returns_none_on_garbage():
    assert T.parse_crossfull("progress only\n") is None


def test_det_failures_only_counts_deterministic_fail():
    p = _payload([
        {"id": "L1", "status": "FAIL"},
        {"id": "L10b", "status": "FAIL", "detail": "gbk"},
        {"id": "L2", "status": "FAIL"},      # LLM 车道：不算
        {"id": "L3", "status": "WARN"},
        {"id": "L5", "status": "NOT-RUN"},
        {"id": "L4", "status": "MANUAL"},
    ])
    assert [f[0] for f in T.deterministic_failures(p)] == ["L1", "L10b"]


def _fake_cli(tmp_path, phase1_steps, phase2_steps):
    marker = tmp_path / "phase2_called"
    script = tmp_path / "fake-cli.sh"
    script.write_text(textwrap.dedent("""\
        #!/usr/bin/env bash
        if [ "${GK_CROSSFULL_SUBAGENT:-1}" = "0" ]; then
          echo '%s'
        else
          echo called > %s
          echo '%s'
        fi
        """ % (json.dumps(_payload(phase1_steps)),
               marker.as_posix(),
               json.dumps(_payload(phase2_steps)))), encoding="utf-8")
    return script, marker


def test_red_phase1_stops_before_llm(tmp_path):
    script, marker = _fake_cli(tmp_path,
                               [{"id": "L10b", "status": "FAIL"}],
                               [{"id": "L1", "status": "OK"}])
    assert T.main(["--cli", str(script)]) == 3
    assert not marker.exists(), "确定性红时不得启动 LLM 车道"


def test_green_phase1_runs_full(tmp_path):
    script, marker = _fake_cli(tmp_path,
                               [{"id": "L10b", "status": "OK"}],
                               [{"id": "L2", "status": "OK"}])
    assert T.main(["--cli", str(script)]) == 0
    assert marker.exists()


def test_force_runs_full_even_when_red(tmp_path):
    script, marker = _fake_cli(tmp_path, [{"id": "L1", "status": "FAIL"}], [])
    assert T.main(["--cli", str(script), "--force"]) == 0
    assert marker.exists()


def test_missing_json_is_fail_loud(tmp_path):
    script = tmp_path / "bad.sh"
    script.write_text("#!/usr/bin/env bash\necho nope\n", encoding="utf-8")
    assert T.main(["--cli", str(script)]) == 2
