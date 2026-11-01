"""test_gk_views.py — B9b 红先（2026-10-27，锚 RED-MIGRATE-INLINE）

把「多字段派生 / 格式化投影」类内联块收敛为显式动词（gk_views.py）：
conflict-view / budget-triple / violations-summary / doc-code-summary /
audit-summary-view / push-check-summary / balance / tier-action / tier-prediction。

每站都按**旧内联的失败面**建模：
  · 解析失败 ⟹ rc≠0（调用方 `2>/dev/null || echo <fallback>` 继续生效）
  · 个别站点旧式在 python 内 `except: print('{}')` ⟹ rc=0 + 输出 `{}`（逐站区分）
"""
import json
import os
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).parent / "gk_views.py"


def _run(*args, stdin_text="", env=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    p = subprocess.run([sys.executable, str(CLI)] + list(args),
                       input=stdin_text, capture_output=True, text=True,
                       encoding="utf-8", env=e)
    return p


class TestConflictView:
    def test_shape_and_defaults(self):
        p = _run("conflict-view", stdin_text='{"corrected": true, "candidates": ["a"]}')
        assert p.returncode == 0, p
        assert json.loads(p.stdout) == {
            "conflict": True, "corrected": True, "candidates": ["a"], "warning": ""}, p

    def test_minimal(self):
        assert json.loads(_run("conflict-view", stdin_text="{}").stdout) == {
            "conflict": True, "corrected": False, "candidates": [], "warning": ""}

    def test_bad_json_nonzero(self):
        assert _run("conflict-view", stdin_text="bad").returncode != 0


class TestBudgetTriple:
    def test_values(self):
        p = _run("budget-triple", stdin_text='{"budget": {"remaining": 3, "max": 9, "used": 6}}')
        assert p.returncode == 0 and p.stdout == "3 9 6\n", p

    def test_defaults_when_missing(self):
        assert _run("budget-triple", stdin_text='{"other": 1}').stdout == "-1 -1 0\n"
        assert _run("budget-triple", stdin_text='{"budget": {"remaining": 0}}').stdout == "0 -1 0\n"

    def test_bad_json_nonzero(self):
        assert _run("budget-triple", stdin_text="bad").returncode != 0


class TestViolationsSummary:
    def test_format(self):
        p = _run("violations-summary",
                 stdin_text='{"violations": [1,2], "max_s": 30, "pending_s": 12, "threshold_s": 25}')
        assert p.returncode == 0
        assert p.stdout == "violations=2 max=30s pending=12s threshold=25s\n", p

    def test_defaults(self):
        assert _run("violations-summary", stdin_text="{}").stdout == \
            "violations=0 max=0s pending=0s threshold=0s\n"

    def test_bad_json_nonzero(self):
        assert _run("violations-summary", stdin_text="bad").returncode != 0


class TestDocCodeSummary:
    def test_list_lengths_collapsed(self):
        p = _run("doc-code-summary", stdin_text=json.dumps({
            "doc_changes": ["a.md", "b.md"], "code_changes": ["x.py"],
            "unpushed_commits": 4, "entropy_rate": 1.5, "push_needed": True}))
        assert p.returncode == 0
        assert json.loads(p.stdout) == {
            "doc_changes": 2, "code_changes": 1, "unpushed_commits": 4,
            "entropy_rate": 1.5, "push_needed": True}, p

    def test_integers_pass_through(self):
        p = _run("doc-code-summary", stdin_text='{"doc_changes": 3, "code_changes": 2}')
        out = json.loads(p.stdout)
        assert out["doc_changes"] == 3 and out["code_changes"] == 2, out
        assert out["unpushed_commits"] == 0 and out["entropy_rate"] is None
        assert out["push_needed"] is False

    def test_bad_json_prints_braces_exit_zero(self):
        """旧式在 python 内 `except: print('{}')` ⟹ rc=0，不走 shell 兜底。"""
        p = _run("doc-code-summary", stdin_text="bad")
        assert p.returncode == 0 and p.stdout == "{}\n", p


class TestAuditSummaryView:
    def test_shape(self):
        p = _run("audit-summary-view", stdin_text=json.dumps(
            {"result": {"audit_summary": {"total_fields": 9, "matches": 7}}}))
        assert p.returncode == 0
        assert json.loads(p.stdout) == {"total": 9, "matches": 7}, p

    def test_defaults(self):
        assert json.loads(_run("audit-summary-view", stdin_text="{}").stdout) == \
            {"total": 0, "matches": 0}

    def test_bad_json_nonzero(self):
        assert _run("audit-summary-view", stdin_text="bad").returncode != 0


class TestPushCheckSummary:
    def test_shape(self):
        p = _run("push-check-summary", stdin_text=json.dumps({
            "doc_changes": 1, "code_changes": 2, "unpushed_commits": 3,
            "push_needed": True, "ignored": "x"}))
        assert p.returncode == 0
        assert json.loads(p.stdout) == {
            "doc_changes": 1, "code_changes": 2, "unpushed_commits": 3,
            "push_needed": True}, p

    def test_missing_key_nonzero(self):
        """旧式 `d['doc_changes']` 缺键抛 KeyError ⟹ rc≠0 ⟹ 调用方 `|| echo '{}'`。"""
        assert _run("push-check-summary", stdin_text='{"code_changes": 1}').returncode != 0


class TestBalance:
    def test_balance_from_env(self):
        p = _run("balance", env={"BAL_RESP": json.dumps(
            {"balance_infos": [{"total_balance": "12.34"}]})})
        assert p.returncode == 0 and p.stdout == "12.34\n", p

    def test_empty_or_bad_env_prints_empty(self):
        assert _run("balance", env={"BAL_RESP": ""}).stdout == "\n"
        assert _run("balance", env={"BAL_RESP": "bad"}).stdout == "\n"
        assert _run("balance", env={"BAL_RESP": '{"balance_infos": []}'}).stdout == "\n"


class TestTier:
    def test_action(self):
        assert _run("tier-action", stdin_text='{"tier_recommendation": {"action": "raise"}}'
                    ).stdout == "raise\n"
        assert _run("tier-action", stdin_text="{}").stdout == "\n"
        assert _run("tier-action", stdin_text='{"tier_recommendation": null}').stdout == "\n"

    def test_action_bad_json_nonzero(self):
        assert _run("tier-action", stdin_text="bad").returncode != 0

    def test_prediction_format(self):
        p = _run("tier-prediction", stdin_text=json.dumps(
            {"tier_recommendation": {"prediction": {
                "from_tier": 3, "to_tier": 4, "last_budget_status": "low",
                "predicted_raise_pays": True}}}))
        assert p.returncode == 0
        assert p.stdout == "3->4 b=low pays=True\n", p

    def test_prediction_missing_fields_prints_none(self):
        assert _run("tier-prediction", stdin_text="{}").stdout == \
            "None->None b=None pays=None\n"


class TestCrossRContext:
    """B9c：cmd_reflect 的跨 R 历史 markdown（旧式 python 内 print，失败由调用方 `|| echo ""`）。"""

    def _state(self, tmp_path, hist):
        sf = tmp_path / "state.json"
        sf.write_text(json.dumps({"history": hist}), encoding="utf-8")
        return str(sf)

    def test_last_three_phases(self, tmp_path):
        hist = [{"r_phase": "R%d" % i, "best": {"score": i}, "rejection_count": i,
                 "monitor_scores_summary": {"S": i}} for i in range(1, 5)]
        p = _run("cross-r-context", self._state(tmp_path, hist))
        assert p.returncode == 0, p
        # 旧式 `print(out)`：out 每行自带 \n，print 再补一个 ⟹ 尾部空行
        assert p.stdout == (
            "## Cross-R Phase History\n"
            "- R2: best_score=2, rejections=2, scores={'S': 2}\n"
            "- R3: best_score=3, rejections=3, scores={'S': 3}\n"
            "- R4: best_score=4, rejections=4, scores={'S': 4}\n"
            "\n")

    def test_defaults_for_missing_fields(self, tmp_path):
        p = _run("cross-r-context", self._state(tmp_path, [{}]))
        assert p.stdout == ("## Cross-R Phase History\n"
                            "- ?: best_score=N/A, rejections=0, scores={}\n\n")

    def test_empty_history_prints_blank(self, tmp_path):
        p = _run("cross-r-context", self._state(tmp_path, []))
        assert p.returncode == 0 and p.stdout == "\n"

    def test_missing_state_nonzero(self, tmp_path):
        assert _run("cross-r-context", str(tmp_path / "nope.json")).returncode != 0


class TestKeyMetaTail:
    """B9c：key status 的 key_rotation_log_tail 注入（旧式失败 `|| cat "$_KEY_META"`）。"""

    def test_merge_and_unicode(self):
        p = _run("key-meta-tail", stdin_text='{"a": 1, "中文": "值"}',
                 env={"KL_TAIL": '[{"key_type": "context"}]'})
        assert p.returncode == 0, p
        assert p.stdout == json.dumps(
            {"a": 1, "中文": "值", "key_rotation_log_tail": [{"key_type": "context"}]},
            indent=2, ensure_ascii=False) + "\n"

    def test_empty_env_falls_back_to_empty_list(self):
        p = _run("key-meta-tail", stdin_text='{"a": 1}', env={"KL_TAIL": ""})
        assert p.returncode == 0
        assert json.loads(p.stdout)["key_rotation_log_tail"] == []

    def test_bad_stdin_nonzero(self):
        assert _run("key-meta-tail", stdin_text="bad", env={"KL_TAIL": "[]"}).returncode != 0


class TestDepthMerge:
    """B9c：audit --depth 合并 python_depth（旧式失败 `|| echo "$depth_result"`）。"""

    def test_merge(self):
        p = _run("depth-merge", stdin_text='{"ok": true}',
                 env={"PY_DEPTH": '{"depth_checks": [1], "summary": {"total": 1}}'})
        assert p.returncode == 0, p
        assert p.stdout == ('{"ok": true, "python_depth": [1], '
                            '"python_depth_summary": {"total": 1}}\n')

    def test_missing_env_uses_empty_defaults(self):
        p = _run("depth-merge", stdin_text='{"ok": true}', env={"PY_DEPTH": ""})
        assert p.stdout == '{"ok": true, "python_depth": [], "python_depth_summary": {}}\n'

    def test_bad_stdin_nonzero(self):
        assert _run("depth-merge", stdin_text="bad", env={"PY_DEPTH": "{}"}).returncode != 0


class TestCiRunsTable:
    """B9d：ci-diagnose list 的表格（旧式空表 ⟹ 'No CI runs found'）。"""

    def test_header_and_rows(self):
        resp = json.dumps({"workflow_runs": [
            {"id": "1234567890", "status": "completed", "conclusion": "success",
             "head_branch": "master", "display_title": "ci: ok"},
        ]})
        p = _run("ci-runs-table", "5", stdin_text=resp)
        assert p.returncode == 0, p
        lines = p.stdout.split("\n")
        assert lines[0] == "{:<12} {:<8} {:<8} {:<30} {}".format(
            "RUN_ID", "STATUS", "RESULT", "BRANCH", "TITLE")
        assert lines[1] == "-" * 90
        assert lines[2] == "{:<12} {:<8} {:<8} {:<30} {}".format(
            "34567890", "complet", "\u2713 success", "master", "ci: ok")

    def test_empty_runs(self):
        p = _run("ci-runs-table", "5", stdin_text='{"workflow_runs": []}')
        assert p.returncode == 0 and p.stdout == "No CI runs found\n"

    def test_hint_when_full_page(self):
        runs = [{"id": str(i), "status": "completed", "conclusion": "failure",
                 "head_branch": "b", "display_title": "t"} for i in range(2)]
        p = _run("ci-runs-table", "2", stdin_text=json.dumps({"workflow_runs": runs}))
        assert "Use: ci-diagnose fetch <RUN_ID>  to download logs locally" in p.stdout

    def test_no_hint_when_partial_page(self):
        runs = [{"id": "1", "status": "completed", "conclusion": "failure",
                 "head_branch": "b", "display_title": "t"}]
        p = _run("ci-runs-table", "5", stdin_text=json.dumps({"workflow_runs": runs}))
        assert "Use: ci-diagnose fetch" not in p.stdout

    def test_bad_json_nonzero(self):
        assert _run("ci-runs-table", "5", stdin_text="bad").returncode != 0


class TestGnQuery:
    """B9d：gitnexus query 结果判真与结构化提取（旧式失败面 ⟹ 退化为 rg）。"""

    def test_has_results_true(self):
        p = _run("gn-has-results", stdin_text='{"definitions": [{"name": "f"}]}')
        assert p.returncode == 0 and p.stdout == ""

    def test_has_results_false(self):
        assert _run("gn-has-results", stdin_text='{"processes": [], "definitions": []}'
                    ).returncode != 0
        assert _run("gn-has-results", stdin_text="bad").returncode != 0

    def test_extract_lines(self):
        payload = {"processes": [{"summary": "flow", "priority": 0.5}],
                   "process_symbols": [{"filePath": "a.py", "startLine": 1, "endLine": 2,
                                        "name": "fn", "module": "m"}],
                   "definitions": [{"filePath": "b.py", "startLine": 3, "endLine": 4,
                                    "type": "func", "name": "g"}]}
        p = _run("gn-query-results", stdin_text=json.dumps(payload))
        assert p.returncode == 0, p
        assert p.stdout == ("[process] flow (priority=0.500)\n"
                            "a.py:1-2 [fn] m\n"
                            "b.py:3-4 [func:g]\n")

    def test_extract_empty_prints_blank(self):
        p = _run("gn-query-results", stdin_text='{"processes": [], "definitions": []}')
        assert p.returncode == 0 and p.stdout == "\n"

    def test_extract_bad_json_nonzero(self):
        assert _run("gn-query-results", stdin_text="bad").returncode != 0


class TestReleaseTag:
    """B9d：release-check 的 tag 提取（旧式全捕获 ⟹ 恒 rc=0）。"""

    def test_tag_when_id_present(self):
        p = _run("release-tag", stdin_text='{"id": 1, "tag_name": "v1.2.3"}')
        assert p.returncode == 0 and p.stdout == "v1.2.3\n"

    def test_no_id_prints_nothing(self):
        p = _run("release-tag", stdin_text='{"tag_name": "v1.2.3"}')
        assert p.returncode == 0 and p.stdout == ""

    def test_rate_limit_message_prints_nothing(self):
        p = _run("release-tag", stdin_text='{"message": "API rate limit exceeded"}')
        assert p.returncode == 0 and p.stdout == ""

    def test_bad_json_still_zero(self):
        p = _run("release-tag", stdin_text="bad")
        assert p.returncode == 0 and p.stdout == ""


class TestStationProjection:
    """B9e：cmd_advance 的车站投影（旧式解析失败 ⟹ rc≠0，但调用处先经 `valid` 判过）。"""

    def test_projection(self):
        p = _run("station-projection", stdin_text=json.dumps(
            {"station": "S1", "route": "r", "prev": "S0", "next": "S2", "gate": "g",
             "checklist": ["a"], "safety": ["b"], "extra": "drop"}))
        assert p.returncode == 0, p
        assert json.loads(p.stdout) == {
            "station": "S1", "route": "r", "prev": "S0", "next": "S2",
            "gate": "g", "checklist": ["a"], "safety": ["b"]}

    def test_defaults(self):
        p = _run("station-projection", stdin_text="{}")
        assert json.loads(p.stdout) == {
            "station": "", "route": "", "prev": "", "next": "",
            "gate": "", "checklist": [], "safety": []}

    def test_bad_json_nonzero(self):
        assert _run("station-projection", stdin_text="bad").returncode != 0


class TestSelfcheckPyChecks:
    """B9e：self-check 的 python 检查合并（旧式全捕获 ⟹ 恒 rc=0）。"""

    def test_includes_gitnexus_and_joins(self):
        """2026-11-01：gitnexus 判定改由 python 元数据面产出 ⟹ 视图**不再排除**（防伪红/防双写）。"""
        payload = {"checks": [{"check": "a", "status": "PASS"},
                              {"check": "gitnexus", "status": "WARN"},
                              {"check": "b", "status": "FAIL"}]}
        p = _run("selfcheck-py-checks", stdin_text=json.dumps(payload))
        assert p.returncode == 0, p
        assert p.stdout == ('{"check": "a", "status": "PASS"},'
                            '{"check": "gitnexus", "status": "WARN"},'
                            '{"check": "b", "status": "FAIL"}\n')

    def test_no_checks_prints_blank(self):
        p = _run("selfcheck-py-checks", stdin_text='{"checks": []}')
        assert p.returncode == 0 and p.stdout == "\n"

    def test_bad_json_still_zero(self):
        p = _run("selfcheck-py-checks", stdin_text="bad")
        assert p.returncode == 0 and p.stdout == ""


class TestAuditLink:
    """B9e：self-check 引用 audit --state 摘要（旧式异常 ⟹ 'NOT_RUN'）。"""

    def _state(self, tmp_path, data):
        sf = tmp_path / "state.json"
        sf.write_text(json.dumps(data), encoding="utf-8")
        return str(sf)

    def test_with_summary(self, tmp_path):
        sf = self._state(tmp_path, {"gate_data": {"audit_state_result": {
            "audit_summary": {"matches": 7, "total_fields": 9}}}})
        p = _run("audit-link", sf)
        assert p.returncode == 0 and p.stdout == (
            "audit_state matches=7/9 evidence_source=state(unverified)\n")

    def test_missing_result_not_run(self, tmp_path):
        p = _run("audit-link", self._state(tmp_path, {"gate_data": {}}))
        assert p.returncode == 0 and p.stdout == "NOT_RUN\n"

    def test_missing_state_not_run(self, tmp_path):
        p = _run("audit-link", str(tmp_path / "nope.json"))
        assert p.returncode == 0 and p.stdout == "NOT_RUN\n"

    def test_partial_summary_defaults_zero(self, tmp_path):
        sf = self._state(tmp_path, {"gate_data": {"audit_state_result": {}}})
        assert _run("audit-link", sf).stdout == "NOT_RUN\n"
        sf2 = tmp_path / "state2.json"
        sf2.write_text(json.dumps({"gate_data": {"audit_state_result": {
            "audit_summary": {}}}}), encoding="utf-8")
        assert _run("audit-link", str(sf2)).stdout == (
            "audit_state matches=0/0 evidence_source=state(unverified)\n")

    # ── B3b 显示面双读（2026-10-30 收口）：登记存在时透出核验态 ──────────────
    def test_registry_present_ok_surfaces_verified(self, tmp_path):
        import gk_audit_registry as R
        sf = self._state(tmp_path, {"gate_data": {"audit_state_result": {
            "audit_summary": {"matches": 7, "total_fields": 9}}}})
        assert R.register(sf).get("ok"), "登记 sidecar 未落盘"
        assert _run("audit-link", sf).stdout == (
            "audit_state matches=7/9 evidence_source=state+registry(verified)\n")

    def test_registry_mismatch_surfaces_reason(self, tmp_path):
        import gk_audit_registry as R
        sf = self._state(tmp_path, {"gate_data": {"audit_state_result": {
            "audit_summary": {"matches": 7, "total_fields": 9}}}})
        assert R.register(sf).get("ok")
        d = json.loads(Path(sf).read_text(encoding="utf-8"))
        d["gate_data"]["audit_state_result"]["audit_summary"]["matches"] = 8   # 篡改证据
        Path(sf).write_text(json.dumps(d), encoding="utf-8")
        out = _run("audit-link", sf).stdout
        assert "state+registry(mismatch:" in out, out


class TestGnContextSummary:
    """B9f：gitnexus context 计数（guard-edit 用 calls/called_by，monitor 用 sym 前缀且顺序相反）。"""

    def test_plain_counts(self):
        p = _run("gn-context-summary", stdin_text=json.dumps(
            {"incoming": {"calls": [1, 2]}, "outgoing": {"calls": [1]}}))
        assert p.returncode == 0 and p.stdout == "called_by=2 calls=1\n"

    def test_sym_counts_use_dict_len(self):
        """旧式对 incoming/outgoing **字典**取 len（不是 calls 列表长）——逐字保留。"""
        p = _run("gn-context-summary-sym", "fn", stdin_text=json.dumps(
            {"incoming": {"calls": [], "extra": 1}, "outgoing": {}}))
        assert p.returncode == 0 and p.stdout == "fn: calls=0 called_by=2\n"

    def test_bad_json_prints_blank(self):
        assert _run("gn-context-summary", stdin_text="bad").stdout == "\n"
        assert _run("gn-context-summary-sym", "fn", stdin_text="bad").stdout == "\n"

    def test_none_section_prints_blank(self):
        assert _run("gn-context-summary", stdin_text='{"incoming": null}').stdout == "\n"


class TestGnImpactLine:
    """B9f：gitnexus impact 单行（旧式 except ⟹ 不输出）。"""

    def test_line(self):
        p = _run("gn-impact-line", stdin_text=json.dumps(
            {"target": {"name": "fn"}, "impactedCount": 3, "risk": "high"}))
        assert p.returncode == 0 and p.stdout == "fn impact=3 risk=high\n"

    def test_defaults(self):
        assert _run("gn-impact-line", stdin_text="{}").stdout == " impact=0 risk=\n"

    def test_bad_json_no_output(self):
        p = _run("gn-impact-line", stdin_text="bad")
        assert p.returncode == 0 and p.stdout == ""


class TestMonitorFailItems:
    """B9f：monitor 检查串（非合法 JSON 的片段串）→ FAIL 项逐行。"""

    def test_fragment_string(self):
        frag = '{"item":"a","status":"PASS"},{"item":"b","status":"FAIL","evidence":"x:1"},'
        p = _run("monitor-fail-items", stdin_text=frag)
        assert p.returncode == 0, p
        assert p.stdout == '{"item": "b", "evidence": "x:1"}\n'

    def test_unparseable_yields_nothing(self):
        p = _run("monitor-fail-items", stdin_text="not-json")
        assert p.returncode == 0 and p.stdout == ""

    def test_fail_without_evidence(self):
        p = _run("monitor-fail-items", stdin_text='{"item":"c","status":"FAIL"},')
        assert p.stdout == '{"item": "c", "evidence": ""}\n'


class TestGitnexusBaseline:
    """B9f：monitor 注入的 gitnexus 基线段（nodes 空/unavailable ⟹ 空）。"""

    def _state(self, tmp_path, gn):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"gate_data": {"gitnexus": gn}}), encoding="utf-8")
        return str(sf)

    def test_available(self, tmp_path):
        sf = self._state(tmp_path, {"nodes": 10, "edges": 20, "clusters": 2,
                                    "flows": 3, "stage": "S1", "timestamp": "t",
                                    "extra": "drop"})
        p = _run("gitnexus-baseline", sf)
        assert p.returncode == 0
        assert json.loads(p.stdout) == {"nodes": 10, "edges": 20, "clusters": 2,
                                        "flows": 3, "stage": "S1", "timestamp": "t"}

    def test_unavailable_prints_blank(self, tmp_path):
        assert _run("gitnexus-baseline", self._state(tmp_path, {"nodes": "unavailable"})).stdout == "\n"
        assert _run("gitnexus-baseline", self._state(tmp_path, {})).stdout == "\n"

    def test_missing_state_nonzero(self, tmp_path):
        assert _run("gitnexus-baseline", str(tmp_path / "no.json")).returncode != 0


class TestLlmAnalysisMerge:
    """B9f：cross-R llm_analysis 合并（解析失败 ⟹ {text:raw}）。"""

    def test_object_analysis(self):
        p = _run("llm-analysis-merge", stdin_text='{"a": 1}',
                 env={"LLM_ANALYSIS": '{"pattern_assessment": "stable"}'})
        assert p.returncode == 0
        assert json.loads(p.stdout) == {"a": 1,
                                        "llm_analysis": {"pattern_assessment": "stable"}}

    def test_free_text_analysis(self):
        p = _run("llm-analysis-merge", stdin_text='{"a": 1}', env={"LLM_ANALYSIS": "raw text"})
        assert json.loads(p.stdout)["llm_analysis"] == {"text": "raw text"}

    def test_unicode_preserved(self):
        p = _run("llm-analysis-merge", stdin_text='{"t": "中文"}', env={"LLM_ANALYSIS": "x"})
        assert "中文" in p.stdout

    def test_bad_stdin_nonzero(self):
        assert _run("llm-analysis-merge", stdin_text="bad", env={"LLM_ANALYSIS": "x"}
                    ).returncode != 0


class TestRedteamSummary:
    """B9f：redteam 审计摘要（旧式缺键 KeyError ⟹ 调用方 `|| echo '{}'`）。"""

    def _state(self, tmp_path):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"stage": "ECO-DOC"}), encoding="utf-8")
        return str(sf)

    def test_summary(self, tmp_path):
        findings = {"total_findings": 2, "severity_counts": {"High": 2},
                    "mitre_mappings": [{"id": "TA0001"}]}
        p = _run("redteam-summary", "AUDIT-1", self._state(tmp_path),
                 stdin_text=json.dumps(findings))
        assert p.returncode == 0, p
        assert json.loads(p.stdout) == {"audit_id": "AUDIT-1", "type": "redteam",
                                        "current_stage": "ECO-DOC", "total": 2,
                                        "by_severity": {"High": 2}, "mitre": 1}

    def test_missing_key_nonzero(self, tmp_path):
        assert _run("redteam-summary", "A", self._state(tmp_path),
                    stdin_text='{"total_findings": 0}').returncode != 0


class TestDepthResult:
    """B9f：audit --depth 的 result 组装（env 驱动）。"""

    def test_all_env(self):
        p = _run("depth-result", env={"GN_CTX": "c", "GN_DET": "d",
                                      "GN_TARGET": "t", "GN_PROD": "true"})
        assert p.returncode == 0
        assert json.loads(p.stdout) == {"ok": True, "audit_mode": "depth", "target": "t",
                                        "gitnexus_context": "c", "detect_changes": "d",
                                        "production_consumer": "true",
                                        "dead_code_risk": "low"}

    def test_empty_env_unknown_risk(self):
        d = json.loads(_run("depth-result", env={}).stdout)
        assert d["dead_code_risk"] == "unknown" and d["target"] == ""


class TestAttribution:
    """B9f：attribution 的 prompt 转义与 logprobs 报告。"""

    def test_prompt_truncated_after_dumps(self):
        """旧式 `json.dumps(prompt)[:7000]`：**先转义再截断**（与 escape --limit 语义不同）。"""
        prompt = "a" * 8000
        p = _run("attribution-prompt", stdin_text=prompt)
        assert p.returncode == 0
        assert p.stdout.rstrip("\n") == json.dumps(prompt)[:7000]

    def test_prompt_with_quote_now_escaped(self):
        p = _run("attribution-prompt", stdin_text="it's \"fine\"")
        assert p.stdout.rstrip("\n") == json.dumps("it's \"fine\"")

    def test_logprobs_report(self):
        import math
        resp = {"model": "m", "choices": [{"message": {"content": "hi"},
                "logprobs": {"content": [
                    {"token": "h", "top_logprobs": [{"logprob": -0.1}]},
                    {"token": "i", "top_logprobs": [{"logprob": -3.0}]}]}}]}
        p = _run("attribution-report", stdin_text=json.dumps(resp))
        assert p.returncode == 0, p
        d = json.loads(p.stdout)
        assert d["model"] == "m" and d["content"] == "hi"
        assert d["total_tokens"] == 2 and d["attr_points"] == 1
        assert d["attribution"] == [{"pos": 0, "token": "h",
                                     "confidence": round(math.exp(-0.1), 4)}]

    def test_bad_response_nonzero(self):
        assert _run("attribution-report", stdin_text="bad").returncode != 0


class TestAchievementsConfig:
    """B9f：成就配置合并（默认 ⊕ state 覆盖）。"""

    def test_merge(self, tmp_path):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"achievement_config": {"a": {"label": "自定义"}}}),
                      encoding="utf-8")
        defaults = json.dumps({"a": {"label": "A", "msg": "m"}, "b": {"label": "B"}})
        p = _run("achievements-config", str(sf), env={"ACH_DEFAULTS": defaults})
        assert p.returncode == 0, p
        assert json.loads(p.stdout) == {"a": {"label": "自定义", "msg": "m"},
                                        "b": {"label": "B"}}

    def test_missing_state_uses_defaults(self, tmp_path):
        defaults = json.dumps({"a": {"label": "A"}})
        p = _run("achievements-config", str(tmp_path / "no.json"),
                 env={"ACH_DEFAULTS": defaults})
        assert json.loads(p.stdout) == {"a": {"label": "A"}}


class TestAuditSummaryBuild:
    """B9g：audit 主摘要组装（state 读 + 两参注入）。"""

    def _state(self, tmp_path, obj):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(obj), encoding="utf-8")
        return str(sf)

    def test_full_state(self, tmp_path):
        long_target = "T" * 80
        st = self._state(tmp_path, {
            "stage": "R5",
            "history": [{"hook_block_log": [{"kind": "escalation", "tool": "Edit",
                                             "target": "arch"}]}, {}],
            "gate_data": {
                "edit_count": 3,
                "rejected_edits": ["r"],
                "human_calibration_log": [{}, {}],
                "best": {"score": 91},
                "project_type": "standing",
                "hook_block_log": [
                    {"kind": "escalation", "tool": "Bash", "target": long_target},
                    {"kind": "warn"},
                ],
            },
            "monitor_scores": {"m1": {"score": 90, "verdict": "PASS"}},
        })
        p = _run("audit-summary", "AUDIT-1", "performance", st)
        assert p.returncode == 0, p
        assert json.loads(p.stdout) == {
            "audit_id": "AUDIT-1", "audit_type": "performance",
            "history_count": 2, "edit_count": 3, "rejected_count": 1,
            "calibration_count": 2, "best_score": 91, "current_stage": "R5",
            "project_type": "standing",
            "monitor_scores": {"m1": {"score": 90, "verdict": "PASS"}},
            "intent_log": {"current_intents": 2, "current_escalations": 1,
                           "archived_cross_r_intents": 1, "archived_escalations": 1,
                           "latest_chains": [
                               {"tool": "Bash", "target": "T" * 60},
                               {"tool": "Edit", "target": "arch"}]},
        }

    def test_missing_state_empty_defaults(self, tmp_path):
        p = _run("audit-summary", "A", "financial", str(tmp_path / "no.json"))
        assert p.returncode == 0, p
        d = json.loads(p.stdout)
        assert d["history_count"] == 0 and d["edit_count"] == 0
        assert d["best_score"] is None and d["current_stage"] is None
        assert d["monitor_scores"] == {}
        assert d["intent_log"]["current_intents"] == 0

    def test_bad_state_falls_back_to_empty(self, tmp_path):
        sf = tmp_path / "bad.json"
        sf.write_text("{broken", encoding="utf-8")
        p = _run("audit-summary", "A", "redteam", str(sf))
        assert p.returncode == 0, p
        assert json.loads(p.stdout)["history_count"] == 0


class TestRedteamFindings:
    """B9g：redteam findings 收集（state 三域 + ATT&CK 映射）。"""

    def _state(self, tmp_path, obj):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(obj), encoding="utf-8")
        return str(sf)

    def test_collect_three_sources(self, tmp_path):
        import hashlib
        sc = [{"field": "x", "match": False}]
        dc = [{"doc": "d", "check": "c", "match": True}]
        st = self._state(tmp_path, {"gate_data": {
            "audit_state_result": {"state_checks": sc},
            "audit_docs_result": {"docs_checks": dc},
            "gitnexus": {"nodes": "unavailable", "edges": 1, "context": 1,
                         "impact": 1, "query": 1},
        }})
        p = _run("redteam-findings", st)
        assert p.returncode == 0, p
        d = json.loads(p.stdout)
        assert d["total_findings"] == 3
        assert d["severity_counts"] == {"Critical": 0, "High": 0, "Medium": 2,
                                        "Low": 0, "Info": 1}
        assert [f["id"] for f in d["findings"]] == ["VLN-001", "VLN-002", "VLN-003"]
        assert d["findings"][0]["severity"] == "Medium"
        assert d["findings"][1]["severity"] == "Info"
        assert d["findings"][2]["title"] == "GitNexus nodes unavailable"
        assert d["findings"][0]["evidence_hash"] == hashlib.sha256(
            json.dumps(sc[0], sort_keys=True).encode()).hexdigest()[:16]
        assert d["findings"][0]["detail"] == json.dumps(sc[0])
        # E19：显示面显式标注证据来源（只读 state，未做登记封印核验）
        assert d["evidence_source"] == "state(unverified)"
        assert [m["id"] for m in d["mitre_mappings"]] == [
            "TA0001", "TA0004", "TA0005", "TA0007"]

    def test_all_gitnexus_present_no_finding(self, tmp_path):
        st = self._state(tmp_path, {"gate_data": {"gitnexus": {
            "nodes": 1, "edges": 2, "context": 3, "impact": 4, "query": 5}}})
        d = json.loads(_run("redteam-findings", st).stdout)
        assert d["total_findings"] == 0
        assert d["severity_counts"] == {"Critical": 0, "High": 0, "Medium": 0,
                                        "Low": 0, "Info": 0}

    def test_registry_status_included_when_present(self, tmp_path):
        """B3b 显示面双读（2026-10-30）：登记在 ⟹ findings 回包带 registry + 来源升级。"""
        import gk_audit_registry as R
        st = self._state(tmp_path, {"gate_data": {
            "audit_state_result": {"state_checks": []}}})
        assert R.register(st).get("ok"), "登记 sidecar 未落盘"
        d = json.loads(_run("redteam-findings", st).stdout)
        assert d.get("registry", {}).get("ok") is True, d
        assert d["evidence_source"] == "state+registry(verified)", d

    def test_missing_state_all_gitnexus_missing(self, tmp_path):
        """旧式默认值 = `'unavailable'` ⟹ 空 state 时 5 个 gitnexus 键各产一条。"""
        p = _run("redteam-findings", str(tmp_path / "no.json"))
        assert p.returncode == 0, p
        d = json.loads(p.stdout)
        assert d["total_findings"] == 5
        assert [f["title"] for f in d["findings"]] == [
            "GitNexus %s unavailable" % k for k in
            ("nodes", "edges", "context", "impact", "query")]
        assert d["severity_counts"] == {"Critical": 0, "High": 0, "Medium": 5,
                                        "Low": 0, "Info": 0}
        assert len(d["mitre_mappings"]) == 4


class TestRedteamReport:
    """B9g：六段模板报告（stdin=findings，state 只取 stage）。"""

    def _state(self, tmp_path, stage="R5"):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"stage": stage}), encoding="utf-8")
        return str(sf)

    def _findings(self):
        return {"findings": [{"id": "VLN-001", "title": "T1", "severity": "High",
                              "attack_tech": "TA0005", "attack_name": "Defense Evasion",
                              "evidence_hash": "abc123", "detail": "d" * 300,
                              "match": False}],
                "severity_counts": {"Critical": 0, "High": 1, "Medium": 0,
                                    "Low": 0, "Info": 0},
                "total_findings": 1,
                "mitre_mappings": [{"id": "TA0001", "name": "Initial Access",
                                    "desc": "x"}]}

    def test_six_sections(self, tmp_path):
        p = _run("redteam-report", "AUDIT-9", self._state(tmp_path),
                 stdin_text=json.dumps(self._findings()))
        assert p.returncode == 0, p
        out = p.stdout
        assert out.startswith("# ECC-REDTEAM: AUDIT-9\n")
        for sec in ("## 1. Executive Summary", "## 2. Scope & Methodology",
                    "## 3. Findings by Severity", "## 4. Detailed Findings",
                    "## 5. Attack Chain", "## 6. Appendix"):
            assert sec in out
        assert "- Target: R5" in out
        assert "- Total Findings: 1" in out
        assert "- Risk Rating: High" in out
        assert "Step 1: T1 (Defense Evasion)" in out
        assert "  - VLN-001: `sha256:abc123`" in out
        assert "**Description:** " + "d" * 200 + "\n" in out
        assert "- TA0001 (Initial Access): x" in out

    def test_no_findings_no_chain(self, tmp_path):
        empty = {"findings": [], "severity_counts": {}, "total_findings": 0,
                 "mitre_mappings": []}
        out = _run("redteam-report", "A", self._state(tmp_path),
                   stdin_text=json.dumps(empty)).stdout
        assert "No attack chain" in out
        assert "- Risk Rating: Medium" in out

    def test_bad_stdin_nonzero(self, tmp_path):
        assert _run("redteam-report", "A", self._state(tmp_path),
                    stdin_text="bad").returncode != 0


class TestAuditReportAssemble:
    """B9g：§1-§3 报告拼装（env 传主体，date 由 shell 注入）。"""

    def test_conclusion_and_data(self):
        p = _run("audit-report-assemble", "AUDIT-1", "performance", "2026-10-28",
                 env={"SUBAGENT_RESULT": json.dumps({"conclusion": "正文"}),
                      "RESULT_DATA": '{"ok":true}'})
        assert p.returncode == 0, p
        out = p.stdout
        assert out.startswith("# ECC-AUDIT: AUDIT-1\n")
        assert "- Audit Type: performance" in out
        assert "- Date: 2026-10-28" in out
        assert "## §2 Executive Summary\n正文" in out
        assert '```json\n{"ok":true}\n```' in out

    def test_non_json_result_kept_raw(self):
        out = _run("audit-report-assemble", "A", "financial", "D",
                   env={"SUBAGENT_RESULT": "raw text", "RESULT_DATA": ""}).stdout
        assert "## §2 Executive Summary\nraw text" in out

    def test_empty_conclusion_falls_back_to_dict_repr(self):
        out = _run("audit-report-assemble", "A", "compliance", "D",
                   env={"SUBAGENT_RESULT": '{"conclusion": ""}', "RESULT_DATA": ""}).stdout
        assert "## §2 Executive Summary\n{'conclusion': ''}" in out

    def test_content_truncated_to_2000(self):
        out = _run("audit-report-assemble", "A", "compliance", "D",
                   env={"SUBAGENT_RESULT": "x" * 2500, "RESULT_DATA": ""}).stdout
        assert "x" * 2000 in out and "x" * 2001 not in out


class TestMonitorDump:
    """B10a：monitor 全文转储（临时文件覆盖写，_meta 六键）。"""

    def test_writes_meta(self, tmp_path):
        out = tmp_path / "m.json"
        p = _run("monitor-dump", str(out), "R5", "deepseek", "ds-flash", "0.75",
                 "PASS", "2026-10-28T09:00:00+08:00",
                 stdin_text='{"score": 0.75, "checks": []}')
        assert p.returncode == 0, p
        d = json.loads(out.read_text(encoding="utf-8"))
        assert d["checks"] == []
        assert d["_meta"] == {"stage": "R5", "provider": "deepseek",
                              "model": "ds-flash", "score": 0.75, "verdict": "PASS",
                              "timestamp": "2026-10-28T09:00:00+08:00"}
        assert out.read_text(encoding="utf-8").startswith("{\n  "), "indent=2"

    def test_int_score(self, tmp_path):
        out = tmp_path / "m.json"
        _run("monitor-dump", str(out), "S", "p", "m", "0", "PASS", "T",
             stdin_text="{}")
        assert json.loads(out.read_text(encoding="utf-8"))["_meta"]["score"] == 0

    def test_bad_score_nonzero_no_write(self, tmp_path):
        out = tmp_path / "m.json"
        p = _run("monitor-dump", str(out), "S", "p", "m", "abc", "PASS", "T",
                 stdin_text="{}")
        assert p.returncode != 0
        assert not out.exists()

    def test_bad_stdin_nonzero(self, tmp_path):
        out = tmp_path / "m.json"
        assert _run("monitor-dump", str(out), "S", "p", "m", "0", "PASS", "T",
                    stdin_text="not json").returncode != 0


class TestContextCache:
    """B10b：State → `.gatekeeper.context.json` 投影（含自校验 `_checksum`）。"""

    def _state(self, tmp_path, obj):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(obj), encoding="utf-8")
        return str(sf)

    def test_projection_and_checksum(self, tmp_path):
        import hashlib
        st = self._state(tmp_path, {
            "stage": "ECO-DOC", "r_phase": "R7", "branch": "b", "worktree": "/w",
            "gate_data": {"entropy_rate": 0.5, "edit_budget": {"max": 10},
                          "rejected_edits": ["a", "b"]},
        })
        out = tmp_path / "ctx.json"
        p = _run("context-cache", st, str(out))
        assert p.returncode == 0, p
        d = json.loads(out.read_text(encoding="utf-8"))
        cs = d.pop("_checksum")
        assert d["stage"] == "ECO-DOC" and d["r_phase"] == "R7"
        assert d["branch"] == "b" and d["worktree"] == "/w"
        assert d["entropy_rate"] == 0.5
        assert d["edit_budget"] == {"max": 10}
        assert d["previous_rejections"] == 2
        assert len(d["updated_at"]) == 20 and d["updated_at"].endswith("Z")
        payload = json.dumps(d, sort_keys=True, ensure_ascii=False)
        assert cs == hashlib.sha256(payload.encode()).hexdigest()[:16]

    def test_defaults_when_keys_missing(self, tmp_path):
        st = self._state(tmp_path, {})
        out = tmp_path / "ctx.json"
        assert _run("context-cache", st, str(out)).returncode == 0
        d = json.loads(out.read_text(encoding="utf-8"))
        assert d["stage"] == "?" and d["r_phase"] == "?" and d["branch"] == "?"
        assert d["worktree"] == "?" and d["entropy_rate"] == "?"
        assert d["edit_budget"] == {} and d["previous_rejections"] == 0

    def test_checksum_warning_stripped(self, tmp_path):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"stage": "S", "_checksum": "deadbeef",
                                  "gate_data": {}}), encoding="utf-8")
        out = tmp_path / "ctx.json"
        assert _run("context-cache", str(sf), str(out)).returncode == 0
        d = json.loads(out.read_text(encoding="utf-8"))
        assert "_checksum_warning" not in d and d["stage"] == "S"

    def test_missing_state_nonzero_no_write(self, tmp_path):
        out = tmp_path / "ctx.json"
        assert _run("context-cache", str(tmp_path / "no.json"), str(out)).returncode != 0
        assert not out.exists()

    def test_bad_state_nonzero(self, tmp_path):
        sf = tmp_path / "bad.json"
        sf.write_text("{broken", encoding="utf-8")
        out = tmp_path / "ctx.json"
        assert _run("context-cache", str(sf), str(out)).returncode != 0
        assert not out.exists()


class TestAchievementsCheck:
    """B10c：`_check_achievements`（10 项判据 + dict 持久化 + list 归一）。"""

    def _state(self, tmp_path, obj):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(obj), encoding="utf-8")
        return str(sf)

    def test_unlock_then_count(self, tmp_path):
        st = self._state(tmp_path, {"history": [{"r_phase": "R1"}]})
        p = _run("achievements-check", st)
        assert p.returncode == 0, p
        assert json.loads(p.stdout) == ["eco-first-cycle", "redteam-clean"]
        d = json.loads(open(st, encoding="utf-8").read())
        assert d["achievements"]["eco-first-cycle"]["count"] == 1
        assert d["achievements"]["eco-first-cycle"]["granted_at"].endswith("Z")
        # 第二次：已解锁 ⟹ 只递增内存计数且**无新解锁即不落盘**（旧式 `if unlocked:` 守卫）
        p2 = _run("achievements-check", st)
        assert json.loads(p2.stdout) == []
        d2 = json.loads(open(st, encoding="utf-8").read())
        assert d2["achievements"]["eco-first-cycle"]["count"] == 1
        assert d2["achievements"]["redteam-clean"]["count"] == 1

    def test_list_form_normalized_to_dict(self, tmp_path):
        st = self._state(tmp_path, {"history": [{"r_phase": "R1"}],
                                    "achievements": ["eco-first-cycle"]})
        p = _run("achievements-check", st)
        assert json.loads(p.stdout) == ["redteam-clean"]
        d = json.loads(open(st, encoding="utf-8").read())
        assert d["achievements"]["eco-first-cycle"]["count"] == 2
        assert d["achievements"]["eco-first-cycle"]["granted_at"] == ""
        assert d["achievements"]["redteam-clean"]["count"] == 1

    def test_no_unlock_no_write(self, tmp_path):
        st = self._state(tmp_path, {})
        p = _run("achievements-check", st)
        assert p.returncode == 0 and json.loads(p.stdout) == []
        assert open(st, encoding="utf-8").read() == "{}"

    def test_missing_state_nonzero(self, tmp_path):
        assert _run("achievements-check", str(tmp_path / "no.json")).returncode != 0


class TestAchievementsRecord:
    """B10c：`cmd_achievements`（列表投影 + 原样保留的 list-append 分支）。"""

    def _state(self, tmp_path, obj):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(obj), encoding="utf-8")
        return str(sf)

    def _env(self, config, unlocked):
        return {"ACH_RAW": json.dumps(config, ensure_ascii=False),
                "ACH_UNLOCKED": json.dumps(unlocked, ensure_ascii=False)}

    def test_projection_with_dict_state(self, tmp_path):
        st = self._state(tmp_path, {"achievements": {"eco-first-cycle": {"count": 1}}})
        cfg = {"eco-first-cycle": {"label": "First", "msg": "m1"},
               "eco-10-cycles": {"label": "Ten", "msg": "m2"}}
        p = _run("achievements-record", st,
                 env=self._env(cfg, ["eco-first-cycle", "eco-10-cycles"]))
        assert p.returncode == 0, p
        d = json.loads(p.stdout)
        assert d["new_unlocks"] == ["eco-10-cycles"]
        assert d["achievements"][0] == {"id": "eco-first-cycle", "label": "First",
                                        "msg": "m1", "unlocked": True}
        assert d["achievements"][1]["unlocked"] is True
        assert d["achievements"][1]["just_unlocked"] is True
        # 旧式 list-append 分支在 dict 形态下 AttributeError 被 `except: pass` 吞 ⟹ state 不变
        assert json.loads(open(st, encoding="utf-8").read())["achievements"] == {
            "eco-first-cycle": {"count": 1}}

    def test_list_state_appends(self, tmp_path):
        st = self._state(tmp_path, {"achievements": ["old"]})
        cfg = {"new": {"label": "N", "msg": "m"}}
        p = _run("achievements-record", st, env=self._env(cfg, ["new"]))
        d = json.loads(p.stdout)
        assert d["new_unlocks"] == ["new"]
        assert json.loads(open(st, encoding="utf-8").read())["achievements"] == ["old", "new"]

    def test_missing_state_still_reports(self, tmp_path):
        cfg = {"a": {"label": "A", "msg": "m"}}
        p = _run("achievements-record", str(tmp_path / "no.json"),
                 env=self._env(cfg, ["a"]))
        assert p.returncode == 0, p
        assert json.loads(p.stdout)["new_unlocks"] == ["a"]


class TestDispatch:
    def test_unknown_verb_exit_2(self):
        assert _run("nope").returncode == 2

    def test_no_args_exit_2(self):
        assert _run().returncode == 2
