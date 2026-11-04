"""test_gk_balance_audit.py — 余额采样 + token/缓存异常判定（2026-11-04）。

覆盖用户口径：「余额检查命令需要改造一下，需要用于随机或者定期。检查是否存在 token
异常消耗 / 缓存命中突然崩溃？subagent 那边应该已经有类似的东西了？」

三条硬约束：
  ① **复用** `gk_cache_observe.observe()`（不造第二套缓存算法）；
  ② 判定 **advisory**（默认退出 0；`--strict` 才在 high 时退 1）；
  ③ 输入不可解析 **不猜**（退出 2），台账写失败不拖累余额查询。
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_balance_audit as B

SCRIPT = Path(__file__).parent / "gk_balance_audit.py"


def _resp(total=100.0, currency="CNY", available=True):
    return {"is_available": available,
            "balance_infos": [{"currency": currency, "total_balance": str(total),
                               "granted_balance": "0", "topped_up_balance": str(total)}]}


def _call(hit, miss, provider="deepseek"):
    """**真实** subagent 形态：`token_usage.calls[]` 是扁平 provider 原生 usage（无 provider）。"""
    return {"prompt_cache_hit_tokens": hit, "prompt_cache_miss_tokens": miss,
            **({"provider": provider} if provider else {})}


class TestParseAndRecord:
    def test_parse_sums_infos(self):
        snap = B.parse_balance(_resp(12.5), ts=1000)
        assert snap["total"] == 12.5 and snap["currency"] == "CNY" and snap["ts"] == 1000

    def test_unavailable_reads_zero(self):
        assert B.parse_balance(_resp(12.5, available=False), ts=1)["total"] == 0.0

    def test_record_roundtrip_and_rotation(self, tmp_path, monkeypatch):
        monkeypatch.setattr(B, "MAX_LINES", 3)
        p = tmp_path / "h.jsonl"
        for i in range(5):
            r = B.record(p, {"ts": i, "total": float(i), "currency": "CNY"})
            assert r["ok"] is True
        rows = B.read_history(p)
        assert [r["ts"] for r in rows] == [2, 3, 4], "超限须保留尾部"
        assert rows[-1]["total"] == 4.0

    def test_read_history_skips_half_line(self, tmp_path):
        p = tmp_path / "h.jsonl"
        p.write_text('{"ts":1,"total":1.0}\n{"ts":2,"tot\n', encoding="utf-8")
        assert len(B.read_history(p)) == 1


class TestEvaluate:
    def test_no_baseline(self):
        f = B.evaluate(None, {"ts": 1, "total": 50}, 2.0, 10.0, 24.0)
        assert [x["kind"] for x in f] == ["NO_BASELINE"]

    def test_drop_fast_detected(self):
        f = B.evaluate({"ts": 0, "total": 100}, {"ts": 3600, "total": 90}, 2.0, 5.0, 24.0)
        d = [x for x in f if x["kind"] == "DROP_FAST"]
        assert d and d[0]["severity"] == B.HIGH and d[0]["evidence"]["cny_per_h"] == 10.0

    def test_normal_burn_not_flagged(self):
        f = B.evaluate({"ts": 0, "total": 100}, {"ts": 3600, "total": 98}, 2.0, 5.0, 24.0)
        assert not [x for x in f if x["kind"] == "DROP_FAST"]

    def test_topup_not_flagged(self):
        f = B.evaluate({"ts": 0, "total": 10}, {"ts": 3600, "total": 60}, 2.0, 5.0, 24.0)
        assert not [x for x in f if x["kind"] == "DROP_FAST"]

    def test_unexpected_zero(self):
        f = B.evaluate({"ts": 0, "total": 10}, {"ts": 60, "total": 0}, 0.0, 1000.0, 24.0)
        assert "UNEXPECTED_ZERO" in [x["kind"] for x in f]

    def test_insufficient_balance(self):
        f = B.evaluate(None, {"ts": 1, "total": 1.0}, 2.0, 10.0, 24.0)
        assert "INSUFFICIENT_BALANCE" in [x["kind"] for x in f]

    def test_sparse_samples_skips_rate(self):
        f = B.evaluate({"ts": 0, "total": 1000}, {"ts": 48 * 3600, "total": 0.5}, 0.0, 0.1, 24.0)
        kinds = [x["kind"] for x in f]
        assert "SPARSE_SAMPLES" in kinds and "DROP_FAST" not in kinds


class TestCacheHealth:
    def test_collapse_detected(self):
        """真实形态：`token_usage.calls` 扁平 usage（不带 provider）⟹ 按字段名推断。"""
        payload = {"token_usage": {"calls": [_call(100, 900) for _ in range(25)]}}
        f, summ = B.cache_health(payload)
        assert summ["cache_status"] == "BELOW_TARGET"
        assert [x["kind"] for x in f] == ["CACHE_COLLAPSE"]
        assert f[0]["severity"] == B.HIGH

    def test_healthy_not_flagged(self):
        payload = {"token_usage": {"calls": [_call(950, 50) for _ in range(25)]}}
        f, summ = B.cache_health(payload)
        assert summ["cache_status"] in ("EXTREME", "PASS")
        assert not [x for x in f if x["kind"] == "CACHE_COLLAPSE"]

    def test_usage_calls_lane_shape(self):
        """phase_probe 车道形态：`usage_calls` + 显式 provider。"""
        payload = {"provider": "deepseek", "length": 0,
                   "usage_calls": [_call(100, 900, provider="") for _ in range(25)]}
        f, summ = B.cache_health(payload)
        assert summ["cache_status"] == "BELOW_TARGET"
        assert [x["kind"] for x in f] == ["CACHE_COLLAPSE"]

    def test_invalidation_points(self):
        payload = {"token_usage": {"calls": [_call(100, 900) for _ in range(5)]
                                   + [_call(10, 990) for _ in range(20)]}}
        f, summ = B.cache_health(payload)
        assert summ["invalidation_points"]
        assert "CACHE_INVALIDATION" in [x["kind"] for x in f]

    def test_unknown_when_no_usage(self):
        f, summ = B.cache_health({})
        assert summ == {} and f[0]["kind"] == "CACHE_UNKNOWN"

    def test_unknown_provider_not_forced(self):
        """字段名推不出厂商 ⟹ 丢弃并具名 UNKNOWN（禁硬塞默认厂商）。"""
        payload = {"usage_calls": [{"foo": 1} for _ in range(25)]}
        f, summ = B.cache_health(payload)
        assert summ == {} and f[0]["kind"] == "CACHE_UNKNOWN"


class TestSingleSource:
    """2026-11-04（用户：「我怀疑你搞出来双源漂移了」）—— 静态钉住单源。"""

    def _src(self, name):
        return (Path(__file__).parent / name).read_text(encoding="utf-8")

    def _code(self, name):
        """去掉注释与字符串字面量后的代码面（docstring 里**说明**"禁止解析"不算解析）。"""
        import io
        import tokenize
        keep = []
        for tok in tokenize.generate_tokens(io.StringIO(self._src(name)).readline):
            if tok.type not in (tokenize.COMMENT, tokenize.STRING):
                keep.append(tok.string)
        return "".join(keep)

    def test_no_second_balance_parser(self):
        for name in ("gk_balance_audit.py", "balance_format.py"):
            assert "balance_infos" not in self._code(name), (
                "%s 出现第二份余额解析（应委托 gk_views.parse_balance）" % name)
        assert "def parse_balance" in self._src("gk_views.py")

    def test_usage_pipeline_delegates(self):
        src = self._src("gk_balance_audit.py")
        assert "cache_observe.extract_calls(" in src
        assert "cache_observe.flatten_calls(" in src
        assert 'payload.get("token_usage")' not in src, "又自带了一份 usage 提取逻辑"

    def test_probe_shares_flatten(self):
        p = Path(__file__).parent / "gk_phase_probe.py"
        if not p.is_file():
            pytest.skip("phase 族不随公开包（NOT_SHIPPED）")
        src = p.read_text(encoding="utf-8")
        assert "gk_cache_observe.flatten_calls(" in src
        assert "gk_cache_observe.extract_calls(" in src


class TestCli:
    def _run(self, args, stdin=""):
        return subprocess.run([sys.executable, str(SCRIPT), *args], input=stdin,
                              capture_output=True, text=True, timeout=60)

    def test_json_and_record(self, tmp_path):
        hist = tmp_path / "h.jsonl"
        r = self._run(["--stdin", "--json", "--record", "--history", str(hist)],
                      json.dumps(_resp(42)))
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["snapshot"]["total"] == 42.0 and out["recorded"]["ok"] is True
        assert json.loads(hist.read_text(encoding="utf-8").strip())["total"] == 42.0

    def test_audit_detects_drop(self, tmp_path):
        import time
        hist = tmp_path / "h.jsonl"
        hist.write_text(json.dumps({"ts": time.time() - 3600, "total": 100.0}) + "\n",
                        encoding="utf-8")
        r = self._run(["--stdin", "--json", "--audit", "--history", str(hist)],
                      json.dumps(_resp(1.0)))
        out = json.loads(r.stdout)
        kinds = [f["kind"] for f in out["findings"]]
        assert "INSUFFICIENT_BALANCE" in kinds and "DROP_FAST" in kinds, kinds
        assert out["advisory_only"] is True and r.returncode == 0

    def test_strict_exits_one_on_high(self, tmp_path):
        r = self._run(["--stdin", "--json", "--strict", "--history", str(tmp_path / "h")],
                      json.dumps(_resp(0.1)))
        assert r.returncode == 1

    def test_bad_json_exits_two(self):
        r = self._run(["--stdin", "--json"], "{not json")
        assert r.returncode == 2
        assert json.loads(r.stdout)["error"] == "BALANCE_UNPARSEABLE"

    def test_usage_file(self, tmp_path):
        u = tmp_path / "u.json"
        u.write_text(json.dumps({"token_usage": {"calls": [_call(100, 900)] * 25}}),
                     encoding="utf-8")
        r = self._run(["--stdin", "--json", "--usage", str(u), "--history", str(tmp_path / "h")],
                      json.dumps(_resp(50)))
        out = json.loads(r.stdout)
        assert out["cache"]["cache_status"] == "BELOW_TARGET"
        assert "CACHE_COLLAPSE" in [f["kind"] for f in out["findings"]]
