#!/usr/bin/env python3
"""压测：6+ 臂并发触发自愈 ⟹ 经**跨进程单飞** + `gk_sandbox` 限额，只跑 1 次 analyze。

取**真实** `_gx_analyze_embeddings` 函数文本（从 gatekeeper-cli.sh 抽取，不复制实现），
在 stub（_run_gitnexus / _gitnexus_baseline_status / _gx_repo_dir_for_current）下并发 8 路调用。
断言：(a) analyze 恰 1 次（单飞，消并发踩踏）；(b) `gk_sandbox` 限额**真生效**（enforced）且整体 rc=0。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"
N = 8


def _extract(name: str) -> str:
    s = CLI.read_text(encoding="utf-8")
    i = s.find("\n" + name + "() {")
    assert i != -1, "函数 %s 不存在" % name
    j = s.find("\n}", i)
    assert j != -1, "函数 %s 无闭合" % name
    return s[i + 1:j + 2]


def test_stress_concurrent_selfheal_singleflight(tmp_path):
    import gk_sandbox as sb

    func = _extract("_gx_analyze_embeddings")
    ran = tmp_path / "ran"
    done = tmp_path / "done"
    ranout = tmp_path / "ran.txt"
    lines = [
        "#!/usr/bin/env bash",
        "GK_DBG_LOG=/dev/null",
        'RAN="%s"' % ran,
        'DONE="%s"' % done,
        ': > "$RAN"',
        # stub：status 仅在 analyze 落 DONE 之后才报 current（模拟「卡死 → 自愈」）
        '_gitnexus_baseline_status() { [ -f "$DONE" ] && { echo current; return 0; }; echo stale; }',
        # stub：analyze 慢动作 + 计数（真实 analyze 是秒级重操作）
        '_run_gitnexus() { sleep 1; echo x >> "$RAN"; touch "$DONE"; }',
        '_gx_repo_dir_for_current() { echo "%s"; }' % tmp_path,
        func,
    ]
    for _ in range(N):
        lines.append('_gx_analyze_embeddings "%s" &' % tmp_path)
    lines += ["wait", 'wc -l < "$RAN" > "%s"' % ranout]
    h = tmp_path / "h.sh"
    h.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = sb.run(["/usr/bin/env", "bash", str(h)], mem_mb=256, timeout_s=60, max_proc=32)
    assert res["ok"] is True, res
    assert res["enforced"] is True, "沙箱限额未生效（fail-loud 契约）: %s" % res
    assert res["rc"] == 0, res
    assert ranout.read_text(encoding="utf-8").strip() == "1", (
        "并发 %d 路未单飞：analyze 执行次数 != 1（并发踩踏未消）" % N)
