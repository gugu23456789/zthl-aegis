"""卫星实装 P1/P2 交叉审查修复 —— 红先臂集（L2 --crossrev sub-1791261277 发现的 F1-F5）。

红先对照（HEAD 源码，`d71c998`）：
  · F1 `gk_task_gate.adjudicate` 调 `_retain_pipeline` **漏传 `gd`** ⟹ 中枢走 standalone 写 state，
    紧接 `save_state(d)`（旧快照）静默抹掉索引 ⟹ 本文件 F1 臂断言 state 内 `satellite_index` 仍在 ⟹ **红**。
  · F2 `_retain_pipeline` 用固定 `batch_id=pipeline-overflow` / `arm=state` ⟹ 同 batch 多臂坍缩到
    同一索引叶互相覆盖 ⟹ F2 臂按 `batch` 取叶 ⟹ **红（KeyError）**。
  · F3 `gk_audit_state` 的 `state_forms` 项 `match=len(_all)>=1` **恒真** ⟹ 扩根接线回退仍判绿 ⟹
    F3 臂模拟接线回退后断言 `match is False` ⟹ **红**。
  · F4 `gk_satellite.append` **无自锁** ⟹ F4 静态臂断言源码含锁 ⟹ **红**。
  · F5 `gk_finding._ARCHIVE_SUFFIX` 与 `gk_satellite.KIND_SUFFIX["finding"]` 二源（注释式对齐）⟹
    tripwire 臂（HEAD 亦绿，守不变量）。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _mkstate(tmp_path, gd=None):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": gd or {}}), encoding="utf-8")
    return str(st)


# ── F1 [P1]：adjudicate 须 in-tx 传 gd（否则索引被 save_state 抹除 = lost update）──────────

def test_f1_adjudicate_persists_satellite_index(tmp_path):
    """F1：`adjudicate` 触发 `_retain_pipeline` 溢出的索引**须 survive `save_state`**。"""
    import gk_task_gate as TG
    # 25 条已决（超 20 上限 ⟹ 溢出 5）+ 1 条 pending 目标
    recs = [{"id": "d%d" % i, "status": "approved"} for i in range(25)]
    recs.append({"id": "target", "status": "pending"})
    st = _mkstate(tmp_path, {"task_pipeline": recs})
    r = TG.adjudicate(st, "target", "drop")
    assert r.get("ok"), r
    d = json.loads(open(st, encoding="utf-8").read())
    si = (d.get("gate_data") or {}).get("satellite_index") or {}
    assert si, "adjudicate 触发的溢出索引被 save_state 抹除（lost update，F1 未修）"


# ── F2 [P2]：`_retain_pipeline` 溢出须 per-arm 索引键（否则同 batch 多臂坍缩覆盖）─────────

def test_f2_retain_pipeline_per_arm_no_collapse(tmp_path):
    """F2：同 `batch` 多臂溢出 ⟹ **每臂各占一索引叶**（禁坍缩到 `pipeline-overflow/state`）。"""
    import gk_task_gate as TG
    st = _mkstate(tmp_path)
    gd = {"task_pipeline": [{"id": "a%d" % i, "status": "approved", "batch": "bx"}
                            for i in range(25)]}
    dropped = TG._retain_pipeline(gd["task_pipeline"], st, gd)
    assert dropped == 5, "未触发溢出出窗（dropped=%d）" % dropped
    leaves = gd["satellite_index"]["bx"]
    assert len(leaves) == 5, \
        "同 batch 多臂坍缩到同一索引叶（应 5 叶，得 %d）" % len(leaves)
    assert sum(leaf["records"] for leaf in leaves.values()) == 5, leaves


# ── F3 [P2]：audit `state_forms` 判据须可证伪（依赖 extra_roots 命中）────────────────────

def test_f3_state_forms_match_falsifiable(tmp_path):
    """F3：扩根接线回退后 `state_forms` 项须转 **False**（否则 c8 回归不可证伪）。"""
    import gk_audit_state as GA
    import gk_state_forms as gsf
    parent = tmp_path / ".trae"
    skill = parent / "skills" / "myskill"
    skill.mkdir(parents=True)
    (skill / ".gatekeeper.state").write_text('{"gate_data":{}}', encoding="utf-8")
    wt = parent / "worktrees" / "myskill" / "agent" / "session" / "abc"
    wt.mkdir(parents=True)
    (wt / ".gatekeeper.state.myrepo.plan").write_text('{"gate_data":{}}', encoding="utf-8")
    orig = gsf.iter_live_states
    # 模拟「接线被回退」：iter_live_states 忽略 extra_roots（只扫单根）
    gsf.iter_live_states = lambda skill_dir, extra_roots=None: orig(skill_dir)
    try:
        res = GA.check_state_file(str(skill / ".gatekeeper.state"), skill_dir=str(skill))
    finally:
        gsf.iter_live_states = orig
    item = [c for c in res.get("state_checks", []) if c.get("field") == "state_forms"]
    assert item, "state_forms 项缺失"
    assert item[0]["match"] is False, \
        "接线回退仍判绿 ⟹ c8 判据不可证伪（F3 未修）"


# ── F4 [P2]：`gk_satellite.append` 须自锁（并发下 JSONL 行完整性）────────────────────────

def test_f4_append_self_locks():
    """F4（静态）：中枢 `append` 须持锁（`state_lock`/`flock`），禁纯外借调用方。"""
    import inspect
    import gk_satellite as SAT
    seg = inspect.getsource(SAT.append)
    assert ("state_lock" in seg) or ("flock" in seg), \
        "中枢 append 未自锁（并发面无护栏，F4 未修）"


def test_f4_concurrent_large_records_no_partial_lines(tmp_path):
    """F4（行为）：两进程各追加 20 条大记录 ⟹ 片内每行均为合法 JSON、行数 == 40。"""
    import subprocess
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    st = _mkstate(tmp_path)
    prog = (
        "import sys;"
        "sys.path.insert(0, %r);"
        "import gk_satellite as SAT;"
        "r=SAT.append(sys.argv[2],'history',"
        "[{'arm':sys.argv[1],'i':i,'pad':'x'*20000} for i in range(20)],"
        "batch_id='bc',arm=sys.argv[1]);"
        "print(r.get('ok'), r.get('error',''))" % scripts_dir
    )
    ps = [subprocess.Popen([sys.executable, "-c", prog, arm, st],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
          for arm in ("A", "B")]
    for p in ps:
        out, err = p.communicate()
        assert p.returncode == 0 and out.strip().startswith("True"), (out, err)
    shard = st + ".history-archive.jsonl"
    lines = [l for l in open(shard, encoding="utf-8").read().splitlines() if l.strip()]
    assert len(lines) == 40, "并发追加丢行（应 40，得 %d）" % len(lines)
    for i, l in enumerate(lines):
        try:
            json.loads(l)
        except Exception as e:  # noqa: BLE001
            raise AssertionError("片内第 %d 行被撕成半行：%r（%s）" % (i, l[:80], e))


# ── F5 [P2]：finding 片名单源（tripwire；HEAD 亦绿，守不变量）─────────────────────────────

def test_f5_finding_suffix_single_source():
    """F5：`gk_finding._ARCHIVE_SUFFIX` 须与中枢 `KIND_SUFFIX["finding"]` 一致（漂移 tripwire）。"""
    import gk_finding as GF
    import gk_satellite as SAT
    assert GF._ARCHIVE_SUFFIX == SAT.KIND_SUFFIX["finding"], \
        "finding 片名二源漂移：%r != %r" % (GF._ARCHIVE_SUFFIX, SAT.KIND_SUFFIX["finding"])


# ── F7 [P2]：索引段语法校验（含 '.' ⟹ 叶错位；前导 '_' 被 _path_denied 拦）──────────────────

def test_f7_index_segment_syntax_guard(tmp_path):
    """F7：`append` 须对 batch_id/arm 的索引段语法 **fail-loud**（默认路径 ≠ 读回路径）。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    r = SAT.append(st, "pipeline", [{"x": 1}], batch_id="b.1", arm="A")
    assert r.get("ok") is False, "含 '.' 的 batch_id 未被拒（索引叶会切深/错位）"
    r2 = SAT.append(st, "pipeline", [{"x": 1}], batch_id="b1", arm="_bad")
    assert r2.get("ok") is False, "前导 '_' 的 arm 未被拒（会被 _path_denied 拦、片已落索引缺）"
    r3 = SAT.append(st, "pipeline", [{"x": 1}], batch_id="b1", arm="A-1")
    assert r3.get("ok"), r3
