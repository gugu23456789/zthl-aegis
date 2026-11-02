"""gk_satellite 中枢红先臂集 —— P1（`satellite_index` 首生产者 + 卫星片唯一写入者）。

红先对照（HEAD 源码）：`ls scripts/gk_satellite.py` → **不存在** ⟹ 下列臂全部 ImportError 必红。

分片模型 = **(b) 单片 + per-arm 索引叶子**（2026-10-06 质询定稿，**非 (c) arms map**）：
  · 实证：`cmd_set_nested` 禁「目标已是容器」的整键替换（G4）⟹ (c) 的 `satellite_index.<batch>`
    在**第一臂**写入后即成容器 ⟹ **第二臂写入被 fail-loud 拒** ⟹ 与中枢写面结构性不相容。
  · (b) 每臂各占互异叶子 `satellite_index.<batch_id>.<arm>` ⟹ 零覆盖，且与 c4 拦截面 / 宿主
    写面（`_PAYLOAD_KEYS` 只拦载荷键）/ ember `gate_data_full` 快照均兼容。
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _mkstate(tmp_path):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    return str(st)


def test_module_and_single_source_suffix(tmp_path):
    """中枢存在 + 片名**单源**（复用既有片名；漂移 tripwire 对既有常量）。"""
    import gk_satellite as SAT
    assert SAT.KIND_SUFFIX["pipeline"] == ".task-pipeline-archive.jsonl"
    import gk_task_gate as TG
    assert SAT.KIND_SUFFIX["pipeline"] == TG._TASK_PIPE_ARCHIVE_SUFFIX, \
        "中枢片名与既有 gk_task_gate 常量漂移（收敛前须一致）"


def test_append_lands_shard_and_registers_per_arm_leaf(tmp_path):
    """首生产者：append ⟹ ①落片（append-only）②登记 per-arm 索引叶子。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    r = SAT.append(st, "pipeline", [{"id": 1}, {"id": 2}], batch_id="b1", arm="A")
    assert r.get("ok"), r
    shard = SAT.shard_path(st, "pipeline")
    assert os.path.isfile(shard), "片未落盘"
    lines = [l for l in open(shard, encoding="utf-8").read().splitlines() if l.strip()]
    assert len(lines) == 2, "片未落 2 行"
    data = json.load(open(st, encoding="utf-8"))
    leaf = data["gate_data"]["satellite_index"]["b1"]["A"]
    assert leaf["kind"] == "pipeline" and leaf["records"] == 2, leaf


def test_c5_two_arms_same_batch_no_clobber(tmp_path):
    """c5：同 `batch_id` 两臂并发 ⟹ **片数（per-arm 叶子数）== 臂数** 且各臂行数互不覆盖。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    SAT.append(st, "pipeline", [{"a": 1}], batch_id="b2", arm="A")
    SAT.append(st, "pipeline", [{"b": 1}, {"b": 2}], batch_id="b2", arm="B")
    data = json.load(open(st, encoding="utf-8"))
    arms = data["gate_data"]["satellite_index"]["b2"]
    assert set(arms.keys()) == {"A", "B"}, "两臂同 batch 未各占一叶子（片数 != 臂数）"
    shard = SAT.shard_path(st, "pipeline")
    lines = [l for l in open(shard, encoding="utf-8").read().splitlines() if l.strip()]
    assert len(lines) == 3, "两臂行数互覆盖（应 1+2=3）"


def test_c5_concurrent_two_processes_same_batch(tmp_path):
    """c5 **真并发**：两**进程**同 `batch_id` 同时 append ⟹ 两臂各占一叶子 + 行数零丢失。"""
    import subprocess
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    st = _mkstate(tmp_path)
    prog = (
        "import sys;"
        "sys.path.insert(0, %r);"
        "import gk_satellite as SAT;"
        "r=SAT.append(sys.argv[3],'pipeline',"
        "[{'arm':sys.argv[1],'i':i} for i in range(int(sys.argv[2]))],"
        "batch_id='bc',arm=sys.argv[1]);"
        "print(r.get('ok'), r.get('error',''))" % scripts_dir
    )
    ps = [subprocess.Popen([sys.executable, "-c", prog, arm, "20", st],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
          for arm in ("A", "B")]
    res = [p.communicate() for p in ps]
    for (out, err), p in zip(res, ps):
        assert p.returncode == 0 and out.strip().startswith("True"), \
            "并发臂 append 失败：out=%r err=%r" % (out, err)
    data = json.load(open(st, encoding="utf-8"))
    arms = data["gate_data"]["satellite_index"]["bc"]
    assert set(arms.keys()) == {"A", "B"}, "并发两臂未各占一叶子（片数 != 臂数）"
    assert arms["A"]["records"] == 20 and arms["B"]["records"] == 20, arms
    shard = st + ".task-pipeline-archive.jsonl"
    lines = [l for l in open(shard, encoding="utf-8").read().splitlines() if l.strip()]
    assert len(lines) == 40, "并发追加丢行（应 20+20=40，得 %d）" % len(lines)


# ── c5 收敛 wiring（P1 后续：既有溢出写者收敛为调中枢，禁第二直写者）──────────────

def test_converge_retain_pipeline_calls_center_not_direct_write():
    """静态：`_retain_pipeline` 须**调中枢**且**不再直开**片文件（唯一写者 = gk_satellite）。"""
    import inspect
    import gk_task_gate as TG
    seg = inspect.getsource(TG._retain_pipeline)
    assert "gk_satellite" in seg, "`_retain_pipeline` 未调中枢（第二直写者仍在）"
    assert "_TASK_PIPE_ARCHIVE_SUFFIX" not in seg, \
        "`_retain_pipeline` 仍真开片文件（应改调 gk_satellite.append）"


def test_converge_retain_pipeline_in_tx_registers_index(tmp_path):
    """行为：`_retain_pipeline(lst, state, gd)` 溢出 ⟹ 落片 + 索引并入**同一** `gd`（in-tx）。"""
    import gk_task_gate as TG
    st = _mkstate(tmp_path)
    gd = {"task_pipeline": [{"id": "p%d" % i, "status": "approved"} for i in range(25)]}
    dropped = TG._retain_pipeline(gd["task_pipeline"], st, gd)
    assert dropped == 5, "未触发溢出出窗（得 dropped=%d）" % dropped
    shard = st + ".task-pipeline-archive.jsonl"
    assert os.path.isfile(shard), "溢出未落片"
    # [F2 修 · ECC-2E31D62BCCB8] per-arm 索引键：25 条 id=p0..p24，溢出 5 条（p0..p4）各占一叶
    #   （原固定 `pipeline-overflow`/`state` 会坍缩到单叶互相覆盖）。
    leaves = gd["satellite_index"]["pipeline-overflow"]
    assert len(leaves) == 5, "同批多臂坍塌到同一叶（应 5 叶）：%r" % (sorted(leaves),)
    assert sum(l["records"] for l in leaves.values()) == 5, leaves
    assert all(l["kind"] == "pipeline" for l in leaves.values()), leaves


def test_append_in_tx_does_not_write_state(tmp_path):
    """hazard 护栏：传 `gd` 时 `append` **不得**写 state（否则 caller 的 save_state 会覆盖索引）。"""
    import gk_satellite as SAT
    st = _mkstate(tmp_path)
    before = open(st, encoding="utf-8").read()
    gd = {}
    r = SAT.append(st, "pipeline", [{"x": 1}], batch_id="bx", arm="A", gd=gd)
    assert r.get("ok") and gd["satellite_index"]["bx"]["A"]["records"] == 1, r
    assert open(st, encoding="utf-8").read() == before, "in-tx append 竟写了 state（应零 state 写）"


def test_converge_cli_history_segment_calls_center():
    """静态：CLI history 落库段须**调中枢**且不再直开片文件（唯一写者 = gk_satellite）。"""
    cli = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gatekeeper-cli.sh")
    src = open(cli, encoding="utf-8").read()
    i = src.index("_hist_evicted=[]")
    seg = src[i:i + 900]
    assert "gk_satellite" in seg, "CLI history 段未调中枢（第二直写者仍在）"
    assert "open(_arc,'a'" not in seg, "CLI history 段仍直开片文件（应改调 gk_satellite.append）"


def test_converge_cli_history_registers_index_e2e(tmp_path):
    """e2e：**真跑** CLI history 落库段 ⟹ 片归档 + **索引 leaf 落 state**（in-tx 生效，`gd` 在作用域）。
    HEAD 必红：落库段不产 `satellite_index` ⟹ KeyError。"""
    pytest.importorskip("gk_moa_aggregate")  # history_union 单源已闭源 ⟹ 公开面 skip
    import subprocess
    from pathlib import Path
    CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"
    txt = CLI.read_text(encoding="utf-8")
    i = txt.index("GK_HMAC_VALID=")
    src = txt[i:txt.index('\n"', i) + 1]
    body = src.split('python3 -c "', 1)[1]
    state = tmp_path / ".gatekeeper.state"
    big = [{"subagent_id": "old-%d" % k, "batch_id": "bc", "conclusion": "x" * 90000}
           for k in range(3)]
    state.write_text(json.dumps({"gate_data": {"subagent_history": big}}, ensure_ascii=False),
                     encoding="utf-8")
    ecc = {"mode": "subagent", "subagent_id": "sub-new", "nonce": "n1",
           "timestamp": "2026-09-28T00:00:00+00:00", "task": "t", "conclusion": "c"}
    out = tmp_path / "sub-1.json"
    out.write_text(json.dumps(ecc, ensure_ascii=False), encoding="utf-8")
    # [ECC-0A7EBDA60149 附带] Windows：`str(Path)` 的反斜杠落进 `-c` 单引号串会触发
    #   `\U`/`\t` 转义错误（预存在红）⟹ 统一以正斜杠注入（Python 在 Windows 亦接受）。
    _slash = lambda p: str(p).replace("\\", "/")  # noqa: E731
    body = (body.replace("$SKILL_DIR", _slash(CLI.parent))
                .replace("$STATE_FILE", _slash(state))
                .replace("$GK_DBG_LOG", _slash(tmp_path / "dbg.log")))
    # 裁剪线用逃生舱**显式钉死**（2026-11-01 三腿按墙比例放大后默认 800KB ⟹ 90KB 夹具
    # 不再触发出窗；本臂要验的是「出窗即落片+登记索引」通路，与默认值无关）。
    env = dict(os.environ, GK_TASK="t", GK_HMAC_VALID="skip", GK_STATE_TRIM_KB="64",
               GK_OUTPUT_FILE=str(out), GK_REPORT_FILE=str(tmp_path / "sub-1.md"))
    r = subprocess.run([sys.executable, "-c", body], input=json.dumps(ecc),
                       capture_output=True, text=True, env=env, timeout=90)
    assert r.returncode == 0, (r.returncode, r.stderr[-600:])
    d = json.loads(state.read_text(encoding="utf-8"))
    arms = d["gate_data"]["satellite_index"]["bc"]
    assert "state" not in arms, "仍用固定 arm 键（未按条入账）：%r" % (sorted(arms),)
    assert len(arms) >= 2, "应至少 2 臂各占一叶子（片数==臂数）：%r" % (sorted(arms),)
    assert all(arms[a]["arm"] == a for a in arms), arms




