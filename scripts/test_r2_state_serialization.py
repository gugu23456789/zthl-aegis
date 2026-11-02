#!/usr/bin/env python3
"""R2 红先臂：state 序列化单一化（形态抖动 → 单一事实源）。

缺陷（实测 2026-09-21/22）：同一个 state 对象的磁盘字节随"末位写者"在
  158,000 / 161,759 / 181,323 / 211,685 / 224,977 / 231,789 / 244,541 / 251,683 /
  289,835 / 314,527(B) 之间漂移，上限 262,144 B ⟹
  ① `gk_narrow_route._NT_MAX_TOTAL_BYTES*4` 撞墙与否取决于**最后一个写点**；
  ② `gk_finding.save_findings` 的形态（indent=2 + ensure_ascii **True**）实测 314,527 B，
     单次 `finding register` 即越线；
  ③ 多个写点 `open(...,'w')` 未指定 encoding —— 现在能跑纯属 `ensure_ascii=True` 使输出恒为
     ASCII 的副作用；一旦改 ascii=False 即在非 UTF-8 locale 下 UnicodeEncodeError。

统一目标形态（单一事实源）：`ensure_ascii=False` + `indent=1` + `encoding='utf-8'`
+ `newline='\\n'`。

臂清单（红先 = 落刀前必失败）：
  arm1  静态：state 写点（CLI 内联 + B8 抽取模块）已带 canonical 四参（红先）
  arm2  静态：生产 python 写点无裸 `json.dump(` 直写 state（红先）
  arm3  动态：`_state_write` 产出字节 == canonical（红先）
  arm4  动态：`_state_checksum_write` 产出字节 == canonical（红先）
  arm5  动态：`gk_state._write_state` 产出字节 == canonical（红先：现为 indent=2）
  arm6  动态：`gk_finding.save_findings` 产出字节 == canonical（红先：现 ascii=True）
  arm7  CJK 不被逃逸（`\\uXXXX` 计数 0）（红先）
  arm8  对照：形态变更不改 `_checksum` 且 `json.load` 语义等价（修前也绿）
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

SD = Path(__file__).resolve().parent.parent
CLI = SD / "gatekeeper-cli.sh"
SCRIPTS = SD / "scripts"

# 生产 state 写点所在文件（排除 test_*.py / docs）
PROD_PY = ["gk_state.py", "gk_advance.py", "gk_finding.py", "gk_task_gate.py",
           "gk_json_utils.py", "sniffnet_webhook.py", "otd_probes.py",
           "pre_tool_hook.py"]

# B8 抽取（2026-10-28）：CLI 内联的 state 写点已下沉到以下模块 ⟹ arm1 的扫描面
# 必须跟着搬，否则「扫描为空」被当成失败（旧判据）或静默通过（更糟）。
# 2026-10-28 补：`gk_views.py` 的成就写点（`with open(path, "w")` 直写 state）此前漏扫；
# 目标变量是裸 `path`，故以 `open(path` 作精确记号（避免 `reason_path` 之类误命中）。
STATE_WRITER_MODULES = ["gk_state_ops.py", "gk_discover_archive.py", "gk_views.py"]
_STATE_TARGETS = ("state_path", "state_file", "STATE_FILE", "open(path")

CANON_INDENT = 1


def canon(data) -> bytes:
    """canonical 序列化（单一事实源的字节级定义）。"""
    return json.dumps(data, ensure_ascii=False, indent=CANON_INDENT).encode("utf-8")


# ── 静态：从 CLI 抽 state 写行 ──────────────────────────────────────────────
def cli_state_dump_lines() -> list[str]:
    """抽 CLI 的 state 写**代码行**（**逐行跳过注释行**）。

    2026-09-23 实测缺陷（F3a 修复注释触发 arm1 假红）：原实现不跳注释 ⟹
    修复注释里引用的原文 `` `json.dump(open($STATE_FILE,'w'))` `` 被计入写点、
    因缺 canonical 四参而误报「非 canonical 写点」。判据意图是「写**站点**」⟹
    与 arm2（`s.startswith("#")` 跳过）口径对齐，逐行跳过首个非空白字符为 `#` 的行。
    """
    out = []
    for ln in CLI.read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if s.startswith("#"):
            continue
        if "json.dump(" in ln and "STATE_FILE" in ln:
            out.append(s)
    return out


def module_state_dump_sites() -> list[tuple[str, int, str, str]]:
    """抽取模块里的 state 写点（`json.dump` 行 + 其配对的 `open(` 行）。

    判据：`json.dump(` 行的**最近一个** `open(` 目标是 state 变量（`state_path` /
    `state_file`）。ember 快照 / context 缓存 / crossfull 副本等非 state 权威写点不计入
    （与旧 arm1 只看 `STATE_FILE` 的口径一致）。
    """
    sites = []
    for name in STATE_WRITER_MODULES:
        p = SCRIPTS / name
        if not p.is_file():
            continue
        cur_open = ""
        for i, ln in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            s = ln.strip()
            if s.startswith("#"):
                continue
            if "open(" in s:
                cur_open = s
            if "json.dump(" in s:
                if any(t in cur_open for t in _STATE_TARGETS):
                    sites.append((name, i, cur_open, s))
                cur_open = ""
    return sites


def test_arm1_state_dump_sites_all_canonical():
    """每一处 state 写点都显式带 canonical 四参（缺一即形态抖动的来源）。

    扫描面 = CLI 内联写点 ∪ B8 抽取模块（`STATE_WRITER_MODULES`）；两面的参数位置不同：
    CLI heredoc 把四参写在 `json.dump` 同一行，python 模块把 `encoding`/`newline` 放在
    配对的 `open(...)` 上 ⟹ 按「open 行 + dump 行」合并判定。
    """
    cli_lines = cli_state_dump_lines()
    mod_sites = module_state_dump_sites()
    assert cli_lines or mod_sites, "未扫到任何 state 写点 —— 扫描式失效，臂失去意义"
    bad = []
    for ln in cli_lines:
        missing = [k for k in ("ensure_ascii=False", "indent=1",
                               "encoding='utf-8'", "newline='\\n'") if k not in ln]
        if missing:
            bad.append(("gatekeeper-cli.sh", ln, missing))
    for name, _i, op, dp in mod_sites:
        blob = op + " " + dp
        missing = []
        if "ensure_ascii=False" not in blob:
            missing.append("ensure_ascii=False")
        if "indent=1" not in blob:
            missing.append("indent=1")
        if not re.search(r"encoding=[\"']utf-8[\"']", blob):
            missing.append("encoding='utf-8'")
        if not re.search(r"newline=[\"']\\n[\"']", blob):
            missing.append("newline='\\n'")
        if missing:
            bad.append((f"{name}:{_i}", dp, missing))
    assert not bad, "非 canonical 的 state 写点:\n" + "\n".join(
        f"  {where} {ln}\n    缺 {m}" for where, ln, m in bad)


def test_arm1b_cli_read_lines_all_encoded():
    """CLI 每一处 state 读点都显式 encoding —— 否则 ascii=False 落在非 UTF-8 locale 即崩。

    2026-11-02（真因 D 第二轮）：state 读点的路径形态改经 env（`GK_PY_STATE`）传入，
    扫描面随之扩展为两种形态（内联历史形态仍须满足，防回退）。
    """
    lines = [ln.strip() for ln in CLI.read_text(encoding="utf-8").splitlines()
             if "json.load(open('$STATE_FILE'" in ln
             or "open(os.environ['GK_PY_STATE']" in ln]
    assert lines, "未扫到任何 state 读点 —— 扫描式失效"
    bad = [ln for ln in lines if "encoding=" not in ln]
    assert not bad, "未带 encoding 的 CLI state 读点:\n" + "\n".join(bad)


def test_arm2_no_bare_json_dump_to_state_in_prod_py():
    """生产 python 侧不得再内联 `json.dump(` 直写 state（须走单一出纳 dump_state）。"""
    offenders = []
    for name in PROD_PY:
        p = SCRIPTS / name
        if not p.is_file():
            continue
        for i, ln in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            s = ln.strip()
            if s.startswith("#"):
                continue
            if re.search(r"json\.dump\(", s) and re.search(
                    r"state|STATE|sp\b|\.write_text", s):
                offenders.append(f"{name}:{i}: {s}")
    assert not offenders, "内联 json.dump 直写 state:\n" + "\n".join(offenders)


def test_arm2b_prod_py_route_through_dump_state():
    """python 侧 state 写点须委托给单一出纳 `gk_json_utils.dump_state`。"""
    missing = []
    for name in PROD_PY:
        p = SCRIPTS / name
        if not p.is_file():
            continue
        txt = p.read_text(encoding="utf-8")
        if "dump_state(" not in txt and "json.dump(" not in txt \
                and "write_text(" not in txt:
            continue  # 该文件不写 state
        if "dump_state(" not in txt:
            missing.append(name)
    assert not missing, f"未走单一出纳 dump_state 的 python 写点文件: {missing}"


def _sh_path(p) -> str:
    """**宿主感知的 bash 可见路径**：Windows 盘符形态 ⟹ WSL 形态（`C:\\x` → `/mnt/c/x`）。

    [ECC-WINHOST-R2-BASH] 本文件 harness 经 `subprocess.run(["bash", …])` 执行；Windows 上
    `bash` = WSL bash —— 既不认 `C:\\…` 形态的**脚本路径**（`bash C:\\…h.sh` → rc=127
    「No such file or directory」），其内 `python3` 也打不开**驱动形态**的 state ⟹
    arm3/arm4/arm7/arm8（真跑写原语）与 arm9b（故障夹具自证）在 Windows 宿主**恒红**
    （纯路径形态问题，非产品缺陷）。POSIX 上为 no-op。
    """
    s = str(p).replace("\\", "/")
    if os.name == "nt" and len(s) >= 2 and s[1] == ":":
        return "/mnt/" + s[0].lower() + s[2:]
    return s


# ── 动态：抽 bash 真函数体 ────────────────────────────────────────────────
def extract_fn(src: str, name: str) -> str:
    """按花括号配对抽 `name() {` … `}` 的真函数体（非行窗口近似）。"""
    m = re.search(rf"^{re.escape(name)}\(\) *\{{", src, re.M)
    assert m, f"未找到函数 {name}"
    start = src.index("{", m.start())
    depth, i = 0, start
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():i + 1]
        i += 1
    raise AssertionError(f"{name} 花括号不平衡")


def run_bash_writer(fn_name: str, seed: dict, tmp_path: Path, call: str = None):
    """在 tmp state 上跑 CLI 里的 bash 写原语，返回落盘字节。"""
    cli_src = CLI.read_text(encoding="utf-8")
    body = extract_fn(cli_src, fn_name)
    # 2026-11-02（真因 D 第二轮）：写原语的 state / scripts 路径经 env 传入，形态单源
    #   `_gk_py_path` ⟹ harness 须连同其依赖一起抽取（同 test_eco_integration 的抽取表）。
    helpers = "\n".join(extract_fn(cli_src, n)
                        for n in ("_gx_to_win_path", "_gk_py_form", "_gk_py_path"))
    state = tmp_path / "state.json"
    state.write_text(json.dumps(seed, ensure_ascii=False), encoding="utf-8")
    harness = tmp_path / "h.sh"
    # 2026-09-23（**ECC-60BBDCDB2F70 修复**配套）：`_state_write` / `_state_checksum_write`
    # 已改走 python 侧**单一出纳** `gk_json_utils.dump_state`（原子写）⟹ 沙箱 harness 必须
    # 提供真实 `SKILL_DIR` 让该模块可 import（此前只需 `STATE_FILE`）。
    harness.write_text(
        "set -e\n"
        "STATE_FILE=%s\n"
        "SKILL_DIR=%s\n"
        # 2026-09-25（选项 A）：`_with_state_lock` 已从 CLI **拆除** ⟹ 本 harness 不再提供桩。
        #   刻意保留 fail-loud：被测函数若仍引用它 ⟹ `command not found` + `set -e` ⟹ rc!=0 ⟹ 本臂红。
        "gk_dbg() { :; }\n"
        "%s\n"
        "%s\n"
        "%s\n" % (_sh_path(state).replace("'", "'\\''"),
                  _sh_path(SD).replace("'", "'\\''"),
                  helpers, body, call or fn_name + ' "pass"'),
        encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", _sh_path(harness)], capture_output=True, text=True)
    assert r.returncode == 0, f"{fn_name} 执行失败 rc={r.returncode}\n{r.stderr[:800]}"
    return state.read_bytes(), json.loads(state.read_text(encoding="utf-8"))


SEED = {"r_phase": "R2", "stage": "STAGE_1",
        "current": {"last_updated": "2026-09-22T00:00:00Z"},
        "gate_data": {"ecc_findings": [{"id": "ECC-T", "title": "中文标题需保留",
                                        "detail": "形态抖动"}]},
        "monitor_scores": {}, "history": []}


def test_arm3_state_write_is_canonical(tmp_path):
    raw, d = run_bash_writer("_state_write", SEED, tmp_path)
    assert raw == canon(d), (
        f"_state_write 产出非 canonical：{len(raw)}B，"
        f"canonical 应为 {len(canon(d))}B")


def test_arm4_state_checksum_write_is_canonical(tmp_path):
    raw, d = run_bash_writer("_state_checksum_write", SEED, tmp_path)
    assert raw == canon(d), (
        f"_state_checksum_write 产出非 canonical：{len(raw)}B，"
        f"canonical 应为 {len(canon(d))}B")


def _run_py_state_writer(snippet: str, seed: dict, tmp_path: Path):
    """在一个子进程里跑真实 python 写函数（sys.path 指向 scripts）。"""
    state = tmp_path / "state.json"
    state.write_text(json.dumps(seed, ensure_ascii=False), encoding="utf-8")
    code = (
        "import sys,json\n"
        f"sys.path.insert(0, {str(SCRIPTS)!r})\n"
        "import gk_state, gk_finding\n"
        f"p = {str(state)!r}\n"
        f"{snippet}\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, f"writer 失败 rc={r.returncode}\n{r.stderr[:800]}"
    return state.read_bytes(), json.loads(state.read_text(encoding="utf-8"))


def test_arm5_gk_state_write_state_is_canonical(tmp_path):
    raw, d = _run_py_state_writer(
        "s = gk_state._read_state(p)\n"
        "gk_state._write_state(s, p)\n", SEED, tmp_path)
    assert raw == canon(d), (
        f"gk_state._write_state 产出非 canonical：{len(raw)}B，"
        f"canonical 应为 {len(canon(d))}B")


def test_arm6_gk_finding_save_findings_is_canonical(tmp_path):
    raw, d = _run_py_state_writer(
        "fs = gk_finding.load_findings(p)\n"
        "fs.append({'id': 'ECC-NEW', 'title': '新增中文', 'detail': 'x'})\n"
        "gk_finding.save_findings(p, fs)\n"
        "gk_finding._write_checksum(p)\n", SEED, tmp_path)
    assert raw == canon(d), (
        f"gk_finding.save_findings 产出非 canonical：{len(raw)}B，"
        f"canonical 应为 {len(canon(d))}B")


def test_arm7_no_unicode_escape_in_state(tmp_path):
    """CJK 不得被逃逸成 \\uXXXX（ensure_ascii=False 的字节级断言）。"""
    raw, _ = run_bash_writer("_state_write", SEED, tmp_path)
    assert b"\\u" not in raw, "state 中仍存在 \\uXXXX 逃逸（ensure_ascii 未关闭）"
    assert "中文标题需保留".encode("utf-8") in raw, "CJK 明文未保留"


def test_arm8_control_checksum_and_semantics_preserved(tmp_path):
    """对照臂：形态变更不得改 _checksum，且 json.load 语义等价（修前也绿）。"""
    import hashlib
    raw, d = run_bash_writer("_state_write", SEED, tmp_path)
    gd = json.dumps(d.get("gate_data", {}), sort_keys=True, ensure_ascii=True)
    assert d["_checksum"] == hashlib.sha256(gd.encode()).hexdigest()[:16]
    assert d["gate_data"]["ecc_findings"][0]["title"] == "中文标题需保留"
    assert d["r_phase"] == SEED["r_phase"]


def _fault_harness(tmp_path, body: str, call: str, payload: dict):
    """构造「写入必然失败」的沙箱：`ulimit -f 1`（512B）⟹ 任何 >512B 的写入被拒。

    返回 (state_path, before_bytes, after_bytes, rc)。
    """
    state = tmp_path / "state.json"
    state.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    before = state.read_bytes()
    assert len(before) > 512, "探针本身须 >512B，否则 ulimit 触发不到"
    h = tmp_path / "hf.sh"
    h.write_text(
        "ulimit -f 1\n"
        "STATE_FILE=%s\n"
        "SKILL_DIR=%s\n"
        # 2026-09-25（选项 A）：`_with_state_lock` 已从 CLI 拆除 ⟹ 不再提供桩（同 `run_bash_writer`）。
        "gk_dbg() { :; }\n"
        "%s\n"
        "%s\n" % (_sh_path(state).replace("'", "'\\''"),
                  _sh_path(SD).replace("'", "'\\''"),
                  body, call),
        encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", _sh_path(h)], capture_output=True, text=True)
    return state, before, state.read_bytes(), r.returncode


_BIG = {"r_phase": "R2", "stage": "STAGE_1",
        "gate_data": {"probe": "原子性探针" * 120}, "monitor_scores": {}}


def test_arm9_write_failure_keeps_original_state_intact():
    """⑧ 红先（`ECC-60BBDCDB2F70`）：**写入中途失败时，原 state 必须完好**。

    事故形态：`_state_write` 原实现 `json.dump(d, open('$STATE_FILE','w'))` = **先截断再
    流式写** ⟹ 进程中途被杀（2026-09-23 实测：断在 `edit_budget.overrides[].reason` 中途）
    就留下**半截 state**，hook Gate 1 随即拦掉所有 Edit/Write。修后走 `dump_state`
    （tmp + fsync + `os.replace`）⟹ 失败只毁 tmp。
    """
    import tempfile
    cli_src = CLI.read_text(encoding="utf-8")
    body = extract_fn(cli_src, "_state_write")
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        _st, before, after, _rc = _fault_harness(
            tdir, body, '_state_write "d[\'probe\']=\'x\'*400"', _BIG)
        assert after == before, (
            "写失败后原 state 被改写/截断 —— 非原子写（半写风险）："
            f"{len(before)}B -> {len(after)}B")
        json.loads(after.decode("utf-8"))  # 且仍须可解析


def test_arm9b_control_non_atomic_write_is_destroyed():
    """对照组（**判别力自证**）：同一 `ulimit` 下，**非原子**写法确实会毁掉原 state
    ⟹ 证明 arm9 不是恒绿空臂。"""
    import tempfile
    body = ("_state_write() {\n"
            "  python3 -c \"import json;d=json.load(open('$STATE_FILE'));"
            "d['probe']='y'*400;json.dump(d,open('$STATE_FILE','w'))\" 2>/dev/null || true\n"
            "}")
    with tempfile.TemporaryDirectory() as td:
        _st, before, after, _rc = _fault_harness(
            Path(td), body, '_state_write "x"', _BIG)
        assert after != before, "对照组未触发半写 —— ulimit 夹具失效（arm9 判别力不可证）"


# ── 锁唯一持有者（选项 A，2026-09-25 用户裁定：「唯一锁持有者 = python」）──────
# 背景（实测，计划 §4.13.1 RC2）：锁资源 `<state>.lock` 此前**只由 bash `_with_state_lock`
#   （flock(1)）获取**，而 python 侧 ~15 个写通道（`dump_state` / `_write_state` / `gk_finding` …）
#   **全无锁** ⟹ 多会话并发「读-改-写」丢更新（实测：`used=2` 而 `remaining` 只由 8→7）。
# 裁定：持有者改为 python（`gk_json_utils.state_lock`，可重入），bash `_with_state_lock` **拆除**。
# 三臂（红先 = 落刀前必失败）：
#   arm10 静态：CLI **非注释行**不得再出现 `_with_state_lock`（红先：修前 4 处调用 + 1 定义）
#   arm11 静态：锁原语在 python 侧 —— `state_lock` + `update_state`，且 `dump_state` 在锁内写
#   arm12 行为：N 进程并发 `update_state` 自增 ⟹ 终值必须 == N（红先：HEAD 无该 API）
def _py_fn(src: str, name: str) -> str:
    """抽 python 函数体（从 `def name(` 到下一个顶层 `def `/`class `）。"""
    m = re.search(rf"^def {re.escape(name)}\(", src, re.M)
    if not m:
        return ""
    nxt = re.search(r"^(?:def |class )", src[m.end():], re.M)
    return src[m.start():m.end() + (nxt.start() if nxt else len(src) - m.end())]


def test_arm10_bash_state_lock_removed():
    """arm10（静态，红先）：`_with_state_lock` 已拆除 —— CLI 非注释行不得再出现。"""
    hits = [ln.strip() for ln in CLI.read_text(encoding="utf-8").splitlines()
            if "_with_state_lock" in ln and not ln.lstrip().startswith("#")]
    assert not hits, ("bash 持锁未拆除（选项 A：唯一锁持有者 = python）:\n"
                      + "\n".join(hits))


def test_arm11_python_lock_primitive_present():
    """arm11（静态，红先）：锁原语在 python 侧 —— `state_lock` / `update_state` 存在，
    且 `dump_state` 在其内写（写侧互斥的唯一实现点）。"""
    src = (SCRIPTS / "gk_json_utils.py").read_text(encoding="utf-8")
    assert "def state_lock(" in src, "`gk_json_utils.state_lock` 缺席（唯一锁持有者 = python）"
    assert "def update_state(" in src, "`gk_json_utils.update_state` 缺席（原子读-改-写）"
    body = _py_fn(src, "dump_state")
    assert "state_lock(" in body, "`dump_state` 未取锁 —— 写侧互斥点缺失"


def test_arm12_concurrent_update_state_no_lost_update(tmp_path):
    """arm12（行为，红先）：N 进程并发 `update_state` 自增 ⟹ 终值必须 == N。

    红先性：HEAD 无 `update_state`（`AttributeError`）⟹ 子进程 rc!=0 ⟹ 本臂红。
    修后：锁内读-改-写全程互斥 ⟹ 终值恒 == N（不丢更新）。
    """
    state = tmp_path / ".gatekeeper.state"
    state.write_text(json.dumps({"gate_data": {}, "n": 0}),
                     encoding="utf-8", newline="\n")
    n = 8
    child = (
        "import os,sys\n"
        "sys.path.insert(0, os.environ['GK_SCRIPTS'])\n"
        "import gk_json_utils as J\n"
        "def bump(d):\n"
        "    d['n'] = int(d.get('n', 0)) + 1\n"
        "    return d\n"
        "r = J.update_state(os.environ['GK_STATE'], bump)\n"
        "sys.exit(0 if r.get('ok') else 1)\n"
    )
    env = dict(os.environ, GK_SCRIPTS=str(SCRIPTS), GK_STATE=str(state))
    ps = [subprocess.Popen([sys.executable, "-c", child], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          for _ in range(n)]
    rcs = [p.wait(timeout=180) for p in ps]
    assert rcs == [0] * n, "并发 `update_state` 子进程非零退出（API 缺席或取锁失败）: %r" % rcs
    got = json.loads(state.read_text(encoding="utf-8")).get("n")
    assert got == n, "并发读-改-写**丢更新**：n=%r（应 %d）" % (got, n)


# 跨 I/O 的 RMW 站点（2026-09-25，ECC-567E8C847F16 / 选项 A）：这些模块的「读 state →
# 跨 LLM API / 长流程 → 写 state」窗口内他人写入会被整体覆盖回旧值（丢更新）⟹ 必须改
# **_锁内重放**（`gk_json_utils.update_state`），不得再走无锁的 `gk_state._write_state`。
RMW_CROSS_IO = ["gk_appeal.py", "gk_escalate_resolve.py", "gk_monitor_api.py"]


def test_arm13_cross_io_rmw_uses_update_state():
    """arm13（静态，红先）：跨 I/O 的 RMW 模块已改**锁内重放**（不再「先 read 后 write」）。

    红先性：HEAD 上三文件均 `from gk_state import ... _write_state` 且直接调用（窗口跨
    LLM API / 判据流程 ⟹ 非原子）⟹ 本臂红。修后：`update_state(` 在场且无 `_write_state` 调用 ⟹ 绿。
    """
    offenders = []
    for name in RMW_CROSS_IO:
        src = (SCRIPTS / name).read_text(encoding="utf-8")
        code = "\n".join(ln for ln in src.splitlines()
                         if not ln.strip().startswith("#"))
        if "update_state(" not in code:
            offenders.append(f"{name}: 未走 `update_state`（锁内读-改-写）")
        stale = [ln.strip() for ln in code.splitlines()
                 if re.search(r"(?<![A-Za-z_])_write_state\(", ln)]
        if stale:
            offenders.append(f"{name}: 仍有无锁 `_write_state` RMW 调用: {stale}")
    assert not offenders, "跨 I/O RMW 未收口（丢更新窗口仍在）:\n" + "\n".join(offenders)


def test_arm14_gk_advance_run_holds_state_lock():
    """arm14（静态，红先）：`gk_advance.main` 对 `_run` **全段持锁**。

    `_run` 的「读 state → 判据决策 → 8 处写 state」是一整个 RMW（同一份内存 `d`），
    本文件 0 subprocess / 0 requests ⟹ 全段持锁不引入「锁内等待」。
    红先性：HEAD 上 `main` 直接 `result = _run(...)`（无锁）⟹ 本臂红。
    """
    src = (SCRIPTS / "gk_advance.py").read_text(encoding="utf-8")
    body = _py_fn(src, "main")
    assert body, "未抽到 `gk_advance.main` —— 抽取式失效，臂失去意义"
    assert "state_lock(" in body, (
        "`gk_advance.main` 未持 `state_lock` ⟹ advance 的读-判-写非原子（并发写者丢更新）")
    assert re.search(r"with state_lock\([^)]*\):\s*\n\s*result = _run\(", body), (
        "`state_lock` 未包住 `_run(...)` —— 持锁区间不是整个 RMW")


# ── RC1（写通路多入口）判据面：CLI 内联**父 state** 写点穷举（2026-09-25 实测复核）──
# 既有守卫（`test_gk_state_write_single_entry.py` arm③ `test_state_inline_dump_sites_converged`）
# 的 regex = `json[.]dump[(][^)]*STATE_FILE` ⟹ **不覆盖** heredoc 截断写（`cat > "$STATE_FILE"`）。
# 本臂把**两类**站点一并纳入上界守卫：非注释行站点数一旦增加即红 —— 逼出「又开了一个写入口」，
# 使「穷举」不再只靠人工 grep 台账。
#   · 实测（HEAD=5ac28b2）`$STATE_FILE` 裸直写 **10** 处：
#     1117/1168/1196/3933/5128/5152/6125/9595/9642/9778
#   · 另有 **1** 处**副本** state 直写（`GK_CF_STATE`，L8182）—— 按设计**排除**：
#     该段只写 isolated crossfull 副本，同段 L8186 有「父 state 只读」负向断言。
#   · heredoc 截断写 **2** 处：989 / 1147（`cmd_discover` 两支）。
_CLI_STATE_DUMP_SITES_MAX = 10
_CLI_STATE_HEREDOC_SITES_MAX = 2


def _cli_code_lines() -> list:
    """CLI 非注释行 → [(行号, 内容)]（逐行跳过首个非空白字符为 `#` 的行）。"""
    return [(i, ln) for i, ln in enumerate(
        CLI.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
        if not ln.lstrip().startswith("#")]


def test_arm15_cli_state_write_sites_enumerated():
    """arm15（守门，**不隶属红先族**）：CLI 内联父 state 写点穷举不增。

    判据意图 = 「单写原语」收敛面的**上界**（非红先）：落刀前该面本就有 N 处，故本臂在
    现状下即绿；它的价值是**回退保护 + 台账锚**（失败消息直接列出站点行号）。
    """
    lines = _cli_code_lines()
    dumps = [(i, ln.strip()) for i, ln in lines
             if re.search(r"json\.dump[(][^)]*STATE_FILE", ln)]
    heredocs = [(i, ln.strip()) for i, ln in lines
                if re.search(r'cat > "\$STATE_FILE"|cat > \$STATE_FILE', ln)]
    assert len(dumps) <= _CLI_STATE_DUMP_SITES_MAX, (
        f"CLI 内联 `$STATE_FILE` 直写站点增至 {len(dumps)}（穷举上界 {_CLI_STATE_DUMP_SITES_MAX}）"
        " ⟹ 又多了一个写入口（R18 单写原语收敛面回退）:\n"
        + "\n".join(f"  {i}: {ln}" for i, ln in dumps))
    assert len(heredocs) <= _CLI_STATE_HEREDOC_SITES_MAX, (
        f"CLI heredoc 截断写站点增至 {len(heredocs)}（上界 {_CLI_STATE_HEREDOC_SITES_MAX}）:\n"
        + "\n".join(f"  {i}: {ln}" for i, ln in heredocs))


# ── L5 体积体检（2026-09-25 · `ECC-75DAED1C537C`）──
def _production_state():
    """生产 state 落点（与 `gatekeeper-cli.sh` 启动块**同源**）：worktree 根 → 主树。

    技能仓以 git worktree 开发时，治理对象是**主树** state（启动块 `git rev-parse
    --git-common-dir` 的父目录）；纯 clone 无任何 state ⟹ 返回 None（由臂内超墙夹具兜底）。
    """
    local = SD / ".gatekeeper.state"
    if local.is_file():
        return local
    try:
        p = subprocess.run(["git", "-C", str(SD), "rev-parse", "--git-common-dir"],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0 or not p.stdout.strip():
        return None
    common = Path(p.stdout.strip())
    if not common.is_absolute():
        common = SD / common
    main = common.parent / ".gatekeeper.state"
    return main if main.is_file() else None


def test_arm16_state_size_metered(tmp_path):
    """arm16（守门，**不隶属红先族**）：体积体检口径自测 + 生产 state 硬墙守门。

    仪表意义（实测）：`subagent_history` 的 80,364 B **不是「忘加 cap」** —— 是
    `gatekeeper-cli.sh` `_HIST_MAX_BYTES=81920` 的**配额满额运行**；而该配额的预算依据
    （2026-09-14）算的是「非 history 分量 95,413 B」，**实测已涨到 160,013 B** ⟹ 依据过期。
    各子系统各自定价、无人汇总 ⟹ 谁膨胀就吃掉他人预留。本臂把「体积 + 单键占比」变成可机检，
    使配额调整有**活值**可依。
    """
    import gk_json_utils as J

    # ① 口径自测（tmp，与生产 state 解耦）
    s = tmp_path / "s.json"
    payload = {"gate_data": {"big": ["x" * 500] * 20, "small": 1}}
    s.write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                 encoding="utf-8", newline="\n")
    rep = J.state_size_report(str(s))
    assert rep["ok"] and not rep["over_wall"], rep
    assert rep["disk_bytes"] == rep["canon_bytes"] and not rep["form_diverged"], rep
    assert rep["top_keys"][0]["key"] == "gate_data", rep
    assert rep["gate_data_sub"][0]["key"] == "big", rep
    heavy = [w for w in rep["warnings"] if w.startswith("SINGLE_KEY_HEAVY")]
    assert heavy and "gate_data" in heavy[0], (
        "单键占比告警未触发（判据失效）: " + json.dumps(rep["top_keys"], ensure_ascii=False))

    # ② 预留阈值本身可判（reserve=墙 ⟹ 阈值 0 ⟹ 任何非空 state 都应 LOW_MARGIN）
    tiny = J.state_size_report(str(s), reserve=J.STATE_SIZE_WALL)
    assert any(w.startswith("LOW_MARGIN") for w in tiny["warnings"]), tiny

    # ③ 生产 state 硬墙守门。⚠ 生产 state 被并发会话写 ⟹ 本臂是**运行时守门**；
    #    若真越墙而红，属**真实告警**（state 撑爆），不得当假红/自身回归处理。
    #    2026-10-29（去存量跳过）：落点与 CLI 启动块**同源** —— 技能仓 worktree 形态下治理对象
    #    是**主树** state（`git rev-parse --git-common-dir` 的父目录）；原实现只看 worktree 根
    #    ⟹ 恒不存在 ⟹ 恒 skip（跳过的是可跑的真守门）。落点不存在（纯 clone）时改由**超墙夹具**
    #    自证判据仍可判 —— 任何环境都有真断言，不再静默跳过。
    over = tmp_path / "over_wall.json"
    over.write_text(json.dumps({"gate_data": {"x": "y" * J.STATE_SIZE_WALL}}),
                    encoding="utf-8", newline="\n")
    over_rep = J.state_size_report(str(over))
    assert over_rep["ok"] is False and over_rep["over_wall"], (
        "超墙夹具未被判越墙 ⟹ 硬墙判据失效（阈值比对形同虚设）")
    assert any(w.startswith("OVER_WALL") for w in over_rep["warnings"]), over_rep["warnings"]

    prod = _production_state()
    if prod is not None:
        preal = J.state_size_report(str(prod))
        assert preal["ok"], (
            "state 已越硬墙（canon %d > wall %d）—— 须先裁体积再裁决：%s"
            % (preal["canon_bytes"], preal["wall"],
               json.dumps(preal["gate_data_sub"][:5], ensure_ascii=False)))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
