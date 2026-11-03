#!/usr/bin/env python3
"""audit --all 六域聚合回归（F-REV-103 / ECC-350134A03D8F / ECC-9F0E3847E481，2026-09-19）。

根因（读码 + 实测）：`cmd_audit` 的 `--all` 分支里，mktemp 临时目录的清理块被插在
**python 聚合之前** —— 建目录并写五域 + report JSON 之后、五个 `cat` 读成死变量之后，
就对那个目录执行递归强制删除；而紧随其后的 python 聚合是**按文件路径重读**
（`sp = sys.argv[1:7]`）⟹ 六个子项全部 `load-failed: [Errno 2] No such file or
directory: '/tmp/tmp.XXXX/<域>.json'`，路径正是**同一次调用内自建自删**的那个 mktemp 目录。
顶层 `ok` 恒 `true` ⟹ **静默假成功**（`advance ECO-AUDIT → ECO-DOC` 的门禁文案宣传
「必须先 audit --all」，实际只能靠 `audit --state` 单域满足 —— 判据是
`gk_node_guard.audit_all_recorded`，不读 `--all` 的返回值）。

本文件锁三条判据（互补：①② 行为/结构面锁「顺序颠倒」，③ 锁「顶层 ok 派生」）：
  ① 六域结果**不得**出现 `No such file or directory`（= 聚合晚于清理的直接反面）
  ② `--all` 分支内，临时目录清理语句的行号**必须大于** python 聚合语句的行号
  ③ 顶层 `ok` **不得**硬编码 —— 须由六域 all-of 派生，并暴露 `failed_domains`

判据 ① 的断言**只锁 ENOENT 签名**，不锁「六域全 ok」—— 沙箱里域自身可能因缺夹具而
失败（那是**另一回事**，不是本缺陷）；只锁「聚合读不到文件」这一条因果。

red-first 对照臂：`GK_CLI_UNDER_TEST=<旧版 CLI 绝对路径>`（默认 = 仓内 CLI）
⟹ 修复前判据 ①② 均必红。

✅ 已覆盖（2026-09-19 本轮落刀）：F-REV-103 落刀建议①「顶层 `ok` 收紧为六域 all-of」
  —— 判据 ①-补（行为面，落在同一次 `--all` 返回上，零额外耗时）② 判据 ③（源码级
  0.7s 常驻门，抽取聚合片段后锁「不得硬编码顶层 ok」+「须派生 `failed_domains`」）。
  实现 = `gatekeeper-cli.sh` 的 `--all` 聚合 python：先算发布面（state/docs 解包 result，
  其余原样），再由发布面自身收集 `ok is False` 的域 ⟹ 顶层 ok 与 `failed_domains`
  **由构造保证一致**（不存在自报与事实不符的第二真值）。
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SKILL_DIR / "gatekeeper-cli.sh"))

DOMAINS = ("state", "docs", "memory", "crossr", "depth", "report")
ENOENT_SIGNATURE = "No such file or directory"


def _wsl(p: Path) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。

    沙箱**必须**在 WSL 侧建：`os.symlink` 在无特权的 Windows 下报 WinError 1314
    （`test_gk_cli_skildir_guard._mk_sandbox` 同形踩点），故改用 WSL bash 的 `ln -s`。
    """
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _setup_sandbox(tmp_path: Path) -> str:
    """建沙箱技能根（WSL 侧）：`scripts` 软链到真 scripts/ + CLI 实拷 + 最小 state。

    `scripts` 软链 = 合法租户（过 SKILL_DIR 校验）。沙箱的**真实目的 = 隔离**：`audit --state`
    会把 `audit_state_result` 写进活动 `gate_data`，直接在仓内跑本用例会**污染真 state**。

    ⚠ 沙箱**不省时间**（实测判据①：沙箱 187.9s vs 仓内 213.8s）—— 耗时主体是
    `audit --depth` 的 131s 与 `--crossr` 的 40s，而 `--state`/`--docs`/`--memory`
    各约 0.5s。轻量常驻门见判据②（0.01s）。
    """
    sb = (tmp_path / "sb").resolve()
    sb.mkdir()
    wsb = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc",
         'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), wsb, _wsl(CLI_SRC), wsb)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    (sb / ".gatekeeper.state").write_text(
        json.dumps({"stage": "STAGE_0", "r_phase": "R1", "worktree": "", "gate_data": {}}),
        encoding="utf-8")
    return wsb


def _run(wsb: str, *args, timeout=420):
    """跑 CLI。`DEEPSEEK_BASE_URL` 指向死端口 ⟹ API 域**快速失败**而非真跑一轮。

    这不是绕过被测面：本缺陷只在「写域 JSON → 删目录 → 按路径重读」这条**文件时序**上
    发生，与域内容好坏无关。实测该开关只把 `report` 域从约 40s 压到 10.6s（`--depth` 131s /
    `--crossr` 40s 不受影响）⟹ 判据① 实测 **177.6–187.9s**，属**已知的重量级端到端门**；
    轻量常驻门 = 判据②（行序不变量，0.02s）。
    """
    env = dict(os.environ)
    env["DEEPSEEK_BASE_URL"] = "http://127.0.0.1:1"
    return subprocess.run(["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh %s'
                           % (wsb, " ".join(args))],
                          capture_output=True, text=True, timeout=timeout, env=env)


def _last_json_object(text: str):
    """取最后一行可解析的 JSON 对象（域自身可能往 stdout 写非 JSON 噪声）。"""
    payload = None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
    return payload


def test_audit_all_domains_not_enoent(tmp_path):
    """判据①：`audit --all` 的六域结果不得出现 ENOENT（聚合必须晚于清理）。"""
    sb = _setup_sandbox(tmp_path)
    r = _run(sb, "audit", "--all")
    out = r.stdout + r.stderr
    payload = _last_json_object(out)
    assert payload is not None, f"audit --all 未产出 JSON：{out[:600]}"
    assert payload.get("audit_mode") == "all", payload
    for dom in DOMAINS:
        assert dom in payload, f"聚合缺字段 {dom}：{list(payload)}"
        sub = payload[dom]
        err = str(sub.get("error", "")) if isinstance(sub, dict) else ""
        assert ENOENT_SIGNATURE not in err, (
            f"{dom} 聚合读不到域 JSON（清理早于读取）：{err}")
    # ── 判据①-补（2026-09-19，F-REV-103 建议① / ECC-350134A03D8F）：顶层 `ok` 收紧 ──
    # 原聚合 python **硬编码 `"ok": True`** ⟹ 六域全失败时顶层仍报成功（静默假成功）。
    # 三条断言都落在**同一次 `--all` 运行**的返回上（零额外耗时），且都不依赖环境：
    #   ③ `failed_domains` 键必须存在（顶层须暴露失败域，供人与门读取）；
    #   ④ 顶层 `ok` 必须与 `failed_domains` 一致（= all-of 语义）；
    #   ⑤ 该清单必须与**实际观测到的**子域 `ok:false` 集合逐字一致（防"自报与事实不符"）。
    assert "failed_domains" in payload, (
        f"顶层未暴露失败域 ⟹ 子项失败不可见（ECC-350134A03D8F）：{list(payload)}")
    obs = sorted(d for d in DOMAINS
                 if isinstance(payload[d], dict) and payload[d].get("ok") is False)
    assert sorted(payload["failed_domains"]) == obs, (
        f"`failed_domains` 与实测子域失败面不符：自报 {payload['failed_domains']} vs 实测 {obs}")
    assert (payload.get("ok") is True) == (not obs), (
        f"顶层 ok 未收紧为六域 all-of：ok={payload.get('ok')} 失败域={obs}")


def _aggregate_src() -> str:
    """从 CLI 源码里**抽取** `--all` 分支的聚合 python 片段（单一事实源，不复制）。"""
    lines = CLI_SRC.read_text(encoding="utf-8").splitlines()
    start = next(i for i, l in enumerate(lines) if "sp = sys.argv[1:7]" in l)
    lo = start
    while lo > 0 and "python3 -c '" not in lines[lo]:
        lo -= 1
    hi = start
    while hi < len(lines) and '_tmp_audit_dir/state.json"' not in lines[hi]:
        hi += 1
    return "\n".join(lines[lo:hi + 1])


def test_aggregator_derives_ok_from_domains():
    """判据③（源码级，0.02s 常驻门）：聚合片段**不得**硬编码顶层 `ok: True`。

    存在理由：判据①-补 跑一次要 ~190s（`--depth` 131s / `--crossr` 40s），不适合每次落刀都跑；
    本判据锁同一因果的**结构面** —— 只要聚合里出现硬编码 `"ok": True`，顶层就必然与子域脱钩。
    ⚠ 只锁「不得硬编码成功」+「须引用 failed_domains」，**不**锁具体写法（防脆断言）。
    """
    src = _aggregate_src()
    assert "sp = sys.argv[1:7]" in src, f"抽取失败（未取到聚合片段）：{src[:200]}"
    assert "failed_domains" in src, (
        f"聚合片段未计算 failed_domains ⟹ 顶层 ok 无法收紧为六域 all-of：{src[:300]}")
    assert src.count('"ok": True') == 0 and src.count('"ok":True') == 0, (
        f"聚合片段仍硬编码顶层 ok:True ⟹ 子项失败被吞（ECC-350134A03D8F）")


# 聚合 python 的 argv 顺序 ≠ DOMAINS 顺序（它的解包是 s, d, m, c, r, dp ⟹ report 在 depth 前）
ARGV_ORDER = ("state", "docs", "memory", "crossr", "report", "depth")


def _aggregate_payload() -> str:
    """只要聚合 python 的**正文**（去掉首行 `all_results=$(python3 -c '` 与尾部参数行）。"""
    lines = _aggregate_src().splitlines()
    assert "python3 -c '" in lines[0], f"抽取首行异常：{lines[0]!r}"
    body = lines[1:]
    if body and body[-1].lstrip().startswith("' "):
        body = body[:-1]
    return "\n".join(body)


def _run_aggregate(tmp_path: Path, files: dict) -> dict:
    """把抽取出的聚合片段**当程序跑**（合成夹具）：

    `files` 里缺席的域 = 不写文件（走 `load()` 的 load-failed 分支）。每次都开新目录，
    避免上一次的域 JSON 残留干扰缺席语义。
    """
    d = Path(tempfile.mkdtemp(dir=tmp_path))
    paths = []
    for name in ARGV_ORDER:
        p = d / (name + ".json")
        if files.get(name) is not None:
            p.write_text(json.dumps(files[name]), encoding="utf-8")
        paths.append(str(p))
    r = subprocess.run([sys.executable, "-c", _aggregate_payload(), *paths],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"聚合片段运行失败：{r.stderr}"
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_aggregator_ok_is_allof_of_domains(tmp_path):
    """判据③-行为（0.05s 常驻门）：合成夹具 ⟹ 顶层 ok 必须 = 六域 all-of。

    存在理由：判据①-补 的 190s 端到端在沙箱里很可能**失败域为空**（六域都跑通），
    那样 all-of 的**负分支**（有域失败 ⟹ 顶层必须 false）根本没被走过；本判据用合成
    夹具补齐该分支，并顺带锁住「state/docs 解包 result 后不带 ok ⟹ 不得被误判为失败」。
    """
    okw = {"ok": True, "audit_mode": "x", "result": {"a": 1}}
    all_ok = {n: dict(okw) for n in DOMAINS}

    p = _run_aggregate(tmp_path, all_ok)
    assert p["ok"] is True and p["failed_domains"] == [], (
        f"六域全绿时顶层不得报失败：ok={p.get('ok')} 失败域={p.get('failed_domains')}")
    assert p["state"] == {"a": 1}, f"state 未按 result 解包（发布面契约变了）：{p['state']}"
    assert p["audit_mode"] == "all", f"audit_mode 丢失：{p.get('audit_mode')}"

    p = _run_aggregate(tmp_path, {**all_ok, "memory": {"ok": False, "error": "boom"}})
    assert p["ok"] is False and p["failed_domains"] == ["memory"], (
        f"单域失败未把顶层拉黑：ok={p.get('ok')} 失败域={p.get('failed_domains')}")

    p = _run_aggregate(tmp_path, {k: v for k, v in all_ok.items() if k != "depth"})
    assert p["ok"] is False and p["failed_domains"] == ["depth"], (
        f"域 JSON 缺席（load-failed）未计入失败域：{p.get('failed_domains')}")


def test_all_branch_cleanup_ordering_invariant():
    """判据②：结构不变量 —— 清理块行号必须大于 python 聚合行号。

    这是**能最早捕获该缺陷**的门：即便沙箱环境让判据①退化，行序颠倒也必被本判据拦下。
    """
    lines = CLI_SRC.read_text(encoding="utf-8").splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == '--all|all|"")'), None)
    assert start is not None, "未找到 cmd_audit 的 --all 分支锚（case 模式行）"
    # 分支结束 = 下一个同级 `;;` 之后紧随的 case 模式行；此处只取聚合与清理两者行序
    agg = next((i for i in range(start, len(lines))
                if "sp = sys.argv[1:7]" in lines[i]), None)
    clean = next((i for i in range(start, len(lines))
                  if '_tmp_audit_dir" == /tmp/*' in lines[i]), None)
    assert agg is not None, "未找到 --all 分支的 python 聚合语句（sp = sys.argv[1:7]）"
    assert clean is not None, "未找到 --all 分支的临时目录清理判据（/tmp/* 白名单）"
    assert clean > agg, (
        f"清理语句（L{clean + 1}）早于 python 聚合（L{agg + 1}）⟹ 聚合按路径重读必 ENOENT")


def test_domain_failures_not_silently_swallowed():
    """ECC-7131658C9F77（2026-11-03）：`audit --all` 的域失败不得被 `2>/dev/null` 静默吞掉。

    病象：首轮 `--all` 的 crossr 域返回**空文件 + 非零 rc**，stderr 被丢弃 ⟹ 聚合只能报
    `load-failed: Expecting value: line 1 column 1`，既看不到真实错误，也拿不到退出码；
    同一命令单独跑 `audit --crossr` 却成功（1/2 偶发）。

    判据（源码级，0.01s 常驻门）：`--all` 分支的域调用与结果读取必须
      ① 不把 stderr 丢进 `/dev/null`；
      ② 保留每域 stderr 与 rc（`.err` / `.rc`）；
      ③ 空/坏 JSON 合成为具名结果（`empty_or_invalid_result`），而不是只留 parse 异常文本。
    """
    lines = CLI_SRC.read_text(encoding="utf-8").splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == '--all|all|"")'), None)
    assert start is not None, "未找到 cmd_audit 的 --all 分支锚（case 模式行）"
    end = next((i for i in range(start, len(lines)) if 'echo "$all_results"' in lines[i]), None)
    assert end is not None, "未找到 --all 分支的最终回包锚（echo $all_results）"
    seg = "\n".join(lines[start:end])
    # 只锁「域调用/域结果读取」这两类行：`_audit_timed_run` 内部对 `kill -0` 的 2>/dev/null
    # 是进程判活语义（与本缺陷无关），不得被本断言误伤。
    io_lines = [l for l in lines[start:end]
                if ("audit --$_ad" in l) or ('cat "$_tmp_audit_dir/' in l)
                or ("audit --report" in l and ">" in l)]
    assert io_lines, f"未抽到 --all 的域 IO 行：{seg[:300]}"
    for l in io_lines:
        assert "2>/dev/null" not in l, (
            f"域 IO 行仍丢弃 stderr ⟹ 静默吞错、拿不到退出码：{l.strip()}")
    for token in (".err", ".rc", "empty_or_invalid_result"):
        assert token in seg, f"缺域失败诊断载体 `{token}` ⟹ 失败不可复核：{seg[:300]}"


def test_all_branch_persists_aggregate_and_registers():
    """E18/B4（2026-10-29，0.01s）：`audit --all` 聚合结果必须**落库**并登记审计署。

    缺口：原分支只 `echo` 聚合 JSON ⟹ 五域证据在 `gate_data` 里、聚合本身却无痕迹，
    「最近一次全量审计」不可复核、也无法进交付门。行序锁「先落库 → 再登记 → 再回包」。
    """
    lines = CLI_SRC.read_text(encoding="utf-8").splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == '--all|all|"")'), None)
    assert start is not None, "未找到 cmd_audit 的 --all 分支锚（case 模式行）"
    persist = next((i for i in range(start, len(lines))
                    if "['audit_all_result']=" in lines[i]), None)
    assert persist is not None, "--all 分支未把聚合结果写入 gate_data.audit_all_result"
    echo = next((i for i in range(persist, len(lines))
                 if 'echo "$all_results"' in lines[i]), None)
    reg = next((i for i in range(persist, echo or len(lines))
                if "--source audit_all" in lines[i]), None)
    assert echo is not None and reg is not None, "落库后缺 echo 回包或 registry 登记"
    assert start < persist < reg < echo, "行序应为：聚合 → 落库 → 登记 → 回包"
