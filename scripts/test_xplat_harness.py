#!/usr/bin/env python3
r"""跨平台安全网 `xplat_harness` 契约测 + 两类跨平台炸弹的源码守卫臂。

背景（2026-11-01，写行为级测试时连踩三个**叠加**坑）：
  ① 多行字符串作单个 argv 元素传 `bash -c` ⟹ MSYS argv 换行转换破坏
     （注释里反引号内容被当命令执行）；
  ② tempfile 给 Windows 反斜杠路径 `<home>` ⟹ MSYS bash 不认（rc=127）；
  ③ `bash -s` + **text-mode** stdin ⟹ Python Windows 把 `\n` 翻译成 `\r\n`
     ⟹ bash 逐行收到 `a=1\r`。
正解 = `bash -s` + **bytes** stdin（本模块 `run_bash`）。

另有两个源码级守卫臂，盯 `gatekeeper-cli.sh` 里的同类炸弹（Windows 反斜杠专属）：
  · `find_manual_json_splices` —— 手工拼 JSON 嵌路径变量 ⟹ `\U` 非法转义 ⟹
    整文件非法 JSON ⟹ 读侧 `json.loads` 失败 ⟹ **伪装成 stale**（2026-11-01 实锤阻断 v1 主线）；
  · `find_sq_path_injections` —— 内联 python `open('$STATE_FILE')` ⟹ `\U` unicodeescape
    SyntaxError（同日调试日志已见真实 SyntaxError）。

⚠ 与 `pre_tool_hook._quote_regions` 的换行防护**正交**：hook 防「放行前的错误分段」，
  本模块防「放行后的 argv/管道字节层破坏」。层次不同，互不覆盖。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import xplat_harness as xh  # noqa: E402

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


# --------------------------------------------------------------------------- #
# A. run_bash 三坑免疫（行为级）
# --------------------------------------------------------------------------- #
def test_a1_multiline_script_with_backtick_comment_not_executed():
    r"""坑①免疫：多行脚本 + **注释内反引号**不得被当命令执行。

    旧写法 `bash -c <单个 argv>` 下，MSYS 的 argv 换行转换会让注释失效，
    反引号内容被 shell 求值（实测报错内容与脚本意图完全无关 = 极难定位）。
    """
    script = (
        "# 注释里的反引号不得被执行: `echo PWNED`\n"
        "a=1\n"
        "b=2\n"
        "echo \"sum=$((a + b))\"\n"
    )
    r = xh.run_bash(script)
    assert r.returncode == 0, r.stderr
    assert "PWNED" not in r.stdout, "注释内反引号被执行 ⟹ argv 层破坏未被免疫"
    assert "sum=3" in r.stdout, r.stdout


def test_a2_no_tempfile_needed_and_posix_path_forms():
    r"""坑②免疫：`run_bash` 不经临时文件路径 ⟹ 无 `C:\...` 形态问题。

    同时校验 `posix_path`/`win_path` 的双形态换算（MSYS=`/c/`、WSL=`/mnt/c/`）。
    """
    assert xh.posix_path("<home>", flavor="msys") == "/c/Users/x"
    assert xh.posix_path("<home>", flavor="wsl") == "<home>"
    assert xh.posix_path("<home>") == "<home>"     # 已 posix 原样
    assert xh.win_path("/mnt/c/a/b") == "C:/a/b"
    assert xh.win_path("/c/a/b") == "C:/a/b"
    assert xh.win_path("C:\\a\\b") == "C:/a/b"
    # run_bash 本身：脚本里出现 Windows 反斜杠字符串也不该炸（它不经 argv）
    r = xh.run_bash("printf '%s' '<home>'")
    assert r.returncode == 0, r.stderr
    assert r.stdout == "<home>"


def test_a3_bytes_stdin_no_crlf_leak():
    r"""坑③免疫：bytes stdin ⟹ 行尾 `\n` 不被 text-mode 翻译成 `\r\n`。

    判据：脚本用 `read` 逐行读 stdin 自身内容，若被翻译成 CRLF，
    则行内容尾部会带 `\r`（`wc -l` 计数也会因 `\r\n\r\n` 类问题失真）。
    判别力：断言 stdout **完全无** `\r`。
    """
    r = xh.run_bash("printf 'l1\\nl2\\nl3\\n' | sed 's/^/X/'")
    assert r.returncode == 0, r.stderr
    assert r.stdout == "Xl1\nXl2\nXl3\n", repr(r.stdout)
    assert "\r" not in r.stdout, "stdout 出现 \\r ⟹ text-mode CRLF 翻译未被免疫"


def test_a4_env_pass_through():
    """env 经 subprocess 传入（而非拼进脚本源码）—— 与仓内「reason 经 env 传入」先例同口径。"""
    r = xh.run_bash("printf '%s' \"$GK_TEST_INJECT\"", env={"GK_TEST_INJECT": "v'al;ue\""})
    assert r.returncode == 0, r.stderr
    assert r.stdout == "v'al;ue\"", repr(r.stdout)


def test_a5_flavor_probe_cached_and_known():
    """flavor 探测结果须为已知枚举且可缓存（一次会话只探一次）。"""
    f1 = xh.bash_flavor()
    assert f1 in ("msys", "wsl", "unknown"), f1
    assert xh.bash_flavor() is f1          # lru_cache 同对象


# --------------------------------------------------------------------------- #
# B. 源码守卫：gatekeeper-cli.sh 里的同类炸弹
# --------------------------------------------------------------------------- #
#: 残差台账（2026-11-09，用户令「不能改的 json 加守护/边界/注释，确保不被误改」）：
#: key = `sha1(" ".join(line.split()))[:12]`（**整行指纹**，行号漂移不影响）；value = 不改原因。
#: 纪律：新增/改动任一行 ⟹ 指纹不在集合 ⟹ 必红（强制重新审计）；修好一条 ⟹ 必须删对应键。
_RESIDUAL_SPLICES = {
    "3f27f70a3e14": "守卫启动期：SKILL_DIR 已判不可信，不能依赖 $SKILL_DIR/scripts/gk_json.py",
    "9eaa2e20e648": "守卫启动期：同上（gk_state.py 不可解析分支）",
    "3b91d5db657d": "discover idle 回显：与 owner/bind 片段拼接，需独立重构（当前路径变量在 JSON 值内）",
    "8631a703fc57": "discover active 回显（带 warnings）：同上，片段拼接重构面",
    "0a1f91028747": "discover active 回显：同上，片段拼接重构面",
    "ff24f8c209b6": "stage 引用回显：$stage/$ref_file 为固定枚举，路径变量只在 [ -f ] 判定里",
    "9d9583c81f0b": "`|| echo \"{}\"` 字面量兜底：JSON 内无变量（误报）",
    "2593fac4f1dd": "同上（monitor_scores 兜底）",
    "77abae1807e3": "ember 失败回显：$_sub 为子命令枚举（非路径）",
    "82cf8fa33e0c": "rejected_edits 为 state_query 产出的**已转义 JSON 片段**；guidance 经 escape",
    "d65b7f27d395": "suggestion 文案：$feature_branch/$branch 为 git 分支名（ref-format 禁反斜杠）",
    "84328efeb3d7": "error 经 gk_json_utils escape；exit_code 数字（路径变量在 escape 命令内，误报）",
    "31092653b3ed": "message 经 escape；commit/verified 为 sha/布尔（同上，误报）",
    "3d758844cc10": "precheck 为 helper 产出的 JSON 片段；stderr_tail 经 json-escape",
    "de99d9f6ee6c": "detail 为 helper 产出的 JSON 片段；stderr_tail 经 json-escape",
    "e8ead5a6f783": "audit --state 兜底字面量：JSON 内无路径变量（变量在 env 前缀）",
    "a29b4ca8440c": "audit --memory 兜底字面量：同上",
    "aca959613119": "audit crossr 兜底字面量：同上",
    "e582349c21d6": "files 为 --len 数字；signed 布尔（路径变量在 field 命令内，误报）",
}


def test_b1_no_manual_json_splice_with_path_vars():
    r"""守卫①：**禁**手工拼 JSON 且嵌路径变量（Windows 反斜杠 ⟹ `\U` 非法转义）。

    实锤（2026-11-01）：`discover` 写 plan 指针用 `echo "{\"state_file\":\"$STATE_FILE\"...}"`
    ⟹ Windows 下 `$STATE_FILE=<home>` ⟹ 文件成**非法 JSON**
    ⟹ 读侧 `json.loads` 抛 `Invalid \escape` ⟹ `d={}` ⟹ `updated` 空
    ⟹ `_pointer_fresh` 返回 False ⟹ reason=**stale**（真因被伪装成过期）。
    正确写法 = `gk_json.py build`（JSON 构造单一事实源）。

    2026-11-09：33 处中已转 14 处；剩余 19 处**逐行指纹入台账**（见 `_RESIDUAL_SPLICES`）。
    判据从「必须 0」改为「新增/改动任一行必红」—— 不是放宽，而是把「无法一次改完的存量」
    钉成**不可误改**的审计面；任何新拼接或残差行改动都必须重新审计。
    """
    import hashlib
    hits = xh.find_manual_json_splices(CLI)
    got = {hashlib.sha1(" ".join(s.split()).encode("utf-8")).hexdigest()[:12]: (n, s)
           for n, s in hits}
    unknown = sorted(k for k in got if k not in _RESIDUAL_SPLICES)
    missing = sorted(k for k in _RESIDUAL_SPLICES if k not in got)
    assert not unknown, (
        "新增/改动的手工拼 JSON 未审计（Windows 反斜杠下可能产出非法 JSON）：\n"
        + "\n".join(f"  L{got[k][0]}: {got[k][1].strip()[:160]}" for k in unknown)
        + "\n修法：改走 python3 \"$SKILL_DIR/scripts/gk_json.py\" build k=v ... "
          "（序列化单一事实源）；确不能改 ⟹ 在本文件 _RESIDUAL_SPLICES 补指纹 + 原因")
    assert not missing, (
        "残差台账有已修复/已变更的条目未同步移除（防止台账腐化）：\n  " + "\n  ".join(missing)
        + "\n修法：删对应 hash（= 一次审阅动作）")


def test_b2_no_inline_python_sq_path_injection():
    r"""守卫②：`STATE_FILE` 的**外部来源**必须经 `_gk_fwd` 归一（真因 C，2026-11-02 改口径）。

    实锤（2026-11-01 调试日志）：
      `File "<string>", line 5  _lk=state_lock('<home>\...')`
      `SyntaxError: (unicode error) 'unicodeescape' ... truncated \UXXXXXXXX escape`

    ⚠ 口径为什么从「禁内联」改成「断言归一」：真因不是"用了内联"，而是**同一个变量有两种
      路径形态**（路由中枢给 `C:\...`、本地拼接给 `/c/...`），只有前者会让 python 源码出现
      `\U`。在**两个外部来源边界**归一（单一事实源 `_gk_fwd`）后，32 处内联拼接同时变安全
      —— 这比逐个改成 env 传参风险低得多，且直接对准真因。
      `find_sq_path_injections` 保留作清单/观测，不再当闸门（不用放宽判据换绿）。
    """
    hits = xh.find_unnormalized_state_sources(CLI)
    assert not hits, (
        "STATE_FILE 存在**未归一的外部来源赋值**（Windows 反斜杠 ⟹ 内联 python \\U SyntaxError）：\n"
        + "\n".join(f"  L{n}: {s.strip()[:160]}" for n, s in hits)
        + "\n修法：STATE_FILE=\"$(_gk_fwd \"$外部变量\")\"（_gk_fwd 是形态归一单一事实源）"
    )


def test_b2b_gk_fwd_behaviorally_neutralizes_backslash():
    r"""守卫②的行为臂：`_gk_fwd` 的输出嵌进 python 单引号字面量**必须可编译**。

    这是 b2 的**判别力自证** —— 只断言"源码里有 `_gk_fwd` 这个词"是假绿（写个空函数也算）。
    这里真的把 `<home>\.trae\...` 过一遍 `_gk_fwd`，再拼成 python 源码编译。
    ⚠ Windows 反斜杠值走 **env** 传入（不经 argv），这正是本安全网存在的理由。
    """
    win = r"<home>\.trae\skills\spz-gatekeeper-r-sequence\.gatekeeper.state"
    cli_posix = xh.posix_path(CLI, xh.bash_flavor())
    script = (
        # 只取函数定义（单行/多行都吃），不 source 整个 CLI（那是会跑 main 的）
        "eval \"$(awk '/^_gk_fwd\\(\\)/{f=1} f{print} f&&/}[[:space:]]*$/{exit}' '%s')\"\n"
        '_gk_fwd "$GK_TEST_WIN"\n'
    ) % cli_posix
    r = xh.run_bash(script, env={"GK_TEST_WIN": win})
    assert r.returncode == 0, f"run_bash 失败：{r.stderr[:300]}"
    fwd = r.stdout.strip()
    assert fwd, "_gk_fwd 无输出（函数未定义 / awk 抽取失败）"
    assert "\\" not in fwd, f"_gk_fwd 输出仍含反斜杠：{fwd!r}"
    assert fwd.startswith("<home>/"), f"_gk_fwd 形态不对：{fwd!r}"

    # 真·判别：归一后的值拼进 python 单引号字面量必须能编译
    compile("d = open('%s', encoding='utf-8')" % fwd, "<gk_fwd>", "exec")

    # 反证：未归一的原值必须**编译不过**（证明这条臂确实有判别力，不是恒绿）
    try:
        compile("d = open('%s', encoding='utf-8')" % win, "<raw>", "exec")
    except SyntaxError:
        pass
    else:                                 # pragma: no cover - 只在判据失效时触发
        raise AssertionError(
            "反证失败：未归一的 Windows 反斜杠路径竟然能编译 ⟹ 本臂无判别力")


def test_b3_backtick_guard_lives_in_single_source():
    """反引号守卫**单一事实源**在 `test_gk_eval_injection`（不在此处复刻弱化版）。

    本臂只做**接线断言**：确认专职守卫仍在（防被误删后无人发现），
    避免出现两份判据不一致的双源。
    """
    dedicated = Path(__file__).resolve().parent / "test_gk_eval_injection.py"
    assert dedicated.exists(), "专职反引号守卫 test_gk_eval_injection.py 丢失"
    src = dedicated.read_text(encoding="utf-8", errors="replace")
    assert "cli_double_quoted_regions_have_no_backticks" in src, \
        "专职守卫函数被改名/删除 ⟹ 反引号判据失去单一事实源"


# --------------------------------------------------------------------------- #
# C. 守卫自身的判别力自证（防「两边都空 ⟹ 假绿」）
# --------------------------------------------------------------------------- #
def test_c1_guards_have_discriminating_power(tmp_path):
    r"""判别力自证：喂**已知坏样本**，两个守卫都必须命中。

    防假绿：若守卫正则写错（恒空），则 B 组两臂恒绿 = 摆设。
    """
    bad = tmp_path / "gatekeeper-cli.sh"
    bad.write_text(
        'echo "{\\"state_file\\":\\"$STATE_FILE\\",\\"ok\\":true}"\n'
        "python3 -c \"import json;d=json.load(open('$STATE_FILE',encoding='utf-8'))\"\n",
        encoding="utf-8", newline="\n",
    )
    j_hits = xh.find_manual_json_splices(bad)
    s_hits = xh.find_sq_path_injections(bad)
    assert j_hits, "守卫①对已知坏样本未命中 ⟹ 判别力缺失（假绿）"
    assert s_hits, "守卫②对已知坏样本未命中 ⟹ 判别力缺失（假绿）"

    good = tmp_path / "good.sh"
    good.write_text(
        'j=$(python3 "$SKILL_DIR/scripts/gk_json.py" build state_file="$STATE_FILE" ok=true)\n'
        "STATE_FILE=\"$STATE_FILE\" python3 -c \"import os,json;d=json.load(open(os.environ['STATE_FILE'],encoding='utf-8'))\"\n",
        encoding="utf-8", newline="\n",
    )
    assert not xh.find_manual_json_splices(good), "守卫①误报正确写法（gk_json.py build）"
    assert not xh.find_sq_path_injections(good), "守卫②误报正确写法（env 传参）"


def test_c2_real_json_pointer_roundtrip_with_backslash_path(tmp_path):
    r"""端到端自证：Windows 反斜杠路径经 `gk_json.py build` 序列化后必须**可读回**。

    复刻实锤病灶的最小闭环：写指针 → `json.loads` → 取 `state_file`/`updated`
    → `_pointer_fresh` 判据可用（而非伪装 stale）。
    """
    import subprocess
    win_state = "<home>\\.trae\\skills\\spz-gatekeeper-r-sequence\\.gatekeeper.state.x"
    r = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "gk_json.py"),
         "build", f"state_file={win_state}", "plan=v1-front", "writer=discover",
         "updated=2026-11-01T06:28:06Z"],
        capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)          # 必须是合法 JSON
    assert d["state_file"] == win_state, d
    assert d["updated"] == "2026-11-01T06:28:06Z", d
    # 反向：手工拼（病灶写法）在同输入下必须产出非法 JSON —— 证明病灶真实存在
    manual = '{"state_file":"%s","plan":"v1-front"}' % win_state
    with pytest.raises(json.JSONDecodeError):
        json.loads(manual)
