"""test_gk_eval_injection.py — CLI `eval "$(...)"` 发射块的 shell 注入面（`ECC-084E37B42CFB`）。

背景（实测，非推测）：
  `gatekeeper-cli.sh` 有两处把 JSON 值经 python 打印后用 `eval` 读入 shell 变量
  （`_read_plan_metadata` 的 META 块 L596-605、worktree 块 L879-889）。
  原发射用 Python `repr()` —— **`repr()` 不是 shell 安全的序列化器**：
  值含单引号时 `repr` 会改用**双引号**包裹，于是值里的 `$(...)` / 反引号**落在双引号内**
  ⟹ 被 bash 当真命令展开。病象 = `json.dump: command not found` /
  `command substitution: syntax error near unexpected token '||'`
  （即 finding 记的「内插文本被当 shell 代码」）。
  静态门禁查不到它：`bash -n gatekeeper-cli.sh` **rc=0**（引号在静态上是配平的，
  注入只在**运行期**由值的形态触发）。

判据（红先 + 对照臂）：
  ① 正臂：用**从 CLI 源码切出的真实发射块**跑一次 —— 注入载荷**不得**产生副作用，
     且变量值须**逐字**回读（语义不变）；
  ② 对照臂（判别力自证）：把同一块里的 `shlex.quote` 换回 `repr` ⟹ 副作用**必须**出现
     —— 证明正臂不是恒绿空臂。

安全网 R1：只写 `tmp_path`；不 patch 标准库；不执行任何外部载荷（载荷是固定哨兵路径）。
"""
import json
import re
import shlex
import subprocess
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"

_TAIL = '\n" 2>>"$GK_DBG_LOG")"'


def _extract(anchor: str) -> str:
    """切出以 `anchor` 开头的 `eval "$(echo ...)"` 块（**真实源文本**，非副本）。"""
    src = CLI.read_text(encoding="utf-8")
    i = src.index(anchor)
    j = src.index(_TAIL, i)
    return src[i:j] + _TAIL


_BLOCKS = {
    "meta": {
        "anchor": '  eval "$(echo "$_meta_json" | python3 -c "',
        "var": "_meta_json",
        "read": "META_target_repo",
        "make": lambda p: {"meta": {"target_repo": p}},
    },
    "worktree": {
        "anchor": '  eval "$(echo "$_wt_json" | python3 -c "',
        "var": "_wt_json",
        "read": "worktree",
        "make": lambda p: {"worktree": p},
    },
}


def _run(tmp_path, kind: str, transform=None):
    cfg = _BLOCKS[kind]
    sentinel = tmp_path / ("PWNED_" + kind)
    payload = "x'$(touch %s)'" % sentinel
    block = _extract(cfg["anchor"])
    if transform is not None:
        block = transform(block)
    h = tmp_path / ("h_" + kind + ".sh")
    h.write_text(
        "set -u\n"
        + cfg["var"] + "="
        + shlex.quote(json.dumps(cfg["make"](payload), ensure_ascii=False)) + "\n"
        + "GK_DBG_LOG=" + shlex.quote(str(tmp_path / "dbg.log")) + "\n"
        + block + "\n"
        + 'printf \'%s\' "$' + cfg["read"] + '"\n',
        encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", str(h)], capture_output=True, text=True)
    return r, sentinel, payload


def test_meta_emitter_rejects_shell_injection(tmp_path):
    """正臂：META 发射块不得执行值里的 `$(...)`，且值须逐字回读。"""
    r, sentinel, payload = _run(tmp_path, "meta")
    assert r.returncode == 0, r.stderr
    assert not sentinel.exists(), (
        "注入生效 —— 值里的 `$(...)` 被 `eval` 当真命令执行了"
        f"（发射器不是 shell 安全序列化器）；stderr:\n{r.stderr}")
    assert r.stdout == payload, f"变量值未逐字回读：{r.stdout!r} != {payload!r}"


def test_worktree_emitter_rejects_shell_injection(tmp_path):
    """正臂：worktree 发射块同上（同类缺陷的第二个落点）。"""
    r, sentinel, payload = _run(tmp_path, "worktree")
    assert r.returncode == 0, r.stderr
    assert not sentinel.exists(), (
        f"注入生效（worktree 发射块）；stderr:\n{r.stderr}")
    assert r.stdout == payload, f"变量值未逐字回读：{r.stdout!r} != {payload!r}"


def test_control_repr_form_does_inject(tmp_path):
    """对照臂（判别力自证）：把 `shlex.quote` 换回 `repr` ⟹ 注入**必须**出现。"""
    r, sentinel, _ = _run(
        tmp_path, "meta",
        transform=lambda b: b.replace("shlex.quote(", "repr(").replace("import shlex\n", ""))
    assert sentinel.exists(), (
        "对照臂未触发注入 ⟹ 夹具失效，正臂判别力不可证；stderr:\n" + r.stderr)


# ─── 落库块载荷的**反引号**不变量（`ECC-DCC2B8B80AAC`，2026-09-24）────────────────────
# 与上文 `eval` 发射块**同根因族**（bash 双引号内的内容 = 命令替换/变量展开面），但判据不同轴：
#   上文正臂跑「**值形态**触发的注入」；本臂钉「**源码字面**」——载荷里的注释写反引号
#   同样会触发命令替换。实测病象（2026-09-24 plan-refinement 组A/B 派发收尾）：
#   `json.dump: command not found` + `command substitution: syntax error near unexpected token '||'`
#   —— 与 `ECC-084E37B42CFB` **同病象串但不同源** ⟹ 诊断会被误导到 META 发射块（本轮实测即先误判）。
# 该载荷是**脚本字面**（非运行期值形态）⟹ 静态即可判定，属源码不变量，故用静态臂。
def test_monitor_history_payload_has_no_backticks():
    """`monitor --subagent` 落库块的**内联 python 载荷**（bash 双引号内）不得含反引号。

    后果面（本轮实测）：注释里的反引号对被当命令执行 ⟹ stderr 噪声；因替换结果落在注释内
    为空串，写库本身未失败（`gate_data.subagent_last` 已正确落库）——但噪声与真因同形，
    且若换成**非注释**位置即会破坏 python 源（同族事故见 `ECC-084E37B42CFB`）。
    """
    src = CLI.read_text(encoding="utf-8")
    i = src.index('echo "$subagent_out" | GK_TASK=')
    # 2026-09-27 修（本臂**腐化假阳性**）+ C3① 边界更新：正确边界 = 该 payload **自己的**
    # 收尾行（列 0 的 `"` + 重定向）⟹ 取 `\n" 2>>`（C3① 前为 `" 2>/dev/null || true`，
    # 改 fail-loud 后为 `" 2>>"${GK_DBG_LOG…}" || {…}`；`i` 之后首次出现即该收尾行）。
    k = src.index('\n" 2>>', i)
    payload = src[i:k]
    bad = [ln.strip() for ln in payload.splitlines() if "`" in ln]
    assert not bad, (
        "落库块内联 python 载荷含反引号 ⟹ 运行期触发 bash 命令替换：\n" + "\n".join(bad))


def _dq_backtick_hits(src: str):
    """返回 `[(行号, span)]`：落在 **bash 双引号区内** 的 ASCII 反引号。

    词法（上下文栈）：`normal` / `dq` 两种上下文，各自规则与 bash 一致：
      · `dq` 内 `` ` `` = 命令替换 ⟹ **记 hit**（本臂判据，未放松）；`\\` 转义；`"` 退出 dq；
      · `dq` 内 `$(` 是**新的命令上下文**（引号在其中重新生效，配对 `)` 后回到 dq）；
      · `normal` 内 `'…'`、`$'…'`、`#` 注释、`<<EOF` / `<<-EOF` heredoc 体、`$( … )` 嵌套；
      · 任何上下文遇到换行都计行号（旧实现在被跳过的区间里漏计 ⟹ 报告行号漂移）。

    [2026-10-29] 旧实现是「三态 + 上一字符」的**线性**词法，缺 `$( … )` 嵌套与 heredoc 两条语义 ⟹
    在 L9224 `tr -d '"\\\\'`（`"` 属于内层 sq，却被当成外层 dq 的收尾）处**失步**，此后整片
    源码被误判为「双引号区外」，最终把 `audit --verify` 三个**单引号** python 载荷里的正则
    反引号误报成 dq 命中（8 条 FP，`arm: test_cli_double_quoted_regions_have_no_backticks`）。
    """
    hits = []
    n = len(src)
    line = 1

    def _skip_sq(i, ansi):
        """`i` 指向单引号**之后**；返回收尾引号之后的位置。ansi=True 时 `\\'` 不算收尾。"""
        nonlocal line
        while i < n:
            c = src[i]
            if c == "\n":
                line += 1
            elif c == "\\" and ansi:
                i += 2
                continue
            elif c == "'":
                return i + 1
            i += 1
        return n

    def _skip_bt(i):
        """`i` 指向开引号**之后**；返回收尾引号之后的位置（反引号内 `\\`` 转义）。"""
        nonlocal line
        while i < n:
            c = src[i]
            if c == "\n":
                line += 1
            elif c == "\\":
                i += 2
                continue
            elif c == "`":
                return i + 1
            i += 1
        return n

    def _skip_heredoc(i, delim, strip_tabs):
        """`i` 指向**首行末尾换行之后**；跳过正文直到分隔符行，返回其换行之后的位置。"""
        nonlocal line
        while i < n:
            k = src.find("\n", i)
            if k < 0:
                k = n
            seg = src[i:k]
            if strip_tabs:
                seg = seg.lstrip("\t")
            if k < n:
                line += 1
            i = k + 1 if k < n else n
            if seg == delim:
                return i
        return n

    ctx = ["normal"]      # 上下文栈（栈顶有效）
    parens = [0]          # 与 ctx 对齐：该层 normal 上下文内未闭合的 `(`
    pending = []          # 待跳过的 heredoc：[(delim, strip_tabs)]
    i = 0
    prev = "\n"
    while i < n:
        c = src[i]
        top = ctx[-1]
        if c == "\n":
            line += 1
            i += 1
            prev = "\n"
            while pending and top == "normal":
                delim, strip_tabs = pending.pop(0)
                i = _skip_heredoc(i, delim, strip_tabs)
            continue
        if c == "\\":
            if i + 1 < n and src[i + 1] == "\n":
                line += 1
            i += 2
            prev = "\\"
            continue
        if top == "dq":
            if c == '"':
                ctx.pop()
                parens.pop()
                i += 1
                prev = '"'
                continue
            if c == "`":
                j = _skip_bt(i + 1)
                hits.append((line, src[i:j].splitlines()[0][:80]))
                i = j
                prev = "`"
                continue
            if c == "$" and i + 1 < n and src[i + 1] == "(":
                ctx.append("normal")
                parens.append(1)      # `$(` 已消费，深度从 1 起算
                i += 2
                prev = "("
                continue
            i += 1
            continue
        # ── normal 上下文 ──
        if c == "'":
            i = _skip_sq(i + 1, ansi=False)
            prev = "'"
            continue
        if c == "$" and i + 1 < n and src[i + 1] == "'":
            i = _skip_sq(i + 2, ansi=True)
            prev = "'"
            continue
        if c == '"':
            ctx.append("dq")
            parens.append(0)
            i += 1
            prev = '"'
            continue
        if c == "#" and (prev == "\n" or prev in " \t;|&()<>"):
            j = src.find("\n", i)
            i = n if j < 0 else j
            prev = "#"
            continue
        if c == "`":
            i = _skip_bt(i + 1)
            prev = "`"
            continue
        if c == "<" and prev != "<" and i + 1 < n and src[i + 1] == "<" \
                and (i + 2 >= n or src[i + 2] != "<"):
            m = re.match(r"<<(-?)[ \t]*(?:'([^']*)'|\"([^\"]*)\"|([A-Za-z0-9_@./+-]+))", src[i:])
            if m and (m.group(2) or m.group(3) or m.group(4)):
                pending.append((m.group(2) or m.group(3) or m.group(4), m.group(1) == "-"))
                i += m.end()
                prev = ">"
                continue
        if c == "(":
            parens[-1] += 1
            i += 1
            prev = "("
            continue
        if c == ")":
            if parens[-1] > 0:
                parens[-1] -= 1
                if parens[-1] == 0 and len(ctx) > 1:
                    ctx.pop()
                    parens.pop()
            i += 1
            prev = ")"
            continue
        prev = c
        i += 1
    return hits


# ─── 扫描器自检（守「判据未放松」：既抓真命中，也不在已知 idiom 上误报）──────────────
def test_dq_scanner_semantics_selftest():
    """`_dq_backtick_hits` 的判别力与零误报面（每条都对应一类 bash 语义）。"""
    def hits(s):
        return [h[0] for h in _dq_backtick_hits(s)]
    # ① 真命中：双引号内的反引号 = 命令替换
    assert hits('echo "a `id` b"\n') == [1]
    # ② 单引号内 = 字面
    assert hits("echo 'a `id` b'\n") == []
    # ③ 注释内 = 字面
    assert hits("# `id`\necho ok\n") == []
    # ④ `"'"$v"'"` 拼接 idiom 之后仍在单引号区（= 旧实现失步点）
    idiom = (
        "x=$(python3 -c '\n"
        'with open("\'"$p"\'") as f: c=f.read()\n'
        'm = re.search(r"a: `(.+)`", c)\n'
        "'\n"
        ")\n"
    )
    assert hits(idiom) == []
    # ⑤ 双引号内的 `$( … )` 是**新上下文**：内层 `"` 不结束外层 dq
    assert hits('x="$(tr -d \'"\\\\\' ) tail"\n') == []
    assert hits('x="$(echo "inner") `id`"\n') == [1]
    # ⑥ heredoc 体整段跳过（引号/反引号均为字面）
    assert hits("cat <<'EOF'\n\"a `id` b\"\nEOF\necho ok\n") == []
    # ⑦ 行号不漂移：跳过区间内的换行也计数
    assert hits("cat <<'EOF'\nx\nx\nEOF\necho \"`id`\"\n") == [5]
    # ⑧ here-string `<<<` **不是** heredoc（误判会把其后整片源码吞进「正文」⟹ 假阴性）
    assert hits('read -r a b <<< "$x"\necho "`id`"\n') == [2]


def test_cli_double_quoted_regions_have_no_backticks():
    """CLI **全域**：双引号区内不得有 ASCII 反引号（`ECC-186B99627299` 族）。

    上一条臂只钉 `monitor --subagent` 落库那**一个**载荷 ⟹ 同类实例换个载荷即漏网。
    2026-09-26 实测：`_grant_node_budget` 的 `_state_write` 载荷注释内即有一处
    `` `min(<cur>+$_g,$CAP)` ``（`<cur` 会被当输入重定向、`min` 被当命令执行）。
    本臂把判据升为**全文件不变量**：反引号只允许出现在单引号区或注释里。
    """
    hits = _dq_backtick_hits(CLI.read_text(encoding="utf-8"))
    assert not hits, (
        "gatekeeper-cli.sh 双引号区内含 ASCII 反引号 ⟹ bash 运行期命令替换：\n"
        + "\n".join("L%d %s" % h for h in hits))
