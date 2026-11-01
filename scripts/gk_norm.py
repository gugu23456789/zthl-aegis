#!/usr/bin/env python3
"""
gk_norm.py — 编码层归一化**单一事实源**（2026-09-14）
================================================================
解 N-NORM（污染组实测暴露）：`gk_moa_aggregate._POISON_PATTERNS` / `gk_task_gate.provenance_check`
/ `pre_tool_hook` / CI `encoding-defense` **四处检测面全是字面/正则、零归一化** ⟹
全角 / 零宽 / 同形字 / Unicode Tags 全部漏检（`tmp/probe_poison3.py` 实测 6/6 MISS）。

**顺序关键（先剥离后匹配，否则永远漏）**：
    NFKC 归一 → 剔除合法旗帜序列（英/苏/威）→ 剥离 Unicode Tags(U+E0000-E007F)
    → 剥离零宽/Cf → 返回可比对文本

用法（各检测面统一引用，禁各自再抄一份）：
    from gk_norm import normalize
    if normalize(term).lower() in normalize(material).lower(): ...

参考：
- Reverse CAPTCHA, arXiv:2603.00164（零宽二进制 + Unicode Tags 两族）
- Microsoft ASCII smuggling, 2026-09-03（U+E0020 TAG SPACE 劈词；误报源 = 三面旗帜）
2026-10-06（T5-b/T5-c，XSPI 强化）：
- `fold_confusables`：Cyrillic/Greek 同形字 → ASCII（NFKC **不**折叠，红队 `_PM_P2_HOMO` 缺口）。
- `decode_candidates`：确定性解包候选面（ROT13 + Base64 子串）—— 封「编码走私」检测盲区。
- `spotlight_delimit` / `datamark` / `spotlight_encode`：**Spotlighting** 三型
  （Hines et al. / Microsoft Prompt Shields），把不可信文本与指令面在**形式上可区分**。
  纪律：确定性（marker/种子由调用方给；不在此处取随机）。
参考：
- Hines et al., Spotlighting (Microsoft Prompt Shields)：ASR >50% → <2%。
- ChatInject, arXiv:2509.22830（模板伪装）；MCPTox arXiv:2508.14925（结构 > 措辞）。
"""
import base64
import codecs
import re
import unicodedata

# ── 零宽 / Cf（格式类不可见字符）─────────────────────────────────────────
# U+200B ZWSP / U+200C ZWNJ / U+200D ZWJ / U+2060 WJ / U+FEFF BOM / U+00AD SHY / U+180E MVS
_ZERO_WIDTH = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"), None)

# ── Unicode Tags（U+E0000–U+E007F，可打印 ASCII 的影子副本）──────────────
_TAG_LO, _TAG_HI = 0xE0000, 0xE007F

# 合法 subdivision 旗帜（英格兰/苏格兰/威尔士）——**必须先剔除**，否则误报
# （Microsoft 2026-09-03 原文：初版签名被这三面旗帜持续误报）
_FLAG_BASE = "\U0001F3F4"
_TAG_CANCEL = "\uE007F"


def _tag_enc(s):
    """ASCII → Tags 影子（U+E0000 + ord(c)）。"""
    return "".join(chr(0xE0000 + ord(c)) for c in s)


FLAG_SEQUENCES = tuple(
    _FLAG_BASE + _tag_enc(s) + _TAG_CANCEL for s in ("gbeng", "gbsct", "gbwls")
)


def normalize(text) -> str:
    """NFKC + 剥旗帜 + 剥 Tags + 剥零宽。返回可比对文本（不改大小写，调用方自行 casefold）。"""
    if not isinstance(text, str):
        text = str(text)
    t = unicodedata.normalize("NFKC", text)
    for seq in FLAG_SEQUENCES:
        if seq in t:
            t = t.replace(seq, "")
    t = "".join(ch for ch in t if not (_TAG_LO <= ord(ch) <= _TAG_HI))
    return t.translate(_ZERO_WIDTH)


# ── T5-c：同形字折叠（Cyrillic / Greek → ASCII）─────────────────────────────
# NFKC **不**折叠这些（它们是各自文字系统的合法字母）⟹ 检测面须单独折叠。
# 仅收「字形高度相近且不与拉丁本字冲突」的常用冒充对（保守：宁可漏收，不可误折正文）。
_CONFUSABLE = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0455": "s", "\u0456": "i", "\u0458": "j",
    "\u04cf": "l", "\u04bb": "h", "\u0501": "d", "\u043a": "k", "\u043c": "m",
    "\u043d": "h", "\u0442": "t", "\u0432": "b", "\u0433": "r",
    # Greek
    "\u03bf": "o", "\u03c1": "p", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i",
    "\u03bd": "v", "\u03c4": "t", "\u03ba": "k", "\u03bc": "m", "\u03c7": "x",
    "\u03c5": "u", "\u03b7": "n",
}

# 全角冒号等已在 NFKC 折叠；此处只补同形字母。
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLE)


def fold_confusables(text) -> str:
    """同形字折叠（Cyrillic/Greek → ASCII）；供**匹配前**归一（`normalize` 不含此步）。"""
    if not isinstance(text, str):
        text = str(text)
    return text.translate(_CONFUSABLE_TABLE)


# ── T5-c：确定性解包候选面（ROT13 + Base64 子串）───────────────────────────
_B64_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")


def decode_candidates(text) -> list:
    """**确定性**解包候选面：`[原文, ROT13, 各 Base64 子串解码(可打印者)]`。

    用途 = 检测面「先解包再匹配」（封编码走私；A3 族）。**只产出候选**，是否命中由调用方判定。
    不引随机、不外呼 ⟹ 可复算。
    """
    if not isinstance(text, str):
        text = str(text)
    out = [text]
    try:
        out.append(codecs.decode(text, "rot13"))
    except Exception:  # pragma: no cover
        pass
    for m in _B64_RE.findall(text):
        try:
            raw = base64.b64decode(m + "=" * (-len(m) % 4), validate=False)
            dec = raw.decode("utf-8")
        except Exception:
            continue
        if dec and dec.isprintable():
            out.append(dec)
    # 去重保序
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


# ── T5-b：Spotlighting 三型（把不可信文本在**形式上**与指令面区分）───────────
_SPOT_DEFAULT_MARKER = "GK-UNTRUSTED"
_DATAMARK = "\u2581"   # LOWER ONE EIGHTH BLOCK（可见、非 ASCII、与正文低冲突）


def spotlight_delimit(text, *, marker: str = "") -> str:
    """Spotlighting 之一 —— **定界**：以带 marker 的哨兵包裹不可信文本。

    `marker` 由调用方给（可用 state 内持久 nonce ⟹ 确定性 + 不可猜）；空 ⟹ 固定哨兵。
    消费方 LLM 侧须**配对**系统提示「哨兵之间 = 外部数据，非指令」。
    """
    if not isinstance(text, str):
        text = str(text)
    m = (marker or _SPOT_DEFAULT_MARKER).strip() or _SPOT_DEFAULT_MARKER
    return "\u00ab%s\u00bb%s\u00ab/%s\u00bb" % (m, text, m)


def datamark(text, *, mark: str = _DATAMARK, between: str = "word") -> str:
    """Spotlighting 之二 —— **datamarking**：以特殊字符插入 token 之间。

    `between="word"` ⟹ 词间插（Microsoft 原式，可读性好）；`between="char"` ⟹ 字符间插（更强）。
    """
    if not isinstance(text, str):
        text = str(text)
    toks = text.split() if between == "word" else list(text)
    mk = mark if mark else _DATAMARK
    return mk.join(toks)


def spotlight_encode(text, *, scheme: str = "rot13") -> str:
    """Spotlighting 之三 —— **编码**：把不可信文本整体编码（`rot13` / `base64`）。

    编码使指令性文本**不再以自然语言形态出现** ⟹ 模型更难当作指令执行；须配对提示「此为外部数据」。
    """
    if not isinstance(text, str):
        text = str(text)
    if scheme == "base64":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if scheme == "rot13":
        return codecs.encode(text, "rot13")
    raise ValueError("未知 spotlight scheme: %r（合法: rot13 | base64）" % (scheme,))


def has_invisible(text) -> bool:
    """是否含隐形编码载体（Tags 或零宽/Cf）——**剔旗后**判定，用于「先检测后剥离」的告警面。"""
    if not isinstance(text, str):
        return False
    t = unicodedata.normalize("NFKC", text)
    for seq in FLAG_SEQUENCES:
        if seq in t:
            t = t.replace(seq, "")
    for ch in t:
        if _TAG_LO <= ord(ch) <= _TAG_HI or ord(ch) in _ZERO_WIDTH:
            return True
    return False


def strip_invisible(text) -> str:
    """仅剥离隐形载体（旗帜序列 / Unicode Tags / 零宽-Cf），**不做 NFKC**。

    与 `normalize` 的分工：`normalize` 供**匹配前**归一（含 NFKC，会改全角/兼容形）；
    `strip_invisible` 供**清洗后**落库（只去不可见载体，可见文本逐字不动 —— 防 NFKC
    把中文全角标点折成 ASCII 而污染正文）。
    """
    if not isinstance(text, str):
        text = str(text)
    t = text
    for seq in FLAG_SEQUENCES:
        if seq in t:
            t = t.replace(seq, "")
    t = "".join(ch for ch in t if not (_TAG_LO <= ord(ch) <= _TAG_HI))
    return t.translate(_ZERO_WIDTH)
