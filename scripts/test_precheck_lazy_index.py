"""test_precheck_lazy_index.py — 处置前回环闸 · 惰性仓索引（§9-6），红先 5 臂。

背景：`gk_finding._scan_drift` / `scan_title_anchors` 曾**无条件**先 `gk_plan_lint._build_index(root)`
（`os.walk` 整仓）再由 `_resolve_path` 逐锚解析；而 `_resolve_path` 是「直连优先、basename 兜底」
⟹ 仓内相对路径锚（绝大多数）直连即命中，那次全仓 walk **纯属白做**。

判据（落刀前 HEAD 基线：**1/2/3/4 红、5 绿**）：
  arm1 `_lazy_index` API + `_resolve_path` 兼容 callable（HEAD 无 `_lazy_index` ⟹ 红）
  arm2 直连锚 ⟹ 经 `_scan_drift` 零 `_build_index`（HEAD 无条件建 ⟹ 红）
  arm3 直连锚 ⟹ 经 `scan_title_anchors` 零 `_build_index`（HEAD 无条件建 ⟹ 红）
  arm4 basename 兜底仍命中 + 索引只建一次（HEAD 无 `_lazy_index` ⟹ 红）
  arm5 零回归守卫（dict 形态 / 直连命中 / 未命中 None）—— HEAD 绿、落刀后仍绿

安全网：只写 tmp_path；不 patch 标准库；不执行外部载荷；不读网络。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))


def _mk_repo(tmp_path, rel_texts):
    repo = tmp_path / "repo"
    for rel, text in rel_texts.items():
        fp = repo / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(text, encoding="utf-8")
    return str(repo)


def _state_with(path, findings):
    path.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}), encoding="utf-8")
    return str(path)


def _counting_build_index(monkeypatch, pl):
    """把 `gk_plan_lint._build_index` 换为计数器（保原行为，记调用次数）。"""
    calls = {"n": 0}
    real = pl._build_index

    def _counting(repo):
        calls["n"] += 1
        return real(repo)

    monkeypatch.setattr(pl, "_build_index", _counting)
    return calls


# ─── arm1：`_lazy_index` API + `_resolve_path` 兼容 callable（HEAD 无符号 ⟹ 红）────
def test_arm1_lazy_index_api(tmp_path):
    import gk_plan_lint as pl
    assert hasattr(pl, "_lazy_index"), "HEAD 无 _lazy_index ⟹ 红"
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})
    get = pl._lazy_index(root)
    assert callable(get), "`_lazy_index` 须返回零参可调用（供 `_resolve_path` 惰性触发）"
    # 直连命中（不该触发兜底）
    assert pl._resolve_path("real.py", root, get) == str(Path(root) / "real.py")
    # basename 兜底（首次触发 walk）
    assert pl._resolve_path("sub/real.py", root, get) == str(Path(root) / "real.py")


# ─── arm2：直连锚 ⟹ `_scan_drift` 零 `_build_index`（HEAD 无条件建 ⟹ 红）────────
def test_arm2_scan_drift_direct_anchor_skips_walk(tmp_path, monkeypatch):
    import gk_plan_lint as pl
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})
    monkeypatch.setattr(gf, "DEFAULT_SKILL", root, raising=False)
    calls = _counting_build_index(monkeypatch, pl)
    st = _state_with(tmp_path / "d.json",
                     [{"id": "ECC-D", "status": "open", "title": "见 real.py:1 处"}])
    gf._scan_drift(st, ["ECC-D"])
    assert calls["n"] == 0, ("直连锚不得触发全仓 walk（§9-6）；", calls["n"])


# ─── arm3：直连锚 ⟹ `scan_title_anchors` 零 `_build_index`（HEAD 无条件建 ⟹ 红）──
def test_arm3_scan_title_anchors_direct_anchor_skips_walk(tmp_path, monkeypatch):
    import gk_plan_lint as pl
    import gk_finding as gf
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})
    calls = _counting_build_index(monkeypatch, pl)
    st = _state_with(tmp_path / "s.json",
                     [{"id": "ECC-S", "status": "open", "title": "见 real.py:1 处"}])
    gf.scan_title_anchors(st, root)
    assert calls["n"] == 0, ("直连锚不得触发全仓 walk（§9-6）；", calls["n"])


# ─── arm4：basename 兜底仍命中 + 索引只建一次（HEAD 无 `_lazy_index` ⟹ 红）────────
def test_arm4_basename_fallback_builds_at_most_once(tmp_path, monkeypatch):
    import gk_plan_lint as pl
    root = _mk_repo(tmp_path, {"deep/real.py": "a\nb\n"})
    calls = _counting_build_index(monkeypatch, pl)
    get = pl._lazy_index(root)
    assert pl._resolve_path("deep/real.py", root, get) == str(Path(root) / "deep" / "real.py")  # 直连
    assert pl._resolve_path("x/real.py", root, get) == str(Path(root) / "deep" / "real.py")      # 兜底→walk
    assert pl._resolve_path("y/real.py", root, get) == str(Path(root) / "deep" / "real.py")      # 兜底→复用
    assert calls["n"] == 1, ("兜底索引须只建一次；", calls["n"])


# ─── arm5：零回归守卫（dict 形态 / 直连命中 / 未命中 None）—— HEAD 绿、落刀后仍绿 ──
def test_arm5_zero_regression_direct_and_missing(tmp_path):
    import gk_plan_lint as pl
    root = _mk_repo(tmp_path, {"real.py": "a\nb\n"})
    plain = pl._build_index(root)                    # dict 形态（既有调用点 lint() 用）
    assert pl._resolve_path("real.py", root, plain) == str(Path(root) / "real.py")
    assert pl._resolve_path("nope/x.py", root, plain) is None
