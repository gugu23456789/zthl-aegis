"""红先臂：principal 相似度 BLAS/GEMM 路径（finding `ECC-5B314A80DD49`）。

背景：`gk_finding.principal` ② 阶段用纯 Python 双层循环算两两余弦（`_cosine` 每对
512 维 ×3 次解释器循环）⟹ `O(n²·d)`，n 跨线即成瓶颈（见 finding 的规模表）。本 finding
补一条 **numpy/BLAS 路径**（`_emb_links_numpy`：`V @ V.T` 一次 GEMM 出 `cos>=emb_tau` 的对），
**numpy 缺席则回退**现有逐对 `_cosine`（零回归）；结果**逐位等价**。

**红先对照**：HEAD（`776af26`）的 `gk_finding` **无** `_emb_links_numpy` ⟹ 三条臂全 AttributeError ⟹ 红。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 固定夹具：4 条 4 维向量（含 1 对近邻 + 若干异项，避免恰好贴 emb_tau 的浮点边界）
_IDS = ["A", "B", "C", "D"]
_EMB = {
    "A": [1.0, 0.0, 0.0, 0.0],
    "B": [0.99, 0.1, 0.0, 0.0],   # cos(A,B) ≈ 0.985 ⟹ 连
    "C": [0.0, 1.0, 0.0, 0.0],   # 与 A/B 均不连
    "D": [0.5, 0.5, 0.5, 0.5],   # 与 A/B 均不连
}
_TAU = 0.9


def _python_reference(idxs, emb, tau):
    """纯 Python 逐对 `_cosine` 参考集（与旧路径同语义）。"""
    import gk_finding as gf
    ref = set()
    for i in range(len(idxs)):
        for j in range(i + 1, len(idxs)):
            vi, vj = emb.get(idxs[i]), emb.get(idxs[j])
            if vi and vj and gf._cosine(vi, vj) >= tau:
                ref.add((i, j))
    return ref


def test_emb_links_numpy_exists():
    """正臂（API 缺席）：`gk_finding` 须暴露 BLAS 路径 `_emb_links_numpy`。"""
    import gk_finding as gf
    assert hasattr(gf, "_emb_links_numpy"), "缺 BLAS 路径 _emb_links_numpy（HEAD 无此函数）"


def test_numpy_path_equals_python_reference():
    """正臂（等价性）：numpy 路径的对集须与纯 Python 逐对参考**完全相同**。"""
    import gk_finding as gf
    got = gf._emb_links_numpy(_IDS, _EMB, _TAU)
    assert got is not None, "numpy 可用时应返回对集（非 None）"
    ref = _python_reference(_IDS, _EMB, _TAU)
    assert got == ref, "numpy 路径 %r ≠ 纯 Python 参考 %r" % (got, ref)


def test_falls_back_without_numpy():
    """正臂（回退）：numpy 不可用 ⟹ `_emb_links_numpy` 须返回 None（调用方走旧路径），不崩。"""
    import gk_finding as gf
    orig = gf._get_numpy
    try:
        gf._get_numpy = lambda: None          # 模拟 numpy 缺席
        assert gf._emb_links_numpy(_IDS, _EMB, _TAU) is None, "numpy 缺席须返回 None（回退）"
    finally:
        gf._get_numpy = orig


# ── 续：矩阵向量化 + LSH 候选（`ECC-5B314A80DD49` 续刀）─────────────────────────
# ① `_jaccard_matrix_numpy`（token 位矩阵 GEMM，去 Python 双层）
# ② `_sim_matrix_numpy`（sim 改 numpy float64）
# ③ `_lsh_candidates` / `_sim_matrix_lsh`（余弦超平面 + token MinHash 候选）
_SC_IDS = ["F0", "F1", "F2", "F3", "F4"]
_SC_SIGS = [{"a", "b", "c"}, {"a", "b"}, {"b", "c", "d"}, {"x"}, set()]
_SC_EMB = {
    "F0": [1.0, 0.0, 0.0],
    "F1": [0.99, 0.05, 0.0],
    "F2": [0.0, 1.0, 0.0],
    "F3": [0.0, 0.0, 1.0],
    "F4": [0.5, 0.5, 0.5],
}


def _sc_ref(ids, sigs, emb, tau):
    from gk_moa_aggregate import _jaccard
    import gk_finding as gf
    n = len(ids)
    sim = [[0.0] * n for _ in range(n)]
    links = 0
    for i in range(n):
        for j in range(i + 1, n):
            s = _jaccard(sigs[i], sigs[j])
            vi, vj = emb.get(ids[i]), emb.get(ids[j])
            if vi and vj and gf._cosine(vi, vj) >= tau:
                s = 1.0
                links += 1
            sim[i][j] = sim[j][i] = s
    return sim, links


def test_jaccard_matrix_numpy_equals_python():
    """① Jaccard 向量化：`M@M.T` 矩阵须与逐对 `_jaccard` 逐格一致。"""
    from gk_moa_aggregate import _jaccard
    import gk_finding as gf
    np = gf._get_numpy()
    assert np is not None, "本臂需 numpy（规范测试面已装）"
    M = gf._jaccard_matrix_numpy(_SC_SIGS, np)
    n = len(_SC_SIGS)
    for i in range(n):
        for j in range(n):
            if i == j:
                continue
            assert abs(float(M[i, j]) - _jaccard(_SC_SIGS[i], _SC_SIGS[j])) < 1e-12


def test_sim_matrix_is_numpy_and_equals_python():
    """② numpy sim：返回 ndarray 且与纯 Python 参考逐格一致（含 emb_links 计数）。"""
    import gk_finding as gf
    np = gf._get_numpy()
    assert np is not None
    sim, links = gf._sim_matrix_numpy(_SC_IDS, _SC_SIGS, _SC_EMB, _TAU, np)
    assert hasattr(sim, "shape") and tuple(sim.shape) == (len(_SC_IDS), len(_SC_IDS)), \
        "sim 应为 n×n ndarray（非 Python list-of-lists）"
    ref, rlinks = _sc_ref(_SC_IDS, _SC_SIGS, _SC_EMB, _TAU)
    for i in range(len(_SC_IDS)):
        for j in range(len(_SC_IDS)):
            assert abs(float(sim[i, j]) - ref[i][j]) < 1e-12, "sim(%d,%d) 不一致" % (i, j)
    assert links == rlinks, "emb_links 计数不一致：%r ≠ %r" % (links, rlinks)


def _sc_lsh_fixture(n):
    """前两条近重复（token 4/5 重合 + 向量近）；其余互异。"""
    ids = ["F%d" % i for i in range(n)]
    sigs = [set() for _ in range(n)]
    sigs[0] = {"a", "b", "c", "d"}
    sigs[1] = {"a", "b", "c", "d", "e"}
    for k in range(2, n):
        sigs[k] = {"tok%d" % k}
    emb = {"F0": [1.0, 0.0, 0.0], "F1": [1.0, 0.03, 0.0]}
    for k in range(2, n):
        v = [0.0, 0.0, 0.0]
        v[k % 3] = 1.0
        v[(k + 1) % 3] = 0.01 * (k % 11)
        emb[ids[k]] = v
    return ids, sigs, emb


def test_lsh_candidates_include_neardup():
    """③ LSH：近重复对 (0,1) 必在候选集内，且候选数远小于 n²。"""
    import gk_finding as gf
    np = gf._get_numpy()
    assert np is not None
    n = 64
    ids, sigs, emb = _sc_lsh_fixture(n)
    cand = gf._lsh_candidates(ids, sigs, emb, np)
    assert (0, 1) in cand, "LSH 漏掉了近重复对 (0,1)"
    assert 0 < len(cand) < (n * (n - 1)) // 2, "LSH 候选数应远小于 n²"


def test_lsh_candidates_deterministic():
    """③ LSH：固定 seed ⟹ 两次候选集完全相同（确定性）。"""
    import gk_finding as gf
    np = gf._get_numpy()
    assert np is not None
    ids, sigs, emb = _sc_lsh_fixture(64)
    assert gf._lsh_candidates(ids, sigs, emb, np) == gf._lsh_candidates(ids, sigs, emb, np)


# ── 续：凝聚聚类 O(n³) → Lance-Williams 增量 + LSH 常态启用（`ECC-5B314A80DD49` 再续刀）──
def _naive_avg_linkage(sim, n, tau):
    """朴素 `O(n³)` 参考实现（与改写前的 `_avg_linkage` 逐字一致）。"""
    groups = [[i] for i in range(n)]
    while len(groups) > 1:
        best = None
        for a in range(len(groups)):
            for b in range(a + 1, len(groups)):
                tot, cnt = 0.0, 0
                for i in groups[a]:
                    for j in groups[b]:
                        tot += sim[i][j]
                        cnt += 1
                avg = (tot / cnt) if cnt else 0.0
                if avg >= tau and (best is None or avg > best[0]):
                    best = (avg, a, b)
        if best is None:
            break
        _, a, b = best
        groups[a] = groups[a] + groups[b]
        del groups[b]
    groups.sort(key=lambda g: (-len(g), g[0]))
    return groups


def test_avg_linkage_lw_exists():
    """本续刀判别臂：`gk_moa_aggregate._avg_linkage_lw`（LW 增量）须存在。"""
    import gk_moa_aggregate as ga
    assert hasattr(ga, "_avg_linkage_lw"), "缺 Lance-Williams 增量实现 _avg_linkage_lw"


def test_avg_linkage_lw_equals_naive():
    """等价性：LW 增量版须与朴素 O(n³) 版**逐分组完全一致**（含并列 tie 序）。"""
    import random
    from gk_moa_aggregate import _avg_linkage_lw
    rnd = random.Random(20261011)
    for n, tau in [(1, 0.6), (2, 0.6), (5, 0.6), (9, 0.6), (12, 0.5), (16, 0.7)]:
        for _ in range(8):
            sim = [[0.0] * n for _ in range(n)]
            for i in range(n):
                for j in range(i + 1, n):
                    v = rnd.choice([0.0, 1.0, rnd.random()])
                    sim[i][j] = sim[j][i] = v
            assert _avg_linkage_lw(sim, n, tau) == _naive_avg_linkage(sim, n, tau), \
                "n=%d tau=%s：LW 与朴素不一致" % (n, tau)


def test_avg_linkage_delegates_to_lw():
    """对外入口：`_avg_linkage` 须委托 LW 实现（同输入同输出）。"""
    from gk_moa_aggregate import _avg_linkage, _avg_linkage_lw
    sim = [[0.0, 0.9, 0.0], [0.9, 0.0, 0.8], [0.0, 0.8, 0.0]]
    assert _avg_linkage(sim, 3, 0.5) == _avg_linkage_lw(sim, 3, 0.5)


def test_lsh_default_enabled():
    """③ 常态启用：`gk_finding._LSH_N_DEFAULT` 缺省须为 1（用户裁定，永走 LSH）。"""
    import gk_finding as gf
    assert gf._LSH_N_DEFAULT == 1, "LSH 默认阈值应为 1（常态启用），实为 %r" % gf._LSH_N_DEFAULT
