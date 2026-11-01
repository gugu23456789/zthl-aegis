"""红先测试：`.gk-trash` 自动释放 —— TTL 默认 3 天 + cron 作业编排（W1，2026-10-06）。

覆盖三面：
  1. **默认 TTL = 3 天**（`gatekeeper-cli.sh` 编排默认 + `gk_worktree_reclaim` 函数默认，两处一致）；
  2. **`/tmp` 面零回归**（`scan_tmp`/`reclaim_tmp` 默认仍 7 —— owner 只裁 `.gk-trash` 面）；
  3. **cron 作业编排**（`gk_trash_cron.sh` 走 `apply-worktree --reclaim --trash --apply`，
     **不复制删除判据**）+ **功能面**（龄期门 / RESTORE-MAP 自洽校验在默认 TTL 下仍生效）。
"""
import inspect
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_worktree_reclaim as R  # noqa: E402

_SKILL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sig_default(fn, name):
    return inspect.signature(fn).parameters[name].default


def test_trash_default_ttl_is_3_days():
    assert _sig_default(R.scan_trash, "days") == 3
    assert _sig_default(R.reclaim_trash, "days") == 3


def test_tmp_default_ttl_unchanged():
    # owner 只裁 `.gk-trash` 面；`/tmp` 是全局共享区，龄期门维持 7 天（零回归）
    assert _sig_default(R.scan_tmp, "days") == 7
    assert _sig_default(R.reclaim_tmp, "days") == 7


def test_cli_defaults_trash_3_tmp_7():
    with open(os.path.join(_SKILL, "gatekeeper-cli.sh"), encoding="utf-8") as fh:
        txt = fh.read()
    assert 'reclaim_trash="0" trash_days="3"' in txt
    assert '--trash-days) trash_days="${2:-3}"' in txt
    # tmp 面默认仍 7（零回归）
    assert 'tmp_days="7"' in txt
    assert '--tmp-days) tmp_days="${2:-7}"' in txt


def test_trash_cron_script_no_second_impl():
    with open(os.path.join(_SKILL, "scripts", "gk_trash_cron.sh"), encoding="utf-8") as fh:
        txt = fh.read()
    assert "apply-worktree --reclaim --trash --apply" in txt
    assert "purged" in txt and "held" in txt
    # 禁在脚本内自造删除/扫描逻辑（单一事实源 = gk_worktree_reclaim）
    assert "rmtree" not in txt and "os.remove" not in txt


def _mk_trash():
    return tempfile.mkdtemp(prefix="gk_trash_ttl_")


def _touch_aged(path, days):
    old = time.time() - days * 86400
    os.utime(path, (old, old))


def test_age_gate_default_3d_purges_aged_keeps_fresh():
    td = _mk_trash()
    old_dir = os.path.join(td, "old-batch")
    new_dir = os.path.join(td, "new-batch")
    os.makedirs(old_dir)
    os.makedirs(new_dir)
    for d in (old_dir, new_dir):
        with open(os.path.join(d, "f.txt"), "w", encoding="utf-8") as fh:
            fh.write("x")
    _touch_aged(old_dir, 5)                     # 5 天 > TTL 3 天
    rep = R.reclaim_trash(td)                   # dry-run，默认 days=3
    names = [it["name"] for it in rep["items"]]
    assert "old-batch" in names and "new-batch" not in names
    rep2 = R.reclaim_trash(td, apply=True)      # apply
    assert any(p.endswith("old-batch") for p in rep2["purged"])
    assert os.path.isdir(new_dir) and not os.path.isdir(old_dir)


def test_restore_map_gap_held_fail_loud():
    td = _mk_trash()
    bad = os.path.join(td, "half-moved")
    os.makedirs(bad)
    with open(os.path.join(bad, "RESTORE-MAP.tsv"), "w", encoding="utf-8") as fh:
        fh.write("missing-name\t/orig/path\n")
    _touch_aged(bad, 5)
    rep = R.reclaim_trash(td, apply=True)
    assert rep["ok"] is False
    assert any(p.endswith("half-moved") for p in rep["held"])
    assert os.path.isdir(bad)                   # 半搬态拒删：可逆性承诺不破
