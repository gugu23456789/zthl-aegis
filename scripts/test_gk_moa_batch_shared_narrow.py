"""n4 组 fan-out 红先：一次 MoA 批的三组 G1/G2/G3 必须共享同一 `batch_id`。

机理（2026-10-05）：`compute_batch_id(plan, narrow_tasks, epoch)` =
`sha256(plan + "\n" + "\n".join(sorted(窄任务集)) + 桶)[:12]`；`--batch-narrow` 是 batch_id 的
窄任务输入（派发侧 `GK_BATCH_NARROW`）。若 fan-out 让各臂传**自己那组**的串 ⟹ 三组 batch_id
分叉 ⟹ `moa-aggregate --batch <id>` 只取单组 K 臂（R4「取恰 3×K」必失败）。

红先契约（HEAD 必红）：`cmd_plan_refinement` 下发段须按批 fan-out，且对**全部臂**传**同一**
`--batch-narrow`（批级共享集 = 3 组串并集），`--arm-group` 逐臂变。HEAD 固定单臂、无 fan-out ⟹ 红。

锚形态：`cmd_plan_refinement() {`（函数头）—— 符号锚，非行号。
"""
import re
from pathlib import Path

_CLI = Path(__file__).resolve().parents[1] / "gatekeeper-cli.sh"
_HEAD = "cmd_plan_refinement() {"


def _fanout_block() -> str:
    src = _CLI.read_text(encoding="utf-8")
    i = src.find(_HEAD)
    assert i != -1, f"锚失效：{_HEAD} 未找到"
    j = src.find("\ncmd_", i + len(_HEAD))
    return src[i: j if j != -1 else len(src)]


def test_arm_bn1_fanout_passes_batch_narrow():
    """臂 bn1（静态）：下发段须传 `--batch-narrow`（batch_id 的窄任务输入），否则三组必分叉。"""
    blk = _fanout_block()
    assert "--batch-narrow" in blk, (
        "cmd_plan_refinement 下发段未传 --batch-narrow ⟹ 三组 batch_id 分叉（n4 未修）"
    )


def test_arm_bn2_batch_narrow_is_shared_across_groups():
    """臂 bn2（静态）：`--batch-narrow` 实参须**唯一共享**（非逐臂各异），且带 `--arm-group`。"""
    blk = _fanout_block()
    args = re.findall(r"--batch-narrow\s+(\S+)", blk)
    assert args, "未找到 --batch-narrow 实参（下发段未按批注入批级共享集）"
    assert len(set(args)) == 1, (
        "--batch-narrow 实参不唯一 %s ⟹ 非批级共享 ⟹ batch_id 分叉" % sorted(set(args))
    )
    assert "--arm-group" in blk, "下发段未传 --arm-group ⟹ 组别身份缺失"
