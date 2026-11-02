#!/usr/bin/env python3
"""gk_context_build.py — `context --update` 上下文构建器（B10g，2026-10-28）

  build <skill_dir> <state_file> <out_file>

扫描子代理 runner / CLI 关键行 → files 清单；state 取 r_phase；可选 RED 静态引擎
findings 与 gitnexus 语义地图层；覆盖写 out_file（indent=2 / ensure_ascii=False）。

⚠ 逐字保留旧内联的三处怪癖：
  1. gitnexus 层注入在 `if os.path.exists(red_attacks)` **内**（无引擎则无该键）
  2. 文件读取用裸 `open(...)`（不带 encoding，与旧式一致）
  3. r_phase 非字符串（如 null）时 `[:100]` 抛错并被 `except: pass` 吞 ⟹ 保持 'unknown'
"""
import json
import os
import subprocess
import sys


def build(skill, state_file, out_file) -> dict:
    cli = os.path.join(skill, "gatekeeper-cli.sh")
    sr = os.path.join(skill, "scripts", "subagent_runner.py")

    ctx = {"files": [], "r_phase": "unknown"}

    try:
        if os.path.exists(state_file):
            s = json.load(open(state_file, encoding="utf-8"))
            ctx["r_phase"] = s.get("r_phase", s.get("stage", "IDLE"))[:100]
    except Exception:  # noqa: BLE001 — 旧式 `except: pass`
        pass

    if os.path.exists(sr):
        with open(sr) as f:
            lines = f.readlines()
        ctx["files"] = []
        for i, line in enumerate(lines):
            ln = i + 1
            if "class EccOutput" in line:
                ctx["files"].append(
                    "scripts/subagent_runner.py L%d-%d (EccOutput Pydantic model)"
                    % (ln, ln + 18))
            if line.strip().startswith("nonce=") and "uuid" in line:
                ctx["files"].append(
                    "scripts/subagent_runner.py L%d (nonce generation)" % ln)
            if "hmac.new(" in line:
                ctx["files"].append(
                    "scripts/subagent_runner.py L%d-%d (HMAC-SHA256 signing)" % (ln, ln + 4))
            if line.strip().startswith("TOOL_REGISTRY"):
                ctx["files"].append(
                    "scripts/subagent_runner.py L%d-%d (TOOL_REGISTRY)" % (ln, ln + 7))
            if "evidence 格式要求" in line or "每条 evidence" in line:
                ctx["files"].append(
                    "scripts/subagent_runner.py L%d-%d (evidence format requirements)"
                    % (ln, ln + 6))
        if not ctx["files"]:
            ctx["files"] = ["scripts/subagent_runner.py "
                            "(auto-scan incomplete, run context --update again)"]
    else:
        ctx["files"] = ["scripts/subagent_runner.py not found"]

    if os.path.exists(cli):
        with open(cli) as f:
            lines = f.readlines()
        notes = []
        for i, line in enumerate(lines):
            ln = i + 1
            if "cmd_advance()" in line:
                notes.append("gatekeeper-cli.sh L%d (cmd_advance — stage transition machine)" % ln)
            if "rejected_edits" in line and "setdefault" in line:
                notes.append("gatekeeper-cli.sh L%d (rejected_edits cap=20 FIFO)" % ln)
            if "monitor_mode=" in line and "api" in line:
                notes.append("gatekeeper-cli.sh L%d (monitor_mode --local/--api switching)" % ln)
        ctx["files"].extend(notes[:5])

    # 2026-11-01：`rejected_edits` 写面已迁到 gk_advance.py（CLI 内只剩读面/注释）⟹ 旧锚
    #   `gatekeeper-cli.sh * rejected_edits+setdefault` 静默失效。补 python 侧锚，单源标注 cap=20。
    adv = os.path.join(skill, "scripts", "gk_advance.py")
    if os.path.exists(adv):
        try:
            with open(adv, encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    if "rejected_edits" in line and "setdefault" in line:
                        ctx["files"].append(
                            "gk_advance.py L%d (rejected_edits cap=20 FIFO)" % (i + 1))
                        break
        except OSError:
            pass

    red_attacks = os.path.join(skill, "scripts", "_red_attacks.py")
    if os.path.exists(red_attacks):
        try:
            r = subprocess.run(["python3", red_attacks, "all"], capture_output=True,
                               text=True, timeout=30, cwd=skill)
            if r.returncode == 0:
                red = json.loads(r.stdout)
                ctx["red_findings"] = red.get("ecc_findings", red.get("details", []))
                ctx["red_count"] = red.get("findings", len(ctx["red_findings"]))
        except Exception:  # noqa: BLE001 — 旧式 `except: pass`
            pass

        # gitnexus 语义地图层（旧式嵌在上面的 if 内 —— 无 _red_attacks.py 则不注入）
        ctx["gitnexus"] = {
            "repo": "spz-gatekeeper-r-sequence",
            "index_status": os.environ.get("GK_GN_STATUS", "unknown"),
            "usage": "用 gx_query 语义搜索定位符号 → gx_context 看调用链"
                     " → gx_impact 看爆破半径 → read 读文件行号",
        }

    # 2026-10-30（签名竞态修复 ④）：**原子发布** —— 原 `json.dump(open(out,'w'))` 就地截断重写，
    #   读者（并发 6 臂的 `_ctx_inject_probe`）会读到半截 JSON ⟹ 判 sig_invalid ⟹ 各自重复自愈。
    #   现写 `<out>.tmp.<pid>` → fsync → `os.replace`（同目录原子 rename）。
    tmp = "%s.tmp.%d" % (out_file, os.getpid())
    try:
        with open(tmp, "w") as f:
            json.dump(ctx, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, out_file)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return {"ok": True, "context_file": out_file, "files": len(ctx.get("files", []))}


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 4 or args[0] != "build":
        print("usage: gk_context_build.py build <skill_dir> <state_file> <out_file>",
              file=sys.stderr)
        return 2
    print(json.dumps(build(args[1], args[2], args[3])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
