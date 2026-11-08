#!/usr/bin/env python3
"""gk_ci_security_lint.py — GitHub Actions 供应链/权限静态门（2026-11-02）。

检查（确定性，0 API）：
  1. 顶层 `permissions` 必须存在且不得 `write-all`；
  2. 所有 `uses:` 必须是 40 位 commit SHA（本地 `./` 例外）；
  3. `actions/checkout` 必须 `persist-credentials: false`；
  4. 每个 job 必须有 `timeout-minutes`；
  5. 名字含 security/audit 的 job 不得 `continue-on-error: true`；
  6. `run:` 不得直接插值 `inputs.*` / 不可信 `github.event.*`（模板注入）；
  7. `pull_request_target` 不得 checkout PR head；
  8. release workflow 建议有 `attest-build-provenance` + `id-token`/`attestations: write`
     （缺失为 WARN；`--strict` 计失败）。

用法：
  python3 scripts/gk_ci_security_lint.py [--json] [--strict]
exit 1 = issues>0（或 --strict 且 warnings>0）。
"""
import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parent.parent
WF_DIR = ROOT / ".github" / "workflows"
# 2026-11-04 修：原式只认 `owner/repo@sha`（恰好一个 `/`），把带子路径的 action
#   全部误判为「未钉」（`github/codeql-action/upload-sarif@<sha>`、
#   `actions/aws/configure-aws-credentials@<sha>` 等），与 §9 的 SHA pin 纪律自相矛盾。
PIN_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}$")
INJECT_RE = re.compile(
    r"\$\{\{\s*(?:inputs\.|github\.event\.(?:pull_request|issue|comment|review|head_commit|commits)"
    r"|github\.head_ref)")
PR_HEAD_RE = re.compile(r"github\.event\.pull_request\.(?:head|head_ref)")
# 2026-11-08（供应链）：pip 安装必须来自依赖单一事实源 `requirements-ci.txt`，
#   否则每个 requirement 必须 `==` 钉死 —— 浮动 spec（`pytest`、`pkg>=1,<2`）在 runner 上
#   随时可能解析到上游新版本，是投毒面的直接入口（上游小版本被接管 ⟹ CI 自动执行）。
PIP_INSTALL_RE = re.compile(r"-m\s+pip\s+install\b(.*)")
REQ_PIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?==[A-Za-z0-9._+-]+$")
CANONICAL_REQ_FILE = "-r requirements-ci.txt"


def _on(doc):
    return doc.get("on", doc.get(True))


def _steps(job):
    out = []
    for s in job.get("steps") or []:
        if isinstance(s, dict):
            out.append(s)
    return out


def _perm_write(doc, key):
    p = doc.get("permissions")
    return isinstance(p, dict) and str(p.get(key, "")).lower() == "write"


def _pip_install_problems(run: str) -> list:
    """pip 安装行的供应链问题（浮动版本 / pip 自更新 / 绕过单一事实源）。"""
    out = []
    for line in run.splitlines():
        if not PIP_INSTALL_RE.search(line):
            continue
        if re.search(r"--upgrade\s+pip", line):
            out.append("pip 自更新（`--upgrade pip` 未钉版本）")
        if CANONICAL_REQ_FILE in line:
            continue                       # 合规形态：单一事实源
        args = PIP_INSTALL_RE.search(line).group(1).replace('"', " ").replace("'", " ")
        # 去掉 flag 与其可选值（`-r x` / `-i url` 等）后剩下的才是 requirement spec
        toks = [t for t in args.split() if not t.startswith("-")]
        floats = [t for t in toks if not REQ_PIN_RE.match(t)]
        if floats:
            out.append("pip 安装未钉版本: %s（改用 `%s`）"
                       % (", ".join(floats), CANONICAL_REQ_FILE))
    return out


def lint_doc(name: str, doc: dict) -> dict:
    issues, warns = [], []
    checks = 0

    def bad(msg):
        issues.append({"workflow": name, "error": msg})

    def warn(msg):
        warns.append({"workflow": name, "warning": msg})

    if not isinstance(doc, dict):
        bad("YAML 顶层不是 mapping")
        return {"ok": False, "issues": issues, "warnings": warns, "checks": 1}

    checks += 1
    perms = doc.get("permissions")
    if perms is None:
        bad("缺顶层 permissions（最小权限）")
    elif str(perms).lower() == "write-all":
        bad("permissions: write-all（过宽）")

    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict) or not jobs:
        bad("缺 jobs")
        return {"ok": False, "issues": issues, "warnings": warns, "checks": checks}

    is_release = "release" in name.lower() or str(doc.get("name", "")).lower() == "release"
    has_attest = False
    for jid, job in jobs.items():
        if not isinstance(job, dict):
            continue
        checks += 1
        tm = job.get("timeout-minutes")
        if not isinstance(tm, int) or tm <= 0:
            bad("job %s 缺 timeout-minutes" % jid)
        if ("security" in jid.lower() or "audit" in jid.lower()) and job.get("continue-on-error") is True:
            bad("安全 job %s 不得 continue-on-error: true" % jid)
        if str(job.get("permissions", "")).lower() == "write-all":
            bad("job %s permissions: write-all（过宽）" % jid)
        for s in _steps(job):
            uses = str(s.get("uses") or "").strip()
            if uses:
                checks += 1
                if uses.startswith("./"):
                    pass
                elif uses.startswith("docker://"):
                    warn("job %s 使用 docker:// action（需额外信任）" % jid)
                elif not PIN_RE.match(uses):
                    bad("job %s 的 uses 未钉 40 位 SHA: %s" % (jid, uses))
                if uses.startswith("actions/checkout@"):
                    w = s.get("with") or {}
                    pc = w.get("persist-credentials")
                    if pc is not False and str(pc).lower() != "false":
                        bad("job %s checkout 未设 persist-credentials: false" % jid)
                if uses.startswith("actions/attest-build-provenance@"):
                    has_attest = True
                    if not _perm_write(job, "id-token"):
                        bad("job %s 缺 permissions.id-token: write（attestation）" % jid)
                    if not _perm_write(job, "attestations"):
                        bad("job %s 缺 permissions.attestations: write（attestation）" % jid)
            run = s.get("run")
            if isinstance(run, str):
                checks += 1
                if INJECT_RE.search(run):
                    bad("job %s 的 run 直接插值不可信上下文（改用 env 中转）" % jid)
                for p in _pip_install_problems(run):
                    checks += 1
                    bad("job %s 的 %s" % (jid, p))

    on = _on(doc)
    if isinstance(on, dict) and "pull_request_target" in on:
        for jid, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for s in _steps(job):
                if str(s.get("uses") or "").startswith("actions/checkout@"):
                    ref = str((s.get("with") or {}).get("ref") or "")
                    if PR_HEAD_RE.search(ref):
                        bad("job %s 在 pull_request_target 下 checkout PR head（不可信代码）" % jid)

    if is_release and not has_attest:
        warn("release workflow 缺 attest-build-provenance（供应链 attestation）")
    return {"ok": not issues, "issues": issues, "warnings": warns, "checks": checks}


def check(workflow_dir: Path = None) -> dict:
    if yaml is None:
        return {"ok": False, "issues": [{"error": "PyYAML 不可用（CI 请 pip install pyyaml==6.0.2）"}],
                "warnings": [], "checks": 0, "workflows": []}
    wd = Path(workflow_dir) if workflow_dir else WF_DIR
    files = sorted(wd.glob("*.yml")) + sorted(wd.glob("*.yaml"))
    issues, warns, names = [], [], []
    total = 0
    for p in files:
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            issues.append({"workflow": p.name, "error": "YAML 解析失败: %s" % e})
            continue
        r = lint_doc(p.name, doc)
        names.append(p.name)
        issues += r["issues"]
        warns += r["warnings"]
        total += r["checks"]
    return {"ok": not issues, "issues": issues, "warnings": warns,
            "checks": total, "workflows": names}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_ci_security_lint.py")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true")
    a = ap.parse_args(argv)
    r = check()
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("gk_ci_security_lint: %s workflows=%d issues=%d warnings=%d checks=%d"
              % ("PASS" if r["ok"] else "FAIL", len(r["workflows"]),
                 len(r["issues"]), len(r["warnings"]), r["checks"]))
        for i in r["issues"]:
            print("FAIL", i)
        for w in r["warnings"]:
            print("WARN", w)
    bad = bool(r["issues"]) or (a.strict and bool(r["warnings"]))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
