#!/usr/bin/env python3
"""定时审计触发器（E19，2026-10-29）。

验收：脚本存在且语法可过；默认只跑确定性三域（不派 LLM）；域失败会聚合为 rc≠0；
日志落 `${HOME}/.gatekeeper/audit-cron.log`；SKILL_DIR 由脚本位置派生（不写死安装目录）。
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SCRIPT = SCRIPTS / "gk_audit_cron.sh"


def _sandbox(tmp_path, fail_domain="--docs", cli_body=None):
    sb = tmp_path / "sb"
    (sb / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, sb / "scripts" / "gk_audit_cron.sh")
    body = cli_body if cli_body is not None else (
        'echo "{\\"ok\\":true,\\"audit_mode\\":\\"$2\\"}"\n'
        'if [ "$2" = "%s" ]; then exit 3; fi\n'
        'exit 0\n' % fail_domain)
    (sb / "gatekeeper-cli.sh").write_text(
        '#!/usr/bin/env bash\n' + body, encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    return sb, home


def _run(sb, home, extra_env=None):
    env = dict(os.environ)
    env["HOME"] = str(home)
    env.update(extra_env or {})
    return subprocess.run(["bash", str(sb / "scripts" / "gk_audit_cron.sh")],
                          capture_output=True, text=True, timeout=120, env=env)


def test_script_syntax_ok():
    r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stderr


def test_default_domains_are_deterministic_only():
    """默认不得含 crossr / depth / report（会派 subagent 或跑 gitnexus 全量）。"""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "GK_AUDIT_CRON_DOMAINS:-state docs memory" in src
    default_line = src.split("GK_AUDIT_CRON_DOMAINS:-")[1].split("\n")[0]
    for heavy in ("crossr", "depth", "report"):
        assert heavy not in default_line, heavy


def test_skill_dir_derived_not_hardcoded():
    src = SCRIPT.read_text(encoding="utf-8")
    assert "BASH_SOURCE" in src and "/mnt/c/Users" not in src


def test_runs_domains_and_aggregates_failure(tmp_path):
    sb, home = _sandbox(tmp_path)
    r = _run(sb, home)
    assert r.returncode == 1, (r.stdout, r.stderr)
    log = (home / ".gatekeeper" / "audit-cron.log").read_text(encoding="utf-8")
    for d in ("state", "docs", "memory"):
        assert "domain=%s" % d in log, log
    assert "domain=docs rc=3" in log
    assert "exit=1" in log
    assert "domain=report" not in log
    # E20：失败通知 = 告警文件 + stdout ALERT 行（cron output 文件可见）
    alert = home / ".gatekeeper" / "audit-cron.alert.json"
    assert alert.exists(), "失败未落告警文件"
    doc = json.loads(alert.read_text(encoding="utf-8"))
    assert doc["rc"] == 1 and doc["failed_domains"] == "docs(rc=3)", doc
    assert doc["log"].endswith("audit-cron.log")
    assert "ALERT: audit-cron failed domains=docs(rc=3)" in r.stdout, r.stdout
    assert not (home / ".gatekeeper" / "audit-cron.alert.json.tmp").exists()


def test_ok_false_json_counts_as_failure(tmp_path):
    """rc=0 但回包 `ok:false` 也算失败（CLI 的 `|| echo` 兜底会让 rc 恒 0）。"""
    sb, home = _sandbox(
        tmp_path, cli_body='echo \'{"ok":false,"error":"heredoc boom"}\'\nexit 0\n')
    r = _run(sb, home, {"GK_AUDIT_CRON_DOMAINS": "state"})
    assert r.returncode == 1, (r.stdout, r.stderr)
    doc = json.loads((home / ".gatekeeper" / "audit-cron.alert.json").read_text(
        encoding="utf-8"))
    assert doc["failed_domains"] == "state(heredoc boom)", doc


def test_mismatch_only_is_not_failure(tmp_path):
    """检查项 mismatch 不算失败（否则存量 7 条 mismatch 会天天告警）。"""
    sb, home = _sandbox(
        tmp_path,
        cli_body='echo \'{"ok":true,"result":{"audit_summary":'
                 '{"matches":14,"total_fields":21}}}\'\nexit 0\n')
    r = _run(sb, home, {"GK_AUDIT_CRON_DOMAINS": "state"})
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert not (home / ".gatekeeper" / "audit-cron.alert.json").exists()


def test_success_clears_stale_alert(tmp_path):
    sb, home = _sandbox(tmp_path)
    alert = home / ".gatekeeper" / "audit-cron.alert.json"
    alert.parent.mkdir(parents=True, exist_ok=True)
    alert.write_text('{"rc":1,"failed_domains":"docs"}', encoding="utf-8")
    r = _run(sb, home, {"GK_AUDIT_CRON_DOMAINS": "state"})
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert not alert.exists(), "成功未清除陈旧告警"
    assert "ALERT:" not in r.stdout


def test_env_override_domains(tmp_path):
    sb, home = _sandbox(tmp_path)
    r = _run(sb, home, {"GK_AUDIT_CRON_DOMAINS": "state"})
    assert r.returncode == 0, (r.stdout, r.stderr)
    log = (home / ".gatekeeper" / "audit-cron.log").read_text(encoding="utf-8")
    assert "domains=state" in log and "domain=memory" not in log
