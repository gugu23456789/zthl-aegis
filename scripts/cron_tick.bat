@echo off
REM Gatekeeper cron scheduler tick (2026-08-21 rotation blind-spot backstop)
REM Windows Task Scheduler calls this hourly: runs one --once tick inside WSL.
REM 2026-11-01 修复：原 `cd ~/.trae/...` 在 WSL root（HOME=/root）下解析为 /root/.trae
REM ⟹ 路径不存在、tick 每小时 rc=1、全部作业逾期（audit-daily 首跑未发生）。改绝对路径。
wsl.exe bash -lc "cd <home>/.trae/skills/spz-gatekeeper-r-sequence && python3 scripts/cron_scheduler.py --once"
