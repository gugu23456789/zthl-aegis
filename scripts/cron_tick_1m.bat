@echo off
REM Gatekeeper 60s tick（408 T5，2026-11-13）：审计署 4B 生命周期按需启停。
REM Windows 计划任务最小粒度 1min ⟹ 本文件按「每 1 分钟」重复触发（或由常驻
REM `python scripts/cron_scheduler.py --interval 60` 替代）。作业体 = gk_audit_model_tick.py，
REM 判据/启停全在 gk_audit_lifecycle.tick()（本文件只做调度，不复制判据）。
setlocal
set "LOG=%TEMP%\gatekeeper-cron-tick-1m.log"
"C:\Windows\System32\wsl.exe" bash -lc "cd <home>/.trae/skills/spz-gatekeeper-r-sequence && python3 scripts/cron_scheduler.py --once" >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo [%DATE% %TIME%] rc=%RC% >> "%LOG%"
exit /b %RC%
