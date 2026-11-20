@echo off
title ThreatPulse - Threat Intelligence Dashboard
cd /d "%~dp0"

where py >nul 2>nul && (set "PY=py -3") || (
  where python >nul 2>nul && (set "PY=python") || (
    echo.
    echo  Python is not installed.
    echo  1. Install it from https://www.python.org/downloads/
    echo     ^(tick "Add Python to PATH" during setup^)
    echo  2. Then double-click this file again.
    echo.
    start "" https://www.python.org/downloads/
    pause
    exit /b 1
  )
)

echo Starting ThreatPulse... your browser will open automatically.
%PY% run.py --open %*
pause
