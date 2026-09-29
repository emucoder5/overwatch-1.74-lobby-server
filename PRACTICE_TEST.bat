@echo off
rem Starts the server and the game with the Practice Range test (experiments\practice.json).
title Overwatch 1.74 lobby server - Practice Range test
cd /d "%~dp0"
where py >nul 2>nul || (
  echo Python is not installed. Install Python 3.10 or newer ^(64-bit^) from python.org, then start again.
  start "" https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
py -3 -B -m ow174 --mode retail --experiment practice %*
pause
