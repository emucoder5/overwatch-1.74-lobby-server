@echo off
rem Practice Range test, retail mode with the relay: the practice_keys handoff, and the game server
rem answers with ONE sealed command per game packet (experiments\replies\bisect_a9_c8.json), to find the
rem command that made the game give up early in capture 6b6a7071.
title Overwatch 1.74 lobby server - Practice Range bisect
cd /d "%~dp0"
where py >nul 2>nul || (
  echo Python is not installed. Install Python 3.10 or newer ^(64-bit^) from python.org, then start again.
  start "" https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
set "OW174_REPLY_PLAN=%~dp0experiments\replies\bisect_a9_c8.json"
py -3 -B -m ow174 --mode retail --experiment practice_keys %*
pause
