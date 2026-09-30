@echo off
rem Practice Range test, retail mode with the relay: the practice_keys handoff, and the game server
rem answers with the reply plan you pick (experiments\replies\*.json).
title Overwatch 1.74 lobby server - Practice Range replies
cd /d "%~dp0"
where py >nul 2>nul || (
  echo Python is not installed. Install Python 3.10 or newer ^(64-bit^) from python.org, then start again.
  start "" https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
echo.
echo   1  silent               no replies (timing baseline)
echo   2  echo_ce              the game's own packet back, sealed with the +0xCE key
echo   3  bisect_a9_c8         one command per packet
echo   4  echo_ce + trace      like 2, plus a log of the game's own seal/open calls
echo.
set "pick="
set /p "pick=Which test? [1-4]: "
set "plan="
set "OW174_GCM_TRACE="
if "%pick%"=="1" set "plan=silent"
if "%pick%"=="2" set "plan=echo_ce"
if "%pick%"=="3" set "plan=bisect_a9_c8"
if "%pick%"=="4" ( set "plan=echo_ce" & set "OW174_GCM_TRACE=1" )
if not defined plan (
  echo Pick 1, 2, 3 or 4.
  pause
  exit /b 1
)
set "OW174_REPLY_PLAN=%~dp0experiments\replies\%plan%.json"
echo Running %plan%
py -3 -B -m ow174 --mode retail --experiment practice_keys %*
pause
