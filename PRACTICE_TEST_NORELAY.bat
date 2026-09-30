@echo off
rem Practice Range test WITHOUT the relay DLL: tournament mode dials the lobby directly,
rem so this works even when the relay fails to inject in retail mode. Sends the
rem practice_keys handoff; the game-server instance is the active responder
rem (ow174/matches/responder.py) on this branch, so it replies and logs the reaction.
title Overwatch 1.74 lobby server - Practice Range test (no relay)
cd /d "%~dp0"
where py >nul 2>nul || (
  echo Python is not installed. Install Python 3.10 or newer ^(64-bit^) from python.org, then start again.
  start "" https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
py -3 -B -m ow174 --mode tournament --experiment practice_keys %*
pause
