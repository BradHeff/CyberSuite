@echo off
REM CyberSuite launcher for Windows.
cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
  py -m cybersuite %*
  goto :eof
)

where python >nul 2>&1
if %errorlevel%==0 (
  python -m cybersuite %*
  goto :eof
)

echo Python 3 is required but was not found on PATH.
echo Install it from https://www.python.org/downloads/ ^(tick "Add Python to PATH"^).
pause
