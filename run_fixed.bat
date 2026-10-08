@echo off
title SecureShop - Remediated Fixed Mode (Port 5000)
cd /d "%~dp0"
echo ==============================================================================
echo   Starting SecureShop in FIXED / SECURE Mode (Hardened Retest Posture)
echo   Target URL: http://127.0.0.1:5000
echo ==============================================================================
echo.
echo Defensive Controls:
echo   - Parameterized queries (SQLi neutralized)
echo   - Strict ownership and RBAC enforcement (403 on IDOR)
echo   - Debug mode disabled, defensive HTTP headers applied
echo   - Passwords cryptographically hashed (scrypt)
echo   - Structured security logging to security.log
echo.
if exist ".\venv\Scripts\python.exe" (
    start http://127.0.0.1:5000
    .\venv\Scripts\python.exe app.py --mode secure --port 5000
) else (
    start http://127.0.0.1:5000
    py app.py --mode secure --port 5000
)
pause
