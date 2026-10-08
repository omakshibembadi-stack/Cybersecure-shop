@echo off
title SecureShop - Baseline Vulnerable Mode (Port 5000)
cd /d "%~dp0"
echo ==============================================================================
echo   Starting SecureShop in VULNERABLE Mode for Red Team / ZAP Scanning
echo   Target URL: http://127.0.0.1:5000
echo ==============================================================================
echo.
echo Test Accounts:
echo   - Admin:    admin / AdminPass123!
echo   - Customer: alice / AlicePass456!
echo   - Customer: bob   / BobPass789!
echo.
if exist ".\venv\Scripts\python.exe" (
    start http://127.0.0.1:5000
    .\venv\Scripts\python.exe app.py --mode vulnerable --port 5000
) else (
    start http://127.0.0.1:5000
    py app.py --mode vulnerable --port 5000
)
pause
