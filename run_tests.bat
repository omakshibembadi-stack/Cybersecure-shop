@echo off
title SecureShop - Automated Security & Functional Test Suite
cd /d "%~dp0"
echo ==============================================================================
echo   Running All Automated Security & Functional Tests for SecureShop
echo ==============================================================================
echo.
if exist ".\venv\Scripts\python.exe" (
    .\venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
) else (
    py -m unittest discover -s tests -p "test_*.py" -v
)
echo.
echo ==============================================================================
echo   Testing Complete! Press any key to close this window.
echo ==============================================================================
pause
