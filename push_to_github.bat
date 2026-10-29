@echo off
title Push SecureShop to GitHub
cd /d "%~dp0"
echo ==============================================================================
echo   Pushing SecureShop to https://github.com/omakshibembadi-stack/Cybersecure-shop
echo ==============================================================================
echo.
git push -u origin main
echo.
echo ==============================================================================
echo   Push finished! Check https://github.com/omakshibembadi-stack/Cybersecure-shop
echo ==============================================================================
pause
