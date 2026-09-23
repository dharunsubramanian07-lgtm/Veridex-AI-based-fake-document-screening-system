@echo off
title VERIDEX - AI Identity & Document Screening System
cd /d "%~dp0"
echo ========================================================
echo Starting VERIDEX AI Identity & Document Screening System...
echo ========================================================
echo.
"%~dp0venv\Scripts\python.exe" -m streamlit run "%~dp0app.py"
pause
