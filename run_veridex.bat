@echo off
title VERIDEX AI Screening System
color 0B
echo =========================================================================
echo       VERIDEX - AI-Powered Fake Identity & Document Screening System
echo                   Ministry of Home Affairs / SSB
echo =========================================================================
echo.
echo Starting Streamlit server on http://localhost:8503 ...
echo.

cd /d "%~dp0"

if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" -m streamlit run app.py --server.port 8503
) else if exist "D:\fake-id spare final 1\fake-id-screening - 1\venv\Scripts\python.exe" (
    "D:\fake-id spare final 1\fake-id-screening - 1\venv\Scripts\python.exe" -m streamlit run app.py --server.port 8503
) else (
    python -m streamlit run app.py --server.port 8503
)

pause
