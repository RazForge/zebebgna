@echo off
title Zebebgna - Receipt Verification Tool
color 0B

echo.
echo  ========================================
echo   ZEBEGNA - Receipt Verification Tool
echo   Guard your transactions
echo  ========================================
echo.

REM --- Check if Python is installed ---
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo.
    echo  Please install Python 3.8 or later from:
    echo  https://www.python.org/downloads/
    echo.
    echo  Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo  [OK] Python found.
echo.

REM --- Check if dependencies are installed ---
echo  Checking dependencies...
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo  Installing dependencies (this may take a moment)...
    echo.
    pip install -e ".[web]" --quiet
    if errorlevel 1 (
        echo  [ERROR] Failed to install dependencies.
        echo  Please check your internet connection and try again.
        echo.
        pause
        exit /b 1
    )
    echo  [OK] Dependencies installed.
) else (
    echo  [OK] Dependencies already installed.
)

echo.
echo  Starting Zebebgna...
echo  Your browser will open automatically.
echo  Press Ctrl+C to stop the server.
echo.

REM --- Open browser after short delay ---
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:5000"

REM --- Start the web app ---
python webapp.py

echo.
echo  Zebebgna has stopped.
pause
