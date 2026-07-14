@echo off
title Velocity Auth Server
echo ============================================
echo   Velocity Client - Auth Server
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    python3 --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python not found! Install Python 3.7+ from python.org
        pause
        exit /b 1
    )
    set PY=python3
) else (
    set PY=python
)

:: Check Flask
%PY% -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [SETUP] Installing Flask...
    %PY% -m pip install flask
    echo.
)

echo [INFO] Starting server on all interfaces (0.0.0.0:5000)
echo [INFO] Admin Panel: http://localhost:5000/admin
echo [INFO] From other devices: http://YOUR_LOCAL_IP:5000/admin
echo [INFO] Press Ctrl+C to stop
echo.
%PY% server.py --host 0.0.0.0 --port 5000
pause