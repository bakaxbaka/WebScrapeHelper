@echo off
REM ============================================================================
REM Bitcoin ECDSA Signature Analyzer - Windows Installation Script
REM ============================================================================
REM This script installs all required Python packages for the application
REM ============================================================================

echo.
echo ============================================================================
echo Bitcoin ECDSA Signature Analyzer - Installing Requirements
echo ============================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python found:
python --version
echo.

REM Check if pip is available
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not available
    echo Please ensure Python was installed correctly
    pause
    exit /b 1
)

echo Upgrading pip...
python -m pip install --upgrade pip
echo.

REM Install required packages
echo Installing required Python packages...
echo.

pip install base58==1.0.3
pip install bech32==1.2.0
pip install cryptography==41.0.7
pip install ecdsa==0.18.0
pip install email-validator==2.1.0
pip install Flask==3.0.0
pip install flask-sqlalchemy==3.1.1
pip install gunicorn==21.2.0
pip install psycopg2-binary==2.9.9
pip install requests==2.31.0
pip install trafilatura==1.6.3
pip install validators==0.22.0

echo.
echo ============================================================================
echo Installation Complete!
echo ============================================================================
echo.
echo To run the application:
echo   1. Set up the DATABASE_URL environment variable
echo   2. Set up the SESSION_SECRET environment variable
echo   3. Run: python main.py
echo.
echo For development (with auto-reload):
echo   python main.py
echo.
echo For production:
echo   gunicorn --bind 0.0.0.0:5000 --workers 4 main:app
echo.
pause
