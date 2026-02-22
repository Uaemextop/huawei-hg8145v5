@echo off
REM Huawei HG8145V5 Router Crawler - Windows Launcher
REM This script runs the crawler with default settings

echo =====================================
echo Huawei HG8145V5 Router Web Crawler
echo =====================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from https://www.python.org/
    pause
    exit /b 1
)

echo Python detected!
echo.

REM Check if dependencies are installed
echo Checking dependencies...
pip show requests >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo Dependencies OK!
echo.
echo Starting crawler...
echo Target: http://192.168.100.1
echo Username: Mega_gpon
echo Output: router_backup\
echo.
echo Press Ctrl+C to stop the crawler
echo.

REM Run the crawler
python huawei_crawler.py

echo.
echo =====================================
echo Crawling complete!
echo Check the router_backup folder for downloaded files
echo Review crawler.log for details
echo =====================================
echo.
pause
