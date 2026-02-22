#!/bin/bash
# Huawei HG8145V5 Router Crawler - Unix/Linux/Mac Launcher
# This script runs the crawler with default settings

echo "====================================="
echo "Huawei HG8145V5 Router Web Crawler"
echo "====================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.7 or higher"
    exit 1
fi

echo "Python detected!"
python3 --version
echo ""

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "ERROR: pip3 is not installed"
    echo "Please install pip3"
    exit 1
fi

# Check if dependencies are installed
echo "Checking dependencies..."
if ! pip3 show requests &> /dev/null; then
    echo "Installing dependencies..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
fi

echo "Dependencies OK!"
echo ""
echo "Starting crawler..."
echo "Target: http://192.168.100.1"
echo "Username: Mega_gpon"
echo "Output: router_backup/"
echo ""
echo "Press Ctrl+C to stop the crawler"
echo ""

# Run the crawler
python3 huawei_crawler.py

echo ""
echo "====================================="
echo "Crawling complete!"
echo "Check the router_backup folder for downloaded files"
echo "Review crawler.log for details"
echo "====================================="
