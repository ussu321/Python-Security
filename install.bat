@echo off
REM Ethical Hacking Python - Windows Installer
REM Developed by issu321
REM https://github.com/issu321/Ethical-Hacking-Python

title Ethical Hacking Python Installer
color 0A

type assets\banner.txt

echo [INFO] Ethical Hacking Python - Windows Installer
echo [INFO] Detecting Python...

python --version >nul 2>&1
if errorlevel 1 (
    python3 --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python is not installed or not in PATH.
        echo [ERROR] Please install Python 3.11+ from https://python.org
        pause
        exit /b 1
    ) else (
        set PYTHON_CMD=python3
    )
) else (
    set PYTHON_CMD=python
)

%PYTHON_CMD% --version
echo [OK] Python detected.

if not exist venv (
    echo [INFO] Creating virtual environment...
    %PYTHON_CMD% -m venv venv
) else (
    echo [WARN] Virtual environment already exists.
)

echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

echo [INFO] Installing dependencies...
pip install -r requirements.txt

echo [OK] Installation complete!
echo [INFO] Launching Ethical Hacking Python...

streamlit run app.py --server.headless true --server.port 8501

pause
