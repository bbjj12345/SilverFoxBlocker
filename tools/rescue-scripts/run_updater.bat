@echo off
setlocal enabledelayedexpansion

:: 获取脚本所在目录（去掉末尾反斜杠）
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

:: 定义路径
set "PYTHON_DIR=%SCRIPT_DIR%\python-3.14.5-embed-amd64"
set "ARIA2_DIR=%SCRIPT_DIR%\aria2-1.37.0-win-64bit-build1"
set "PYTHON_EXE=%PYTHON_DIR%\python.exe"
set "SCRIPT_PATH=%SCRIPT_DIR%\update_360jijiuxiang_multi.py"

:: 加入 PATH
set "PATH=%PYTHON_DIR%;%ARIA2_DIR%;%PATH%"
set "PYTHONPATH=%PYTHON_DIR%"

cd /d "%SCRIPT_DIR%"

echo ========================================
echo Path   : %SCRIPT_DIR%
echo Python : %PYTHON_EXE%
echo aria2  : %ARIA2_DIR%\aria2c.exe
echo ========================================
echo.

if not exist "%PYTHON_EXE%" (
    echo [error] Can't find Python: %PYTHON_EXE%
    pause
    exit /b 1
)

if not exist "%SCRIPT_PATH%" (
    echo [error] Can't find: %SCRIPT_PATH%
    pause
    exit /b 1
)

echo Running update_360jijiuxiang.py ...
"%PYTHON_EXE%" "%SCRIPT_PATH%"

if errorlevel 1 (
    echo.
    echo [error] Fail to run update!
)

echo.
echo Press any key to continue...
pause >nul