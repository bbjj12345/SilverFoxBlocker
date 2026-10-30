@echo off
setlocal enabledelayedexpansion

:: 获取脚本所在目录（去掉末尾的反斜杠）
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

:: 定义路径
set "PYTHON_DIR=%SCRIPT_DIR%\python-3.14.5-embed-amd64"
set "ARIA2_DIR=%SCRIPT_DIR%\aria2-1.37.0-win-64bit-build1"
set "PYTHON_EXE=%PYTHON_DIR%\python.exe"
set "SCRIPT_PATH=%SCRIPT_DIR%\update_hrkill_unsign.py"

:: 将嵌入式 Python 和 aria2 添加到 PATH
set "PATH=%PYTHON_DIR%;%ARIA2_DIR%;%PATH%"

:: 告诉 Python 去哪里找依赖库
set "PYTHONPATH=%PYTHON_DIR%"

:: 切换到脚本目录（避免相对路径问题）
cd /d "%SCRIPT_DIR%"

:: 显示调试信息
echo ========================================
echo Path: %SCRIPT_DIR%
echo Python : %PYTHON_EXE%
echo aria2 : %ARIA2_DIR%\aria2c.exe
echo ========================================
echo.

:: 检查 Python 是否存在
if not exist "%PYTHON_EXE%" (
    echo [error] Can't find Python: %PYTHON_EXE%
    pause
    exit /b 1
)

:: 检查脚本是否存在
if not exist "%SCRIPT_PATH%" (
    echo [error] Can't find: %SCRIPT_PATH%
    pause
    exit /b 1
)

:: 运行爬虫
echo Running update_hrkill_unsign.py ...
"%PYTHON_EXE%" "%SCRIPT_PATH%"

:: 检查运行结果
if errorlevel 1 (
    echo.
    echo [error] Fail to run update!
)

:: 暂停以便查看结果（WinPE下通常没有自动关闭控制台）
echo.
echo Press any key to continue...
pause >nul