@echo off
setlocal enabledelayedexpansion
title XOR Key Recovery Tool

:: ── Find Python ──────────────────────────────────────────────────────────────
:: Try 'py' launcher first (standard Windows installer), then 'python', then 'python3'
set PYTHON=
where py >nul 2>&1 && set PYTHON=py
if "%PYTHON%"=="" where python >nul 2>&1 && set PYTHON=python
if "%PYTHON%"=="" where python3 >nul 2>&1 && set PYTHON=python3

if "%PYTHON%"=="" (
    cls
    echo ============================================
    echo   ERROR: Python not found
    echo ============================================
    echo.
    echo Python is required but was not found on PATH.
    echo.
    echo 1. Download Python from: https://www.python.org/downloads/
    echo 2. During install, tick "Add Python to PATH"
    echo 3. Restart this tool after installing
    echo.
    pause
    exit /b 1
)

echo [OK] Found Python: %PYTHON%
timeout /t 1 >nul

:MENU
cls
echo ============================================
echo         XOR KEY RECOVERY TOOL
echo     For repeating-key XOR encrypted files
echo ============================================
echo.
echo  [1]  Compare two ciphertexts to cancel key
echo       (drag ^& drop two encrypted files)
echo.
echo  [2]  Decrypt a file using a known key
echo       (drag ^& drop one encrypted file)
echo.
echo  [3]  Exit
echo.
echo ============================================
set /p CHOICE= Select option (1/2/3): 

if "%CHOICE%"=="1" goto COMPARE
if "%CHOICE%"=="2" goto DECRYPT
if "%CHOICE%"=="3" exit /b
echo Invalid choice. Try again.
timeout /t 2 >nul
goto MENU

:: ---------------------------------------------
:COMPARE
cls
echo ============================================
echo    OPTION 1 - KEY RECOVERY (XOR Cancel)
echo ============================================
echo.
echo Drag and drop FILE 1 (first ciphertext) then press Enter:
set /p FILE1= FILE 1: 

set FILE1=%FILE1:"=%

if not exist "%FILE1%" (
    echo ERROR: File not found: %FILE1%
    pause
    goto MENU
)

echo.
echo Drag and drop FILE 2 (second ciphertext) then press Enter:
set /p FILE2= FILE 2: 

set FILE2=%FILE2:"=%

if not exist "%FILE2%" (
    echo ERROR: File not found: %FILE2%
    pause
    goto MENU
)

echo.
echo Running key recovery...
echo Output will be saved to: %~dp0output.txt
echo.

%PYTHON% "%~dp0xor_tool.py" compare "%FILE1%" "%FILE2%" "%~dp0output.txt"
set PYEXIT=%ERRORLEVEL%

echo.
if %PYEXIT% NEQ 0 (
    echo ============================================
    echo ERROR: Python script failed (exit code %PYEXIT%)
    echo Check %~dp0error_log.txt for details
    echo ============================================
) else (
    echo ============================================
    echo Done! Results saved to:
    echo %~dp0output.txt
    echo ============================================
    echo.
    echo Opening output.txt...
    start notepad "%~dp0output.txt"
)
echo.
pause
goto MENU

:: ---------------------------------------------
:DECRYPT
cls
echo ============================================
echo      OPTION 2 - DECRYPT FILE
echo ============================================
echo.
echo Drag and drop the ENCRYPTED FILE then press Enter:
set /p FILE1= FILE: 

set FILE1=%FILE1:"=%

if not exist "%FILE1%" (
    echo ERROR: File not found: %FILE1%
    pause
    goto MENU
)

echo.
echo Enter the XOR key as hex (e.g. 02aaf8c6dcab4726efbb0098):
set /p HEXKEY= KEY (hex): 

echo.
echo Decrypting...
echo Output will be saved to: %~dp0output.txt
echo.

%PYTHON% "%~dp0xor_tool.py" decrypt "%FILE1%" "%HEXKEY%" "%~dp0output.txt"
set PYEXIT=%ERRORLEVEL%

echo.
if %PYEXIT% NEQ 0 (
    echo ============================================
    echo ERROR: Python script failed (exit code %PYEXIT%)
    echo Check %~dp0error_log.txt for details
    echo ============================================
) else (
    echo ============================================
    echo Done! Results saved to:
    echo %~dp0output.txt
    echo ============================================
    echo.
    echo Opening output.txt...
    start notepad "%~dp0output.txt"
)
echo.
pause
goto MENU
