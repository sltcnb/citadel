@echo off
REM Build fo-collector.exe as a self-contained Windows EXE using PyInstaller.
REM Run this script on a Windows machine (or Wine).
REM
REM Usage:  build.bat
REM Output: dist\fo-collector.exe

setlocal

set BINARY_NAME=fo-collector
set PYTHON=python

echo [*] Installing build dependencies...
%PYTHON% -m pip install -q -r requirements-build.txt
if %ERRORLEVEL% neq 0 (
    echo [!] pip install failed
    exit /b 1
)

echo [*] Building %BINARY_NAME%.exe...
%PYTHON% -m PyInstaller ^
    --onefile ^
    --name %BINARY_NAME% ^
    --strip ^
    --clean ^
    --uac-admin ^
    collect.py

if %ERRORLEVEL% neq 0 (
    echo [!] PyInstaller build failed
    exit /b 1
)

echo.
echo [+] Done:  dist\%BINARY_NAME%.exe
for %%A in ("dist\%BINARY_NAME%.exe") do echo     Size:  %%~zA bytes
echo.
echo Deploy:
echo     Copy dist\fo-collector.exe to the target system
echo     Run as Administrator:  fo-collector.exe --verbose
echo     Direct upload:         fo-collector.exe --api-url http://FO_HOST/api/v1 --case-id CASE_ID
