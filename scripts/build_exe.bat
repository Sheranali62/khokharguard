@echo off
REM ============================================================
REM LocalGuard Antivirus - build the Windows executable
REM Prereqs: Python 3.12+, pip install -r requirements.txt
REM          pip install pyinstaller
REM ============================================================
setlocal
cd /d "%~dp0.."

echo [1/3] Cleaning previous build output...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [2/3] Running compileall (syntax verification)...
python -m compileall -q .
if errorlevel 1 (
    echo COMPILE FAILED - fix errors before building.
    exit /b 1
)

echo [3/3] Running PyInstaller...
pyinstaller localguard.spec --noconfirm
if errorlevel 1 (
    echo PYINSTALLER FAILED.
    exit /b 1
)

echo.
echo Build complete: dist\LocalGuard\LocalGuard.exe
echo Installer next: iscc installer\LocalGuard_Setup.iss
endlocal
