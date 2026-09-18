@echo off
REM ============================================================
REM LocalGuard Antivirus - run the full verification suite
REM ============================================================
setlocal
cd /d "%~dp0.."

echo [1/2] python -m compileall ...
python -m compileall -q .
if errorlevel 1 (
    echo COMPILE FAILED
    exit /b 1
)

echo [2/2] pytest ...
python -m pytest
if errorlevel 1 (
    echo TESTS FAILED
    exit /b 1
)

echo.
echo All checks passed.
endlocal
