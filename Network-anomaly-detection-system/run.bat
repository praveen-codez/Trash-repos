@echo off
REM ============================================================
REM  AEGIS-IDS - compile and run helper
REM  Double-click this file, or run "run.bat" from a terminal.
REM ============================================================

REM Work from the folder this script lives in (so paths are correct).
cd /d "%~dp0"

echo ============================================
echo   AEGIS-IDS : Compiling...
echo ============================================

REM Compile both source files. -d . puts .class files in the project root.
javac -d . src/FlowRecord.java src/AegisIDS.java

REM If javac failed (errorlevel not zero), stop here and show why.
if errorlevel 1 (
    echo.
    echo [FAILED] Compilation errors above. Fix them and try again.
    echo.
    pause
    exit /b 1
)

echo [OK] Compiled successfully.
echo.
echo ============================================
echo   AEGIS-IDS : Running...
echo ============================================
echo.

REM Run the program (class name only, no .java or .class).
java AegisIDS

echo.
echo ============================================
echo   Done. Press any key to close this window.
echo ============================================
pause >nul
