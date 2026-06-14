@echo off
setlocal

cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    set "PYTHON=py -3"
) else (
    set "PYTHON=python"
)

echo [1/5] Checking Python...
%PYTHON% --version
if errorlevel 1 (
    echo Python was not found. Please install Python 3.8+ and add it to PATH.
    pause
    exit /b 1
)

echo [2/5] Installing build dependencies...
%PYTHON% -m pip install --upgrade pip
if errorlevel 1 goto failed

%PYTHON% -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto failed

echo [3/5] Cleaning old build output...
if exist build rmdir /s /q build
if exist dist\Cryptoden rmdir /s /q dist\Cryptoden

echo [4/5] Building executable...
%PYTHON% -m PyInstaller --clean --noconfirm Cryptoden.spec
if errorlevel 1 goto failed

echo [5/5] Build finished.
echo Output: %cd%\dist\Cryptoden\Cryptoden.exe
pause
exit /b 0

:failed
echo Build failed. Check the error messages above.
pause
exit /b 1
