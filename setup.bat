@echo off
echo SecurePassManager Setup Script
echo ============================
echo.

:: Check for administrator privileges
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo This setup requires administrator privileges.
    echo Please run as administrator and try again.
    exit /b 1
)

echo Checking for dependencies...

:: Check for Visual Studio
where cl >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Visual Studio C++ compiler not found.
    echo Please install Visual Studio with "Desktop development with C++" workload.
    echo You can download it from: https://visualstudio.microsoft.com/vs/community/
    echo.
    echo After installation, run this script again.
    exit /b 1
)

:: Check for CMake
where cmake >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo CMake not found. Installing CMake...
    echo.
    
    :: Check for Chocolatey
    where choco >nul 2>&1
    IF %ERRORLEVEL% NEQ 0 (
        echo Installing Chocolatey...
        @powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
        IF %ERRORLEVEL% NEQ 0 (
            echo Failed to install Chocolatey.
            exit /b 1
        )
        :: Refresh environment variables
        call RefreshEnv.cmd
    )
    
    echo Installing CMake using Chocolatey...
    choco install cmake -y
    IF %ERRORLEVEL% NEQ 0 (
        echo Failed to install CMake.
        exit /b 1
    )
    :: Refresh environment variables
    call RefreshEnv.cmd
)

echo Installing/updating dependencies...

:: Install dependencies using Chocolatey
where choco >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    echo Installing/updating OpenSSL...
    choco install openssl -y
    
    echo Installing/updating SQLite...
    choco install sqlite -y
) ELSE (
    echo Chocolatey not found. Please install dependencies manually:
    echo - OpenSSL: https://slproweb.com/products/Win32OpenSSL.html
    echo - SQLite: https://www.sqlite.org/download.html
    echo.
    echo After installing dependencies, run this script again.
    exit /b 1
)

echo.
echo Building SecurePassManager...
echo.

:: Create build directory
if not exist build mkdir build
cd build

:: Configure with CMake
echo Running CMake configuration...
cmake .. -G "Visual Studio 17 2022" -A x64
IF %ERRORLEVEL% NEQ 0 (
    echo CMake configuration failed.
    exit /b 1
)

:: Build the project
echo Building project (this may take a few minutes)...
cmake --build . --config Release
IF %ERRORLEVEL% NEQ 0 (
    echo Build failed.
    exit /b 1
)

echo.
echo ============================
echo SecurePassManager has been successfully built!
echo.
echo You can find the executable at:
echo   %CD%\Release\securepass.exe
echo.
echo To start using SecurePassManager, run:
echo   %CD%\Release\securepass.exe --help
echo.
echo Thank you for using SecurePassManager!
echo ============================

cd .. 