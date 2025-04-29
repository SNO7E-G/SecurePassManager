# SecurePassManager Dependencies Installation Script for Windows
# This script installs all necessary dependencies for building SecurePassManager on Windows

# Ensure script is running with administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrator privileges. Please run as administrator."
    exit 1
}

Write-Host "SecurePassManager Dependencies Installation" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green
Write-Host ""

# Check if Chocolatey is installed
Write-Host "Checking for Chocolatey package manager..." -ForegroundColor Cyan
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey not found. Installing..." -ForegroundColor Yellow
    
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        Write-Host "Chocolatey installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Chocolatey. Please install it manually."
        Write-Error "Visit https://chocolatey.org/install for instructions."
        exit 1
    }
}
else {
    Write-Host "Chocolatey is already installed." -ForegroundColor Green
}

# Install Visual Studio Build Tools if needed
Write-Host "Checking for Visual Studio Build Tools..." -ForegroundColor Cyan
if (!(Get-Command cl -ErrorAction SilentlyContinue) -and !(Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC" -ErrorAction SilentlyContinue) -and 
    !(Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC" -ErrorAction SilentlyContinue)) {
    
    Write-Host "Visual Studio Build Tools not found. Installing..." -ForegroundColor Yellow
    choco install visualstudio2022buildtools -y --package-parameters "--add Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install Visual Studio Build Tools."
        Write-Error "Please install Visual Studio 2022 with C++ development components manually."
        exit 1
    }
    
    Write-Host "Visual Studio Build Tools installed successfully." -ForegroundColor Green
}
else {
    Write-Host "Visual Studio Build Tools are already installed." -ForegroundColor Green
}

# Install CMake
Write-Host "Installing CMake..." -ForegroundColor Cyan
choco install cmake -y
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install CMake."
    exit 1
}

# Install OpenSSL
Write-Host "Installing OpenSSL..." -ForegroundColor Cyan
choco install openssl -y
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install OpenSSL."
    exit 1
}

# Install SQLite
Write-Host "Installing SQLite..." -ForegroundColor Cyan
choco install sqlite -y
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install SQLite."
    exit 1
}

# Optionally install Ninja build system
Write-Host "Installing Ninja build system..." -ForegroundColor Cyan
choco install ninja -y
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to install Ninja build system. Will use default generator."
}

# Refresh environment variables
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

Write-Host ""
Write-Host "=======================================" -ForegroundColor Green
Write-Host "All dependencies installed successfully!" -ForegroundColor Green
Write-Host "You can now build SecurePassManager using:" -ForegroundColor Green
Write-Host " 1. mkdir build" -ForegroundColor Yellow
Write-Host " 2. cd build" -ForegroundColor Yellow 
Write-Host " 3. cmake .." -ForegroundColor Yellow
Write-Host " 4. cmake --build . --config Release" -ForegroundColor Yellow
Write-Host "=======================================" -ForegroundColor Green 