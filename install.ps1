# ==============================================================================
# SentryIP One-Line Automated Installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/Samore141025/SentryIP/main/install.ps1 | iex
# ==============================================================================

Write-Host ">>> SentryIP Windows 1-Click Installer" -ForegroundColor Green

$InstallDir = "$HOME\.sentryip-app"

# Check Python
$python = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "Error: Python 3.11+ is required. Please install Python from https://python.org" -ForegroundColor Red
    exit 1
}

if (Test-Path $InstallDir) {
    Write-Host "Updating SentryIP in $InstallDir..." -ForegroundColor Cyan
    git -C $InstallDir pull --quiet
} else {
    Write-Host "Cloning SentryIP repository..." -ForegroundColor Cyan
    git clone --quiet https://github.com/Samore141025/SentryIP.git $InstallDir
}

Set-Location $InstallDir
Write-Host "Configuring Python virtual environment..." -ForegroundColor Cyan
python -m venv .venv
& "$InstallDir\.venv\Scripts\pip.exe" install --upgrade pip --quiet
& "$InstallDir\.venv\Scripts\pip.exe" install -e . --quiet

# Create runner batch file in user local bin
$UserBin = "$HOME\AppData\Local\Microsoft\WindowsApps"
$BatchContent = "@echo off`n`"$InstallDir\.venv\Scripts\python.exe`" -m sentryip.cli %*"
Set-Content -Path "$UserBin\sentryip.cmd" -Value $BatchContent -Force

Write-Host "`n✔ SentryIP successfully installed on Windows!" -ForegroundColor Green
Write-Host "Run 'sentryip' from any PowerShell or Command Prompt window to begin." -ForegroundColor Yellow
Write-Host "Run 'sentryip --keys' to configure your API keys." -ForegroundColor Yellow
