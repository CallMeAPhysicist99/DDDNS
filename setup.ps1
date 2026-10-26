# One-time setup on a new Windows device, from the project folder:
#
#     powershell -ExecutionPolicy Bypass -File setup.ps1
#
# Creates the Python venv, installs the Python packages into it, and installs
# the sidecar's Node.js packages. Safe to run again (e.g. after an update).
# Needs Python 3.10+ and Node.js 18+ installed first.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js 18 or newer is needed: https://nodejs.org"
}
if (-not (Test-Path "venv\Scripts\python.exe")) {
    if (Get-Command py -ErrorAction SilentlyContinue) { py -3 -m venv venv } else { python -m venv venv }
    if (-not (Test-Path "venv\Scripts\python.exe")) { throw "Couldn't create the venv. Is Python 3.10+ installed?" }
}
& venv\Scripts\python.exe -m pip install --upgrade -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

Push-Location core\sidecar
try {
    npm install
    if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Done. Start the node with:  venv\Scripts\python.exe main.py"
