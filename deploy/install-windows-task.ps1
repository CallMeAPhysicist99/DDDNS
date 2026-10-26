# Runs DDDNS headless at Windows start-up, as a scheduled task (no login needed).
#
# Join your network once interactively first (python main.py, /join <topic>, /quit).
# Then, in PowerShell started with "Run as administrator", from the project folder:
#
#     powershell -ExecutionPolicy Bypass -File deploy\install-windows-task.ps1 -Network home
#
# Start it right away:   Start-ScheduledTask -TaskName DDDNS
# Remove it again:       Unregister-ScheduledTask -TaskName DDDNS -Confirm:$false
# What it's doing:       data\dddns.log
#
# It runs as SYSTEM, so the project folder must be readable by SYSTEM (anything
# outside a OneDrive "online-only" folder is). Stopping the task ends the node
# without a goodbye; its peers notice the disconnect anyway.

param(
    [Parameter(Mandatory = $true)][string]$Network,
    [string]$TaskName = "DDDNS"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root "venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "No venv found at $python. Run setup.ps1 first." }

$action = New-ScheduledTaskAction -Execute $python -WorkingDirectory $root `
    -Argument "main.py --headless --network `"$Network`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null
Write-Host "Registered task '$TaskName': starts DDDNS on network '$Network' at every start-up."
Write-Host "Start it now with: Start-ScheduledTask -TaskName $TaskName"
