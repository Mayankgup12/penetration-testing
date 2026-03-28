# Run PTF from project root (Use with Task Scheduler for startup + months-long uptime)
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$env:PYTHONUNBUFFERED = "1"
python run.py
