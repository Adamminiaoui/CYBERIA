$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue

if (-not $pythonCommand) {
    Write-Error "Python was not found in PATH. Install Python or activate your virtual environment before running this script."
}

$pythonPath = $pythonCommand.Source

Write-Host "Starting CyberAI SOC services from $projectRoot"
Write-Host "Using Python: $pythonPath"

Start-Process -FilePath $pythonPath `
    -ArgumentList @("-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8000") `
    -WorkingDirectory $projectRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $projectRoot "api_server.out.log") `
    -RedirectStandardError (Join-Path $projectRoot "api_server.err.log")

Start-Sleep -Seconds 2

Start-Process -FilePath $pythonPath `
    -ArgumentList @("-m", "streamlit", "run", "dashboard/app.py", "--server.address", "127.0.0.1", "--server.headless", "true", "--server.port", "8501") `
    -WorkingDirectory $projectRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $projectRoot "streamlit.out.log") `
    -RedirectStandardError (Join-Path $projectRoot "streamlit.err.log")

Write-Host "API: http://127.0.0.1:8000/threats"
Write-Host "Dashboard: http://127.0.0.1:8501"
Write-Host "Logs: api_server.*.log and streamlit.*.log"
