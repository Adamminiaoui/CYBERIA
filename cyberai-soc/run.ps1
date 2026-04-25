$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonPath = "C:\Users\Adam\AppData\Local\Programs\Python\Python313\python.exe"

if (-not (Test-Path $pythonPath)) {
    Write-Error "Python not found at $pythonPath"
}

Write-Host "Starting CyberAI SOC services from $projectRoot"

Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$projectRoot'; & '$pythonPath' -m uvicorn api.main:app --host 127.0.0.1 --port 8000"
)

Start-Sleep -Seconds 2

Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$projectRoot'; & '$pythonPath' -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.headless true --server.port 8501"
)

Write-Host "API: http://127.0.0.1:8000/threats"
Write-Host "Dashboard: http://127.0.0.1:8501"
