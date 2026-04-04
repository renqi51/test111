# 双窗口开发启动（Windows）：分别启动后端与前端。需已安装 Python 3.11+ 与 Node 18+。
$scriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projRoot = Split-Path -Parent $scriptsDir
$backend = Join-Path $projRoot "backend"
$frontend = Join-Path $projRoot "frontend"

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backend'; python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
Start-Sleep -Seconds 2
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$frontend'; npm run dev"

Write-Host "已尝试打开两个终端：后端 :8000 与前端 :5173"
