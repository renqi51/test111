# 使用 Docker 在本机启动 Neo4j（开发环境）。
# 前提：已安装 Docker Desktop，并处于运行状态。

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$projRoot = Split-Path -Parent $root
$compose = Join-Path $projRoot "docker-compose.neo4j.yml"

if (-not (Test-Path $compose)) {
  Write-Error "未找到 $compose，请确认项目根目录下存在 docker-compose.neo4j.yml"
  exit 1
}

Write-Host "使用 docker compose 启动 Neo4j 容器（neo4j-3gpp-exposure）..."
docker compose -f $compose up -d

Write-Host "Neo4j Web 控制台: http://localhost:7474"
Write-Host "默认用户名/密码: neo4j / password （请仅用于本地开发）"

