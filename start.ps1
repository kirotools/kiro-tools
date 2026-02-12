#Requires -Version 5.1
param(
    [Parameter(Position=0)]
    [ValidateSet("start","stop","restart","status","build","logs","update","version","help")]
    [string]$Command = "help",
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$Port = if ($env:KIRO_PORT) { $env:KIRO_PORT } else { "8045" }
$Bin = ".\target\release\kiro-tools.exe"
$Dist = ".\webui\dist"
$PidFile = "kiro-tools.pid"
$LogFile = "kiro-tools.log"
$LogMaxBytes = 10 * 1024 * 1024

function Write-Success($msg) { Write-Host $msg -ForegroundColor Green }
function Write-Warn($msg)    { Write-Host $msg -ForegroundColor Yellow }
function Write-Err($msg)     { Write-Host $msg -ForegroundColor Red }

function Get-SavedPid {
    if (Test-Path $PidFile) { return (Get-Content $PidFile -Raw).Trim() }
    return $null
}

function Test-PidAlive($pid) {
    if (-not $pid) { return $false }
    try { $p = Get-Process -Id $pid -ErrorAction Stop; return -not $p.HasExited } catch { return $false }
}

function Remove-PidFile { Remove-Item -Force -ErrorAction SilentlyContinue $PidFile }

function Invoke-LogRotate {
    if (Test-Path $LogFile) {
        $size = (Get-Item $LogFile).Length
        if ($size -ge $LogMaxBytes) {
            Write-Warn "日志文件超过 10MB，执行轮转..."
            Move-Item -Force $LogFile "$LogFile.1"
        }
    }
}

function Invoke-Build {
    Write-Success ">>> 构建后端..."
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "后端构建失败" }

    Write-Success ">>> 构建前端..."
    Push-Location webui
    try {
        npm install --legacy-peer-deps
        npm run build
        if ($LASTEXITCODE -ne 0) { throw "前端构建失败" }
    } finally { Pop-Location }

    Write-Success ">>> 构建完成"
}

function Wait-Healthy($pid) {
    for ($i = 0; $i -lt 5; $i++) {
        if (-not (Test-PidAlive $pid)) { return $false }
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:$Port/health" -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
            if ($r.StatusCode -eq 200) { return $true }
        } catch {}
        Start-Sleep -Seconds 1
    }
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:$Port/health" -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
        return $r.StatusCode -eq 200
    } catch { return $false }
}

function Invoke-Start {
    $pid = Get-SavedPid
    if (Test-PidAlive $pid) {
        Write-Warn "服务已在运行 (PID: $pid, 端口: $Port)"
        return
    }
    Remove-PidFile

    if (-not (Test-Path $Bin) -or -not (Test-Path $Dist)) {
        Write-Warn "未检测到构建产物，开始构建..."
        Invoke-Build
    }

    if (-not $env:KIRO_CREDS_FILE) {
        Write-Warn "警告: KIRO_CREDS_FILE 未设置，凭证可能需要通过其他方式配置"
    }

    Invoke-LogRotate

    Write-Success ">>> 启动 kiro-tools (端口: $Port)..."
    $env:KIRO_DIST_PATH = $Dist
    $proc = Start-Process -FilePath $Bin -NoNewWindow -PassThru -RedirectStandardOutput $LogFile -RedirectStandardError "$LogFile.err"
    Set-Content -Path $PidFile -Value $proc.Id

    if (Wait-Healthy $proc.Id) {
        Write-Success "启动成功 (PID: $($proc.Id), 端口: $Port)"
        Write-Host "日志: .\start.ps1 logs"
    } else {
        Write-Err "启动失败，请检查日志: Get-Content $LogFile"
        Remove-PidFile
        exit 1
    }
}

function Invoke-Stop {
    $pid = Get-SavedPid
    if (-not (Test-PidAlive $pid)) {
        Remove-PidFile
        Write-Warn "服务未运行"
        return
    }
    Write-Success ">>> 停止服务 (PID: $pid)..."
    try { Stop-Process -Id $pid -ErrorAction Stop } catch {}
    for ($i = 0; $i -lt 5; $i++) {
        if (-not (Test-PidAlive $pid)) { break }
        Start-Sleep -Seconds 1
    }
    if (Test-PidAlive $pid) {
        Write-Warn "强制终止..."
        try { Stop-Process -Id $pid -Force -ErrorAction Stop } catch {}
    }
    Remove-PidFile
    Write-Success "已停止"
}

function Invoke-Status {
    $pid = Get-SavedPid
    if (Test-PidAlive $pid) {
        Write-Success "运行中 (PID: $pid, 端口: $Port)"
    } else {
        Remove-PidFile
        Write-Err "未运行"
    }
}

function Invoke-Logs {
    if (-not (Test-Path $LogFile)) {
        Write-Warn "日志文件不存在"
        exit 1
    }
    Get-Content $LogFile -Wait -Tail 50
}

function Invoke-Update {
    Write-Success ">>> 拉取最新代码..."
    git pull
    Write-Success ">>> 开始构建..."
    Invoke-Build
    Write-Success ">>> 重启服务..."
    Invoke-Stop
    Invoke-Start
}

function Invoke-Version {
    $ver = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"(.+)"' | Select-Object -First 1).Matches.Groups[1].Value
    Write-Host "kiro-tools v$ver"
}

function Show-Usage {
    Write-Host "用法: .\start.ps1 <command> [-Rebuild]"
    Write-Host "  start              - 构建(如需)并启动服务"
    Write-Host "  stop               - 停止服务"
    Write-Host "  restart             - 重启服务"
    Write-Host "  restart -Rebuild    - 重新构建并重启服务"
    Write-Host "  status             - 查看运行状态"
    Write-Host "  build              - 仅构建不启动"
    Write-Host "  logs               - 查看实时日志"
    Write-Host "  update             - 拉取更新、构建并重启"
    Write-Host "  version            - 显示版本号"
}

switch ($Command) {
    "start"   { Invoke-Start }
    "stop"    { Invoke-Stop }
    "restart" { if ($Rebuild) { Invoke-Stop; Invoke-Build; Invoke-Start } else { Invoke-Stop; Invoke-Start } }
    "status"  { Invoke-Status }
    "build"   { Invoke-Build }
    "logs"    { Invoke-Logs }
    "update"  { Invoke-Update }
    "version" { Invoke-Version }
    default   { Show-Usage }
}
