param(
  [int]$TimeoutSeconds = 180,
  [switch]$Detach = $true,
  [switch]$Down,
  [switch]$OpenBrowser
)

$ErrorActionPreference = 'Stop'

function Resolve-ComposeCommand {
  if (Get-Command docker -ErrorAction SilentlyContinue) {
    try {
      & docker version | Out-Null
    } catch {
      throw "Docker is installed but the engine is not reachable. Start Docker Desktop and retry."
    }

    try {
      & docker compose version | Out-Null
      return @{ Kind = 'docker compose'; Cmd = @('docker', 'compose') }
    } catch {
      # fall through
    }
  }

  if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    try {
      & docker-compose version | Out-Null
      return @{ Kind = 'docker-compose'; Cmd = @('docker-compose') }
    } catch {
      throw "docker-compose is present but not working."
    }
  }

  throw "Docker Compose not found. Install Docker Desktop (recommended) and ensure 'docker' is on PATH."
}

function Invoke-Compose([string[]]$ComposeCmd, [string[]]$Args) {
  if ($ComposeCmd.Length -eq 1) {
    & $ComposeCmd[0] @Args
  } else {
    & $ComposeCmd[0] $ComposeCmd[1] @Args
  }
}

function Wait-Health([string]$Url, [int]$TimeoutSec) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $lastErr = $null

  while ((Get-Date) -lt $deadline) {
    try {
      $resp = Invoke-RestMethod -Method Get -Uri $Url -TimeoutSec 5
      if ($null -ne $resp -and $resp.status -eq 'ok') {
        return $true
      }
      $lastErr = "Unexpected response: $($resp | ConvertTo-Json -Compress)"
    } catch {
      $lastErr = $_.Exception.Message
    }
    Start-Sleep -Seconds 2
  }

  Write-Host "Timed out waiting for: $Url" -ForegroundColor Red
  if ($lastErr) {
    Write-Host "Last error: $lastErr" -ForegroundColor DarkRed
  }
  return $false
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $repoRoot
try {
  $compose = Resolve-ComposeCommand
  $composeCmd = [string[]]$compose.Cmd

  Write-Host "Using $($compose.Kind)" -ForegroundColor Cyan

  if ($Down) {
    Invoke-Compose $composeCmd @('down')
    exit 0
  }

  if ($Detach) {
    Invoke-Compose $composeCmd @('up', '--build', '-d')
  } else {
    Invoke-Compose $composeCmd @('up', '--build')
  }

  Write-Host "Waiting for backend health..." -ForegroundColor Cyan
  $ok1 = Wait-Health 'http://localhost:8000/api/health' $TimeoutSeconds

  Write-Host "Waiting for web proxy health..." -ForegroundColor Cyan
  $ok2 = Wait-Health 'http://localhost:8080/api/health' $TimeoutSeconds

  if (-not ($ok1 -and $ok2)) {
    Write-Host "\nCompose status:" -ForegroundColor Yellow
    Invoke-Compose $composeCmd @('ps')

    Write-Host "\nRecent logs (backend/web):" -ForegroundColor Yellow
    try { Invoke-Compose $composeCmd @('logs', '--tail', '200', 'backend', 'web') } catch { }

    throw "Smoke test failed (health checks did not pass)."
  }

  Write-Host "\nOK: backend and proxy health checks passed." -ForegroundColor Green
  Write-Host "Next manual check (UI): open http://localhost:8080 and run a Ghost Baseline or Ghost Analyze action." -ForegroundColor Green

  if ($OpenBrowser) {
    Start-Process 'http://localhost:8080'
  }

} finally {
  Pop-Location
}
