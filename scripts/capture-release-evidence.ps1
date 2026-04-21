param(
  [int]$TimeoutSeconds = 180
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

function Test-Health([string]$Url) {
  try {
    $resp = Invoke-RestMethod -Method Get -Uri $Url -TimeoutSec 5
    return ($null -ne $resp -and $resp.status -eq 'ok')
  } catch {
    return $false
  }
}

function Wait-Health([string]$Url, [int]$TimeoutSec) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    if (Test-Health $Url) {
      return $true
    }
    Start-Sleep -Seconds 2
  }
  Write-Host "Timed out waiting for health endpoint: $Url" -ForegroundColor Red
  return $false
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$uiRoot = Join-Path $repoRoot 'Evidence Protector Web UI'

$baseUrl = $env:EVIDENCE_PROTECTOR_BASE_URL
if ([string]::IsNullOrWhiteSpace($baseUrl)) {
  $baseUrl = 'http://127.0.0.1:8080'
}

$healthUrl = $env:EVIDENCE_PROTECTOR_HEALTH_URL
if ([string]::IsNullOrWhiteSpace($healthUrl)) {
  $healthUrl = "$($baseUrl.TrimEnd('/'))/api/health"
}

$captureTimeout = $env:EVIDENCE_PROTECTOR_CAPTURE_TIMEOUT_SECONDS
if (-not [string]::IsNullOrWhiteSpace($captureTimeout)) {
  $parsedTimeout = 0
  if ([int]::TryParse($captureTimeout, [ref]$parsedTimeout) -and $parsedTimeout -gt 0) {
    $TimeoutSeconds = $parsedTimeout
  }
}

Push-Location $repoRoot
try {
  if (-not (Test-Health $healthUrl)) {
    $compose = Resolve-ComposeCommand
    $composeCmd = [string[]]$compose.Cmd
    Write-Host "Release capture preflight: stack not healthy at $healthUrl, starting compose..." -ForegroundColor Yellow
    Invoke-Compose $composeCmd @('up', '--build', '-d')
    if (-not (Wait-Health $healthUrl $TimeoutSeconds)) {
      throw "Release capture preflight failed (health check did not pass)."
    }
  }

  Push-Location $uiRoot
  try {
    Write-Host "Release capture preflight: ensuring Playwright Chromium is installed..." -ForegroundColor Cyan
    & npx playwright install chromium

    & npm run capture:evidence
  } finally {
    Pop-Location
  }
} finally {
  Pop-Location
}
