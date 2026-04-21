$ErrorActionPreference = 'Stop'

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildVenv = Join-Path $RootDir '.venv-build'
$DistDir = Join-Path $RootDir 'dist/standalone'

python -m venv $BuildVenv
$Python = Join-Path $BuildVenv 'Scripts/python.exe'

& $Python -m pip install --upgrade pip
& $Python -m pip install "$RootDir[packaging]"

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

& (Join-Path $BuildVenv 'Scripts/pyinstaller.exe') `
  --onefile `
  --clean `
  --name evidence-protector `
  --distpath $DistDir `
  --workpath (Join-Path $RootDir 'build/pyinstaller') `
  --specpath (Join-Path $RootDir 'build/pyinstaller') `
  (Join-Path $RootDir 'scripts/ep_launcher.py')

Write-Host "Standalone binary generated: $(Join-Path $DistDir 'evidence-protector.exe')"
