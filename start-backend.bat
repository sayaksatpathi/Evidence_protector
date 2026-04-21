@echo off
setlocal

REM Evidence Protector - Start Backend (FastAPI)
REM Double-click to start quickly.
REM
REM Defaults:
REM - Skips pip install if deps look present
REM - Exits quickly if port 8000 is already in use
REM
REM Options:
REM   start-backend.bat --install   (force pip install -r requirements.txt)

pushd "%~dp0"

set "PY_EXE=.venv\Scripts\python.exe"
set "FORCE_INSTALL=0"
if /I "%~1"=="--install" set "FORCE_INSTALL=1"

REM If something is already listening on 8000, don't block the user.
for /f "tokens=1,2,3,4,5" %%a in ('netstat -ano ^| findstr /R /C:":8000 .*LISTENING"') do (
  echo Backend already running or port 8000 is in use.
  echo Try: http://127.0.0.1:8000/api/health
  popd
  exit /b 0
)

set "NEW_VENV=0"
if not exist "%PY_EXE%" (
  echo Creating virtual environment .venv...
  py -3 -m venv .venv >nul 2>&1
  if errorlevel 1 (
    python -m venv .venv
  )
  set "NEW_VENV=1"
)

if not exist "%PY_EXE%" (
  echo ERROR: Could not find .venv\Scripts\python.exe
  echo Install Python 3.10+ and try again.
  pause
  popd
  exit /b 1
)

set "NEED_INSTALL=%FORCE_INSTALL%"
if "%NEED_INSTALL%"=="0" (
  if "%NEW_VENV%"=="1" (
    set "NEED_INSTALL=1"
  ) else (
    "%PY_EXE%" -c "import fastapi, uvicorn, click, rich; import dateutil; import multipart" >nul 2>&1
    if errorlevel 1 set "NEED_INSTALL=1"
  )
)

if "%NEED_INSTALL%"=="1" (
  echo Installing Python dependencies...
  "%PY_EXE%" -m pip install -q --upgrade pip
  "%PY_EXE%" -m pip install -q -r requirements.txt
  if errorlevel 1 (
    echo ERROR: pip install failed.
    pause
    popd
    exit /b 1
  )
) else (
  echo Dependencies already installed. Skipping pip install.
)

REM Optional security knobs (uncomment if you want them)
REM set "EVIDENCE_PROTECTOR_API_KEY=change-me"
REM set "EVIDENCE_PROTECTOR_ALLOW_LOCALHOST_WITHOUT_KEY=1"
REM set "EVIDENCE_PROTECTOR_MAX_LOG_BYTES=52428800"
REM set "EVIDENCE_PROTECTOR_MAX_MANIFEST_BYTES=5242880"

echo Starting backend on http://127.0.0.1:8000 ...
echo Press CTRL+C to stop.
echo.
"%PY_EXE%" -m uvicorn evidence_protector_api:app --reload --host 127.0.0.1 --port 8000

popd
endlocal