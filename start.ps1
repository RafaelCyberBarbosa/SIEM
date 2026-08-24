Write-Host "ZeroDay - local dev startup" -ForegroundColor Cyan

if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
}

& ".venv\Scripts\pip.exe" install -q -r requirements.txt

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example - edit it to set a real SECRET_KEY and ADMIN_PASSWORD." -ForegroundColor Yellow
}

if (-not (Test-Path "data")) {
    New-Item -ItemType Directory -Path "data" | Out-Null
}

Write-Host "Starting SIEM on http://localhost:8000 ..." -ForegroundColor Green
& ".venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
