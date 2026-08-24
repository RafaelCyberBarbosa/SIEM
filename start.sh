#!/usr/bin/env bash
set -e

echo "ZeroDay - local dev startup"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

.venv/bin/pip install -q -r requirements.txt

if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "Created .env from .env.example - edit it to set a real SECRET_KEY and ADMIN_PASSWORD."
fi

mkdir -p data

echo "Starting SIEM on http://localhost:8000 ..."
.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
