$ErrorActionPreference = "Stop"

Write-Host "=== WebScrapeHelper environment setup ===" -ForegroundColor Cyan

Write-Host "[1/6] Python"
python --version
python -m pip --version

Write-Host "[2/6] Node.js"
if (Get-Command node -ErrorAction SilentlyContinue) {
    node --version
    npm --version
} else {
    Write-Warning "Node.js is not installed or not on PATH. It is optional because this repository currently has no package.json."
}

Write-Host "[3/6] Python dependencies"
python -m pip install --disable-pip-version-check -r requirements.txt

Write-Host "[4/6] Dependency consistency"
python -m pip check

Write-Host "[5/6] Python syntax"
python -m compileall -q .

Write-Host "[6/6] Flask smoke test"
python -c "from webapp import create_app; app=create_app(); print('Flask app OK'); print('Routes:', len(list(app.url_map.iter_rules())))"

Write-Host "=== Environment READY ===" -ForegroundColor Green
Write-Host "Run: python main.py"
Write-Host "Production: gunicorn -w 2 -b 0.0.0.0:5000 main:app"
