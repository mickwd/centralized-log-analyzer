<#
.SYNOPSIS
    Demo local completa en Windows: venv, datos de ejemplo, recolección, análisis y dashboard.

.EXAMPLE
    .\scripts\demo.ps1            # genera samples, recolecta y analiza
    .\scripts\demo.ps1 -Serve     # además levanta el dashboard en http://127.0.0.1:8000
#>
[CmdletBinding()]
param(
    [switch]$Serve,
    [int]$Port = 8000
)

# Continue: lo que Python escribe en stderr (logs) no debe cortar el script en PowerShell 5.1.
# Los errores reales se detectan con $LASTEXITCODE.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    Write-Host 'Creando entorno virtual...'
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'no se pudo crear el venv' }
    & $python -m pip install --quiet --upgrade pip
    & $python -m pip install --quiet -r requirements-dev.txt
    & $python -m pip install --quiet -e .
    if ($LASTEXITCODE -ne 0) { throw 'falló la instalación de dependencias' }
}

$env:PYTHONIOENCODING = 'utf-8'
$env:LOGAN_DATABASE_URL = 'sqlite:///data/demo.db'
if (Test-Path 'data\demo.db') { Remove-Item 'data\demo.db*' -Force }

Write-Host "`n== Generando logs de ejemplo" -ForegroundColor Cyan
& $python scripts\generate_samples.py
if ($LASTEXITCODE -ne 0) { throw 'falló la generación de samples' }

Write-Host "`n== Recolectando" -ForegroundColor Cyan
& $python -m loganalyzer collect --inventory config\hosts.demo.yaml
if ($LASTEXITCODE -ne 0) { throw 'falló la recolección' }

Write-Host "`n== Analizando" -ForegroundColor Cyan
& $python -m loganalyzer analyze --since-hours 240
if ($LASTEXITCODE -ne 0) { throw 'falló el análisis' }

if ($Serve) {
    Write-Host "`nDashboard en http://127.0.0.1:$Port (Ctrl+C para salir)" -ForegroundColor Green
    & $python -m loganalyzer serve --port $Port
}
