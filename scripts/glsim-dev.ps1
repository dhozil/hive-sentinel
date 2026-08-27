# Launcher GLSim dengan patch bug proxy-cache aktif.
# Pemakaian: .\scripts\glsim-dev.ps1 [-Port 4000] [-Validators 5]
param(
    [int]$Port = 4000,
    [int]$Validators = 5
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

# Matikan instance lama di port yang sama
$env:PYTHONPATH = $projectRoot
$env:PYTHONUTF8 = "1"

Write-Host "Menjalankan GLSim dengan patch sitecustomize ($projectRoot)"
Write-Host "  Port: $port | Validators: $Validators"

glsim --port $Port --validators $Validators --no-browser
