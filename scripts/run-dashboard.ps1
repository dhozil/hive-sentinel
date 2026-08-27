# HIVE SENTINEL dashboard launcher (Windows)
# Usage:  .\scripts\run-dashboard.ps1
param(
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$frontend = Join-Path $projectRoot "frontend"

# Bebaskan port jika ada proses lama
$existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Port $Port sedang dipakai — proses lama akan dihentikan." -ForegroundColor Yellow
    $existing | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object {
        Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep 1
}

Write-Host "Menjalankan HIVE SENTINEL dashboard..." -ForegroundColor Cyan
Write-Host "  Buka di browser: http://localhost:$Port" -ForegroundColor Green
Write-Host "  (Tekan Ctrl+C untuk menghentikan)" -ForegroundColor DarkGray
Write-Host ""

Set-Location $frontend
node server.mjs
