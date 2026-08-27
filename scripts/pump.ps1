# Pump: meneruskan attempt dari HoneypotTarget ke AttackAnalyzer via CLI.
# Diperlukan karena StudioNet belum mengeksekusi pesan async emit().
# Di testnet/localnet asli, emit() berjalan otomatis - script ini opsional.
#
# Pemakaian:
#   .\scripts\pump.ps1                       # forward attempt baru saja
#   .\scripts\pump.ps1 -All                  # forward ulang semua attempt
#   .\scripts\pump.ps1 -Honeypot 0x.. -Analyzer 0x..

param(
    [string]$Honeypot = "0xf82771c6c344686D01bde1f4f9a3de636ab86bBe",
    [string]$Analyzer = "0xc39a709F1341a389456521E29b69f10FDffC5175",
    [switch]$All
)

$ErrorActionPreference = "Continue"
$stateFile = Join-Path $PSScriptRoot ".pump_state"

function Get-Value($text, $key) {
    $m = [regex]::Match($text, "${key}:\s*'((?:[^'\\]|\\.)*)'")
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

$infoOut = (genlayer call $Honeypot get_vault_info 2>$null | Out-String)
$total = [int]([regex]::Match($infoOut, "total_attempts:\s*(\d+)")).Groups[1].Value
if ($total -eq 0) { Write-Host "Tidak ada attempt di honeypot."; exit 0 }

$last = 0
if (-not $All -and (Test-Path $stateFile)) {
    $last = [int](Get-Content $stateFile -ErrorAction SilentlyContinue)
}

Write-Host "Honeypot : $Honeypot ($total attempt)"
Write-Host "Analyzer : $Analyzer"
Write-Host "Forward  : attempt index $($last)..$($total - 1)"

for ($i = $last; $i -lt $total; $i++) {
    $raw = (genlayer call $Honeypot get_attempt --args $i 2>$null | Out-String)
    $plea = Get-Value $raw "plea"
    $attacker = Get-Value $raw "sender"
    if (-not $plea) { Write-Host "[$i] plea kosong/gagal parse, skip" -ForegroundColor Yellow; continue }

    $preview = $plea.Substring(0, [Math]::Min(60, $plea.Length))
    Write-Host "[$i] $preview..." -NoNewline
    genlayer write $Analyzer analyze_payload --args "$plea" "$attacker" 2>$null | Out-Null
    Write-Host " OK" -ForegroundColor Green

    # Enrich: cek jejak on-chain alamat penyerang via RPC publik.
    Write-Host "     enrich sender..." -NoNewline
    $statsOut = (genlayer call $Analyzer get_stats 2>$null | Out-String)
    $rid = [int]([regex]::Match($statsOut, "reports_total:\s*(\d+)")).Groups[1].Value
    if ($rid -gt 0) {
        genlayer write $Analyzer enrich_sender --args ($rid - 1) "https://ethereum-rpc.publicnode.com" 2>$null | Out-Null
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " skip (tidak ada laporan)" -ForegroundColor Yellow
    }
}

Set-Content -Path $stateFile -Value $total
Write-Host "Selesai."
