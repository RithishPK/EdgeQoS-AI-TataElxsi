<#
Runs the whole CAKE vs HTB+FQ-CoDel matrix unattended.

The laptop must be joined to Tata-AI-Router first, otherwise its traffic never
crosses the Pi and every cell reads the same.

For each cell: SSH sets the scheduler and prints the live qdisc, then the
benchmark runs locally. Rep 2 runs the cells in reverse order, so a drift in
link conditions over the session does not line up with one scheduler.

  .\run-matrix.ps1
  .\run-matrix.ps1 -Reps 3 -Pi 10.42.0.1
#>

[CmdletBinding()]
param(
  [string]$Pi = "10.42.0.1",
  [string]$User = "raspberrypi4",
  [string]$Key = "$env:USERPROFILE\.ssh\edgeqos_ed25519",
  [int]$Reps = 2,
  [string]$OutDir = "$PSScriptRoot\results",
  [string[]]$Cells = @("baseline", "htb-ai-off", "cake-ai-off", "htb-ai-on", "cake-ai-on"),
  [int]$Streams = 4
)

$ErrorActionPreference = "Stop"
$cells = $Cells

function Invoke-Pi([string]$Cmd) {
  & ssh -i $Key -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10 "$User@$Pi" $Cmd 2>&1
}

Write-Host "Checking the Pi is reachable at $Pi ..." -ForegroundColor Cyan
$probe = Invoke-Pi "echo READY"
if ($probe -notmatch "READY") {
  Write-Host "Cannot reach $Pi over SSH. Is this laptop on Tata-AI-Router?" -ForegroundColor Red
  Write-Host $probe
  exit 1
}

# Confirm traffic actually routes through the Pi, so the run cannot be meaningless.
# Find-NetRoute asks the stack which route it would really pick; reading the
# route table directly is misleading, because a disconnected adapter can keep a
# stale 0.0.0.0/0 entry at a lower metric that is never actually used.
$route = Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction SilentlyContinue |
         Where-Object { $_.NextHop }
$gw = $route.NextHop
Write-Host "Effective next hop to the internet: $gw" -ForegroundColor Cyan
if ($gw -ne "10.42.0.1") {
  Write-Host "ABORT: internet traffic does not go via the Pi (10.42.0.1)." -ForegroundColor Red
  Write-Host "       Every cell would read the same. Join Tata-AI-Router first." -ForegroundColor Red
  exit 1
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir "matrix-run.log"
$started = Get-Date
"=== matrix run started $started ===" | Out-File -Append -Encoding utf8 $log

for ($rep = 1; $rep -le $Reps; $rep++) {
  $order = $cells
  if ($rep % 2 -eq 0) { $order = $cells[($cells.Count - 1)..0] }

  foreach ($cell in $order) {
    $label = "$cell-r$rep"
    Write-Host "`n======== $label ========" -ForegroundColor Green

    $verify = Invoke-Pi "sudo sh /tmp/edgeqos-cell.sh $cell"
    $verify | Out-File -Append -Encoding utf8 $log
    $verify | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

    if ($verify -match "error=None") {
      # keep going
    } else {
      Write-Host "  cell did not apply cleanly - skipping this run" -ForegroundColor Red
      "SKIPPED $label" | Out-File -Append -Encoding utf8 $log
      continue
    }

    & "$PSScriptRoot\edgeqos-bench.ps1" -Label $label -Pi $Pi -OutDir $OutDir -Streams $Streams
  }
}

Write-Host "`nReturning the Pi to baseline (AI off, no shaping)..." -ForegroundColor Cyan
Invoke-Pi "sudo sh /tmp/edgeqos-cell.sh baseline" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

$elapsed = [int]((Get-Date) - $started).TotalMinutes
Write-Host "`nDone in ~$elapsed min. Summary: $OutDir\summary.csv" -ForegroundColor Green
Import-Csv (Join-Path $OutDir "summary.csv") |
  Format-Table label, scheduler, ai_enabled, idle_p50_ms, down_p95_ms, down_p99_ms,
               up_p95_ms, up_p99_ms, bloat_down_ms, bloat_up_ms,
               throughput_down_mbps, throughput_up_mbps -AutoSize
