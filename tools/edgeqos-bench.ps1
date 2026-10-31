<#
EDGEqos scheduler benchmark - run on the ASUS laptop while it is connected to Tata-AI-Router.

One invocation = one cell of the test matrix. It generates the competing load itself and
measures latency under that load, so the result does not depend on reading a game's ping display.

  .\edgeqos-bench.ps1 -Label baseline-noshape
  .\edgeqos-bench.ps1 -Label htb-ai-off
  .\edgeqos-bench.ps1 -Label htb-ai-on      -SetAi on
  .\edgeqos-bench.ps1 -Label cake-ai-off
  .\edgeqos-bench.ps1 -Label cake-ai-on     -SetAi on

Timeline per run (~75 s):
  0-10 s   idle      latency with no load
  10-34 s  download  4 parallel downloads saturating the downlink
  34-42 s  recover
  42-66 s  upload    4 parallel uploads saturating the uplink
  66-72 s  recover

Latency probe: 10 samples/s to -PingTarget for the whole run, tagged by phase.
The number that answers "is CAKE better" is p99 and max during load, not the average.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Label,
  [string]$Pi = "10.42.0.1",
  [string]$PingTarget = "1.1.1.1",
  [ValidateSet("on", "off", "leave")][string]$SetAi = "leave",
  [int]$Streams = 4,
  [int]$IdleSec = 10,
  [int]$LoadSec = 24,
  [int]$RecoverSec = 8,
  [string]$OutDir = "$PSScriptRoot\results"
)

$ErrorActionPreference = "Stop"
# Cloudflare caps __down at just under 100 MB per request AND rate-limits sustained use
# (it returned 429 after seven runs, silently zeroing three cells of the first matrix).
# Each worker loops requests until its deadline, and workers are spread across hosts so
# no single provider sees the whole load.
$DownUrls = @(
  "https://proof.ovh.net/files/100Mb.dat",
  "https://ash-speed.hetzner.com/100MB.bin",
  "https://speed.cloudflare.com/__down?bytes=90000000"
)
$UpUrl   = "https://speed.cloudflare.com/__up"
$UpFile  = Join-Path $env:TEMP "edgeqos-up-payload.bin"
$UpBytes = 200MB

# ---------- helpers ----------

function Get-PiStatus {
  try { return Invoke-RestMethod -Uri "http://$Pi`:8080/api/status" -TimeoutSec 3 }
  catch { return $null }
}

function Set-PiAi([bool]$Enable) {
  # /api/control only hands out a token to the admin device; from the home LAN it is view-only.
  try {
    $tok = (Invoke-RestMethod -Uri "http://$Pi`:8080/api/control" -TimeoutSec 3).token
  } catch {
    Write-Host "  cannot get control token (view-only from here) - set AI $(if($Enable){'ON'}else{'OFF'}) on the dashboard yourself, then press Enter" -ForegroundColor Yellow
    Read-Host | Out-Null
    return
  }
  Invoke-RestMethod -Uri "http://$Pi`:8080/api/control" -Method Post -TimeoutSec 10 `
    -Headers @{ "X-EdgeQoS-Token" = $tok } -ContentType "application/json" `
    -Body (@{ ai_enabled = $Enable } | ConvertTo-Json) | Out-Null
  Start-Sleep -Seconds 12   # let the qdisc settle and the rate estimators refill
}

function Percentile([double[]]$Values, [double]$P) {
  if ($Values.Count -eq 0) { return $null }
  $s = $Values | Sort-Object
  $i = [math]::Ceiling(($P / 100.0) * $s.Count) - 1
  if ($i -lt 0) { $i = 0 }
  if ($i -ge $s.Count) { $i = $s.Count - 1 }
  return [double]$s[$i]
}

function New-UploadPayload {
  if ((Test-Path $UpFile) -and ((Get-Item $UpFile).Length -ge $UpBytes)) { return }
  $fs = [System.IO.File]::Create($UpFile)
  try { $fs.SetLength($UpBytes) } finally { $fs.Close() }
}

function Start-LoadJobs([string]$Kind, [int]$Seconds) {
  $jobs = @()
  for ($i = 0; $i -lt $Streams; $i++) {
    if ($Kind -eq "down") {
      $url = $DownUrls[$i % $DownUrls.Count]
      $jobs += Start-Job -ArgumentList $url, $Seconds -ScriptBlock {
        param($u, $s)
        $deadline = (Get-Date).AddSeconds($s); $total = 0
        while ((Get-Date) -lt $deadline) {
          $left = [int][math]::Ceiling(($deadline - (Get-Date)).TotalSeconds)
          if ($left -le 0) { break }
          $out = & curl.exe -s --max-time $left -o NUL -w "%{size_download}" $u
          $n = 0; if ([long]::TryParse(("$out").Trim(), [ref]$n)) { $total += $n }
        }
        $total
      }
    } else {
      $jobs += Start-Job -ArgumentList $UpUrl, $Seconds, $UpFile -ScriptBlock {
        param($u, $s, $f)
        $deadline = (Get-Date).AddSeconds($s); $total = 0
        while ((Get-Date) -lt $deadline) {
          $left = [int][math]::Ceiling(($deadline - (Get-Date)).TotalSeconds)
          if ($left -le 0) { break }
          $out = & curl.exe -s --max-time $left -o NUL -w "%{size_upload}" -T $f $u
          $n = 0; if ([long]::TryParse(("$out").Trim(), [ref]$n)) { $total += $n }
        }
        $total
      }
    }
  }
  return $jobs
}

function Stop-LoadJobs($Jobs) {
  $total = 0
  foreach ($j in $Jobs) {
    try {
      Wait-Job $j -Timeout 20 | Out-Null
      foreach ($line in (Receive-Job $j -ErrorAction SilentlyContinue)) {
        $n = 0
        if ([long]::TryParse(("$line").Trim(), [ref]$n)) { $total += $n }
      }
    } catch { }
    Remove-Job $j -Force -ErrorAction SilentlyContinue
  }
  return $total
}

# ---------- run ----------

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-UploadPayload

if ($SetAi -ne "leave") {
  Write-Host "Setting AI $($SetAi.ToUpper())..." -ForegroundColor Cyan
  Set-PiAi ($SetAi -eq "on")
}

$pre = Get-PiStatus
if ($null -eq $pre) {
  Write-Host "WARNING: cannot reach the dashboard at $Pi`:8080 - is this laptop on Tata-AI-Router?" -ForegroundColor Yellow
  $schedBefore = "unknown"; $aiBefore = "unknown"
} else {
  $schedBefore = "$($pre.scheduler)"
  $aiBefore = "$($pre.control.ai_enabled)"
  Write-Host "Pi reports: scheduler=$schedBefore ai_enabled=$aiBefore caps=$($pre.download_mbit)/$($pre.upload_mbit) Mb/s" -ForegroundColor Cyan
}

# Phase boundaries. Load starts at $dnStart / $upStart; the measured window skips a 2 s ramp
# so the percentiles describe the saturated steady state, not the ramp-up.
$ramp     = 2
$dnStart  = $IdleSec
$dnEnd    = $dnStart + $LoadSec
$upStart  = $dnEnd + $RecoverSec
$upEnd    = $upStart + $LoadSec
$runSeconds = $upEnd + $RecoverSec

$plan = @(
  @{ Name = "idle";      Start = 0;                 End = $dnStart },
  @{ Name = "download";  Start = $dnStart + $ramp;  End = $dnEnd },
  @{ Name = "recover-1"; Start = $dnEnd + $ramp;    End = $upStart },
  @{ Name = "upload";    Start = $upStart + $ramp;  End = $upEnd },
  @{ Name = "recover-2"; Start = $upEnd + $ramp;    End = $runSeconds }
)
$measuredSec = $LoadSec - $ramp

$ping    = New-Object System.Net.NetworkInformation.Ping
$samples = New-Object System.Collections.Generic.List[object]
$apiLog  = New-Object System.Collections.Generic.List[object]
$downJobs = $null; $upJobs = $null
$downStarted = $false; $upStarted = $false
$downBytes = 0; $upBytes = 0
$nextApi = 0.0
$sw = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "`nRun '$Label' - $runSeconds s. Probing $PingTarget at 10 Hz." -ForegroundColor Green

try {
  while ($sw.Elapsed.TotalSeconds -lt $runSeconds) {
    $t = $sw.Elapsed.TotalSeconds

    if ($t -ge $dnStart -and -not $downStarted) {
      Write-Host "  [$([int]$t)s] download load x$Streams" -ForegroundColor DarkGray
      $downJobs = Start-LoadJobs "down" $LoadSec; $downStarted = $true
    }
    if ($t -ge ($dnEnd + 1) -and $null -ne $downJobs) {
      $downBytes = Stop-LoadJobs $downJobs; $downJobs = $null
    }
    if ($t -ge $upStart -and -not $upStarted) {
      Write-Host "  [$([int]$t)s] upload load x$Streams" -ForegroundColor DarkGray
      $upJobs = Start-LoadJobs "up" $LoadSec; $upStarted = $true
    }
    if ($t -ge ($upEnd + 1) -and $null -ne $upJobs) {
      $upBytes = Stop-LoadJobs $upJobs; $upJobs = $null
    }

    $phase = "gap"
    foreach ($p in $plan) { if ($t -ge $p.Start -and $t -lt $p.End) { $phase = $p.Name; break } }

    $rtt = $null
    try {
      $r = $ping.Send($PingTarget, 900)
      if ($r.Status -eq "Success") { $rtt = [double]$r.RoundtripTime }
    } catch { }
    $samples.Add([pscustomobject]@{ t = [math]::Round($t, 2); phase = $phase; rtt_ms = $rtt })

    if ($t -ge $nextApi) {
      $nextApi = $t + 2
      $s = Get-PiStatus
      if ($null -ne $s) {
        $apiLog.Add([pscustomobject]@{
          t = [math]::Round($t, 1); phase = $phase
          scheduler = "$($s.scheduler)"; ai = "$($s.control.ai_enabled)"
          total_down_mbit = $s.total_download_mbit; total_up_mbit = $s.total_upload_mbit
          drop_percent = $s.capture_interval.drop_percent
          pi_rtt_p95 = $s.latency.rtt_p95_ms
        })
      }
    }

    $sleep = 100 - [int]((($sw.Elapsed.TotalSeconds - $t) * 1000))
    if ($sleep -gt 0) { Start-Sleep -Milliseconds $sleep }
  }
} finally {
  if ($null -ne $downJobs) { $downBytes = Stop-LoadJobs $downJobs }
  if ($null -ne $upJobs)   { $upBytes   = Stop-LoadJobs $upJobs }
}
$sw.Stop()

$post = Get-PiStatus

# ---------- summarise ----------

function Phase-Stats([string]$Name) {
  $rows = $samples | Where-Object { $_.phase -eq $Name }
  $ok = @($rows | Where-Object { $null -ne $_.rtt_ms } | ForEach-Object { [double]$_.rtt_ms })
  $sent = @($rows).Count
  $loss = 0.0
  if ($sent -gt 0) { $loss = [math]::Round(100.0 * ($sent - $ok.Count) / $sent, 1) }
  $mx = $null
  if ($ok.Count -gt 0) { $mx = [double]($ok | Measure-Object -Maximum).Maximum }
  return [pscustomobject]@{
    phase  = $Name
    n      = $sent
    p50    = Percentile $ok 50
    p95    = Percentile $ok 95
    p99    = Percentile $ok 99
    max    = $mx
    loss_pct = $loss
  }
}

$idle = Phase-Stats "idle"
$dn   = Phase-Stats "download"
$up   = Phase-Stats "upload"
$stats = @($idle, (Phase-Stats "recover-1"), $dn, $up, (Phase-Stats "recover-2"))

$downMbps = [math]::Round(($downBytes * 8.0) / $LoadSec / 1e6, 2)
$upMbps   = [math]::Round(($upBytes   * 8.0) / $LoadSec / 1e6, 2)

# bufferbloat: how much latency the load adds on top of the idle baseline
$bloatDown = $null; $bloatUp = $null
if ($null -ne $idle.p50) {
  if ($null -ne $dn.p95) { $bloatDown = [math]::Round($dn.p95 - $idle.p50, 1) }
  if ($null -ne $up.p95) { $bloatUp   = [math]::Round($up.p95 - $idle.p50, 1) }
}

$capDown = $null; $capUp = $null
if ($null -ne $pre) { $capDown = $pre.download_mbit; $capUp = $pre.upload_mbit }
$schedAfter = "unknown"; $aiAfter = "unknown"
if ($null -ne $post) { $schedAfter = "$($post.scheduler)"; $aiAfter = "$($post.control.ai_enabled)" }
$dropMax = $null
if ($apiLog.Count -gt 0) { $dropMax = ($apiLog | Measure-Object drop_percent -Maximum).Maximum }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$samples | Export-Csv -NoTypeInformation -Path (Join-Path $OutDir "$Label-$stamp-ping.csv")
$apiLog  | Export-Csv -NoTypeInformation -Path (Join-Path $OutDir "$Label-$stamp-api.csv")

$summary = [pscustomobject]@{
  label             = $Label
  timestamp         = $stamp
  scheduler         = $schedBefore
  ai_enabled        = $aiBefore
  cap_down_mbit     = $capDown
  cap_up_mbit       = $capUp
  ping_target       = $PingTarget
  idle_p50_ms       = $idle.p50
  idle_p95_ms       = $idle.p95
  down_p50_ms       = $dn.p50
  down_p95_ms       = $dn.p95
  down_p99_ms       = $dn.p99
  down_max_ms       = $dn.max
  down_loss_pct     = $dn.loss_pct
  up_p50_ms         = $up.p50
  up_p95_ms         = $up.p95
  up_p99_ms         = $up.p99
  up_max_ms         = $up.max
  up_loss_pct       = $up.loss_pct
  bloat_down_ms     = $bloatDown
  bloat_up_ms       = $bloatUp
  throughput_down_mbps = $downMbps
  throughput_up_mbps   = $upMbps
  pi_drop_pct_max    = $dropMax
  scheduler_after    = $schedAfter
  ai_after           = $aiAfter
}

Write-Host "`n--- $Label (scheduler=$schedBefore, ai=$aiBefore) ---" -ForegroundColor Green
$stats | Format-Table phase, n, p50, p95, p99, max, loss_pct -AutoSize
Write-Host ("throughput      : {0} Mb/s down, {1} Mb/s up" -f $downMbps, $upMbps)
Write-Host ("latency added   : +{0} ms (download), +{1} ms (upload)  [p95 over idle p50]" -f $bloatDown, $bloatUp) -ForegroundColor Yellow
if ($downMbps -le 0 -or $upMbps -le 0) {
  # A rate-limited or blocked load source produces a plausible-looking latency row
  # with no load behind it. Say so loudly rather than recording a clean-looking lie.
  Write-Host "INVALID: a load phase moved zero bytes - latency for that phase is meaningless." -ForegroundColor Red
}
if ($summary.ai_after -ne $aiBefore -or $summary.scheduler_after -ne $schedBefore) {
  Write-Host "WARNING: Pi state changed during the run - discard this result." -ForegroundColor Red
}

$all = Join-Path $OutDir "summary.csv"
if (Test-Path $all) { $summary | Export-Csv -NoTypeInformation -Append -Path $all }
else                { $summary | Export-Csv -NoTypeInformation -Path $all }

Write-Host "`nsaved -> $all" -ForegroundColor Cyan
