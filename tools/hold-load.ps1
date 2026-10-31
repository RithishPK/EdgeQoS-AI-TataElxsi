<#
Sustained bulk load from this laptop, held across several test cells.

Unlike edgeqos-bench.ps1 this does NOT measure anything and does NOT stop
between cells: the point is that the competing traffic stays identical while
the scheduler is switched underneath it, so the only thing that changes
between cells is the Pi's configuration.

  .\hold-load.ps1 -Seconds 720

The victim measurement for this test is the iPhone's in-game ping, read by the
user. A probe on this machine would sit inside this machine's own per-host
share - the share being saturated here - so it would measure the aggressor,
not the protected device.
#>
[CmdletBinding()]
param(
  [int]$Seconds = 720,
  [int]$DownStreams = 4,
  [int]$UpStreams = 2
)

$downUrls = @(
  "https://proof.ovh.net/files/100Mb.dat",
  "https://ash-speed.hetzner.com/100MB.bin",
  "https://speed.cloudflare.com/__down?bytes=90000000"
)
$upUrl  = "https://speed.cloudflare.com/__up"
$upFile = Join-Path $env:TEMP "edgeqos-up-payload.bin"
if (-not (Test-Path $upFile)) {
  $fs = [System.IO.File]::Create($upFile)
  try { $fs.SetLength(200MB) } finally { $fs.Close() }
}

$jobs = @()
for ($i = 0; $i -lt $DownStreams; $i++) {
  $u = $downUrls[$i % $downUrls.Count]
  $jobs += Start-Job -ArgumentList $u, $Seconds -ScriptBlock {
    param($u, $s)
    $end = (Get-Date).AddSeconds($s); $total = 0
    while ((Get-Date) -lt $end) {
      $left = [int][math]::Ceiling(($end - (Get-Date)).TotalSeconds)
      if ($left -le 0) { break }
      $out = & curl.exe -s --max-time $left -o NUL -w "%{size_download}" $u
      $n = 0; if ([long]::TryParse(("$out").Trim(), [ref]$n)) { $total += $n }
    }
    $total
  }
}
for ($i = 0; $i -lt $UpStreams; $i++) {
  $jobs += Start-Job -ArgumentList $upUrl, $Seconds, $upFile -ScriptBlock {
    param($u, $s, $f)
    $end = (Get-Date).AddSeconds($s); $total = 0
    while ((Get-Date) -lt $end) {
      $left = [int][math]::Ceiling(($end - (Get-Date)).TotalSeconds)
      if ($left -le 0) { break }
      $out = & curl.exe -s --max-time $left -o NUL -w "%{size_upload}" -T $f $u
      $n = 0; if ([long]::TryParse(("$out").Trim(), [ref]$n)) { $total += $n }
    }
    $total
  }
}

Write-Host "holding $DownStreams down + $UpStreams up streams for $Seconds s" -ForegroundColor Green
$bytes = 0
foreach ($j in $jobs) {
  Wait-Job $j -Timeout ($Seconds + 60) | Out-Null
  foreach ($line in (Receive-Job $j -ErrorAction SilentlyContinue)) {
    $n = 0; if ([long]::TryParse(("$line").Trim(), [ref]$n)) { $bytes += $n }
  }
  Remove-Job $j -Force -ErrorAction SilentlyContinue
}
Write-Host ("load finished: {0:N1} GB moved, avg {1:N1} Mb/s" -f ($bytes / 1GB), ($bytes * 8 / $Seconds / 1e6))
