# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later

#Requires -Version 7
<#
.SYNOPSIS
Starts out\network-sandbox.exe with a test whitelist and sends real requests through it with curl.

.DESCRIPTION
Needs internet access and a built exe (run build.ps1 first). The allowed HTTPS cases also
work behind TLS inspection (e.g. FortiGate) as long as the company CA is in the Windows
certificate store, because curl.exe uses Schannel.
#>
param(
    [int]$Port = 18080
)
$ErrorActionPreference = 'Stop'

$exe = Join-Path $PSScriptRoot 'out\network-sandbox.exe'
if (-not (Test-Path $exe)) { throw "$exe not found - run build.ps1 first" }

$work = Join-Path ([IO.Path]::GetTempPath()) "network-sandbox-manual-$PID"
New-Item -ItemType Directory $work | Out-Null
$config = Join-Path $work 'network-sandbox.ini'
$log = Join-Path $work 'network-sandbox.log'
@"
[network-sandbox]
port=$Port
logfile=$log
loglevel=info

[whitelist]
api.anthropic.com:443
*.githubusercontent.com:443
example.com:80
"@ | Set-Content $config

$proxy = "http://127.0.0.1:$Port"
$failures = 0

function Test-Case {
    param(
        [string]$Name,
        [string]$Url,
        [ValidateSet('http_connect', 'http_code')][string]$Field,
        [string]$Expected,
        [string]$BodyContains,
        [switch]$Direct  # send to the proxy port without using it as a proxy
    )
    $body = Join-Path $work 'body.txt'
    $curlArgs = @('-s', '--max-time', '20', '-o', $body, '-w', "%{$Field}", $Url)
    if (-not $Direct) { $curlArgs = @('-x', $proxy) + $curlArgs }
    $actual = curl.exe @curlArgs
    $text = if (Test-Path $body) { Get-Content $body -Raw } else { '' }
    $ok = $actual -eq $Expected -and (-not $BodyContains -or $text -like "*$BodyContains*")
    if (-not $ok) { $script:failures++ }
    [pscustomobject]@{
        Result   = if ($ok) { 'PASS' } else { 'FAIL' }
        Test     = $Name
        Expected = "$Field=$Expected"
        Actual   = "$Field=$actual"
    }
    Remove-Item $body -ErrorAction SilentlyContinue
}

$process = Start-Process $exe -ArgumentList '-config', $config -PassThru -NoNewWindow
try {
    # Wait until the proxy accepts connections.
    $deadline = (Get-Date).AddSeconds(5)
    while ($true) {
        if ($process.HasExited) { throw "network-sandbox exited with code $($process.ExitCode)" }
        try { [Net.Sockets.TcpClient]::new('127.0.0.1', $Port).Dispose(); break } catch {}
        if ((Get-Date) -gt $deadline) { throw "network-sandbox did not start listening on port $Port" }
        Start-Sleep -Milliseconds 100
    }

    $results = @(
        Test-Case 'HTTPS, exact entry: tunnel opens'      'https://api.anthropic.com/'        http_connect 200
        Test-Case 'HTTPS, wildcard entry: tunnel opens'   'https://raw.githubusercontent.com/' http_connect 200
        Test-Case 'HTTPS, wildcard apex: denied'          'https://githubusercontent.com/'     http_connect 403
        Test-Case 'HTTPS, not whitelisted: denied'        'https://www.wikipedia.org/'         http_connect 403
        Test-Case 'HTTPS, host allowed on port 80 only'   'https://example.com/'               http_connect 403
        Test-Case 'HTTP, whitelisted: forwarded'          'http://example.com/'                http_code 200 -BodyContains 'Example Domain'
        Test-Case 'HTTP, not whitelisted: denied'         'http://www.wikipedia.org/'          http_code 403 -BodyContains 'not in whitelist'
        Test-Case 'HTTP, loopback via proxy: denied'      "http://127.0.0.1:$Port/"            http_code 403
        Test-Case 'Direct request to proxy: rejected'     "http://127.0.0.1:$Port/"            http_code 400 -Direct
    )
    $results | Format-Table -AutoSize
}
finally {
    Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
    $process.WaitForExit()
    Write-Host "--- $log"
    Get-Content $log -ErrorAction SilentlyContinue | Write-Host
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures) {
    Write-Host "$failures test(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'All manual tests passed' -ForegroundColor Green
