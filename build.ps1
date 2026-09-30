# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later

#Requires -Version 7
# Runs all checks and tests, then builds out\network-sandbox.exe from the sources in src\.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Invoke-Step([string]$Name, [scriptblock]$Command) {
    Write-Host "==> $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Name failed (exit code $LASTEXITCODE)" }
}

Invoke-Step 'gofmt' {
    $unformatted = gofmt -l src
    if ($unformatted) { Write-Host "Not formatted:`n$unformatted"; $global:LASTEXITCODE = 1 }
}
Invoke-Step 'go vet' { go vet ./... }
Invoke-Step 'go test' { go test -count=1 ./... }

$env:CGO_ENABLED = '0'  # static binary, no C runtime dependency
Invoke-Step 'go build' { go build -trimpath -ldflags '-s -w' -o out/network-sandbox.exe ./src }

Write-Host "Built $(Join-Path $PSScriptRoot 'out\network-sandbox.exe')"
