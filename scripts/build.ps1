# Builds VEN on Windows without make.
#   .\scripts\build.ps1            # release build with embedded dashboard
#   .\scripts\build.ps1 -SkipWeb   # Go only, reuse web/dist
#   .\scripts\build.ps1 -Check     # vet, tests, type check, frontend build
param(
    [switch]$SkipWeb,
    [switch]$Check,
    [string]$Version = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not $Version) {
    $Version = (git describe --tags --always --dirty 2>$null)
    if (-not $Version) { $Version = "0.1.0-dev" }
}

function Invoke-Checked([string]$cmd, [string[]]$cmdArgs) {
    & $cmd @cmdArgs
    if ($LASTEXITCODE -ne 0) { throw "$cmd $($cmdArgs -join ' ') failed with exit code $LASTEXITCODE" }
}

function Build-Web {
    Invoke-Checked npm @("--prefix", "web", "ci")
    Invoke-Checked npm @("--prefix", "web", "run", "build")
    New-Item -ItemType File -Force "web/dist/.gitkeep" | Out-Null
}

if ($Check) {
    Invoke-Checked go @("vet", "./...")
    Invoke-Checked go @("test", "./...")
    Invoke-Checked npm @("--prefix", "web", "run", "typecheck")
    Build-Web
    exit 0
}

if (-not $SkipWeb) { Build-Web }
$env:CGO_ENABLED = "0"
New-Item -ItemType Directory -Force bin | Out-Null
Invoke-Checked go @("build", "-trimpath", "-ldflags", "-s -w -X github.com/enigma-137/ven/internal/app.Version=$Version", "-o", "bin/ven.exe", "./cmd/ven")
Write-Host "Built bin/ven.exe ($Version)"
