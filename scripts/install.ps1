# Install the latest VEN release on Windows (PowerShell):
#   irm https://raw.githubusercontent.com/enigma-137/ven/HEAD/scripts/install.ps1 | iex
# Options: $env:VEN_VERSION = "v0.2.0" to pin a version.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = "enigma-137/ven"
$dir = Join-Path $env:LOCALAPPDATA "Programs\ven"

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "Unsupported CPU: $env:PROCESSOR_ARCHITECTURE" }
}

$version = $env:VEN_VERSION
if (-not $version) {
    $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
}
if (-not $version) { throw "Could not find the latest release" }

$name = "ven_$($version.TrimStart('v'))_windows_$arch"
$base = "https://github.com/$repo/releases/download/$version"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ven-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading VEN $version for windows/$arch..."
    Invoke-WebRequest "$base/$name.zip" -OutFile "$tmp\$name.zip" -UseBasicParsing
    Invoke-WebRequest "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS" -UseBasicParsing

    $line = Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match " $([regex]::Escape("$name.zip"))$" }
    if (-not $line) { throw "No checksum for $name.zip" }
    $expected = ($line -split " ")[0]
    $actual = (Get-FileHash "$tmp\$name.zip" -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) { throw "Checksum mismatch: the download is corrupted or was tampered with" }

    Expand-Archive "$tmp\$name.zip" -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item "$tmp\$name\ven.exe" "$dir\ven.exe" -Force
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ";") -notcontains $dir) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
    Write-Host "Added $dir to your PATH. Open a new terminal to use ven."
}
Write-Host "Installed $dir\ven.exe ($version)"
