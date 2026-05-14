# Watchdog installer (Windows PowerShell). Downloads latest GitHub
# Release binaries for the host arch and drops them into
# $env:WATCHDOG_INSTALL_DIR (default $env:USERPROFILE\.watchdog\bin).
#
# Usage:
#   iwr -useb https://raw.githubusercontent.com/Maxlemore97/Watchdog/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "Maxlemore97/Watchdog"
$InstallDir = if ($env:WATCHDOG_INSTALL_DIR) { $env:WATCHDOG_INSTALL_DIR } else { "$env:USERPROFILE\.watchdog\bin" }
$Version = if ($env:WATCHDOG_VERSION) { $env:WATCHDOG_VERSION } else { "latest" }

function Info($msg) { Write-Host "watchdog-install: $msg" }
function Fail($msg) { Write-Host "watchdog-install: $msg" -ForegroundColor Red; exit 1 }

# Detect arch
$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { Fail "unsupported arch: $($env:PROCESSOR_ARCHITECTURE)" }
}

# Resolve version
if ($Version -eq "latest") {
    $latest = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $latest.tag_name
    if (-not $Version) { Fail "could not resolve latest version" }
}

Info "installing watchdog $Version (windows/$Arch) into $InstallDir"

$versionBare = $Version.TrimStart("v")
$archive = "watchdog_${versionBare}_windows_${Arch}.zip"
$url = "https://github.com/$Repo/releases/download/$Version/$archive"

$tmp = Join-Path $env:TEMP "watchdog-install-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    $archivePath = Join-Path $tmp $archive
    Info "fetching $url"
    Invoke-WebRequest -Uri $url -OutFile $archivePath -UseBasicParsing

    Info "extracting"
    Expand-Archive -Path $archivePath -DestinationPath $tmp -Force

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    foreach ($bin in @(
        "watchdog-pretool", "watchdog-session", "watchdog-prompt", "watchdog-scan",
        "watchdog-mcp", "watchdog-shim", "watchdog-shim-exec", "watchdog-action"
    )) {
        $src = Join-Path $tmp "$bin.exe"
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination (Join-Path $InstallDir "$bin.exe") -Force
        }
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# PATH hint
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($userPath -split ";" | Where-Object { $_ -eq $InstallDir })) {
    Write-Host ""
    Write-Host "NOTE: $InstallDir is not on your user PATH." -ForegroundColor Yellow
    Write-Host "Run this to add it (then restart your shell):"
    Write-Host "  [Environment]::SetEnvironmentVariable('Path', '$InstallDir;' + [Environment]::GetEnvironmentVariable('Path', 'User'), 'User')"
}

Info "done."
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. watchdog-shim install"
Write-Host "  2. Add the shim dir to the FRONT of your PATH."
Write-Host "  3. watchdog-shim doctor"
Write-Host ""
Write-Host "See https://github.com/$Repo for full docs."
