#Requires -Version 5.1
# Installs the latest terra release (or TERRA_VERSION=x.y.z), verifying its
# release checksum before anything is put in place. When GitHub CLI is present,
# it verifies the release attestation too.
param(
    [switch]$Prerelease,
    [string]$Version = $env:TERRA_VERSION
)

$ErrorActionPreference = "Stop"

$repo = "terrarium-sh/terrarium"
if (-not $Version) { $Version = "latest" }
if ($Version -ne "latest" -and $Version -notlike "v*") {
    $Version = "v$Version"
}

$architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($architecture) {
    "AMD64" { $asset = "terra-x86_64-pc-windows-msvc" }
    "ARM64" { $asset = "terra-aarch64-pc-windows-msvc" }
    default { throw "terrarium: no release for Windows/$architecture yet" }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("terra-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    if ($Version -eq "latest" -and $Prerelease) {
        # releases/latest/download resolves to the newest stable release only.
        $releasesJson = Join-Path $tmp "releases.json"
        curl.exe -fsSL --proto "=https" --tlsv1.2 "https://api.github.com/repos/$repo/releases?per_page=1" -o $releasesJson
        if ($LASTEXITCODE -ne 0) { throw "terrarium: could not resolve the newest release" }
        $Version = @((Get-Content -Raw -LiteralPath $releasesJson | ConvertFrom-Json))[0].tag_name
        if (-not $Version) { throw "terrarium: could not resolve the newest release" }
    }

    $base = if ($Version -eq "latest") {
        "https://github.com/$repo/releases/latest/download"
    } else {
        "https://github.com/$repo/releases/download/$Version"
    }
    $archive = "$asset.tar.gz"
    $sumsPath = Join-Path $tmp "SHA256SUMS"
    $archivePath = Join-Path $tmp $archive
    curl.exe -fsSL --proto "=https" --tlsv1.2 "$base/SHA256SUMS" -o $sumsPath
    if ($LASTEXITCODE -ne 0) { throw "terrarium: could not download SHA256SUMS" }
    curl.exe -fsSL --proto "=https" --tlsv1.2 "$base/$archive" -o $archivePath
    if ($LASTEXITCODE -ne 0) { throw "terrarium: could not download $archive" }

    # The checksum comes from the same release ref as the binary, so a tampered
    # mirror of one alone cannot pass; the mismatch must be said out loud.
    $expected = $null
    foreach ($line in Get-Content -LiteralPath $sumsPath) {
        $fields = $line -split '\s+'
        if ($fields[-1] -eq $archive) { $expected = $fields[0]; break }
    }
    if (-not $expected) {
        throw "terrarium: $archive is not in this release's SHA256SUMS - refusing to install"
    }
    $got = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    if ($got -ne $expected) {
        throw "terrarium: CHECKSUM MISMATCH for $archive`n  expected: $expected`n  got:      $got`nnothing was installed"
    }

    if (Get-Command gh -ErrorAction SilentlyContinue) {
        gh attestation verify $archivePath --repo $repo --signer-workflow "$repo/.github/workflows/release.yml"
        if ($LASTEXITCODE -ne 0) {
            throw "terrarium: release attestation verification failed"
        }
    } else {
        Write-Warning "terrarium: GitHub CLI is unavailable; checksum verified but attestation was not"
    }

    $extract = Join-Path $tmp "extract"
    New-Item -ItemType Directory -Path $extract | Out-Null
    tar -xzf $archivePath -C $extract
    if ($LASTEXITCODE -ne 0) { throw "terrarium: could not extract $archive" }
    $binary = Join-Path $extract "terra.exe"
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "terrarium: $archive does not contain terra.exe"
    }

    $bin = Join-Path $env:LOCALAPPDATA "Programs\terra"
    $target = Join-Path $bin "terra.exe"
    if (Test-Path -LiteralPath $target -PathType Container) {
        throw "terrarium: $target exists but is not a regular file - move it aside first"
    }
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    Copy-Item -LiteralPath $binary -Destination $target -Force

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @($userPath -split ';' | Where-Object { $_ })
    if ($entries -notcontains $bin) {
        [Environment]::SetEnvironmentVariable("Path", (($entries + $bin) -join ';'), "User")
        Write-Host "added $bin to the user PATH - open a new terminal to use terra"
    }
    Write-Host "installed terra at $target"
} finally {
    Remove-Item -Recurse -Force -LiteralPath $tmp
}
