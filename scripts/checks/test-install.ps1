#Requires -Version 5.1
# Runs install.ps1 against local release fixtures: `curl.exe` and `gh` are shadowed by functions,
# which PowerShell resolves before external commands.
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installer = Join-Path $root "install.ps1"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("terra-install-test-" + [guid]::NewGuid().ToString("N"))
$release = Join-Path $tmp "release"
New-Item -ItemType Directory -Path $release | Out-Null
$environmentKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $true)
$originalPath = $environmentKey.GetValue("Path", $null, "DoNotExpandEnvironmentNames")
$originalKind = if ($null -ne $originalPath) { $environmentKey.GetValueKind("Path") } else { $null }
$originalLocalAppData = $env:LOCALAPPDATA
$script:urls = [System.Collections.Generic.List[string]]::new()

function curl.exe {
    $url = @($args | Where-Object { $_ -like "https://*" })[0]
    $output = $args[[array]::IndexOf($args, "-o") + 1]
    $script:urls.Add($url)
    $name = if ($url -like "https://api.github.com/*") { "releases.json" } else { Split-Path -Leaf $url }
    Copy-Item -LiteralPath (Join-Path $script:release $name) -Destination $output
    $global:LASTEXITCODE = 0
}

function gh { $global:LASTEXITCODE = 0 }

function Assert([bool]$condition, [string]$message) {
    if (-not $condition) { throw "test-install.ps1: $message" }
}

try {
    Set-Content -LiteralPath (Join-Path $release "terra.exe") -Value "stub terra"
    foreach ($asset in "terra-x86_64-pc-windows-msvc", "terra-aarch64-pc-windows-msvc") {
        tar -czf (Join-Path $release "$asset.tar.gz") -C $release terra.exe
        if ($LASTEXITCODE -ne 0) { throw "test-install.ps1: could not pack $asset" }
    }
    $sums = Get-ChildItem -LiteralPath $release -Filter "*.tar.gz" | ForEach-Object {
        "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)"
    }
    Set-Content -LiteralPath (Join-Path $release "SHA256SUMS") -Value $sums
    Set-Content -LiteralPath (Join-Path $release "releases.json") -Value '[{"tag_name": "v1.3.0-rc.1"}]'
    $env:LOCALAPPDATA = Join-Path $tmp "localappdata"
    $installed = Join-Path $env:LOCALAPPDATA "Programs\terra\terra.exe"
    $environmentKey.SetValue("Path", "%USERPROFILE%\terra-test-bin", "ExpandString")

    # A pinned version passed as a flag to the downloaded script.
    & $installer -Version 1.2.3 | Out-Null
    Assert ((Get-Content -Raw -LiteralPath $installed) -eq (Get-Content -Raw -LiteralPath (Join-Path $release "terra.exe"))) "the pinned install did not place terra.exe"
    Assert ($script:urls -match "/releases/download/v1\.2\.3/") "the pinned install did not fetch v1.2.3"
    $rawPath = $environmentKey.GetValue("Path", "", "DoNotExpandEnvironmentNames")
    Assert ($rawPath -like "%USERPROFILE%\terra-test-bin;*") "an unexpanded PATH entry was rewritten: $rawPath"
    Assert ($environmentKey.GetValueKind("Path") -eq "ExpandString") "the user PATH lost its expandable type"

    # The documented one-liner: `irm | iex` with the prerelease chosen by environment.
    $script:urls.Clear()
    Remove-Item -LiteralPath $installed
    $env:TERRA_PRERELEASE = "1"
    Get-Content -Raw -LiteralPath $installer | Invoke-Expression | Out-Null
    Remove-Item Env:\TERRA_PRERELEASE
    Assert (Test-Path -LiteralPath $installed -PathType Leaf) "the iex install did not place terra.exe"
    Assert ($script:urls -match "/releases/download/v1\.3\.0-rc\.1/") "TERRA_PRERELEASE did not select the prerelease"
    Assert (-not (Test-Path variable:repo)) "the installer left its variables in the caller's session"

    # A checksum mismatch installs nothing.
    Set-Content -LiteralPath (Join-Path $release "SHA256SUMS") -Value ($sums -replace "^[0-9a-f]+", ("0" * 64))
    Remove-Item -LiteralPath $installed
    $refused = $false
    try { & $installer -Version 1.2.3 | Out-Null } catch { $refused = $_.Exception.Message -like "*CHECKSUM MISMATCH*" }
    Assert $refused "a checksum mismatch was not refused"
    Assert (-not (Test-Path -LiteralPath $installed)) "a checksum mismatch still installed terra.exe"
    Write-Host "install.ps1 checks passed"
} finally {
    $env:LOCALAPPDATA = $originalLocalAppData
    if ($null -ne $originalPath) {
        $environmentKey.SetValue("Path", $originalPath, $originalKind)
    } else {
        $environmentKey.DeleteValue("Path", $false)
    }
    $environmentKey.Close()
    Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
}
