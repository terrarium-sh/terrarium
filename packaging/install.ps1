#Requires -Version 5.1
# Installs terra.exe from beside this script, without the network.
$ErrorActionPreference = "Stop"

$binary = Join-Path $PSScriptRoot "terra.exe"
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "terrarium: $PSScriptRoot does not contain terra.exe - run this script from the extracted release archive"
}

$bin = Join-Path $env:LOCALAPPDATA "Programs\terra"
$target = Join-Path $bin "terra.exe"
if (Test-Path -LiteralPath $target -PathType Container) {
    throw "terrarium: $target exists but is not a regular file - move it aside first"
}
New-Item -ItemType Directory -Force -Path $bin | Out-Null
Copy-Item -LiteralPath $binary -Destination $target -Force

# The raw registry value: GetEnvironmentVariable expands it, and writing that back would
# freeze entries such as %USERPROFILE%\bin into fixed paths.
$environment = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $true)
$entries = @($environment.GetValue("Path", "", "DoNotExpandEnvironmentNames") -split ';' | Where-Object { $_ })
$expanded = @($entries | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) })
if ($expanded -notcontains $bin) {
    $environment.SetValue("Path", (($entries + $bin) -join ';'), "ExpandString")
    # A .NET user-variable change broadcasts the update, so new terminals see the PATH.
    [Environment]::SetEnvironmentVariable("TERRA_INSTALL_PATH_UPDATE", "1", "User")
    [Environment]::SetEnvironmentVariable("TERRA_INSTALL_PATH_UPDATE", $null, "User")
    Write-Host "added $bin to the user PATH - open a new terminal to use terra"
}
$environment.Close()
$installedVersion = try { (& $target --version 2>$null) -join " " } catch { $null }
if (-not $installedVersion) { $installedVersion = "terra" }
Write-Host "installed $installedVersion at $target"
