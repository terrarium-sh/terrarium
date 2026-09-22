$ErrorActionPreference = "Stop"
. "$PSScriptRoot/invoke-native.ps1"

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) "terra-build-host-$([guid]::NewGuid())"
$argumentLog = Join-Path $temporaryDirectory "arguments"
$nativeScript = Join-Path $temporaryDirectory "native.ps1"
$pwsh = Join-Path $PSHOME $(if ($IsWindows) { "pwsh.exe" } else { "pwsh" })

New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
try {
    Set-Content -LiteralPath $nativeScript -NoNewline -Value @'
[IO.File]::WriteAllLines($env:TERRA_BUILD_HOST_ARGUMENT_LOG, [string[]]$args)
exit [int]$env:TERRA_BUILD_HOST_EXIT_CODE
'@
    $env:TERRA_BUILD_HOST_ARGUMENT_LOG = $argumentLog
    $env:TERRA_BUILD_HOST_EXIT_CODE = "0"
    Invoke-Native -Command $pwsh -Arguments @("-NoLogo", "-NoProfile", "-File", $nativeScript, "-o", "path with spaces", "--feature", "value with spaces")
    if (Compare-Object @(Get-Content -LiteralPath $argumentLog) @("-o", "path with spaces", "--feature", "value with spaces")) {
        throw "native arguments changed"
    }

    $env:TERRA_BUILD_HOST_EXIT_CODE = "42"
    try {
        Invoke-Native -Command $pwsh -Arguments @("-NoLogo", "-NoProfile", "-File", $nativeScript)
        throw "native failure was ignored"
    } catch {
        if ($_.Exception.Message -notlike "native command failed (42):*") {
            throw
        }
    }
} finally {
    Remove-Item Env:TERRA_BUILD_HOST_ARGUMENT_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:TERRA_BUILD_HOST_EXIT_CODE -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

exit 0
