$ErrorActionPreference = "Stop"
. "$PSScriptRoot/invoke-native.ps1"

$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) "terra-build-host-$([guid]::NewGuid())"
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar
) + [IO.Path]::DirectorySeparatorChar
$pathComparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
$resolvedTemporaryDirectory = [IO.Path]::GetFullPath($temporaryDirectory)
if (-not $resolvedTemporaryDirectory.StartsWith($temporaryRoot, $pathComparison)) {
    throw "refusing temporary path outside TEMP: $resolvedTemporaryDirectory"
}
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

    if ($IsWindows) {
        $archiveRoot = Join-Path $temporaryDirectory "source-archive"
        $fakeTools = Join-Path $archiveRoot "fake-tools"
        $archiveToolchainDirectory = Join-Path $archiveRoot "scripts/toolchain"
        New-Item -ItemType Directory -Force $fakeTools, $archiveToolchainDirectory,
            (Join-Path $archiveRoot "components/block/wit"),
            (Join-Path $archiveRoot "components/wit/terra/deps"),
            (Join-Path $archiveRoot "components/wit/terra/shared"),
            (Join-Path $archiveRoot "build") | Out-Null
        if (Test-Path -LiteralPath (Join-Path $archiveRoot ".git")) {
            throw "source archive preflight fixture unexpectedly has a Git directory"
        }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "build-host.ps1") -Destination $archiveToolchainDirectory
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "invoke-native.ps1") -Destination $archiveToolchainDirectory
        Set-Content -LiteralPath (Join-Path $archiveRoot "Makefile") -Value @(
            "COMPONENTS := block agent vsock-frontend fs mem boot vmm interrupt-controller",
            "WASM_TOOLS_VERSION := 1.259.0"
        )
        Set-Content -LiteralPath (Join-Path $archiveRoot "components/rust-toolchain.toml") -Value 'channel = "nightly-test"'
        Set-Content -LiteralPath (Join-Path $archiveRoot "components/block/wit/host.wit") -Value "../wit/terra/host.wit"
        New-Item -ItemType SymbolicLink -Path (Join-Path $archiveRoot "components/wit/terra/deps/valid") -Target (Join-Path $archiveRoot "components/wit/terra/shared") | Out-Null
        New-Item -ItemType SymbolicLink -Path (Join-Path $archiveRoot "components/wit/terra/deps/broken") -Target (Join-Path $archiveRoot "missing-wit-target") | Out-Null
        foreach ($asset in @("vmlinux.gz", "rootfs.img.gz", "volume.img.gz", "boot.img.gz")) {
            [IO.File]::WriteAllBytes((Join-Path $archiveRoot "build/$asset"), [byte[]](1))
        }
        Set-Content -LiteralPath (Join-Path $fakeTools "rustup.cmd") -Value @'
@echo off
echo rustup>>"%TERRA_BUILD_HOST_PREFLIGHT_LOG%"
exit /b 91
'@
        Set-Content -LiteralPath (Join-Path $fakeTools "cargo.cmd") -Value @'
@echo off
echo cargo %*>>"%TERRA_BUILD_HOST_PREFLIGHT_LOG%"
exit /b 0
'@
        Set-Content -LiteralPath (Join-Path $fakeTools "wasm-tools.cmd") -Value @'
@echo off
echo wasm-tools %*>>"%TERRA_BUILD_HOST_PREFLIGHT_LOG%"
exit /b 91
'@

        $targetArchitecture = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64" } else { "x86_64" }
        $buildScriptContent = Get-Content -LiteralPath (Join-Path $archiveToolchainDirectory "build-host.ps1") -Raw
        $targetPattern = '"(' + [regex]::Escape($targetArchitecture) + '-pc-windows-[^"]+)"'
        $archiveTargetMatch = [regex]::Match($buildScriptContent, $targetPattern)
        if (-not $archiveTargetMatch.Success) {
            throw "host build script has no target for $targetArchitecture"
        }
        $archiveTarget = $archiveTargetMatch.Groups[1].Value
        $guest = if ($archiveTarget -like "aarch64-*") { "aarch64" } else { "x86_64" }
        $originalPath = $env:PATH
        $originalPreflightLog = [Environment]::GetEnvironmentVariable("TERRA_BUILD_HOST_PREFLIGHT_LOG")
        $env:PATH = "$fakeTools;$originalPath"
        $env:TERRA_BUILD_HOST_PREFLIGHT_LOG = Join-Path $temporaryDirectory "preflight-tools.log"
        try {
            Push-Location $archiveRoot
            try {
                try {
                    & ./scripts/toolchain/build-host.ps1 -Target $archiveTarget
                    throw "host build preflight accepted a WIT placeholder or missing socket probe"
                } catch {
                    $preflightMessage = $_.Exception.Message
                    if ($preflightMessage -notlike "*shared WIT paths must be symbolic links*" -or
                        $preflightMessage -notlike "*missing staged $guest guest build assets: build/socket-probe*") {
                        throw
                    }
                    if ($preflightMessage -notlike "*shared WIT symbolic links must resolve*") {
                        throw "host build preflight accepted a broken WIT link"
                    }
                    $normalizedPreflightMessage = $preflightMessage.Replace('\', '/')
                    if ($normalizedPreflightMessage -notlike "*components/wit/terra/deps/broken*" -or
                        $normalizedPreflightMessage -like "*components/wit/terra/deps/valid*") {
                        throw "host build preflight did not distinguish resolved and broken directory links: $preflightMessage"
                    }
                }
                if (Test-Path -LiteralPath $env:TERRA_BUILD_HOST_PREFLIGHT_LOG) {
                    throw "host build preflight invoked a tool before reporting its failures"
                }

                $prebuiltComponents = Join-Path $archiveRoot "portable-components"
                New-Item -ItemType Directory -Path $prebuiltComponents | Out-Null
                foreach ($component in @("block", "agent", "vsock-frontend", "fs", "mem", "boot", "interrupt-controller")) {
                    $artifactName = "terra_$($component.Replace('-', '_'))_component.wasm"
                    [IO.File]::WriteAllBytes((Join-Path $prebuiltComponents $artifactName), [byte[]](1))
                }
                try {
                    & ./scripts/toolchain/build-host.ps1 -Target $archiveTarget -ComponentsDirectory $prebuiltComponents
                    throw "host build preflight accepted a missing prebuilt component"
                } catch {
                    $preflightMessage = $_.Exception.Message
                    if ($preflightMessage -notlike "*missing prebuilt component artifact:*terra_vmm_component.wasm*" -or
                        $preflightMessage -notlike "*missing staged $guest guest build assets: build/socket-probe*") {
                        throw
                    }
                }
                if (Test-Path -LiteralPath $env:TERRA_BUILD_HOST_PREFLIGHT_LOG) {
                    throw "host build preflight invoked a tool before validating prebuilt components"
                }

                Remove-Item -LiteralPath (Join-Path $archiveRoot "components/wit/terra/deps/broken")
                Remove-Item -LiteralPath (Join-Path $archiveRoot "components/block/wit/host.wit")
                $witTarget = Join-Path $archiveRoot "components/wit/terra/host.wit"
                Set-Content -LiteralPath $witTarget -Value "package terra:host;"
                New-Item -ItemType SymbolicLink -Path (Join-Path $archiveRoot "components/block/wit/host.wit") -Target $witTarget | Out-Null
                [IO.File]::WriteAllBytes((Join-Path $archiveRoot "build/socket-probe"), [byte[]](1))
                [IO.File]::WriteAllBytes((Join-Path $prebuiltComponents "terra_vmm_component.wasm"), [byte[]](1))
                foreach ($file in @("LICENSE", "NOTICE")) {
                    [IO.File]::WriteAllBytes((Join-Path $archiveRoot $file), [byte[]](1))
                }
                $licenseDirectory = Join-Path $archiveRoot "packaging/licenses"
                $manDirectory = Join-Path $archiveRoot "packaging/man"
                $releaseDirectory = Join-Path $archiveRoot "target/$archiveTarget/release"
                New-Item -ItemType Directory -Force $licenseDirectory, $manDirectory, $releaseDirectory | Out-Null
                foreach ($file in @("GPL-2.0.txt", "applevisor-MIT.txt", "uds_windows-MIT.txt", "uds_windows-THIRDPARTYNOTICES.txt")) {
                    [IO.File]::WriteAllBytes((Join-Path $licenseDirectory $file), [byte[]](1))
                }
                $expectedExecutable = Join-Path $releaseDirectory "terra.exe"
                [IO.File]::WriteAllBytes($expectedExecutable, [byte[]](1, 2, 3))
                & ./scripts/toolchain/build-host.ps1 -Target $archiveTarget -ComponentsDirectory $prebuiltComponents
                $toolInvocations = @(Get-Content -LiteralPath $env:TERRA_BUILD_HOST_PREFLIGHT_LOG)
                $cargoInvocations = @($toolInvocations | Where-Object { $_ -like "cargo *" })
                if ($toolInvocations.Count -ne 10 -or $cargoInvocations.Count -ne 10 -or
                    @($cargoInvocations | Where-Object { $_ -like "*precompile-component*" }).Count -ne 8 -or
                    @($toolInvocations | Where-Object { $_ -like "rustup *" -or $_ -like "wasm-tools *" }).Count -ne 0) {
                    throw "prebuilt component build invoked unexpected tools: $($toolInvocations -join '; ')"
                }
                foreach ($component in @("block", "agent", "vsock-frontend", "fs", "mem", "boot", "vmm", "interrupt-controller")) {
                    $artifactName = "terra_$($component.Replace('-', '_'))_component.wasm"
                    $sourceHash = (Get-FileHash -LiteralPath (Join-Path $prebuiltComponents $artifactName) -Algorithm SHA256).Hash
                    $stagedHash = (Get-FileHash -LiteralPath (Join-Path $archiveRoot "components/target/wasm-components/release/$artifactName") -Algorithm SHA256).Hash
                    if ($sourceHash -ne $stagedHash) {
                        throw "prebuilt component was not staged unchanged: $artifactName"
                    }
                }
                $builtExecutable = Join-Path $archiveRoot "dist/terra.exe"
                if (-not (Test-Path -LiteralPath $builtExecutable -PathType Leaf) -or
                    (Get-FileHash -LiteralPath $expectedExecutable -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $builtExecutable -Algorithm SHA256).Hash) {
                    throw "host executable was not copied to dist"
                }

                foreach ($component in @("block", "agent", "vsock-frontend", "fs", "mem", "boot", "vmm", "interrupt-controller")) {
                    $componentTarget = if ($component -eq "agent") { "wasm32-wasip3" } else { "wasm32-unknown-unknown" }
                    $componentArtifactDirectory = Join-Path $archiveRoot "components/target/$componentTarget/release"
                    New-Item -ItemType Directory -Force $componentArtifactDirectory | Out-Null
                    $artifactName = "terra_$($component.Replace('-', '_'))_component.wasm"
                    [IO.File]::WriteAllBytes((Join-Path $componentArtifactDirectory $artifactName), [byte[]](1))
                }
                Set-Content -LiteralPath (Join-Path $fakeTools "rustup.cmd") -Value @'
@echo off
echo rustup %*>>"%TERRA_BUILD_HOST_PREFLIGHT_LOG%"
exit /b 0
'@
                Set-Content -LiteralPath (Join-Path $fakeTools "wasm-tools.cmd") -Value @'
@echo off
echo wasm-tools %*>>"%TERRA_BUILD_HOST_PREFLIGHT_LOG%"
exit /b 0
'@
                Clear-Content -LiteralPath $env:TERRA_BUILD_HOST_PREFLIGHT_LOG
                & ./scripts/toolchain/build-host.ps1 -Target $archiveTarget
                $toolInvocations = @(Get-Content -LiteralPath $env:TERRA_BUILD_HOST_PREFLIGHT_LOG)
                $cargoInvocations = @($toolInvocations | Where-Object { $_ -like "cargo *" })
                $componentCargoInvocations = @($cargoInvocations | Where-Object { $_ -like "*--manifest-path components/Cargo.toml*" })
                $nativeCargoInvocations = @($cargoInvocations | Where-Object {
                    $_ -notlike "*--manifest-path components/Cargo.toml*" -and $_ -notlike "* install wasm-tools *"
                })
                if ($componentCargoInvocations.Count -ne 8 -or
                    @($componentCargoInvocations | Where-Object { $_ -notlike "*--target-dir components/target*" }).Count -ne 0) {
                    throw "component builds did not use their fixed Cargo target directory: $($componentCargoInvocations -join '; ')"
                }
                if ($nativeCargoInvocations.Count -ne 10 -or
                    @($nativeCargoInvocations | Where-Object { $_ -notlike "*--target-dir target*" }).Count -ne 0) {
                    throw "native builds did not use their fixed Cargo target directory: $($nativeCargoInvocations -join '; ')"
                }
            } finally {
                Pop-Location
            }
        } finally {
            $env:PATH = $originalPath
            if ($null -eq $originalPreflightLog) {
                Remove-Item Env:TERRA_BUILD_HOST_PREFLIGHT_LOG -ErrorAction SilentlyContinue
            } else {
                $env:TERRA_BUILD_HOST_PREFLIGHT_LOG = $originalPreflightLog
            }
        }
    }

    if ($IsWindows) {
        $fakeRustupDirectory = Join-Path $temporaryDirectory "actual-checkout-fake-rustup"
        New-Item -ItemType Directory -Path $fakeRustupDirectory | Out-Null
        $actualCheckoutLog = Join-Path $temporaryDirectory "actual-checkout-preflight.log"
        Set-Content -LiteralPath (Join-Path $fakeRustupDirectory "rustup.cmd") -Value @'
@echo off
echo rustup %*>>"%TERRA_BUILD_HOST_ACTUAL_LOG%"
exit /b 93
'@
        $actualTarget = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
        $originalPath = $env:PATH
        $originalActualLog = [Environment]::GetEnvironmentVariable("TERRA_BUILD_HOST_ACTUAL_LOG")
        $env:PATH = "$fakeRustupDirectory;$originalPath"
        $env:TERRA_BUILD_HOST_ACTUAL_LOG = $actualCheckoutLog
        try {
            try {
                & (Join-Path $PSScriptRoot "build-host.ps1") -Target $actualTarget
                throw "actual checkout preflight unexpectedly passed the fake Rustup command"
            } catch {
                if ($_.Exception.Message -notlike "native command failed (93): rustup target add*") {
                    throw
                }
            }
            if ((Get-Content -LiteralPath $actualCheckoutLog) -notlike "rustup target add $actualTarget") {
                throw "actual checkout preflight did not reach fake Rustup"
            }
        } finally {
            $env:PATH = $originalPath
            if ($null -eq $originalActualLog) {
                Remove-Item Env:TERRA_BUILD_HOST_ACTUAL_LOG -ErrorAction SilentlyContinue
            } else {
                $env:TERRA_BUILD_HOST_ACTUAL_LOG = $originalActualLog
            }
        }
    }
} finally {
    Remove-Item Env:TERRA_BUILD_HOST_ARGUMENT_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:TERRA_BUILD_HOST_EXIT_CODE -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $temporaryDirectory) {
        $cleanupPath = (Resolve-Path -LiteralPath $temporaryDirectory).Path
        if (-not $cleanupPath.StartsWith($temporaryRoot, $pathComparison) -or
            $cleanupPath -ne $resolvedTemporaryDirectory) {
            throw "refusing temporary cleanup outside TEMP: $cleanupPath"
        }
        Remove-Item -LiteralPath $cleanupPath -Recurse -Force
    }
}

exit 0
