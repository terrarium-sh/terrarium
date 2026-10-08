param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")]
    [string]$Target,
    [Parameter()]
    [string]$ComponentsDirectory
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot/invoke-native.ps1"
$componentLine = Select-String -LiteralPath Makefile -Pattern '^COMPONENTS\s*:=\s*(.+)$' | Select-Object -First 1
if ($null -eq $componentLine) {
    throw "could not find COMPONENTS in Makefile"
}
$components = $componentLine.Matches[0].Groups[1].Value -split '\s+'
$componentToolchain = $null
$wasmToolsVersion = $null
if (-not $PSBoundParameters.ContainsKey("ComponentsDirectory")) {
    $toolchainLine = Select-String -LiteralPath components/rust-toolchain.toml -Pattern '^channel\s*=\s*"([^"]+)"$' | Select-Object -First 1
    if ($null -eq $toolchainLine) {
        throw "could not find component toolchain"
    }
    $componentToolchain = $toolchainLine.Matches[0].Groups[1].Value
    $wasmToolsLine = Select-String -LiteralPath Makefile -Pattern '^WASM_TOOLS_VERSION := (.+)$' | Select-Object -First 1
    if ($null -eq $wasmToolsLine) {
        throw "could not find WASM_TOOLS_VERSION in Makefile"
    }
    $wasmToolsVersion = $wasmToolsLine.Matches[0].Groups[1].Value
}
$guest = if ($Target -like "aarch64-*") { "aarch64" } else { "x86_64" }
$hostArchitecture = if ($Target -like "aarch64-*") { "ARM64" } else { "AMD64" }

$preflightFailures = @()
if ($env:PROCESSOR_ARCHITECTURE -ne $hostArchitecture) {
    $preflightFailures += "build target $Target requires a native $hostArchitecture host, found $env:PROCESSOR_ARCHITECTURE"
}

$witSymlinkPaths = @("components/block/wit/host.wit")
foreach ($directory in @("components/vmm/wit", "components/interrupt-controller/wit")) {
    $witSymlinkPaths += @(Get-ChildItem -LiteralPath $directory -Filter "*.wit" -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        [IO.Path]::GetRelativePath((Get-Location).Path, $_.FullName)
    })
}
$dependencyDirectories = @("components/wit/terra/deps") + @(
    Get-ChildItem -Path "components/*/wit/deps" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object FullName
)
foreach ($directory in $dependencyDirectories) {
    $witSymlinkPaths += @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        [IO.Path]::GetRelativePath((Get-Location).Path, $_.FullName)
    })
}
$unmaterializedWitSymlinks = @($witSymlinkPaths | Where-Object {
    $item = Get-Item -LiteralPath $_ -Force -ErrorAction SilentlyContinue
    $null -eq $item -or $item.LinkType -ne "SymbolicLink"
})
if ($unmaterializedWitSymlinks.Count -gt 0) {
    $examples = $unmaterializedWitSymlinks | Select-Object -First 3
    $preflightFailures += "shared WIT paths must be symbolic links ($($examples -join ', ')); enable Windows symlink creation and restore or extract the links correctly"
}
$unresolvedWitSymlinks = @($witSymlinkPaths | Where-Object {
    $item = Get-Item -LiteralPath $_ -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item.LinkType -ne "SymbolicLink") {
        return $false
    }
    try {
        $targetPath = [string]$item.Target
        if (-not [IO.Path]::IsPathRooted($targetPath)) {
            $targetPath = Join-Path ([IO.Path]::GetDirectoryName($item.FullName)) $targetPath
        }
        $resolvedTarget = Resolve-Path -LiteralPath $targetPath -ErrorAction Stop
        -not (Test-Path -LiteralPath $resolvedTarget.ProviderPath)
    } catch {
        $true
    }
})
if ($unresolvedWitSymlinks.Count -gt 0) {
    $examples = $unresolvedWitSymlinks | Select-Object -First 3
    $preflightFailures += "shared WIT symbolic links must resolve ($($examples -join ', ')); restore the linked WIT files and directories"
}

$guestAssets = "build/vmlinux.gz", "build/rootfs.img.gz", "build/volume.img.gz", "build/boot.img.gz", "build/socket-probe"
$missingGuestAssets = @($guestAssets | Where-Object {
    -not (Test-Path -LiteralPath $_ -PathType Leaf) -or (Get-Item -LiteralPath $_).Length -eq 0
})
if ($missingGuestAssets.Count -gt 0) {
    $preflightFailures += "missing staged $guest guest build assets: $($missingGuestAssets -join ', '); copy all five matching files from the Linux guest-assets build into build/"
}

$prebuiltComponentPaths = @{}
if ($PSBoundParameters.ContainsKey("ComponentsDirectory")) {
    if (-not (Test-Path -LiteralPath $ComponentsDirectory -PathType Container)) {
        $preflightFailures += "prebuilt component directory not found: $ComponentsDirectory"
    } else {
        $resolvedComponentsDirectory = (Resolve-Path -LiteralPath $ComponentsDirectory).ProviderPath
        foreach ($component in $components) {
            $artifactName = "terra_$($component.Replace('-', '_'))_component.wasm"
            $artifactPath = Join-Path $resolvedComponentsDirectory $artifactName
            if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf) -or (Get-Item -LiteralPath $artifactPath).Length -eq 0) {
                $preflightFailures += "missing prebuilt component artifact: $artifactPath"
            } else {
                $prebuiltComponentPaths[$component] = $artifactPath
            }
        }
    }
}

if ($preflightFailures.Count -gt 0) {
    throw "Windows host build preflight failed:`n - $($preflightFailures -join "`n - ")"
}

$componentOutputDirectory = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path "components/target/wasm-components/release"))
if ($PSBoundParameters.ContainsKey("ComponentsDirectory")) {
    New-Item -ItemType Directory -Force $componentOutputDirectory | Out-Null
    foreach ($component in $components) {
        $destination = Join-Path $componentOutputDirectory "terra_$($component.Replace('-', '_'))_component.wasm"
        if (-not [string]::Equals($prebuiltComponentPaths[$component], $destination, [StringComparison]::OrdinalIgnoreCase)) {
            Copy-Item -LiteralPath $prebuiltComponentPaths[$component] -Destination $destination -Force
        }
    }
} else {
    Invoke-Native -Command rustup -Arguments @("target", "add", $Target)
    Invoke-Native -Command rustup -Arguments @("toolchain", "install", $componentToolchain, "--profile", "minimal", "--target", "wasm32-unknown-unknown", "--target", "wasm32-wasip3")
    Invoke-Native -Command cargo -Arguments @("+$componentToolchain", "install", "wasm-tools", "--version", $wasmToolsVersion, "--locked")
}

foreach ($component in $components) {
    $artifactStem = $component.Replace("-", "_")
    $wrappedArtifact = Join-Path $componentOutputDirectory "terra_$($artifactStem)_component.wasm"
    if (-not $PSBoundParameters.ContainsKey("ComponentsDirectory")) {
        $componentTarget = if ($component -eq "agent") { "wasm32-wasip3" } else { "wasm32-unknown-unknown" }
        Invoke-Native -Command cargo -Arguments @("+$componentToolchain", "build", "--locked", "--release", "--target", $componentTarget, "--target-dir", "components/target", "--manifest-path", "components/Cargo.toml", "--package", "terra-$component-component")
        New-Item -ItemType Directory -Force $componentOutputDirectory | Out-Null
        $componentArtifact = "components/target/$componentTarget/release/terra_$($artifactStem)_component.wasm"
        if ($component -eq "agent") {
            Copy-Item -Force $componentArtifact $wrappedArtifact
        } else {
            Invoke-Native -Command wasm-tools -Arguments @("component", "new", $componentArtifact, "-o", $wrappedArtifact)
        }
        Invoke-Native -Command wasm-tools -Arguments @("validate", "--features", "cm-async", $wrappedArtifact)
    }
    $precompileArguments = @("run", "--locked", "--release", "--target", $Target, "--target-dir", "target", "-p", "terra-runtime", "--features", "compiler", "--example", "precompile-component", "--", $wrappedArtifact, "build/terra-$component-component.cwasm")
    if ($component -eq "policy") {
        $precompileArguments += "--policy"
    }
    Invoke-Native -Command cargo -Arguments $precompileArguments
}

Invoke-Native -Command cargo -Arguments @("build", "--locked", "--release", "--target", $Target, "--target-dir", "target", "--package", "terra")
Invoke-Native -Command cargo -Arguments @("run", "--locked", "--target", $Target, "--target-dir", "target", "--package", "terra", "--example", "gen-docs")
New-Item -ItemType Directory -Force dist | Out-Null
New-Item -ItemType Directory -Force dist/LICENSES | Out-Null
Copy-Item "target/$Target/release/terra.exe" dist/terra.exe
Copy-Item LICENSE, NOTICE dist
Copy-Item packaging/licenses/GPL-2.0.txt, packaging/licenses/applevisor-MIT.txt, packaging/licenses/uds_windows-MIT.txt, packaging/licenses/uds_windows-THIRDPARTYNOTICES.txt dist/LICENSES
Copy-Item -Recurse -Force packaging/man dist
