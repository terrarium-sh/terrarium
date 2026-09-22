param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")]
    [string]$Target
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot/invoke-native.ps1"
$componentLine = Select-String -LiteralPath Makefile -Pattern '^COMPONENTS\s*:=\s*(.+)$' | Select-Object -First 1
if ($null -eq $componentLine) {
    throw "could not find COMPONENTS in Makefile"
}
$components = $componentLine.Matches[0].Groups[1].Value -split '\s+'
$toolchainLine = Select-String -LiteralPath components/rust-toolchain.toml -Pattern '^channel\s*=\s*"([^"]+)"$' | Select-Object -First 1
if ($null -eq $toolchainLine) {
    throw "could not find component toolchain"
}
$componentToolchain = $toolchainLine.Matches[0].Groups[1].Value
$guest = if ($Target -like "aarch64-*") { "aarch64" } else { "x86_64" }
$hostArchitecture = if ($Target -like "aarch64-*") { "ARM64" } else { "AMD64" }

if ($env:PROCESSOR_ARCHITECTURE -ne $hostArchitecture) {
    throw "build target $Target requires a native $hostArchitecture host, found $env:PROCESSOR_ARCHITECTURE"
}

$guestAssets = "build/vmlinux.gz", "build/rootfs.img.gz", "build/volume.img.gz", "build/boot.img.gz"
foreach ($asset in $guestAssets) {
    if (-not (Test-Path -LiteralPath $asset -PathType Leaf) -or (Get-Item -LiteralPath $asset).Length -eq 0) {
        throw "missing staged $guest guest asset: $asset"
    }
}
Invoke-Native -Command rustup -Arguments @("target", "add", $Target)
Invoke-Native -Command rustup -Arguments @("toolchain", "install", $componentToolchain, "--profile", "minimal", "--target", "wasm32-unknown-unknown")
Invoke-Native -Command cargo -Arguments @("+$componentToolchain", "install", "wasm-tools", "--version", "1.248.0", "--locked")

foreach ($component in $components) {
    $artifactStem = $component.Replace("-", "_")
    Invoke-Native -Command cargo -Arguments @("+$componentToolchain", "build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "--manifest-path", "components/Cargo.toml", "--package", "terra-$component-component")
    New-Item -ItemType Directory -Force components/target/wasm-components/release | Out-Null
    Invoke-Native -Command wasm-tools -Arguments @("component", "new", "components/target/wasm32-unknown-unknown/release/terra_$($artifactStem)_component.wasm", "-o", "components/target/wasm-components/release/terra_$($artifactStem)_component.wasm")
    Invoke-Native -Command wasm-tools -Arguments @("validate", "--features", "cm-async", "components/target/wasm-components/release/terra_$($artifactStem)_component.wasm")
    $precompileArguments = @("run", "--locked", "--release", "--target", $Target, "-p", "terra-runtime", "--features", "compiler", "--example", "precompile-component", "--", "components/target/wasm-components/release/terra_$($artifactStem)_component.wasm", "build/terra-$component-component.cwasm")
    if ($component -eq "policy") {
        $precompileArguments += "--policy"
    }
    Invoke-Native -Command cargo -Arguments $precompileArguments
}

Invoke-Native -Command cargo -Arguments @("build", "--locked", "--release", "--target", $Target, "--package", "terra")
Invoke-Native -Command cargo -Arguments @("run", "--locked", "--target", $Target, "--package", "terra", "--example", "gen-docs")
New-Item -ItemType Directory -Force dist | Out-Null
New-Item -ItemType Directory -Force dist/LICENSES | Out-Null
Copy-Item "target/$Target/release/terra.exe" dist/terra.exe
Copy-Item LICENSE, NOTICE dist
Copy-Item packaging/licenses/GPL-2.0.txt, packaging/licenses/applevisor-MIT.txt, packaging/licenses/uds_windows-MIT.txt, packaging/licenses/uds_windows-THIRDPARTYNOTICES.txt dist/LICENSES
Copy-Item -Recurse -Force packaging/man dist
