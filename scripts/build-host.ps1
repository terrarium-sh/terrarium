param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")]
    [string]$Target
)

$ErrorActionPreference = "Stop"
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

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Command,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "native command failed ($LASTEXITCODE): $Command $($Arguments -join ' ')"
    }
}

if ($env:PROCESSOR_ARCHITECTURE -ne $hostArchitecture) {
    throw "build target $Target requires a native $hostArchitecture host, found $env:PROCESSOR_ARCHITECTURE"
}

$guestAssets = "build/vmlinux.gz", "build/rootfs.img.gz", "build/volume.img.gz", "build/boot.img.gz", "build/vmlinux.gz.sha256", "build/boot.img.gz.sha256"
foreach ($asset in $guestAssets) {
    if (-not (Test-Path -LiteralPath $asset -PathType Leaf) -or (Get-Item -LiteralPath $asset).Length -eq 0) {
        throw "missing staged $guest guest asset: $asset"
    }
}
foreach ($asset in "vmlinux.gz", "boot.img.gz") {
    $expected = (Get-Content -LiteralPath "build/$asset.sha256" -Raw).Trim()
    if ($expected -notmatch '^[0-9a-f]{64}$' -or $expected -ne (Get-FileHash -LiteralPath "build/$asset" -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw "invalid staged guest asset hash: build/$asset"
    }
}

Invoke-Native rustup target add $Target
Invoke-Native rustup toolchain install $componentToolchain --profile minimal --target wasm32-wasip3
Invoke-Native cargo "+$componentToolchain" install wasm-tools --version 1.248.0 --locked

foreach ($component in $components) {
    Invoke-Native cargo "+$componentToolchain" build --locked --release --target wasm32-wasip3 --manifest-path "components/$component/Cargo.toml"
    Invoke-Native wasm-tools validate --features cm-async "components/$component/target/wasm32-wasip3/release/terra_$($component)_component.wasm"
    $precompileArguments = @("run", "--locked", "--release", "--target", $Target, "-p", "terra-runtime", "--features", "compiler", "--example", "precompile-component", "--", "components/$component/target/wasm32-wasip3/release/terra_$($component)_component.wasm", "build/terra-$component-component.cwasm")
    if ($component -eq "policy") {
        $precompileArguments += "--policy"
    }
    Invoke-Native cargo @precompileArguments
}

Invoke-Native cargo build --locked --release --target $Target --package terra
Invoke-Native cargo run --locked --target $Target --package terra --example gen-docs
New-Item -ItemType Directory -Force dist | Out-Null
New-Item -ItemType Directory -Force dist/LICENSES | Out-Null
Copy-Item "target/$Target/release/terra.exe" dist/terra.exe
Copy-Item LICENSE, NOTICE dist
Copy-Item packaging/licenses/GPL-2.0.txt, packaging/licenses/applevisor-MIT.txt, packaging/licenses/uds_windows-MIT.txt, packaging/licenses/uds_windows-THIRDPARTYNOTICES.txt dist/LICENSES
Copy-Item -Recurse -Force packaging/man, packaging/completions dist
