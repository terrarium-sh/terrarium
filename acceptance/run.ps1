#Requires -Version 5.1
# Checks that terra works on this machine: boots boxes from the acceptance
# recipes in a private home and drives every feature through the terra CLI.
# Needs only terra, curl and tar. Run alone, it fetches the suite of the release
# terra reports, verified against its SHA256SUMS, and runs that release's copy.
param(
    [string]$Terra = "terra",
    [string]$Suite
)

$ErrorActionPreference = "Stop"
$repo = "terrarium-sh/terrarium"
$boxes = "probe", "isolated", "offline", "bad-bake"

if (Test-Path -LiteralPath $Terra -PathType Leaf) {
    $Terra = (Resolve-Path -LiteralPath $Terra).Path
} else {
    $Terra = (Get-Command $Terra -CommandType Application | Select-Object -First 1).Source
}
if (-not $Suite -and $PSScriptRoot -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot "recipes/probe.yaml"))) {
    $Suite = $PSScriptRoot
}

# A release or git build reports <version>+<hash>; a build outside a git checkout
# reports only the crate version, which names no release.
function Get-TerraVersion {
    $version = ((& $Terra --version) -split " ")[1]
    if ($version -match "\+") { $version -replace "\+.*", "" } else { "dev" }
}

# Get-FileHash comes from a module that Windows PowerShell cannot load when it inherits
# PowerShell 7's PSModulePath, so hash with .NET directly.
function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)) -replace "-", ""
    } finally {
        $stream.Dispose()
    }
}

# --- Without a suite: hand over to the runner of the release terra reports,
# --- so runner and recipes always match.

if (-not $Suite) {
    $version = Get-TerraVersion
    if ($version -eq "dev") { throw "terra is a development build; pass -Suite <checkout>/acceptance" }
    $download = Join-Path ([IO.Path]::GetTempPath()) ("terra-acceptance-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path (Join-Path $download "suite") | Out-Null
    try {
        $base = "https://github.com/$repo/releases/download/v$version"
        $curl = if ($env:OS -eq "Windows_NT") { "curl.exe" } else { "curl" }
        $sums = Join-Path $download "SHA256SUMS"
        $archive = Join-Path $download "suite.tar.gz"
        & $curl -fsSL --proto "=https" --tlsv1.2 "$base/SHA256SUMS" -o $sums
        if ($LASTEXITCODE -ne 0) { throw "could not download SHA256SUMS" }
        & $curl -fsSL --proto "=https" --tlsv1.2 "$base/terra-acceptance.tar.gz" -o $archive
        if ($LASTEXITCODE -ne 0) { throw "could not download terra-acceptance.tar.gz" }
        $expected = $null
        foreach ($line in Get-Content -LiteralPath $sums) {
            $fields = $line -split '\s+'
            if ($fields[-1] -eq "terra-acceptance.tar.gz") { $expected = $fields[0] }
        }
        if (-not $expected -or (Get-Sha256 $archive) -ne $expected) {
            throw "terra-acceptance.tar.gz does not match the v$version SHA256SUMS - not running it"
        }
        tar -xzf $archive -C (Join-Path $download "suite")
        if ($LASTEXITCODE -ne 0) { throw "could not extract terra-acceptance.tar.gz" }
        & (Join-Path $download "suite/run.ps1") -Terra $Terra
        $status = $LASTEXITCODE
    } finally {
        Remove-Item -Recurse -Force -LiteralPath $download
    }
    exit $status
}

# --- A private home and project, removed again unless a step fails.

$work = Join-Path ([IO.Path]::GetTempPath()) ("terra-acceptance-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$project = Join-Path $work "project"
$log = Join-Path $work "step.log"
$step = $null
$stepWatch = $null
$results = New-Object System.Collections.Generic.List[object]
$suiteWatch = [Diagnostics.Stopwatch]::StartNew()
New-Item -ItemType Directory -Path (Join-Path $work "home") | Out-Null
$savedHome = $env:HOME
$savedProfile = $env:USERPROFILE
$env:HOME = Join-Path $work "home"
$env:USERPROFILE = $env:HOME

# --- Step helpers. Every command's output goes to the step log, which is
# --- printed when the step fails. Terra arguments are explicit arrays so
# --- PowerShell never takes `--` or a flag for its own.

function Start-Step($Name) {
    $script:step = $Name
    $script:stepWatch = [Diagnostics.Stopwatch]::StartNew()
    Write-Host ("{0,-58} " -f $Name) -NoNewline
    Set-Content -LiteralPath $log -Value $null
}

function Complete-Step {
    Write-Host "ok"
    Add-StepResult "ok"
}

function Add-StepResult($Result) {
    $results.Add([pscustomobject]@{ Result = $Result; Seconds = [int][math]::Floor($stepWatch.Elapsed.TotalSeconds); Name = $step })
    $script:stepWatch = $null
}

function Format-Duration([int]$Seconds) {
    if ($Seconds -ge 60) { "{0}m{1:d2}s" -f [math]::Floor($Seconds / 60), ($Seconds % 60) } else { "${Seconds}s" }
}

function Write-Summary {
    Write-Host ""
    foreach ($result in $results) {
        $status = "  {0,-4}" -f $result.Result
        if ($env:NO_COLOR) {
            Write-Host $status -NoNewline
        } else {
            Write-Host $status -NoNewline -ForegroundColor $(if ($result.Result -eq "ok") { "Green" } else { "Red" })
        }
        Write-Host (" {0,6}  {1}" -f (Format-Duration $result.Seconds), $result.Name)
    }
    $failed = @($results | Where-Object { $_.Result -ne "ok" }).Count
    Write-Host ("  {0} passed, {1} failed in {2}" -f ($results.Count - $failed), $failed, (Format-Duration ([math]::Floor($suiteWatch.Elapsed.TotalSeconds))))
}

function Write-Note($Text) {
    Add-Content -LiteralPath $log -Value $Text
}

function Get-TerraOutput([string[]]$Arguments, [int]$ExitCode = 0, [switch]$Fails) {
    $ErrorActionPreference = "Continue"
    $output = (& $Terra @Arguments 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $status = $LASTEXITCODE
    Write-Note $output
    if ($Fails) {
        if ($status -eq 0) { throw "terra $($Arguments -join ' ') succeeded" }
    } elseif ($status -ne $ExitCode) {
        throw "terra $($Arguments -join ' ') exited $status, expected $ExitCode"
    }
    $output
}

function Invoke-Terra([string[]]$Arguments, [int]$ExitCode = 0) {
    Get-TerraOutput $Arguments -ExitCode $ExitCode | Out-Null
}

function Invoke-GuestCheck([string]$Script, [string[]]$Flags = @()) {
    Invoke-Terra (@("probe", "exec", "--no-tty") + $Flags + @("--", "sh", "-e", "/suite/guest/$Script"))
}

function Assert-Equal($Actual, $Expected) {
    if ("$Actual".Trim() -ne $Expected) {
        Write-Note "expected '$Expected', got '$Actual'"
        throw "unexpected output"
    }
}

function Assert-Contains($Text, $Needle) {
    if (-not "$Text".Contains($Needle)) {
        Write-Note "expected output containing '$Needle'"
        throw "unexpected output"
    }
}

function Assert-Listed($Name, $State) {
    Assert-Contains (Get-TerraOutput @("ls", "--state", $State, "--quiet")) $Name
}

function Read-Text($Path) {
    [IO.File]::ReadAllText((Join-Path $project $Path))
}

function Write-Text($Path, $Text) {
    [IO.File]::WriteAllText((Join-Path $project $Path), $Text)
}

function Get-FileSha256($Path) {
    Get-Sha256 (Join-Path $project $Path)
}

function Read-Http($Port, $Attempts) {
    for ($attempt = 1; ; $attempt++) {
        try {
            return (New-Object Net.WebClient).DownloadString("http://127.0.0.1:$Port/")
        } catch {
            if ($attempt -ge $Attempts) { Write-Note "$_"; throw }
            Start-Sleep -Seconds 1
        }
    }
}

# --- Steps.

$passed = $false
Push-Location
try {
    Start-Step "terra runs"
    $version = Get-TerraVersion
    Complete-Step

    New-Item -ItemType Directory -Path $project, (Join-Path $project "work"), (Join-Path $project "readonly") | Out-Null
    Copy-Item -Recurse -LiteralPath $Suite -Destination (Join-Path $project "suite")
    Set-Location -LiteralPath $project
    Write-Text "work/host" "HOST_SEED"
    Write-Text "work/host-update" "INITIAL"
    Write-Text "readonly/seed" "READ_ONLY"
    $allowedPort = Get-Random -Minimum 30000 -Maximum 50000
    $deniedPort = $allowedPort + 1
    foreach ($recipe in $boxes) {
        $text = (Read-Text "suite/recipes/$recipe.yaml") `
            -replace "\{allowed_port\}", $allowedPort `
            -replace "\{denied_port\}", $deniedPort
        Write-Text "$recipe.yaml" $text
    }

    Start-Step "setup bakes the recipe, and again is a no-op"
    Assert-Contains (Get-TerraOutput @("./probe.yaml", "setup")) "BAKE_OK"
    Invoke-Terra @("probe", "setup")
    Assert-Contains (Get-TerraOutput @("probe", "show", "--json", "--with-env-values")) "recipe-value"
    Complete-Step

    Start-Step "a detached box runs its hooks, daemons and workload"
    Invoke-Terra @("probe", "-d")
    Invoke-GuestCheck "exercise-ready.sh"
    Assert-Equal (Read-Text "work/ready") "recipe-value"
    Assert-Listed "probe" "running"
    Complete-Step

    Start-Step "exec: user, root, hostname, env, workdir, status, streams"
    Assert-Equal (Get-TerraOutput @("probe", "exec", "--no-tty", "--", "id", "-u")) "1000"
    Assert-Equal (Get-TerraOutput @("probe", "exec", "--no-tty", "--root", "--", "id", "-u")) "0"
    Assert-Equal (Get-TerraOutput @("probe", "exec", "--no-tty", "--", "hostname")) "probe"
    Invoke-Terra @("probe", "exec", "--no-tty", "--env", "PROBE=exec-value", "--workdir", "/tmp", "--",
        "sh", "-ec", 'test $PROBE = exec-value; test $(pwd) = /tmp')
    Invoke-Terra @("probe", "exec", "--no-tty", "--", "sh", "-c", "exit 7") -ExitCode 7
    $ErrorActionPreference = "Continue"
    $stdout = (& $Terra probe exec --no-tty "--" sh -c 'echo out; echo err >&2' 2>$null) -join "`n"
    $ErrorActionPreference = "Stop"
    Assert-Equal $stdout "out"
    Assert-Contains (Get-TerraOutput @("probe", "exec", "--no-tty", "--", "sh", "-c", 'echo out; echo err >&2')) "err"
    Assert-Contains (Get-TerraOutput @("probe", "exec", "--tty", "--",
        "sh", "-c", 'test -t 0; test -t 1; echo TTY_OK')) "TTY_OK"
    Complete-Step

    Start-Step "the guest runs containers: namespaces, cgroups, overlayfs"
    Invoke-Terra @("probe", "exec", "--no-tty", "--root", "--", "sh", "-c", "echo ROOT_WRITE > /etc/workload-probe")
    Invoke-GuestCheck "namespaces.sh"
    Invoke-GuestCheck "overlay.sh" @("--root")
    Complete-Step

    Start-Step "the guest gets no hardware virtualization"
    Invoke-GuestCheck "no-virtualization.sh" @("--root")
    Complete-Step

    Start-Step "shares: read-write, read-only, links"
    Invoke-GuestCheck "shares.sh"
    Assert-Equal (Read-Text "work/host") "linked"
    Assert-Equal (Read-Text "work/after") "renamed"
    Assert-Equal ((Get-ChildItem -Force -LiteralPath (Join-Path $project "readonly")).Name -join " ") "seed"
    Complete-Step

    Start-Step "shares: host edits reach the guest as file events"
    Invoke-GuestCheck "watcher-ready.sh" @("--root")
    Write-Text "work/host-update" "LIVE_UPDATE"
    Write-Text "work/host-created" "CREATED"
    Invoke-GuestCheck "file-events-created.sh" @("--root")
    Remove-Item -LiteralPath (Join-Path $project "work/host-created")
    Invoke-GuestCheck "file-events-deleted.sh" @("--root")
    Invoke-GuestCheck "shares-persisted.sh"
    Complete-Step

    Start-Step "sync copies files both ways and mirrors deletions"
    New-Item -ItemType Directory -Path (Join-Path $project "sync-source/nested") | Out-Null
    $payload = New-Object byte[] 65536
    (New-Object Random).NextBytes($payload)
    [IO.File]::WriteAllBytes((Join-Path $project "sync-source/nested/binary"), $payload)
    Write-Text "sync-source/value" "first"
    Invoke-Terra @("probe", "sync", "./sync-source/", ":/tmp/synced/")
    Invoke-Terra @("probe", "sync", ":/tmp/synced/", "./sync-back/")
    Assert-Equal (Get-FileSha256 "sync-back/nested/binary") (Get-FileSha256 "sync-source/nested/binary")
    Assert-Equal (Read-Text "sync-back/value") "first"
    Invoke-Terra @("probe", "exec", "--no-tty", "--", "sh", "-c", "printf extra > /tmp/synced/extra")
    Invoke-Terra @("probe", "sync", "--delete", "--checksum", "./sync-source/", ":/tmp/synced/")
    Invoke-Terra @("probe", "exec", "--no-tty", "--", "sh", "-c", "test ! -e /tmp/synced/extra")
    Complete-Step

    Start-Step "network: published ports, allowlist, local DNS, denial"
    Assert-Equal (Read-Http $allowedPort 60) "GUEST_NETWORK"
    Assert-Equal (Read-Http $deniedPort 5) "DENIED_ROUTE"
    Assert-Contains (Get-TerraOutput @("probe", "exec", "--no-tty",
        "--env", "ALLOWED_PORT=$allowedPort", "--env", "DENIED_PORT=$deniedPort",
        "--", "sh", "-e", "/suite/guest/network.sh")) "NETWORK_OK"
    Complete-Step

    Start-Step "network: a box without an allowlist reaches nothing"
    Invoke-Terra @("./isolated.yaml", "setup")
    Assert-Contains (Get-TerraOutput @("isolated", "--foreground")) "ISOLATED_OK"
    Complete-Step

    Start-Step "network: a box with networking off keeps loopback"
    Invoke-Terra @("./offline.yaml", "setup")
    Invoke-Terra @("offline", "-d")
    Assert-Contains (Get-TerraOutput @("offline", "exec", "--no-tty", "--",
        "sh", "-e", "/suite/guest/local-only.sh")) "LOCAL_ONLY_OK"
    Invoke-Terra @("offline", "stop")
    Assert-Listed "offline" "stopped"
    Complete-Step

    Start-Step "stop runs pre_stop and keeps the box"
    Invoke-Terra @("probe", "stop")
    Assert-Listed "probe" "stopped"
    Assert-Equal ((Read-Text "work/hooks") -replace "`r", "" -replace "`n", " ") "start stop"
    Complete-Step

    Start-Step "storage: inspect, export, persist, import"
    $storage = Get-TerraOutput @("probe", "storage", "show", "--json")
    Assert-Contains $storage "rootfs.img"
    Assert-Contains $storage "vol-data.img"
    $exported = Join-Path $work "storage.terra"
    Invoke-Terra @("probe", "storage", "export", $exported)
    if ((Get-Item -LiteralPath $exported).Length -eq 0) { throw "empty storage export" }
    Invoke-Terra @("probe", "storage", "prune")
    $restarted = Get-TerraOutput @("probe", "--foreground", "--root", "--", "sh", "-e", "/suite/guest/storage-restart.sh")
    Assert-Contains $restarted "RESTART_OK"
    Assert-Contains $restarted "STOP_OK"
    Invoke-Terra @("probe", "storage", "import", $exported)
    Assert-Contains (Get-TerraOutput @("probe", "--foreground", "--",
        "sh", "-ec", 'test $(cat /data/value) = PERSISTED; echo RESTORED_OK')) "RESTORED_OK"
    Complete-Step

    Start-Step "a foreground command's exit status is terra's"
    Invoke-Terra @("probe", "--foreground", "--", "sh", "-c", "exit 7") -ExitCode 7
    Complete-Step

    Start-Step "logs show host and guest diagnostics"
    Invoke-Terra @("probe", "logs", "--tail", "20")
    Invoke-Terra @("probe", "logs", "--diagnostics", "--tail", "20")
    Complete-Step

    Start-Step "a failing bake fails setup and is diagnosable"
    Assert-Contains (Get-TerraOutput @("./bad-bake.yaml", "setup") -Fails) "FAILED_BAKE"
    Assert-Contains (Get-TerraOutput @("bad-bake", "logs", "--diagnostics")) "init failed"
    Complete-Step

    Start-Step "rm discards the box, --purge forgets it"
    Invoke-Terra @("probe", "rm")
    Assert-Listed "probe" "not_created"
    Invoke-Terra @("probe", "rm", "--purge")
    if ((Get-TerraOutput @("ls", "--quiet")) -split "`n" -contains "probe") { throw "probe is still listed" }
    Complete-Step

    Write-Host "terra $version works on this machine"
    $passed = $true
} catch {
    if ($stepWatch) { Add-StepResult "FAIL" }
    Write-Host "FAIL"
    Write-Host "$step failed: $_"
    if (Test-Path -LiteralPath $log) {
        Get-Content -LiteralPath $log | ForEach-Object { Write-Host "    $_" }
    }
} finally {
    if (Test-Path -LiteralPath $project) {
        Set-Location -LiteralPath $project
        $ErrorActionPreference = "Continue"
        foreach ($name in $boxes) {
            & $Terra $name rm --force --purge --timeout 5 *> $null
        }
    }
    Pop-Location
    if (-not [Console]::IsOutputRedirected) { Write-Summary }
    $env:HOME = $savedHome
    $env:USERPROFILE = $savedProfile
    if ($passed) {
        Remove-Item -Recurse -Force -LiteralPath $work
    } else {
        Write-Host "kept $work for inspection"
    }
}
# Explicit: the cleanup's last native call would otherwise set the script's exit code.
if ($passed) { exit 0 } else { exit 1 }
