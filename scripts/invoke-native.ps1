function Invoke-Native {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Command,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "native command failed ($LASTEXITCODE): $Command $($Arguments -join ' ')"
    }
}
