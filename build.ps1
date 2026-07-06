param(
    [string]$Output = "",
    [string]$Target = ""
)

$ErrorActionPreference = "Stop"

$args = @("build", "--release")
if ($Target) {
    $args += @("--target", $Target)
}

cargo @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$binDir = if ($Target) { "target\$Target\release" } else { "target\release" }
$built = Join-Path $binDir "malscan.exe"
if (-not (Test-Path $built)) {
    $built = Join-Path $binDir "malscan"
}

if ($Output) {
    Copy-Item $built $Output -Force
    Write-Host "Built $Output"
} else {
    Write-Host "Built $built"
}
