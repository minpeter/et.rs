# Run the CI artifact on a native Windows host without Cargo or protoc.
# Example: powershell -NoProfile -File .\Run-WindowsRuntime.ps1
# Only ephemeral loopback endpoints and test-owned processes are used.
$ErrorActionPreference = 'Stop'
$env:ET_WINDOWS_RUNTIME_BINARY = Join-Path $PSScriptRoot 'et.exe'
$testExecutable = Join-Path $PSScriptRoot 'windows_runtime.exe'
if (!(Test-Path $env:ET_WINDOWS_RUNTIME_BINARY) -or !(Test-Path $testExecutable)) {
    throw 'Extract et.exe and windows_runtime.exe beside this script'
}
[string[]]$testArguments = if ($args.Count -eq 0) { @('--test-threads=1', '--nocapture') } else { $args }
& $testExecutable @testArguments
exit $LASTEXITCODE
