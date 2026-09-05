$script:observedTargets = @()
$script:cleanupCalls = 0
function Complete-ObservedProcesses {
    param($Targets, $Mode, $BeforeKill)
    # Fail the body while both real, ready targets still need final cleanup.
    $script:observedTargets = $Targets
    throw 'injected probe body failure'
}
function Stop-ObservedProcess {
    param([Diagnostics.Process]$Process)
    $Process.Kill()
    if (!$Process.WaitForExit(10000)) { throw 'injected target exit failed' }
    $script:cleanupCalls++
    if ($script:cleanupCalls -eq 1) {
        throw [ComponentModel.Win32Exception]::new(5)
    }
}
$failure = $null
try {
    try { Test-ProcessCleanup -Scenario 'error' } catch { $failure = $_ }
    if ($script:observedTargets.Count -ne 2) { throw 'probe did not create both targets' }
    if ($script:cleanupCalls -ne 2) { throw 'probe fallback abandoned a remaining target' }
    if ($null -eq $failure) { throw 'probe fallback concealed its failure' }
    Write-Output 'FALLBACK_PROBE_PASS'
} finally {
    foreach ($target in $script:observedTargets) {
        try {
            if (!$target.HasExited) {
                $target.Kill()
                if (!$target.WaitForExit(10000)) { throw 'probe external cleanup failed' }
            }
        } catch [InvalidOperationException] {
            # The real probe has already disposed a successfully cleaned handle.
        }
    }
}
# Expected caught exceptions must not become PowerShell's implicit exit status.
exit 0
