function Stop-ObservedProcess {
    param([Diagnostics.Process]$Process)
    try {
        $Process.Kill()
    } catch [InvalidOperationException], [ComponentModel.Win32Exception] {
        # Kill may race another owner completing exit. Only confirmed process
        # completion makes that error benign; real termination errors escape.
        if (!$Process.HasExited) { throw }
    }
}

function Complete-ObservedProcesses {
    param(
        [Diagnostics.Process[]]$Targets,
        [string]$Mode,
        [scriptblock]$BeforeKill = {}
    )
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($process in $Targets) {
        $processId = $process.Id
        try {
            if ($Mode -ne 'WAIT' -and !$process.HasExited) {
                & $BeforeKill $process
                Stop-ObservedProcess $process
            }
            if (!$process.WaitForExit(10000)) {
                # A watchdog failure stays a failure even if fallback succeeds.
                $failures.Add("process $processId cleanup timed out")
                & $BeforeKill $process
                Stop-ObservedProcess $process
                if (!$process.WaitForExit(10000)) {
                    $failures.Add("process $processId fallback cleanup timed out")
                }
            }
        } catch {
            # One target's error must not abandon the remaining owned handles.
            $failures.Add("process ${processId}: $($_.Exception.Message)")
        }
    }
    if ($failures.Count -ne 0) { throw ($failures -join '; ') }
}
