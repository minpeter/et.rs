function Test-ProcessCleanup {
    param([ValidateSet('race', 'error')][string]$Scenario)
    $targets = @()
    try {
        # Given: both real targets signal readiness, then block on a kernel event.
        foreach ($index in 0..1) {
            $process = [Diagnostics.Process]::new()
            $process.StartInfo.FileName = Join-Path $PSHOME 'powershell.exe'
            $process.StartInfo.Arguments = '-NoProfile -NonInteractive -Command "[Console]::WriteLine(''READY''); [void]([Threading.ManualResetEvent]::new($false)).WaitOne()"'
            $process.StartInfo.UseShellExecute = $false
            $process.StartInfo.CreateNoWindow = $true
            $process.StartInfo.RedirectStandardOutput = $true
            if (!$process.Start()) { $process.Dispose(); throw 'Could not start native target' }
            $targets += $process
            $null = $process.Handle
            $ready = $process.StandardOutput.ReadLineAsync()
            if (!$ready.Wait(10000) -or $ready.Result -ne 'READY') {
                throw 'Native target readiness event failed'
            }
        }
        $firstId = $targets[0].Id
        $beforeKill = {
            param([Diagnostics.Process]$Process)
            if ($Process.Id -eq $firstId) {
                switch ($Scenario) {
                    'race' {
                        # Exact competing-exit barrier between the state check
                        # and Kill: no timing sleeps and no fake process object.
                        $Process.Kill()
                        if (!$Process.WaitForExit(10000)) { throw 'Competing exit barrier failed' }
                    }
                    'error' { throw [ComponentModel.Win32Exception]::new(5) }
                }
            }
        }.GetNewClosure()
        # When: cleanup sees either a completed competing exit or a real error
        # category injected only at the narrow pre-kill seam.
        $failure = $null
        try {
            Complete-ObservedProcesses -Targets $targets -Mode 'CLEANUP' -BeforeKill $beforeKill
        } catch { $failure = $_ }

        # Then: later targets always retire, while genuine errors remain visible.
        if (!$targets[1].HasExited) { throw 'Cleanup abandoned the second target' }
        switch ($Scenario) {
            'race' {
                if ($null -ne $failure) { throw $failure }
                if (!$targets[0].HasExited) { throw 'Competing exit was not observed' }
            }
            'error' {
                if ($null -eq $failure) { throw 'Cleanup concealed a termination error' }
                if ($targets[0].HasExited) { throw 'Error probe did not preserve its live target' }
            }
        }
        Write-Output ('CLEANUP_PROBE_PASS scenario=' + $Scenario)
    } finally {
        foreach ($process in $targets) {
            if (!$process.HasExited) { Stop-ObservedProcess $process }
            if (!$process.WaitForExit(10000)) { throw 'Probe fallback cleanup failed' }
            $process.Dispose()
        }
    }
}
