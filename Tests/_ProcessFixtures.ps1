<#
.SYNOPSIS
    Shared fixtures for the two process suites: the host binary this suite runs on, and starting a
    probe in its own process and waiting for it under a bound.

.DESCRIPTION
    Dot-sourced by Process.Tests.ps1 and ProcessTree.Tests.ps1. It is not a suite: its name does not
    match Tests\*.Tests.ps1, so the runner never executes it on its own.
#>
# The host running this suite, taken from the live process rather than PATH.
$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

function Start-ProbeProcess {
    <#
    .SYNOPSIS
        Starts a probe script in its own process. Values arrive through the environment, so a
        quoting defect in the code under test cannot corrupt the probe's own inputs.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][hashtable]$Environment
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:HostExe
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }

    return [System.Diagnostics.Process]::Start($psi)
}

function Wait-ProbeProcess {
    <#
    .SYNOPSIS
        Bounded wait plus process-tree kill, so a probe that proves a hang cannot hang this suite.
    #>
    param(
        [Parameter(Mandatory = $true)]$Process,
        [int]$TimeoutMs = 90000
    )

    $outTask = $Process.StandardOutput.ReadToEndAsync()
    $errTask = $Process.StandardError.ReadToEndAsync()
    $exited = $Process.WaitForExit($TimeoutMs)

    if (-not $exited) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe')
        $psi.Arguments = '/T /F /PID {0}' -f $Process.Id
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $killer = [System.Diagnostics.Process]::Start($psi)
        if ($killer) {
            [void]$killer.StandardOutput.ReadToEndAsync()
            [void]$killer.StandardError.ReadToEndAsync()
            [void]$killer.WaitForExit(10000)
            try { $killer.Dispose() } catch { $null = $_ }
        }
        [void]$Process.WaitForExit(10000)
    }

    [void]$outTask.Wait(5000)
    [void]$errTask.Wait(5000)

    $exitCode = -1
    if ($exited) { try { $exitCode = [int]$Process.ExitCode } catch { $exitCode = -1 } }

    return [PSCustomObject]@{
        Exited     = $exited
        ExitCode   = $exitCode
        Output     = $(if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' })
        ErrorText  = $(if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' })
    }
}

function Reset-WacTestLog {
    <#
    .SYNOPSIS
        Puts module logging back to a clean, non-degraded state.
    .DESCRIPTION
        The degraded flag is sticky by design, so a case that breaks logging on purpose would
        otherwise route every LATER case's lines to a fallback that is no longer injected.
    #>
    # Close the log the CASE opened, before anything else. Initialize-WacRun below does not
    # close a log that is already open - it just replaces the writer - so without this the old
    # FileStream stays live on the case's own sandbox, Remove-TestSandbox cannot delete the
    # locked .log, and it fails silently. Measured: 12 leaked sandbox directories in %TEMP%.
    Close-WacLog

    Set-WacLogWriter -Writer $null
    Set-WacLogFallbackWriter -Writer $null

    $sandbox = New-TestSandbox -Prefix 'logreset'
    try {
        [void](Initialize-WacRun -BaseName 'reset' -CandidateRoot @($sandbox) -BudgetMinutes 60)
        Close-WacLog
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}
