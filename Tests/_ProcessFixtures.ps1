<#
.SYNOPSIS
    Shared fixtures for the two process suites: the host binary this suite runs on, and starting a
    probe in its own process and waiting for it under a bound.

.DESCRIPTION
    Dot-sourced by Process.Tests.ps1 and ProcessTree.Tests.ps1. It is not a suite: its name does not
    match Tests\*.Tests.ps1, so the runner never executes it on its own.
#>
. (Join-Path -Path $PSScriptRoot -ChildPath '_ProbeProcess.ps1')

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
