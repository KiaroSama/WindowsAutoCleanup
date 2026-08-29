<#
.SYNOPSIS
    The pre-flight safety gate both entry-point scripts cross before their first mutation.

.DESCRIPTION
    Dot-sourced by Install-WindowsAutoCleanupTask.ps1 and Uninstall-WindowsAutoCleanupTask.ps1 into
    their own scope. It is deliberately NOT part of a module and exports nothing: the entry points
    can only call what a module EXPORTS, the Deploy package's export list is fixed, and a decision
    both scripts have to make identically must not exist as two copies that drift.

    Nothing here has a side effect. It reads two verdicts that Core has already produced and returns
    a third, so the gate can be exercised directly rather than only through an elevated run against
    the live Task Scheduler.
#>

Set-StrictMode -Version 2.0

function Get-OperationSafetyVerdict {
    <#
    .SYNOPSIS
        May this run change anything at all?
    .DESCRIPTION
        Both entry points used to check the LOG only, and only at the very end - after the
        deployment had been replaced and the task re-registered - and neither ever consulted STATE
        trust. So an elevated run whose machine state directory a standard user can replace or
        redirect installed anyway, wrote its audit trail through that path, and reported the problem
        afterwards, by which time the machine had already been changed.

        UNKNOWN is refused exactly like FALSE. $null means the question was never answered:
        Initialize-WacRun evaluates state trust only for an elevated run using the roots it chose
        itself, and an unanswered security question is not a yes.

        ORDER MATTERS, and it follows the run's own precedence: a SecurityRefusal outranks
        Incomplete work. A verdict that was reached and came back untrusted is now the reason there
        is no durable log at all - Initialize-WacRun refuses to create one in a directory it does
        not trust - so testing the log first would report the symptom (exit 6, "no durable audit
        log") and bury the cause (exit 7, "not machine-trusted"). The $null case stays BELOW the log
        check, because there the log failure is the only thing actually known.
    .OUTPUTS
        Ok, ExitCode, Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$LogHealth,
        [Parameter(Mandatory = $true)][AllowNull()]$StateTrust
    )

    if ($StateTrust -and -not $StateTrust.IsTrusted) {
        return [PSCustomObject]@{
            Ok = $false
            ExitCode = 7
            Reason = ('Refused before any change: the machine state directory is not machine-trusted, so nothing was staged, registered or deleted. {0}: {1}' -f [string]$StateTrust.Path, [string]$StateTrust.Reason)
        }
    }

    if (-not $LogHealth -or -not $LogHealth.IsDurable) {
        $detail = if ($LogHealth) { [string]$LogHealth.Reason } else { 'No log health was reported at all.' }
        return [PSCustomObject]@{
            Ok = $false
            ExitCode = 6
            Reason = ('Refused before any change: this run has no durable audit log, so what it did could not be explained afterwards. {0}' -f $detail)
        }
    }

    if (-not $StateTrust) {
        return [PSCustomObject]@{
            Ok = $false
            ExitCode = 7
            Reason = 'Refused before any change: whether the machine state directory is trustworthy was never established, and an unanswered trust question is not a yes. Nothing was staged, registered or deleted.'
        }
    }

    return [PSCustomObject]@{
        Ok = $true
        ExitCode = 0
        Reason = ('The audit log is durable and {0} is machine-trusted.' -f [string]$StateTrust.Path)
    }
}
