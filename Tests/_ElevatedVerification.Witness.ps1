<#
.SYNOPSIS
    The maintenance witness: reading and judging what Tests\_SandboxMaintenanceFixture.psm1 recorded
    about the machine maintenance a sandboxed child was stopped from performing (ledger WAC-10R).

.DESCRIPTION
    Dot-sourced by Invoke-ElevatedVerification.ps1 beside _ElevatedVerification.Harness.ps1, and
    kept apart from it because this is a separate question. The harness owns the sandbox, the child
    and the run log; this file owns the ONE artifact the maintenance fixture leaves behind and the
    verdict read from it. It defines functions only and runs nothing at dot-source time.

    The verdict is POSITIVE. "No DISM ran" is unfalsifiable on its own - a run that crashed before
    the first step satisfies it - so a full sandboxed run has to show that it REACHED each of the
    five maintenance entry points and that each one was intercepted there.
#>

function Test-KeyPresent {
    <#
    .SYNOPSIS
        $true when the log line carries the key at all, whatever its value.
    .DESCRIPTION
        Write-WacTreeResult OMITS failed= entirely when the count is zero, so "this target reported
        no failure" cannot be written as failed=0 - that pair never appears. The question that can
        be asked is whether the field is there, which is what makes "only the bait line carries a
        failure" checkable.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line,
        [Parameter(Mandatory = $true)][string]$Key
    )

    return ($Line -cmatch ('(^|\s){0}=' -f [regex]::Escape($Key)))
}

# ------------------------------------------------------------------------------------------------
# The maintenance witness - what the sandbox maintenance fixture recorded
# ------------------------------------------------------------------------------------------------

# The five maintenance entry points a sandboxed run reaches, in Run.ps1's order. It is the same list
# the fixture exports from Get-WacMaintenanceStage, and SandboxMaintenanceGuard.Tests.ps1 compares
# the two so they cannot drift apart silently.
$script:MaintenanceStage = @(
    'DeliveryOptimizationCache', 'ComponentCleanup', 'PnpCleanHandler', 'DriverPackagePrune', 'LegacyDiskCleanup'
)

function Get-SandboxWitnessText {
    <#
    .SYNOPSIS
        The raw maintenance-witness text for one sandbox, or '' when the run never reached a step.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $path = Join-Path -Path $Sandbox -ChildPath 'maintenance-witness.log'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return '' }
    return [string][System.IO.File]::ReadAllText($path)
}

function Get-SandboxWitness {
    <#
    .SYNOPSIS
        Parses witness text into the stages that were intercepted and the tripwires that fired.
    .DESCRIPTION
        Pure, so the parsing is testable without a child process. A tripwire line means something
        tried to reach a REAL system tool despite the entry-point interception - a hole in the
        fixture - and it is never routine.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text)

    $intercepted = New-Object 'System.Collections.Generic.List[string]'
    $tripwire = New-Object 'System.Collections.Generic.List[string]'
    $malformed = New-Object 'System.Collections.Generic.List[string]'

    foreach ($line in @($Text -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $match = [regex]::Match($line, '(?i)\b(?<kind>intercepted|tripwire)\s+stage=(?<stage>\S+)')
        if (-not $match.Success) {
            [void]$malformed.Add($line.Trim())
            continue
        }
        if ($match.Groups['kind'].Value -ieq 'tripwire') { [void]$tripwire.Add($line.Trim()) }
        else { [void]$intercepted.Add([string]$match.Groups['stage'].Value) }
    }

    return [PSCustomObject]@{
        Intercepted = @($intercepted.ToArray())
        Tripwire    = @($tripwire.ToArray())
        Malformed   = @($malformed.ToArray())
    }
}

function Add-MaintenanceEvidence {
    <#
    .SYNOPSIS
        Proves from the witness that this child serviced nothing on the real machine.
    .DESCRIPTION
        POSITIVE, not an absence. A full sandboxed run must show every one of the five maintenance
        entry points reached AND intercepted, which is only true when the run really got that far;
        a run that stopped at a gate must show none of them. Either way a tripwire - something that
        tried to launch a real tool or enter a fresh runspace anyway - fails the scenario, and so
        does a Recycle Bin stage, because every sandboxed child is launched with -SkipRecycleBin.
    .PARAMETER ExpectFullSequence
        The child was expected to reach the cleanup phase. Without it, the child was expected to
        exit at a gate and nothing at all may have been intercepted.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Evidence,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Problem,
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$ExpectFullSequence
    )

    $witness = Get-SandboxWitness -Text (Get-SandboxWitnessText -Sandbox $Sandbox)

    foreach ($line in @($witness.Tripwire)) {
        [void]$Problem.Add(('{0} reached a REAL system tool despite the maintenance fixture: {1}' -f $Label, $line))
    }
    foreach ($line in @($witness.Malformed)) {
        [void]$Problem.Add(('{0} wrote an unreadable maintenance witness line, so the interception cannot be proven: {1}' -f $Label, $line))
    }
    if (@($witness.Intercepted) -contains 'RecycleBin') {
        [void]$Problem.Add(('{0} reached the global Recycle Bin step even though -SkipRecycleBin was passed' -f $Label))
    }

    if (-not $ExpectFullSequence) {
        if (@($witness.Intercepted).Count -gt 0) {
            [void]$Problem.Add(('{0} reached a maintenance step before its gate: {1}' -f $Label, (@($witness.Intercepted) -join ', ')))
        }
        else {
            [void]$Evidence.Add(('{0} reached no maintenance step at all' -f $Label))
        }
        return
    }

    foreach ($stage in $script:MaintenanceStage) {
        if (@($witness.Intercepted) -notcontains $stage) {
            [void]$Problem.Add(('{0} never reached the {1} maintenance step, so its interception is unproven: witness={2}' -f `
                $Label, $stage, (@($witness.Intercepted) -join ', ')))
        }
    }
    [void]$Evidence.Add(('{0} intercepted every maintenance step and launched no system tool: {1}' -f `
        $Label, (@($witness.Intercepted) -join ', ')))
}
