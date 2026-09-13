<#
.SYNOPSIS
    MAINTENANCE - the one lane that really services this machine: the online DISM component store
    cleanup, the pnpclean driver package handler and the Delivery Optimization cache purge.

.DESCRIPTION
    Dot-sourced by Invoke-ElevatedVerification.ps1. It lives in its own file because it is its own
    lane: the sandboxed scenarios prove an exit code and are now genuinely fixture-only, and
    _ElevatedVerification.MachineScenarios.ps1 holds the two opt-in STEPS (driver pruning, legacy
    cleanmgr). This one exists because those three supported maintenance operations used to run
    inside EXIT2 and the uncontended EXIT3 control by accident (ledger WAC-10R), where they were
    reported as sandbox scope. Stopping that would have deleted the only coverage they had, so the
    coverage moved here instead - to a lane that says what it is.

    ARMED, NOT DEFAULT. Two independent conditions, both required:

        WAC_VM_MAINTENANCE=1   set deliberately, in the guest, for this run
        an elevated session    DISM /Online and pnpclean need it anyway

    Unarmed it touches nothing and records Execution=NotArmed, which is NOT a pass for the live
    validation: a guard that refuses has validated nothing, and the scenario record keeps the two
    words apart so a summary can never blur them. It is meant for a disposable Windows guest with a
    checkpoint taken first, in line with every other machine-changing lane in this repository.

    WHAT IT DOES NOT DO. /ResetBase is excluded here exactly as it is everywhere else - the child is
    launched with -ResetWindowsUpdateBase:$false and the exclusion is asserted from the child's own
    configuration line, not assumed. Driver pruning and legacy Disk Cleanup stay at their defaults,
    so this lane deletes no driver package and sweeps no other drive; those two have their own
    scenarios. The Recycle Bin stays skipped. The FILE plan is still the sandbox fixture's, so the
    only things this lane changes are the three maintenance operations it is named for.
#>

$script:MaintenanceSwitch = 'WAC_VM_MAINTENANCE'

function Get-MaintenanceArming {
    <#
    .SYNOPSIS
        Whether the lane may run, and the exact reason when it may not.
    .OUTPUTS
        Armed, Execution (Executed | NotArmed | Unsupported) and Reason.
    #>
    param()

    if ([string]::Equals([string]$env:WAC_VM_MAINTENANCE, '1', [System.StringComparison]::Ordinal) -ne $true) {
        return [PSCustomObject]@{
            Armed = $false; Execution = 'NotArmed'
            Reason = ('{0} is not set to 1, so no maintenance operation was performed on this machine.' -f $script:MaintenanceSwitch)
        }
    }
    if (-not (Test-WacIsAdministrator)) {
        return [PSCustomObject]@{
            Armed = $false; Execution = 'Unsupported'
            Reason = 'DISM /Online and the pnpclean handler need an elevated session; nothing was performed.'
        }
    }

    return [PSCustomObject]@{ Armed = $true; Execution = 'Executed'; Reason = 'The live maintenance lane ran.' }
}

function Invoke-MaintenanceScenario {
    <#
    .SYNOPSIS
        Runs the real DISM, pnpclean and Delivery Optimization steps against this machine, once
        armed, and proves from the child's own log that all three were attempted and none of them
        was /ResetBase.
    .DESCRIPTION
        The evidence is the child's log rather than the maintenance witness, because there is no
        witness here: this child deliberately carries NO maintenance fixture, which is the whole
        difference between this lane and the sandboxed ones. What is checked instead is that each
        of the three steps really reported a result, and that none reported the "did not start"
        shape a leftover interception would produce - so an accidentally fixture-carrying tree
        fails this scenario rather than passing it quietly.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null

    $arming = Get-MaintenanceArming
    if (-not $arming.Armed) {
        $watch.Stop()
        [void]$evidence.Add([string]$arming.Reason)
        return (New-ScenarioRecord -Name 'MAINTENANCE' -ExpectedExitCode 0 -Machine -Execution ([string]$arming.Execution) `
            -Expected 'the real DISM, pnpclean and Delivery Optimization steps run and report results' `
            -ActualExitCode 0 -Evidence @($evidence.ToArray()) -Problem @() `
            -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
    }

    $execution = 'Executed'
    try {
        $sandbox = New-VerificationSandbox -Prefix 'wac-maintenance'
        [void](New-SandboxBait -Sandbox $sandbox)

        # NO -InterceptMaintenance. That is what makes this lane real, and Start-VerificationChild is
        # told about it by name below so the launch gate lets exactly this child through.
        $commandLine = Get-RunChildCommandLine -ScriptPath (New-VerificationScratchTree -Sandbox $sandbox) `
            -MutexName (New-VerificationMutexName)
        $child = Start-VerificationChild -CommandLine $commandLine -AllowRealMaintenance `
            -Environment (Get-SandboxEnvironment -Sandbox $sandbox)
        $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
        $exitCode = $result.ExitCode

        if (-not $result.Exited) {
            [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
        }
        # 0 is the clean answer; 2 and 6 are real outcomes of real maintenance on a real machine and
        # are reported rather than hidden. Anything else is this lane failing, not the machine.
        if (@(0, 2, 6) -notcontains $result.ExitCode) {
            [void]$problem.Add(('the maintenance run exited {0}. stderr: {1}' -f `
                (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
        }

        $text = Get-SandboxLogText -Sandbox $sandbox
        Add-ResetBaseEvidence -Evidence $evidence -Problem $problem -Text $text

        # Each of the three has to have produced its own step line, and DISM and pnpclean have to
        # say attempted=True - the field that separates "the tool ran on this machine" from every
        # kind of skip. The Delivery Optimization purge is deliberately not held to that: a machine
        # without the DO cmdlets safe-skips for a real environmental reason, which this records as
        # evidence rather than inventing a failure out of it.
        foreach ($step in @(
                @{ Category = 'Windows component store cleanup (DISM)'; MustAttempt = $true }
                @{ Category = 'Device driver packages (pnpclean)'; MustAttempt = $true }
                @{ Category = 'Delivery Optimization cache'; MustAttempt = $false })) {
            $stepLines = @(Get-MatchingLine -Text $text -Needle ('category="{0}"' -f $step.Category))
            if ($stepLines.Count -eq 0) {
                [void]$problem.Add(('the run produced no step result for {0}, so it was never reached' -f $step.Category))
                continue
            }

            [void]$evidence.Add($stepLines[0])
            if ($step.MustAttempt -and -not (Test-KeyValue -Line $stepLines[0] -Pair 'attempted=True')) {
                [void]$problem.Add(('{0} reported attempted=False, so this lane validated nothing for it' -f $step.Category))
            }
        }

        # A tree that still carried the interception would say so in its own log, and this lane must
        # never accept that as a pass: an intercepted run has validated no maintenance at all.
        if (@(Get-MatchingLine -Text $text -Needle 'SANDBOX FIXTURE').Count -gt 0) {
            [void]$problem.Add('the maintenance lane ran an INTERCEPTED child, so no real maintenance was validated')
            $execution = 'NotArmed'
        }

        # The file plan is still sandbox-only here, so the machine's own allow-list locations are
        # untouched by this lane even while its three steps are real.
        [void](Add-LogEvidence -Evidence $evidence -Problem $problem -Text $text -Needle '[Summary] Cleanup totals.')
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $child
        if (-not (Remove-VerificationSandbox -Path $sandbox)) {
            [void]$problem.Add(('the sandbox could not be removed: {0}' -f $sandbox))
        }
    }

    if ($problem.Count -gt 0 -and $execution -ceq 'Executed') { $execution = 'Failed' }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'MAINTENANCE' -ExpectedExitCode 0 -Machine -Execution $execution `
        -Expected 'the real DISM, pnpclean and Delivery Optimization steps run, with /ResetBase off' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}
