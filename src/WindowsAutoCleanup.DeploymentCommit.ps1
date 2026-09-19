<#
.SYNOPSIS
    The durable decision that one deployment generation FINISHED (ledger WAC-02R).

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Deploy.psm1, so it shares that module's session state: the
    in-flight transaction it stamps is the one Switch-WacDeploymentStage built, and the record it
    writes is the one Save-WacDeploymentJournal owns.

    Commitment used to be a thing the NEXT process inferred. It read what was lying on the disk - a
    manifest hash that matched the record, or a healthy tree beside a recovery copy it could not
    promote - and concluded from that shape that the run which made it had succeeded. Neither
    observation carries that claim. A tree can be intact, be exactly the tree the record names, and
    still belong to a generation that died before it registered the task that goes with it; retiring
    the recovery copy on that reading discards the only installation the machine ever had working.

    So the process that ESTABLISHES commitment is the one that writes it down, at the one moment it
    is true: after the replacement task and the replacement files have both been verified, and
    before either recovery copy is retired. The ordering is the whole contract. A decision written
    after the copy is gone would describe a state nothing could be rolled back to, and a copy
    retired before the decision is written leaves a generation that finished looking exactly like
    one that was interrupted.
#>

function Set-WacDeploymentCommitted {
    <#
    .SYNOPSIS
        Stamps this process's swap record Committed. Call it only once both halves are verified, and
        only before retiring a recovery copy.
    .DESCRIPTION
        Recorded is $false ONLY when the stamp was attempted and the write did not land. A process
        holding no open swap record has nothing to stamp and nothing to lose - Switch-WacDeploymentStage
        without -KeepPrevious has already ended its transaction and deleted the record - so that case
        is Recorded with a reason rather than a failure the caller has to special-case.
    .OUTPUTS
        Recorded and Reason.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Task)

    $result = [PSCustomObject]@{ Recorded = $false; Reason = '' }

    if (-not $script:DeploymentTransaction) {
        $result.Recorded = $true
        $result.Reason = 'this process holds no open swap transaction, so there was no decision to record.'
        return $result
    }

    if ($PSBoundParameters.ContainsKey('Task')) {
        $proof = New-Object 'System.Collections.Generic.List[object]'
        try {
            foreach ($item in @($Task)) {
                $xml = [string](Export-ScheduledTask -TaskName $item.TaskName -TaskPath $item.TaskPath -ErrorAction Stop)
                if (-not (Test-WacCapturedTaskDefinition -Xml $xml -Task $item).Match) {
                    throw 'The replacement task export did not match the verified registration.'
                }
                [void]$proof.Add([PSCustomObject]@{
                    TaskName = [string]$item.TaskName; TaskPath = [string]$item.TaskPath
                    Definition = $xml; Captured = $true
                })
            }
        }
        catch { $result.Reason = $_.Exception.Message; return $result }
        $script:DeploymentTransaction | Add-Member -NotePropertyName ReplacementTask -NotePropertyValue @($proof.ToArray()) -Force
        $script:DeploymentTransaction | Add-Member -NotePropertyName TaskDecision -NotePropertyValue $true -Force
    }
    $script:DeploymentTransaction.Committed = $true
    if (-not (Save-WacDeploymentJournal -Transaction $script:DeploymentTransaction -Stage 'Committed')) {
        # Put the in-memory flag back. It is what a rollback in this same process would otherwise
        # read as "already committed", and the durable record - the only thing a later process sees
        # - does not say it.
        $script:DeploymentTransaction.Committed = $false
        $result.Reason = ('the commit decision could not be written to the transaction record beside the deployment: {0}' -f
            [string](Get-WacDeploymentJournalPath -DeploymentRoot $script:DeploymentTransaction.Root))
        return $result
    }

    $result.Recorded = $true
    $result.Reason = 'the generation is recorded as committed.'
    return $result
}

function Set-WacRecoveryTaskAcknowledgement {
    <#
    .SYNOPSIS
        Records completion of the task half before any recovery file is removed.
    #>
    param([string]$DeploymentRoot, [ValidateSet('RestoreOriginal', 'CommitReplacement')][string]$Verdict)
    $kind = 'Swap'
    $read = Read-WacDeploymentJournal -DeploymentRoot $DeploymentRoot
    if ([string]$read.State -ceq 'Absent') {
        $kind = 'TaskCapture'
        $read = Read-WacDeploymentJournal -DeploymentRoot $DeploymentRoot -Kind $kind
    }
    if ([string]$read.State -cne 'Valid') { return $false }
    $read.Record | Add-Member -NotePropertyName TaskReconciledVerdict -NotePropertyValue $Verdict -Force
    return (Write-WacDeploymentJournal -DeploymentRoot $DeploymentRoot -Kind $kind -Record $read.Record)
}
