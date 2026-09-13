<#
.SYNOPSIS
    Removing a scheduled-task registration this project owns: prove it is ours, capture its exact
    definition, make that capture durable, unregister, and prove it is gone.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Deploy.psm1; see that file for why the parts are dot-sourced
    rather than imported. Split out of WindowsAutoCleanup.ScheduledTask.ps1, which had reached the
    size at which a file stops being read: that file now answers "what is registered and is it ours"
    - a set of pure, side-effect-free questions - and this one owns the single call in the package
    that DESTROYS a registration. The split is where it is because the transaction boundary belongs
    with the destructive step, not with the questions that lead up to it.

    Only Remove-WacInstalledTask lives here. Test-WacTaskIsOurs and Get-WacTaskQueryResult stayed
    behind: both are asked by callers that remove nothing, and following them here would have moved
    the ownership proof away from the lookup it belongs to.
#>

function Remove-WacInstalledTask {
    <#
    .SYNOPSIS
        Captures a task's exact definition, unregisters it once it passes the ownership proof, and
        PROVES it is gone.
    .DESCRIPTION
        The definition is exported BEFORE the unregister and handed back on the result, because a
        caller that removes an old registration as one step of an upgrade has to be able to put
        exactly that registration back when a later step fails. -RequireDefinitionCapture makes
        that mandatory: the installer passes it, since a removal it could not undo is not a step it
        is allowed to take, and the uninstaller does not, because there is nothing to roll back to.

        -OnCaptured is the TRANSACTION BOUNDARY (ledger WAC-02R). A capture that lives only in the
        caller's memory dies with the caller's process, so an upgrade killed between this unregister
        and its next durable write left a machine with no registration and nothing on disk saying one
        had ever existed. The callback is handed the captured result and answers whether it made that
        capture durable; on anything but $true the task is LEFT REGISTERED and the refusal says why.
        A machine left exactly as it was found is strictly better than one missing a task nothing can
        describe. Without the parameter the behaviour is byte-for-byte what it was, so the
        uninstaller is unaffected.

        The order is fixed and the export stays INSIDE it: ownership first, then the capture, then
        durability, then the unregister. Exporting a task before proving it is ours would read a
        foreign definition off the machine to no purpose.

        Verification is ternary. It used to be `try { Get-ScheduledTask } catch { $null }`, so an
        access-denied or RPC failure on the read-back was indistinguishable from the task really
        being gone, and an arbitrary query exception was reported as a verified removal.
    .OUTPUTS
        TaskName, TaskPath, Removed, Verified, Captured, CaptureDurable ($null when no callback was
        supplied), Definition, CaptureReason, Reason.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Task,
        [string]$DeploymentRoot,
        [switch]$AllowLegacyMigration,
        [switch]$RequireDefinitionCapture,
        [AllowNull()][scriptblock]$OnCaptured
    )

    $proof = Test-WacTaskIsOurs -Task $Task -DeploymentRoot $DeploymentRoot -AllowLegacyMigration:$AllowLegacyMigration

    $result = [PSCustomObject]@{
        TaskName = $proof.TaskName
        TaskPath = $proof.TaskPath
        Removed = $false
        Verified = $false
        Captured = $false
        CaptureDurable = $null
        Definition = $null
        CaptureReason = $null
        Reason = $proof.Reason
    }

    if (-not $proof.IsOurs) {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'Refused to remove a task that is not ours.' -Data @{
            task = ('{0}{1}' -f $result.TaskPath, $result.TaskName); reason = $proof.Reason
        }
        return $result
    }

    $export = ''
    try { $export = [string](Export-ScheduledTask -TaskName $result.TaskName -TaskPath $result.TaskPath -ErrorAction Stop) }
    catch { $export = ''; $result.CaptureReason = $_.Exception.Message }

    if ([string]::IsNullOrWhiteSpace($export)) {
        if (-not $result.CaptureReason) { $result.CaptureReason = 'The scheduler returned an empty task definition.' }
    }
    else {
        $result.Captured = $true
        $result.Definition = $export
        $result.CaptureReason = 'The definition was captured before the removal.'
    }

    if ($RequireDefinitionCapture -and -not $result.Captured) {
        $result.Reason = ('The task was left registered because its definition could not be captured first, so removing it could not have been undone: {0}' -f [string]$result.CaptureReason)
        Write-WacLog -Level ERROR -Component 'Deploy' -Message 'Refused to remove a task whose definition could not be captured.' -Data @{
            task = ('{0}{1}' -f $result.TaskPath, $result.TaskName); reason = [string]$result.CaptureReason
        }
        return $result
    }

    # Only with something to record. A callback handed a capture that does not exist could write
    # nothing useful, and refusing on its answer would block a removal the caller already decided it
    # does not need to undo.
    if ($OnCaptured -and $result.Captured) {
        $durable = $false
        try { $durable = [bool](& $OnCaptured $result) }
        catch {
            $durable = $false
            $result.CaptureReason = ('{0} Making it durable failed: {1}' -f [string]$result.CaptureReason, $_.Exception.Message)
        }

        $result.CaptureDurable = $durable
        if (-not $durable) {
            $result.Reason = ('The task was left registered because its captured definition could not be recorded where a later run would find it: {0}' -f [string]$result.CaptureReason)
            Write-WacLog -Level ERROR -Component 'Deploy' -Message 'Refused to unregister a task whose capture could not be made durable.' -Data @{
                task = ('{0}{1}' -f $result.TaskPath, $result.TaskName); reason = [string]$result.CaptureReason
            }
            return $result
        }
    }

    try {
        Unregister-ScheduledTask -TaskName $result.TaskName -TaskPath $result.TaskPath -Confirm:$false -ErrorAction Stop
        $result.Removed = $true
    }
    catch {
        $result.Reason = $_.Exception.Message
        return $result
    }

    $verify = Get-WacTaskQueryResult -TaskPath $result.TaskPath -TaskName $result.TaskName
    if ($verify.State -eq 'Found') {
        $result.Reason = 'Unregister-ScheduledTask reported success but the task is still registered.'
        Write-WacLog -Level ERROR -Component 'Deploy' -Message 'A task survived its own removal.' -Data @{ task = ('{0}{1}' -f $result.TaskPath, $result.TaskName) }
        return $result
    }
    if ($verify.State -ne 'Absent') {
        $result.Reason = ('The removal could not be verified: {0}' -f [string]$verify.Reason)
        Write-WacLog -Level ERROR -Component 'Deploy' -Message 'A task removal could not be verified.' -Data @{
            task = ('{0}{1}' -f $result.TaskPath, $result.TaskName); reason = [string]$verify.Reason
        }
        return $result
    }

    $result.Verified = $true
    $result.Reason = 'Removed and verified absent.'
    Write-WacLog -Level INFO -Component 'Deploy' -Message 'Scheduled task removed.' -Data @{ task = ('{0}{1}' -f $result.TaskPath, $result.TaskName) }
    return $result
}
