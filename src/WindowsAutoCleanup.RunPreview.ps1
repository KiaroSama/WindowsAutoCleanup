<#
.SYNOPSIS
    What this run WOULD delete, printed without deleting any of it.

.DESCRIPTION
    This tool runs unattended, as SYSTEM, and its whole job is removing files. An operator who wants
    to know what a configuration actually selects has had exactly one way to find out: run it and
    read the log afterwards. That is a poor trade for a question asked BEFORE the deletion.

    The preview answers it from the same code the run uses. It calls the same allow-list builder with
    the same skip list, so what it prints is what the run would sweep - not a second description of
    it that can drift. Nothing here deletes, moves, writes to the registry or starts an external
    tool; the only writes are this script's own log lines.

    IT IS NOT A DRY RUN OF THE WHOLE RUN, and says so. The maintenance steps - the component store,
    the driver handler, the profile-driven disk cleanup, the Recycle Bin - have no way to enumerate
    what they would remove without doing it, so the preview reports whether each is switched on
    rather than pretending to list its contents. Claiming otherwise would be the more dangerous
    error: an operator who believes an empty list means "nothing will happen" is exactly who this
    exists to protect.

    Dot-sourced by Run.ps1, like the run report, because it reads the same run state.
#>

function Write-WacPreviewLine {
    <#
    .SYNOPSIS
        One line of the preview, to the console the operator is watching AND to the durable log.
    .DESCRIPTION
        The console is where the answer is wanted; the log is what makes the answer auditable later.
        Write-Host is deliberate and matches the project's other interactive surfaces: this mode is
        only ever reached from an operator's own session, never from the scheduled trigger.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'The preview is an interactive report; its console text is the product.')]
    param([string]$Text = '')

    Write-Host $Text
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        Write-WacLog -Level INFO -Component 'Preview' -Message ('| ' + $Text)
    }
}

function Show-WacRunPreview {
    <#
    .SYNOPSIS
        Prints the selected targets, the exclusions and the destructive options, and returns the
        exit code this preview earned.
    .DESCRIPTION
        The exit code is NOT "what the run would exit with" - the run has not happened. It says
        whether the PREVIEW itself could answer: 0 when the allow-list was fully built, and the
        project's Incomplete code when discovery was cut short, because a partial list read as a
        complete one is the misunderstanding this whole mode exists to prevent.
    .OUTPUTS
        An exit code.
    #>
    [CmdletBinding()]
    param(
        [string[]]$SkipCategory = @(),
        [switch]$SkipRecycleBin,
        [switch]$ResetWindowsUpdateBase,
        [switch]$PruneSupersededDrivers,
        [switch]$EnableLegacyDiskCleanup
    )

    Write-WacPreviewLine -Text ''
    Write-WacPreviewLine -Text 'PREVIEW - nothing on this machine is changed by this run.'
    Write-WacPreviewLine -Text ''

    # The opt-ins first. They are the part an operator gets wrong at the highest cost, and unlike the
    # allow-list they cannot be enumerated without performing them.
    Write-WacPreviewLine -Text 'Destructive options, as this invocation sets them:'
    foreach ($row in @(
            @{ Name = 'Windows Update component base reset (/ResetBase)'; On = [bool]$ResetWindowsUpdateBase
                Note = 'makes every installed update permanently un-installable' },
            @{ Name = 'Superseded driver-package pruning'; On = [bool]$PruneSupersededDrivers
                Note = 'exports a recoverable backup before deleting any package' },
            @{ Name = 'Legacy Disk Cleanup handlers (cleanmgr)'; On = [bool]$EnableLegacyDiskCleanup
                Note = 'enumerates every drive in the computer, not only C:' },
            @{ Name = 'Recycle Bin (drive C: only)'; On = (-not [bool]$SkipRecycleBin)
                Note = 'empties it; the contents are not recoverable afterwards' })) {
        Write-WacPreviewLine -Text ('  [{0}] {1}' -f $(if ($row.On) { 'ON ' } else { 'off' }), $row.Name)
        if ($row.On) { Write-WacPreviewLine -Text ('        {0}' -f $row.Note) }
    }
    Write-WacPreviewLine -Text ''

    $skip = @($SkipCategory | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($skip.Count -gt 0) {
        Write-WacPreviewLine -Text ('Categories excluded by -SkipCategory: {0}' -f ($skip -join ', '))
        Write-WacPreviewLine -Text ''
    }

    # The SAME builder the run calls, with the same skip list. A preview that built its own list
    # would be a second description of the selection, free to drift from the one that deletes.
    $targetSet = Get-WacCleanupTargetSet -SkipCategory $skip
    $targets = @($targetSet.Target)

    if ($targets.Count -eq 0) {
        Write-WacPreviewLine -Text 'Allow-list: no target was selected.'
    }
    else {
        Write-WacPreviewLine -Text ('Allow-list: {0} target(s) would be swept.' -f $targets.Count)
        foreach ($target in ($targets | Sort-Object -Property Category, Path)) {
            $what = if ([string]$target.Mode -ceq 'Pattern') {
                'files matching {0} (no recursion)' -f [string]$target.Pattern
            }
            elseif ([bool]$target.DeleteRoot) { 'the directory and everything in it' }
            else { 'everything inside, keeping the directory' }

            Write-WacPreviewLine -Text ('  {0}' -f [string]$target.Path)
            Write-WacPreviewLine -Text ('      {0} | {1}' -f [string]$target.Category, $what)
        }
    }
    Write-WacPreviewLine -Text ''

    # An allow-list that could not be finished is the one result that must not read as "nothing to
    # clean": the same distinction the run itself makes, carried into the preview.
    $outcome = [string]$targetSet.Outcome
    if ($outcome -cne 'Succeeded') {
        Write-WacPreviewLine -Text ('The allow-list was NOT fully built ({0}), so this list is partial: {1}' -f
            $outcome, [string]$targetSet.Detail)
        Write-WacPreviewLine -Text ''
    }

    Write-WacPreviewLine -Text 'The maintenance steps cannot be listed without performing them, so only their state is shown above.'
    Write-WacPreviewLine -Text 'Run without -Preview to carry this out.'
    Write-WacPreviewLine -Text ''

    return (Write-WacRunVerdict -Outcome $(if ($outcome -ceq 'Succeeded') { 'Succeeded' } else { 'Incomplete' }))
}
