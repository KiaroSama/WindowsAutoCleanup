<#
.SYNOPSIS
    The Recycle Bin sweep: every user's bin on the target drive, and the post-condition that proves
    it.

.DESCRIPTION
    One responsibility, one predicate. Test-WacRecycleBinEntryName decides what may be deleted,
    Get-WacRecycleBinScan measures with it and Clear-WacRecycleBin deletes with it and then measures
    again with it, so nothing here can report a clean sweep over a scope it did not look at.

    Split out of WindowsAutoCleanup.Steps.psm1, which imports this module and re-exports it, so
    importing the package entry point still resolves all three names.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the CALLER's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.FileSystem.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.StepContract.psm1') -DisableNameChecking -ErrorAction Stop

# A bound for the in-process work. It is a ceiling, not an expected duration.
$script:RecycleBinScanTimeoutMs = 1000 * 60 * 5

# ---------------------------------------------------------------------------------------------
# 4. Recycle Bin
# ---------------------------------------------------------------------------------------------

function Test-WacRecycleBinEntryName {
    <#
    .SYNOPSIS
        The single predicate that decides whether a Recycle Bin entry may be deleted.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)

    return ($Name.StartsWith('$I', [System.StringComparison]::OrdinalIgnoreCase) -or
            $Name.StartsWith('$R', [System.StringComparison]::OrdinalIgnoreCase))
}

function Get-WacRecycleBinScan {
    <#
    .SYNOPSIS
        Every deletable entry inside the per-SID Recycle Bin directories on the target drive, plus
        the per-SID directories that could not be read and the ones that were refused.
    .DESCRIPTION
        The C:\$Recycle.Bin\<SID> layout, the $I/$R metadata-plus-content pair and desktop.ini are
        described in NO Microsoft reference page - community Q&A only. Deletion is therefore
        restricted to entries whose leaf name begins with $I or $R: the per-SID directory itself and
        desktop.ini are never returned, so they can never be deleted.

        The scope is every user's bin on the target drive, which is what the SYSTEM task needs:
        Clear-RecycleBin empties the CALLING identity's bin only, so under SYSTEM it reclaimed
        nothing while logging success.

        A per-SID directory that cannot be enumerated, or that is a reparse point, is RECORDED
        rather than dropped in silence. Dropping it is how a run that never looked at half the bins
        reported a clean sweep. Measured on this project's reference machine: a per-SID directory
        grants SYSTEM, BUILTIN\Administrators and the owning user Full Control, so an elevated run -
        the only kind this tool performs - reads every one of them, and an unreadable one is a real
        anomaly rather than a benign steady state. Unelevated, every OTHER user's directory is
        denied, which is one more reason the run refuses to start without administrator rights.

        This is also the post-condition probe. Measuring and deleting through one predicate is the
        point.
    .OUTPUTS
        Root, Item, Unreadable and Refused.
    #>
    param([string]$Root = ((Get-WacTargetDrive) + '\$Recycle.Bin'))

    $items = New-Object 'System.Collections.Generic.List[object]'
    $unreadable = New-Object 'System.Collections.Generic.List[string]'
    $refused = New-Object 'System.Collections.Generic.List[string]'

    $normalizedRoot = Get-WacNormalizedPath -Path $Root
    if (-not $normalizedRoot -or -not (Test-Path -LiteralPath $normalizedRoot -PathType Container)) {
        return [PSCustomObject]@{ Root = [string]$Root; Item = @(); Unreadable = @(); Refused = @() }
    }

    try {
        $sidDirectories = @(Get-ChildItem -LiteralPath $normalizedRoot -Directory -Force -ErrorAction Stop)
    }
    catch {
        # An empty bin and an unreadable bin both used to come back as @(), so a run that could not
        # look at the Recycle Bin at all reported Succeeded. Throwing here lets Clear-WacRecycleBin
        # tell the two apart and report the second as a failure instead of a clean sweep.
        throw ('The Recycle Bin root could not be enumerated: {0}' -f $_.Exception.Message)
    }

    foreach ($sidDirectory in $sidDirectories) {
        if ($sidDirectory.Name -notmatch '^S-\d+-\d+') { continue }

        if (($sidDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            [void]$refused.Add(('a per-SID directory is a reparse point: {0}' -f $sidDirectory.FullName))
            continue
        }

        $sidPath = Get-WacNormalizedPath -Path $sidDirectory.FullName
        if (-not $sidPath) {
            [void]$refused.Add(('a per-SID directory would not canonicalise: {0}' -f $sidDirectory.FullName))
            continue
        }

        try {
            $entries = @(Get-ChildItem -LiteralPath $sidPath -Force -ErrorAction Stop)
        }
        catch {
            [void]$unreadable.Add(('{0}: {1}' -f $sidPath, $_.Exception.Message))
            continue
        }

        foreach ($entry in $entries) {
            if (-not (Test-WacRecycleBinEntryName -Name $entry.Name)) { continue }

            $entryPath = Get-WacNormalizedPath -Path $entry.FullName
            if (-not $entryPath -or -not (Test-WacIsWithinRoot -ChildPath $entryPath -RootPath $sidPath)) {
                [void]$refused.Add(('an entry resolved outside its own per-SID directory: {0}' -f $entry.FullName))
                continue
            }

            $attributes = 0
            try { $attributes = [int]$entry.Attributes } catch { $attributes = 0 }

            $length = 0L
            if ($entry -is [System.IO.FileInfo]) {
                try { $length = [int64]$entry.Length } catch { $length = 0L }
            }

            [void]$items.Add([PSCustomObject]@{
                Path           = $entryPath
                SidPath        = $sidPath
                IsDirectory    = ($entry -is [System.IO.DirectoryInfo])
                IsReparsePoint = (($attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0)
                Length         = $length
            })
        }
    }

    return [PSCustomObject]@{
        Root       = [string]$normalizedRoot
        Item       = @($items.ToArray())
        Unreadable = @($unreadable.ToArray())
        Refused    = @($refused.ToArray())
    }
}

function Clear-WacRecycleBin {
    <#
    .SYNOPSIS
        Empties every user's Recycle Bin on the target drive and proves the post-condition.
    .DESCRIPTION
        Both scans run bounded, because enumerating a bin on a sick disk blocks in the OS and no
        cooperative deadline check behind it would ever run.

        Outcomes: a refused per-SID directory or a refused deletion is a SecurityRefusal; an
        unreadable per-SID directory, a deadline stop, or a residue with a recorded reason is
        Incomplete; a failed deletion, or a residue nothing accounts for, is Failed. Nothing here
        reports Succeeded for a scope it did not measure.
    #>
    [CmdletBinding()]
    param([string]$Root = ((Get-WacTargetDrive) + '\$Recycle.Bin'))

    $category = 'Recycle Bin (drive {0} only)' -f (Get-WacTargetDrive)
    $component = 'RecycleBin'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $scanBlock = {
        param($BinRoot)
        Get-WacRecycleBinScan -Root $BinRoot
    }

    $scanRun = Invoke-WacStepBounded -ScriptBlock $scanBlock -TimeoutMs $script:RecycleBinScanTimeoutMs `
        -ArgumentList @($Root) -Component $component

    if ($scanRun.Outcome -cne 'Succeeded') {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome $scanRun.Outcome -Attempted $true `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail ('The Recycle Bin could not be enumerated: {0}' -f $scanRun.Error)))
    }

    # A bounded block that writes a NON-terminating error comes back Succeeded with no output at
    # all - that is Invoke-WacBounded's documented contract, and the caller is the one that has to
    # decide. Nothing measured means nothing proven, which is Incomplete and never an empty bin.
    $scan = $null
    if (@($scanRun.Output).Count -gt 0) { $scan = @($scanRun.Output)[0] }
    if ($null -eq $scan) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'Incomplete' -Attempted $true `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail ('The Recycle Bin scan returned nothing: {0}' -f $scanRun.Error)))
    }

    $before = @($scan.Item)

    $stats = New-WacDeletionStats
    $bytes = 0L
    $deadlineStopped = $false
    $after = $null

    foreach ($item in $before) {
        if (Test-WacDeadlineExpired) {
            $stats.SkippedDeadline++
            $deadlineStopped = $true
            break
        }

        if ($item.IsReparsePoint) {
            # -NoPendingDelete is gone with delayed deletion itself: nothing verified at
            # registration time binds the name Session Manager resolves at the next boot.
            Remove-WacLeaf -Path $item.Path -RootPath $item.SidPath -Stats $stats -IsDirectory:$item.IsDirectory -IsReparsePoint
            continue
        }

        if ($item.IsDirectory) {
            # A recycled folder is a $R directory with its original contents inside it.
            # Remove-WacTree applies the same leaf primitive to every child, so reparse points and
            # locked files are handled identically to the file case.
            $treeResult = Remove-WacTree -Category $category -Path $item.Path -DeleteRoot
            $stats.FilesDeleted += $treeResult.FilesDeleted
            $stats.DirectoriesDeleted += $treeResult.DirectoriesDeleted
            $stats.ReparsePointsDeleted += $treeResult.ReparsePointsDeleted
            $stats.PendingDeletes += $treeResult.PendingDeletes
            $stats.Failed += $treeResult.Failed
            $stats.SkippedLocked += $treeResult.SkippedLocked
            $stats.SkippedDenied += $treeResult.SkippedDenied
            $stats.SkippedNotEmpty += $treeResult.SkippedNotEmpty
            $stats.SkippedVanished += $treeResult.SkippedVanished
            $stats.SkippedDeadline += $treeResult.SkippedDeadline
            if ($treeResult.SkippedDeadline -gt 0) { $deadlineStopped = $true }
            # A refusal raised inside a recycled FOLDER would otherwise be dropped here and could
            # never reach the exit code, which is the one signal it exists to raise.
            $stats.RefusedIdentity += $treeResult.RefusedIdentity
            $stats.RefusedOutOfRoot += $treeResult.RefusedOutOfRoot
            $bytes += $treeResult.BytesDeleted
            continue
        }

        Remove-WacLeaf -Path $item.Path -RootPath $item.SidPath -Stats $stats -Length $item.Length
    }

    $bytes += $stats.BytesDeleted

    if ($before.Count -gt 0) {
        # The post-condition is measured with the SAME predicate the enumeration used, and under the
        # same bound. An unprovable post-condition is Incomplete, never a clean sweep.
        $afterRun = Invoke-WacStepBounded -ScriptBlock $scanBlock -TimeoutMs $script:RecycleBinScanTimeoutMs `
            -ArgumentList @($Root) -Component $component

        if ($afterRun.Outcome -cne 'Succeeded') {
            $stopwatch.Stop()
            return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'Incomplete' -Attempted $true `
                -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail ('The sweep could not be verified: {0}' -f $afterRun.Error)))
        }

        if (@($afterRun.Output).Count -gt 0) { $after = @($afterRun.Output)[0] }
        if ($null -eq $after) {
            $stopwatch.Stop()
            return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'Incomplete' -Attempted $true `
                -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
                -Detail ('The sweep could not be verified: the post-condition probe returned nothing. {0}' -f $afterRun.Error)))
        }
    }

    $unreadable = New-Object 'System.Collections.Generic.List[string]'
    $refused = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in @($scan.Unreadable)) { [void]$unreadable.Add([string]$entry) }
    foreach ($entry in @($scan.Refused)) { [void]$refused.Add([string]$entry) }
    if ($after) {
        foreach ($entry in @($after.Unreadable)) { [void]$unreadable.Add([string]$entry) }
        foreach ($entry in @($after.Refused)) { [void]$refused.Add([string]$entry) }
    }
    if ($stats.RefusedIdentity -gt 0) { [void]$refused.Add('a deletion was refused by the identity re-check') }
    if ($stats.RefusedOutOfRoot -gt 0) { [void]$refused.Add('a deletion was refused because the path left its root') }

    $remaining = 0
    if ($after) { $remaining = @($after.Item).Count }

    # Anything that legitimately explains a residue: the deadline, or a leaf the filesystem would
    # not give up. A residue with no such explanation means the purge claim is simply false.
    $explained = ($deadlineStopped -or $stats.SkippedLocked -gt 0 -or $stats.SkippedDenied -gt 0 -or
                  $stats.SkippedNotEmpty -gt 0 -or $stats.SkippedVanished -gt 0 -or $stats.PendingDeletes -gt 0)

    # Assigned in precedence order, so the last one that applies wins:
    # SecurityRefusal beats Failed beats Incomplete.
    $outcome = 'Succeeded'
    if ($deadlineStopped -or $unreadable.Count -gt 0 -or ($remaining -gt 0 -and $explained)) { $outcome = 'Incomplete' }
    if ($stats.Failed -gt 0 -or ($remaining -gt 0 -and -not $explained)) { $outcome = 'Failed' }
    if ($refused.Count -gt 0) { $outcome = 'SecurityRefusal' }

    if ($unreadable.Count -gt 0) {
        Write-WacLog -Level WARNING -Component $component -Message 'A per-SID Recycle Bin directory could not be read, so this sweep did not cover every user.' -Data @{
            count = $unreadable.Count; first = $unreadable[0]
        }
    }
    if ($refused.Count -gt 0) {
        Write-WacLog -Level ERROR -Component $component -Message 'A Recycle Bin location was refused.' -Data @{
            count = $refused.Count; first = $refused[0]
        }
    }

    $stopwatch.Stop()

    $detail = 'before={0} after={1} files={2} dirs={3} freed={4} unreadableSid={5} refused={6}' -f `
        $before.Count, $remaining, $stats.FilesDeleted, $stats.DirectoriesDeleted, (Format-WacBytes -Bytes $bytes), $unreadable.Count, $refused.Count

    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome $outcome -Attempted $true `
        -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail $detail))
}

Export-ModuleMember -Function @(
    'Test-WacRecycleBinEntryName', 'Get-WacRecycleBinScan', 'Clear-WacRecycleBin'
)
