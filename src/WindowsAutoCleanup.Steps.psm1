<#
.SYNOPSIS
    The tool-driven cleanup steps: DISM, the Recycle Bin, Delivery Optimization and the optional
    legacy Disk Cleanup.

.DESCRIPTION
    Every step returns the same result shape and never throws for an expected condition, so the
    orchestrator can total them without knowing what any individual tool does:

        Category, Outcome, Attempted, Succeeded, RebootRequired, Detail, DurationMs, Skipped, Failed

    Outcome is the contract; the three booleans are DERIVED from it so callers written against the
    older shape keep working. The vocabulary is shared with the driver steps:

        Succeeded        the work ran and its post-condition holds
        SafeSkip         the work was deliberately not done, and nothing was mutated
        Incomplete       the work started and could not be finished, or its result cannot be proven
        SecurityRefusal  something the step refuses to touch was found in its way
        Failed           the work ran and failed

    A benign, expected steady state must never produce SecurityRefusal or Incomplete.

    Every external tool runs through Core's Invoke-WacProcess with a timeout taken from
    Get-WacStepTimeoutMs, so no step can outlive the run budget and none of them can be replaced by
    a PATH-resolved executable. The blocking IN-PROCESS work - the Delivery Optimization cmdlets,
    the VolumeCaches registry snapshot and restore, and the Recycle Bin scan - runs through
    Invoke-WacBounded, because a call that blocks in the OS blocks every deadline check behind it.

    Two steps are opt-in because they cannot satisfy the project's invariants by default:
    driver pruning (a wrong equivalence decision deletes a needed package) and legacy cleanmgr
    (its /sagerun profile runs against every drive on the machine).
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the CALLER's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.FileSystem.psm1') -DisableNameChecking -ErrorAction Stop

$script:DismTimeoutMs     = 1000 * 60 * 120
$script:CleanMgrTimeoutMs = 1000 * 60 * 5

# Bounds for the in-process work. They are ceilings, not expected durations: the registry snapshot
# takes milliseconds and the cache purge normally takes seconds.
$script:DeliveryOptimizationConfigTimeoutMs = 1000 * 60
$script:DeliveryOptimizationPurgeTimeoutMs  = 1000 * 60 * 10
$script:RecycleBinScanTimeoutMs             = 1000 * 60 * 5
$script:VolumeCacheRegistryTimeoutMs        = 1000 * 30

# Captured at import: inside a module $PSCommandPath is this .psm1, and Invoke-WacBounded needs a
# real path to import into the runspace it creates.
$script:StepsModulePath = $PSCommandPath

$script:BoundedInvoker = $null

$script:VolumeCacheKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'

# The 'Offline Pages Files' handler has no StateFlags value, so it is never written.
$script:DiskCleanupSkipHandler = @('Offline Pages Files')

$script:DiskCleanupCategory = @(
    'Update Cleanup'
    'Microsoft Defender'
    'Windows Defender'
    'Windows Upgrade Log Files'
    'Setup Log Files'
    'Downloaded Program Files'
    'Internet Cache Files'
    'Windows Error Reporting Files'
    'Windows Error Reporting Archive Files'
    'Windows Error Reporting Queue Files'
    'Windows Error Reporting System Archive Files'
    'Windows Error Reporting System Queue Files'
    'Windows Error Reporting Temp Files'
    'D3D Shader Cache'
    'Delivery Optimization Files'
    'Device Driver Packages'
    'Language Pack'
    'Temporary Files'
    'Thumbnail Cache'
)

function Get-WacDiskCleanupCategory {
    <#
    .SYNOPSIS
        The cleanmgr handler names this project enables when the legacy step is opted into.
    .DESCRIPTION
        Exported so the orchestrator can filter it - 'Update Cleanup' has to come out when DISM
        already handled the component store on the supported path.
    #>
    return @($script:DiskCleanupCategory)
}

function New-WacStepResult {
    <#
    .SYNOPSIS
        The single result shape every step returns.
    .DESCRIPTION
        -Outcome is the contract. Succeeded, Skipped and Failed are DERIVED from it, so a caller
        that reads only the booleans keeps working and can never see a combination the outcome
        cannot express.

        A caller that passes the booleans instead gets its own values back untouched, plus the
        Outcome those booleans describe. That path exists only so older callers keep working; new
        code passes -Outcome.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Outcome,
        [bool]$Attempted = $false,
        [bool]$Succeeded = $false,
        [bool]$RebootRequired = $false,
        [string]$Detail = '',
        [int]$DurationMs = 0,
        [bool]$Skipped = $false,
        [bool]$Failed = $false
    )

    if ($PSBoundParameters.ContainsKey('Outcome')) {
        $Succeeded = ($Outcome -ceq 'Succeeded')
        $Skipped   = ($Outcome -ceq 'SafeSkip')
        $Failed    = ($Outcome -ceq 'Failed' -or $Outcome -ceq 'Incomplete' -or $Outcome -ceq 'SecurityRefusal')
    }
    elseif ($Failed) { $Outcome = 'Failed' }
    elseif ($Skipped) { $Outcome = 'SafeSkip' }
    elseif ($Succeeded) { $Outcome = 'Succeeded' }
    else { $Outcome = 'SafeSkip' }

    return [PSCustomObject]@{
        Category       = $Category
        Outcome        = $Outcome
        Attempted      = $Attempted
        Succeeded      = $Succeeded
        RebootRequired = $RebootRequired
        Detail         = $Detail
        DurationMs     = $DurationMs
        Skipped        = $Skipped
        Failed         = $Failed
    }
}

function Write-WacStepResult {
    <#
    .SYNOPSIS
        Logs one step result at the severity its outcome deserves.
    #>
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][string]$Component
    )

    $outcome = ''
    if (@($Result.PSObject.Properties.Name) -ccontains 'Outcome') { $outcome = [string]$Result.Outcome }

    $level = 'INFO'
    if ($outcome -ceq 'SecurityRefusal') { $level = 'ERROR' }
    elseif ($Result.Failed) { $level = 'WARNING' }

    Write-WacLog -Level $level -Component $Component -Message 'Step complete.' -Data @{
        category   = $Result.Category
        outcome    = $outcome
        attempted  = $Result.Attempted
        succeeded  = $Result.Succeeded
        skipped    = $Result.Skipped
        failed     = $Result.Failed
        reboot     = $Result.RebootRequired
        durationMs = $Result.DurationMs
        detail     = $Result.Detail
    }

    return $Result
}

function Get-WacSystemToolPath {
    <#
    .SYNOPSIS
        Resolves a System32 tool by absolute path, or $null when it is absent.
    .DESCRIPTION
        Never Get-Command: PATH is extensible by a standard user, and this code runs as SYSTEM.
    #>
    param([Parameter(Mandatory = $true)][string]$Leaf)

    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) { return $null }

    $candidate = Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath $Leaf
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    return $null
}

# ---------------------------------------------------------------------------------------------
# Bounding the in-process work
# ---------------------------------------------------------------------------------------------

function Set-WacStepBoundedInvoker {
    <#
    .SYNOPSIS
        Replaces the bounded in-process runner. Pass $null to restore the real one.
    .DESCRIPTION
        The invoker receives (ScriptBlock, TimeoutMs, ArgumentList, Component, IgnoreRunBudget) and
        must return Invoke-WacBounded's shape: Outcome, Started, TimedOut, Output, HadErrors, Error,
        DurationMs.

        It exists because Invoke-WacBounded runs its block as TEXT in a fresh runspace with a fresh
        import of this module, so a stub installed in the caller's module instance is invisible in
        there - and a Delivery Optimization test whose stub is invisible purges the real cache.
        A block invoked through this seam keeps this module's session state, so a suite's function
        shadows do apply to it. Measured on both shipped hosts.
    #>
    param([scriptblock]$Invoker)
    $script:BoundedInvoker = $Invoker
}

function Invoke-WacStepBounded {
    <#
    .SYNOPSIS
        Runs one blocking in-process call under a wall-clock bound.
    .DESCRIPTION
        Keep the block down to the single blocking call and return DATA: in production it runs in
        its own runspace WITHOUT strict mode, and Write-WacLog inside it goes nowhere.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [AllowEmptyCollection()][object[]]$ArgumentList = @(),
        [string]$Component = 'Steps',
        [switch]$IgnoreRunBudget
    )

    if ($script:BoundedInvoker) {
        return (& $script:BoundedInvoker $ScriptBlock $TimeoutMs $ArgumentList $Component ([bool]$IgnoreRunBudget))
    }

    return (Invoke-WacBounded -ScriptBlock $ScriptBlock -TimeoutMs $TimeoutMs -ArgumentList $ArgumentList `
        -ImportModule @($script:StepsModulePath) -Component $Component -IgnoreRunBudget:$IgnoreRunBudget)
}

# ---------------------------------------------------------------------------------------------
# 1. DISM component store cleanup
# ---------------------------------------------------------------------------------------------

function Invoke-WacComponentCleanup {
    <#
    .SYNOPSIS
        dism.exe /Online /Cleanup-Image /StartComponentCleanup [/ResetBase] /Quiet.
    .DESCRIPTION
        /ResetBase is appended ONLY when the caller passes -ResetBase, because it makes every
        installed update permanently un-installable. The switch defaults to off, so a lost or
        mis-forwarded parameter can never turn it on.
    #>
    [CmdletBinding()]
    param([switch]$ResetBase)

    $category = 'Windows component store cleanup (DISM)'
    $component = 'Dism'

    $dism = Get-WacSystemToolPath -Leaf 'dism.exe'
    if (-not $dism) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'SafeSkip' -Detail 'dism.exe was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'SafeSkip' -Detail 'DISM /Online requires administrator rights.'))
    }

    $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:DismTimeoutMs
    if ($timeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'Incomplete' -Detail 'The run budget was exhausted before DISM could start.'))
    }

    # /Quiet is not documented for /Cleanup-Image on any current Microsoft page, though it works and
    # is required for unattended execution. It is used deliberately with that risk understood.
    $arguments = @('/Online', '/Cleanup-Image', '/StartComponentCleanup')
    if ($ResetBase) { $arguments += '/ResetBase' }
    $arguments += '/Quiet'

    if ($ResetBase) {
        Write-WacLog -Level WARNING -Component $component -Message 'ResetBase is enabled: every currently installed Windows update becomes permanently un-installable.'
    }
    Write-WacLog -Level DEBUG -Component $component -Message 'The /Quiet switch is undocumented for /Cleanup-Image.'

    $run = Invoke-WacProcess -FilePath $dism -ArgumentList $arguments -TimeoutMs $timeoutMs -Component $component

    if ($run.TimedOut) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'Incomplete' -Attempted $true -DurationMs ([int]$run.DurationMs) `
            -Detail ('DISM exceeded its {0} ms deadline and its process tree was terminated.' -f $timeoutMs)))
    }

    $exitCode = $run.ExitCode

    # There is no DISM exit-code table in current Microsoft documentation. 3010 is the generic
    # ERROR_SUCCESS_REBOOT_REQUIRED constant, so mapping it to "succeeded, reboot pending" is an
    # INFERENCE, not a documented DISM contract. 3017 is ERROR_FAIL_REBOOT_REQUIRED - a failure -
    # and must never be folded into success.
    if ($exitCode -eq 0 -or $exitCode -eq 3010) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'Succeeded' -Attempted $true `
            -RebootRequired ($exitCode -eq 3010) -DurationMs ([int]$run.DurationMs) -Detail ('dism.exe exited with {0}.' -f $exitCode)))
    }

    $detail = if ($null -eq $exitCode) { 'dism.exe did not start.' } else { 'dism.exe exited with {0}.' -f $exitCode }
    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'Failed' -Attempted $true -DurationMs ([int]$run.DurationMs) -Detail $detail))
}

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

# ---------------------------------------------------------------------------------------------
# 5. Delivery Optimization cache
# ---------------------------------------------------------------------------------------------

function Get-WacDeliveryOptimizationCacheLocation {
    <#
    .SYNOPSIS
        Where the Delivery Optimization cache actually is, resolved through the supported cmdlet.
    .DESCRIPTION
        DOModifyCacheDrive (Windows 10 1607+) "specifies the drive that Delivery Optimization should
        use for its cache", and "the drive location can be specified using environment variables,
        drive letter or using a full path", so the cache can legitimately live off C: and its
        location cannot be assumed from a registry letter. The supported way to resolve where it
        actually is, is Get-DOConfig -Verbose, whose WorkingDirectory is documented as "the local
        folder containing the Delivery Optimization cache" - hence the expansion through the
        environment before the path is normalised.

        A location that cannot be determined is NOT purged: SafeSkip is the fail-closed answer,
        because the alternative is purging a cache this run has no business touching.
    .OUTPUTS
        Outcome (Succeeded | SafeSkip | Incomplete | Failed), Path, Drive, OnTargetDrive, Detail.
    #>
    [CmdletBinding()]
    param()

    $result = [PSCustomObject]@{ Outcome = 'SafeSkip'; Path = ''; Drive = ''; OnTargetDrive = $false; Detail = '' }

    if (-not (Get-Command -Name 'Get-DOConfig' -ErrorAction SilentlyContinue)) {
        $result.Detail = 'Get-DOConfig is unavailable, so the effective cache location cannot be resolved.'
        return $result
    }

    # Resolved by NAME inside the block: in production that is the real cmdlet in a fresh runspace,
    # and under the test seam it is whatever this module's Get-Command has been shadowed to return,
    # so a test can never reach the real Delivery Optimization service.
    $configRun = Invoke-WacStepBounded -Component 'DeliveryOptimization' -TimeoutMs $script:DeliveryOptimizationConfigTimeoutMs -ScriptBlock {
        $command = Get-Command -Name 'Get-DOConfig' -ErrorAction Stop
        if (-not $command) { throw 'Get-DOConfig could not be resolved.' }

        # -Verbose is what makes Get-DOConfig report the full configuration, WorkingDirectory
        # included.
        $config = @(& $command -Verbose)
        if ($config.Count -eq 0 -or $null -eq $config[0]) { return '' }

        $property = @($config[0].PSObject.Properties | Where-Object { $_.Name -eq 'WorkingDirectory' })
        if ($property.Count -eq 0) { return '' }
        return [string]$property[0].Value
    }

    if ($configRun.Outcome -cne 'Succeeded') {
        $result.Outcome = $configRun.Outcome
        $result.Detail = 'The Delivery Optimization configuration could not be read: {0}' -f $configRun.Error
        return $result
    }

    $working = ''
    if (@($configRun.Output).Count -gt 0) { $working = [string](@($configRun.Output)[0]) }

    if ([string]::IsNullOrWhiteSpace($working)) {
        $result.Detail = 'Get-DOConfig reported no WorkingDirectory, so the effective cache location is unknown.'
        return $result
    }

    $normalized = Get-WacNormalizedPath -Path ([System.Environment]::ExpandEnvironmentVariables($working))
    if (-not $normalized) {
        $result.Detail = 'The Delivery Optimization cache location could not be normalised: {0}' -f $working
        return $result
    }

    $result.Outcome = 'Succeeded'
    $result.Path = $normalized
    $result.Drive = $normalized.Substring(0, 2)
    $result.OnTargetDrive = (Test-WacIsOnTargetDrive -Path $normalized)
    $result.Detail = 'The Delivery Optimization cache is at {0}.' -f $normalized
    return $result
}

function Clear-WacDeliveryOptimizationCache {
    <#
    .SYNOPSIS
        Purges the Delivery Optimization cache through its own cmdlet, and only on the target drive.
    .DESCRIPTION
        Delete-DeliveryOptimizationCache is the supported entry point and it coordinates with the
        service that owns the files. Its reference page is an unfilled stub published only for
        Windows Server 2025, so availability is detected at runtime rather than assumed.

        The effective cache location is resolved FIRST. Policy can move the cache to another drive,
        and this tool's headline invariant is that a default run touches the target drive only, so
        an off-drive cache is a distinct SafeSkip naming the drive rather than a silent purge.
    #>
    [CmdletBinding()]
    param()

    $category = 'Delivery Optimization cache'
    $component = 'DeliveryOptimization'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    if (-not (Get-Command -Name 'Delete-DeliveryOptimizationCache' -ErrorAction SilentlyContinue)) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'SafeSkip' `
            -Detail 'Delete-DeliveryOptimizationCache is unavailable; use the directory targets instead.'))
    }

    if (Test-WacDeadlineExpired) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'Incomplete' `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail 'The run budget was exhausted before the cache could be purged.'))
    }

    $location = Get-WacDeliveryOptimizationCacheLocation
    if ($location.Outcome -cne 'Succeeded') {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome $location.Outcome `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail $location.Detail))
    }

    if (-not $location.OnTargetDrive) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'SafeSkip' `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('The Delivery Optimization cache is on drive {0} ({1}); this run only touches drive {2}, so it was left alone.' -f $location.Drive, $location.Path, (Get-WacTargetDrive))))
    }

    $purgeRun = Invoke-WacStepBounded -Component $component -TimeoutMs $script:DeliveryOptimizationPurgeTimeoutMs -ScriptBlock {
        $command = Get-Command -Name 'Delete-DeliveryOptimizationCache' -ErrorAction Stop
        if (-not $command) { throw 'Delete-DeliveryOptimizationCache could not be resolved.' }

        # -IncludePinnedFiles is never passed: a pinned file is one the service was told to keep.
        [void](& $command -Force -ErrorAction Stop)
    }

    $stopwatch.Stop()

    if ($purgeRun.Outcome -cne 'Succeeded') {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome $purgeRun.Outcome -Attempted $true `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail ('Delete-DeliveryOptimizationCache failed: {0}' -f $purgeRun.Error)))
    }

    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome 'Succeeded' -Attempted $true `
        -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail ('Delete-DeliveryOptimizationCache completed against {0}.' -f $location.Path)))
}

# ---------------------------------------------------------------------------------------------
# 6. Legacy Disk Cleanup (opt-in, affects every drive)
# ---------------------------------------------------------------------------------------------

function Test-WacRegistryValueEqual {
    <#
    .SYNOPSIS
        Byte-for-byte comparison of two registry values, including REG_BINARY and REG_MULTI_SZ.
    #>
    param(
        [AllowNull()][AllowEmptyString()]$Expected,
        [AllowNull()][AllowEmptyString()]$Actual
    )

    if ($null -eq $Expected -or $null -eq $Actual) { return ($null -eq $Expected -and $null -eq $Actual) }

    $expectedIsArray = ($Expected -is [System.Array])
    $actualIsArray = ($Actual -is [System.Array])
    if ($expectedIsArray -ne $actualIsArray) { return $false }

    if ($expectedIsArray) {
        if ($Expected.Length -ne $Actual.Length) { return $false }
        for ($index = 0; $index -lt $Expected.Length; $index++) {
            if (-not (Test-WacRegistryValueEqual -Expected $Expected[$index] -Actual $Actual[$index])) { return $false }
        }
        return $true
    }

    # Ordinal: PowerShell's -eq is case-insensitive for strings, and a restored value that differs
    # only in case is not the value that was there before.
    if ($Expected -is [string] -and $Actual -is [string]) {
        return [string]::Equals($Expected, $Actual, [System.StringComparison]::Ordinal)
    }

    return ($Expected -eq $Actual)
}

function Get-WacRegistryValueFact {
    <#
    .SYNOPSIS
        Existence, RAW value and RegistryValueKind of one registry value, as three separate facts.
    .DESCRIPTION
        Three facts, not one: the previous code cast the value to [int] and treated a read or type
        error as absence, so a pre-existing REG_SZ was replaced by a DWORD and an unreadable value
        was DELETED by the "restore".

        DoNotExpandEnvironmentNames is what makes a REG_EXPAND_SZ round trip: without it the read
        returns the expanded text, and writing that back would silently bake the current environment
        into someone else's value.

        THROWS when the key or an existing value cannot be read. A caller that cannot read the
        original state must not mutate it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$ValueName
    )

    $key = $null
    try { $key = Get-Item -LiteralPath $KeyPath -ErrorAction Stop }
    catch { throw ('The registry key {0} could not be opened: {1}' -f $KeyPath, $_.Exception.Message) }
    if ($null -eq $key) { throw ('The registry key {0} could not be opened.' -f $KeyPath) }

    $exists = $false
    try {
        foreach ($name in @($key.GetValueNames())) {
            if ([string]::Equals([string]$name, $ValueName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $exists = $true
                break
            }
        }
    }
    catch { throw ('The value names of {0} could not be read: {1}' -f $KeyPath, $_.Exception.Message) }

    $value = $null
    $kind = $null
    if ($exists) {
        try {
            $value = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = $key.GetValueKind($ValueName)
        }
        catch { throw ('The existing {0} value of {1} could not be read: {2}' -f $ValueName, $KeyPath, $_.Exception.Message) }

        if ($null -eq $value -or $null -eq $kind) {
            throw ('The existing {0} value of {1} read back as nothing.' -f $ValueName, $KeyPath)
        }
    }

    return [PSCustomObject]@{
        KeyPath   = $KeyPath
        ValueName = $ValueName
        WasAbsent = (-not $exists)
        Value     = $value
        Kind      = $kind
    }
}

function Get-WacDiskCleanupStateFlag {
    <#
    .SYNOPSIS
        Snapshots the StateFlags<n> value of EVERY VolumeCaches handler as existence, raw value and
        RegistryValueKind.
    .DESCRIPTION
        Recording WasAbsent is what makes the restore exact rather than approximate; recording the
        KIND is what stops a pre-existing non-DWORD value from being replaced by a DWORD.

        THROWS rather than returning a partial snapshot: an original value that cannot be read
        cannot be put back, so the mutation must not start at all.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateRange(0, 9999)][int]$SageId,
        # Injectable so the snapshot/restore round trip can be proved against a scratch key instead
        # of requiring an elevated session and mutating the machine's real cleanmgr profiles.
        [string]$KeyPath = $script:VolumeCacheKeyPath
    )

    $snapshot = New-Object 'System.Collections.Generic.List[object]'
    $valueName = 'StateFlags{0:0000}' -f $SageId

    $handlers = @()
    try { $handlers = @(Get-ChildItem -LiteralPath $KeyPath -ErrorAction Stop) }
    catch { throw ('The VolumeCaches key could not be read: {0}' -f $_.Exception.Message) }

    foreach ($handler in $handlers) {
        $fact = Get-WacRegistryValueFact -KeyPath ([string]$handler.PSPath) -ValueName $valueName

        [void]$snapshot.Add([PSCustomObject]@{
            KeyPath   = $fact.KeyPath
            Name      = [string](Split-Path -Leaf $handler.Name)
            ValueName = $fact.ValueName
            WasAbsent = $fact.WasAbsent
            Value     = $fact.Value
            Kind      = $fact.Kind
        })
    }

    return @($snapshot.ToArray())
}

function Restore-WacDiskCleanupStateFlag {
    <#
    .SYNOPSIS
        Puts every StateFlags value back exactly - existence, value AND kind - and verifies each one.
    .DESCRIPTION
        The write goes through New-ItemProperty with the ORIGINAL RegistryValueKind, because the
        RegistryKey object the provider hands back is read-only on both shipped hosts (measured:
        SetValue throws "Cannot write to the registry key").

        Every entry is read back and compared before it counts as restored, so a restore that
        silently did nothing cannot be reported as success.
    .OUTPUTS
        Restored, Failed and Handler (the names that could not be put back).
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$Snapshot)

    $failedHandler = New-Object 'System.Collections.Generic.List[string]'
    $restored = 0

    foreach ($entry in @($Snapshot)) {
        if ($null -eq $entry) { continue }

        try {
            if ($entry.WasAbsent) {
                Remove-ItemProperty -LiteralPath $entry.KeyPath -Name $entry.ValueName -Force -ErrorAction SilentlyContinue
            }
            else {
                [void](New-ItemProperty -LiteralPath $entry.KeyPath -Name $entry.ValueName `
                    -PropertyType $entry.Kind -Value $entry.Value -Force -ErrorAction Stop)
            }

            $current = Get-WacRegistryValueFact -KeyPath $entry.KeyPath -ValueName $entry.ValueName
            if ($current.WasAbsent -ne $entry.WasAbsent) { throw 'the value did not read back with its original presence' }
            if (-not $entry.WasAbsent) {
                if ($current.Kind -ne $entry.Kind) { throw 'the value did not read back with its original kind' }
                if (-not (Test-WacRegistryValueEqual -Expected $entry.Value -Actual $current.Value)) {
                    throw 'the value did not read back byte for byte'
                }
            }

            $restored++
        }
        catch {
            [void]$failedHandler.Add([string]$entry.Name)
            Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'A StateFlags value could not be restored.' -Data @{
                handler = $entry.Name; error = $_.Exception.Message
            }
        }
    }

    return [PSCustomObject]@{
        Restored = $restored
        Failed   = $failedHandler.Count
        Handler  = @($failedHandler.ToArray())
    }
}

function Enable-WacDiskCleanupCategory {
    <#
    .SYNOPSIS
        Turns on the requested handlers for one sage profile.
    .DESCRIPTION
        Only 0 (off) and 2 (on) are documented values, so nothing else is ever written. The
        'Offline Pages Files' handler is skipped because it has no StateFlags value at all.

        A write that fails is COUNTED, not merely logged: a half-written profile means cleanmgr
        would run against a selection nobody chose.
    .OUTPUTS
        Touched and Failed.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateRange(0, 9999)][int]$SageId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Category,
        [string]$KeyPath = $script:VolumeCacheKeyPath
    )

    $valueName = 'StateFlags{0:0000}' -f $SageId
    $touched = 0
    $failed = 0

    foreach ($name in $Category) {
        if ($script:DiskCleanupSkipHandler -contains $name) { continue }

        $key = Join-Path -Path $KeyPath -ChildPath $name
        if (-not (Test-Path -LiteralPath $key)) { continue }

        try {
            [void](New-ItemProperty -LiteralPath $key -Name $valueName -PropertyType DWord -Value 2 -Force -ErrorAction Stop)
            $touched++
        }
        catch {
            $failed++
            Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'A StateFlags value could not be set.' -Data @{ handler = $name; error = $_.Exception.Message }
        }
    }

    return [PSCustomObject]@{ Touched = $touched; Failed = $failed }
}

function Invoke-WacLegacyDiskCleanup {
    <#
    .SYNOPSIS
        Runs cleanmgr.exe with a sage profile. Disabled by default because it is not C:-only.
    .DESCRIPTION
        Microsoft documents that /sagerun:n enumerates ALL drives in the computer and that /d is not
        used with /sagerun. The C:-only guarantee is therefore impossible here, which is why this
        step is opt-in and logs a prominent warning when it runs.

        The pre-existing StateFlags value of every handler - presence, raw value and kind - is
        snapshotted before anything is written and put back in a finally block, under its own bound
        that ignores the run budget: a rollback that is skipped because the budget expired is how
        someone else's cleanmgr profile gets destroyed.

        Outcomes: an unreadable original value is a SafeSkip, because the step declines BEFORE
        mutating anything and the machine is left exactly as it was. Once state HAS been written, a
        cleanmgr the watchdog had to kill, a handler that could not be written and a restore that
        could not be verified are all Incomplete - never the benign skip a timeout used to report.
    #>
    [CmdletBinding()]
    param(
        [switch]$Enabled,
        [ValidateRange(0, 9999)][int]$SageId = 9999,
        [AllowEmptyCollection()][string[]]$Category = $script:DiskCleanupCategory
    )

    $stepCategory = 'Disk Cleanup handlers (cleanmgr)'
    $component = 'DiskCleanup'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    if (-not $Enabled) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Outcome 'SafeSkip' `
            -Detail 'Legacy Disk Cleanup is disabled by default because /sagerun runs against every drive.'))
    }

    $cleanmgr = Get-WacSystemToolPath -Leaf 'cleanmgr.exe'
    if (-not $cleanmgr) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Outcome 'SafeSkip' -Detail 'cleanmgr.exe was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Outcome 'SafeSkip' -Detail 'Writing a cleanmgr sage profile requires administrator rights.'))
    }

    $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:CleanMgrTimeoutMs
    if ($timeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Outcome 'Incomplete' -Detail 'The run budget was exhausted before cleanmgr could start.'))
    }

    Write-WacLog -Level WARNING -Component $component -Message 'Legacy Disk Cleanup is enabled: cleanmgr /sagerun enumerates EVERY drive in this computer and /d is ignored, so this step is NOT limited to the target drive.'

    $keyPath = $script:VolumeCacheKeyPath
    $snapshot = @()
    $mutated = $false
    $attempted = $false
    $outcome = 'SafeSkip'
    $detail = ''
    $durationMs = 0

    try {
        # The key path travels as an ARGUMENT: in production the block runs in a fresh runspace
        # whose copy of this module knows nothing about a redirected key.
        $snapshotRun = Invoke-WacStepBounded -Component $component -TimeoutMs $script:VolumeCacheRegistryTimeoutMs `
            -ArgumentList @($SageId, $keyPath) -ScriptBlock {
                param($SageId, $KeyPath)
                Get-WacDiskCleanupStateFlag -SageId $SageId -KeyPath $KeyPath
            }

        if ($snapshotRun.Outcome -ceq 'Succeeded') {
            $snapshot = @($snapshotRun.Output)
        }

        if ($snapshotRun.Outcome -ceq 'Incomplete') {
            $outcome = 'Incomplete'
            $detail = 'The cleanmgr profile could not be snapshotted within its bound: {0}' -f $snapshotRun.Error
        }
        elseif ($snapshotRun.Outcome -cne 'Succeeded') {
            # Nothing has been written yet, and nothing will be: an original value that cannot be
            # read cannot be put back. Declining before the first mutation leaves the machine
            # exactly as it was, which is a safe skip and not a failed run.
            $outcome = 'SafeSkip'
            $detail = 'The existing cleanmgr profile could not be read, so nothing was changed: {0}' -f $snapshotRun.Error
        }
        elseif ($snapshot.Count -eq 0) {
            $outcome = 'SafeSkip'
            $detail = 'No VolumeCaches handlers were readable.'
            if ($snapshotRun.HadErrors) {
                $detail = 'The cleanmgr profile could not be snapshotted, so nothing was changed: {0}' -f $snapshotRun.Error
            }
        }
        else {
            $enabledResult = Enable-WacDiskCleanupCategory -SageId $SageId -Category $Category -KeyPath $keyPath
            # Touched counts values actually written, so this is "did this run change anything",
            # not "did it intend to".
            $mutated = ($enabledResult.Touched -gt 0)

            if ($enabledResult.Failed -gt 0) {
                $outcome = 'Incomplete'
                $detail = '{0} cleanmgr handler(s) could not be written, so cleanmgr was not started.' -f $enabledResult.Failed
            }
            elseif ($enabledResult.Touched -eq 0) {
                $outcome = 'SafeSkip'
                $detail = 'None of the requested cleanmgr handlers exist on this machine.'
            }
            else {
                $attempted = $true
                $run = Invoke-WacProcess -FilePath $cleanmgr -ArgumentList @(('/sagerun:{0}' -f $SageId)) -TimeoutMs $timeoutMs -Component $component
                $durationMs = [int]$run.DurationMs

                if ($run.TimedOut) {
                    # State HAS been mutated by this point, so a killed cleanmgr is an unfinished
                    # step, not the benign skip it used to report.
                    $outcome = 'Incomplete'
                    $detail = 'cleanmgr exceeded its {0} ms watchdog and its process tree was terminated.' -f $timeoutMs
                }
                elseif ($run.ExitCode -eq 0) {
                    $outcome = 'Succeeded'
                    $detail = 'cleanmgr /sagerun:{0} completed over {1} handler(s) on every drive.' -f $SageId, $enabledResult.Touched
                }
                else {
                    $outcome = 'Failed'
                    $detail = 'cleanmgr exited with {0}.' -f $run.ExitCode
                }
            }
        }
    }
    finally {
        # Only when this run actually wrote something. A step that declined still rewrote every
        # value it had snapshotted, which is a registry write nobody asked for.
        if ($mutated -and @($snapshot).Count -gt 0) {
            # -IgnoreRunBudget with its own explicit bound: the rollback still has to run when the
            # budget that stopped the work has already expired.
            $restoreRun = Invoke-WacStepBounded -Component $component -TimeoutMs $script:VolumeCacheRegistryTimeoutMs -IgnoreRunBudget `
                -ArgumentList @(, $snapshot) -ScriptBlock {
                    param($Snapshot)
                    Restore-WacDiskCleanupStateFlag -Snapshot $Snapshot
                }

            $restoreFailed = 0
            if ($restoreRun.Outcome -cne 'Succeeded') {
                $restoreFailed = @($snapshot).Count
                Write-WacLog -Level ERROR -Component $component -Message 'The cleanmgr profile restore could not be completed.' -Data @{
                    outcome = $restoreRun.Outcome; error = $restoreRun.Error
                }
            }
            else {
                $restoreResult = @($restoreRun.Output)[0]
                if ($null -eq $restoreResult) { $restoreFailed = @($snapshot).Count }
                else { $restoreFailed = [int]$restoreResult.Failed }
            }

            if ($restoreFailed -gt 0) {
                # A profile this run wrote and could not put back is the worst outcome this step
                # has, so it overrides whatever cleanmgr itself reported.
                $outcome = 'Incomplete'
                $detail = '{0} The pre-existing cleanmgr profile could not be restored for {1} handler(s).' -f $detail, $restoreFailed
            }
        }
    }

    $stopwatch.Stop()
    if ($durationMs -le 0) { $durationMs = [int]$stopwatch.Elapsed.TotalMilliseconds }

    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Outcome $outcome `
        -Attempted $attempted -DurationMs $durationMs -Detail $detail.Trim()))
}

Export-ModuleMember -Function @(
    'New-WacStepResult', 'Write-WacStepResult', 'Get-WacSystemToolPath', 'Get-WacDiskCleanupCategory',
    'Set-WacStepBoundedInvoker', 'Invoke-WacStepBounded',
    'Invoke-WacComponentCleanup',
    'Test-WacRecycleBinEntryName', 'Get-WacRecycleBinScan', 'Clear-WacRecycleBin',
    'Get-WacDeliveryOptimizationCacheLocation', 'Clear-WacDeliveryOptimizationCache',
    'Test-WacRegistryValueEqual', 'Get-WacRegistryValueFact',
    'Get-WacDiskCleanupStateFlag', 'Restore-WacDiskCleanupStateFlag', 'Enable-WacDiskCleanupCategory',
    'Invoke-WacLegacyDiskCleanup'
)
