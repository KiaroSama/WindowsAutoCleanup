<#
.SYNOPSIS
    The tool-driven cleanup steps: DISM, pnpclean, pnputil driver pruning, the Recycle Bin,
    Delivery Optimization and the optional legacy Disk Cleanup.

.DESCRIPTION
    Every step returns the same result shape and never throws for an expected condition, so the
    orchestrator can total them without knowing what any individual tool does:

        Category, Attempted, Succeeded, RebootRequired, Detail, DurationMs, Skipped, Failed

    Every external tool runs through Core's Invoke-WacProcess with a timeout taken from
    Get-WacStepTimeoutMs, so no step can outlive the run budget and none of them can be replaced by
    a PATH-resolved executable.

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
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [bool]$Attempted = $false,
        [bool]$Succeeded = $false,
        [bool]$RebootRequired = $false,
        [string]$Detail = '',
        [int]$DurationMs = 0,
        [bool]$Skipped = $false,
        [bool]$Failed = $false
    )

    return [PSCustomObject]@{
        Category       = $Category
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

    $level = if ($Result.Failed) { 'WARNING' } else { 'INFO' }

    Write-WacLog -Level $level -Component $Component -Message 'Step complete.' -Data @{
        category   = $Result.Category
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
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'dism.exe was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'DISM /Online requires administrator rights.'))
    }

    $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:DismTimeoutMs
    if ($timeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'The run budget was exhausted before DISM could start.'))
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
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Failed $true -DurationMs ([int]$run.DurationMs) -Detail ('DISM exceeded its {0} ms deadline and its process tree was terminated.' -f $timeoutMs)))
    }

    $exitCode = $run.ExitCode

    # There is no DISM exit-code table in current Microsoft documentation. 3010 is the generic
    # ERROR_SUCCESS_REBOOT_REQUIRED constant, so mapping it to "succeeded, reboot pending" is an
    # INFERENCE, not a documented DISM contract. 3017 is ERROR_FAIL_REBOOT_REQUIRED - a failure -
    # and must never be folded into success.
    if ($exitCode -eq 0 -or $exitCode -eq 3010) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Succeeded $true `
            -RebootRequired ($exitCode -eq 3010) -DurationMs ([int]$run.DurationMs) -Detail ('dism.exe exited with {0}.' -f $exitCode)))
    }

    $detail = if ($null -eq $exitCode) { 'dism.exe did not start.' } else { 'dism.exe exited with {0}.' -f $exitCode }
    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Failed $true -DurationMs ([int]$run.DurationMs) -Detail $detail))
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

function Get-WacRecycleBinItem {
    <#
    .SYNOPSIS
        Every deletable entry inside the per-SID Recycle Bin directories on the target drive.
    .DESCRIPTION
        The C:\$Recycle.Bin\<SID> layout, the $I/$R metadata-plus-content pair and desktop.ini are
        described in NO Microsoft reference page - community Q&A only. Deletion is therefore
        restricted to entries whose leaf name begins with $I or $R: the per-SID directory itself and
        desktop.ini are never returned, so they can never be deleted.

        This is also the post-condition probe. Measuring and deleting through one predicate is the
        point: the previous code enumerated every SID directory but deleted only the calling
        identity's bin, so under SYSTEM it reported success for a scope it had never touched.
    #>
    param([string]$Root = ((Get-WacTargetDrive) + '\$Recycle.Bin'))

    $items = New-Object 'System.Collections.Generic.List[object]'

    $normalizedRoot = Get-WacNormalizedPath -Path $Root
    if (-not $normalizedRoot -or -not (Test-Path -LiteralPath $normalizedRoot -PathType Container)) { return @() }

    try {
        $sidDirectories = @(Get-ChildItem -LiteralPath $normalizedRoot -Directory -Force -ErrorAction Stop)
    }
    catch {
        # An empty bin and an unreadable bin both used to come back as @(), so a run that could not
        # look at the Recycle Bin at all reported Succeeded. Throwing here lets Clear-WacRecycleBin
        # tell the two apart and report the second as a failure instead of a clean sweep.
        Write-WacLog -Level WARNING -Component 'RecycleBin' -Message 'The Recycle Bin root could not be enumerated.' -Data @{ path = $normalizedRoot; error = $_.Exception.Message }
        throw ('The Recycle Bin root could not be enumerated: {0}' -f $_.Exception.Message)
    }

    foreach ($sidDirectory in $sidDirectories) {
        if ($sidDirectory.Name -notmatch '^S-\d+-\d+') { continue }
        if (($sidDirectory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }

        $sidPath = Get-WacNormalizedPath -Path $sidDirectory.FullName
        if (-not $sidPath) { continue }

        try {
            $entries = @(Get-ChildItem -LiteralPath $sidPath -Force -ErrorAction Stop)
        }
        catch {
            Write-WacLog -Level DEBUG -Component 'RecycleBin' -Message 'A per-SID Recycle Bin directory could not be enumerated.' -Data @{ path = $sidPath; error = $_.Exception.Message }
            continue
        }

        foreach ($entry in $entries) {
            if (-not (Test-WacRecycleBinEntryName -Name $entry.Name)) { continue }

            $entryPath = Get-WacNormalizedPath -Path $entry.FullName
            if (-not $entryPath -or -not (Test-WacIsWithinRoot -ChildPath $entryPath -RootPath $sidPath)) { continue }

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

    return @($items.ToArray())
}

function Clear-WacRecycleBin {
    <#
    .SYNOPSIS
        Empties every user's Recycle Bin on the target drive.
    .DESCRIPTION
        Clear-RecycleBin deletes the content of the CURRENT USER's recycle bin only, so under a
        SYSTEM scheduled task it reclaimed nearly nothing while still logging success. There is no
        documented supported way for SYSTEM to empty every user's bin, so this sweeps the on-disk
        layout directly and reports what it actually removed.
    #>
    [CmdletBinding()]
    param([string]$Root = ((Get-WacTargetDrive) + '\$Recycle.Bin'))

    $category = 'Recycle Bin (drive {0} only)' -f (Get-WacTargetDrive)
    $component = 'RecycleBin'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # An unreadable Recycle Bin root is not an empty one. Reporting a clean sweep for a scope that
    # was never measured is exactly the false-success shape this step was rewritten to remove.
    $before = @()
    try {
        $before = @(Get-WacRecycleBinItem -Root $Root)
    }
    catch {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Failed $true `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail ('The Recycle Bin could not be enumerated: {0}' -f $_.Exception.Message)))
    }

    if ($before.Count -eq 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Succeeded $true `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail 'No Recycle Bin entries were present.'))
    }

    $stats = New-WacDeletionStats
    $bytes = 0L

    foreach ($item in $before) {
        if (Test-WacDeadlineExpired) {
            $stats.SkippedDeadline++
            break
        }

        if ($item.IsReparsePoint) {
            Remove-WacLeaf -Path $item.Path -RootPath $item.SidPath -Stats $stats -IsDirectory:$item.IsDirectory -IsReparsePoint -NoPendingDelete
            continue
        }

        if ($item.IsDirectory) {
            # A recycled folder is a $R directory with its original contents inside it. Remove-WacTree
            # applies the same leaf primitive to every child, so reparse points and locked files are
            # handled identically to the file case.
            $treeResult = Remove-WacTree -Category $category -Path $item.Path -DeleteRoot
            $stats.FilesDeleted += $treeResult.FilesDeleted
            $stats.DirectoriesDeleted += $treeResult.DirectoriesDeleted
            $stats.ReparsePointsDeleted += $treeResult.ReparsePointsDeleted
            $stats.PendingDeletes += $treeResult.PendingDeletes
            $stats.Failed += $treeResult.Failed
            $bytes += $treeResult.BytesDeleted
            continue
        }

        Remove-WacLeaf -Path $item.Path -RootPath $item.SidPath -Stats $stats -Length $item.Length
    }

    $bytes += $stats.BytesDeleted
    $after = @(Get-WacRecycleBinItem -Root $Root)
    $stopwatch.Stop()

    $detail = 'before={0} after={1} files={2} dirs={3} freed={4}' -f `
        $before.Count, $after.Count, $stats.FilesDeleted, $stats.DirectoriesDeleted, (Format-WacBytes -Bytes $bytes)

    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true `
        -Succeeded ($after.Count -eq 0) -Failed ($stats.Failed -gt 0) `
        -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail $detail))
}

# ---------------------------------------------------------------------------------------------
# 5. Delivery Optimization cache
# ---------------------------------------------------------------------------------------------

function Clear-WacDeliveryOptimizationCache {
    <#
    .SYNOPSIS
        Purges the Delivery Optimization cache through its own cmdlet.
    .DESCRIPTION
        Delete-DeliveryOptimizationCache is the supported entry point and it coordinates with the
        service that owns the files. Its reference page is an unfilled stub published only for
        Windows Server 2025, so availability is detected at runtime rather than assumed.

        When the cmdlet is absent this returns Skipped, and the caller should fall back to the
        Delivery Optimization directory targets. The cache path itself is undocumented and can be
        relocated off C: by DOModifyCacheDrive, which is exactly why the cmdlet is preferred.
    #>
    [CmdletBinding()]
    param()

    $category = 'Delivery Optimization cache'
    $component = 'DeliveryOptimization'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $command = Get-Command -Name 'Delete-DeliveryOptimizationCache' -ErrorAction SilentlyContinue
    if (-not $command) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true `
            -Detail 'Delete-DeliveryOptimizationCache is unavailable; use the directory targets instead.'))
    }

    if (Test-WacDeadlineExpired) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'The run budget was exhausted before the cmdlet could run.'))
    }

    try {
        # An in-process cmdlet cannot be watchdogged the way Invoke-WacProcess bounds a child
        # process; the deadline check above is the only bound available without hosting it out of
        # process, which its own service coordination would not survive.
        [void](& $command -Force -ErrorAction Stop)
    }
    catch {
        $stopwatch.Stop()
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Failed $true `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail ('Delete-DeliveryOptimizationCache failed: {0}' -f $_.Exception.Message)))
    }

    $stopwatch.Stop()
    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Succeeded $true `
        -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail 'Delete-DeliveryOptimizationCache completed.'))
}

# ---------------------------------------------------------------------------------------------
# 6. Legacy Disk Cleanup (opt-in, affects every drive)
# ---------------------------------------------------------------------------------------------

function Get-WacDiskCleanupStateFlag {
    <#
    .SYNOPSIS
        Snapshots the StateFlags<n> value of EVERY VolumeCaches handler, including absent ones.
    .DESCRIPTION
        The previous code deleted the value from every handler afterwards, which destroyed any
        profile another tool or the user had already configured under the same id. Recording
        WasAbsent is what makes the restore exact rather than approximate.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateRange(0, 9999)][int]$SageId,
        # Injectable so the snapshot/restore round trip can be proved against a scratch key instead
        # of requiring an elevated session and mutating the machine's real cleanmgr profiles.
        [string]$KeyPath = $script:VolumeCacheKeyPath
    )

    $snapshot = New-Object 'System.Collections.Generic.List[object]'
    $valueName = 'StateFlags{0:0000}' -f $SageId

    try {
        $handlers = @(Get-ChildItem -LiteralPath $KeyPath -ErrorAction Stop)
    }
    catch {
        Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'The VolumeCaches key could not be read.' -Data @{ error = $_.Exception.Message }
        return @()
    }

    foreach ($handler in $handlers) {
        $value = $null
        $wasAbsent = $true
        try {
            $property = Get-ItemProperty -LiteralPath $handler.PSPath -Name $valueName -ErrorAction Stop
            $value = [int]$property.$valueName
            $wasAbsent = $false
        }
        catch {
            $wasAbsent = $true
        }

        [void]$snapshot.Add([PSCustomObject]@{
            KeyPath   = [string]$handler.PSPath
            Name      = [string](Split-Path -Leaf $handler.Name)
            ValueName = $valueName
            WasAbsent = $wasAbsent
            Value     = $value
        })
    }

    return @($snapshot.ToArray())
}

function Restore-WacDiskCleanupStateFlag {
    <#
    .SYNOPSIS
        Puts every StateFlags value back exactly as the snapshot found it.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$Snapshot)

    if (-not $Snapshot) { return 0 }

    $restored = 0
    foreach ($entry in $Snapshot) {
        try {
            if ($entry.WasAbsent) {
                Remove-ItemProperty -LiteralPath $entry.KeyPath -Name $entry.ValueName -ErrorAction SilentlyContinue
            }
            else {
                [void](New-ItemProperty -LiteralPath $entry.KeyPath -Name $entry.ValueName -PropertyType DWord -Value $entry.Value -Force -ErrorAction Stop)
            }
            $restored++
        }
        catch {
            Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'A StateFlags value could not be restored.' -Data @{ handler = $entry.Name; error = $_.Exception.Message }
        }
    }

    return $restored
}

function Enable-WacDiskCleanupCategory {
    <#
    .SYNOPSIS
        Turns on the requested handlers for one sage profile. Returns how many were written.
    .DESCRIPTION
        Only 0 (off) and 2 (on) are documented values, so nothing else is ever written. The
        'Offline Pages Files' handler is skipped because it has no StateFlags value at all.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateRange(0, 9999)][int]$SageId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Category,
        [string]$KeyPath = $script:VolumeCacheKeyPath
    )

    $valueName = 'StateFlags{0:0000}' -f $SageId
    $touched = 0

    foreach ($name in $Category) {
        if ($script:DiskCleanupSkipHandler -contains $name) { continue }

        $key = Join-Path -Path $KeyPath -ChildPath $name
        if (-not (Test-Path -LiteralPath $key)) { continue }

        try {
            [void](New-ItemProperty -LiteralPath $key -Name $valueName -PropertyType DWord -Value 2 -Force -ErrorAction Stop)
            $touched++
        }
        catch {
            Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'A StateFlags value could not be set.' -Data @{ handler = $name; error = $_.Exception.Message }
        }
    }

    return $touched
}

function Invoke-WacLegacyDiskCleanup {
    <#
    .SYNOPSIS
        Runs cleanmgr.exe with a sage profile. Disabled by default because it is not C:-only.
    .DESCRIPTION
        Microsoft documents that /sagerun:n enumerates ALL drives in the computer and that /d is not
        used with /sagerun. The C:-only guarantee is therefore impossible here, which is why this
        step is opt-in and logs a prominent warning when it runs.

        The pre-existing StateFlags values of every handler are snapshotted before the profile is
        written and restored exactly - including "was absent" - in a finally block.
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
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Skipped $true `
            -Detail 'Legacy Disk Cleanup is disabled by default because /sagerun runs against every drive.'))
    }

    $cleanmgr = Get-WacSystemToolPath -Leaf 'cleanmgr.exe'
    if (-not $cleanmgr) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Skipped $true -Detail 'cleanmgr.exe was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Skipped $true -Detail 'Writing a cleanmgr sage profile requires administrator rights.'))
    }

    $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:CleanMgrTimeoutMs
    if ($timeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Skipped $true -Detail 'The run budget was exhausted before cleanmgr could start.'))
    }

    Write-WacLog -Level WARNING -Component $component -Message 'Legacy Disk Cleanup is enabled: cleanmgr /sagerun enumerates EVERY drive in this computer and /d is ignored, so this step is NOT limited to the target drive.'

    $snapshot = @()
    $result = $null

    try {
        $snapshot = @(Get-WacDiskCleanupStateFlag -SageId $SageId)
        if ($snapshot.Count -eq 0) {
            return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Skipped $true -Detail 'No VolumeCaches handlers were readable.'))
        }

        $touched = Enable-WacDiskCleanupCategory -SageId $SageId -Category $Category
        if ($touched -eq 0) {
            return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $stepCategory -Skipped $true -Detail 'None of the requested cleanmgr handlers exist on this machine.'))
        }

        $run = Invoke-WacProcess -FilePath $cleanmgr -ArgumentList @(('/sagerun:{0}' -f $SageId)) -TimeoutMs $timeoutMs -Component $component

        if ($run.TimedOut) {
            # A killed cleanmgr has done whatever it managed before the watchdog fired. That is an
            # incomplete legacy step, not a failed run: DISM and the allow-list are authoritative.
            $result = New-WacStepResult -Category $stepCategory -Attempted $true -Skipped $true -DurationMs ([int]$run.DurationMs) `
                -Detail ('cleanmgr exceeded its {0} ms watchdog and its process tree was terminated.' -f $timeoutMs)
        }
        elseif ($run.ExitCode -eq 0) {
            $result = New-WacStepResult -Category $stepCategory -Attempted $true -Succeeded $true -DurationMs ([int]$run.DurationMs) `
                -Detail ('cleanmgr /sagerun:{0} completed over {1} handler(s) on every drive.' -f $SageId, $touched)
        }
        else {
            $result = New-WacStepResult -Category $stepCategory -Attempted $true -Failed $true -DurationMs ([int]$run.DurationMs) `
                -Detail ('cleanmgr exited with {0}.' -f $run.ExitCode)
        }
    }
    finally {
        [void](Restore-WacDiskCleanupStateFlag -Snapshot $snapshot)
    }

    $stopwatch.Stop()
    return (Write-WacStepResult -Component $component -Result $result)
}

Export-ModuleMember -Function @(
    'New-WacStepResult', 'Write-WacStepResult', 'Get-WacSystemToolPath', 'Get-WacDiskCleanupCategory',
    'Invoke-WacComponentCleanup',
    'Test-WacRecycleBinEntryName', 'Get-WacRecycleBinItem', 'Clear-WacRecycleBin',
    'Clear-WacDeliveryOptimizationCache',
    'Get-WacDiskCleanupStateFlag', 'Restore-WacDiskCleanupStateFlag', 'Enable-WacDiskCleanupCategory',
    'Invoke-WacLegacyDiskCleanup'
)
