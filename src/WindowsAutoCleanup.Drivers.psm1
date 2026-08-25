<#
.SYNOPSIS
    Driver-store cleanup: the Windows pnpclean handler and opt-in superseded-package pruning.

.DESCRIPTION
    Split out of WindowsAutoCleanup.Steps.psm1 because the driver store is its own domain with its
    own risk profile: everything here talks to the pnp subsystem and can remove a package the
    machine still needs. Keeping it separate means the riskiest code in the project can be reviewed
    and tested on its own.

    The structured pnputil output IS documented. 'create-a-driver-inventory' (ms.date 2025-11-15)
    documents /format and /output-file for /enum-drivers and publishes the device-association
    predicate this module deletes on:

        [xml] $out = pnputil /enum-drivers /devices /format xml
        $out.pnputil.driver | where {$_.devices.count -eq 0}

    The same page says "Don't use scripts to process the default output or the 'text' /format option
    since that output can change and is localized", which is why the localized text output is never
    parsed here - not even as a fallback. The pnputil syntax reference still lists /format only under
    /enum-containers, so the two pages disagree about AVAILABILITY: this module feature-detects the
    structured output at run time instead of trusting either page's version table.

    Microsoft's driver-store documentation also states that staged files "shouldn't be removed or
    modified in any way", and there is no reference page for pnpclean.dll at all. Both mechanisms are
    therefore best-effort, and package pruning stays off unless the caller opts in.

    The implementation lives in the WindowsAutoCleanup.Driver*.ps1 files beside this one, one per
    responsibility, and they are DOT-SOURCED rather than imported, for the reason Core.psm1 records
    at length: a nested Import-Module gives each part its own session state, so a part could neither
    call another part reliably nor see its $script: state. This file keeps the pnputil contract - the
    enumeration command and its exit-code classes - the pnpclean handler, and the pruning step.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the CALLER's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.FileSystem.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Steps.psm1') -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DriverInventory.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DriverBackup.ps1')

$script:PnpCleanTimeoutMs = 1000 * 60 * 120
$script:PnpUtilTimeoutMs  = 1000 * 60 * 2

# pnputil documents 0, 3010 (ERROR_SUCCESS_REBOOT_REQUIRED) and 1641 (ERROR_SUCCESS_REBOOT_INITIATED)
# as success; 259 (ERROR_NO_MORE_ITEMS) is benign. The documented list is explicitly partial, so
# treating every other non-zero code as a hard failure would manufacture false failures.
$script:PnpUtilSuccessCode = @(0, 3010, 1641)
$script:PnpUtilBenignCode  = @(259)
$script:PnpUtilRebootCode  = @(3010, 1641)

# The one enumeration this module runs. /devices is what turns the output from "these two packages
# look alike" into "this package is installed on nothing", which is the only evidence a deletion may
# rest on.
$script:PnpUtilEnumArgument = @('/enum-drivers', '/devices', '/format', 'xml')

# Run-level precedence: SecurityRefusal beats Failed beats Incomplete beats a clean outcome.
$script:OutcomeRank = @{ 'Succeeded' = 0; 'SafeSkip' = 0; 'Incomplete' = 1; 'Failed' = 2; 'SecurityRefusal' = 3 }

function Get-WacHigherOutcome {
    <#
    .SYNOPSIS
        The higher-precedence of two outcomes. Pure.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Current,
        [Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Candidate
    )

    if ($script:OutcomeRank[$Candidate] -gt $script:OutcomeRank[$Current]) { return $Candidate }
    return $Current
}

function New-WacDriverStepResult {
    <#
    .SYNOPSIS
        New-WacStepResult expressed in the five-outcome vocabulary.
    .DESCRIPTION
        Succeeded / SafeSkip / Incomplete / SecurityRefusal / Failed is the shared contract, and the
        Succeeded + Skipped + Failed booleans are derived from it. New-WacStepResult is gaining
        -Outcome in another module; until that lands this bridge derives the booleans itself, and it
        always guarantees the returned object carries .Outcome so callers and tests read one
        vocabulary either way.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Outcome,
        [string]$Detail = '',
        [int]$DurationMs = 0,
        [bool]$Attempted = $false,
        [bool]$RebootRequired = $false
    )

    $argument = @{
        Category       = $Category
        Detail         = $Detail
        DurationMs     = $DurationMs
        Attempted      = $Attempted
        RebootRequired = $RebootRequired
    }

    if ((Get-Command -Name 'New-WacStepResult' -ErrorAction Stop).Parameters.ContainsKey('Outcome')) {
        $argument['Outcome'] = $Outcome
    }
    else {
        $argument['Succeeded'] = ($Outcome -eq 'Succeeded')
        $argument['Skipped']   = ($Outcome -eq 'SafeSkip')
        $argument['Failed']    = ($Outcome -eq 'Failed' -or $Outcome -eq 'Incomplete' -or $Outcome -eq 'SecurityRefusal')
    }

    $result = New-WacStepResult @argument
    if (-not (@($result.PSObject.Properties.Name) -ccontains 'Outcome')) {
        Add-Member -InputObject $result -MemberType NoteProperty -Name 'Outcome' -Value $Outcome
    }

    return $result
}

# ---------------------------------------------------------------------------------------------
# 2. pnpclean driver package handler
# ---------------------------------------------------------------------------------------------

function Get-WacDriverStoreSize {
    <#
    .SYNOPSIS
        File count and byte total of the driver store FileRepository.
    .DESCRIPTION
        This walks a very large tree, so it is only ever called when the caller explicitly asks for
        the measurement: taking it before AND after every pnpclean run cost real minutes for a
        diagnostic number nothing depended on.
    #>
    $repository = $null
    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $repository = Join-Path -Path $env:SystemRoot -ChildPath 'System32\DriverStore\FileRepository'
    }

    $result = [PSCustomObject]@{ Path = $repository; Files = 0L; Bytes = 0L; Measured = $false }
    if (-not $repository -or -not (Test-Path -LiteralPath $repository -PathType Container)) { return $result }

    try {
        $info = New-Object System.IO.DirectoryInfo((Get-WacLongPath -Path $repository))
        foreach ($file in $info.EnumerateFiles('*', [System.IO.SearchOption]::AllDirectories)) {
            if (Test-WacDeadlineExpired) { return $result }
            $result.Files++
            try { $result.Bytes += [int64]$file.Length } catch { $null = $_ }
        }
        $result.Measured = $true
    }
    catch {
        Write-WacLog -Level DEBUG -Component 'PnpClean' -Message 'The driver store could not be measured.' -Data @{ error = $_.Exception.Message }
    }

    return $result
}

function Invoke-WacPnpCleanHandler {
    <#
    .SYNOPSIS
        Runs the Windows driver package cleanup handler, bounded.
    .DESCRIPTION
        rundll32.exe <System32>\pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN. This entry point has
        no Microsoft reference page at all; it is used because it is the same handler the Disk
        Cleanup 'Device Driver Packages' category invokes, and it decides for itself what is safe to
        remove instead of this tool guessing.
    #>
    [CmdletBinding()]
    param([switch]$MeasureDriverStore)

    $category = 'Device driver packages (pnpclean)'
    $component = 'PnpClean'

    $rundll32 = Get-WacSystemToolPath -Leaf 'rundll32.exe'
    $pnpclean = Get-WacSystemToolPath -Leaf 'pnpclean.dll'
    if (-not $rundll32 -or -not $pnpclean) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'rundll32.exe or pnpclean.dll was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'The driver package cleanup handler requires administrator rights.'))
    }

    $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpCleanTimeoutMs
    if ($timeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -Detail 'The run budget was exhausted before pnpclean could start.'))
    }

    $before = $null
    if ($MeasureDriverStore) { $before = Get-WacDriverStoreSize }

    $arguments = @(('{0},RunDLL_PnpClean' -f $pnpclean), '/DRIVERS', '/MAXCLEAN')
    $run = Invoke-WacProcess -FilePath $rundll32 -ArgumentList $arguments -TimeoutMs $timeoutMs -Component $component

    if ($run.TimedOut) {
        # Killed on its deadline. It may have removed packages and it may not have, and nothing here
        # can tell which - that is precisely what Incomplete means.
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -Attempted $true -DurationMs ([int]$run.DurationMs) `
            -Detail ('pnpclean exceeded its {0} ms deadline and its process tree was terminated.' -f $timeoutMs)))
    }

    $detail = 'rundll32.exe exited with {0}.' -f $run.ExitCode

    if ($MeasureDriverStore -and $before -and $before.Measured) {
        $after = Get-WacDriverStoreSize
        if ($after.Measured) {
            $freed = [int64]($before.Bytes - $after.Bytes)
            $detail = '{0} Driver store change: {1}.' -f $detail, (Format-WacBytes -Bytes ([Math]::Max(0L, $freed)))
        }
    }

    $outcome = 'Failed'
    if ($run.ExitCode -eq 0) { $outcome = 'Succeeded' }

    return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
        -Outcome $outcome -Attempted $true -DurationMs ([int]$run.DurationMs) -Detail $detail))
}

function Invoke-WacDriverPackagePrune {
    <#
    .SYNOPSIS
        Exports and then deletes driver packages that are superseded AND installed on nothing.
        Disabled by default.
    .DESCRIPTION
        Off unless the caller passes -Enabled: a wrong decision here removes a driver the machine
        needs, and the driver store documentation says staged files should not be modified
        programmatically at all.

        The whole step fails closed. If the structured enumeration is unavailable, malformed, or
        carries no device associations, nothing is deleted and the step safe-skips - the localized
        text output is never parsed as a fallback because Microsoft documents it as changeable and
        localized. Every surviving candidate is exported into a content-addressed directory and that
        copy is proved before its package is removed.

        /force, /uninstall and /reboot are never passed: they would delete a package in use, rip a
        driver off live devices, or restart the machine.
    #>
    [CmdletBinding()]
    param(
        [switch]$Enabled,
        [string]$BackupRoot
    )

    $category = 'Superseded driver packages (pnputil)'
    $component = 'DriverPrune'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    if (-not $Enabled) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'Driver package pruning is disabled by default; pass -Enabled to opt in.'))
    }

    $pnputil = Get-WacSystemToolPath -Leaf 'pnputil.exe'
    if (-not $pnputil) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'pnputil.exe was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'Driver package pruning requires administrator rights.'))
    }

    # No recoverable backup means no deletion. This is the fail-closed condition for the whole step.
    if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'No -BackupRoot was supplied, so no package can be exported before deletion.'))
    }

    $normalizedBackupRoot = Get-WacNormalizedPath -Path $BackupRoot
    if (-not $normalizedBackupRoot) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'The -BackupRoot path could not be normalised.'))
    }

    try {
        if (-not (Test-Path -LiteralPath $normalizedBackupRoot -PathType Container)) {
            [void](New-Item -Path $normalizedBackupRoot -ItemType Directory -Force -ErrorAction Stop)
        }
    }
    catch {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('The backup directory could not be created ({0}): {1}' -f (Get-WacIoFailureKind -ErrorRecord $_), $_.Exception.Message)))
    }

    $enumTimeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
    if ($enumTimeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail 'The run budget was exhausted before pnputil could start.'))
    }

    $enum = Invoke-WacProcess -FilePath $pnputil -ArgumentList $script:PnpUtilEnumArgument -TimeoutMs $enumTimeoutMs -Component $component

    if ($enum.TimedOut) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -Attempted $true -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail 'The driver enumeration exceeded its deadline and its process tree was terminated; nothing was pruned.'))
    }

    if ($script:PnpUtilSuccessCode -notcontains $enum.ExitCode) {
        # An older pnputil rejects an argument it does not know and prints its usage, so a non-zero
        # exit IS the feature detection for /devices and /format. Nothing is assumed from a version.
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('Structured driver enumeration is unavailable (pnputil exited with {0}); pruning was skipped.' -f $enum.ExitCode)))
    }

    $parsed = ConvertFrom-WacPnpUtilDriverXml -Text ([string]$enum.StandardOutput)
    if (-not $parsed.IsValid -or -not $parsed.HasDeviceEvidence) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('{0} Pruning was skipped.' -f $parsed.Reason)))
    }

    $enumerated = @($parsed.Driver).Count
    $candidates = @(Get-WacSupersededDriver -Driver $parsed.Driver)
    if ($candidates.Count -eq 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Succeeded' -Attempted $true -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('{0} driver package(s) enumerated, {1} dropped as incomplete; no package is both superseded and installed on nothing.' -f $enumerated, $parsed.DroppedRow)))
    }

    Write-WacLog -Level INFO -Component $component -Message 'Superseded driver packages found.' -Data @{
        candidates = $candidates.Count; enumerated = $enumerated; dropped = $parsed.DroppedRow
    }

    $deleted = 0
    $skipped = 0
    $refused = 0
    $incomplete = 0
    $rebootRequired = $false
    $outcome = 'Succeeded'

    foreach ($candidate in $candidates) {
        if (Test-WacDeadlineExpired) {
            $remaining = $candidates.Count - $deleted - $skipped - $refused - $incomplete
            $incomplete += $remaining
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
            Write-WacLog -Level WARNING -Component $component -Message 'The run deadline expired mid-prune.' -Data @{ remaining = $remaining }
            break
        }

        $backup = Export-WacDriverBackup -PnpUtil $pnputil -Driver $candidate -BackupRoot $normalizedBackupRoot `
            -EnumeratedPackage $enumerated -Component $component

        if ($backup.Outcome -cne 'Succeeded') {
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate $backup.Outcome
            if ($backup.Outcome -ceq 'SecurityRefusal') { $refused++ }
            elseif ($backup.Outcome -ceq 'Incomplete') { $incomplete++ }
            else { $skipped++ }

            $level = 'WARNING'
            if ($backup.Outcome -ceq 'SecurityRefusal') { $level = 'ERROR' }
            Write-WacLog -Level $level -Component $component -Message 'The package was left in place because its backup could not be trusted.' -Data @{
                driver = $candidate.DriverName; outcome = $backup.Outcome; reason = $backup.Reason; directory = $backup.Directory
            }
            continue
        }

        $deleteTimeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
        if ($deleteTimeoutMs -le 0) {
            $incomplete++
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
            continue
        }

        # Never /force, /uninstall or /reboot.
        $delete = Invoke-WacProcess -FilePath $pnputil -ArgumentList @('/delete-driver', [string]$candidate.DriverName) `
            -TimeoutMs $deleteTimeoutMs -Component $component

        if ($delete.TimedOut) {
            $incomplete++
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
            Write-WacLog -Level WARNING -Component $component -Message 'The deletion exceeded its deadline, so whether the package was removed is unknown.' -Data @{
                driver = $candidate.DriverName; backup = $backup.Directory
            }
            continue
        }

        if ($script:PnpUtilSuccessCode -contains $delete.ExitCode) {
            $deleted++
            if ($script:PnpUtilRebootCode -contains $delete.ExitCode) { $rebootRequired = $true }

            # The stamp is what makes this directory a backup rather than a copy: from here the
            # package is gone and no later run may overwrite it.
            if (-not (Complete-WacDriverBackup -Path $backup.Directory -Manifest $backup.Manifest)) {
                Write-WacLog -Level WARNING -Component $component -Message 'The deletion could not be recorded in the backup manifest.' -Data @{
                    driver = $candidate.DriverName; backup = $backup.Directory
                }
            }
            Write-WacLog -Level INFO -Component $component -Message 'Removed a superseded driver package.' -Data @{
                driver = $candidate.DriverName; original = $candidate.OriginalName; version = [string]$candidate.Version
                supersededBy = $candidate.SupersededByName; exitCode = $delete.ExitCode
                backup = $backup.Directory; backupFiles = $backup.FileCount
            }
        }
        elseif ($script:PnpUtilBenignCode -contains $delete.ExitCode) {
            $skipped++
        }
        else {
            # pnputil refuses a package that is still in use. That is the protection working - and
            # because the package stayed, its export is a copy of something, not the only copy of
            # it. Keeping it would cost the space and collide with every later run.
            [void](Remove-WacDriverBackupDirectory -Path $backup.Directory)
            Write-WacLog -Level INFO -Component $component -Message 'pnputil declined to remove a package.' -Data @{ driver = $candidate.DriverName; exitCode = $delete.ExitCode }
            $skipped++
        }
    }

    $stopwatch.Stop()
    return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
        -Outcome $outcome -Attempted $true -RebootRequired $rebootRequired `
        -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
        -Detail ('candidates={0} deleted={1} skipped={2} refused={3} incomplete={4} enumerated={5} backup={6}' -f `
            $candidates.Count, $deleted, $skipped, $refused, $incomplete, $enumerated, $normalizedBackupRoot)))
}

Export-ModuleMember -Function @(
    'Get-WacDriverStoreSize', 'Invoke-WacPnpCleanHandler',
    'Get-WacDriverVersionPart', 'ConvertFrom-WacPnpUtilDriverXml', 'Get-WacSupersededDriver',
    'Get-WacDriverBackupIdentity', 'Get-WacDriverBackupFileHash', 'New-WacDriverBackupManifest',
    'Test-WacDriverBackupIntact', 'Test-WacDriverBackupIsResidue',
    'Export-WacDriverBackup', 'Invoke-WacDriverPackagePrune'
)
