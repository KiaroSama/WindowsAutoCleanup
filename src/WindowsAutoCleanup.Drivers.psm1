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
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DriverBackupStore.ps1')

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

# Run-level precedence (SecurityRefusal beats Failed beats Incomplete beats a clean outcome) lives in
# StepContract.psm1, which this module reaches through Steps.psm1. There used to be a byte-identical
# copy of the table and the function here.

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

    # rundll32 returns as soon as it has handed the work over, so its code is the weakest of the
    # three facts available. The shared rule keeps the other two from being dropped.
    $settled = Resolve-WacSettledOutcome -Outcome $outcome -Detail $detail -Run $run

    return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
        -Outcome $settled.Outcome -Attempted $true -DurationMs ([int]$run.DurationMs) -Detail $settled.Detail))
}

# ---------------------------------------------------------------------------------------------
# 3. Superseded driver package pruning
# ---------------------------------------------------------------------------------------------

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

        The deletion and its backup are ONE commit. A pending marker goes into the export directory
        before pnputil is asked to remove anything and comes off only once the stamped manifest has
        been read back, so from the moment a removal becomes possible the directory is protected
        from reclamation whatever happens next.

        An exit code never decides what happened to the store. EVERY attempt that STARTED is
        followed by a bounded confirming enumeration - a documented success, a reboot-required
        3010/1641, the benign 259 and an undocumented non-zero alike - and only that answer clears
        the marker, reclaims the export or advances a count: Removed commits the backup, Present
        clears or reclaims it now that the non-deletion is proved, and Unknown keeps both the marker
        and the export and returns Incomplete. A reboot-required code that leaves the package listed
        is the one Present that keeps its export: the restart may still remove it, so the attempt is
        unresolved rather than refuted, and Resolve-WacDriverBackupPending settles it on a later
        run. deleted and a clean outcome therefore advance only from a proven store postcondition
        PLUS a durable commit; a process that never started, a killed one, a result with no readable
        exit code, a commit that failed and a removal that happened behind an undocumented exit code
        are all Incomplete or Failed.

        /force, /uninstall and /reboot are never passed: they would delete a package in use, rip a
        driver off live devices, or restart the machine.
    #>
    [CmdletBinding()]
    param(
        [switch]$Enabled,
        [string]$BackupRoot,
        # Empty means the real machine location. Named so a harness can point the legacy probe at a
        # sandbox instead of at whatever the machine running the suite happens to have.
        [string]$LegacyBackupRoot = ''
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

    # The sibling Logs directory under the same data root has always been walked for this; the
    # backup root never was, and it is not an ancestor of Logs, so a weaker owner, a weaker DACL or
    # a reparse component HERE was invisible while log trust still passed. A backup a standard user
    # can replace, empty or redirect is not a backup, and the walk runs before anything is read,
    # reclaimed, exported, marked or committed underneath it. When the root does not exist yet the
    # walk verifies the nearest existing ancestor instead - the directory the root is about to be
    # created in and inherit from, which is the thing that has to be trustworthy.
    $rootTrust = Test-WacStatePathIsTrusted -Path $normalizedBackupRoot
    if (-not $rootTrust.IsTrusted) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SecurityRefusal' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('The driver backup root is not machine-trusted, so nothing was exported or deleted. {0}' -f [string]$rootTrust.Reason)))
    }

    # REFUSED now, not reported. An export is the only copy of a package about to be deleted, so a
    # principal who can create a NAME here can plant wac-driver-backup.json, the pending marker or
    # the commit file before this step writes them. Warning and continuing was the old behaviour and
    # it was not a guard. Get-WacDriverBackupRoot is what makes refusing affordable: the default
    # root moved off %ProgramData%, whose inherited BUILTIN\Users grant no healthy install can shed,
    # onto %SystemRoot%\Logs, measured to report Writers=[]. A caller naming its own root gets the
    # same rule rather than an exemption.
    if (@($rootTrust.Writers).Count -gt 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SecurityRefusal' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('Non-administrative principals can create content in the driver backup root, so an export there cannot be trusted as the only copy of a deleted package. Nothing was exported or deleted. root={0} writers={1}' -f `
                $normalizedBackupRoot, (@($rootTrust.Writers) -join ', '))))
    }

    # Created through the pinned-handle primitive, never Test-Path then New-Item -Force: -Force
    # ADOPTS a directory that appeared after the walk above, which is precisely the race. A name
    # that already exists comes back as a collision and is refused rather than taken over.
    #
    # And proved by the STRICT rule from the handle of the directory that was actually created or
    # opened, which is the half the Writers check above cannot supply. That check reads the
    # PRE-CREATE pathname verdict, and an ACE that is inherit-only on the parent grants nothing
    # there - so Writers comes back empty - and becomes effective on this root the moment it is
    # created. Measured: (A;OICIIO;0x100116;;;BU) on the parent, (A;OICIID;0x100116;;;BU) on the
    # child. Both checks are kept: the walk answers for the ancestor chain, this answers for the
    # object.
    $backupDirectory = Open-WacDriverBackupDirectory -Path $normalizedBackupRoot -MayCreate -MaxCreate 8
    Close-WacTrustedDirectory -Handle $backupDirectory.Handle
    if (-not $backupDirectory.IsTrusted) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SecurityRefusal' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('The driver backup root could not be created or proved, so nothing was exported or deleted. {0}{1}' -f `
                [string]$backupDirectory.Reason, $(if (@($backupDirectory.Writers).Count -gt 0) { ' writers=' + (@($backupDirectory.Writers) -join ', ') } else { '' }))))
    }

    # The pre-relocation root, which until now had no production caller at all - so an unresolved
    # deletion left in %ProgramData%\WindowsAutoCleanup\DriverBackup was silently forgotten while
    # this step went on reporting clean runs. It is DETECTED and never believed: nothing there is
    # read, moved, committed or removed, and the count alone raises the floor under every outcome
    # below so the run cannot end clean while it stands. See
    # Test-WacLegacyDriverBackupRootUnresolved for the recovery rule an operator follows to clear it.
    $legacyRoot = $LegacyBackupRoot
    if ([string]::IsNullOrWhiteSpace($legacyRoot)) { $legacyRoot = [string](Get-WacLegacyDriverBackupRoot) }
    $legacy = Test-WacLegacyDriverBackupRootUnresolved -Path $legacyRoot

    $floor = 'Succeeded'
    $legacyDetail = ''
    if ($legacy.Unresolved) {
        $floor = 'Incomplete'
        $legacyDetail = ' ' + [string]$legacy.Detail
        Write-WacLog -Level WARNING -Component $component -Message 'The pre-relocation driver backup root still holds state that only an operator can settle.' -Data @{
            root = [string]$legacy.Path; entries = [int]$legacy.EntryCount
        }
    }

    $enumTimeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
    if ($enumTimeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome (Get-WacHigherOutcome -Current 'Incomplete' -Candidate $floor) -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('The run budget was exhausted before pnputil could start.' + $legacyDetail)))
    }

    $enum = Invoke-WacProcess -FilePath $pnputil -ArgumentList $script:PnpUtilEnumArgument -TimeoutMs $enumTimeoutMs -Component $component

    # THE CANDIDATE LIST IS ONLY AS GOOD AS THE RUN THAT PRODUCED IT (ledger WAC-05R). The
    # per-candidate loop below has asked this question about its own pnputil since the last round;
    # the enumeration that decides WHICH packages that loop touches never did, and it is the more
    # dangerous of the two. Truncated output still parses into valid XML, and a package whose device
    # rows never arrived reads as installed on nothing - which is precisely what makes a package a
    # deletion candidate. So a store that was half read could nominate a live package for removal.
    # Resolve-WacSettledOutcome raises the outcome and arms the latch in one move, so the step stops
    # here rather than acting on a list it cannot stand behind.
    $enumSettled = Resolve-WacSettledOutcome -Outcome 'SafeSkip' -Detail 'The driver store was not enumerated.' -Run $enum
    if ([string]$enumSettled.Outcome -cne 'SafeSkip') {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome (Get-WacHigherOutcome -Current ([string]$enumSettled.Outcome) -Candidate $floor) -Attempted $true `
            -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) -Detail ([string]$enumSettled.Detail + $legacyDetail)))
    }

    if ($enum.TimedOut) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome (Get-WacHigherOutcome -Current 'Incomplete' -Candidate $floor) -Attempted $true -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('The driver enumeration exceeded its deadline and its process tree was terminated; nothing was pruned.' + $legacyDetail)))
    }

    if ($script:PnpUtilSuccessCode -notcontains $enum.ExitCode) {
        # An older pnputil rejects an argument it does not know and prints its usage, so a non-zero
        # exit IS the feature detection for /devices and /format. Nothing is assumed from a version.
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome (Get-WacHigherOutcome -Current 'SafeSkip' -Candidate $floor) -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail (('Structured driver enumeration is unavailable (pnputil exited with {0}); pruning was skipped.' -f $enum.ExitCode) + $legacyDetail)))
    }

    $parsed = ConvertFrom-WacPnpUtilDriverXml -Text ([string]$enum.StandardOutput)
    if (-not $parsed.IsValid -or -not $parsed.HasDeviceEvidence) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome (Get-WacHigherOutcome -Current 'SafeSkip' -Candidate $floor) -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail (('{0} Pruning was skipped.' -f $parsed.Reason) + $legacyDetail)))
    }

    $enumerated = @($parsed.Driver).Count

    # Before the candidate list is used, because a package whose removal completed at a restart is
    # no longer in that list at all. See Resolve-WacDriverBackupPending for the whole argument.
    $pending = Resolve-WacDriverBackupPending -PnpUtil $pnputil -BackupRoot $normalizedBackupRoot -Component $component

    $candidates = @(Get-WacSupersededDriver -Driver $parsed.Driver)
    if ($candidates.Count -eq 0 -and $pending.Count -eq 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome (Get-WacHigherOutcome -Current 'Succeeded' -Candidate $floor) -Attempted $true -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail (('{0} driver package(s) enumerated, {1} dropped as incomplete; no package is both superseded and installed on nothing.' -f $enumerated, $parsed.DroppedRow) + $legacyDetail)))
    }

    if ($candidates.Count -gt 0) {
        Write-WacLog -Level INFO -Component $component -Message 'Superseded driver packages found.' -Data @{
            candidates = $candidates.Count; enumerated = $enumerated; dropped = $parsed.DroppedRow
        }
    }

    $deleted = [int]$pending.Deleted
    $skipped = 0
    $refused = [int]$pending.Refused
    $incomplete = [int]$pending.Incomplete
    $failed = [int]$pending.Failed
    $rebootRequired = $false
    $outcome = [string]$pending.Outcome

    # Indexed rather than foreach so the remaining count is read off the position instead of being
    # derived by subtracting the counters, which no longer start at zero.
    for ($index = 0; $index -lt $candidates.Count; $index++) {
        $candidate = $candidates[$index]

        if (Test-WacDeadlineExpired) {
            $remaining = $candidates.Count - $index
            $incomplete += $remaining
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
            Write-WacLog -Level WARNING -Component $component -Message 'The run deadline expired mid-prune.' -Data @{ remaining = $remaining }
            break
        }

        # An earlier deletion that could not be proven stopped may still be writing to the driver
        # store. Starting the next one on top of it is the race this latch exists to prevent, and it
        # does not self-clear: nothing in this process can observe that pnputil finishing.
        if (-not (Test-WacMutationAllowed)) {
            $remaining = $candidates.Count - $index
            $incomplete += $remaining
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
            Write-WacLog -Level ERROR -Component $component -Message 'Pruning stopped: an earlier deletion could not be proven stopped, so no further package was touched.' -Data @{ remaining = $remaining }
            break
        }

        # Spoken for by the reconciliation above: its directory carries an attempt nobody has
        # settled, so this run neither exports it again nor asks pnputil to remove it again - and it
        # is not counted twice either, because the reconciliation already reported it.
        if (@($pending.Held) -contains (Get-WacDriverBackupIdentity -Driver $candidate).Name) { continue }

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

        # The marker goes down BEFORE the process is started, because from the instant pnputil may
        # have removed something this directory stops being an ordinary export. A marker that cannot
        # be written is therefore a reason not to delete at all.
        if (-not (Set-WacDriverBackupDeletePending -Path $backup.Directory -DriverName ([string]$candidate.DriverName))) {
            $failed++
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Failed'
            [void](Remove-WacDriverBackupDirectory -Path $backup.Directory)
            Write-WacLog -Level ERROR -Component $component -Message 'The deletion was abandoned because the pending-deletion marker could not be written.' -Data @{
                driver = $candidate.DriverName; backup = $backup.Directory
            }
            continue
        }

        # Never /force, /uninstall or /reboot.
        $delete = Invoke-WacProcess -FilePath $pnputil -ArgumentList @('/delete-driver', [string]$candidate.DriverName) `
            -TimeoutMs $deleteTimeoutMs -Component $component

        # Read defensively: Started is part of the runner's contract, but under Set-StrictMode 2.0 a
        # property an injected runner omits throws rather than reading as absent.
        $started = $true
        if (@($delete.PSObject.Properties.Name) -ccontains 'Started') { $started = [bool]$delete.Started }

        # Read the same defensive way, for a sharper reason (ledger WAC-05R): a pnputil this run
        # could not prove stopped may STILL be writing to the driver store while the code below
        # decides whether the export protecting that package can be reclaimed. The runner reports
        # that honestly, and this was the only destructive consumer that ignored the answer.
        $terminationProven = $true
        if (@($delete.PSObject.Properties.Name) -ccontains 'TerminationProven') { $terminationProven = [bool]$delete.TerminationProven }

        # TimedOut is answered FIRST because it is the only one of these that says the tool ran:
        # a process killed on its deadline may have removed the package, so nothing here may treat
        # it as "never started" and throw the export away.
        if ($delete.TimedOut -or ($started -and $null -eq $delete.ExitCode) -or ($started -and -not $terminationProven)) {
            # Killed on its deadline, exited without an exit code anyone could read, or left part of
            # its tree alive. Whether the package survived is unknown, so the marker STAYS and the
            # export is kept: it may be the only copy left of something that is already gone. An
            # exit code from a root whose tree outlived it is not an answer about the store.
            $incomplete++
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'

            # ARMS THE QUARANTINE. Preserving this package's export was necessary but not sufficient:
            # the run used to simply `continue` to the next candidate, so a pnputil that may still be
            # writing to the driver store had the next deletion started on top of it. The latch is
            # checked at the top of this loop, so the remaining candidates are left untouched with
            # their evidence intact.
            # Arms that latch AND records the same fact in the directory, so the next run does not
            # settle this attempt against a store reading taken beside a writer nobody stopped.
            $marked = Set-WacDriverBackupAbandoned -Path $backup.Directory `
                -Reason ('a driver deletion could not be proven finished: {0}' -f [string]$candidate.DriverName)

            Write-WacLog -Level CRITICAL -Component $component -Message 'The deletion produced no trustworthy result; no further package will be touched this run.' -Data @{
                driver = $candidate.DriverName; backup = $backup.Directory; recorded = $marked
                timedOut = [bool]$delete.TimedOut; terminationProven = $terminationProven
            }
            continue
        }

        if (-not $started) {
            # Process.Start itself failed, so nothing ran and nothing was removed: the export is a
            # copy of a package that is still installed and may go. But a step that cannot start its
            # own tool has not done its work either, and reporting that as a skip hid a broken run.
            $failed++
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Failed'
            [void](Remove-WacDriverBackupDirectory -Path $backup.Directory)
            Write-WacLog -Level ERROR -Component $component -Message 'pnputil could not be started, so the package was left in place.' -Data @{
                driver = $candidate.DriverName; error = [string]$delete.StandardError
            }
            continue
        }

        # THE POSTCONDITION, and it runs for EVERY attempt that started - with no exceptions left.
        # An exit code is what the TOOL believes; only the store can say what a mutating process
        # actually left behind, and 259, an undocumented non-zero and a reboot-required 3010/1641
        # are exactly as unproven as a reported success. Reboot-required used to skip this on the
        # argument that the package is legitimately still enumerable until the restart. That is
        # true, and it is not a reason to assert a removal nobody observed: the same code with the
        # same store answer is also what a removal that never happens looks like. So the check runs,
        # and it is the ANSWER that is read differently below - a reboot-required Present keeps its
        # export instead of reclaiming it, because the restart may still remove the package.
        $rebootPending = $script:PnpUtilRebootCode -contains $delete.ExitCode
        $reportedSuccess = $script:PnpUtilSuccessCode -contains $delete.ExitCode

        $confirm = Test-WacDriverPackageRemoved -PnpUtil $pnputil -DriverName $candidate.DriverName `
            -TimeoutMs (Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs) -Component $component
        $state = [string]$confirm.State
        $confirmReason = [string]$confirm.Reason

        # Reported by the tool, not derived from a count: a restart is what resolves this attempt,
        # so the operator needs to be told about it whether or not the removal could be proved yet.
        if ($rebootPending) { $rebootRequired = $true }

        if ($state -cne 'Removed' -and $state -cne 'Present') {
            # Whether it went cannot be established. The marker STAYS and the export is kept: it may
            # be the only copy left of something that is already gone.
            $incomplete++
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
            Write-WacLog -Level WARNING -Component $component -Message 'The package removal could not be confirmed against the driver store.' -Data @{
                driver = $candidate.DriverName; backup = $backup.Directory; exitCode = $delete.ExitCode; reason = $confirmReason
            }
            continue
        }

        if ($state -ceq 'Present') {
            if ($rebootPending) {
                # 3010/1641 and the package still listed. Present here is NOT a refuted removal: the
                # documented meaning of the code is that the store loses the package at the next
                # restart, and this run cannot see past that. So nothing is counted, nothing is
                # reclaimed, and the export and its marker STAY - they are what
                # Resolve-WacDriverBackupPending settles on the first run after the restart, and
                # without them a removal that really happened would leave no recoverable copy.
                $incomplete++
                $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
                Write-WacLog -Level WARNING -Component $component -Message 'pnputil asked for a restart and the package is still in the store, so the removal is pending that restart and was not counted.' -Data @{
                    driver = $candidate.DriverName; exitCode = $delete.ExitCode; backup = $backup.Directory
                }
                continue
            }

            # The package is provably still installed, so this export is a copy of a live package
            # and not the only copy of anything. Whatever is done with it, it is done only now that
            # the store has been asked - and the marker never outlives a proven non-deletion,
            # because a permanently protected directory refuses this package on every later run.
            if ($reportedSuccess) {
                $failed++
                $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Failed'
                [void](Remove-WacDriverBackupDirectory -Path $backup.Directory)
                Write-WacLog -Level ERROR -Component $component -Message 'pnputil reported success but the package is still in the driver store; nothing was removed.' -Data @{
                    driver = $candidate.DriverName; exitCode = $delete.ExitCode; reason = $confirmReason
                }
                continue
            }

            if ($script:PnpUtilBenignCode -contains $delete.ExitCode) {
                # ERROR_NO_MORE_ITEMS, and the store agrees nothing went. The attempt left no
                # ambiguity behind, so the marker comes off and the export stays exactly as
                # reclaimable as it was.
                [void](Clear-WacDriverBackupDeletePending -Path $backup.Directory)
                $skipped++
                continue
            }

            # pnputil refuses a package that is still in use. That is the protection working, and
            # the store has now confirmed it, so the export costs space and collides with every
            # later run for nothing.
            [void](Remove-WacDriverBackupDirectory -Path $backup.Directory)
            Write-WacLog -Level INFO -Component $component -Message 'pnputil declined to remove a package, and the store confirms it is still installed.' -Data @{
                driver = $candidate.DriverName; exitCode = $delete.ExitCode
            }
            $skipped++
            continue
        }

        # The package is gone, and the STORE is what says so - the exit code, reboot-required
        # included, only ever said what the tool believed. The stamp is what makes this directory a
        # backup rather than a copy, and it is written atomically. Only once it is durable does the
        # count advance and the marker come off; a commit that failed leaves a removed package
        # behind a protected export, which is a failed run and not a deletion anyone may call
        # successful.
        if (-not (Complete-WacDriverBackup -Path $backup.Directory -Manifest $backup.Manifest)) {
            $failed++
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Failed'
            Write-WacLog -Level ERROR -Component $component -Message 'The package was removed but its backup could not be committed; the export is protected and needs manual recovery.' -Data @{
                driver = $candidate.DriverName; backup = $backup.Directory
            }
            continue
        }

        $deleted++

        if (-not $reportedSuccess) {
            # The store says the package is gone and the tool said something outside its documented
            # success set. Nothing is lost - the removal is real and its backup is committed - but a
            # tool that mutates the store while contradicting its own exit code is not a clean run,
            # and an exit code is never again allowed to be the thing that decides that.
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Failed'
            Write-WacLog -Level ERROR -Component $component -Message 'The package was removed even though pnputil reported no documented success; the run is not clean.' -Data @{
                driver = $candidate.DriverName; exitCode = $delete.ExitCode; backup = $backup.Directory
            }
        }

        Write-WacLog -Level INFO -Component $component -Message 'Removed a superseded driver package.' -Data @{
            driver = $candidate.DriverName; original = $candidate.OriginalName; version = [string]$candidate.Version
            supersededBy = $candidate.SupersededByName; exitCode = $delete.ExitCode
            backup = $backup.Directory; backupFiles = $backup.FileCount
        }
    }

    $stopwatch.Stop()
    return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
        -Outcome (Get-WacHigherOutcome -Current $outcome -Candidate $floor) -Attempted $true -RebootRequired $rebootRequired `
        -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
        -Detail (('candidates={0} deleted={1} skipped={2} refused={3} incomplete={4} failed={5} pending={6} enumerated={7} backup={8}' -f `
            $candidates.Count, $deleted, $skipped, $refused, $incomplete, $failed, $pending.Count, $enumerated, $normalizedBackupRoot) + $legacyDetail)))
}

Export-ModuleMember -Function @(
    'Get-WacDriverStoreSize', 'Invoke-WacPnpCleanHandler',
    'Get-WacDriverVersionPart', 'ConvertFrom-WacPnpUtilDriverXml', 'Get-WacSupersededDriver',
    'Test-WacDriverPackageRemoved',
    'Get-WacDriverBackupIdentity', 'Get-WacDriverBackupFileHash', 'New-WacDriverBackupManifest',
    'Test-WacDriverBackupIntact', 'Test-WacDriverBackupIsResidue',
    'Export-WacDriverBackup', 'Invoke-WacDriverPackagePrune'
)
