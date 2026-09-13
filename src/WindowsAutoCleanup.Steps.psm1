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

# The three modules this one is the entry point for. Their functions are re-exported below, so a
# caller - and the fresh runspace the bounded seam creates - still gets the whole package from one
# import of this file.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.StepContract.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.RecycleBin.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DiskCleanup.psm1') -DisableNameChecking -ErrorAction Stop

$script:DismTimeoutMs = 1000 * 60 * 120

# Bounds for the in-process work. They are ceilings, not expected durations: the cache purge
# normally takes seconds.
$script:DeliveryOptimizationConfigTimeoutMs = 1000 * 60
$script:DeliveryOptimizationPurgeTimeoutMs  = 1000 * 60 * 10

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
        # The exit code is what DISM believes about ITSELF. Servicing hands work to children, so a
        # clean code with a live descendant or truncated output is not a finished step - one shared
        # rule answers that for every tool rather than each step inventing its own.
        $settled = Resolve-WacSettledOutcome -Outcome 'Succeeded' -Detail ('dism.exe exited with {0}.' -f $exitCode) -Run $run
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome $settled.Outcome -Attempted $true `
            -RebootRequired ($exitCode -eq 3010) -DurationMs ([int]$run.DurationMs) -Detail $settled.Detail))
    }

    # THE FAILURE PATH GOES THROUGH THE GATE TOO. A non-zero exit says DISM believes it failed; it
    # says nothing about whether the servicing children it started are still running, and a step that
    # failed is exactly the one after which another mutation must not begin (ledger WAC-05R).
    $detail = if ($null -eq $exitCode) { 'dism.exe did not start.' } else { 'dism.exe exited with {0}.' -f $exitCode }
    $failed = Resolve-WacSettledOutcome -Outcome 'Failed' -Detail $detail -Run $run
    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Outcome $failed.Outcome -Attempted $true -DurationMs ([int]$run.DurationMs) -Detail $failed.Detail))
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

    # Expanded first, because the drive can be configured as an environment variable.
    $expanded = ([System.Environment]::ExpandEnvironmentVariables($working)).Trim()

    $normalized = Get-WacNormalizedPath -Path $expanded
    if (-not $normalized) {
        $result.Detail = 'The Delivery Optimization cache location could not be normalised: {0}' -f $working
        return $result
    }

    # The RAW value has to be an absolute drive path, and this is asked of the raw value rather
    # than of the normalised one because normalising is what destroys the evidence: GetFullPath
    # COMPLETES a relative value against this process's current directory, so 'Cache',
    # '..\Cache', a bare 'C:' (which is the current directory ON C:, not its root) or an unset
    # '%Var%\Cache' all come back as a rooted path that looks like it sits on the target drive.
    # A location whose drive cannot be read off the value itself is not a location this run knows,
    # and the fail-closed answer is to leave the cache alone.
    if ($expanded -notmatch '^[A-Za-z]:[\\/]') {
        $result.Detail = 'The Delivery Optimization cache location is not an absolute path, so the drive it is on cannot be determined: {0}' -f $working
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

    # -Mutating: this purge DELETES cached payloads. An abandoned one is not a terminated one, so it
    # has to arm the quarantine latch that stops the run scheduling the next mutation on top of it.
    $purgeRun = Invoke-WacStepBounded -Component $component -TimeoutMs $script:DeliveryOptimizationPurgeTimeoutMs -Mutating -ScriptBlock {
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

Export-ModuleMember -Function @(
    'New-WacStepResult', 'Write-WacStepResult', 'Get-WacSystemToolPath', 'Get-WacDiskCleanupCategory',
    'Set-WacStepBoundedInvoker', 'Invoke-WacStepBounded', 'Invoke-WacGuardedStep',
    'Get-WacHigherOutcome', 'Test-WacOutcomeIsClean', 'Get-WacOutcomeRankTable',
    'Test-WacToolLifetimeSettled', 'Resolve-WacSettledOutcome',
    'Invoke-WacComponentCleanup',
    'Test-WacRecycleBinEntryName', 'Get-WacRecycleBinScan', 'Clear-WacRecycleBin',
    'Get-WacDeliveryOptimizationCacheLocation', 'Clear-WacDeliveryOptimizationCache',
    'Test-WacRegistryValueEqual', 'Get-WacRegistryValueFact',
    'Get-WacDiskCleanupStateFlag', 'Restore-WacDiskCleanupStateFlag', 'Enable-WacDiskCleanupCategory',
    'Test-WacDiskCleanupProfileExact',
    'Invoke-WacLegacyDiskCleanup'
)
