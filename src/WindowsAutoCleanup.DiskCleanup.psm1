<#
.SYNOPSIS
    The opt-in legacy Disk Cleanup step, and the exact VolumeCaches profile it borrows and puts
    back.

.DESCRIPTION
    cleanmgr /sagerun runs against EVERY drive in the computer, which is why the step is opt-in.
    What makes it safe to run at all is everything else in this file: the StateFlags<n> value of
    every handler is snapshotted as existence, RAW value and RegistryValueKind, the profile is
    written, and the original is put back and verified byte for byte in a finally block under a
    bound that ignores the run budget.

    Split out of WindowsAutoCleanup.Steps.psm1, which imports this module and re-exports it, so
    importing the package entry point still resolves every name below.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the CALLER's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.StepContract.psm1') -DisableNameChecking -ErrorAction Stop

$script:CleanMgrTimeoutMs = 1000 * 60 * 5

# A bound for the in-process work. It is a ceiling, not an expected duration: the registry snapshot
# takes milliseconds.
$script:VolumeCacheRegistryTimeoutMs = 1000 * 30

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
        Writes the EXACT sage profile: the requested handlers on, and every other handler that
        carries a value for this sage id explicitly off.
    .DESCRIPTION
        Only 0 (off) and 2 (on) are documented values, so nothing else is ever written. The
        'Offline Pages Files' handler is never ENABLED because it has no StateFlags value of its
        own; it is still disabled like any other handler if it turns out to carry one.

        Turning the requested handlers on is NOT enough. The sage id is a fixed number this project
        borrows, and a machine where someone once ran cleanmgr /sageset with that same number
        already carries enabled values on handlers nobody here selected - /sagerun would run those
        too, and putting the profile back afterwards does not undo what they deleted. Every handler
        that is not requested and DOES carry a value is therefore written to 0. One that carries no
        value at all is already unselected, so leaving it alone keeps this the smallest write that
        still produces the exact selection.

        A write that fails is COUNTED, not merely logged: a half-written profile means cleanmgr
        would run against a selection nobody chose.
    .OUTPUTS
        Touched (values actually written), Failed, and Enabled (the handler names switched on).
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateRange(0, 9999)][int]$SageId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Category,
        [string]$KeyPath = $script:VolumeCacheKeyPath
    )

    $valueName = 'StateFlags{0:0000}' -f $SageId
    $touched = 0
    $failed = 0
    $enabled = New-Object 'System.Collections.Generic.List[string]'

    # A hashtable so the lookup is case-insensitive, which is what the registry is.
    $requested = @{}
    foreach ($name in $Category) {
        if ($script:DiskCleanupSkipHandler -contains $name) { continue }
        $requested[[string]$name] = $true
    }

    $handlers = @()
    try { $handlers = @(Get-ChildItem -LiteralPath $KeyPath -ErrorAction Stop) }
    catch {
        # Without the whole handler list the profile cannot be made exact, so nothing is written.
        Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'The VolumeCaches key could not be enumerated, so no cleanmgr profile was written.' -Data @{ error = $_.Exception.Message }
        return [PSCustomObject]@{ Touched = 0; Failed = 1; Enabled = @() }
    }

    foreach ($handler in $handlers) {
        $name = [string](Split-Path -Leaf $handler.Name)
        $wanted = $requested.ContainsKey($name)

        if (-not $wanted) {
            # An unrequested handler with no value is already off, and writing a 0 over nothing
            # would only add a value someone else's profile never had.
            $present = $false
            try { $present = (-not (Get-WacRegistryValueFact -KeyPath ([string]$handler.PSPath) -ValueName $valueName).WasAbsent) }
            catch {
                $failed++
                Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'A StateFlags value could not be read, so the profile cannot be made exact.' -Data @{ handler = $name; error = $_.Exception.Message }
                continue
            }
            if (-not $present) { continue }
        }

        $value = 0
        if ($wanted) { $value = 2 }

        try {
            [void](New-ItemProperty -LiteralPath ([string]$handler.PSPath) -Name $valueName -PropertyType DWord -Value $value -Force -ErrorAction Stop)
            $touched++
            if ($wanted) { [void]$enabled.Add($name) }
        }
        catch {
            $failed++
            Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'A StateFlags value could not be set.' -Data @{ handler = $name; error = $_.Exception.Message }
        }
    }

    return [PSCustomObject]@{ Touched = $touched; Failed = $failed; Enabled = @($enabled.ToArray()) }
}

function Test-WacDiskCleanupProfileExact {
    <#
    .SYNOPSIS
        Reads the whole sage profile back and answers whether EXACTLY the expected handlers are on.
    .DESCRIPTION
        A write reporting success is not the same fact as the profile being right, and it is the
        handlers this run never touched that make the difference: one of them carrying an enabled
        value from an old cleanmgr /sageset with the same number is precisely what /sagerun would
        run anyway. cleanmgr is started only once every handler has been read back and value 2 was
        found on the expected ones and on nothing else.

        Enabled is DWORD 2 and nothing else. That is the only documented "run this handler" value,
        and Enable-WacDiskCleanupCategory writes a DWORD over any other kind it finds, so anything
        that is not a DWORD 2 here is either off or a write that did not take.
    .OUTPUTS
        Ok, Reason and Enabled (the handler names found switched on).
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateRange(0, 9999)][int]$SageId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Expected,
        [string]$KeyPath = $script:VolumeCacheKeyPath
    )

    $valueName = 'StateFlags{0:0000}' -f $SageId
    $result = [PSCustomObject]@{ Ok = $false; Reason = ''; Enabled = @() }

    $wanted = @{}
    foreach ($name in $Expected) { $wanted[[string]$name] = $true }

    $on = New-Object 'System.Collections.Generic.List[string]'
    $wrong = New-Object 'System.Collections.Generic.List[string]'

    $handlers = @()
    try { $handlers = @(Get-ChildItem -LiteralPath $KeyPath -ErrorAction Stop) }
    catch {
        $result.Reason = 'the VolumeCaches key could not be read back ({0})' -f $_.Exception.Message
        return $result
    }

    foreach ($handler in $handlers) {
        $name = [string](Split-Path -Leaf $handler.Name)

        $fact = $null
        try { $fact = Get-WacRegistryValueFact -KeyPath ([string]$handler.PSPath) -ValueName $valueName }
        catch {
            $result.Reason = 'the {0} value of {1} could not be read back ({2})' -f $valueName, $name, $_.Exception.Message
            return $result
        }

        $isOn = ((-not $fact.WasAbsent) -and $fact.Kind -eq [Microsoft.Win32.RegistryValueKind]::DWord -and ([int]$fact.Value) -eq 2)
        if ($isOn) { [void]$on.Add($name) }
        if ($isOn -ne $wanted.ContainsKey($name)) { [void]$wrong.Add($name) }
    }

    $result.Enabled = @($on.ToArray())

    if ($wrong.Count -gt 0) {
        $result.Reason = '{0} handler(s) do not match the requested selection: {1}' -f $wrong.Count, ((@($wrong.ToArray()) | Sort-Object) -join ', ')
        return $result
    }

    $result.Ok = $true
    return $result
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

        Between those two the profile is made EXACT rather than merely extended, and then read back
        before cleanmgr is launched. A sage id is a number, not a reservation: the one this step
        defaults to may already carry enabled values from somebody's earlier /sageset, and /sagerun
        would run those categories too. Restoring the profile afterwards does not undo what they
        deleted, so the selection has to be provably right BEFORE the launch. Allocating an unused
        sage id instead was the documented alternative and is not what this does: it would still be
        a guess about a number this code does not own, and the guess would have to be re-made on
        every run, while making one id exact fixes every id a caller can pass.

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
            # not "did it intend to". Switching somebody else's leftover selection off counts too.
            $mutated = ($enabledResult.Touched -gt 0)
            $enabledHandler = @($enabledResult.Enabled)

            $exact = $null
            if ($enabledResult.Failed -eq 0 -and $enabledHandler.Count -gt 0) {
                $exact = Test-WacDiskCleanupProfileExact -SageId $SageId -Expected $enabledHandler -KeyPath $keyPath
            }

            if ($enabledResult.Failed -gt 0) {
                $outcome = 'Incomplete'
                $detail = '{0} cleanmgr handler(s) could not be written, so cleanmgr was not started.' -f $enabledResult.Failed
            }
            elseif ($enabledHandler.Count -eq 0) {
                $outcome = 'SafeSkip'
                $detail = 'None of the requested cleanmgr handlers exist on this machine.'
            }
            elseif (-not $exact.Ok) {
                # An unverified profile is a run against a selection nobody chose, and /sagerun
                # deletes on every drive. The finally block still puts every touched value back.
                $outcome = 'Incomplete'
                $detail = 'The cleanmgr profile did not read back as the exact requested selection, so cleanmgr was not started: {0}' -f $exact.Reason
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
                    $detail = 'cleanmgr /sagerun:{0} completed over {1} handler(s) on every drive.' -f $SageId, $enabledHandler.Count
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
    'Get-WacDiskCleanupCategory',
    'Test-WacRegistryValueEqual', 'Get-WacRegistryValueFact',
    'Get-WacDiskCleanupStateFlag', 'Restore-WacDiskCleanupStateFlag', 'Enable-WacDiskCleanupCategory',
    'Invoke-WacLegacyDiskCleanup'
)
