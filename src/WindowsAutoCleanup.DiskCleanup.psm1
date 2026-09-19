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

# Never select Offline Pages Files; it still receives an explicit off value.
$script:DiskCleanupSkipHandler = @('Offline Pages Files')

# The durable copy of somebody else's cleanmgr selection, written BEFORE this step borrows the
# profile and retired only once every value is proven back (ledger WAC-05R).
$script:CleanMgrSnapshotName = 'cleanmgr-profile.json'

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
        Writes the EXACT sage profile: requested handlers on and every other handler explicitly off.
    .DESCRIPTION
        Only 0 (off) and 2 (on) are documented values, so nothing else is ever written. The
        'Offline Pages Files' handler is never ENABLED; it is disabled like every other unrequested
        handler, including when the borrowed profile has no existing value.

        Turning the requested handlers on is NOT enough. The sage id is a fixed number this project
        borrows, and a machine where someone once ran cleanmgr /sageset with that same number
        already carries enabled values on handlers nobody here selected - /sagerun would run those
        too, and putting the profile back afterwards does not undo what they deleted. Absence does
        not override a handler's default selection. A controlled native Sandbox run stalled with
        absent unrequested values, completed with explicit zeros, then stalled again after restore.
        Every unrequested handler therefore gets DWORD 0, verified before launch and restored after.

        A write that fails is COUNTED, not merely logged: a half-written profile means cleanmgr
        would run against a selection nobody chose.
    .PARAMETER KnownHandler
        The handler names the caller already snapshotted for its rollback. A handler that appeared
        between that snapshot and this write has no recorded original, so writing to it would leave
        a borrowed-profile value that the restore cannot put back; such a handler is refused and
        counted as a failure, which stops the launch instead of silently mutating it. An empty list
        means no snapshot was taken, which is the direct unit-test shape and keeps the previous
        unconditional behaviour.
    .OUTPUTS
        Touched (values actually written), Failed, and Enabled (the handler names switched on).
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateRange(0, 9999)][int]$SageId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Category,
        [string]$KeyPath = $script:VolumeCacheKeyPath,
        [AllowEmptyCollection()][string[]]$KnownHandler = @()
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

    # $null rather than an empty hashtable, so "the caller passed no snapshot" stays distinguishable
    # from "the caller snapshotted an empty key".
    $known = $null
    if ($KnownHandler.Count -gt 0) {
        $known = @{}
        foreach ($name in $KnownHandler) { $known[[string]$name] = $true }
    }

    $handlers = @()
    try { $handlers = @(Get-ChildItem -LiteralPath $KeyPath -ErrorAction Stop) }
    catch {
        # Without the whole handler list the profile cannot be made exact, so nothing is written.
        Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'The VolumeCaches key could not be enumerated, so no cleanmgr profile was written.' -Data @{ error = $_.Exception.Message }
        return [PSCustomObject]@{ Touched = 0; Failed = 1; Enabled = @() }
    }

    if (@($handlers | Where-Object { $requested.ContainsKey([string](Split-Path -Leaf $_.Name)) }).Count -eq 0) {
        return [PSCustomObject]@{ Touched = 0; Failed = 0; Enabled = @() }
    }

    foreach ($handler in $handlers) {
        $name = [string](Split-Path -Leaf $handler.Name)

        if ($null -ne $known -and -not $known.ContainsKey($name)) {
            # This handler did not exist when the rollback snapshot was taken, so its original value
            # was never recorded and nothing here could put it back afterwards. Refusing to write it
            # is counted as a failure, which is what keeps cleanmgr from being launched at all.
            $failed++
            Write-WacLog -Level WARNING -Component 'DiskCleanup' -Message 'A VolumeCaches handler appeared after the profile was snapshotted, so it was left untouched.' -Data @{ handler = $name }
            continue
        }

        $wanted = $requested.ContainsKey($name)

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
        found on the expected ones, with explicit DWORD 0 on every other handler.

        Enabled is DWORD 2 and nothing else. That is the only documented "run this handler" value,
        and disabled is DWORD 0. Missing values, wrong kinds and other numbers are not proof of an
        explicit selection, so they fail the read-back even for unrequested handlers.

        The answer is SET EQUALITY, which needs both directions. Walking the enumerated handlers
        alone only ever proves "nothing observed is wrong": an expected handler that was never
        enumerated - because it disappeared between the write and this read, or because the whole
        enumeration came back empty - is in no observed record, so it can never be found wrong and
        an unproven profile reads back as exact. Every expected name is therefore also subtracted
        from the observed-enabled set and reported as MISSING, so a selection is only exact when the
        two sets are equal.
    .OUTPUTS
        Ok, Reason, Enabled (the handler names found switched on) and Missing (the expected handler
        names that were not read back as enabled).
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateRange(0, 9999)][int]$SageId,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Expected,
        [string]$KeyPath = $script:VolumeCacheKeyPath
    )

    $valueName = 'StateFlags{0:0000}' -f $SageId
    $result = [PSCustomObject]@{ Ok = $false; Reason = ''; Enabled = @(); Missing = @() }

    $wanted = @{}
    foreach ($name in $Expected) { $wanted[[string]$name] = $true }

    $on = New-Object 'System.Collections.Generic.List[string]'
    $wrong = New-Object 'System.Collections.Generic.List[string]'
    # A bare hashtable is case-insensitive, which is what the registry is, so this is the right
    # lookup for subtracting the expected set from what was actually observed switched on.
    $onLookup = @{}

    $handlers = @()
    # -ErrorAction Stop is what makes this a COMPLETE enumeration or none at all: a subkey the
    # provider cannot open would otherwise be a non-terminating error and a short list.
    try { $handlers = @(Get-ChildItem -LiteralPath $KeyPath -ErrorAction Stop) }
    catch {
        $result.Reason = 'the VolumeCaches key could not be read back ({0})' -f $_.Exception.Message
        $result.Missing = @($Expected)
        return $result
    }

    foreach ($handler in $handlers) {
        $name = [string](Split-Path -Leaf $handler.Name)

        $fact = $null
        try { $fact = Get-WacRegistryValueFact -KeyPath ([string]$handler.PSPath) -ValueName $valueName }
        catch {
            $result.Reason = 'the {0} value of {1} could not be read back ({2})' -f $valueName, $name, $_.Exception.Message
            $result.Missing = @($Expected)
            return $result
        }

        $isOn = ((-not $fact.WasAbsent) -and $fact.Kind -eq [Microsoft.Win32.RegistryValueKind]::DWord -and ([int]$fact.Value) -eq 2)
        if ($isOn) {
            [void]$on.Add($name)
            $onLookup[$name] = $true
        }
        $expectedValue = 0
        if ($wanted.ContainsKey($name)) { $expectedValue = 2 }
        if ($fact.WasAbsent -or $fact.Kind -ne [Microsoft.Win32.RegistryValueKind]::DWord -or ([int]$fact.Value) -ne $expectedValue) {
            [void]$wrong.Add($name)
        }
    }

    # The other direction of the equality: an expected handler nobody enumerated is not proven on.
    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in $Expected) {
        if (-not $onLookup.ContainsKey([string]$name)) { [void]$missing.Add([string]$name) }
    }

    $result.Enabled = @($on.ToArray())
    $result.Missing = @($missing.ToArray())

    $problem = New-Object 'System.Collections.Generic.List[string]'
    if ($missing.Count -gt 0) {
        [void]$problem.Add(('{0} expected handler(s) did not read back as enabled: {1}' -f $missing.Count, ((@($missing.ToArray()) | Sort-Object) -join ', ')))
    }
    if ($wrong.Count -gt 0) {
        [void]$problem.Add(('{0} handler(s) do not match the requested selection: {1}' -f $wrong.Count, ((@($wrong.ToArray()) | Sort-Object) -join ', ')))
    }

    if ($problem.Count -gt 0) {
        $result.Reason = (@($problem.ToArray()) -join '; ')
        return $result
    }

    $result.Ok = $true
    return $result
}

function Save-WacCleanMgrSnapshot {
    param([object[]]$Snapshot)
    $write = Write-WacControlFile -Name $script:CleanMgrSnapshotName -Content (ConvertTo-Json -InputObject @($Snapshot) -Depth 4)
    return ([string]$write.Kind -ceq 'Created')
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
        before cleanmgr is launched. Exact means SET EQUALITY against a complete enumeration, not
        "nothing observed looked wrong": a handler that vanishes between the write and the read-back
        is a missing proof, not a pass, and a handler that appears after the snapshot is refused
        outright because this run has no original for it to put back.

        A sage id is a number, not a reservation: the one this step defaults to may already carry
        enabled values from somebody's earlier /sageset, and /sagerun would run those categories
        too. Restoring the profile afterwards does not undo what they deleted, so the selection has
        to be provably right BEFORE the launch. Allocating an unused sage id instead was the
        documented alternative and is not what this does: it would still be a guess about a number
        this code does not own, and the guess would have to be re-made on every run, while making
        one id exact fixes every id a caller can pass.

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
    $snapshotOwned = $false
    $attempted = $false
    $outcome = 'SafeSkip'
    $detail = ''
    $durationMs = 0

    try {
        # The key path travels as an ARGUMENT: in production the block runs in a fresh runspace
        # whose copy of this module knows nothing about a redirected key.
        $snapshotRun = Invoke-WacStepBounded -Component $component -Label 'snapshot' -TimeoutMs $script:VolumeCacheRegistryTimeoutMs `
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
        elseif (-not (Save-WacCleanMgrSnapshot -Snapshot $snapshot)) {
            $outcome = 'Incomplete'
            $detail = 'The cleanmgr recovery record is unavailable or already held; no profile was changed. Resolve the retained original before retrying.'
        }
        elseif (-not (Test-WacMutationAllowed)) {
            $snapshotOwned = $true
            # Writing the sage profile IS a mutation, and it is followed by a whole-machine
            # /sagerun. Neither may start while an earlier mutator could still be running.
            $outcome = 'Incomplete'
            $detail = 'An earlier operation could not be proven stopped, so the cleanmgr profile was not written and cleanmgr was not started.'
        }
        else {
            $snapshotOwned = $true
            # The snapshot's handler names travel with the write. A handler that turned up after the
            # snapshot has no recorded original, and writing to a borrowed profile value this run
            # cannot put back is exactly what the rollback exists to prevent.
            # BOUNDED, and -Mutating. Writing the sage profile is a registry mutation and it was
            # called directly: a wedged registry blocked it outside every deadline the run has, and
            # an abandoned write is not a finished one.
            $writeRun = Invoke-WacStepBounded -Component $component -Label 'write' -Mutating -MutationKind InProcess `
                -TimeoutMs $script:VolumeCacheRegistryTimeoutMs `
                -ArgumentList @($SageId, $Category, $keyPath, @(@($snapshot) | ForEach-Object { [string]$_.Name })) -ScriptBlock {
                    param($SageId, $Category, $KeyPath, $KnownHandler)
                    Enable-WacDiskCleanupCategory -SageId $SageId -Category $Category -KeyPath $KeyPath -KnownHandler $KnownHandler
                }

            if ($writeRun.Outcome -cne 'Succeeded') {
                $enabledResult = [PSCustomObject]@{ Touched = 1; Enabled = @(); Failed = 1 }
            }
            else {
                $enabledResult = @($writeRun.Output)[0]
                if ($null -eq $enabledResult) { $enabledResult = [PSCustomObject]@{ Touched = 1; Enabled = @(); Failed = 1 } }
            }
            # Touched counts values actually written, so this is "did this run change anything",
            # not "did it intend to". Switching somebody else's leftover selection off counts too.
            $mutated = ($enabledResult.Touched -gt 0)
            $enabledHandler = @($enabledResult.Enabled)

            $exact = $null
            if ($enabledResult.Failed -eq 0 -and $enabledHandler.Count -gt 0) {
                # The read-back is bounded for the same reason the write is.
                $exactRun = Invoke-WacStepBounded -Component $component -Label 'readback' `
                    -TimeoutMs $script:VolumeCacheRegistryTimeoutMs `
                    -ArgumentList @($SageId, $enabledHandler, $keyPath) -ScriptBlock {
                        param($SageId, $Expected, $KeyPath)
                        Test-WacDiskCleanupProfileExact -SageId $SageId -Expected $Expected -KeyPath $KeyPath
                    }

                if ($exactRun.Outcome -cne 'Succeeded') {
                    $exact = [PSCustomObject]@{ Ok = $false; Reason = ('the profile read-back did not complete: {0}' -f $exactRun.Error); Enabled = @(); Missing = @() }
                }
                else {
                    $exact = @($exactRun.Output)[0]
                    if ($null -eq $exact) { $exact = [PSCustomObject]@{ Ok = $false; Reason = 'the profile read-back returned nothing'; Enabled = @(); Missing = @() } }
                }
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

                # The watchdog above was sized BEFORE the snapshot, the profile write and the exact
                # read-back. All three are synchronous, each carries its own bound, and together
                # they can consume the budget that number was drawn from. Handing cleanmgr the
                # stale allowance would let one step overrun the whole run - so reclamp against the
                # live deadline immediately before the launch, and start no tool at all when
                # preparation has already spent everything.
                $launchTimeoutMs = Get-WacStepTimeoutMs -RequestedMs $timeoutMs
                if ($launchTimeoutMs -le 0) {
                    # The profile was mutated, so this is not a benign skip: the finally block still
                    # restores every touched value, and the step reports unfinished work.
                    $outcome = 'Incomplete'
                    $detail = 'The run budget was exhausted while the cleanmgr profile was prepared, so cleanmgr was not started.'
                }
                else {
                    $run = Invoke-WacProcess -FilePath $cleanmgr -ArgumentList @(('/sagerun:{0}' -f $SageId)) -TimeoutMs $launchTimeoutMs -Component $component
                    $durationMs = [int]$run.DurationMs

                    if ($run.TimedOut) {
                        # State HAS been mutated by this point, so a killed cleanmgr is an
                        # unfinished step, not the benign skip it used to report.
                        $outcome = 'Incomplete'
                        $detail = 'cleanmgr exceeded its {0} ms watchdog and its process tree was terminated.' -f $launchTimeoutMs
                    }
                    elseif ($run.ExitCode -eq 0) {
                        $outcome = 'Succeeded'
                        $detail = 'cleanmgr /sagerun:{0} completed over {1} handler(s) on every drive.' -f $SageId, $enabledHandler.Count
                    }
                    else {
                        $outcome = 'Failed'
                        $detail = 'cleanmgr exited with {0}.' -f $run.ExitCode
                    }

                    # cleanmgr drives shell handlers, several of which outlive the process that
                    # started them. Its exit code alone was deciding this step.
                    $settled = Resolve-WacSettledOutcome -Outcome $outcome -Detail $detail -Run $run
                    $outcome = $settled.Outcome
                    $detail = $settled.Detail
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
            $restoreRun = Invoke-WacStepBounded -Component $component -Label 'restore' -TimeoutMs $script:VolumeCacheRegistryTimeoutMs -IgnoreRunBudget -Mutating -MutationKind InProcess `
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
                # COMBINED with what cleanmgr reported, never substituted for it. Assigning
                # 'Incomplete' outright DOWNGRADED a recorded failure: the shared ranking is
                # SecurityRefusal > Failed > Incomplete, so a nonzero cleanmgr exit (Failed, rank 2)
                # followed by a restore failure became Incomplete (rank 1) - two problems reported
                # as less serious than the first one alone, and the run turned from exit 2 into
                # exit 6. Get-WacHigherOutcome keeps the worse of the two, so a restore failure can
                # only ever raise the verdict. Both facts stay in $detail; neither erases the other.
                $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
                $detail = '{0} The pre-existing cleanmgr profile could not be restored for {1} handler(s). The original values are kept in the control store for recovery.' -f $detail, $restoreFailed
            }
            else {
                # PROVEN BACK, so the durable copy has nothing left to protect. Retiring it only
                # here is what makes it a recovery record rather than a formality: a restore that
                # failed, or one this run never reached, leaves the originals on disk for the next
                # run or an operator - which is the whole reason they were written before the first
                # value was touched.
                if (-not (Remove-WacControlFile -Name $script:CleanMgrSnapshotName)) {
                    $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'

                    Write-WacLog -Level WARNING -Component $component -Message 'The cleanmgr profile was restored but its recovery copy could not be retired; it is harmless and can be removed by hand.' -Data @{
                        store = [string](Get-WacControlRoot); name = $script:CleanMgrSnapshotName
                    }
                }
            }
        }
    }

    if ($snapshotOwned -and -not $mutated) {
        # A created record with provably zero profile writes belongs to this attempt alone.
        if (-not (Remove-WacControlFile -Name $script:CleanMgrSnapshotName)) {
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
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
    # EXPORTED BECAUSE A BOUNDED WORKER CALLS IT. Invoke-WacStepBounded runs its block as text in a
    # fresh runspace that imports the package, so an unexported name is simply not there - and the
    # read-back failing is what stops cleanmgr from ever being launched on an enabled run.
    'Test-WacDiskCleanupProfileExact',
    'Invoke-WacLegacyDiskCleanup'
)
