#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the WindowsAutoCleanup.DiskCleanup registry primitives: category
    selection and the StateFlags snapshot/restore that makes borrowing someone else's sage profile
    survivable, plus the guard that the step runs nothing unless it is asked to
    (ledger P0-1, brief B2-5 / T-8).

.DESCRIPTION
    The cleanmgr LAUNCH contract - the argument vector, the timeout, a non-zero exit, a profile
    that cannot be verified, and the handler nobody selected being switched off and put back -
    lives in DiskCleanupProfile.Tests.ps1. The two were one suite until it reached the 800-line
    ceiling. They share the fixture header below, which is carried in both files rather than
    extracted into a third; keep the two copies identical.

    cleanmgr.exe is never executed. The step runs against Core's injected process invoker, which
    records the file path, argument vector and timeout it was handed and returns a canned result;
    the invoker is removed again in a finally block, and Test-WacIsAdministrator is only forced to
    $true while that invoker is installed, so a stray call outside a fixture can only ever be
    skipped.

    Every registry case reads and writes a per-process scratch key under HKCU, never the real
    HKLM VolumeCaches key. The restoration assertions read the registry DIRECTLY rather than through
    the module's own reader, so a defect shared by both sides cannot make them pass.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_StepHarness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
# The package entry point last, so its own non-forced imports bind to the instances forced here and
# a shadow installed in one of them is the one the code under test sees.
foreach ($moduleLeaf in @('Core', 'FileSystem', 'StepContract', 'RecycleBin', 'DiskCleanup', 'Steps')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

$script:StepModule = Get-Module -Name 'WindowsAutoCleanup.DiskCleanup'

# A registry root unique to this process: the two hosts run their suites concurrently against the
# same HKCU hive, so a fixed key name would make them race each other.
$script:ScratchKeyRoot = 'HKCU:\Software\WacTests_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12)

function New-ScratchVolumeCacheKey {
    <#
    .SYNOPSIS
        A disposable VolumeCaches-shaped key under HKCU with a known StateFlags starting state.
    #>
    param([Parameter(Mandatory = $true)][string]$KeyPath)

    # CreateSubKey rather than New-Item: the provider probes a parent by ENUMERATING it, and the two
    # hosts create and delete their own scratch roots under HKCU:\Software at the same time, so that
    # enumeration intermittently answers ERROR_NO_MORE_DATA. The Win32 call creates the whole chain
    # without reading anything else under the parent.
    $relative = $KeyPath -replace '^(?i)HKCU:\\', ''
    foreach ($handler in @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'Not A Real Handler')) {
        $created = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(($relative + '\' + $handler))
        if ($null -eq $created) { throw ('the scratch key {0} could not be created' -f $handler) }
        $created.Close()
    }

    # One handler starts with a value another tool could have configured; the rest start absent.
    [void](New-ItemProperty -LiteralPath (Join-Path -Path $KeyPath -ChildPath 'Thumbnail Cache') `
        -Name 'StateFlags9999' -PropertyType DWord -Value 7 -Force -ErrorAction Stop)

    return $KeyPath
}

function Add-ScratchStateFlagValue {
    <#
    .SYNOPSIS
        Writes one StateFlags value of an arbitrary kind, so a NON-DWORD original can be covered.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$Handler,
        [Parameter(Mandatory = $true)][string]$ValueName,
        [Parameter(Mandatory = $true)][Microsoft.Win32.RegistryValueKind]$Kind,
        [Parameter(Mandatory = $true)]$Value
    )

    [void](New-ItemProperty -LiteralPath (Join-Path -Path $KeyPath -ChildPath $Handler) `
        -Name $ValueName -PropertyType $Kind -Value $Value -Force -ErrorAction Stop)
}

function Get-StateFlagValue {
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$Handler,
        [Parameter(Mandatory = $true)][string]$ValueName
    )

    try {
        $property = Get-ItemProperty -LiteralPath (Join-Path -Path $KeyPath -ChildPath $Handler) -Name $ValueName -ErrorAction Stop
        return [int]$property.$ValueName
    }
    catch {
        return $null
    }
}

function Get-StateFlagFact {
    <#
    .SYNOPSIS
        Existence, raw value and kind of one StateFlags value, read WITHOUT the module under test.
    .DESCRIPTION
        A byte-for-byte restoration assertion that read through the module's own reader could pass
        because both sides share the same defect. This reads the registry directly.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$Handler,
        [Parameter(Mandatory = $true)][string]$ValueName
    )

    $key = Get-Item -LiteralPath (Join-Path -Path $KeyPath -ChildPath $Handler) -ErrorAction Stop
    $exists = (@($key.GetValueNames()) -ccontains $ValueName)
    if (-not $exists) { return [PSCustomObject]@{ Exists = $false; Kind = $null; Text = '<absent>' } }

    $value = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $text = ''
    if ($value -is [System.Array]) { $text = (@($value | ForEach-Object { [string]$_ }) -join ',') }
    else { $text = [string]$value }

    return [PSCustomObject]@{
        Exists = $true
        Kind   = [string]$key.GetValueKind($ValueName)
        Text   = $text
    }
}

function Assert-StateFlagFact {
    param(
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)][string]$Handler
    )

    Assert-Equal $Expected.Exists $Actual.Exists ('presence changed for {0}' -f $Handler)
    Assert-Equal ([string]$Expected.Kind) ([string]$Actual.Kind) ('kind changed for {0}' -f $Handler)
    Assert-Equal $Expected.Text $Actual.Text ('value changed for {0}' -f $Handler)
}

$script:ObservedProfile = @{}

function Set-ProfileObserver {
    <#
    .SYNOPSIS
        Delegates to the recording invoker and records, as it passes, the profile cleanmgr would
        actually have been run against - the only moment that answers "which categories did this
        run enable", because the step puts the profile back straight afterwards.
    #>
    $keyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    $script:ObservedProfile = @{}
    $observed = $script:ObservedProfile
    $inner = $script:RecordingInvoker

    Set-WacProcessInvoker -Invoker {
        param($FilePath, $ArgumentList, $TimeoutMs)

        foreach ($handler in @(Get-ChildItem -LiteralPath $keyPath -ErrorAction Stop)) {
            $name = [string](Split-Path -Leaf $handler.Name)
            $observed[$name] = (Get-StateFlagFact -KeyPath $keyPath -Handler $name -ValueName 'StateFlags9999').Text
        }

        return (& $inner $FilePath $ArgumentList $TimeoutMs)
    }.GetNewClosure()
}

# ---------------------------------------------------------------------------------------------
# Legacy Disk Cleanup (ledger P0-1, brief B2-5 / T-8)
# ---------------------------------------------------------------------------------------------

Test-Case 'the legacy cleanmgr step is disabled by default and runs no process at all' {
    Invoke-WithStubbedTool -StubToolPath -Body {
        $result = Invoke-WacLegacyDiskCleanup

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-True $result.Skipped $result.Detail
        Assert-False $result.Attempted
        Assert-False $result.Succeeded
        Assert-Equal 0 $script:StubCall.Count 'the disabled legacy step still started a process'
    }
}

Test-Case 'Get-WacDiskCleanupCategory excludes the handler that has no StateFlags value' {
    $categories = @(Get-WacDiskCleanupCategory)

    Assert-True ($categories.Count -gt 5)
    Assert-False ($categories -ccontains 'Offline Pages Files') 'a handler with no StateFlags value is offered to callers'
    Assert-True ($categories -ccontains 'Update Cleanup') 'the orchestrator cannot filter Update Cleanup if it is absent'
    Assert-True ($categories -ccontains 'Temporary Files')

    # The caller must not be able to corrupt the module's own list through the returned array.
    $categories[0] = 'Corrupted'
    Assert-False ((@(Get-WacDiskCleanupCategory)) -ccontains 'Corrupted') 'the returned category list aliases module state'
}

Test-Case 'the StateFlags snapshot records absence, value AND kind as three separate facts' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        Add-ScratchStateFlagValue -KeyPath $key -Handler 'Not A Real Handler' -ValueName 'StateFlags9999' `
            -Kind ([Microsoft.Win32.RegistryValueKind]::String) -Value 'someone else profile'

        $snapshot = @(Get-WacDiskCleanupStateFlag -SageId 9999 -KeyPath $key)

        Assert-Equal 4 $snapshot.Count 'the snapshot must cover every handler, not only the ones it writes'
        foreach ($entry in $snapshot) { Assert-Equal 'StateFlags9999' $entry.ValueName }

        $thumbnail = @($snapshot | Where-Object { $_.Name -eq 'Thumbnail Cache' })
        Assert-Equal 1 $thumbnail.Count
        Assert-False $thumbnail[0].WasAbsent 'a pre-existing value was recorded as absent'
        Assert-Equal 7 $thumbnail[0].Value
        Assert-Equal 'DWord' ([string]$thumbnail[0].Kind)

        # The value the old [int] cast destroyed: a REG_SZ is carried through as a REG_SZ.
        $stringValued = @($snapshot | Where-Object { $_.Name -eq 'Not A Real Handler' })
        Assert-False $stringValued[0].WasAbsent 'a non-DWORD value was recorded as absent'
        Assert-Equal 'someone else profile' ([string]$stringValued[0].Value)
        Assert-Equal 'String' ([string]$stringValued[0].Kind)

        $temporary = @($snapshot | Where-Object { $_.Name -eq 'Temporary Files' })
        Assert-True $temporary[0].WasAbsent 'an absent value was recorded as present'
        Assert-Equal $null $temporary[0].Value
        Assert-Equal $null $temporary[0].Kind
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'the snapshot throws rather than reporting an unreadable original value as absent' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Get-Item' -Body {
            # -Path is carried too: this suite's own helpers read function: paths through Get-Item,
            # and inside the module they reach this shadow like everything else does.
            param(
                [Parameter(Mandatory = $true, ParameterSetName = 'Literal')][string]$LiteralPath,
                [Parameter(Mandatory = $true, ParameterSetName = 'Path', Position = 0)][string]$Path
            )
            if ($Path) { return (Microsoft.PowerShell.Management\Get-Item -Path $Path -ErrorAction Stop) }
            if ($LiteralPath -match 'Thumbnail Cache') { throw (New-Object System.Security.SecurityException('Requested registry access is not allowed.')) }
            return (Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -ErrorAction Stop)
        }

        try {
            Assert-Throws -ScriptBlock { Get-WacDiskCleanupStateFlag -SageId 9999 -KeyPath $key } -Pattern 'could not be opened'
        }
        finally {
            Remove-ModuleFunction -Module $script:StepModule -Name 'Get-Item'
        }
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'the sage id is zero padded to four digits' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        $snapshot = @(Get-WacDiskCleanupStateFlag -SageId 7 -KeyPath $key)
        Assert-Equal 'StateFlags0007' $snapshot[0].ValueName
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'selected handlers are enabled and every other existing handler is explicitly disabled' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        $enabled = Enable-WacDiskCleanupCategory -SageId 9999 -KeyPath $key `
            -Category @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'No Such Handler')

        Assert-Equal 4 $enabled.Touched 'all existing handlers require an explicit selection'
        Assert-Equal 0 $enabled.Failed
        Assert-Equal 2 (Get-StateFlagValue -KeyPath $key -Handler 'Temporary Files' -ValueName 'StateFlags9999')
        Assert-Equal 2 (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999')
        Assert-Equal 0 (Get-StateFlagValue -KeyPath $key -Handler 'Offline Pages Files' -ValueName 'StateFlags9999') 'Offline Pages Files was not disabled'
        Assert-Equal 0 (Get-StateFlagValue -KeyPath $key -Handler 'Not A Real Handler' -ValueName 'StateFlags9999') 'absence does not override a handler default'
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a handler write failure is counted, not swallowed' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'New-ItemProperty' -Body {
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [Parameter(Mandatory = $true)][string]$Name,
                $PropertyType, $Value, [switch]$Force
            )
            # The signature has to match the real one; the values themselves are unused here.
            $null = $LiteralPath, $Name, $PropertyType, $Value, $Force
            throw (New-Object System.UnauthorizedAccessException('Requested registry access is not allowed.'))
        }

        try {
            $enabled = Enable-WacDiskCleanupCategory -SageId 9999 -KeyPath $key -Category @('Temporary Files', 'Thumbnail Cache')

            Assert-Equal 0 $enabled.Touched
            Assert-Equal 4 $enabled.Failed 'a write that threw was reported as a success'
        }
        finally {
            Remove-ModuleFunction -Module $script:StepModule -Name 'New-ItemProperty'
        }
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'restoring the snapshot puts every kind back byte for byte, and absence back to absent' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        Add-ScratchStateFlagValue -KeyPath $key -Handler 'Not A Real Handler' -ValueName 'StateFlags9999' `
            -Kind ([Microsoft.Win32.RegistryValueKind]::MultiString) -Value ([string[]]@('one', 'two'))
        Add-ScratchStateFlagValue -KeyPath $key -Handler 'Offline Pages Files' -ValueName 'StateFlags9999' `
            -Kind ([Microsoft.Win32.RegistryValueKind]::ExpandString) -Value '%SystemRoot%\keep'

        $expected = @{}
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'Not A Real Handler')) {
            $expected[$handler] = Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999'
        }

        $snapshot = @(Get-WacDiskCleanupStateFlag -SageId 9999 -KeyPath $key)
        [void](Enable-WacDiskCleanupCategory -SageId 9999 -KeyPath $key -Category @('Temporary Files', 'Thumbnail Cache', 'Not A Real Handler'))
        Assert-Equal 2 (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') 'the profile was not written before the restore'

        $restore = Restore-WacDiskCleanupStateFlag -Snapshot $snapshot

        Assert-Equal 4 $restore.Restored
        Assert-Equal 0 $restore.Failed
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'Not A Real Handler')) {
            Assert-StateFlagFact -Expected $expected[$handler] -Actual (Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999') -Handler $handler
        }

        # The exact defect this replaced: a REG_SZ or REG_MULTI_SZ original coming back as a DWord.
        Assert-Equal 'MultiString' (Get-StateFlagFact -KeyPath $key -Handler 'Not A Real Handler' -ValueName 'StateFlags9999').Kind
        Assert-Equal 'ExpandString' (Get-StateFlagFact -KeyPath $key -Handler 'Offline Pages Files' -ValueName 'StateFlags9999').Kind
        Assert-Equal '%SystemRoot%\keep' (Get-StateFlagFact -KeyPath $key -Handler 'Offline Pages Files' -ValueName 'StateFlags9999').Text
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a restore that silently did nothing is reported as failed, not restored' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        $snapshot = @(Get-WacDiskCleanupStateFlag -SageId 9999 -KeyPath $key)
        [void](Enable-WacDiskCleanupCategory -SageId 9999 -KeyPath $key -Category @('Temporary Files', 'Thumbnail Cache'))

        # The write reports success and changes nothing. Without the read-back this was a green
        # restore over a profile that had actually been left at the value cleanmgr wanted.
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'New-ItemProperty' -Body {
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [Parameter(Mandatory = $true)][string]$Name,
                $PropertyType, $Value, [switch]$Force
            )
            # The signature has to match the real one; the values themselves are unused here.
            $null = $LiteralPath, $Name, $PropertyType, $Value, $Force
            return
        }

        try {
            $restore = Restore-WacDiskCleanupStateFlag -Snapshot $snapshot

            Assert-Equal 1 $restore.Failed 'the unverified restore of the pre-existing value passed'
            Assert-True ($restore.Handler -ccontains 'Thumbnail Cache') ('handlers reported: {0}' -f ($restore.Handler -join ','))
            Assert-Equal 3 $restore.Restored 'the absent values are removed, so they still restore'
        }
        finally {
            Remove-ModuleFunction -Module $script:StepModule -Name 'New-ItemProperty'
        }
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------------------------
# WAC-08: "exact" has to mean SET EQUALITY, not "nothing observed looked wrong"
#
# Walking the enumerated handlers alone can only ever prove the second. An expected handler that is
# never enumerated appears in no observed record, so it can never be found wrong, and a profile
# nobody proved reads back as exact - which is a cleanmgr /sagerun on every drive against a
# selection this run cannot vouch for.
# ---------------------------------------------------------------------------------------------

function New-HandlerKey {
    <#
    .SYNOPSIS
        A VolumeCaches-shaped scratch key holding exactly the handlers named, and no others.
    .DESCRIPTION
        CreateSubKey rather than New-Item, for the same reason New-ScratchVolumeCacheKey uses it:
        the provider probes a parent by ENUMERATING it, and the two hosts create and delete their
        own scratch roots under HKCU:\Software at the same time.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [AllowEmptyCollection()][string[]]$Handler = @()
    )

    $relative = $KeyPath -replace '^(?i)HKCU:\\', ''
    $created = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($relative)
    if ($null -eq $created) { throw ('the scratch key {0} could not be created' -f $KeyPath) }
    $created.Close()

    foreach ($name in $Handler) {
        $child = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(($relative + '\' + $name))
        if ($null -eq $child) { throw ('the scratch key {0} could not be created' -f $name) }
        $child.Close()
    }

    return $KeyPath
}

function Invoke-ProfileExact {
    <#
    .SYNOPSIS
        Calls Test-WacDiskCleanupProfileExact inside the module's own scope.
    .DESCRIPTION
        The function is deliberately not exported: it is the step's internal proof, not part of the
        step contract, and exporting it only to test it would widen the module's surface.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Expected,
        [int]$SageId = 9999
    )

    return (& $script:StepModule {
        param($s, $e, $k)
        Test-WacDiskCleanupProfileExact -SageId $s -Expected ([string[]]@($e)) -KeyPath $k
    } $SageId (@($Expected)) $KeyPath)
}

Test-Case 'an expected handler that was never enumerated is not proven enabled' {
    # The WAC-08 counterexample exactly: Expected={A} against an enumeration that returns only a
    # correctly disabled B. Nothing observed is wrong, and the selection is still unproven.
    $key = New-HandlerKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'Vanished') -Handler @('Thumbnail Cache')
    try {
        Add-ScratchStateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999' `
            -Kind ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0

        $exact = Invoke-ProfileExact -KeyPath $key -Expected @('Temporary Files')

        Assert-False $exact.Ok ('an unenumerated handler passed the exact check: {0}' -f $exact.Reason)
        Assert-True (@($exact.Missing) -ccontains 'Temporary Files') ('missing: {0}' -f (@($exact.Missing) -join ','))
        Assert-Equal 0 (@($exact.Enabled)).Count 'nothing was enabled, so nothing may be reported as enabled'
        Assert-True ($exact.Reason -match 'did not read back as enabled') $exact.Reason
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a non-empty selection against an EMPTY enumeration is not exact' {
    # The degenerate form of the same defect: nothing at all comes back, so no handler can be found
    # wrong, and a check that only subtracts in one direction has nothing to object to.
    $key = New-HandlerKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'Empty')
    try {
        $exact = Invoke-ProfileExact -KeyPath $key -Expected @('Temporary Files', 'Thumbnail Cache')

        Assert-False $exact.Ok ('an empty enumeration passed the exact check: {0}' -f $exact.Reason)
        Assert-Equal 2 (@($exact.Missing)).Count ('missing: {0}' -f (@($exact.Missing) -join ','))
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'an unexpected value, kind or enabled handler still fails the exact check' {
    # Controls for the other direction of the equality, which the one-sided walk already caught.
    # They are here so the added subtraction cannot quietly replace them.
    $scenario = @(
        @{ Name = 'an unexpected handler left enabled'; Key = 'Unexpected'
           Kind = [Microsoft.Win32.RegistryValueKind]::DWord; Value = 2; Wrong = 'Thumbnail Cache' },
        @{ Name = 'a value that is neither 0 nor 2'; Key = 'OddValue'
           Kind = [Microsoft.Win32.RegistryValueKind]::DWord; Value = 7; Wrong = 'Thumbnail Cache' },
        @{ Name = 'the right number written as the wrong kind'; Key = 'WrongKind'
           Kind = [Microsoft.Win32.RegistryValueKind]::String; Value = '0'; Wrong = 'Thumbnail Cache' }
    )

    try {
        foreach ($entry in $scenario) {
            $key = New-HandlerKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath $entry['Key']) `
                -Handler @('Temporary Files', 'Thumbnail Cache')
            Add-ScratchStateFlagValue -KeyPath $key -Handler 'Temporary Files' -ValueName 'StateFlags9999' `
                -Kind ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
            Add-ScratchStateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999' `
                -Kind $entry['Kind'] -Value $entry['Value']

            $exact = Invoke-ProfileExact -KeyPath $key -Expected @('Temporary Files')

            Assert-False $exact.Ok ('{0}: passed the exact check' -f $entry['Name'])
            Assert-True ($exact.Reason -match [regex]::Escape($entry['Wrong'])) ('{0}: {1}' -f $entry['Name'], $exact.Reason)
        }
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a correct selection passes, empty or not' {
    # The controls that stop the equality check from becoming a blanket refusal. A profile that IS
    # exactly right has to read back as exactly right, including the case where nothing is selected.
    try {
        $key = New-HandlerKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'Correct') `
            -Handler @('Temporary Files', 'Thumbnail Cache')
        Add-ScratchStateFlagValue -KeyPath $key -Handler 'Temporary Files' -ValueName 'StateFlags9999' `
            -Kind ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
        Add-ScratchStateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999' `
            -Kind ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0

        $exact = Invoke-ProfileExact -KeyPath $key -Expected @('Temporary Files')
        Assert-True $exact.Ok ('a correct selection was refused: {0}' -f $exact.Reason)
        Assert-Equal 'Temporary Files' ((@($exact.Enabled)) -join ',')
        Assert-Equal 0 (@($exact.Missing)).Count

        $offKey = New-HandlerKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'AllOff') `
            -Handler @('Temporary Files', 'Thumbnail Cache')
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
            Add-ScratchStateFlagValue -KeyPath $offKey -Handler $handler -ValueName 'StateFlags9999' `
                -Kind ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 0
        }

        $none = Invoke-ProfileExact -KeyPath $offKey -Expected @()
        Assert-True $none.Ok ('an all-off profile with nothing selected was refused: {0}' -f $none.Reason)
        Assert-Equal 0 (@($none.Enabled)).Count
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a handler missing from the rollback snapshot is refused, not written' {
    # A handler that appeared after the snapshot has no recorded original, so a value written to it
    # could not be put back. Refusing is counted as a failure, which is what stops the launch.
    $key = New-HandlerKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'Appeared') `
        -Handler @('Temporary Files', 'Thumbnail Cache')
    try {
        $enabled = Enable-WacDiskCleanupCategory -SageId 9999 -KeyPath $key `
            -Category @('Temporary Files') -KnownHandler @('Temporary Files')

        Assert-Equal 1 $enabled.Touched 'the snapshotted handler must still be written'
        Assert-Equal 1 $enabled.Failed 'a handler with no recorded original was written anyway'
        Assert-Equal 2 (Get-StateFlagValue -KeyPath $key -Handler 'Temporary Files' -ValueName 'StateFlags9999')
        Assert-Equal $null (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') `
            'a borrowed profile value with no snapshot was mutated'
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Complete-TestRun
