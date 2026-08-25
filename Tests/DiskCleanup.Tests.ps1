#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.DiskCleanup: the opt-in legacy cleanmgr step and the
    StateFlags snapshot/restore that makes borrowing someone else's sage profile survivable
    (ledger P0-1, brief B2-5 / T-8).

.DESCRIPTION
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

    foreach ($handler in @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'Not A Real Handler')) {
        [void](New-Item -Path (Join-Path -Path $KeyPath -ChildPath $handler) -Force -ErrorAction Stop)
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

Test-Case 'only the documented value 2 is written, and Offline Pages Files never is' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        $enabled = Enable-WacDiskCleanupCategory -SageId 9999 -KeyPath $key `
            -Category @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'No Such Handler')

        Assert-Equal 2 $enabled.Touched 'only existing, non-skipped handlers may be written'
        Assert-Equal 0 $enabled.Failed
        Assert-Equal 2 (Get-StateFlagValue -KeyPath $key -Handler 'Temporary Files' -ValueName 'StateFlags9999')
        Assert-Equal 2 (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999')
        Assert-Equal $null (Get-StateFlagValue -KeyPath $key -Handler 'Offline Pages Files' -ValueName 'StateFlags9999') 'Offline Pages Files was written'
        Assert-Equal $null (Get-StateFlagValue -KeyPath $key -Handler 'Not A Real Handler' -ValueName 'StateFlags9999') 'an unrequested handler was written'
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
            Assert-Equal 2 $enabled.Failed 'a write that threw was reported as a success'
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

Test-Case 'an enabled cleanmgr run passes only /sagerun and restores the profile afterwards' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        Add-ScratchStateFlagValue -KeyPath $key -Handler 'Not A Real Handler' -ValueName 'StateFlags9999' `
            -Kind ([Microsoft.Win32.RegistryValueKind]::Binary) -Value ([byte[]]@(1, 2, 3))

        $expected = @{}
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'Not A Real Handler')) {
            $expected[$handler] = Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999'
        }

        Invoke-WithStubbedTool -StubToolPath -Body {
            $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

            Assert-Equal 1 $script:StubCall.Count 'the legacy step must run exactly one process'
            Assert-Equal (Join-Path -Path $script:System32 -ChildPath 'cleanmgr.exe') $script:StubCall[0].FilePath

            $argv = @($script:StubCall[0].Arguments)
            Assert-Equal 1 $argv.Count ('vector: {0}' -f ($argv -join ' '))
            Assert-Equal '/sagerun:9999' $argv[0]
            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True $result.Succeeded $result.Detail
            Assert-False $result.Failed $result.Detail

            # Snapshot and restore both went through the bound, and the restore ignores the budget.
            Assert-Equal 2 $script:BoundedCall.Count 'the snapshot and the restore must both be bounded'
            Assert-False $script:BoundedCall[0].IgnoreRunBudget 'the snapshot must respect the run budget'
            Assert-True $script:BoundedCall[1].IgnoreRunBudget 'the restore must run even after the budget expired'
            Assert-True ($script:BoundedCall[1].TimeoutMs -gt 0) 'the restore was given no time at all'
        }

        foreach ($handler in @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'Not A Real Handler')) {
            Assert-StateFlagFact -Expected $expected[$handler] -Actual (Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999') -Handler $handler
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a second enabled cleanmgr run over the same state is still benign' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        $expected = @{}
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
            $expected[$handler] = Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999'
        }

        Invoke-WithStubbedTool -StubToolPath -Body {
            $first = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999
            Assert-Equal 'Succeeded' $first.Outcome $first.Detail
        }

        # Run TWO over the state run one left behind. A step that turns its own leftovers into a
        # non-benign outcome fails exactly here and nowhere else.
        Invoke-WithStubbedTool -StubToolPath -Body {
            $second = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

            Assert-Equal 'Succeeded' $second.Outcome $second.Detail
            Assert-False $second.Failed $second.Detail
        }

        foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
            Assert-StateFlagFact -Expected $expected[$handler] -Actual (Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999') -Handler $handler
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'an unreadable original value declines BEFORE anything is mutated' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        $expected = @{}
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
            $expected[$handler] = Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999'
        }

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
            Invoke-WithStubbedTool -StubToolPath -Body {
                $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

                Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
                Assert-False $result.Failed 'declining before any mutation is not a failed run'
                Assert-Equal 0 $script:StubCall.Count 'cleanmgr ran against a profile that could not be snapshotted'
                Assert-True ($result.Detail -match 'could not be read') $result.Detail
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepModule -Name 'Get-Item'
        }

        foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
            Assert-StateFlagFact -Expected $expected[$handler] -Actual (Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999') -Handler $handler
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a handler that cannot be written is Incomplete and starts no process' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        $expected = Get-StateFlagFact -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999'

        Set-ModuleFunctionBody -Module $script:StepModule -Name 'New-ItemProperty' -Body {
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [Parameter(Mandatory = $true)][string]$Name,
                $PropertyType, $Value, [switch]$Force
            )
            # Only the profile WRITE fails; the restore of a pre-existing value must still work.
            if ($Value -eq 2) { throw (New-Object System.UnauthorizedAccessException('Requested registry access is not allowed.')) }
            return (Microsoft.PowerShell.Management\New-ItemProperty -LiteralPath $LiteralPath -Name $Name -PropertyType $PropertyType -Value $Value -Force:$Force -ErrorAction Stop)
        }

        try {
            Invoke-WithStubbedTool -StubToolPath -Body {
                $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

                Assert-Equal 'Incomplete' $result.Outcome $result.Detail
                Assert-True $result.Failed 'a half-written profile must reach the exit code'
                Assert-False $result.Skipped
                Assert-Equal 0 $script:StubCall.Count 'cleanmgr ran against a profile it could not write'
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepModule -Name 'New-ItemProperty'
        }

        Assert-StateFlagFact -Expected $expected -Actual (Get-StateFlagFact -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') -Handler 'Thumbnail Cache'
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a restore that fails makes the whole step Incomplete' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        Invoke-WithStubbedTool -StubToolPath -Body {
            # call:0 is the snapshot, call:1 is the restore.
            $script:BoundedForce['call:1'] = @{ Outcome = 'Failed'; Error = 'the restore could not run' }
            $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-True $result.Failed 'a profile that could not be put back must reach the exit code'
            Assert-True ($result.Detail -match 'could not be restored') $result.Detail
            Assert-Equal 1 $script:StubCall.Count 'cleanmgr itself should still have run'
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a cleanmgr timeout after the profile was written is Incomplete, not a benign skip' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        $expected = Get-StateFlagFact -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999'

        Invoke-WithStubbedTool -StubToolPath -Body {
            $script:StubResult['/sagerun:9999'] = @{ ExitCode = $null; TimedOut = $true }
            $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-False $result.Skipped 'a killed cleanmgr that had already mutated state is not a benign skip'
            Assert-False $result.Succeeded
            Assert-True $result.Failed
            Assert-True $result.Attempted
        }

        Assert-StateFlagFact -Expected $expected -Actual (Get-StateFlagFact -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') -Handler 'Thumbnail Cache'
        Assert-Equal $null (Get-StateFlagValue -KeyPath $key -Handler 'Temporary Files' -ValueName 'StateFlags9999') 'a timeout skipped the restore'
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a non-zero cleanmgr exit code is a failure' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        Invoke-WithStubbedTool -StubToolPath -Body {
            $script:StubResult['/sagerun:9999'] = @{ ExitCode = 1 }
            $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

            Assert-Equal 'Failed' $result.Outcome $result.Detail
            Assert-True $result.Failed $result.Detail
            Assert-False $result.Succeeded
        }

        Assert-Equal 7 (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') 'a failure skipped the restore'
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a cleanmgr run whose handlers are all missing writes nothing and starts no process' {
    $emptyKey = Join-Path -Path $script:ScratchKeyRoot -ChildPath 'EmptyVolumeCaches'
    [void](New-Item -Path (Join-Path -Path $emptyKey -ChildPath 'Not A Real Handler') -Force -ErrorAction Stop)
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $emptyKey
    try {
        Invoke-WithStubbedTool -StubToolPath -Body {
            $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

            Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
            Assert-True $result.Skipped $result.Detail
            Assert-Equal 0 $script:StubCall.Count 'cleanmgr ran even though no handler could be enabled'

            # A step that wrote nothing must not "restore" anything either: rewriting every value it
            # snapshotted is a registry write nobody asked for.
            Assert-Equal 1 $script:BoundedCall.Count 'a step that mutated nothing still ran a restore'
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'the REAL bound carries arguments in and a snapshot back out' {
    # The registry snapshot travels the same boundary: two scalars in, an array of records out.
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        Set-WacStepBoundedInvoker -Invoker $null

        $bounded = Invoke-WacStepBounded -Component 'DiskCleanup' -TimeoutMs 30000 -ArgumentList @(9999, $key) -ScriptBlock {
            param($SageId, $KeyPath)
            Get-WacDiskCleanupStateFlag -SageId $SageId -KeyPath $KeyPath
        }

        Assert-Equal 'Succeeded' $bounded.Outcome ([string]$bounded.Error)
        $snapshot = @($bounded.Output)
        Assert-Equal 4 $snapshot.Count 'the snapshot did not survive the runspace boundary'

        $thumbnail = @($snapshot | Where-Object { $_.Name -eq 'Thumbnail Cache' })
        Assert-Equal 1 $thumbnail.Count
        Assert-Equal 7 $thumbnail[0].Value
        Assert-Equal 'DWord' ([string]$thumbnail[0].Kind)
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Complete-TestRun
