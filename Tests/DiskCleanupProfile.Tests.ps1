#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the cleanmgr LAUNCH contract of the opt-in legacy disk cleanup step: the
    argument vector, the timeout, a non-zero exit, a profile that cannot be verified, and the
    handler nobody selected being switched off and put back (ledger P0-1, brief B2-5 / T-8).

.DESCRIPTION
    Split out of DiskCleanup.Tests.ps1 when that suite reached the 800-line ceiling. The registry
    primitives it kept - category selection, the StateFlags snapshot, the byte-for-byte restore -
    are asserted there; every case here goes through Invoke-WacLegacyDiskCleanup itself. The two
    suites share the fixture header below, which is carried in both files rather than extracted
    into a third; keep the two copies identical.

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
# Legacy Disk Cleanup: the cleanmgr launch (ledger P0-1, brief B2-5 / T-8)
# ---------------------------------------------------------------------------------------------

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

Test-Case 'a handler nobody selected is switched off for the run and put back exactly afterwards' {
    # A sage id is a number this project borrows, not one it owns. On a machine where someone once
    # ran cleanmgr /sageset:9999 their handlers are ALREADY enabled, so enabling only the requested
    # ones leaves theirs running too - and putting the profile back does not undo what they deleted.
    $scenario = @(
        @{ Key = 'Clean';   Name = 'a clean run';       Canned = @{ ExitCode = 0 };                        Outcome = 'Succeeded' },
        @{ Key = 'Launch';  Name = 'a failed launch';   Canned = @{ ExitCode = $null; TimedOut = $false }; Outcome = 'Failed' },
        @{ Key = 'Killed';  Name = 'a killed cleanmgr'; Canned = @{ ExitCode = $null; TimedOut = $true };  Outcome = 'Incomplete' }
    )
    $handlerName = @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'Not A Real Handler')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'

    try {
        foreach ($entry in $scenario) {
            # A key of its own per row rather than one deleted and recreated between them.
            $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath $entry['Key'])
            Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
            # Enabled at this very sage id and requested by nobody. 'Offline Pages Files' is the one
            # this step refuses to ENABLE, which is no reason to leave it running.
            foreach ($stale in @('Not A Real Handler', 'Offline Pages Files')) {
                Add-ScratchStateFlagValue -KeyPath $key -Handler $stale -ValueName 'StateFlags9999' `
                    -Kind ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
            }

            $expected = @{}
            foreach ($handler in $handlerName) {
                $expected[$handler] = Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999'
            }

            Invoke-WithStubbedTool -StubToolPath -Body {
                $script:StubResult['/sagerun:9999'] = $entry['Canned']
                Set-ProfileObserver
                $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999 -Category @('Temporary Files', 'Thumbnail Cache')

                Assert-Equal 1 $script:StubCall.Count ('{0}: cleanmgr must have run exactly once' -f $entry['Name'])
                Assert-Equal $entry['Outcome'] $result.Outcome ('{0}: {1}' -f $entry['Name'], $result.Detail)

                $seen = $script:ObservedProfile
                Assert-Equal '2' ([string]$seen['Temporary Files']) ('{0}: a requested handler was not enabled' -f $entry['Name'])
                Assert-Equal '2' ([string]$seen['Thumbnail Cache']) ('{0}: a requested handler was not enabled' -f $entry['Name'])
                Assert-Equal '0' ([string]$seen['Not A Real Handler']) ('{0}: cleanmgr ran a category nobody selected' -f $entry['Name'])
                Assert-Equal '0' ([string]$seen['Offline Pages Files']) ('{0}: cleanmgr ran a category nobody selected' -f $entry['Name'])
            }

            foreach ($handler in $handlerName) {
                Assert-StateFlagFact -Expected $expected[$handler] `
                    -Actual (Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999') `
                    -Handler ('{0} after {1}' -f $handler, $entry['Name'])
            }
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'an unverifiable profile is never launched, and a restore fault is reported handler by handler' {
    # Two registry-write faults, one table. Row 1 is a profile write that reports success and does
    # nothing - what an enabled-but-not-really selection looks like from inside the step; row 2 is
    # the restore of one pre-existing value failing. Both end non-success.
    $scenario = @(
        @{ Name = 'a profile write that changed nothing'
           Shadow = {
               param([Parameter(Mandatory = $true)][string]$LiteralPath, [Parameter(Mandatory = $true)][string]$Name,
                   $PropertyType, $Value, [switch]$Force)
               if ($LiteralPath -match 'Temporary Files') { return }
               return (Microsoft.PowerShell.Management\New-ItemProperty -LiteralPath $LiteralPath -Name $Name -PropertyType $PropertyType -Value $Value -Force:$Force -ErrorAction Stop)
           }
           Key = 'NoWrite'; Ran = 0; Detail = 'did not read back as the exact requested selection'
           After = @{ 'Temporary Files' = '<absent>'; 'Thumbnail Cache' = '7'; 'Not A Real Handler' = '2' } },

        # 7 is the pre-existing Thumbnail Cache value and nothing else here ever writes it, so only
        # that one restore fails; the profile writes themselves are 2 and 0.
        @{ Name = 'a restore that failed on one handler'
           Shadow = {
               param([Parameter(Mandatory = $true)][string]$LiteralPath, [Parameter(Mandatory = $true)][string]$Name,
                   $PropertyType, $Value, [switch]$Force)
               if ($Value -eq 7) { throw (New-Object System.UnauthorizedAccessException('Requested registry access is not allowed.')) }
               return (Microsoft.PowerShell.Management\New-ItemProperty -LiteralPath $LiteralPath -Name $Name -PropertyType $PropertyType -Value $Value -Force:$Force -ErrorAction Stop)
           }
           Key = 'NoRestore'; Ran = 1; Detail = 'could not be restored for 1 handler'
           After = @{ 'Temporary Files' = '<absent>'; 'Thumbnail Cache' = '2'; 'Not A Real Handler' = '2' } }
    )

    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'

    try {
        foreach ($entry in $scenario) {
            $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath $entry['Key'])
            Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key

            Add-ScratchStateFlagValue -KeyPath $key -Handler 'Not A Real Handler' -ValueName 'StateFlags9999' `
                -Kind ([Microsoft.Win32.RegistryValueKind]::DWord) -Value 2
            Set-ModuleFunctionBody -Module $script:StepModule -Name 'New-ItemProperty' -Body $entry['Shadow']

            try {
                Invoke-WithStubbedTool -StubToolPath -Body {
                    Set-ProfileObserver
                    $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999 -Category @('Temporary Files', 'Thumbnail Cache')

                    Assert-Equal $entry['Ran'] $script:StubCall.Count ('{0}: cleanmgr ran the wrong number of times' -f $entry['Name'])
                    Assert-Equal 'Incomplete' $result.Outcome ('{0}: {1}' -f $entry['Name'], $result.Detail)
                    Assert-True $result.Failed ('{0} was reported as a clean run: {1}' -f $entry['Name'], $result.Detail)
                    Assert-False $result.Skipped ('{0} was reported as a benign skip: {1}' -f $entry['Name'], $result.Detail)
                    Assert-True ($result.Detail -match $entry['Detail']) ('{0}: {1}' -f $entry['Name'], $result.Detail)

                    # The restore asserted below only means something if this run switched the
                    # unrequested handler off in the first place.
                    if ($entry['Ran'] -gt 0) {
                        Assert-Equal '0' ([string]$script:ObservedProfile['Not A Real Handler']) `
                            ('{0}: cleanmgr ran a category nobody selected' -f $entry['Name'])
                    }
                }
            }
            finally {
                Remove-ModuleFunction -Module $script:StepModule -Name 'New-ItemProperty'
            }

            foreach ($handler in @($entry['After'].Keys)) {
                Assert-Equal ([string]$entry['After'][$handler]) `
                    (Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999').Text `
                    ('{0}: {1} was left in the wrong state' -f $entry['Name'], $handler)
            }
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Complete-TestRun
