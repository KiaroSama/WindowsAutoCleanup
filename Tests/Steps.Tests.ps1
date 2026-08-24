#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Steps: the shared outcome contract, the DISM argument
    vector and exit-code mapping (invariant P0-2), the Recycle Bin sweep and its post-condition
    (ledger P1-9, brief T-7), the opt-in legacy cleanmgr step and its StateFlags snapshot/restore
    (ledger P0-1, brief B2-5/T-8), and the C-only Delivery Optimization boundary (brief B2-1).

.DESCRIPTION
    No external tool is ever executed. Every step runs against Core's injected process invoker, which
    records the file path, argument vector and timeout it was handed and returns a canned result; the
    invoker is removed again in a finally block, and Test-WacIsAdministrator is only forced to $true
    while that invoker is installed, so a stray call outside a fixture can only ever be skipped.

    The in-process bounded work runs through the module's own bounded seam, installed the same way.
    That seam is what keeps the Delivery Optimization cases safe: Invoke-WacBounded runs its block as
    TEXT in a fresh runspace with a fresh import of the module, where a stub is invisible, so a test
    that let it do that would purge this machine's real cache. Through the seam the block keeps the
    module's session state, so the Get-Command shadow below is the only thing it can ever resolve.

    The Recycle Bin cases sweep a disposable $Recycle.Bin tree under TEMP - never the real bin - and
    the cleanmgr cases read and write a per-process scratch key under HKCU, never HKLM.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
foreach ($moduleLeaf in @('Core', 'FileSystem', 'Steps')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

$script:StepsModule = Get-Module -Name 'WindowsAutoCleanup.Steps'
$script:System32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32'

# A registry root unique to this process: the two hosts run their suites concurrently against the
# same HKCU hive, so a fixed key name would make them race each other.
$script:ScratchKeyRoot = 'HKCU:\Software\WacTests_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12)

$script:StubCall = New-Object 'System.Collections.Generic.List[object]'
$script:StubResult = @{}

$script:BoundedCall = New-Object 'System.Collections.Generic.List[object]'
$script:BoundedForce = @{}

# Handed to Set-WacProcessInvoker. It closes over this suite's script scope, so the recorded calls
# are visible to the assertions without any global state.
$script:RecordingInvoker = {
    param($FilePath, $ArgumentList, $TimeoutMs)

    $argv = @($ArgumentList)
    [void]$script:StubCall.Add([PSCustomObject]@{
        FilePath  = [string]$FilePath
        Arguments = $argv
        TimeoutMs = [int]$TimeoutMs
    })

    $exitCode = 0
    $timedOut = $false
    $standardOutput = ''

    $key = ''
    if ($argv.Count -gt 0) { $key = [string]$argv[0] }
    if ($script:StubResult.ContainsKey($key)) {
        $canned = $script:StubResult[$key]
        if ($canned.ContainsKey('ExitCode')) { $exitCode = $canned['ExitCode'] }
        if ($canned.ContainsKey('TimedOut')) { $timedOut = [bool]$canned['TimedOut'] }
        if ($canned.ContainsKey('Out')) { $standardOutput = [string]$canned['Out'] }
    }

    return [PSCustomObject]@{
        ExitCode       = $exitCode
        TimedOut       = $timedOut
        StandardOutput = $standardOutput
        StandardError  = ''
        DurationMs     = 5
        Started        = (-not $timedOut)
    }
}

# Handed to Set-WacStepBoundedInvoker. It records the bound it was given and then runs the block
# IN PROCESS, which is the whole point: the block keeps the module's session state, so a shadowed
# cmdlet inside it is the one that runs. A forced entry short-circuits it so the Incomplete and
# Failed branches can be reached without waiting for a real timeout.
$script:RecordingBounded = {
    param($ScriptBlock, $TimeoutMs, $ArgumentList, $Component, $IgnoreRunBudget)

    $index = $script:BoundedCall.Count
    [void]$script:BoundedCall.Add([PSCustomObject]@{
        Index           = $index
        TimeoutMs       = [int]$TimeoutMs
        Component       = [string]$Component
        IgnoreRunBudget = [bool]$IgnoreRunBudget
    })

    foreach ($key in @(('call:{0}' -f $index), [string]$Component)) {
        if (-not $script:BoundedForce.ContainsKey($key)) { continue }

        $forced = $script:BoundedForce[$key]
        $forcedOutcome = [string]$forced['Outcome']
        return [PSCustomObject]@{
            Outcome    = $forcedOutcome
            Started    = ($forcedOutcome -cne 'Incomplete')
            TimedOut   = ($forcedOutcome -ceq 'Incomplete')
            Output     = @()
            HadErrors  = ($forcedOutcome -cne 'Succeeded')
            Error      = [string]$forced['Error']
            DurationMs = 1
        }
    }

    $output = @()
    $failure = $null
    try { $output = @(& $ScriptBlock @ArgumentList) }
    catch { $failure = [string]$_.Exception.Message }

    $outcome = 'Succeeded'
    if ($failure) { $outcome = 'Failed' }

    return [PSCustomObject]@{
        Outcome    = $outcome
        Started    = $true
        TimedOut   = $false
        Output     = $output
        HadErrors  = ($null -ne $failure)
        Error      = $failure
        DurationMs = 1
    }
}

function Get-ModuleFunctionBody {
    <#
    .SYNOPSIS
        The scriptblock a name currently resolves to inside a module, so it can be put back exactly.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (& $Module { param($n) (Get-Item -Path ('function:' + $n)).ScriptBlock } $Name)
}

function Set-ModuleFunctionBody {
    <#
    .SYNOPSIS
        Replaces a name inside a module's own scope. Only the module sees the replacement.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
}

function Remove-ModuleFunction {
    <#
    .SYNOPSIS
        Removes a shadow installed by Set-ModuleFunctionBody.
    .DESCRIPTION
        No scope qualifier: 'function:script:<name>' is accepted by Set-Item but does not remove.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    & $Module { param($n) Remove-Item -Path ('function:' + $n) -Force -ErrorAction SilentlyContinue } $Name
}

function Get-ModuleVariableValue {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (& $Module { param($n) Get-Variable -Name $n -ValueOnly -Scope Script } $Name)
}

function Set-ModuleVariableValue {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowNull()]$Value
    )

    & $Module { param($n, $v) Set-Variable -Name $n -Value $v -Scope Script } $Name $Value
}

function Invoke-WithBoundedSeam {
    <#
    .SYNOPSIS
        Runs a body with the recording bounded invoker installed, then removes it.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$Body)

    $script:BoundedCall.Clear()
    $script:BoundedForce = @{}

    Set-WacStepBoundedInvoker -Invoker $script:RecordingBounded
    try { & $Body }
    finally {
        Set-WacStepBoundedInvoker -Invoker $null
        $script:BoundedForce = @{}
    }
}

function Invoke-WithStubbedTool {
    <#
    .SYNOPSIS
        Runs a body with the recording process invoker and the bounded seam installed and the
        privilege check forced on, then restores all three.
    .DESCRIPTION
        The privilege stub is deliberately scoped to the same window as the invoker: outside a
        fixture the module sees the real check, so nothing in this suite can reach a real dism.exe or
        cleanmgr.exe even if a case forgets to arm the invoker.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [switch]$StubToolPath
    )

    $script:StubCall.Clear()
    $script:StubResult = @{}
    $script:BoundedCall.Clear()
    $script:BoundedForce = @{}

    $originalAdmin = Get-ModuleFunctionBody -Module $script:StepsModule -Name 'Test-WacIsAdministrator'
    Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Test-WacIsAdministrator' -Body { return $true }

    $originalToolPath = $null
    if ($StubToolPath) {
        $originalToolPath = Get-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-WacSystemToolPath'
        # Existence is not probed: cleanmgr.exe ships only with the Desktop Experience, and whether
        # the runner happens to have it must not decide whether this behaviour is covered.
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-WacSystemToolPath' -Body {
            param([Parameter(Mandatory = $true)][string]$Leaf)
            return (Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath $Leaf)
        }
    }

    Set-WacProcessInvoker -Invoker $script:RecordingInvoker
    Set-WacStepBoundedInvoker -Invoker $script:RecordingBounded
    try {
        & $Body
    }
    finally {
        Set-WacProcessInvoker -Invoker $null
        Set-WacStepBoundedInvoker -Invoker $null
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Test-WacIsAdministrator' -Body $originalAdmin
        if ($originalToolPath) {
            Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-WacSystemToolPath' -Body $originalToolPath
        }
        $script:StubResult = @{}
        $script:BoundedForce = @{}
    }
}

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

function New-TestFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Content = 'payload'
    )

    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    [System.IO.File]::WriteAllText($Path, $Content)
    return $Path
}

function New-TestRecycleBin {
    <#
    .SYNOPSIS
        A disposable $Recycle.Bin tree holding one of every entry shape the sweep has to classify.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $bin = Join-Path -Path $Sandbox -ChildPath '$Recycle.Bin'
    $sid = Join-Path -Path $bin -ChildPath 'S-1-5-21-1111111111-2222222222-3333333333-1001'
    $notSid = Join-Path -Path $bin -ChildPath 'NotASid'

    [void][System.IO.Directory]::CreateDirectory($sid)
    [void][System.IO.Directory]::CreateDirectory($notSid)

    [void](New-TestFile (Join-Path -Path $sid -ChildPath '$IAAAAAA.txt') 'metadata')
    [void](New-TestFile (Join-Path -Path $sid -ChildPath '$RAAAAAA.txt') 'content')
    [void](New-TestFile (Join-Path -Path $sid -ChildPath 'desktop.ini') '[.ShellClassInfo]')
    [void](New-TestFile (Join-Path -Path $sid -ChildPath 'notes.txt') 'not a bin entry')
    [void](New-TestFile (Join-Path -Path $notSid -ChildPath '$IZZZZZZ.txt') 'another identity')

    $recycledFolder = Join-Path -Path $sid -ChildPath '$RBBBBBB'
    [void](New-TestFile (Join-Path -Path $recycledFolder -ChildPath 'sub\deep.txt') 'deep')

    $readOnly = Join-Path -Path $sid -ChildPath '$RCCCCCC.txt'
    [void](New-TestFile $readOnly 'read only')
    (Get-Item -LiteralPath $readOnly -Force).Attributes = [System.IO.FileAttributes]::ReadOnly

    return [PSCustomObject]@{
        Bin            = $bin
        Sid            = $sid
        NotSid         = $notSid
        RecycledFolder = $recycledFolder
        ReadOnly       = $readOnly
    }
}

function Add-TestRecycleBinSid {
    <#
    .SYNOPSIS
        A second, SID-shaped per-user directory with one deletable entry in it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Bin,
        [Parameter(Mandatory = $true)][string]$Sid
    )

    $path = Join-Path -Path $Bin -ChildPath $Sid
    [void][System.IO.Directory]::CreateDirectory($path)
    [void](New-TestFile (Join-Path -Path $path -ChildPath '$RSECOND.txt') 'second user content')
    return $path
}

function Invoke-WithStubbedDeliveryOptimization {
    <#
    .SYNOPSIS
        Runs a body with command discovery inside the module redirected to stubs, and the bounded
        seam installed.
    .DESCRIPTION
        Neither real Delivery Optimization cmdlet may ever run from a test, so Get-Command itself is
        shadowed inside the module for the duration: it can only ever hand back a stub, or nothing.
        The bounded blocks re-resolve the command by NAME, which is why shadowing discovery is
        sufficient to contain them. Every shadow is removed again afterwards.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [ValidateSet('Present', 'Absent', 'Failing')][string]$Mode = 'Present',
        [ValidateSet('Present', 'Absent', 'Empty', 'Failing')][string]$ConfigMode = 'Present',
        [string]$WorkingDirectory = 'C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache'
    )

    # The stubs assert their own inputs: the step has to purge with -Force, and must never ask for
    # pinned files to be deleted as well.
    $purgeMode = $Mode
    $purgeStub = {
        [CmdletBinding()] param([switch]$Force, [switch]$IncludePinnedFiles)
        if (-not $Force) { throw 'the cache purge was invoked without -Force' }
        if ($IncludePinnedFiles) { throw 'pinned Delivery Optimization files must never be purged' }
        $env:WAC_TEST_DO_CALLS = [string](1 + [int]$env:WAC_TEST_DO_CALLS)
        if ($purgeMode -eq 'Failing') { throw 'stubbed cache purge failed' }
    }.GetNewClosure()

    $configStubMode = $ConfigMode
    $configWorkingDirectory = $WorkingDirectory
    $configStub = {
        [CmdletBinding()] param()
        $env:WAC_TEST_DO_CONFIG_CALLS = [string](1 + [int]$env:WAC_TEST_DO_CONFIG_CALLS)
        if ($configStubMode -eq 'Failing') { throw 'stubbed Get-DOConfig failed' }
        if ($configStubMode -eq 'Empty') { return [PSCustomObject]@{ DownloadMode = 1 } }
        return [PSCustomObject]@{ DownloadMode = 1; WorkingDirectory = $configWorkingDirectory }
    }.GetNewClosure()

    if ($Mode -ne 'Absent') {
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Delete-DeliveryOptimizationCache' -Body $purgeStub
    }
    if ($ConfigMode -ne 'Absent') {
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-DOConfig' -Body $configStub
    }

    # Discovery hands back the stubs themselves through a closure, and $null for 'Absent'. Resolving
    # a name inside a stub would run in THIS suite's session state, not the module's, and silently
    # find nothing - which is why the real cmdlets can never be reached from here either.
    $deleteAvailable = ($Mode -ne 'Absent')
    $configAvailable = ($ConfigMode -ne 'Absent')
    $discovery = {
        param([Parameter(Position = 0)][string]$Name)
        if ($Name -eq 'Delete-DeliveryOptimizationCache' -and $deleteAvailable) { return $purgeStub }
        if ($Name -eq 'Get-DOConfig' -and $configAvailable) { return $configStub }
        return $null
    }.GetNewClosure()

    Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-Command' -Body $discovery

    $script:BoundedCall.Clear()
    $script:BoundedForce = @{}
    Set-WacStepBoundedInvoker -Invoker $script:RecordingBounded

    $env:WAC_TEST_DO_CALLS = '0'
    $env:WAC_TEST_DO_CONFIG_CALLS = '0'
    try {
        & $Body
    }
    finally {
        Set-WacStepBoundedInvoker -Invoker $null
        $script:BoundedForce = @{}
        Remove-ModuleFunction -Module $script:StepsModule -Name 'Get-Command'
        Remove-ModuleFunction -Module $script:StepsModule -Name 'Delete-DeliveryOptimizationCache'
        Remove-ModuleFunction -Module $script:StepsModule -Name 'Get-DOConfig'
        Remove-Item -LiteralPath 'Env:WAC_TEST_DO_CALLS' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Env:WAC_TEST_DO_CONFIG_CALLS' -ErrorAction SilentlyContinue
    }
}

function Invoke-WithExpiredDeadline {
    <#
    .SYNOPSIS
        Runs a body with the run budget already gone, then puts a budget far enough out that no
        later case in this suite is capped by it.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$Body)

    Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddSeconds(-5))
    try { & $Body }
    finally { Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddDays(30)) }
}

# ---------------------------------------------------------------------------------------------
# The shared outcome contract
# ---------------------------------------------------------------------------------------------

Test-Case 'every outcome derives exactly one set of booleans' {
    $expected = @(
        @{ Outcome = 'Succeeded';       Succeeded = $true;  Skipped = $false; Failed = $false }
        @{ Outcome = 'SafeSkip';        Succeeded = $false; Skipped = $true;  Failed = $false }
        @{ Outcome = 'Incomplete';      Succeeded = $false; Skipped = $false; Failed = $true }
        @{ Outcome = 'SecurityRefusal'; Succeeded = $false; Skipped = $false; Failed = $true }
        @{ Outcome = 'Failed';          Succeeded = $false; Skipped = $false; Failed = $true }
    )

    foreach ($case in $expected) {
        $result = New-WacStepResult -Category 'c' -Outcome $case.Outcome
        Assert-Equal $case.Outcome $result.Outcome
        Assert-Equal $case.Succeeded $result.Succeeded ('Succeeded is wrong for {0}' -f $case.Outcome)
        Assert-Equal $case.Skipped $result.Skipped ('Skipped is wrong for {0}' -f $case.Outcome)
        Assert-Equal $case.Failed $result.Failed ('Failed is wrong for {0}' -f $case.Outcome)
    }
}

Test-Case 'an outcome overrides whatever booleans a caller also passed' {
    # A caller that passes both must not be able to produce a result the outcome cannot express.
    $result = New-WacStepResult -Category 'c' -Outcome 'SafeSkip' -Succeeded $true -Failed $true

    Assert-Equal 'SafeSkip' $result.Outcome
    Assert-True $result.Skipped
    Assert-False $result.Succeeded 'a stale Succeeded survived the outcome'
    Assert-False $result.Failed 'a stale Failed survived the outcome'
}

Test-Case 'a boolean-only caller keeps its own values and is labelled with an outcome' {
    $failed = New-WacStepResult -Category 'c' -Failed $true -Attempted $true
    Assert-Equal 'Failed' $failed.Outcome
    Assert-True $failed.Failed

    $skipped = New-WacStepResult -Category 'c' -Skipped $true
    Assert-Equal 'SafeSkip' $skipped.Outcome

    $succeeded = New-WacStepResult -Category 'c' -Succeeded $true
    Assert-Equal 'Succeeded' $succeeded.Outcome

    # Nothing set at all is benign, never a run-failing outcome invented out of nowhere.
    $nothing = New-WacStepResult -Category 'c'
    Assert-Equal 'SafeSkip' $nothing.Outcome
    Assert-False $nothing.Failed
}

Test-Case 'an unknown outcome name is rejected rather than silently accepted' {
    Assert-Throws -ScriptBlock { New-WacStepResult -Category 'c' -Outcome 'Fine' } -Pattern 'ValidateSet|argument'
}

# ---------------------------------------------------------------------------------------------
# DISM: the argument vector is the invariant (P0-2)
# ---------------------------------------------------------------------------------------------

Test-Case 'DISM runs exactly one process with the documented argument vector and no /ResetBase' {
    Invoke-WithStubbedTool -Body {
        $result = Invoke-WacComponentCleanup

        Assert-Equal 1 $script:StubCall.Count 'the component store step must run exactly one process'
        Assert-Equal (Join-Path -Path $script:System32 -ChildPath 'dism.exe') $script:StubCall[0].FilePath

        $argv = @($script:StubCall[0].Arguments)
        Assert-Equal 4 $argv.Count ('vector: {0}' -f ($argv -join ' '))
        Assert-Equal '/Online' $argv[0]
        Assert-Equal '/Cleanup-Image' $argv[1]
        Assert-Equal '/StartComponentCleanup' $argv[2]
        Assert-Equal '/Quiet' $argv[3]
        Assert-False ($argv -ccontains '/ResetBase') 'DISM must never receive /ResetBase by default'
        Assert-True $result.Attempted
    }
}

Test-Case 'DISM with -ResetBase:$false is byte-identical to the default vector' {
    Invoke-WithStubbedTool -Body {
        [void](Invoke-WacComponentCleanup -ResetBase:$false)

        Assert-Equal 1 $script:StubCall.Count
        $argv = @($script:StubCall[0].Arguments)
        Assert-Equal '/Online /Cleanup-Image /StartComponentCleanup /Quiet' ($argv -join ' ')
        Assert-False ($argv -ccontains '/ResetBase') '-ResetBase:$false still reached DISM'
    }
}

Test-Case 'DISM adds /ResetBase only when it is explicitly requested' {
    Invoke-WithStubbedTool -Body {
        [void](Invoke-WacComponentCleanup -ResetBase)

        $argv = @($script:StubCall[0].Arguments)
        Assert-Equal 5 $argv.Count ('vector: {0}' -f ($argv -join ' '))
        Assert-Equal '/Online /Cleanup-Image /StartComponentCleanup /ResetBase /Quiet' ($argv -join ' ')
    }
}

Test-Case 'DISM exit 0 is success with no reboot flag' {
    Invoke-WithStubbedTool -Body {
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Succeeded' $result.Outcome
        Assert-True $result.Succeeded
        Assert-False $result.RebootRequired
        Assert-False $result.Failed
        Assert-False $result.Skipped
        Assert-True $result.Attempted
    }
}

Test-Case 'DISM exit 3010 is success plus RebootRequired' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = 3010 }
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Succeeded' $result.Outcome
        Assert-True $result.RebootRequired
        Assert-False $result.Failed
    }
}

Test-Case 'DISM exit 3017 is a failure and is never folded into success' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = 3017 }
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Failed' $result.Outcome
        Assert-False $result.Succeeded
        Assert-True $result.Failed
        Assert-False $result.RebootRequired
        Assert-True $result.Attempted
    }
}

Test-Case 'a DISM timeout is incomplete, never a skip, and is bounded by the step ceiling' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = $null; TimedOut = $true }
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Incomplete' $result.Outcome
        Assert-False $result.Succeeded
        Assert-False $result.Skipped 'a killed DISM must not be reported as a benign skip'
        Assert-True $result.Failed 'an incomplete step must still reach the run footer'
        Assert-True ($script:StubCall[0].TimeoutMs -gt 0)
        Assert-True ($script:StubCall[0].TimeoutMs -le (1000 * 60 * 120)) ('timeout was {0} ms' -f $script:StubCall[0].TimeoutMs)
    }
}

Test-Case 'a DISM that never started is a failure, not a skip' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = $null }
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Failed' $result.Outcome
        Assert-True $result.Failed
        Assert-False $result.Succeeded
        Assert-False $result.Skipped
    }
}

# ---------------------------------------------------------------------------------------------
# Recycle Bin (ledger P1-9, brief T-7)
# ---------------------------------------------------------------------------------------------

Test-Case 'the Recycle Bin enumeration returns only $I/$R entries inside per-SID directories' {
    $sandbox = New-TestSandbox -Prefix 'st-binenum'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $scan = Get-WacRecycleBinScan -Root $tree.Bin
        $items = @($scan.Item)

        Assert-Equal 4 $items.Count (($items | ForEach-Object { Split-Path -Leaf $_.Path }) -join '; ')
        Assert-Equal 0 (@($scan.Unreadable)).Count 'a readable bin reported an unreadable directory'
        Assert-Equal 0 (@($scan.Refused)).Count 'a clean bin reported a refusal'

        foreach ($item in $items) {
            Assert-True (Test-WacRecycleBinEntryName -Name (Split-Path -Leaf $item.Path)) ('not a bin entry: {0}' -f $item.Path)
            Assert-Equal (Get-WacNormalizedPath -Path $tree.Sid) $item.SidPath 'an entry outside the per-SID directory was enumerated'
        }

        $leaf = @($items | ForEach-Object { Split-Path -Leaf $_.Path } | Sort-Object)
        Assert-Equal '$IAAAAAA.txt,$RAAAAAA.txt,$RBBBBBB,$RCCCCCC.txt' ($leaf -join ',')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the sweep deletes every enumerated entry and nothing else' {
    $sandbox = New-TestSandbox -Prefix 'st-binsweep'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True $result.Succeeded $result.Detail
            Assert-False $result.Failed $result.Detail
            Assert-True $result.Attempted

            # Both the scan and the post-condition probe must have gone through the bound.
            Assert-Equal 2 $script:BoundedCall.Count 'the scan and its post-condition probe must both be bounded'
            foreach ($call in $script:BoundedCall) {
                Assert-Equal 'RecycleBin' $call.Component
                Assert-True ($call.TimeoutMs -gt 0) 'a bounded Recycle Bin scan was given no time at all'
                Assert-False $call.IgnoreRunBudget 'a Recycle Bin scan must not ignore the run budget'
            }
        }

        # The post-condition is measured with the SAME predicate the enumeration used.
        Assert-Equal 0 (@((Get-WacRecycleBinScan -Root $tree.Bin).Item)).Count 'the bin still reports entries after a successful sweep'

        Assert-False (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$IAAAAAA.txt')) 'a $I metadata file survived'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'a $R content file survived'
        Assert-False (Test-Path -LiteralPath $tree.ReadOnly) 'a read-only $R entry survived'
        Assert-False (Test-Path -LiteralPath $tree.RecycledFolder) 'a recycled folder tree survived'

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath 'desktop.ini')) 'desktop.ini was deleted'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath 'notes.txt')) 'a non-$I/$R file was deleted'
        Assert-True (Test-Path -LiteralPath $tree.Sid) 'the per-SID directory itself was deleted'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.NotSid -ChildPath '$IZZZZZZ.txt')) 'a directory that is not a SID was swept'
        Assert-True (Test-Path -LiteralPath $tree.Bin) 'the bin root itself was deleted'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the sweep works through the REAL bound, not only through the test seam' {
    # Every other Recycle Bin case runs the block in process through the seam, which cannot catch a
    # module that fails to import into the runspace, a function the runspace cannot resolve, or a
    # result that does not survive the boundary. This one takes the production path: no seam.
    $sandbox = New-TestSandbox -Prefix 'st-binreal'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        Set-WacStepBoundedInvoker -Invoker $null

        $result = Clear-WacRecycleBin -Root $tree.Bin

        Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        Assert-True ($result.Detail -match 'before=4 after=0') $result.Detail
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'the real bounded path deleted nothing'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
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

Test-Case 'every per-SID directory on the drive is swept, not only the calling identity' {
    $sandbox = New-TestSandbox -Prefix 'st-binallusers'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $second = Add-TestRecycleBinSid -Bin $tree.Bin -Sid 'S-1-5-21-1111111111-2222222222-3333333333-1002'
        $third = Add-TestRecycleBinSid -Bin $tree.Bin -Sid 'S-1-5-18'

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $tree.Bin
            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        }

        Assert-False (Test-Path -LiteralPath (Join-Path -Path $second -ChildPath '$RSECOND.txt')) 'a second user bin was left untouched'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $third -ChildPath '$RSECOND.txt')) 'the service account bin was left untouched'
        Assert-True (Test-Path -LiteralPath $second) 'a per-SID directory was deleted'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an unreadable per-SID directory is Incomplete, never silently omitted' {
    $sandbox = New-TestSandbox -Prefix 'st-bindenied'
    $deniedSid = 'S-1-5-21-1111111111-2222222222-3333333333-4444'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $denied = Add-TestRecycleBinSid -Bin $tree.Bin -Sid $deniedSid

        # A real access-denied enumeration needs a second identity, which a suite cannot create
        # here. The failure is injected at the same call the real one throws from, so the classifier
        # under test sees exactly the exception it would see in production.
        # A cmdlet is not in the module function drive, so the shadow is REMOVED afterwards rather
        # than restored: removing it reveals the cmdlet again. Measured on both hosts.
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-ChildItem' -Body {
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [switch]$Directory,
                [switch]$Force
            )

            if ($LiteralPath -match 'S-1-5-21-1111111111-2222222222-3333333333-4444') {
                throw (New-Object System.UnauthorizedAccessException('Access to the path is denied.'))
            }
            return (Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Directory:$Directory -Force:$Force -ErrorAction Stop)
        }

        try {
            Invoke-WithBoundedSeam -Body {
                $result = Clear-WacRecycleBin -Root $tree.Bin

                Assert-Equal 'Incomplete' $result.Outcome $result.Detail
                Assert-False $result.Succeeded 'a bin that was never fully read reported success'
                Assert-True $result.Failed 'an unreadable per-SID directory must reach the exit code'
                Assert-True ($result.Detail -match 'unreadableSid=[1-9]') $result.Detail
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepsModule -Name 'Get-ChildItem'
        }

        # The readable bins were still swept: an anomaly in one identity is not a reason to stop.
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'the readable bins were skipped too'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $denied -ChildPath '$RSECOND.txt')) 'an unreadable bin was deleted from anyway'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a per-SID directory that is a reparse point is a SecurityRefusal and is never followed' {
    $sandbox = New-TestSandbox -Prefix 'st-binsidlink'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $outside = Join-Path -Path $sandbox -ChildPath 'outside'
        [void](New-TestFile (Join-Path -Path $outside -ChildPath '$RVICTIM.txt') 'must survive')

        $link = Join-Path -Path $tree.Bin -ChildPath 'S-1-5-21-1111111111-2222222222-3333333333-5555'
        New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop | Out-Null

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
            Assert-False $result.Succeeded
            Assert-True $result.Failed 'a refusal must reach the exit code'
            Assert-True ($result.Detail -match 'refused=[1-9]') $result.Detail
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $outside -ChildPath '$RVICTIM.txt')) 'the sweep followed a per-SID junction out of the bin'
        Assert-True (Test-Path -LiteralPath $link) 'a per-SID directory was deleted rather than refused'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'entries left behind with nothing to explain them are a failure' {
    $sandbox = New-TestSandbox -Prefix 'st-binresidue'
    try {
        $bin = Join-Path -Path $sandbox -ChildPath '$Recycle.Bin'
        $sid = Join-Path -Path $bin -ChildPath 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        [void](New-TestFile (Join-Path -Path $sid -ChildPath '$RLEFT.txt') 'not going anywhere')

        # A deletion primitive that claims everything went fine and removes nothing. Before the
        # post-condition probe existed this shape reported a clean sweep.
        # Removing the shadow reveals the real Remove-WacLeaf from the FileSystem module, which is
        # what keeps that function's own session state intact. Measured on both hosts.
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Remove-WacLeaf' -Body {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)][string]$Path,
                [Parameter(Mandatory = $true)][string]$RootPath,
                [Parameter(Mandatory = $true)]$Stats,
                [switch]$IsDirectory,
                [switch]$IsReparsePoint,
                [int64]$Length = 0
            )
            # The signature has to match the real one; the values themselves are unused here.
            $null = $Path, $RootPath, $Stats, $IsDirectory, $IsReparsePoint, $Length
            return
        }

        try {
            Invoke-WithBoundedSeam -Body {
                $result = Clear-WacRecycleBin -Root $bin

                Assert-Equal 'Failed' $result.Outcome $result.Detail
                Assert-False $result.Succeeded 'a purge that removed nothing reported success'
                Assert-True $result.Failed
                Assert-True ($result.Detail -match 'before=1 after=1') $result.Detail
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepsModule -Name 'Remove-WacLeaf'
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $sid -ChildPath '$RLEFT.txt')) 'the fixture deleted the entry after all'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'entries left behind by a locked leaf are Incomplete rather than a lie' {
    $sandbox = New-TestSandbox -Prefix 'st-binlocked'
    try {
        $bin = Join-Path -Path $sandbox -ChildPath '$Recycle.Bin'
        $sid = Join-Path -Path $bin -ChildPath 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        [void](New-TestFile (Join-Path -Path $sid -ChildPath '$RLOCKED.txt') 'held open elsewhere')

        # Removing the shadow reveals the real Remove-WacLeaf from the FileSystem module, which is
        # what keeps that function's own session state intact. Measured on both hosts.
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Remove-WacLeaf' -Body {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)][string]$Path,
                [Parameter(Mandatory = $true)][string]$RootPath,
                [Parameter(Mandatory = $true)]$Stats,
                [switch]$IsDirectory,
                [switch]$IsReparsePoint,
                [int64]$Length = 0
            )
            # The signature has to match the real one; the values themselves are unused here.
            $null = $Path, $RootPath, $IsDirectory, $IsReparsePoint, $Length
            $Stats.SkippedLocked++
        }

        try {
            Invoke-WithBoundedSeam -Body {
                $result = Clear-WacRecycleBin -Root $bin

                Assert-Equal 'Incomplete' $result.Outcome $result.Detail
                Assert-False $result.Succeeded
                Assert-True $result.Failed 'an unfinished sweep must still reach the exit code'
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepsModule -Name 'Remove-WacLeaf'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the run budget stops the sweep and reports Incomplete without deleting anything' {
    $sandbox = New-TestSandbox -Prefix 'st-bindeadline'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            Invoke-WithExpiredDeadline -Body {
                $result = Clear-WacRecycleBin -Root $tree.Bin

                Assert-Equal 'Incomplete' $result.Outcome $result.Detail
                Assert-False $result.Succeeded
                Assert-True $result.Failed
            }
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'the sweep deleted after the budget had expired'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a scan that exceeds its bound is Incomplete, not an empty bin' {
    $sandbox = New-TestSandbox -Prefix 'st-binbound'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $script:BoundedForce['call:0'] = @{ Outcome = 'Incomplete'; Error = 'the work did not finish within 1 ms.' }
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-False $result.Succeeded 'a bin that was never scanned reported a clean sweep'
            Assert-True $result.Failed
            Assert-Equal 1 $script:BoundedCall.Count 'the sweep ran even though its scan never finished'
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'an unscanned bin was swept anyway'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a bounded scan that comes back with nothing in it is Incomplete' {
    # Invoke-WacBounded reports Succeeded with EMPTY output when the block only wrote a
    # non-terminating error, so the caller has to decide. Nothing measured is nothing proven.
    $sandbox = New-TestSandbox -Prefix 'st-binnooutput'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $script:BoundedForce['call:0'] = @{ Outcome = 'Succeeded'; Error = 'Get-WacRecycleBinScan is not recognized.' }
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'returned nothing') $result.Detail
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'a bin that was never scanned was swept anyway'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a post-condition probe that comes back with nothing in it is Incomplete' {
    $sandbox = New-TestSandbox -Prefix 'st-binpostempty'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $script:BoundedForce['call:1'] = @{ Outcome = 'Succeeded'; Error = 'the probe wrote an error and no result' }
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-False $result.Succeeded 'an unverified sweep reported success'
            Assert-True ($result.Detail -match 'returned nothing') $result.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a post-condition probe that cannot finish is Incomplete, never a clean sweep' {
    $sandbox = New-TestSandbox -Prefix 'st-binpost'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $script:BoundedForce['call:1'] = @{ Outcome = 'Incomplete'; Error = 'the work did not finish within 1 ms.' }
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-False $result.Succeeded 'an unverified sweep reported success'
            Assert-True ($result.Detail -match 'could not be verified') $result.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an unreadable Recycle Bin root is a failure, not an empty bin' {
    $sandbox = New-TestSandbox -Prefix 'st-binroot'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        # A cmdlet is not in the module function drive, so the shadow is REMOVED afterwards rather
        # than restored: removing it reveals the cmdlet again. Measured on both hosts.
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-ChildItem' -Body {
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [switch]$Directory,
                [switch]$Force
            )
            # The signature has to match the real one; the values themselves are unused here.
            $null = $LiteralPath, $Directory, $Force
            throw (New-Object System.UnauthorizedAccessException('Access to the path is denied.'))
        }

        try {
            Invoke-WithBoundedSeam -Body {
                $result = Clear-WacRecycleBin -Root $tree.Bin

                Assert-Equal 'Failed' $result.Outcome $result.Detail
                Assert-False $result.Succeeded 'an unreadable bin reported a clean sweep'
                Assert-True ($result.Detail -match 'could not be enumerated') $result.Detail
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepsModule -Name 'Get-ChildItem'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'sweeping an already empty Recycle Bin is success, not failure' {
    $sandbox = New-TestSandbox -Prefix 'st-binempty'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            [void](Clear-WacRecycleBin -Root $tree.Bin)

            # The SECOND run over the same persistent state is the one that catches a step which
            # turns its own leftovers into a permanent non-benign outcome.
            $second = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Succeeded' $second.Outcome $second.Detail
            Assert-True $second.Succeeded $second.Detail
            Assert-False $second.Failed $second.Detail
            Assert-True $second.Attempted
            Assert-True ($second.Detail -match 'before=0 after=0') $second.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a reparse point in the Recycle Bin is deleted as a link and its target survives' {
    $sandbox = New-TestSandbox -Prefix 'st-binlink'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $outside = Join-Path -Path $sandbox -ChildPath 'outside'
        [void](New-TestFile (Join-Path -Path $outside -ChildPath 'must-survive.txt') 'sentinel')

        $link = Join-Path -Path $tree.Sid -ChildPath '$RDDDDDD'
        New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop | Out-Null

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $tree.Bin
            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        }

        Assert-False (Test-Path -LiteralPath $link) 'the junction itself survived the sweep'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $outside -ChildPath 'must-survive.txt')) 'the sweep followed a junction out of the bin'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the Recycle Bin sweep of a missing root reports success without touching anything' {
    $sandbox = New-TestSandbox -Prefix 'st-binmissing'
    try {
        $absent = Join-Path -Path $sandbox -ChildPath 'no-such-bin'

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $absent

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-False $result.Failed $result.Detail
        }

        Assert-False (Test-Path -LiteralPath $absent) 'the sweep created its own root'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
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
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-Item' -Body {
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
            Remove-ModuleFunction -Module $script:StepsModule -Name 'Get-Item'
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
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'New-ItemProperty' -Body {
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
            Remove-ModuleFunction -Module $script:StepsModule -Name 'New-ItemProperty'
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
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'New-ItemProperty' -Body {
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
            Remove-ModuleFunction -Module $script:StepsModule -Name 'New-ItemProperty'
        }
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'an enabled cleanmgr run passes only /sagerun and restores the profile afterwards' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $key
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
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a second enabled cleanmgr run over the same state is still benign' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $key
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
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'an unreadable original value declines BEFORE anything is mutated' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        $expected = @{}
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
            $expected[$handler] = Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999'
        }

        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-Item' -Body {
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
            Remove-ModuleFunction -Module $script:StepsModule -Name 'Get-Item'
        }

        foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
            Assert-StateFlagFact -Expected $expected[$handler] -Actual (Get-StateFlagFact -KeyPath $key -Handler $handler -ValueName 'StateFlags9999') -Handler $handler
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a handler that cannot be written is Incomplete and starts no process' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        $expected = Get-StateFlagFact -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999'

        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'New-ItemProperty' -Body {
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
            Remove-ModuleFunction -Module $script:StepsModule -Name 'New-ItemProperty'
        }

        Assert-StateFlagFact -Expected $expected -Actual (Get-StateFlagFact -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') -Handler 'Thumbnail Cache'
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a restore that fails makes the whole step Incomplete' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $key
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
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a cleanmgr timeout after the profile was written is Incomplete, not a benign skip' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $key
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
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a non-zero cleanmgr exit code is a failure' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $key
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
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a cleanmgr run whose handlers are all missing writes nothing and starts no process' {
    $emptyKey = Join-Path -Path $script:ScratchKeyRoot -ChildPath 'EmptyVolumeCaches'
    [void](New-Item -Path (Join-Path -Path $emptyKey -ChildPath 'Not A Real Handler') -Force -ErrorAction Stop)
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $emptyKey
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
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------------------------
# Delivery Optimization: the C-only boundary (brief B2-1)
# ---------------------------------------------------------------------------------------------

Test-Case 'Delivery Optimization resolves the cache location before it purges anything' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal '1' $env:WAC_TEST_DO_CONFIG_CALLS 'the effective cache location was not resolved exactly once'
        Assert-Equal '1' $env:WAC_TEST_DO_CALLS 'the cmdlet path was not taken exactly once'
        Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        Assert-True $result.Succeeded $result.Detail
        Assert-True $result.Attempted
        Assert-False $result.Skipped
        Assert-False $result.Failed

        # Both in-process cmdlets ran under a bound, and neither of them ignores the run budget.
        Assert-Equal 2 $script:BoundedCall.Count 'the config read and the purge must both be bounded'
        foreach ($call in $script:BoundedCall) {
            Assert-Equal 'DeliveryOptimization' $call.Component
            Assert-True ($call.TimeoutMs -gt 0) 'a bounded Delivery Optimization call was given no time at all'
            Assert-False $call.IgnoreRunBudget
        }
    }
}

Test-Case 'a Delivery Optimization cache on another drive is a SafeSkip that names the drive' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -WorkingDirectory 'D:\DOCache' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-True $result.Skipped
        Assert-False $result.Failed 'a relocated cache is an expected steady state, not a failure'
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'an off-drive cache was purged anyway'
        Assert-True ($result.Detail -match 'drive D:') $result.Detail
        Assert-True ($result.Detail -match 'D:\\DOCache') $result.Detail

        # Twice over the same configuration stays exactly as benign.
        $second = Clear-WacDeliveryOptimizationCache
        Assert-Equal 'SafeSkip' $second.Outcome $second.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the second run purged an off-drive cache'
    }
}

Test-Case 'a cache location given as an environment variable is expanded before it is judged' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -WorkingDirectory '%SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\DO' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        # DOModifyCacheDrive accepts environment variables, a drive letter or a full path, so an
        # unexpanded string must not be compared against the drive as-is.
        Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        Assert-Equal '1' $env:WAC_TEST_DO_CALLS
        Assert-True ($result.Detail -match 'ServiceProfiles') $result.Detail
        Assert-False ($result.Detail -match '%SystemRoot%') ('the path was never expanded: {0}' -f $result.Detail)
    }
}

Test-Case 'an unresolvable cache location fails closed and purges nothing' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Empty' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'a cache whose location is unknown was purged anyway'
        Assert-True ($result.Detail -match 'WorkingDirectory') $result.Detail
    }

    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -WorkingDirectory '\\server\share\do' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'a UNC cache location was purged anyway'
        Assert-True ($result.Detail -match 'could not be normalised') $result.Detail
    }
}

Test-Case 'Delivery Optimization is a SafeSkip when the configuration cmdlet is absent' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Absent' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the cache was purged without resolving where it is'
        Assert-True ($result.Detail -match 'Get-DOConfig is unavailable') $result.Detail
    }
}

Test-Case 'a configuration read that exceeds its bound is Incomplete and purges nothing' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        $script:BoundedForce['call:0'] = @{ Outcome = 'Incomplete'; Error = 'the work did not finish within 1 ms.' }
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Incomplete' $result.Outcome $result.Detail
        Assert-True $result.Failed 'an unresolved location must reach the exit code'
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the cache was purged after the location read timed out'
    }
}

Test-Case 'a configuration read that throws is reported, never treated as C:' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Failing' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Failed' $result.Outcome $result.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the cache was purged after the location read failed'
        Assert-True ($result.Detail -match 'stubbed Get-DOConfig failed') $result.Detail
    }
}

Test-Case 'Delivery Optimization is a SafeSkip when the purge cmdlet is absent' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Absent' -ConfigMode 'Present' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-True $result.Skipped $result.Detail
        Assert-False $result.Attempted 'an absent cmdlet must not be reported as attempted'
        Assert-False $result.Failed
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS
        Assert-Equal '0' $env:WAC_TEST_DO_CONFIG_CALLS 'availability must be settled before the configuration is read'
    }
}

Test-Case 'a Delivery Optimization purge failure is reported, never swallowed' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Failing' -ConfigMode 'Present' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Failed' $result.Outcome $result.Detail
        Assert-True $result.Failed $result.Detail
        Assert-False $result.Succeeded
        Assert-True $result.Attempted
        Assert-True ($result.Detail -match 'stubbed cache purge failed') $result.Detail
    }
}

Test-Case 'a purge that exceeds its bound is Incomplete, not a completed purge' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        $script:BoundedForce['call:1'] = @{ Outcome = 'Incomplete'; Error = 'the work did not finish within 1 ms.' }
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Incomplete' $result.Outcome $result.Detail
        Assert-False $result.Succeeded 'a purge that never finished reported success'
        Assert-True $result.Failed
    }
}

Test-Case 'an exhausted run budget stops Delivery Optimization before it resolves anything' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        Invoke-WithExpiredDeadline -Body {
            $result = Clear-WacDeliveryOptimizationCache

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-Equal '0' $env:WAC_TEST_DO_CONFIG_CALLS
            Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the cache was purged after the budget expired'
        }
    }
}

Test-Case 'two Delivery Optimization runs in a row stay benign' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        $first = Clear-WacDeliveryOptimizationCache
        $second = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Succeeded' $first.Outcome $first.Detail
        Assert-Equal 'Succeeded' $second.Outcome $second.Detail
        Assert-False $second.Failed 'the second run over the same state stopped being benign'
        Assert-Equal '2' $env:WAC_TEST_DO_CALLS
    }
}

Complete-TestRun
