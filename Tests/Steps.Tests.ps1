#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Steps: the DISM argument vector and exit-code mapping
    (invariant P0-2), the Recycle Bin sweep (ledger P1-9), the opt-in legacy cleanmgr step and its
    StateFlags snapshot/restore (ledger P0-1), and Delivery Optimization.

.DESCRIPTION
    No external tool is ever executed. Every step runs against Core's injected process invoker, which
    records the file path, argument vector and timeout it was handed and returns a canned result; the
    invoker is removed again in a finally block, and Test-WacIsAdministrator is only forced to $true
    while that invoker is installed, so a stray call outside a fixture can only ever be skipped.

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

function Invoke-WithStubbedTool {
    <#
    .SYNOPSIS
        Runs a body with the recording invoker installed and the privilege check forced on, then
        restores both.
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
    try {
        & $Body
    }
    finally {
        Set-WacProcessInvoker -Invoker $null
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Test-WacIsAdministrator' -Body $originalAdmin
        if ($originalToolPath) {
            Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-WacSystemToolPath' -Body $originalToolPath
        }
        $script:StubResult = @{}
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

        Assert-True $result.Succeeded
        Assert-True $result.RebootRequired
        Assert-False $result.Failed
    }
}

Test-Case 'DISM exit 3017 is a failure and is never folded into success' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = 3017 }
        $result = Invoke-WacComponentCleanup

        Assert-False $result.Succeeded
        Assert-True $result.Failed
        Assert-False $result.RebootRequired
        Assert-True $result.Attempted
    }
}

Test-Case 'a DISM timeout is a failure, bounded by the step ceiling' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = $null; TimedOut = $true }
        $result = Invoke-WacComponentCleanup

        Assert-False $result.Succeeded
        Assert-True $result.Failed
        Assert-True ($script:StubCall[0].TimeoutMs -gt 0)
        Assert-True ($script:StubCall[0].TimeoutMs -le (1000 * 60 * 120)) ('timeout was {0} ms' -f $script:StubCall[0].TimeoutMs)
    }
}

Test-Case 'a DISM that never started is a failure, not a skip' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = $null }
        $result = Invoke-WacComponentCleanup

        Assert-True $result.Failed
        Assert-False $result.Succeeded
        Assert-False $result.Skipped
    }
}

# ---------------------------------------------------------------------------------------------
# Recycle Bin (ledger P1-9)
# ---------------------------------------------------------------------------------------------

Test-Case 'the Recycle Bin enumeration returns only $I/$R entries inside per-SID directories' {
    $sandbox = New-TestSandbox -Prefix 'st-binenum'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $items = @(Get-WacRecycleBinItem -Root $tree.Bin)

        Assert-Equal 4 $items.Count (($items | ForEach-Object { Split-Path -Leaf $_.Path }) -join '; ')
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

        $result = Clear-WacRecycleBin -Root $tree.Bin

        Assert-True $result.Succeeded $result.Detail
        Assert-False $result.Failed $result.Detail
        Assert-True $result.Attempted

        # The post-condition is measured with the SAME predicate the enumeration used.
        Assert-Equal 0 (@(Get-WacRecycleBinItem -Root $tree.Bin)).Count 'the bin still reports entries after a successful sweep'

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

Test-Case 'sweeping an already empty Recycle Bin is success, not failure' {
    $sandbox = New-TestSandbox -Prefix 'st-binempty'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        [void](Clear-WacRecycleBin -Root $tree.Bin)

        $second = Clear-WacRecycleBin -Root $tree.Bin

        Assert-True $second.Succeeded $second.Detail
        Assert-False $second.Failed $second.Detail
        Assert-True $second.Attempted
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

        $result = Clear-WacRecycleBin -Root $tree.Bin

        Assert-True $result.Succeeded $result.Detail
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
        $result = Clear-WacRecycleBin -Root $absent

        Assert-True $result.Succeeded $result.Detail
        Assert-False $result.Failed $result.Detail
        Assert-False (Test-Path -LiteralPath $absent) 'the sweep created its own root'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Legacy Disk Cleanup (ledger P0-1)
# ---------------------------------------------------------------------------------------------

Test-Case 'the legacy cleanmgr step is disabled by default and runs no process at all' {
    Invoke-WithStubbedTool -StubToolPath -Body {
        $result = Invoke-WacLegacyDiskCleanup

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

Test-Case 'the StateFlags snapshot records absence and a pre-existing value' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        $snapshot = @(Get-WacDiskCleanupStateFlag -SageId 9999 -KeyPath $key)

        Assert-Equal 4 $snapshot.Count 'the snapshot must cover every handler, not only the ones it writes'
        foreach ($entry in $snapshot) { Assert-Equal 'StateFlags9999' $entry.ValueName }

        $thumbnail = @($snapshot | Where-Object { $_.Name -eq 'Thumbnail Cache' })
        Assert-Equal 1 $thumbnail.Count
        Assert-False $thumbnail[0].WasAbsent 'a pre-existing value was recorded as absent'
        Assert-Equal 7 $thumbnail[0].Value

        $temporary = @($snapshot | Where-Object { $_.Name -eq 'Temporary Files' })
        Assert-True $temporary[0].WasAbsent 'an absent value was recorded as present'
        Assert-Equal $null $temporary[0].Value
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
        $touched = Enable-WacDiskCleanupCategory -SageId 9999 -KeyPath $key `
            -Category @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files', 'No Such Handler')

        Assert-Equal 2 $touched 'only existing, non-skipped handlers may be written'
        Assert-Equal 2 (Get-StateFlagValue -KeyPath $key -Handler 'Temporary Files' -ValueName 'StateFlags9999')
        Assert-Equal 2 (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999')
        Assert-Equal $null (Get-StateFlagValue -KeyPath $key -Handler 'Offline Pages Files' -ValueName 'StateFlags9999') 'Offline Pages Files was written'
        Assert-Equal $null (Get-StateFlagValue -KeyPath $key -Handler 'Not A Real Handler' -ValueName 'StateFlags9999') 'an unrequested handler was written'
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'restoring the snapshot puts an absent value back to absent and a set value back exactly' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        $snapshot = @(Get-WacDiskCleanupStateFlag -SageId 9999 -KeyPath $key)
        [void](Enable-WacDiskCleanupCategory -SageId 9999 -KeyPath $key -Category @('Temporary Files', 'Thumbnail Cache'))
        Assert-Equal 2 (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') 'the profile was not written before the restore'

        $restored = Restore-WacDiskCleanupStateFlag -Snapshot $snapshot

        Assert-Equal 4 $restored
        Assert-Equal $null (Get-StateFlagValue -KeyPath $key -Handler 'Temporary Files' -ValueName 'StateFlags9999') 'a value that was absent was left behind'
        Assert-Equal 7 (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') 'a pre-existing profile was destroyed'
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
        Invoke-WithStubbedTool -StubToolPath -Body {
            $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

            Assert-Equal 1 $script:StubCall.Count 'the legacy step must run exactly one process'
            Assert-Equal (Join-Path -Path $script:System32 -ChildPath 'cleanmgr.exe') $script:StubCall[0].FilePath

            $argv = @($script:StubCall[0].Arguments)
            Assert-Equal 1 $argv.Count ('vector: {0}' -f ($argv -join ' '))
            Assert-Equal '/sagerun:9999' $argv[0]
            Assert-True $result.Succeeded $result.Detail
            Assert-False $result.Failed $result.Detail
        }

        Assert-Equal $null (Get-StateFlagValue -KeyPath $key -Handler 'Temporary Files' -ValueName 'StateFlags9999') 'the run left its own StateFlags value behind'
        Assert-Equal 7 (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') 'the run destroyed a pre-existing profile'
        Assert-Equal $null (Get-StateFlagValue -KeyPath $key -Handler 'Offline Pages Files' -ValueName 'StateFlags9999') 'Offline Pages Files was written'
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'a cleanmgr timeout is reported Skipped, not Failed, and still restores the profile' {
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        Invoke-WithStubbedTool -StubToolPath -Body {
            $script:StubResult['/sagerun:9999'] = @{ ExitCode = $null; TimedOut = $true }
            $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999

            Assert-True $result.Skipped $result.Detail
            Assert-False $result.Failed 'a killed cleanmgr must not be reported as a failed run'
            Assert-False $result.Succeeded
            Assert-True $result.Attempted
        }

        Assert-Equal 7 (Get-StateFlagValue -KeyPath $key -Handler 'Thumbnail Cache' -ValueName 'StateFlags9999') 'a timeout skipped the restore'
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

            Assert-True $result.Skipped $result.Detail
            Assert-Equal 0 $script:StubCall.Count 'cleanmgr ran even though no handler could be enabled'
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepsModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------------------------
# Delivery Optimization
# ---------------------------------------------------------------------------------------------

function Invoke-WithStubbedDeliveryOptimization {
    <#
    .SYNOPSIS
        Runs a body with command discovery inside the module redirected to a stub.
    .DESCRIPTION
        The real Delete-DeliveryOptimizationCache must never run from a test, so Get-Command itself is
        shadowed inside the module for the duration: it can only ever hand back the stub, or nothing.
        Both shadows are removed again afterwards.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [Parameter(Mandatory = $true)][ValidateSet('Present', 'Absent', 'Failing')][string]$Mode
    )

    # The stubs assert their own inputs: the step has to purge with -Force, and must never ask for
    # pinned files to be deleted as well.
    $stub = $null
    if ($Mode -eq 'Failing') {
        $stub = {
            [CmdletBinding()] param([switch]$Force, [switch]$IncludePinnedFiles)
            if (-not $Force) { throw 'the cache purge was invoked without -Force' }
            if ($IncludePinnedFiles) { throw 'pinned Delivery Optimization files must never be purged' }
            throw 'stubbed cache purge failed'
        }
    }
    elseif ($Mode -eq 'Present') {
        $stub = {
            [CmdletBinding()] param([switch]$Force, [switch]$IncludePinnedFiles)
            if (-not $Force) { throw 'the cache purge was invoked without -Force' }
            if ($IncludePinnedFiles) { throw 'pinned Delivery Optimization files must never be purged' }
            $env:WAC_TEST_DO_CALLS = [string](1 + [int]$env:WAC_TEST_DO_CALLS)
        }
        Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Delete-DeliveryOptimizationCache' -Body $stub
    }

    # Discovery hands back the stub itself through a closure, and $null for 'Absent'. Resolving the
    # name inside the stub would run in THIS suite's session state, not the module's, and silently
    # find nothing - which is why the real cmdlet can never be reached from here either.
    $discovery = {
        param([Parameter(Position = 0)][string]$Name)
        if ($Name -eq 'Delete-DeliveryOptimizationCache') { return $stub }
        return $null
    }.GetNewClosure()

    Set-ModuleFunctionBody -Module $script:StepsModule -Name 'Get-Command' -Body $discovery

    $env:WAC_TEST_DO_CALLS = '0'
    try {
        & $Body
    }
    finally {
        # No scope qualifier: 'function:script:<name>' is accepted by Set-Item but does not remove.
        & $script:StepsModule {
            Remove-Item -Path 'function:Get-Command' -Force -ErrorAction SilentlyContinue
            Remove-Item -Path 'function:Delete-DeliveryOptimizationCache' -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath 'Env:WAC_TEST_DO_CALLS' -ErrorAction SilentlyContinue
    }
}

Test-Case 'Delivery Optimization prefers the supported cmdlet when it is present' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal '1' $env:WAC_TEST_DO_CALLS 'the cmdlet path was not taken exactly once'
        Assert-True $result.Succeeded $result.Detail
        Assert-True $result.Attempted
        Assert-False $result.Skipped
        Assert-False $result.Failed
    }
}

Test-Case 'Delivery Optimization is Skipped when the cmdlet is absent' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Absent' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-True $result.Skipped $result.Detail
        Assert-False $result.Attempted 'an absent cmdlet must not be reported as attempted'
        Assert-False $result.Succeeded
        Assert-False $result.Failed
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS
    }
}

Test-Case 'a Delivery Optimization cmdlet failure is reported, never swallowed' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Failing' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-True $result.Failed $result.Detail
        Assert-False $result.Succeeded
        Assert-True $result.Attempted
        Assert-True ($result.Detail -match 'stubbed cache purge failed') $result.Detail
    }
}

Complete-TestRun
