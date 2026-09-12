#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for Run.ps1's elevated relaunch: the argument vector it builds for the child,
    and what it does with the child once it has one.

.DESCRIPTION
    Both halves run the SHIPPED code. Get-WacRunRelaunchArgument and Invoke-WacElevatedRelaunch are
    lifted out of Run.ps1 by AST and dot-sourced into this suite, so what the cases below exercise
    is produced by the file that ships, not by a copy of it living here.

    Nothing is ever started with -Verb RunAs. The relaunch cases stand Start-Process in and hand
    back a child this suite started itself, with this suite's own token; the termination they assert
    is then performed by the shipped Stop-WacProcessTree against that real process id.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'

Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_RunProbe.ps1')

# Defining the extracted functions is the whole point: what the cases below exercise is produced by
# the shipped code, not by a copy of it living in this suite.
. ([scriptblock]::Create((Get-RunFunctionText -Name 'Get-WacRunRelaunchArgument')))
. ([scriptblock]::Create((Get-RunFunctionText -Name 'Invoke-WacElevatedRelaunch')))

# Also SHIPPED, not stood in for: the relaunch has to let go of the machine-wide operation lock
# before it starts the child, because the child re-runs Run.ps1 and takes the same lock. A parent
# that kept holding it would make its own elevated run exit 3.
. ([scriptblock]::Create((Get-RunFunctionText -Name 'Exit-WacBootstrapLock')))

function New-TestOperationLock {
    <#
    .SYNOPSIS
        A stand-in for the held mutex that records the release. No kernel object is created: this
        asserts the ORDER the shipped code releases in, not that Mutex.ReleaseMutex works.
    #>
    $lock = New-Object PSObject
    Add-Member -InputObject $lock -MemberType NoteProperty -Name 'Released' -Value $false
    Add-Member -InputObject $lock -MemberType ScriptMethod -Name 'ReleaseMutex' -Value { $this.Released = $true }
    Add-Member -InputObject $lock -MemberType ScriptMethod -Name 'Dispose' -Value { }
    return $lock
}

# Invoke-WacElevatedRelaunch hands the script's own bound-parameter snapshot straight to the
# argument builder. The relaunch cases stand that builder in - the vector it really returns has its
# own cases - so an empty table is all the call site needs.
$script:BoundParameter = @{}

# Run.ps1 holds the operation lock across the whole bootstrap, so the lifted relaunch always has one
# to let go of. Cases that assert the release replace this with New-TestOperationLock.
$script:OperationLock = $null

function Get-RelaunchVector {
    <#
    .SYNOPSIS
        Sets the script-scope variables Run.ps1 would have bound, then returns the real vector.
    #>
    param(
        [hashtable]$Bound = @{},
        [bool]$Reset = $true,
        [bool]$Prune = $false,
        [bool]$Legacy = $false,
        [bool]$SkipBin = $false,
        [string]$Level = 'INFO',
        [int]$Budget = 210,
        [AllowEmptyCollection()][string[]]$Category = @(),
        [string]$Mutex = 'Global\WindowsAutoCleanup',
        [string]$ScriptFile = 'C:\Tools\WindowsAutoCleanup\Run.ps1'
    )

    $script:ResetWindowsUpdateBase = $Reset
    $script:PruneSupersededDrivers = $Prune
    $script:EnableLegacyDiskCleanup = $Legacy
    $script:SkipRecycleBin = $SkipBin
    $script:LogLevel = $Level
    $script:BudgetMinutes = $Budget
    $script:SkipCategory = @($Category)
    $script:MutexName = $Mutex
    $script:ScriptPath = $ScriptFile

    return @(Get-WacRunRelaunchArgument -Bound $Bound)
}

function Get-RelaunchPayload {
    <#
    .SYNOPSIS
        The PowerShell source the child will execute: the element after -Command.
    .DESCRIPTION
        The vector is -NoProfile -ExecutionPolicy Bypass [-HostSwitch...] -Command <payload>.
        -Command rather than -File is deliberate and load-bearing: Windows PowerShell 5.1 refuses to
        bind -Switch:$false under -File at all, so every switch value in this file is asserted on the
        payload PowerShell will actually parse.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Vector)

    for ($i = 0; $i -lt $Vector.Count; $i++) {
        if ([string]::Equals($Vector[$i], '-Command', [System.StringComparison]::Ordinal)) {
            if ($i + 1 -lt $Vector.Count) { return $Vector[$i + 1] }
        }
    }
    return ''
}

function Test-PayloadHasSwitch {
    <#
    .SYNOPSIS
        Ordinal check for an exact '-Name:$value' token in the payload.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Payload,
        [Parameter(Mandatory = $true)][string]$Token
    )

    return $Payload.IndexOf($Token, [System.StringComparison]::Ordinal) -ge 0
}

function Test-PayloadHasBareSwitch {
    <#
    .SYNOPSIS
        True when the payload carries '-Name' with no ':value' suffix, which would let the child fall
        back to its own default.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Payload,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return [regex]::IsMatch($Payload, ('(?<![\w:$])-' + [regex]::Escape($Name) + '(?![\w:])'))
}

function Test-VectorContains {
    <#
    .SYNOPSIS
        Ordinal membership. PowerShell's -contains is case-insensitive and would pass a casing
        regression in a switch name.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Vector,
        [Parameter(Mandatory = $true)][string]$Value
    )

    foreach ($element in $Vector) {
        if ([string]::Equals($element, $Value, [System.StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------------------------
# The relaunch vector
# ---------------------------------------------------------------------------------------------

Test-Case 'Run.ps1 parses cleanly and keeps the relaunch vector in one testable function' {
    Assert-Equal 0 (@($script:RunErrors).Count) (($script:RunErrors | ForEach-Object { [string]$_ }) -join ' ; ')
    Assert-True (@($script:RunTokens).Count -gt 100) 'the parser produced no tokens for Run.ps1'

    $vector = Get-RelaunchVector
    Assert-True (Test-VectorContains -Vector $vector -Value '-Command') `
        ('the relaunch must go through -Command, not -File: ' + ($vector -join ' '))
    Assert-True ((Get-RelaunchPayload -Vector $vector).Length -gt 0) 'the -Command payload was empty'
}

Test-Case 'The default relaunch vector states every switch explicitly' {
    $vector = Get-RelaunchVector

    $expected = "-NoProfile -ExecutionPolicy Bypass -Command " +
        "`$LASTEXITCODE = 1; & 'C:\Tools\WindowsAutoCleanup\Run.ps1' -EnableLegacyDiskCleanup:`$false " +
        "-PruneSupersededDrivers:`$false -ResetWindowsUpdateBase:`$true -SkipRecycleBin:`$false " +
        "-BudgetMinutes '210' -LogLevel 'INFO'; exit `$LASTEXITCODE"

    Assert-Equal $expected ($vector -join ' ')
}

Test-Case 'An explicit -ResetWindowsUpdateBase:$false survives the relaunch (ledger P0-2)' {
    $vector = Get-RelaunchVector -Reset $false -Bound @{ ResetWindowsUpdateBase = $false }

    # The load-bearing assertion. A vector that merely CONTAINS the text '-ResetWindowsUpdateBase'
    # is the defect: the child then applies the $true default and DISM runs /ResetBase anyway.
    $payload = Get-RelaunchPayload -Vector $vector

    Assert-True (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$false') `
        ('the payload was ' + $payload)
    Assert-False (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$true') `
        'the child was told the opposite of what the parent was given'
    Assert-False (Test-PayloadHasBareSwitch -Payload $payload -Name 'ResetWindowsUpdateBase') `
        'a bare switch lets the child fall back to its default'

    $expected = "`$LASTEXITCODE = 1; & 'C:\Tools\WindowsAutoCleanup\Run.ps1' -EnableLegacyDiskCleanup:`$false " +
        "-PruneSupersededDrivers:`$false -ResetWindowsUpdateBase:`$false -SkipRecycleBin:`$false " +
        "-BudgetMinutes '210' -LogLevel 'INFO'; exit `$LASTEXITCODE"
    Assert-Equal $expected $payload
}

Test-Case 'An explicit -ResetWindowsUpdateBase:$true is emitted explicitly too' {
    $vector = Get-RelaunchVector -Reset $true -Bound @{ ResetWindowsUpdateBase = $true }

    $payload = Get-RelaunchPayload -Vector $vector
    Assert-True (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$true') $payload
    Assert-False (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$false') $payload
    Assert-False (Test-PayloadHasBareSwitch -Payload $payload -Name 'ResetWindowsUpdateBase') $payload
}

Test-Case 'The three opt-in switches round-trip in both states' {
    $off = Get-RelaunchPayload -Vector (Get-RelaunchVector)
    foreach ($name in @('PruneSupersededDrivers', 'EnableLegacyDiskCleanup', 'SkipRecycleBin')) {
        Assert-True (Test-PayloadHasSwitch -Payload $off -Token ('-{0}:$false' -f $name)) ('missing off state for ' + $name)
        Assert-False (Test-PayloadHasBareSwitch -Payload $off -Name $name) ('bare switch emitted for ' + $name)
    }

    $on = Get-RelaunchPayload -Vector (Get-RelaunchVector -Prune $true -Legacy $true -SkipBin $true `
        -Bound @{ PruneSupersededDrivers = $true; EnableLegacyDiskCleanup = $true; SkipRecycleBin = $true })
    foreach ($name in @('PruneSupersededDrivers', 'EnableLegacyDiskCleanup', 'SkipRecycleBin')) {
        Assert-True (Test-PayloadHasSwitch -Payload $on -Token ('-{0}:$true' -f $name)) ('missing on state for ' + $name)
        Assert-False (Test-PayloadHasSwitch -Payload $on -Token ('-{0}:$false' -f $name)) ('both states emitted for ' + $name)
    }

    # An opt-in switch the caller never asked for must still be stated, and stated as false.
    Assert-True (Test-PayloadHasSwitch -Payload $off -Token '-EnableLegacyDiskCleanup:$false')
}

Test-Case 'A script path containing spaces is quoted exactly once on the command line' {
    $spaced = 'C:\Program Files\Windows Auto Cleanup\Run.ps1'
    $vector = Get-RelaunchVector -ScriptFile $spaced

    # Two quoting layers, each applied exactly once: the payload single-quotes the path for the
    # PowerShell parser, and ConvertTo-WacCommandLine double-quotes the payload for CreateProcess.
    # Doing either twice is how a relaunch ends up looking for a directory called '"C:\Program'.
    $payload = Get-RelaunchPayload -Vector $vector
    Assert-True ($payload.StartsWith(("`$LASTEXITCODE = 1; & '" + $spaced + "' "), [System.StringComparison]::Ordinal)) $payload

    $commandLine = ConvertTo-WacCommandLine -ArgumentList $vector
    $expected = '-NoProfile -ExecutionPolicy Bypass -Command "' + $payload + '"'
    Assert-Equal $expected $commandLine
}

Test-Case 'SkipCategory appears only when it was bound and travels as one token' {
    $absent = Get-RelaunchVector -Category @('Temp')
    Assert-False (Test-VectorContains -Vector $absent -Value '-SkipCategory') `
        'an unbound -SkipCategory was forwarded to the child'

    $empty = Get-RelaunchVector -Category @() -Bound @{ SkipCategory = @() }
    Assert-False (Test-VectorContains -Vector $empty -Value '-SkipCategory') `
        'an empty -SkipCategory was forwarded as a value-less switch'

    $bound = Get-RelaunchPayload -Vector (Get-RelaunchVector -Category @('Windows Update cache', 'Temp') `
        -Bound @{ SkipCategory = @('Windows Update cache', 'Temp') })

    # Under -Command the child's parser sees a real ARRAY, so each category keeps its own quoting and
    # a space inside a category name can no longer split it into two elements.
    $expectedFragment = "-SkipCategory 'Windows Update cache','Temp'"
    Assert-True ($bound.IndexOf($expectedFragment, [System.StringComparison]::Ordinal) -ge 0) `
        ('the payload was ' + $bound)
}

Test-Case 'MutexName appears only when it was bound' {
    $absent = Get-RelaunchPayload -Vector (Get-RelaunchVector -Mutex 'Global\WindowsAutoCleanup')
    Assert-False ($absent.IndexOf('-MutexName', [System.StringComparison]::Ordinal) -ge 0) `
        'the default mutex name was forwarded even though it was never bound'

    $bound = Get-RelaunchPayload -Vector (Get-RelaunchVector -Mutex 'Global\WacTestProbe' `
        -Bound @{ MutexName = 'Global\WacTestProbe' })
    $expectedFragment = "-MutexName 'Global\WacTestProbe'"
    Assert-True ($bound.IndexOf($expectedFragment, [System.StringComparison]::Ordinal) -ge 0) $bound
}

Test-Case 'The elevated relaunch host binds the values the vector carries' {
    $sandbox = New-TestSandbox -Prefix 'orch-relaunch'
    try {
        # The child must be started by the host Run.ps1 would really elevate through, not by the
        # host running this suite: the two do not agree on -File and switch values (see the
        # companion case below), so testing the wrong one would prove nothing about the relaunch.
        $relaunchHost = Get-WacCanonicalPowerShellHost
        Assert-True ([bool]$relaunchHost) 'no machine-trusted PowerShell host was found, so the relaunch cannot be tested'

        $probe = New-ProbeScript -Body $script:ArgumentProbeBody `
            -Path (Join-Path -Path $sandbox -ChildPath 'Windows Auto Cleanup\Relaunch Probe.ps1')

        $vector = Get-RelaunchVector -ScriptFile $probe -Reset $false -Prune $true -Level 'DEBUG' -Budget 42 `
            -Category @('Windows Update cache', 'Temp') -Mutex 'Global\WacTestProbe' `
            -Bound @{
            ResetWindowsUpdateBase = $false
            PruneSupersededDrivers = $true
            SkipCategory           = @('Windows Update cache', 'Temp')
            MutexName              = 'Global\WacTestProbe'
        }

        $result = Invoke-Probe -CommandLine (ConvertTo-WacCommandLine -ArgumentList $vector) -TimeoutMs 90000 -HostExe $relaunchHost

        Assert-True $result.Exited 'the probe child did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ('the relaunch vector did not bind in ' + $relaunchHost + ': ' + $result.ErrorText)
        Assert-Equal $probe (Get-ProbeValue -Output $result.Output -Key 'SELF') 'the spaced script path did not survive quoting'
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'RESET') 'the child fell back to the default (ledger P0-2)'
        Assert-Equal 'True' (Get-ProbeValue -Output $result.Output -Key 'PRUNE')
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'LEGACY')
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'SKIPBIN')
        Assert-Equal 'DEBUG' (Get-ProbeValue -Output $result.Output -Key 'LOGLEVEL')
        Assert-Equal '42' (Get-ProbeValue -Output $result.Output -Key 'BUDGET')
        Assert-Equal 'Global\WacTestProbe' (Get-ProbeValue -Output $result.Output -Key 'MUTEX')
        Assert-Equal 'Windows Update cache|Temp' (Get-ProbeValue -Output $result.Output -Key 'CATEGORY')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The named half of the vector survives -File on the host running this suite' {
    $sandbox = New-TestSandbox -Prefix 'orch-named'
    try {
        $probe = New-ProbeScript -Body $script:ArgumentProbeBody `
            -Path (Join-Path -Path $sandbox -ChildPath 'Windows Auto Cleanup\Named Probe.ps1')

        # Named values and the script path only. The boolean half is covered by the case above,
        # against the host that actually receives it.
        $vector = Get-WacRelaunchArgument -ScriptPath $probe -NamedValue @{
            LogLevel      = 'WARNING'
            BudgetMinutes = '7'
            SkipCategory  = 'Windows Update cache,Temp'
            MutexName     = 'Global\WacTestProbe'
        }

        $result = Invoke-Probe -CommandLine (ConvertTo-WacCommandLine -ArgumentList $vector) -TimeoutMs 90000

        Assert-True $result.Exited 'the probe child did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)
        Assert-Equal $probe (Get-ProbeValue -Output $result.Output -Key 'SELF') 'the spaced script path did not survive quoting'
        Assert-Equal 'WARNING' (Get-ProbeValue -Output $result.Output -Key 'LOGLEVEL')
        Assert-Equal '7' (Get-ProbeValue -Output $result.Output -Key 'BUDGET')
        Assert-Equal 'Global\WacTestProbe' (Get-ProbeValue -Output $result.Output -Key 'MUTEX')
        # One -File token has to re-split into two categories, spaces and all.
        Assert-Equal 'Windows Update cache|Temp' (Get-ProbeValue -Output $result.Output -Key 'CATEGORY')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An elevated child that overruns the run budget is terminated, and the run is Incomplete' {
    # Invoke-WacElevatedRelaunch had no coverage at all: every end-to-end case above runs the rig
    # with -Scheduled, which fails fast instead of relaunching, so nothing has ever exercised the
    # wait, the termination or the 6. The function is LIFTED out of the shipped file and only the
    # things it talks to are stood in for. Nothing is ever started with -Verb RunAs here: the
    # stand-in hands back a child this case started itself, with this suite's own token.
    $logged = New-Object 'System.Collections.Generic.List[object]'

    function Write-WacLog {
        param([string]$Level, [string]$Component, [string]$Message, [hashtable]$Data)
        $null = $Component; $null = $Data
        [void]$logged.Add([PSCustomObject]@{ Level = $Level; Message = $Message })
    }
    function Get-WacCanonicalPowerShellHost { return $script:HostExe }
    function Get-WacRunRelaunchArgument {
        param([hashtable]$Bound)
        $null = $Bound
        return @('-NoProfile', '-Command', 'exit 0')
    }

    # An ordinary child of this suite, and the process the SHIPPED Stop-WacProcessTree is then
    # asked to terminate by its real id - so the kill under test is a real one.
    $child = Start-ProbeProcess -CommandLine (ConvertTo-WacCommandLine -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 120'))
    try {
        # The wait is the ONLY thing stood in for: a real WaitForExit would have to sit out the
        # real budget to come back false, and the value the shipped code asks it for is asserted
        # exactly in the next case. Everything after it - the id, the process tree, the kill - is
        # the live child above.
        $overrunning = New-Object PSObject
        Add-Member -InputObject $overrunning -MemberType NoteProperty -Name 'Id' -Value $child.Id
        Add-Member -InputObject $overrunning -MemberType ScriptMethod -Name 'WaitForExit' -Value {
            param([int]$Milliseconds)
            $null = $Milliseconds
            return $false
        }

        Set-Item -Path 'function:Start-Process' -Value {
            [CmdletBinding()]
            param([string]$FilePath, [string]$ArgumentList, [string]$Verb, [switch]$PassThru)
            if ($Verb -cne 'RunAs') { throw 'the relaunch did not ask for elevation' }
            if (-not $PassThru) { throw 'the relaunch kept no handle on the child it started' }
            $null = $FilePath; $null = $ArgumentList
            return $overrunning
        }

        # Script-scoped because that is where the lifted function reads the budget from, and set
        # per case because Get-RelaunchVector rewrites the same variable. 210 is the shipped
        # default, so the wait asserted below is the one a real unelevated run asks for.
        $script:BudgetMinutes = 210
        $lock = New-TestOperationLock
        $script:OperationLock = $lock
        $exit = Invoke-WacElevatedRelaunch

        Assert-Equal 6 $exit 'a child that never finished the work it was started for did not report Incomplete'

        # The child re-runs Run.ps1 and takes the SAME machine-wide lock. A parent still holding it
        # would make its own elevated run exit 3 against itself.
        Assert-True $lock.Released `
            'the parent never released the machine-wide lock, so the child it started would be refused'
        Assert-True ($null -eq $script:OperationLock) 'the released lock was left behind to be released twice'
        Assert-True ($child.WaitForExit(10000)) 'the overrunning child was left running'
        $budget = @($logged | Where-Object { $_.Message.Contains('exceeded the run budget') })
        Assert-Equal 1 $budget.Count 'the run never said why it gave up on its child'
        Assert-Equal 'CRITICAL' $budget[0].Level `
        'the reason this run exits 6 was written below the highest level -LogLevel accepts'
        Assert-Equal 0 (@($logged | Where-Object { $_.Message.Contains('could not be established') }).Count) `
        'a termination that WAS established was reported as unestablished'
    }
    finally {
        try { if (-not $child.HasExited) { [void](Stop-WacProcessTree -ProcessId $child.Id) } } catch { $null = $_ }
        try { $child.Dispose() } catch { $null = $_ }
    }
}

Test-Case 'A termination that cannot be established is CRITICAL, and the child gets its own full budget' {
    $logged = New-Object 'System.Collections.Generic.List[object]'

    function Write-WacLog {
        param([string]$Level, [string]$Component, [string]$Message, [hashtable]$Data)
        $null = $Component; $null = $Data
        [void]$logged.Add([PSCustomObject]@{ Level = $Level; Message = $Message })
    }
    function Get-WacCanonicalPowerShellHost { return $script:HostExe }
    function Get-WacRunRelaunchArgument {
        param([hashtable]$Bound)
        $null = $Bound
        return @('-NoProfile', '-Command', 'exit 0')
    }

    # Stop-WacProcessTree binds a real kernel handle, so $false is not "probably fine": it means
    # termination could not be ESTABLISHED and the child may still be running.
    function Stop-WacProcessTree {
        param([int]$ProcessId)
        return [PSCustomObject]@{
            Root = $ProcessId; Proven = $false; Bound = @($ProcessId); Survivor = @($ProcessId)
            TaskkillExit = $null; Reason = 'test stand-in: termination could not be proven'
        }
    }

    # A stand-in child: nothing has to be started to reach a wait that comes back false, and the
    # wait the shipped code asks for can be read back exactly.
    $script:RelaunchWaitMs = -1
    $standIn = New-Object PSObject
    Add-Member -InputObject $standIn -MemberType NoteProperty -Name 'Id' -Value 424242
    Add-Member -InputObject $standIn -MemberType ScriptMethod -Name 'WaitForExit' -Value {
        param([int]$Milliseconds)
        $script:RelaunchWaitMs = $Milliseconds
        return $false
    }

    Set-Item -Path 'function:Start-Process' -Value {
        [CmdletBinding()]
        param([string]$FilePath, [string]$ArgumentList, [string]$Verb, [switch]$PassThru)
        $null = $FilePath; $null = $ArgumentList; $null = $Verb; $null = $PassThru
        return $standIn
    }

    $script:BudgetMinutes = 210
    $script:OperationLock = New-TestOperationLock
    $exit = Invoke-WacElevatedRelaunch

    Assert-Equal 6 $exit 'a child that could not be proven terminated was not reported as Incomplete'

    # The child arms the SAME budget from its own start time, so a parent that waited only for what
    # is left of its own would kill a child that was still working.
    Assert-Equal 12660000 $script:RelaunchWaitMs 'the parent did not wait out the child full budget plus a start-up margin'

    $unestablished = @($logged | Where-Object { $_.Message.Contains('could not be established') })
    Assert-Equal 1 $unestablished.Count 'a child that may still be running was not reported at all'
    Assert-Equal 'CRITICAL' $unestablished[0].Level `
    'a child that may still be running was reported below the highest level -LogLevel accepts'
}

Test-Case 'The relaunch reports what happened: no trusted host and a refused elevation are 4, and the child exit code is the run exit code' {
    $logged = New-Object 'System.Collections.Generic.List[object]'

    function Write-WacLog {
        param([string]$Level, [string]$Component, [string]$Message, [hashtable]$Data)
        $null = $Component; $null = $Data
        [void]$logged.Add([PSCustomObject]@{ Level = $Level; Message = $Message })
    }
    function Get-WacRunRelaunchArgument {
        param([hashtable]$Bound)
        $null = $Bound
        return @('-NoProfile', '-Command', 'exit 0')
    }

    # Nothing canonical and machine-trusted to relaunch INTO is a refusal to relaunch at all.
    function Get-WacCanonicalPowerShellHost { return $null }
    Assert-Equal 4 (Invoke-WacElevatedRelaunch) 'a relaunch with no trusted host to use did not report an elevation failure'
    Assert-Equal 'CRITICAL' $logged[$logged.Count - 1].Level `
    'the reason this run exits 4 was written below the highest level -LogLevel accepts'

    function Get-WacCanonicalPowerShellHost { return $script:HostExe }

    # What a cancelled UAC prompt looks like from in here.
    Set-Item -Path 'function:Start-Process' -Value {
        [CmdletBinding()]
        param([string]$FilePath, [string]$ArgumentList, [string]$Verb, [switch]$PassThru)
        $null = $FilePath; $null = $ArgumentList; $null = $Verb; $null = $PassThru
        throw 'The operation was canceled by the user.'
    }

    $script:BudgetMinutes = 210
    Assert-Equal 4 (Invoke-WacElevatedRelaunch) 'a cancelled elevation did not report 4'
    Assert-Equal 'CRITICAL' $logged[$logged.Count - 1].Level `
    'a cancelled elevation was explained below the highest level -LogLevel accepts'

    # And the reason the parent waits at all: it used to return 0 the moment the child was started,
    # so a failed cleanup looked like a success to anything reading the exit code.
    $standIn = New-Object PSObject
    Add-Member -InputObject $standIn -MemberType NoteProperty -Name 'Id' -Value 424243
    Add-Member -InputObject $standIn -MemberType NoteProperty -Name 'ExitCode' -Value 7
    Add-Member -InputObject $standIn -MemberType ScriptMethod -Name 'WaitForExit' -Value {
        param([int]$Milliseconds)
        $null = $Milliseconds
        return $true
    }

    Set-Item -Path 'function:Start-Process' -Value {
        [CmdletBinding()]
        param([string]$FilePath, [string]$ArgumentList, [string]$Verb, [switch]$PassThru)
        $null = $FilePath; $null = $ArgumentList; $null = $Verb; $null = $PassThru
        return $standIn
    }

    Assert-Equal 7 (Invoke-WacElevatedRelaunch) 'the parent did not report the exit code its child produced'
}

Test-Case 'The child exit code is read through a cached handle, so 5.1 cannot report a failure as 0' {
    # The stand-in above answers ExitCode from a plain property, so it passes whether or not the
    # handle was ever cached. Real Windows PowerShell 5.1 does not: Start-Process -PassThru returns
    # a Process whose handle was never cached, and once the child has gone ExitCode answers 0 for
    # ANY real exit code. Measured on both shipped hosts with a child that exited 1 - PowerShell 7
    # reported 1, 5.1 reported 0. Since this function hands the child's code back as the RUN's exit
    # code, and the elevated child is a 5.1 host, a failed cleanup reported success to the scheduler.
    # WaitForExit is not a substitute; the installer and uninstaller call it and still read Handle
    # first. This case models that behaviour so the ordering is asserted rather than assumed.
    function Write-WacLog {
        param([string]$Level, [string]$Component, [string]$Message, [hashtable]$Data)
        $null = $Level; $null = $Component; $null = $Message; $null = $Data
    }
    function Get-WacRunRelaunchArgument {
        param([hashtable]$Bound)
        $null = $Bound
        return @('-NoProfile', '-Command', 'exit 0')
    }
    function Get-WacCanonicalPowerShellHost { return $script:HostExe }

    $script:HandleWasCached = $false
    $standIn = New-Object PSObject
    Add-Member -InputObject $standIn -MemberType NoteProperty -Name 'Id' -Value 424244
    Add-Member -InputObject $standIn -MemberType ScriptProperty -Name 'Handle' -Value {
        $script:HandleWasCached = $true
        return ([IntPtr]1)
    }
    Add-Member -InputObject $standIn -MemberType ScriptProperty -Name 'ExitCode' -Value {
        if ($script:HandleWasCached) { return 5 }
        return 0
    }
    Add-Member -InputObject $standIn -MemberType ScriptMethod -Name 'WaitForExit' -Value {
        param([int]$Milliseconds)
        $null = $Milliseconds
        return $true
    }

    Set-Item -Path 'function:Start-Process' -Value {
        [CmdletBinding()]
        param([string]$FilePath, [string]$ArgumentList, [string]$Verb, [switch]$PassThru)
        $null = $FilePath; $null = $ArgumentList; $null = $Verb; $null = $PassThru
        return $standIn
    }

    $script:BudgetMinutes = 210
    Assert-Equal 5 (Invoke-WacElevatedRelaunch) `
        'the exit code was read without caching the handle first, so on 5.1 a failed elevated run reports 0'
    Assert-True $script:HandleWasCached 'the handle was never cached'
}

Complete-TestRun
