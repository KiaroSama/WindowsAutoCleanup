#Requires -Version 5.1
<#
.SYNOPSIS
    The stub-module sandbox EntryPointGuard.Tests.ps1 runs the real entry-point scripts inside,
    and the stand-ins that drive it.

.DESCRIPTION
    Dot-sourced, not imported, so the suite keeps one script scope - the same reason _Harness.ps1
    is. It is its own file because it is its own responsibility: everything here builds, drives or
    reports on the sandbox, and what each CASE proves stays in the suite beside the case.
    Assert-NothingMutated is the one shared assertion, because every case makes it identically.

    The entry-point scripts are copied byte for byte and only their DEPENDENCIES are replaced, so
    the code under test is the shipped code. Every stub records the calls it receives, and the
    ones that would change the machine also throw, so a flow that reaches one fails loudly.

    $script:RepoRoot is the suite's, read when these functions run rather than when they load.
#>

Set-StrictMode -Version 2.0

# Reached only when the gate has already let the run through, and each is the LAST thing its entry
# point does before it stops for an unrelated reason. Seeing one is how a benign run proves the gate
# passed without anything real being staged, registered or deleted.
$script:GatePassedMarker = @{
    'Install-WindowsAutoCleanupTask.ps1' = 'Test-WacSystemDriveSupported'
    'Uninstall-WindowsAutoCleanupTask.ps1' = 'Get-WacDeploymentSlotPath'
}

# Nothing in this list may be reached by any run in this suite, refused or not: no run here is ever
# allowed to change the machine. Log retention is deliberately NOT in it - pruning old logs on a
# trusted state directory is correct - and is asserted separately for a REFUSED run, where the
# directory being pruned may be the very one the run just refused.
$script:MutatingCall = @(
    'New-WacDeploymentStage', 'Switch-WacDeploymentStage', 'Remove-WacDeployment',
    'Remove-WacDeploymentPrevious', 'Restore-WacDeploymentPrevious', 'Remove-WacInstalledTask')

function New-StubDeployment {
    <#
    .SYNOPSIS
        A sandbox holding the REAL entry points and the REAL shared gate over stub modules.
    .DESCRIPTION
        The scripts are copied byte for byte: the code under test is the shipped code, only its
        dependencies are replaced. Every stub records its own name, and the ones that would change
        the machine also throw, so a flow that reaches one fails loudly instead of quietly.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $src = Join-Path -Path $Sandbox -ChildPath 'src'
    [void][System.IO.Directory]::CreateDirectory($src)
    [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $Sandbox -ChildPath 'state'))

    foreach ($name in $script:EntryPoint) {
        Copy-Item -LiteralPath (Join-Path -Path $script:RepoRoot -ChildPath $name) `
            -Destination (Join-Path -Path $Sandbox -ChildPath $name) -Force
    }
    foreach ($part in @('WindowsAutoCleanup.EntryGate.ps1', 'WindowsAutoCleanup.InstallerTask.ps1')) {
        Copy-Item -LiteralPath (Join-Path -Path $script:RepoRoot -ChildPath ('src\' + $part)) `
            -Destination (Join-Path -Path $src -ChildPath $part) -Force
    }

    $core = @(
        'Set-StrictMode -Version 2.0',
        'function Add-StubCall { param([string]$Name) [System.IO.File]::AppendAllText($env:WAC_STUB_CALLS, $Name + [Environment]::NewLine) }',
        'function Initialize-WacRun { param([string]$BaseName, [string[]]$CandidateRoot, [string]$LogLevel, [int]$BudgetMinutes, [string]$BootstrapLogPath, [int]$ShutdownMarginSeconds) Add-StubCall ''Initialize-WacRun''; return $true }',
        # Every line that reaches the FILE log is recorded, because "nothing was written through the
        # path this run refused" is only checkable if the writes are visible.
        'function Write-WacLog { param($Level, $Component, $Message, $Data) [System.IO.File]::AppendAllText($env:WAC_STUB_LOGWRITES, ($Component + ''|'' + $Message + [Environment]::NewLine)) }',
        'function Test-WacDeadlineExpired { return ($env:WAC_STUB_BUDGET -eq ''expired'') }',
        'function Close-WacLog { Add-StubCall ''Close-WacLog'' }',
        'function Get-WacLogPath { return (Join-Path -Path $env:WAC_STUB_STATE -ChildPath ''run.log'') }',
        'function Get-WacLogDirectory { return $env:WAC_STUB_STATE }',
        'function Get-WacDataRoot { return $env:WAC_STUB_STATE }',
        'function Remove-WacOldLog { param($LogDirectory, $Pattern, $KeepCount) Add-StubCall ''Remove-WacOldLog'' }',
        'function Test-WacIsAdministrator { return ($env:WAC_STUB_ADMIN -ne ''False'') }',
        'function Test-WacSystemDriveSupported { Add-StubCall ''Test-WacSystemDriveSupported''; return $false }',
        'function Get-WacCanonicalPowerShellHost { Add-StubCall ''Get-WacCanonicalPowerShellHost''; if ($env:WAC_STUB_HOST) { return $env:WAC_STUB_HOST }; return $null }',
        'function Enter-WacSingleInstance { param([string]$Name) Add-StubCall ''Enter-WacSingleInstance''; return ([PSCustomObject]@{ Name = $Name }) }',
        'function Exit-WacSingleInstance { param($Mutex) Add-StubCall ''Exit-WacSingleInstance'' }',
        # The structured verdict the shipped terminator returns. Every non-null PSCustomObject is
        # truthy, so a wrapper that tests the RESULT instead of .Proven passes its unproven case.
        'function Stop-WacProcessTree {',
        '    param([int]$ProcessId, [int]$TimeoutMs = 10000)',
        '    Add-StubCall ''Stop-WacProcessTree''',
        '    $proven = ($env:WAC_STUB_TERMINATION -eq ''proven'')',
        '    $survivor = @()',
        '    if (-not $proven) { $survivor = @($ProcessId) }',
        '    return ([PSCustomObject]@{ Root = $ProcessId; Proven = $proven; Bound = @($ProcessId); Survivor = $survivor; TaskkillExit = 255; Reason = ''stubbed termination verdict'' })',
        '}',
        # Shadows the cmdlet: a function beats a cmdlet in command resolution, which is what lets the
        # elevation branch be exercised without a real UAC prompt. The child it hands back never
        # exits within the wrapper''s bound, so the expiry branch is reached deterministically and
        # without waiting for it.
        'function Start-Process {',
        '    param($FilePath, $ArgumentList, [string]$Verb, [switch]$PassThru, $ErrorAction)',
        '    Add-StubCall ''Start-Process''',
        '    $fake = [PSCustomObject]@{ Id = [int]$env:WAC_STUB_CHILD_PID; Handle = [IntPtr]::Zero; ExitCode = 0 }',
        '    Add-Member -InputObject $fake -MemberType ScriptMethod -Name WaitForExit -Value { param([int]$ms) return $false }',
        '    return $fake',
        '}',
        'function Get-WacNormalizedPath { param($Path) if ([string]::IsNullOrWhiteSpace($Path)) { return $null } return ([System.IO.Path]::GetFullPath($Path).TrimEnd(''\'')) }',
        'function Test-WacIsWithinRoot { param($ChildPath, $RootPath) return $false }',
        'function ConvertTo-WacCommandLine { param($ArgumentList) return (@($ArgumentList) -join '' '') }',
        'function Get-WacRelaunchArgument { param($ScriptPath, $BooleanSwitch, $PresentSwitch, $NamedValue, $HostSwitch) return @($ScriptPath) }',
        'function Get-WacLogHealth {',
        '    return [PSCustomObject]@{',
        '        Path = (Get-WacLogPath)',
        '        IsDurable = ($env:WAC_STUB_LOG_DURABLE -eq ''True'')',
        '        Degraded = ($env:WAC_STUB_LOG_DURABLE -ne ''True'')',
        '        FallbackKind = ''None''',
        '        FailedWrites = 0',
        '        Reason = ''stubbed log health''',
        '    }',
        '}',
        'function Get-WacStateTrust {',
        '    if ($env:WAC_STUB_STATE_MODE -eq ''null'') { return $null }',
        '    return [PSCustomObject]@{',
        '        Path = $env:WAC_STUB_STATE_PATH',
        '        IsTrusted = ($env:WAC_STUB_STATE_MODE -eq ''trusted'')',
        '        Reason = $env:WAC_STUB_STATE_REASON',
        '        Checked = @()',
        '        Failures = @()',
        '        Writers = @()',
        '    }',
        '}',
        'Export-ModuleMember -Function *-*'
    )
    [System.IO.File]::WriteAllLines((Join-Path -Path $src -ChildPath 'WindowsAutoCleanup.Core.psm1'),
        [string[]]$core, (New-Object System.Text.UTF8Encoding($false)))

    $deploy = New-Object 'System.Collections.Generic.List[string]'
    [void]$deploy.Add('Set-StrictMode -Version 2.0')
    [void]$deploy.Add('Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath ''WindowsAutoCleanup.Core.psm1'') -DisableNameChecking -ErrorAction Stop')
    # Per-run unique when the caller supplies one: this suite runs on two hosts at once, and a
    # fixed name would make the two runs contend for the lock a case is trying to observe.
    [void]$deploy.Add('function Get-WacOperationLockName { if ($env:WAC_STUB_LOCK) { return $env:WAC_STUB_LOCK }; return ''Local\WacStubLock'' }')
    [void]$deploy.Add('function Get-WacTaskName { return ''WindowsAutoCleanup'' }')
    [void]$deploy.Add('function Get-WacTaskFolder { return ''\WindowsAutoCleanup\'' }')
    [void]$deploy.Add('function Get-WacTaskDescription { return ''stub'' }')
    [void]$deploy.Add('function Get-WacTaskActionArgument { param($RunScript, $ResetWindowsUpdateBase, $PruneSupersededDrivers, $EnableLegacyDiskCleanup) return ''stub'' }')
    [void]$deploy.Add('function Get-WacInstallerRelaunchArgument { param($ScriptPath, $DailyRunTime, $ResetWindowsUpdateBase, $PruneSupersededDrivers, $EnableLegacyDiskCleanup, $NoPause) return @($ScriptPath) }')
    [void]$deploy.Add('function Get-WacDeploymentSlotPath { param([string]$DeploymentRoot) Add-StubCall ''Get-WacDeploymentSlotPath''; return $null }')
    [void]$deploy.Add('function Test-WacTaskReferencesRoot { param($Task, $DeploymentRoot) return $false }')
    [void]$deploy.Add('function Test-WacTaskIsOurs { param($Task, $DeploymentRoot, $AllowLegacyMigration) return ([PSCustomObject]@{ IsOurs = $false; Reason = ''stub'' }) }')

    # Reached only by a run that got past the gate, so every one of these is a test failure by the
    # time it is called: it records itself and then makes the run fail where it happened.
    foreach ($tripwire in @('Get-WacDeploymentOwnership', 'Test-WacDeploymentTrusted', 'Get-WacInstalledTask',
        'New-WacDeploymentStage', 'Switch-WacDeploymentStage', 'Remove-WacDeployment',
        'Remove-WacDeploymentPrevious', 'Restore-WacDeploymentPrevious', 'Remove-WacInstalledTask')) {
        [void]$deploy.Add(('function {0} {{ param($A, $B, $C, $D) Add-StubCall ''{0}''; throw ''{0} was reached, which this run was never allowed to do.'' }}' -f $tripwire))
    }
    [void]$deploy.Add('Export-ModuleMember -Function *-*')

    [System.IO.File]::WriteAllLines((Join-Path -Path $src -ChildPath 'WindowsAutoCleanup.Deploy.psm1'),
        [string[]]$deploy.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-StubbedEntryPoint {
    <#
    .SYNOPSIS
        Runs one real entry point over the stub modules in a bounded child, and reports what it did.
    .OUTPUTS
        ExitCode, Called (the stub calls it made, in order), LogWrites (every line that reached the
        FILE log), Console, TimedOut.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$ScriptName,
        [Parameter(Mandatory = $true)][ValidateSet('trusted', 'untrusted', 'null')][string]$StateMode,
        [string]$StatePath = '',
        [string]$StateReason = '',
        [bool]$LogDurable = $true,
        [bool]$Admin = $true,
        [ValidateSet('ok', 'expired')][string]$Budget = 'ok',
        [string]$HostPath = '',
        [ValidateSet('proven', 'unproven')][string]$Termination = 'unproven',
        [int]$ChildPid = 0,
        [string]$LockName = '',
        [ValidateRange(10, 300)][int]$TimeoutSeconds = 90
    )

    $callFile = Join-Path -Path $Sandbox -ChildPath 'calls.txt'
    $logFile = Join-Path -Path $Sandbox -ChildPath 'logwrites.txt'
    $outFile = Join-Path -Path $Sandbox -ChildPath 'console.txt'
    $resultFile = Join-Path -Path $Sandbox -ChildPath 'exit.txt'
    foreach ($stale in @($callFile, $logFile, $outFile, $resultFile)) {
        if (Test-Path -LiteralPath $stale -PathType Leaf) { [System.IO.File]::Delete($stale) }
    }
    [System.IO.File]::WriteAllText($callFile, '')
    [System.IO.File]::WriteAllText($logFile, '')

    $wrapper = Join-Path -Path $Sandbox -ChildPath 'wrapper.ps1'
    $entry = Join-Path -Path $Sandbox -ChildPath $ScriptName
    $lines = @(
        '$code = 90',
        'try {',
        ('    & ''{0}'' -NoPause *> ''{1}''' -f $entry, $outFile),
        '    if ($null -ne $LASTEXITCODE) { $code = [int]$LASTEXITCODE }',
        '}',
        'catch {',
        '    $code = 91',
        ('    [System.IO.File]::AppendAllText(''{0}'', ($_ | Out-String))' -f $outFile),
        '}',
        ('[System.IO.File]::WriteAllText(''{0}'', "EXIT=$code")' -f $resultFile),
        'exit $code'
    )
    [System.IO.File]::WriteAllLines($wrapper, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))

    $hostName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Join-Path -Path $PSHOME -ChildPath $hostName)
    $psi.Arguments = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $wrapper)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $script:RepoRoot
    $psi.EnvironmentVariables['WAC_STUB_CALLS'] = $callFile
    $psi.EnvironmentVariables['WAC_STUB_LOGWRITES'] = $logFile
    $psi.EnvironmentVariables['WAC_STUB_STATE'] = (Join-Path -Path $Sandbox -ChildPath 'state')
    $psi.EnvironmentVariables['WAC_STUB_STATE_MODE'] = $StateMode
    $psi.EnvironmentVariables['WAC_STUB_STATE_PATH'] = $StatePath
    $psi.EnvironmentVariables['WAC_STUB_STATE_REASON'] = $StateReason
    $psi.EnvironmentVariables['WAC_STUB_LOG_DURABLE'] = ([string]$LogDurable)
    $psi.EnvironmentVariables['WAC_STUB_ADMIN'] = ([string]$Admin)
    $psi.EnvironmentVariables['WAC_STUB_BUDGET'] = $Budget
    $psi.EnvironmentVariables['WAC_STUB_HOST'] = $HostPath
    $psi.EnvironmentVariables['WAC_STUB_TERMINATION'] = $Termination
    $psi.EnvironmentVariables['WAC_STUB_CHILD_PID'] = ([string]$ChildPid)
    $psi.EnvironmentVariables['WAC_STUB_LOCK'] = $LockName

    $child = [System.Diagnostics.Process]::Start($psi)
    $exited = $false
    try {
        $exited = $child.WaitForExit([int]($TimeoutSeconds * 1000))
        if (-not $exited) {
            [void](Stop-WacProcessTree -ProcessId $child.Id)
            [void]$child.WaitForExit(10000)
        }
    }
    finally {
        try { $child.Dispose() } catch { $null = $_ }
    }

    $exitCode = $null
    if (Test-Path -LiteralPath $resultFile -PathType Leaf) {
        $exitCode = [int](([System.IO.File]::ReadAllText($resultFile)).Trim().Substring(5))
    }

    $console = ''
    if (Test-Path -LiteralPath $outFile -PathType Leaf) { $console = [System.IO.File]::ReadAllText($outFile) }

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Called = @(@([System.IO.File]::ReadAllLines($callFile)) | Where-Object { $_.Trim() })
        LogWrites = @(@([System.IO.File]::ReadAllLines($logFile)) | Where-Object { $_.Trim() })
        Console = $console
        TimedOut = (-not $exited)
    }
}

function Assert-NothingMutated {
    <#
    .SYNOPSIS
        Proves a run changed nothing. With -Refused, also proves it stopped AT the gate and never
        wrote through the path it refused.
    #>
    param(
        [Parameter(Mandatory = $true)]$Run,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$ScriptName,
        [switch]$Refused
    )

    Assert-False $Run.TimedOut ('{0}: the entry point never finished inside its bound' -f $Label)
    foreach ($call in $script:MutatingCall) {
        Assert-False ($Run.Called -contains $call) ('{0}: {1} was called; the calls were: {2}' -f $Label, $call, ($Run.Called -join ', '))
    }

    if (-not $Refused) { return }

    Assert-True ($Run.Called -contains 'Enter-WacSingleInstance') `
        ('{0}: the lock was never taken, so the refusal was not made under it' -f $Label)
    Assert-False ($Run.Called -contains $script:GatePassedMarker[$ScriptName]) `
        ('{0}: the run continued past the gate; calls: {1}' -f $Label, ($Run.Called -join ', '))
    Assert-False ($Run.Called -contains 'Remove-WacOldLog') `
        ('{0}: the refused run still pruned files inside the directory it refused' -f $Label)

    # The invocation record used to be written to the run log BEFORE the gate had decided whether
    # this run may write there at all, so a refusal about the log directory arrived through the log
    # directory. A refused run writes NOTHING to the file log; its console output is unaffected.
    Assert-Equal 0 @($Run.LogWrites).Count `
        ('{0}: the refused run wrote through the path it refused: {1}' -f $Label, (@($Run.LogWrites) -join ' / '))
}

function New-TestUntrustedStatePath {
    <#
    .SYNOPSIS
        Four state paths that are untrusted for four different real reasons, plus the verdict Core
        actually returns for each.
    .DESCRIPTION
        The verdicts are computed here, by the shipped rule, against directories this suite crafts -
        so what the entry points are fed is a real refusal rather than an invented one. Everyone
        (S-1-1-0) is on Core's never-administrative list, which is what makes the writable cases
        untrusted even on an elevated runner where the sandbox owner is BUILTIN\Administrators.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $cases = New-Object 'System.Collections.Generic.List[object]'

    $writable = Join-Path -Path $Sandbox -ChildPath 'writable'
    [void][System.IO.Directory]::CreateDirectory($writable)
    Add-TestEveryoneAce -Path $writable
    [void]$cases.Add([PSCustomObject]@{ Name = 'user-writable'; Path = $writable })

    $parent = Join-Path -Path $Sandbox -ChildPath 'inherited'
    [void][System.IO.Directory]::CreateDirectory($parent)
    Add-TestEveryoneAce -Path $parent -Inheritable
    $inherited = Join-Path -Path $parent -ChildPath 'Logs'
    [void][System.IO.Directory]::CreateDirectory($inherited)
    [void]$cases.Add([PSCustomObject]@{ Name = 'inherited-unsafe'; Path = $inherited })

    $target = Join-Path -Path $Sandbox -ChildPath 'linktarget'
    [void][System.IO.Directory]::CreateDirectory($target)
    $link = Join-Path -Path $Sandbox -ChildPath 'link'
    New-Item -ItemType Junction -Path $link -Target $target -ErrorAction Stop | Out-Null
    [void]$cases.Add([PSCustomObject]@{ Name = 'reparse'; Path = (Join-Path -Path $link -ChildPath 'Logs') })

    # A drive letter nothing is mounted on: the volume cannot be inspected, so the trust question
    # cannot be answered at all, which is the inaccessible case and must refuse exactly like a
    # writable one.
    $free = @([char[]](90..80) | Where-Object { -not (Test-Path -LiteralPath ('{0}:\' -f $_)) })
    Assert-True ($free.Count -gt 0) 'every drive letter from P: to Z: is in use, so the inaccessible case cannot be built'
    [void]$cases.Add([PSCustomObject]@{ Name = 'inaccessible'; Path = ('{0}:\WindowsAutoCleanup\Logs' -f $free[0]) })

    return @($cases.ToArray())
}

function Add-TestEveryoneAce {
    <#
    .SYNOPSIS
        Grants Everyone Modify on a path the test itself created, so it is untrusted on ANY runner.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Inheritable
    )

    $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    if ($Inheritable) {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    }

    $acl = Get-Acl -LiteralPath $Path
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')),
        [System.Security.AccessControl.FileSystemRights]::Modify,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Wait-ForStubFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 30
    )

    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([datetime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

function Start-StubElevatedChild {
    <#
    .SYNOPSIS
        A stand-in for the elevated child: it takes the operation lock, outlives the wrapper's wait,
        and performs its mutation only AFTER the wrapper has given up on it.
    .DESCRIPTION
        It is not elevated, and it does not have to be. What the expiry branch reports on is a child
        the parent could not prove had exited, and this process is exactly that - alive, holding the
        machine-wide lock the next run would need, and still able to change the machine. The
        mutation is a file write inside the sandbox, which is a real one and a safe one.
    .OUTPUTS
        Process, and the Started / Release / Mutation file paths that drive and observe it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$LockName
    )

    $driver = Join-Path -Path $Sandbox -ChildPath 'elevated-child.ps1'
    [System.IO.File]::WriteAllLines($driver, [string[]]@(
        'param([string]$LockName, [string]$StartedFile, [string]$ReleaseFile, [string]$MutationFile)',
        'Set-StrictMode -Version 2.0',
        '$created = $false',
        '$mutex = New-Object System.Threading.Mutex($false, $LockName, [ref]$created)',
        'if (-not $mutex.WaitOne(0)) { exit 2 }',
        'try {',
        '    [System.IO.File]::WriteAllText($StartedFile, ''held'')',
        '    $deadline = [datetime]::UtcNow.AddSeconds(120)',
        '    while (-not (Test-Path -LiteralPath $ReleaseFile) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }',
        '    [System.IO.File]::WriteAllText($MutationFile, ''the child was still changing this machine'')',
        '}',
        'finally {',
        '    try { $mutex.ReleaseMutex() } catch { $null = $_ }',
        '    try { $mutex.Dispose() } catch { $null = $_ }',
        '}',
        'exit 0'
    ), (New-Object System.Text.UTF8Encoding($false)))

    $started = Join-Path -Path $Sandbox -ChildPath 'child.started'
    $release = Join-Path -Path $Sandbox -ChildPath 'child.release'
    $mutation = Join-Path -Path $Sandbox -ChildPath 'child.mutation'
    foreach ($stale in @($started, $release, $mutation)) {
        if (Test-Path -LiteralPath $stale -PathType Leaf) { [System.IO.File]::Delete($stale) }
    }

    $hostName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Join-Path -Path $PSHOME -ChildPath $hostName)
    $psi.Arguments = ConvertTo-WacCommandLine -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $driver,
        '-LockName', $LockName, '-StartedFile', $started, '-ReleaseFile', $release, '-MutationFile', $mutation)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $script:RepoRoot

    return [PSCustomObject]@{
        Process = [System.Diagnostics.Process]::Start($psi)
        Started = $started
        Release = $release
        Mutation = $mutation
    }
}
