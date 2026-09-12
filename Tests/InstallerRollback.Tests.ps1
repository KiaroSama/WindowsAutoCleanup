#Requires -Version 5.1
<#
.SYNOPSIS
    What the installer leaves behind when a step between the swap and the final assertion fails
    (ledger G2-b, G2-c).

.DESCRIPTION
    The REAL Install-WindowsAutoCleanupTask.ps1 runs here, unmodified, in a bounded child process
    whose src\ holds stub modules and whose PSModulePath resolves 'ScheduledTasks' to a stub module
    of the same name. Nothing touches the live Task Scheduler, %ProgramFiles% or %ProgramData%: the
    stubs report what each scenario tells them to and journal every call they receive, and the
    assertions are made against that journal.

    Shadowing the ScheduledTasks module through PSModulePath is the only mechanism that works.
    Measured on both hosts: a function exported by an earlier import does NOT survive
    'Import-Module ScheduledTasks' - the later import wins - so a stub has to be found by that
    import rather than defined before it.

    Each scenario asks the same question: is the pair (registered task, deployment on disk) still
    consistent afterwards, or was the live tree conservatively retained because something could not
    be proven?
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function Get-CapturedTaskXml {
    <#
    .SYNOPSIS
        The definition the stub scheduler exports for the task an upgrade removes.
    .DESCRIPTION
        A real Export-ScheduledTask carries the ACTION, and the rollback proves the task it put back
        is the one that was captured rather than merely a task registered under that name. A fixture
        with no Exec element would exercise none of that, so this mirrors what the stub scheduler
        hands back on the read-back: the canonical host, the argument builder's output and the
        deployment root, all derived from the sandbox the scenario runs in.

        One line, no newlines: the journal is line-based.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $root = Join-Path -Path $Sandbox -ChildPath 'WindowsAutoCleanup'
    $arguments = '-NoProfile -Command "& ''{0}'' -Scheduled"' -f (Join-Path -Path $root -ChildPath 'Run.ps1')

    return ('<?xml version="1.0" encoding="UTF-16"?>' +
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' +
        '<RegistrationInfo><Description>the previous task</Description></RegistrationInfo>' +
        '<Settings><Hidden>true</Hidden></Settings>' +
        ('<Actions Context="Author"><Exec><Command>{0}</Command><Arguments>{1}</Arguments><WorkingDirectory>{2}</WorkingDirectory></Exec></Actions>' -f
            'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            [System.Security.SecurityElement]::Escape($arguments),
            [System.Security.SecurityElement]::Escape($root)) +
        '</Task>')
}

function Write-TestModule {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Line
    )

    [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $Path))
    [System.IO.File]::WriteAllLines($Path, [string[]]$Line, (New-Object System.Text.UTF8Encoding($false)))
}

function New-RollbackSandbox {
    <#
    .SYNOPSIS
        The real installer over stub Core, stub Deploy and a stub ScheduledTasks module.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $src = Join-Path -Path $Sandbox -ChildPath 'src'
    [void][System.IO.Directory]::CreateDirectory($src)

    Copy-Item -LiteralPath (Join-Path -Path $script:RepoRoot -ChildPath 'Install-WindowsAutoCleanupTask.ps1') `
        -Destination (Join-Path -Path $Sandbox -ChildPath 'Install-WindowsAutoCleanupTask.ps1') -Force
    foreach ($part in @('WindowsAutoCleanup.EntryGate.ps1', 'WindowsAutoCleanup.InstallerTask.ps1')) {
        Copy-Item -LiteralPath (Join-Path -Path $script:RepoRoot -ChildPath ('src\' + $part)) `
            -Destination (Join-Path -Path $src -ChildPath $part) -Force
    }

    Write-TestModule -Path (Join-Path -Path $src -ChildPath 'WindowsAutoCleanup.Core.psm1') -Line @(
        'Set-StrictMode -Version 2.0',
        'function Add-Journal { param([string]$Entry) [System.IO.File]::AppendAllText($env:WAC_RB_JOURNAL, $Entry + [Environment]::NewLine) }',
        'function Get-JournalCount { param([string]$Name) return @(@([System.IO.File]::ReadAllLines($env:WAC_RB_JOURNAL)) | Where-Object { $_ -eq $Name -or $_.StartsWith($Name + ''|'') }).Count }',
        'function Get-StepBehaviour {',
        '    param([string]$Name, [string]$Plan, [string]$Fallback)',
        '    $steps = @(($Plan -split '','') | Where-Object { $_ })',
        '    if ($steps.Count -eq 0) { return $Fallback }',
        '    $index = Get-JournalCount -Name $Name',
        '    if ($index -ge $steps.Count) { $index = $steps.Count - 1 }',
        '    return $steps[$index]',
        '}',
        'function Initialize-WacRun { param([string]$BaseName, [string[]]$CandidateRoot, [string]$LogLevel, [int]$BudgetMinutes, [string]$BootstrapLogPath, [int]$ShutdownMarginSeconds) Add-Journal (''Initialize-WacRun|budget='' + $BudgetMinutes + ''|margin='' + $ShutdownMarginSeconds); return $true }',
        # The child budget, driven by the SEQUENCE of checks rather than by a clock: WAC_RB_BUDGET is
        # the zero-based index of the first check that finds the deadline gone, so a scenario can put
        # the expiry exactly where it wants it and every run is deterministic. -1 never expires.
        # Each check journals itself, so a check that was silently removed shows up as a shifted plan.
        'function Test-WacDeadlineExpired {',
        '    $index = Get-JournalCount -Name ''deadline-check''',
        '    Add-Journal ''deadline-check''',
        '    $from = -1',
        '    if ($env:WAC_RB_BUDGET) { $from = [int]$env:WAC_RB_BUDGET }',
        '    if ($from -lt 0) { return $false }',
        '    return ($index -ge $from)',
        '}',
        'function Write-WacLog { param($Level, $Component, $Message, $Data) }',
        'function Close-WacLog { }',
        'function Get-WacLogPath { return (Join-Path -Path $env:WAC_RB_ROOT -ChildPath ''run.log'') }',
        'function Get-WacLogDirectory { return $env:WAC_RB_ROOT }',
        'function Get-WacDataRoot { return $env:WAC_RB_ROOT }',
        'function Remove-WacOldLog { param($LogDirectory, $Pattern, $KeepCount) }',
        'function Test-WacIsAdministrator { return $true }',
        'function Test-WacSystemDriveSupported { return $true }',
        'function Get-WacCanonicalPowerShellHost { return ''C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'' }',
        'function Enter-WacSingleInstance { param([string]$Name) return ([PSCustomObject]@{ Name = $Name }) }',
        'function Exit-WacSingleInstance { param($Mutex) }',
        'function Stop-WacProcessTree { param([int]$ProcessId, [int]$TimeoutMs = 10000) return ([PSCustomObject]@{ Root = $ProcessId; Proven = $false; Bound = @(); Survivor = @($ProcessId); TaskkillExit = $null; Reason = ''stub'' }) }',
        'function Get-WacNormalizedPath { param($Path) if ([string]::IsNullOrWhiteSpace($Path)) { return $null } return ([System.IO.Path]::GetFullPath($Path).TrimEnd(''\'')) }',
        'function Test-WacIsWithinRoot { param($ChildPath, $RootPath) return $false }',
        'function ConvertTo-WacCommandLine { param($ArgumentList) return (@($ArgumentList) -join '' '') }',
        'function Get-WacRelaunchArgument { param($ScriptPath, $BooleanSwitch, $PresentSwitch, $NamedValue, $HostSwitch) return @($ScriptPath) }',
        'function Get-WacLogHealth { return ([PSCustomObject]@{ Path = (Get-WacLogPath); IsDurable = $true; Degraded = $false; FallbackKind = ''None''; FailedWrites = 0; Reason = ''stub'' }) }',
        'function Get-WacStateTrust { return ([PSCustomObject]@{ Path = $env:WAC_RB_ROOT; IsTrusted = $true; Reason = ''stub''; Checked = @(); Failures = @(); Writers = @() }) }',
        'Export-ModuleMember -Function *-*'
    )

    Write-TestModule -Path (Join-Path -Path $src -ChildPath 'WindowsAutoCleanup.Deploy.psm1') -Line @(
        'Set-StrictMode -Version 2.0',
        'Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath ''WindowsAutoCleanup.Core.psm1'') -DisableNameChecking -ErrorAction Stop',
        'function Get-WacOperationLockName { return ''Local\WacRollbackStub'' }',
        'function Get-WacTaskName { return ''WindowsAutoCleanup'' }',
        'function Get-WacTaskFolder { return ''\WindowsAutoCleanup\'' }',
        'function Get-WacTaskDescription { return ''WindowsAutoCleanup stub description'' }',
        'function Get-WacTaskActionArgument { param($RunScript, $ResetWindowsUpdateBase, $PruneSupersededDrivers, $EnableLegacyDiskCleanup) return (''-NoProfile -Command "& '''''' + $RunScript + '''''' -Scheduled"'') }',
        'function Get-WacInstallerRelaunchArgument { param($ScriptPath, $DailyRunTime, $ResetWindowsUpdateBase, $PruneSupersededDrivers, $EnableLegacyDiskCleanup, $NoPause) return @($ScriptPath) }',
        'function Get-WacDeploymentSlotPath { param([string]$DeploymentRoot) $root = Join-Path -Path $env:WAC_RB_ROOT -ChildPath ''WindowsAutoCleanup''; return ([PSCustomObject]@{ Root = $root; Staging = ($root + ''.staging''); Previous = ($root + ''.previous'') }) }',
        'function Get-WacDeploymentOwnership { param([string]$DeploymentRoot) return ([PSCustomObject]@{ Root = $DeploymentRoot; Exists = $true; Kind = ''Managed''; IsOurs = $true; Version = ''1.2.0''; Tampered = $false; Findings = @(); Reason = ''stub'' }) }',
        'function Test-WacDeploymentTrusted { param([string]$DeploymentRoot) return ([PSCustomObject]@{ DeploymentRoot = $DeploymentRoot; IsTrusted = $true; CheckedCount = 1; Untrusted = @(); Reason = ''stub'' }) }',
        'function Test-WacTaskIsOurs { param($Task, $DeploymentRoot, $AllowLegacyMigration) return ([PSCustomObject]@{ IsOurs = $true; Reason = ''stub'' }) }',
        'function Test-WacTaskReferencesRoot { param($Task, $DeploymentRoot) return $false }',
        'function New-WacDeploymentStage { param([string]$SourceRoot) Add-Journal ''New-WacDeploymentStage''; return ([PSCustomObject]@{ StagingRoot = (Get-WacDeploymentSlotPath).Staging; Manifest = $null; FileCount = 4; Version = ''1.2.0'' }) }',
        'function Switch-WacDeploymentStage { param([switch]$KeepPrevious) Add-Journal ''Switch-WacDeploymentStage''; $slots = Get-WacDeploymentSlotPath; return ([PSCustomObject]@{ DeploymentRoot = $slots.Root; RunScript = (Join-Path -Path $slots.Root -ChildPath ''Run.ps1''); FileCount = 4; PreviousKept = [bool]$KeepPrevious }) }',
        'function Restore-WacDeploymentPrevious { Add-Journal ''Restore-WacDeploymentPrevious''; return ([PSCustomObject]@{ Restored = $true; HadPrevious = $true; Reason = ''stub'' }) }',
        'function Remove-WacDeploymentPrevious { Add-Journal ''Remove-WacDeploymentPrevious''; return $true }',
        'function Remove-WacDeployment { param([string]$Path, [string]$DeploymentRoot) Add-Journal (''Remove-WacDeployment|'' + $Path); return ([PSCustomObject]@{ Path = $Path; Removed = $true; Reason = $null }) }',
        'function New-StubRegisteredTask {',
        '    param([switch]$Broken)',
        '    $slots = Get-WacDeploymentSlotPath',
        '    $arguments = Get-WacTaskActionArgument -RunScript (Join-Path -Path $slots.Root -ChildPath ''Run.ps1'')',
        '    $action = [PSCustomObject]@{ Execute = (Get-WacCanonicalPowerShellHost); Arguments = $arguments; WorkingDirectory = $slots.Root }',
        '    $actions = @($action)',
        '    if ($Broken) { $actions = @($action, $action) }',
        '    return [PSCustomObject]@{',
        '        TaskName = (Get-WacTaskName)',
        '        TaskPath = (Get-WacTaskFolder)',
        '        Description = (Get-WacTaskDescription)',
        '        Actions = $actions',
        '        Principal = [PSCustomObject]@{ RunLevel = ''Highest''; LogonType = ''ServiceAccount''; UserId = ''SYSTEM'' }',
        '        Settings = [PSCustomObject]@{ Hidden = $true; Compatibility = ''Win8''; MultipleInstances = ''IgnoreNew''; StartWhenAvailable = $true; ExecutionTimeLimit = ''PT4H'' }',
        '        Triggers = @([PSCustomObject]@{ StartBoundary = ''2026-01-01T20:00:00'' })',
        '    }',
        '}',
        'function Get-WacInstalledTask {',
        '    param([switch]$IncludeLegacy)',
        '    $state = Get-StepBehaviour -Name ''Get-WacInstalledTask'' -Plan $env:WAC_RB_LOOKUP -Fallback ''Absent''',
        '    Add-Journal (''Get-WacInstalledTask|'' + $state)',
        '    if ($state -eq ''Failed'') { return ([PSCustomObject]@{ State = ''Failed''; Task = @(); Failure = @([PSCustomObject]@{ TaskPath = (Get-WacTaskFolder); Reason = ''the scheduler could not be queried'' }) }) }',
        '    if ($state -eq ''Absent'') { return ([PSCustomObject]@{ State = ''Absent''; Task = @(); Failure = @() }) }',
        '    $task = New-StubRegisteredTask -Broken:($state -eq ''Bad'')',
        '    return ([PSCustomObject]@{ State = ''Found''; Task = @($task); Failure = @() })',
        '}',
        'function Remove-WacInstalledTask {',
        '    param($Task, [string]$DeploymentRoot, [switch]$AllowLegacyMigration, [switch]$RequireDefinitionCapture)',
        '    $outcome = Get-StepBehaviour -Name ''Remove-WacInstalledTask'' -Plan $env:WAC_RB_REMOVE -Fallback ''Verified''',
        '    $captured = ($env:WAC_RB_CAPTURE -ne ''no'')',
        '    Add-Journal (''Remove-WacInstalledTask|'' + $outcome + ''|captured='' + $captured)',
        '    $result = [PSCustomObject]@{ TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder); Removed = $false; Verified = $false; Captured = $captured; Definition = $null; CaptureReason = ''stub''; Reason = ''stub'' }',
        '    if ($captured) { $result.Definition = $env:WAC_RB_XML }',
        '    if ($RequireDefinitionCapture -and -not $captured) { $result.Reason = ''the definition could not be captured first''; return $result }',
        '    if ($outcome -eq ''Refused'') { $result.Reason = ''the task is not ours''; return $result }',
        '    $result.Removed = $true',
        '    if ($outcome -eq ''Verified'') { $result.Verified = $true }',
        '    else { $result.Reason = ''the removal could not be verified'' }',
        '    return $result',
        '}',
        'Export-ModuleMember -Function *-*'
    )

    $module = Join-Path -Path $Sandbox -ChildPath 'Modules\ScheduledTasks'
    Write-TestModule -Path (Join-Path -Path $module -ChildPath 'ScheduledTasks.psm1') -Line @(
        'Set-StrictMode -Version 2.0',
        'function Add-Journal { param([string]$Entry) [System.IO.File]::AppendAllText($env:WAC_RB_JOURNAL, $Entry + [Environment]::NewLine) }',
        'function New-ScheduledTaskTrigger { param([switch]$Daily, $At) return ([PSCustomObject]@{ Kind = ''Daily''; At = $At }) }',
        'function New-ScheduledTaskAction { param($Execute, $Argument, $WorkingDirectory) return ([PSCustomObject]@{ Execute = $Execute; Arguments = $Argument; WorkingDirectory = $WorkingDirectory }) }',
        'function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) return ([PSCustomObject]@{ UserId = $UserId; LogonType = $LogonType; RunLevel = $RunLevel }) }',
        'function New-ScheduledTaskSettingsSet { param($Compatibility, [switch]$Hidden, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, [switch]$StartWhenAvailable, $MultipleInstances, $ExecutionTimeLimit, $RestartCount, $RestartInterval) return ([PSCustomObject]@{ Hidden = [bool]$Hidden }) }',
        'function New-ScheduledTask { param($Action, $Trigger, $Principal, $Settings, $Description) return ([PSCustomObject]@{ Description = $Description }) }',
        'function Get-ScheduledTaskInfo { param($TaskName, $TaskPath, $ErrorAction) return ([PSCustomObject]@{ NextRunTime = ''stub'' }) }',
        'function Register-ScheduledTask {',
        '    param($TaskName, $TaskPath, $InputObject, $Xml, [switch]$Force, $ErrorAction)',
        '    if ($Xml) { Add-Journal (''Register-ScheduledTask|xml|'' + $Xml); return ([PSCustomObject]@{ TaskName = $TaskName; TaskPath = $TaskPath }) }',
        '    Add-Journal ''Register-ScheduledTask|task''',
        '    if ($env:WAC_RB_REGISTER -eq ''throw'') { throw ''the scheduler refused the registration'' }',
        '    return ([PSCustomObject]@{ TaskName = $TaskName; TaskPath = $TaskPath })',
        '}',
        'function Unregister-ScheduledTask { param($TaskName, $TaskPath, $Confirm, $ErrorAction) Add-Journal ''Unregister-ScheduledTask'' }',
        'Export-ModuleMember -Function *-*'
    )
}

function Invoke-RollbackScenario {
    <#
    .SYNOPSIS
        Runs the real installer over the stubs with one scenario's behaviour, bounded.
    .OUTPUTS
        ExitCode, Journal (the calls in order), Console, TimedOut.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [string]$Lookup = 'Absent',
        [string]$Remove = 'Verified',
        [ValidateSet('yes', 'no')][string]$Capture = 'yes',
        [ValidateSet('ok', 'throw')][string]$Register = 'ok',
        # Zero-based index of the first budget check that finds the deadline gone; -1 never expires.
        [ValidateRange(-1, 32)][int]$Budget = -1,
        [ValidateRange(10, 300)][int]$TimeoutSeconds = 90
    )

    $journal = Join-Path -Path $Sandbox -ChildPath 'journal.txt'
    $outFile = Join-Path -Path $Sandbox -ChildPath 'console.txt'
    $resultFile = Join-Path -Path $Sandbox -ChildPath 'exit.txt'
    foreach ($stale in @($journal, $outFile, $resultFile)) {
        if (Test-Path -LiteralPath $stale -PathType Leaf) { [System.IO.File]::Delete($stale) }
    }
    [System.IO.File]::WriteAllText($journal, '')

    $wrapper = Join-Path -Path $Sandbox -ChildPath 'wrapper.ps1'
    $entry = Join-Path -Path $Sandbox -ChildPath 'Install-WindowsAutoCleanupTask.ps1'
    [System.IO.File]::WriteAllLines($wrapper, [string[]]@(
        ('$env:PSModulePath = ''{0}'' + '';'' + $env:PSModulePath' -f (Join-Path -Path $Sandbox -ChildPath 'Modules')),
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
    ), (New-Object System.Text.UTF8Encoding($false)))

    $hostName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Join-Path -Path $PSHOME -ChildPath $hostName)
    $psi.Arguments = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $wrapper)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $script:RepoRoot
    $psi.EnvironmentVariables['WAC_RB_JOURNAL'] = $journal
    $psi.EnvironmentVariables['WAC_RB_ROOT'] = $Sandbox
    $psi.EnvironmentVariables['WAC_RB_LOOKUP'] = $Lookup
    $psi.EnvironmentVariables['WAC_RB_REMOVE'] = $Remove
    $psi.EnvironmentVariables['WAC_RB_CAPTURE'] = $Capture
    $psi.EnvironmentVariables['WAC_RB_REGISTER'] = $Register
    $psi.EnvironmentVariables['WAC_RB_BUDGET'] = ([string]$Budget)
    $psi.EnvironmentVariables['WAC_RB_XML'] = (Get-CapturedTaskXml -Sandbox $Sandbox)

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
        Journal = @(@([System.IO.File]::ReadAllLines($journal)) | Where-Object { $_.Trim() })
        Console = $console
        TimedOut = (-not $exited)
    }
}

function Test-JournalHas {
    param(
        [Parameter(Mandatory = $true)]$Run,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    return (@(@($Run.Journal) | Where-Object { $_ -match $Pattern }).Count -gt 0)
}

Test-Case 'A registration that fails after the old task was removed restores BOTH the tree and the task' {
    # Ledger G2-c. Rollback used to restore the deployment and unregister whatever this run
    # registered, and stop there - the task the upgrade had already removed to make room was simply
    # gone, on a machine the installer had just reported as rolled back.
    $sandbox = New-TestSandbox -Prefix 'rb-register'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Absent,Found' -Remove 'Verified' -Register 'throw'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacInstalledTask\|Verified\|captured=True$') ($run.Journal -join ' / ')
        Assert-True (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') ($run.Journal -join ' / ')
        Assert-True (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') ($run.Journal -join ' / ')

        # The exact definition that was captured, put back through the scheduler and read back.
        Assert-True (Test-JournalHas -Run $run -Pattern ([regex]::Escape('Register-ScheduledTask|xml|' + (Get-CapturedTaskXml -Sandbox $sandbox)))) `
            ($run.Journal -join ' / ')
        Assert-True ($run.Console -match 're-registered and verified') $run.Console

        # And the commit never happened: the previous tree is not thrown away on a failed run.
        Assert-False (Test-JournalHas -Run $run -Pattern '^Remove-WacDeploymentPrevious$') ($run.Journal -join ' / ')

        # Order matters: the tree the restored task points into has to be back before the task is.
        $restore = [array]::IndexOf($run.Journal, 'Restore-WacDeploymentPrevious')
        $reregister = @(0..($run.Journal.Count - 1) | Where-Object { $run.Journal[$_] -match '^Register-ScheduledTask\|xml' })
        Assert-True ($reregister.Count -eq 1 -and $restore -lt $reregister[0]) `
            ('the task was restored before the tree it runs: ' + ($run.Journal -join ' / '))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A rollback that cannot prove the new task is gone KEEPS the deployment it may reference' {
    # Deleting the tree under a registration that may still point at it turns a recoverable state
    # into a scheduled task that fails every night with a missing file.
    $sandbox = New-TestSandbox -Prefix 'rb-unverified'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Bad,Found' -Remove 'Verified,Unverified'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacInstalledTask\|Unverified') ($run.Journal -join ' / ')
        Assert-False (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') `
            ('the deployment was rolled back under a task whose removal was never proven: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Remove-WacDeploymentPrevious$') ($run.Journal -join ' / ')
        Assert-True ($run.Console -match 'KEPT') $run.Console
        Assert-True ($run.Console -match 'rollback is INCOMPLETE') $run.Console
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A rollback whose scheduler will not answer KEEPS the deployment too' {
    # Ledger G2-b at its sharpest: "the query failed" is not "there is no task", and a rollback that
    # reads it as one deletes the tree out from under a registration it never saw.
    $sandbox = New-TestSandbox -Prefix 'rb-failed'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Bad,Failed' -Remove 'Verified'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Get-WacInstalledTask\|Failed$') ($run.Journal -join ' / ')
        Assert-False (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') `
            ('the deployment was rolled back on an unanswered lookup: ' + ($run.Journal -join ' / '))
        Assert-True ($run.Console -match 'could not be queried') $run.Console
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An upgrade refuses before the swap when the scheduler cannot be queried at all' {
    # Staging already clears the .staging and .previous slots, which is a deletion, so a lookup that
    # cannot be answered has to stop the run before that - not after.
    $sandbox = New-TestSandbox -Prefix 'rb-discovery'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Failed'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-False (Test-JournalHas -Run $run -Pattern '^New-WacDeploymentStage$') `
            ('the run staged a deployment on an unanswered lookup: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') ($run.Journal -join ' / ')
        Assert-False (Test-JournalHas -Run $run -Pattern '^Register-ScheduledTask') ($run.Journal -join ' / ')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An old task whose definition cannot be captured is left registered and nothing goes live' {
    # A removal that could not be undone is not a step an upgrade is allowed to take.
    $sandbox = New-TestSandbox -Prefix 'rb-nocapture'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found' -Capture 'no'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 7 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern 'captured=False') ($run.Journal -join ' / ')
        Assert-False (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') `
            ('a refused conflict still swapped the tree into place: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Register-ScheduledTask') ($run.Journal -join ' / ')
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacDeployment\|') 'the staged tree was left behind after the refusal'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A clean upgrade commits, rolls nothing back, and the second identical run is still clean' {
    # The benign steady state. A machine where everything works must not be turned into a refusal or
    # an incomplete by any of the guards above, on the first run or on the one after it.
    $sandbox = New-TestSandbox -Prefix 'rb-clean'
    try {
        New-RollbackSandbox -Sandbox $sandbox

        foreach ($pass in @('first', 'second')) {
            $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Remove 'Verified'

            Assert-False $run.TimedOut ('{0} pass: the installer never finished inside its bound' -f $pass)
            Assert-Equal 0 $run.ExitCode ('{0} pass: {1}' -f $pass, $run.Console)
            Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacDeploymentPrevious$') `
                ('{0} pass: the previous tree was never discarded, so the install did not commit' -f $pass)
            Assert-False (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') `
                ('{0} pass: a successful install rolled itself back' -f $pass)
            Assert-False (Test-JournalHas -Run $run -Pattern '^Register-ScheduledTask\|xml') `
                ('{0} pass: a successful install re-registered the old task' -f $pass)
            Assert-False ($run.Console -match 'Refused|refused|INCOMPLETE') `
                ('{0} pass: a benign upgrade reported a refusal: {1}' -f $pass, $run.Console)
            Assert-True ($run.Console -match 'Final status: success') ('{0} pass: {1}' -f $pass, $run.Console)
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A conflict phase that removed a task before it refused puts that task back' {
    # The removal happens one phase before the swap, so a refusal there leaves no deployment to roll
    # back - but the machine has still lost a registration to make room for one that will now never
    # exist. Whatever was captured has to go back on the way out.
    $sandbox = New-TestSandbox -Prefix 'rb-conflict'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Remove 'Unverified'

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacInstalledTask\|Unverified') ($run.Journal -join ' / ')
        Assert-True (Test-JournalHas -Run $run -Pattern ([regex]::Escape('Register-ScheduledTask|xml|' + (Get-CapturedTaskXml -Sandbox $sandbox)))) `
            ('the removed task was not put back: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') `
            ('a refused conflict phase still swapped the tree into place: ' + ($run.Journal -join ' / '))
        Assert-True (Test-JournalHas -Run $run -Pattern '^Remove-WacDeployment\|.*\.staging$') `
            ('the staged tree was left behind: ' + ($run.Journal -join ' / '))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A budget that runs out before the staging phase leaves the machine untouched' {
    # The advertised child budget used to be armed by Initialize-WacRun and then read by nothing:
    # the parent waited 40 minutes for a 30-minute deadline no operation ever observed. The first
    # check sits before anything is inspected, the second before the tree is copied.
    $sandbox = New-TestSandbox -Prefix 'rb-budget-early'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Found' -Budget 1

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True ($run.Console -match 'run budget expired before the runtime was staged') $run.Console

        # The margin is what makes the deadline enforceable: without it the budget the phases stop
        # at is the same instant the rollback would have to start from.
        Assert-True (Test-JournalHas -Run $run -Pattern '^Initialize-WacRun\|budget=30\|margin=600$') `
            ('the child budget was armed without a shutdown margin: ' + ($run.Journal -join ' / '))

        foreach ($forbidden in @('^New-WacDeploymentStage$', '^Switch-WacDeploymentStage$', '^Register-ScheduledTask')) {
            Assert-False (Test-JournalHas -Run $run -Pattern $forbidden) `
                ('an expired budget still reached ' + $forbidden + ': ' + ($run.Journal -join ' / '))
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A budget that runs out after the swap rolls the tree and the task back instead of registering' {
    # The late-mutation case at the phase level: the new tree IS live by the time the budget goes,
    # so stopping is not enough - the swap has to be undone and the registration this upgrade
    # removed to make room has to go back. Index 5 is the check inside the rollback try.
    $sandbox = New-TestSandbox -Prefix 'rb-budget-late'
    try {
        New-RollbackSandbox -Sandbox $sandbox
        $run = Invoke-RollbackScenario -Sandbox $sandbox -Lookup 'Found,Found,Absent,Found' -Budget 5

        Assert-False $run.TimedOut 'the installer never finished inside its bound'
        Assert-Equal 1 $run.ExitCode $run.Console
        Assert-True (Test-JournalHas -Run $run -Pattern '^Switch-WacDeploymentStage$') `
            ('the budget expired before the swap, so this case proves nothing about undoing one: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Register-ScheduledTask\|task$') `
            ('the task was registered with no budget left to read it back: ' + ($run.Journal -join ' / '))
        Assert-True (Test-JournalHas -Run $run -Pattern '^Restore-WacDeploymentPrevious$') `
            ('the live tree was left swapped after the budget expired: ' + ($run.Journal -join ' / '))
        Assert-True (Test-JournalHas -Run $run -Pattern ([regex]::Escape('Register-ScheduledTask|xml|' + (Get-CapturedTaskXml -Sandbox $sandbox)))) `
            ('the task the upgrade removed was not put back: ' + ($run.Journal -join ' / '))
        Assert-False (Test-JournalHas -Run $run -Pattern '^Remove-WacDeploymentPrevious$') `
            ('the rollback point was discarded on a run that did not commit: ' + ($run.Journal -join ' / '))
        Assert-True ($run.Console -match 'budget expired after the swap') $run.Console
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
