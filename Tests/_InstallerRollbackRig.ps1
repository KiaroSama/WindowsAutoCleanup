#Requires -Version 5.1
<#
.SYNOPSIS
    The rig that runs the REAL Install-WindowsAutoCleanupTask.ps1 in a bounded child process over a
    stubbed module tree.

.DESCRIPTION
    Dot-sourced by InstallerRollback.Tests.ps1 and InstallerCommitExit.Tests.ps1. It is not a suite:
    its name does not match Tests\*.Tests.ps1, so the runner never executes it alone.

    Nothing here touches the live Task Scheduler, %ProgramFiles% or %ProgramData%: the stubs report
    what each scenario tells them to and journal every call they receive, so the assertions are made
    against that journal and against the child's real exit code.

    Shadowing the ScheduledTasks module through PSModulePath is the only mechanism that works.
    Measured on both hosts: a function exported by an earlier import does NOT survive
    'Import-Module ScheduledTasks' - the later import wins - so a stub has to be found by that
    import rather than defined before it.

    What a consuming suite owes this file: $script:RepoRoot, and an import of
    src\WindowsAutoCleanup.Core.psm1 for the Stop-WacProcessTree that reaps a child which outran
    its bound.
#>

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
    foreach ($part in @('WindowsAutoCleanup.EntryGate.ps1', 'WindowsAutoCleanup.InstallerTask.ps1',
        'WindowsAutoCleanup.InstallerRecovery.ps1')) {
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
        # The quarantine admission the shared gate makes before either entry point changes anything.
        # Clear here: every scenario in this suite is about what happens AFTER the gate lets the run
        # through, and EntryPointGuard.Tests.ps1 owns the refusal.
        'function Test-WacMutationAllowed { return $true }',
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
        # The commit point's two record deletions, as RESULTS rather than gestures. WAC_RB_COMMIT
        # fails one of them while the install itself still lands, which is the only way a durable
        # record outlives the commit that was supposed to end it.
        'function Remove-WacDeploymentPrevious { Add-Journal ''Remove-WacDeploymentPrevious''; return ($env:WAC_RB_COMMIT -ne ''swap-stays'') }',
        'function Remove-WacDeployment { param([string]$Path, [string]$DeploymentRoot) Add-Journal (''Remove-WacDeployment|'' + $Path); return ([PSCustomObject]@{ Path = $Path; Removed = $true; Reason = $null }) }',
        # The durable capture record, as REAL file I/O rather than a flag: the conflict phase
        # writes it, the reconciliation at the top of a run reads it, and the commit deletes it,
        # so the assertions below are about a file the shipped code actually drove.
        'function Get-WacDeploymentJournalPath { param([string]$DeploymentRoot, [string]$Kind = ''Swap'') $root = (Get-WacDeploymentSlotPath).Root; if ($Kind -eq ''TaskCapture'') { return ($root + ''.taskcapture.json'') }; return ($root + ''.transaction.json'') }',
        'function Write-WacTaskCaptureRecord {',
        '    param([object[]]$Capture, [string]$DeploymentRoot)',
        '    Add-Journal (''Write-WacTaskCaptureRecord|'' + @($Capture).Count)',
        '    if ($env:WAC_RB_RECORD -eq ''fail'') { return $false }',
        '    [System.IO.File]::WriteAllText((Get-WacDeploymentJournalPath -Kind ''TaskCapture''), (ConvertTo-Json -InputObject @($Capture) -Depth 5))',
        '    return $true',
        '}',
        'function Read-WacTaskCaptureRecord {',
        '    param([string]$DeploymentRoot)',
        '    $path = Get-WacDeploymentJournalPath -Kind ''TaskCapture''',
        '    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return ([PSCustomObject]@{ State = ''Absent''; Schema = 0; Capture = @(); Reason = '''' }) }',
        '    $items = @(ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path)))',
        '    Add-Journal (''Read-WacTaskCaptureRecord|'' + @($items).Count)',
        '    return ([PSCustomObject]@{ State = ''Valid''; Schema = 2; Capture = @($items); Reason = ''stub'' })',
        '}',
        # The ONE commit decision the generation gets (ledger WAC-02R). The installer asks for it
        # before anything is staged and hands it to the task half; the file half derives the same
        # one inside New-WacDeploymentStage, which this sandbox stubs out. WAC_RB_PLAN is the
        # verdict a scenario wants; the capture it carries is the real record on disk.
        'function Get-WacDeploymentRecoveryPlan {',
        '    param([string]$DeploymentRoot)',
        '    $verdict = $env:WAC_RB_PLAN',
        '    if (-not $verdict) { $verdict = ''None'' }',
        '    Add-Journal (''Get-WacDeploymentRecoveryPlan|'' + $verdict)',
        '    return ([PSCustomObject]@{',
        '        Verdict = $verdict; Reason = ''stub''; Slots = (Get-WacDeploymentSlotPath)',
        '        Swap = $null; Capture = (Read-WacTaskCaptureRecord); Linked = ($env:WAC_RB_LINKED -eq ''yes'')',
        '        SlotState = ''Absent''; Promotable = $null; Corroboration = $null; Live = $null',
        '    })',
        '}',
        # Whether a task standing at a captured name IS that capture. 'differ' is a task that wears
        # the name and is not the task - the shape the name-only comparison could not see.
        'function Test-WacCapturedTaskDefinition {',
        '    param([string]$Xml, $Task)',
        '    $null = $Xml, $Task',
        '    $match = ($env:WAC_RB_SEMANTICS -ne ''differ'')',
        '    Add-Journal (''Test-WacCapturedTaskDefinition|'' + $match)',
        '    return ([PSCustomObject]@{ Match = $match; Reason = ''stub'' })',
        '}',
        'function Remove-WacTaskCaptureRecord {',
        '    param([string]$DeploymentRoot)',
        '    Add-Journal ''Remove-WacTaskCaptureRecord''',
        '    if ($env:WAC_RB_COMMIT -eq ''capture-stays'') { return $false }',
        '    $path = Get-WacDeploymentJournalPath -Kind ''TaskCapture''',
        '    if (Test-Path -LiteralPath $path -PathType Leaf) { [System.IO.File]::Delete($path) }',
        '    return $true',
        '}',
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
        '    param($Task, [string]$DeploymentRoot, [switch]$AllowLegacyMigration, [switch]$RequireDefinitionCapture, [AllowNull()][scriptblock]$OnCaptured)',
        '    $outcome = Get-StepBehaviour -Name ''Remove-WacInstalledTask'' -Plan $env:WAC_RB_REMOVE -Fallback ''Verified''',
        '    $captured = ($env:WAC_RB_CAPTURE -ne ''no'')',
        '    Add-Journal (''Remove-WacInstalledTask|'' + $outcome + ''|captured='' + $captured)',
        '    $result = [PSCustomObject]@{ TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder); Removed = $false; Verified = $false; Captured = $captured; CaptureDurable = $null; Definition = $null; CaptureReason = ''stub''; Reason = ''stub'' }',
        '    if ($captured) { $result.Definition = $env:WAC_RB_XML }',
        '    if ($RequireDefinitionCapture -and -not $captured) { $result.Reason = ''the definition could not be captured first''; return $result }',
        # The transaction boundary, modelled here because Remove-WacInstalledTask is one of the
        # things this sandbox replaces: the capture is made durable BEFORE anything is removed,
        # and on a write that failed the task stays registered.
        '    if ($OnCaptured -and $captured) {',
        '        $durable = $false',
        '        try { $durable = [bool](& $OnCaptured $result) } catch { $durable = $false }',
        '        $result.CaptureDurable = $durable',
        '        if (-not $durable) { $result.Reason = ''the captured definition could not be recorded where a later run would find it''; return $result }',
        '    }',
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
        # The scheduler's answers, in the order they are asked for. Restore-CapturedTask asks one
        # more question than it used to (ledger WAC-02R): before it registers a captured definition
        # it checks what, if anything, already stands at that name, because Register-ScheduledTask
        # -Force would otherwise overwrite a task somebody else created there. A scenario that put
        # a task back therefore answers ABSENT at that position - which is the truth, since the
        # phase before it unregistered the one that was there - and Found at the read-back after.
        [string]$Lookup = 'Absent',
        [string]$Remove = 'Verified',
        [ValidateSet('yes', 'no')][string]$Capture = 'yes',
        [ValidateSet('ok', 'throw')][string]$Register = 'ok',
        # Whether the durable capture record can be written at all. 'fail' is the transaction
        # boundary: the task stays registered and the upgrade stops before it changes anything.
        [ValidateSet('ok', 'fail')][string]$Record = 'ok',
        # The recovery plan's verdict, and whether a task standing at a captured name IS that
        # capture. Both are what the real module derives from disk; here they are what the scenario
        # says, so a case can put the pair in a state and see what the installer does with it.
        [ValidateSet('None', 'RestoreOriginal', 'CommitReplacement', 'Refuse')][string]$Plan = 'None',
        [ValidateSet('same', 'differ')][string]$Semantics = 'same',
        [ValidateSet('yes', 'no')][string]$Linked = 'no',
        # Whether the two record deletions at the commit point SUCCEED. The install itself still
        # lands either way: 'swap-stays' and 'capture-stays' are a durable record outliving the
        # commit that ended it, which leaves a later run reconciling a state that is already settled.
        [ValidateSet('clean', 'swap-stays', 'capture-stays')][string]$Commit = 'clean',
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
    $psi.EnvironmentVariables['WAC_RB_RECORD'] = $Record
    $psi.EnvironmentVariables['WAC_RB_PLAN'] = $Plan
    $psi.EnvironmentVariables['WAC_RB_SEMANTICS'] = $Semantics
    $psi.EnvironmentVariables['WAC_RB_LINKED'] = $Linked
    $psi.EnvironmentVariables['WAC_RB_COMMIT'] = $Commit
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

    # The child's HOST wrapped this, so a phrase that reads as one line in the log can arrive with a
    # newline inside it. Measured in CI: Windows PowerShell 5.1 broke
    # "...; putting it back from the durable record." after "putting it " and the assertion matching
    # "putting it back" failed on both images while pwsh passed. ConsoleText collapses every run of
    # whitespace to one space so a text assertion cannot depend on the console width of whatever host
    # ran the child; Console keeps the layout, because that is what makes a failure message readable.
    $consoleText = ($console -replace '\s+', ' ')

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Journal = @(@([System.IO.File]::ReadAllLines($journal)) | Where-Object { $_.Trim() })
        Console = $console
        ConsoleText = $consoleText
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
