#Requires -Version 5.1
<#
.SYNOPSIS
    The pre-flight guard both entry points cross before their first mutation: the wiring that puts
    it first, and the behaviour when it refuses.

.DESCRIPTION
    Two halves, and they need each other.

    The WIRING half is read off the AST of the shipped scripts. The lock ordering, the position of
    the safety verdict and the relationship between the parent's elevation deadline and the child's
    own budget are all invariants about code that only executes in an ELEVATED run against the live
    Task Scheduler, which is not something to execute on a workstation.

    The BEHAVIOUR half runs the real entry-point scripts, unmodified, in a bounded child process
    against a sandbox whose src\ holds STUB modules. The stub reports the run as elevated, so the
    elevated branch really executes; every destructive operation is a recording stand-in that must
    never be called; and the state-trust verdict handed to the gate is a REAL one, computed here by
    Core against a directory this suite crafted to be user-writable, inherited-unsafe, behind a
    reparse point or on a volume that cannot be inspected at all. Nothing touches the live Task
    Scheduler, the real %ProgramFiles% or the real %ProgramData%.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:EntryPoint = @('Install-WindowsAutoCleanupTask.ps1', 'Uninstall-WindowsAutoCleanupTask.ps1')

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

function Get-EntryPointAst {
    param([Parameter(Mandatory = $true)][string]$Name)

    $path = Join-Path -Path $script:RepoRoot -ChildPath $Name
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count ('{0} does not parse' -f $Name)
    return $ast
}

function Get-EntryPointMain {
    <#
    .SYNOPSIS
        The Invoke-Main definition of one entry point.
    .DESCRIPTION
        Ordering here is about the order things HAPPEN, which is the order of the calls inside
        Invoke-Main - not the order in which the helper functions those calls reach happen to be
        defined higher up the file.
    #>
    param([Parameter(Mandatory = $true)]$Ast)

    $main = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Main'
    }, $true))

    Assert-Equal 1 $main.Count 'the entry point no longer has exactly one Invoke-Main'
    return $main[0]
}

function Get-CallOffset {
    param(
        [Parameter(Mandatory = $true)]$Ast,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $commands = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true))

    return @($commands | Where-Object { $_.GetCommandName() -eq $Name } | ForEach-Object { [int]$_.Extent.StartOffset } | Sort-Object)
}

# ---------------------------------------------------------------------------------------------
# Wiring: the guard is first, and the wrapper outlasts what it started
# ---------------------------------------------------------------------------------------------

Test-Case 'Both entry points take the machine-wide lock before they inspect or change anything' {
    # Ledger B2-3, the entry-point half. Anything read before the lock is held can be read while an
    # upgrade replaces the tree underneath it. The lock is the first thing Invoke-Main does that
    # touches the machine, and it is released in the finally at the bottom of the file, so it covers
    # the commit and the rollback too.
    foreach ($name in $script:EntryPoint) {
        $main = Get-EntryPointMain -Ast (Get-EntryPointAst -Name $name)

        $lock = @(Get-CallOffset -Ast $main -Name 'Enter-WacSingleInstance')
        Assert-Equal 1 $lock.Count ('{0} no longer takes the machine-wide lock exactly once' -f $name)

        $after = @('Get-WacDeploymentSlotPath', 'Get-WacDeploymentOwnership', 'Get-WacInstalledTask',
            'New-WacDeploymentStage', 'Switch-WacDeploymentStage', 'Register-ScheduledTask',
            'Remove-WacDeployment', 'Remove-WacOldLog', 'Remove-InstalledTask',
            'Remove-InstalledDeployment', 'Resolve-ConflictingTask', 'Test-WacDeploymentTrusted')

        foreach ($command in $after) {
            foreach ($offset in @(Get-CallOffset -Ast $main -Name $command)) {
                Assert-True ($lock[0] -lt $offset) `
                    ('{0} calls {1} before it holds the machine-wide lock' -f $name, $command)
            }
        }

        # Deploy.Tests.ps1 proves the lock NAME is the one the runtime takes; this proves both entry
        # points ask for that name rather than inventing one, and give it back.
        $text = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath $name))
        Assert-True ($text -match 'Enter-WacSingleInstance -Name \(Get-WacOperationLockName\)') `
            ('{0} does not take the shared operation lock' -f $name)
        Assert-True ($text -match 'Exit-WacSingleInstance -Mutex \$script:InstanceLock') `
            ('{0} does not release the lock in its finally' -f $name)
    }
}

Test-Case 'Both entry points settle log and state trust before their first mutation' {
    # The gate used to be the LOG only, checked at the very end - after the deployment had been
    # replaced and the task registered - and state trust was never consulted at all.
    foreach ($name in $script:EntryPoint) {
        $main = Get-EntryPointMain -Ast (Get-EntryPointAst -Name $name)

        $verdict = @(Get-CallOffset -Ast $main -Name 'Get-OperationSafetyVerdict')
        Assert-Equal 1 $verdict.Count ('{0} no longer asks for a pre-flight safety verdict' -f $name)

        $mutators = @('New-WacDeploymentStage', 'Switch-WacDeploymentStage', 'Register-ScheduledTask',
            'Remove-WacDeployment', 'Remove-WacOldLog', 'Remove-InstalledTask', 'Remove-RetainedLog',
            'Remove-InstalledDeployment', 'Resolve-ConflictingTask', 'Get-WacInstalledTask',
            'Get-WacDeploymentOwnership', 'Get-WacDeploymentSlotPath', 'Test-WacSystemDriveSupported')

        foreach ($command in $mutators) {
            foreach ($offset in @(Get-CallOffset -Ast $main -Name $command)) {
                Assert-True ($verdict[0] -lt $offset) `
                    ('{0} reaches {1} before the safety verdict is taken' -f $name, $command)
            }
        }

        # A refusal leaves through the verdict's own exit code, and is never explained through the
        # log directory it may just have refused.
        $text = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath $name))
        Assert-True ($text -match '(?s)if \(-not \$safety\.Ok\)[\s\S]{0,700}?return \$safety\.ExitCode') `
            ('{0} does not return the refusal verdict''s own exit code' -f $name)
        Assert-True ($text -match '(?s)\$safety\.Reason[^\r\n]*-NoLog') `
            ('{0} explains the refusal through the log it may have just refused' -f $name)
    }

    # One body, dot-sourced by both, so the two cannot drift apart.
    Assert-True (Test-Path -LiteralPath (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.EntryGate.ps1') -PathType Leaf) `
        'the shared pre-flight gate is gone'
    foreach ($name in $script:EntryPoint) {
        $text = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath $name))
        Assert-True ($text -match 'WindowsAutoCleanup\.EntryGate\.ps1') ('{0} no longer loads the shared gate' -f $name)
        Assert-False ($text -match 'function Get-OperationSafetyVerdict') `
            ('{0} carries its own copy of the gate, which is how two copies drift' -f $name)
    }
}

Test-Case 'Neither UAC wrapper can give up while its elevated child is still allowed to be working' {
    # Ledger G4. The installer waited 20 minutes and the uninstaller 10 for a child whose own
    # deadline was 30, and on expiry each RETURNED while that still-mutating elevated child carried
    # on. The parent bound is derived from the child's budget now, so it cannot be shortened past it
    # by editing one number.
    foreach ($name in $script:EntryPoint) {
        $ast = Get-EntryPointAst -Name $name

        $assignments = @{}
        foreach ($node in @($ast.FindAll({
            param($item)
            $item -is [System.Management.Automation.Language.AssignmentStatementAst]
        }, $true))) {
            $assignments[[string]$node.Left.Extent.Text] = [string]$node.Right.Extent.Text
        }

        foreach ($variable in @('$script:RunBudgetMinutes', '$script:ChildShutdownMarginMinutes', '$script:ElevationTimeoutMs')) {
            Assert-True $assignments.ContainsKey($variable) ('{0} no longer defines {1}' -f $name, $variable)
        }

        $budget = [int]$assignments['$script:RunBudgetMinutes']
        $margin = [int]$assignments['$script:ChildShutdownMarginMinutes']
        Assert-True ($budget -ge 30) ('{0} shrank the child budget to {1}' -f $name, $budget)
        Assert-True ($margin -ge 5) ('{0} left no shutdown margin ({1})' -f $name, $margin)
        Assert-Equal '($script:RunBudgetMinutes + $script:ChildShutdownMarginMinutes) * 60000' `
            $assignments['$script:ElevationTimeoutMs'] `
            ('{0} no longer derives the parent bound from the child budget' -f $name)
        Assert-True ((($budget + $margin) * 60000) -gt ($budget * 60000)) 'the parent bound is not longer than the child budget'

        # The child has to be armed with exactly that budget, or the derivation means nothing.
        $text = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath $name))
        Assert-True ($text -match 'Initialize-WacRun[^\r\n]*-BudgetMinutes \$script:RunBudgetMinutes') `
            ('{0} arms the child with a budget unrelated to the bound the parent waits' -f $name)

        # And on expiry the child is terminated and the outcome PROVEN, never silently left running.
        $expiry = @($ast.FindAll({
            param($item)
            $item -is [System.Management.Automation.Language.IfStatementAst]
        }, $true) | Where-Object { $_.Extent.Text -match 'WaitForExit\(\$script:ElevationTimeoutMs\)' })
        Assert-Equal 1 $expiry.Count ('{0} no longer bounds the wait on its elevated child' -f $name)
        Assert-True ($expiry[0].Extent.Text -match 'Stop-WacProcessTree -ProcessId \$child\.Id') `
            ('{0} abandons an elevated child that outran the deadline' -f $name)
        Assert-True ($expiry[0].Extent.Text -match 'CRITICAL') `
            ('{0} does not report a termination it could not establish' -f $name)
    }
}

# ---------------------------------------------------------------------------------------------
# Behaviour: the real scripts, elevated branch, stub modules, nothing destructive reached
# ---------------------------------------------------------------------------------------------

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
        'function Initialize-WacRun { param([string]$BaseName, [string[]]$CandidateRoot, [string]$LogLevel, [int]$BudgetMinutes, [string]$BootstrapLogPath) Add-StubCall ''Initialize-WacRun''; return $true }',
        'function Write-WacLog { param($Level, $Component, $Message, $Data) }',
        'function Close-WacLog { Add-StubCall ''Close-WacLog'' }',
        'function Get-WacLogPath { return (Join-Path -Path $env:WAC_STUB_STATE -ChildPath ''run.log'') }',
        'function Get-WacLogDirectory { return $env:WAC_STUB_STATE }',
        'function Get-WacDataRoot { return $env:WAC_STUB_STATE }',
        'function Remove-WacOldLog { param($LogDirectory, $Pattern, $KeepCount) Add-StubCall ''Remove-WacOldLog'' }',
        'function Test-WacIsAdministrator { return $true }',
        'function Test-WacSystemDriveSupported { Add-StubCall ''Test-WacSystemDriveSupported''; return $false }',
        'function Get-WacCanonicalPowerShellHost { Add-StubCall ''Get-WacCanonicalPowerShellHost''; return $null }',
        'function Enter-WacSingleInstance { param([string]$Name) Add-StubCall ''Enter-WacSingleInstance''; return ([PSCustomObject]@{ Name = $Name }) }',
        'function Exit-WacSingleInstance { param($Mutex) Add-StubCall ''Exit-WacSingleInstance'' }',
        'function Stop-WacProcessTree { param([int]$ProcessId, [int]$TimeoutMs = 10000) Add-StubCall ''Stop-WacProcessTree''; return $false }',
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
    [void]$deploy.Add('function Get-WacOperationLockName { return ''Local\WacStubLock'' }')
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
        ExitCode, Called (the stub calls it made, in order), Console, TimedOut.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$ScriptName,
        [Parameter(Mandatory = $true)][ValidateSet('trusted', 'untrusted', 'null')][string]$StateMode,
        [string]$StatePath = '',
        [string]$StateReason = '',
        [bool]$LogDurable = $true,
        [ValidateRange(10, 300)][int]$TimeoutSeconds = 90
    )

    $callFile = Join-Path -Path $Sandbox -ChildPath 'calls.txt'
    $outFile = Join-Path -Path $Sandbox -ChildPath 'console.txt'
    $resultFile = Join-Path -Path $Sandbox -ChildPath 'exit.txt'
    foreach ($stale in @($callFile, $outFile, $resultFile)) {
        if (Test-Path -LiteralPath $stale -PathType Leaf) { [System.IO.File]::Delete($stale) }
    }
    [System.IO.File]::WriteAllText($callFile, '')

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
    $psi.EnvironmentVariables['WAC_STUB_STATE'] = (Join-Path -Path $Sandbox -ChildPath 'state')
    $psi.EnvironmentVariables['WAC_STUB_STATE_MODE'] = $StateMode
    $psi.EnvironmentVariables['WAC_STUB_STATE_PATH'] = $StatePath
    $psi.EnvironmentVariables['WAC_STUB_STATE_REASON'] = $StateReason
    $psi.EnvironmentVariables['WAC_STUB_LOG_DURABLE'] = ([string]$LogDurable)

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

Test-Case 'An untrusted state path refuses both entry points before anything is staged, registered or deleted' {
    $sandbox = New-TestSandbox -Prefix 'gate-untrusted'
    try {
        New-StubDeployment -Sandbox $sandbox
        $link = Join-Path -Path $sandbox -ChildPath 'link'

        try {
            foreach ($case in (New-TestUntrustedStatePath -Sandbox $sandbox)) {
                # The verdict is Core's, not this suite's opinion of it.
                $verdict = Test-WacStatePathIsTrusted -Path $case.Path
                Assert-False $verdict.IsTrusted ('{0}: {1} came back TRUSTED, so the case proves nothing' -f $case.Name, $case.Path)

                foreach ($name in $script:EntryPoint) {
                    $label = '{0} / {1}' -f $case.Name, $name
                    $run = Invoke-StubbedEntryPoint -Sandbox $sandbox -ScriptName $name -StateMode 'untrusted' `
                        -StatePath ([string]$verdict.Path) -StateReason ([string]$verdict.Reason)

                    Assert-Equal 7 $run.ExitCode ('{0}: {1}' -f $label, $run.Console)
                    Assert-NothingMutated -Run $run -Label $label -ScriptName $name -Refused

                    # The refusal came out of the CONSOLE, not through the path it just refused.
                    Assert-True ($run.Console -match 'Refused before any change') ('{0}: {1}' -f $label, $run.Console)
                }
            }
        }
        finally {
            try { [System.IO.Directory]::Delete($link, $false) } catch { $null = $_ }
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An unanswered state-trust question and a lost audit log refuse just as hard as a false one' {
    # Ledger G1. $null is NOT ESTABLISHED, not "fine", and a run with no durable log cannot explain
    # what it did afterwards - so neither may be allowed to reach a mutation and report it later.
    $sandbox = New-TestSandbox -Prefix 'gate-unknown'
    try {
        New-StubDeployment -Sandbox $sandbox

        foreach ($name in $script:EntryPoint) {
            $indeterminate = Invoke-StubbedEntryPoint -Sandbox $sandbox -ScriptName $name -StateMode 'null'
            Assert-Equal 7 $indeterminate.ExitCode ('{0} indeterminate: {1}' -f $name, $indeterminate.Console)
            Assert-NothingMutated -Run $indeterminate -Label ('{0} indeterminate' -f $name) -ScriptName $name -Refused
            Assert-True ($indeterminate.Console -match 'never established') $indeterminate.Console

            $undurable = Invoke-StubbedEntryPoint -Sandbox $sandbox -ScriptName $name -StateMode 'trusted' `
                -StatePath 'C:\Windows' -StateReason 'stub' -LogDurable $false
            Assert-Equal 6 $undurable.ExitCode ('{0} undurable log: {1}' -f $name, $undurable.Console)
            Assert-NothingMutated -Run $undurable -Label ('{0} undurable log' -f $name) -ScriptName $name -Refused
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A benign, trusted machine is let through - and is still benign the second time' {
    # The defect that has shipped twice here is the opposite one: a steady state that is perfectly
    # normal being reported as a security refusal. A trusted state path has to PASS the gate, and
    # running it again over the same sandbox has to pass again with the same answer.
    $sandbox = New-TestSandbox -Prefix 'gate-benign'
    try {
        New-StubDeployment -Sandbox $sandbox

        $trusted = Test-WacStatePathIsTrusted -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32')
        Assert-True $trusted.IsTrusted ('%SystemRoot%\System32 is not machine-trusted on this host: ' + [string]$trusted.Reason)

        foreach ($name in $script:EntryPoint) {
            $first = $null
            foreach ($pass in @('first', 'second')) {
                $run = Invoke-StubbedEntryPoint -Sandbox $sandbox -ScriptName $name -StateMode 'trusted' `
                    -StatePath ([string]$trusted.Path) -StateReason ([string]$trusted.Reason)

                Assert-Equal 5 $run.ExitCode ('{0} {1} pass: {2}' -f $name, $pass, $run.Console)
                Assert-NothingMutated -Run $run -Label ('{0} {1} pass' -f $name, $pass)
                Assert-True ($run.Called -contains $script:GatePassedMarker[$name]) `
                    ('{0} {1} pass: a benign run was stopped by the gate; calls: {2}' -f $name, $pass, ($run.Called -join ', '))
                Assert-False ($run.Console -match 'Refused before any change') `
                    ('{0} {1} pass: a benign steady state produced a security refusal' -f $name, $pass)

                if ($pass -eq 'first') { $first = $run.ExitCode }
                else { Assert-Equal $first $run.ExitCode ('{0}: the second run over the same state answered differently' -f $name) }
            }
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
