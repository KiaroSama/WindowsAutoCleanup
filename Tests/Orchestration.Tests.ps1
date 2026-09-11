#Requires -Version 5.1
<#
.SYNOPSIS
    Pins how Run.ps1 WIRES the modules together (ledger R-6).

.DESCRIPTION
    Every module is covered by its own behavioural suite, but the orchestration between them was not:
    a reviewer hard-wired eight documented invariants - DISM /ResetBase forced on, cleanmgr enabled by
    default, the protected roots dropped, the mutex and system-drive gates short-circuited, the log
    retention raised to 9999, the relaunch reading the wrong bound-parameter dictionary - and the full
    suite stayed green each time.

    Run.ps1 exits before its main body when the process is not elevated, so the wiring cannot be
    driven end to end from a test. These cases parse Run.ps1 and assert on the real call AST instead.
    That is deliberately NOT a text grep: the assertions look at the argument EXPRESSION bound to a
    named parameter, so replacing a variable with a literal is caught while reformatting is not.

    Runtime coverage for the pieces themselves lives in the per-module suites.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'
$script:InstallPath = Join-Path -Path $script:RepoRoot -ChildPath 'Install-WindowsAutoCleanupTask.ps1'

Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function Get-ScriptAst {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        throw ('{0} does not parse: {1}' -f $Path, (($errors | ForEach-Object { $_.Message }) -join '; '))
    }
    return $ast
}

$script:RunAst = Get-ScriptAst -Path $script:RunPath
$script:InstallAst = Get-ScriptAst -Path $script:InstallPath

function Get-CommandCall {
    <#
    .SYNOPSIS
        Every invocation of a named command in a parsed script.
    #>
    param(
        [Parameter(Mandatory = $true)]$Ast,
        [Parameter(Mandatory = $true)][string]$Name
    )

    # Filter OUTSIDE the predicate. A FindAll scriptblock is a separate scope that PSScriptAnalyzer
    # cannot see into, so using $Name in there makes it report the parameter as declared-but-unused -
    # and suppressing that would hide the real version of the same warning elsewhere.
    $commands = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true))

    return @($commands | Where-Object { $_.GetCommandName() -eq $Name })
}

function Get-BoundArgumentText {
    <#
    .SYNOPSIS
        The source text of the expression bound to -Parameter on a command call, or $null.
    .DESCRIPTION
        Handles both spellings PowerShell produces: '-Name:<expr>' keeps the expression on the
        CommandParameterAst itself, while '-Name <expr>' puts it in the following element.
    #>
    param(
        [Parameter(Mandatory = $true)]$Command,
        [Parameter(Mandatory = $true)][string]$Parameter
    )

    $elements = @($Command.CommandElements)
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $element = $elements[$i]
        if (-not ($element -is [System.Management.Automation.Language.CommandParameterAst])) { continue }
        if ($element.ParameterName -ne $Parameter) { continue }

        if ($null -ne $element.Argument) { return [string]$element.Argument.Extent.Text }
        if ($i + 1 -lt $elements.Count) { return [string]$elements[$i + 1].Extent.Text }
        return ''
    }

    return $null
}

function Assert-ParameterTracksVariable {
    <#
    .SYNOPSIS
        Asserts a parameter is bound to an expression mentioning $Variable, and not to a literal.
    #>
    param(
        [Parameter(Mandatory = $true)]$Ast,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Parameter,
        [Parameter(Mandatory = $true)][string]$Variable
    )

    $calls = @(Get-CommandCall -Ast $Ast -Name $Command)
    Assert-Equal 1 $calls.Count ('expected exactly one call to {0}' -f $Command)

    $text = Get-BoundArgumentText -Command $calls[0] -Parameter $Parameter
    Assert-True ($null -ne $text) ('{0} does not bind -{1} at all' -f $Command, $Parameter)
    Assert-True ($text.IndexOf('$' + $Variable, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) `
        ('{0} -{1} is bound to [{2}] instead of tracking ${3}' -f $Command, $Parameter, $text, $Variable)
}

# ---------------------------------------------------------------------------------------------
# The flagship invariant: an explicit false must reach DISM
# ---------------------------------------------------------------------------------------------

Test-Case 'DISM ResetBase tracks the parameter and is never hard-wired' {
    Assert-ParameterTracksVariable -Ast $script:RunAst -Command 'Invoke-WacComponentCleanup' `
        -Parameter 'ResetBase' -Variable 'ResetWindowsUpdateBase'
}

Test-Case 'The scheduled task action carries the caller ResetWindowsUpdateBase value' {
    $calls = @(Get-CommandCall -Ast $script:InstallAst -Name 'Get-WacTaskActionArgument')
    Assert-True ($calls.Count -ge 1) 'the installer never builds a task action argument string'

    $text = Get-BoundArgumentText -Command $calls[0] -Parameter 'ResetWindowsUpdateBase'
    Assert-True ($null -ne $text) 'the task action does not state ResetWindowsUpdateBase at all'
    Assert-True ($text.IndexOf('$ResetWindowsUpdateBase', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) `
        ('the task action hard-wires ResetWindowsUpdateBase to [{0}]' -f $text)
}

# ---------------------------------------------------------------------------------------------
# Opt-in destructive steps stay opt-in
# ---------------------------------------------------------------------------------------------

Test-Case 'The legacy all-drives Disk Cleanup tracks its opt-in switch' {
    Assert-ParameterTracksVariable -Ast $script:RunAst -Command 'Invoke-WacLegacyDiskCleanup' `
        -Parameter 'Enabled' -Variable 'EnableLegacyDiskCleanup'
}

Test-Case 'Driver pruning tracks its opt-in switch and always names a backup root' {
    Assert-ParameterTracksVariable -Ast $script:RunAst -Command 'Invoke-WacDriverPackagePrune' `
        -Parameter 'Enabled' -Variable 'PruneSupersededDrivers'

    $calls = @(Get-CommandCall -Ast $script:RunAst -Name 'Invoke-WacDriverPackagePrune')
    $backup = Get-BoundArgumentText -Command $calls[0] -Parameter 'BackupRoot'
    Assert-True ($null -ne $backup) `
        'driver pruning is invoked without a backup root, so a deleted package would be unrecoverable'
    Assert-True ($backup.IndexOf('DriverBackup', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) $backup
}

Test-Case 'All three protected roots are registered before any target is swept' {
    $calls = @(Get-CommandCall -Ast $script:RunAst -Name 'Add-WacProtectedRoot')
    Assert-Equal 3 $calls.Count 'Run.ps1 no longer registers exactly three protected roots'

    $bound = @($calls | ForEach-Object { Get-BoundArgumentText -Command $_ -Parameter 'Path' })
    $joined = ($bound -join ' ')
    foreach ($expected in @('ScriptRoot', 'Get-WacDeploymentRoot', 'Get-WacDataRoot')) {
        Assert-True ($joined.IndexOf($expected, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) `
            ('the {0} protected root is no longer registered: {1}' -f $expected, $joined)
    }

    # Registration must happen before the target loop, or the roots protect nothing.
    $addOffset = ($calls | ForEach-Object { $_.Extent.StartOffset } | Sort-Object)[0]
    $sweep = @(Get-CommandCall -Ast $script:RunAst -Name 'Get-WacCleanupTargetSet')
    Assert-Equal 1 $sweep.Count
    Assert-True ($addOffset -lt $sweep[0].Extent.StartOffset) `
        'the protected roots are registered after the cleanup targets are enumerated'
}

Test-Case 'The allow-list is built through the BOUNDED builder, never the bare one' {
    # The inversion of what this file used to assert. Get-WacCleanupTarget walks every profile's
    # Edge directory and queries Win32_UserProfile through CIM; both block in the OS, which blocks
    # every cooperative deadline check sitting behind them. Worse, it cannot say it failed: an
    # allow-list that was never finished and an allow-list with nothing in it are the same empty
    # array, so a timed-out discovery used to read as a clean run with nothing to clean.
    Assert-Equal 0 (@(Get-CommandCall -Ast $script:RunAst -Name 'Get-WacCleanupTarget')).Count `
        'Run.ps1 calls the unbounded allow-list builder directly'

    $sweep = @(Get-CommandCall -Ast $script:RunAst -Name 'Get-WacCleanupTargetSet')
    Assert-Equal 1 $sweep.Count 'Run.ps1 no longer builds the allow-list under a bound'

    # And the outcome has to be consumed, not just the list: a step result is what carries an
    # Incomplete or Failed discovery into the footer's verdict.
    $text = [System.IO.File]::ReadAllText($script:RunPath)
    Assert-True ($text -match '(?s)Get-WacCleanupTargetSet.{0,900}?New-WacStepResult.{0,200}?\$targetSet\.Outcome') `
        'the discovery outcome is never recorded as a step, so a failed discovery cannot reach the verdict'
}

# ---------------------------------------------------------------------------------------------
# Safety gates
# ---------------------------------------------------------------------------------------------

Test-Case 'The machine-wide lock is taken before the first module is loaded' {
    # An installer holding the SAME lock is free to replace the deployment this script loads its
    # modules out of, so a lock taken after Import-Module does not protect the import - the part
    # that most needs protecting. Core's Enter-WacSingleInstance cannot be used for it: Core is one
    # of the files the lock exists to keep still.
    $text = [System.IO.File]::ReadAllText($script:RunPath)

    Assert-Equal 0 (@(Get-CommandCall -Ast $script:RunAst -Name 'Enter-WacSingleInstance')).Count `
        'Run.ps1 takes the lock through a module it has to load first'

    $lock = @(Get-CommandCall -Ast $script:RunAst -Name 'Enter-WacBootstrapLock')
    Assert-Equal 1 $lock.Count 'Run.ps1 no longer takes the machine-wide lock in its bootstrap'

    $imports = @(Get-CommandCall -Ast $script:RunAst -Name 'Import-Module')
    Assert-True ($imports.Count -ge 1) 'Run.ps1 imports no modules at all'
    $firstImport = ($imports | ForEach-Object { $_.Extent.StartOffset } | Sort-Object)[0]
    Assert-True ($lock[0].Extent.StartOffset -lt $firstImport) `
        'the machine-wide lock is taken after a mutable deployed module has already been loaded'

    # The lock name still has to be the one the installer and uninstaller take; Deploy.Tests.ps1
    # pins the two literals against each other.
    Assert-Equal '$MutexName' (Get-BoundArgumentText -Command $lock[0] -Parameter 'Name') `
        'the bootstrap lock no longer takes the name -MutexName carries'

    Assert-True ($text -match '(?s)\$script:OperationLock.{0,600}?exit 3') `
        'failing to hold the lock no longer exits with the documented code 3'
    Assert-True ((@(Get-CommandCall -Ast $script:RunAst -Name 'Exit-WacBootstrapLock')).Count -ge 2) `
        'the lock is never released: the elevated relaunch and the shutdown both have to let go of it'
}

Test-Case 'The system-drive gate is wired to an exit' {
    $text = [System.IO.File]::ReadAllText($script:RunPath)

    $driveCalls = @(Get-CommandCall -Ast $script:RunAst -Name 'Test-WacSystemDriveSupported')
    Assert-Equal 1 $driveCalls.Count 'Run.ps1 no longer checks the online system drive'
    Assert-True ($text -match '(?s)Test-WacSystemDriveSupported.{0,600}?exit 5') `
        'an unsupported system drive no longer exits with the documented code 5'
}

Test-Case 'The run-level verdicts are reached BEFORE anything on the machine is mutated' {
    # Ledger: Initialize-WacRun recorded the state directory's trust verdict and Run.ps1 read it
    # only in the footer, so a SECURITY refusal arrived after the sweep, DISM, the driver step and
    # the Recycle Bin had all already run. A refusal after the damage is a report, not a control.
    $gate = @(Get-CommandCall -Ast $script:RunAst -Name 'Get-WacRunLevelOutcome')
    Assert-Equal 1 $gate.Count 'Run.ps1 no longer asks for the run-level verdicts before it cleans'
    $gateOffset = $gate[0].Extent.StartOffset

    foreach ($mutator in @('Remove-WacOldLog', 'Clear-WacDeliveryOptimizationCache',
            'Get-WacCleanupTargetSet', 'Invoke-WacComponentCleanup', 'Invoke-WacPnpCleanHandler',
            'Invoke-WacDriverPackagePrune', 'Invoke-WacLegacyDiskCleanup', 'Clear-WacRecycleBin')) {
        foreach ($call in @(Get-CommandCall -Ast $script:RunAst -Name $mutator)) {
            Assert-True ($gateOffset -lt $call.Extent.StartOffset) `
                ('{0} runs before the run-level verdicts are reached' -f $mutator)
        }
    }

    # And a refusing gate has to leave the same verdict line a footer would, or a run that exits 7
    # here would have no status= in its own audit log.
    $text = [System.IO.File]::ReadAllText($script:RunPath)
    Assert-True ($text -match '(?s)\$preflight.{0,600}?exit \(Write-WacRunVerdict -Outcome \$preflight\)') `
        'the pre-cleanup gate exits without writing the run verdict'
}

Test-Case 'The run budget is armed from process start and keeps a shutdown margin' {
    # Initialize-WacRun arms its deadline from wherever it is called, which left module import and
    # the trust preflight outside the budget entirely, and left the footer nothing to run in.
    $calls = @(Get-CommandCall -Ast $script:RunAst -Name 'Initialize-WacRun')
    Assert-Equal 1 $calls.Count

    Assert-Equal '$script:StartUtc' (Get-BoundArgumentText -Command $calls[0] -Parameter 'StartUtc') `
        'the budget is armed where the log is opened, so module import and the lock fall outside it'
    Assert-Equal '$script:CleanupMarginSeconds' (Get-BoundArgumentText -Command $calls[0] -Parameter 'ShutdownMarginSeconds') `
        'the run keeps no time back to write its own verdict in'

    # And the two values have to be captured before the modules are loaded, not after.
    $startAssign = @($script:RunAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst]
    }, $true) | Where-Object { $_.Left.Extent.Text -eq '$script:StartUtc' })
    Assert-Equal 1 $startAssign.Count 'Run.ps1 no longer records when the process itself started'

    $imports = @(Get-CommandCall -Ast $script:RunAst -Name 'Import-Module')
    $firstImport = ($imports | ForEach-Object { $_.Extent.StartOffset } | Sort-Object)[0]
    Assert-True ($startAssign[0].Extent.StartOffset -lt $firstImport) `
        'the start instant is captured after the modules are already loaded'
}

Test-Case 'Nothing on the run entry path queries CIM directly' {
    # Free space and the OS caption were Win32_LogicalDisk and Win32_OperatingSystem queries: RPC
    # round trips to the WMI service, made twice and once per run OUTSIDE every step contract, with
    # no bound of their own. Diagnostics that can stall the whole run before a single cleanup step
    # starts. Win32_UserProfile is still queried, but from inside Get-WacCleanupTargetSet, which is
    # what bounds it.
    $reportPath = Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.RunReport.ps1'
    $reportErrors = $null
    $reportTokens = $null
    $reportAst = [System.Management.Automation.Language.Parser]::ParseFile($reportPath, [ref]$reportTokens, [ref]$reportErrors)
    Assert-Equal 0 (@($reportErrors).Count) 'the run report part does not parse'

    foreach ($pair in @(@{ Name = 'Run.ps1'; Ast = $script:RunAst }, @{ Name = 'RunReport'; Ast = $reportAst })) {
        foreach ($cmdlet in @('Get-CimInstance', 'Get-WmiObject', 'New-CimSession')) {
            Assert-Equal 0 (@(Get-CommandCall -Ast $pair.Ast -Name $cmdlet)).Count `
                ('{0} makes an unbounded {1} call on the run entry path' -f $pair.Name, $cmdlet)
        }
    }
}

# The lock's own runtime behaviour - a SECOND PROCESS being refused while it is held - is proven
# end to end in RunExitCode.Tests.ps1, which holds the rig's lock from the test process and asserts
# the child's exit 3.


Test-Case 'Log retention stays at the documented 30' {
    $calls = @(Get-CommandCall -Ast $script:RunAst -Name 'Remove-WacOldLog')
    Assert-Equal 1 $calls.Count
    Assert-Equal '30' (Get-BoundArgumentText -Command $calls[0] -Parameter 'KeepCount') `
        'the README documents a retention of 30 run logs'
}

Test-Case 'The relaunch reads the script-scope snapshot, not the automatic dictionary' {
    # Ledger P0-2 in its literal shape. A function gets its OWN empty $PSBoundParameters, so passing
    # the automatic variable here silently drops -SkipCategory and -MutexName across the relaunch.
    $calls = @(Get-CommandCall -Ast $script:RunAst -Name 'Get-WacRunRelaunchArgument')
    Assert-Equal 1 $calls.Count

    $bound = Get-BoundArgumentText -Command $calls[0] -Parameter 'Bound'
    Assert-Equal '$script:BoundParameter' $bound `
        'the relaunch no longer reads the script-scope bound-parameter snapshot'
}

Test-Case 'Run.ps1 binds parameters by name only' {
    # With positional binding, '-ResetWindowsUpdateBase $false' (a space instead of a colon) bound the
    # SWITCH to true and dropped the leftover token into the positional -SkipCategory, so DISM ran
    # /ResetBase after the user explicitly asked for it not to.
    $attributes = @($script:RunAst.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' })
    Assert-Equal 1 $attributes.Count 'Run.ps1 has no CmdletBinding attribute'
    Assert-True ($attributes[0].Extent.Text -match '(?i)PositionalBinding\s*=\s*\$false') `
        ('positional binding is still enabled: {0}' -f $attributes[0].Extent.Text)
}

Test-Case 'Log retention asks Core for the log directory rather than splitting a possibly-null path' {
    # Split-Path -Parent $null is a TERMINATING binding error on both shipped hosts, so the old
    # spelling killed the run inside its own retention step on exactly the path where logging had
    # already failed - the one run that most needed to report why.
    $calls = @(Get-CommandCall -Ast $script:RunAst -Name 'Remove-WacOldLog')
    Assert-Equal 1 $calls.Count

    $bound = [string](Get-BoundArgumentText -Command $calls[0] -Parameter 'LogDirectory')
    Assert-True ($bound.IndexOf('Get-WacLogDirectory', [System.StringComparison]::Ordinal) -ge 0) `
    ('log retention no longer asks Core for the directory: ' + $bound)
    Assert-True ($bound.IndexOf('Split-Path', [System.StringComparison]::Ordinal) -lt 0) $bound
}

Test-Case 'The run log adopts the pre-import bootstrap log' {
    # Nothing inside a module can log its own import failure. If this binding goes, an import or
    # parse failure is recorded only in a temp file nobody is told about.
    $calls = @(Get-CommandCall -Ast $script:RunAst -Name 'Initialize-WacRun')
    Assert-Equal 1 $calls.Count 'Run.ps1 no longer initialises the run exactly once'

    $bound = [string](Get-BoundArgumentText -Command $calls[0] -Parameter 'BootstrapLogPath')
    Assert-True ($bound.IndexOf('BootstrapLogPath', [System.StringComparison]::Ordinal) -ge 0) `
    ('the bootstrap log is never handed to Core, so an import failure stays orphaned: ' + $bound)
}
Test-Case 'the elevated contention fixture owns the lock until its contender exits' {
    $path = Join-Path $PSScriptRoot '_ElevatedVerification.SandboxScenarios.ps1'
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count 'the elevated scenarios must parse'
    $scenario = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Invoke-Exit3Scenario'
    }, $true)
    Assert-True ($null -ne $scenario) 'the live EXIT3 scenario is missing'
    $calls = @($scenario.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -in @('Enter-WacSingleInstance', 'Exit-WacSingleInstance',
            'Start-VerificationChild', 'Wait-VerificationChild')
    }, $true) | ForEach-Object { $_.GetCommandName() })
    # Structural guard complements the live VM case: a historical log line cannot keep a lock held.
    $expected = 'Enter-WacSingleInstance,Start-VerificationChild,Wait-VerificationChild,' +
        'Exit-WacSingleInstance,Start-VerificationChild,Wait-VerificationChild,Exit-WacSingleInstance'
    Assert-Equal $expected ($calls -join ',') 'contention must be held through the wait, then tested after release'
}

Complete-TestRun
