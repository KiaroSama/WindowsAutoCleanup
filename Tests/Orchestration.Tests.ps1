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

# ---------------------------------------------------------------------------------------------
# Safety gates
# ---------------------------------------------------------------------------------------------

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
    $sweep = @(Get-CommandCall -Ast $script:RunAst -Name 'Get-WacCleanupTarget')
    Assert-Equal 1 $sweep.Count
    Assert-True ($addOffset -lt $sweep[0].Extent.StartOffset) `
        'the protected roots are registered after the cleanup targets are enumerated'
}

Test-Case 'The single-instance lock and the system-drive gate are both wired to an exit' {
    $text = [System.IO.File]::ReadAllText($script:RunPath)

    # Behavioural coverage for the lock itself lives in the case below; this asserts the ORCHESTRATION
    # keeps both gates, because a reviewer removed each of them with the suite still green.
    $mutexCalls = @(Get-CommandCall -Ast $script:RunAst -Name 'Enter-WacSingleInstance')
    Assert-Equal 1 $mutexCalls.Count 'Run.ps1 no longer takes the machine-wide lock'
    Assert-True ($text -match '(?s)Enter-WacSingleInstance.{0,600}?exit 3') `
        'failing to take the lock no longer exits with the documented code 3'

    $driveCalls = @(Get-CommandCall -Ast $script:RunAst -Name 'Test-WacSystemDriveSupported')
    Assert-Equal 1 $driveCalls.Count 'Run.ps1 no longer checks the online system drive'
    Assert-True ($text -match '(?s)Test-WacSystemDriveSupported.{0,600}?exit 5') `
        'an unsupported system drive no longer exits with the documented code 5'
}

# The lock's own runtime behaviour - a SECOND PROCESS being refused while it is held, and the lock
# becoming available again after Exit-WacSingleInstance - is proven in Core.Tests.ps1. It cannot be
# proven through Run.ps1 from a test: exit code 3 is only reachable after the elevation check, so an
# unelevated run never gets that far and an elevated one would perform a real machine-wide cleanup.


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

Complete-TestRun
