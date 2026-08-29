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

# The stub sandbox and the stand-ins that drive it; see there for what each stub replaces.
. (Join-Path -Path $PSScriptRoot -ChildPath '_StubEntryPoint.ps1')

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
        Assert-True ($text -match 'Initialize-WacRun[^\r\n]*-ShutdownMarginSeconds \(\$script:ChildShutdownMarginMinutes \* 60\)') `
            ('{0} arms the child budget without holding back the shutdown margin the rollback runs in' -f $name)

        # And the budget has to be CONSUMED, before the phases it bounds. A deadline that is armed
        # and then read by nothing is the defect this replaced, not a fix for it.
        $budgetMain = Get-EntryPointMain -Ast $ast
        $checks = @(Get-CallOffset -Ast $budgetMain -Name 'Test-RunBudget')
        Assert-True ($checks.Count -ge 2) ('{0} reads its own run budget only {1} time(s)' -f $name, $checks.Count)
        foreach ($command in @('New-WacDeploymentStage', 'Switch-WacDeploymentStage', 'Register-ScheduledTask',
                'Remove-InstalledTask', 'Remove-InstalledDeployment')) {
            foreach ($offset in @(Get-CallOffset -Ast $budgetMain -Name $command)) {
                Assert-True ($checks[0] -lt $offset) `
                    ('{0} reaches {1} without ever checking its budget first' -f $name, $command)
            }
        }

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

                # The other half of the refusal rule: a run the gate LET THROUGH does write its
                # invocation record, so moving that write behind the gate did not simply delete it.
                Assert-True (@($run.LogWrites | Where-Object { $_ -match ' invoked\.$' }).Count -eq 1) `
                    ('{0} {1} pass: the invocation record did not reach the log exactly once: {2}' -f `
                        $name, $pass, (@($run.LogWrites) -join ' / '))

                if ($pass -eq 'first') { $first = $run.ExitCode }
                else { Assert-Equal $first $run.ExitCode ('{0}: the second run over the same state answered differently' -f $name) }
            }
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A run whose budget is already gone stops before it inspects or changes anything' {
    # The advertised child budget was armed by Initialize-WacRun and then read by nothing, so the
    # parent's wait outlasted a deadline no operation observed. The first check sits immediately
    # after the gate; the deeper phase checks are exercised in InstallerRollback.Tests.ps1.
    $sandbox = New-TestSandbox -Prefix 'gate-budget'
    try {
        New-StubDeployment -Sandbox $sandbox

        $trusted = Test-WacStatePathIsTrusted -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32')
        Assert-True $trusted.IsTrusted ('%SystemRoot%\System32 is not machine-trusted on this host: ' + [string]$trusted.Reason)

        foreach ($name in $script:EntryPoint) {
            $run = Invoke-StubbedEntryPoint -Sandbox $sandbox -ScriptName $name -StateMode 'trusted' `
                -StatePath ([string]$trusted.Path) -StateReason ([string]$trusted.Reason) -Budget 'expired'

            Assert-Equal 1 $run.ExitCode ('{0}: {1}' -f $name, $run.Console)
            Assert-NothingMutated -Run $run -Label ('{0} expired budget' -f $name)
            Assert-False ($run.Called -contains $script:GatePassedMarker[$name]) `
                ('{0}: an expired budget did not stop the run; calls: {1}' -f $name, ($run.Called -join ', '))
            Assert-True ($run.Console -match 'run budget expired') $run.Console

            # It crossed the gate, so it IS entitled to its log - and the expiry is recorded in it.
            Assert-True (@($run.LogWrites | Where-Object { $_ -match 'run budget expired' }).Count -gt 0) `
                ('{0}: the budget refusal never reached the log: {1}' -f $name, (@($run.LogWrites) -join ' / '))
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Neither wrapper reports an unproven termination as proof, and neither tells the operator to re-run' {
    # Stop-WacProcessTree returns a VERDICT. Both wrappers used it as a Boolean - and every non-null
    # PSCustomObject is truthy - so the success branch ran unconditionally and the CRITICAL branch
    # beneath it was unreachable: an operator whose elevated child was still mutating the machine
    # was told it was proven gone and invited to start a second one over it.
    $sandbox = New-TestSandbox -Prefix 'gate-expiry'
    try {
        New-StubDeployment -Sandbox $sandbox
        $stubHost = Join-Path -Path $PSHOME -ChildPath 'stub-host.exe'

        foreach ($name in $script:EntryPoint) {
            $lockName = 'Local\WacStubLock_' + [guid]::NewGuid().ToString('N')
            $child = Start-StubElevatedChild -Sandbox $sandbox -LockName $lockName
            try {
                Assert-True (Wait-ForStubFile -Path $child.Started) `
                    ('{0}: the stand-in child never took the operation lock' -f $name)

                $run = Invoke-StubbedEntryPoint -Sandbox $sandbox -ScriptName $name -StateMode 'trusted' `
                    -Admin $false -HostPath $stubHost -LockName $lockName `
                    -ChildPid $child.Process.Id -Termination 'unproven'

                Assert-False $run.TimedOut ('{0}: the wrapper never finished inside its bound' -f $name)
                Assert-True ($run.Called -contains 'Stop-WacProcessTree') `
                    ('{0}: the wrapper never tried to terminate the child; calls: {1}' -f $name, ($run.Called -join ', '))
                Assert-Equal 8 $run.ExitCode ('{0}: an unproven termination did not get its own exit code: {1}' -f $name, $run.Console)
                Assert-True ($run.Console -match 'could NOT be proven terminated') $run.Console
                Assert-False ($run.Console -match 'proven gone') `
                    ('{0}: an unproven termination was reported as proof: {1}' -f $name, $run.Console)
                # The success text ends "...; re-run the installer." and this path must never carry
                # it. The negative form the CRITICAL line DOES carry is asserted right after, so
                # this cannot be satisfied by a wrapper that simply stopped saying anything.
                Assert-False ($run.Console -match ';\s*re-run the ') `
                    ('{0}: the operator was told to re-run over a live child: {1}' -f $name, $run.Console)
                Assert-True ($run.Console -match 'Do NOT re-run the ') `
                    ('{0}: the operator was not told to leave the live child alone: {1}' -f $name, $run.Console)

                # And the report was accurate: the child really is still there, still holding the
                # machine-wide lock that a second run would have to take.
                $contended = Enter-WacSingleInstance -Name $lockName
                if ($contended) { Exit-WacSingleInstance -Mutex $contended }
                Assert-False $contended `
                    ('{0}: the stand-in child had already released the operation lock, so this proves nothing' -f $name)

                [System.IO.File]::WriteAllText($child.Release, 'go')
                Assert-True ($child.Process.WaitForExit(30000)) ('{0}: the stand-in child never finished' -f $name)
                Assert-True (Test-Path -LiteralPath $child.Mutation -PathType Leaf) `
                    ('{0}: the child never performed its late mutation, so the wrapper had nothing to be wrong about' -f $name)
            }
            finally {
                try { if (-not $child.Process.HasExited) { [void](Stop-WacProcessTree -ProcessId $child.Process.Id) } } catch { $null = $_ }
                try { $child.Process.Dispose() } catch { $null = $_ }
            }

            # The success branch is still REACHABLE, or the assertions above would also pass on a
            # wrapper that had simply stopped reporting a proven kill at all.
            $proven = Invoke-StubbedEntryPoint -Sandbox $sandbox -ScriptName $name -StateMode 'trusted' `
                -Admin $false -HostPath $stubHost -ChildPid 0 -Termination 'proven'

            Assert-Equal 1 $proven.ExitCode ('{0} proven: {1}' -f $name, $proven.Console)
            Assert-True ($proven.Console -match 'terminated and proven gone') $proven.Console
            Assert-False ($proven.Console -match 'could NOT be proven terminated') $proven.Console
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
