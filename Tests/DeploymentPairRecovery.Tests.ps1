#Requires -Version 5.1
<#
.SYNOPSIS
    The deployment tree and the scheduled-task registration as ONE recovery transaction, across the
    death of the process that started it (ledger WAC-02R).

.DESCRIPTION
    The counterexample this suite exists to pin, in the external review's own words: start with
    files A and task A; an upgrade leaves files B, the recovery slot holding A, task B registered,
    and both records uncommitted. On restart the task half counted ANY same-name task as accounted
    for and deleted task A's capture; the file half then restored files A from the swap record. The
    machine ended with files A under task B and task A's evidence destroyed. Two individually
    durable records do not make the pair atomic.

    Every scenario here drives a REAL installer process - the real Deploy module, the real slots,
    the real records, the real swap, the real reconciliation - terminates it at a named point with
    Environment.Exit, and resumes in a genuinely NEW process that reads nothing but the disk. The
    scheduler is backed by a JSON file so registrations outlive the process that made them.
    _PairRecoveryFixture.ps1 says exactly what is real and what is stubbed.

    The two halves are asserted INDEPENDENTLY: Get-PairInventory hashes the files, and
    Get-PairTaskSemantics reads the whole registration. A case that compared only one of them could
    not have seen this defect, because each half on its own looked entirely consistent.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
# For Get-WacTaskActionArgument and Get-WacTaskDescription: the fixture registers tasks through the
# module's own generators, because the ownership proof compares the argument string ordinally
# against exactly the strings that generator produces.
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_DeployFixtures.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_PairRecoveryFixture.ps1')

function New-PairCheckout {
    <#
    .SYNOPSIS
        One source checkout the child can deploy, identified by the content of its Run.ps1.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (New-TestCheckout -Path (Join-Path -Path $Sandbox -ChildPath $Name) -RunContent ('# ' + $Name))
}

function Install-PairBaseline {
    <#
    .SYNOPSIS
        A committed installation: files A at the deployment root and task A registered, with no
        record of either transaction left behind.
    .OUTPUTS
        Inventory (files A) and Semantics (task A).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)]$Fixture
    )

    $run = Invoke-PairRun -Sandbox $Sandbox -Fixture $Fixture -Source (New-PairCheckout -Sandbox $Sandbox -Name 'A')
    Assert-False $run.TimedOut 'the baseline install never finished inside its bound'
    Assert-Equal 0 $run.ExitCode ($run.Journal -join ' / ')
    Assert-False (Test-Path -LiteralPath $Fixture.SwapRecord) 'the baseline install left a swap record behind'
    Assert-False (Test-Path -LiteralPath $Fixture.CaptureRecord) 'the baseline install left a capture record behind'

    return ([PSCustomObject]@{
        Inventory = (Get-PairInventory -Path $Fixture.Root)
        Semantics = (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $Fixture)[0])
    })
}

# ---------------------------------------------------------------------------------------------
# The counterexample, and the coherent pair that has to come out of it
# ---------------------------------------------------------------------------------------------

Test-Case 'An upgrade killed before it committed puts BOTH the tree and the registration back' {
    # THE defect. Task B and task A differ only in their arguments - exactly what an upgrade that
    # adds a switch produces - so nothing but a semantic comparison can tell them apart, and the
    # name-based one retired task A's capture and then restored files A underneath task B.
    $sandbox = New-TestSandbox -Prefix 'wac02r-pair-uncommitted'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $baseline = Install-PairBaseline -Sandbox $sandbox -Fixture $fixture

        # The upgrade: files B staged and swapped in, task B registered, then the process dies
        # before anything commits.
        # A string this version really does generate, for a switch the operator can really ask for:
        # ours by the ownership proof, and a DIFFERENT task from the baseline by its semantics.
        $upgraded = Get-WacTaskActionArgument -RunScript (Join-Path -Path $fixture.Root -ChildPath 'Run.ps1') -PruneSupersededDrivers
        $killed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B') `
            -NewArguments $upgraded -Stop 'after-register'

        Assert-False $killed.TimedOut 'the upgrade never reached its stopping point inside the bound'
        Assert-Equal 70 $killed.ExitCode ($killed.Journal -join ' / ')
        Assert-True (Test-Path -LiteralPath $fixture.Previous -PathType Container) 'the fixture did not reach the state this case is about'
        Assert-True (Test-Path -LiteralPath $fixture.SwapRecord -PathType Leaf) 'the interrupted upgrade left no swap record'
        Assert-True (Test-Path -LiteralPath $fixture.CaptureRecord -PathType Leaf) 'the interrupted upgrade left no capture record'
        Assert-Equal $baseline.Inventory (Get-PairInventory -Path $fixture.Previous) 'the recovery slot does not hold the tree that was moved aside'
        Assert-True ((Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) -ne $baseline.Semantics) `
            'the fixture registered a task the baseline could not be told apart from, so this case proves nothing'

        # A NEW process, with nothing but the disk, reconciling before it stages anything of its own.
        $next = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'C') -Stop 'after-reconcile'

        Assert-False $next.TimedOut 'the next run never reached its stopping point inside the bound'
        Assert-True (Test-PairJournalHas -Run $next -Pattern '^EVENT\|plan\|RestoreOriginal') `
            ('the uncommitted swap was not read as one: ' + ($next.Journal -join ' / '))
        Assert-True (Test-PairJournalHas -Run $next -Pattern '^EVENT\|reconcile\|ok=True\|restored=1') `
            ('the registration half of the transaction was not rolled back: ' + ($next.Journal -join ' / '))

        # THE PAIR. The registration is task A again, and it is task A by its whole semantics rather
        # than by its name.
        Assert-Equal $baseline.Semantics (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) `
            'the machine kept the replacement registration while its tree was being rolled back'
        Assert-Equal 1 @(Get-PairTask -Fixture $fixture).Count 'the rollback left two registrations behind'

        # And the record is KEPT while the file half is still outstanding: it is the only thing on
        # the machine that says what the registration was.
        Assert-True (Test-Path -LiteralPath $fixture.CaptureRecord -PathType Leaf) `
            'the capture record was deleted while the tree it belongs to had still to be restored'

        # Now let a third process finish the file half, and read both halves back together.
        $final = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'C') -Stop 'after-stage'
        Assert-False $final.TimedOut 'the third run never reached its stopping point inside the bound'
        Assert-Equal $baseline.Inventory (Get-PairInventory -Path $fixture.Root) `
            'the tree at the deployment root is not the one the restored registration was taken away from'
        Assert-Equal $baseline.Semantics (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) `
            'the registration changed while the tree was being put back'
        Assert-False (Test-Path -LiteralPath $fixture.Previous) 'the recovery slot was left behind after it was reconciled'
        Assert-False (Test-Path -LiteralPath $fixture.SwapRecord) 'the reconciled swap record was left on disk'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A record written while the task is still registered is accounted for, not acted on' {
    # The state a run killed BETWEEN the capture write and the unregister leaves: the record is on
    # disk and nothing is missing. There is no phase-level seam between those two steps - the
    # unregister happens inside Remove-WacInstalledTask, and TaskCaptureTransaction.Tests.ps1 drives
    # that seam directly - so the state is produced here rather than stopped at.
    $sandbox = New-TestSandbox -Prefix 'wac02r-pair-record-only'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $baseline = Install-PairBaseline -Sandbox $sandbox -Fixture $fixture

        $savedProgramFiles = $env:ProgramFiles
        try {
            $env:ProgramFiles = $fixture.ProgramFiles
            Assert-True (Write-WacTaskCaptureRecord -DeploymentRoot $fixture.Root -Capture @([PSCustomObject]@{
                TaskName = (Get-WacTaskName); TaskPath = (Get-WacTaskFolder)
                Definition = [string]@(Get-PairTask -Fixture $fixture)[0].Xml
            })) 'the fixture could not write the record this case is about'
        }
        finally {
            $env:ProgramFiles = $savedProgramFiles
        }

        $next = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B') -Stop 'after-reconcile'
        Assert-True (Test-PairJournalHas -Run $next -Pattern '^EVENT\|reconcile\|ok=True\|restored=0\|accounted=1') `
            ('a registration that was never lost was re-registered over: ' + ($next.Journal -join ' / '))
        Assert-Equal $baseline.Semantics (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) `
            'the registration was rewritten by a run that had nothing to put back'
        Assert-Equal $baseline.Inventory (Get-PairInventory -Path $fixture.Root) 'the tree changed on a run that only reconciled'
        Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) 'a fully accounted record was kept'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A run killed after the unregister and before the swap puts the registration back' {
    # The machine has files A and NO task: the registration is genuinely missing and the record is
    # the only description of it there is.
    $sandbox = New-TestSandbox -Prefix 'wac02r-pair-after-unregister'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $baseline = Install-PairBaseline -Sandbox $sandbox -Fixture $fixture

        $killed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B') -Stop 'after-unregister'
        Assert-Equal 70 $killed.ExitCode ($killed.Journal -join ' / ')
        Assert-Equal 0 @(Get-PairTask -Fixture $fixture).Count 'the fixture did not reach the state this case is about'
        Assert-Equal $baseline.Inventory (Get-PairInventory -Path $fixture.Root) 'the tree moved before the swap this case stops short of'

        $next = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B') -Stop 'after-reconcile'
        Assert-True (Test-PairJournalHas -Run $next -Pattern '^EVENT\|reconcile\|ok=True\|restored=1') `
            ('the lost registration was not put back: ' + ($next.Journal -join ' / '))
        Assert-Equal $baseline.Semantics (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) `
            'what went back is not the registration that was taken away'

        # No swap was in flight, so the transaction is genuinely over and the record goes.
        Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) 'a fully reconciled capture record was left on disk'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A run killed between the two moves restores the pair from the slot that survived' {
    # Death with the original in the recovery slot, nothing at the deployment root, and the task
    # already unregistered. Both halves are missing, and both have to come back together.
    $sandbox = New-TestSandbox -Prefix 'wac02r-pair-between-moves'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $baseline = Install-PairBaseline -Sandbox $sandbox -Fixture $fixture

        $killed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B') -Stop 'after-unregister'
        Assert-Equal 70 $killed.ExitCode ($killed.Journal -join ' / ')

        # The first move of the swap, and nothing after it - by hand, because the point of stopping
        # here is that no process got between the two Directory.Move calls.
        [System.IO.Directory]::Move($fixture.Root, $fixture.Previous)

        $next = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'C') -Stop 'after-stage'
        Assert-False $next.TimedOut 'the next run never reached its stopping point inside the bound'
        Assert-Equal $baseline.Inventory (Get-PairInventory -Path $fixture.Root) 'the only tree left on the machine was not put back'
        Assert-Equal $baseline.Semantics (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) `
            'the registration that belongs with the restored tree was not put back'
        Assert-False (Test-Path -LiteralPath $fixture.Previous) 'the recovery slot was left behind after it was reconciled'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# What must never be touched, and what must still work
# ---------------------------------------------------------------------------------------------

Test-Case 'A FOREIGN task standing at the captured name stops the run and is left alone' {
    # Never overwrite a same-name task to resolve uncertainty. Register-ScheduledTask -Force would
    # have replaced it outright.
    $sandbox = New-TestSandbox -Prefix 'wac02r-pair-foreign'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        [void](Install-PairBaseline -Sandbox $sandbox -Fixture $fixture)

        $killed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B') -Stop 'after-unregister'
        Assert-Equal 70 $killed.ExitCode ($killed.Journal -join ' / ')

        # Somebody else registers a task at the name our dead run emptied.
        $foreignXml = New-PairTaskXml -Root 'C:\Windows' -Arguments '/c echo hello' -Description 'somebody else entirely'
        $foreign = ConvertFrom-Json -InputObject (ConvertTo-Json -Depth 12 -InputObject ([PSCustomObject]@{
            TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\'; Description = 'somebody else entirely'
            Xml = $foreignXml
            Actions = @([PSCustomObject]@{ Execute = 'C:\Windows\System32\cmd.exe'; Arguments = '/c echo hello'; WorkingDirectory = 'C:\Windows' })
            Principal = [PSCustomObject]@{ UserId = 'S-1-5-18'; LogonType = 'ServiceAccount'; RunLevel = 'HighestAvailable' }
            Settings = [PSCustomObject]@{ Enabled = 'true'; Hidden = 'true' }
            Triggers = @()
        }))
        [System.IO.File]::WriteAllText($fixture.Tasks, (ConvertTo-Json -InputObject @($foreign) -Depth 12))
        $before = Get-PairTaskSemantics -Task $foreign

        $next = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B')
        Assert-Equal 1 $next.ExitCode ($next.Journal -join ' / ')
        Assert-True ($next.JournalText -match 'cannot be proven ours') ($next.Journal -join ' / ')
        Assert-Equal $before (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) `
            'a task this project cannot prove is its own was registered over'
        Assert-True (Test-Path -LiteralPath $fixture.CaptureRecord -PathType Leaf) 'the evidence was cleared over a foreign task'
        Assert-False (Test-PairJournalHas -Run $next -Pattern '^EVENT\|staged$') `
            ('the run staged over an unresolved registration: ' + ($next.Journal -join ' / '))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'An authorized uninstall ends the records, so a later install resurrects nothing' {
    # The records live BESIDE the slots, so removing the deployment left them exactly where they
    # were and the next install re-registered a task whose files the operator had just removed.
    $sandbox = New-TestSandbox -Prefix 'wac02r-pair-uninstall'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        [void](Install-PairBaseline -Sandbox $sandbox -Fixture $fixture)

        $killed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B') -Stop 'after-unregister'
        Assert-Equal 70 $killed.ExitCode ($killed.Journal -join ' / ')
        Assert-True (Test-Path -LiteralPath $fixture.CaptureRecord -PathType Leaf) 'the fixture did not reach the state this case is about'

        # The uninstaller's own closing step, over the deployment it has just proven removed.
        $savedProgramFiles = $env:ProgramFiles
        try {
            $env:ProgramFiles = $fixture.ProgramFiles
            $slots = Get-WacDeploymentSlotPath
            foreach ($slot in @($slots.Root, $slots.Staging, $slots.Previous)) {
                if (Test-Path -LiteralPath $slot) { [System.IO.Directory]::Delete($slot, $true) }
            }
            foreach ($kind in @('Swap', 'TaskCapture')) {
                Assert-True (Remove-WacDeploymentJournal -DeploymentRoot $slots.Root -Kind $kind) `
                    ('the uninstall could not end the {0} transaction' -f $kind)
            }
        }
        finally {
            $env:ProgramFiles = $savedProgramFiles
        }

        Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) 'the uninstall left a capture record for a later install to act on'

        # A later install now sees a clean machine: one fresh registration, and no resurrection of
        # the task whose files were removed.
        $again = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'D')
        Assert-Equal 0 $again.ExitCode ($again.Journal -join ' / ')
        Assert-True (Test-PairJournalHas -Run $again -Pattern '^EVENT\|reconcile\|ok=True\|restored=0\|accounted=0') `
            ('the install reconciled a transaction the uninstall had ended: ' + ($again.Journal -join ' / '))
        Assert-Equal 1 @(Get-PairTask -Fixture $fixture).Count 'the install left more or fewer than one registration'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A commit whose record outlives it reports INCOMPLETE, not success' {
    # The removal results were discarded with [void], so an install that committed while its record
    # stayed on disk announced success - and the next run then read a settled deployment as an
    # unfinished transaction. The tree and the task really are in place, so this is not a rollback;
    # it is an install whose audit state is not what a success would be claiming.
    $sandbox = New-TestSandbox -Prefix 'wac02r-pair-incomplete'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $baseline = Install-PairBaseline -Sandbox $sandbox -Fixture $fixture

        $killed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B') -Stop 'after-unregister'
        Assert-Equal 70 $killed.ExitCode ($killed.Journal -join ' / ')
        Assert-True (Test-Path -LiteralPath $fixture.CaptureRecord -PathType Leaf) 'the fixture did not reach the state this case is about'

        # A directory at one of the write protocol's own artifact names: the record itself deletes,
        # this cannot, and the transaction is therefore not proven over.
        [void][System.IO.Directory]::CreateDirectory($fixture.CaptureRecord + '.last')

        $run = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'C')
        Assert-False $run.TimedOut 'the install never finished inside its bound'
        Assert-Equal 6 $run.ExitCode ('an install whose transaction outlived it reported success: ' + ($run.Journal -join ' / '))
        Assert-True (Test-PairJournalHas -Run $run -Pattern '^EVENT\|capture-ended\|False') ($run.Journal -join ' / ')

        # And it really did install: incomplete is about the audit state, not about the work.
        Assert-Equal '# C' ([System.IO.File]::ReadAllText((Join-Path -Path $fixture.Root -ChildPath 'Run.ps1'))) `
            'the run reported incomplete because it had not actually deployed'
        Assert-Equal 1 @(Get-PairTask -Fixture $fixture).Count 'the run left more or fewer than one registration'
        Assert-Equal $baseline.Semantics (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) `
            'the registration this run installed is not the one it asked for'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Two clean reinstalls in a row leave no record, no recovery slot and one registration' {
    # The benign steady state. None of the guards above may turn a machine where everything works
    # into a refusal, on the first upgrade or on the one after it.
    $sandbox = New-TestSandbox -Prefix 'wac02r-pair-clean'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        [void](Install-PairBaseline -Sandbox $sandbox -Fixture $fixture)

        foreach ($pass in @('B', 'C')) {
            $run = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name $pass)

            Assert-False $run.TimedOut ('pass {0}: the install never finished inside its bound' -f $pass)
            Assert-Equal 0 $run.ExitCode ('pass {0}: {1}' -f $pass, ($run.Journal -join ' / '))
            Assert-True (Test-PairJournalHas -Run $run -Pattern '^EVENT\|plan\|None') `
                ('pass {0}: a clean machine was read as an outstanding transaction: {1}' -f $pass, ($run.Journal -join ' / '))
            Assert-False (Test-Path -LiteralPath $fixture.SwapRecord) ('pass {0}: the committed install left a swap record' -f $pass)
            Assert-False (Test-Path -LiteralPath $fixture.CaptureRecord) ('pass {0}: the committed install left a capture record' -f $pass)
            Assert-False (Test-Path -LiteralPath $fixture.Previous) ('pass {0}: the committed install left a recovery slot' -f $pass)
            Assert-Equal 1 @(Get-PairTask -Fixture $fixture).Count ('pass {0}: the install left more or fewer than one registration' -f $pass)

            # The deployment tree is deliberately NOT a copy of the checkout - the walk excludes
            # .git, Logs, README.md and every dot-name - so the build is identified by the files both
            # sides do agree on, and the exclusions are asserted rather than assumed.
            Assert-Equal ('# ' + $pass) ([System.IO.File]::ReadAllText((Join-Path -Path $fixture.Root -ChildPath 'Run.ps1'))) `
                ('pass {0}: the deployment root does not hold the Run.ps1 this pass installed' -f $pass)
            foreach ($excluded in @('.git', 'Logs', 'README.md', 'src\.ignoreme')) {
                Assert-False (Test-Path -LiteralPath (Join-Path -Path $fixture.Root -ChildPath $excluded)) `
                    ('pass {0}: {1} reached the deployment' -f $pass, $excluded)
            }
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A new install that fails its OWN prerequisites still leaves the pair coherent' {
    # R02-1. The two halves used to be reconciled at different distances from the door: the task
    # half ran first, and the file half lived inside New-WacDeploymentStage - behind that function's
    # validation of the NEW source, and behind the canonical-host and budget checks the caller makes
    # in front of it. Each of those can return, and a return in that window is what leaves task A
    # standing over files B: an unfinished pair, exposed, with no further attempt scheduled to close
    # it, because the installer that would have closed it is the one that just gave up.
    #
    # The prerequisite modelled here is the source, which is the one this driver can fail honestly.
    # The host and budget checks sit in the installer itself and are covered by Installer.Tests.ps1;
    # what makes them the same case is their POSITION, and position is what this asserts.
    $sandbox = New-TestSandbox -Prefix 'wac02r-prereq'
    try {
        $fixture = New-PairSandbox -Sandbox $sandbox
        $baseline = Install-PairBaseline -Sandbox $sandbox -Fixture $fixture

        $upgraded = Get-WacTaskActionArgument -RunScript (Join-Path -Path $fixture.Root -ChildPath 'Run.ps1') -PruneSupersededDrivers
        $killed = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source (New-PairCheckout -Sandbox $sandbox -Name 'B') `
            -NewArguments $upgraded -Stop 'after-register'
        Assert-False $killed.TimedOut 'the upgrade never reached its stopping point inside the bound'
        Assert-True (Test-Path -LiteralPath $fixture.Previous -PathType Container) 'the fixture did not reach the state this case is about'

        # A source with no Run.ps1 in it: the run refuses, as it should, AFTER both halves are back.
        $unusable = Join-Path -Path $sandbox -ChildPath 'unusable'
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $unusable -ChildPath 'src'))

        $next = Invoke-PairRun -Sandbox $sandbox -Fixture $fixture -Source $unusable
        Assert-False $next.TimedOut 'the resuming run never finished inside the bound'
        Assert-True ([int]$next.ExitCode -ne 0) 'a run given a source it cannot deploy reported success'
        Assert-True (Test-PairJournalHas -Run $next -Pattern '^EVENT\|recover\|Restored') `
            ('the file half never ran, so the new install''s own prerequisite decided it: ' + ($next.Journal -join ' / '))

        # THE PAIR, after a run that failed. Both halves are the baseline's, and neither the slot nor
        # the record is left standing for a later run to find.
        Assert-Equal $baseline.Inventory (Get-PairInventory -Path $fixture.Root) `
            'the deployment root was left holding the replacement of a transaction that never committed'
        Assert-Equal $baseline.Semantics (Get-PairTaskSemantics -Task @(Get-PairTask -Fixture $fixture)[0]) `
            'the registration was left pointing at a tree that is no longer there'
        Assert-Equal 1 @(Get-PairTask -Fixture $fixture).Count 'the resumed run left two registrations behind'
        Assert-False (Test-Path -LiteralPath $fixture.Previous) 'the recovery slot was left behind after both halves were reconciled'
        Assert-False (Test-Path -LiteralPath $fixture.SwapRecord) 'the reconciled swap record was left on disk'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
