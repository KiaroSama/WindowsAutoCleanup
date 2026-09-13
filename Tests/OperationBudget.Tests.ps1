#Requires -Version 5.1
<#
.SYNOPSIS
    How ONE operation's time budget is divided among its phases, and which clock measures it
    (ledger WAC-06R).

.DESCRIPTION
    Two claims that were correct by construction and that nothing measured. Both were recorded as
    stated limits rather than quietly counted as covered, and both turn out to be discriminable once
    the right thing is held still:

      the CLOCK      the tree wait polls against a Stopwatch, not the civil clock, because a wall
                     clock moved by an NTP or DST correction changes the length of the one wait
                     whose entire purpose is to be bounded. A real test cannot move the machine's
                     clock - but it can make the CIVIL clock answer differently while the monotonic
                     one carries on, which is exactly the divergence the choice exists to survive.
      the DEBIT      creating the pipes, compiling the helper on first use, CreateProcessW and the
                     job assignment are part of the operation, not something that happens before it
                     starts. Measuring that against a real tool put it below the noise, so the setup
                     is made slow on purpose and the budget handed to the next phase is read
                     directly instead of being inferred from a wall time.

    Neither case runs a real external tool. What is under test is arithmetic and a loop condition;
    putting a genuine process behind them would add seconds of wall time and a source of flakiness
    without adding evidence.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:CoreModule = Get-Module -Name 'WindowsAutoCleanup.Core'

function Get-ModuleFunctionBody {
    param([Parameter(Mandatory = $true)]$Module, [Parameter(Mandatory = $true)][string]$Name)

    return (& $Module { param($n) (Get-Item -Path ('function:' + $n)).ScriptBlock } $Name)
}

function Set-ModuleFunctionBody {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
}

function Remove-ModuleFunctionBody {
    <#
    .SYNOPSIS
        Drops a function this suite ADDED to the module scope, rather than restoring a body it
        replaced. Shadowing a cmdlet creates a name the module did not have, and leaving a
        script-scoped Get-Date behind would follow every later call in the process.
    #>
    param([Parameter(Mandatory = $true)]$Module, [Parameter(Mandatory = $true)][string]$Name)

    & $Module { param($n)
        if (Test-Path -LiteralPath ('function:script:' + $n)) { Remove-Item -LiteralPath ('function:script:' + $n) -Force }
    } $Name
}

Test-Case 'The tree wait spends its own budget on a monotonic clock, not on the civil one' {
    # The loop is held open - the tree never stops being Alive - so the ONLY thing that can end it is
    # its own budget, and how long it lasts is therefore a direct reading of which clock it asked.
    #
    # The civil clock is then made to run away: every call answers an hour later than the last. A
    # loop reading it concludes on its first check that its budget went long ago and returns at once;
    # a loop reading a Stopwatch never notices, because nothing moved the monotonic clock. The
    # divergence is the whole point - it is what an NTP or DST correction does to a running wait.
    $budgetMs = 400
    $realTreeState = Get-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacOwnedTreeState'

    # Initialised HERE, not inside the shadow. Correct code never calls Get-Date at all, so an
    # uninitialised counter would make the shadow throw only in the run that DOES call it - and the
    # case would then fail with a strict-mode error about a variable instead of the sentence that
    # names what went wrong. A guard is only as useful as the message it fails with.
    $script:WacBudgetClockCall = 0
    try {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacOwnedTreeState' -Body {
            param($Launch)
            $null = $Launch
            return ([PSCustomObject]@{ State = 'Alive'; ActiveProcesses = 1 })
        }
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-Date' -Body {
            param([switch]$AsUTC)
            $null = $AsUTC
            $script:WacBudgetClockCall = 1 + [int]$script:WacBudgetClockCall
            return ([DateTime]::UtcNow.AddHours($script:WacBudgetClockCall))
        }

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $tree = Wait-WacOwnedTreeQuiet -Launch ([PSCustomObject]@{ Job = [IntPtr]::Zero }) -BudgetMs $budgetMs
        $watch.Stop()

        # The claim, first: the wait lasted its budget. A civil-clock loop returns on its first
        # check, so anything close to zero here means the clock this loop asked can be moved.
        Assert-True ([int]$tree.WaitedMs -ge [int]($budgetMs * 0.8)) `
            ('the tree wait gave up after {0} ms of a {1} ms budget, so a clock that moved cut it short' -f [int]$tree.WaitedMs, $budgetMs)
        Assert-Equal 'Alive' ([string]$tree.State) `
            'the wait ended for a reason other than its budget, so its length measures nothing'

        # And it really did wait, rather than reporting a number it never spent.
        Assert-True ([int]$watch.Elapsed.TotalMilliseconds -ge [int]($budgetMs * 0.8)) `
            ('the reported wait of {0} ms was not actually spent' -f [int]$tree.WaitedMs)
    }
    finally {
        Remove-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-Date'
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacOwnedTreeState' -Body $realTreeState
    }
}

Test-Case 'The launch itself is debited from the operation budget the next phase receives' {
    # Starting the tool is part of the operation. Handing the root the ORIGINAL timeout afterwards
    # means the operation as a whole always overruns by however long the start took - invisible at
    # real setup costs of a few milliseconds against a thirty-second budget, which is why this was
    # left unmeasured. Making the start expensive turns it into a number worth asserting, and the
    # budget handed on is read directly rather than inferred from a wall clock.
    $budgetMs = 2000
    $setupMs = 400
    $realStart = Get-ModuleFunctionBody -Module $script:CoreModule -Name 'Start-WacOwnedProcess'
    $realOwnedTool = Get-ModuleFunctionBody -Module $script:CoreModule -Name 'Invoke-WacOwnedTool'

    # Set before the run so a shadow that never fires is a clear assertion below rather than a
    # strict-mode error about an unset variable. A replacement body keeps the session state it was
    # CREATED in, which is this file's - the same reason the driver fixtures read their recorder
    # from here rather than from inside the module they installed it into.
    $script:WacBudgetHandedOn = -1
    try {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Start-WacOwnedProcess' -Body {
            param([string]$FilePath, $ArgumentList)
            $null = $FilePath, $ArgumentList
            # A real launch this slow would be a bad machine; the point is only that the cost is
            # large enough to be told apart from measurement noise.
            Start-Sleep -Milliseconds 400
            return ([PSCustomObject]@{
                State = 'Resumed'; ProcessId = 0; Owned = $true; Stopped = $false
                Failure = ''; Degraded = ''; Job = [IntPtr]::Zero
            })
        }
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Invoke-WacOwnedTool' -Body {
            param($Launch, [int]$TimeoutMs, [string]$FilePath, [string]$Component)
            $null = $Launch, $FilePath, $Component
            $script:WacBudgetHandedOn = $TimeoutMs
            return ([PSCustomObject]@{
                ExitCode = 0; TimedOut = $false; StandardOutput = ''; StandardError = ''
                DurationMs = 0; Started = $true; TerminationProven = $true; OutputComplete = $true
                Owned = $true; OwnedTreeState = 'Complete'
            })
        }

        $result = Invoke-WacProcess -FilePath 'C:\Windows\System32\cmd.exe' -ArgumentList @('/c', 'rem') `
            -TimeoutMs $budgetMs -Component 'Test'
        $handed = [int]$script:WacBudgetHandedOn

        Assert-Equal 0 ([int]$result.ExitCode) 'the fixture did not reach the owned-tool phase at all'
        Assert-True ($handed -ge 0) 'the owned-tool phase was never reached, so no budget was observed'
        Assert-True ($handed -le ($budgetMs - [int]($setupMs * 0.75))) `
            ('the root was handed {0} ms of a {1} ms operation after a {2} ms start, so the start was not debited' -f $handed, $budgetMs, $setupMs)

        # The other direction, so a mutation that simply zeroes the budget cannot pass this case:
        # what was taken away is the start, not the operation.
        Assert-True ($handed -ge ($budgetMs - ($setupMs * 3))) `
            ('the root was handed only {0} ms of a {1} ms operation, which is more than the start can account for' -f $handed, $budgetMs)
    }
    finally {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Invoke-WacOwnedTool' -Body $realOwnedTool
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Start-WacOwnedProcess' -Body $realStart
    }
}

Complete-TestRun
