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
$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

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

Test-Case 'R06-1 a launcher that declines AFTER spending the budget starts no fallback process' {
    # The fallback used to begin with the ORIGINAL -TimeoutMs and a brand-new stopwatch, so every
    # millisecond the native launcher spent before declining was free: a launcher that took the whole
    # budget to answer "I cannot own this" was followed by a tool that then got the whole budget
    # again. Worse than the overrun is that it STARTS something at all - a spent budget is a reason
    # not to run a tool, and this was the one path that did not ask.
    $sandbox = New-TestSandbox -Prefix 'r06-late'
    $marker = Join-Path -Path $sandbox -ChildPath 'ran.txt'
    $realStart = Get-ModuleFunctionBody -Module $script:CoreModule -Name 'Start-WacOwnedProcess'
    try {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Start-WacOwnedProcess' -Body {
            param([string]$FilePath, $ArgumentList)
            $null = $FilePath, $ArgumentList
            # Spends the caller's whole budget and then declines ownership, which is the shape a
            # first-use compile of the native helper produces on a slow machine.
            Start-Sleep -Milliseconds 700
            return $null
        }

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $run = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 400 -Component 'Test' `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command',
                ('[System.IO.File]::WriteAllText("{0}", "ran")' -f $marker))
        $watch.Stop()

        Assert-False (Test-Path -LiteralPath $marker -PathType Leaf) `
            'the fallback started a tool after the budget for the whole operation was already spent'
        Assert-False ([bool]$run.Started) 'a run that started nothing reported that it had started'

        # And it did not spend a second budget discovering that. The launcher's own 700 ms is the
        # floor here; anything approaching 700 + 400 means the fallback re-armed the original bound.
        Assert-True ([int]$watch.Elapsed.TotalMilliseconds -lt 1000) `
            ('the operation took {0} ms after a 400 ms budget, so the fallback started its own' -f [int]$watch.Elapsed.TotalMilliseconds)
    }
    finally {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Start-WacOwnedProcess' -Body $realStart
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'R06-2 two pipes held open in the managed path share ONE drain grant' {
    # Handing the same duration to two waits spends it twice. The owned path was corrected for this;
    # the fallback kept the old shape, so a tool whose stdout AND stderr were both held could take
    # two full grants beyond its deadline - and the accounting believed it had given out one.
    #
    # The child keeps both pipes open by starting a grandchild that inherits them and outlives it, so
    # the root can exit while EOF never arrives. Nothing here waits on a guess: the measurement is a
    # ceiling, and the assertion is that one grant was spent rather than two.
    $sandbox = New-TestSandbox -Prefix 'r06-drain'
    $marker = Join-Path -Path $sandbox -ChildPath 'holder.pid'
    $realStart = Get-ModuleFunctionBody -Module $script:CoreModule -Name 'Start-WacOwnedProcess'
    try {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Start-WacOwnedProcess' -Body { return $null }

        $holder = @(
            ('[System.IO.File]::WriteAllText("{0}", [string]$PID)' -f $marker)
            'Start-Sleep -Seconds 25'
        ) -join '; '
        # -NoNewWindow is what makes the grandchild INHERIT this process's standard handles:
        # without it Start-Process shell-executes and the grandchild gets its own, so both pipes
        # reach EOF the moment the root exits and no drain is ever under pressure.
        $root = @(
            ('$c = Start-Process -FilePath "{0}" -NoNewWindow -ArgumentList ' -f $script:HostExe) +
                ("'-NoProfile','-NonInteractive','-EncodedCommand','{0}' -PassThru" -f
                    [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($holder)))
            ('$d = [System.Diagnostics.Stopwatch]::StartNew()')
            ('while (-not (Test-Path -LiteralPath "{0}") -and $d.Elapsed.TotalSeconds -lt 20) {{ Start-Sleep -Milliseconds 50 }}' -f $marker)
            'exit 0'
        ) -join '; '

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $run = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 20000 -Component 'Test' `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand',
                [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($root)))
        $watch.Stop()

        Assert-True (Test-Path -LiteralPath $marker -PathType Leaf) 'the grandchild never took the pipes, so this case never reached its own scenario'
        Assert-False ([bool]$run.OutputComplete) 'both pipes reached EOF, so no drain grant was ever under pressure'

        # ONE grant is 5 s. Two would be ten, and the root itself returns as soon as the marker is
        # there - so the ceiling below separates the two shapes with room to spare for a slow runner.
        Assert-True ([int]$watch.Elapsed.TotalMilliseconds -lt 9000) `
            ('the call took {0} ms, which is two drain grants rather than one shared between the pipes' -f [int]$watch.Elapsed.TotalMilliseconds)
    }
    finally {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Start-WacOwnedProcess' -Body $realStart
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            $held = 0
            try { $held = [int]([System.IO.File]::ReadAllText($marker)).Trim() } catch { $held = 0 }
            if ($held -gt 0) { Stop-Process -Id $held -Force -ErrorAction SilentlyContinue }
        }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'R06-5 an identity discovered by the LAST pass is terminated, not counted as a survivor' {
    # The loop binds whatever its rescan found and then ends, so an identity that appeared during the
    # final pass was bound and never asked to terminate - and the survivor check that follows tests a
    # process nobody told to stop. That reads as "1 identity/identities in the tree could not be
    # proven gone", which is the shape of the intermittent this project has carried since 2026-09-11.
    #
    # The scan is shimmed rather than raced: a real child, returned only on the call that lands in
    # the last pass, is the same situation arriving deterministically.
    $sandbox = New-TestSandbox -Prefix 'late-descendant'
    $marker = Join-Path -Path $sandbox -ChildPath 'child.pid'
    $realEnum = Get-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacProcessDescendantId'
    $root = $null
    $child = $null
    try {
        $childSource = @(
            ('[System.IO.File]::WriteAllText("{0}", [string]$PID)' -f $marker)
            'Start-Sleep -Seconds 40'
        ) -join '; '
        $rootSource = @(
            ('$c = Start-Process -FilePath "{0}" -WindowStyle Hidden -ArgumentList ' -f $script:HostExe) +
                ("'-NoProfile','-NonInteractive','-EncodedCommand','{0}' -PassThru" -f
                    [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($childSource)))
            'Start-Sleep -Seconds 40'
        ) -join '; '

        $root = Start-Process -FilePath $script:HostExe -PassThru -WindowStyle Hidden -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-EncodedCommand',
            [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($rootSource)))

        $appeared = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $marker -PathType Leaf) -and $appeared.Elapsed.TotalSeconds -lt 20) {
            Start-Sleep -Milliseconds 50
        }
        Assert-True (Test-Path -LiteralPath $marker -PathType Leaf) 'the fixture tree never formed, so this case measures nothing'

        $childId = [int]([System.IO.File]::ReadAllText($marker).Trim())
        $child = [System.Diagnostics.Process]::GetProcessById($childId)
        Assert-False $child.HasExited 'the child was not running before the kill'

        # Call 1 is the pre-loop scan; calls 2, 3 and 4 close passes 1, 2 and 3. Only the fourth
        # hands over the real child, so it is bound by the pass after which the loop stops.
        # The counter lives in the environment, not in a script variable: the shim runs inside the
        # module's own scope, where StrictMode turns a first read of an unset variable into a
        # terminating error - and a case that dies there has not measured its assertion.
        $env:WAC_LATE_DESCENDANT = [string]$childId
        $env:WAC_LATE_SCANS = '0'
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacProcessDescendantId' -Body {
            param([Parameter(Mandatory = $true)][int]$ProcessId)
            $null = $ProcessId
            $seen = 1 + [int]$env:WAC_LATE_SCANS
            $env:WAC_LATE_SCANS = [string]$seen
            # Nothing owns 0xFFFFFFC, so it binds nothing and merely keeps the loop going.
            if ($seen -lt 4) { return @(268435452) }
            return @([int]$env:WAC_LATE_DESCENDANT)
        }

        $stopped = Stop-WacProcessTree -ProcessId $root.Id -TimeoutMs 20000

        Assert-True ($child.WaitForExit(15000)) `
            ('the child discovered by the last pass was never terminated; the call said: ' + [string]$stopped.Reason)
        Assert-True $stopped.Proven `
            ('a tree whose last-pass discovery was terminated still reported failure: ' + [string]$stopped.Reason)
    }
    finally {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacProcessDescendantId' -Body $realEnum
        $env:WAC_LATE_DESCENDANT = $null
        $env:WAC_LATE_SCANS = $null
        if ($child -and -not $child.HasExited) { try { $child.Kill() } catch { $null = $_ } }
        if ($root) { Stop-Process -Id $root.Id -Force -ErrorAction SilentlyContinue }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'R06-3 the termination floor is granted once for a call, not once per pass' {
    # Stop-WacProcessTree makes up to three passes, and the floor that keeps a very short bound from
    # turning "asked" into "gave up" was recomputed inside the loop. The cap made each wait small and
    # nothing made their SUM small, so a caller's 200 ms bound could still be followed by three
    # near-second waits - unaccounted, and once per tree.
    #
    # The tree here is real and deliberately outlives its bound: the root starts a child that sleeps,
    # so pass one cannot clear it and the loop runs its full three.
    $sandbox = New-TestSandbox -Prefix 'r06-floor'
    $marker = Join-Path -Path $sandbox -ChildPath 'child.pid'
    $root = $null
    try {
        $child = @(
            ('[System.IO.File]::WriteAllText("{0}", [string]$PID)' -f $marker)
            'Start-Sleep -Seconds 30'
        ) -join '; '
        $rootSource = @(
            ('$c = Start-Process -FilePath "{0}" -WindowStyle Hidden -ArgumentList ' -f $script:HostExe) +
                ("'-NoProfile','-NonInteractive','-EncodedCommand','{0}' -PassThru" -f
                    [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($child)))
            'Start-Sleep -Seconds 30'
        ) -join '; '

        $root = Start-Process -FilePath $script:HostExe -PassThru -WindowStyle Hidden -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-EncodedCommand',
            [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($rootSource)))

        $appeared = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $marker -PathType Leaf) -and $appeared.Elapsed.TotalSeconds -lt 20) {
            Start-Sleep -Milliseconds 50
        }
        Assert-True (Test-Path -LiteralPath $marker -PathType Leaf) 'the fixture tree never formed, so this case measures nothing'

        $stopped = Stop-WacProcessTree -ProcessId $root.Id -TimeoutMs 1000

        # THE GRANT, not the wall time, and that distinction is the whole case. A terminated process
        # normally exits at once, so these waits are ceilings that go unspent - an overrun built out
        # of ceilings is invisible to a stopwatch. One floor for a 1000 ms bound is 1000; the floor
        # handed out again on each of three passes is three times that, and nothing in the elapsed
        # time would ever show it.
        Assert-True ([int]$stopped.GrantedWaitMs -le 1000) `
            ('terminating a three-pass tree under a 1000 ms bound granted itself {0} ms of waiting, so the floor was handed out again on every pass' -f [int]$stopped.GrantedWaitMs)

        # And the control: it really did grant something, so the assertion above is not satisfied by
        # a call that never reached its wait at all.
        Assert-True ([int]$stopped.GrantedWaitMs -gt 0) 'the termination never granted itself any wait, so this case measures nothing'
    }
    finally {
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            $held = 0
            try { $held = [int]([System.IO.File]::ReadAllText($marker)).Trim() } catch { $held = 0 }
            if ($held -gt 0) { Stop-Process -Id $held -Force -ErrorAction SilentlyContinue }
        }
        if ($root) { Stop-Process -Id $root.Id -Force -ErrorAction SilentlyContinue }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'R06-4 the termination floor is spent ONCE for a call, not once for every pass' {
    # The limit this closes, stated in an earlier round: the three-pass loop breaks the moment the
    # tree clears, so a real tree kills in pass one and the passes that would show a re-granted floor
    # never run. A tree that keeps spawning through a kill is not safely constructible either.
    #
    # What makes it measurable is the ENUMERATION, which is the loop's own continue condition and the
    # only step in it that a test can hold still. Shimmed to answer "one more id" every time, the
    # loop runs its full three passes; shimmed to take 150 ms doing so, the caller's bound is really
    # being spent, which is the only condition under which the floor is visible at all - a floor of
    # min(1000, TimeoutMs) is invisible while the remaining budget is still larger than it.
    #
    # The id it answers with is owned by nothing, so it binds nothing, terminates nothing and leaves
    # the verdict alone: this case measures the ACCOUNTING, and GrantedWaitMs is what the call says
    # it handed out. A 200 ms bound plus one floor is ~250 ms of grant; a floor re-granted per pass
    # is three of them.
    $realEnum = Get-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacProcessDescendantId'
    $child = $null
    try {
        $child = Start-Process -FilePath $script:HostExe -PassThru -WindowStyle Hidden -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30')

        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacProcessDescendantId' -Body {
            param([Parameter(Mandatory = $true)][int]$ProcessId)
            $null = $ProcessId
            # Real elapsed time, so the remaining budget actually shrinks between passes. Nothing
            # owns id 0xFFFFFFC, so binding it fails with ERROR_INVALID_PARAMETER and the loop keeps
            # going without acquiring a handle to anything.
            Start-Sleep -Milliseconds 150
            return @(268435452)
        }

        $result = Stop-WacProcessTree -ProcessId $child.Id -TimeoutMs 200

        Assert-True ($null -ne $result.GrantedWaitMs) 'the termination result no longer states what it granted, so nothing here is measurable'
        Assert-True ([int]$result.GrantedWaitMs -le 400) `
            ('a 200 ms bound handed out {0} ms of termination grant, so the floor was granted again on every pass' -f [int]$result.GrantedWaitMs)
        # A lower bound only, and it is not the floor's proof: at the first pass the remaining budget
        # is still the whole bound, so min(1000, TimeoutMs) never binds there. What this catches is a
        # call that granted nothing at all - the shape in which the ceiling above would pass
        # vacuously.
        Assert-True ([int]$result.GrantedWaitMs -ge 150) `
            ('the call granted {0} ms, so the loop this measures did not run and the ceiling above proves nothing' -f [int]$result.GrantedWaitMs)
    }
    finally {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacProcessDescendantId' -Body $realEnum
        if ($child) { Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue }
    }
}

Complete-TestRun
