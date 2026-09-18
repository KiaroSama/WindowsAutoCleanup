#Requires -Version 5.1
<#
.SYNOPSIS
    What a finished external tool actually proves, and what every step must do before it returns
    (ledger WAC-05R, acceptance R05-1 and R05-2).

.DESCRIPTION
    Two defects with one shape: a fact nobody established was read as a fact in our favour.

      R05-1  THE CONTRACT WAS NEGATIVE. It vetoed only on evidence, so a result that stated nothing
             was settled, and an UNOWNED run was exempted outright on the grounds that its pipe
             reaching EOF stood in for a job object. It does not. A pipe reaches EOF when every
             WRITE HANDLE on it closes, which is a fact about handles: a descendant that closes or
             redirects its own standard handles goes on running with the pipe already at EOF, and
             the root then exits zero. Output closure is not tree completion.
      R05-2  TWO STEPS RETURNED BEFORE THE FINALIZER. A DISM or pnpclean killed on its deadline is
             the tool most likely to have left something running, and it was the one exit that
             skipped the completion check entirely: the step reported Incomplete, which told the
             footer something was unfinished, while the latch stayed down and the next guarded
             mutator started on top of it.

    The distinction the repair rests on is that a tool's result answers two different questions, and
    only one of them may authorise a deletion:

      Settled           - the whole lifetime is established. Nothing of ours is still running.
      OutputTrustworthy - the bytes in hand are all of them. A reader may believe its answer; it may
                          not conclude anything about what is still alive.

    Keeping them apart is what stops the repair becoming fail-shut. A machine that cannot give a tool
    a job object can still READ with it - it just cannot delete on the strength of that read.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
foreach ($moduleLeaf in @('Core', 'FileSystem', 'Steps', 'Drivers')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

. (Join-Path -Path $PSScriptRoot -ChildPath '_StepHarness.ps1')

# The harness reaches into ONE module, and the two steps under test here live in two: DISM in
# Steps.psm1, pnpclean in DriverHandler.ps1 which Drivers.psm1 dot-sources. It is read at call time,
# so each case points it at the module whose step it is about rather than this suite owning one.
$script:StepsPackage = Get-Module -Name 'WindowsAutoCleanup.Steps'
$script:DriversPackage = Get-Module -Name 'WindowsAutoCleanup.Drivers'
$script:StepModule = $script:StepsPackage

# rundll32 is invoked with the handler entry point as its FIRST argument, and the recording
# invoker keys on that, so the stub has to name it exactly as the step builds it.
$script:PnpCleanKey = '{0}\System32\pnpclean.dll,RunDLL_PnpClean' -f $env:SystemRoot

$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

function New-LifetimeRun {
    <#
    .SYNOPSIS
        A complete run result, with only the named facts changed. Written positively so a case says
        exactly which fact it is varying and nothing is silently absent.
    #>
    param([hashtable]$Change = @{})

    $run = [PSCustomObject]@{
        ExitCode = 0; TimedOut = $false; StandardOutput = ''; StandardError = ''
        DurationMs = 5; Started = $true
        TerminationProven = $true; OutputComplete = $true
        Owned = $true; OwnedTreeState = 'Complete'
    }
    foreach ($name in @($Change.Keys)) { $run.$name = $Change[$name] }
    return $run
}

function New-DetachedDescendantArgument {
    <#
    .SYNOPSIS
        A root that starts a child, waits for the child to CLOSE both inherited pipe ends, then exits
        zero while the child keeps running.
    .DESCRIPTION
        This is the shape the old exemption could not see. The child closes its standard handles, so
        both pipes reach EOF and the parent's reads complete; the root then exits zero; and the child
        is still there. Every signal the unowned runner has says finished.

        The marker is written by the CHILD after it has closed its handles, so the root can wait for
        a real signal rather than for a guessed interval.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][int]$HoldSeconds
    )

    $child = @(
        '[Console]::Out.Close()'
        '[Console]::Error.Close()'
        ('[System.IO.File]::WriteAllText("{0}", [string]$PID)' -f $MarkerPath)
        ('Start-Sleep -Seconds {0}' -f $HoldSeconds)
    ) -join '; '

    $root = @(
        ('$c = Start-Process -FilePath "{0}" -WindowStyle Hidden -ArgumentList ' -f $script:HostExe) +
            ("'-NoProfile','-NonInteractive','-EncodedCommand','{0}' -PassThru" -f (ConvertTo-LifetimeEncoded -Source $child))
        ('$d = [System.Diagnostics.Stopwatch]::StartNew()')
        ('while (-not (Test-Path -LiteralPath "{0}") -and $d.Elapsed.TotalSeconds -lt 20) {{ Start-Sleep -Milliseconds 50 }}' -f $MarkerPath)
        'exit 0'
    ) -join '; '

    return @('-NoProfile', '-NonInteractive', '-EncodedCommand', (ConvertTo-LifetimeEncoded -Source $root))
}

function ConvertTo-LifetimeEncoded {
    param([Parameter(Mandatory = $true)][string]$Source)
    return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Source))
}

function Stop-LifetimeDescendant {
    <#
    .SYNOPSIS
        Reaps the deliberately abandoned child by the pid IT recorded, never by name.
    #>
    param([Parameter(Mandatory = $true)][string]$MarkerPath)

    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) { return }
    $recorded = 0
    try { $recorded = [int]([System.IO.File]::ReadAllText($MarkerPath)).Trim() } catch { $recorded = 0 }
    if ($recorded -gt 0) { Stop-Process -Id $recorded -Force -ErrorAction SilentlyContinue }
}

Test-Case 'R05-1 a result that states nothing, or states only EOF, is not a finished tool' {
    # The contract in isolation, across every shape a runner can produce. The end-to-end half is the
    # case below; this one pins the rule each producer is held to.
    Assert-False ((Test-WacToolLifetimeSettled -Run $null).Settled) 'a missing result was read as a finished tool'

    # MISSING FACTS ARE UNKNOWN. Each of the four is required, and dropping any one of them is enough.
    foreach ($fact in @('Started', 'TerminationProven', 'OutputComplete', 'OwnedTreeState')) {
        $partial = New-LifetimeRun
        $partial.PSObject.Properties.Remove($fact)
        # A contract that reaches for the missing field instead of answering unknown THROWS, and a
        # strict-mode error names a variable rather than the defect. Caught here so the failure says
        # what went wrong.
        $verdict = $null
        try { $verdict = Test-WacToolLifetimeSettled -Run $partial }
        catch {
            throw ('a result that never stated {0} made the contract read the field anyway instead of answering unknown: {1}' -f
                $fact, [string]$_.Exception.Message)
        }
        Assert-False $verdict.Settled ('a result that never stated {0} was read as a finished tool' -f $fact)
        Assert-True ([string]$verdict.Reason).Contains($fact) `
            ('the refusal did not name the fact that was missing: {0}' -f [string]$verdict.Reason)
    }

    # THE EXEMPTION THAT WAS REMOVED: unowned, root exited, both pipes at EOF, tree unreadable.
    $eof = New-LifetimeRun -Change @{ Owned = $false; OwnedTreeState = 'Unknown' }
    $verdict = Test-WacToolLifetimeSettled -Run $eof
    Assert-False $verdict.Settled 'pipe EOF was accepted as proof that nothing this run started is alive'
    Assert-True $verdict.OutputTrustworthy 'the bytes that did arrive were thrown away with the tree claim'

    # AND THE CONTROL, without which "never settled" would satisfy every assertion above.
    $finished = Test-WacToolLifetimeSettled -Run (New-LifetimeRun)
    Assert-True $finished.Settled 'a tool that finished cleanly was refused'
    Assert-True $finished.OutputTrustworthy 'a clean run was not trusted for its own output'

    # A tool that never started has no tree to prove - but only when the result agrees nothing is
    # left. A suspended process nobody could confirm terminating is NOT that.
    Assert-True ((Test-WacToolLifetimeSettled -Run (New-LifetimeRun -Change @{ Started = $false })).Settled) `
        'a tool that never ran was treated as unfinished work'
    Assert-False ((Test-WacToolLifetimeSettled -Run (New-LifetimeRun -Change @{ Started = $false; OwnedTreeState = 'Unknown' })).Settled) `
        'a process that was created and could not be proven gone was read as never started'
}

Test-Case 'R05-1 an unprovable tool quarantines a MUTATOR and still lets a READER answer' {
    # The consequence, which is the half that matters: asserting the flags alone would not notice if
    # nothing consulted them. Both directions, because a rule that refused everything would pass the
    # first assertion and make the tool useless on any machine without job objects.
    $eof = New-LifetimeRun -Change @{ Owned = $false; OwnedTreeState = 'Unknown' }
    try {
        Reset-WacAbandonedMutator
        $read = Resolve-WacSettledOutcome -Outcome 'Succeeded' -Detail 'enumerated' -Run $eof -Kind 'ReadOnly'
        Assert-Equal 'Succeeded' ([string]$read.Outcome) 'a tool that changed nothing was reported unfinished'
        Assert-True (Test-WacMutationAllowed) 'a read stopped the run'

        Reset-WacAbandonedMutator
        $wrote = Resolve-WacSettledOutcome -Outcome 'Succeeded' -Detail 'serviced' -Run $eof -Kind 'Mutating'
        Assert-Equal 'Incomplete' ([string]$wrote.Outcome) 'an unprovable mutator reported success'
        Assert-False (Test-WacMutationAllowed) 'an unprovable mutator left the run free to start the next one'

        # A tree seen to be ALIVE is not the same as one nobody could read, and the read-only
        # allowance stops there: "I cannot look" and "I looked and it is running" are different facts.
        Reset-WacAbandonedMutator
        $alive = Resolve-WacSettledOutcome -Outcome 'Succeeded' -Detail 'enumerated' `
            -Run (New-LifetimeRun -Change @{ OwnedTreeState = 'Alive' }) -Kind 'ReadOnly'
        Assert-Equal 'Incomplete' ([string]$alive.Outcome) `
            'a read whose own descendant was still running reported a finished answer'
    }
    finally { Reset-WacAbandonedMutator }
}

Test-Case 'R05-1 a real descendant that closes its pipes and lives is not a finished tool' {
    # End to end through the MANAGED FALLBACK, which is the path the exemption existed for. The
    # launcher is forced to decline ownership, so the runner has nothing but the root's exit code and
    # the pipes - exactly the evidence the old contract called sufficient.
    $sandbox = New-TestSandbox -Prefix 'r05-eof'
    $marker = Join-Path -Path $sandbox -ChildPath 'child.pid'
    try {
        Set-WacOwnedProcessLauncher -Launcher { return $null }
        Reset-WacAbandonedMutator

        $run = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 40000 -Component 'Test' `
            -ArgumentList (New-DetachedDescendantArgument -MarkerPath $marker -HoldSeconds 30)

        # The fixture has to have produced the shape this case is about, or it proves nothing.
        Assert-True (Test-Path -LiteralPath $marker -PathType Leaf) 'the child never closed its handles, so the case never reached its own scenario'
        Assert-Equal 0 ([int]$run.ExitCode) 'the root did not exit zero, so this is not the case under test'
        Assert-True ([bool]$run.OutputComplete) 'both pipes did not reach EOF, so the old exemption was never in play'
        Assert-False ([bool]$run.Owned) 'the launcher was not forced into the managed fallback'

        $verdict = Test-WacToolLifetimeSettled -Run $run
        Assert-False $verdict.Settled `
            'a root that exited zero with its pipes at EOF was read as proof that the child it left behind is gone'

        # And the run is fenced: a mutating step on this result must not let the next one start.
        [void](Resolve-WacSettledOutcome -Outcome 'Succeeded' -Detail 'serviced' -Run $run -Kind 'Mutating')
        Assert-False (Test-WacMutationAllowed) 'a live descendant left the run free to start the next mutation'
    }
    finally {
        Set-WacOwnedProcessLauncher -Launcher $null
        Reset-WacAbandonedMutator
        Stop-LifetimeDescendant -MarkerPath $marker
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'R05-2 a DISM killed on its deadline stops the next mutator, and a proven one does not' {
    # The real step function, not a reimplementation of its rule. The timeout branch was the only
    # exit that returned without asking whether anything was still running.
    $script:StepModule = $script:StepsPackage
    try {
        Invoke-WithStubbedTool -Body {
            Reset-WacAbandonedMutator
            $script:StubResult['/Online'] = @{ ExitCode = $null; TimedOut = $true; TerminationProven = $false; OwnedTreeState = 'Unknown' }

            $result = Invoke-WacComponentCleanup

            Assert-Equal 'Incomplete' ([string]$result.Outcome) ([string]$result.Detail)
            Assert-False (Test-WacMutationAllowed) `
                'a DISM killed on its deadline with a tree nobody could read left the run free to start the next mutator'
            Assert-True ([string]$result.Detail).Contains('could not be proven stopped') `
                ('the step did not say what was unproven: {0}' -f [string]$result.Detail)
        }

        # THE CONTROL. A deadline the runner DID resolve - tree terminated and proven - is still
        # Incomplete work, but it is not a reason to fence the rest of the run. Without this the case
        # above would pass just as well against a step that quarantined on every timeout.
        Invoke-WithStubbedTool -Body {
            Reset-WacAbandonedMutator
            $script:StubResult['/Online'] = @{ ExitCode = $null; TimedOut = $true }

            $result = Invoke-WacComponentCleanup

            Assert-Equal 'Incomplete' ([string]$result.Outcome) ([string]$result.Detail)
            Assert-True (Test-WacMutationAllowed) `
                'a deadline whose tree was proven gone fenced the rest of the run anyway'
        }
    }
    finally { Reset-WacAbandonedMutator }
}

Test-Case 'R05-2 a pnpclean killed on its deadline stops the next mutator too' {
    # The same defect in the second step, and it needs its own case: the two functions are separate
    # copies of the same shape, and fixing one told us nothing about the other.
    $script:StepModule = $script:DriversPackage
    try {
        Invoke-WithStubbedTool -StubToolPath -Body {
            Reset-WacAbandonedMutator
            $script:StubResult[$script:PnpCleanKey] = @{ ExitCode = $null; TimedOut = $true; TerminationProven = $false; OwnedTreeState = 'Unknown' }

            $result = Invoke-WacPnpCleanHandler

            Assert-Equal 'Incomplete' ([string]$result.Outcome) ([string]$result.Detail)
            Assert-False (Test-WacMutationAllowed) `
                'a pnpclean killed on its deadline left the run free to start the next mutator'
        }

        Invoke-WithStubbedTool -StubToolPath -Body {
            Reset-WacAbandonedMutator
            $script:StubResult[$script:PnpCleanKey] = @{ ExitCode = $null; TimedOut = $true }

            $result = Invoke-WacPnpCleanHandler

            Assert-Equal 'Incomplete' ([string]$result.Outcome) ([string]$result.Detail)
            Assert-True (Test-WacMutationAllowed) 'a proven deadline fenced the rest of the run anyway'
        }
    }
    finally {
        Reset-WacAbandonedMutator
        $script:StepModule = $script:StepsPackage
    }
}

Complete-TestRun
