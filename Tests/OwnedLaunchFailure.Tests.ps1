#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-13: a launch that fails must never let one logical invocation execute twice.

.DESCRIPTION
    The native launcher creates a process suspended, binds it to a job, then resumes it. Everything
    after that resume - adopting pipe streams, closing handles - can still fail, and the first
    version collapsed any such failure to $null. Its caller read $null as "nothing started" and ran
    the same command again through the managed path. For `pnputil /delete-driver` or
    `cleanmgr /sagerun` that is one deletion executing twice, and closing the first job cannot undo
    what it already did.

    The fix is a launch STATE, not a patch: NeverCreated (nothing exists - a retry is safe), Created
    (suspended, executed nothing, terminated by the launcher - reported, never retried) and Resumed
    (effects are possible - never retried under any failure).

    THE SEAMS ARE NATIVE, deliberately. Those states are produced inside `WacOwnedProcess.Start`,
    between CreateProcessW and ResumeThread; a test that swaps the whole launcher for one returning
    $null exercises the substitute rather than the code. `Set-WacOwnedProcessFault` fails exactly one
    phase and can never make a phase succeed, so production behaviour with no fault armed is the
    same code these cases run.

    THE ASSERTION IS AN INVOCATION COUNTER written by a real child, not a call count on a mock: the
    defect was two real processes doing the same work.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

function Get-InvocationCount {
    <#
    .SYNOPSIS
        How many times the fixture tool actually ran. Absent file means zero.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    return @(Get-Content -LiteralPath $Path | Where-Object { $_.Trim() }).Count
}

function New-CountingArgument {
    <#
    .SYNOPSIS
        A harmless tool that appends one line per execution and optionally holds afterwards.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$CounterPath,
        [string]$PidPath = '',
        [int]$HoldSeconds = 0
    )

    $source = "Add-Content -LiteralPath '$CounterPath' -Value 'ran'"
    if ($PidPath) { $source += "; Set-Content -LiteralPath '$PidPath' -Value ([string]`$PID)" }
    if ($HoldSeconds -gt 0) { $source += "; Start-Sleep -Seconds $HoldSeconds" }
    $source += '; exit 0'

    return @('-NoProfile', '-NonInteractive', '-Command', $source)
}

function Wait-ProcessGone {
    param([Parameter(Mandatory = $true)][int]$ProcessId, [int]$BudgetMs = 6000)

    $deadline = [datetime]::UtcNow.AddMilliseconds($BudgetMs)
    while ([datetime]::UtcNow -lt $deadline) {
        if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue))
}

function Stop-FixtureByCommandLine {
    <#
    .SYNOPSIS
        Reaps a fixture child identified by a unique string in its command line, and says how many
        it stopped.
    .DESCRIPTION
        Needed only by the case that deliberately leaves a SUSPENDED process behind: the shared
        result contract carries no process id, and a suspended child writes no pid file because it
        has executed nothing. Matching on this case's own sandbox path cannot touch anything else -
        the path contains a fresh GUID.
    #>
    param([Parameter(Mandatory = $true)][string]$Marker)

    $stopped = 0
    foreach ($row in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Marker) -and $_.ProcessId -ne $PID })) {
        Stop-Process -Id ([int]$row.ProcessId) -Force -ErrorAction SilentlyContinue
        $stopped++
    }
    return $stopped
}

Test-Case 'a failure AFTER the child was resumed reports it and never runs the command twice' {
    # THE regression. The child is already executing when the launcher fails, so the only correct
    # number of invocations is the one that already happened.
    $sandbox = New-TestSandbox -Prefix 'wac13-once'
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'invocations.txt'
        [void](Set-WacOwnedProcessFault -Phase AfterResume -Message 'injected stream adoption failure')

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 30000 `
            -ArgumentList (New-CountingArgument -CounterPath $counter) -Component 'Test'

        Assert-Equal 1 (Get-InvocationCount -Path $counter) `
            'the command executed a second time after a failure that happened once it was already running'
        Assert-True ([bool]$result.Started) 'a tool that really ran was reported as never started'
    }
    finally {
        [void](Set-WacOwnedProcessFault -Phase None)
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a failure BEFORE the resume runs nothing at all, and is reported as a failed start' {
    # The other side of the contract. The process was created, so it is not retried - but it was
    # suspended the whole time, so it executed nothing and left nothing behind.
    $sandbox = New-TestSandbox -Prefix 'wac13-none'
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'invocations.txt'
        [void](Set-WacOwnedProcessFault -Phase BeforeResume -Message 'injected pre-resume failure')

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 30000 `
            -ArgumentList (New-CountingArgument -CounterPath $counter) -Component 'Test'

        Assert-Equal 0 (Get-InvocationCount -Path $counter) `
            'a process that was never resumed still managed to execute'
        Assert-True (-not $result.Started) 'a tool that never ran was reported as started'
        Assert-Equal $null $result.ExitCode 'an exit code was reported for a tool that never ran'
        Assert-True ([bool]$result.TerminationProven) `
            'a suspended process that was terminated without ever running was left unproven'
    }
    finally {
        [void](Set-WacOwnedProcessFault -Phase None)
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a launch that could not take a job still runs the tool once, and never claims ownership' {
    # The non-null Owned=false launch, which is a different object from a null launcher: the child
    # HAS been created and resumed. It must run exactly once and report honestly.
    $sandbox = New-TestSandbox -Prefix 'wac13-nojob'
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'invocations.txt'
        [void](Set-WacOwnedProcessFault -Phase JobAssign -Message 'injected assignment failure')

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 30000 `
            -ArgumentList (New-CountingArgument -CounterPath $counter) -Component 'Test'

        Assert-Equal 1 (Get-InvocationCount -Path $counter) 'the jobless launch did not run exactly once'
        Assert-True ([bool]$result.Started) 'the jobless launch was reported as never started'
        Assert-Equal 0 ([int]$result.ExitCode) 'the jobless launch lost the exit code'
        Assert-True (-not $result.Owned) 'a launch with no job claimed ownership'
        Assert-Equal 'Unknown' ([string]$result.OwnedTreeState) `
            'a launch with no job reported a job verdict it cannot have'
    }
    finally {
        [void](Set-WacOwnedProcessFault -Phase None)
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a jobless launch that times out is still terminated, not merely reported' {
    # TerminateJob(IntPtr.Zero) answered $false and stopped nothing, so a timed-out tool with no job
    # kept running while the run reported a deadline. Without a job the handle-binding walk is the
    # only honest stop, and its verdict is what must be reported.
    $sandbox = New-TestSandbox -Prefix 'wac13-kill'
    $childId = 0
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'invocations.txt'
        $pidFile = Join-Path -Path $sandbox -ChildPath 'child.pid'
        [void](Set-WacOwnedProcessFault -Phase JobAssign -Message 'injected assignment failure')

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 3000 `
            -ArgumentList (New-CountingArgument -CounterPath $counter -PidPath $pidFile -HoldSeconds 60) `
            -Component 'Test'

        Assert-True ([bool]$result.TimedOut) 'the jobless tool was not held to its deadline'
        if (Test-Path -LiteralPath $pidFile) {
            $text = (Get-Content -LiteralPath $pidFile -Raw).Trim()
            if ($text -match '^\d+$') { $childId = [int]$text }
        }
        Assert-True ($childId -gt 0) 'the fixture never recorded the child, so nothing was proved'
        Assert-True (Wait-ProcessGone -ProcessId $childId) `
            'a jobless tool survived its own deadline - nothing actually terminated it'
        $childId = 0
    }
    finally {
        if ($childId -gt 0) { Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue }
        [void](Set-WacOwnedProcessFault -Phase None)
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a suspended process that could not be terminated is never reported as stopped' {
    # WAC-13 defect 1. TerminateProcess is a REQUEST and it is asynchronous; the launcher used to
    # discard even the request's own return value, close the handle, and have the dispatch report
    # TerminationProven=true regardless. A root this run can no longer see is exactly the thing it
    # must not claim to have stopped.
    #
    # Driven through the launcher rather than through Invoke-WacProcess, because with the request
    # refused the suspended process really is left behind and this case has to reap it.
    $sandbox = New-TestSandbox -Prefix 'owned-terminate'
    $launch = $null
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'ran.txt'
        [void](Set-WacOwnedProcessFault -Phase BeforeResume -Message 'injected pre-resume failure')
        [WacOwnedProcess]::FaultTerminateRefused = $true

        $argv = New-CountingArgument -CounterPath $counter
        $commandLine = (ConvertTo-WacCommandLineArgument -Value $script:HostExe) + ' ' + (ConvertTo-WacCommandLine -ArgumentList $argv)
        # The same working directory the shipped launcher derives; CreateProcessW is handed a
        # real one rather than a null, exactly as production does.
        $workingDirectory = [System.IO.Path]::GetDirectoryName($script:HostExe)
        $launch = [WacOwnedProcess]::Start($script:HostExe, $commandLine, $workingDirectory, 2000)

        Assert-Equal 'Created' ([string]$launch.State) 'the fixture did not reach the suspended state this case is about'
        Assert-False ([bool]$launch.Stopped) 'a termination request that was refused was reported as a confirmed stop'
        Assert-True (([string]$launch.Degraded).Length -gt 0) 'an unconfirmed termination said nothing about why'
        Assert-Equal 0 (Get-InvocationCount -Path $counter) 'a process that was never resumed executed the command'
    }
    finally {
        [WacOwnedProcess]::FaultTerminateRefused = $false
        [void](Set-WacOwnedProcessFault -Phase None)
        # The case deliberately left it suspended; nothing else will reap it.
        if ($launch -and $launch.ProcessId -gt 0) {
            Stop-Process -Id ([int]$launch.ProcessId) -Force -ErrorAction SilentlyContinue
        }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a suspended process that WAS terminated reports a confirmed stop' {
    # The control for the case above. Without it "never proven" satisfies that assertion and every
    # ordinary failed start would start reporting an unaccounted live root.
    $sandbox = New-TestSandbox -Prefix 'owned-terminate-ok'
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'ran.txt'
        [void](Set-WacOwnedProcessFault -Phase BeforeResume -Message 'injected pre-resume failure')

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 30000 `
            -ArgumentList (New-CountingArgument -CounterPath $counter) -Component 'Test'

        Assert-False ([bool]$result.Started) 'a process that never ran was reported as started'
        Assert-True ([bool]$result.TerminationProven) 'a confirmed termination was not reported as proven'
        Assert-Equal 'Complete' ([string]$result.OwnedTreeState) 'a confirmed termination left the tree state unresolved'
        Assert-Equal 0 (Get-InvocationCount -Path $counter) 'a process that was never resumed executed the command'
    }
    finally {
        [void](Set-WacOwnedProcessFault -Phase None)
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an UNOWNED tool that fails after it started is stopped, not merely reported' {
    # WAC-13 defect 2, and the reason the existing jobless-timeout case does not cover it: that one
    # is reached from the TIMEOUT branch. This one throws while the tool is running, which used to
    # land in a catch whose finally only called Close - and with Job zero, closing handles terminates
    # nothing at all. The tool kept running while the run reported an exception.
    $sandbox = New-TestSandbox -Prefix 'owned-unowned-throw'
    $childId = 0
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'ran.txt'
        $pidPath = Join-Path -Path $sandbox -ChildPath 'child.pid'

        [void](Set-WacOwnedProcessFault -Phase JobAssign -Message 'injected assignment failure')
        [void](Set-WacOwnedRunFault -Phase 'ReadAcquire')

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 30000 `
            -ArgumentList (New-CountingArgument -CounterPath $counter -PidPath $pidPath -HoldSeconds 60) -Component 'Test'

        Assert-True ([bool]$result.Started) 'a tool that had already started was reported as not started'
        Assert-False ([bool]$result.Owned) 'a launch whose job assignment failed claimed ownership'

        if (Test-Path -LiteralPath $pidPath) {
            $recorded = (Get-Content -LiteralPath $pidPath -Raw).Trim()
            if ($recorded -match '^[0-9]+$') { $childId = [int]$recorded }
        }

        # The TOOL is what matters, not the message. Either it wrote its pid - in which case that
        # process has to be gone - or it was stopped before it got that far.
        if ($childId -gt 0) {
            Assert-True (Wait-ProcessGone -ProcessId $childId) `
                ('an unowned tool that failed after starting was left running: pid {0}' -f $childId)
        }
        Assert-True ([bool]$result.TerminationProven) `
            'the walk stopped the tool but its verdict was not carried into the result'
    }
    finally {
        [void](Set-WacOwnedRunFault -Phase 'None')
        [void](Set-WacOwnedProcessFault -Phase None)
        if ($childId -gt 0) { Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a stream that cannot be constructed leaves nothing created and no damaged handle' {
    # WAC-13 defect 3. A SafeFileHandle adopts the raw pipe handle the moment it is constructed, so
    # a throw from the FileStream over it used to be followed by the raw cleanup closing the SAME
    # handle - a double close on a number the OS may already have reissued. The visible consequence
    # is not an exception here but damage LATER, so the assertion is that the very next launch in
    # this process still works.
    $sandbox = New-TestSandbox -Prefix 'owned-stream'
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'ran.txt'
        [void](Set-WacOwnedProcessFault -Phase OutStream -Message 'injected stream construction failure')

        $first = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 30000 `
            -ArgumentList (New-CountingArgument -CounterPath $counter) -Component 'Test'

        # The streams are built BEFORE CreateProcessW, so nothing was created and the managed
        # fallback is the safe answer - it runs the command exactly once.
        Assert-Equal 1 (Get-InvocationCount -Path $counter) 'the fallback after a pre-creation failure did not run the command exactly once'
        Assert-True ([bool]$first.Started) 'the fallback did not report the tool as started'

        [void](Set-WacOwnedProcessFault -Phase None)
        $secondCounter = Join-Path -Path $sandbox -ChildPath 'ran2.txt'
        $second = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 30000 `
            -ArgumentList (New-CountingArgument -CounterPath $secondCounter) -Component 'Test'

        Assert-Equal 0 ([int]$second.ExitCode) 'the launch after a stream failure did not work, which is what a damaged handle looks like'
        Assert-True ([bool]$second.Owned) 'ownership was lost after a stream failure in an earlier launch'
        Assert-Equal 1 (Get-InvocationCount -Path $secondCounter) 'the launch after a stream failure did not run its command once'
    }
    finally {
        [void](Set-WacOwnedProcessFault -Phase None)
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a termination that was never confirmed is reported unproven by the caller too' {
    # The CONSUMER half of WAC-13 defect 1. The launcher answering Stopped=$false is only useful if
    # the dispatch reads it: that branch used to return TerminationProven=$true unconditionally, so
    # a suspended root nobody could stop was reported to the run as cleanly terminated.
    #
    # The process really is left behind here - that is the whole point - so the case reaps it by the
    # unique sandbox path in its own command line.
    $sandbox = New-TestSandbox -Prefix 'owned-unconfirmed'
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'ran.txt'
        [void](Set-WacOwnedProcessFault -Phase BeforeResume -Message 'injected pre-resume failure')
        [WacOwnedProcess]::FaultTerminateRefused = $true

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 30000 `
            -ArgumentList (New-CountingArgument -CounterPath $counter) -Component 'Test'

        Assert-False ([bool]$result.Started) 'a process that never ran was reported as started'
        Assert-False ([bool]$result.TerminationProven) `
            'a suspended root that could not be confirmed stopped was reported as proven terminated'
        Assert-Equal 'Unknown' ([string]$result.OwnedTreeState) `
            'an unconfirmed termination reported a resolved tree state'
        Assert-Equal 0 (Get-InvocationCount -Path $counter) 'a process that was never resumed executed the command'
    }
    finally {
        [WacOwnedProcess]::FaultTerminateRefused = $false
        [void](Set-WacOwnedProcessFault -Phase None)
        [void](Stop-FixtureByCommandLine -Marker $sandbox)
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a termination that was GRANTED but not confirmed in its budget is not a stop' {
    # WAC-13 defect 1, and the half the two cases above could not reach. They discriminate whether
    # the REQUEST succeeded; neither can discriminate the WAIT that follows it, because a suspended
    # process dies the instant it is asked and the wait therefore never changes an answer. The state
    # that matters in production - the request granted, the process still there when the budget ran
    # out - is exactly the state a fixture cannot produce on demand, so the launcher carries a seam
    # for it beside the one that refuses the request.
    #
    # Driven through the launcher, like its sibling: the caller's view of this is already covered by
    # 'a termination that was never confirmed is reported unproven by the caller too'.
    $sandbox = New-TestSandbox -Prefix 'owned-confirm'
    $launch = $null
    try {
        $counter = Join-Path -Path $sandbox -ChildPath 'ran.txt'
        [void](Set-WacOwnedProcessFault -Phase BeforeResume -Message 'injected pre-resume failure')
        [WacOwnedProcess]::FaultConfirmNotSignalled = $true

        $argv = New-CountingArgument -CounterPath $counter
        $commandLine = (ConvertTo-WacCommandLineArgument -Value $script:HostExe) + ' ' + (ConvertTo-WacCommandLine -ArgumentList $argv)
        $workingDirectory = [System.IO.Path]::GetDirectoryName($script:HostExe)
        $launch = [WacOwnedProcess]::Start($script:HostExe, $commandLine, $workingDirectory, 2000)

        Assert-Equal 'Created' ([string]$launch.State) 'the fixture did not reach the suspended state this case is about'
        Assert-False ([bool]$launch.Stopped) `
            'a termination whose confirmation never came back was reported as a confirmed stop, so asking was treated as stopping'

        # WHICH refusal it was. The sibling case produces a false Stopped from a REFUSED request; if
        # both cases accepted either message, either one could pass for the other.
        Assert-True ([string]$launch.Degraded).Contains('had not exited') `
            ('the degraded reason describes a refused request rather than an unconfirmed exit: {0}' -f [string]$launch.Degraded)
        Assert-Equal 0 (Get-InvocationCount -Path $counter) 'a process that was never resumed executed the command'
    }
    finally {
        [WacOwnedProcess]::FaultConfirmNotSignalled = $false
        [void](Set-WacOwnedProcessFault -Phase None)
        # The request really was granted here - only its confirmation was withheld - but this case
        # must not depend on that to leave the machine clean.
        if ($launch -and $launch.ProcessId -gt 0) {
            Stop-Process -Id ([int]$launch.ProcessId) -Force -ErrorAction SilentlyContinue
        }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a stream failure stands down from the handle its SafeFileHandle already owns' {
    # WAC-13 defect 3, asserted DIRECTLY. The case above it asserts the consequence - that the next
    # launch still works - and that assertion cannot fail for this reason: closing a handle twice on
    # Windows normally produces nothing observable in-process, so the ordering that prevents it could
    # be reverted with the whole suite still green. That is the shape of a guard nothing measures.
    #
    # The launcher therefore counts the read ends it closed RAW, meaning ones no SafeFileHandle had
    # adopted. With the fault armed the count is the whole assertion: stderr's read end was never
    # adopted and is legitimately closed here, stdout's was adopted one line before the throw and
    # must be left to its owner. One, not two.
    $launch = $null
    try {
        [void](Set-WacOwnedProcessFault -Phase OutStream -Message 'injected stream construction failure')
        Assert-Equal 0 (Get-WacOwnedProcessRawCloseCount) 'arming a fault did not reset the count this case reads'

        $commandLine = ConvertTo-WacCommandLineArgument -Value $script:HostExe
        $workingDirectory = [System.IO.Path]::GetDirectoryName($script:HostExe)
        $launch = [WacOwnedProcess]::Start($script:HostExe, $commandLine, $workingDirectory, 2000)

        Assert-Equal 'NeverCreated' ([string]$launch.State) `
            ('the fault fired somewhere other than before CreateProcessW: {0}' -f [string]$launch.Failure)
        Assert-Equal 1 (Get-WacOwnedProcessRawCloseCount) `
            'the raw cleanup closed a read end a SafeFileHandle had already adopted, which is a double close on a handle number the OS may have reissued'
    }
    finally {
        [void](Set-WacOwnedProcessFault -Phase None)
        if ($launch -and $launch.ProcessId -gt 0) {
            Stop-Process -Id ([int]$launch.ProcessId) -Force -ErrorAction SilentlyContinue
        }
    }
}

Complete-TestRun
