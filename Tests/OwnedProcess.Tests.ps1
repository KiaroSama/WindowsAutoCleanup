#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-05R: ownership established at creation, and the three facts it lets the runner keep apart.

.DESCRIPTION
    The defect was that a Toolhelp snapshot is a picture of NOW, not a history. In A -> B -> C, if B
    exits before the walk, C is not reachable from A's rows: only A is bound and killed, and the run
    still reported the tree proven stopped while C kept running. The same shape also let a root's
    exit code stand in for "everything this run started has finished".

    A job object answers it structurally. Every process created by a member is a member, so C is in
    the job whether or not B is still there, and ActiveProcesses is the answer with no enumeration,
    no pid and no race against a recycled parent id. CREATE_SUSPENDED is what closes the last window:
    the child is assigned before its first instruction, so it cannot have spawned anything outside.

    THE FIXTURE IS THE DEFECT. Every case here builds a real A -> B -> C where B has already exited,
    which is precisely the shape the old proof could not see. Every process is one this suite
    created: nothing is discovered, matched by name, or killed by pid.

    Cleanup is part of what is asserted. C is left running on purpose and must be dead once the run
    returns, because closing the job handle is the kill-on-close backstop firing.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

function ConvertTo-EncodedCommand {
    <#
    .SYNOPSIS
        Base64 UTF-16LE for -EncodedCommand.
    .DESCRIPTION
        Three nested payloads quoted by hand is how a fixture starts failing for its own reasons
        rather than the behaviour's. Encoding removes every quoting question from the nesting.
    #>
    param([Parameter(Mandatory = $true)][string]$Source)
    return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Source))
}

function New-OrphanMakerArgument {
    <#
    .SYNOPSIS
        Arguments for a root A that starts B, waits for B to EXIT, then exits 0 itself.
    .DESCRIPTION
        B starts the long-lived C and records C's process id before returning, so by the time A has
        waited for B the marker is always written - the case never races its own fixture. The result
        when A exits: A gone, B gone, C alive and reachable only through the job.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        # Seconds A stays alive AFTER B has exited. Zero is the orphan shape; a positive value is
        # the same shape held open so a deadline can cut it off.
        [int]$KeepRootAliveSeconds = 0
    )

    $c = ConvertTo-EncodedCommand -Source 'Start-Sleep -Seconds 8'
    $bSource = "`$c = Start-Process -FilePath '$script:HostExe' -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','$c' -NoNewWindow -PassThru; Set-Content -LiteralPath '$MarkerPath' -Value ([string]`$c.Id); exit 0"
    $b = ConvertTo-EncodedCommand -Source $bSource
    # Two traps, both hit while writing this. The hold goes BEFORE the exit, not after it: appending
    # to a source that already ends in "exit 0" changes nothing, which is how the first version timed
    # nothing and still looked plausible. And the delimiter is ${hold}, never a backtick - inside a
    # double-quoted string a backtick is the ESCAPE character, so "$hold`exit" is $hold followed by
    # `e, which is ESC on PowerShell 7 and a bare "e" on 5.1. The payload became unparseable and the
    # root exited 1.
    $hold = ''
    if ($KeepRootAliveSeconds -gt 0) { $hold = "Start-Sleep -Seconds $KeepRootAliveSeconds; " }
    $aSource = "`$b = Start-Process -FilePath '$script:HostExe' -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','$b' -NoNewWindow -PassThru; `$b.WaitForExit(); ${hold}exit 0"

    return @('-NoProfile', '-NonInteractive', '-Command', $aSource)
}

function New-DirectChildArgument {
    <#
    .SYNOPSIS
        Arguments for a root A that starts ONE long-lived child, records its id, then holds.
    .DESCRIPTION
        The shallow fixture. A -> C is enough to prove a deadline terminates more than the root, and
        it costs two process startups rather than three - which is what keeps the case from racing a
        loaded runner instead of testing the behaviour.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [int]$KeepRootAliveSeconds = 30
    )

    $c = ConvertTo-EncodedCommand -Source 'Start-Sleep -Seconds 90'
    $aSource = "`$c = Start-Process -FilePath '$script:HostExe' -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','$c' -NoNewWindow -PassThru; Set-Content -LiteralPath '$MarkerPath' -Value ([string]`$c.Id); Start-Sleep -Seconds $KeepRootAliveSeconds; exit 0"

    return @('-NoProfile', '-NonInteractive', '-Command', $aSource)
}

function Wait-ProcessGone {
    <#
    .SYNOPSIS
        Bounded wait for a process id to disappear. $true when it is gone.
    .DESCRIPTION
        Bounded polling against a deadline, never a blind sleep: the kernel reaps a job's victims
        asynchronously, so the answer is "within this budget", not "at this instant".
    #>
    param([Parameter(Mandatory = $true)][int]$ProcessId, [int]$BudgetMs = 4000)

    $deadline = [datetime]::UtcNow.AddMilliseconds($BudgetMs)
    while ([datetime]::UtcNow -lt $deadline) {
        if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue))
}

function Get-MarkedProcessId {
    param([Parameter(Mandatory = $true)][string]$MarkerPath)

    if (-not (Test-Path -LiteralPath $MarkerPath)) { return 0 }
    $text = (Get-Content -LiteralPath $MarkerPath -Raw).Trim()
    if ($text -match '^\d+$') { return [int]$text }
    return 0
}

Test-Case 'an ordinary tool is owned from creation and reports a complete, empty tree' {
    # The control for everything below. Without it a hard-wired 'Alive' would satisfy the regression
    # case and every real tool call in the project would start reporting an unproven stop.
    $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 20000 `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', "'owned-ok'; exit 4")

    Assert-True ([bool]$result.Started) 'the owned launch did not start'
    Assert-True ([bool]$result.Owned) 'the tool was not owned from creation on this machine'
    Assert-Equal 4 ([int]$result.ExitCode) 'the native launch lost the exit code'
    Assert-True ($result.StandardOutput -match 'owned-ok') 'the native pipes lost the output'
    Assert-Equal 'Complete' ([string]$result.OwnedTreeState) 'a finished tool left the job reporting members'
    Assert-True ([bool]$result.TerminationProven) 'a finished owned tree was not reported as stopped'
    Assert-True ([bool]$result.OutputComplete) 'a finished tool was reported as having incomplete output'
}

Test-Case 'a grandchild whose parent already exited keeps the tree unproven, and dies with the job' {
    # THE regression, and the exact shape a snapshot cannot answer: when the verdict is taken, B is
    # gone, so C has no path back to A. The old proof bound A alone, found nothing else, and called
    # the tree stopped. The job holds C regardless of B, so it cannot.
    $sandbox = New-TestSandbox -Prefix 'owned-orphan'
    $childId = 0
    try {
        # B and C inherit A's stdout pipe, so the reads cannot EOF while C lives and the run would
        # otherwise pay the full 5-second read budget. An expired deadline plus a tiny recovery
        # reserve clamps that budget without touching the tool's own timeout, which is passed
        # explicitly: past the deadline a drain draws from the reserve, so both knobs are needed.
        # It also makes the incomplete-output witness part of what this case exercises.
        Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddMilliseconds(-1))
        Reset-WacShutdownReserve -ReserveMs 250

        $marker = Join-Path -Path $sandbox -ChildPath 'grandchild.pid'
        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 25000 `
            -ArgumentList (New-OrphanMakerArgument -MarkerPath $marker) -Component 'Test'

        $childId = Get-MarkedProcessId -MarkerPath $marker
        Assert-True ($childId -gt 0) 'the fixture never recorded the grandchild, so nothing was proved'

        Assert-True ([bool]$result.Started) 'the root did not start'
        Assert-True (-not $result.TimedOut) 'the root did not exit on its own, so this is not the shape under test'
        Assert-Equal 0 ([int]$result.ExitCode) 'the root did not exit cleanly - its clean exit is the reassuring half'
        Assert-True ([bool]$result.Owned) 'the tool was not owned, so the job verdict below proves nothing'

        Assert-Equal 'Alive' ([string]$result.OwnedTreeState) `
            'a job still holding a live grandchild was reported as an empty tree'
        Assert-True (-not $result.TerminationProven) `
            'a clean root exit was reported as proof the whole tree had stopped while a grandchild ran'

        # The backstop, asserted rather than assumed: Invoke-WacProcess has returned, so the job
        # handle is closed, so KILL_ON_JOB_CLOSE has fired on everything still inside it.
        Assert-True (-not $result.OutputComplete) `
            'a pipe still held open by the grandchild was handed over as the whole output'
        Assert-True (Wait-ProcessGone -ProcessId $childId) `
            'the grandchild outlived the run - the kill-on-close backstop did not fire'
        $childId = 0
    }
    finally {
        if ($childId -gt 0) { Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue }
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddHours(1))
        Reset-WacShutdownReserve
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a deadline terminates the whole owned tree in one call, and says so' {
    # One TerminateJobObject, no enumeration, no pid, nothing unrelated reachable by it: membership
    # was decided at creation. The same A -> B -> C fixture, cut off while C is still running.
    $sandbox = New-TestSandbox -Prefix 'owned-kill'
    $childId = 0
    try {
        $marker = Join-Path -Path $sandbox -ChildPath 'grandchild.pid'
        # ONE level, not two. This case is about what a DEADLINE does - one TerminateJobObject over
        # the whole job - and the missing-intermediate property is proved by the case above. Waiting
        # for a three-deep chain to record its marker before the bound expires made the fixture race
        # the machine: 2500 ms lost it on a loaded runner, 6000 ms still lost it at 16 concurrent
        # suites. A starts the child directly and records it immediately, so the bound only has to
        # outlast two startups rather than three.
        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 6000 `
            -ArgumentList (New-DirectChildArgument -MarkerPath $marker -KeepRootAliveSeconds 30) `
            -Component 'Test'

        $childId = Get-MarkedProcessId -MarkerPath $marker
        Assert-True ($childId -gt 0) 'the fixture never recorded the grandchild, so nothing was proved'

        Assert-True ([bool]$result.TimedOut) 'the root was not held to its deadline'
        Assert-Equal $null $result.ExitCode 'a killed tool reported an exit code as though it had finished'
        Assert-Equal 'Complete' ([string]$result.OwnedTreeState) `
            'the job still held members after it was terminated'
        Assert-True ([bool]$result.TerminationProven) `
            'a job that terminated cleanly was not reported as a proven stop'
        Assert-True (Wait-ProcessGone -ProcessId $childId) `
            'the grandchild survived the job termination'
        $childId = 0
    }
    finally {
        if ($childId -gt 0) { Stop-Process -Id $childId -Force -ErrorAction SilentlyContinue }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a machine without job ownership still runs the tool, and never claims to own it' {
    # The conservative fallback. A job object that cannot be created must not stop maintenance, and
    # must not be reported as ownership either. The launcher seam models the unavailability; the
    # fallback path itself is the managed start that the rest of Process.Tests.ps1 covers.
    try {
        Set-WacOwnedProcessLauncher -Launcher { return $null }

        $result = Invoke-WacProcess -FilePath $script:HostExe -TimeoutMs 20000 `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', "'fallback-ok'; exit 5")

        Assert-True ([bool]$result.Started) 'the fallback did not run the tool at all'
        Assert-Equal 5 ([int]$result.ExitCode) 'the fallback lost the exit code'
        Assert-True ($result.StandardOutput -match 'fallback-ok') 'the fallback lost the output'
        Assert-True (-not $result.Owned) 'an unowned run claimed ownership'
        Assert-Equal 'Unknown' ([string]$result.OwnedTreeState) `
            'an unowned run reported a job verdict it cannot have'
    }
    finally {
        Set-WacOwnedProcessLauncher -Launcher $null
    }
}

Complete-TestRun
