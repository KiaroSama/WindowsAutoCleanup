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

Complete-TestRun
