#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-12: a failed profile restore may RAISE the cleanmgr step's outcome, never lower it.

.DESCRIPTION
    The finally block used to assign `$outcome = 'Incomplete'` whenever the profile could not be put
    back. That is an assignment, not a combination, and the shared ranking is

        SecurityRefusal (3) > Failed (2) > Incomplete (1) > SafeSkip / Succeeded (0)

    so a nonzero cleanmgr exit (Failed) followed by a restore failure came out as Incomplete - two
    problems reported as LESS serious than the first one alone. Run.ps1 maps Failed to exit 2 and
    Incomplete to exit 6, so the run's exit code changed because a second thing went wrong. This is
    a wrong verdict, never a false success: exit 6 is still non-clean.

    The fix routes it through Get-WacHigherOutcome, so the pair is monotonic.

    cleanmgr.exe is never executed: the step runs against Core's injected process invoker, and the
    restore runs against the injected bounded invoker, so both sides of the cross product are chosen
    by the fixture. Registry state lives in a per-process scratch key under HKCU, never the real
    HKLM VolumeCaches key.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_StepHarness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
foreach ($moduleLeaf in @('Core', 'FileSystem', 'StepContract', 'RecycleBin', 'DiskCleanup', 'Steps')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

$script:StepModule = Get-Module -Name 'WindowsAutoCleanup.DiskCleanup'

# Unique per process: both hosts run their suites concurrently against the same HKCU hive.
$script:ScratchRoot = 'HKCU:\Software\WacOutcome_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12)

function New-OutcomeVolumeCacheKey {
    <#
    .SYNOPSIS
        A disposable VolumeCaches-shaped key with one handler already configured, so the step has
        something to snapshot and therefore reaches its restore branch at all.
    #>
    param([Parameter(Mandatory = $true)][string]$KeyPath)

    # CreateSubKey rather than New-Item: the provider probes the parent by ENUMERATING it, and two
    # hosts creating scratch roots under HKCU:\Software concurrently make that enumeration
    # intermittently answer ERROR_NO_MORE_DATA.
    $relative = $KeyPath -replace '^(?i)HKCU:\\', ''
    foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
        $created = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(($relative + '\' + $handler))
        if ($null -eq $created) { throw ('the scratch key {0} could not be created' -f $handler) }
        $created.Close()
    }

    [void](New-ItemProperty -LiteralPath (Join-Path -Path $KeyPath -ChildPath 'Thumbnail Cache') `
        -Name 'StateFlags9999' -PropertyType DWord -Value 7 -Force -ErrorAction Stop)

    return $KeyPath
}

Test-Case 'a failed restore never lowers a recorded cleanmgr failure' {
    # THE regression. Before the fix this returned Incomplete: the assignment in the finally block
    # replaced Failed outright, so the run reported exit 6 where exit 2 was correct.
    $script:Captured = $null
    $key = New-OutcomeVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        # Set INSIDE the body: Invoke-WithStubbedTool clears both tables as it installs the seams,
        # so anything armed before the call is wiped before the step ever runs.
        Invoke-WithStubbedTool -StubToolPath -Body {
            $script:StubResult = @{ '/sagerun:9999' = @{ ExitCode = 3 } }
            $script:BoundedForce = @{ 'label:restore' = @{ Outcome = 'Failed'; Error = 'forced by the fixture' } }
            $script:Captured = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999
        }

        Assert-Equal 'Failed' $script:Captured.Outcome `
            ('a restore failure downgraded the recorded cleanmgr failure. detail: ' + $script:Captured.Detail)
        # Both independent facts survive in the diagnostics; neither erases the other.
        Assert-True ($script:Captured.Detail -match 'cleanmgr exited with 3') `
            ('the cleanmgr failure vanished from the detail: ' + $script:Captured.Detail)
        Assert-True ($script:Captured.Detail -match 'could not be restored') `
            ('the restore failure vanished from the detail: ' + $script:Captured.Detail)
    }
    finally {
        $script:StubResult = @{}
        $script:BoundedForce = @{}
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'the tool outcome and the restore outcome combine to the higher-ranked one, every way round' {
    # The cross product the ledger asks for. Succeeded and SafeSkip share rank 0, so a restore
    # failure legitimately RAISES a clean run to Incomplete; Failed outranks Incomplete and must
    # survive; a timed-out restore is Incomplete like a failed one.
    $cases = @(
        @{ Name = 'clean tool, clean restore'; Tool = @{ ExitCode = 0 }; Restore = ''; Expect = 'Succeeded' },
        @{ Name = 'clean tool, failed restore'; Tool = @{ ExitCode = 0 }; Restore = 'Failed'; Expect = 'Incomplete' },
        @{ Name = 'clean tool, timed-out restore'; Tool = @{ ExitCode = 0 }; Restore = 'Incomplete'; Expect = 'Incomplete' },
        @{ Name = 'failed tool, clean restore'; Tool = @{ ExitCode = 3 }; Restore = ''; Expect = 'Failed' },
        @{ Name = 'failed tool, failed restore'; Tool = @{ ExitCode = 3 }; Restore = 'Failed'; Expect = 'Failed' },
        @{ Name = 'failed tool, timed-out restore'; Tool = @{ ExitCode = 3 }; Restore = 'Incomplete'; Expect = 'Failed' },
        @{ Name = 'killed tool, clean restore'; Tool = @{ TimedOut = $true }; Restore = ''; Expect = 'Incomplete' },
        @{ Name = 'killed tool, failed restore'; Tool = @{ TimedOut = $true }; Restore = 'Failed'; Expect = 'Incomplete' }
    )

    foreach ($case in $cases) {
        $script:Captured = $null
        $key = New-OutcomeVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchRoot -ChildPath 'VolumeCaches')
        $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
        try {
            # Script scope, not a closure: GetNewClosure() would rebind $script: to the closure's own
            # module scope, and the captured result would never reach these assertions.
            $script:CaseTool = $case.Tool
            $script:CaseRestore = [string]$case.Restore
            Invoke-WithStubbedTool -StubToolPath -Body {
                $script:StubResult = @{ '/sagerun:9999' = $script:CaseTool }
                if ($script:CaseRestore) {
                    $script:BoundedForce = @{ 'label:restore' = @{ Outcome = $script:CaseRestore; Error = 'forced' } }
                }
                $script:Captured = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999
            }

            Assert-Equal $case.Expect $script:Captured.Outcome `
                ('{0}: wrong combined outcome. detail: {1}' -f $case.Name, $script:Captured.Detail)
        }
        finally {
            $script:StubResult = @{}
            $script:BoundedForce = @{}
            Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
            Remove-Item -LiteralPath $script:ScratchRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Test-Case 'the documented ranking itself is unchanged, in both directions' {
    # The fix depends on Get-WacHigherOutcome being monotonic and on the ranking staying put. If a
    # later edit reordered the table, the call site above would silently start downgrading again.
    Assert-Equal 'Failed' (Get-WacHigherOutcome -Current 'Failed' -Candidate 'Incomplete') 'Incomplete outranked Failed'
    Assert-Equal 'Failed' (Get-WacHigherOutcome -Current 'Incomplete' -Candidate 'Failed') 'Failed did not outrank Incomplete'
    Assert-Equal 'Incomplete' (Get-WacHigherOutcome -Current 'Succeeded' -Candidate 'Incomplete') 'Incomplete did not outrank Succeeded'
    Assert-Equal 'SecurityRefusal' (Get-WacHigherOutcome -Current 'Failed' -Candidate 'SecurityRefusal') 'SecurityRefusal did not outrank Failed'
    Assert-Equal 'SecurityRefusal' (Get-WacHigherOutcome -Current 'SecurityRefusal' -Candidate 'Incomplete') 'Incomplete lowered SecurityRefusal'
}

# ---------------------------------------------------------------------------------------------
# WAC-06R: the launch allowance is reclamped immediately before the launch
# ---------------------------------------------------------------------------------------------

Test-Case 'preparation that spends the remaining budget starts no tool at all' {
    # The cleanmgr watchdog was computed once, near the top of the step, and handed to the launch
    # unchanged. Between those two points the step snapshots the profile, writes it and reads it
    # back - three synchronous phases, each with its own bound - so the run budget that number was
    # drawn from can be smaller by then, or gone. The stale allowance let one step start a
    # whole-machine /sagerun after the run was already out of time.
    #
    # The clock is moved in the read-back because that is the last thing before the launch and a
    # test cannot aim a real wall clock at that instant. The launch decision itself is not stubbed:
    # Invoke-WacProcess is the recording seam, so "no tool was started" is an observation, not an
    # assertion about a mock's own arguments.
    $script:Captured = $null
    $key = New-OutcomeVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    $originalExact = Get-ModuleFunctionBody -Module $script:StepModule -Name 'Test-WacDiskCleanupProfileExact'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Test-WacDiskCleanupProfileExact' -Body {
            param($SageId, $Expected, $KeyPath)
            # The shadow only needs Expected; naming the other two keeps the real signature.
            $null = $SageId, $KeyPath
            Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddMilliseconds(-1))
            return [PSCustomObject]@{ Ok = $true; Reason = ''; Enabled = @($Expected); Missing = @() }
        }

        Invoke-WithStubbedTool -StubToolPath -Body {
            $script:Captured = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999
        }

        Assert-Equal 0 ($script:StubCall.Count) `
            ('cleanmgr was started after the run budget had already been spent on preparation. detail: ' + [string]$script:Captured.Detail)
        Assert-Equal 'Incomplete' ([string]$script:Captured.Outcome) `
            ('a step that could not start its tool did not report unfinished work. detail: ' + [string]$script:Captured.Detail)
        Assert-True ($script:Captured.Detail -match 'not started') `
            ('the reason the tool never ran is missing from the detail: ' + [string]$script:Captured.Detail)

        # The recovery reserve is explicit and survives expiry: the profile this step wrote is put
        # back even though the budget that stopped the step is gone.
        Assert-True (@($script:BoundedCall | Where-Object { $_.IgnoreRunBudget }).Count -ge 1) `
            'the mutated profile was left behind because the budget had expired'
    }
    finally {
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Test-WacDiskCleanupProfileExact' -Body $originalExact
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddHours(1))
        $script:StubResult = @{}
        $script:BoundedForce = @{}
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Complete-TestRun
