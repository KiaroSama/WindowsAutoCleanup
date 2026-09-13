<#
.SYNOPSIS
    The three scenarios that prove an exit code inside a sandbox: EXIT5, EXIT3 and EXIT2.

.DESCRIPTION
    Dot-sourced by Invoke-ElevatedVerification.ps1. Every scenario here runs the real Run.ps1
    against a sandboxed %ProgramData% and leaves this machine's own state alone; the scenarios that
    deliberately change the machine live in _ElevatedVerification.MachineScenarios.ps1 and in
    _ElevatedVerification.MaintenanceScenario.ps1.

    "Leaves this machine's own state alone" used to be true only of FILES (ledger WAC-10R). The
    scratch copy replaced the allow-list builder but kept the real maintenance modules, so EXIT2 and
    the uncontended EXIT3 control executed the real online DISM, the real pnpclean handler and the
    real Delivery Optimization purge while being reported as sandbox scope. Every child launched
    from here now also carries _SandboxMaintenanceFixture.psm1, and each scenario PROVES from that
    fixture's witness which maintenance steps it reached and that every one of them was stopped.
#>

# ------------------------------------------------------------------------------------------------
# Scenario EXIT5 - the online system drive is not C:
# ------------------------------------------------------------------------------------------------

function Invoke-Exit5Scenario {
    <#
    .SYNOPSIS
        An elevated child whose %SystemDrive% is not C: must exit 5 and delete nothing.
    .DESCRIPTION
        Test-WacSystemDriveSupported compares Get-WacNormalizedPath of $env:SystemDrive against C:,
        and Run.ps1 runs that check AFTER the elevation gate and BEFORE the mutex, so the child has
        to be elevated for the branch to be reachable at all. SystemDrive is the one root that can
        be redirected without breaking the host: measured, both shipped hosts start normally with
        SystemDrive=Z: while neither survives a redirected SystemRoot.

        The bait assertion is what makes the gate falsifiable, and it means something only because
        the injected fixture really does name the bait directory: a child that failed to see the
        redirected SystemDrive, ran past the exit-5 gate and swept its targets WOULD delete it.
        Skipping every category, as this scenario used to, made the check unfalsifiable - no cleanup
        target covering the bait could ever be constructed, so the file survived whether or not the
        redirect took effect.

        What keeps a run that got past the gate confined is no longer a list of disabled category
        names. It is the fixture in the scratch copy: every target it can name is built from this
        sandbox, the whole set is proven contained before the child's deletion loop starts, and each
        entry is proven again immediately before it is used.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null

    try {
        $sandbox = New-VerificationSandbox -Prefix 'wac-exit5'
        $baitFile = Join-Path -Path (New-SandboxBait -Sandbox $sandbox) -ChildPath 'bait.txt'

        $commandLine = Get-RunChildCommandLine -ScriptPath (New-VerificationScratchTree -Sandbox $sandbox -InterceptMaintenance) `
            -MutexName (New-VerificationMutexName)
        $table = Get-SandboxEnvironment -Sandbox $sandbox -Extra @{ SystemDrive = 'Z:' }

        $child = Start-VerificationChild -CommandLine $commandLine -Environment $table
        $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
        $exitCode = $result.ExitCode

        if (-not $result.Exited) {
            [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
        }
        if ($result.ExitCode -ne 5) {
            [void]$problem.Add(('expected exit 5, got {0}. stderr: {1}' -f (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
        }

        $text = Get-SandboxLogText -Sandbox $sandbox
        [void](Add-LogEvidence -Evidence $evidence -Problem $problem -Text $text `
            -Needle '[CRITICAL] [Run] The online system drive is not C:')

        foreach ($forbidden in @('[Result] Target complete.', '[Summary]')) {
            if (@(Get-MatchingLine -Text $text -Needle $forbidden).Count -gt 0) {
                [void]$problem.Add(('the run reached "{0}" even though the system drive is unsupported' -f $forbidden))
            }
        }

        if (-not (Test-Path -LiteralPath $baitFile -PathType Leaf)) {
            [void]$problem.Add('the bait file inside the redirected allow-list directory was deleted')
        }
        else {
            [void]$evidence.Add(('bait intact: {0}' -f $baitFile))
        }

        # The exit-5 gate sits BEFORE the first maintenance step, so this child must have reached
        # none of them. It is the negative control for the other two scenarios' witness assertions:
        # a fixture that wrote its lines unconditionally would fail here.
        Add-MaintenanceEvidence -Evidence $evidence -Problem $problem -Sandbox $sandbox -Label 'the unsupported-drive run'
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $child
        if (-not (Remove-VerificationSandbox -Path $sandbox)) {
            [void]$problem.Add(('the sandbox could not be removed: {0}' -f $sandbox))
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'EXIT5' -ExpectedExitCode 5 `
        -Expected 'exit 5, a CRITICAL system-drive line, and nothing deleted' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}

# ------------------------------------------------------------------------------------------------
# Scenario EXIT3 - another run holds the machine-wide lock
# ------------------------------------------------------------------------------------------------

function Invoke-Exit3Scenario {
    <#
    .SYNOPSIS
        A contended elevated run exits 3; after release, an uncontended control can clean.
    .DESCRIPTION
        This harness deliberately owns a real, run-unique kernel mutex until the contender exits.
        A log line only proved a previous child HAD the lock; a fast cleanup could finish between
        observing that line and starting the contender. Holding the production mutex primitive
        removes that race without slowing the application or mocking its contention check.

        The second sandbox's bait check needs the same treatment as EXIT5's for the same reason: the
        injected fixture names the bait directory, so a second child which failed to exit 3 and swept
        its targets would delete it. With every category skipped the file survived either way and the
        "mutated nothing" evidence line asserted nothing about the mutex at all. Each run gets its
        own scratch copy, because each fixture is pinned to the sandbox of the child that loads it.
        After release, the control must exit 0 and delete its OWN bait: this proves both that the
        lock was released and that the bait would otherwise be deleted.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $firstSandbox = ''
    $secondSandbox = ''
    $firstChild = $null
    $secondChild = $null
    $heldMutex = $null

    try {
        $mutexName = New-VerificationMutexName
        $firstSandbox = New-VerificationSandbox -Prefix 'wac-exit3-first'
        $secondSandbox = New-VerificationSandbox -Prefix 'wac-exit3-second'
        $firstBait = Join-Path -Path (New-SandboxBait -Sandbox $firstSandbox) -ChildPath 'bait.txt'
        $secondBait = Join-Path -Path (New-SandboxBait -Sandbox $secondSandbox) -ChildPath 'bait.txt'

        # One command line, but a scratch tree each: the fixture in a child's copy is pinned to the
        # sandbox whose environment that child is given, and the two runs use different sandboxes.
        $firstCommandLine = Get-RunChildCommandLine -ScriptPath (New-VerificationScratchTree -Sandbox $firstSandbox -InterceptMaintenance) `
            -MutexName $mutexName
        $secondCommandLine = Get-RunChildCommandLine -ScriptPath (New-VerificationScratchTree -Sandbox $secondSandbox -InterceptMaintenance) `
            -MutexName $mutexName

        $heldMutex = Enter-WacSingleInstance -Name $mutexName
        if (-not $heldMutex) { throw 'The fixture could not acquire its unique kernel mutex.' }
        try {
            [void]$evidence.Add('the fixture acquired the real kernel mutex before starting the contender')
            $secondChild = Start-VerificationChild -CommandLine $secondCommandLine `
                -Environment (Get-SandboxEnvironment -Sandbox $secondSandbox)
            $secondResult = Wait-VerificationChild -Child $secondChild -TimeoutMs $TimeoutMs
            $exitCode = $secondResult.ExitCode

            if (-not $secondResult.Exited) {
                [void]$problem.Add('the second child did not finish inside its wall timeout and its tree was terminated')
            }
            if ($secondResult.ExitCode -ne 3) {
                [void]$problem.Add(('expected the second run to exit 3, got {0}. stderr: {1}' -f `
                    (Get-RunExitDetail -ExitCode $secondResult.ExitCode), $secondResult.ErrorText.Trim()))
            }

            $secondText = Get-SandboxLogText -Sandbox $secondSandbox
            [void](Add-LogEvidence -Evidence $evidence -Problem $problem -Text $secondText `
                -Needle 'already holds the machine-wide lock')

            foreach ($forbidden in @('[Result] Target complete.', '[Summary]')) {
                if (@(Get-MatchingLine -Text $secondText -Needle $forbidden).Count -gt 0) {
                    [void]$problem.Add(('the locked-out run reached "{0}" instead of exiting without mutating anything' -f $forbidden))
                }
            }

            if (-not (Test-Path -LiteralPath $secondBait -PathType Leaf)) {
                [void]$problem.Add('the locked-out run deleted the bait file, so it mutated state before exiting')
            }
            else {
                [void]$evidence.Add(('locked-out run mutated nothing: {0} intact' -f $secondBait))
            }

            # "Mutated nothing" has to cover the machine as well as the sandbox: the exit-3 branch
            # is ahead of every maintenance step, so the locked-out run must have reached none.
            Add-MaintenanceEvidence -Evidence $evidence -Problem $problem -Sandbox $secondSandbox -Label 'the locked-out run'
        }
        finally {
            Exit-WacSingleInstance -Mutex $heldMutex
            $heldMutex = $null
        }

        $firstChild = Start-VerificationChild -CommandLine $firstCommandLine `
            -Environment (Get-SandboxEnvironment -Sandbox $firstSandbox)
        $firstResult = Wait-VerificationChild -Child $firstChild -TimeoutMs $TimeoutMs
        if (-not $firstResult.Exited) {
            [void]$problem.Add('the first child did not finish inside its wall timeout and its tree was terminated')
        }
        if ($firstResult.ExitCode -ne 0) {
            [void]$problem.Add(('the uncontended control did not succeed after release: {0}' -f $firstResult.ExitCode))
        }
        else {
            [void]$evidence.Add('the uncontended control acquired the released lock and exited 0')
        }
        if (Test-Path -LiteralPath $firstBait -PathType Leaf) {
            [void]$problem.Add('the uncontended control left its bait, so the non-mutation check had no positive control')
        }
        else {
            [void]$evidence.Add('the uncontended control deleted its own bait')
        }

        # THE CONTROL IS THE ONE THAT USED TO SERVICE THIS MACHINE (ledger WAC-10R). It runs the
        # whole cleanup phase, so it must have reached every maintenance step and been stopped at
        # each - the opposite expectation from the locked-out run above, from the same witness.
        Add-MaintenanceEvidence -Evidence $evidence -Problem $problem -Sandbox $firstSandbox `
            -Label 'the uncontended control' -ExpectFullSequence
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $secondChild
        Stop-VerificationChild -Child $firstChild
        Exit-WacSingleInstance -Mutex $heldMutex
        foreach ($path in @($secondSandbox, $firstSandbox)) {
            if (-not (Remove-VerificationSandbox -Path $path)) {
                [void]$problem.Add(('the sandbox could not be removed: {0}' -f $path))
            }
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'EXIT3' -ExpectedExitCode 3 `
        -Expected 'the contended run exits 3 without mutation; after release, the control exits 0 and deletes its bait' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}

# ------------------------------------------------------------------------------------------------
# Scenario EXIT2 - the run completed with at least one real failure
# ------------------------------------------------------------------------------------------------

function Test-Exit2TargetEvidence {
    <#
    .SYNOPSIS
        Judges every '[Result] Target complete.' line a run produced against ONE immutable bait
        directory: all inside the sandbox, and the failure belongs to the bait alone.
    .DESCRIPTION
        PURE, and separate from the scenario, because the bug it closes was invisible while the two
        were one block (ledger WAC-10R). The scenario stored its bait path in $target and then
        REUSED $target as the loop variable that receives each line's own path, so by the time the
        bait assertion ran, $target held whichever target the child happened to report LAST. With a
        single result line the two values are the same string and the defect cannot be seen; with
        several - which is the normal case, since the fixture always names three - the assertion was
        checking a different directory than the one the locked subdirectory was planted in.

        So the bait path arrives as a parameter and is never assigned to. Each line's path is read
        into its OWN variable, compared with the bait by normalised equality rather than by
        substring (a sibling '...\LocalCopy2' contains '...\LocalCopy'), and the order the child
        reported the targets in cannot change the answer.

        The failure claim is two-sided. The bait line must carry failed=1, and no other line may
        carry a failed= field at all - Write-WacTreeResult omits the field entirely at zero, so
        "failed=0" is not a thing any clean line says, and asking whether the field is PRESENT is
        what proves the exit 2 came from the bait rather than from something else in the run.
    .OUTPUTS
        Evidence and Problem, both string arrays.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$BaitTarget
    )

    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'

    $normalizedSandbox = Get-WacNormalizedPath -Path $Sandbox
    $normalizedBait = Get-WacNormalizedPath -Path $BaitTarget
    if (-not $normalizedSandbox -or -not $normalizedBait) {
        [void]$problem.Add(('the sandbox {0} or the bait directory {1} does not normalise, so no result line can be judged' -f $Sandbox, $BaitTarget))
        return [PSCustomObject]@{ Evidence = @($evidence.ToArray()); Problem = @($problem.ToArray()) }
    }

    $resultLines = @(Get-MatchingLine -Text $Text -Needle '[Result] Target complete.')
    if ($resultLines.Count -lt 1) {
        [void]$problem.Add('the log shows no cleaned target at all, so the sweep never ran')
    }

    $baitLine = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $resultLines) {
        [void]$evidence.Add($line)

        # EVERY touched target must lie inside the sandbox: a [Result] line for a path outside it
        # would mean an allow-list entry on the real machine was cleaned for real. That is the
        # invariant; the COUNT is not - 'Defender cleanup files' has two entries and a guest where
        # both exist legitimately completes two targets, which is why this checks each path rather
        # than demanding one line.
        $linePath = Get-ResultLinePath -Line $line
        if ([string]::IsNullOrWhiteSpace($linePath)) {
            [void]$problem.Add(('a result line carries no readable path, so containment cannot be proven: {0}' -f $line))
            continue
        }

        $normalizedLine = Get-WacNormalizedPath -Path $linePath
        if (-not $normalizedLine) {
            [void]$problem.Add(('a result path could not be normalised, so containment cannot be proven: {0}' -f $line))
            continue
        }
        if (-not (Test-WacIsWithinRoot -ChildPath $normalizedLine -RootPath $normalizedSandbox)) {
            [void]$problem.Add(('a target outside the sandbox was cleaned for real: {0}' -f $line))
            continue
        }

        if ([string]::Equals($normalizedLine, $normalizedBait, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$baitLine.Add($line)
        }
        elseif (Test-KeyPresent -Line $line -Key 'failed') {
            [void]$problem.Add(('a target other than the bait reported a failure, so exit 2 is not attributable to the locked directory: {0}' -f $line))
        }
    }

    if ($baitLine.Count -ne 1) {
        [void]$problem.Add(('expected exactly one result line for the bait directory {0}, got {1}' -f $normalizedBait, $baitLine.Count))
        return [PSCustomObject]@{ Evidence = @($evidence.ToArray()); Problem = @($problem.ToArray()) }
    }

    if (-not (Test-KeyValue -Line $baitLine[0] -Pair 'failed=1')) {
        [void]$problem.Add(('the bait target did not report exactly failed=1, so the locked directory never reached the Failed bucket: {0}' -f $baitLine[0]))
    }
    else {
        [void]$evidence.Add(('the bait target {0} is the one that reported failed=1' -f $normalizedBait))
    }

    return [PSCustomObject]@{ Evidence = @($evidence.ToArray()); Problem = @($problem.ToArray()) }
}

function Invoke-Exit2Scenario {
    <#
    .SYNOPSIS
        A real deletion failure inside the sandbox must produce failed>0 and exit 2.
    .DESCRIPTION
        WHY THIS PARTICULAR FAILURE IS COUNTED AS Failed AND NOT AS ONE OF THE SKIP COUNTERS.

        The sandbox allow-list directory holds a subdirectory that this harness opens with
        CreateFileW(dwShareMode = 0) and keeps open for the whole child run. Enumerating that
        subdirectory then fails with ERROR_SHARING_VIOLATION, which .NET raises as IOException, and
        Get-WacIoFailureKind classifies an IOException as 'Busy'. Invoke-WacTreeSweep
        (FileSystem.psm1) routes its enumeration failures like this:

            Denied   -> SkippedDenied
            NotFound -> SkippedVanished
            anything else, which includes Busy -> Failed++

        That "anything else" is the only branch in the traversal that increments Failed, and it is
        why a merely locked or protected FILE cannot be used here: Remove-WacLeaf maps a Busy file
        to PendingDeletes or SkippedLocked, a Denied one to SkippedDenied, and a Busy DIRECTORY to
        SkippedNotEmpty. None of those reach the Failed bucket, so none of them can produce exit 2.

        The guards that run BEFORE the enumeration all still pass, which is what makes the outcome
        deterministic rather than a fail-closed skip: Test-WacIsReparsePoint reads attributes through
        GetFileAttributesEx and opens no handle, and Test-WacPathResolvesToItself opens the directory
        for FILE_READ_ATTRIBUTES, which is exempt from the share-mode check. Only the FILE_READ_DATA
        access that a directory listing needs collides with the lock. Measured on both shipped hosts:
        Remove-WacTree returns Failed=1, FilesDeleted=1, SkippedNotEmpty=1.

        Alternatives considered and rejected: a path over MAX_PATH reaches the same Failed branch,
        but only under Windows PowerShell 5.1 - PowerShell 7 deletes it successfully - and a DISM or
        pnpclean non-zero exit also sets a step's Failed flag, but neither can be forced
        deterministically and both would mutate the real machine instead of the sandbox.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null
    $handle = $null

    try {
        $sandbox = New-VerificationSandbox -Prefix 'wac-exit2'

        # IMMUTABLE for the rest of the scenario. It is read back after the child has run, so
        # nothing below may assign to it - which is exactly what the old spelling did.
        $baitTarget = New-SandboxBait -Sandbox $sandbox

        # The fixture's other two directories, so the child completes SEVERAL targets and the bait
        # is not simply the last line in the log by default.
        [void](New-SandboxSiblingTarget -Sandbox $sandbox)

        # bait.txt proves the sweep really ran; the locked subdirectory produces the failure.
        $deletable = Join-Path -Path $baitTarget -ChildPath 'bait.txt'
        $lockedDirectory = Join-Path -Path $baitTarget -ChildPath 'locked'
        $survivor = Join-Path -Path $lockedDirectory -ChildPath 'inside.txt'
        [void][System.IO.Directory]::CreateDirectory($lockedDirectory)
        [System.IO.File]::WriteAllText($survivor, 'inside', $script:Utf8NoBom)

        $handle = [WacVerificationLock]::Open($lockedDirectory)

        $commandLine = Get-RunChildCommandLine -ScriptPath (New-VerificationScratchTree -Sandbox $sandbox -InterceptMaintenance) `
            -MutexName (New-VerificationMutexName)
        $child = Start-VerificationChild -CommandLine $commandLine `
            -Environment (Get-SandboxEnvironment -Sandbox $sandbox)
        $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
        $exitCode = $result.ExitCode

        if (-not $result.Exited) {
            [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
        }
        if ($result.ExitCode -ne 2) {
            [void]$problem.Add(('expected exit 2, got {0}. stderr: {1}' -f (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
        }

        $text = Get-SandboxLogText -Sandbox $sandbox

        # Containment and attribution, judged against the IMMUTABLE bait path rather than against
        # whatever the loop last parsed. Both halves are in one pure function so the ordering they
        # depend on can be exercised without an elevated child.
        $targetVerdict = Test-Exit2TargetEvidence -Text $text -Sandbox $sandbox -BaitTarget $baitTarget
        foreach ($line in @($targetVerdict.Evidence)) { [void]$evidence.Add($line) }
        foreach ($line in @($targetVerdict.Problem)) { [void]$problem.Add($line) }

        # The totals line disambiguates: exactly failed=1 proves the exit 2 came from this
        # deletion and not from an unrelated DISM or pnpclean failure on the operator's machine.
        # Test-KeyValue rather than a substring test: IndexOf('failed=1') is also satisfied by
        # failed=10, failed=11 and failed=100, so it only ruled out totals of 2..9.
        $totalLines = @(Get-MatchingLine -Text $text -Needle '[Summary] Cleanup totals.')
        if ($totalLines.Count -eq 0) {
            [void]$problem.Add('the run never reached the summary totals')
        }
        else {
            [void]$evidence.Add($totalLines[0])
            if (-not (Test-KeyValue -Line $totalLines[0] -Pair 'failed=1')) {
                [void]$problem.Add('the summary totals did not report exactly failed=1')
            }
        }

        # The footer records the run's OUTCOME by name now, not a sentence: status=Failed is
        # what maps to exit 2, and its absence means the 2 came from somewhere else.
        [void](Add-LogEvidence -Evidence $evidence -Problem $problem -Text $text -Needle 'status=Failed')

        if (Test-Path -LiteralPath $deletable -PathType Leaf) {
            [void]$problem.Add('the deletable bait file survived, so the sweep never really ran')
        }
        if (-not (Test-Path -LiteralPath $survivor -PathType Leaf)) {
            [void]$problem.Add('the file inside the locked directory was deleted, so the lock did not hold')
        }

        # THIS SCENARIO IS THE ONE THAT USED TO SERVICE THIS MACHINE (ledger WAC-10R). It runs the
        # entire cleanup phase, so every maintenance step must appear in the witness as reached and
        # intercepted, and no tool may have been launched - while the file failure above still
        # drives the exit 2.
        Add-MaintenanceEvidence -Evidence $evidence -Problem $problem -Sandbox $sandbox `
            -Label 'the failing run' -ExpectFullSequence
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $child
        if ($handle) { try { $handle.Dispose() } catch { $null = $_ } }
        if (-not (Remove-VerificationSandbox -Path $sandbox)) {
            [void]$problem.Add(('the sandbox could not be removed: {0}' -f $sandbox))
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'EXIT2' -ExpectedExitCode 2 `
        -Expected 'a real sandbox deletion failure produces failed=1 and exit 2' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}
