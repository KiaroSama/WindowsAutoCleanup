<#
.SYNOPSIS
    The three scenarios that prove an exit code inside a sandbox: EXIT5, EXIT3 and EXIT2.

.DESCRIPTION
    Dot-sourced by Invoke-ElevatedVerification.ps1. Every scenario here runs the real Run.ps1
    against a sandboxed %ProgramData% and leaves this machine's own state alone; the scenarios that
    deliberately change the machine live in _ElevatedVerification.MachineScenarios.ps1.
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

        'Defender cleanup files' is the ONE category deliberately left enabled, and that is what
        makes the bait assertion mean anything. Every entry of that category is built purely from
        %ProgramData% (Targets.psm1), which this harness has already redirected into the sandbox, so
        keeping it on cannot reach the operator's machine - but a child that failed to see the
        redirected SystemDrive, ran past the exit-5 gate and swept its targets WOULD delete the
        bait. Skipping every category, as this scenario used to, made the check unfalsifiable: no
        cleanup target covering the bait directory could ever be constructed, so the file survived
        whether or not the redirect took effect. Every other category stays disabled, which is what
        keeps a run that got past the gate confined to the sandbox.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null

    try {
        $skip = @(Get-NonSandboxCategory -Keep 'Defender cleanup files')
        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        else {
            $sandbox = New-VerificationSandbox -Prefix 'wac-exit5'
            $baitFile = Join-Path -Path (New-SandboxBait -Sandbox $sandbox) -ChildPath 'bait.txt'

            $commandLine = Get-RunChildCommandLine -MutexName (New-VerificationMutexName) -SkipCategory $skip
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
        }
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

        The second sandbox's bait check needs the same treatment as EXIT5's for the same reason:
        'Defender cleanup files' stays ENABLED so that a second child which failed to exit 3 and
        swept its targets would delete it. With every category skipped the file survived either way
        and the "mutated nothing" evidence line asserted nothing about the mutex at all. Both
        runs share one command line. After release, the control must exit 0 and delete its OWN bait:
        this proves both that the lock was released and that the bait would otherwise be deleted.
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
        $skip = @(Get-NonSandboxCategory -Keep 'Defender cleanup files')
        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        else {
            $mutexName = New-VerificationMutexName
            $firstSandbox = New-VerificationSandbox -Prefix 'wac-exit3-first'
            $secondSandbox = New-VerificationSandbox -Prefix 'wac-exit3-second'
            $firstBait = Join-Path -Path (New-SandboxBait -Sandbox $firstSandbox) -ChildPath 'bait.txt'
            $secondBait = Join-Path -Path (New-SandboxBait -Sandbox $secondSandbox) -ChildPath 'bait.txt'

            $commandLine = Get-RunChildCommandLine -MutexName $mutexName -SkipCategory $skip

            $heldMutex = Enter-WacSingleInstance -Name $mutexName
            if (-not $heldMutex) { throw 'The fixture could not acquire its unique kernel mutex.' }
            try {
                [void]$evidence.Add('the fixture acquired the real kernel mutex before starting the contender')
                $secondChild = Start-VerificationChild -CommandLine $commandLine `
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
            }
            finally {
                Exit-WacSingleInstance -Mutex $heldMutex
                $heldMutex = $null
            }

            $firstChild = Start-VerificationChild -CommandLine $commandLine `
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
        }
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
        $skip = @(Get-NonSandboxCategory -Keep 'Defender cleanup files')
        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        else {
            $sandbox = New-VerificationSandbox -Prefix 'wac-exit2'
            $target = New-SandboxBait -Sandbox $sandbox

            # bait.txt proves the sweep really ran; the locked subdirectory produces the failure.
            $deletable = Join-Path -Path $target -ChildPath 'bait.txt'
            $lockedDirectory = Join-Path -Path $target -ChildPath 'locked'
            $survivor = Join-Path -Path $lockedDirectory -ChildPath 'inside.txt'
            [void][System.IO.Directory]::CreateDirectory($lockedDirectory)
            [System.IO.File]::WriteAllText($survivor, 'inside', $script:Utf8NoBom)

            $handle = [WacVerificationLock]::Open($lockedDirectory)

            $commandLine = Get-RunChildCommandLine -MutexName (New-VerificationMutexName) -SkipCategory $skip
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

            # EVERY touched target must lie inside the sandbox: a [Result] line for a path outside it
            # would mean an allow-list entry on the real machine was cleaned for real. That is the
            # invariant; the count is not. This used to demand exactly one line, which is an
            # assumption about the MACHINE rather than about containment - 'Defender cleanup files'
            # has two entries (LocalCopy and Support, Targets.psm1), both built from %ProgramData%
            # and therefore both redirected into the sandbox, so a guest where the second one exists
            # legitimately completes two targets. Windows Sandbox happened to have only the first,
            # and a Hyper-V guest failed the scenario on that difference alone while containment was
            # intact. Checking every path is strictly stronger than counting lines and carries no
            # environment assumption.
            $resultLines = @(Get-MatchingLine -Text $text -Needle '[Result] Target complete.')
            if ($resultLines.Count -lt 1) {
                [void]$problem.Add('the log shows no cleaned target at all, so the sweep never ran')
            }
            foreach ($line in $resultLines) {
                [void]$evidence.Add($line)
                # A SUBSTRING test was wrong in both directions. It accepted a sibling - the sandbox
                # `...\wac-exit2_ab12` is a substring of `...\wac-exit2_ab12-other`, so a target in
                # a different directory whose name merely starts with the sandbox's passed - and it
                # matched the sandbox path wherever it appeared in the line, including inside an
                # unrelated field. The path is taken from the line's own `path=` field and compared
                # with the shipped containment rule, which is prefix-safe at the separator.
                $target = Get-ResultLinePath -Line $line
                if ([string]::IsNullOrWhiteSpace($target)) {
                    [void]$problem.Add(('a result line carries no readable path, so containment cannot be proven: {0}' -f $line))
                    continue
                }
                $normalizedTarget = Get-WacNormalizedPath -Path $target
                $normalizedSandbox = Get-WacNormalizedPath -Path $sandbox
                if (-not $normalizedTarget -or -not $normalizedSandbox) {
                    [void]$problem.Add(('a result path could not be normalised, so containment cannot be proven: {0}' -f $line))
                    continue
                }
                if (-not (Test-WacIsWithinRoot -ChildPath $normalizedTarget -RootPath $normalizedSandbox)) {
                    [void]$problem.Add(('a target outside the sandbox was cleaned for real: {0}' -f $line))
                }
            }

            # The bait target specifically: it is the one the locked subdirectory was planted in, so
            # it is the one that proves the failure reached the Failed bucket rather than a skip.
            $baitLines = @($resultLines | Where-Object { $_.IndexOf($target, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 })
            if ($baitLines.Count -ne 1) {
                [void]$problem.Add(('expected exactly one result line for the sandbox bait directory {0}, got {1}' -f $target, $baitLines.Count))
            }
            elseif (-not (Test-KeyValue -Line $baitLines[0] -Pair 'failed=1')) {
                [void]$problem.Add('the target result did not report exactly failed=1, so the locked directory never reached the Failed bucket')
            }

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
        }
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
