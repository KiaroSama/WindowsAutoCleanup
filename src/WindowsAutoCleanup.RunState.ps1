<#
.SYNOPSIS
    Everything Initialize-WacRun sets up for one run: the machine-wide state roots, the durable
    audit log, and the wall-clock budget every later timeout is clamped to.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1; see that file for why the parts are dot-sourced
    rather than imported. The log and the deadline live together because one function opens both -
    Initialize-WacRun writes every variable below - and state two responsibilities both write is
    not two responsibilities.
#>

$script:LogWriter           = $null
$script:LogPath             = $null
$script:LogLevel            = 'INFO'
$script:ExecutionId         = $null
$script:DeadlineUtc         = $null
$script:LevelRank           = @{ DEBUG = 0; INFO = 1; WARNING = 2; ERROR = 3; CRITICAL = 4 }

# Audit health. A run whose durable log could not be created, or which lost a line mid-run, is not
# entitled to report success: the shared result contract calls that Incomplete (exit 6). These stay
# sticky for the life of the process on purpose - a later successful write does not un-lose a line.
$script:LogDegraded         = $false
$script:LogOpened           = $false
$script:LogFailedWrites     = 0
$script:LogFallbackKind     = 'None'
$script:LogFailReason       = $null
$script:LogFallbackWriter   = $null
$script:StateTrust          = $null

# ---------------------------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------------------------

function New-WacLogFile {
    <#
    .SYNOPSIS
        Creates a new log file inside a directory that has been proved through its own handle,
        trying each candidate root in order. Returns the opened StreamWriter, or $null.
    .DESCRIPTION
        Both halves of this used to be a pathname round trip, and both were wrong.

        The DIRECTORY was reached with Test-Path followed by New-Item -Force. New-Item -Force does
        not create-or-fail, it creates-or-ADOPTS: a directory that appeared between the test and the
        create was taken over silently, and the object actually written to was never verified.
        Since Initialize-WacRun's preflight can only verify the nearest EXISTING ancestor when the
        candidate root does not exist yet, and %ProgramData% lets a local standard user create names
        by default, that user could introduce the predictable candidate directory in the window and
        the SYSTEM audit log would be written into a directory they own. Open-WacTrustedDirectory
        replaces it: collision-failing creation anchored to a proved parent handle, then the owner,
        DACL, reparse state, volume and resolved identity of the object actually opened.

        The FILE was created by pathname with FileMode::CreateNew. CreateNew was already right about
        collisions - New-Item -Force truncated, so two runs starting in the same second shared one
        log and the first one's content was lost - but a pathname create is still a second, separate
        resolution of the directory's name. It is now created RELATIVE to the directory handle, so
        the file lands inside the object that was verified or it is not created at all.

        The pin lives exactly as long as the window it closes: the handle is opened before the
        verification and released once the log file exists. Holding it for the whole run would buy
        nothing the open log-file handle does not already give, and would leave a raw handle for
        every caller to remember to release.

        Root names WHICH candidate the file landed in. The caller has already reached one trust
        verdict per candidate root and has to attach the verdict for the one actually used;
        re-deriving that from the path would be a second answer to a question already answered.
    .PARAMETER RequireMachineTrust
        Demand an administrative owner and DACL, and a local fixed volume, for the directory the
        log is created in. Pass it only when the run makes a machine-trust claim: an unelevated run
        logs inside the invoking user's own profile, which the user owns by construction.
    .PARAMETER Refusal
        Optional. Every candidate that was skipped is appended here as a Path/Reason pair. Nothing
        can be logged yet at this point in a run, so the caller has to carry the reasons to whatever
        sink it ends up with - and, when the run made a machine-trust claim, into the verdict its
        exit code is derived from.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$BaseName,
        [Parameter(Mandatory = $true)][string[]]$CandidateRoot,
        [switch]$RequireMachineTrust,
        [AllowNull()][System.Collections.Generic.List[object]]$Refusal
    )

    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd_HH-mm-ss')

    foreach ($root in $CandidateRoot) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }

        # A candidate that THREW and a candidate that was refused mean the same thing here - this
        # one cannot be used - and the one thing neither may do is stop the remaining candidates
        # being tried. The predecessor had exactly this shape (catch { continue }) around New-Item.
        $directory = $null
        try {
            $directory = Open-WacTrustedDirectory -Path $root -RequireMachineTrust:$RequireMachineTrust
        }
        catch {
            $directory = [PSCustomObject]@{
                Path = $root; IsTrusted = $false; Handle = [IntPtr]::Zero
                Reason = ('The directory could not be prepared: {0}' -f $_.Exception.Message)
            }
        }

        if (-not $directory.IsTrusted) {
            if ($null -ne $Refusal) {
                [void]$Refusal.Add([PSCustomObject]@{ Path = $root; Reason = [string]$directory.Reason })
            }
            continue
        }

        try {
            for ($attempt = 0; $attempt -lt 50; $attempt++) {
                $suffix = if ($attempt -eq 0) { '' } else { '_{0:00}' -f $attempt }
                $name = '{0}_{1}_UTC{2}.log' -f $BaseName, $stamp, $suffix

                $file = New-WacBoundFile -DirectoryHandle $directory.Handle -Name $name
                if ($file.Kind -eq 'Collision') { continue }
                if ($file.Kind -ne 'Created') {
                    # An EMPTY collection is falsy in PowerShell, so the test has to be explicit:
                    # 'if ($Refusal)' silently discarded every reason until the first one was added.
                    if ($null -ne $Refusal) {
                        [void]$Refusal.Add([PSCustomObject]@{
                                Path = $root
                                Reason = ('The log file could not be created (NTSTATUS 0x{0:X8}).' -f $file.NtStatus)
                            })
                    }
                    break
                }

                $writer = New-Object System.IO.StreamWriter($file.Stream, (New-Object System.Text.UTF8Encoding($false)))
                $writer.AutoFlush = $true
                return [PSCustomObject]@{
                    Path = (Join-Path -Path $directory.Path -ChildPath $name)
                    Writer = $writer
                    Root = $root
                }
            }
        }
        catch {
            if ($null -ne $Refusal) {
                [void]$Refusal.Add([PSCustomObject]@{
                        Path = $root
                        Reason = ('The log file could not be opened: {0}' -f $_.Exception.Message)
                    })
            }
        }
        finally {
            Close-WacTrustedDirectory -Handle $directory.Handle
        }
    }

    return $null
}

function Set-WacLogFallbackWriter {
    <#
    .SYNOPSIS
        Replaces the degraded-mode log sink. This is the seam that makes the fallback PROVABLE.
    .DESCRIPTION
        The scriptblock receives one already-formatted line. Pass $null to restore the real chain
        (Event Log, then console). A test injects a collector here so it can assert the line really
        reached a sink, instead of asserting that Write-WacLog did not throw - which is exactly the
        non-assertion the old swallowing catch turned every log failure into.
    #>
    param([scriptblock]$Writer)
    $script:LogFallbackWriter = $Writer
}

function Set-WacLogWriter {
    <#
    .SYNOPSIS
        Replaces the object Write-WacLog writes through. The seam that makes a mid-run write FAILURE
        reproducible, in the same spirit as Set-WacProcessInvoker.
    .DESCRIPTION
        A write to an open handle on a healthy local disk essentially cannot be made to fail on
        demand: disk-full and device errors are not reproducible in a test, and the alternatives
        (a VHD, a quota) cost far more than the path being proved. Anything exposing WriteLine is
        accepted; pass $null to detach. Close-WacLog already tolerates an object without Flush or
        Dispose, because it wraps both.

        The outgoing writer is CLOSED, not merely dropped. A test that swaps a real log for a
        throwing stub would otherwise abandon an open FileStream on its own sandbox, which then
        cannot be deleted - Remove-TestSandbox fails silently and the directory survives the run.
        Measured before this: one leaked directory per host, per swapping case. No shipped code
        calls this function, so closing here changes nothing outside the tests it exists for.
    #>
    param([object]$Writer)
    Close-WacLog
    $script:LogWriter = $Writer
}

function Write-WacFallbackLine {
    <#
    .SYNOPSIS
        Writes one line to the best sink that ACCEPTS it, and reports which one did.
    .DESCRIPTION
        "Verified" here means the write itself did not throw - not that a probe succeeded earlier.
        A pre-flight probe would prove the sink worked once and leave the real line unaccounted for.

        Event Log before console, because the production caller is a SYSTEM scheduled task with no
        console at all: Write-Host there goes nowhere and would be a fallback in name only.
        The source is the pre-registered 'Application' source rather than a WindowsAutoCleanup one.
        Registering a source needs an administrator, and EventLog.SourceExists cannot be used to
        find out - measured on BOTH hosts, unelevated, it throws because it tries to search the
        Security log ("The source ... was not found ... Inaccessible logs: Security"). Writing to
        the pre-registered source works at either privilege level and needs no probe.

        Console only when there is one: a task registered "run whether user is logged on or not"
        reports UserInteractive false, and that is the case the Event Log branch exists for.
    .OUTPUTS
        [string] the sink that took the line: Injected, EventLog, Console or None.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line)

    if ($script:LogFallbackWriter) {
        try {
            & $script:LogFallbackWriter $Line
            return 'Injected'
        }
        catch {
            $null = $_
        }
    }

    try {
        [System.Diagnostics.EventLog]::WriteEntry(
            'Application', $Line, [System.Diagnostics.EventLogEntryType]::Warning, 9001)
        return 'EventLog'
    }
    catch {
        $null = $_
    }

    if ([Environment]::UserInteractive) {
        try {
            Write-Host $Line
            return 'Console'
        }
        catch {
            $null = $_
        }
    }

    return 'None'
}

function Set-WacLogDegraded {
    <#
    .SYNOPSIS
        Records that durable audit output was required and could not be produced.
    #>
    param([Parameter(Mandatory = $true)][string]$Reason)

    $script:LogDegraded = $true
    if (-not $script:LogFailReason) { $script:LogFailReason = $Reason }
}

function Get-WacLogHealth {
    <#
    .SYNOPSIS
        Whether this run's audit trail is durable. Feeds the run's Incomplete verdict (exit 6).
    .DESCRIPTION
        IsDurable is false when the log file could not be created, when a write failed mid-run, or
        when a bootstrap log that WAS supplied could not be folded in. Every one of those loses
        audit output that the run was asked to produce, and none of them may read as success.

        It reads a flag rather than the live writer, so Close-WacLog does not retroactively turn a
        healthy run into an incomplete one. A caller computing its exit code after closing the log
        is the normal order, not a mistake.
    #>
    return [PSCustomObject]@{
        Path         = $script:LogPath
        IsDurable    = ($script:LogOpened -and (-not $script:LogDegraded))
        Degraded     = $script:LogDegraded
        FallbackKind = $script:LogFallbackKind
        FailedWrites = $script:LogFailedWrites
        Reason       = $script:LogFailReason
    }
}

function Get-WacStateTrust {
    <#
    .SYNOPSIS
        The trust verdict for the directory this run's audit log was opened in, or $null.
    .DESCRIPTION
        $null means NOT EVALUATED, which is the correct answer for an unelevated run: that log lives
        in the invoking user's own profile, the user owns it by construction, and no SYSTEM audit
        claim rests on it. It is equally the answer when the caller named its own -CandidateRoot,
        because then the location is the caller's choice and not a claim this module made. Only an
        elevated run using the roots this module chose makes a machine-trust claim to refuse on.

        A non-$null verdict with IsTrusted false can only be seen through Initialize-WacRun
        returning $false: a trusted root is the precondition for opening the log, not a fact
        discovered afterwards. It has TWO sources, and they are deliberately indistinguishable
        here - the pathname preflight refusing the ancestor chain, and the handle check refusing
        the directory actually created or opened. The caller's question is only "was this run's
        state directory refused on security grounds", never which of the two guards said so.
    #>
    return $script:StateTrust
}

function Copy-WacBootstrapLog {
    <#
    .SYNOPSIS
        Folds a pre-import bootstrap log into the run log, so an import failure is not orphaned.
    .DESCRIPTION
        Nothing inside this module can log before the module is imported, so the entry point owns
        the few lines that capture a parse or import failure. This is the other half: once the real
        log exists, the bootstrap content is copied into it and the run has ONE audit artifact.

        A supplied bootstrap path that cannot be read is a LOST audit log, so it degrades the run
        rather than being ignored.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $info = New-Object System.IO.FileInfo($Path)
        if (-not $info.Exists) {
            Write-WacLog -Level DEBUG -Component 'Log' -Message 'No bootstrap log was produced.' -Data @{ path = $Path }
            return $true
        }

        if ($info.Length -gt 262144) {
            Set-WacLogDegraded -Reason ('The bootstrap log at {0} is too large to fold in ({1} bytes).' -f $Path, $info.Length)
            Write-WacLog -Level WARNING -Component 'Log' -Message 'Bootstrap log too large to adopt; it is left in place.' -Data @{ path = $Path; bytes = $info.Length }
            return $false
        }

        # Folded in at WARNING, not INFO: a bootstrap log exists because something happened before
        # this module could log it, and a run started with -LogLevel WARNING would otherwise drop the
        # very import failure the bootstrap log was written to preserve.
        $lines = @([System.IO.File]::ReadAllLines($Path))
        Write-WacLog -Level WARNING -Component 'Log' -Message 'Adopting the pre-import bootstrap log.' -Data @{ path = $Path; lines = $lines.Count }
        foreach ($line in $lines) {
            Write-WacLog -Level WARNING -Component 'Bootstrap' -Message ([string]$line)
        }
        return $true
    }
    catch {
        Set-WacLogDegraded -Reason ('The bootstrap log at {0} could not be read: {1}' -f $Path, $_.Exception.Message)
        Write-WacLog -Level ERROR -Component 'Log' -Message 'The bootstrap log could not be adopted.' -Data @{ path = $Path; error = $_.Exception.Message }
        return $false
    }
}

function Get-WacStateRootVerdict {
    <#
    .SYNOPSIS
        The trust verdict for one candidate state root, with an unanswerable question reported as a
        refusal instead of as an exception.
    .DESCRIPTION
        Not exported, and deliberately its own function: FALSE and UNKNOWN have to be
        indistinguishable to the caller. A check that came back untrusted, a check that returned
        nothing at all, and a check that threw all mean the same thing here - the trust question was
        not answered yes - and the one thing none of them may do is let the run touch the path
        anyway. Returning a synthesised IsTrusted=$false verdict rather than $null also keeps the
        answer usable by everything downstream: Get-WacRunLevelOutcome and
        Get-OperationSafetyVerdict both read .IsTrusted, and $null already means NOT EVALUATED.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $reason = 'The trust check produced no verdict at all.'
    try {
        $verdict = Test-WacStatePathIsTrusted -Path $Path
        # Reading .IsTrusted is the presence test: strict mode turns a missing property into a
        # terminating error, which the catch below turns into a refusal rather than into a crash.
        if ($null -ne $verdict -and $null -ne $verdict.IsTrusted) { return $verdict }
    }
    catch {
        $reason = ('The trust question could not be answered: {0}' -f $_.Exception.Message)
    }

    return [PSCustomObject]@{
        Path = $Path; IsTrusted = $false; Reason = $reason
        Checked = @(); Failures = @(); Writers = @()
    }
}

function Initialize-WacRun {
    <#
    .SYNOPSIS
        Verifies that a machine-trusted state directory exists, and only then opens the run log,
        arms the overall deadline and adopts any bootstrap log.
    .DESCRIPTION
        Returns $true only when a log file was really created. The old code assigned $LogPath even
        after every fallback failed, so later writes silently went nowhere while the run reported
        success.

        A failure here no longer goes quiet either: the reason is written to the verified fallback
        sink and Get-WacLogHealth reports IsDurable false, which the caller must map to Incomplete.

        The trust check lives here rather than at the call sites because this is the one function
        every entry point already calls; a guard a caller has to remember is a guard one caller will
        forget. It runs BEFORE the log is created, and a root it refuses is never touched at all.
        The caller still owns the exit code; what this function owns is that no directory, file,
        write, append, copy or delete reaches a path whose trust it is about to deny.
    .PARAMETER StartUtc
        The instant the budget is measured from. Defaults to now, which is right for a caller whose
        work begins here and wrong for one that had to load a module tree first.
    .PARAMETER ShutdownMarginSeconds
        Held back from the budget so the caller still has time to write its own verdict.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BaseName,
        [string[]]$CandidateRoot,
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
        [int]$BudgetMinutes = 210,
        [string]$BootstrapLogPath,
        [Nullable[datetime]]$StartUtc,
        [int]$ShutdownMarginSeconds = 0
    )

    # Whether the MODULE chose the roots, which is also whether this run makes a machine-trust
    # claim worth verifying. A caller that named its own -CandidateRoot has taken that location on
    # itself; no shipped entry point does, and RunSurface.Tests pins that none of them starts.
    $moduleChoseRoot = $false

    if (-not $CandidateRoot -or $CandidateRoot.Count -eq 0) {
        $moduleChoseRoot = $true
        if (Test-WacIsAdministrator) {
            $CandidateRoot = @(
                (Join-Path -Path (Get-WacDataRoot) -ChildPath 'Logs'),
                (Get-WacFallbackDataRoot)
            )
        }
        else {
            # Never let a standard user be the one who CREATES %ProgramData%\WindowsAutoCleanup: the
            # creator becomes its owner and, through CREATOR OWNER inheritance, gains full control of
            # the directory the SYSTEM task later writes its audit log and driver backups into. An
            # unelevated run logs under the user's own profile instead.
            $userRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:TEMP }
            $CandidateRoot = @(Join-Path -Path $userRoot -ChildPath 'WindowsAutoCleanup\Logs')
        }
    }

    $script:LogLevel = $LogLevel
    $script:ExecutionId = [guid]::NewGuid().ToString('N')
    # -StartUtc is the caller's own start instant, not this line's. A budget armed where the log is
    # opened excludes everything that had to happen first - five module imports, the machine-wide
    # lock, the trust preflight - so a run could be well into its budget before the budget began.
    # -ShutdownMarginSeconds comes off the other end for the mirror-image reason: a run that spends
    # its last millisecond inside a cleanup step has nothing left to write its own verdict with.
    $armFrom = if ($null -eq $StartUtc) { (Get-Date).ToUniversalTime() } else { [datetime]$StartUtc }
    $script:DeadlineUtc = $armFrom.AddMinutes($BudgetMinutes).AddSeconds(-$ShutdownMarginSeconds)
    $script:LogDegraded = $false
    $script:LogOpened = $false
    $script:LogFailedWrites = 0
    $script:LogFallbackKind = 'None'
    $script:LogFailReason = $null
    $script:StateTrust = $null

    # THE TRUST PREFLIGHT, and it really is a PRE-flight now. It used to run after New-WacLogFile
    # had already created the directory and the log file, so the refusal was written THROUGH the
    # very path it was refusing and the documented guarantee - nothing written before a refusal -
    # was false. Every candidate is resolved and verified here, before any New-Item, any
    # FileStream(CreateNew), any append, any copy and any delete can reach it.
    #
    # Only a run using the roots THIS MODULE chose has a machine-trust claim: an unelevated run
    # logs inside the invoking user's own profile, which the user owns by construction. Both leave
    # the verdict $null - NOT EVALUATED - which is the answer Get-WacStateTrust documents and which
    # the run-level gate already treats as benign, so a benign unelevated run still exits 0.
    #
    # WHAT THIS CHECK IS FOR, now that it is no longer the only guard. It answers the question the
    # handle-bound half CANNOT: whether the whole ANCESTOR CHAIN up to the volume root is owned by
    # an administrative principal, free of reparse points, and grants no non-administrator Delete,
    # DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership or GENERIC_ALL. Renaming the
    # root aside and dropping a junction in its place needs exactly one of those rights, so proving
    # they are absent is what makes the pathname the log is created under stable in the first place.
    # Open-WacTrustedDirectory deliberately inspects nothing above the directory it opens.
    #
    # The window this comment used to describe - check by pathname, then create by pathname - is
    # CLOSED. It stated that managed code could not open a leaf relative to a directory handle and
    # that the native surface offered no such primitive; the second half was a decision, not a fact,
    # and it has been reversed. The creation is now collision-failing and anchored to a proved
    # parent handle, and the object obtained is verified through that handle before use.
    #
    # Kept whole for the protected-root registration below. Narrowing $CandidateRoot to the trusted
    # ones is right for CREATING the log and wrong for deciding what cleanup must never delete: a
    # root this run refuses to write into is still a root it must not sweep.
    $allCandidateRoot = @($CandidateRoot)

    # Whether this run makes a machine-trust claim at all. It decides two things that must not
    # drift apart: whether the ancestor preflight below runs, and whether the directory the log is
    # created in has to prove an administrative owner and DACL through its own handle.
    $machineClaim = ($moduleChoseRoot -and (Test-WacIsAdministrator))

    $verdictByRoot = $null
    if ($machineClaim) {
        $verdictByRoot = @{}
        $trustedRoot = New-Object 'System.Collections.Generic.List[string]'
        $refusal = New-Object 'System.Collections.Generic.List[string]'
        $firstRefusal = $null

        foreach ($root in $CandidateRoot) {
            if ([string]::IsNullOrWhiteSpace($root)) { continue }

            $verdict = Get-WacStateRootVerdict -Path $root
            $verdictByRoot[$root] = $verdict
            if ($verdict.IsTrusted) {
                [void]$trustedRoot.Add($root)
                continue
            }

            if (-not $firstRefusal) { $firstRefusal = $verdict }
            [void]$refusal.Add(('{0}: {1}' -f $root, [string]$verdict.Reason))
        }

        if ($trustedRoot.Count -eq 0) {
            $script:LogPath = $null
            $script:LogWriter = $null
            $script:StateTrust = $firstRefusal

            $reason = ('No machine-trusted state directory was found, so none of them was created, opened or written to: {0}' -f ($refusal -join ' | '))
            Set-WacLogDegraded -Reason $reason
            $script:LogFallbackKind = Write-WacFallbackLine -Line (
                '[{0} UTC] [CRITICAL] [Log] {1}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $reason)
            return $false
        }

        $CandidateRoot = @($trustedRoot.ToArray())
    }

    # THE SECOND HALF OF THE PREFLIGHT, and the half that used to be missing. The check above is by
    # pathname and can only verify the nearest EXISTING ancestor when the candidate root does not
    # exist yet, so on its own it leaves a window in which the predictable candidate directory can
    # be created by anyone allowed to create names in that ancestor - which, on the default
    # %ProgramData% descriptor, is every local standard user. New-WacLogFile now closes that window
    # rather than documenting it: the directory is created collision-failing or opened, and the
    # object actually obtained is verified through its own handle before a byte is written to it.
    $refusal = New-Object 'System.Collections.Generic.List[object]'
    $created = New-WacLogFile -BaseName $BaseName -CandidateRoot $CandidateRoot `
        -RequireMachineTrust:$machineClaim -Refusal $refusal
    if (-not $created) {
        $script:LogPath = $null
        $script:LogWriter = $null

        $reason = ('No log file could be created under any of: {0}' -f ($CandidateRoot -join '; '))
        if ($refusal.Count -gt 0) {
            $reason = ('{0} | {1}' -f $reason,
                ((@($refusal | ForEach-Object { '{0}: {1}' -f $_.Path, $_.Reason })) -join ' | '))

            # A run that made a machine-trust claim and had its state directory refused BY THE
            # HANDLE CHECK is refusing for a security reason, and must say so in the one field the
            # exit code is derived from. Without this the same refusal reached Run.ps1's generic
            # "no log anywhere" gate and reported exit 1, which reads as a malfunction rather than
            # as the deliberate refusal it is. The verdict shape is the one Get-WacStateRootVerdict
            # produces, because Run.ps1 and Get-OperationSafetyVerdict both read it.
            if ($machineClaim) {
                $script:StateTrust = [PSCustomObject]@{
                    Path = [string]$refusal[0].Path
                    IsTrusted = $false
                    Reason = [string]$refusal[0].Reason
                    Checked = @(); Failures = @(); Writers = @()
                }
            }
        }
        Set-WacLogDegraded -Reason $reason
        $script:LogFallbackKind = Write-WacFallbackLine -Line (
            '[{0} UTC] [CRITICAL] [Log] {1}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $reason)
        return $false
    }

    $script:LogPath = $created.Path
    $script:LogWriter = $created.Writer
    $script:LogOpened = $true

    foreach ($root in $allCandidateRoot) { Add-WacProtectedRoot -Path $root }
    Add-WacProtectedRoot -Path (Get-WacDataRoot)
    Add-WacProtectedRoot -Path (Get-WacDeploymentRoot)

    if ($BootstrapLogPath) { [void](Copy-WacBootstrapLog -Path $BootstrapLogPath) }

    # The verdict for the root the log ACTUALLY landed in, reached before that root was touched.
    # It is recorded rather than re-taken: asking again now would answer a different question at a
    # different instant, and the answer that matters is the one the creation was allowed on.
    if ($verdictByRoot -and $verdictByRoot.ContainsKey($created.Root)) {
        $script:StateTrust = $verdictByRoot[$created.Root]
        Write-WacLog -Level INFO -Component 'Log' -Message 'The machine state directory was verified before anything was created in it.' -Data @{
            path = [string]$script:StateTrust.Path; reason = [string]$script:StateTrust.Reason
        }
    }

    return $true
}

function Get-WacLogPath { return $script:LogPath }
function Get-WacExecutionId { return $script:ExecutionId }

function Get-WacLogDirectory {
    <#
    .SYNOPSIS
        The directory holding this run's log, or $null when there is no log.
    .DESCRIPTION
        Exists because Split-Path -Parent $null is a TERMINATING parameter-binding error on both
        shipped hosts (measured), and the retention call in the uninstaller reached it on exactly
        the path where logging had already failed - so the run died in its own cleanup rather than
        reporting the log failure it was in the middle of handling.
    #>
    if (-not $script:LogPath) { return $null }
    try { return (Split-Path -Parent $script:LogPath) } catch { return $null }
}

function ConvertTo-WacLogSafeText {
    <#
    .SYNOPSIS
        One log record stays one physical line, whatever the value contained.
    .DESCRIPTION
        Values reaching the log come from the filesystem and from external process output, and NTFS
        permits CR and LF in a name even though Explorer cannot type one. A raw line break ends the
        record early and hands the rest of the line to whoever chose the name - which, in a
        world-writable swept location, is anyone. Measured: one Write-WacLog call with a CR+LF in a
        -Data value produced TWO lines, the second of which was a complete forged record carrying
        its own timestamp, level, component and status.

        Quoting does not contain it. The key=value rule already quotes a value matching \s, and \s
        MATCHES a newline - but quoting only wraps a string that still holds the break, so the
        record still splits and the closing quote lands inside the forged half.

        The escapes are readable rather than lossy, so the audit trail still shows what the name
        really was. The angle-bracket form is deliberate: a backslash escape (\r) would be ambiguous
        against an ordinary path, because C:\reports genuinely contains the two characters \ and r,
        and disambiguating it would mean doubling every backslash - turning every logged path into
        C:\\Windows\\Temp. Windows forbids < and > in a file name, so <CR> cannot be produced by any
        real path, and ordinary paths pass through completely untouched.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $safe = $Text.Replace("`r", '<CR>').Replace("`n", '<LF>').Replace("`t", '<TAB>')
    # Anything else below 0x20, plus DEL, becomes <0xNN> rather than reaching the file raw.
    return [regex]::Replace($safe, '[\x00-\x1F\x7F]', { param($m) '<0x{0:X2}>' -f [int][char]$m.Value })
}

function Write-WacLog {
    <#
    .SYNOPSIS
        Writes one structured log line: [timestamp UTC] [LEVEL] [Component] message key=value ...
    .DESCRIPTION
        One StreamWriter with AutoFlush replaces the previous Add-Content call, which reopened and
        closed the file on every single line. Durability is unchanged; throughput is not.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Component,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [hashtable]$Data
    )

    if ($script:LevelRank[$Level] -lt $script:LevelRank[$script:LogLevel]) { return }

    # Before Initialize-WacRun there is deliberately nothing to say: helpers such as
    # Register-WacDeleteOnReboot are callable without a run. Once a run has DECLARED its logging
    # broken, the same lines go to the fallback instead of evaporating.
    if (-not $script:LogWriter -and -not $script:LogDegraded) { return }

    # $Level and $Component are constrained by ValidateSet and by caller-supplied constants, so they
    # are NOT escaped - doing so would change the documented format. $Message and every $Data value
    # can carry a filename or external process output, so both go through the escape first.
    $line = '[{0} UTC] [{1}] [{2}] {3}' -f `
        (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Component,
        (ConvertTo-WacLogSafeText -Text $Message)

    if ($Data -and $Data.Count -gt 0) {
        $parts = New-Object 'System.Collections.Generic.List[string]'
        foreach ($key in @($Data.Keys | Sort-Object)) {
            $value = ConvertTo-WacLogSafeText -Text ([string]$Data[$key])
            if ($value -match '[\s"]') { $value = '"{0}"' -f ($value -replace '"', "'") }
            [void]$parts.Add(('{0}={1}' -f $key, $value))
        }
        $line = '{0} | {1}' -f $line, ($parts -join ' ')
    }

    if (-not $script:LogWriter) {
        $script:LogFallbackKind = Write-WacFallbackLine -Line $line
        return
    }

    try {
        $script:LogWriter.WriteLine($line)
    }
    catch {
        # A lost line is lost audit output, not a nuisance. The old catch swallowed it whole, so a
        # disk that filled up mid-run - or a log whose directory was pulled out from under it - left
        # the run reporting success on an audit trail that had stopped being written.
        $script:LogFailedWrites++
        Set-WacLogDegraded -Reason ('A log write failed: {0}' -f $_.Exception.Message)
        $script:LogFallbackKind = Write-WacFallbackLine -Line $line
    }
}

function Close-WacLog {
    if (-not $script:LogWriter) { return }
    try { $script:LogWriter.Flush() } catch { $null = $_ }
    try { $script:LogWriter.Dispose() } catch { $null = $_ }
    $script:LogWriter = $null
}

function Remove-WacOldLog {
    <#
    .SYNOPSIS
        Bounded log retention: keeps the newest $KeepCount files matching the pattern.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$LogDirectory,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [int]$KeepCount = 30
    )

    # There is nothing to retain when logging never started. Guarding HERE rather than in each
    # caller is the point: the uninstaller reached this with a null directory on exactly the run
    # where the log had failed to open.
    if ([string]::IsNullOrWhiteSpace($LogDirectory)) { return 0 }
    if ($KeepCount -lt 1) { return 0 }
    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) { return 0 }

    $removed = 0
    try {
        $files = @(Get-ChildItem -LiteralPath $LogDirectory -Filter $Pattern -File -ErrorAction Stop |
            Sort-Object -Property LastWriteTimeUtc -Descending)
    }
    catch {
        return 0
    }

    if ($files.Count -le $KeepCount) { return 0 }

    foreach ($file in $files[$KeepCount..($files.Count - 1)]) {
        if ($script:LogPath -and $file.FullName -ieq $script:LogPath) { continue }
        try {
            [System.IO.File]::Delete($file.FullName)
            $removed++
        }
        catch {
            $null = $_
        }
    }

    return $removed
}

# ---------------------------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------------------------

function Set-WacDeadline {
    param([Parameter(Mandatory = $true)][datetime]$DeadlineUtc)
    $script:DeadlineUtc = $DeadlineUtc
}

function Get-WacRemainingMs {
    <#
    .SYNOPSIS
        Milliseconds left in the overall run budget, or [int]::MaxValue when no budget is armed.
    #>
    if (-not $script:DeadlineUtc) { return [int]::MaxValue }

    $remaining = ($script:DeadlineUtc - (Get-Date).ToUniversalTime()).TotalMilliseconds
    if ($remaining -le 0) { return 0 }
    if ($remaining -ge [int]::MaxValue) { return [int]::MaxValue }
    return [int]$remaining
}

function Test-WacDeadlineExpired {
    return ((Get-WacRemainingMs) -le 0)
}

function Get-WacStepTimeoutMs {
    <#
    .SYNOPSIS
        A step never gets more time than the run budget still has.
    #>
    param([Parameter(Mandatory = $true)][int]$RequestedMs)

    $remaining = Get-WacRemainingMs
    if ($RequestedMs -lt $remaining) { return $RequestedMs }
    return $remaining
}
