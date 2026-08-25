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

function Get-WacDataRoot {
    <#
    .SYNOPSIS
        Machine-wide state/log root. Never inside a directory this tool cleans.
    #>
    if ($env:ProgramData) { return (Join-Path -Path $env:ProgramData -ChildPath 'WindowsAutoCleanup') }
    return (Join-Path -Path $env:SystemRoot -ChildPath 'Logs\WindowsAutoCleanup')
}

function Get-WacDeploymentRoot {
    <#
    .SYNOPSIS
        Canonical machine-wide install location for the runtime the scheduled task executes.
    #>
    if ($env:ProgramFiles) { return (Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsAutoCleanup') }
    return (Join-Path -Path $env:SystemRoot -ChildPath 'WindowsAutoCleanup')
}

function New-WacLogFile {
    <#
    .SYNOPSIS
        Creates a new log file with create-new semantics, trying each candidate root in order.
    .DESCRIPTION
        New-Item -Force truncates an existing file, so two runs starting in the same second used to
        share one log and the first one's content was lost. CreateNew fails instead, and the suffix
        loop makes the name collision-proof. Returns the opened StreamWriter, or $null.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$BaseName,
        [Parameter(Mandatory = $true)][string[]]$CandidateRoot
    )

    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd_HH-mm-ss')

    foreach ($root in $CandidateRoot) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }

        try {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) {
                New-Item -Path $root -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        }
        catch {
            continue
        }

        for ($attempt = 0; $attempt -lt 50; $attempt++) {
            $suffix = if ($attempt -eq 0) { '' } else { '_{0:00}' -f $attempt }
            $name = '{0}_{1}_UTC{2}.log' -f $BaseName, $stamp, $suffix
            $path = Join-Path -Path $root -ChildPath $name

            try {
                $stream = New-Object System.IO.FileStream(
                    $path,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::Read)
                $writer = New-Object System.IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($false)))
                $writer.AutoFlush = $true
                return [PSCustomObject]@{ Path = $path; Writer = $writer }
            }
            catch {
                # A CreateNew collision surfaces as IOException, but a constructor exception reaches
                # us wrapped, so classify explicitly rather than relying on a typed catch: getting
                # this wrong makes a same-second collision abandon the whole candidate root.
                if ((Get-WacIoFailureKind -ErrorRecord $_) -eq 'Busy') { continue }
                break
            }
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
    #>
    param([object]$Writer)
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
        claim rests on it. Only an elevated run makes a machine-trust claim worth refusing on.
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

function Initialize-WacRun {
    <#
    .SYNOPSIS
        Opens the run log, arms the overall deadline, adopts any bootstrap log and verifies that the
        directory the log landed in is machine-trusted.
    .DESCRIPTION
        Returns $true only when a log file was really created. The old code assigned $LogPath even
        after every fallback failed, so later writes silently went nowhere while the run reported
        success.

        A failure here no longer goes quiet either: the reason is written to the verified fallback
        sink and Get-WacLogHealth reports IsDurable false, which the caller must map to Incomplete.

        The trust check lives here rather than at the call sites because this is the one function
        every entry point already calls; a guard a caller has to remember is a guard one caller will
        forget. It VERIFIES and records - refusing the run is the orchestrator's decision.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BaseName,
        [string[]]$CandidateRoot,
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
        [int]$BudgetMinutes = 210,
        [string]$BootstrapLogPath
    )

    if (-not $CandidateRoot -or $CandidateRoot.Count -eq 0) {
        if (Test-WacIsAdministrator) {
            $CandidateRoot = @(
                (Join-Path -Path (Get-WacDataRoot) -ChildPath 'Logs'),
                (Join-Path -Path $env:SystemRoot -ChildPath 'Logs\WindowsAutoCleanup')
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
    $script:DeadlineUtc = (Get-Date).ToUniversalTime().AddMinutes($BudgetMinutes)
    $script:LogDegraded = $false
    $script:LogOpened = $false
    $script:LogFailedWrites = 0
    $script:LogFallbackKind = 'None'
    $script:LogFailReason = $null
    $script:StateTrust = $null

    $created = New-WacLogFile -BaseName $BaseName -CandidateRoot $CandidateRoot
    if (-not $created) {
        $script:LogPath = $null
        $script:LogWriter = $null

        $reason = ('No log file could be created under any of: {0}' -f ($CandidateRoot -join '; '))
        Set-WacLogDegraded -Reason $reason
        $script:LogFallbackKind = Write-WacFallbackLine -Line (
            '[{0} UTC] [CRITICAL] [Log] {1}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $reason)
        return $false
    }

    $script:LogPath = $created.Path
    $script:LogWriter = $created.Writer
    $script:LogOpened = $true

    foreach ($root in $CandidateRoot) { Add-WacProtectedRoot -Path $root }
    Add-WacProtectedRoot -Path (Get-WacDataRoot)
    Add-WacProtectedRoot -Path (Get-WacDeploymentRoot)

    if ($BootstrapLogPath) { [void](Copy-WacBootstrapLog -Path $BootstrapLogPath) }

    # Only an elevated run writes into the machine-wide state root and hands SYSTEM an audit trail,
    # so only an elevated run has a trust claim to verify. See Get-WacStateTrust for why $null is
    # the right answer otherwise.
    if (Test-WacIsAdministrator) {
        $script:StateTrust = Test-WacStatePathIsTrusted -Path (Split-Path -Parent $script:LogPath)
        if (-not $script:StateTrust.IsTrusted) {
            Write-WacLog -Level ERROR -Component 'Log' -Message 'The audit log directory is not machine-trusted.' -Data @{
                path = $script:StateTrust.Path; reason = $script:StateTrust.Reason
            }
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

    $line = '[{0} UTC] [{1}] [{2}] {3}' -f `
        (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Component, $Message

    if ($Data -and $Data.Count -gt 0) {
        $parts = New-Object 'System.Collections.Generic.List[string]'
        foreach ($key in @($Data.Keys | Sort-Object)) {
            $value = [string]$Data[$key]
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
