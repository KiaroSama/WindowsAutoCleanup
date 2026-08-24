<#
.SYNOPSIS
    Shared infrastructure for WindowsAutoCleanup: logging, path safety, the run deadline,
    the bounded external-process runner, single-instance locking and machine-trust checks.

.DESCRIPTION
    Nothing here has a side effect until Initialize-WacRun is called. The module owns its own state
    so callers cannot corrupt it by accident, and the seams tests need (Set-WacProcessInvoker, an
    injectable mutex name, an injectable clock deadline) are explicit rather than implied.
#>

Set-StrictMode -Version 2.0

$script:TargetDrive         = 'C:'
$script:LogWriter           = $null
$script:LogPath             = $null
$script:LogLevel            = 'INFO'
$script:ExecutionId         = $null
$script:DeadlineUtc         = $null
$script:ProcessInvoker      = $null
$script:ProtectedRoots      = New-Object 'System.Collections.Generic.List[string]'
$script:PendingDeleteWarned = $false
$script:LevelRank           = @{ DEBUG = 0; INFO = 1; WARNING = 2; ERROR = 3; CRITICAL = 4 }

# ---------------------------------------------------------------------------------------------
# Native helpers
# ---------------------------------------------------------------------------------------------

function Initialize-WacNative {
    if ('WacNative' -as [type]) { return $true }

    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class WacNative
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileExW(string lpExistingFileName, string lpNewFileName, int dwFlags);

    private const uint FILE_READ_ATTRIBUTES         = 0x0080;
    private const uint FILE_SHARE_READ_WRITE_DELETE = 0x0007;
    private const uint OPEN_EXISTING                = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_NAME_NORMALIZED         = 0x00000000;
    private const uint VOLUME_NAME_DOS              = 0x00000000;
    private const int  MOVEFILE_DELAY_UNTIL_REBOOT  = 0x00000004;

    // Resolves the final on-disk path of the object named by 'path'.
    //
    // Only the followLinks=true direction has documented semantics: "a final path is the path that
    // is returned when a path is fully resolved". Comparing that answer with the requested path is
    // therefore a sound proof that no component was swapped for a junction, symlink or mount point.
    //
    // followLinks=false binds the handle to the reparse point itself (documented on CreateFileW),
    // but GetFinalPathNameByHandleW does NOT document what path it then returns, so callers must
    // not depend on it; the explicit FILE_ATTRIBUTE_REPARSE_POINT test is the supported companion
    // check. See .ai/LESSON_WINDOWS_APIS.md.
    //
    // Returns null when the object cannot be opened; callers must treat null as "unverifiable".
    public static string GetFinalPath(string path, bool followLinks)
    {
        uint flags = FILE_FLAG_BACKUP_SEMANTICS;
        if (!followLinks) { flags |= FILE_FLAG_OPEN_REPARSE_POINT; }

        using (SafeFileHandle handle = CreateFileW(
            path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, flags, IntPtr.Zero))
        {
            if (handle.IsInvalid) { return null; }

            StringBuilder buffer = new StringBuilder(1024);
            uint length = GetFinalPathNameByHandleW(
                handle, buffer, (uint)buffer.Capacity, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (length == 0) { return null; }

            if (length >= buffer.Capacity)
            {
                buffer = new StringBuilder((int)length + 1);
                length = GetFinalPathNameByHandleW(
                    handle, buffer, (uint)buffer.Capacity, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                if (length == 0) { return null; }
            }

            return buffer.ToString();
        }
    }

    // Queues the path for deletion during the next boot.
    // Documented requirement is only that the caller belongs to the administrators group or is
    // LocalSystem - no named privilege. The return value reflects whether the pending-rename entry
    // was placed, NOT whether the object will actually be deleted, and a directory is removed at
    // restart only if it is empty by then. Callers must log this as "queued", never as "deleted".
    public static bool DeleteOnReboot(string path)
    {
        return MoveFileExW(path, null, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}
'@
        return $true
    }
    catch {
        return $false
    }
}

# ---------------------------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------------------------

function Get-WacNormalizedPath {
    <#
    .SYNOPSIS
        Canonicalises a path to 'X:' or 'X:\some\path' with no trailing separator, or $null.
    .DESCRIPTION
        Every path comparison in this project routes through this one function. Mixing it with
        Resolve-Path is a real defect: GetFullPath expands 8.3 short names and Resolve-Path does not,
        which is invisible on a long-profile developer machine and breaks on an 8.3 CI runner.
        UNC, device, volume-GUID and drive-relative forms are rejected outright: none can ever be a
        valid C: cleanup target, and drive-relative forms resolve against a mutable per-drive
        working directory.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $candidate = $Path.Trim()

    if ($candidate.StartsWith('\\?\', [System.StringComparison]::OrdinalIgnoreCase)) {
        if ($candidate -match '^\\\\\?\\([A-Za-z]:\\.*)$') { $candidate = $Matches[1] }
        elseif ($candidate -match '^\\\\\?\\([A-Za-z]:)\\?$') { return $Matches[1].ToUpperInvariant() }
        else { return $null }
    }

    if ($candidate -match '^[A-Za-z]:$') { return $candidate.ToUpperInvariant() }
    if ($candidate -match '^[A-Za-z]:(?!\\)') { return $null }
    if ($candidate.StartsWith('\\')) { return $null }

    try {
        $full = [System.IO.Path]::GetFullPath($candidate)
    }
    catch {
        return $null
    }

    if ($full -notmatch '^[A-Za-z]:\\') { return $null }

    $trimmed = $full.TrimEnd('\')
    if ($trimmed -match '^[A-Za-z]:$') { return $trimmed.ToUpperInvariant() }
    return ($trimmed.Substring(0, 2).ToUpperInvariant() + $trimmed.Substring(2))
}

function Get-WacLongPath {
    <#
    .SYNOPSIS
        Adds the \\?\ extended-length prefix when a path is long enough to need it.
    .DESCRIPTION
        Windows PowerShell 5.1 runs on .NET Framework, which throws PathTooLongException above
        MAX_PATH unless the prefix is used. The prefix disables all further normalisation, so it is
        only ever applied to an already fully-normalised absolute drive path.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path.Length -lt 240) { return $Path }
    if ($Path.StartsWith('\\?\', [System.StringComparison]::OrdinalIgnoreCase)) { return $Path }
    if ($Path -notmatch '^[A-Za-z]:\\') { return $Path }
    return ('\\?\' + $Path)
}

function Get-WacTargetDrive {
    return $script:TargetDrive
}

function Test-WacIsOnTargetDrive {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $false }

    return ($normalized -ieq $script:TargetDrive -or
            $normalized.StartsWith($script:TargetDrive + '\', [System.StringComparison]::OrdinalIgnoreCase))
}

function Add-WacProtectedRoot {
    <#
    .SYNOPSIS
        Registers a path cleanup must never delete, descend into, or be contained by.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return }
    foreach ($existing in $script:ProtectedRoots) {
        if ($existing -ieq $normalized) { return }
    }
    [void]$script:ProtectedRoots.Add($normalized)
}

function Clear-WacProtectedRoot {
    $script:ProtectedRoots.Clear()
}

$script:FixedProtectedRootCache = $null

function Get-WacFixedProtectedRoot {
    <#
    .SYNOPSIS
        The never-delete system roots, normalised once.
    .DESCRIPTION
        These are constants, but re-normalising all eleven on every call made Test-WacIsProtectedPath
        cost about a millisecond - measured as the single dominant per-leaf cost of a sweep, larger
        than the delete itself. Caching turns the protection check from the bottleneck into noise,
        which is what makes the per-leaf handle verification in Remove-WacLeaf affordable.
    #>
    if ($null -ne $script:FixedProtectedRootCache) { return $script:FixedProtectedRootCache }

    $roots = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @(
        'C:', 'C:\Windows', 'C:\Users', 'C:\ProgramData',
        'C:\Program Files', 'C:\Program Files (x86)',
        'C:\Windows\System32', 'C:\Windows\SysWOW64',
        'C:\Windows\WinSxS', 'C:\Windows\System32\DriverStore',
        'C:\$Recycle.Bin'
    )) {
        $p = Get-WacNormalizedPath -Path $item
        if ($p) { [void]$roots.Add($p) }
    }

    $script:FixedProtectedRootCache = $roots.ToArray()
    return $script:FixedProtectedRootCache
}

function Test-WacIsProtectedPath {
    <#
    .SYNOPSIS
        True when the path must never be deleted.
    .DESCRIPTION
        Protection is bidirectional for registered roots: a target equal to, inside, OR an ancestor
        of a protected root is refused. The ancestor direction is what stops a checkout living under
        %TEMP% from deleting itself while %TEMP% is being cleaned.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $true }

    foreach ($p in (Get-WacFixedProtectedRoot)) {
        if ($normalized -ieq $p) { return $true }
    }

    foreach ($root in $script:ProtectedRoots) {
        if ($normalized -ieq $root) { return $true }
        if ($normalized.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($root.StartsWith($normalized + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }

    return $false
}

function Test-WacIsProtectedSubtree {
    <#
    .SYNOPSIS
        True when the path IS a protected root or lives inside one, so nothing under it may be touched.
    .DESCRIPTION
        This is the one-directional half of the protection rule, and the distinction matters.
        Test-WacIsProtectedPath is bidirectional: it also refuses an ANCESTOR of a protected root, so
        the ancestor is never deleted. But a checkout installed under %TEMP% makes %TEMP% such an
        ancestor, and refusing the whole target there would silently stop cleaning temp altogether.
        So: a target root or a traversal entry is tested with THIS function (skip the protected
        subtree, keep cleaning everything around it), while an individual delete is tested with
        Test-WacIsProtectedPath (never delete an ancestor of a protected root either).
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $true }

    foreach ($p in (Get-WacFixedProtectedRoot)) {
        if ($normalized -ieq $p) { return $true }
    }

    foreach ($root in $script:ProtectedRoots) {
        if ($normalized -ieq $root) { return $true }
        if ($normalized.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }

    return $false
}

function Test-WacIsSafeTargetPath {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $false }
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { return $false }
    if (Test-WacIsProtectedSubtree -Path $normalized) { return $false }

    return $true
}

function Test-WacIsWithinRoot {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$ChildPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$RootPath
    )

    $child = Get-WacNormalizedPath -Path $ChildPath
    $root = Get-WacNormalizedPath -Path $RootPath
    if (-not $child -or -not $root) { return $false }

    return ($child -ieq $root -or $child.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase))
}

function Get-WacFinalPath {
    <#
    .SYNOPSIS
        Handle-verified final path, or $null when the object cannot be opened.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Initialize-WacNative)) { return $null }

    try {
        # Always follow. Only that direction has documented semantics; the no-follow answer is
        # undocumented, so nothing here may depend on it.
        $raw = [WacNative]::GetFinalPath((Get-WacLongPath -Path $Path), $true)
    }
    catch {
        return $null
    }

    if (-not $raw) { return $null }
    return (Get-WacNormalizedPath -Path $raw)
}

function Test-WacFinalPathMatches {
    <#
    .SYNOPSIS
        Fast handle check: does this ALREADY-NORMALISED path still resolve to itself?
    .DESCRIPTION
        Same guarantee as Test-WacPathResolvesToItself, but flattened for the hot path. The nested
        advanced-function calls in the general version cost about 1.5 ms per call, which is far too
        much to pay once per deleted file; this version does one P/Invoke and one ordinal compare and
        the caller guarantees the input is already normalised.

        This is the check that closes the junction-swap race properly. Verifying once per DIRECTORY
        leaves a window that is as long as the directory takes to sweep - measured at roughly 12
        seconds for 3000 entries - during which an attacker who can write to an allow-listed target
        (C:\Windows\Temp grants BUILTIN\Users write by default) can replace the directory with a
        junction and have every subsequent delete resolve through it as SYSTEM.

        A path that cannot be opened returns $false, so callers fail closed.
    #>
    param([Parameter(Mandatory = $true)][string]$NormalizedPath)

    if (-not (Initialize-WacNative)) { return $false }

    $raw = $null
    try {
        $long = if ($NormalizedPath.Length -ge 240) { '\\?\' + $NormalizedPath } else { $NormalizedPath }
        $raw = [WacNative]::GetFinalPath($long, $true)
    }
    catch {
        return $false
    }

    if (-not $raw) { return $false }
    if ($raw.StartsWith('\\?\', [System.StringComparison]::OrdinalIgnoreCase)) { $raw = $raw.Substring(4) }

    return [string]::Equals($raw.TrimEnd('\'), $NormalizedPath, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-WacPathResolvesToItself {
    <#
    .SYNOPSIS
        Proves no component of the path is a reparse point that redirects somewhere else.
    .DESCRIPTION
        This is the junction-swap defence. It binds a handle to the object and asks Windows for that
        object's real path; a swapped component makes the answer differ from the requested path.
        A path that cannot be opened is reported as NOT self-resolving, so every caller fails closed.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $expected = Get-WacNormalizedPath -Path $Path
    if (-not $expected) { return $false }

    $final = Get-WacFinalPath -Path $expected
    if (-not $final) { return $false }

    return ($final -ieq $expected)
}

function Test-WacIsReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $attributes = [System.IO.File]::GetAttributes((Get-WacLongPath -Path $Path))
        return (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    }
    catch {
        # Unreadable attributes are an unverifiable safety condition: fail closed.
        return $true
    }
}

function Test-WacIsDeleteOnRebootAllowed {
    <#
    .SYNOPSIS
        Every guard that must pass before a path may be queued for deletion at the next boot.
    .DESCRIPTION
        Separated from Register-WacDeleteOnReboot so the decision can be asserted directly. It has to
        be: MoveFileEx only works for an administrator or LocalSystem, so on an unelevated shell the
        registration fails anyway and a test that asserts only the return value passes for the wrong
        reason - it would go green even with the guard deleted, and only turn red on an elevated CI
        runner. Testing the decision instead makes the guard verifiable at any privilege level.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $false }
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { return $false }
    if (Test-WacIsProtectedPath -Path $normalized) { return $false }

    # The handle check is the one that matters here. MoveFileEx stores the literal path string and
    # the session manager re-resolves it at the next boot, so a path accepted now can be redirected
    # at leisure - an arbitrary delete as SYSTEM with no timing window at all.
    if (-not (Test-WacFinalPathMatches -NormalizedPath $normalized)) { return $false }

    return $true
}

function Register-WacDeleteOnReboot {
    <#
    .SYNOPSIS
        Queues a locked file or empty directory for deletion at the next boot.
    .DESCRIPTION
        The handle check here is not optional. MoveFileEx stores the literal PATH STRING in
        PendingFileRenameOperations and the session manager re-resolves it at the next boot, before
        anything is loaded that could object. Without proving the path resolves to itself now, an
        attacker who can write to an allow-listed target could get a locked file queued, then replace
        an ancestor directory with a junction at leisure and have the boot-time delete land anywhere
        - a race-free arbitrary delete as SYSTEM, with hours or days to set it up.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-WacIsDeleteOnRebootAllowed -Path $Path)) { return $false }
    $normalized = Get-WacNormalizedPath -Path $Path

    if (-not (Initialize-WacNative)) {
        if (-not $script:PendingDeleteWarned) {
            Write-WacLog -Level WARNING -Component 'FileSystem' -Message 'Pending-delete registration is unavailable; locked files are skipped instead.'
            $script:PendingDeleteWarned = $true
        }
        return $false
    }

    try {
        return [WacNative]::DeleteOnReboot((Get-WacLongPath -Path $normalized))
    }
    catch {
        return $false
    }
}

function Get-WacIoFailureKind {
    <#
    .SYNOPSIS
        Classifies an I/O failure from the error record instead of relying on a typed catch clause.
    .DESCRIPTION
        PowerShell wraps an exception thrown by a .NET METHOD in MethodInvocationException, and the
        two hosts do not agree on whether a typed `catch [T]` then matches the inner exception.
        Measured here: under Windows PowerShell 5.1, after other cases had already run in the same
        process, an IOException ("The directory is not empty") from
        [System.IO.Directory]::Delete was caught by `catch [System.UnauthorizedAccessException]`.
        That mattered: Remove-WacTree builds its retry queue from SkippedNotEmpty, so the
        misclassification silently disabled the second directory pass - one half of the
        "temp is never really emptied" defect.

        Order is load-bearing. DirectoryNotFoundException, FileNotFoundException and
        PathTooLongException all derive from IOException, so they must be tested first.
    #>
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    $exception = $null
    try { $exception = $ErrorRecord.Exception } catch { $exception = $null }

    while ($exception -and
           ($exception -is [System.Management.Automation.MethodInvocationException]) -and
           $exception.InnerException) {
        $exception = $exception.InnerException
    }

    if (-not $exception) { return 'Other' }
    if ($exception -is [System.IO.DirectoryNotFoundException]) { return 'NotFound' }
    if ($exception -is [System.IO.FileNotFoundException]) { return 'NotFound' }
    if ($exception -is [System.IO.PathTooLongException]) { return 'TooLong' }
    if ($exception -is [System.UnauthorizedAccessException]) { return 'Denied' }
    if ($exception -is [System.IO.IOException]) { return 'Busy' }

    return 'Other'
}

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

function Initialize-WacRun {
    <#
    .SYNOPSIS
        Opens the run log and arms the overall deadline.
    .DESCRIPTION
        Returns $true only when a log file was really created. The old code assigned $LogPath even
        after every fallback failed, so later writes silently went nowhere while the run reported
        success.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BaseName,
        [string[]]$CandidateRoot,
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
        [int]$BudgetMinutes = 210
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

    $created = New-WacLogFile -BaseName $BaseName -CandidateRoot $CandidateRoot
    if (-not $created) {
        $script:LogPath = $null
        $script:LogWriter = $null
        return $false
    }

    $script:LogPath = $created.Path
    $script:LogWriter = $created.Writer

    foreach ($root in $CandidateRoot) { Add-WacProtectedRoot -Path $root }
    Add-WacProtectedRoot -Path (Get-WacDataRoot)
    Add-WacProtectedRoot -Path (Get-WacDeploymentRoot)

    return $true
}

function Get-WacLogPath { return $script:LogPath }
function Get-WacExecutionId { return $script:ExecutionId }

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

    if (-not $script:LogWriter) { return }
    if ($script:LevelRank[$Level] -lt $script:LevelRank[$script:LogLevel]) { return }

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

    try {
        $script:LogWriter.WriteLine($line)
    }
    catch {
        # Cleanup must stay silent even when logging fails.
        $null = $_
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
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [int]$KeepCount = 30
    )

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

# ---------------------------------------------------------------------------------------------
# Bounded external process execution
# ---------------------------------------------------------------------------------------------

function ConvertTo-WacCommandLineArgument {
    <#
    .SYNOPSIS
        Quotes one argument per the CommandLineToArgvW rules.
    .DESCRIPTION
        ProcessStartInfo.ArgumentList does not exist on .NET Framework, so Windows PowerShell 5.1
        must be handed a single command-line string. Building that string by hand is exactly where
        injection and "path with spaces" defects come from, so it happens in one tested place.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')

    for ($i = 0; $i -lt $Value.Length; $i++) {
        $backslashes = 0
        while ($i -lt $Value.Length -and $Value[$i] -eq '\') { $backslashes++; $i++ }

        if ($i -eq $Value.Length) {
            [void]$builder.Append('\', $backslashes * 2)
            break
        }
        elseif ($Value[$i] -eq '"') {
            [void]$builder.Append('\', $backslashes * 2 + 1)
            [void]$builder.Append('"')
        }
        else {
            [void]$builder.Append('\', $backslashes)
            [void]$builder.Append($Value[$i])
        }
    }

    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-WacCommandLine {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ArgumentList)

    if ($ArgumentList.Count -eq 0) { return '' }
    return (($ArgumentList | ForEach-Object { ConvertTo-WacCommandLineArgument -Value $_ }) -join ' ')
}

function ConvertTo-WacPowerShellLiteral {
    <#
    .SYNOPSIS
        Wraps a value as a single-quoted PowerShell string literal.
    .DESCRIPTION
        A single-quoted literal is inert - PowerShell expands nothing inside it - so doubling an
        embedded quote is the whole escape rule. Everything interpolated into a -Command payload goes
        through here, so a value containing a quote cannot terminate the literal and become code.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Value)

    if ($null -eq $Value) { return "''" }
    return ("'" + ($Value -replace "'", "''") + "'")
}

function Get-WacRelaunchCommand {
    <#
    .SYNOPSIS
        The PowerShell source a relaunched child executes. Pure, so it can be asserted on directly.
    .DESCRIPTION
        Boolean switches are always emitted in the explicit -Name:$true / -Name:$false form, so the
        child can never fall back to a default the parent did not ask for (ledger P0-2). Keys are
        emitted in sorted order so a test can assert on the exact string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [hashtable]$BooleanSwitch = @{},
        [AllowEmptyCollection()][string[]]$PresentSwitch = @(),
        [hashtable]$NamedValue = @{},
        [hashtable]$ArrayValue = @{}
    )

    $parts = New-Object 'System.Collections.Generic.List[string]'
    [void]$parts.Add('&')
    [void]$parts.Add((ConvertTo-WacPowerShellLiteral -Value $ScriptPath))

    foreach ($name in @($BooleanSwitch.Keys | Sort-Object)) {
        [void]$parts.Add(('-{0}:${1}' -f $name, ([bool]$BooleanSwitch[$name]).ToString().ToLowerInvariant()))
    }

    foreach ($name in @($PresentSwitch | Sort-Object)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        [void]$parts.Add(('-{0}' -f $name))
    }

    foreach ($name in @($NamedValue.Keys | Sort-Object)) {
        [void]$parts.Add(('-{0}' -f $name))
        [void]$parts.Add((ConvertTo-WacPowerShellLiteral -Value ([string]$NamedValue[$name])))
    }

    foreach ($name in @($ArrayValue.Keys | Sort-Object)) {
        $values = @($ArrayValue[$name] | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($values.Count -eq 0) { continue }
        [void]$parts.Add(('-{0}' -f $name))
        [void]$parts.Add((($values | ForEach-Object { ConvertTo-WacPowerShellLiteral -Value ([string]$_) }) -join ','))
    }

    # Two halves, both load-bearing:
    #   * the child script ends with `exit <code>`, which leaves the HOST at its default 0 unless the
    #     code is re-raised, so the payload ends by re-raising it;
    #   * $LASTEXITCODE is UNDEFINED until something sets it, and `exit $null` is exit 0 - so a child
    #     that never ran at all (missing file, parameter-binding failure) would report SUCCESS.
    #     Seeding it with 1 first means the default answer is failure and only the child can change it.
    return ('$LASTEXITCODE = 1; ' + ($parts -join ' ') + '; exit $LASTEXITCODE')
}

function Get-WacRelaunchArgument {
    <#
    .SYNOPSIS
        The child argument VECTOR for an elevated relaunch or a scheduled-task action.
    .DESCRIPTION
        -Command, not -File, and that is load-bearing rather than a style choice.

        Measured on this machine against a `[switch]$Flag = $true` script:

            host             -File "s.ps1" -Flag:$false     -Command "& 's.ps1' -Flag:$false"
            powershell.exe   exit 1, binding error          exit 0, Flag=False
            pwsh 7           exit 0, Flag=False             exit 0, Flag=False

        With -File every token after the script path is a literal STRING, and Windows PowerShell 5.1
        refuses to convert one into a SwitchParameter, so a valued switch cannot be expressed at all.
        There is NO -File spelling that carries "false" to both hosts. Because both the relaunch host
        and the scheduled-task host are powershell.exe whenever PowerShell 7 is absent, keeping -File
        would have made the ledger P0-2 fix work only on machines that happen to have pwsh 7 - and on
        every other machine the child would die during parameter binding before it could open a log.

        -Command is parsed by PowerShell, so the explicit form binds on both hosts, arrays arrive as
        real arrays instead of one comma-joined string, and `exit $LASTEXITCODE` carries the child's
        real exit code back. Everything interpolated into the payload is emitted through
        ConvertTo-WacPowerShellLiteral, and the payload deliberately contains no double quote, so
        quoting it for CreateProcess stays one unambiguous step.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [hashtable]$BooleanSwitch = @{},
        [AllowEmptyCollection()][string[]]$PresentSwitch = @(),
        [hashtable]$NamedValue = @{},
        [hashtable]$ArrayValue = @{},
        [AllowEmptyCollection()][string[]]$HostSwitch = @()
    )

    $arguments = New-Object 'System.Collections.Generic.List[string]'
    [void]$arguments.Add('-NoProfile')
    [void]$arguments.Add('-ExecutionPolicy')
    [void]$arguments.Add('Bypass')
    foreach ($switch in $HostSwitch) {
        if ([string]::IsNullOrWhiteSpace($switch)) { continue }
        [void]$arguments.Add($switch)
    }
    [void]$arguments.Add('-Command')
    [void]$arguments.Add((Get-WacRelaunchCommand -ScriptPath $ScriptPath -BooleanSwitch $BooleanSwitch `
        -PresentSwitch $PresentSwitch -NamedValue $NamedValue -ArrayValue $ArrayValue))

    return @($arguments.ToArray())
}

function Stop-WacProcessTree {
    <#
    .SYNOPSIS
        Kills a process AND its children. Process.Kill() alone leaves the children running.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [int]$TimeoutMs = 10000
    )

    $killed = $false
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe')
        $psi.Arguments = ConvertTo-WacCommandLine -ArgumentList @('/T', '/F', '/PID', [string]$ProcessId)
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $killer = [System.Diagnostics.Process]::Start($psi)
        if ($killer) {
            [void]$killer.StandardOutput.ReadToEndAsync()
            [void]$killer.StandardError.ReadToEndAsync()
            $killed = $killer.WaitForExit($TimeoutMs)
            try { $killer.Dispose() } catch { $null = $_ }
        }
    }
    catch {
        $killed = $false
    }

    if (-not $killed) {
        try {
            $orphan = Get-Process -Id $ProcessId -ErrorAction Stop
            $orphan.Kill()
            $killed = $true
        }
        catch {
            $null = $_
        }
    }

    return $killed
}

function Set-WacProcessInvoker {
    <#
    .SYNOPSIS
        Replaces the real process runner. This is the injection seam that lets tests exercise DISM,
        pnputil and cleanmgr behaviour without ever running them.
    .DESCRIPTION
        The scriptblock receives (FilePath, ArgumentList, TimeoutMs) and must return an object with
        ExitCode, TimedOut, StandardOutput, StandardError and DurationMs. Pass $null to restore the
        real runner.
    #>
    param([scriptblock]$Invoker)
    $script:ProcessInvoker = $Invoker
}

function Get-WacProcessInvoker { return $script:ProcessInvoker }

function Invoke-WacProcess {
    <#
    .SYNOPSIS
        Runs an external tool with a hard deadline, full output capture and process-tree termination.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [AllowEmptyCollection()][string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [string]$Component = 'Process'
    )

    if ($script:ProcessInvoker) {
        return (& $script:ProcessInvoker $FilePath $ArgumentList $TimeoutMs)
    }

    if ($TimeoutMs -le 0) {
        Write-WacLog -Level WARNING -Component $Component -Message 'Run budget exhausted before the tool could start.' -Data @{ tool = $FilePath }
        return [PSCustomObject]@{
            ExitCode = $null; TimedOut = $true; StandardOutput = ''; StandardError = ''
            DurationMs = 0; Started = $false
        }
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = $null

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = ConvertTo-WacCommandLine -ArgumentList $ArgumentList
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8

        Write-WacLog -Level DEBUG -Component $Component -Message 'Starting external tool.' -Data @{
            tool = $FilePath; args = $psi.Arguments; timeoutMs = $TimeoutMs
        }

        $process = [System.Diagnostics.Process]::Start($psi)
        if (-not $process) { throw 'Process.Start returned no process.' }

        # ReadToEndAsync avoids the classic full-pipe deadlock without needing event handlers.
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()

        $exited = $process.WaitForExit($TimeoutMs)
        $timedOut = -not $exited

        if ($timedOut) {
            Write-WacLog -Level WARNING -Component $Component -Message 'External tool exceeded its deadline; terminating the process tree.' -Data @{
                tool = $FilePath; pid = $process.Id; timeoutMs = $TimeoutMs
            }
            [void](Stop-WacProcessTree -ProcessId $process.Id)
            [void]$process.WaitForExit(10000)
        }

        [void]$outTask.Wait(5000)
        [void]$errTask.Wait(5000)

        $stdout = if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' }
        $stderr = if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' }

        $exitCode = $null
        if (-not $timedOut) {
            try { $exitCode = [int]$process.ExitCode } catch { $exitCode = $null }
        }

        $stopwatch.Stop()
        return [PSCustomObject]@{
            ExitCode = $exitCode
            TimedOut = $timedOut
            StandardOutput = $stdout
            StandardError = $stderr
            DurationMs = [int]$stopwatch.Elapsed.TotalMilliseconds
            Started = $true
        }
    }
    catch {
        $stopwatch.Stop()
        Write-WacLog -Level WARNING -Component $Component -Message 'External tool failed to start.' -Data @{
            tool = $FilePath; error = $_.Exception.Message
        }
        return [PSCustomObject]@{
            ExitCode = $null; TimedOut = $false; StandardOutput = ''; StandardError = [string]$_.Exception.Message
            DurationMs = [int]$stopwatch.Elapsed.TotalMilliseconds; Started = $false
        }
    }
    finally {
        if ($process) { try { $process.Dispose() } catch { $null = $_ } }
    }
}

# ---------------------------------------------------------------------------------------------
# Single instance
# ---------------------------------------------------------------------------------------------

function Enter-WacSingleInstance {
    <#
    .SYNOPSIS
        Takes the machine-wide mutation lock, or returns $null when another run already owns it.
    .DESCRIPTION
        Task Scheduler's IgnoreNew only stops a second SCHEDULED start; it does nothing about a
        manual run overlapping the scheduled one. The mutex name is a parameter so concurrent test
        suites can use a unique Local\ name instead of observing production's Global\ lock.
    #>
    param([string]$Name = 'Global\WindowsAutoCleanup')

    $mutex = $null
    try {
        $createdNew = $false
        $mutex = New-Object System.Threading.Mutex($false, $Name, [ref]$createdNew)
    }
    catch {
        return $null
    }

    $owned = $false
    try {
        $owned = $mutex.WaitOne(0)
    }
    catch {
        # AbandonedMutexException means a previous run died holding the lock and WE NOW OWN IT.
        # WaitOne is a .NET method, so the exception can arrive wrapped in a
        # MethodInvocationException; treating that as "not acquired" would make every run after a
        # crash exit with code 3 and never clean again.
        $exception = $_.Exception
        while ($exception -and
               ($exception -is [System.Management.Automation.MethodInvocationException]) -and
               $exception.InnerException) {
            $exception = $exception.InnerException
        }
        $owned = ($exception -is [System.Threading.AbandonedMutexException])
    }

    if (-not $owned) {
        try { $mutex.Dispose() } catch { $null = $_ }
        return $null
    }

    return $mutex
}

function Exit-WacSingleInstance {
    param($Mutex)

    if (-not $Mutex) { return }
    try { $Mutex.ReleaseMutex() } catch { $null = $_ }
    try { $Mutex.Dispose() } catch { $null = $_ }
}

# ---------------------------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------------------------

function Test-WacIsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-WacIsWindowsServer {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($null -ne $os.ProductType -and [int]$os.ProductType -ne 1) { return $true }
        if ($os.Caption -match '\bServer\b') { return $true }
    }
    catch {
        $null = $_
    }

    return $false
}

function Test-WacSystemDriveSupported {
    <#
    .SYNOPSIS
        The whole allow-list is written for C:. Anything else must fail loudly, not half-work.
    #>
    $systemDrive = Get-WacNormalizedPath -Path $env:SystemDrive
    return ($systemDrive -ieq $script:TargetDrive)
}

function Get-WacCanonicalPowerShellHost {
    <#
    .SYNOPSIS
        Returns a machine-wide, non-PATH-resolved PowerShell host path, or $null.
    .DESCRIPTION
        Get-Command searches PATH, which a standard user can extend, and can select a per-user or
        portable pwsh.exe. A host chosen that way must never be registered to run as SYSTEM, so only
        canonical machine locations are considered and each candidate must also pass the
        machine-trust check.
    #>
    param([switch]$SkipTrustCheck)

    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if ($env:ProgramFiles) {
        [void]$candidates.Add((Join-Path -Path $env:ProgramFiles -ChildPath 'PowerShell\7\pwsh.exe'))
    }
    [void]$candidates.Add((Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'))

    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        if ($SkipTrustCheck) { return $candidate }
        $trust = Test-WacPathIsMachineTrusted -Path $candidate
        if ($trust.IsTrusted) { return $candidate }
    }

    return $null
}

function Test-WacIsRealUserProfilePath {
    <#
    .SYNOPSIS
        Shared acceptance test for a candidate profile directory.
    .PARAMETER RequireUserHive
        Also demand ntuser.dat or ntuser.man. Microsoft's profile-cleanup sample uses that check to
        tell a real profile from an orphaned ProfileList entry, so it belongs to the registry
        FALLBACK path only. Win32_UserProfile already distinguishes real profiles through its
        documented Special property, and applying the hive check there would silently drop every
        profile whose root denies access to the current identity.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [switch]$RequireUserHive
    )

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $false }
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { return $false }
    if (-not [System.IO.Directory]::Exists((Get-WacLongPath -Path $normalized))) { return $false }
    if (Test-WacIsReparsePoint -Path $normalized) { return $false }

    $systemRoot = Get-WacNormalizedPath -Path $env:SystemRoot
    if ($systemRoot -and (Test-WacIsWithinRoot -ChildPath $normalized -RootPath $systemRoot)) { return $false }

    if (-not $RequireUserHive) { return $true }

    foreach ($hive in @('ntuser.dat', 'ntuser.man')) {
        # File.Exists returns false instead of writing to the error stream when access is denied,
        # which keeps a locked-down profile from polluting the caller's error output.
        if ([System.IO.File]::Exists((Get-WacLongPath -Path (Join-Path -Path $normalized -ChildPath $hive)))) { return $true }
    }

    return $false
}

function Get-WacUserProfilePath {
    <#
    .SYNOPSIS
        Real interactive user profile directories on C:.
    .DESCRIPTION
        Treating every directory under C:\Users as a profile is wrong: it picks up templates, stale
        folders and anything a user happened to create.
        Win32_UserProfile is the documented source, because its Special property is the supported way
        to separate real user profiles from service and system profiles. The ProfileList registry key
        is the fallback for hosts where the WMI class is unavailable; there the documented recipe is
        to skip the well-known SIDs S-1-5-18/19/20 and any '.bak' key, then confirm the profile with
        ntuser.dat/ntuser.man. The undocumented per-SID Flags/State values are never consulted.
    #>
    $results = New-Object 'System.Collections.Generic.List[string]'

    $addCandidate = {
        param([string]$Candidate, [bool]$RequireHive)

        $normalized = Get-WacNormalizedPath -Path $Candidate
        if (-not $normalized) { return }
        if (-not (Test-WacIsRealUserProfilePath -Path $normalized -RequireUserHive:$RequireHive)) { return }
        foreach ($existing in $results) {
            if ($existing -ieq $normalized) { return }
        }
        [void]$results.Add($normalized)
    }

    $wmiWorked = $false
    try {
        $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop)
        $wmiWorked = $true
        foreach ($userProfile in $profiles) {
            if ($userProfile.Special) { continue }
            & $addCandidate ([string]$userProfile.LocalPath) $false
        }
    }
    catch {
        Write-WacLog -Level DEBUG -Component 'Profiles' -Message 'Win32_UserProfile is unavailable; falling back to the ProfileList registry key.' -Data @{ error = $_.Exception.Message }
    }

    if ($wmiWorked -and $results.Count -gt 0) { return @($results.ToArray()) }

    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $wellKnown = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')

    try {
        $subKeys = @(Get-ChildItem -LiteralPath $key -ErrorAction Stop)
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Profiles' -Message 'Could not read the ProfileList registry key; no user profiles will be cleaned.' -Data @{ error = $_.Exception.Message }
        return @($results.ToArray())
    }

    foreach ($subKey in $subKeys) {
        $sid = Split-Path -Leaf $subKey.Name
        if ($sid.EndsWith('.bak', [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-WacLog -Level WARNING -Component 'Profiles' -Message 'ProfileList holds a .bak entry; that profile is skipped.' -Data @{ sid = $sid }
            continue
        }
        if ($wellKnown -contains $sid) { continue }

        $imagePath = $null
        try { $imagePath = [string](Get-ItemProperty -LiteralPath $subKey.PSPath -Name 'ProfileImagePath' -ErrorAction Stop).ProfileImagePath }
        catch { continue }

        if ([string]::IsNullOrWhiteSpace($imagePath)) { continue }
        & $addCandidate ([Environment]::ExpandEnvironmentVariables($imagePath)) $true
    }

    return @($results.ToArray())
}

function Get-WacFreeBytes {
    param([string]$Drive = 'C:')

    try {
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $Drive) -ErrorAction Stop
        if ($disk -and $null -ne $disk.FreeSpace) { return [int64]$disk.FreeSpace }
    }
    catch {
        try {
            $psDrive = Get-PSDrive -Name $Drive.TrimEnd(':') -ErrorAction Stop
            if ($psDrive -and $null -ne $psDrive.Free) { return [int64]$psDrive.Free }
        }
        catch {
            $null = $_
        }
    }

    return $null
}

function Format-WacBytes {
    param([Nullable[Int64]]$Bytes)

    if ($null -eq $Bytes) { return 'Unknown' }
    if ($Bytes -lt 0) { return ('{0:N0} bytes' -f $Bytes) }

    $value = [double]$Bytes
    $units = @('bytes', 'KB', 'MB', 'GB', 'TB')
    $index = 0

    while ($value -ge 1024 -and $index -lt ($units.Count - 1)) {
        $value = $value / 1024
        $index++
    }

    if ($index -eq 0) { return ('{0:N0} {1}' -f $value, $units[$index]) }
    return ('{0:N2} {1}' -f $value, $units[$index])
}

# ---------------------------------------------------------------------------------------------
# Machine trust
# ---------------------------------------------------------------------------------------------

function Test-WacPathIsMachineTrusted {
    <#
    .SYNOPSIS
        True when a standard user cannot modify the path, so SYSTEM may safely execute it.
    .DESCRIPTION
        This VERIFIES; it never mutates an ACL. Two conditions must both hold:
          * the owner is SYSTEM, Administrators, TrustedInstaller, or an administrator account -
            an owner implicitly keeps WRITE_DAC, so a user-owned file can be rewritten at any moment
            no matter how good its DACL looks;
          * no non-administrative principal holds a write-class right.
        Anything unreadable returns IsTrusted=$false so callers fail closed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{
        Path = $Path
        IsTrusted = $false
        Owner = $null
        Reason = $null
        UntrustedWriters = @()
    }

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized -or -not (Test-Path -LiteralPath $normalized)) {
        $result.Reason = 'Path does not exist.'
        return $result
    }

    try {
        $acl = Get-Acl -LiteralPath $normalized -ErrorAction Stop
    }
    catch {
        $result.Reason = ('Security descriptor is unreadable: {0}' -f $_.Exception.Message)
        return $result
    }

    $trustedOwnerSids = @(
        'S-1-5-18',                                                                   # SYSTEM
        'S-1-5-32-544',                                                               # BUILTIN\Administrators
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'              # TrustedInstaller
    )

    $ownerSid = $null
    try { $ownerSid = [string]$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { $ownerSid = $null }
    $result.Owner = $ownerSid

    $ownerTrusted = $false
    if ($ownerSid) {
        if ($trustedOwnerSids -contains $ownerSid) {
            $ownerTrusted = $true
        }
        else {
            # An individual administrator owning the path is acceptable: that account can already
            # rewrite any ACL on the machine, so it is not an escalation. A non-admin owner is not.
            $ownerTrusted = Test-WacSidIsAdministrator -Sid $ownerSid
        }
    }

    if (-not $ownerTrusted) {
        $result.Reason = ('Owner {0} is not an administrative principal; an owner implicitly keeps WRITE_DAC.' -f $ownerSid)
        return $result
    }

    # Only ATOMIC write-class bits belong in this mask. Composite values such as Modify and
    # FullControl also contain read and Synchronize bits, so OR-ing them in makes the mask match a
    # plain ReadAndExecute ACE and reports every System32 binary as untrusted. The composites are
    # still caught, because each of them contains these atomic bits.
    $writeRights = [int]([System.Security.AccessControl.FileSystemRights]::WriteData) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::AppendData) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::WriteAttributes) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::Delete) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::ChangePermissions) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::TakeOwnership)

    # GENERIC_WRITE (0x40000000) and GENERIC_ALL (0x10000000) are not translated into specific
    # rights inside a raw ACE, so a mask built only from specific rights cannot see them.
    $genericWriteRights = 0x40000000 -bor 0x10000000

    $untrusted = New-Object 'System.Collections.Generic.List[string]'

    try {
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    }
    catch {
        $result.Reason = ('Access rules are unreadable: {0}' -f $_.Exception.Message)
        return $result
    }

    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

        # An InheritOnly ACE grants nothing on THIS object; it is a template for children. Skipping
        # it is not a loophole, it is the definition. It matters because System32 and %ProgramFiles%
        # both carry an inherit-only CREATOR OWNER GENERIC_ALL entry, which would otherwise mark
        # every Windows directory untrusted. Whether a non-admin can create a child here - the thing
        # CREATOR OWNER would then apply to - is decided by the effective write rules below.
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        try { $propagation = $rule.PropagationFlags } catch { $propagation = [System.Security.AccessControl.PropagationFlags]::None }
        if (([int]$propagation -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }

        if ((([int]$rule.FileSystemRights -band [int]$writeRights) -eq 0) -and
            (([int]$rule.FileSystemRights -band [int]$genericWriteRights) -eq 0)) { continue }

        $sid = [string]$rule.IdentityReference.Value
        if ($trustedOwnerSids -contains $sid) { continue }
        if (Test-WacSidIsAdministrator -Sid $sid) { continue }

        [void]$untrusted.Add($sid)
    }

    if ($untrusted.Count -gt 0) {
        $result.UntrustedWriters = @($untrusted.ToArray() | Sort-Object -Unique)
        $result.Reason = ('Non-administrative principals hold write access: {0}' -f ($result.UntrustedWriters -join ', '))
        return $result
    }

    # A NULL DACL grants EVERYONE full access, and it surfaces here as zero access rules - which the
    # loop above would otherwise read as "nobody has write access". No real protected object has an
    # empty rule set, so treat it as unverifiable and fail closed.
    if ($rules.Count -eq 0) {
        $result.Reason = 'The security descriptor exposes no access rules, which is what a NULL DACL (everyone, full control) looks like.'
        return $result
    }

    $result.IsTrusted = $true
    $result.Reason = 'Owner and DACL are administrative only.'
    return $result
}

function Test-WacSidIsAdministrator {
    <#
    .SYNOPSIS
        True when the SID is a built-in administrative principal or a member of local Administrators.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Sid)

    if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }

    $alwaysAdmin = @(
        'S-1-5-18',        # SYSTEM
        'S-1-5-32-544',    # BUILTIN\Administrators
        'S-1-5-32-549',    # Server Operators
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
    )
    if ($alwaysAdmin -contains $Sid) { return $true }

    # Well-known groups that must never be treated as administrative.
    $neverAdmin = @(
        'S-1-1-0',      # Everyone
        'S-1-5-11',     # Authenticated Users
        'S-1-5-32-545', # BUILTIN\Users
        'S-1-5-32-546', # Guests
        'S-1-5-4',      # INTERACTIVE
        'S-1-5-113',    # Local account
        'S-1-3-0',      # CREATOR OWNER
        'S-1-5-32-547'  # Power Users
    )
    if ($neverAdmin -contains $Sid) { return $false }

    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        foreach ($member in $members) {
            if ([string]$member.SID.Value -ieq $Sid) { return $true }
        }
    }
    catch {
        # Get-LocalGroupMember is unavailable or failed (domain member, restricted SKU). Fall back to
        # the current elevated identity, which is who is installing.
        try {
            $current = [Security.Principal.WindowsIdentity]::GetCurrent()
            if ([string]$current.User.Value -ieq $Sid -and (Test-WacIsAdministrator)) { return $true }
        }
        catch {
            $null = $_
        }
    }

    return $false
}

Export-ModuleMember -Function @(
    'Initialize-WacNative',
    'Get-WacNormalizedPath', 'Get-WacLongPath', 'Get-WacTargetDrive',
    'Test-WacIsOnTargetDrive', 'Test-WacIsProtectedPath', 'Test-WacIsProtectedSubtree',
    'Test-WacIsSafeTargetPath', 'Test-WacIsWithinRoot',
    'Add-WacProtectedRoot', 'Clear-WacProtectedRoot',
    'Get-WacFinalPath', 'Test-WacPathResolvesToItself', 'Test-WacFinalPathMatches',
    'Get-WacFixedProtectedRoot', 'Test-WacIsReparsePoint',
    'Test-WacIsDeleteOnRebootAllowed', 'Register-WacDeleteOnReboot',
    'Get-WacIoFailureKind',
    'Get-WacDataRoot', 'Get-WacDeploymentRoot',
    'Initialize-WacRun', 'Write-WacLog', 'Close-WacLog', 'Get-WacLogPath', 'Get-WacExecutionId',
    'New-WacLogFile', 'Remove-WacOldLog',
    'Set-WacDeadline', 'Get-WacRemainingMs', 'Test-WacDeadlineExpired', 'Get-WacStepTimeoutMs',
    'ConvertTo-WacCommandLineArgument', 'ConvertTo-WacCommandLine',
    'ConvertTo-WacPowerShellLiteral', 'Get-WacRelaunchCommand', 'Get-WacRelaunchArgument',
    'Stop-WacProcessTree',
    'Invoke-WacProcess', 'Set-WacProcessInvoker', 'Get-WacProcessInvoker',
    'Enter-WacSingleInstance', 'Exit-WacSingleInstance',
    'Test-WacIsAdministrator', 'Test-WacIsWindowsServer', 'Test-WacSystemDriveSupported',
    'Get-WacCanonicalPowerShellHost', 'Get-WacUserProfilePath', 'Test-WacIsRealUserProfilePath', 'Get-WacFreeBytes', 'Format-WacBytes',
    'Test-WacPathIsMachineTrusted', 'Test-WacSidIsAdministrator'
)
