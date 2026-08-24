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
$script:ProcessHandleOpener = $null
$script:ProtectedRoots      = New-Object 'System.Collections.Generic.List[string]'
$script:PendingDeleteWarned = $false
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

# Captured at import: inside a module $PSCommandPath is this .psm1 (measured on both hosts), and
# Invoke-WacBounded needs a real path to import into the runspace it creates.
$script:CoreModulePath      = $PSCommandPath

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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    private const uint FILE_READ_ATTRIBUTES         = 0x0080;
    private const uint FILE_SHARE_READ_WRITE_DELETE = 0x0007;
    private const uint OPEN_EXISTING                = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_NAME_NORMALIZED         = 0x00000000;
    private const uint VOLUME_NAME_DOS              = 0x00000000;
    private const int  MOVEFILE_DELAY_UNTIL_REBOOT  = 0x00000004;
    private const int  SYNCHRONIZE                  = 0x00100000;
    private const int  PROCESS_TERMINATE             = 0x00000001;

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

    // Opens a handle BOUND to whatever owns 'processId' at this instant. Every later question -
    // has it exited yet, terminate it - is then asked of the HANDLE, so the answer keeps referring
    // to the process that was opened however Windows later reuses the number.
    //
    // The mask is exactly the two rights used: SYNCHRONIZE to wait on it and PROCESS_TERMINATE to
    // kill it. PROCESS_QUERY_LIMITED_INFORMATION is deliberately NOT requested - nothing here reads
    // an exit code, the wait is the exit test, and every unnecessary right is one more reason for
    // the OS to refuse an open it would otherwise have granted.
    //
    // Returns 0 with the handle set, otherwise the Win32 error with handle = IntPtr.Zero. Measured
    // identically on both shipped hosts: 87 ERROR_INVALID_PARAMETER when nothing owns the id
    // (0, -1, 999999, 4194303 and 2147483647 all gave 87) and 5 ERROR_ACCESS_DENIED for a protected
    // process (PID 4, csrss). A process that has exited while someone still holds a handle to it
    // opens SUCCESSFULLY and its handle is already signalled - which is how "it was gone before we
    // asked" is told apart from "nothing owns this id".
    public static int OpenProcessForTermination(int processId, out IntPtr handle)
    {
        handle = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, false, processId);
        if (handle == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
        return 0;
    }

    // 0 is WAIT_OBJECT_0: the process this handle is bound to has exited. 258 is WAIT_TIMEOUT.
    public static int WaitForProcessExit(IntPtr handle, int milliseconds)
    {
        return WaitForSingleObject(handle, milliseconds);
    }

    // Documented as asynchronous: it ASKS for termination and returns before the process is gone,
    // which is why the caller must still wait on the handle afterwards.
    public static bool TerminateBoundProcess(IntPtr handle)
    {
        return TerminateProcess(handle, 1);
    }

    public static void CloseProcessHandle(IntPtr handle)
    {
        if (handle != IntPtr.Zero) { CloseHandle(handle); }
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

function Set-WacProcessHandleOpener {
    <#
    .SYNOPSIS
        Replaces the OpenProcess call Stop-WacProcessTree binds its handle with. $null restores it.
    .DESCRIPTION
        The scriptblock receives (ProcessId) and must return an object exposing Handle and
        Win32Error, in the same spirit as Set-WacProcessInvoker and Set-WacLogWriter.

        It exists for exactly one arm: "the id exists but the OS will not hand over a handle". Only
        a protected process produces that for real - PID 4 and csrss measured 5 ERROR_ACCESS_DENIED
        on both hosts - and a case that asks the shipped code to terminate one of those is not
        something to run on a workstation, at any privilege level.

        Inject a FAILURE (Handle = IntPtr.Zero) and nothing else: a fabricated non-zero handle is
        waited on, terminated and closed for real.
    #>
    param([scriptblock]$Opener)
    $script:ProcessHandleOpener = $Opener
}

function Stop-WacProcessTree {
    <#
    .SYNOPSIS
        Kills a process AND its children, and returns $true only when the target is PROVEN gone.
    .DESCRIPTION
        The old body returned taskkill's WaitForExit(): its EXIT CODE was never read and the target
        was never re-checked, so "taskkill ran" was reported as "the process is dead". Measured on
        both shipped hosts, taskkill /T /F /PID returns

            0    SUCCESS: the process ... has been terminated
            128  ERROR: The process "<pid>" not found
            255  ERROR: ... could not be terminated (critical system process)

        and all three exited, so all three used to return $true. A failed kill was indistinguishable
        from a real one, and Invoke-WacProcess went on to report a bounded, cleaned-up timeout while
        the tool it was supposed to have killed kept running.

        The verdict comes from a kernel handle OPENED AT ENTRY and held until this call returns, and
        that is meant literally. System.Diagnostics.Process keeps no handle of its own unless it
        STARTED the process: HasExited, WaitForExit and Kill each re-open the raw id and close it
        again, so a Process object handed back by Get-Process proves nothing the replaced code did
        not - it was the same reuse window under a better name. Waiting on, and terminating through,
        ONE bound handle is what keeps every answer attached to the process that was opened,
        whatever Windows later does with the number.

        That is also why Get-Process is gone from this path. It answers about an id, it cannot see a
        process that exited while a handle to it is still open, and its failure does not say WHY.
        OpenProcess does: 87 ERROR_INVALID_PARAMETER means nothing owns the id, which IS the outcome
        the caller wanted; anything else - 5 ERROR_ACCESS_DENIED for a protected process - means the
        state could not be read at all. Unreadable state is never reported as proof here, the same
        way Test-WacIsReparsePoint refuses to call an unreadable descriptor safe.

        taskkill's exit code is read and logged because it is the only evidence of WHY a kill did
        not take (255 refused vs 128 raced to exit), but it is never the verdict on its own.
    .OUTPUTS
        [bool] $true only when the target is known to have exited.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [int]$TimeoutMs = 10000
    )

    if ($TimeoutMs -le 0) { $TimeoutMs = 1 }

    $bound = [IntPtr]::Zero
    # -1 is not a Win32 code. It stands for "no handle could be bound at all", which is a different
    # claim from "nothing owns this id" and must never be reported as one.
    $openError = -1
    if ($script:ProcessHandleOpener) {
        $injected = & $script:ProcessHandleOpener $ProcessId
        $bound = [IntPtr]$injected.Handle
        $openError = [int]$injected.Win32Error
    }
    elseif (Initialize-WacNative) {
        $openError = [WacNative]::OpenProcessForTermination($ProcessId, [ref]$bound)
    }

    if ($bound -eq [IntPtr]::Zero) {
        # ERROR_INVALID_PARAMETER: nothing owns this id, so the target is gone and the caller got
        # what it asked for. Every OTHER failure is unverifiable, and unverifiable is not success.
        if ($openError -eq 87) { return $true }

        Write-WacLog -Level WARNING -Component 'Process' -Message 'The target could not be opened, so termination is unverifiable.' -Data @{
            pid = $ProcessId
            win32Error = $openError
        }
        return $false
    }

    try {
        # Already gone before anything was asked of it. The handle is what makes this the TARGET's
        # own exit rather than a later occupant of the number, so no kill is needed or attempted.
        if ([WacNative]::WaitForProcessExit($bound, 0) -eq 0) { return $true }

        $exitCode = $null
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
                if ($killer.WaitForExit($TimeoutMs)) {
                    try { $exitCode = [int]$killer.ExitCode } catch { $exitCode = $null }
                }
                else {
                    # taskkill itself overran its bound. Killing it directly is not recursion: it is
                    # our own child and has no tree of its own worth walking.
                    try { $killer.Kill() } catch { $null = $_ }
                }
                try { $killer.Dispose() } catch { $null = $_ }
            }
        }
        catch {
            $exitCode = $null
        }

        # The proof. taskkill returns once it has ASKED for termination, so the target may still be
        # tearing down; waiting on the bound handle is the deterministic signal that it finished.
        $verified = ([WacNative]::WaitForProcessExit($bound, $TimeoutMs) -eq 0)

        if (-not $verified) {
            # The escalation goes through the SAME handle rather than the id, so it cannot land on
            # whatever inherited the number while taskkill was running.
            [void][WacNative]::TerminateBoundProcess($bound)
            $verified = ([WacNative]::WaitForProcessExit($bound, $TimeoutMs) -eq 0)
        }

        if (-not $verified) {
            Write-WacLog -Level WARNING -Component 'Process' -Message 'Termination could not be established; the target may still be running.' -Data @{
                pid = $ProcessId
                taskkillExit = $(if ($null -eq $exitCode) { 'none' } else { [string]$exitCode })
            }
        }

        return $verified
    }
    finally {
        [WacNative]::CloseProcessHandle($bound)
    }
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
# Bounded in-process work
# ---------------------------------------------------------------------------------------------

function Invoke-WacBounded {
    <#
    .SYNOPSIS
        Runs IN-PROCESS work under a real wall-clock bound and returns a shared-contract outcome.
    .DESCRIPTION
        The run budget used to cover only external tools and the traversal loop. Everything else -
        the Delivery Optimization cmdlet, a CIM/WMI profile query, registry work, a Recycle Bin
        scan, target construction, a deployment walk - runs inside this process, and a call that
        blocks in the OS blocks every deadline check sitting behind it. A 210-minute budget can be
        blown by one of them without a single clock read.

        Cooperative checking cannot fix that, because the thread never comes back to check. So the
        work runs in its own runspace and the caller waits on a handle: expiry is a real bound, not
        a request. Measured cost of the runspace on BOTH shipped hosts: ~80 ms bare, ~100 ms with
        this module imported into it. That is fine per PHASE and far too expensive per file - this
        is for phase-level blocking calls, never for the traversal loop's inner steps.

        Expiry is NOT success. The outcome is 'Incomplete', which the shared result contract maps to
        exit code 6. An exhausted run budget also refuses to START the work, which is what "stop
        scheduling new work" means; a bounded rollback that must still run after expiry passes
        -IgnoreRunBudget and supplies its own explicit bound.

        The pipeline holds exactly ONE AddScript, and that is not cosmetic. Arming strict mode as a
        separate first statement was tried and had to be rejected on measured evidence:

          * AddScript / AddStatement / AddScript turns a THROW inside the block into an ordinary
            error-stream record instead of an exception out of EndInvoke, so a broken step reported
            Succeeded;
          * with a batched pipeline, abandoning a blocked runspace crashes the HOST at process exit
            when the worker wakes into a closing runspace - measured on both hosts, pwsh exited
            -532462766 (unhandled InvalidRunspaceStateException from BatchInvocationWorkItem) and
            Windows PowerShell 5.1 exited 2. A single AddScript exits 0 in the same scenario.

        Prefixing the block's own text is not an alternative either: a param() block has to be the
        first statement in a script. So a bounded block runs WITHOUT strict mode, which is one more
        reason to keep it down to the single blocking call and leave the logic outside.

        A terminating error is Failed. A non-terminating one leaves Outcome Succeeded with
        HadErrors set and Error populated - reported, never swallowed, and the caller decides.

        ponytail: a runspace whose thread is stuck inside a blocking NATIVE call is abandoned rather
        than aborted - PowerShell.Stop() cannot interrupt one and Thread.Abort does not exist on
        .NET Core. Measured cost of one abandoned call: 2-3 threads until the process exits. That is
        the right trade for a tool that runs once a day and then leaves; if a caller ever abandons
        many, move that work to a child process and kill it with Stop-WacProcessTree instead.
    .OUTPUTS
        Outcome (Succeeded | Incomplete | Failed), Started, TimedOut, Output, HadErrors, Error,
        DurationMs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [AllowEmptyCollection()][object[]]$ArgumentList = @(),
        [AllowEmptyCollection()][string[]]$ImportModule = @(),
        [string]$Component = 'Bounded',
        [switch]$IgnoreRunBudget
    )

    $budgetMs = $TimeoutMs
    if (-not $IgnoreRunBudget) { $budgetMs = Get-WacStepTimeoutMs -RequestedMs $TimeoutMs }

    if ($budgetMs -le 0) {
        Write-WacLog -Level WARNING -Component $Component -Message 'Run budget exhausted before the work could be scheduled.' -Data @{ requestedMs = $TimeoutMs }
        return [PSCustomObject]@{
            Outcome = 'Incomplete'; Started = $false; TimedOut = $true
            Output = @(); HadErrors = $false
            Error = 'The run budget expired before this work was scheduled.'
            DurationMs = 0
        }
    }

    $modules = New-Object 'System.Collections.Generic.List[string]'
    if ($script:CoreModulePath) { [void]$modules.Add($script:CoreModulePath) }
    foreach ($module in $ImportModule) {
        if (-not [string]::IsNullOrWhiteSpace($module)) { [void]$modules.Add($module) }
    }

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $runspace = $null
    $shell = $null
    $abandoned = $false

    try {
        $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
        if ($modules.Count -gt 0) { $state.ImportPSModule([string[]]$modules.ToArray()) }

        $runspace = [runspacefactory]::CreateRunspace($state)
        $runspace.Open()

        $shell = [powershell]::Create()
        $shell.Runspace = $runspace
        [void]$shell.AddScript($ScriptBlock.ToString())
        foreach ($argument in $ArgumentList) { [void]$shell.AddArgument($argument) }

        $handle = $shell.BeginInvoke()

        if (-not $handle.AsyncWaitHandle.WaitOne($budgetMs)) {
            $abandoned = $true
            try { [void]$shell.BeginStop($null, $null) } catch { $null = $_ }
            $watch.Stop()

            Write-WacLog -Level WARNING -Component $Component -Message 'In-process work exceeded its bound and was abandoned.' -Data @{ budgetMs = $budgetMs }
            return [PSCustomObject]@{
                Outcome = 'Incomplete'; Started = $true; TimedOut = $true
                Output = @(); HadErrors = $false
                Error = ('The work did not finish within {0} ms.' -f $budgetMs)
                DurationMs = [int]$watch.Elapsed.TotalMilliseconds
            }
        }

        $output = @()
        $failure = $null
        try {
            $output = @($shell.EndInvoke($handle))
        }
        catch {
            # A terminating error inside the block surfaces HERE, wrapped, not in the error stream.
            $failure = [string]$_.Exception.Message
        }

        $errors = @()
        try { $errors = @($shell.Streams.Error) } catch { $errors = @() }

        $watch.Stop()
        $outcome = 'Succeeded'
        if ($failure) { $outcome = 'Failed' }

        $errorText = $failure
        if (-not $errorText -and $errors.Count -gt 0) {
            $errorText = (@($errors | ForEach-Object { [string]$_ }) -join '; ')
        }

        return [PSCustomObject]@{
            Outcome = $outcome; Started = $true; TimedOut = $false
            Output = $output; HadErrors = ($errors.Count -gt 0)
            Error = $errorText
            DurationMs = [int]$watch.Elapsed.TotalMilliseconds
        }
    }
    catch {
        $watch.Stop()
        Write-WacLog -Level WARNING -Component $Component -Message 'Bounded work could not be started.' -Data @{ error = $_.Exception.Message }
        return [PSCustomObject]@{
            Outcome = 'Failed'; Started = $false; TimedOut = $false
            Output = @(); HadErrors = $true
            Error = [string]$_.Exception.Message
            DurationMs = [int]$watch.Elapsed.TotalMilliseconds
        }
    }
    finally {
        # Disposing either object waits for the pipeline, so an abandoned runspace must be left
        # alone: cleaning it up here would reintroduce exactly the unbounded wait this function
        # exists to prevent.
        if (-not $abandoned) {
            if ($shell) { try { $shell.Dispose() } catch { $null = $_ } }
            if ($runspace) { try { $runspace.Dispose() } catch { $null = $_ } }
        }
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

    # Zero rules is an EMPTY DACL, not a NULL one. Measured through this exact managed API on both
    # shipped hosts: 'O:BAG:BAD:NO_ACCESS_CONTROL' (a real NULL DACL, which grants everyone full
    # access) comes back as ONE rule, Allow S-1-1-0 0xFFFFFFFF, so the loop above already refuses it
    # on the write bits. It is 'O:BAG:BAD:' - a present but empty DACL - that yields zero rules.
    # Either way there is nothing here to evaluate, and no real protected object looks like this, so
    # fail closed rather than read an empty rule set as "nobody has write access".
    if ($rules.Count -eq 0) {
        $result.Reason = 'The security descriptor exposes no access rules to evaluate.'
        return $result
    }

    $result.IsTrusted = $true
    $result.Reason = 'Owner and DACL are administrative only.'
    return $result
}

function Test-WacAncestorAclIsAdministrative {
    <#
    .SYNOPSIS
        The ancestor trust rule, taken over a descriptor the caller already holds.
    .DESCRIPTION
        An ancestor is NOT asked the leaf's question. Test-WacPathIsMachineTrusted asks "can a
        non-administrator write anything here at all", which is right for the directory that holds
        the audit log and wrong one level up: the default DACL of C:\ grants Authenticated Users
        CreateDirectories, so the strict question marks every volume root untrusted and no state
        root on a healthy Windows install would ever pass.

        Creating a NEW name beside an existing one cannot replace the existing one. Redirecting or
        removing an existing child needs one of Delete, DeleteSubdirectoriesAndFiles,
        ChangePermissions, TakeOwnership, or GENERIC_ALL (which is not decomposed into specific
        rights inside a raw ACE). GENERIC_WRITE is deliberately absent: on a directory it maps to
        add-file, add-subdirectory, write-EA, write-attributes and READ_CONTROL, none of which
        reaches an existing child.

        The OWNER test stays strict, because an owner implicitly keeps WRITE_DAC and can grant
        itself any of the above at any moment.
    .OUTPUTS
        IsTrusted / Owner / Reason.
    #>
    param([Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$Acl)

    $verdict = [PSCustomObject]@{ IsTrusted = $false; Owner = $null; Reason = $null }

    $ownerSid = $null
    try { $ownerSid = [string]$Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { $ownerSid = $null }
    $verdict.Owner = $ownerSid

    if (-not (Test-WacSidIsAdministrator -Sid ([string]$ownerSid))) {
        $verdict.Reason = ('Owner {0} is not an administrative principal; an owner implicitly keeps WRITE_DAC.' -f $ownerSid)
        return $verdict
    }

    $replaceRights = [int]([System.Security.AccessControl.FileSystemRights]::Delete) -bor
                     [int]([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -bor
                     [int]([System.Security.AccessControl.FileSystemRights]::ChangePermissions) -bor
                     [int]([System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    $genericAll = 0x10000000

    $rules = $null
    try { $rules = @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) }
    catch {
        $verdict.Reason = ('Access rules are unreadable: {0}' -f $_.Exception.Message)
        return $verdict
    }

    if ($rules.Count -eq 0) {
        $verdict.Reason = 'The security descriptor exposes no access rules to evaluate.'
        return $verdict
    }

    $writers = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        try { $propagation = $rule.PropagationFlags } catch { $propagation = [System.Security.AccessControl.PropagationFlags]::None }
        if (([int]$propagation -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }

        if ((([int]$rule.FileSystemRights -band $replaceRights) -eq 0) -and
            (([int]$rule.FileSystemRights -band $genericAll) -eq 0)) { continue }

        $sid = [string]$rule.IdentityReference.Value
        if (Test-WacSidIsAdministrator -Sid $sid) { continue }

        [void]$writers.Add($sid)
    }

    if ($writers.Count -gt 0) {
        $verdict.Reason = ('Non-administrative principals can replace children here: {0}' -f
            ((@($writers.ToArray() | Sort-Object -Unique)) -join ', '))
        return $verdict
    }

    $verdict.IsTrusted = $true
    $verdict.Reason = 'Owner and DACL are administrative only.'
    return $verdict
}

function Test-WacStatePathIsTrusted {
    <#
    .SYNOPSIS
        Proves a log / state / driver-backup path is on a local fixed disk, free of reparse points,
        and writable only by administrative principals - itself AND every ancestor up to the root.
    .DESCRIPTION
        %ProgramData%\WindowsAutoCleanup holds the audit log a SYSTEM task writes and the driver
        backups a restore would read. Checking the leaf alone proves less than it looks: write
        access to a PARENT is enough to rename the whole directory aside and drop a different one
        in its place, and a reparse point anywhere in the chain redirects the whole thing.

        The question asked of every level - leaf included - is "can a non-administrator REPLACE,
        delete or redirect this", not the stricter "can a non-administrator write anything here at
        all" that Test-WacPathIsMachineTrusted asks of executable code. Measured on a stock Windows
        11 install: C:\ProgramData grants BUILTIN\Users (S-1-5-32-545) create-file and
        create-folder, and that ACE is inherited by %ProgramData%\WindowsAutoCleanup. Since this
        project is forbidden to rewrite an ACL, the strict question would answer "untrusted" on
        every default machine forever, which is not a finding - it is a check nobody can act on.

        That residual risk is REPORTED rather than hidden: Writers lists the non-administrative
        principals that can create new content in the leaf, so a caller that needs the stricter
        guarantee - driver backups being read back during a restore, for instance - can require it
        to be empty without this function having to refuse every run to say so.

        Nothing here is swallowed. An unreadable descriptor, a reparse point, an unresolvable
        ancestor and a chain longer than -MaxDepth are all recorded as FAILURES and all leave
        IsTrusted false, because every one of them means the trust question was not answered - and
        an unanswered security question is not a yes.

        A path that does not exist yet is legitimate on a first run, so the nearest existing
        ancestor is verified instead and Reason says so. That is the directory the leaf will be
        created in, which is the thing that has to be trustworthy.
    .OUTPUTS
        Path (what was actually verified), IsTrusted, Reason, Checked, Failures, Writers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [ValidateRange(1, 128)][int]$MaxDepth = 64
    )

    $result = [PSCustomObject]@{
        Path = $Path
        IsTrusted = $false
        Reason = $null
        Checked = @()
        Failures = @()
        Writers = @()
    }

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) {
        $result.Reason = 'The path is not a usable local drive path.'
        return $result
    }

    $drive = $null
    try { $drive = New-Object System.IO.DriveInfo($normalized.Substring(0, 2)) } catch { $drive = $null }
    if (-not $drive) {
        $result.Reason = ('The volume for {0} could not be inspected.' -f $normalized)
        return $result
    }
    if (-not $drive.IsReady -or [string]$drive.DriveType -ne 'Fixed') {
        $result.Reason = ('{0} is not on a ready local fixed disk (DriveType={1}).' -f $normalized, $drive.DriveType)
        return $result
    }

    # Walk down to the first component that exists. Bounded by MaxDepth like the walk back up, so a
    # pathological path cannot spin here either.
    $existing = $normalized
    $descend = 0
    while (-not (Test-Path -LiteralPath $existing)) {
        $descend++
        if ($descend -gt $MaxDepth) {
            $result.Reason = ('No existing ancestor of {0} was found within {1} levels.' -f $normalized, $MaxDepth)
            return $result
        }

        $parent = [System.IO.Path]::GetDirectoryName($existing)
        if ([string]::IsNullOrEmpty($parent)) {
            $result.Reason = ('No existing ancestor of {0} exists.' -f $normalized)
            return $result
        }
        $existing = Get-WacNormalizedPath -Path $parent
        if (-not $existing) {
            $result.Reason = ('An ancestor of {0} could not be canonicalised.' -f $normalized)
            return $result
        }
    }

    $result.Path = $existing
    $checked = New-Object 'System.Collections.Generic.List[string]'
    $failures = New-Object 'System.Collections.Generic.List[object]'

    $current = $existing
    $isLeaf = $true
    $depth = 0
    $reachedRoot = $false

    while ($true) {
        $depth++
        if ($depth -gt $MaxDepth) {
            [void]$failures.Add([PSCustomObject]@{
                Path = $current
                Reason = ('The ancestor chain exceeded the {0}-level depth limit before reaching the volume root.' -f $MaxDepth)
            })
            break
        }

        $probe = $current
        if ($probe -match '^[A-Za-z]:$') { $probe = $probe + '\' }
        [void]$checked.Add($probe)

        if (Test-WacIsReparsePoint -Path $probe) {
            [void]$failures.Add([PSCustomObject]@{
                Path = $probe
                Reason = 'The path is a reparse point, or its attributes are unreadable; either way it can redirect elsewhere.'
            })
        }
        else {
            # Get-Acl on a bare 'X:' is DRIVE-RELATIVE and returns the session's current directory
            # on that drive, which is why $probe was re-rooted to 'X:\' above.
            $acl = $null
            try { $acl = Get-Acl -LiteralPath $probe -ErrorAction Stop }
            catch {
                [void]$failures.Add([PSCustomObject]@{
                    Path = $probe
                    Reason = ('Security descriptor is unreadable: {0}' -f $_.Exception.Message)
                })
            }

            if ($acl) {
                $verdict = Test-WacAncestorAclIsAdministrative -Acl $acl
                if (-not $verdict.IsTrusted) {
                    [void]$failures.Add([PSCustomObject]@{ Path = $probe; Reason = $verdict.Reason })
                }
            }

            # The stricter question is asked of the leaf only, and only to REPORT the answer.
            if ($isLeaf) {
                $strict = Test-WacPathIsMachineTrusted -Path $probe
                if (-not $strict.IsTrusted) { $result.Writers = @($strict.UntrustedWriters) }
            }
        }

        if ($current -match '^[A-Za-z]:$') { $reachedRoot = $true; break }

        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent)) { $reachedRoot = $true; break }

        $next = Get-WacNormalizedPath -Path $parent
        if (-not $next -or $next -ieq $current) {
            [void]$failures.Add([PSCustomObject]@{
                Path = $current
                Reason = 'The ancestor chain could not be followed to the volume root.'
            })
            break
        }

        $current = $next
        $isLeaf = $false
    }

    $result.Checked = @($checked.ToArray())
    $result.Failures = @($failures.ToArray())

    if ($failures.Count -gt 0) {
        $result.Reason = (@($failures.ToArray() | ForEach-Object { '{0}: {1}' -f $_.Path, $_.Reason }) -join ' | ')
        return $result
    }

    if (-not $reachedRoot) {
        $result.Reason = 'The ancestor chain did not reach the volume root.'
        return $result
    }

    $result.IsTrusted = $true
    $result.Reason = ('{0} and all {1} ancestors are local, non-reparse, and cannot be replaced by a non-administrator.' -f $existing, ($checked.Count - 1))
    if ($result.Writers.Count -gt 0) {
        $result.Reason = ('{0} Non-administrative principals can still create content in it: {1}' -f
            $result.Reason, ($result.Writers -join ', '))
    }
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
    'Get-WacLogDirectory', 'Get-WacLogHealth', 'Get-WacStateTrust',
    'Set-WacLogFallbackWriter', 'Set-WacLogWriter',
    'New-WacLogFile', 'Remove-WacOldLog',
    'Set-WacDeadline', 'Get-WacRemainingMs', 'Test-WacDeadlineExpired', 'Get-WacStepTimeoutMs',
    'ConvertTo-WacCommandLineArgument', 'ConvertTo-WacCommandLine',
    'ConvertTo-WacPowerShellLiteral', 'Get-WacRelaunchCommand', 'Get-WacRelaunchArgument',
    'Stop-WacProcessTree', 'Set-WacProcessHandleOpener',
    'Invoke-WacProcess', 'Set-WacProcessInvoker', 'Get-WacProcessInvoker', 'Invoke-WacBounded',
    'Enter-WacSingleInstance', 'Exit-WacSingleInstance',
    'Test-WacIsAdministrator', 'Test-WacIsWindowsServer', 'Test-WacSystemDriveSupported',
    'Get-WacCanonicalPowerShellHost', 'Get-WacUserProfilePath', 'Test-WacIsRealUserProfilePath', 'Get-WacFreeBytes', 'Format-WacBytes',
    'Test-WacPathIsMachineTrusted', 'Test-WacSidIsAdministrator', 'Test-WacStatePathIsTrusted'
)
