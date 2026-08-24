#Requires -Version 5.1
<#
.SYNOPSIS
    Assertions, disposable sandboxes and the case runner shared by every Tests\*.Tests.ps1 suite.

.DESCRIPTION
    Dot-sourced rather than imported so a suite keeps one script scope and can reach module state
    directly. Pester is deliberately not a dependency: only 3.4.0 is installed on the development
    machine and hosted CI images drift, so the suites must rely on nothing beyond the two shipped
    PowerShell hosts.

    A suite is a plain script: dot-source this file, declare Test-Case blocks, call Complete-TestRun.
    Every case prints its line the moment it finishes, which is also what gives Run-Tests.ps1 its
    idle-progress signal.

    A case that cannot run here calls Set-TestSkipped with a reason. There is deliberately no
    outcome between "proved something" and "did not": a skip is its own outcome, it is excluded
    from passed=, and it makes the suite exit 3.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:WacCases     = New-Object 'System.Collections.Generic.List[object]'
$script:WacSandboxes = New-Object 'System.Collections.Generic.List[string]'

# Prefix that marks a thrown skip. Test-Case checks for it BEFORE it treats a caught exception as a
# failure, which is the whole mechanism: a skip cannot reach the pass branch by accident.
$script:WacSkipToken = 'WAC-TEST-SKIP: '

function Get-WacTestLocation {
    param([Parameter(Mandatory = $true)]$Invocation)

    $file = '<inline>'
    if ($Invocation.ScriptName) { $file = Split-Path -Leaf $Invocation.ScriptName }
    return ('{0}:{1}' -f $file, $Invocation.ScriptLineNumber)
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Condition,
        [string]$Message = 'Expected a true value.'
    )

    if (-not $Condition) { throw ('{0} {1}' -f (Get-WacTestLocation $MyInvocation), $Message) }
}

function Assert-False {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Condition,
        [string]$Message = 'Expected a false value.'
    )

    if ($Condition) { throw ('{0} {1}' -f (Get-WacTestLocation $MyInvocation), $Message) }
}

function Assert-Equal {
    <#
    .SYNOPSIS
        Compares two values. Strings compare ORDINALLY, because PowerShell's -eq is case-insensitive
        and would silently pass a quoting or casing regression.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()]$Expected,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()]$Actual,
        [string]$Message = ''
    )

    if ($Expected -is [string] -and $Actual -is [string]) {
        $equal = [string]::Equals($Expected, $Actual, [System.StringComparison]::Ordinal)
    }
    elseif ($null -eq $Expected -or $null -eq $Actual) {
        $equal = ($null -eq $Expected -and $null -eq $Actual)
    }
    else {
        $equal = ($Expected -eq $Actual)
    }

    if (-not $equal) {
        $detail = 'expected [{0}] but got [{1}]' -f $Expected, $Actual
        if ($Message) { $detail = '{0} -- {1}' -f $Message, $detail }
        throw ('{0} {1}' -f (Get-WacTestLocation $MyInvocation), $detail)
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [string]$Pattern,
        [string]$Message = 'Expected a terminating error.'
    )

    $caught = $null
    try { & $ScriptBlock | Out-Null }
    catch { $caught = $_ }

    if (-not $caught) { throw ('{0} {1}' -f (Get-WacTestLocation $MyInvocation), $Message) }
    if ($Pattern -and ([string]$caught) -notmatch $Pattern) {
        throw ('{0} error did not match /{1}/: {2}' -f (Get-WacTestLocation $MyInvocation), $Pattern, $caught)
    }
}

function Set-TestSkipped {
    <#
    .SYNOPSIS
        Declares the running case UNABLE TO RUN here, with a reason. Never counted as a pass.
    .DESCRIPTION
        It THROWS rather than returns on purpose. A body that called this and then carried on would
        assert under the very assumption it had just declared invalid, which is how the previous
        shape of this suite reported green on a GitHub runner while asserting nothing.

        The reason is mandatory because a skip fails the suite (exit 3): whoever reads that failure
        needs to know which capability was missing, not merely that something was not run.
    #>
    param([Parameter(Mandatory = $true)][string]$Reason)

    throw ('{0}{1}' -f $script:WacSkipToken, $Reason)
}

# ---------------------------------------------------------------------------------------------
# Launching a genuinely unprivileged child WITHOUT creating a console
# ---------------------------------------------------------------------------------------------

function Initialize-WacTestLaunch {
    <#
    .SYNOPSIS
        Compiles the restricted-token launcher once per process. $false means it is unavailable.
    .DESCRIPTION
        Same shape as Initialize-WacNative in the shipped module: the type is added at most once,
        because Add-Type cannot redefine a type in a process and this file is dot-sourced by every
        suite - and, in a suite that dot-sources it twice, twice.
    #>
    if ('WacTestLaunch' -as [type]) { return $true }

    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

// Starts a child under a SAFER "normal user" token with CREATE_NO_WINDOW.
//
// WHY THIS EXISTS AT ALL. runas.exe /trustlevel:0x20000 does the same token work, but it composes
// its child's startup info itself, so the CreateNoWindow a caller sets on the ProcessStartInfo for
// runas never reaches the process runas launches. That child therefore gets a real console; when
// the machine's default terminal is Windows Terminal (HKCU\Console\%%Startup\DelegationTerminal),
// the console is handed to WindowsTerminal.exe and a window belonging to THAT process pops to the
// foreground and steals focus. -WindowStyle Hidden cannot fix it either: it hides the PowerShell
// host's own window, and under Windows Terminal the host does not own the window. The only fix is
// to never create a console, which means creating the token here and passing CREATE_NO_WINDOW to
// CreateProcessAsUser ourselves.
public static class WacTestLaunch
{
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SaferCreateLevel(
        uint dwScopeId, uint dwLevelId, uint OpenFlags, out IntPtr pLevelHandle, IntPtr lpReserved);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SaferComputeTokenFromLevel(
        IntPtr LevelHandle, IntPtr InAccessToken, out IntPtr OutAccessToken, uint dwFlags, IntPtr lpReserved);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SaferCloseLevel(IntPtr hLevelHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUserW(
        IntPtr hToken, string lpApplicationName, StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    private const uint SAFER_SCOPEID_USER        = 2;
    private const uint SAFER_LEVELID_NORMALUSER  = 0x20000;
    private const uint SAFER_LEVEL_OPEN          = 1;
    private const uint CREATE_NO_WINDOW          = 0x08000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint WAIT_OBJECT_0             = 0;

    // A live handle on the child. Holding it is what stops Windows reissuing the id to an unrelated
    // process, so the caller may kill this id's tree without proving the identity first.
    public sealed class Child : IDisposable
    {
        private IntPtr handle;
        private readonly int id;

        internal Child(IntPtr processHandle, int processId)
        {
            handle = processHandle;
            id = processId;
        }

        public int Id { get { return id; } }

        public bool WaitForExit(int milliseconds)
        {
            return WaitForSingleObject(handle, (uint)milliseconds) == WAIT_OBJECT_0;
        }

        // -1 when the code cannot be read; every real caller checks WaitForExit first.
        public int ExitCode
        {
            get
            {
                uint code;
                if (!GetExitCodeProcess(handle, out code)) { return -1; }
                return unchecked((int)code);
            }
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
                handle = IntPtr.Zero;
            }
        }
    }

    public sealed class Result
    {
        public Child Child;
        public string Error;
    }

    // Sorted because a CreateProcess environment block is documented as sorted; the block is one
    // buffer of "name=value\0" runs closed by a second \0.
    private static IntPtr BuildEnvironment(string[] pairs)
    {
        if (pairs == null || pairs.Length == 0) { return IntPtr.Zero; }

        string[] sorted = (string[])pairs.Clone();
        Array.Sort(sorted, StringComparer.OrdinalIgnoreCase);

        StringBuilder block = new StringBuilder();
        foreach (string pair in sorted) { block.Append(pair).Append('\0'); }
        block.Append('\0');
        return Marshal.StringToHGlobalUni(block.ToString());
    }

    public static Result Start(string applicationName, string commandLine, string[] environment, string workingDirectory)
    {
        Result result = new Result();
        result.Error = "";

        IntPtr level = IntPtr.Zero;
        IntPtr token = IntPtr.Zero;
        IntPtr block = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        try
        {
            // SAFER_LEVELID_NORMALUSER against the CALLER's own token: the result is a primary token
            // whose Administrators SID is deny-only, which is why no SE_ASSIGNPRIMARYTOKEN_NAME and
            // no password, consent prompt or secondary-logon service are involved.
            if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, out level, IntPtr.Zero))
            {
                result.Error = "SaferCreateLevel failed with Win32 error " + Marshal.GetLastWin32Error();
                return result;
            }

            if (!SaferComputeTokenFromLevel(level, IntPtr.Zero, out token, 0, IntPtr.Zero))
            {
                result.Error = "SaferComputeTokenFromLevel failed with Win32 error " + Marshal.GetLastWin32Error();
                return result;
            }

            block = BuildEnvironment(environment);

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));

            uint flags = CREATE_NO_WINDOW;
            if (block != IntPtr.Zero) { flags |= CREATE_UNICODE_ENVIRONMENT; }

            // StringBuilder, not string: CreateProcess may write into this buffer, and the Unicode
            // marshaller would hand it the managed string's own storage.
            StringBuilder line = new StringBuilder(commandLine, commandLine.Length + 1);

            // No handle is inherited and no stream is redirected. Both call sites report through
            // files the child writes, so inheriting handles would buy nothing and cost the
            // complexity of making them inheritable for a restricted token.
            if (!CreateProcessAsUserW(token, applicationName, line, IntPtr.Zero, IntPtr.Zero, false,
                    flags, block, workingDirectory, ref si, out pi))
            {
                result.Error = "CreateProcessAsUserW failed with Win32 error " + Marshal.GetLastWin32Error();
                return result;
            }

            result.Child = new Child(pi.hProcess, pi.dwProcessId);
            pi.hProcess = IntPtr.Zero;
            return result;
        }
        finally
        {
            if (pi.hProcess != IntPtr.Zero) { CloseHandle(pi.hProcess); }
            if (pi.hThread != IntPtr.Zero) { CloseHandle(pi.hThread); }
            if (block != IntPtr.Zero) { Marshal.FreeHGlobal(block); }
            if (token != IntPtr.Zero) { CloseHandle(token); }
            if (level != IntPtr.Zero) { SaferCloseLevel(level); }
        }
    }
}
'@
        return $true
    }
    catch {
        return $false
    }
}

function Start-TestRestrictedProcess {
    <#
    .SYNOPSIS
        Starts one child under a SAFER normal-user token, with no console and therefore no window.
    .DESCRIPTION
        There is ONE of these because two suites need it and a guard that lives in each caller is
        one edit away from being forgotten.

        The child is a REAL child of the calling process: it can be waited on by handle, killed with
        an ordinary process-tree kill, and it dies with the suite when the test runner force-kills
        that tree. None of the orphan machinery runas.exe forced is needed.

        Failure is REPORTED, not thrown, so a caller can keep its own fallback: on a machine that
        cannot produce a restricted token, Child is $null and Error says which call failed.
    .OUTPUTS
        Child - a handle-owning object exposing Id, WaitForExit(ms), ExitCode and Dispose(), or
        $null. Error - empty on success. The caller MUST Dispose the child it is given.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Arguments,
        [hashtable]$Environment = @{},
        [string]$WorkingDirectory
    )

    if (-not (Initialize-WacTestLaunch)) {
        return [PSCustomObject]@{ Child = $null; Error = 'the restricted-token launcher did not compile on this host' }
    }

    # The child gets THIS process's environment plus the overrides, and an override REPLACES its
    # variable rather than being appended beside it: environment names are case-insensitive on
    # Windows, so a block holding both PROGRAMDATA and ProgramData leaves it undefined which one the
    # child reads. Matched ordinally rather than through a case-insensitive hashtable, whose
    # comparison is culture-sensitive and treats I and i as different letters in a Turkish locale.
    $pairs = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in ([Environment]::GetEnvironmentVariables()).GetEnumerator()) {
        $overridden = $false
        foreach ($key in $Environment.Keys) {
            if ([string]::Equals([string]$key, [string]$entry.Key, [System.StringComparison]::OrdinalIgnoreCase)) {
                $overridden = $true
                break
            }
        }
        if (-not $overridden) { [void]$pairs.Add(('{0}={1}' -f $entry.Key, $entry.Value)) }
    }
    foreach ($key in $Environment.Keys) { [void]$pairs.Add(('{0}={1}' -f $key, [string]$Environment[$key])) }

    # lpApplicationName is passed as well as argv[0] so a program path containing a space cannot be
    # split - the exact failure that forces runas's inner command line to be escaped as \" .
    $commandLine = '"{0}"' -f $FilePath
    if ($Arguments) { $commandLine = '{0} {1}' -f $commandLine, $Arguments }
    if (-not $WorkingDirectory) { $WorkingDirectory = (Get-Location).Path }

    # Caught rather than allowed to propagate: every failure of this call is reported the same way,
    # so a caller's fallback is chosen by inspecting a value instead of by catching an exception.
    try {
        $started = [WacTestLaunch]::Start($FilePath, $commandLine, [string[]]$pairs.ToArray(), $WorkingDirectory)
    }
    catch {
        return [PSCustomObject]@{ Child = $null; Error = ('the restricted-token launch threw: {0}' -f $_.Exception.Message) }
    }

    return [PSCustomObject]@{ Child = $started.Child; Error = [string]$started.Error }
}

function New-TestSandbox {
    <#
    .SYNOPSIS
        Creates a disposable directory under TEMP and tracks it for automatic cleanup.
    .DESCRIPTION
        The path is canonicalised through GetFullPath, the same call Get-WacNormalizedPath uses, so
        a comparison against a module return value cannot break on a CI runner whose TEMP is an 8.3
        name such as C:\Users\RUNNER~1\AppData\Local\Temp.
    #>
    param([string]$Prefix = 'wac')

    $name = '{0}_{1}' -f $Prefix, [guid]::NewGuid().ToString('N').Substring(0, 12)
    $path = [System.IO.Path]::GetFullPath((Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $name))
    [void][System.IO.Directory]::CreateDirectory($path)
    [void]$script:WacSandboxes.Add($path)
    return $path
}

function Remove-TestSandboxItem {
    <#
    .SYNOPSIS
        Best-effort recursive delete that survives read-only attributes, reparse points and >MAX_PATH.
    #>
    param([Parameter(Mandatory = $true)][string]$LongPath)

    $info = New-Object System.IO.DirectoryInfo($LongPath)
    if (-not $info.Exists) { return }

    $entries = @()
    try { $entries = @($info.GetFileSystemInfos()) } catch { $entries = @() }

    foreach ($entry in $entries) {
        $isReparse = $false
        try { $isReparse = (([int]$entry.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) }
        catch { $isReparse = $false }

        if (-not $isReparse) {
            try { $entry.Attributes = [System.IO.FileAttributes]::Normal } catch { $null = $_ }
        }

        try {
            if ($isReparse) {
                # Delete the link itself. Remove-Item throws a spurious NullReferenceException on
                # some junctions under Windows PowerShell 5.1.
                if ($entry -is [System.IO.DirectoryInfo]) { [System.IO.Directory]::Delete($entry.FullName, $false) }
                else { [System.IO.File]::Delete($entry.FullName) }
            }
            elseif ($entry -is [System.IO.DirectoryInfo]) {
                Remove-TestSandboxItem -LongPath $entry.FullName
            }
            else {
                [System.IO.File]::Delete($entry.FullName)
            }
        }
        catch {
            $null = $_
        }
    }

    try { [System.IO.Directory]::Delete($LongPath, $false) } catch { $null = $_ }
}

function Remove-TestSandbox {
    <#
    .SYNOPSIS
        Removes one sandbox, or every sandbox this suite created when -Path is omitted.
    #>
    param([string]$Path)

    if (-not $Path) {
        foreach ($tracked in @($script:WacSandboxes.ToArray())) { Remove-TestSandbox -Path $tracked }
        $script:WacSandboxes.Clear()
        return
    }

    $long = $Path
    if ($long.Length -ge 240 -and -not $long.StartsWith('\\?\')) { $long = '\\?\' + $long }
    Remove-TestSandboxItem -LongPath $long

    for ($i = $script:WacSandboxes.Count - 1; $i -ge 0; $i--) {
        if ($script:WacSandboxes[$i] -ieq $Path) { $script:WacSandboxes.RemoveAt($i) }
    }
}

function Test-Case {
    <#
    .SYNOPSIS
        Runs one case, records pass/fail/skip with the failing line, and prints it immediately.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $failure = $null
    $skip = $null

    try {
        & $Body | Out-Null
    }
    catch {
        $message = [string]$_.Exception.Message

        if ($message.StartsWith($script:WacSkipToken, [System.StringComparison]::Ordinal)) {
            $skip = $message.Substring($script:WacSkipToken.Length)
        }
        else {
            $failure = $message
            # A non-assertion exception carries no call-site prefix, so take one from the error record.
            if ($failure -notmatch '^\S+\.ps1:\d+ ') {
                $where = '<unknown>'
                try {
                    if ($_.InvocationInfo -and $_.InvocationInfo.ScriptName) {
                        $where = '{0}:{1}' -f (Split-Path -Leaf $_.InvocationInfo.ScriptName), $_.InvocationInfo.ScriptLineNumber
                    }
                }
                catch { $where = '<unknown>' }
                $failure = '{0} {1}' -f $where, $failure
            }
        }
    }

    $watch.Stop()
    $ms = [int]$watch.Elapsed.TotalMilliseconds

    [void]$script:WacCases.Add([PSCustomObject]@{ Name = $Name; Failure = $failure; Skip = $skip; DurationMs = $ms })

    if ($failure) { Write-Host ('FAIL  {0}  ({1} ms)  {2}' -f $Name, $ms, $failure) }
    elseif ($skip) { Write-Host ('SKIP  {0}  ({1} ms)  {2}' -f $Name, $ms, $skip) }
    else { Write-Host ('pass  {0}  ({1} ms)' -f $Name, $ms) }
}

function Complete-TestRun {
    <#
    .SYNOPSIS
        Cleans up tracked sandboxes, prints the suite total and exits non-zero on failure.
    #>
    param()

    Remove-TestSandbox

    $failed = @($script:WacCases | Where-Object { $_.Failure })
    $skipped = @($script:WacCases | Where-Object { -not $_.Failure -and $_.Skip })
    $total = $script:WacCases.Count
    $elapsed = 0
    foreach ($case in $script:WacCases) { $elapsed += $case.DurationMs }

    # skipped= was appended rather than inserted mid-line: Run-Tests.ps1 keys its "this run proved
    # something" check off the literal 'TOTAL cases=', and its roll-up reads skipped= by name.
    Write-Host ('TOTAL cases={0} passed={1} failed={2} skipped={3} duration={4}ms' -f `
            $total, ($total - $failed.Count - $skipped.Count), $failed.Count, $skipped.Count, $elapsed)

    # A suite that declared nothing is a silent false green, not a pass.
    if ($total -eq 0) {
        Write-Host 'FAIL  suite declared no cases.'
        exit 2
    }

    if ($failed.Count -gt 0) { exit 1 }

    # A skip is missing evidence, so the suite does NOT exit 0. Exit 3 is distinct from a real
    # assertion failure (1) and from an empty suite (2), and Run-Tests.ps1 fails the whole run on
    # any non-zero suite exit - which is what stops "the environment could not run it" from ever
    # reading as "it passed" again.
    if ($skipped.Count -gt 0) {
        foreach ($case in $skipped) { Write-Host ('FAIL  skipped, so nothing was proven: {0} -- {1}' -f $case.Name, $case.Skip) }
        exit 3
    }

    exit 0
}
