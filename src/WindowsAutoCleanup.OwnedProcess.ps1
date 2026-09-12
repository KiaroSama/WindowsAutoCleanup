<#
.SYNOPSIS
    Ownership at creation: a suspended native launch assigned to a kill-on-close Job Object before
    its first thread ever runs.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Process.ps1, which is where the tool-running policy lives. This
    file is only the mechanism.

    WHY THIS EXISTS (ledger WAC-05R). Termination used to be proved by walking a Toolhelp snapshot
    from the root down the parent-process-id relation. A snapshot is a picture of NOW, not a history:
    in A -> B -> C, if B exits before the walk, C is no longer reachable from A's rows, so only A is
    bound and killed while C keeps running - and the run still reported Proven=true. Parent ids are
    also recycled, so the walk has to re-verify every candidate and can still lose a race.

    A job object answers the same question without enumerating anything. Every process created by a
    member of the job is itself a member, transitively and automatically, whatever happens to the
    intermediates. So:

      * "is the owned tree finished?"      -> ActiveProcesses == 0. No walk, no pid, no race.
      * "stop the owned tree"              -> TerminateJobObject. One call, the whole tree, proven.
      * "what if we crash before that?"    -> KILL_ON_JOB_CLOSE. The last handle closing kills it,
                                              including when this process dies unexpectedly.

    AND WHY SUSPENDED. Creating the job after a free-running Start() closes no race: between the
    start returning and the assign call the child may already have spawned a grandchild OUTSIDE the
    job. CREATE_SUSPENDED removes the window entirely - a suspended process has never executed an
    instruction, so it cannot have created anything. Assign, then resume.

    Measured, and the reason this file is native at all: on BOTH shipped hosts - PowerShell 7.6.5 and
    Windows PowerShell 5.1.26100.9444 - ProcessStartInfo exposes NO creation-flag, suspended-start,
    job-object or attribute-list member, and no Process.Start overload accepts one. Ownership at
    creation is therefore unreachable through System.Diagnostics.Process, which is why the whole
    start path - inheritable pipes, command line, exit code - is rebuilt here.

    WHAT THIS DOES NOT OWN, stated rather than papered over:
      * A process started on this project's behalf by ANOTHER process - a service, a WMI/COM
        activation - is created by that service's parent and joins that service's job, not ours.
        cleanmgr's shell handlers are the realistic case. Such a process is invisible here, and the
        result says so through Owned=$false rather than pretending.
      * An elevated child cannot be owned from a medium-integrity parent, so the elevated relaunch
        does not try. The elevated process runs this same code and owns ITS OWN children; ownership
        is established on the far side of the boundary, where it can be.
      * When the job cannot be created or assigned, the launch still happens and reports
        Owned=$false. A conservative fallback that says so is worth more than a job object without
        the kill-on-close backstop, which reads as ownership while providing none.
#>

# Test seam. Given a scriptblock, Start-WacOwnedProcess calls it INSTEAD of the native launcher, so a
# suite can drive the degraded path without breaking the machine's job support. $null restores.
$script:OwnedProcessLauncher = $null

function Set-WacOwnedProcessLauncher {
    param([scriptblock]$Launcher)
    $script:OwnedProcessLauncher = $Launcher
}

function Initialize-WacOwnedProcessNative {
    <#
    .SYNOPSIS
        Compiles the suspended-launch/job-object helper. Idempotent; $false when unavailable.
    .DESCRIPTION
        A caller that cannot compile this must not claim ownership. It falls back to the managed
        start path and reports Owned=$false, which is a true statement about a real process rather
        than a refusal to run maintenance at all.
    #>
    if ('WacOwnedProcess' -as [type]) { return $true }

    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class WacOwnedLaunch
{
    public IntPtr Job = IntPtr.Zero;
    public IntPtr Process = IntPtr.Zero;
    public IntPtr Thread = IntPtr.Zero;
    public int ProcessId;
    // True only when the process was created suspended, assigned to a kill-on-close job, and then
    // resumed - in that order. Anything less is not ownership and must not be reported as any.
    public bool Owned;
    public string Degraded = "";
    public Stream StandardOutput;
    public Stream StandardError;
}

public static class WacOwnedProcess
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    {
        public long TotalUserTime, TotalKernelTime;
        public long ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObjectW(IntPtr a, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length, IntPtr returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SECURITY_ATTRIBUTES sa, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(IntPtr h, int mask, int flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
        uint creationFlags, IntPtr environment, string currentDirectory,
        ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES sa,
        uint disposition, uint flags, IntPtr template);

    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int HANDLE_FLAG_INHERIT = 0x00000001;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectBasicAccountingInformation = 1;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint INFINITE = 0xFFFFFFFF;

    private static IntPtr CreateKillOnCloseJob()
    {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) { return IntPtr.Zero; }

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, buffer, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size))
            {
                // A job WITHOUT the backstop is worse than none: it looks like ownership and does not
                // survive this process dying. Refuse it rather than keep it.
                CloseHandle(job);
                return IntPtr.Zero;
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }

        return job;
    }

    // -1 when the job cannot be queried. That is NOT the same answer as zero and the caller must not
    // read it as one.
    public static int ActiveProcessesInJob(IntPtr job)
    {
        if (job == IntPtr.Zero) { return -1; }

        int size = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, buffer, (uint)size, IntPtr.Zero))
            {
                return -1;
            }
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info =
                (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)Marshal.PtrToStructure(buffer, typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            return (int)info.ActiveProcesses;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public static bool TerminateJob(IntPtr job)
    {
        if (job == IntPtr.Zero) { return false; }
        return TerminateJobObject(job, 1);
    }

    public static bool WaitForExit(IntPtr process, int timeoutMs)
    {
        if (process == IntPtr.Zero) { return false; }
        uint wait = timeoutMs < 0 ? INFINITE : (uint)timeoutMs;
        return WaitForSingleObject(process, wait) == WAIT_OBJECT_0;
    }

    // null when the code cannot be read, so "unreadable" never arrives as a plausible number.
    public static object GetExitCode(IntPtr process)
    {
        uint code;
        if (process == IntPtr.Zero || !GetExitCodeProcess(process, out code)) { return null; }
        return unchecked((int)code);
    }

    public static void Close(WacOwnedLaunch launch)
    {
        if (launch == null) { return; }
        if (launch.StandardOutput != null) { try { launch.StandardOutput.Dispose(); } catch { } }
        if (launch.StandardError != null) { try { launch.StandardError.Dispose(); } catch { } }
        if (launch.Thread != IntPtr.Zero) { CloseHandle(launch.Thread); launch.Thread = IntPtr.Zero; }
        if (launch.Process != IntPtr.Zero) { CloseHandle(launch.Process); launch.Process = IntPtr.Zero; }
        // LAST, and deliberately: this is the kill-on-close backstop firing. Anything still alive in
        // the job dies here, which is what makes an abandoned run safe.
        if (launch.Job != IntPtr.Zero) { CloseHandle(launch.Job); launch.Job = IntPtr.Zero; }
    }

    public static WacOwnedLaunch Start(string applicationName, string commandLine, string workingDirectory)
    {
        WacOwnedLaunch launch = new WacOwnedLaunch();

        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        sa.lpSecurityDescriptor = IntPtr.Zero;
        sa.bInheritHandle = 1;

        IntPtr outRead = IntPtr.Zero, outWrite = IntPtr.Zero;
        IntPtr errRead = IntPtr.Zero, errWrite = IntPtr.Zero;
        IntPtr nul = IntPtr.Zero;
        bool handedOver = false;

        try
        {
            if (!CreatePipe(out outRead, out outWrite, ref sa, 0)) { throw new InvalidOperationException("The stdout pipe could not be created."); }
            if (!CreatePipe(out errRead, out errWrite, ref sa, 0)) { throw new InvalidOperationException("The stderr pipe could not be created."); }

            // The READ ends must not reach the child: an inherited read end keeps the pipe alive and
            // the parent's own ReadToEnd would never see EOF.
            SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);

            // Detached stdin. Automation must never be able to block on a console read, and handing
            // the child our own stdin would let it consume the caller's.
            nul = CreateFileW("NUL", 0x80000000, 3, ref sa, 3, 0, IntPtr.Zero);

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = nul;
            si.hStdOutput = outWrite;
            si.hStdError = errWrite;

            launch.Job = CreateKillOnCloseJob();

            PROCESS_INFORMATION pi;
            StringBuilder line = new StringBuilder(commandLine);
            uint flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;

            if (!CreateProcessW(applicationName, line, IntPtr.Zero, IntPtr.Zero, true,
                    flags, IntPtr.Zero, workingDirectory, ref si, out pi))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            launch.Process = pi.hProcess;
            launch.Thread = pi.hThread;
            launch.ProcessId = pi.dwProcessId;

            // THE ORDERING THAT MATTERS. The process exists but has never run an instruction, so it
            // cannot yet have created a child. Assigning here, before ResumeThread, is what makes
            // every descendant a member of the job with no window at all.
            if (launch.Job == IntPtr.Zero)
            {
                launch.Degraded = "the job object could not be created with its kill-on-close backstop";
            }
            else if (!AssignProcessToJobObject(launch.Job, launch.Process))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(launch.Job);
                launch.Job = IntPtr.Zero;
                launch.Degraded = "the suspended process could not be assigned to the job object (error " + error + ")";
            }
            else
            {
                launch.Owned = true;
            }

            if (ResumeThread(launch.Thread) == 0xFFFFFFFF)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            // Our copies of the WRITE ends close here. While the parent holds one the pipe can never
            // reach EOF, so this is what lets an outstanding read mean "a child still holds it".
            CloseHandle(outWrite); outWrite = IntPtr.Zero;
            CloseHandle(errWrite); errWrite = IntPtr.Zero;
            if (nul != IntPtr.Zero) { CloseHandle(nul); nul = IntPtr.Zero; }

            launch.StandardOutput = new FileStream(new SafeFileHandle(outRead, true), FileAccess.Read, 4096, false);
            launch.StandardError = new FileStream(new SafeFileHandle(errRead, true), FileAccess.Read, 4096, false);
            handedOver = true;
            return launch;
        }
        finally
        {
            if (outWrite != IntPtr.Zero) { CloseHandle(outWrite); }
            if (errWrite != IntPtr.Zero) { CloseHandle(errWrite); }
            if (nul != IntPtr.Zero) { CloseHandle(nul); }
            if (!handedOver)
            {
                if (outRead != IntPtr.Zero) { CloseHandle(outRead); }
                if (errRead != IntPtr.Zero) { CloseHandle(errRead); }
                Close(launch);
            }
        }
    }
}
'@
        return $true
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Process' -Message 'The owned-process helper could not be compiled; tools will run without job ownership.' -Data @{ error = $_.Exception.Message }
        return $false
    }
}

function Start-WacOwnedProcess {
    <#
    .SYNOPSIS
        Starts a tool suspended, binds it to a kill-on-close job, then resumes it.
    .DESCRIPTION
        Returns $null when ownership is unavailable, which tells the caller to use the managed start
        path and report Owned=$false. It never returns a half-owned launch.
    .OUTPUTS
        A WacOwnedLaunch, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [AllowEmptyCollection()][string[]]$ArgumentList = @()
    )

    if ($script:OwnedProcessLauncher) {
        return (& $script:OwnedProcessLauncher $FilePath $ArgumentList)
    }

    if (-not (Initialize-WacOwnedProcessNative)) { return $null }

    # argv[0] by convention, even though lpApplicationName already fixes the image: a tool that reads
    # its own command line - and several Windows tools do - must see its name where it expects it.
    $commandLine = (ConvertTo-WacCommandLineArgument -Value $FilePath)
    $tail = ConvertTo-WacCommandLine -ArgumentList $ArgumentList
    if ($tail) { $commandLine = $commandLine + ' ' + $tail }

    $directory = $null
    try { $directory = [System.IO.Path]::GetDirectoryName($FilePath) } catch { $directory = $null }
    if ([string]::IsNullOrWhiteSpace($directory)) { $directory = $null }

    try {
        return [WacOwnedProcess]::Start($FilePath, $commandLine, $directory)
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Process' -Message 'The owned launch failed; falling back to an unowned start.' -Data @{
            tool = $FilePath; error = $_.Exception.Message
        }
        return $null
    }
}

function Get-WacOwnedTreeState {
    <#
    .SYNOPSIS
        Whether every process in an owned job has finished.
    .DESCRIPTION
        Three answers, never two. 'Complete' is the only one that licenses reclaiming state a
        mutator may still be touching; 'Alive' says something this run started is still running even
        though the root is gone; 'Unknown' is an unreadable job and is not a synonym for either.
    .OUTPUTS
        Complete | Alive | Unknown, and the active count (-1 when unreadable).
    #>
    param([Parameter(Mandatory = $true)]$Launch)

    if ($null -eq $Launch -or -not $Launch.Owned) {
        return [PSCustomObject]@{ State = 'Unknown'; ActiveProcesses = -1 }
    }

    $active = -1
    try { $active = [int][WacOwnedProcess]::ActiveProcessesInJob($Launch.Job) } catch { $active = -1 }

    $state = 'Unknown'
    if ($active -eq 0) { $state = 'Complete' }
    elseif ($active -gt 0) { $state = 'Alive' }

    return [PSCustomObject]@{ State = $state; ActiveProcesses = $active }
}

function Invoke-WacOwnedTool {
    <#
    .SYNOPSIS
        Runs an already-owned launch to completion and returns the shared Invoke-WacProcess contract.
    .DESCRIPTION
        Lives beside the mechanism rather than in Process.ps1 because it IS the mechanism's policy:
        every verdict below is read off the job, and none of it means anything without one.

        Three facts are kept apart, which is the whole point of the ledger item:

          Root exit          - the root process handle is signalled. Says nothing about descendants.
          Owned-tree state   - ActiveProcesses on the job. 'Complete' is the only answer that
                               licenses reclaiming state a mutator may still be touching.
          Output completion  - both pipes reached EOF within the budget. A pipe EOFs only when every
                               write handle closes, so an outstanding read is a second, independent
                               witness that a descendant is alive.

        A timeout is one TerminateJobObject call: the entire tree, no enumeration, no pid, no race
        with a recycled parent id, and nothing unrelated can be caught by it because membership is
        decided by creation, not by a name or a number.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Launch,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string]$Component = 'Process'
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $outReader = New-Object System.IO.StreamReader($Launch.StandardOutput, [System.Text.Encoding]::UTF8)
    $errReader = New-Object System.IO.StreamReader($Launch.StandardError, [System.Text.Encoding]::UTF8)
    $outTask = $outReader.ReadToEndAsync()
    $errTask = $errReader.ReadToEndAsync()

    $exited = [WacOwnedProcess]::WaitForExit($Launch.Process, $TimeoutMs)
    $timedOut = -not $exited
    $killedJob = $false

    if ($timedOut) {
        Write-WacLog -Level WARNING -Component $Component -Message 'External tool exceeded its deadline; terminating the job it was created in.' -Data @{
            tool = $FilePath; pid = $Launch.ProcessId; timeoutMs = $TimeoutMs; owned = [bool]$Launch.Owned
        }
        $killedJob = [bool][WacOwnedProcess]::TerminateJob($Launch.Job)
        [void][WacOwnedProcess]::WaitForExit($Launch.Process, 10000)
    }

    # Same accounting rule as the unowned path: the read waits are part of the run budget, not an
    # extra ten seconds per tool on top of it.
    $readBudgetMs = Get-WacStepTimeoutMs -RequestedMs 5000
    if ($readBudgetMs -lt 250) { $readBudgetMs = 250 }
    [void]$outTask.Wait($readBudgetMs)
    [void]$errTask.Wait($readBudgetMs)

    $outputComplete = ($outTask.IsCompleted -and $errTask.IsCompleted)
    $stdout = if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' }
    $stderr = if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' }

    $exitCode = $null
    if (-not $timedOut) {
        try { $exitCode = [WacOwnedProcess]::GetExitCode($Launch.Process) } catch { $exitCode = $null }
    }

    # Queried AFTER the reads on purpose: by then the root's own accounting has settled, so a job
    # that still reports members is reporting real descendants rather than a not-yet-reaped root.
    $tree = Get-WacOwnedTreeState -Launch $Launch
    $terminationProven = ($tree.State -ceq 'Complete')

    if (-not $terminationProven) {
        Write-WacLog -Level CRITICAL -Component $Component -Message 'The owned job still holds live processes, so the tool cannot be reported as stopped.' -Data @{
            tool = $FilePath; pid = $Launch.ProcessId; treeState = [string]$tree.State
            activeProcesses = [int]$tree.ActiveProcesses; timedOut = $timedOut; jobTerminated = $killedJob
        }
    }
    elseif (-not $outputComplete) {
        # The job is empty and a read still has not finished. Nothing this run owns can be holding
        # the pipe, so the handle went to something outside the job - a service or COM activation
        # started on our behalf. The output is still not the whole output, and the verdict says so.
        Write-WacLog -Level WARNING -Component $Component -Message 'The owned tree finished but an output pipe is still held, so a process outside the job inherited it.' -Data @{
            tool = $FilePath; pid = $Launch.ProcessId; readBudgetMs = $readBudgetMs
        }
    }

    $stopwatch.Stop()
    return [PSCustomObject]@{
        ExitCode = $exitCode
        TimedOut = $timedOut
        StandardOutput = $stdout
        StandardError = $stderr
        DurationMs = [int]$stopwatch.Elapsed.TotalMilliseconds
        Started = $true
        TerminationProven = $terminationProven
        OutputComplete = $outputComplete
        # Ownership is reported, never assumed: a caller that needs to know whether the verdict above
        # rests on a job or on a best-effort walk can ask.
        Owned = [bool]$Launch.Owned
        OwnedTreeState = [string]$tree.State
    }
}
