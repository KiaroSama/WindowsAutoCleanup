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

function Set-WacOwnedProcessFault {
    <#
    .SYNOPSIS
        Arms or clears ONE native launch-phase failure. Injects failure only, never success.
    .DESCRIPTION
        The launch states that decide whether a retry is legal are produced inside the native Start,
        between CreateProcessW and ResumeThread. A test that replaces the whole launcher cannot reach
        them, so the seam lives where the phases do.

        -Phase None clears every fault. Always clear in a finally: a fault left armed would make every
        later launch in the process fail.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('None', 'JobAssign', 'BeforeResume', 'AfterResume', 'OutStream', 'ErrStream', 'TerminateRefused', 'TerminateNotConfirmed')][string]$Phase,
        [AllowEmptyString()][string]$Message = 'injected by a test'
    )

    if (-not (Initialize-WacOwnedProcessNative)) { return $false }

    [WacOwnedProcess]::ClearFaults()
    switch ($Phase) {
        'JobAssign'    { [WacOwnedProcess]::FaultAtJobAssign = $Message }
        'BeforeResume' { [WacOwnedProcess]::FaultBeforeResume = $Message }
        'AfterResume'  { [WacOwnedProcess]::FaultAfterResume = $Message }
        'OutStream'    { [WacOwnedProcess]::FaultAtOutStream = $Message }
        'ErrStream'    { [WacOwnedProcess]::FaultAtErrStream = $Message }
        'TerminateRefused' { [WacOwnedProcess]::FaultTerminateRefused = $true }
        # The one state a real suspended process will not produce on demand: the request is GRANTED
        # and the process has still not exited when the confirmation budget runs out. Without this
        # the wait can never change an answer in a test, because a suspended process dies at once.
        'TerminateNotConfirmed' { [WacOwnedProcess]::FaultConfirmNotSignalled = $true }
        default        { $null = $Phase }
    }
    return $true
}

function Get-WacOwnedProcessRawCloseCount {
    <#
    .SYNOPSIS
        How many pipe read ends the last launch closed RAW, rather than leaving to their owner.
    .DESCRIPTION
        Reset by Set-WacOwnedProcessFault, so a case arms its fault and then reads a number that
        belongs to its own launch. -1 means the helper is not available, which is not zero: no
        launch happened, so nothing can be concluded either way.
    #>

    if (-not (Initialize-WacOwnedProcessNative)) { return -1 }
    return [int][WacOwnedProcess]::RawReadHandleClosures
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
    public bool DeadlineExpired;
    // True only when the process was created suspended, assigned to a kill-on-close job, and then
    // resumed - in that order. Anything less is not ownership and must not be reported as any.
    public bool Owned;
    public string Degraded = "";
    public Stream StandardOutput;
    public Stream StandardError;

    // HOW FAR THE LAUNCH GOT, and the only thing that may decide whether retrying is legal.
    //
    //   NeverCreated - CreateProcessW never returned a process. Nothing exists, nothing ran, and a
    //                  managed fallback start is the SAFE answer.
    //   Created      - the process exists and is SUSPENDED. It has executed no instruction, so it
    //                  has no effects and no descendants - but it WAS created, so this is reported
    //                  as a failed start rather than retried. The launcher terminates it.
    //   Resumed      - the first instruction ran. Effects are possible from this moment on, so this
    //                  launch is NEVER retried under any failure, only reported.
    //
    // This field exists because collapsing a post-resume failure to null made the caller start the
    // same command a second time: for pnputil /delete-driver or cleanmgr /sagerun that is one
    // logical invocation executing twice, and closing the first job cannot undo what it already did.
    public string State = "NeverCreated";
    public string Failure = "";

    // ONLY meaningful for State == "Created": whether that suspended process is CONFIRMED gone.
    // TerminateProcess is documented as asynchronous - it asks, and returns before the process has
    // exited - and the previous code discarded even the request's own return value, then reported
    // TerminationProven=true regardless. A request that failed, and one that succeeded but had not
    // finished when the handle was closed, both read as proof.
    public bool Stopped = false;
}

public static class WacOwnedProcess
{
    // TEST SEAMS, and the reason they are native rather than a PowerShell shim: the states this
    // contract exists to distinguish are produced INSIDE Start, between CreateProcessW and
    // ResumeThread. Replacing the whole launcher with one that answers null cannot reach them - it
    // tests the substitute, not the code. Each field makes exactly ONE phase fail; none can make a
    // phase succeed or be skipped, so production behaviour with all three null is untouched.
    public static string FaultAtJobAssign = null;
    public static string FaultBeforeResume = null;
    public static string FaultAfterResume = null;
    // The window between a SafeFileHandle adopting a raw pipe handle and the FileStream taking the
    // SafeFileHandle. Nothing else can produce it on demand, and it is the one window in which two
    // owners could close the same handle.
    public static string FaultAtOutStream = null;
    public static string FaultAtErrStream = null;
    // A termination REQUEST that fails, which no test can provoke against a real suspended process.
    public static bool FaultTerminateRefused = false;
    public static bool FaultConfirmNotSignalled = false;

    // Counts the read ends this frame closed RAW - that is, ones no SafeFileHandle had adopted.
    // It exists because the ownership rule it measures has no other observable: a double close on
    // Windows usually does nothing visible in-process, so the ordering that prevents one could be
    // reverted with every test still green. Diagnostic only; nothing branches on it.
    public static int RawReadHandleClosures = 0;

    public static void ClearFaults()
    {
        FaultAtJobAssign = null;
        FaultBeforeResume = null;
        FaultAfterResume = null;
        FaultAtOutStream = null;
        FaultAtErrStream = null;
        FaultTerminateRefused = false;
        FaultConfirmNotSignalled = false;
        RawReadHandleClosures = 0;
    }

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
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

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
        // Stop remaining writers before disposing their redirected streams.
        if (launch.Job != IntPtr.Zero) { CloseHandle(launch.Job); launch.Job = IntPtr.Zero; }
        if (launch.StandardOutput != null) { try { launch.StandardOutput.Dispose(); } catch { } }
        if (launch.StandardError != null) { try { launch.StandardError.Dispose(); } catch { } }
        if (launch.Thread != IntPtr.Zero) { CloseHandle(launch.Thread); launch.Thread = IntPtr.Zero; }
        if (launch.Process != IntPtr.Zero) { CloseHandle(launch.Process); launch.Process = IntPtr.Zero; }
    }

    public static WacOwnedLaunch Start(string applicationName, string commandLine, string workingDirectory,
        int terminateConfirmMs)
    {
        return Start(applicationName, commandLine, workingDirectory, terminateConfirmMs, long.MaxValue);
    }

    public static WacOwnedLaunch Start(string applicationName, string commandLine, string workingDirectory,
        int terminateConfirmMs, long deadlineTick)
    {
        WacOwnedLaunch launch = new WacOwnedLaunch();

        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        sa.lpSecurityDescriptor = IntPtr.Zero;
        sa.bInheritHandle = 1;

        IntPtr outRead = IntPtr.Zero, outWrite = IntPtr.Zero;
        IntPtr errRead = IntPtr.Zero, errWrite = IntPtr.Zero;
        IntPtr nul = IntPtr.Zero;
        // Each read end is owned by EXACTLY one thing. Once a SafeFileHandle has adopted it the
        // finally block must not close it too - the previous version could close both, which is a
        // double close on a handle the OS may already have recycled.
        bool outAdopted = false, errAdopted = false;
        // Held only while THIS frame owns them. A SafeFileHandle adopts the raw handle the moment it
        // is constructed, so the raw cleanup below has to stand down at that instant - not after the
        // FileStream over it has also succeeded. Constructing the stream can throw, and the previous
        // ordering then closed a handle the SafeFileHandle finalizer still owned: a double close on
        // a number the OS may already have handed to something else.
        SafeFileHandle outSafe = null, errSafe = null;

        try
        {
            if (!CreatePipe(out outRead, out outWrite, ref sa, 0)) { throw new InvalidOperationException("The stdout pipe could not be created."); }
            if (!CreatePipe(out errRead, out errWrite, ref sa, 0)) { throw new InvalidOperationException("The stderr pipe could not be created."); }

            // The READ ends must not reach the child: an inherited read end keeps the pipe alive and
            // the parent's own ReadToEnd would never see EOF.
            if (!SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0) ||
                !SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0))
            { throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }

            // Detached stdin. Automation must never be able to block on a console read, and handing
            // the child our own stdin would let it consume the caller's.
            nul = CreateFileW("NUL", 0x80000000, 3, ref sa, 3, 0, IntPtr.Zero);
            if (nul == new IntPtr(-1)) { nul = IntPtr.Zero; throw new InvalidOperationException("Detached stdin could not be opened."); }

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = nul;
            si.hStdOutput = outWrite;
            si.hStdError = errWrite;

            launch.Job = CreateKillOnCloseJob();

            // ADOPTED BEFORE THE CHILD RUNS. Constructing a FileStream can fail, and a failure after
            // ResumeThread is unrecoverable in the only sense that matters: the tool has already
            // started doing whatever it does. The pipes exist independently of the child, so every
            // allocation that can throw moves ahead of the resume.
            outSafe = new SafeFileHandle(outRead, true);
            outAdopted = true;
            if (FaultAtOutStream != null) { throw new InvalidOperationException(FaultAtOutStream); }
            launch.StandardOutput = new FileStream(outSafe, FileAccess.Read, 4096, false);
            outSafe = null;

            errSafe = new SafeFileHandle(errRead, true);
            errAdopted = true;
            if (FaultAtErrStream != null) { throw new InvalidOperationException(FaultAtErrStream); }
            launch.StandardError = new FileStream(errSafe, FileAccess.Read, 4096, false);
            errSafe = null;

            PROCESS_INFORMATION pi;
            StringBuilder line = new StringBuilder(commandLine);
            uint flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;

            if (System.Diagnostics.Stopwatch.GetTimestamp() >= deadlineTick)
            { launch.DeadlineExpired = true; throw new TimeoutException("Launch deadline expired before process creation."); }
            if (!CreateProcessW(applicationName, line, IntPtr.Zero, IntPtr.Zero, true,
                    flags, IntPtr.Zero, workingDirectory, ref si, out pi))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            launch.Process = pi.hProcess;
            launch.Thread = pi.hThread;
            launch.ProcessId = pi.dwProcessId;
            launch.State = "Created";

            // THE ORDERING THAT MATTERS. The process exists but has never run an instruction, so it
            // cannot yet have created a child. Assigning here, before ResumeThread, is what makes
            // every descendant a member of the job with no window at all.
            if (launch.Job == IntPtr.Zero)
            {
                launch.Degraded = "the job object could not be created with its kill-on-close backstop";
            }
            else if (FaultAtJobAssign != null || !AssignProcessToJobObject(launch.Job, launch.Process))
            {
                int error = FaultAtJobAssign != null ? -1 : Marshal.GetLastWin32Error();
                CloseHandle(launch.Job);
                launch.Job = IntPtr.Zero;
                launch.Degraded = FaultAtJobAssign != null
                    ? FaultAtJobAssign
                    : "the suspended process could not be assigned to the job object (error " + error + ")";
            }
            else
            {
                launch.Owned = true;
            }

            if (FaultBeforeResume != null) { throw new InvalidOperationException(FaultBeforeResume); }

            if (System.Diagnostics.Stopwatch.GetTimestamp() >= deadlineTick)
            { launch.DeadlineExpired = true; throw new TimeoutException("Launch deadline expired before resume."); }
            if (ResumeThread(launch.Thread) == 0xFFFFFFFF)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            launch.State = "Resumed";

            // The window this whole contract exists for: the child is RUNNING and the launcher still
            // has work left that can fail. Whatever happens from here, the command must never be
            // started a second time.
            if (FaultAfterResume != null) { throw new InvalidOperationException(FaultAfterResume); }

            // Our copies of the WRITE ends close here. While the parent holds one the pipe can never
            // reach EOF, so this is what lets an outstanding read mean "a child still holds it".
            CloseHandle(outWrite); outWrite = IntPtr.Zero;
            CloseHandle(errWrite); errWrite = IntPtr.Zero;
            if (nul != IntPtr.Zero) { CloseHandle(nul); nul = IntPtr.Zero; }

            return launch;
        }
        catch (Exception error)
        {
            // NEVER rethrown. Throwing here is what erased the difference between "nothing was
            // created" and "a tool is already running", and the caller answered both by starting the
            // command a second time. The launch object carries the truth out instead.
            launch.Failure = error.Message;

            if (launch.State == "NeverCreated")
            {
                // Nothing exists. Release everything; the caller may safely use the managed path.
                Close(launch);
            }
            else if (launch.State == "Created")
            {
                // Suspended and never resumed, so it has executed nothing and has no descendants -
                // but "asked it to stop" is not "it stopped". The REQUEST's own result is checked,
                // and then confirmed on the bound process handle BEFORE that handle is closed,
                // because after the close there is nothing left to ask.
                bool asked = false;
                try { asked = !FaultTerminateRefused && TerminateProcess(launch.Process, 1); } catch { asked = false; }
                if (asked && terminateConfirmMs > 0)
                {
                    launch.Stopped = !FaultConfirmNotSignalled &&
                        WaitForSingleObject(launch.Process, (uint)terminateConfirmMs) == WAIT_OBJECT_0;
                }
                if (!launch.Stopped)
                {
                    launch.Degraded = asked
                        ? "the suspended process was asked to terminate and had not exited when its handle was released"
                        : "the suspended process could not be asked to terminate";
                }
                Close(launch);
            }
            // Resumed keeps its handles: the caller still has to wait on it, read it and stop it.
            return launch;
        }
        finally
        {
            if (outWrite != IntPtr.Zero) { CloseHandle(outWrite); }
            if (errWrite != IntPtr.Zero) { CloseHandle(errWrite); }
            if (nul != IntPtr.Zero) { CloseHandle(nul); }
            // Only a read end NO SafeFileHandle took responsibility for. The counter makes that
            // condition observable: it is the only way a test can tell this frame stood down from a
            // handle it no longer owned, rather than closing it a second time and getting away with
            // it because Windows rarely complains.
            if (!outAdopted && outRead != IntPtr.Zero) { RawReadHandleClosures++; CloseHandle(outRead); }
            if (!errAdopted && errRead != IntPtr.Zero) { RawReadHandleClosures++; CloseHandle(errRead); }
            // Adopted, but the stream never took it: this frame is still the single owner, so it
            // closes deterministically here rather than leaving it to a finalizer.
            if (outSafe != null) { try { outSafe.Dispose(); } catch { } }
            if (errSafe != null) { try { errSafe.Dispose(); } catch { } }
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
        [AllowEmptyCollection()][string[]]$ArgumentList = @(),
        [long]$DeadlineTick = [long]::MaxValue
    )

    if ($script:OwnedProcessLauncher) {
        return (& $script:OwnedProcessLauncher $FilePath $ArgumentList)
    }

    if (-not ('WacOwnedProcess' -as [type]) -and $DeadlineTick -ne [long]::MaxValue) {
        # Compilation runs inside the existing bounded worker; it can never launch a tool.
        $left = [int][Math]::Max(0, [Math]::Min([int]::MaxValue,
            ($DeadlineTick - [System.Diagnostics.Stopwatch]::GetTimestamp()) * 1000.0 / [System.Diagnostics.Stopwatch]::Frequency))
        $compiled = Initialize-WacOwnedProcessBounded -TimeoutMs $left
        if ($compiled.Outcome -cne 'Succeeded' -or -not ('WacOwnedProcess' -as [type])) { return $null }
    }
    if (-not (Initialize-WacOwnedProcessNative)) { return $null }
    if ([System.Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTick) { return $null }

    # argv[0] by convention, even though lpApplicationName already fixes the image: a tool that reads
    # its own command line - and several Windows tools do - must see its name where it expects it.
    $commandLine = (ConvertTo-WacCommandLineArgument -Value $FilePath)
    $tail = ConvertTo-WacCommandLine -ArgumentList $ArgumentList
    if ($tail) { $commandLine = $commandLine + ' ' + $tail }

    $directory = $null
    try { $directory = [System.IO.Path]::GetDirectoryName($FilePath) } catch { $directory = $null }
    if ([string]::IsNullOrWhiteSpace($directory)) { $directory = $null }

    # The native Start no longer throws across the resume boundary: it returns a launch carrying
    # State. Only a catastrophic marshalling failure reaches this catch, and only NeverCreated - here
    # or in the returned object - may become $null, because $null is what licenses the caller to run
    # the same command again.
    try {
        # The confirmation budget for a suspended process that has to be terminated before it ever
        # ran. Drawn from the RUN BUDGET only, never claimed from the recovery reserve: this number
        # is computed on EVERY launch and the overwhelming majority of launches never use it, so
        # claiming it here would debit the reserve once per tool for a confirmation that does not
        # happen - which measurably starved the drain that does. Past the deadline it is 0, the
        # confirmation does not run, and Stopped stays false, which is the honest answer.
        $launch = [WacOwnedProcess]::Start($FilePath, $commandLine, $directory, (Get-WacStepTimeoutMs -RequestedMs 5000), $DeadlineTick)
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Process' -Message 'The owned launcher failed before any process could be created; an unowned start is safe.' -Data @{
            tool = $FilePath; error = $_.Exception.Message
        }
        return $null
    }

    if ($null -eq $launch) { return $null }

    if (-not [string]::IsNullOrEmpty([string]$launch.Failure)) {
        Write-WacLog -Level WARNING -Component 'Process' -Message 'The owned launch did not complete.' -Data @{
            tool = $FilePath; state = [string]$launch.State; error = [string]$launch.Failure
        }
    }

    # Nothing was created, so nothing ran: the caller may safely fall back.
    if ([string]$launch.State -ceq 'NeverCreated') { return $null }

    return $launch
}
