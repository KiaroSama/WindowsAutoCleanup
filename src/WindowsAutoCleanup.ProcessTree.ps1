<#
.SYNOPSIS
    Proving that a process, and everything it started, has stopped.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Process.ps1, which is itself dot-sourced by
    WindowsAutoCleanup.Core.psm1; see Core for why the parts are dot-sourced rather than imported.

    It is its own file because it is its own question. The rest of Process.ps1 is about STARTING
    work and holding it to a deadline; everything here is about the evidence that the work is over -
    the toolhelp snapshot that says which identities a tree is made of, the kernel handle bound to
    each of them before anything is killed, and the structured verdict that separates "proven gone"
    from "nobody could tell".
#>

# The injected opener seam lives with the only code that binds a handle.
$script:ProcessHandleOpener = $null
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

function Initialize-WacProcessTreeNative {
    <#
    .SYNOPSIS
        Compiles the toolhelp snapshot helper Stop-WacProcessTree enumerates a tree with. Idempotent.
    .DESCRIPTION
        Separate from Initialize-WacNative because it answers a different question and only the
        termination path ever asks it: WacNative binds and kills ONE identity, this one says which
        identities a tree is made of. Returns $false when it could not be compiled, and a caller
        that cannot read the tree must not claim a tree was terminated.
    #>
    if ('WacProcessTree' -as [type]) { return $true }

    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class WacProcessTree
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    // The ONLY Process32NextW failure that means the walk finished rather than broke. See the check
    // after the enumeration loop in GetDescendantIds.
    private const int ERROR_NO_MORE_FILES = 18;

    // Every id reachable from rootId through the parent-process-id relation, nearest generation
    // first. One snapshot answers for the whole machine, so a deep tree costs one call rather than
    // one per level, and no WMI/CIM service is involved - this runs on the path that has to work
    // when something is already wedged.
    //
    // These are CANDIDATES, not proven descendants. Parent IDs outlive their original processes.
    // The caller checks each bound candidate's current parent ID and creation time against its
    // already-bound parent before admitting it to the termination set.
    //
    // null means the snapshot could not be taken or read. That is not the same answer as an empty
    // array and the caller must not read it as one.
    public static int[] GetDescendantIds(int rootId)
    {
        IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) { return null; }

        try
        {
            List<int> ids = new List<int>();
            List<int> parents = new List<int>();

            PROCESSENTRY32W entry = new PROCESSENTRY32W();
            entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));
            if (!Process32FirstW(snapshot, ref entry)) { return null; }
            do
            {
                ids.Add((int)entry.th32ProcessID);
                parents.Add((int)entry.th32ParentProcessID);
            }
            while (Process32NextW(snapshot, ref entry));

            // Process32NextW returns false for TWO different reasons and this loop used to treat
            // them as one: ERROR_NO_MORE_FILES means the walk finished, anything else means it was
            // CUT SHORT. A truncated snapshot silently became a complete one, so descendants past
            // the break were never enumerated and "no more children" was reported over a tree the
            // walk had stopped reading. Returning null puts it back on the one path the caller
            // already handles correctly - "nobody knows", which keeps the verdict unproven - rather
            // than on the empty-array path that means "this process has no children".
            if (Marshal.GetLastWin32Error() != ERROR_NO_MORE_FILES) { return null; }

            List<int> found = new List<int>();
            List<int> frontier = new List<int>();
            frontier.Add(rootId);

            while (frontier.Count > 0)
            {
                List<int> next = new List<int>();
                for (int i = 0; i < ids.Count; i++)
                {
                    int id = ids[i];
                    if (id == rootId || id == 0) { continue; }
                    if (found.Contains(id)) { continue; }
                    if (!frontier.Contains(parents[i])) { continue; }
                    found.Add(id);
                    next.Add(id);
                }
                frontier = next;
            }

            return found.ToArray();
        }
        finally
        {
            CloseHandle(snapshot);
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

function Get-WacProcessDescendantId {
    <#
    .SYNOPSIS
        The ids below one process id, or $null when the tree could not be read at all.
    .DESCRIPTION
        $null and an empty array are different answers and the caller has to keep them apart: one
        means "this process has no children", the other means "nobody knows", and only the first is
        evidence.
    #>
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    if (-not (Initialize-WacProcessTreeNative)) { return $null }

    $ids = $null
    try { $ids = [WacProcessTree]::GetDescendantIds($ProcessId) } catch { return $null }
    if ($null -eq $ids) { return $null }

    # The comma is the whole point: `return @()` writes NOTHING to the output stream, so a process
    # with no children came back as $null and was read as "nobody knows" - the one distinction this
    # function exists to make. Measured: it turned a completely successful tree kill into
    # Proven=$false.
    return , ([int[]]$ids)
}

function Open-WacProcessBinding {
    <#
    .SYNOPSIS
        A kernel handle bound to whatever owns an id at this instant, plus why it could not be bound.
    .DESCRIPTION
        Split out of Stop-WacProcessTree because a tree needs one of these per identity, and the
        injected opener seam has to reach every one of them rather than only the root.
    .OUTPUTS
        Id, Handle (IntPtr::Zero when nothing was bound), Win32Error.
    #>
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $handle = [IntPtr]::Zero
    # -1 is not a Win32 code. It stands for "no handle could be bound at all", which is a different
    # claim from "nothing owns this id" and must never be reported as one.
    $win32 = -1

    if ($script:ProcessHandleOpener) {
        $injected = & $script:ProcessHandleOpener $ProcessId
        $handle = [IntPtr]$injected.Handle
        $win32 = [int]$injected.Win32Error
    }
    elseif (Initialize-WacNative) {
        $win32 = [WacNative]::OpenProcessForTermination($ProcessId, [ref]$handle)
    }

    $parentId = -1
    $created = 0L
    $identityKnown = $false
    if ($handle -ne [IntPtr]::Zero) {
        try { $identityKnown = [WacNative]::ReadProcessIdentity($handle, [ref]$parentId, [ref]$created) }
        catch { $identityKnown = $false }
    }
    return [PSCustomObject]@{
        Id = $ProcessId; Handle = $handle; Win32Error = $win32
        ParentId = $parentId; Created = $created; IdentityKnown = $identityKnown
    }
}

function New-WacTerminationResult {
    <#
    .SYNOPSIS
        The structured verdict Stop-WacProcessTree returns.
    .DESCRIPTION
        Proven is the only field a caller may treat as evidence, and it is $true ONLY when every
        identity the call bound is known to have exited. The rest is why: Bound is what was proved,
        Survivor is what was not, and Reason is the sentence for the log.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$Root,
        [Parameter(Mandatory = $true)][bool]$Proven,
        [Parameter(Mandatory = $true)][string]$Reason,
        [AllowEmptyCollection()][int[]]$Bound = @(),
        [AllowEmptyCollection()][int[]]$Survivor = @(),
        $TaskkillExit = $null
    )

    return [PSCustomObject]@{
        Root         = $Root
        Proven       = $Proven
        Bound        = [int[]]$Bound
        Survivor     = [int[]]$Survivor
        TaskkillExit = $TaskkillExit
        Reason       = $Reason
    }
}

function Stop-WacProcessTree {
    <#
    .SYNOPSIS
        Kills a process AND its descendants, and reports termination as PROVEN only when every one
        of them is known to have exited.
    .DESCRIPTION
        Snapshot entries are only candidates. Each one is opened before termination and its
        parent ID and creation time are read from that same handle. It is admitted only when its
        parent is already bound and it is not older than that parent. This rejects stale parent
        IDs and IDs reused between enumeration and binding. taskkill /T is not used, because its
        independent walk would bypass those checks. TaskkillExit remains null for compatibility.

        Termination and exit verification use the retained handles, never a later PID lookup.
        An unreadable tree or a candidate whose identity cannot be proved leaves Proven false.

        A Windows job object with kill-on-close would be stronger still, because a job assigned AT
        CREATION cannot be escaped by a grandchild. It is not reachable from here.
        System.Diagnostics.Process on either shipped host exposes neither CREATE_SUSPENDED nor
        STARTUPINFOEX's PROC_THREAD_ATTRIBUTE_JOB_LIST, so AssignProcessToJobObject could only run
        after the child is already executing - the same escape window this pays for - and the child
        that matters most, the elevated relaunch, runs at high integrity where a medium-integrity
        parent cannot obtain the PROCESS_SET_QUOTA the assignment requires.

        A process spawned WHILE the kill is in flight is caught by re-enumerating after each pass.
        That loop is bounded: a tree still spawning after three passes is reported as unproven
        rather than chased forever.
    .OUTPUTS
        Root, Proven, Bound, Survivor, TaskkillExit, Reason. Only Proven is evidence.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [int]$TimeoutMs = 10000
    )

    if ($TimeoutMs -le 0) { $TimeoutMs = 1 }
    [void](Initialize-WacNative)

    $root = Open-WacProcessBinding -ProcessId $ProcessId
    if ($root.Handle -eq [IntPtr]::Zero) {
        # ERROR_INVALID_PARAMETER: nothing owns this id, so the target is gone and the caller got
        # what it asked for. Every OTHER failure is unverifiable, and unverifiable is not success.
        if ($root.Win32Error -eq 87) {
            return (New-WacTerminationResult -Root $ProcessId -Proven $true `
                    -Reason 'Nothing owns the target id, so the target is gone.')
        }

        Write-WacLog -Level WARNING -Component 'Process' -Message 'The target could not be opened, so termination is unverifiable.' -Data @{
            pid        = $ProcessId
            win32Error = $root.Win32Error
        }
        return (New-WacTerminationResult -Root $ProcessId -Proven $false -Survivor @($ProcessId) `
                -Reason ('The target could not be opened (Win32 error {0}), so termination is unverifiable.' -f $root.Win32Error))
    }

    $bound = New-Object 'System.Collections.Generic.List[object]'
    [void]$bound.Add($root)
    $unreadable = New-Object 'System.Collections.Generic.List[int]'
    $treeUnreadable = $false
    $taskkillExit = $null

    # Binds every id in the supplied list that is not bound already. An id nothing owns any more is
    # simply gone; an id that refuses to open is recorded and keeps the verdict at unproven.
    $bindEach = {
        param($Candidate)

        foreach ($id in @($Candidate)) {
            $known = $false
            foreach ($entry in $bound) { if ([int]$entry.Id -eq [int]$id) { $known = $true; break } }
            if ($known -or $unreadable.Contains([int]$id)) { continue }

            $binding = Open-WacProcessBinding -ProcessId ([int]$id)
            if ($binding.Handle -ne [IntPtr]::Zero) {
                if (-not $binding.IdentityKnown) {
                    [void]$unreadable.Add([int]$id)
                    [WacNative]::CloseProcessHandle($binding.Handle)
                    continue
                }
                $parent = @($bound | Where-Object { $_.Id -eq $binding.ParentId })
                if ($parent.Count -ne 1 -or $binding.Created -lt $parent[0].Created) {
                    # A different parent, or a child older than its alleged parent, is not ours.
                    [WacNative]::CloseProcessHandle($binding.Handle)
                    continue
                }
                [void]$bound.Add($binding)
                continue
            }
            if ($binding.Win32Error -eq 87) { continue }
            [void]$unreadable.Add([int]$id)
        }
    }

    try {
        # THE ROOT IS CHECKED BEFORE THE TREE, and the order is the whole point.
        #
        # A recorded parent id is NOT proof of parentage once that parent is dead: Windows never
        # clears th32ParentProcessID when a parent exits, and it reuses process ids. So an exited
        # target keeps "children" in the snapshot that are unrelated live processes which merely
        # inherited its number. Measured on this machine: over 400 rounds of start-exit-enumerate
        # under six churn workers, 12 rounds (3%) showed an already-exited id with recorded
        # children, and they were real live processes - conhost.exe, and once Microsoft.CmdPal.UI.exe.
        #
        # Reading the tree first therefore did two bad things: it skipped this fast path, and then it
        # BOUND AND TERMINATED those unrelated processes. A tree can only be owned if it was observed
        # while its root was alive; a root that had already exited when the call began never gave us
        # one, so the honest answer is "the target is gone" and nothing is killed.
        if ([WacNative]::WaitForProcessExit($root.Handle, 0) -eq 0) {
            return (New-WacTerminationResult -Root $ProcessId -Proven $true -Bound @($ProcessId) `
                    -Reason 'The target had already exited before this call, so no live tree was ever observed and nothing was killed.')
        }

        if (-not $root.IdentityKnown) {
            return (New-WacTerminationResult -Root $ProcessId -Proven $false -Survivor @($ProcessId) `
                    -Reason 'The bound root identity could not be read; no process was terminated.')
        }

        $descendant = Get-WacProcessDescendantId -ProcessId $ProcessId
        if ($null -eq $descendant) { $treeUnreadable = $true } else { & $bindEach $descendant }

        # Never hand the root to taskkill /T: its independent PID walk bypasses our identity proof.
        # TaskkillExit stays null in the compatibility result; termination uses only bound handles.
        $waitDeadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)

        # Terminate validated identities at once rather than waiting out the caller's bound first.
        #
        # Three passes: every pass after the first exists only for a process that appeared DURING
        # the kill, and a tree still spawning after three is not settling - the caller needs an
        # answer more than it needs another round.
        for ($pass = 1; $pass -le 3; $pass++) {
            $null = $pass
            $pending = @($bound | Where-Object { [WacNative]::WaitForProcessExit($_.Handle, 0) -ne 0 })

            # The escalation goes through each identity's OWN handle rather than its id, so it
            # cannot land on whatever inherited the number while taskkill was running.
            foreach ($entry in $pending) { [void][WacNative]::TerminateBoundProcess($entry.Handle) }

            # TerminateProcess is documented as asynchronous: it ASKS for termination and returns
            # before the process is gone. This wait is the deterministic signal that it finished.
            # The floor keeps a caller's very short bound from turning "asked" into "gave up"; the
            # ceiling keeps a long one from being spent here rather than on the rescan.
            #
            # The floor is itself capped by $TimeoutMs, which the caller claimed from the run budget
            # or the recovery reserve. Without that cap a bound of 200 ms still waited a full second
            # here - a small overrun, but an unaccounted one, and per tree (ledger WAC-06R).
            $floor = [int][Math]::Min(1000, $TimeoutMs)
            $left = [int][Math]::Max(0, ($waitDeadline - [datetime]::UtcNow).TotalMilliseconds)
            $killDeadline = [datetime]::UtcNow.AddMilliseconds([Math]::Min(5000, [Math]::Max($floor, $left)))
            foreach ($entry in $pending) {
                $wait = [int][Math]::Max(0, ($killDeadline - [datetime]::UtcNow).TotalMilliseconds)
                [void][WacNative]::WaitForProcessExit($entry.Handle, $wait)
            }

            $descendant = Get-WacProcessDescendantId -ProcessId $ProcessId
            if ($null -eq $descendant) { $treeUnreadable = $true; break }
            if (@($descendant).Count -eq 0) { break }
            & $bindEach $descendant
        }

        $survivor = New-Object 'System.Collections.Generic.List[int]'
        foreach ($entry in $bound) {
            if ([WacNative]::WaitForProcessExit($entry.Handle, 0) -ne 0) { [void]$survivor.Add([int]$entry.Id) }
        }
        foreach ($id in $unreadable) { [void]$survivor.Add([int]$id) }

        $proven = (($survivor.Count -eq 0) -and (-not $treeUnreadable))
        $reason = if ($proven) {
            'Every bound identity in the tree is known to have exited.'
        }
        elseif ($treeUnreadable) {
            'The process tree could not be enumerated, so nothing below the target was proven gone.'
        }
        else {
            '{0} identity/identities in the tree could not be proven gone.' -f $survivor.Count
        }

        if (-not $proven) {
            Write-WacLog -Level WARNING -Component 'Process' -Message 'Termination could not be established; part of the target tree may still be running.' -Data @{
                pid            = $ProcessId
                survivors      = (@($survivor.ToArray()) -join ',')
                treeUnreadable = $treeUnreadable
                taskkillExit   = $(if ($null -eq $taskkillExit) { 'none' } else { [string]$taskkillExit })
            }
        }

        return (New-WacTerminationResult -Root $ProcessId -Proven $proven -Reason $reason `
                -Bound @(@($bound | ForEach-Object { [int]$_.Id })) -Survivor @($survivor.ToArray()) `
                -TaskkillExit $taskkillExit)
    }
    finally {
        foreach ($entry in $bound) { [WacNative]::CloseProcessHandle($entry.Handle) }
    }
}
