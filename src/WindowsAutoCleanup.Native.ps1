<#
.SYNOPSIS
    The native interop surface: the embedded WacNative type and the loader that compiles it.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1; see that file for why the parts are dot-sourced
    rather than imported. It is separate because two unrelated responsibilities depend on it - path
    verification uses GetFinalPath and DeleteOnReboot, process termination uses the handle-bound
    Open/Wait/Terminate trio - so it belongs with neither of them.
#>

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
    private const uint DELETE_ACCESS                = 0x00010000;
    private const int  FileDispositionInformation   = 13;

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_DISPOSITION_INFORMATION { [MarshalAs(UnmanagedType.U1)] public bool DeleteFile; }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtSetInformationFile(
        SafeFileHandle FileHandle, out IO_STATUS_BLOCK IoStatusBlock,
        ref FILE_DISPOSITION_INFORMATION FileInformation, int Length, int FileInformationClass);

    // Outcomes of DeleteBoundLeaf. Deliberately coarse: the caller maps them onto the counters it
    // already has, and the Win32 / NTSTATUS values carry the detail.
    public const int DELETE_OK                 = 0;
    public const int DELETE_OPEN_FAILED        = 1;
    public const int DELETE_IDENTITY_MISMATCH  = 2;
    public const int DELETE_DISPOSITION_FAILED = 3;

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

    // Deletes the object at 'path' through a handle BOUND to it, so nothing swapped between the
    // identity check and the delete can redirect the operation.
    //
    // This is the whole point of the function. The predecessor opened a handle, asked it for the
    // final path, CLOSED it, then deleted by PATHNAME - a second, independent resolution of the same
    // name. That window was sub-millisecond rather than the multi-second per-directory one before
    // it, but it was still a window, and this tool runs as SYSTEM over directories a standard user
    // can write to (C:\Windows\Temp grants BUILTIN\Users write by default). Here the handle opened
    // for the check is the same handle the disposition is set on, so the delete lands on the object
    // that was verified, or it does not land at all.
    //
    // openReparsePoint deletes the LINK itself and skips the identity check, because resolving the
    // link is exactly what must not happen when the link is the thing being removed.
    //
    // FILE_DISPOSITION_INFORMATION only MARKS the object; the unlink happens when the last handle
    // closes, which is why the using block is load-bearing rather than tidy.
    public static int DeleteBoundLeaf(
        string path, string expectedFinalPath, bool openReparsePoint, out int win32Error, out int ntStatus)
    {
        win32Error = 0;
        ntStatus = 0;

        uint flags = FILE_FLAG_BACKUP_SEMANTICS;
        if (openReparsePoint) { flags |= FILE_FLAG_OPEN_REPARSE_POINT; }

        using (SafeFileHandle handle = CreateFileW(
            path, DELETE_ACCESS | FILE_READ_ATTRIBUTES, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, flags, IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                win32Error = Marshal.GetLastWin32Error();
                return DELETE_OPEN_FAILED;
            }

            if (!openReparsePoint)
            {
                StringBuilder buffer = new StringBuilder(1024);
                uint length = GetFinalPathNameByHandleW(
                    handle, buffer, (uint)buffer.Capacity, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                if (length != 0 && length >= buffer.Capacity)
                {
                    buffer = new StringBuilder((int)length + 1);
                    length = GetFinalPathNameByHandleW(
                        handle, buffer, (uint)buffer.Capacity, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                }
                if (length == 0)
                {
                    win32Error = Marshal.GetLastWin32Error();
                    return DELETE_IDENTITY_MISMATCH;
                }

                string actual = buffer.ToString();
                if (actual.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) { actual = actual.Substring(4); }
                if (!string.Equals(actual.TrimEnd('\\'), expectedFinalPath, StringComparison.OrdinalIgnoreCase))
                {
                    return DELETE_IDENTITY_MISMATCH;
                }
            }

            IO_STATUS_BLOCK iosb;
            FILE_DISPOSITION_INFORMATION disposition = new FILE_DISPOSITION_INFORMATION();
            disposition.DeleteFile = true;

            ntStatus = NtSetInformationFile(
                handle, out iosb, ref disposition,
                Marshal.SizeOf(typeof(FILE_DISPOSITION_INFORMATION)), FileDispositionInformation);

            if (ntStatus != 0) { return DELETE_DISPOSITION_FAILED; }
            return DELETE_OK;
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
