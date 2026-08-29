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

    // The same export under a raw-handle signature. The trusted-directory primitive hands its
    // handle back to PowerShell and closes it explicitly, which a SafeFileHandle would fight over.
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileRaw(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(
        SafeFileHandle handle, int ObjectType, int SecurityInfo,
        IntPtr ppsidOwner, IntPtr ppsidGroup, IntPtr ppDacl, IntPtr ppSacl,
        out IntPtr ppSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
        IntPtr SecurityDescriptor, uint RequestedStringSDRevision, int SecurityInformation,
        out IntPtr StringSecurityDescriptor, out int StringSecurityDescriptorLen);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

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

    // The trusted-directory primitive. FILE_SHARE_READ_WRITE deliberately WITHHOLDS
    // FILE_SHARE_DELETE: while such a handle is open the object cannot be renamed or deleted by
    // anyone, which is what turns "verified once" into "verified and pinned".
    private const uint FILE_LIST_DIRECTORY          = 0x00000001;
    private const uint FILE_TRAVERSE                = 0x00000020;
    private const uint READ_CONTROL_ACCESS          = 0x00020000;
    private const uint GENERIC_WRITE_ACCESS         = 0x40000000;
    private const uint FILE_SHARE_READ_ONLY         = 0x00000001;
    private const uint FILE_SHARE_READ_WRITE        = 0x00000003;
    private const uint FILE_ATTRIBUTE_REPARSE_FLAG  = 0x00000400;
    private const uint FILE_ATTRIBUTE_NORMAL_FLAG   = 0x00000080;
    private const uint FILE_DIRECTORY_FILE_OPT      = 0x00000001;
    private const uint FILE_NON_DIRECTORY_FILE_OPT  = 0x00000040;
    // The same bit as FILE_LIST_DIRECTORY, under the name it carries on a non-directory object.
    private const uint FILE_READ_DATA_ACCESS        = 0x00000001;
    private const uint FILE_CREATE_DISPOSITION      = 2;
    private const int  SE_FILE_OBJECT               = 1;
    private const int  OWNER_AND_DACL               = 0x00000001 | 0x00000004;
    private const uint SDDL_REVISION_1              = 1;

    private static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    // Pack = 4 is load-bearing, not decoration. Every field of the Win32 struct is a DWORD or a
    // pair of them, so the native layout is 4-byte aligned throughout - but the FILETIMEs are
    // declared here as long, and under the default packing a long is aligned to 8, which inserts
    // four bytes of padding after dwFileAttributes and shifts EVERY LATER FIELD. Measured before
    // this was fixed: NumberOfLinks read back as 2031616 (0x1F0000) for an ordinary one-link file.
    // It went unnoticed while FileAttributes, at offset 0, was the only field anyone read.
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_DISPOSITION_INFORMATION { [MarshalAs(UnmanagedType.U1)] public bool DeleteFile; }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtSetInformationFile(
        SafeFileHandle FileHandle, out IO_STATUS_BLOCK IoStatusBlock,
        ref FILE_DISPOSITION_INFORMATION FileInformation, int Length, int FileInformationClass);

    // Opening a leaf RELATIVE to a directory handle is the only way to stop an ancestor swap from
    // redirecting the open, and managed code cannot express it: every .NET open takes a path string,
    // which the kernel resolves from the volume root every time.
    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtOpenFile(
        out IntPtr FileHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes,
        out IO_STATUS_BLOCK IoStatusBlock, uint ShareAccess, uint OpenOptions);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtCreateFile(
        out IntPtr FileHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes,
        out IO_STATUS_BLOCK IoStatusBlock, IntPtr AllocationSize, uint FileAttributes,
        uint ShareAccess, uint CreateDisposition, uint CreateOptions, IntPtr EaBuffer, uint EaLength);

    private const uint OBJ_CASE_INSENSITIVE           = 0x00000040;
    private const uint SYNCHRONIZE_ACCESS             = 0x00100000;
    private const uint FILE_OPEN_REPARSE_POINT_OPT    = 0x00200000;
    private const uint FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020;
    private const uint FILE_OPEN_FOR_BACKUP_INTENT    = 0x00004000;

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
        CloseNativeHandle(handle);
    }

    // Closes any handle this type hands out. One implementation under an honest name, because the
    // directory primitive below returns handles that are not processes.
    public static void CloseNativeHandle(IntPtr handle)
    {
        if (handle != IntPtr.Zero) { CloseHandle(handle); }
    }

    // Every right the directory primitive needs and nothing else: list and traverse so the handle
    // can anchor a relative create, read-attributes so the reparse test can be answered from the
    // handle, and READ_CONTROL so the owner and DACL can be read from the handle too.
    private const uint DIRECTORY_ACCESS =
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES |
        READ_CONTROL_ACCESS | SYNCHRONIZE_ACCESS;

    // Opens an EXISTING directory and PINS it: the share mode withholds FILE_SHARE_DELETE, so for
    // as long as the returned handle lives nobody can rename the object out of the way or delete
    // it. FILE_FLAG_OPEN_REPARSE_POINT means a link is opened as the link, so DescribeHandle can
    // report it and the caller can refuse instead of silently following it somewhere else.
    //
    // Returns 0 with the handle set, otherwise the Win32 error with handle = IntPtr.Zero. The
    // caller owns the handle and must pass it to CloseNativeHandle.
    public static int OpenPinnedDirectory(string path, out IntPtr handle)
    {
        handle = IntPtr.Zero;

        IntPtr raw = CreateFileRaw(
            ExtendedPath(path), DIRECTORY_ACCESS, FILE_SHARE_READ_WRITE, IntPtr.Zero,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);

        if (raw == INVALID_HANDLE) { return Marshal.GetLastWin32Error(); }
        handle = raw;
        return 0;
    }

    // What the handle itself says the object is. attributes carries FILE_ATTRIBUTE_REPARSE_POINT
    // when the object is a link, and finalPath is then left null on purpose: what
    // GetFinalPathNameByHandleW returns for a handle opened WITHOUT following the link is not
    // documented, so it must not be turned into an identity claim. A caller that sees the reparse
    // bit has all it needs - refuse.
    //
    // Returns 0 on success, otherwise the Win32 error.
    public static int DescribeHandle(IntPtr handle, out uint attributes, out string finalPath)
    {
        attributes = 0;
        finalPath = null;

        // ownsHandle: false throughout this section. The raw handle belongs to the caller, and a
        // SafeFileHandle that owned it would close it when the GC got round to the wrapper.
        SafeFileHandle borrowed = new SafeFileHandle(handle, false);

        BY_HANDLE_FILE_INFORMATION information;
        if (!GetFileInformationByHandle(borrowed, out information)) { return Marshal.GetLastWin32Error(); }

        attributes = information.FileAttributes;
        if ((attributes & FILE_ATTRIBUTE_REPARSE_FLAG) != 0) { return 0; }

        finalPath = FinalPathOf(borrowed);
        if (finalPath == null) { return Marshal.GetLastWin32Error(); }
        return 0;
    }

    // The owner and DACL OF THE OPEN OBJECT, as SDDL. Reading them from the handle rather than from
    // the name is the point: a pathname read is a second, independent resolution, and the whole
    // reason this primitive exists is that the second resolution can land somewhere else.
    //
    // Returns 0 on success, otherwise the Win32 / error code. Nothing here writes a descriptor.
    public static int GetHandleDescriptor(IntPtr handle, out string sddl)
    {
        sddl = null;

        IntPtr descriptor;
        uint status = GetSecurityInfo(
            new SafeFileHandle(handle, false), SE_FILE_OBJECT, OWNER_AND_DACL,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out descriptor);
        if (status != 0) { return (int)status; }

        try
        {
            IntPtr text;
            int length;
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor, SDDL_REVISION_1, OWNER_AND_DACL, out text, out length))
            {
                return Marshal.GetLastWin32Error();
            }

            try { sddl = Marshal.PtrToStringUni(text); }
            finally { LocalFree(text); }
        }
        finally
        {
            LocalFree(descriptor);
        }

        return 0;
    }

    // Creates ONE new child under a directory handle, and FAILS if the name is already taken.
    //
    // Both halves matter. FILE_CREATE is the collision-failing disposition - an existing name comes
    // back as STATUS_OBJECT_NAME_COLLISION (0xC0000035) rather than being opened, truncated or
    // adopted, which is exactly the behaviour New-Item -Force and FileMode.Create do not have. And
    // the create is RELATIVE to a directory handle the caller has already proved, so the kernel
    // resolves the name against an object we hold open instead of walking a path from the volume
    // root: no swap of any ancestor between the proof and the create can move where it lands.
    //
    // Returns an NTSTATUS: 0 with the handle set, otherwise the failure with handle = IntPtr.Zero.
    // The caller owns the handle.
    public static int CreateBoundDirectory(IntPtr parent, string name, out IntPtr handle)
    {
        return CreateRelative(parent, name, true, out handle);
    }

    public static int CreateBoundFile(IntPtr parent, string name, out IntPtr handle)
    {
        return CreateRelative(parent, name, false, out handle);
    }

    // Opens ONE EXISTING child file under a directory handle, for reading only, and reports what
    // the object on the other end of that name actually turned out to be.
    //
    // Three properties, all load-bearing, because the caller is about to read - or to decide the
    // fate of - a file whose NAME is predictable and whose content it did not necessarily write:
    //   * BOUND. The name is resolved against a directory object the caller holds open, so nothing
    //     that happens to any ancestor's name can move where the open lands.
    //   * NO-FOLLOW. FILE_OPEN_REPARSE_POINT binds to the link itself, and 'attributes' then carries
    //     FILE_ATTRIBUTE_REPARSE_POINT so the caller can refuse instead of reading somewhere else.
    //   * LINK-COUNTED. 'links' is BY_HANDLE_FILE_INFORMATION.NumberOfLinks. A hard link is a second
    //     directory entry for the SAME file, so it carries no reparse attribute and resolves to a
    //     perfectly ordinary path - a reparse check misses it completely. A count above 1 means the
    //     bytes behind this name are also reachable under another name that this tool never chose.
    //
    // FILE_NON_DIRECTORY_FILE makes a directory planted at the name an open failure rather than a
    // surprise. Returns an NTSTATUS: 0 with the handle set, otherwise the failure with
    // handle = IntPtr.Zero. The caller owns the handle.
    public static int OpenBoundLeafForRead(
        IntPtr parent, string name, out IntPtr handle, out uint attributes, out uint links)
    {
        handle = IntPtr.Zero;
        attributes = 0;
        links = 0;

        if (string.IsNullOrEmpty(name)) { return unchecked((int)0xC000003B); }
        if (name.IndexOf('\\') >= 0 || name.IndexOf('/') >= 0) { return unchecked((int)0xC000003B); }

        IntPtr namePtr = Marshal.StringToHGlobalUni(name);
        IntPtr unicodePtr = IntPtr.Zero;
        IntPtr opened = IntPtr.Zero;
        try
        {
            UNICODE_STRING unicode = new UNICODE_STRING();
            unicode.Length = (ushort)(name.Length * 2);
            unicode.MaximumLength = (ushort)(name.Length * 2);
            unicode.Buffer = namePtr;

            unicodePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(unicode, unicodePtr, false);

            OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            objectAttributes.RootDirectory = parent;
            objectAttributes.ObjectName = unicodePtr;
            objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;

            IO_STATUS_BLOCK iosb;
            int status = NtOpenFile(
                out opened, FILE_READ_DATA_ACCESS | FILE_READ_ATTRIBUTES | SYNCHRONIZE_ACCESS,
                ref objectAttributes, out iosb, FILE_SHARE_READ_ONLY,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE_OPT | FILE_OPEN_REPARSE_POINT_OPT);
            if (status != 0) { opened = IntPtr.Zero; return status; }

            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(new SafeFileHandle(opened, false), out information))
            {
                // STATUS_UNSUCCESSFUL. An object that will not describe itself is unverifiable, and
                // the handle is dropped here so no caller can read through it anyway.
                return unchecked((int)0xC0000001);
            }

            attributes = information.FileAttributes;
            links = information.NumberOfLinks;
            handle = opened;
            opened = IntPtr.Zero;
            return 0;
        }
        finally
        {
            if (opened != IntPtr.Zero) { CloseHandle(opened); }
            if (unicodePtr != IntPtr.Zero) { Marshal.FreeHGlobal(unicodePtr); }
            Marshal.FreeHGlobal(namePtr);
        }
    }

    private static int CreateRelative(IntPtr parent, string name, bool directory, out IntPtr handle)
    {
        handle = IntPtr.Zero;
        if (string.IsNullOrEmpty(name)) { return unchecked((int)0xC000003B); }
        // A single component only. A separator would put the resolution back in the kernel's hands
        // and defeat the anchoring this whole function exists for.
        if (name.IndexOf('\\') >= 0 || name.IndexOf('/') >= 0) { return unchecked((int)0xC000003B); }

        IntPtr namePtr = Marshal.StringToHGlobalUni(name);
        IntPtr unicodePtr = IntPtr.Zero;
        try
        {
            UNICODE_STRING unicode = new UNICODE_STRING();
            unicode.Length = (ushort)(name.Length * 2);
            unicode.MaximumLength = (ushort)(name.Length * 2);
            unicode.Buffer = namePtr;

            unicodePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(unicode, unicodePtr, false);

            OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES();
            attributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            attributes.RootDirectory = parent;
            attributes.ObjectName = unicodePtr;
            attributes.Attributes = OBJ_CASE_INSENSITIVE;

            uint access = directory ? DIRECTORY_ACCESS : (GENERIC_WRITE_ACCESS | SYNCHRONIZE_ACCESS);
            uint share = directory ? FILE_SHARE_READ_WRITE : FILE_SHARE_READ_ONLY;
            uint options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT_OPT |
                (directory
                    ? (FILE_DIRECTORY_FILE_OPT | FILE_OPEN_FOR_BACKUP_INTENT)
                    : FILE_NON_DIRECTORY_FILE_OPT);

            IO_STATUS_BLOCK iosb;
            return NtCreateFile(
                out handle, access, ref attributes, out iosb, IntPtr.Zero,
                FILE_ATTRIBUTE_NORMAL_FLAG, share, FILE_CREATE_DISPOSITION, options, IntPtr.Zero, 0);
        }
        finally
        {
            if (unicodePtr != IntPtr.Zero) { Marshal.FreeHGlobal(unicodePtr); }
            Marshal.FreeHGlobal(namePtr);
        }
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
    // A REPARSE LEAF IS NOT EXEMPT FROM CONTAINMENT, and an earlier version of this function got
    // that wrong. FILE_FLAG_OPEN_REPARSE_POINT stops the FINAL component being followed; every
    // INTERMEDIATE component is still resolved. Skipping the identity proof for links therefore let
    // an ancestor swapped to a junction redirect the open to a link OUTSIDE the allow-list, and that
    // link was then unlinked - the exact escape the threat model forbids.
    //
    // The fix is structural rather than another check. The parent is opened and proved first, and
    // the leaf is then opened RELATIVE TO THAT HANDLE with NtOpenFile: the kernel resolves the leaf
    // name against a directory object we hold open, not against a path it walks from the volume root,
    // so no later swap of any ancestor can reach it. The link case keeps FILE_OPEN_REPARSE_POINT, so
    // the LINK is what gets removed and its target is still never followed.
    //
    // FILE_DISPOSITION_INFORMATION only MARKS the object; the unlink happens when the last handle
    // closes, which is why the using block is load-bearing rather than tidy.
    public static int DeleteBoundLeaf(
        string path, string expectedFinalPath, bool openReparsePoint, out int win32Error, out int ntStatus)
    {
        win32Error = 0;
        ntStatus = 0;

        string parent = null;
        string leaf = null;
        if (!SplitLeaf(expectedFinalPath, out parent, out leaf)) { return DELETE_IDENTITY_MISMATCH; }

        // The anchor. Opened WITHOUT the reparse flag on purpose: a directory that is itself a link
        // must resolve, so that its proved final path is the real directory the leaf lives in.
        //
        // The OPEN takes the extended-length form and the COMPARISON does not. Deriving the parent
        // from expectedFinalPath drops the \\?\ prefix the caller had applied, and without it a
        // parent past MAX_PATH cannot be opened at all - measured, it silently deleted nothing.
        using (SafeFileHandle parentHandle = CreateFileW(
            ExtendedPath(parent), FILE_READ_ATTRIBUTES, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero))
        {
            if (parentHandle.IsInvalid)
            {
                win32Error = Marshal.GetLastWin32Error();
                return DELETE_OPEN_FAILED;
            }

            // Proving the PARENT proves the whole ancestor chain at this instant, and the relative
            // open below then pins it, so a swap after this point cannot move the target.
            string actualParent = FinalPathOf(parentHandle);
            if (actualParent == null) { win32Error = Marshal.GetLastWin32Error(); return DELETE_IDENTITY_MISMATCH; }
            if (!string.Equals(actualParent, parent, StringComparison.OrdinalIgnoreCase))
            {
                return DELETE_IDENTITY_MISMATCH;
            }

            IntPtr rawLeaf;
            int status = OpenRelative(parentHandle, leaf, openReparsePoint, out rawLeaf);
            if (status != 0) { ntStatus = status; return DELETE_OPEN_FAILED; }

            using (SafeFileHandle leafHandle = new SafeFileHandle(rawLeaf, true))
            {
                // Defence in depth for a NON-link: the anchored open already makes redirection
                // impossible, and this still refuses if the leaf is not the object we expected.
                if (!openReparsePoint)
                {
                    string actual = FinalPathOf(leafHandle);
                    if (actual == null) { win32Error = Marshal.GetLastWin32Error(); return DELETE_IDENTITY_MISMATCH; }
                    if (!string.Equals(actual, expectedFinalPath, StringComparison.OrdinalIgnoreCase))
                    {
                        return DELETE_IDENTITY_MISMATCH;
                    }
                }

                IO_STATUS_BLOCK iosb;
                FILE_DISPOSITION_INFORMATION disposition = new FILE_DISPOSITION_INFORMATION();
                disposition.DeleteFile = true;

                ntStatus = NtSetInformationFile(
                    leafHandle, out iosb, ref disposition,
                    Marshal.SizeOf(typeof(FILE_DISPOSITION_INFORMATION)), FileDispositionInformation);

                if (ntStatus != 0) { return DELETE_DISPOSITION_FAILED; }
                return DELETE_OK;
            }
        }
    }

    // Splits a full path into its directory and its last component. Refuses anything without both,
    // because a leaf with no parent cannot be anchored and must not fall back to an unbound open.
    private static bool SplitLeaf(string full, out string parent, out string leaf)
    {
        parent = null;
        leaf = null;
        if (string.IsNullOrEmpty(full)) { return false; }

        string trimmed = full.TrimEnd('\\');
        int cut = trimmed.LastIndexOf('\\');
        if (cut <= 0 || cut == trimmed.Length - 1) { return false; }

        parent = trimmed.Substring(0, cut);
        leaf = trimmed.Substring(cut + 1);
        // A volume root keeps its trailing separator, otherwise "C:" names the current directory.
        if (parent.Length == 2 && parent[1] == ':') { parent = parent + "\\"; }
        return leaf.Length > 0;
    }

    // The extended-length form of an already-normalised absolute path. Only ever used for an OPEN;
    // every comparison stays on the plain form, because GetFinalPathNameByHandleW's answer has the
    // prefix stripped before it is compared.
    private static string ExtendedPath(string full)
    {
        if (string.IsNullOrEmpty(full)) { return full; }
        if (full.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) { return full; }
        // A UNC path takes the \\?\UNC\ form; anything else takes the plain prefix.
        if (full.StartsWith(@"\\", StringComparison.Ordinal)) { return @"\\?\UNC\" + full.Substring(2); }
        return @"\\?\" + full;
    }

    // The handle's own final path, with the extended-length prefix and any trailing separator
    // removed so it compares against a normalised path. Null when the object cannot answer.
    private static string FinalPathOf(SafeFileHandle handle)
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
        if (length == 0) { return null; }

        string actual = buffer.ToString();
        if (actual.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) { actual = actual.Substring(4); }
        return actual.TrimEnd('\\');
    }

    // Opens one name relative to a directory handle. The name must be a single component: anything
    // with a separator in it would be resolved by the kernel and defeat the anchoring.
    private static int OpenRelative(SafeFileHandle parent, string name, bool noFollow, out IntPtr handle)
    {
        handle = IntPtr.Zero;
        if (name.IndexOf('\\') >= 0 || name.IndexOf('/') >= 0) { return unchecked((int)0xC000003B); }

        IntPtr namePtr = Marshal.StringToHGlobalUni(name);
        IntPtr unicodePtr = IntPtr.Zero;
        try
        {
            UNICODE_STRING unicode = new UNICODE_STRING();
            unicode.Length = (ushort)(name.Length * 2);
            unicode.MaximumLength = (ushort)(name.Length * 2);
            unicode.Buffer = namePtr;

            unicodePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(unicode, unicodePtr, false);

            OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES();
            attributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            attributes.RootDirectory = parent.DangerousGetHandle();
            attributes.ObjectName = unicodePtr;
            attributes.Attributes = OBJ_CASE_INSENSITIVE;

            uint options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT;
            if (noFollow) { options |= FILE_OPEN_REPARSE_POINT_OPT; }

            IO_STATUS_BLOCK iosb;
            return NtOpenFile(
                out handle, DELETE_ACCESS | FILE_READ_ATTRIBUTES | SYNCHRONIZE_ACCESS,
                ref attributes, out iosb, FILE_SHARE_READ_WRITE_DELETE, options);
        }
        finally
        {
            if (unicodePtr != IntPtr.Zero) { Marshal.FreeHGlobal(unicodePtr); }
            Marshal.FreeHGlobal(namePtr);
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
