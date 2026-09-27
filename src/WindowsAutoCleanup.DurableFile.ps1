<#
.SYNOPSIS
    Writes and renames that are on disk when the call returns, so a power cut leaves the previous
    record or the new one - never a torn one.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1.

    WHY IT EXISTS. The live power-cut campaign (2026-09-27) cut a guest seconds after the installer
    and the uninstaller published a transaction record. File.WriteAllText had left the bytes in the
    cache and File.Replace had not made the rename durable, so the machine came back with a record
    that could not be parsed. Both the next install and the next uninstall refused on it - which is
    correct, because unreadable is never absence - and so the machine could do neither, forever.

    The two halves are separate facts and both are needed: FlushFileBuffers (FileStream.Flush with
    $true) puts the file's DATA on disk; MOVEFILE_WRITE_THROUGH makes MoveFileExW return only once
    the RENAME is on disk. Research: .ai/RESEARCH/durable-rename-windows.md (MoveFileExW docs; the
    same pattern as python-atomicwrites).
#>

function Initialize-WacDurableFile {
    if ('WacDurableFile' -as [type]) { return }
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class WacDurableFile
{
    private const int MOVEFILE_REPLACE_EXISTING = 0x1;
    private const int MOVEFILE_WRITE_THROUGH = 0x8;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileExW(string lpExistingFileName, string lpNewFileName, int dwFlags);

    public static int MoveFlags(bool replace)
    {
        return MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0);
    }

    // 0 on success, otherwise the Win32 error.
    public static int Move(string source, string destination, bool replace)
    {
        return MoveFileExW(source, destination, MoveFlags(replace)) ? 0 : Marshal.GetLastWin32Error();
    }
}
'@
}

function Write-WacFileDurable {
    <#
    .SYNOPSIS
        Creates or truncates Path, writes Bytes and returns only once they are on disk. Throws on failure.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes
    )

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Move-WacFileDurable {
    <#
    .SYNOPSIS
        Renames Source to Destination and returns only once the rename is on disk. Throws on failure.
    .DESCRIPTION
        Without -Replace an existing Destination fails the move, as File.Move does. With -Replace the
        swap is one rename: there is never a moment without a record at Destination.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [switch]$Replace
    )

    Initialize-WacDurableFile
    $code = [WacDurableFile]::Move($Source, $Destination, [bool]$Replace)
    if ($code -ne 0) { throw ('{0} could not be renamed to {1} (Win32 {2}).' -f $Source, $Destination, $code) }
}
