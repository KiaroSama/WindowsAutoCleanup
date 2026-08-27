<#
.SYNOPSIS
    The handle-bound delete primitive and the classification of its outcomes.

.DESCRIPTION
    Split out of WindowsAutoCleanup.FileSystem.psm1 because it is one responsibility with its own
    threat model: it is the only place that decides HOW an object is removed, and the decision it
    encodes is the project's answer to the deletion race.

    The threat model is explicit and in scope. This tool runs as SYSTEM over directories a local
    standard user can write to - the default Windows Temp grants BUILTIN\Users write - so a user who
    can swap an ancestor for a junction is an attacker we defend against, not one we document away.

    The answer is that the identity proof and the delete happen on ONE handle. The predecessor
    opened a handle, asked it for the final path, closed it, and then deleted by PATHNAME, which is
    a second and independent resolution of the same name. Narrowing that window is not closing it.

    Dot-sourced, not imported: a nested module gets its own session state, and this code shares
    $script: state and helpers with the module that owns it.
#>

function Invoke-WacBoundDelete {
    <#
    .SYNOPSIS
        Deletes one object through a handle bound to it, or reports why it did not.
    .DESCRIPTION
        A thin, testable seam over WacNative::DeleteBoundLeaf. It exists so a suite can drive every
        native outcome - including ones that cannot be produced on demand, such as a disposition
        that fails with an unexpected NTSTATUS - without a real filesystem that behaves that way.
    .OUTPUTS
        0 deleted, 1 could not open, 2 identity mismatch, 3 disposition refused.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$LongPath,
        [Parameter(Mandatory = $true)][string]$ExpectedFinalPath,
        [switch]$OpenReparsePoint,
        [Parameter(Mandatory = $true)][ref]$Win32Error,
        [Parameter(Mandatory = $true)][ref]$NtStatus
    )

    if ($script:BoundDeleteOverride) {
        return (& $script:BoundDeleteOverride $LongPath $ExpectedFinalPath ([bool]$OpenReparsePoint) $Win32Error $NtStatus)
    }

    if (-not (Initialize-WacNative)) {
        # No native surface means no way to bind the delete to a handle, and deleting by pathname
        # instead would silently reopen the exact race this function exists to close.
        $Win32Error.Value = 0
        $NtStatus.Value = 0
        return 3
    }

    return [WacNative]::DeleteBoundLeaf(
        $LongPath, $ExpectedFinalPath, [bool]$OpenReparsePoint, $Win32Error, $NtStatus)
}

function Set-WacBoundDeleteOverride {
    <#
    .SYNOPSIS
        Test seam. Pass $null to restore the real native call.
    #>
    param([AllowNull()][scriptblock]$ScriptBlock)
    $script:BoundDeleteOverride = $ScriptBlock
}

function Get-WacBoundDeleteKind {
    <#
    .SYNOPSIS
        Maps a DeleteBoundLeaf result onto the failure kinds the counters are written against.
    .DESCRIPTION
        Measured on both hosts rather than assumed: a missing file opens with Win32 2, a non-empty
        directory refuses the disposition with STATUS_DIRECTORY_NOT_EMPTY (0xC0000101), and a
        read-only file refuses it with STATUS_CANNOT_DELETE (0xC0000121) - which is why that maps to
        Denied and earns the attribute-clearing retry rather than a hard failure.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$Code,
        [int]$Win32Error = 0,
        [int]$NtStatus = 0
    )

    if ($Code -eq 2) { return 'Identity' }

    if ($Code -eq 1) {
        if ($Win32Error -eq 2 -or $Win32Error -eq 3) { return 'NotFound' }
        if ($Win32Error -eq 5) { return 'Denied' }
        if ($Win32Error -eq 32 -or $Win32Error -eq 33) { return 'Busy' }
        return 'Other'
    }

    if ($Code -eq 3) {
        # Compared as unsigned text: an NTSTATUS is a negative [int] in PowerShell.
        $status = '0x{0:X8}' -f $NtStatus
        if ($status -eq '0xC0000101') { return 'NotEmpty' }
        if ($status -eq '0xC0000121' -or $status -eq '0xC0000022') { return 'Denied' }
        if ($status -eq '0xC0000043' -or $status -eq '0xC0000019') { return 'Busy' }
        if ($status -eq '0xC0000034' -or $status -eq '0xC000003A') { return 'NotFound' }
        return 'Other'
    }

    return 'Other'
}

function Test-WacDirectorySafeToDescend {
    <#
    .SYNOPSIS
        Re-proves, immediately before descending, that a directory is still the object we expect.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RootPath
    )

    if (-not (Test-WacIsWithinRoot -ChildPath $Path -RootPath $RootPath)) { return $false }
    if (Test-WacIsReparsePoint -Path $Path) { return $false }
    if (-not (Test-WacPathResolvesToItself -Path $Path)) { return $false }

    return $true
}
