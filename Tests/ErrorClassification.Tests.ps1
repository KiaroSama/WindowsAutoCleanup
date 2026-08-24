#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for Core's Get-WacIoFailureKind and for the deletion behaviour that depends on
    it: a directory left occupied must be recorded as SkippedNotEmpty so the retry pass sees it.

.DESCRIPTION
    Every classification case triggers the real I/O condition inside a disposable sandbox and passes
    the ErrorRecord that PowerShell actually produced. That matters because the two hosts disagree on
    whether an exception thrown by a .NET METHOD reaches a typed `catch [T]` directly or wrapped in
    MethodInvocationException: under Windows PowerShell 5.1 an IOException ("the directory is not
    empty") from [System.IO.Directory]::Delete was measured being caught by
    `catch [System.UnauthorizedAccessException]`, which silently disabled Remove-WacTree's second
    directory pass - half of the "temp is never really emptied" defect (ledger U-1).

    Nothing here mutates an ACL, and no file outside a sandbox this suite created is touched.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.FileSystem.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function Get-CaughtRecord {
    <#
    .SYNOPSIS
        Runs a probe that is expected to fail and returns the ErrorRecord PowerShell produced.
    .DESCRIPTION
        A probe that does NOT fail is itself a failure: the condition under test was never triggered,
        so classifying its (absent) error would be a false green.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$ScriptBlock)

    $caught = $null
    try { & $ScriptBlock | Out-Null }
    catch { $caught = $_ }

    if (-not $caught) { throw 'the probe completed without an error, so the condition under test was never triggered.' }
    return $caught
}

function New-WrappedRecord {
    <#
    .SYNOPSIS
        An ErrorRecord whose exception is a MethodInvocationException around $Inner, optionally
        nested, which is the shape a .NET method call produces on Windows PowerShell 5.1.
    #>
    param(
        [Parameter(Mandatory = $true)][System.Exception]$Inner,
        [int]$Depth = 1
    )

    $exception = $Inner
    for ($i = 0; $i -lt $Depth; $i++) {
        $exception = New-Object System.Management.Automation.MethodInvocationException(
            'Exception calling "Delete" with "2" argument(s).', $exception)
    }

    return (New-Object System.Management.Automation.ErrorRecord(
            $exception, 'WacTestProbe', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null))
}

function New-TestFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Content = 'payload'
    )

    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    [System.IO.File]::WriteAllText($Path, $Content)
    return $Path
}

# ---------------------------------------------------------------------------------------------
# Real I/O conditions
# ---------------------------------------------------------------------------------------------

Test-Case 'Deleting a non-empty directory classifies as Busy, never Denied' {
    $sandbox = New-TestSandbox -Prefix 'ec-notempty'
    try {
        $dir = Join-Path -Path $sandbox -ChildPath 'occupied'
        [void](New-TestFile (Join-Path -Path $dir -ChildPath 'child.txt'))

        $record = Get-CaughtRecord { [System.IO.Directory]::Delete($dir, $false) }
        $kind = Get-WacIoFailureKind -ErrorRecord $record

        # 'Denied' here is the ledger U-1 defect: Remove-WacTree builds its retry queue from
        # SkippedNotEmpty, so a Denied classification removes the directory from the second pass.
        Assert-Equal 'Busy' $kind ('the exception was ' + $record.Exception.GetType().FullName)
        Assert-True (Test-Path -LiteralPath $dir) 'the probe deleted the directory it was meant to fail on'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Deleting a missing file classifies as NotFound' {
    $sandbox = New-TestSandbox -Prefix 'ec-nofile'
    try {
        # File.Delete on a missing name whose parent EXISTS is a documented no-op, so the failing
        # form is the one Remove-WacLeaf actually meets: the parent vanished underneath it.
        $missing = Join-Path -Path $sandbox -ChildPath 'gone\payload.txt'
        $record = Get-CaughtRecord { [System.IO.File]::Delete($missing) }
        Assert-Equal 'NotFound' (Get-WacIoFailureKind -ErrorRecord $record) `
            ('the exception was ' + $record.Exception.GetType().FullName)

        # And the plain FileNotFoundException shape, which derives from IOException and must not be
        # swallowed by the IOException catch-all.
        $absent = Join-Path -Path $sandbox -ChildPath 'absent.txt'
        $opened = Get-CaughtRecord {
            [System.IO.File]::Open($absent, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        }
        Assert-Equal 'NotFound' (Get-WacIoFailureKind -ErrorRecord $opened) `
            ('the exception was ' + $opened.Exception.GetType().FullName)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Deleting a missing directory classifies as NotFound' {
    $sandbox = New-TestSandbox -Prefix 'ec-nodir'
    try {
        $missing = Join-Path -Path $sandbox -ChildPath 'never-created'
        $record = Get-CaughtRecord { [System.IO.Directory]::Delete($missing, $false) }

        Assert-Equal 'NotFound' (Get-WacIoFailureKind -ErrorRecord $record) `
            ('the exception was ' + $record.Exception.GetType().FullName)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Deleting a file held with FileShare::None classifies as Busy' {
    $sandbox = New-TestSandbox -Prefix 'ec-locked'
    $handle = $null
    try {
        $locked = New-TestFile (Join-Path -Path $sandbox -ChildPath 'locked.bin')
        $handle = New-Object System.IO.FileStream(
            $locked, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

        $record = Get-CaughtRecord { [System.IO.File]::Delete($locked) }

        Assert-Equal 'Busy' (Get-WacIoFailureKind -ErrorRecord $record) `
            ('the exception was ' + $record.Exception.GetType().FullName)
        Assert-True (Test-Path -LiteralPath $locked) 'the locked file was deleted'
    }
    finally {
        if ($handle) { try { $handle.Dispose() } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Deleting a read-only file classifies as Denied' {
    $sandbox = New-TestSandbox -Prefix 'ec-denied'
    try {
        $readOnly = New-TestFile (Join-Path -Path $sandbox -ChildPath 'readonly.txt')
        [System.IO.File]::SetAttributes($readOnly, [System.IO.FileAttributes]::ReadOnly)

        $record = Get-CaughtRecord { [System.IO.File]::Delete($readOnly) }

        # Denied is what makes Remove-WacLeaf clear the attribute and retry, so it must not be
        # collapsed into the IOException catch-all either.
        Assert-Equal 'Denied' (Get-WacIoFailureKind -ErrorRecord $record) `
            ('the exception was ' + $record.Exception.GetType().FullName)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Wrapping and type order
# ---------------------------------------------------------------------------------------------

Test-Case 'A wrapped MethodInvocationException classifies from its inner exception' {
    $single = New-WrappedRecord -Inner (New-Object System.IO.IOException('The directory is not empty.'))
    Assert-Equal 'Busy' (Get-WacIoFailureKind -ErrorRecord $single)

    # Two hosts, two wrapping depths: the unwrap loop has to reach the bottom, not just one level.
    $nested = New-WrappedRecord -Depth 3 -Inner (New-Object System.IO.IOException('The directory is not empty.'))
    Assert-Equal 'Busy' (Get-WacIoFailureKind -ErrorRecord $nested)

    $denied = New-WrappedRecord -Inner (New-Object System.UnauthorizedAccessException('Access to the path is denied.'))
    Assert-Equal 'Denied' (Get-WacIoFailureKind -ErrorRecord $denied)

    $gone = New-WrappedRecord -Depth 2 -Inner (New-Object System.IO.DirectoryNotFoundException('Could not find a part of the path.'))
    Assert-Equal 'NotFound' (Get-WacIoFailureKind -ErrorRecord $gone)
}

Test-Case 'Types derived from IOException are classified before the IOException catch-all' {
    Assert-Equal 'NotFound' (Get-WacIoFailureKind -ErrorRecord (New-WrappedRecord -Inner (New-Object System.IO.DirectoryNotFoundException('x'))))
    Assert-Equal 'NotFound' (Get-WacIoFailureKind -ErrorRecord (New-WrappedRecord -Inner (New-Object System.IO.FileNotFoundException('x'))))
    Assert-Equal 'TooLong' (Get-WacIoFailureKind -ErrorRecord (New-WrappedRecord -Inner (New-Object System.IO.PathTooLongException('x'))))
    Assert-Equal 'Busy' (Get-WacIoFailureKind -ErrorRecord (New-WrappedRecord -Inner (New-Object System.IO.IOException('x'))))
}

Test-Case 'An unrelated failure classifies as Other rather than a deletion outcome' {
    $other = New-WrappedRecord -Inner (New-Object System.InvalidOperationException('not an I/O problem'))
    Assert-Equal 'Other' (Get-WacIoFailureKind -ErrorRecord $other)

    # A record with no usable exception must fail closed, not throw and abort a whole sweep.
    Assert-Equal 'Other' (Get-WacIoFailureKind -ErrorRecord ([PSCustomObject]@{ Exception = $null }))
}

# ---------------------------------------------------------------------------------------------
# The consequence (ledger U-1)
# ---------------------------------------------------------------------------------------------

Test-Case 'A directory kept occupied by a locked file is recorded as SkippedNotEmpty, not SkippedDenied' {
    $sandbox = New-TestSandbox -Prefix 'ec-consequence'
    $handle = $null
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'root'
        $sub = Join-Path -Path $root -ChildPath 'sub'
        $locked = New-TestFile (Join-Path -Path $sub -ChildPath 'locked.bin')

        $handle = New-Object System.IO.FileStream(
            $locked, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

        $blocked = Remove-WacTree -Category 'ec-consequence' -Path $root

        Assert-True $blocked.Attempted
        # The load-bearing counter: a Denied classification would drop the directory from the retry
        # queue and hide it from the "not emptied" evidence in the log.
        Assert-Equal 1 $blocked.SkippedNotEmpty ('denied=' + $blocked.SkippedDenied + ' failed=' + $blocked.Failed)
        Assert-Equal 0 $blocked.SkippedDenied
        Assert-Equal 0 $blocked.DirectoriesDeleted
        # Delete-on-reboot registration only succeeds for an administrator, so either counter is a
        # correct outcome for the locked FILE; being counted nowhere is not.
        Assert-True (($blocked.SkippedLocked + $blocked.PendingDeletes) -ge 1) `
            ('locked=' + $blocked.SkippedLocked + ' pending=' + $blocked.PendingDeletes)
        Assert-True (Test-Path -LiteralPath $sub) 'an occupied directory must not be removed'

        # Releasing the handle is the same state change the in-run retry pass waits for: the
        # directory is now empty and the very next attempt removes it.
        $handle.Dispose()
        $handle = $null

        $retried = Remove-WacTree -Category 'ec-consequence' -Path $root

        Assert-Equal 1 $retried.FilesDeleted
        Assert-Equal 1 $retried.DirectoriesDeleted ('notEmpty=' + $retried.SkippedNotEmpty + ' denied=' + $retried.SkippedDenied)
        Assert-Equal 0 $retried.SkippedNotEmpty
        Assert-False (Test-Path -LiteralPath $sub) 'the directory survived after its last handle was released'
        Assert-True (Test-Path -LiteralPath $root) 'deletion climbed above the target root'
    }
    finally {
        if ($handle) { try { $handle.Dispose() } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Remove-WacLeaf sends an occupied directory to the retry queue instead of delete-on-reboot' {
    $sandbox = New-TestSandbox -Prefix 'ec-leaf'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'root'
        $sub = Join-Path -Path $root -ChildPath 'sub'
        $file = New-TestFile (Join-Path -Path $sub -ChildPath 'child.txt')

        $stats = New-WacDeletionStats
        Remove-WacLeaf -Path $sub -RootPath $root -Stats $stats -IsDirectory

        # Even with pending deletes ALLOWED, a non-empty directory must land in SkippedNotEmpty:
        # queueing it for reboot would abandon the retry pass that actually empties it.
        Assert-Equal 1 $stats.SkippedNotEmpty ('denied=' + $stats.SkippedDenied + ' pending=' + $stats.PendingDeletes)
        Assert-Equal 0 $stats.SkippedDenied
        Assert-Equal 0 $stats.PendingDeletes
        Assert-Equal 0 $stats.DirectoriesDeleted

        [System.IO.File]::Delete($file)

        $second = New-WacDeletionStats
        Remove-WacLeaf -Path $sub -RootPath $root -Stats $second -IsDirectory
        Assert-Equal 1 $second.DirectoriesDeleted
        Assert-Equal 0 (Get-WacSkippedTotal -Stats $second)
        Assert-False (Test-Path -LiteralPath $sub)
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
