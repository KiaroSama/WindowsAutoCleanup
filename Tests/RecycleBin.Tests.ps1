#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.RecycleBin: the enumeration predicate, the sweep of
    every user's bin on the target drive and the post-condition that proves it (ledger P1-9,
    brief T-7).

.DESCRIPTION
    The cases sweep a disposable $Recycle.Bin tree under TEMP - never the real bin. Deletion runs
    against FileSystem's own primitives, so a refusal or a locked leaf reaches the outcome the same
    way it does in production.

    Most cases run the bounded block in process through the module's seam, installed from
    _StepHarness.ps1. One case deliberately does not: it removes the seam and takes the production
    path, which is the only thing that can catch a package that fails to import into the fresh
    runspace or a function the runspace cannot resolve.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_StepHarness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
# The package entry point last, so its own non-forced imports bind to the instances forced here and
# a shadow installed in one of them is the one the code under test sees.
foreach ($moduleLeaf in @('Core', 'FileSystem', 'StepContract', 'RecycleBin', 'DiskCleanup', 'Steps')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

$script:StepModule = Get-Module -Name 'WindowsAutoCleanup.RecycleBin'

function New-TestFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Content = 'payload'
    )

    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    [System.IO.File]::WriteAllText($Path, $Content)
    return $Path
}

function New-TestRecycleBin {
    <#
    .SYNOPSIS
        A disposable $Recycle.Bin tree holding one of every entry shape the sweep has to classify.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $bin = Join-Path -Path $Sandbox -ChildPath '$Recycle.Bin'
    $sid = Join-Path -Path $bin -ChildPath 'S-1-5-21-1111111111-2222222222-3333333333-1001'
    $notSid = Join-Path -Path $bin -ChildPath 'NotASid'

    [void][System.IO.Directory]::CreateDirectory($sid)
    [void][System.IO.Directory]::CreateDirectory($notSid)

    [void](New-TestFile (Join-Path -Path $sid -ChildPath '$IAAAAAA.txt') 'metadata')
    [void](New-TestFile (Join-Path -Path $sid -ChildPath '$RAAAAAA.txt') 'content')
    [void](New-TestFile (Join-Path -Path $sid -ChildPath 'desktop.ini') '[.ShellClassInfo]')
    [void](New-TestFile (Join-Path -Path $sid -ChildPath 'notes.txt') 'not a bin entry')
    [void](New-TestFile (Join-Path -Path $notSid -ChildPath '$IZZZZZZ.txt') 'another identity')

    $recycledFolder = Join-Path -Path $sid -ChildPath '$RBBBBBB'
    [void](New-TestFile (Join-Path -Path $recycledFolder -ChildPath 'sub\deep.txt') 'deep')

    $readOnly = Join-Path -Path $sid -ChildPath '$RCCCCCC.txt'
    [void](New-TestFile $readOnly 'read only')
    (Get-Item -LiteralPath $readOnly -Force).Attributes = [System.IO.FileAttributes]::ReadOnly

    return [PSCustomObject]@{
        Bin            = $bin
        Sid            = $sid
        NotSid         = $notSid
        RecycledFolder = $recycledFolder
        ReadOnly       = $readOnly
    }
}

function Add-TestRecycleBinSid {
    <#
    .SYNOPSIS
        A second, SID-shaped per-user directory with one deletable entry in it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Bin,
        [Parameter(Mandatory = $true)][string]$Sid
    )

    $path = Join-Path -Path $Bin -ChildPath $Sid
    [void][System.IO.Directory]::CreateDirectory($path)
    [void](New-TestFile (Join-Path -Path $path -ChildPath '$RSECOND.txt') 'second user content')
    return $path
}

# ---------------------------------------------------------------------------------------------
# Recycle Bin (ledger P1-9, brief T-7)
# ---------------------------------------------------------------------------------------------

Test-Case 'the Recycle Bin enumeration returns only $I/$R entries inside per-SID directories' {
    $sandbox = New-TestSandbox -Prefix 'st-binenum'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $scan = Get-WacRecycleBinScan -Root $tree.Bin
        $items = @($scan.Item)

        Assert-Equal 4 $items.Count (($items | ForEach-Object { Split-Path -Leaf $_.Path }) -join '; ')
        Assert-Equal 0 (@($scan.Unreadable)).Count 'a readable bin reported an unreadable directory'
        Assert-Equal 0 (@($scan.Refused)).Count 'a clean bin reported a refusal'

        foreach ($item in $items) {
            Assert-True (Test-WacRecycleBinEntryName -Name (Split-Path -Leaf $item.Path)) ('not a bin entry: {0}' -f $item.Path)
            Assert-Equal (Get-WacNormalizedPath -Path $tree.Sid) $item.SidPath 'an entry outside the per-SID directory was enumerated'
        }

        $leaf = @($items | ForEach-Object { Split-Path -Leaf $_.Path } | Sort-Object)
        Assert-Equal '$IAAAAAA.txt,$RAAAAAA.txt,$RBBBBBB,$RCCCCCC.txt' ($leaf -join ',')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the sweep deletes every enumerated entry and nothing else' {
    $sandbox = New-TestSandbox -Prefix 'st-binsweep'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True $result.Succeeded $result.Detail
            Assert-False $result.Failed $result.Detail
            Assert-True $result.Attempted

            # Both the scan and the post-condition probe must have gone through the bound.
            Assert-Equal 2 $script:BoundedCall.Count 'the scan and its post-condition probe must both be bounded'
            foreach ($call in $script:BoundedCall) {
                Assert-Equal 'RecycleBin' $call.Component
                Assert-True ($call.TimeoutMs -gt 0) 'a bounded Recycle Bin scan was given no time at all'
                Assert-False $call.IgnoreRunBudget 'a Recycle Bin scan must not ignore the run budget'
            }
        }

        # The post-condition is measured with the SAME predicate the enumeration used.
        Assert-Equal 0 (@((Get-WacRecycleBinScan -Root $tree.Bin).Item)).Count 'the bin still reports entries after a successful sweep'

        Assert-False (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$IAAAAAA.txt')) 'a $I metadata file survived'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'a $R content file survived'
        Assert-False (Test-Path -LiteralPath $tree.ReadOnly) 'a read-only $R entry survived'
        Assert-False (Test-Path -LiteralPath $tree.RecycledFolder) 'a recycled folder tree survived'

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath 'desktop.ini')) 'desktop.ini was deleted'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath 'notes.txt')) 'a non-$I/$R file was deleted'
        Assert-True (Test-Path -LiteralPath $tree.Sid) 'the per-SID directory itself was deleted'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.NotSid -ChildPath '$IZZZZZZ.txt')) 'a directory that is not a SID was swept'
        Assert-True (Test-Path -LiteralPath $tree.Bin) 'the bin root itself was deleted'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the sweep works through the REAL bound, not only through the test seam' {
    # Every other Recycle Bin case runs the block in process through the seam, which cannot catch a
    # module that fails to import into the runspace, a function the runspace cannot resolve, or a
    # result that does not survive the boundary. This one takes the production path: no seam.
    $sandbox = New-TestSandbox -Prefix 'st-binreal'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        Set-WacStepBoundedInvoker -Invoker $null

        $result = Clear-WacRecycleBin -Root $tree.Bin

        Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        Assert-True ($result.Detail -match 'before=4 after=0') $result.Detail
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'the real bounded path deleted nothing'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'every per-SID directory on the drive is swept, not only the calling identity' {
    $sandbox = New-TestSandbox -Prefix 'st-binallusers'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $second = Add-TestRecycleBinSid -Bin $tree.Bin -Sid 'S-1-5-21-1111111111-2222222222-3333333333-1002'
        $third = Add-TestRecycleBinSid -Bin $tree.Bin -Sid 'S-1-5-18'

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $tree.Bin
            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        }

        Assert-False (Test-Path -LiteralPath (Join-Path -Path $second -ChildPath '$RSECOND.txt')) 'a second user bin was left untouched'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $third -ChildPath '$RSECOND.txt')) 'the service account bin was left untouched'
        Assert-True (Test-Path -LiteralPath $second) 'a per-SID directory was deleted'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an unreadable per-SID directory is Incomplete, never silently omitted' {
    $sandbox = New-TestSandbox -Prefix 'st-bindenied'
    $deniedSid = 'S-1-5-21-1111111111-2222222222-3333333333-4444'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $denied = Add-TestRecycleBinSid -Bin $tree.Bin -Sid $deniedSid

        # A real access-denied enumeration needs a second identity, which a suite cannot create
        # here. The failure is injected at the same call the real one throws from, so the classifier
        # under test sees exactly the exception it would see in production.
        # A cmdlet is not in the module function drive, so the shadow is REMOVED afterwards rather
        # than restored: removing it reveals the cmdlet again. Measured on both hosts.
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Get-ChildItem' -Body {
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [switch]$Directory,
                [switch]$Force
            )

            if ($LiteralPath -match 'S-1-5-21-1111111111-2222222222-3333333333-4444') {
                throw (New-Object System.UnauthorizedAccessException('Access to the path is denied.'))
            }
            return (Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Directory:$Directory -Force:$Force -ErrorAction Stop)
        }

        try {
            Invoke-WithBoundedSeam -Body {
                $result = Clear-WacRecycleBin -Root $tree.Bin

                Assert-Equal 'Incomplete' $result.Outcome $result.Detail
                Assert-False $result.Succeeded 'a bin that was never fully read reported success'
                Assert-True $result.Failed 'an unreadable per-SID directory must reach the exit code'
                Assert-True ($result.Detail -match 'unreadableSid=[1-9]') $result.Detail
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepModule -Name 'Get-ChildItem'
        }

        # The readable bins were still swept: an anomaly in one identity is not a reason to stop.
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'the readable bins were skipped too'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $denied -ChildPath '$RSECOND.txt')) 'an unreadable bin was deleted from anyway'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a per-SID directory that is a reparse point is a SecurityRefusal and is never followed' {
    $sandbox = New-TestSandbox -Prefix 'st-binsidlink'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $outside = Join-Path -Path $sandbox -ChildPath 'outside'
        [void](New-TestFile (Join-Path -Path $outside -ChildPath '$RVICTIM.txt') 'must survive')

        $link = Join-Path -Path $tree.Bin -ChildPath 'S-1-5-21-1111111111-2222222222-3333333333-5555'
        New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop | Out-Null

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
            Assert-False $result.Succeeded
            Assert-True $result.Failed 'a refusal must reach the exit code'
            Assert-True ($result.Detail -match 'refused=[1-9]') $result.Detail
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $outside -ChildPath '$RVICTIM.txt')) 'the sweep followed a per-SID junction out of the bin'
        Assert-True (Test-Path -LiteralPath $link) 'a per-SID directory was deleted rather than refused'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'entries left behind with nothing to explain them are a failure' {
    $sandbox = New-TestSandbox -Prefix 'st-binresidue'
    try {
        $bin = Join-Path -Path $sandbox -ChildPath '$Recycle.Bin'
        $sid = Join-Path -Path $bin -ChildPath 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        [void](New-TestFile (Join-Path -Path $sid -ChildPath '$RLEFT.txt') 'not going anywhere')

        # A deletion primitive that claims everything went fine and removes nothing. Before the
        # post-condition probe existed this shape reported a clean sweep.
        # Removing the shadow reveals the real Remove-WacLeaf from the FileSystem module, which is
        # what keeps that function's own session state intact. Measured on both hosts.
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Remove-WacLeaf' -Body {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)][string]$Path,
                [Parameter(Mandatory = $true)][string]$RootPath,
                [Parameter(Mandatory = $true)]$Stats,
                [switch]$IsDirectory,
                [switch]$IsReparsePoint,
                [int64]$Length = 0
            )
            # The signature has to match the real one; the values themselves are unused here.
            $null = $Path, $RootPath, $Stats, $IsDirectory, $IsReparsePoint, $Length
            return
        }

        try {
            Invoke-WithBoundedSeam -Body {
                $result = Clear-WacRecycleBin -Root $bin

                Assert-Equal 'Failed' $result.Outcome $result.Detail
                Assert-False $result.Succeeded 'a purge that removed nothing reported success'
                Assert-True $result.Failed
                Assert-True ($result.Detail -match 'before=1 after=1') $result.Detail
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepModule -Name 'Remove-WacLeaf'
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $sid -ChildPath '$RLEFT.txt')) 'the fixture deleted the entry after all'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'entries left behind by a locked leaf are Incomplete rather than a lie' {
    $sandbox = New-TestSandbox -Prefix 'st-binlocked'
    try {
        $bin = Join-Path -Path $sandbox -ChildPath '$Recycle.Bin'
        $sid = Join-Path -Path $bin -ChildPath 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        [void](New-TestFile (Join-Path -Path $sid -ChildPath '$RLOCKED.txt') 'held open elsewhere')

        # Removing the shadow reveals the real Remove-WacLeaf from the FileSystem module, which is
        # what keeps that function's own session state intact. Measured on both hosts.
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Remove-WacLeaf' -Body {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)][string]$Path,
                [Parameter(Mandatory = $true)][string]$RootPath,
                [Parameter(Mandatory = $true)]$Stats,
                [switch]$IsDirectory,
                [switch]$IsReparsePoint,
                [int64]$Length = 0
            )
            # The signature has to match the real one; the values themselves are unused here.
            $null = $Path, $RootPath, $IsDirectory, $IsReparsePoint, $Length
            $Stats.SkippedLocked++
        }

        try {
            Invoke-WithBoundedSeam -Body {
                $result = Clear-WacRecycleBin -Root $bin

                Assert-Equal 'Incomplete' $result.Outcome $result.Detail
                Assert-False $result.Succeeded
                Assert-True $result.Failed 'an unfinished sweep must still reach the exit code'
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepModule -Name 'Remove-WacLeaf'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the run budget stops the sweep and reports Incomplete without deleting anything' {
    $sandbox = New-TestSandbox -Prefix 'st-bindeadline'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            Invoke-WithExpiredDeadline -Body {
                $result = Clear-WacRecycleBin -Root $tree.Bin

                Assert-Equal 'Incomplete' $result.Outcome $result.Detail
                Assert-False $result.Succeeded
                Assert-True $result.Failed
            }
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'the sweep deleted after the budget had expired'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a scan that exceeds its bound is Incomplete, not an empty bin' {
    $sandbox = New-TestSandbox -Prefix 'st-binbound'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $script:BoundedForce['call:0'] = @{ Outcome = 'Incomplete'; Error = 'the work did not finish within 1 ms.' }
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-False $result.Succeeded 'a bin that was never scanned reported a clean sweep'
            Assert-True $result.Failed
            Assert-Equal 1 $script:BoundedCall.Count 'the sweep ran even though its scan never finished'
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'an unscanned bin was swept anyway'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a bounded scan that comes back with nothing in it is Incomplete' {
    # Invoke-WacBounded reports Succeeded with EMPTY output when the block only wrote a
    # non-terminating error, so the caller has to decide. Nothing measured is nothing proven.
    $sandbox = New-TestSandbox -Prefix 'st-binnooutput'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $script:BoundedForce['call:0'] = @{ Outcome = 'Succeeded'; Error = 'Get-WacRecycleBinScan is not recognized.' }
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'returned nothing') $result.Detail
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $tree.Sid -ChildPath '$RAAAAAA.txt')) 'a bin that was never scanned was swept anyway'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a post-condition probe that comes back with nothing in it is Incomplete' {
    $sandbox = New-TestSandbox -Prefix 'st-binpostempty'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $script:BoundedForce['call:1'] = @{ Outcome = 'Succeeded'; Error = 'the probe wrote an error and no result' }
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-False $result.Succeeded 'an unverified sweep reported success'
            Assert-True ($result.Detail -match 'returned nothing') $result.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a post-condition probe that cannot finish is Incomplete, never a clean sweep' {
    $sandbox = New-TestSandbox -Prefix 'st-binpost'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            $script:BoundedForce['call:1'] = @{ Outcome = 'Incomplete'; Error = 'the work did not finish within 1 ms.' }
            $result = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-False $result.Succeeded 'an unverified sweep reported success'
            Assert-True ($result.Detail -match 'could not be verified') $result.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an unreadable Recycle Bin root is a failure, not an empty bin' {
    $sandbox = New-TestSandbox -Prefix 'st-binroot'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        # A cmdlet is not in the module function drive, so the shadow is REMOVED afterwards rather
        # than restored: removing it reveals the cmdlet again. Measured on both hosts.
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Get-ChildItem' -Body {
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [switch]$Directory,
                [switch]$Force
            )
            # The signature has to match the real one; the values themselves are unused here.
            $null = $LiteralPath, $Directory, $Force
            throw (New-Object System.UnauthorizedAccessException('Access to the path is denied.'))
        }

        try {
            Invoke-WithBoundedSeam -Body {
                $result = Clear-WacRecycleBin -Root $tree.Bin

                Assert-Equal 'Failed' $result.Outcome $result.Detail
                Assert-False $result.Succeeded 'an unreadable bin reported a clean sweep'
                Assert-True ($result.Detail -match 'could not be enumerated') $result.Detail
            }
        }
        finally {
            Remove-ModuleFunction -Module $script:StepModule -Name 'Get-ChildItem'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'sweeping an already empty Recycle Bin is success, not failure' {
    $sandbox = New-TestSandbox -Prefix 'st-binempty'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox

        Invoke-WithBoundedSeam -Body {
            [void](Clear-WacRecycleBin -Root $tree.Bin)

            # The SECOND run over the same persistent state is the one that catches a step which
            # turns its own leftovers into a permanent non-benign outcome.
            $second = Clear-WacRecycleBin -Root $tree.Bin

            Assert-Equal 'Succeeded' $second.Outcome $second.Detail
            Assert-True $second.Succeeded $second.Detail
            Assert-False $second.Failed $second.Detail
            Assert-True $second.Attempted
            Assert-True ($second.Detail -match 'before=0 after=0') $second.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a reparse point in the Recycle Bin is deleted as a link and its target survives' {
    $sandbox = New-TestSandbox -Prefix 'st-binlink'
    try {
        $tree = New-TestRecycleBin -Sandbox $sandbox
        $outside = Join-Path -Path $sandbox -ChildPath 'outside'
        [void](New-TestFile (Join-Path -Path $outside -ChildPath 'must-survive.txt') 'sentinel')

        $link = Join-Path -Path $tree.Sid -ChildPath '$RDDDDDD'
        New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop | Out-Null

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $tree.Bin
            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        }

        Assert-False (Test-Path -LiteralPath $link) 'the junction itself survived the sweep'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $outside -ChildPath 'must-survive.txt')) 'the sweep followed a junction out of the bin'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the Recycle Bin sweep of a missing root reports success without touching anything' {
    $sandbox = New-TestSandbox -Prefix 'st-binmissing'
    try {
        $absent = Join-Path -Path $sandbox -ChildPath 'no-such-bin'

        Invoke-WithBoundedSeam -Body {
            $result = Clear-WacRecycleBin -Root $absent

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-False $result.Failed $result.Detail
        }

        Assert-False (Test-Path -LiteralPath $absent) 'the sweep created its own root'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
