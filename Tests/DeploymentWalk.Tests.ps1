#Requires -Version 5.1
<#
.SYNOPSIS
    The bounded deployment walk: what it can see, and what it says when it cannot see everything
    (ledger G2-d).

.DESCRIPTION
    Split out of Deploy.Tests.ps1 by responsibility. Every case here is about ONE question - does
    Get-WacDeploymentItem know the difference between "there is nothing there" and "I could not
    look" - and about the two callers whose safety depends on the answer: the delete pass, which
    must remove nothing at all over an incomplete walk, and the copy, whose depth bound has to stop
    exactly where the walk's does.

    %ProgramFiles% is redirected into a disposable sandbox for every case that touches a deployment
    root and restored in a finally block. The only ACL work here is the fixture that makes a
    directory genuinely unreadable so the walk has something real to fail on, and it is lifted in a
    finally so the sandbox can still be deleted.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_DeployFixtures.ps1')

$script:DeployModule = Get-Module -Name 'WindowsAutoCleanup.Deploy'

function Set-ModuleFunctionBody {
    <#
    .SYNOPSIS
        Replaces a name inside a module's own scope. Only the module sees the replacement.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
}

function Remove-ModuleFunctionBody {
    <#
    .SYNOPSIS
        Takes a name back out of a module's own scope, for a replacement that had no original.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    & $Module { param($n) if (Test-Path -Path ('function:' + $n)) { Remove-Item -Path ('function:' + $n) -Force } } $Name
}

function Block-TestDirectoryListing {
    <#
    .SYNOPSIS
        Denies THIS account the right to list a directory, so an enumeration really fails.
    .DESCRIPTION
        A real ACE rather than an injected exception: "the walk could not read a subtree" is the
        case that used to come back as "the subtree is empty", and it is worth proving against the
        filesystem itself. The owner of a directory keeps READ_CONTROL and WRITE_DAC implicitly, so
        the ACE can always be lifted again - but owner rights do NOT include listing, so the denial
        bites on an elevated runner too. Only ever called on a directory the test created.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        ([System.Security.Principal.WindowsIdentity]::GetCurrent().User),
        [System.Security.AccessControl.FileSystemRights]::ListDirectory,
        [System.Security.AccessControl.AccessControlType]::Deny)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Unblock-TestDirectoryListing {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $acl = Get-Acl -LiteralPath $Path
        [void]$acl.RemoveAccessRuleAll((New-Object System.Security.AccessControl.FileSystemAccessRule(
            ([System.Security.Principal.WindowsIdentity]::GetCurrent().User),
            [System.Security.AccessControl.FileSystemRights]::ListDirectory,
            [System.Security.AccessControl.AccessControlType]::Deny)))
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    catch {
        $null = $_
    }
}

function New-TestNestedTree {
    <#
    .SYNOPSIS
        Creates Root\d1\d2\...\d<Depth>\<FileName> and returns the file's full path.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][int]$Depth,
        [string]$FileName = 'deep.txt'
    )

    $current = $Root
    for ($level = 1; $level -le $Depth; $level++) {
        $current = Join-Path -Path $current -ChildPath ('d{0}' -f $level)
    }
    [void][System.IO.Directory]::CreateDirectory($current)

    $file = Join-Path -Path $current -ChildPath $FileName
    [System.IO.File]::WriteAllText($file, 'deep')
    return $file
}

# ---------------------------------------------------------------------------------------------
# The walk says when it could not see everything (ledger G2-d)
# ---------------------------------------------------------------------------------------------

Test-Case 'The walk reports an unreadable subtree instead of returning it as empty' {
    Invoke-InDeploymentSandbox -Prefix 'walk-denied' -Body {
        param($sandbox)

        $root = Join-Path -Path $sandbox -ChildPath 'tree'
        $closed = Join-Path -Path $root -ChildPath 'closed'
        [void][System.IO.Directory]::CreateDirectory($closed)
        [System.IO.File]::WriteAllText((Join-Path -Path $root -ChildPath 'open.txt'), 'x')
        [System.IO.File]::WriteAllText((Join-Path -Path $closed -ChildPath 'hidden.txt'), 'x')

        Block-TestDirectoryListing -Path $closed
        try {
            $walk = Get-WacDeploymentItem -Root $root

            Assert-False $walk.Complete 'an unreadable subtree was walked as if it were empty'
            $failures = @(@($walk.Failure) | Where-Object { $_.Path -ieq $closed })
            Assert-Equal 1 $failures.Count ((@($walk.Failure) | ForEach-Object { $_.Path }) -join ', ')
            Assert-True ($failures[0].Reason -match 'could not be enumerated') ([string]$failures[0].Reason)

            # The directory itself is still reported - it exists and was seen - and so is the file
            # beside it. What is missing is only what was behind the denial.
            $paths = @(@($walk.Entry) | ForEach-Object { $_.Path })
            Assert-True ($paths -contains $closed) 'the unreadable directory itself was dropped'
            Assert-False ($paths -contains (Join-Path -Path $closed -ChildPath 'hidden.txt')) 'the walk read through a denial'
        }
        finally {
            Unblock-TestDirectoryListing -Path $closed
        }

        # And once the denial is lifted the same walk is complete again: the refusal is a fact about
        # the tree at the time, not sticky state.
        $again = Get-WacDeploymentItem -Root $root
        Assert-True $again.Complete ((@($again.Failure) | ForEach-Object { $_.Reason }) -join '; ')
    }
}

Test-Case 'The walk reports depth exhaustion instead of truncating silently' {
    Invoke-InDeploymentSandbox -Prefix 'walk-depth' -Body {
        param($sandbox)

        $root = Join-Path -Path $sandbox -ChildPath 'tree'
        [void][System.IO.Directory]::CreateDirectory($root)
        $tooDeep = New-TestNestedTree -Root $root -Depth 9

        $walk = Get-WacDeploymentItem -Root $root
        Assert-False $walk.Complete 'the walk stopped at the depth limit and called the result complete'
        Assert-True (@(@($walk.Failure) | Where-Object { $_.Reason -match 'depth limit' }).Count -ge 1) `
            ((@($walk.Failure) | ForEach-Object { $_.Reason }) -join '; ')
        Assert-False ((@($walk.Entry) | ForEach-Object { $_.Path }) -contains $tooDeep) `
            'a file past the depth limit was enumerated after all'

        # A tree that fits is complete, and the deepest file in it IS enumerated.
        $fits = Join-Path -Path $sandbox -ChildPath 'fits'
        [void][System.IO.Directory]::CreateDirectory($fits)
        $deepest = New-TestNestedTree -Root $fits -Depth 7
        $ok = Get-WacDeploymentItem -Root $fits
        Assert-True $ok.Complete ((@($ok.Failure) | ForEach-Object { $_.Reason }) -join '; ')
        Assert-True ((@($ok.Entry) | ForEach-Object { $_.Path }) -contains $deepest) 'the deepest legal file was not enumerated'
    }
}

Test-Case 'A node the walk cannot account for is a hard failure, not a skipped entry' {
    Invoke-InDeploymentSandbox -Prefix 'walk-nodes' -Body {
        param($sandbox)

        $root = Join-Path -Path $sandbox -ChildPath 'tree'
        [void][System.IO.Directory]::CreateDirectory($root)
        $vanished = Join-Path -Path $root -ChildPath 'gone.txt'
        [System.IO.File]::WriteAllText($vanished, 'x')
        [System.IO.File]::Delete($vanished)

        # Three entries a real enumeration can hand back but a test cannot produce on demand: one
        # that is neither a file nor a directory, one whose path will not canonicalise, and one that
        # was deleted after the enumeration listed it.
        Set-ModuleFunctionBody -Module $script:DeployModule -Name 'Get-ChildItem' -Body {
            param([string]$LiteralPath, [switch]$Force, [string]$ErrorAction)

            # Declared so the call under test binds exactly as it does against the real cmdlet.
            $null = $Force, $ErrorAction

            return @(
                [PSCustomObject]@{ FullName = (Join-Path -Path $LiteralPath -ChildPath 'device') },
                (New-Object System.IO.FileInfo('\\server\share\unc.txt')),
                (New-Object System.IO.FileInfo($vanished))
            )
        }.GetNewClosure()

        try {
            $walk = Get-WacDeploymentItem -Root $root

            Assert-False $walk.Complete 'entries the walk could not account for were quietly skipped'
            Assert-Equal 0 @($walk.Entry).Count 'an entry that failed its checks was still reported as walked'
            Assert-Equal 3 @($walk.Failure).Count ((@($walk.Failure) | ForEach-Object { $_.Reason }) -join '; ')

            $reasons = ((@($walk.Failure) | ForEach-Object { $_.Reason }) -join '; ')
            Assert-True ($reasons -match 'neither a file nor a directory') $reasons
            Assert-True ($reasons -match 'canonicalised') $reasons
            Assert-True ($reasons -match 'disappeared') $reasons
        }
        finally {
            Remove-ModuleFunctionBody -Module $script:DeployModule -Name 'Get-ChildItem'
        }

        # The replacement really is gone: the same walk over the same tree is complete again.
        Assert-True (Get-WacDeploymentItem -Root $root).Complete 'the injected enumerator outlived the case'
    }
}

Test-Case 'Remove-WacDeployment deletes nothing at all when the tree cannot be fully enumerated' {
    Invoke-InDeploymentSandbox -Prefix 'walk-nodelete' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        $deployment = Install-WacDeployment -SourceRoot $source
        $slots = Get-WacDeploymentSlotPath
        $closed = Join-Path -Path $slots.Root -ChildPath 'src'
        $module = Join-Path -Path $closed -ChildPath 'WindowsAutoCleanup.Core.psm1'

        Block-TestDirectoryListing -Path $closed
        try {
            $removal = Remove-WacDeployment -Path $slots.Root

            Assert-False $removal.Removed 'a tree that could not be fully enumerated was deleted anyway'
            Assert-True ([string]$removal.Reason -match 'could not be fully enumerated') ([string]$removal.Reason)

            # Nothing at all, not "everything the walk happened to see". The refusal is worthless if
            # it fires after the delete pass has already taken files out of the tree.
            Assert-True (Test-Path -LiteralPath $deployment.RunScript -PathType Leaf) 'the refused delete still removed files'
            Assert-True (Test-Path -LiteralPath $module -PathType Leaf) 'a module file was deleted by a refused removal'
        }
        finally {
            Unblock-TestDirectoryListing -Path $closed
        }

        # And with the tree readable again the same call succeeds, so the refusal was about the
        # evidence rather than about the path.
        $second = Remove-WacDeployment -Path $slots.Root
        Assert-True $second.Removed ([string]$second.Reason)
        Assert-False (Test-Path -LiteralPath $slots.Root) 'the deployment survived a removal that reported success'
    }
}

Test-Case 'The copy and the walk agree on the deepest level a deployment can hold' {
    # Measured before the fix: Copy-WacDeploymentTree counted depth from the src directory and
    # Get-WacDeploymentItem from the deployment root, so a file seven directories below src was
    # copied=True, enumerated=0 - present in the deployment, absent from the manifest, invisible to
    # the trust check, and undeletable, because the delete pass never saw it either.
    Invoke-InDeploymentSandbox -Prefix 'depth-agree' -Body {
        param($sandbox)

        $source = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout')
        [void](New-TestNestedTree -Root (Join-Path -Path $source -ChildPath 'src') -Depth 6 -FileName 'edge.psm1')
        $relative = 'src\d1\d2\d3\d4\d5\d6\edge.psm1'

        $stage = New-WacDeploymentStage -SourceRoot $source
        $staged = Join-Path -Path $stage.StagingRoot -ChildPath $relative

        Assert-True (Test-Path -LiteralPath $staged -PathType Leaf) 'the deepest legal file was not copied'
        $walk = Get-WacDeploymentItem -Root $stage.StagingRoot
        Assert-True $walk.Complete ((@($walk.Failure) | ForEach-Object { $_.Reason }) -join '; ')
        Assert-True ((@($walk.Entry) | ForEach-Object { $_.Path }) -contains $staged) `
            'the deepest copied file was never enumerated, so it is in no manifest either'
        Assert-True ((@($stage.Manifest.File) | ForEach-Object { $_.Path }) -contains $relative) `
            ((@($stage.Manifest.File) | ForEach-Object { $_.Path }) -join ', ')

        [void](Remove-WacDeployment -Path $stage.StagingRoot)

        # One level deeper is REFUSED at staging rather than copied into a deployment that could
        # never account for it.
        $overDeep = New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'checkout2')
        [void](New-TestNestedTree -Root (Join-Path -Path $overDeep -ChildPath 'src') -Depth 7 -FileName 'past.psm1')

        $refusal = $null
        try { [void](New-WacDeploymentStage -SourceRoot $overDeep) } catch { $refusal = $_ }
        Assert-True ($null -ne $refusal) 'a tree deeper than the walk can enumerate was staged anyway'
        Assert-False (Test-Path -LiteralPath (Get-WacDeploymentSlotPath).Root) 'the refused stage reached the deployment root'

        # Refused BEFORE the copy, and that ordering IS the defect. Refusing afterwards leaves the
        # unreachable file sitting in the slot the next switch swaps into the deployment root, where
        # nothing can enumerate, hash or delete it - which is why these are asserted on disk, and
        # asserted before the message is looked at.
        $staging = (Get-WacDeploymentSlotPath).Staging
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $staging -ChildPath 'src\d1\d2\d3\d4\d5\d6\d7')) `
            'the directory past the limit was created before the refusal'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $staging -ChildPath 'src\d1\d2\d3\d4\d5\d6\d7\past.psm1')) `
            'the file past the limit was copied into the staging slot before the refusal'
        Assert-True ([string]$refusal.Exception.Message -match 'deeper than the') `
            ('the refusal did not come from the copy guard: ' + [string]$refusal.Exception.Message)
    }
}

Complete-TestRun
