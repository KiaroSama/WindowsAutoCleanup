#Requires -Version 5.1
<#
.SYNOPSIS
    The handle-bound delete: the identity proof and the unlink happen on ONE handle.
    TEMP: containment, reparse-point handling, attribute clearing, >MAX_PATH reach, locked files,
    deepest-first directory removal, pattern deletion and the run deadline.

.DESCRIPTION
    Every sandbox, junction and file handle is released in a finally block. Nothing here touches a
    path outside the sandbox it created.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.FileSystem.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function New-TestDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    [void][System.IO.Directory]::CreateDirectory($Path)
    return $Path
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
# Containment
# ---------------------------------------------------------------------------------------------
# The handle-bound delete (the deletion-race decision)
#
# The threat model is now explicit: a local standard user who can write into an allow-listed target
# IS in scope, because this runs as SYSTEM and the default Windows Temp grants BUILTIN\Users write.
# So the delete is issued on the SAME handle the identity was proved on. These cases pin that
# decision; without them the primitive could quietly regress to verify-then-delete-by-name and every
# existing case would stay green - which is exactly how this project has shipped vacuous assertions.
# ---------------------------------------------------------------------------------------------

Test-Case 'Remove-WacLeaf resolves the path once, on the handle it deletes through' {
    <#
        Structural, and deliberately so: the guarantee is "there is no SECOND resolution", and the
        only way to state that is that no separate resolve-by-name call survives in the body.
    #>
    $module = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'src\WindowsAutoCleanup.FileSystem.psm1'
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($module, [ref]$null, [ref]$parseErrors)
    Assert-Equal 0 @($parseErrors).Count 'the module no longer parses'

    $body = @($ast.FindAll({
                param($node)
                ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and
                ($node.Name -eq 'Remove-WacLeaf')
            }, $true))
    Assert-Equal 1 $body.Count 'exactly one Remove-WacLeaf must exist'

    $text = $body[0].Extent.Text
    Assert-False ($text -match 'Test-WacFinalPathMatches') 'a second, separate path resolution came back'
    Assert-False ($text -match '\[System\.IO\.(File|Directory)\]::Delete') 'a delete-by-pathname came back'
    Assert-True ($text -match 'Invoke-WacBoundDelete') 'the bound delete is not the primitive any more'
}

Test-Case 'A leaf whose identity no longer matches is refused, and the object survives' {
    $sandbox = New-TestSandbox -Prefix 'fs-bound-identity'
    try {
        $root = New-TestDirectory -Path (Join-Path -Path $sandbox -ChildPath 'root')
        $victim = New-TestFile -Path (Join-Path -Path $root -ChildPath 'victim.txt')

        $stats = New-WacDeletionStats
        # Claim the leaf resolves somewhere it does not. That is precisely what a swapped ancestor
        # produces, and it is the branch the whole design exists for.
        # The seam also pins the CALL: the identity the primitive is asked to prove must be the leaf
        # itself, not some ancestor, and the link flag must be off for an ordinary file. Getting
        # either wrong would make the whole proof meaningless while every assertion below still
        # passed, so they are asserted here rather than discarded.
        $seen = [PSCustomObject]@{ LongPath = $null; Expected = $null; Reparse = $null; Win32 = $null; Nt = $null }
        Set-WacBoundDeleteOverride -ScriptBlock {
            param($longPath, $expected, $openReparsePoint, $win32, $ntStatus)
            $seen.LongPath = $longPath
            $seen.Expected = $expected
            $seen.Reparse = $openReparsePoint
            $seen.Win32 = $win32
            $seen.Nt = $ntStatus
            return 2
        }.GetNewClosure()
        try { Remove-WacLeaf -Path $victim -RootPath $root -Stats $stats }
        finally { Set-WacBoundDeleteOverride -ScriptBlock $null }

        Assert-Equal $victim $seen.Expected 'the identity proved was not the leaf being deleted'
        Assert-True ($seen.LongPath -like '*victim.txt') 'the path opened was not the leaf being deleted'
        Assert-False ([bool]$seen.Reparse) 'an ordinary file was opened as a reparse point'
        Assert-True ($null -ne $seen.Win32) 'the Win32 out-parameter was never passed through'
        Assert-True ($null -ne $seen.Nt) 'the NTSTATUS out-parameter was never passed through'

        Assert-Equal 1 ([int]$stats.RefusedIdentity) 'the mismatch was not counted as an identity refusal'
        Assert-Equal 0 ([int]$stats.FilesDeleted) 'a refused leaf was counted as deleted'
        Assert-True (Test-Path -LiteralPath $victim) 'the refused object was deleted anyway'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Every native delete outcome maps to the counter it was measured to deserve' {
    # The values are measured, not assumed: see the function comment. A wrong mapping here is how a
    # read-only file becomes a hard failure, or a locked file becomes a silent success.
    Assert-Equal 'Identity' (Get-WacBoundDeleteKind -Code 2)
    Assert-Equal 'NotFound' (Get-WacBoundDeleteKind -Code 1 -Win32Error 2)
    Assert-Equal 'NotFound' (Get-WacBoundDeleteKind -Code 1 -Win32Error 3)
    Assert-Equal 'Denied'   (Get-WacBoundDeleteKind -Code 1 -Win32Error 5)
    Assert-Equal 'Busy'     (Get-WacBoundDeleteKind -Code 1 -Win32Error 32)
    Assert-Equal 'Other'    (Get-WacBoundDeleteKind -Code 1 -Win32Error 1117)
    Assert-Equal 'NotEmpty' (Get-WacBoundDeleteKind -Code 3 -NtStatus ([int]0xC0000101))
    Assert-Equal 'Denied'   (Get-WacBoundDeleteKind -Code 3 -NtStatus ([int]0xC0000121))
    Assert-Equal 'Denied'   (Get-WacBoundDeleteKind -Code 3 -NtStatus ([int]0xC0000022))
    Assert-Equal 'Busy'     (Get-WacBoundDeleteKind -Code 3 -NtStatus ([int]0xC0000043))
    Assert-Equal 'Other'    (Get-WacBoundDeleteKind -Code 3 -NtStatus ([int]0xC0000001))
}

Test-Case 'A disposition that fails for an unexplained reason is a failure, never a silent success' {
    $sandbox = New-TestSandbox -Prefix 'fs-bound-other'
    try {
        $root = New-TestDirectory -Path (Join-Path -Path $sandbox -ChildPath 'root')
        $victim = New-TestFile -Path (Join-Path -Path $root -ChildPath 'victim.txt')

        $stats = New-WacDeletionStats
        Set-WacBoundDeleteOverride -ScriptBlock {
            param($longPath, $expected, $openReparsePoint, $win32, $ntStatus)
            # An NTSTATUS the classifier has never seen. The point of the case is that an unmapped
            # status must not fall through to anything benign.
            $ntStatus.Value = [int]0xC0000001
            $win32.Value = 0
            [void]$longPath; [void]$expected; [void]$openReparsePoint
            return 3
        }
        try { Remove-WacLeaf -Path $victim -RootPath $root -Stats $stats }
        finally { Set-WacBoundDeleteOverride -ScriptBlock $null }

        Assert-Equal 1 ([int]$stats.Failed) 'an unexplained disposition failure was not counted as a failure'
        Assert-Equal 0 ([int]$stats.FilesDeleted) 'it was counted as deleted'
        Assert-True (Test-Path -LiteralPath $victim) 'the object went away despite the failure'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
