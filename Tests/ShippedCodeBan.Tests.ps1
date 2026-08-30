#Requires -Version 5.1
<#
.SYNOPSIS
    The standing proof that the removed ACL-hardening capability has not come back, and that no
    shipped file resolves an executable through Get-Command (ledger P0-6 / U-2).

.DESCRIPTION
    Every shipped file is parsed and scanned as TOKENS, not text: the modules document which APIs
    they never call, so a plain text search would report that documentation as a violation. The
    scanner itself is exercised against a control pair, so a scan that silently stopped finding
    anything would fail here rather than pass everywhere.

    The scanned set is the two entry-point scripts, Run.ps1, and every module and dot-sourced module
    part under src\ - a capability could otherwise come back in a file the scan never opened.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------------------------------------
# The ACL-hardening capability stays deleted (ledger P0-6 / U-2)
# ---------------------------------------------------------------------------------------------

function Get-ShippedCodeToken {
    <#
    .SYNOPSIS
        Every non-comment token of one shipped file.
    .DESCRIPTION
        Comments are dropped deliberately: the modules DOCUMENT which APIs they never call, so a
        plain text search would report that documentation as a violation.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)

    Assert-Equal 0 @($errors).Count ('{0} does not parse' -f $Path)
    return @(@($tokens) | Where-Object { $_.Kind -ne 'Comment' })
}

function Get-ShippedFile {
    $files = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in @('Run.ps1', 'Install-WindowsAutoCleanupTask.ps1', 'Uninstall-WindowsAutoCleanupTask.ps1')) {
        [void]$files.Add((Join-Path -Path $script:RepoRoot -ChildPath $name))
    }
    # Both extensions: a module's implementation now lives in dot-sourced .ps1 parts beside its
    # .psm1, and a scan that opened only the .psm1 would stop covering most of the shipped code.
    foreach ($module in @(Get-ChildItem -LiteralPath (Join-Path -Path $script:RepoRoot -ChildPath 'src') -File |
        Where-Object { $_.Extension -imatch '^\.psm?1$' })) {
        [void]$files.Add($module.FullName)
    }
    return @($files.ToArray())
}

Test-Case 'No shipped file contains an ACL, owner or terminal-wrapper call' {
    # Word-anchored: the read-only FileSystemRights constant TakeOwnership, and Get-Acl / GetOwner /
    # GetAccessRules, are how the module VERIFIES trust and must not be mistaken for a mutation.
    $forbidden = '(?i)(\bSet-Acl\b|\bSetOwner\b|\bSetAccessRule|\bSetAccessControl\b|\bAddAccessRule|\bRemoveAccessRule|\bicacls\b|\btakeown\b|\bwt\.exe\b)'
    $files = Get-ShippedFile

    Assert-True ($files.Count -ge 9) ('only {0} shipped files were scanned' -f $files.Count)

    foreach ($file in $files) {
        $hits = @(@(Get-ShippedCodeToken -Path $file) | Where-Object { $_.Text -match $forbidden } | ForEach-Object { $_.Text })
        Assert-Equal 0 $hits.Count ('{0}: {1}' -f (Split-Path -Leaf $file), ($hits -join ', '))
    }
}

Test-Case 'No shipped file resolves an executable through Get-Command' {
    foreach ($file in Get-ShippedFile) {
        $tokens = Get-ShippedCodeToken -Path $file

        for ($i = 0; $i -lt $tokens.Count; $i++) {
            if ($tokens[$i].Text -notmatch '(?i)^Get-Command$') { continue }

            # Only the rest of the same statement can belong to this call.
            $offending = New-Object 'System.Collections.Generic.List[string]'
            for ($j = $i + 1; $j -lt $tokens.Count -and $j -le ($i + 12); $j++) {
                if ($tokens[$j].Kind -eq 'NewLine' -or $tokens[$j].Kind -eq 'Semi') { break }
                if ($tokens[$j].Text -match '(?i)(^Application$|\.exe|\.cmd|\.bat|\.com)') { [void]$offending.Add($tokens[$j].Text) }
            }

            Assert-Equal 0 $offending.Count ('{0}:{1} resolves an executable: {2}' -f `
                (Split-Path -Leaf $file), $tokens[$i].Extent.StartLineNumber, (@($offending.ToArray()) -join ', '))
        }
    }
}

Test-Case 'The shipped-code scanner flags a real call and ignores the same words in a comment' {
    $sandbox = New-TestSandbox -Prefix 'scan-control'
    try {
        $forbidden = '(?i)(\bSet-Acl\b|\bSetOwner\b|\bSetAccessRule|\bSetAccessControl\b|\bAddAccessRule|\bRemoveAccessRule|\bicacls\b|\btakeown\b|\bwt\.exe\b)'

        $clean = Join-Path -Path $sandbox -ChildPath 'clean.ps1'
        [System.IO.File]::WriteAllLines($clean, [string[]]@(
            '# Nothing here calls Set-Acl, SetOwner, icacls or takeown.',
            '<# .SYNOPSIS Never uses wt.exe either. #>',
            '$acl = Get-Acl -LiteralPath $env:SystemRoot',
            '$rights = [System.Security.AccessControl.FileSystemRights]::TakeOwnership',
            '$null = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])',
            '$null = $rights'
        ), (New-Object System.Text.UTF8Encoding($false)))

        $dirty = Join-Path -Path $sandbox -ChildPath 'dirty.ps1'
        [System.IO.File]::WriteAllLines($dirty, [string[]]@(
            '$acl = Get-Acl -LiteralPath $env:TEMP',
            '$acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier(''S-1-5-32-544'')))',
            'Set-Acl -LiteralPath $env:TEMP -AclObject $acl'
        ), (New-Object System.Text.UTF8Encoding($false)))

        $cleanHits = @(@(Get-ShippedCodeToken -Path $clean) | Where-Object { $_.Text -match $forbidden })
        Assert-Equal 0 $cleanHits.Count (($cleanHits | ForEach-Object { $_.Text }) -join ', ')

        $dirtyHits = @(@(Get-ShippedCodeToken -Path $dirty) | Where-Object { $_.Text -match $forbidden } | ForEach-Object { $_.Text })
        Assert-Equal 2 $dirtyHits.Count ($dirtyHits -join ', ')
        Assert-True ($dirtyHits -contains 'SetOwner') ($dirtyHits -join ', ')
        Assert-True ($dirtyHits -contains 'Set-Acl') ($dirtyHits -join ', ')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# A trust verdict's Reason stays inert (the tripwire behind RunExitCode's three-shape refusal loop)
# ---------------------------------------------------------------------------------------------

function Get-ReasonBranchSite {
    <#
    .SYNOPSIS
        Every place a shipped file uses a .Reason property as a BRANCH CONDITION.
    .DESCRIPTION
        Assigning it and logging it are fine and expected - Reason exists to be written into the
        audit trail. What must not happen is code DECIDING on it: the moment a branch keys off the
        wording of a reason, the four "why was it untrusted" variants RunExitCode.Tests.ps1 used to
        spawn a child process for each stop being redundant.

        The AST is walked rather than the text scanned: a comment mentioning .Reason, and the string
        interpolations that build log messages out of it, must not read as violations.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
    Assert-Equal 0 @($errors).Count ('{0} does not parse' -f $Path)

    $sites = New-Object 'System.Collections.Generic.List[string]'

    # Collect the CONDITION subtrees explicitly, by node type. Reaching for a generic .Condition
    # property does not work: an IfStatementAst carries .Clauses, not .Condition, and under
    # Set-StrictMode -Version 2.0 asking for the missing property is a terminating error.
    $conditions = New-Object 'System.Collections.Generic.List[object]'

    foreach ($node in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] }, $true))) {
        foreach ($clause in $node.Clauses) { [void]$conditions.Add($clause.Item1) }
    }
    foreach ($node in @($ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.WhileStatementAst] -or
                    $n -is [System.Management.Automation.Language.DoWhileStatementAst] -or
                    $n -is [System.Management.Automation.Language.DoUntilStatementAst] -or
                    $n -is [System.Management.Automation.Language.SwitchStatementAst]
                }, $true))) {
        if ($node.Condition) { [void]$conditions.Add($node.Condition) }
    }
    # Any COMPARISON involving .Reason, wherever it sits: assigning the result of one to a variable
    # and branching on that variable later is the same decision, one statement apart. Only
    # comparison operators count - in PowerShell `+` and `-f` are BinaryExpressionAst too, so a
    # catch-all here reports every log line that formats a Reason into a message. Measured: 55
    # false positives before this filter, 0 after.
    $comparison = @('Ieq', 'Ine', 'Ceq', 'Cne', 'Igt', 'Ige', 'Ilt', 'Ile', 'Cgt', 'Cge', 'Clt', 'Cle',
        'Ilike', 'Inotlike', 'Clike', 'Cnotlike', 'Imatch', 'Inotmatch', 'Cmatch', 'Cnotmatch',
        'Icontains', 'Inotcontains', 'Ccontains', 'Cnotcontains', 'Iin', 'Inotin', 'Cin', 'Cnotin',
        'Is', 'IsNot')
    foreach ($node in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.BinaryExpressionAst] }, $true))) {
        if ($comparison -contains [string]$node.Operator) { [void]$conditions.Add($node) }
    }

    foreach ($condition in $conditions) {
        foreach ($hit in @($condition.FindAll({
                        param($inner)
                        $inner -is [System.Management.Automation.Language.MemberExpressionAst] -and
                        $inner.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                        $inner.Member.Value -ieq 'Reason'
                    }, $true))) {
            # An assignment TO .Reason is not a decision, and the left side of one never appears
            # inside a condition subtree, so nothing extra is needed to exclude it.
            [void]$sites.Add(('{0}:{1}' -f (Split-Path -Leaf $Path), $hit.Extent.StartLineNumber))
        }
    }

    return @($sites.ToArray())
}

Test-Case 'No shipped file branches on a trust verdict Reason' {
    # RunExitCode.Tests.ps1 exercises ONE untrusted shape rather than four, because the four differed
    # only in this string. That reduction is safe exactly as long as this stays true; when it stops
    # being true, this case fails and points straight at the shapes that need to come back.
    $offenders = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in Get-ShippedFile) {
        foreach ($site in (Get-ReasonBranchSite -Path $file)) { [void]$offenders.Add($site) }
    }

    Assert-Equal 0 $offenders.Count ('a shipped file decides on a Reason string: ' + ($offenders -join ', '))
}

Test-Case 'The Reason scanner flags a real branch and ignores an assignment or a log line' {
    # A scanner that cannot detect its own target is worse than no scanner.
    $sandbox = New-TestSandbox -Prefix 'reason-scan'
    try {
        $violation = Join-Path -Path $sandbox -ChildPath 'violation.ps1'
        [System.IO.File]::WriteAllText($violation, @'
function Test-Thing {
    $verdict = Get-Something
    if ($verdict.Reason -eq 'reparse') { return $false }
    return $true
}
'@)
        Assert-True (@(Get-ReasonBranchSite -Path $violation).Count -ge 1) 'the scanner missed a real branch on Reason'

        $benign = Join-Path -Path $sandbox -ChildPath 'benign.ps1'
        [System.IO.File]::WriteAllText($benign, @'
function Test-Thing {
    $result = [PSCustomObject]@{ Reason = '' }
    $verdict = Get-Something
    $result.Reason = 'Owner is not administrative'
    # A comment mentioning $verdict.Reason must not count.
    Write-Thing -Data @{ reason = [string]$verdict.Reason }
    if ($verdict.IsTrusted) { return $true }
    return $result
}
'@)
        Assert-Equal 0 @(Get-ReasonBranchSite -Path $benign).Count 'the scanner flagged an assignment or a log line'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
