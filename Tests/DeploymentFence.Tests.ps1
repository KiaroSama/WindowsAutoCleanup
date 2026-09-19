#Requires -Version 5.1
<#
.SYNOPSIS
    The runtime refuses to clean from a deployment whose two halves were never reconciled
    (ledger WAC-02R).

.DESCRIPTION
    An installation is a tree at the deployment root and a scheduled registration that runs it, and
    only the generation that put them there ever establishes that they belong to each other. While
    that generation is in flight it keeps a durable record beside the root; a record still standing
    means the process that made it did not finish.

    The runtime used to ask nothing about it. A scheduled cleanup fires on its trigger whatever the
    last installer left behind, so an upgrade killed between its two halves was followed - hours
    later, unattended - by a SYSTEM-privileged run deleting files under an authority nobody had
    reconciled, and recording the night as an ordinary success.

    Two things are proven here: what the check answers for each shape a record path can be in, and
    that the pre-cleanup gate is where the answer is read. The gate's position is an AST assertion
    for the same reason Orchestration.Tests.ps1 makes one - a refusal reached after the deletions is
    a report, not a control, and only the ORDER of the calls can say which one this is.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:CoreModule = Get-Module -Name 'WindowsAutoCleanup.Core'

function Get-ModuleFunctionBody {
    <#
    .SYNOPSIS
        The scriptblock a name currently resolves to inside a module, so it can be put back
        exactly. Same seam Deploy.Tests.ps1 and Steps.Tests.ps1 already use.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (& $Module { param($n) (Get-Item -Path ('function:' + $n)).ScriptBlock } $Name)
}

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

function New-FenceRoot {
    <#
    .SYNOPSIS
        A deployment root inside a disposable sandbox, with nothing outstanding beside it.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $root = Join-Path -Path (Join-Path -Path $Sandbox -ChildPath 'PF') -ChildPath 'WindowsAutoCleanup'
    [void][System.IO.Directory]::CreateDirectory($root)
    return $root
}

Test-Case 'A deployment with no transaction beside it is settled' {
    $sandbox = New-TestSandbox -Prefix 'fence-clean'
    try {
        $verdict = Test-WacDeploymentGenerationSettled -DeploymentRoot (New-FenceRoot -Sandbox $sandbox)
        Assert-True ([bool]$verdict.Settled) ([string]$verdict.Reason)
        Assert-Equal 0 @($verdict.Outstanding).Count 'a settled deployment named something outstanding'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'EITHER record standing beside the deployment leaves it unsettled, and is named' {
    # Two records, two lifetimes: the swap record says a tree may be half-replaced, the capture
    # record says a registration may be missing and its definition is in there. Either alone is an
    # unfinished generation, and a check that only looked for the swap half would let a run clean
    # while the machine had no idea which task was supposed to be running it.
    foreach ($suffix in @('.transaction.json', '.taskcapture.json')) {
        $sandbox = New-TestSandbox -Prefix 'fence-open'
        try {
            $root = New-FenceRoot -Sandbox $sandbox
            $record = $root + $suffix
            [System.IO.File]::WriteAllText($record, '{}', (New-Object System.Text.UTF8Encoding($false)))

            $verdict = Test-WacDeploymentGenerationSettled -DeploymentRoot $root
            Assert-False ([bool]$verdict.Settled) ('a deployment carrying {0} was read as settled' -f $suffix)
            Assert-True (@($verdict.Outstanding) -contains $record) `
                ('the refusal did not name the record it found: {0}' -f ((@($verdict.Outstanding)) -join ','))
        }
        finally { Remove-TestSandbox -Path $sandbox }
    }
}

Test-Case 'A record path that cannot be read is not an absence' {
    # The whole doctrine of this project in one line. Get-WacPathPresence answers Unresolved when it
    # was not allowed to look, and a check that folded that into "nothing there" would hand a run
    # permission to mutate precisely on the machines whose state it could not see.
    $sandbox = New-TestSandbox -Prefix 'fence-unknown'
    $real = Get-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacPathPresence'
    try {
        $root = New-FenceRoot -Sandbox $sandbox
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacPathPresence' -Body {
            param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)
            $null = $Path
            return 'Unresolved'
        }

        $verdict = Test-WacDeploymentGenerationSettled -DeploymentRoot $root
        Assert-False ([bool]$verdict.Settled) 'a record path nobody could read was treated as no record'
        Assert-True ([string]$verdict.Reason).Contains('could not be read') `
            ('the refusal did not say what was unknown: {0}' -f [string]$verdict.Reason)
    }
    finally {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacPathPresence' -Body $real
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A deployment root that cannot be resolved settles nothing' {
    # Not the same as "there is no deployment". A root that will not canonicalise is a machine this
    # check could not look at, and the gate above turns that into a refusal rather than into the
    # permission that an empty answer would be.
    $real = Get-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacNormalizedPath'
    try {
        Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacNormalizedPath' -Body {
            param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)
            $null = $Path
            return $null
        }

        $verdict = Test-WacDeploymentGenerationSettled -DeploymentRoot 'C:
owhere\WindowsAutoCleanup'
        Assert-False ([bool]$verdict.Settled) 'an unresolvable deployment root was read as settled'
        Assert-True ([string]$verdict.Reason).Contains('could not be resolved') `
            ('the refusal did not say the root was unresolvable: {0}' -f [string]$verdict.Reason)
    }
    finally { Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-WacNormalizedPath' -Body $real }
}

Test-Case 'The record names this check uses are the ones the journal writes' {
    # DUPLICATED ON PURPOSE - the runtime does not import the deployment module - so the drift is
    # what has to be impossible, exactly as the operation-lock name is guarded between the module
    # and Run.ps1.
    $fence = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.DeploymentFence.ps1'))
    $journal = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.DeploymentJournal.ps1'))
    $quote = [string][char]39

    foreach ($name in @('DeploymentJournalSuffix', 'TaskCaptureJournalSuffix')) {
        $pattern = '\$script:{0}\s*=\s*{1}([^{1}]+){1}' -f $name, $quote
        $match = [regex]::Match($journal, $pattern)
        Assert-True $match.Success ('the journal no longer declares this record name, so the guard compares nothing: {0}' -f $name)
        Assert-True ($fence.Contains($quote + $match.Groups[1].Value + $quote)) `
            ('the fence does not carry the record name the journal writes: {0}' -f $match.Groups[1].Value)
    }
}

Test-Case 'The pre-cleanup gate is where the answer is read, ahead of every mutation' {
    $reportPath = Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.RunReport.ps1'
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($reportPath, [ref]$null, [ref]$errors)
    Assert-Equal 0 @($errors).Count 'RunReport.ps1 does not parse'

    $gate = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Get-WacRunLevelOutcome'
            }, $true))
    Assert-Equal 1 $gate.Count 'Get-WacRunLevelOutcome is no longer a single function in RunReport.ps1'

    $calls = @($gate[0].FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst] -and
                [string]$node.GetCommandName() -ceq 'Test-WacDeploymentGenerationSettled'
            }, $true))
    Assert-Equal 1 $calls.Count 'the run-level gate no longer asks whether the deployment generation is settled'

    Assert-True ([string]$gate[0].Extent.Text -match "Test-WacDeploymentGenerationSettled[\s\S]*?Candidate 'SecurityRefusal'") `
        'an unsettled deployment generation no longer raises a SECURITY refusal'
}

Complete-TestRun