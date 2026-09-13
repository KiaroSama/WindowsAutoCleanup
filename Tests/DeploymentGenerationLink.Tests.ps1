#Requires -Version 5.1
<#
.SYNOPSIS
    What the generation link is DERIVED from, and the single decision it is allowed to authorise
    (ledger WAC-02R).

.DESCRIPTION
    Two individually durable records are not an atomic pair. The link - both records carrying the
    same transaction id - is what lets one be read as the other half of the other, and it gates
    exactly one thing: retiring a capture whose task is no longer the registered one. Believing it
    too readily destroys the only evidence on the machine that a registration ever existed.

    Both halves of that sentence needed a case and neither had one. DeploymentTransactionState
    proves that a pair written by one process IS linked and that a re-stamped one is not; nothing
    proved what happens when NEITHER record carries an id, and nothing at all exercised the
    consequence - the -Linked knob in InstallerRollback.Tests.ps1 was plumbed through the rig and
    then never passed by a single scenario.

    The two cases are deliberately at different levels, because they are different claims and the
    cheap one should not drag the expensive one's setup behind it:

      derivation  - real records on disk, through the real reader. A legacy pair carries no id at
                    all, and the guard that must keep it unlinked is the one an over-eager rewrite
                    of that expression silently removes.
      consequence - the decision function alone, with the two classifiers it consults stubbed. What
                    is under test is what Resolve-CapturedTaskAgainstPlan does with a verdict and a
                    link, not how a task is recognised; TaskMatch.Tests.ps1 owns the second.
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

# Dot-sourced the way the installer dot-sources it, into THIS scope, so the collaborators it
# resolves at call time are the ones defined below.
. (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.InstallerRecovery.ps1')

$script:DeployModule = Get-Module -Name 'WindowsAutoCleanup.Deploy'
$script:Message = New-Object 'System.Collections.Generic.List[string]'
$script:Touched = New-Object 'System.Collections.Generic.List[string]'

function Reset-LinkFixture {
    & $script:DeployModule { $script:DeploymentTransaction = $null }
    $script:Message.Clear()
    $script:Touched.Clear()
}

function Write-InstallerMessage {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data = @{},
        [switch]$NoLog
    )

    $null = $Data, $NoLog
    [void]$script:Message.Add(('{0}|{1}' -f $Level, $Message))
}

function Test-WacCapturedTaskDefinition {
    <#
    .SYNOPSIS
        Shadows the real comparison so these cases are about the DECISION, not about recognition.
        Answers "a different task wears this name", which is the only state where the link matters.
    #>
    param([AllowEmptyString()][string]$Xml, $Task)

    $null = $Xml, $Task
    return ([PSCustomObject]@{ Match = $false; Reason = 'a different task wears the captured name' })
}

function Test-WacTaskIsOurs {
    param($Task, $DeploymentRoot, [switch]$AllowLegacyMigration)

    $null = $Task, $DeploymentRoot, $AllowLegacyMigration
    return ([PSCustomObject]@{ IsOurs = $true; Reason = 'stub' })
}

function Remove-WacInstalledTask {
    <#
    .SYNOPSIS
        Records the call and refuses. Neither case under test may reach a registration change at
        all, so a stub that SUCCEEDS would let a wrong verdict pass quietly.
    #>
    param($Task, [string]$DeploymentRoot, [switch]$AllowLegacyMigration)

    $null = $Task, $DeploymentRoot, $AllowLegacyMigration
    [void]$script:Touched.Add('Remove-WacInstalledTask')
    return ([PSCustomObject]@{ Verified = $false; Reason = 'the stub must not be reached' })
}

function Restore-CapturedTask {
    param($Definition)

    $null = $Definition
    [void]$script:Touched.Add('Restore-CapturedTask')
    return $false
}

function New-LinkPlan {
    <#
    .SYNOPSIS
        The smallest plan shape Resolve-CapturedTaskAgainstPlan reads: a verdict and a link.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Verdict,
        [Parameter(Mandatory = $true)][bool]$Linked
    )

    return ([PSCustomObject]@{ Verdict = $Verdict; Linked = $Linked })
}

function New-LinkCapture {
    return ([PSCustomObject]@{
        TaskName = 'WindowsAutoCleanup'
        TaskPath = '\WindowsAutoCleanup\'
        Definition = '<Task />'
    })
}

function New-LinkRegistration {
    return @([PSCustomObject]@{ TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\' })
}

function Clear-JournalGeneration {
    <#
    .SYNOPSIS
        Removes the transaction id from a record on disk, leaving everything else it says intact.
    .DESCRIPTION
        This is what a record written by a build from before generation ids looks like, and it is
        not reachable through the writer: Write-WacDeploymentJournal stamps an id into every record
        it produces. The field is deleted rather than blanked, because an ABSENT property and an
        empty one reach the reader by different routes and the absent one is the real legacy shape.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($Path))
    $record.PSObject.Properties.Remove('TransactionId')
    [System.IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $record -Depth 6),
        (New-Object System.Text.UTF8Encoding($false)))
}

Test-Case 'A pair carrying NO generation at all is never one transaction' {
    # The guard in front of the comparison, and the whole reason it is there. Both halves of a
    # legacy pair answer the empty string, and an equality test alone reads two empty strings as a
    # match - so dropping the guard links every record written before ids existed to every other
    # one, which is the state that authorises retiring a capture. The docstring has always said an
    # old pair is never linked; nothing measured it.
    Reset-LinkFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-legacy-pair' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v1') -RunContent '# original v1'))
        Reset-LinkFixture

        Assert-True (Write-WacTaskCaptureRecord -DeploymentRoot $slots.Root -Capture @([PSCustomObject]@{
            TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\'; Definition = '<Task />'
        })) 'the fixture could not write a capture record'

        [void](New-WacDeploymentStage -SourceRoot (New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v2') -RunContent '# replacement v2'))
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Reset-LinkFixture

        # Both records lose their id, which is the pair an upgrade from an older build leaves.
        foreach ($kind in @('Swap', 'TaskCapture')) {
            Clear-JournalGeneration -Path (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root -Kind $kind)
        }

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root

        # Read back first, so a failure below says whether the fixture or the rule is wrong.
        Assert-Equal '' ([string]$plan.Swap.Generation) 'the swap record still carries a generation, so the fixture proved nothing'
        Assert-Equal '' ([string]$plan.Capture.Generation) 'the capture record still carries a generation, so the fixture proved nothing'

        Assert-False $plan.Linked `
            'two records that carry no generation at all were read as one transaction, so an upgrade from a build without ids can retire a capture it never wrote'
    }
}

Test-Case 'An unlinked pair does not let a committed replacement account for a capture' {
    # THE CONSEQUENCE, which is the only thing that makes the flag matter. Accounted is what retires
    # the capture record; a pair whose halves nothing ties together must not reach it, because the
    # record is the only description of the registration this machine lost. Both directions are
    # asserted in one case: without the linked half, a rule that never returns Accounted at all
    # would pass the unlinked half for the wrong reason.
    Reset-LinkFixture
    $capture = New-LinkCapture
    $registered = New-LinkRegistration

    $linked = Resolve-CapturedTaskAgainstPlan -Capture $capture -Registered $registered `
        -Plan (New-LinkPlan -Verdict 'CommitReplacement' -Linked $true) -DeploymentRoot 'C:\Program Files\WindowsAutoCleanup'
    Assert-Equal 'Accounted' ([string]$linked.Action) `
        ('a committed replacement of a LINKED pair was not accounted for: {0}' -f [string]$linked.Reason)

    $unlinked = Resolve-CapturedTaskAgainstPlan -Capture $capture -Registered $registered `
        -Plan (New-LinkPlan -Verdict 'CommitReplacement' -Linked $false) -DeploymentRoot 'C:\Program Files\WindowsAutoCleanup'
    Assert-Equal 'Refused' ([string]$unlinked.Action) `
        ('a capture no swap record accounts for was retired by a commit that has nothing to do with it: {0}' -f [string]$unlinked.Reason)
    Assert-True ([string]$unlinked.Reason).Contains('nothing on this machine says the run that replaced it finished') `
        ('the refusal did not say why the pair could not be closed: {0}' -f [string]$unlinked.Reason)

    # Neither verdict may touch a registration: one accounts for what is already there, the other
    # refuses. A stub that was reached at all means the decision leaked into an action.
    Assert-Equal 0 @($script:Touched).Count `
        ('a registration was changed while only accounting for one: {0}' -f (@($script:Touched) -join ', '))
}

Complete-TestRun
