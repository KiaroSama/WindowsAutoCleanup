#Requires -Version 5.1
<#
.SYNOPSIS
    The states a deployment transaction can be in that are neither "a healthy tree" nor "nothing
    here", and what each of them is allowed to authorise (ledger WAC-02R).

.DESCRIPTION
    Three defects that all reduce to the same mistake - reading an answer this build cannot give as
    an answer it can:

      * An EXISTING BUT EMPTY deployment root is adopted as ours by design, and had no fingerprint
        because it has no files, so the swap recorded it as an original whose content could not be
        inventoried and THREW. Every install onto a machine carrying an empty directory at the
        deployment path failed. Absent, Empty and Substantive are three states, not two.
      * A record path that cannot be inspected - a directory standing at the name, an unreadable
        parent - answered Test-Path -PathType Leaf with $false, which read as "no transaction here".
      * A record REMOVAL that failed returned nothing anyone looked at, so a committed installation
        went on looking unfinished to the next run while the installer reported success.

    DeploymentRecovery.Tests.ps1 owns the reconciliation of a recovery slot and
    DeploymentRollback.Tests.ps1 the in-process rollback; this file owns the state machine
    underneath both of them, and is separate because those two had reached the size at which a file
    stops being read.
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

function Reset-StateFixture {
    & $script:DeployModule { $script:DeploymentTransaction = $null }
}

function New-StateStage {
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RunContent
    )

    # BOTH halves, in the installer's order (ledger WAC-02R): reconciling the recovery slot was
    # New-WacDeploymentStage's own first act until that put the file half behind the new install's
    # source validation, and this fixture stands in for the caller that performs it now.
    [void](Resolve-WacDeploymentRecoverySlot -Slots (Get-WacDeploymentSlotPath))
    return (New-WacDeploymentStage -SourceRoot (New-TestCheckout -Path (Join-Path -Path $Sandbox -ChildPath $Name) -RunContent $RunContent))
}

function Get-StateJournalField {
    <#
    .SYNOPSIS
        One field of the swap record as it sits on disk, read without the module's own reader.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $Root
    $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path))
    if (-not (@($record.PSObject.Properties.Name) -ccontains $Name)) { return $null }
    return $record.$Name
}

# ---------------------------------------------------------------------------------------------
# Absent, Empty and Substantive are three states
# ---------------------------------------------------------------------------------------------

Test-Case 'An install onto an EXISTING EMPTY deployment root succeeds and records what it replaced' {
    # The directory this project deliberately adopts as ours was also the one shape the swap could
    # not describe: Get-WacDeploymentFingerprint refuses a tree with no files in it, so a [bool]
    # HadOriginal sent an empty root down the path that demands an inventory and every install onto
    # one threw before it moved anything.
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-empty-root' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void][System.IO.Directory]::CreateDirectory($slots.Root)

        $ownership = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root
        Assert-True $ownership.IsOurs ('the fixture is not the adopted-empty shape this case is about: ' + [string]$ownership.Reason)
        Assert-True $ownership.IsEmpty ([string]$ownership.Reason)

        [void](New-StateStage -Sandbox $sandbox -Name 'v1' -RunContent '# first install')
        $switched = Switch-WacDeploymentStage -KeepPrevious

        Assert-True $switched.PreviousKept 'the empty directory was not moved aside, so there is nothing to put back'
        Assert-Equal '# first install' ([System.IO.File]::ReadAllText($switched.RunScript))
        Assert-Equal 'Empty' ([string](Get-StateJournalField -Root $slots.Root -Name 'OriginalState')) `
            'the durable record does not say what kind of original it moved aside'

        # And the rollback puts the empty directory back, and PROVES it did.
        $restored = Restore-WacDeploymentPrevious
        Assert-True $restored.Restored ([string]$restored.Reason)
        Assert-True (Test-Path -LiteralPath $slots.Root -PathType Container) 'the empty original was not put back'
        Assert-Equal 0 @(Get-ChildItem -LiteralPath $slots.Root -Force).Count 'what came back is not the empty directory that was moved aside'
        Assert-False (Test-Path -LiteralPath (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root)) `
            'a completed rollback left its transaction record on disk'
    }
}

Test-Case 'An empty original that gained FILES in the recovery slot is not put back over the replacement' {
    # The corroboration for an empty original is that it is still empty. A slot that acquired files
    # while it sat there is not what was moved aside, and promoting it would replace a verified
    # deployment with something nothing on this machine can vouch for.
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-empty-grew' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void][System.IO.Directory]::CreateDirectory($slots.Root)

        [void](New-StateStage -Sandbox $sandbox -Name 'v1' -RunContent '# first install')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'), '# not what was moved aside')

        $restored = Restore-WacDeploymentPrevious
        Assert-False $restored.Restored 'a recovery slot that had gained files was reported as the empty directory moved aside'
        Assert-True ([string]$restored.Reason -match 'holds files') ([string]$restored.Reason)
        Assert-Equal '# first install' ([System.IO.File]::ReadAllText((Join-Path -Path $slots.Root -ChildPath 'Run.ps1'))) `
            'the refusal deleted the verified deployment anyway'
    }
}

Test-Case 'A SUBSTANTIVE original is still recorded, fingerprinted and proven on the way back' {
    # The other two states must not have been broken by teaching the record about the third.
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-substantive' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v1') -RunContent '# original v1'))
        Reset-StateFixture

        [void](New-StateStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        Assert-Equal 'Substantive' ([string](Get-StateJournalField -Root $slots.Root -Name 'OriginalState')) `
            'a tree with files in it was recorded as something other than substantive'
        Assert-True (([string](Get-StateJournalField -Root $slots.Root -Name 'OriginalFingerprint')).Length -gt 0) `
            'a substantive original was recorded with no inventory to prove it by'

        $restored = Restore-WacDeploymentPrevious
        Assert-True $restored.Restored ([string]$restored.Reason)
        Assert-Equal '# original v1' ([System.IO.File]::ReadAllText((Join-Path -Path $slots.Root -ChildPath 'Run.ps1')))
    }
}

Test-Case 'A FIRST install with no original at all is recorded as absent and rolled back by removal' {
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-absent-original' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](New-StateStage -Sandbox $sandbox -Name 'v1' -RunContent '# first install')
        [void](Switch-WacDeploymentStage -KeepPrevious)

        Assert-Equal 'Absent' ([string](Get-StateJournalField -Root $slots.Root -Name 'OriginalState')) `
            'an install that moved nothing aside recorded an original anyway'

        $restored = Restore-WacDeploymentPrevious
        Assert-True $restored.Restored ([string]$restored.Reason)
        Assert-False (Test-Path -LiteralPath $slots.Root) 'the tree this run installed was left behind by its own rollback'
    }
}

# ---------------------------------------------------------------------------------------------
# A record path that cannot be inspected is not an absent record
# ---------------------------------------------------------------------------------------------

Test-Case 'A DIRECTORY standing at the swap record path refuses staging instead of reading as absent' {
    # Test-Path -PathType Leaf answers $false for a directory, so the reader called it absence - and
    # absence is permission to discard a recovery copy.
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-record-directory' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v1') -RunContent '# original v1'))
        Reset-StateFixture

        [void](New-StateStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Reset-StateFixture

        # The record goes, and a directory takes its name.
        $record = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root
        [System.IO.File]::Delete($record)
        [void][System.IO.Directory]::CreateDirectory($record)

        $read = Read-WacDeploymentJournal -DeploymentRoot $slots.Root
        Assert-Equal 'Unreadable' ([string]$read.State) 'a directory at the record path was read as no record at all'
        Assert-True ([string]$read.Reason -match 'directory') ([string]$read.Reason)

        $refused = $false
        $reason = ''
        try { [void](New-StateStage -Sandbox $sandbox -Name 'v3' -RunContent '# replacement v3') }
        catch { $refused = $true; $reason = [string]$_.Exception.Message }

        Assert-True $refused 'a record path nobody could inspect was treated as no record at all'
        Assert-True ($reason -match 'could not be read') ('the refusal did not name the reason: ' + $reason)
        Assert-Equal '# original v1' ([System.IO.File]::ReadAllText((Join-Path -Path $slots.Previous -ChildPath 'Run.ps1'))) `
            'the copy in the recovery slot was destroyed'
    }
}

Test-Case 'A recovery slot that is a FILE refuses instead of reading as no slot at all' {
    # Test-Path -PathType Container has the same hole, and the branch it guarded went on to delete
    # the swap record - the only evidence the transaction had been in flight.
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-slot-file' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v1') -RunContent '# original v1'))
        Reset-StateFixture

        [void](New-StateStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Reset-StateFixture

        [System.IO.Directory]::Delete($slots.Previous, $true)
        [System.IO.File]::WriteAllText($slots.Previous, 'not a directory')

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'Refuse' ([string]$plan.Verdict) 'a file standing at the recovery slot was read as no slot at all'
        Assert-Equal 'Unreadable' ([string]$plan.SlotState) ([string]$plan.Reason)
        Assert-True (Test-Path -LiteralPath (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root) -PathType Leaf) `
            'the only evidence the transaction had been in flight was deleted'
    }
}

Test-Case 'A record whose recovery slot is GONE is not cleared unless the outcome is proven' {
    # Recovery deleted the record whenever the slot was absent, on the grounds that there is nothing
    # left to put back - which is true and is not the point: the record also says whether the tree
    # standing at the root ever committed.
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-slot-gone' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v1') -RunContent '# original v1'))
        Reset-StateFixture

        [void](New-StateStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Reset-StateFixture

        # The recovery copy is gone AND what stands at the root is not the replacement the record
        # names - so neither half of the transaction can be accounted for.
        [System.IO.Directory]::Delete($slots.Previous, $true)
        [System.IO.File]::WriteAllText((Join-Path -Path $slots.Root -ChildPath 'Run.ps1'), '# a different build')
        [void](New-WacDeploymentManifest -StagingRoot $slots.Root)

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'Refuse' ([string]$plan.Verdict) 'a transaction nobody could account for was closed anyway'
        Assert-True (Test-Path -LiteralPath (Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root) -PathType Leaf) `
            'the record was deleted while the outcome it describes was still unknown'

        # And the benign half. What makes it benign is NOT that the replacement is live - a live
        # replacement is equally what a run that died before registering its task leaves behind - but
        # that the generation wrote down that it finished, while the copy it replaced was still there
        # to roll back to. The refusal above has to be cleared first, or staging the next tree refuses
        # on it, which would prove nothing about the second half.
        [void](Remove-WacDeploymentJournal -DeploymentRoot $slots.Root)
        Reset-StateFixture
        [void](New-StateStage -Sandbox $sandbox -Name 'v3' -RunContent '# replacement v3')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Assert-True ([bool](Set-WacDeploymentCommitted).Recorded) 'the commit decision could not be recorded'
        Reset-StateFixture
        [System.IO.Directory]::Delete($slots.Previous, $true)

        $settled = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'CommitReplacement' ([string]$settled.Verdict) ([string]$settled.Reason)
    }
}

# ---------------------------------------------------------------------------------------------
# A removal that failed is a result, not a gesture
# ---------------------------------------------------------------------------------------------

Test-Case 'A record removal that could not finish reports FAILURE rather than a closed transaction' {
    # Every caller discarded this answer with [void], so a committed installation whose record
    # survived went on looking unfinished to the next run while its installer reported success.
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-removal-failed' -Body {
        param($sandbox)

        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath
        [void][System.IO.Directory]::CreateDirectory($slots.Root)

        $record = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root
        [System.IO.File]::WriteAllText($record, '{}')

        # A directory at one of the write protocol's own artifact names: the record itself deletes,
        # the artifact cannot, and the transaction is therefore not proven over.
        [void][System.IO.Directory]::CreateDirectory($record + '.last')

        Assert-False (Remove-WacDeploymentJournal -DeploymentRoot $slots.Root) `
            'a removal that left part of the transaction on disk reported success'
        Assert-False (Test-Path -LiteralPath $record -PathType Leaf) 'the record itself was not deleted'

        # Cleared, and now the same call proves it.
        [System.IO.Directory]::Delete($record + '.last', $true)
        Assert-True (Remove-WacDeploymentJournal -DeploymentRoot $slots.Root) `
            'a transaction with nothing left on disk reported itself unfinished'
    }
}

Test-Case 'The write protocol leaves no artifact of its own behind' {
    # The staging name is transient by construction and the backup one is no longer written at all.
    # Both are swept when the transaction ends, so a machine carrying one from an older build is
    # left clean rather than accumulating.
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-artifacts' -Body {
        param($sandbox)

        $null = $sandbox
        $slots = Get-WacDeploymentSlotPath
        [void][System.IO.Directory]::CreateDirectory($slots.Root)
        $record = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root

        foreach ($pass in @('first', 'second')) {
            # Through the module's scope: the writer is internal, and the artifacts it leaves are
            # what this case is about rather than anything a caller of the export list can see.
            Assert-True (& $script:DeployModule { param($r, $p, $s)
                Write-WacDeploymentJournal -DeploymentRoot $r -Record ([PSCustomObject]@{
                    Schema = 3; ProjectId = $p; Root = $r; Stage = $s })
            } $slots.Root (Get-WacDeploymentProjectId) $pass) ('the {0} write failed' -f $pass)
            Assert-False (Test-Path -LiteralPath ($record + '.new')) ('the {0} write left its staging file behind' -f $pass)
            Assert-False (Test-Path -LiteralPath ($record + '.last')) ('the {0} write left a backup nothing reads' -f $pass)
        }

        # A second write REPLACED the first rather than failing silently: the record says 'second'.
        $read = Read-WacDeploymentJournal -DeploymentRoot $slots.Root
        Assert-Equal 'Valid' ([string]$read.State) ([string]$read.Reason)
        Assert-Equal 'second' ([string]$read.Record.Stage) `
            'the replace of an existing record did not land, so every later stage was lost'

        # And an artifact an older build left is swept with the record it belongs to.
        [System.IO.File]::WriteAllText($record + '.last', 'left by an older build')
        Assert-True (Remove-WacDeploymentJournal -DeploymentRoot $slots.Root) 'the removal could not clear its own artifacts'
        foreach ($artifact in @($record, ($record + '.new'), ($record + '.last'))) {
            Assert-False (Test-Path -LiteralPath $artifact) ('{0} outlived the transaction it belongs to' -f $artifact)
        }
    }
}

Test-Case 'Both records of one process carry the SAME generation, and an unlinked pair is not one' {
    # What makes two files one transaction. Equal ids mean one generation and one commit decision;
    # a capture whose generation no swap record accounts for is ambiguity, and ambiguity preserves
    # both halves rather than letting them retire each other.
    Reset-StateFixture
    Invoke-InDeploymentSandbox -Prefix 'wac02r-generation' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        [void](Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v1') -RunContent '# original v1'))
        Reset-StateFixture

        Assert-True (Write-WacTaskCaptureRecord -DeploymentRoot $slots.Root -Capture @([PSCustomObject]@{
            TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\'; Definition = '<Task />'
        })) 'the fixture could not write a capture record'

        [void](New-StateStage -Sandbox $sandbox -Name 'v2' -RunContent '# replacement v2')
        [void](Switch-WacDeploymentStage -KeepPrevious)
        Reset-StateFixture

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-True $plan.Linked 'two records this process wrote were not read as one transaction'
        Assert-Equal ([string]$plan.Swap.Generation) ([string]$plan.Capture.Generation) 'the two halves carry different generations'
        Assert-True (([string]$plan.Swap.Generation).Length -gt 0) 'the records carry no generation at all'

        # A capture from a DIFFERENT generation is not this transaction's other half.
        $capturePath = Get-WacDeploymentJournalPath -DeploymentRoot $slots.Root -Kind 'TaskCapture'
        $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($capturePath))
        $record.TransactionId = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
        [System.IO.File]::WriteAllText($capturePath, (ConvertTo-Json -InputObject $record -Depth 5),
            (New-Object System.Text.UTF8Encoding($false)))

        $unlinked = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-False $unlinked.Linked 'two records from different runs were read as one transaction'
    }
}

Test-Case 'The installer maps a record that outlived its own commit to a non-success exit' {
    # Both record deletions at the commit point were discarded with [void], so an install whose
    # transaction stayed on disk announced success while the next run read a settled deployment as
    # unfinished. The work really is done, so this is INCOMPLETE (6) rather than a failure - the
    # same shape the undurable-audit-log rule beside it already had.
    $path = Join-Path -Path $script:RepoRoot -ChildPath 'Install-WindowsAutoCleanupTask.ps1'
    $text = [System.IO.File]::ReadAllText($path)

    Assert-True ($text -match '\$committed = \[bool\]\(Remove-WacDeploymentPrevious\)') `
        'the swap record removal result is discarded again'
    Assert-True ($text -match '\$captureEnded = \[bool\]\(Remove-WacTaskCaptureRecord') `
        'the capture record removal result is discarded again'
    Assert-True ($text -match '\$decisionRecorded = \[bool\]\$decision\.Recorded') `
        'the commit decision is no longer recorded before either recovery copy is retired'
    Assert-True ($text -match '(?s)if \(-not \$decisionRecorded -or -not \$committed -or -not \$captureEnded\) \{[\s\S]{0,900}?return 6') `
        'an install whose transaction record outlived it no longer reports a non-success exit'

    # And it is reached on the SUCCESS path, after the commit, not from a catch.
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count 'the installer does not parse'
    $guard = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.IfStatementAst]
    }, $true) | Where-Object { $_.Extent.Text -match '\$committed -or -not \$captureEnded' })
    Assert-Equal 1 $guard.Count 'the incomplete-transaction verdict is no longer a single guarded decision'
    Assert-Equal 0 @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CatchClauseAst]
    }, $true) | Where-Object { $_.Extent.Text -match '\$captureEnded' }).Count `
        'the commit verdict was moved into a catch, where a failed install would reach it too'
}

Test-Case 'The uninstaller ends outstanding records, and only once the removal is proven clean' {
    # The records live BESIDE the slots - which is what stops a move or a delete of a slot carrying
    # them off - so removing the deployment left both of them exactly where they were. An authorized
    # uninstall that succeeded and a crashed upgrade then looked identical on disk, and the next
    # install re-registered a task whose files the operator had just asked to have removed.
    #
    # Asserted against the source rather than by driving the uninstaller, because the state that
    # matters is an ORDERING - after the removal, and only on a clean one - and the end-to-end
    # effect of ending the records is covered in DeploymentPairRecovery.Tests.ps1.
    $path = Join-Path -Path $script:RepoRoot -ChildPath 'Uninstall-WindowsAutoCleanupTask.ps1'
    $text = [System.IO.File]::ReadAllText($path)

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count 'the uninstaller does not parse'

    $closers = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true) | Where-Object { $_.GetCommandName() -eq 'Close-OutstandingJournal' })
    Assert-Equal 1 $closers.Count 'the uninstaller no longer ends the transaction records it leaves behind'

    Assert-True ($text -match '(?s)\$deployment = Remove-InstalledDeployment[^\r\n]*\r?\n\s*if \(\$deployment\.Clean\) \{ \[void\]\(Close-OutstandingJournal') `
        'the records are ended somewhere other than immediately after a PROVEN clean deployment removal'

    Assert-True ($text -match '(?s)function Close-OutstandingJournal[\s\S]{0,3000}?Remove-WacDeploymentJournal') `
        'the closing step no longer deletes the records'
    # No -f here: the quantifier {0,3000} IS a format placeholder to the format operator - argument
    # zero padded to a width of three thousand - so the pattern silently stopped being a pattern.
    foreach ($kind in @('Swap', 'TaskCapture')) {
        Assert-True ($text -match ("(?s)function Close-OutstandingJournal[\s\S]{0,3000}?'" + $kind + "'")) `
            ('the closing step never names the {0} record' -f $kind)
    }
}

Complete-TestRun
