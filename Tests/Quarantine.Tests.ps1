#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-05R: the uncertainty an abandoned mutator leaves has to outlive the process that raised it,
    and the run sequence has to read it.

.DESCRIPTION
    Two halves of one defect, proven together because they only matter together.

    THE LATCH DIED WITH THE PROCESS. An in-process mutating block that misses its bound is
    abandoned, not stopped - PowerShell.Stop() cannot interrupt a blocking native call - so the run
    stops scheduling mutations. That latch was a module variable, and Run.ps1 releases the
    machine-wide operation lock and exits. The next holder of that lock, which is the next scheduled
    run or an installer, learned nothing: releasing the mutex erased the one fact that mattered.
    The marker is now durable and is retired only on PROOF that the process which wrote it is gone.

    THE SEQUENCE NEVER ASKED. The latch was enforced where mutations happen - the driver candidate
    loop, cleanmgr's profile write, Remove-WacTree, every -Mutating bounded block - and nowhere in
    the step sequence. So a quarantined run still launched dism.exe and pnpclean.dll, two external
    mutators that have no such guard of their own. Invoke-WacGuardedStep is now in front of every
    one of them.

    The rig cases below run the SHIPPED Run.ps1 in a sandbox against a marker this process planted,
    so the marker genuinely crosses a process boundary rather than being asserted about in the
    process that wrote it.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'

Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# Both deletion primitives are asserted here rather than in FileSystem.Tests.ps1: the contract under
# test is the quarantine's, and keeping its consumers in one file is what makes a missing one visible.
Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.FileSystem.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_RunProbe.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_RunRig.ps1')

$script:Utf8 = New-Object System.Text.UTF8Encoding($false)

function Set-TestDataRoot {
    <#
    .SYNOPSIS
        Points BOTH roots the quarantine reads at a sandbox, for the duration of a case.
    .DESCRIPTION
        Two roots since ledger WAC-14: the marker itself lives in the strict CONTROL store, and the
        legacy location under %ProgramData% is still checked for presence so a record written by an
        older build is never silently believed or deleted. A case that redirected only one of them
        would be reading this machine's real state for the other.

        The descriptor verdict is answered too, because an unelevated suite cannot own a TEMP
        directory the way -RequireStrictTrust demands. The collision-failing create, the reparse
        refusal and the hard-link refusal stay the kernel's answers - QuarantineStore.Tests.ps1 is
        where those are proven.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    [void][System.IO.Directory]::CreateDirectory($Path)
    $env:ProgramData = $Path

    $store = Join-Path -Path $Path -ChildPath 'Control'
    [void][System.IO.Directory]::CreateDirectory($store)
    Set-WacControlRoot -Path $store
    Set-WacDirectoryTrustJudge -ScriptBlock {
        param($Sddl, $Strict)
        $null = $Sddl; $null = $Strict
        return [PSCustomObject]@{ IsTrusted = $true; Owner = $null; Reason = 'test shim: descriptor verdict'; Writers = @() }
    }
}

function Reset-TestDataRoot {
    <#
    .SYNOPSIS
        Undoes Set-TestDataRoot. Called from every case's finally, whichever way it ended.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$SavedProgramData)

    Set-WacDirectoryTrustJudge -ScriptBlock $null
    Restore-SuiteControlStore
    $env:ProgramData = $SavedProgramData
}

function Write-TestMarker {
    <#
    .SYNOPSIS
        Plants a quarantine marker under a given %ProgramData%, exactly as an earlier process would.
    .DESCRIPTION
        -Text writes the file verbatim, which is how the torn case is produced. Otherwise the record
        is built from the parameters, so a case can name a process that is alive, one whose id now
        belongs to something else, or none at all.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ProgramData,
        [int]$ProcessId = $PID,
        [string]$ProcessCreated,
        [string]$Text,
        # Omitted on purpose by default: that is a record from a build before the field existed, and
        # what the resolver does with one of those is part of what these cases pin down.
        [ValidateSet('InProcess', 'External')][string]$Kind
    )

    # Straight into the redirected control store, because that is where the shipped reader looks.
    $directory = Join-Path -Path $ProgramData -ChildPath 'Control'
    [void][System.IO.Directory]::CreateDirectory($directory)
    $path = Join-Path -Path $directory -ChildPath (Get-WacQuarantineMarkerName)

    # ContainsKey, not a null test: a [string] parameter left unbound is the EMPTY STRING, so
    # `$null -ne $Text` was true for every caller and every marker was written empty.
    if ($PSBoundParameters.ContainsKey('Text')) {
        [System.IO.File]::WriteAllText($path, $Text, $script:Utf8)
        return $path
    }

    $created = if ($PSBoundParameters.ContainsKey('ProcessCreated')) { $ProcessCreated } else { [string](Get-WacCurrentProcessCreated) }
    $record = [PSCustomObject]@{
        ProcessId = $ProcessId
        ProcessCreated = $created
        RaisedUtc = ((Get-Date).ToUniversalTime().ToString('o'))
        Count = 1
        Reason = 'planted by Quarantine.Tests.ps1'
    }
    if ($PSBoundParameters.ContainsKey('Kind')) {
        Add-Member -InputObject $record -MemberType NoteProperty -Name 'OperationKind' -Value $Kind
    }
    [System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $record -Depth 3), $script:Utf8)
    return $path
}

# The id of a process that is CERTAINLY still running: this one. Binding one's own process needs no
# privilege at all, so the alive branch below never depends on what the runner permits.
function Get-LiveCreated { return [string](Get-WacCurrentProcessCreated) }

Test-Case 'an abandoned mutation is recorded where the next process can find it' {
    # The producer half. Before this the abandonment existed only as a module variable, so the fact
    # never left the process - which is the whole defect.
    $sandbox = New-TestSandbox -Prefix 'quarantine-write'
    $saved = [string]$env:ProgramData
    try {
        Set-TestDataRoot -Path $sandbox
        Reset-WacAbandonedMutator

        [void](Add-WacAbandonedMutator -Reason 'a test abandoned a mutating block')

        Assert-Equal 'Valid' ([string](Read-WacControlFile -Name (Get-WacQuarantineMarkerName)).State) `
            'no durable marker was written into the control store'
        Assert-False (Test-WacMutationAllowed) 'the in-memory latch did not arm'

        $marker = Read-WacQuarantineMarker
        Assert-Equal 'Valid' ([string]$marker.State) ('the marker just written did not read back: ' + [string]$marker.Reason)
        Assert-Equal $PID ([int]$marker.Record.ProcessId) 'the marker did not record the process that raised it'
        Assert-True (([string]$marker.Record.Reason).Contains('abandoned a mutating block')) `
            ('the marker did not record what was abandoned: ' + [string]$marker.Record.Reason)
    }
    finally {
        Reset-WacAbandonedMutator
        Reset-TestDataRoot -SavedProgramData $saved
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'clearing the in-memory latch cannot erase the machine uncertainty' {
    # THE regression for the ledger item. Reset-WacAbandonedMutator is what a new run used to call,
    # and what a suite still calls between cases: it opens the door again IN THIS PROCESS, and it
    # must not be able to discard a fact about the machine. Only Resolve-WacQuarantine may retire a
    # marker, and only on proof.
    $sandbox = New-TestSandbox -Prefix 'quarantine-reset'
    $saved = [string]$env:ProgramData
    try {
        Set-TestDataRoot -Path $sandbox
        Reset-WacAbandonedMutator
        [void](Add-WacAbandonedMutator -Reason 'a test abandoned a mutating block')

        Reset-WacAbandonedMutator
        Assert-True (Test-WacMutationAllowed) 'the in-memory reset did not clear the latch it owns'
        Assert-Equal 'Valid' ([string](Read-WacControlFile -Name (Get-WacQuarantineMarkerName)).State) `
            'the in-memory reset deleted the durable marker, which is the erasure this fix exists to stop'

        # What a NEW run does. The process that raised it is this one, and it is still running.
        $resolved = Resolve-WacQuarantine
        Assert-Equal 'Quarantined' ([string]$resolved.State) ('a live abandonment was not carried forward: ' + [string]$resolved.Reason)
        Assert-False (Test-WacMutationAllowed) 'a new run started mutating with an unretired abandonment on the machine'
    }
    finally {
        Reset-WacAbandonedMutator
        Reset-TestDataRoot -SavedProgramData $saved
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'only IN-PROCESS work is retired by proving the host that reported it is gone' {
    # The host's death proves one thing: no thread of that process survived it. That is the whole
    # argument for retiring a record, and it holds for an in-process block and for nothing else
    # (ledger WAC-05R). An external tool, a service-dispatched operation or an unowned descendant
    # outlives the process that launched it, so retiring THEIR record on the launcher's death is
    # proving the wrong thing - and it was the one path that could clear the machine while the work
    # it was worried about carried on.
    #
    # The evidence is an identity, never a clock: the id is the same, the creation time is not, so
    # whatever owns that id now is a different process.
    $sandbox = New-TestSandbox -Prefix 'quarantine-retire'
    $saved = [string]$env:ProgramData
    try {
        Set-TestDataRoot -Path $sandbox
        Reset-WacAbandonedMutator

        $live = [long](Get-LiveCreated)
        [void](Write-TestMarker -ProgramData $sandbox -ProcessId $PID -ProcessCreated ([string]($live + 1)) -Kind 'InProcess')

        $resolved = Resolve-WacQuarantine
        Assert-Equal 'Retired' ([string]$resolved.State) ('a finished in-process abandonment was not retired: ' + [string]$resolved.Reason)
        Assert-True (Test-WacMutationAllowed) 'a retired quarantine still refused every mutation'
        Assert-Equal 'Absent' ([string](Read-WacControlFile -Name (Get-WacQuarantineMarkerName)).State) 'a retired marker was left in the store'

        # THE HALF THAT WAS MISSING. The same proof against EXTERNAL work settles nothing, and a
        # record from a build before the field existed reads as external because that is the answer
        # that keeps it.
        foreach ($planted in @(@{ Kind = 'External' }, @{})) {
            Reset-WacAbandonedMutator
            [void](Write-TestMarker -ProgramData $sandbox -ProcessId $PID -ProcessCreated ([string]($live + 1)) @planted)

            $external = Resolve-WacQuarantine
            $label = if ($planted.ContainsKey('Kind')) { 'an external' } else { 'a legacy' }
            Assert-Equal 'Quarantined' ([string]$external.State) `
                ('{0} abandonment was retired because the process that REPORTED it had died: {1}' -f $label, [string]$external.Reason)
            Assert-False (Test-WacMutationAllowed) ('{0} abandonment left the run free to mutate' -f $label)
            Assert-True (([string](Read-WacControlFile -Name (Get-WacQuarantineMarkerName)).State) -cne 'Absent') `
                ('{0} record was deleted, so the next run will not learn about it' -f $label)
        }
    }
    finally {
        Reset-WacAbandonedMutator
        Reset-TestDataRoot -SavedProgramData $saved
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a marker that cannot be read is not absence' {
    # Three answers, never two. A torn write or a file something else left must not read as "there
    # was no abandonment here", because that is the reading that licenses mutating the machine.
    $sandbox = New-TestSandbox -Prefix 'quarantine-torn'
    $saved = [string]$env:ProgramData
    try {
        Set-TestDataRoot -Path $sandbox
        Reset-WacAbandonedMutator
        [void](Write-TestMarker -ProgramData $sandbox -Text '{"ProcessId": 12')

        Assert-Equal 'Unreadable' ([string](Read-WacQuarantineMarker).State) 'a torn marker read as something this run could act on'

        $resolved = Resolve-WacQuarantine
        Assert-Equal 'Quarantined' ([string]$resolved.State) ('a torn marker did not fail closed: ' + [string]$resolved.Reason)
        Assert-False (Test-WacMutationAllowed) 'a run mutated the machine over a marker it could not read'
        Assert-Equal 'Valid' ([string](Read-WacControlFile -Name (Get-WacQuarantineMarkerName)).State) 'a marker that could not be parsed was deleted anyway'
    }
    finally {
        Reset-WacAbandonedMutator
        Reset-TestDataRoot -SavedProgramData $saved
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a marker naming no usable process can never be retired' {
    # A record with an id nothing can be proven about is the same class as a torn one. It is called
    # out separately because it is the shape a partially written or hand-edited marker takes, and
    # because it needs no process binding at all - so the answer cannot depend on the runner.
    $sandbox = New-TestSandbox -Prefix 'quarantine-noid'
    $saved = [string]$env:ProgramData
    try {
        Set-TestDataRoot -Path $sandbox
        Reset-WacAbandonedMutator
        [void](Write-TestMarker -ProgramData $sandbox -ProcessId 0 -ProcessCreated '0')

        Assert-Equal 'Quarantined' ([string](Resolve-WacQuarantine).State) 'a marker naming no process was treated as retired'
        Assert-False (Test-WacMutationAllowed) 'a run mutated the machine over a marker with no identity'
    }
    finally {
        Reset-WacAbandonedMutator
        Reset-TestDataRoot -SavedProgramData $saved
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'both deletion primitives refuse while a mutation is unproven' {
    # Remove-WacTree carried the latch and Remove-WacFilesByPattern did not, although it deletes
    # exactly as much - one consumer of a contract updated and its sibling left behind, which is the
    # shape this round exists to remove. Run.ps1 refuses the whole sweep at the loop head as well;
    # both are kept, because the primitives are exported and a guard that lives only in one caller
    # is not a guard.
    $sandbox = New-TestSandbox -Prefix 'quarantine-sweep'
    $saved = [string]$env:ProgramData
    try {
        Set-TestDataRoot -Path (Join-Path -Path $sandbox -ChildPath 'state')
        Reset-WacAbandonedMutator

        $target = Join-Path -Path $sandbox -ChildPath 'target'
        [void][System.IO.Directory]::CreateDirectory($target)
        $victim = Join-Path -Path $target -ChildPath 'cache.tmp'
        [System.IO.File]::WriteAllText($victim, 'x')

        # The control first: without it "always refuse" would satisfy everything below.
        $before = Remove-WacFilesByPattern -Category 'Quarantine test' -Path $target -Pattern @('*.tmp')
        Assert-True ([bool]$before.Attempted) 'the pattern sweep refused before anything was abandoned'
        Assert-False ([System.IO.File]::Exists($victim)) 'the control case deleted nothing, so the case proves nothing'

        [System.IO.File]::WriteAllText($victim, 'x')
        [void](Add-WacAbandonedMutator -Reason 'a test abandoned a mutating block')

        $pattern = Remove-WacFilesByPattern -Category 'Quarantine test' -Path $target -Pattern @('*.tmp')
        Assert-False ([bool]$pattern.Attempted) 'the pattern sweep ran while a mutation could still be writing'
        Assert-True ([System.IO.File]::Exists($victim)) 'a quarantined pattern sweep deleted a file anyway'

        $tree = Remove-WacTree -Category 'Quarantine test' -Path $target
        Assert-False ([bool]$tree.Attempted) 'the tree sweep ran while a mutation could still be writing'
        Assert-True ([System.IO.File]::Exists($victim)) 'a quarantined tree sweep deleted a file anyway'
    }
    finally {
        Reset-WacAbandonedMutator
        Reset-TestDataRoot -SavedProgramData $saved
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a quarantined run starts no mutating step' {
    # The ORCHESTRATION half, through the SHIPPED Run.ps1 in a child process. The latch is armed in
    # the rig's Initialize-WacRun shim, immediately after the real one has resolved the durable
    # record - so what this proves is the step SEQUENCE reading the latch, which is the ledger item.
    # Where the record itself comes from, and that it survives a process, is QuarantineStore's job.
    $rig = New-RunRig -Prefix 'quarantine-rig-armed'
    try {
        $plan = @{ quarantined = $true; targets = @((New-PlanTarget -Category 'Temp' -FilesDeleted 3)) }
        $result = Invoke-RunRig -Rig $rig -Plan $plan

        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'

        $text = Get-RigLogText -Rig $rig
        # Every shim step logs through the SHIPPED Write-WacStepResult under this component, so its
        # absence is the proof that no step ran - not an assertion about a flag the guard sets.
        Assert-False ($text.Contains('[TestStep]')) `
        ('a quarantined run started a mutating step anyway: ' + $text)
        Assert-True ($text.Contains('an earlier mutation was abandoned and cannot be proven finished')) `
        ('the run did not record why the steps were refused: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'a run with nothing unresolved cleans normally' {
    # The control, and the one that keeps the guard from becoming a permanent stop. Without it
    # "always refuse" satisfies the case above and this tool would never clean anything again.
    $rig = New-RunRig -Prefix 'quarantine-rig-clean'
    try {
        $plan = @{ targets = @((New-PlanTarget -Category 'Temp' -FilesDeleted 3)) }
        Assert-RigExit -Rig $rig -Result (Invoke-RunRig -Rig $rig -Plan $plan) -ExitCode 0 -Status 'Succeeded'

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text.Contains('[TestStep]')) ('a run with no abandonment skipped its steps: ' + $text)
        Assert-False ($text.Contains('an earlier mutation was abandoned')) `
        ('a clean run reported a quarantine it did not have: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Complete-TestRun
