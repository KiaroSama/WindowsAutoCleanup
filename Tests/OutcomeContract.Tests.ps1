#Requires -Version 5.1
<#
.SYNOPSIS
    The outcome precedence lattice and the exit-code map, tested directly.

.DESCRIPTION
    These four values decide which exit code the tool reports, and until this suite existed they were
    exercised only as a side effect of the child processes RunExitCode.Tests.ps1 spawns - roughly a
    third of the ordered outcome pairs and six of the eight documented exit codes. A precedence
    inversion between two outcomes that no end-to-end scenario happens to combine would have shipped
    green, and the first place anyone would notice is a machine reporting the wrong verdict.

    The expected values below are written as LITERALS. Reading them from the implementation would
    assert that the code equals itself; stating the contract independently is the whole point, and it
    means changing the contract requires deliberately stating the new one here.

    RunReport.ps1 is DOT-SOURCED rather than imported: it is not a module, deliberately, because it
    runs in Run.ps1's own script scope (see RunSurface.Tests.ps1 for why that must stay true).
    The rank table and Get-WacHigherOutcome live in StepContract.psm1 - ONE copy, reached through
    Steps.psm1. RunReport.ps1 and Drivers.psm1 each used to hold their own; Run.ps1 held a third as a
    raw table index. Invoke-DriverHigherOutcome below still calls through the driver module's scope
    on purpose, because that reachability is what the merge could have broken.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_StepHarness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Steps.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Drivers.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
. (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.RunReport.ps1')

$script:DriverModule = Get-Module WindowsAutoCleanup.Drivers

# The contract, stated independently of the implementation.
$script:ExpectedRank = [ordered]@{
    'Succeeded' = 0; 'SafeSkip' = 0; 'Incomplete' = 1; 'Failed' = 2; 'SecurityRefusal' = 3
}
$script:ExpectedExitCode = [ordered]@{
    'Succeeded' = 0; 'SafeSkip' = 0; 'Incomplete' = 6; 'Failed' = 2; 'SecurityRefusal' = 7
}
$script:ExpectedLogLevel = [ordered]@{
    'Succeeded' = 'INFO'; 'SafeSkip' = 'INFO'
    'Incomplete' = 'CRITICAL'; 'Failed' = 'CRITICAL'; 'SecurityRefusal' = 'CRITICAL'
}

function Invoke-DriverHigherOutcome {
    <#
    .SYNOPSIS
        The lattice as the DRIVER module sees it.
    .DESCRIPTION
        Drivers.psm1 used to define its own byte-identical copy; the two were merged into
        StepContract.psm1, which Drivers reaches through Steps.psm1. This still calls through the
        driver module's scope on purpose - it proves the merged function is actually reachable from
        that load path, which is the thing the merge could have broken.
    #>
    param([string]$Current, [string]$Candidate)

    return (& $script:DriverModule { param($c, $n) Get-WacHigherOutcome -Current $c -Candidate $n } $Current $Candidate)
}

# ---------------------------------------------------------------------------------------------
# Precedence
# ---------------------------------------------------------------------------------------------

Test-Case 'every ordered pair of outcomes resolves to the higher-ranked one' {
    # All 25 ordered pairs, in both argument positions, against both copies of the lattice. The tie
    # rule this pins: equal ranks keep $Current, so SafeSkip after Succeeded stays Succeeded - both
    # map to exit 0, so either answer is correct at the exit code and only one is correct here.
    foreach ($current in $script:ExpectedRank.Keys) {
        foreach ($candidate in $script:ExpectedRank.Keys) {
            $expected = if ($script:ExpectedRank[$candidate] -gt $script:ExpectedRank[$current]) { $candidate } else { $current }

            Assert-Equal $expected (Get-WacHigherOutcome -Current $current -Candidate $candidate) `
            ('the lattice disagreed for current={0} candidate={1}' -f $current, $candidate)
            Assert-Equal $expected (Invoke-DriverHigherOutcome -Current $current -Candidate $candidate) `
            ('driver lattice disagreed for current={0} candidate={1}' -f $current, $candidate)
        }
    }
}

Test-Case 'exactly one rank table exists, and it is the documented one' {
    # This case used to assert that the run copy and the driver copy AGREED, because there were two
    # byte-identical tables and nothing prevented them drifting. They were merged into
    # StepContract.psm1; the case is kept rather than deleted so the reason the merge was safe stays
    # on record, and it now asserts what replaced the agreement: one table, reachable from the load
    # paths that used to hold their own, carrying exactly the documented ranks.
    $table = Get-WacOutcomeRankTable

    Assert-Equal $script:ExpectedRank.Keys.Count @($table.Keys).Count 'the rank table has a different number of outcomes'
    foreach ($name in $script:ExpectedRank.Keys) {
        Assert-Equal $script:ExpectedRank[$name] $table[$name] ('rank for {0}' -f $name)
    }

    # A caller may not mutate the rule the exit code rests on.
    $table['Succeeded'] = 99
    Assert-Equal 0 (Get-WacOutcomeRankTable)['Succeeded'] 'the accessor handed out the live table rather than a copy'

    # And the merged function is reachable from the driver load path, not just from Steps.
    Assert-Equal 'SecurityRefusal' (Invoke-DriverHigherOutcome -Current 'Failed' -Candidate 'SecurityRefusal') `
        'the driver module cannot reach the merged lattice'
}

# ---------------------------------------------------------------------------------------------
# The exit-code and log-level maps
# ---------------------------------------------------------------------------------------------

Test-Case 'the exit-code map is exactly the documented five entries' {
    # Note the codes are NOT ordered the same way as the ranks: Incomplete ranks below Failed but
    # exits 6 against 2. That inversion is exactly what a table test catches and an end-to-end test,
    # which only ever sees whichever outcome won, does not.
    Assert-Equal $script:ExpectedExitCode.Keys.Count @($script:OutcomeExitCode.Keys).Count 'the exit-code map has a different number of entries'

    foreach ($name in $script:ExpectedExitCode.Keys) {
        Assert-Equal $script:ExpectedExitCode[$name] $script:OutcomeExitCode[$name] ('exit code for {0}' -f $name)
    }

    foreach ($name in @($script:OutcomeExitCode.Keys)) {
        Assert-True ($script:ExpectedRank.Contains($name)) ('the exit map carries an outcome the rank table does not know: ' + $name)
    }
}

Test-Case 'every non-clean outcome is logged at a level no -LogLevel can gate out' {
    # A footer hard-wired to INFO/WARNING once wrote 'status=SecurityRefusal exitCode=7' into a log
    # that -LogLevel ERROR then dropped, leaving the audit log of a refusing run empty. CRITICAL is
    # the highest level the parameter accepts, so it is the only one nothing can suppress.
    foreach ($name in $script:ExpectedLogLevel.Keys) {
        Assert-Equal $script:ExpectedLogLevel[$name] $script:OutcomeLogLevel[$name] ('log level for {0}' -f $name)
    }
}

# ---------------------------------------------------------------------------------------------
# Reading one step's outcome
# ---------------------------------------------------------------------------------------------

Test-Case 'a step that states no outcome fails closed rather than passing' {
    $stated = [PSCustomObject]@{ Outcome = 'Incomplete' }
    Assert-Equal 'Incomplete' (Get-WacStepOutcome -Step $stated)

    $silent = [PSCustomObject]@{ Succeeded = $true }
    Assert-Equal 'Failed' (Get-WacStepOutcome -Step $silent) 'a step with no Outcome property was not read as a failure'

    # -ccontains is case-SENSITIVE on purpose: a differently-cased property is not the contract, and
    # accepting it would let a typo decide an exit code. Do not "fix" this to -contains.
    $miscased = [PSCustomObject]@{ outcome = 'Succeeded' }
    Assert-Equal 'Failed' (Get-WacStepOutcome -Step $miscased) 'a lowercase outcome property was accepted as the contract'
}

Test-Case 'a tool that cannot be proven finished stops the next mutation, not just the verdict' {
    # WAC-05R. Raising the outcome to Incomplete told the FOOTER something was unfinished and
    # stopped nothing: an unsettled DISM could be followed straight away by pnpclean, by the driver
    # loop, or by cleanmgr's profile restore racing a write that may still be in flight.
    try {
        Reset-WacAbandonedMutator
        Assert-True (Test-WacMutationAllowed) 'the latch was already armed, so this case proves nothing'

        $unsettled = [PSCustomObject]@{
            ExitCode = 0; TimedOut = $false; Started = $true
            TerminationProven = $false; OutputComplete = $true
            Owned = $true; OwnedTreeState = 'Alive'
        }

        $result = Resolve-WacSettledOutcome -Outcome 'Succeeded' -Detail 'the tool exited 0.' -Run $unsettled

        Assert-Equal 'Incomplete' ([string]$result.Outcome) 'an unsettled tool was still reported as a success'
        Assert-False (Test-WacMutationAllowed) `
            'an unsettled tool raised the verdict but left the run free to start another mutation'
    }
    finally { Reset-WacAbandonedMutator }
}

Test-Case 'a settled tool leaves the run free to continue' {
    # The control. Without it "always quarantine" satisfies the case above and one ordinary DISM
    # would stop every later step of every run.
    try {
        Reset-WacAbandonedMutator

        $settled = [PSCustomObject]@{
            ExitCode = 0; TimedOut = $false; Started = $true
            TerminationProven = $true; OutputComplete = $true
            Owned = $true; OwnedTreeState = 'Complete'
        }

        $result = Resolve-WacSettledOutcome -Outcome 'Succeeded' -Detail 'the tool exited 0.' -Run $settled

        Assert-Equal 'Succeeded' ([string]$result.Outcome) 'a settled tool was downgraded'
        Assert-True (Test-WacMutationAllowed) 'a settled tool quarantined the run anyway'
    }
    finally { Reset-WacAbandonedMutator }
}

Test-Case 'a result that says nothing is not a settled one' {
    # A null contract, and a contract whose tree state is Unknown, were both read as settled - the
    # shared consumer only ever looked for the literal value 'Alive'.
    try {
        Reset-WacAbandonedMutator
        Assert-False ((Test-WacToolLifetimeSettled -Run $null).Settled) 'a missing result was treated as a finished tool'

        $unknown = [PSCustomObject]@{
            ExitCode = 0; TimedOut = $false; Started = $true
            TerminationProven = $true; OutputComplete = $true
            Owned = $true; OwnedTreeState = 'Unknown'
        }
        Assert-False ((Test-WacToolLifetimeSettled -Run $unknown).Settled) `
            'an owned launch whose tree could not be read was treated as a finished tool'

        # THE EXEMPTION THAT USED TO LIVE HERE IS GONE, and this case now asserts why (ledger
        # WAC-05R). An UNOWNED launch has no job to ask, so it called its pipe reaching EOF an
        # independent witness for a finished tree. It is not one: a pipe reaches EOF when every
        # WRITE HANDLE closes, and a descendant that closes or redirects its own standard handles
        # keeps running with the pipe already at EOF. EOF is a fact about handles.
        $unowned = [PSCustomObject]@{
            ExitCode = 0; TimedOut = $false; Started = $true
            TerminationProven = $true; OutputComplete = $true
            Owned = $false; OwnedTreeState = 'Unknown'
        }
        $verdict = Test-WacToolLifetimeSettled -Run $unowned
        Assert-False $verdict.Settled `
            'pipe EOF was accepted as proof of a finished tree, so a descendant that closed its handles reads as gone'

        # What it DOES establish, which is what keeps the repair from becoming fail-shut: the bytes
        # all arrived. A reader may believe its answer on that; nothing may delete on it.
        Assert-True $verdict.OutputTrustworthy `
            'a complete read was thrown away with the tree claim, which would refuse every managed fallback'

        # And the consequence, which is the half that matters: the same result quarantines a MUTATOR
        # and lets a READER report. Asserting the flag alone would not notice if nothing consulted it.
        Reset-WacAbandonedMutator
        [void](Resolve-WacSettledOutcome -Outcome 'Succeeded' -Detail 'read' -Run $unowned -Kind 'ReadOnly')
        Assert-True (Test-WacMutationAllowed) 'a tool that changed nothing stopped the run'

        Reset-WacAbandonedMutator
        $mutating = Resolve-WacSettledOutcome -Outcome 'Succeeded' -Detail 'wrote' -Run $unowned -Kind 'Mutating'
        Assert-Equal 'Incomplete' ([string]$mutating.Outcome) 'an unprovable mutator still reported success'
        Assert-False (Test-WacMutationAllowed) `
            'an unprovable mutator left the run free to start the next one on top of it'
    }
    finally { Reset-WacAbandonedMutator }
}

Complete-TestRun
