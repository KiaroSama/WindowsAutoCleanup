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
    Drivers.psm1 holds a second copy of the same rank table and is reached through its module scope,
    since it does not export the function.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_StepHarness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
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

            Assert-Equal $expected (Get-WacHigherRunOutcome -Current $current -Candidate $candidate) `
            ('run lattice disagreed for current={0} candidate={1}' -f $current, $candidate)
            Assert-Equal $expected (Invoke-DriverHigherOutcome -Current $current -Candidate $candidate) `
            ('driver lattice disagreed for current={0} candidate={1}' -f $current, $candidate)
        }
    }
}

Test-Case 'the run lattice and the driver lattice hold the same table' {
    # The two copies have not drifted. Nothing prevents it, and a drift would surface only as a run
    # whose driver step and whose footer disagree about which outcome wins.
    $driverRank = Get-ModuleVariableValue -Module $script:DriverModule -Name 'OutcomeRank'

    Assert-Equal $script:ExpectedRank.Keys.Count @($driverRank.Keys).Count 'the driver rank table has a different number of outcomes'
    Assert-Equal $script:ExpectedRank.Keys.Count @($script:OutcomeRank.Keys).Count 'the run rank table has a different number of outcomes'

    foreach ($name in $script:ExpectedRank.Keys) {
        Assert-Equal $script:ExpectedRank[$name] $script:OutcomeRank[$name] ('run rank for {0}' -f $name)
        Assert-Equal $script:ExpectedRank[$name] $driverRank[$name] ('driver rank for {0}' -f $name)
    }
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

Complete-TestRun
