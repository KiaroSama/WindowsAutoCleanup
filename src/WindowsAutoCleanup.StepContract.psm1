<#
.SYNOPSIS
    The vocabulary every cleanup step of this package shares.

.DESCRIPTION
    Three things live here because every step in the package needs all three and none of them
    belongs to one tool:

        the result shape a step returns, and the log line that records it
        the absolute System32 resolver every step uses instead of PATH
        the bounded seam the blocking IN-PROCESS work runs through

    Nothing in this file knows what any individual tool does. It is imported by the step modules
    and re-exported by WindowsAutoCleanup.Steps.psm1, which is the package's single entry point.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the CALLER's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop

# The ENTRY POINT of the package, not this file: Invoke-WacBounded runs its block as TEXT in a fresh
# runspace, and a block handed to this seam may call any step function the package exports, so the
# runspace has to import the module that exports all of them. Resolved at import, because
# Invoke-WacBounded needs a real path.
$script:StepsModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Steps.psm1'

$script:BoundedInvoker = $null

function New-WacStepResult {
    <#
    .SYNOPSIS
        The single result shape every step returns.
    .DESCRIPTION
        -Outcome is the contract. Succeeded, Skipped and Failed are DERIVED from it, so a caller
        that reads only the booleans keeps working and can never see a combination the outcome
        cannot express.

        A caller that passes the booleans instead gets its own values back untouched, plus the
        Outcome those booleans describe. That path exists only so older callers keep working; new
        code passes -Outcome.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Outcome,
        [bool]$Attempted = $false,
        [bool]$Succeeded = $false,
        [bool]$RebootRequired = $false,
        [string]$Detail = '',
        [int]$DurationMs = 0,
        [bool]$Skipped = $false,
        [bool]$Failed = $false
    )

    if ($PSBoundParameters.ContainsKey('Outcome')) {
        $Succeeded = ($Outcome -ceq 'Succeeded')
        $Skipped   = ($Outcome -ceq 'SafeSkip')
        $Failed    = ($Outcome -ceq 'Failed' -or $Outcome -ceq 'Incomplete' -or $Outcome -ceq 'SecurityRefusal')
    }
    elseif ($Failed) { $Outcome = 'Failed' }
    elseif ($Skipped) { $Outcome = 'SafeSkip' }
    elseif ($Succeeded) { $Outcome = 'Succeeded' }
    else { $Outcome = 'SafeSkip' }

    return [PSCustomObject]@{
        Category       = $Category
        Outcome        = $Outcome
        Attempted      = $Attempted
        Succeeded      = $Succeeded
        RebootRequired = $RebootRequired
        Detail         = $Detail
        DurationMs     = $DurationMs
        Skipped        = $Skipped
        Failed         = $Failed
    }
}

function Write-WacStepResult {
    <#
    .SYNOPSIS
        Logs one step result at the severity its OUTCOME deserves.
    .DESCRIPTION
        The level is read off the outcome rather than off the derived Failed flag, because Failed is
        also $true for Incomplete and for SecurityRefusal - and because a result built by a caller
        that sets the booleans directly can carry an outcome its Failed flag does not agree with.

        SecurityRefusal is CRITICAL rather than ERROR for one reason: CRITICAL is the highest level
        -LogLevel accepts, so it is the only level no operator setting can gate out. A step that
        makes the run exit 7 must not be missing from the audit log of that run.
    #>
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][string]$Component
    )

    $outcome = ''
    if (@($Result.PSObject.Properties.Name) -ccontains 'Outcome') { $outcome = [string]$Result.Outcome }

    $level = 'INFO'
    if ($outcome -ceq 'SecurityRefusal') { $level = 'CRITICAL' }
    elseif ($outcome -ceq 'Failed' -or $outcome -ceq 'Incomplete') { $level = 'WARNING' }
    elseif ($outcome -eq '' -and $Result.Failed) { $level = 'WARNING' }

    Write-WacLog -Level $level -Component $Component -Message 'Step complete.' -Data @{
        category   = $Result.Category
        outcome    = $outcome
        attempted  = $Result.Attempted
        succeeded  = $Result.Succeeded
        skipped    = $Result.Skipped
        failed     = $Result.Failed
        reboot     = $Result.RebootRequired
        durationMs = $Result.DurationMs
        detail     = $Result.Detail
    }

    return $Result
}

function Get-WacSystemToolPath {
    <#
    .SYNOPSIS
        Resolves a System32 tool by absolute path, or $null when it is absent.
    .DESCRIPTION
        Never Get-Command: PATH is extensible by a standard user, and this code runs as SYSTEM.
    #>
    param([Parameter(Mandatory = $true)][string]$Leaf)

    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) { return $null }

    $candidate = Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath $Leaf
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    return $null
}

# ---------------------------------------------------------------------------------------------
# Bounding the in-process work
# ---------------------------------------------------------------------------------------------

function Set-WacStepBoundedInvoker {
    <#
    .SYNOPSIS
        Replaces the bounded in-process runner. Pass $null to restore the real one.
    .DESCRIPTION
        The invoker receives (ScriptBlock, TimeoutMs, ArgumentList, Component, IgnoreRunBudget, Label) and
        must return Invoke-WacBounded's shape: Outcome, Started, TimedOut, Output, HadErrors, Error,
        DurationMs.

        It exists because Invoke-WacBounded runs its block as TEXT in a fresh runspace with a fresh
        import of this module, so a stub installed in the caller's module instance is invisible in
        there - and a Delivery Optimization test whose stub is invisible purges the real cache.
        A block invoked through this seam keeps this module's session state, so a suite's function
        shadows do apply to it. Measured on both shipped hosts.
    #>
    param([scriptblock]$Invoker)
    $script:BoundedInvoker = $Invoker
}

function Invoke-WacStepBounded {
    <#
    .SYNOPSIS
        Runs one blocking in-process call under a wall-clock bound.
    .DESCRIPTION
        Keep the block down to the single blocking call and return DATA: in production it runs in
        its own runspace WITHOUT strict mode, and Write-WacLog inside it goes nowhere.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [AllowEmptyCollection()][object[]]$ArgumentList = @(),
        [string]$Component = 'Steps',
        [switch]$IgnoreRunBudget,
        [switch]$Mutating,
        [ValidateSet('InProcess', 'External')][string]$MutationKind = 'External',
        # A STABLE name for this particular bounded call. It never reaches a log line - Component
        # still does that - and exists so a fixture can select one call by what it IS rather than by
        # its position. Selecting by ordinal coupled five suites to the ORDER of bounded calls, which
        # is why a phase could not be added to a step without renumbering unrelated tests.
        [string]$Label = ''
    )

    if ($script:BoundedInvoker) {
        return (& $script:BoundedInvoker $ScriptBlock $TimeoutMs $ArgumentList $Component ([bool]$IgnoreRunBudget) $Label)
    }

    return (Invoke-WacBounded -ScriptBlock $ScriptBlock -TimeoutMs $TimeoutMs -ArgumentList $ArgumentList `
        -ImportModule @($script:StepsModulePath) -Component $Component -IgnoreRunBudget:$IgnoreRunBudget -Mutating:$Mutating -MutationKind $MutationKind)
}

# ------------------------------------------------------------------------------------------------
# Outcome precedence - ONE copy
# ------------------------------------------------------------------------------------------------
#
# This rule decides the process exit code, and it used to exist THREE times: a table plus a function
# in RunReport.ps1, a byte-identical pair in Drivers.psm1, and a raw table index in Run.ps1 with no
# function boundary at all. Adding a sixth outcome meant three synchronised edits with nothing to
# catch a missed one, and a miss would surface only as a run whose driver step and whose footer
# disagree about which outcome wins.
#
# It lives here because this file is already the shared result vocabulary, and because it is the one
# place BOTH load paths reach: Run.ps1 imports Steps.psm1 (which dot-sources this) and dot-sources
# RunReport.ps1 into its own scope, while Drivers.psm1 imports Steps.psm1 too. RunReport.ps1 cannot
# become a module - it deliberately runs in Run.ps1's script scope - so the shared home had to be
# somewhere both could import from.

$script:OutcomeRank = @{ 'Succeeded' = 0; 'SafeSkip' = 0; 'Incomplete' = 1; 'Failed' = 2; 'SecurityRefusal' = 3 }

function Get-WacHigherOutcome {
    <#
    .SYNOPSIS
        The higher-precedence of two outcomes. Pure.
    .DESCRIPTION
        Equal ranks keep $Current, so SafeSkip after Succeeded stays Succeeded - both map to exit 0,
        so either answer is right at the exit code and only one is right here.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Current,
        [Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Candidate
    )

    if ($script:OutcomeRank[$Candidate] -gt $script:OutcomeRank[$Current]) { return $Candidate }
    return $Current
}

function Test-WacOutcomeIsClean {
    <#
    .SYNOPSIS
        True when an outcome carries no bad news. Replaces a raw rank index in Run.ps1.
    #>
    param([Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Outcome)

    return ($script:OutcomeRank[$Outcome] -eq 0)
}

function Get-WacOutcomeRankTable {
    <#
    .SYNOPSIS
        A COPY of the rank table, for tests that assert the contract. Callers get a clone so nothing
        outside this file can mutate the rule the exit code rests on.
    #>
    return @{} + $script:OutcomeRank
}

# The facts a runner must state for anything to be concluded about a tool's lifetime. They are
# REQUIRED, not optional: see Test-WacToolLifetimeSettled for why a missing one is now unknown
# rather than harmless.
$script:LifetimeFact = @('Started', 'TerminationProven', 'OutputComplete', 'OwnedTreeState')

function Get-WacRunTreeState {
    <#
    .SYNOPSIS
        A run's tree state, or 'Unknown' when it does not state one. Defensive on purpose: this is
        the one place that reads the field WITHOUT the positive contract's judgement, because its
        caller is deciding how much a missing answer costs rather than whether it is acceptable.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()]$Run)

    if ($null -eq $Run) { return 'Unknown' }
    $names = @()
    try { $names = @($Run.PSObject.Properties.Name) } catch { $names = @() }
    if ($names -cnotcontains 'OwnedTreeState') { return 'Unknown' }
    return [string]$Run.OwnedTreeState
}

function Test-WacToolLifetimeSettled {
    <#
    .SYNOPSIS
        What an external tool's result actually establishes: whether its WHOLE tree finished, and
        separately whether its output can be believed.
    .DESCRIPTION
        A root's exit code is what the tool BELIEVES about itself. It says nothing about a child the
        tool started, and nothing about output that never arrived. This is the one place that
        question is answered, so the steps cannot drift apart on it.

        THE CONTRACT IS POSITIVE NOW, and that is the repair (ledger WAC-05R). It used to read
        defensively: a property the result did not carry could not contradict anything, so the veto
        fired only on evidence and a result that stated nothing at all was settled. That is the same
        mistake as reading a failed probe as proven absence - it makes silence the strongest possible
        answer. Every fact below must be PRESENT and must say yes; a missing one is unknown, and
        unknown is not settled.

        THE UNOWNED EXEMPTION IS GONE, and it was the sharpest instance of the same thing. An unowned
        runner concluded a complete tree from pipe EOF. A pipe reaches EOF when every WRITE HANDLE on
        it is closed, which is a fact about handles, not about processes: a descendant that closes or
        redirects its own standard handles goes on running with the pipe already at EOF. So EOF
        establishes output closure and nothing more, and only a job object can answer for the tree.

        TWO ANSWERS, because they authorise different things and conflating them is what let a
        half-read enumeration license a deletion:

          Settled           - the whole lifetime is established. Only this may authorise a later
                              mutation, because only this says nothing of ours is still running.
          OutputTrustworthy - the bytes in hand are the tool's whole output. A read-only caller may
                              believe its ANSWER on this, and must not conclude anything else from it.
    .OUTPUTS
        Settled, OutputTrustworthy, Reason (empty when settled).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowNull()]$Run)

    $result = [PSCustomObject]@{ Settled = $false; OutputTrustworthy = $false; Reason = '' }

    # A NULL result is not a settled one. Nothing ran that could be asked, and "we have no answer"
    # was being read as "the answer was yes".
    if ($null -eq $Run) {
        $result.Reason = 'no run result was produced at all, so nothing about the tool could be established'
        return $result
    }

    $names = @()
    try { $names = @($Run.PSObject.Properties.Name) } catch { $names = @() }

    $missing = @($script:LifetimeFact | Where-Object { $names -cnotcontains $_ })
    if ($missing.Count -gt 0) {
        $result.Reason = ('the run result does not state {0}, so its lifetime is unknown' -f (@($missing) -join ', '))
        return $result
    }

    # NEVER STARTED is the one settled state that needs no tree: nothing was created, so nothing of
    # ours can be alive. It is still not taken on trust - the result has to agree that the tree is
    # complete, which is exactly what a suspended process nobody could confirm terminating does NOT
    # say.
    if (-not [bool]$Run.Started) {
        if (([string]$Run.OwnedTreeState) -ceq 'Complete' -and
            [bool]$Run.TerminationProven -and [bool]$Run.OutputComplete) {
            $result.Settled = $true
            $result.OutputTrustworthy = $true
            return $result
        }
        $result.Reason = 'the tool never ran and what was created could not be proven gone'
        return $result
    }

    $reasons = New-Object 'System.Collections.Generic.List[string]'

    if (-not [bool]$Run.TerminationProven) { [void]$reasons.Add('the tool could not be proven stopped') }
    if (-not [bool]$Run.OutputComplete) { [void]$reasons.Add('the tool output is incomplete') }

    # Output is trustworthy on strictly less evidence than the tree is: the bytes are all there once
    # every writer has closed and the root is known stopped. That is deliberately weaker, and the
    # caller that acts on it is told so by the name.
    $result.OutputTrustworthy = ($reasons.Count -eq 0)

    switch ([string]$Run.OwnedTreeState) {
        'Complete' { }
        'Alive'    { [void]$reasons.Add('work this run started is still alive') }
        default    { [void]$reasons.Add('whether work this run started is still alive could not be established') }
    }

    if ($reasons.Count -gt 0) {
        $result.Reason = (@($reasons.ToArray()) -join '; ')
        return $result
    }

    $result.Settled = $true
    return $result
}

function Invoke-WacGuardedStep {
    <#
    .SYNOPSIS
        Runs one maintenance step, or refuses to start it while the run is quarantined.
    .DESCRIPTION
        The quarantine latch was enforced where mutations HAPPEN - the driver candidate loop,
        cleanmgr's profile write, Remove-WacTree, every -Mutating bounded block - and nowhere in the
        sequence that decides whether a step runs at all. So a run with an abandoned mutator still
        LAUNCHED dism.exe and pnpclean.dll: both are external mutators, both were started
        unconditionally, and both were relied on to refuse somewhere deeper down, which neither
        does. Pushing the guard down into each tool would be the same mistake once per tool.

        One gate, in front of the step. A step that never starts is Incomplete, not SafeSkip: the
        work the run was asked to do was not done, the footer must say so, and the exit code must
        carry it. SecurityRefusal would be wrong in the other direction - nothing here refused for a
        trust reason, and exit 7 means something specific on this project.

        The step is passed as a block rather than a name so the guard sits between the orchestrator
        and the call, where the decision is, instead of inside each step where five copies of it
        would drift.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][scriptblock]$Step,
        [string]$Component = 'Run'
    )

    if (Test-WacMutationAllowed) { return (& $Step) }

    return (Write-WacStepResult -Component $Component -Result (New-WacStepResult -Category $Category `
        -Outcome 'Incomplete' -Attempted $false `
        -Detail 'The step was not started: an earlier mutation was abandoned and cannot be proven finished, so nothing further on this machine may be changed by this run.'))
}

function Resolve-WacSettledOutcome {
    <#
    .SYNOPSIS
        Raises a step outcome to Incomplete when the tool's lifetime is not settled, explains it, AND
        stops the run from scheduling another mutation.
    .DESCRIPTION
        Combined through Get-WacHigherOutcome, never assigned: an unsettled lifetime can only make a
        verdict worse. A recorded Failed stays Failed.

        IT ARMS THE QUARANTINE, and that is the whole point of the rename (ledger WAC-05R). Raising
        the outcome only told the FOOTER something was unfinished - it did not stop anything, so an
        unsettled DISM could be followed straight away by pnpclean, by the driver loop, or by
        cleanmgr's profile restore racing a write that may still be in flight. "This tool cannot be
        proven finished" and "nothing else may start" are the same fact, and one of them was being
        reported while the other was not acted on.

        A function named Get- that changes the run's state would be the wrong shape, so it is not
        one: every caller was updated with the rename rather than left pointing at an older answer.
    .OUTPUTS
        Outcome and Detail.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Outcome,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Detail,
        [Parameter(Mandatory = $true)][AllowNull()]$Run,
        # WHAT THE TOOL WAS ASKED TO DO, and the default is the dangerous answer on purpose: a caller
        # that does not say gets the mutating rule. Only a tool that cannot change the machine may
        # declare itself ReadOnly, and doing so buys exactly one thing - an unprovable TREE does not
        # arm the latch, because nothing was changed for a survivor to be racing. It never buys a
        # completion claim: an unsettled read is still Incomplete, and its ANSWER is usable only when
        # OutputTrustworthy says the bytes all arrived.
        [ValidateSet('Mutating', 'ReadOnly')][string]$Kind = 'Mutating'
    )

    $settled = Test-WacToolLifetimeSettled -Run $Run
    if ($settled.Settled) {
        return [PSCustomObject]@{ Outcome = $Outcome; Detail = $Detail; OutputTrustworthy = $true }
    }

    # A read-only tool whose bytes all arrived is allowed to report its own answer without dragging
    # the run down, because it mutated nothing: the only thing left unproven is a descendant, and a
    # descendant of a reader cannot be mid-write on anything this run owns. The outcome is still not
    # raised to Incomplete for that case alone - but the flag travels, and a consumer that wants to
    # DELETE something on the strength of this read has to look at Settled, not at this.
    if ([string]$Kind -ceq 'ReadOnly' -and $settled.OutputTrustworthy -and
        ([string](Get-WacRunTreeState -Run $Run)) -cne 'Alive') {
        return [PSCustomObject]@{ Outcome = $Outcome; Detail = $Detail; OutputTrustworthy = $true }
    }

    # THE STOP, for a mutator. Whatever this tool left behind may still be writing, so nothing else
    # this run would do may start on top of it. Add-WacAbandonedMutator is the same latch an
    # abandoned in-process mutator raises, and it is fail-closed for the same reason: nothing here
    # can observe the unsettled work finishing.
    if ([string]$Kind -ceq 'Mutating') {
        [void](Add-WacAbandonedMutator -Reason ('an external tool could not be proven finished: {0}' -f $settled.Reason))
    }

    return [PSCustomObject]@{
        Outcome = (Get-WacHigherOutcome -Current $Outcome -Candidate 'Incomplete')
        Detail = ('{0} The step cannot be reported finished: {1}. No further change will be made by this run.' -f $Detail, $settled.Reason).Trim()
        OutputTrustworthy = [bool]$settled.OutputTrustworthy
    }
}

Export-ModuleMember -Function @(
    'Test-WacToolLifetimeSettled', 'Resolve-WacSettledOutcome', 'Get-WacRunTreeState',
    'New-WacStepResult', 'Write-WacStepResult', 'Get-WacSystemToolPath',
    'Set-WacStepBoundedInvoker', 'Invoke-WacStepBounded', 'Invoke-WacGuardedStep',
    'Get-WacHigherOutcome', 'Test-WacOutcomeIsClean', 'Get-WacOutcomeRankTable'
)
