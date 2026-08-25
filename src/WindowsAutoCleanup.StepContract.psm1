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
        The invoker receives (ScriptBlock, TimeoutMs, ArgumentList, Component, IgnoreRunBudget) and
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
        [switch]$IgnoreRunBudget
    )

    if ($script:BoundedInvoker) {
        return (& $script:BoundedInvoker $ScriptBlock $TimeoutMs $ArgumentList $Component ([bool]$IgnoreRunBudget))
    }

    return (Invoke-WacBounded -ScriptBlock $ScriptBlock -TimeoutMs $TimeoutMs -ArgumentList $ArgumentList `
        -ImportModule @($script:StepsModulePath) -Component $Component -IgnoreRunBudget:$IgnoreRunBudget)
}

Export-ModuleMember -Function @(
    'New-WacStepResult', 'Write-WacStepResult', 'Get-WacSystemToolPath',
    'Set-WacStepBoundedInvoker', 'Invoke-WacStepBounded'
)
