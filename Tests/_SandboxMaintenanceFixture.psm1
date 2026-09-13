#Requires -Version 5.1
<#
.SYNOPSIS
    The elevated harness's MAINTENANCE interception fixture: every step that would service or purge
    the real machine is stopped at a test-only boundary, and the stop is recorded (ledger WAC-10R).

.DESCRIPTION
    WHY IT EXISTS. _SandboxTargetFixture.psm1 confines the FILE plan, and that is all it confines.
    The scratch copy still carried the real maintenance modules and the real %SystemRoot%, so the
    sandboxed scenarios executed the real online DISM component cleanup, the real pnpclean driver
    package handler and the real Delivery Optimization cache purge on the operator's machine while
    being reported as "sandbox" scope. Positive file containment cannot isolate those effects:
    none of them goes through an allow-list path.

    Redirecting %SystemRoot% is not survivable - measured, Windows PowerShell 5.1 refuses to start
    at all with one - so the tools are cut off ABOVE the filesystem instead, at three boundaries
    that are all test-only. No shipped file learns a switch, and no production safety check is
    weakened or bypassed: every refusal below lands the run on a path the shipped code already has
    for a machine where the tool is absent.

      1. MODULE. This file is copied over src\WindowsAutoCleanup.Drivers.psm1 in the scratch tree,
         with the shipped module preserved beside it as WindowsAutoCleanup.Drivers.Shipped.psm1 and
         imported here, so the real driver surface survives intact. Drivers is the LAST module
         Run.ps1 imports, so the six entry points redefined below win command resolution in the
         run's own scope - which is the only scope that calls them.

      2. PROCESS. Set-WacProcessInvoker is the shipped injection seam for exactly this ("lets tests
         exercise DISM, pnputil and cleanmgr behaviour without ever running them"). Every external
         tool in this project runs through Core's Invoke-WacProcess - dism, rundll32/pnpclean,
         pnputil and cleanmgr, and nothing else - so one invoker is a complete second barrier, and
         it covers any call site boundary 1 failed to name.

      3. RUNSPACE. Set-WacStepBoundedInvoker is the matching seam for the in-process work.
         Invoke-WacStepBounded otherwise runs its block as TEXT in a FRESH runspace with a fresh
         import of the module tree, where nothing shadowed in this process exists - which is how a
         Delivery Optimization stub that looked installed could still purge the real cache.

    NOTHING HERE IS SILENT. Each interception appends a line to <sandbox>\maintenance-witness.log
    and writes one to the child's own run log, so the harness can prove POSITIVELY that the run
    reached each maintenance step and that each one was stopped - rather than inferring it from an
    absence. Lines are one of two kinds:

        intercepted  boundary 1 - the run called a maintenance entry point and got a SafeSkip.
        tripwire     boundary 2 or 3 - something tried to reach a real tool anyway. A tripwire line
                     is a DEFECT in this fixture, and the harness fails the scenario on one.

    FAIL CLOSED. The witness path comes from WAC_VERIFY_SANDBOX_ROOT, pinned on first use, and an
    absent, unnormalisable or non-existent value throws instead of degrading to an unrecorded run:
    an interception nobody can prove is worth nothing.
#>

Set-StrictMode -Version 2.0

# The shipped module this file stands in front of. There is deliberately NO fallback to
# WindowsAutoCleanup.Drivers.psm1: in the scratch tree that name IS this file, so a fallback would
# import the fixture into itself. A scratch tree that failed to preserve the shipped module refuses
# to load rather than running with a driver surface that is quietly missing.
$script:ShippedDriversPath = Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Drivers.Shipped.psm1'
if (-not (Test-Path -LiteralPath $script:ShippedDriversPath -PathType Leaf)) {
    throw ('the shipped driver module was not preserved at {0}; refusing to stand in for it' -f $script:ShippedDriversPath)
}

# Core for the path and log primitives, Steps for the step-result vocabulary and the two invoker
# seams. Both are the real, unmodified modules from the scratch tree.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Steps.psm1') -DisableNameChecking -ErrorAction Stop
$script:ShippedDrivers = Import-Module -Name $script:ShippedDriversPath -DisableNameChecking -PassThru -ErrorAction Stop

# Test-only, and read by nothing in the shipped tree. The same variable the target fixture pins,
# because the two fixtures confine one sandbox and a second name could only ever disagree with it.
$script:SandboxRootVariable = 'WAC_VERIFY_SANDBOX_ROOT'
$script:WitnessLeaf = 'maintenance-witness.log'
$script:PinnedSandboxRoot = $null
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# The five entry points a sandboxed run reaches, in Run.ps1's own order. Clear-WacRecycleBin is the
# sixth and is NOT here: every sandboxed child is launched with -SkipRecycleBin, so Run.ps1 never
# calls it, and a witness line for it would mean that skip had stopped working.
$script:InterceptedStage = @(
    'DeliveryOptimizationCache', 'ComponentCleanup', 'PnpCleanHandler', 'DriverPackagePrune', 'LegacyDiskCleanup'
)

function Get-WacMaintenanceStage {
    <#
    .SYNOPSIS
        The stage names a sandboxed run must produce, so the harness and this file cannot drift.
    #>
    [OutputType([string[]])]
    param()

    return [string[]]@($script:InterceptedStage)
}

function Reset-WacMaintenanceFixture {
    <#
    .SYNOPSIS
        Drops the pinned sandbox root so the next call re-reads the environment. For suites only.
    #>
    param()

    $script:PinnedSandboxRoot = $null
}

function Get-WacMaintenanceWitnessPath {
    <#
    .SYNOPSIS
        The witness file inside the authorised sandbox, pinned for the life of the process.
    .DESCRIPTION
        It sits at the sandbox ROOT, beside PD\ and LA\, so no allow-list target can ever cover it:
        an interception record the sweep could delete would be no record at all.
    #>
    param()

    if (-not $script:PinnedSandboxRoot) {
        $raw = [System.Environment]::GetEnvironmentVariable($script:SandboxRootVariable)
        if ([string]::IsNullOrWhiteSpace($raw)) {
            throw ('{0} is not set, so no maintenance interception could be recorded; refusing to continue' -f $script:SandboxRootVariable)
        }

        $normalized = Get-WacNormalizedPath -Path $raw
        if (-not $normalized) {
            throw ('{0} does not normalise to a usable path ({1}); refusing to continue' -f $script:SandboxRootVariable, $raw)
        }
        if (-not (Test-Path -LiteralPath $normalized -PathType Container)) {
            throw ('the sandbox root {0} is not an existing directory; refusing to continue' -f $normalized)
        }

        $script:PinnedSandboxRoot = $normalized
    }

    return (Join-Path -Path $script:PinnedSandboxRoot -ChildPath $script:WitnessLeaf)
}

function Write-WacMaintenanceWitness {
    <#
    .SYNOPSIS
        Records one interception in the sandbox witness file AND in the child's own run log.
    .DESCRIPTION
        Two independent sinks on purpose. The witness file is what the harness parses; the run log
        is the child's own account of the same event, written by the shipped logger, so a witness
        file and a run log that disagree are visible rather than interchangeable.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('intercepted', 'tripwire')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Detail
    )

    $line = '{0} {1} stage={2} detail={3}' -f `
        ((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')), $Kind, $Stage, $Detail
    [System.IO.File]::AppendAllText((Get-WacMaintenanceWitnessPath), ($line + [System.Environment]::NewLine), $script:Utf8NoBom)

    # A tripwire is a hole in boundary 1, so it is logged loudly. An interception is the designed
    # path and is logged at INFO beside the step result the caller is about to receive.
    $level = $(if ($Kind -ceq 'tripwire') { 'CRITICAL' } else { 'INFO' })
    Write-WacLog -Level $level -Component 'SandboxMaintenance' -Message 'A machine maintenance operation was refused by the sandbox fixture.' -Data @{
        kind = $Kind; stage = $Stage; detail = $Detail
    }
}

function New-WacInterceptedStep {
    <#
    .SYNOPSIS
        Records the interception and returns the shipped SafeSkip result for that step.
    .DESCRIPTION
        SafeSkip, not Failed: it ranks with Succeeded, so a sandboxed run's exit code still comes
        from what the run really did to its own files. The detail names the fixture, so a reader of
        the child's log can never mistake it for the machine genuinely lacking the tool.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Component,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    Write-WacMaintenanceWitness -Kind 'intercepted' -Stage $Stage -Detail $Detail
    return (Write-WacStepResult -Component $Component -Result (New-WacStepResult -Category $Category `
        -Outcome 'SafeSkip' -Detail ('SANDBOX FIXTURE: {0}' -f $Detail)))
}

# ------------------------------------------------------------------------------------------------
# Boundary 1 - the six maintenance entry points Run.ps1 calls, each with the shipped signature
# ------------------------------------------------------------------------------------------------

function Invoke-WacComponentCleanup {
    [CmdletBinding()]
    param([switch]$ResetBase)

    # Recorded rather than honoured: /ResetBase is excluded from this harness outright, and a run
    # that somehow asked for it must still leave a trace of having asked.
    return (New-WacInterceptedStep -Component 'Dism' -Category 'Windows component store cleanup (DISM)' `
        -Stage 'ComponentCleanup' -Detail ('dism.exe /Online /Cleanup-Image was not run (resetBase={0})' -f [bool]$ResetBase))
}

function Clear-WacDeliveryOptimizationCache {
    [CmdletBinding()]
    param()

    return (New-WacInterceptedStep -Component 'DeliveryOptimization' -Category 'Delivery Optimization cache' `
        -Stage 'DeliveryOptimizationCache' -Detail 'Delete-DeliveryOptimizationCache was not run')
}

function Invoke-WacPnpCleanHandler {
    [CmdletBinding()]
    param([switch]$MeasureDriverStore)

    $null = $MeasureDriverStore
    return (New-WacInterceptedStep -Component 'PnpClean' -Category 'Device driver packages (pnpclean)' `
        -Stage 'PnpCleanHandler' -Detail 'rundll32.exe pnpclean.dll,RunDLL_PnpClean was not run')
}

function Invoke-WacDriverPackagePrune {
    [CmdletBinding()]
    param(
        [switch]$Enabled,
        [string]$BackupRoot,
        [string]$LegacyBackupRoot = ''
    )

    $null = $BackupRoot
    $null = $LegacyBackupRoot
    return (New-WacInterceptedStep -Component 'DriverPrune' -Category 'Superseded driver packages (pnputil)' `
        -Stage 'DriverPackagePrune' -Detail ('pnputil /delete-driver was not run (enabled={0})' -f [bool]$Enabled))
}

function Invoke-WacLegacyDiskCleanup {
    [CmdletBinding()]
    param(
        [switch]$Enabled,
        [ValidateRange(0, 9999)][int]$SageId = 9999,
        [AllowEmptyCollection()][string[]]$Category = @()
    )

    $null = $SageId
    $null = $Category
    return (New-WacInterceptedStep -Component 'DiskCleanup' -Category 'Disk Cleanup handlers (cleanmgr)' `
        -Stage 'LegacyDiskCleanup' -Detail ('cleanmgr /sagerun was not run (enabled={0})' -f [bool]$Enabled))
}

function Clear-WacRecycleBin {
    [CmdletBinding()]
    param([string]$Root = '')

    $null = $Root
    return (New-WacInterceptedStep -Component 'RecycleBin' -Category 'Recycle Bin (drive C: only)' `
        -Stage 'RecycleBin' -Detail 'the global Recycle Bin was not emptied')
}

# ------------------------------------------------------------------------------------------------
# Boundaries 2 and 3 - installed at import, so they are armed before the run's first step
# ------------------------------------------------------------------------------------------------

# A scriptblock keeps the session state it was DEFINED in, so both of these resolve
# Write-WacMaintenanceWitness in this module however far from here they are invoked. That is what
# lets the seams be armed from a module at all, and it is measured on both shipped hosts.
Set-WacProcessInvoker -Invoker {
    param($FilePath, $ArgumentList, $TimeoutMs)

    $null = $TimeoutMs
    Write-WacMaintenanceWitness -Kind 'tripwire' -Stage 'Invoke-WacProcess' `
        -Detail ('{0} {1}' -f $FilePath, (@($ArgumentList) -join ' '))

    # Started=$false with no exit code is what the shipped callers read as "the tool did not start",
    # and every one of them reports that as Failed or Incomplete. A hole in boundary 1 therefore
    # fails the scenario instead of passing quietly.
    return [PSCustomObject]@{
        ExitCode = $null; TimedOut = $false; StandardOutput = ''
        StandardError = 'refused by the sandbox maintenance fixture'
        DurationMs = 0; Started = $false; TerminationProven = $true; OutputComplete = $true
        Owned = $false; OwnedTreeState = 'Complete'
    }
}

Set-WacStepBoundedInvoker -Invoker {
    param($ScriptBlock, $TimeoutMs, $ArgumentList, $Component, $IgnoreRunBudget)

    $null = $ScriptBlock
    $null = $TimeoutMs
    $null = $ArgumentList
    $null = $IgnoreRunBudget
    Write-WacMaintenanceWitness -Kind 'tripwire' -Stage 'Invoke-WacStepBounded' -Detail ([string]$Component)

    return [PSCustomObject]@{
        Outcome = 'Failed'; Started = $false; TimedOut = $false; Output = @(); HadErrors = $true
        Error = 'refused by the sandbox maintenance fixture'; DurationMs = 0
    }
}

# The shipped driver surface, plus the interceptions. Read from the imported module rather than
# listed by hand, so a driver function added tomorrow still reaches the child.
Export-ModuleMember -Function (@(
    @($script:ShippedDrivers.ExportedFunctions.Keys) + @(
        'Get-WacMaintenanceStage', 'Reset-WacMaintenanceFixture',
        'Get-WacMaintenanceWitnessPath', 'Write-WacMaintenanceWitness',
        'Invoke-WacComponentCleanup', 'Clear-WacDeliveryOptimizationCache', 'Invoke-WacPnpCleanHandler',
        'Invoke-WacDriverPackagePrune', 'Invoke-WacLegacyDiskCleanup', 'Clear-WacRecycleBin'
    )
) | Select-Object -Unique)
