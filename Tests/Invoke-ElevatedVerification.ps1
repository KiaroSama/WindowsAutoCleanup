#Requires -Version 5.1

<#
.SYNOPSIS
    Elevated end-to-end verification of the three Run.ps1 exit codes no unit suite can reach -
    5 (the online system drive is not C:), 3 (another run holds the machine-wide lock) and
    2 (the run completed with at least one real deletion failure) - plus the two opt-in steps whose
    promises only a real, elevated, machine-changing run can test.

.DESCRIPTION
    This is NOT a Tests\*.Tests.ps1 suite and is deliberately named so Run-Tests.ps1 and the CI
    "every discovered suite ran" guard - both of which glob Tests\*.Tests.ps1 - never pick it up.
    It has to be started by hand, once, from an ELEVATED session, because all three exit codes sit
    behind Run.ps1's elevation gate.

    There are two classes of scenario and the summary keeps them apart.

    SANDBOXED - EXIT5, EXIT3, EXIT2. Each runs the REAL Run.ps1 as a bounded child process whose
    %ProgramData%, %LOCALAPPDATA%, %TEMP% and %TMP% are redirected into a disposable sandbox under
    %ProgramData%\WindowsAutoCleanup\Verification\Sandbox - NOT under %TEMP%, because an elevated
    child refuses a state directory that is not machine-trusted and a per-user temp directory is
    not one. The harness proves that root is trusted before it starts anything. So the
    run log, the machine state directory and every cleanup target derived from those roots land
    inside the sandbox instead of on the operator's machine. Every allow-list category except the
    single sandbox-confined one the scenario needs is disabled with -SkipCategory, the Recycle Bin
    with -SkipRecycleBin, and both destructive opt-ins are off.

    MACHINE-CHANGING - DRIVERS, CLEANMGR. These exist to test the two opt-in steps, so by definition
    they change the machine: DRIVERS exports and then deletes superseded oem<n>.inf driver packages,
    and CLEANMGR runs cleanmgr /sagerun, which enumerates EVERY drive in the computer. They run only
    when asked for by name or through -Scenario All; -Scenario Sandboxed runs the first three alone.
    They still redirect the same roots, still disable EVERY allow-list category, and still skip the
    Recycle Bin, so the only machine state either one may change is the state its own step owns.

    /ResetBase is excluded from EVERY scenario - it makes each installed update permanently
    un-installable. Every child is launched with -ResetWindowsUpdateBase:$false, and DRIVERS and
    CLEANMGR both assert from the child's own log that it really was off.

    WHAT THIS HARNESS STILL RUNS FOR REAL, and why it cannot be avoided: Steps' Get-WacSystemToolPath
    resolves dism.exe, rundll32.exe and cleanmgr.exe under %SystemRoot%, so the only way to make
    those steps report "not found" would be to redirect %SystemRoot%. That is not survivable:
    measured on this project's two hosts, Windows PowerShell 5.1 refuses to start at all with a
    redirected SystemRoot ("Internal Windows PowerShell error. Loading managed Windows PowerShell
    failed with error 8009001d") and PowerShell 7 starts but loses CIM. So the EXIT2 scenario, and
    the first run of the EXIT3 scenario, do perform the real DISM component-store cleanup (WITHOUT
    /ResetBase), the real pnpclean driver-package handler and the real Delivery Optimization cache
    purge. All three are supported, non-destructive maintenance operations, and the harness never
    kills them: the -BudgetMinutes budget handed to every child is DERIVED from -TimeoutSeconds so
    that it always expires first, which means a slow tool is terminated by Run.ps1's own production
    watchdog and never from outside. That ordering used to live in this comment only - any
    -TimeoutSeconds below the fixed 20-minute budget was accepted and silently inverted it.

.PARAMETER Scenario
    EXIT5, EXIT3, EXIT2, DRIVERS, CLEANMGR, Sandboxed (the three sandboxed exit-code scenarios only)
    or All (the default: all five).

.PARAMETER ResultPath
    Machine-readable JSON result file. Defaults to a timestamped file under
    %ProgramData%\WindowsAutoCleanup\Verification.

.PARAMETER TimeoutSeconds
    Wall-clock ceiling for one child process. The child's -BudgetMinutes budget is DERIVED from it
    as floor((TimeoutSeconds - 300) / 60) minutes, so "the child's own watchdog fires first" is a
    property of the arithmetic instead of a promise in a comment. The 300-second margin is what the
    child then has left to write its footer and close its log. A value too small to leave a whole
    minute of budget - anything under 360 - is REFUSED before any child starts rather than silently
    inverting the ordering, which is what the old fixed 20-minute budget did for anything under 1200.

.EXAMPLE
    .\Tests\Invoke-ElevatedVerification.ps1

.EXAMPLE
    .\Tests\Invoke-ElevatedVerification.ps1 -Scenario EXIT2

.NOTES
    Harness exit codes:
      0  every selected scenario passed
      1  at least one selected scenario failed
      2  the harness refused to run: not elevated, or a precondition was not met
#>

[CmdletBinding()]
param(
    [ValidateSet('EXIT5', 'EXIT3', 'EXIT2', 'DRIVERS', 'CLEANMGR', 'Sandboxed', 'All')][string]$Scenario = 'All',
    [string]$ResultPath,
    [ValidateRange(60, 7200)][int]$TimeoutSeconds = 1800
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# The budget handed to every child is DERIVED from the wall timeout rather than configured beside
# it. The harness's one safety promise is that a slow DISM is stopped by Run.ps1's own watchdog and
# never by an outside kill, and that promise holds only while the child's budget expires first.
# It used to be a fixed 20 minutes against a timeout accepted as low as 60 seconds, with nothing
# comparing the two, so any -TimeoutSeconds under 1200 inverted the ordering silently and the
# harness would have taskkilled a running DISM. Deriving the budget makes the ordering a property
# of the arithmetic; the 300-second margin is the child's own shutdown, footer and log flush. The
# comparison below enforces what the arithmetic alone cannot - a timeout too small to leave a whole
# minute of budget - and it refuses before any child is started.
$script:ChildBudgetMinutes = [int][Math]::Floor(($TimeoutSeconds - 300) / 60)
if ($script:ChildBudgetMinutes -lt 1 -or ($script:ChildBudgetMinutes * 60) -ge $TimeoutSeconds) {
    Write-Host ('REFUSED: -TimeoutSeconds {0} leaves a child budget of {1} minute(s), which cannot expire before the harness would kill the child. Pass at least 360.' -f `
        $TimeoutSeconds, $script:ChildBudgetMinutes)
    exit 2
}

# The sage profile Invoke-WacLegacyDiskCleanup defaults to, and the deadline for the harness's own
# pnputil snapshots. Both belong to the harness, not to the child: the child gets -BudgetMinutes.
$script:VerificationSageId = 9999
$script:PnpUtilProbeMs = 120000

foreach ($moduleName in @('Core', 'Targets')) {
    $modulePath = Join-Path -Path $script:SrcRoot -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $moduleName)
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        Write-Host ('REFUSED: a required module is missing: {0}' -f $modulePath)
        exit 2
    }
    Import-Module -Name $modulePath -Force -DisableNameChecking -ErrorAction Stop
}

# The scenarios and the infrastructure they share. Dot-sourced rather than imported: they run in
# THIS script's scope, where the parameters above and the state Main sets up are the same variables.
. (Join-Path -Path $PSScriptRoot -ChildPath '_ElevatedVerification.Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_ElevatedVerification.SandboxScenarios.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_ElevatedVerification.MachineScenarios.ps1')

# ------------------------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $script:RunPath -PathType Leaf)) {
    Write-Host ('REFUSED: Run.ps1 was not found at {0}.' -f $script:RunPath)
    exit 2
}

if (-not (Test-WacIsAdministrator)) {
    Write-Host 'REFUSED: Invoke-ElevatedVerification.ps1 must run in an ELEVATED PowerShell session.'
    Write-Host '         Run.ps1 exit codes 5, 3 and 2 all sit behind its elevation gate, so an'
    Write-Host '         unelevated run could only ever observe the relaunch path.'
    Write-Host '         Start an elevated host, then run:'
    Write-Host ('             {0} -NoProfile -File "{1}"' -f `
        (Split-Path -Leaf ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)), $PSCommandPath)
    exit 2
}

if (-not (Initialize-VerificationLock)) { exit 2 }

$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
# NOT %TEMP%, which is where this used to live. Each sandbox becomes the child's %ProgramData%,
# and an ELEVATED child verifies that its state directory is machine-trusted: measured on a stock
# Windows 11 install, a sandbox under a per-user temp directory answers untrusted at every level
# of the chain, so every scenario that reached the footer would exit 7 (security refusal) instead
# of the code it was checking. %ProgramData%\WindowsAutoCleanup is trusted, and it is also a safer
# home for the DRIVERS sandbox, which is KEPT when it holds the only recoverable copy of a deleted
# driver package - a temp cleaner is exactly what must not reach that.
$script:SandboxRoot = [System.IO.Path]::GetFullPath((Join-Path -Path (Get-WacDataRoot) -ChildPath 'Verification\Sandbox'))
try { [void][System.IO.Directory]::CreateDirectory($script:SandboxRoot) }
catch {
    Write-Host ('REFUSED: the sandbox root {0} could not be created: {1}' -f $script:SandboxRoot, $_.Exception.Message)
    exit 2
}

# Run.ps1 only ever builds targets on C:, so a sandbox anywhere else would produce no target at all
# and every scenario would pass for the wrong reason.
if (-not (Test-WacIsOnTargetDrive -Path $script:SandboxRoot)) {
    Write-Host ('REFUSED: the sandbox root {0} is not on {1}, so no sandbox path could ever become an allow-list target.' -f `
        $script:SandboxRoot, (Get-WacTargetDrive))
    exit 2
}

# Refuse loudly rather than let every scenario report a security refusal the harness itself caused.
# This is the same check the child makes on its own state directory, made here on the directory
# the child's %ProgramData% will live in.
$script:SandboxTrust = Test-WacStatePathIsTrusted -Path $script:SandboxRoot
if (-not $script:SandboxTrust.IsTrusted) {
    Write-Host ('REFUSED: the sandbox root {0} is not machine-trusted, so every child would exit 7 (security refusal) whatever else it did.' -f $script:SandboxRoot)
    Write-Host ('         {0}' -f $script:SandboxTrust.Reason)
    exit 2
}

if (-not $ResultPath) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd_HH-mm-ss')
    $ResultPath = Join-Path -Path (Get-WacDataRoot) -ChildPath ('Verification\ElevatedVerification_{0}_UTC.json' -f $stamp)
}

$script:SandboxedScenario = @('EXIT5', 'EXIT3', 'EXIT2')
$script:MachineScenario = @('DRIVERS', 'CLEANMGR')

$selected = @($Scenario)
if ($Scenario -eq 'Sandboxed') { $selected = @($script:SandboxedScenario) }
elseif ($Scenario -eq 'All') { $selected = @($script:SandboxedScenario + $script:MachineScenario) }

$machineSelected = @($selected | Where-Object { $script:MachineScenario -contains $_ })

Write-Host ''
Write-Host ('WindowsAutoCleanup elevated verification - host {0}, scenarios {1}' -f $script:HostExe, ($selected -join ', '))
Write-Host ('Sandbox root {0}; child budget {1} min (derived); wall timeout {2}s per child.' -f `
    $script:SandboxRoot, $script:ChildBudgetMinutes, $TimeoutSeconds)
Write-Host 'The EXIT2 scenario and the first EXIT3 run execute the real DISM component cleanup'
Write-Host '(without /ResetBase), pnpclean and the Delivery Optimization purge; see the .DESCRIPTION.'
if ($machineSelected.Count -gt 0) {
    Write-Host ''
    Write-Host ('*** {0} CHANGE THIS MACHINE and are not sandboxed:' -f ($machineSelected -join ' and '))
    Write-Host '***   DRIVERS  deletes superseded driver packages, each exported first; if any package is'
    Write-Host '***            removed its sandbox is KEPT, because it then holds the only recoverable copy.'
    Write-Host '***   CLEANMGR runs cleanmgr /sagerun, which enumerates EVERY drive in this computer.'
    Write-Host '*** /ResetBase is excluded from every scenario. Use -Scenario Sandboxed for the safe set.'
}
Write-Host ''

$records = New-Object 'System.Collections.Generic.List[object]'
$timeoutMs = $TimeoutSeconds * 1000

foreach ($name in $selected) {
    Write-Host ('--- {0} starting' -f $name)

    $record = $null
    switch ($name) {
        'EXIT5' { $record = Invoke-Exit5Scenario -TimeoutMs $timeoutMs }
        'EXIT3' { $record = Invoke-Exit3Scenario -TimeoutMs $timeoutMs }
        'EXIT2' { $record = Invoke-Exit2Scenario -TimeoutMs $timeoutMs }
        'DRIVERS' { $record = Invoke-DriversScenario -TimeoutMs $timeoutMs }
        'CLEANMGR' { $record = Invoke-CleanmgrScenario -TimeoutMs $timeoutMs }
        default { throw ('no scenario is wired up for {0}' -f $name) }
    }

    [void]$records.Add($record)
    Write-Host ('--- {0} {1} ({2} ms)' -f $name, $(if ($record.Passed) { 'PASS' } else { 'FAIL' }), $record.DurationMs)
    foreach ($line in $record.Evidence) { Write-Host ('      evidence: {0}' -f $line) }
    foreach ($line in $record.Problem) { Write-Host ('      PROBLEM : {0}' -f $line) }
    Write-Host ''
}

$failed = @($records | Where-Object { -not $_.Passed })

$report = [PSCustomObject]@{
    Tool        = 'WindowsAutoCleanup elevated verification'
    ScriptPath  = $script:RunPath
    HostPath    = $script:HostExe
    PSVersion   = [string]$PSVersionTable.PSVersion
    FinishedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    Scenarios   = @($records.ToArray())
    PassedCount = ($records.Count - $failed.Count)
    FailedCount = $failed.Count
    MachineCount = @($records | Where-Object { $_.Machine }).Count
    OverallPass = ($failed.Count -eq 0)
}

$written = $ResultPath
try {
    $directory = Split-Path -Parent $ResultPath
    if ($directory -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }
    # An explicit -Depth: the default of 2 silently truncates the nested Evidence arrays on 5.1.
    [System.IO.File]::WriteAllText($ResultPath, ($report | ConvertTo-Json -Depth 6), $script:Utf8NoBom)
}
catch {
    $written = ''
    Write-Host ('WARNING the result file could not be written: {0}' -f $_.Exception.Message)
}

Write-Host '=========================================================================================='
Write-Host ('{0,-9} {1,-8} {2,-7} {3,-7} {4,-7} {5,11}  {6}' -f `
    'SCENARIO', 'SCOPE', 'RESULT', 'EXPECT', 'ACTUAL', 'DURATION', 'PROBLEMS')
Write-Host '------------------------------------------------------------------------------------------'

# Sandboxed rows first, then a banner, then the rows that changed this machine. The separation is
# the point: a reader must never have to remember which scenario names touch the real machine.
$machineHeaderShown = $false
foreach ($record in $records) {
    if ($record.Machine -and -not $machineHeaderShown) {
        Write-Host '--- these ones CHANGED THIS MACHINE (authorised, not sandboxed) ---------------------------'
        $machineHeaderShown = $true
    }
    Write-Host ('{0,-9} {1,-8} {2,-7} {3,-7} {4,-7} {5,8} ms  {6}' -f `
        $record.Name,
        $(if ($record.Machine) { 'MACHINE' } else { 'sandbox' }),
        $(if ($record.Passed) { 'PASS' } else { 'FAIL' }),
        $record.ExpectedExitCode,
        $record.ActualExitCode,
        $record.DurationMs,
        @($record.Problem).Count)
}
Write-Host '=========================================================================================='
Write-Host ('{0} of {1} scenario(s) passed.' -f $report.PassedCount, $records.Count)
if ($written) { Write-Host ('Result file: {0}' -f $written) }

if ($failed.Count -gt 0) { exit 1 }
exit 0
