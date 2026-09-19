#Requires -Version 5.1

<#
.SYNOPSIS
    Removes the WindowsAutoCleanup scheduled task and the %ProgramFiles% deployment.

.DESCRIPTION
    The task is unregistered only after it proves it belongs to this project: v1.1.0 deleted any
    task named WindowsAutoCleanup by name alone. The pre-1.2 task at the root task path is adopted
    when its description and action still match what the old installer wrote.

    Only %ProgramFiles%\WindowsAutoCleanup and its swap slots are deleted. This checkout is never
    touched, and neither is anything outside those three paths.

    Actions are written to %ProgramData%\WindowsAutoCleanup\Logs and printed to the console.

.PARAMETER NoPause
    Do not wait for a key press before exiting. For automation and tests.

.PARAMETER RemoveLogs
    Also delete the log files under %ProgramData%\WindowsAutoCleanup\Logs. Logs are kept by
    default. The log this run is writing survives so the uninstall stays auditable.

.PARAMETER KeepLogs
    Keep the log files even when -RemoveLogs is also passed. Use it to make the safe choice
    explicit in a script whose flags come from somewhere else.

.EXAMPLE
    .\Uninstall-WindowsAutoCleanupTask.ps1 -NoPause -RemoveLogs

.NOTES
    Exit codes:
      0  success
      1  error, or a removal that could not be verified
      3  another WindowsAutoCleanup operation - a cleanup run, an install or an uninstall - already
         holds the machine-wide lock
      4  elevation was cancelled or failed
      5  unsupported environment (the deployment root cannot be resolved)
      6  refused before any change, or everything of ours was removed, but either way this run's
         audit log is not durable
      7  refused: the machine state directory could not be proven machine-trusted, or something at
         the task path or the deployment path could not be proven ours. Nothing was changed
      8  the elevated uninstaller outran its budget and could NOT be proven terminated. It may still
         be running as administrator, still holding the machine-wide lock and still changing this
         machine. Do not re-run the uninstaller until that process has exited
#>

# Write-Host is deliberate: the uninstaller is a user-facing console tool and the structured
# record goes to the file log separately.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output is the point of an interactive installer; the file log is written through Write-WacLog.')]
[CmdletBinding()]
param(
    [switch]$NoPause,

    [switch]$RemoveLogs,

    [switch]$KeepLogs
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Same reason as the installer (ledger P0-2): inside a function $PSBoundParameters is that
# function's own, so the script's must be captured here, before anything else runs.
$script:BoundParameter = @{}
foreach ($key in $PSBoundParameters.Keys) { $script:BoundParameter[$key] = $PSBoundParameters[$key] }

$script:ScriptRoot = Split-Path -Parent $PSCommandPath
$script:LogReady = $false
$script:InstanceLock = $null
$script:Relaunched = $false

# Nothing is written to the run LOG until Open-UninstallerLogGate has established that this run is
# allowed to write there; see that function. The record itself is built at the bottom of the file.
$script:LogGateOpen = $false
$script:InvocationRecord = @{}

# The elevated child's own budget, and the parent bound derived FROM it. The parent used to wait 10
# minutes for a child whose own deadline was 30, and on expiry it returned while that still-mutating
# elevated child carried on unregistering and deleting with nobody watching. A wrapper's deadline
# has to outlast everything the child it started can legitimately do.
#
# The child READS this budget too, at every phase boundary; see Test-RunBudget. A deadline no
# operation observes is a number, not a bound, and the parent was outlasting exactly that.
$script:RunBudgetMinutes = 30
$script:ChildShutdownMarginMinutes = 10
$script:ElevationTimeoutMs = ($script:RunBudgetMinutes + $script:ChildShutdownMarginMinutes) * 60000

Import-Module -Name (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') -DisableNameChecking -Force -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') -DisableNameChecking -Force -ErrorAction Stop

# Dot-sourced, not imported: the pre-flight gate has to be one body shared by both entry points, and
# a module can only hand a script what it EXPORTS.
. (Join-Path -Path $script:ScriptRoot -ChildPath 'src\WindowsAutoCleanup.EntryGate.ps1')

function Write-UninstallerMessage {
    <#
    .SYNOPSIS
        One line to the console and, unless -NoLog, one structured record to the run log.
    .DESCRIPTION
        -NoLog exists for the refusal raised when the directory this run's audit log lives in is not
        machine-trusted: explaining that refusal through the very path it just refused would be a
        write into a location a standard user can replace. -NoConsole is its mirror image, for the
        one record that is printed before the gate and logged after it.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data,
        [switch]$NoLog,
        [switch]$NoConsole
    )

    # $script:LogGateOpen as well as $script:LogReady: a run that has not yet proven it may write
    # into its own log directory does not get to write into it, whatever it has to say.
    if ($script:LogReady -and $script:LogGateOpen -and -not $NoLog) {
        if ($Data) { Write-WacLog -Level $Level -Component 'Uninstaller' -Message $Message -Data $Data }
        else { Write-WacLog -Level $Level -Component 'Uninstaller' -Message $Message }
    }

    if ($NoConsole) { return }

    $colour = switch ($Level) {
        'WARNING' { 'Yellow' }
        'ERROR' { 'Red' }
        'CRITICAL' { 'Red' }
        default { 'Gray' }
    }
    Write-Host ('[{0}] {1}' -f $Level, $Message) -ForegroundColor $colour
}

function Open-UninstallerLogGate {
    <#
    .SYNOPSIS
        Lets this run write to its own log file, and puts the invocation record in it. Idempotent.
    .DESCRIPTION
        The invocation record used to be written to the run log BEFORE Get-OperationSafetyVerdict
        had decided whether this run may write there at all, so an elevated run whose machine state
        directory a standard user can replace or redirect put its very first line through the path
        the gate was about to refuse. Nothing reaches the file log until this runs.

        It is called from the only two places that have established the right to write: the
        unelevated branch, whose log lives in the invoking user's own profile and therefore carries
        no machine-trust claim to refuse, and the elevated branch immediately after the verdict
        passes. Everything before it - the refusal itself, and a run that lost the machine-wide lock
        before the trust question was even asked - stays on the console, which writes nothing
        anywhere.
    #>
    if ($script:LogGateOpen) { return }
    $script:LogGateOpen = $true
    Write-UninstallerMessage -Level INFO -Message 'Uninstaller invoked.' -Data $script:InvocationRecord -NoConsole
}

function Test-RunBudget {
    <#
    .SYNOPSIS
        $true while this run still has budget for the phase it is about to start.
    .DESCRIPTION
        Initialize-WacRun arms the child's own deadline, and nothing in this script used to READ it:
        the parent's wait therefore outlasted a number no operation ever observed, which is not a
        budget. A medium-integrity parent generally cannot terminate its own elevated child, so the
        bound that actually stops the work has to be checked by the child itself, at every phase
        boundary, before that phase starts.

        The shutdown margin is held back from the deadline by -ShutdownMarginSeconds, so the final
        verdict still has time after this has returned $false.

        ponytail: cooperative, so one phase that blocks inside the OS forever is still not
        interrupted by it. Running the Scheduler calls under Invoke-WacBounded would fix that and
        would also have to marshal CIM objects across a runspace boundary; the parent's own bound
        plus an honest CRITICAL is the trade until that is worth paying for.
    #>
    param([Parameter(Mandatory = $true)][string]$Phase)

    if (-not (Test-WacDeadlineExpired)) { return $true }

    Write-UninstallerMessage -Level ERROR -Message ('The run budget expired before {0}, so this phase was never started.' -f $Phase) -Data @{
        phase = $Phase
        budgetMinutes = $script:RunBudgetMinutes
        shutdownMarginMinutes = $script:ChildShutdownMarginMinutes
    }
    return $false
}

function Wait-UninstallerExit {
    if ($NoPause) { return }
    if ($script:Relaunched) { return }
    try { if ([System.Console]::IsInputRedirected) { return } } catch { return }

    try {
        Write-Host ''
        Write-Host 'Press any key to close this window...' -ForegroundColor Cyan
        $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch {
        try { Read-Host -Prompt 'Press Enter to close this window' | Out-Null } catch { $null = $_ }
    }
}

function Invoke-UninstallerElevation {
    <#
    .SYNOPSIS
        Relaunches this script elevated and returns the child's real exit code.
    .DESCRIPTION
        Inside the main try (ledger P1-12) so a cancelled UAC prompt is logged, honours -NoPause and
        exits 4. wt.exe is never used as the wrapper: it is PATH-resolved and swallows the exit code.
    #>
    $hostPath = Get-WacCanonicalPowerShellHost
    if (-not $hostPath) {
        Write-UninstallerMessage -Level ERROR -Message 'No machine-trusted PowerShell host was found for the elevated relaunch.'
        return 4
    }

    $present = New-Object 'System.Collections.Generic.List[string]'
    if ($NoPause) { [void]$present.Add('NoPause') }
    if ($RemoveLogs) { [void]$present.Add('RemoveLogs') }
    if ($KeepLogs) { [void]$present.Add('KeepLogs') }

    $vector = Get-WacRelaunchArgument -ScriptPath $PSCommandPath -PresentSwitch @($present.ToArray())
    $commandLine = ConvertTo-WacCommandLine -ArgumentList $vector

    Write-UninstallerMessage -Level INFO -Message 'Requesting elevation.' -Data @{
        host = $hostPath
        arguments = $commandLine
        explicitParameters = (@($script:BoundParameter.Keys | Sort-Object) -join ',')
    }

    $script:Relaunched = $true
    $child = $null
    try {
        $child = Start-Process -FilePath $hostPath -ArgumentList $commandLine -Verb RunAs -PassThru -ErrorAction Stop
    }
    catch {
        Write-UninstallerMessage -Level ERROR -Message ('Elevation was cancelled or failed: {0}' -f $_.Exception.Message)
        return 4
    }

    if (-not $child) {
        Write-UninstallerMessage -Level ERROR -Message 'Elevation returned no child process.'
        return 4
    }

    try { $null = $child.Handle } catch { $null = $_ }

    if (-not $child.WaitForExit($script:ElevationTimeoutMs)) {
        # Past this point the child has outrun its OWN deadline plus the shutdown margin, so it is
        # not still working - it is wedged.
        #
        # Stop-WacProcessTree returns a VERDICT and only .Proven is evidence. Testing the returned
        # object itself was the defect: every non-null PSCustomObject is truthy, so the success
        # branch was taken unconditionally and this wrapper told the operator to re-run the
        # uninstaller over a live, still-mutating, elevated child. An unelevated parent generally
        # cannot terminate an elevated child at all, so that outcome gets its own exit code and its
        # own instruction rather than being folded into the ordinary failure.
        Write-UninstallerMessage -Level ERROR -Message 'The elevated uninstaller outran its own budget and the parent deadline.' -Data @{ pid = $child.Id; timeoutMs = $script:ElevationTimeoutMs }

        $termination = Stop-WacProcessTree -ProcessId $child.Id
        if ([bool]$termination.Proven) {
            Write-UninstallerMessage -Level ERROR -Message 'The elevated uninstaller was terminated and proven gone. The task or the deployment may be half-removed; re-run the uninstaller.' -Data @{
                pid = $child.Id; reason = [string]$termination.Reason
            }
            return 1
        }

        Write-UninstallerMessage -Level CRITICAL -Message 'The elevated uninstaller could NOT be proven terminated. It may still be running as administrator, still holding the machine-wide lock and still changing this machine. Do NOT re-run the uninstaller; wait until that process has exited.' -Data @{
            pid = $child.Id
            survivors = (@($termination.Survivor) -join ',')
            reason = [string]$termination.Reason
        }
        return 8
    }

    $code = 1
    try { $code = [int]$child.ExitCode } catch { $code = 1 }
    Write-UninstallerMessage -Level INFO -Message 'The elevated uninstaller finished.' -Data @{ exitCode = $code }
    return $code
}

function Remove-InstalledTask {
    <#
    .SYNOPSIS
        Removes our task wherever it is registered, including the pre-1.2 one at the root task path.
    .OUTPUTS
        Clean   - nothing of ours is left registered.
        Refused - a task with our name was left in place because it could not be proven ours.
        Remaining - the tasks still registered after this pass, for the deployment decision.
    #>
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    $result = [PSCustomObject]@{ Clean = $true; Refused = $false; Remaining = @() }

    # Ternary discovery: a scheduler that will not answer is not a machine with nothing registered.
    # Treating it as one is how the uninstaller went on to delete a deployment that a task it never
    # saw still points at.
    $discovery = Get-WacInstalledTask -IncludeLegacy
    if ($discovery.State -eq 'Failed') {
        Write-UninstallerMessage -Level ERROR -Message 'The Task Scheduler could not be queried, so whether a WindowsAutoCleanup task is still registered is unknown. Nothing was unregistered, and the deployment will be kept.' -Data @{
            findings = ((@($discovery.Failure | ForEach-Object { '{0}: {1}' -f $_.TaskPath, $_.Reason })) -join '; ')
        }
        $result.Clean = $false
        return $result
    }

    if ($discovery.State -eq 'Absent') {
        Write-UninstallerMessage -Level INFO -Message 'No WindowsAutoCleanup task is registered. Nothing to remove.'
        return $result
    }

    $remaining = New-Object 'System.Collections.Generic.List[object]'
    foreach ($task in @($discovery.Task)) {
        $removal = Remove-WacInstalledTask -Task $task -DeploymentRoot $DeploymentRoot -AllowLegacyMigration
        $label = '{0}{1}' -f $removal.TaskPath, $removal.TaskName

        if ($removal.Verified) {
            Write-UninstallerMessage -Level INFO -Message 'Scheduled task removed and verified absent.' -Data @{ task = $label; reason = [string]$removal.Reason }
            continue
        }

        [void]$remaining.Add($task)

        if ($removal.Removed) {
            Write-UninstallerMessage -Level ERROR -Message 'The task was unregistered but is still present.' -Data @{ task = $label; reason = $removal.Reason }
            $result.Clean = $false
            continue
        }

        # Not ours: leaving someone else's task alone is the correct outcome. It is still reported
        # as a REFUSAL rather than as success, because the operator asked for a removal that this
        # run deliberately did not perform.
        Write-UninstallerMessage -Level WARNING -Message 'A task with this name was left in place because it does not belong to WindowsAutoCleanup.' -Data @{ task = $label; reason = $removal.Reason }
        $result.Refused = $true
    }

    $result.Remaining = @($remaining.ToArray())
    return $result
}

function Remove-InstalledDeployment {
    <#
    .SYNOPSIS
        Deletes the deployment root and any leftover swap slot. Returns $true on success.
    .DESCRIPTION
        Refuses outright when the directory at the deployment path cannot be proven to belong to
        this project (ledger B2-3): a same-name directory at the expected path is not evidence, and
        an installer that deletes on that basis destroys whatever else happens to live there.
    .OUTPUTS
        Clean, Refused, Reason.
    #>
    param([Parameter(Mandatory = $true)]$Slots)

    $result = [PSCustomObject]@{ Clean = $true; Refused = $false; Reason = $null }

    $source = Get-WacNormalizedPath -Path $script:ScriptRoot
    if ($source -and (Test-WacIsWithinRoot -ChildPath $source -RootPath $Slots.Root)) {
        Write-UninstallerMessage -Level WARNING -Message 'This script is running from inside the deployment root, so the deployment was left in place. Run the uninstaller from your own checkout.' -Data @{ root = $Slots.Root }
        $result.Clean = $false
        $result.Reason = 'The uninstaller is running from inside the deployment root.'
        return $result
    }

    $ownership = Get-WacDeploymentOwnership -DeploymentRoot $Slots.Root
    if (-not $ownership.IsOurs) {
        Write-UninstallerMessage -Level ERROR -Message 'Refusing to delete a directory at the deployment path that cannot be proven to belong to WindowsAutoCleanup. It was left exactly as it was found.' -Data @{
            root = $ownership.Root; kind = $ownership.Kind; reason = $ownership.Reason
            findings = ((@($ownership.Findings) | Sort-Object) -join '; ')
        }
        $result.Clean = $false
        $result.Refused = $true
        $result.Reason = $ownership.Reason
        return $result
    }

    Write-UninstallerMessage -Level INFO -Message 'Deployment path ownership proven.' -Data @{
        root = $ownership.Root; kind = $ownership.Kind; version = [string]$ownership.Version
        tampered = [bool]$ownership.Tampered
    }

    foreach ($path in @($Slots.Root, $Slots.Staging, $Slots.Previous)) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $removal = Remove-WacDeployment -Path $path
        if ($removal.Removed) {
            Write-UninstallerMessage -Level INFO -Message 'Deployment directory removed.' -Data @{ path = $path }
        }
        else {
            Write-UninstallerMessage -Level ERROR -Message 'The deployment directory could not be fully removed.' -Data @{ path = $path; reason = [string]$removal.Reason }
            $result.Clean = $false
            $result.Reason = [string]$removal.Reason
        }
    }

    return $result
}

function Close-OutstandingJournal {
    <#
    .SYNOPSIS
        Ends any deployment transaction record left beside a deployment this run has just removed.
    .DESCRIPTION
        Ledger WAC-02R. The records live BESIDE the slots - that is what stops a move or a delete of
        a slot carrying them off - so deleting the deployment root, the staging slot and the recovery
        slot left both of them exactly where they were. An authorized uninstall that succeeded and a
        crashed upgrade then looked identical on disk, and the next install read that leftover
        capture record and RE-REGISTERED a scheduled task whose files the operator had just asked to
        have removed, pointing at a deployment root that no longer exists.

        Only after the removal is proven clean, and only then: while any part of the deployment is
        still there, the records are still the truth about it. Every task was unregistered and
        verified absent before this point, so nothing the capture record names is missing any more -
        the transaction it describes is genuinely over.
    .OUTPUTS
        [bool] $true when nothing outstanding is left on disk.
    #>
    param([Parameter(Mandatory = $true)]$Slots)

    foreach ($kind in @('TaskCapture', 'Swap', 'Uninstall')) {
        if (-not (Remove-WacDeploymentJournal -DeploymentRoot $Slots.Root -Kind $kind)) {
            Write-UninstallerMessage -Level ERROR -Message 'Uninstall evidence cleanup could not finish; its intent remains and blocks installation. Resume the uninstaller after resolving the reported I/O failure.' -Data @{ kind = $kind; root = $Slots.Root }
            return $false
        }
    }
    return $true
}

function Write-OutstandingIntentNotice {
    <#
    .SYNOPSIS
        Says, in the run that caused it, that this machine is now fenced and which file fences it.
    .DESCRIPTION
        An uninstall records its intent before it removes anything, and every later installer and
        every scheduled cleanup refuses while that record stands. A run that ends without retiring it
        therefore leaves a machine that can neither install nor clean - and it used to say only that
        the files had been kept, leaving the operator to infer both the fence and its cause.

        The remedy named here is resuming the uninstaller, which is what retires the record on
        evidence. The path is named so nobody has to go looking for what stopped them.
    #>
    param([Parameter(Mandatory = $true)]$Slots)

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $Slots.Root -Kind 'Uninstall'
    if (-not $path) { return }
    if ([string](Get-WacPathPresence -Path $path) -cne 'Present') { return }

    Write-UninstallerMessage -Level ERROR -Message 'This uninstall did not finish, so the intent record it wrote before it started still stands. While that record is there, every install and every scheduled cleanup on this machine refuses to change anything. Re-run the uninstaller to resume: it retires the record once the removal is accounted for.' -Data @{ record = $path }
}

function Remove-RetainedLog {
    <#
    .SYNOPSIS
        Deletes the stored log files, except the one this run is writing.
    #>
    $logPath = Get-WacLogPath
    $directory = Get-WacLogDirectory
    if (-not $directory) { $directory = Join-Path -Path (Get-WacDataRoot) -ChildPath 'Logs' }
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { return }

    $removed = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $directory -Filter '*.log' -File -ErrorAction SilentlyContinue)) {
        if ($logPath -and $file.FullName -ieq $logPath) { continue }
        try { [System.IO.File]::Delete($file.FullName); $removed++ } catch { $null = $_ }
    }

    Write-UninstallerMessage -Level INFO -Message 'Log files removed.' -Data @{ directory = $directory; removed = $removed; kept = [string]$logPath }
}

function Invoke-Main {
    if (-not (Test-WacIsAdministrator)) {
        # This branch's log is the invoking user's OWN profile log, which the user owns by
        # construction and on which no SYSTEM audit claim rests, so there is no trust question here
        # to refuse and the record may go straight in.
        Open-UninstallerLogGate
        return (Invoke-UninstallerElevation)
    }

    # The SAME lock the runtime and the installer take (ledger B2-3). The uninstaller used to take a
    # different name from Run.ps1, so it could delete the deployment tree out from under a cleanup
    # run that was executing it. Held through the ownership proof and the removal, and released in
    # the finally at the bottom of the file.
    $script:InstanceLock = Enter-WacSingleInstance -Name (Get-WacOperationLockName)
    if (-not $script:InstanceLock) {
        Write-UninstallerMessage -Level ERROR -Message 'Another WindowsAutoCleanup operation - a cleanup run, an install or an uninstall - already holds the machine-wide lock.' -Data @{ lock = (Get-WacOperationLockName) }
        return 3
    }

    # Every trust question this run can be refused on is asked HERE, before the log retention pass
    # below, before any task is unregistered and before anything is deleted.
    $safety = Get-OperationSafetyVerdict -LogHealth (Get-WacLogHealth) -StateTrust (Get-WacStateTrust)
    if (-not $safety.Ok) {
        # -NoLog: the path being refused is the one the log lives in, so the refusal must not be
        # written through it - and neither the retention pass nor -RemoveLogs runs after this.
        Write-UninstallerMessage -Level ERROR -Message $safety.Reason -NoLog
        return $safety.ExitCode
    }

    # Proven writable, so the record of what this run was asked to do goes into the log now.
    Open-UninstallerLogGate

    if (-not (Test-RunBudget -Phase 'anything on this machine was inspected')) { return 1 }

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) {
        Write-UninstallerMessage -Level ERROR -Message 'The deployment root cannot be resolved on this machine.'
        return 5
    }

    Write-UninstallerMessage -Level INFO -Message 'Running elevated.' -Data @{ root = $slots.Root; log = [string](Get-WacLogPath) }

    # The installer and Run.ps1 both prune to 30; without this, repeated uninstall attempts grow
    # %ProgramData%\WindowsAutoCleanup\Logs forever and the documented retention is simply untrue.
    #
    # Get-WacLogDirectory, not Split-Path -Parent (Get-WacLogPath): the log path is $null exactly
    # when logging failed, and Split-Path -Parent $null is a TERMINATING parameter-binding error on
    # both shipped hosts (measured), so the old spelling killed the run it was reporting on.
    $logDirectory = Get-WacLogDirectory
    if ($logDirectory) {
        [void](Remove-WacOldLog -LogDirectory $logDirectory -Pattern 'Uninstall-WindowsAutoCleanupTask_*.log' -KeepCount 30)
    }

    Import-Module -Name 'ScheduledTasks' -ErrorAction Stop

    if (-not (Test-RunBudget -Phase 'the registered task was unregistered')) { return 1 }
    if (-not (Set-WacUninstallIntent -DeploymentRoot $slots.Root)) {
        Write-UninstallerMessage -Level ERROR -Message 'The uninstall intent could not be recorded, so no task or deployment was removed.'
        return 6
    }
    $tasks = Remove-InstalledTask -DeploymentRoot $slots.Root

    # The files go LAST, and only when nothing can still reach them (ledger B2-3). A failed or
    # refused task removal leaves a registration pointing at Run.ps1; deleting the tree then turns a
    # recoverable state into a scheduled task that fails every night with a missing file.
    $deployment = [PSCustomObject]@{ Clean = $true; Refused = $false; Reason = $null }
    if (-not (Test-RunBudget -Phase 'the deployment files were deleted')) {
        Write-UninstallerMessage -Level ERROR -Message 'The deployment files were KEPT because the run budget expired before they could be deleted. Nothing was half-deleted; re-run the uninstaller.' -Data @{ root = $slots.Root }
        $deployment.Clean = $false
        $deployment.Reason = 'The run budget expired before the deployment could be deleted.'
    }
    elseif (-not $tasks.Clean) {
        Write-UninstallerMessage -Level ERROR -Message 'The deployment files were KEPT because a WindowsAutoCleanup task could not be removed and would still reference them.' -Data @{ root = $slots.Root }
        $deployment.Clean = $false
        $deployment.Reason = 'A task that references the deployment is still registered.'
    }
    elseif (Test-WacTaskReferencesRoot -Task @($tasks.Remaining) -DeploymentRoot $slots.Root) {
        Write-UninstallerMessage -Level ERROR -Message 'The deployment files were KEPT because a task this run left in place still runs something inside the deployment root.' -Data @{ root = $slots.Root }
        $deployment.Clean = $false
        $deployment.Reason = 'A task left in place still references the deployment root.'
    }
    else {
        $deployment = Remove-InstalledDeployment -Slots $slots
        if ($deployment.Clean -and $tasks.Clean -and -not $tasks.Refused) {
            $journalsEnded = Close-OutstandingJournal -Slots $slots
            if (-not $journalsEnded) {
                Write-UninstallerMessage -Level ERROR -Message 'Final status: incomplete. Files were removed but recovery evidence is still pending; resume the uninstaller.'
                return 6
            }
        }
    }

    if ($RemoveLogs -and $KeepLogs) {
        Write-UninstallerMessage -Level WARNING -Message '-KeepLogs overrides -RemoveLogs; the log files were kept.'
    }
    elseif ($RemoveLogs) {
        # A deletion is work, and no new work starts after the deadline. The shutdown margin is for
        # the verdict below and for the finally, not for one more pass over the log directory.
        if (Test-RunBudget -Phase 'the stored log files were deleted') { Remove-RetainedLog }
    }
    else {
        Write-UninstallerMessage -Level INFO -Message 'Log files were kept. Pass -RemoveLogs to delete them.' -Data @{ directory = (Join-Path -Path (Get-WacDataRoot) -ChildPath 'Logs') }
    }

    # A refusal outranks a plain failure: it says the machine was deliberately left as it was, which
    # is a different instruction to the operator than "something broke".
    if ($tasks.Refused -or $deployment.Refused) {
        Write-UninstallerMessage -Level ERROR -Message 'Final status: refused. Something at the task path or the deployment path could not be proven to belong to WindowsAutoCleanup and was left exactly as it was found.'
        Write-OutstandingIntentNotice -Slots $slots
        return 7
    }

    if (-not $tasks.Clean -or -not $deployment.Clean) {
        Write-UninstallerMessage -Level ERROR -Message 'Final status: incomplete. See the errors above.'
        Write-OutstandingIntentNotice -Slots $slots
        return 1
    }

    $logHealth = Get-WacLogHealth
    if (-not $logHealth.IsDurable) {
        Write-UninstallerMessage -Level ERROR -Message 'Final status: incomplete. Everything of ours was removed, but this run has no durable audit log.' -Data @{
            degraded = [bool]$logHealth.Degraded; failedWrites = [int]$logHealth.FailedWrites; reason = [string]$logHealth.Reason
        }
        return 6
    }

    Write-UninstallerMessage -Level INFO -Message 'Final status: success.'
    return 0
}

# -ShutdownMarginSeconds is what makes the budget enforceable rather than decorative: the phase
# checks in Test-RunBudget stop new work at the deadline, and the margin is the time left over for
# the final verdict that runs after they do.
$script:LogReady = Initialize-WacRun -BaseName 'Uninstall-WindowsAutoCleanupTask' -BudgetMinutes $script:RunBudgetMinutes -ShutdownMarginSeconds ($script:ChildShutdownMarginMinutes * 60)
if (-not $script:LogReady) {
    Write-Host '[WARNING] No log file could be created; continuing with console output only.' -ForegroundColor Yellow
}

# Printed before the admin branch so a relaunch that never happens is still explained on screen.
# The LOG copy is written by Open-UninstallerLogGate, once this run has proven it may write it.
$script:InvocationRecord = @{
    host = ('{0} {1}' -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion)
    source = $script:ScriptRoot
    elevated = [bool](Test-WacIsAdministrator)
    explicitParameters = (@($script:BoundParameter.Keys | Sort-Object) -join ',')
}
Write-UninstallerMessage -Level INFO -Message 'Uninstaller invoked.' -Data $script:InvocationRecord -NoLog

$exitCode = 1
try {
    $exitCode = Invoke-Main
}
catch {
    Write-UninstallerMessage -Level ERROR -Message ('Uninstaller failed: {0}' -f $_.Exception.Message)
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-UninstallerMessage -Level ERROR -Message ('At: {0}' -f $_.InvocationInfo.PositionMessage)
    }
    $exitCode = 1
}
finally {
    Exit-WacSingleInstance -Mutex $script:InstanceLock
    Close-WacLog
}

Wait-UninstallerExit
exit $exitCode
