#Requires -Version 5.1
<#
.SYNOPSIS
    Installs or updates the WindowsAutoCleanup scheduled task.

.DESCRIPTION
    Registers a daily scheduled task named WindowsAutoCleanup. The task runs the
    Run.ps1 script from the same folder where this installer is executed.
    The script is not copied or moved.

    The installer writes a transcript of its actions to a log file under the project's
    Logs folder, then pauses before exiting so the result remains visible even when the
    elevated window would otherwise close immediately.

.PARAMETER DailyRunTime
    Daily task run time in 24-hour HH:mm format.

.PARAMETER NoPause
    Do not wait for a key press before exiting. Intended for automation and tests.

.PARAMETER ResetWindowsUpdateBase
    Adds -ResetWindowsUpdateBase to the scheduled Run.ps1 action. Enabled by
    default. This enables DISM /ResetBase and makes installed Windows updates
    non-uninstallable. Pass -ResetWindowsUpdateBase:$false to disable it.
#>

[CmdletBinding()]
param(
    # Configure the daily run time. Use 24-hour HH:mm format.
    [ValidatePattern('^(?:[01]\d|2[0-3]):[0-5]\d$')]
    [string]$DailyRunTime = '20:00',

    # Useful for automation, tests, and GitHub Actions because it prevents the
    # elevated console from waiting for a key press before exiting.
    [switch]$NoPause,

    # Aggressive Windows Update component cleanup for scheduled runs is enabled by
    # default. Installed Windows updates cannot be uninstalled after DISM /ResetBase.
    [switch]$ResetWindowsUpdateBase = $true
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'WindowsAutoCleanup'
$TaskPath = '\'
$TaskDescription = 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.'

$script:ScriptRoot = Split-Path -Parent $PSCommandPath
$script:LogRoot = Join-Path -Path $script:ScriptRoot -ChildPath 'Logs'
$script:LogPath = $null

function Initialize-InstallerLog {
    try {
        if (-not (Test-Path -LiteralPath $script:LogRoot -PathType Container)) {
            New-Item -Path $script:LogRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $name = 'Install-WindowsAutoCleanupTask_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        $script:LogPath = Join-Path -Path $script:LogRoot -ChildPath $name
        New-Item -Path $script:LogPath -ItemType File -Force -ErrorAction Stop | Out-Null
    }
    catch {
        $fallbackRoot = if ($env:TEMP) { $env:TEMP } else { 'C:\Windows\Temp' }
        $script:LogPath = Join-Path -Path $fallbackRoot -ChildPath ('Install-WindowsAutoCleanupTask_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        New-Item -Path $script:LogPath -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

function Write-InstallerLine {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('INFO','SUCCESS','WARN','ERROR')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        default   { Write-Host $line -ForegroundColor White }
    }
    if ($script:LogPath) {
        try { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    }
}

function Wait-InstallerExit {
    if ($NoPause) { return }

    # Keep the elevated console open so the user can read the result. Wait for any key
    # press through the host RawUI when available; fall back to Read-Host when it is not
    # (for example, inside PowerShell ISE or under non-interactive hosts).
    try {
        Write-Host ''
        Write-Host 'Press any key to close this window...' -ForegroundColor Cyan
        $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch {
        try { Read-Host -Prompt 'Press Enter to close this window' | Out-Null } catch { }
    }
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-PreferredPowerShellPath {
    # Prefer PowerShell 7 (pwsh.exe) when available; fall back to Windows PowerShell 5.1.
    $pwshCmd = Get-Command -Name 'pwsh.exe' -ErrorAction SilentlyContinue
    if ($pwshCmd -and $pwshCmd.Source -and (Test-Path -LiteralPath $pwshCmd.Source -PathType Leaf)) {
        return $pwshCmd.Source
    }

    if ($env:ProgramFiles) {
        $defaultPwsh = Join-Path -Path $env:ProgramFiles -ChildPath 'PowerShell\7\pwsh.exe'
        if (Test-Path -LiteralPath $defaultPwsh -PathType Leaf) {
            return $defaultPwsh
        }
    }

    return (Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

function Invoke-ElevatedRelaunchIfNeeded {
    if (Test-IsAdministrator) { return }

    # Self-elevate with the preferred PowerShell host (PowerShell 7 when installed,
    # Windows PowerShell 5.1 as a guaranteed fallback). Post-registration verification
    # below makes any silent failure of the ScheduledTasks module visible.
    $installerHost = Get-PreferredPowerShellPath
    $scriptArg = '"{0}"' -f $PSCommandPath
    $dailyRunTimeArg = '"{0}"' -f $DailyRunTime
    $childArgs = '-NoProfile -ExecutionPolicy Bypass -File {0} -DailyRunTime {1}' -f $scriptArg, $dailyRunTimeArg
    if ($ResetWindowsUpdateBase) {
        $childArgs = '{0} -ResetWindowsUpdateBase' -f $childArgs
    }
    if ($NoPause) {
        $childArgs = '{0} -NoPause' -f $childArgs
    }

    try {
        $wt = Get-Command -Name 'wt.exe' -ErrorAction SilentlyContinue
        if ($wt -and $wt.Source) {
            $wtArgs = '"{0}" {1}' -f $installerHost, $childArgs
            $proc = Start-Process -FilePath $wt.Source -ArgumentList $wtArgs -Verb RunAs -PassThru -Wait -ErrorAction Stop
        }
        else {
            $proc = Start-Process -FilePath $installerHost -ArgumentList $childArgs -Verb RunAs -PassThru -Wait -ErrorAction Stop
        }
        if ($null -ne $proc.ExitCode) { exit $proc.ExitCode }
        exit 0
    }
    catch {
        throw "Failed to relaunch installer as administrator: $($_.Exception.Message)"
    }
}

# --------------------------------------------------------------------
# Main flow. Everything below runs only after admin elevation succeeds.
# --------------------------------------------------------------------

Invoke-ElevatedRelaunchIfNeeded

try {
    Initialize-InstallerLog
    Write-InstallerLine -Level INFO -Message ("Installer started. Log: {0}" -f $script:LogPath)
    Write-InstallerLine -Level INFO -Message ("Admin rights active: {0}" -f (Test-IsAdministrator))
    Write-InstallerLine -Level INFO -Message ("PowerShell host: {0} {1}" -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion)
    Write-InstallerLine -Level INFO -Message ("Script folder: {0}" -f $script:ScriptRoot)

    $mainScript = Join-Path -Path $script:ScriptRoot -ChildPath 'Run.ps1'
    if (-not (Test-Path -LiteralPath $mainScript -PathType Leaf)) {
        throw "Main script not found: $mainScript"
    }
    Write-InstallerLine -Level INFO -Message ("Main script: {0}" -f $mainScript)
    Write-InstallerLine -Level INFO -Message ("Windows Update ResetBase scheduled mode: {0}" -f ([bool]$ResetWindowsUpdateBase))

    try {
        $runTime = [DateTime]::ParseExact($DailyRunTime, 'HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw "Invalid DailyRunTime value '$DailyRunTime'. Use 24-hour HH:mm format, for example '03:00'."
    }

    # Pick the host the scheduled task will use. Prefer pwsh.exe (PowerShell 7) when
    # installed at task-creation time, so scheduled runs match the user's preferred host.
    # Fall back to Windows PowerShell 5.1 (always present on supported Windows).
    $taskHost = Get-PreferredPowerShellPath
    if (-not (Test-Path -LiteralPath $taskHost -PathType Leaf)) {
        throw "PowerShell executable for the task action not found: $taskHost"
    }
    Write-InstallerLine -Level INFO -Message ("Task host (for scheduled runs): {0}" -f $taskHost)

    # Make sure the ScheduledTasks module is loaded. It is part of Windows so this should
    # always succeed under Windows PowerShell 5.1, but we surface a clear error if not.
    try {
        Import-Module -Name 'ScheduledTasks' -ErrorAction Stop
    }
    catch {
        throw "Could not load the ScheduledTasks module: $($_.Exception.Message)"
    }

    $quotedMainScript = '"{0}"' -f $mainScript
    $taskArguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {0} -Scheduled' -f $quotedMainScript
    if ($ResetWindowsUpdateBase) {
        $taskArguments = '{0} -ResetWindowsUpdateBase' -f $taskArguments
    }

    $action = New-ScheduledTaskAction -Execute $taskHost -Argument $taskArguments -WorkingDirectory $script:ScriptRoot

    # Build a concrete DateTime for today at the configured run time. New-ScheduledTaskTrigger
    # requires DateTime for -At.
    $triggerAt = [DateTime]::Today.Add($runTime.TimeOfDay)
    $trigger = New-ScheduledTaskTrigger -Daily -At $triggerAt

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet `
        -Compatibility Win8 `
        -Hidden `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 10)

    $taskObject = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $TaskDescription

    Write-InstallerLine -Level INFO -Message ("Registering scheduled task '{0}{1}'..." -f $TaskPath, $TaskName)
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -InputObject $taskObject -Force | Out-Null

    # Confirm registration by reading the task back. If this returns nothing, something
    # went wrong silently and we want to surface that as an error.
    $registered = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if (-not $registered) {
        throw "Register-ScheduledTask returned without throwing, but the task could not be found afterwards."
    }

    $registeredHidden = $false
    $registeredRunLevel = $null
    $registeredCompatibility = $null
    $registeredUserId = $null
    $registeredLogonType = $null
    $registeredAction = $null
    $registeredActionExecute = $null
    $registeredActionArguments = $null
    try { $registeredHidden = [bool]$registered.Settings.Hidden } catch { $registeredHidden = $false }
    try { $registeredRunLevel = [string]$registered.Principal.RunLevel } catch { $registeredRunLevel = $null }
    try { $registeredCompatibility = [string]$registered.Settings.Compatibility } catch { $registeredCompatibility = $null }
    try { $registeredUserId = [string]$registered.Principal.UserId } catch { $registeredUserId = $null }
    try { $registeredLogonType = [string]$registered.Principal.LogonType } catch { $registeredLogonType = $null }
    try {
        $registeredAction = @($registered.Actions)[0]
        $registeredActionExecute = [string]$registeredAction.Execute
        $registeredActionArguments = [string]$registeredAction.Arguments
    }
    catch {
        $registeredAction = $null
    }

    if (-not $registeredHidden) {
        throw "Scheduled task was registered, but its Hidden setting is not enabled."
    }
    if ($registeredRunLevel -ne 'Highest') {
        throw "Scheduled task was registered, but its run level is '$registeredRunLevel' instead of 'Highest'."
    }
    if ($registeredCompatibility -ne 'Win8') {
        throw "Scheduled task was registered, but its compatibility is '$registeredCompatibility' instead of 'Win8'."
    }
    if ($registeredUserId -ne 'SYSTEM' -or $registeredLogonType -ne 'ServiceAccount') {
        throw "Scheduled task was registered, but its principal is '$registeredUserId' / '$registeredLogonType' instead of SYSTEM / ServiceAccount."
    }
    if (-not $registeredAction -or -not [string]::Equals($registeredActionExecute, $taskHost, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Scheduled task was registered, but its action executable is '$registeredActionExecute' instead of '$taskHost'."
    }
    if ($registeredActionArguments -notmatch '(^|\s)-WindowStyle\s+Hidden(\s|$)' -or $registeredActionArguments -notmatch '(^|\s)-Scheduled(\s|$)') {
        throw "Scheduled task was registered, but its action arguments are missing -WindowStyle Hidden or -Scheduled."
    }
    if ($ResetWindowsUpdateBase -and $registeredActionArguments -notmatch '(^|\s)-ResetWindowsUpdateBase(\s|$)') {
        throw "Scheduled task was registered, but its action arguments are missing -ResetWindowsUpdateBase."
    }

    Write-InstallerLine -Level SUCCESS -Message ("Scheduled task '{0}' is registered." -f $TaskName)
    Write-InstallerLine -Level INFO -Message ("Daily run time: {0}" -f $DailyRunTime)
    Write-InstallerLine -Level INFO -Message ("Task path: {0}" -f $registered.TaskPath)
    Write-InstallerLine -Level INFO -Message ("Task hidden: {0}" -f $registeredHidden)
    Write-InstallerLine -Level INFO -Message ("Task run level: {0}" -f $registeredRunLevel)
    Write-InstallerLine -Level INFO -Message ("Task compatibility: {0}" -f $registeredCompatibility)
    Write-InstallerLine -Level INFO -Message ("Task principal: {0} / {1}" -f $registeredUserId, $registeredLogonType)
    Write-InstallerLine -Level INFO -Message ("Task action: {0} {1}" -f $registeredActionExecute, $registeredActionArguments)
    Write-InstallerLine -Level SUCCESS -Message 'Final status: success.'

    Wait-InstallerExit
    exit 0
}
catch {
    Write-InstallerLine -Level ERROR -Message ("Installer failed: {0}" -f $_.Exception.Message)
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-InstallerLine -Level ERROR -Message ("At: {0}" -f $_.InvocationInfo.PositionMessage)
    }
    Wait-InstallerExit
    exit 1
}
