#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the WindowsAutoCleanup scheduled task.

.DESCRIPTION
    Removes the scheduled task created by Install-WindowsAutoCleanupTask.ps1. Writes a
    log file under the project's Logs folder and pauses before exiting so the result
    stays visible even when the elevated window would otherwise close immediately.

.PARAMETER NoPause
    Do not wait for a key press before exiting. Intended for automation and tests.
#>

[CmdletBinding()]
param(
    # Useful for automation, tests, and GitHub Actions because it prevents the
    # elevated console from waiting for a key press before exiting.
    [switch]$NoPause
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'WindowsAutoCleanup'
$TaskPath = '\'

$script:ScriptRoot = Split-Path -Parent $PSCommandPath
$script:LogRoot = Join-Path -Path $script:ScriptRoot -ChildPath 'Logs'
$script:LogPath = $null

function Initialize-InstallerLog {
    try {
        if (-not (Test-Path -LiteralPath $script:LogRoot -PathType Container)) {
            New-Item -Path $script:LogRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $name = 'Uninstall-WindowsAutoCleanupTask_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        $script:LogPath = Join-Path -Path $script:LogRoot -ChildPath $name
        New-Item -Path $script:LogPath -ItemType File -Force -ErrorAction Stop | Out-Null
    }
    catch {
        $fallbackRoot = if ($env:ProgramData) { Join-Path -Path $env:ProgramData -ChildPath 'WindowsAutoCleanup\Logs' } else { Join-Path -Path $env:SystemRoot -ChildPath 'Logs\WindowsAutoCleanup' }
        try {
            if (-not (Test-Path -LiteralPath $fallbackRoot -PathType Container)) {
                New-Item -Path $fallbackRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        }
        catch { $null = $_ }
        $script:LogPath = Join-Path -Path $fallbackRoot -ChildPath ('Uninstall-WindowsAutoCleanupTask_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
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
        try { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 -ErrorAction Stop } catch { $null = $_ }
    }
}

function Wait-InstallerExit {
    if ($NoPause) { return }

    try {
        Write-Host ''
        Write-Host 'Press any key to close this window...' -ForegroundColor Cyan
        $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch {
        try { Read-Host -Prompt 'Press Enter to close this window' | Out-Null } catch { $null = $_ }
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
    $pwshCmd = @(Get-Command -Name 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($pwshCmd.Count -gt 0) {
        $pwshPath = [string]$pwshCmd[0].Source
        if ($pwshPath -and (Test-Path -LiteralPath $pwshPath -PathType Leaf)) {
            return $pwshPath
        }
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

    # Self-elevate with the preferred PowerShell host (pwsh.exe when installed, fall back
    # to Windows PowerShell 5.1).
    $uninstallerHost = Get-PreferredPowerShellPath
    $scriptArg = '"{0}"' -f $PSCommandPath
    $childArgs = '-NoProfile -ExecutionPolicy Bypass -File {0}' -f $scriptArg
    if ($NoPause) {
        $childArgs = '{0} -NoPause' -f $childArgs
    }

    try {
        $wt = Get-Command -Name 'wt.exe' -ErrorAction SilentlyContinue
        if ($wt -and $wt.Source) {
            $wtArgs = '"{0}" {1}' -f $uninstallerHost, $childArgs
            $proc = Start-Process -FilePath $wt.Source -ArgumentList $wtArgs -Verb RunAs -PassThru -Wait -ErrorAction Stop
        }
        else {
            $proc = Start-Process -FilePath $uninstallerHost -ArgumentList $childArgs -Verb RunAs -PassThru -Wait -ErrorAction Stop
        }
        if ($null -ne $proc.ExitCode) { exit $proc.ExitCode }
        exit 0
    }
    catch {
        throw "Failed to relaunch uninstaller as administrator: $($_.Exception.Message)"
    }
}

# --------------------------------------------------------------------
# Main flow.
# --------------------------------------------------------------------

Invoke-ElevatedRelaunchIfNeeded

try {
    Initialize-InstallerLog
    Write-InstallerLine -Level INFO -Message ("Uninstaller started. Log: {0}" -f $script:LogPath)
    Write-InstallerLine -Level INFO -Message ("Admin rights active: {0}" -f (Test-IsAdministrator))
    Write-InstallerLine -Level INFO -Message ("PowerShell host: {0} {1}" -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion)

    try {
        Import-Module -Name 'ScheduledTasks' -ErrorAction Stop
    }
    catch {
        throw "Could not load the ScheduledTasks module: $($_.Exception.Message)"
    }

    $existingTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-InstallerLine -Level INFO -Message ("Removing scheduled task '{0}{1}'..." -f $TaskPath, $TaskName)
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-InstallerLine -Level SUCCESS -Message ("Scheduled task '{0}{1}' has been removed." -f $TaskPath, $TaskName)
    }
    else {
        Write-InstallerLine -Level INFO -Message ("Scheduled task '{0}{1}' was not found. Nothing to remove." -f $TaskPath, $TaskName)
    }

    Write-InstallerLine -Level SUCCESS -Message 'Final status: success.'
    Wait-InstallerExit
    exit 0
}
catch {
    Write-InstallerLine -Level ERROR -Message ("Uninstaller failed: {0}" -f $_.Exception.Message)
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-InstallerLine -Level ERROR -Message ("At: {0}" -f $_.InvocationInfo.PositionMessage)
    }
    Wait-InstallerExit
    exit 1
}
