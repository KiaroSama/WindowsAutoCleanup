#Requires -Version 5.1
<#
.SYNOPSIS
    Arms a disposable guest for campaigns, once, inside the guest, elevated, by its owner.
.DESCRIPTION
    Registers the campaign agent as SYSTEM at startup so an explicitly authorized disposable guest
    can report recovery after a cut. Positive virtual hardware evidence is required before arming.
#>
[CmdletBinding()]
param([string]$AgentPath, [string]$Root = 'C:\wac-campaign', [switch]$Unregister)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$taskPath = '\WindowsAutoCleanupCampaign\'
$taskName = 'CampaignAgent'
function Write-ArmingLine { param([string]$Text = '') Write-Host $Text }
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-ArmingLine 'REFUSED: arming requires an elevated session.'
    exit 1
}
if ($Unregister) {
    $existing = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -ieq $taskPath -and $_.TaskName -ieq $taskName })
    if ($existing.Count -eq 0) { Write-ArmingLine 'This guest is not armed.'; exit 0 }
    Unregister-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Confirm:$false -ErrorAction Stop
    Write-ArmingLine 'Disarmed.'
    exit 0
}
. (Join-Path $PSScriptRoot 'WacCampaignChecks.ps1')
$computer = @(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop)
if ($computer.Count -ne 1 -or -not (Test-WacCampaignGuest -Computer $computer[0])) {
    Write-ArmingLine 'REFUSED: positive supported virtual hardware evidence is required before arming.'
    exit 1
}
if ([string]::IsNullOrWhiteSpace($AgentPath)) { $AgentPath = Join-Path $PSScriptRoot 'WacCampaignAgent.ps1' }
if (-not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) { Write-ArmingLine 'REFUSED: the agent file is missing.'; exit 1 }
$agentHome = Join-Path $Root 'agent'
$files = @('WacCampaignAgent.ps1', 'WacCampaignScenario.ps1', 'WacCampaignChecks.ps1',
    'WacCampaignState.ps1', 'Invoke-WacCampaignScript.ps1', 'Register-WacCampaignAgent.ps1')
# Validate the complete source set before creating or copying anything.
foreach ($file in $files) {
    $source = Join-Path (Split-Path -Parent $AgentPath) $file
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw ('Missing required campaign file: ' + $file) }
}
[void](New-Item -ItemType Directory -Path $agentHome -Force)
foreach ($file in $files) {
    $source = Join-Path (Split-Path -Parent $AgentPath) $file
    $destination = Join-Path $agentHome $file
    if ([string]::Equals([IO.Path]::GetFullPath($source), [IO.Path]::GetFullPath($destination), [StringComparison]::OrdinalIgnoreCase)) { continue }
    Copy-Item -LiteralPath $source -Destination $destination -Force -ErrorAction Stop
}
$installed = Join-Path $agentHome 'WacCampaignAgent.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Root "{1}"' -f $installed, $Root.TrimEnd('\'))
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromHours(4))
[void](Register-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force)
Write-ArmingLine ('Armed. The agent watches {0}.' -f $Root)
$kvpKey = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'
$stamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
if (-not (Test-Path -LiteralPath $kvpKey)) { [void](New-Item -Path $kvpKey -Force) }
Set-ItemProperty -LiteralPath $kvpKey -Name 'WacCampaign.ArmingProbe' -Value $stamp -Type String -Force
Write-ArmingLine 'Confirm the return channel from the host:'
Write-ArmingLine '    . .\Tests\Campaign\WacCampaignChannel.ps1'
Write-ArmingLine '    (Read-WacCampaignReport -VMName ''<your vm>'')[''ArmingProbe'']'
Write-ArmingLine ('Expected probe value: {0}' -f $stamp)
exit 0
