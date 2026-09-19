#Requires -Version 5.1
<#
.SYNOPSIS
    Arms a disposable guest for campaigns. Run this ONCE, inside the virtual machine, elevated, by
    the person who owns it.

.DESCRIPTION
    This is the single manual step in the whole campaign, and it is manual on purpose. The host can
    deliver files into a guest and read what the guest publishes, but it cannot start anything in
    there - so a machine runs campaigns only because somebody stood in front of it and said so.

    What it registers: one scheduled task, running the agent as SYSTEM at startup, so the agent
    comes back by itself after the power-loss and restart scenarios cut the machine off mid-way.

.NOTES
    Run it in the guest you intend to throw away. It refuses to arm a machine that looks like a real
    workstation, because the scenarios it enables lose power on purpose.
#>

[CmdletBinding()]
param(
    [string]$AgentPath,
    [string]$Root = 'C:\wac-campaign',
    [switch]$Unregister
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$taskPath = '\WindowsAutoCleanupCampaign\'
$taskName = 'CampaignAgent'

function Write-ArmingLine {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'An operator runs this by hand and reads its output; the console text is the product.')]
    param([string]$Text = '')
    Write-Host $Text
}

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-ArmingLine 'REFUSED: arming registers a SYSTEM scheduled task and needs an elevated session.'
    exit 1
}

if ($Unregister) {
    $existing = @(Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue)
    if ($existing.Count -eq 0) {
        Write-ArmingLine 'This guest is not armed; nothing to remove.'
        exit 0
    }
    Unregister-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Confirm:$false
    Write-ArmingLine 'Disarmed. The agent will not run again.'
    exit 0
}

# A campaign cuts this machine's power on purpose and installs and uninstalls a SYSTEM task in it.
# Asking whether it is really a virtual machine is cheap and the mistake it prevents is not.
$model = [string](Get-CimInstance -ClassName Win32_ComputerSystem).Model
$manufacturer = [string](Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
if ($model -notmatch '(?i)virtual|vmware|kvm|xen|qemu' -and $manufacturer -notmatch '(?i)microsoft|vmware|innotek|qemu|xen') {
    Write-ArmingLine ('REFUSED: this looks like physical hardware ({0} / {1}).' -f $manufacturer, $model)
    Write-ArmingLine 'The campaign scenarios lose power and modify system state on purpose. Arm a disposable guest instead.'
    exit 1
}

if ([string]::IsNullOrWhiteSpace($AgentPath)) {
    $AgentPath = Join-Path -Path $PSScriptRoot -ChildPath 'WacCampaignAgent.ps1'
}
if (-not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) {
    Write-ArmingLine ('REFUSED: the agent was not found at {0}.' -f $AgentPath)
    exit 1
}

# The agent and its scenarios are COPIED into the guest's own directory. Leaving the task pointing
# at wherever the operator happened to unzip this would make arming depend on a folder nobody
# remembers not to delete.
$agentHome = Join-Path -Path $Root -ChildPath 'agent'
[void](New-Item -ItemType Directory -Path $agentHome -Force)
foreach ($file in @('WacCampaignAgent.ps1', 'WacCampaignScenario.ps1')) {
    $source = Join-Path -Path (Split-Path -Parent $AgentPath) -ChildPath $file
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        Write-ArmingLine ('REFUSED: {0} is missing beside the agent; arming half of it would be worse than not arming it.' -f $file)
        exit 1
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path -Path $agentHome -ChildPath $file) -Force
}

$installed = Join-Path -Path $agentHome -ChildPath 'WacCampaignAgent.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Root "{1}"' -f $installed, $Root)
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromHours(4))

[void](Register-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force)

Write-ArmingLine ('Armed. The agent runs as SYSTEM at every startup and watches {0}.' -f $Root)
Write-ArmingLine ''

# Prove the channel NOW rather than discovering at campaign time that the guest cannot speak. The
# host reads this exact value back; an operator who sees it there has verified the whole return path
# before any scenario depends on it.
$kvpKey = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'
$stamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
if (-not (Test-Path -LiteralPath $kvpKey)) { [void](New-Item -Path $kvpKey -Force) }
Set-ItemProperty -LiteralPath $kvpKey -Name 'WacCampaign.ArmingProbe' -Value $stamp -Type String -Force

Write-ArmingLine 'A probe value was published to the host. Confirm the return channel from the HOST with:'
Write-ArmingLine ''
Write-ArmingLine '    . .\Tests\Campaign\WacCampaignChannel.ps1'
Write-ArmingLine '    (Read-WacCampaignReport -VMName ''<your vm>'')[''ArmingProbe'']'
Write-ArmingLine ''
Write-ArmingLine ('It should print {0}. If it prints nothing, Key-Value Pair Exchange is not delivering' -f $stamp)
Write-ArmingLine 'and no campaign can report its results - fix that before running one.'
exit 0
