<#
.SYNOPSIS
    Read-only campaign admission and evidence checks. Loading this file performs no machine change.
#>
Set-StrictMode -Version 2.0

function Test-WacCampaignGuest {
    param([AllowNull()]$Computer)
    if ($null -eq $Computer) { return $false }
    try {
        $model = [string]$Computer.Model
        $maker = [string]$Computer.Manufacturer
        return ($maker -ieq 'Microsoft Corporation' -and $model -ieq 'Virtual Machine') -or
            ($maker -match '^VMware' -and $model -match '^VMware') -or
            ($maker -match '^(innotek GmbH|Oracle Corporation)$' -and $model -ieq 'VirtualBox') -or
            ($maker -match '^(QEMU|Red Hat)$' -and $model -match '^(KVM|Standard PC|QEMU)') -or
            ($maker -ieq 'Xen' -and $model -ieq 'HVM domU')
    }
    catch { return $false }
}

function Test-WacCampaignSummaryShape {
    param([AllowNull()]$Summary)
    if ($null -eq $Summary) { return $false }
    try {
        if ($Summary.schema -isnot [int] -and $Summary.schema -isnot [long]) { return $false }
        if ($Summary.exitCode -isnot [int] -and $Summary.exitCode -isnot [long]) { return $false }
        if ($Summary.schema -ne 1 -or $Summary.mode -cne 'cleanup') { return $false }
        if ([string]::IsNullOrWhiteSpace([string]$Summary.executionId)) { return $false }
        if (@('Succeeded', 'SafeSkip', 'Failed', 'Incomplete', 'SecurityRefusal') -cnotcontains $Summary.outcome) { return $false }
        $when = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse([string]$Summary.completedUtc, [ref]$when)) { return $false }
        if ($null -eq $Summary.steps -or $Summary.steps -is [string]) { return $false }
        return $true
    }
    catch { return $false }
}

function Test-WacCampaignRunEvidence {
    param([AllowNull()]$Summary, [string]$PreviousId = '', [datetime]$StartedUtc = [datetime]::MinValue,
        [int]$ObservedExit = -1, [string]$Category = '')
    if (-not (Test-WacCampaignSummaryShape -Summary $Summary)) { return $false }
    if ($ObservedExit -ne 0 -or $Summary.exitCode -ne 0 -or $Summary.outcome -cne 'Succeeded') { return $false }
    if ([string]$Summary.executionId -ceq $PreviousId) { return $false }
    $when = [datetimeoffset]::Parse([string]$Summary.completedUtc).UtcDateTime
    # The public completion stamp has one-second resolution. A distinct execution ID is also required.
    if ($StartedUtc -ne [datetime]::MinValue -and $when -lt $StartedUtc.ToUniversalTime().AddSeconds(-1)) { return $false }
    if ($when -gt [datetime]::UtcNow.AddMinutes(1)) { return $false }
    if ($Category) {
        try {
            $found = @($Summary.steps | Where-Object { $_.category -ceq $Category })
            if ($found.Count -ne 1 -or $found[0].state -cne 'executed' -or $found[0].outcome -cne 'Succeeded') { return $false }
        }
        catch { return $false }
    }
    return $true
}

function Get-WacCampaignMachine {
    param([string]$ProjectRoot = '', [switch]$Installed)
    $root = Join-Path $env:ProgramFiles 'WindowsAutoCleanup'
    $tasks = @(); $records = @(); $exists = $false; $healthy = $false; $safe = $false
    try {
        # A terminating enumeration failure is unknown, never an empty task inventory.
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -ieq '\WindowsAutoCleanup\' })
        foreach ($suffix in @('', '.previous', '.staging', '.transaction.json', '.taskcapture.json', '.uninstall.json')) {
            $item = $null
            try { $item = Get-Item -LiteralPath ($root + $suffix) -Force -ErrorAction Stop }
            catch {
                if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound) { throw }
            }
            if ($null -ne $item) {
                if ($suffix -eq '') { $exists = $true } else { $records += $suffix }
            }
        }
        if ($Installed -and $exists -and $tasks.Count -eq 1 -and $records.Count -eq 0) {
            Import-Module (Join-Path $ProjectRoot 'src\WindowsAutoCleanup.Deploy.psm1') -DisableNameChecking -ErrorAction Stop
            $task = $tasks[0]
            $healthy = [bool](Get-WacDeploymentOwnership -DeploymentRoot $root).IsHealthy -and
                [bool](Test-WacTaskIsOurs -Task $task -DeploymentRoot $root).IsOurs -and
                [bool](Test-WacTaskReferencesRoot -Task $task -DeploymentRoot $root)
            $expected = Get-WacTaskActionArgument -RunScript (Join-Path $root 'Run.ps1') -ResetWindowsUpdateBase:$false
            $safe = $healthy -and @($task.Actions).Count -eq 1 -and
                [string]::Equals([string]$task.Actions[0].Arguments, $expected, [StringComparison]::Ordinal) -and
                @('SYSTEM', 'S-1-5-18') -icontains [string]$task.Principal.UserId
        }
        return [PSCustomObject]@{ Known = $true; Tasks = @($tasks); Root = $exists; Records = @($records)
            Clean = ($tasks.Count -eq 0 -and -not $exists -and $records.Count -eq 0)
            Coherent = $healthy; SafeMaintenance = $safe }
    }
    catch {
        return [PSCustomObject]@{ Known = $false; Tasks = @($tasks); Root = $exists; Records = @($records)
            Clean = $false; Coherent = $false; SafeMaintenance = $false }
    }
}
