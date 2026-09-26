<#
.SYNOPSIS
    Host-side opt-in, exact VM identity and bounded credential-free campaign exchange.
.DESCRIPTION
    The owner arms the disposable guest separately. The host only copies files and reads KVP data.
    All mutation uses the admitted VM object/Id; names are only the initial selection and diagnostics.
#>
Set-StrictMode -Version 2.0
$script:CampaignChunk = 900
$script:CampaignPrefix = 'WacCampaign.'

function Test-WacCampaignArmed {
    param([switch]$WantDestructive)
    if ([string]$env:WAC_VM_CAMPAIGN -cne '1') {
        return [PSCustomObject]@{ Armed = $false; Destructive = $false; Reason = 'WAC_VM_CAMPAIGN must be exactly 1.' }
    }
    if ($WantDestructive -and [string]$env:WAC_VM_CAMPAIGN_DESTRUCTIVE -cne '1') {
        return [PSCustomObject]@{ Armed = $false; Destructive = $false; Reason = 'WAC_VM_CAMPAIGN_DESTRUCTIVE must separately be exactly 1.' }
    }
    return [PSCustomObject]@{ Armed = $true; Destructive = [bool]$WantDestructive; Reason = '' }
}

function Get-WacCampaignVm {
    param([Parameter(Mandatory = $true)][string]$VMName)
    if ([string]::IsNullOrWhiteSpace($VMName) -or
        [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($VMName)) {
        throw 'VMName must be an explicit literal name, not blank or a wildcard.'
    }
    $found = @(Get-VM -Name $VMName -ErrorAction Stop)
    if ($found.Count -ne 1) { throw 'The literal name did not resolve to exactly one VM.' }
    $vm = $found[0]
    if (-not [string]::Equals([string]$vm.Name, $VMName, [StringComparison]::OrdinalIgnoreCase) -or
        [guid]$vm.Id -eq [guid]::Empty) { throw 'The resolved identity is not the requested VM.' }
    $services = @(Get-VMIntegrationService -VM $vm -ErrorAction Stop)
    foreach ($name in @('Guest Service Interface', 'Key-Value Pair Exchange')) {
        $one = @($services | Where-Object { $_.Name -ceq $name })
        if ($one.Count -ne 1 -or -not $one[0].Enabled) { throw ('The required integration service is unavailable: ' + $name) }
    }
    return $vm
}

function New-WacCampaignCheckpoint {
    param([Parameter(Mandatory = $true)]$Vm, [Parameter(Mandatory = $true)][string]$Name)
    Checkpoint-VM -VM $Vm -SnapshotName $Name -ErrorAction Stop
    $taken = @(Get-VMSnapshot -VM $Vm -Name $Name -ErrorAction Stop)
    if ($taken.Count -ne 1 -or $taken[0].Name -cne $Name -or [guid]$taken[0].VMId -ne [guid]$Vm.Id) {
        throw 'The checkpoint does not belong to the admitted VM.'
    }
    return $taken[0]
}

function Restore-WacCampaignCheckpoint {
    param([Parameter(Mandatory = $true)]$Vm, [Parameter(Mandatory = $true)][string]$Name, [switch]$Keep)
    if ($Keep) { return [PSCustomObject]@{ Restored = $false; Detail = ('kept by request: ' + $Name) } }
    try {
        $snapshot = @(Get-VMSnapshot -VM $Vm -Name $Name -ErrorAction Stop)
        if ($snapshot.Count -ne 1 -or $snapshot[0].Name -cne $Name -or [guid]$snapshot[0].VMId -ne [guid]$Vm.Id) {
            throw 'The checkpoint identity is missing or foreign.'
        }
        Restore-VMSnapshot -VMSnapshot $snapshot[0] -Confirm:$false -ErrorAction Stop
        Remove-VMSnapshot -VMSnapshot $snapshot[0] -Confirm:$false -ErrorAction Stop
        return [PSCustomObject]@{ Restored = $true; Detail = ('restored to ' + $Name) }
    }
    catch { return [PSCustomObject]@{ Restored = $false; Detail = ('restore failed: ' + $_.Exception.Message) } }
}

function Send-WacCampaignPayload {
    param([Parameter(Mandatory = $true)]$Vm, [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$GuestPath)
    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) { throw 'The payload source is missing.' }
    Copy-VMFile -VM $Vm -SourcePath $SourcePath -DestinationPath $GuestPath -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    return $GuestPath
}

function Read-WacCampaignReport {
    param([Parameter(Mandatory = $true)][string]$VMName, [guid]$VmId = [guid]::Empty)
    $result = @{}
    # Name-only mode is retained for the operator's read-only arming probe, never used by the driver.
    $filter = if ($VmId -ne [guid]::Empty) { "Name='{0}'" -f $VmId.ToString('D') }
        else { "ElementName='{0}'" -f $VMName.Replace("'", "''") }
    try {
        $system = @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName 'Msvm_ComputerSystem' -Filter $filter -ErrorAction Stop)
        if ($system.Count -ne 1) { return $result }
        if ($VmId -ne [guid]::Empty -and [guid]$system[0].Name -ne $VmId) { return $result }
        $component = @(Get-CimAssociatedInstance -InputObject $system[0] -ResultClassName 'Msvm_KvpExchangeComponent' -ErrorAction Stop)
        if ($component.Count -ne 1) { return $result }
        foreach ($xml in @($component[0].GuestExchangeItems)) {
            if ([string]::IsNullOrWhiteSpace([string]$xml)) { continue }
            try { $document = [xml]$xml } catch { continue }
            $name = ''; $value = ''
            foreach ($property in @($document.INSTANCE.PROPERTY)) {
                if ([string]$property.NAME -ceq 'Name') { $name = [string]$property.VALUE }
                elseif ([string]$property.NAME -ceq 'Data') { $value = [string]$property.VALUE }
            }
            if ($name.StartsWith($script:CampaignPrefix, [StringComparison]::Ordinal)) {
                $result[$name.Substring($script:CampaignPrefix.Length)] = $value
            }
        }
    }
    catch { return @{} }
    # Empty is an unsuccessful read, not a successful campaign verdict.
    return $result
}

function Join-WacCampaignParts {
    param([Parameter(Mandatory = $true)][hashtable]$Item, [string]$Key = 'Report')
    if (-not $Item.ContainsKey($Key + 'Parts')) { return $null }
    $expected = 0
    if (-not [int]::TryParse([string]$Item[$Key + 'Parts'], [ref]$expected) -or $expected -le 0 -or $expected -gt 4096) { return $null }
    $builder = New-Object Text.StringBuilder
    for ($i = 0; $i -lt $expected; $i++) {
        $part = '{0}.{1}' -f $Key, $i
        if (-not $Item.ContainsKey($part)) { return $null }
        [void]$builder.Append([string]$Item[$part])
    }
    return $builder.ToString()
}

function Wait-WacCampaignSignal {
    param([Parameter(Mandatory = $true)][string]$VMName, [Parameter(Mandatory = $true)][scriptblock]$Until,
        [guid]$VmId = [guid]::Empty, [int]$TimeoutSeconds = 2700, [int]$IdleSeconds = 420, [int]$PollSeconds = 5)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $lastChange = 0.0; $lastShape = ''; $item = @{}
    while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $item = Read-WacCampaignReport -VMName $VMName -VmId $VmId
        if (& $Until $item) { return [PSCustomObject]@{ Signalled = $true; Item = $item; Reason = '' } }
        $shape = (@($item.Keys | Sort-Object) | ForEach-Object { $_ + '=' + [string]$item[$_] }) -join '|'
        if ($shape -cne $lastShape) { $lastShape = $shape; $lastChange = $watch.Elapsed.TotalSeconds }
        elseif (($watch.Elapsed.TotalSeconds - $lastChange) -gt $IdleSeconds) { break }
        $left = [Math]::Max(0, $TimeoutSeconds - $watch.Elapsed.TotalSeconds)
        Start-Sleep -Milliseconds ([int]([Math]::Min([Math]::Max(0.01, $PollSeconds), $left) * 1000))
    }
    return [PSCustomObject]@{ Signalled = $false; Item = $item; Reason = ('No verified signal within the idle/operation deadline; last state: ' + $lastShape) }
}

function Get-WacCampaignVmState {
    param([Parameter(Mandatory = $true)]$Vm)
    try {
        $current = @(Get-VM -Id $Vm.Id -ErrorAction Stop)
        if ($current.Count -ne 1 -or [guid]$current[0].Id -ne [guid]$Vm.Id) { return 'Unknown' }
        return [string]$current[0].State
    }
    catch { return 'Unknown' }
}

function Stop-WacCampaignVm {
    param([Parameter(Mandatory = $true)]$Vm, [switch]$PowerCut, [int]$TimeoutSeconds = 300)
    $trouble = ''
    try {
        if ($PowerCut) { Stop-VM -VM $Vm -TurnOff -Force -Confirm:$false -ErrorAction Stop }
        else { Stop-VM -VM $Vm -Force -Confirm:$false -ErrorAction Stop }
    }
    catch {
        $trouble = $_.Exception.Message
        try { Stop-VM -VM $Vm -TurnOff -Force -Confirm:$false -ErrorAction Stop }
        catch { $trouble += '; forced stop failed: ' + $_.Exception.Message }
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $state = Get-WacCampaignVmState -Vm $Vm
        if ($state -ceq 'Off') { return [PSCustomObject]@{ Off = $true; State = $state; Trouble = $trouble } }
        if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { break }
        Start-Sleep -Milliseconds 250
    } while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    return [PSCustomObject]@{ Off = $false; State = $state; Trouble = $trouble }
}

function Test-WacCampaignReportEvidence {
    param([AllowNull()]$Report, [string]$CampaignId, [string]$Commit, [string]$Scenario)
    try {
        if ($null -eq $Report -or $Report.schema -ne 1 -or $Report.campaignId -cne $CampaignId -or $Report.commit -cne $Commit) { return $false }
        if (@($Report.requested).Count -ne 1 -or $Report.requested[0] -cne $Scenario) { return $false }
        if (@($Report.results).Count -ne 1 -or $Report.results[0].Scenario -cne $Scenario -or @($Report.notRun).Count -ne 0) { return $false }
        $verdict = $Report.results[0].Verdict
        if ($verdict -ceq 'passed') { return $Report.status -ceq 'complete' }
        if ($verdict -ceq 'failed') { return $Report.status -ceq 'failed' }
        return $false
    }
    catch { return $false }
}
