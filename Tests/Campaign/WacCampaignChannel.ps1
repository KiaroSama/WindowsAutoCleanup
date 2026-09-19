<#
.SYNOPSIS
    The host side of the disposable-VM campaign: arming, checkpoints, payload delivery and the
    credential-free channel the guest reports back over.

.DESCRIPTION
    Everything here runs on the HOST. It never asks for guest credentials and never accepts any,
    which is the constraint that shaped the whole design:

      host -> guest   Copy-VMFile, over the Guest Service Interface. Delivers files, and cannot
                      start anything. Nothing runs in the guest that the guest's owner did not arm.
      guest -> host   Key-Value Pair Exchange. The guest writes its own values under
                      HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest and the host reads them off the
                      running machine's KVP component. No logon, no share, no port, no credential
                      anywhere in the path. (The Guest\Parameters subkey belongs to the integration
                      service itself and is not written to.)

    Neither direction can run code in the guest from here. A campaign therefore requires a guest
    that was armed ONCE, deliberately, by its owner - see Tests/Campaign/README.md. That is the
    "protected, opt-in" property this work asks for, and it is structural rather than a flag.
#>

Set-StrictMode -Version 2.0

# One KVP value is limited, so a report longer than this arrives in numbered parts. The limit is
# deliberately conservative: a value silently truncated by the exchange would be a report that still
# reads as complete.
$script:CampaignChunk = 900
$script:CampaignPrefix = 'WacCampaign.'

function Test-WacCampaignArmed {
    <#
    .SYNOPSIS
        Whether this host may run a campaign at all, and whether destructive scenarios are
        separately authorized.
    .DESCRIPTION
        Two independent switches, because they authorize different things. WAC_VM_CAMPAIGN says a
        disposable guest may be driven; WAC_VM_CAMPAIGN_DESTRUCTIVE says the driver-package and
        /ResetBase scenarios may run inside it. The second never implies the first, and neither is
        inferred from the other being set.
    .OUTPUTS
        A result carrying Armed, Destructive and Reason.
    #>
    param([switch]$WantDestructive)

    $armed = [string]$env:WAC_VM_CAMPAIGN -ceq '1'
    $destructive = [string]$env:WAC_VM_CAMPAIGN_DESTRUCTIVE -ceq '1'

    if (-not $armed) {
        return [PSCustomObject]@{ Armed = $false; Destructive = $false
            Reason = 'WAC_VM_CAMPAIGN is not 1, so no virtual machine is driven. This is the opt-in, and it is deliberately not a default.' }
    }
    if ($WantDestructive -and -not $destructive) {
        return [PSCustomObject]@{ Armed = $false; Destructive = $false
            Reason = 'The destructive scenarios need their own authorization: set WAC_VM_CAMPAIGN_DESTRUCTIVE=1 as well. Driver-package removal and /ResetBase are not covered by the campaign opt-in.' }
    }

    return [PSCustomObject]@{ Armed = $true; Destructive = [bool]$WantDestructive; Reason = '' }
}

function Get-WacCampaignVm {
    <#
    .SYNOPSIS
        The one virtual machine this campaign may touch, or a refusal.
    .DESCRIPTION
        There is no default target and no name matching. A campaign that could pick its own victim
        out of a list is one rename away from running against something that is not disposable.
    #>
    param([Parameter(Mandatory = $true)][string]$VMName)

    if ([string]::IsNullOrWhiteSpace($VMName)) {
        throw 'A campaign needs an explicit -VMName. There is no default target.'
    }

    $found = @(Get-VM -Name $VMName -ErrorAction SilentlyContinue)
    if ($found.Count -eq 0) { throw ('No virtual machine is named {0} on this host.' -f $VMName) }
    if ($found.Count -gt 1) { throw ('{0} matches {1} virtual machines; refusing to guess.' -f $VMName, $found.Count) }

    $vm = $found[0]
    $service = @(Get-VMIntegrationService -VM $vm)

    $guestService = @($service | Where-Object { $_.Name -ceq 'Guest Service Interface' })
    if ($guestService.Count -ne 1 -or -not $guestService[0].Enabled) {
        throw ('{0} has the Guest Service Interface disabled, so no payload can be delivered without credentials. Enable it on the host first.' -f $VMName)
    }

    $kvp = @($service | Where-Object { $_.Name -ceq 'Key-Value Pair Exchange' })
    if ($kvp.Count -ne 1 -or -not $kvp[0].Enabled) {
        throw ('{0} has Key-Value Pair Exchange disabled, so the guest has no way to report back. Enable it on the host first.' -f $VMName)
    }

    return $vm
}

function New-WacCampaignCheckpoint {
    <#
    .SYNOPSIS
        The checkpoint the guest is restored to afterwards, taken BEFORE anything is delivered.
    .DESCRIPTION
        Taken first and verified to exist, because a campaign whose isolation is assumed rather than
        proved is just an unattended change to somebody's machine.
    #>
    param([Parameter(Mandatory = $true)]$Vm, [Parameter(Mandatory = $true)][string]$Name)

    Checkpoint-VM -VM $Vm -SnapshotName $Name -ErrorAction Stop
    $taken = @(Get-VMSnapshot -VMName $Vm.Name -Name $Name -ErrorAction SilentlyContinue)
    if ($taken.Count -ne 1) {
        throw ('The campaign checkpoint {0} was not created; refusing to continue.' -f $Name)
    }
    return $taken[0]
}

function Restore-WacCampaignCheckpoint {
    <#
    .SYNOPSIS
        Puts the guest back exactly as it was found, and says so - or says why it could not.
    #>
    param([Parameter(Mandatory = $true)]$Vm, [Parameter(Mandatory = $true)][string]$Name, [switch]$Keep)

    if ($Keep) {
        return [PSCustomObject]@{ Restored = $false; Detail = ('kept by request: {0}' -f $Name) }
    }

    try {
        $snapshot = @(Get-VMSnapshot -VMName $Vm.Name -Name $Name -ErrorAction SilentlyContinue)
        if ($snapshot.Count -ne 1) {
            return [PSCustomObject]@{ Restored = $false
                Detail = ('the checkpoint {0} is gone; the guest was NOT restored' -f $Name) }
        }
        Restore-VMSnapshot -VMSnapshot $snapshot[0] -Confirm:$false -ErrorAction Stop
        Remove-VMSnapshot -VMSnapshot $snapshot[0] -Confirm:$false -ErrorAction SilentlyContinue
        return [PSCustomObject]@{ Restored = $true; Detail = ('restored to {0}' -f $Name) }
    }
    catch {
        return [PSCustomObject]@{ Restored = $false; Detail = ('restore failed: ' + $_.Exception.Message) }
    }
}

function Send-WacCampaignPayload {
    <#
    .SYNOPSIS
        Copies one host file into the running guest over the Guest Service Interface.
    .DESCRIPTION
        -Force overwrites what a previous run left, which is what makes a campaign repeatable. It
        never creates anything outside the campaign directory the guest's agent watches.
    #>
    param(
        [Parameter(Mandatory = $true)]$Vm,
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$GuestPath
    )

    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
        throw ('The payload {0} does not exist on the host.' -f $SourcePath)
    }

    Copy-VMFile -VM $Vm -SourcePath $SourcePath -DestinationPath $GuestPath `
        -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    return $GuestPath
}

function Read-WacCampaignReport {
    <#
    .SYNOPSIS
        Everything the guest has published so far, as a hashtable of name to value.
    .DESCRIPTION
        Read off the RUNNING machine's KVP component. A stopped guest has none, and that is an empty
        READ rather than an absence of findings - two things this project has been bitten by
        treating as one. The caller decides what an empty read means in its own context.
    #>
    param([Parameter(Mandatory = $true)][string]$VMName)

    $result = @{}
    $filter = "ElementName='{0}'" -f $VMName.Replace("'", "''")
    $system = @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName 'Msvm_ComputerSystem' `
            -Filter $filter -ErrorAction SilentlyContinue)
    if ($system.Count -ne 1) { return $result }

    $component = @(Get-CimAssociatedInstance -InputObject $system[0] `
            -ResultClassName 'Msvm_KvpExchangeComponent' -ErrorAction SilentlyContinue)
    if ($component.Count -ne 1) { return $result }

    foreach ($xml in @($component[0].GuestExchangeItems)) {
        if ([string]::IsNullOrWhiteSpace([string]$xml)) { continue }

        $document = $null
        try { $document = [xml]$xml } catch { continue }
        if ($null -eq $document) { continue }

        $name = ''
        $value = ''
        foreach ($property in @($document.INSTANCE.PROPERTY)) {
            if ([string]$property.NAME -ceq 'Name') { $name = [string]$property.VALUE }
            elseif ([string]$property.NAME -ceq 'Data') { $value = [string]$property.VALUE }
        }

        if ($name.StartsWith($script:CampaignPrefix, [System.StringComparison]::Ordinal)) {
            $result[$name.Substring($script:CampaignPrefix.Length)] = $value
        }
    }

    return $result
}

function Join-WacCampaignParts {
    <#
    .SYNOPSIS
        Reassembles a chunked guest report, or $null while it is not all there yet.
    .DESCRIPTION
        A partial report is NOT returned as a short one. Half a verdict that still parses is the
        most expensive shape of wrong answer available here.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Item, [string]$Key = 'Report')

    if (-not $Item.ContainsKey($Key + 'Parts')) { return $null }

    $expected = 0
    if (-not [int]::TryParse([string]$Item[$Key + 'Parts'], [ref]$expected)) { return $null }
    if ($expected -le 0) { return $null }

    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $expected; $i++) {
        $part = '{0}.{1}' -f $Key, $i
        if (-not $Item.ContainsKey($part)) { return $null }
        [void]$builder.Append([string]$Item[$part])
    }
    return $builder.ToString()
}

function Wait-WacCampaignSignal {
    <#
    .SYNOPSIS
        Polls what the guest publishes until a predicate holds, the deadline passes, or the guest
        stops making progress.
    .DESCRIPTION
        Bounded twice over: a wall deadline, and an idle deadline measured from the last CHANGE in
        what the guest publishes. A guest that is alive but no longer progressing is a hang, and a
        wall bound alone would sit through it for the whole budget before saying so.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$VMName,
        [Parameter(Mandatory = $true)][scriptblock]$Until,
        [int]$TimeoutSeconds = 2700,
        [int]$IdleSeconds = 420,
        [int]$PollSeconds = 5
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastChange = Get-Date
    $lastShape = ''
    $item = @{}

    while ((Get-Date) -lt $deadline) {
        $item = Read-WacCampaignReport -VMName $VMName
        if (& $Until $item) {
            return [PSCustomObject]@{ Signalled = $true; Item = $item; Reason = '' }
        }

        $shape = (@($item.Keys | Sort-Object) | ForEach-Object { $_ + '=' + [string]$item[$_] }) -join '|'
        if ($shape -cne $lastShape) {
            $lastShape = $shape
            $lastChange = Get-Date
        }
        elseif (((Get-Date) - $lastChange).TotalSeconds -gt $IdleSeconds) {
            return [PSCustomObject]@{ Signalled = $false; Item = $item
                Reason = ('the guest published nothing new for {0}s; last state: {1}' -f $IdleSeconds, $lastShape) }
        }

        Start-Sleep -Seconds $PollSeconds
    }

    return [PSCustomObject]@{ Signalled = $false; Item = $item
        Reason = ('the guest did not signal within {0}s; last state: {1}' -f $TimeoutSeconds, $lastShape) }
}

function Stop-WacCampaignVm {
    <#
    .SYNOPSIS
        Stops the guest and PROVES it is off.
    .DESCRIPTION
        -TurnOff is the power-loss primitive: it cuts the machine exactly as pulling the plug would.
        That is the whole point of the recovery scenarios, and it is never used as a tidy shutdown.
        A stop that is not verified is not a stop, so the caller always gets the real final state.
    #>
    param([Parameter(Mandatory = $true)]$Vm, [switch]$PowerCut, [int]$TimeoutSeconds = 300)

    $trouble = ''
    try {
        if ($PowerCut) { Stop-VM -VM $Vm -TurnOff -Force -Confirm:$false -ErrorAction Stop }
        else { Stop-VM -VM $Vm -Force -Confirm:$false -ErrorAction Stop }
    }
    catch {
        # A guest that will not shut down politely is still cut, because leaving it running is the
        # one outcome this function may not produce. Both failures are KEPT: a machine that had to
        # be forced, or could not be stopped at all, is something the operator has to be told.
        $trouble = 'polite stop failed: ' + $_.Exception.Message
        try { Stop-VM -VM $Vm -TurnOff -Force -Confirm:$false -ErrorAction Stop }
        catch { $trouble += '; forced stop also failed: ' + $_.Exception.Message }
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $state = [string](Get-VM -Name $Vm.Name -ErrorAction SilentlyContinue).State
        if ($state -ceq 'Off') { return [PSCustomObject]@{ Off = $true; State = $state; Trouble = $trouble } }
        Start-Sleep -Seconds 2
    }

    return [PSCustomObject]@{ Off = $false
        State = [string](Get-VM -Name $Vm.Name -ErrorAction SilentlyContinue).State; Trouble = $trouble }
}
