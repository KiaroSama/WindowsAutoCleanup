<#
.SYNOPSIS
    The structured pnputil driver inventory: parsing it, and the superseded-and-deviceless decision
    made from it. Pure - nothing here runs pnputil or touches a package.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Drivers.psm1; see that file for the pnputil documentation this
    parse rests on, and for why the parts are dot-sourced rather than imported. Everything a deletion
    is allowed to rest on is decided here: a package bound to any device, attached or not, is never a
    candidate, and a row missing a field a decision reads is dropped rather than guessed at.
#>

# ---------------------------------------------------------------------------------------------
# 3. Superseded driver package pruning (opt-in)
# ---------------------------------------------------------------------------------------------

function Get-WacDriverVersionPart {
    <#
    .SYNOPSIS
        The [version] part of a pnputil DriverVersion field, or $null.
    .DESCRIPTION
        The field combines a culture-formatted date and a version: '12/07/2020 1.2.2.0'. The date is
        ambiguous ('03/04/2024' is two different days under en-US and en-GB) and must never reach a
        deletion decision, so only the trailing version is read.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $tokens = @($Text.Trim() -split '\s+')
    for ($i = $tokens.Count - 1; $i -ge 0; $i--) {
        $token = $tokens[$i]
        if ($token -notmatch '^\d+(\.\d+){1,3}$') { continue }

        # A dot-formatted date is shaped exactly like a three-part version: under de-DE the field
        # reads '14.02.2022 1.2.0.44', so a row whose version token was missing would otherwise hand
        # back '14.02.2022' and let a DATE decide a deletion after all.
        #
        # DateTime.TryParse is useless here and actively misleading: under InvariantCulture
        # '14/02/2022' FAILS (month 14) while the legitimate two-part version '10.2' PARSES as
        # 10 February. Match the shape instead - exactly three parts with a four-digit year in the
        # first or last position. A calendar-versioned three-part driver version such as 2020.1.5
        # is refused by this rule too; that only matters for a malformed single-token field, and
        # since pruning is opt-in, refusing is the correct direction to be wrong in.
        $parts = @($token -split '\.')
        if ($parts.Count -eq 3) {
            $yearLike = { param($p) ($p.Length -eq 4 -and [int]$p -ge 1900 -and [int]$p -le 2999) }
            if ((& $yearLike $parts[0]) -or (& $yearLike $parts[2])) { continue }
        }

        try { return [version]$token } catch { return $null }
    }

    return $null
}

function Get-WacXmlChildText {
    <#
    .SYNOPSIS
        The trimmed text of a named child element, or '' when it is absent.
    .DESCRIPTION
        SelectSingleNode rather than $element.Name: under Set-StrictMode -Version 2.0 a dotted read
        of a child element that does not exist throws PropertyNotFoundException, and ExtensionId
        really is absent on every package that is not an extension (measured on a real store).
    #>
    param(
        [Parameter(Mandatory = $true)]$Element,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $child = $Element.SelectSingleNode($Name)
    if ($child) { return ([string]$child.InnerText).Trim() }
    return ''
}

function ConvertFrom-WacPnpUtilDriverXml {
    <#
    .SYNOPSIS
        Parses 'pnputil /enum-drivers /devices /format xml'. Pure: no pnputil required.
    .DESCRIPTION
        Measured on build 10.0.26200 against a real driver store of 50 packages: the root element is
        <PnpUtil>, a package is <Driver DriverName="oem9.inf">, and a package installed on NOTHING
        carries no <Devices> element at all rather than an empty one - 12 of the 50, matching the
        count Microsoft's own '$_.devices.count -eq 0' predicate returns. Device <Status> came back
        as Started, Stopped AND Disconnected, so this enumeration does report a device that is not
        currently attached.

        <ExtensionId> is present only on extension packages and is therefore optional. Every other
        field a deletion decision reads is required, and a row missing one is DROPPED rather than
        guessed at: a dropped row can never become a candidate, and losing the top of a group can
        only ever keep more packages than it removes.

        IsValid answers "is this the structured format", HasDeviceEvidence answers "did /devices
        actually take effect". They are separate because the second is the feature detection: no
        version table is consulted anywhere, the output itself is the evidence.
    .OUTPUTS
        IsValid, HasDeviceEvidence, Reason, DroppedRow, Driver (DriverName, OriginalName,
        ProviderName, ClassName, ClassGuid, ExtensionId, SignerName, Version, VersionText,
        DeviceCount, Key).
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text)

    $result = [PSCustomObject]@{
        IsValid           = $false
        HasDeviceEvidence = $false
        Reason            = ''
        DroppedRow        = 0
        Driver            = @()
    }

    if ([string]::IsNullOrWhiteSpace($Text)) {
        $result.Reason = 'pnputil produced no output.'
        return $result
    }

    $document = New-Object System.Xml.XmlDocument
    # Tool output is still input: never let a DTD in it reach out to anything.
    $document.XmlResolver = $null

    try {
        $document.LoadXml($Text)
    }
    catch {
        $result.Reason = 'The pnputil output is not well-formed XML: {0}' -f $_.Exception.Message
        return $result
    }

    $root = $document.DocumentElement
    if (-not $root -or $root.Name -cne 'PnpUtil') {
        $result.Reason = 'The pnputil output has no <PnpUtil> root element, so the structured format is unavailable.'
        return $result
    }

    $element = @($root.SelectNodes('Driver'))
    if ($element.Count -eq 0) {
        $result.Reason = 'The pnputil output carries no <Driver> element.'
        return $result
    }

    $drivers = New-Object 'System.Collections.Generic.List[object]'
    $dropped = 0
    $deviceEvidence = $false

    foreach ($node in $element) {
        $driverName = ([string]$node.GetAttribute('DriverName')).Trim()
        $originalName = Get-WacXmlChildText -Element $node -Name 'OriginalName'
        $providerName = Get-WacXmlChildText -Element $node -Name 'ProviderName'
        $className    = Get-WacXmlChildText -Element $node -Name 'ClassName'
        $classGuid    = Get-WacXmlChildText -Element $node -Name 'ClassGuid'
        $extensionId  = Get-WacXmlChildText -Element $node -Name 'ExtensionId'
        $signerName   = Get-WacXmlChildText -Element $node -Name 'SignerName'
        $versionText  = Get-WacXmlChildText -Element $node -Name 'DriverVersion'
        $version      = Get-WacDriverVersionPart -Text $versionText

        $deviceCount = @($node.SelectNodes('Devices/Device')).Count
        if ($deviceCount -gt 0) { $deviceEvidence = $true }

        if ([string]::IsNullOrWhiteSpace($driverName) -or [string]::IsNullOrWhiteSpace($originalName) -or
            [string]::IsNullOrWhiteSpace($providerName) -or [string]::IsNullOrWhiteSpace($classGuid) -or
            [string]::IsNullOrWhiteSpace($signerName) -or -not $version) {
            $dropped++
            continue
        }

        [void]$drivers.Add([PSCustomObject]@{
            DriverName   = $driverName
            OriginalName = $originalName
            ProviderName = $providerName
            ClassName    = $className
            ClassGuid    = $classGuid
            ExtensionId  = $extensionId
            SignerName   = $signerName
            Version      = $version
            VersionText  = $versionText
            DeviceCount  = $deviceCount
            Key          = (@($originalName, $classGuid, $extensionId, $providerName, $signerName) -join '|').ToLowerInvariant()
        })
    }

    $result.IsValid = $true
    $result.DroppedRow = $dropped
    $result.HasDeviceEvidence = $deviceEvidence
    $result.Driver = @($drivers.ToArray())

    if (-not $deviceEvidence) {
        $result.Reason = 'No package in the enumeration carried a device association, so /devices produced no evidence to delete on.'
    }

    return $result
}

function Get-WacSupersededDriver {
    <#
    .SYNOPSIS
        Packages that are BOTH installed on no device AND strictly superseded. Pure.
    .DESCRIPTION
        Two conditions, both required, neither sufficient alone:

        1. DEVICE EVIDENCE. Microsoft publishes 'devices.count -eq 0' as the "installed on nothing"
           predicate, and /enum-drivers /devices reports a DISCONNECTED device too (measured: a
           Status of Disconnected appears beside Started and Stopped on a real store). A package
           bound to any device, attached or not, is never a candidate.
        2. SUPERSEDENCE. A strictly higher version of the same package - OriginalName + ClassGuid +
           ExtensionId + ProviderName + SignerName - must still be present, so a device that has
           never been attached to this machine still finds a driver afterwards.

        Condition 1 was the one missing, and it is the one that matters. Measured on the development
        machine: version grouping alone nominated oem106.inf (oemvista.inf 9.26.0.0) for deletion
        while TWO started TAP-Windows adapters were still bound to it - the package installed on
        nothing was the NEWER oem17.inf (9.27.0.0). Adding the device gate takes that same store
        from one candidate to zero.

        This output carries no hardware or compatible IDs, no architecture or target OS, no rank and
        no rollback state, so none of those may be evidence here. Requiring zero devices is the
        conservative substitute: a package no devnode references cannot be the ranked winner for
        anything the machine currently knows about, and condition 2 keeps a higher-versioned sibling
        for anything it does not.

        Only published oem<n>.inf packages are considered - those are the ones /delete-driver
        accepts.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$Driver)

    $candidates = New-Object 'System.Collections.Generic.List[object]'
    if (-not $Driver -or $Driver.Count -eq 0) { return @() }

    $deletable = @($Driver | Where-Object { $_.DriverName -match '^(?i)oem\d+\.inf$' })
    if ($deletable.Count -lt 2) { return @() }

    foreach ($group in (@($deletable) | Group-Object -Property Key)) {
        if ($group.Count -lt 2) { continue }

        $highest = $null
        foreach ($member in $group.Group) {
            if ($null -eq $highest -or $member.Version -gt $highest.Version) { $highest = $member }
        }

        foreach ($member in $group.Group) {
            if ($member.Version -ge $highest.Version) { continue }
            if ($member.DeviceCount -ne 0) { continue }

            # A shallow copy, so the evidence that justified this candidate travels with it into the
            # backup manifest instead of being recomputed from a second, later enumeration.
            $candidate = $member.PSObject.Copy()
            Add-Member -InputObject $candidate -MemberType NoteProperty -Name 'SupersededByName' -Value $highest.DriverName
            Add-Member -InputObject $candidate -MemberType NoteProperty -Name 'SupersededByVersion' -Value ([string]$highest.Version)
            [void]$candidates.Add($candidate)
        }
    }

    return @($candidates.ToArray())
}
