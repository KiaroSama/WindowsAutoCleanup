<#
.SYNOPSIS
    Driver-store cleanup: the Windows pnpclean handler and opt-in superseded-package pruning.

.DESCRIPTION
    Split out of WindowsAutoCleanup.Steps.psm1 because the driver store is its own domain with its
    own risk profile: everything here talks to the pnp subsystem and can remove a package the
    machine still needs. Keeping it separate means the riskiest code in the project can be reviewed
    and tested on its own.

    The structured pnputil output IS documented. 'create-a-driver-inventory' (ms.date 2025-11-15)
    documents /format and /output-file for /enum-drivers and publishes the device-association
    predicate this module deletes on:

        [xml] $out = pnputil /enum-drivers /devices /format xml
        $out.pnputil.driver | where {$_.devices.count -eq 0}

    The same page says "Don't use scripts to process the default output or the 'text' /format option
    since that output can change and is localized", which is why the localized text output is never
    parsed here - not even as a fallback. The pnputil syntax reference still lists /format only under
    /enum-containers, so the two pages disagree about AVAILABILITY: this module feature-detects the
    structured output at run time instead of trusting either page's version table.

    Microsoft's driver-store documentation also states that staged files "shouldn't be removed or
    modified in any way", and there is no reference page for pnpclean.dll at all. Both mechanisms are
    therefore best-effort, and package pruning stays off unless the caller opts in.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the CALLER's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.FileSystem.psm1') -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Steps.psm1') -DisableNameChecking -ErrorAction Stop

$script:PnpCleanTimeoutMs = 1000 * 60 * 120
$script:PnpUtilTimeoutMs  = 1000 * 60 * 2

# pnputil documents 0, 3010 (ERROR_SUCCESS_REBOOT_REQUIRED) and 1641 (ERROR_SUCCESS_REBOOT_INITIATED)
# as success; 259 (ERROR_NO_MORE_ITEMS) is benign. The documented list is explicitly partial, so
# treating every other non-zero code as a hard failure would manufacture false failures.
$script:PnpUtilSuccessCode = @(0, 3010, 1641)
$script:PnpUtilBenignCode  = @(259)
$script:PnpUtilRebootCode  = @(3010, 1641)

# The one enumeration this module runs. /devices is what turns the output from "these two packages
# look alike" into "this package is installed on nothing", which is the only evidence a deletion may
# rest on.
$script:PnpUtilEnumArgument = @('/enum-drivers', '/devices', '/format', 'xml')

# Written into every export directory. Excluded from its own hash list, and the name a recovery tool
# reads to find out which oem<n>.inf a backup directory holds.
$script:BackupManifestName   = 'wac-driver-backup.json'
# 2 added DeletedUtc: the record that tells a backup apart from an export of a package that is
# still installed. A schema-1 manifest has no such record and is therefore reclaimable.
$script:BackupManifestSchema = 2

# Run-level precedence: SecurityRefusal beats Failed beats Incomplete beats a clean outcome.
$script:OutcomeRank = @{ 'Succeeded' = 0; 'SafeSkip' = 0; 'Incomplete' = 1; 'Failed' = 2; 'SecurityRefusal' = 3 }

function Get-WacHigherOutcome {
    <#
    .SYNOPSIS
        The higher-precedence of two outcomes. Pure.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Current,
        [Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Candidate
    )

    if ($script:OutcomeRank[$Candidate] -gt $script:OutcomeRank[$Current]) { return $Candidate }
    return $Current
}

function New-WacDriverStepResult {
    <#
    .SYNOPSIS
        New-WacStepResult expressed in the five-outcome vocabulary.
    .DESCRIPTION
        Succeeded / SafeSkip / Incomplete / SecurityRefusal / Failed is the shared contract, and the
        Succeeded + Skipped + Failed booleans are derived from it. New-WacStepResult is gaining
        -Outcome in another module; until that lands this bridge derives the booleans itself, and it
        always guarantees the returned object carries .Outcome so callers and tests read one
        vocabulary either way.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][ValidateSet('Succeeded', 'SafeSkip', 'Incomplete', 'SecurityRefusal', 'Failed')][string]$Outcome,
        [string]$Detail = '',
        [int]$DurationMs = 0,
        [bool]$Attempted = $false,
        [bool]$RebootRequired = $false
    )

    $argument = @{
        Category       = $Category
        Detail         = $Detail
        DurationMs     = $DurationMs
        Attempted      = $Attempted
        RebootRequired = $RebootRequired
    }

    if ((Get-Command -Name 'New-WacStepResult' -ErrorAction Stop).Parameters.ContainsKey('Outcome')) {
        $argument['Outcome'] = $Outcome
    }
    else {
        $argument['Succeeded'] = ($Outcome -eq 'Succeeded')
        $argument['Skipped']   = ($Outcome -eq 'SafeSkip')
        $argument['Failed']    = ($Outcome -eq 'Failed' -or $Outcome -eq 'Incomplete' -or $Outcome -eq 'SecurityRefusal')
    }

    $result = New-WacStepResult @argument
    if (-not (@($result.PSObject.Properties.Name) -ccontains 'Outcome')) {
        Add-Member -InputObject $result -MemberType NoteProperty -Name 'Outcome' -Value $Outcome
    }

    return $result
}

# ---------------------------------------------------------------------------------------------
# 2. pnpclean driver package handler
# ---------------------------------------------------------------------------------------------

function Get-WacDriverStoreSize {
    <#
    .SYNOPSIS
        File count and byte total of the driver store FileRepository.
    .DESCRIPTION
        This walks a very large tree, so it is only ever called when the caller explicitly asks for
        the measurement: taking it before AND after every pnpclean run cost real minutes for a
        diagnostic number nothing depended on.
    #>
    $repository = $null
    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $repository = Join-Path -Path $env:SystemRoot -ChildPath 'System32\DriverStore\FileRepository'
    }

    $result = [PSCustomObject]@{ Path = $repository; Files = 0L; Bytes = 0L; Measured = $false }
    if (-not $repository -or -not (Test-Path -LiteralPath $repository -PathType Container)) { return $result }

    try {
        $info = New-Object System.IO.DirectoryInfo((Get-WacLongPath -Path $repository))
        foreach ($file in $info.EnumerateFiles('*', [System.IO.SearchOption]::AllDirectories)) {
            if (Test-WacDeadlineExpired) { return $result }
            $result.Files++
            try { $result.Bytes += [int64]$file.Length } catch { $null = $_ }
        }
        $result.Measured = $true
    }
    catch {
        Write-WacLog -Level DEBUG -Component 'PnpClean' -Message 'The driver store could not be measured.' -Data @{ error = $_.Exception.Message }
    }

    return $result
}

function Invoke-WacPnpCleanHandler {
    <#
    .SYNOPSIS
        Runs the Windows driver package cleanup handler, bounded.
    .DESCRIPTION
        rundll32.exe <System32>\pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN. This entry point has
        no Microsoft reference page at all; it is used because it is the same handler the Disk
        Cleanup 'Device Driver Packages' category invokes, and it decides for itself what is safe to
        remove instead of this tool guessing.
    #>
    [CmdletBinding()]
    param([switch]$MeasureDriverStore)

    $category = 'Device driver packages (pnpclean)'
    $component = 'PnpClean'

    $rundll32 = Get-WacSystemToolPath -Leaf 'rundll32.exe'
    $pnpclean = Get-WacSystemToolPath -Leaf 'pnpclean.dll'
    if (-not $rundll32 -or -not $pnpclean) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'rundll32.exe or pnpclean.dll was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'The driver package cleanup handler requires administrator rights.'))
    }

    $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpCleanTimeoutMs
    if ($timeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -Detail 'The run budget was exhausted before pnpclean could start.'))
    }

    $before = $null
    if ($MeasureDriverStore) { $before = Get-WacDriverStoreSize }

    $arguments = @(('{0},RunDLL_PnpClean' -f $pnpclean), '/DRIVERS', '/MAXCLEAN')
    $run = Invoke-WacProcess -FilePath $rundll32 -ArgumentList $arguments -TimeoutMs $timeoutMs -Component $component

    if ($run.TimedOut) {
        # Killed on its deadline. It may have removed packages and it may not have, and nothing here
        # can tell which - that is precisely what Incomplete means.
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -Attempted $true -DurationMs ([int]$run.DurationMs) `
            -Detail ('pnpclean exceeded its {0} ms deadline and its process tree was terminated.' -f $timeoutMs)))
    }

    $detail = 'rundll32.exe exited with {0}.' -f $run.ExitCode

    if ($MeasureDriverStore -and $before -and $before.Measured) {
        $after = Get-WacDriverStoreSize
        if ($after.Measured) {
            $freed = [int64]($before.Bytes - $after.Bytes)
            $detail = '{0} Driver store change: {1}.' -f $detail, (Format-WacBytes -Bytes ([Math]::Max(0L, $freed)))
        }
    }

    $outcome = 'Failed'
    if ($run.ExitCode -eq 0) { $outcome = 'Succeeded' }

    return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
        -Outcome $outcome -Attempted $true -DurationMs ([int]$run.DurationMs) -Detail $detail))
}

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

# ---------------------------------------------------------------------------------------------
# 4. Recoverable backups
# ---------------------------------------------------------------------------------------------

function Get-WacDriverBackupIdentity {
    <#
    .SYNOPSIS
        The immutable backup directory name for a package, and the hash it is derived from. Pure.
    .DESCRIPTION
        oem<n>.inf is a RECYCLABLE name: the number is released when a package is removed and the
        next /add-driver can hand the same number to something completely unrelated. Naming an export
        directory after it lets a later run merge into - or overwrite - the only recoverable copy of
        an earlier deletion.

        The identity is therefore built from package data that does not move (original INF name,
        provider, class, extension, signer, exact version) and stamped with a SHA-256 of that same
        data. Two different packages cannot land in one directory, and the same package always lands
        in its own.
    #>
    param([Parameter(Mandatory = $true)]$Driver)

    $field = @(
        [string]$Driver.OriginalName,
        [string]$Driver.ProviderName,
        [string]$Driver.ClassGuid,
        [string]$Driver.ExtensionId,
        [string]$Driver.SignerName,
        [string]$Driver.VersionText,
        [string]$Driver.Version
    )
    $canonical = ($field -join '|').ToLowerInvariant()

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))
    }
    finally {
        $sha.Dispose()
    }
    $hash = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')

    # GetFileNameWithoutExtension throws on an invalid path character under .NET Framework, and
    # OriginalName is tool output. The hash already carries the identity, so the stem is only a
    # human-readable label and 'driver' is a perfectly good one.
    $stem = ''
    try { $stem = [System.IO.Path]::GetFileNameWithoutExtension([string]$Driver.OriginalName) }
    catch { $stem = '' }
    $stem = ($stem -replace '[^A-Za-z0-9._-]', '_')
    if ($stem.Length -gt 32) { $stem = $stem.Substring(0, 32) }
    if ([string]::IsNullOrWhiteSpace($stem)) { $stem = 'driver' }

    $version = (([string]$Driver.Version) -replace '[^0-9.]', '_')
    if ([string]::IsNullOrWhiteSpace($version)) { $version = '0' }

    return [PSCustomObject]@{
        Name      = ('{0}_{1}_{2}' -f $stem, $version, $hash.Substring(0, 16))
        Hash      = $hash
        Canonical = $canonical
    }
}

function Get-WacDriverBackupFileHash {
    <#
    .SYNOPSIS
        Every exported file under a backup directory with its size and SHA-256, ordered.
    .DESCRIPTION
        Ok is separate from an empty File list on purpose: a directory that could not be READ must
        never be mistaken for a directory that is empty, because one of those two answers is allowed
        to precede a deletion and the other is not.

        The manifest itself is excluded - it records this list, so it cannot be part of what it
        records. Paths are relative and ordinal-sorted so the same export hashes identically on both
        hosts.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    $result = [PSCustomObject]@{ Ok = $false; Reason = ''; File = @() }

    $root = Get-WacNormalizedPath -Path $Path
    if (-not $root) {
        $result.Reason = 'The backup directory path could not be normalised.'
        return $result
    }

    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        $result.Reason = 'The backup directory does not exist.'
        return $result
    }

    $prefix = Get-WacLongPath -Path $root
    $entry = New-Object 'System.Collections.Generic.List[object]'
    $sha = [System.Security.Cryptography.SHA256]::Create()

    try {
        $info = New-Object System.IO.DirectoryInfo($prefix)
        foreach ($file in $info.EnumerateFiles('*', [System.IO.SearchOption]::AllDirectories)) {
            $relative = [string]$file.FullName
            if ($relative.Length -gt $prefix.Length) {
                $relative = $relative.Substring($prefix.Length).TrimStart('\')
            }
            if ($relative -ieq $script:BackupManifestName) { continue }

            $stream = New-Object System.IO.FileStream($file.FullName, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                $bytes = $sha.ComputeHash($stream)
            }
            finally {
                $stream.Dispose()
            }

            [void]$entry.Add([PSCustomObject]@{
                Path   = $relative
                Bytes  = [int64]$file.Length
                Sha256 = (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
            })
        }
    }
    catch {
        # Classified, never caught by type: PowerShell wraps a .NET method exception in
        # MethodInvocationException and the two hosts disagree about typed clauses.
        $result.Reason = 'The backup directory could not be read ({0}): {1}' -f (Get-WacIoFailureKind -ErrorRecord $_), $_.Exception.Message
        return $result
    }
    finally {
        $sha.Dispose()
    }

    $result.Ok = $true
    $result.File = @(@($entry.ToArray()) | Sort-Object -Property { [string]$_.Path })
    return $result
}

function New-WacDriverBackupManifest {
    <#
    .SYNOPSIS
        The record written beside an export: what was deleted, why it was safe, and what was kept.
    .DESCRIPTION
        The manifest is the only thing that maps a content-addressed backup directory back to the
        oem<n>.inf it came from, and the only record of the evidence the deletion rested on. Both
        matter for recovery: the number is reusable, the evidence is not reconstructible afterwards.

        It is also what the collision guard reads. DeletedUtc is written here as empty and stamped
        only once pnputil has really removed the package, so the manifest states which of the two
        things a directory is: the only copy of a package that is gone, or an export of a package
        that is still installed.
    #>
    param(
        [Parameter(Mandatory = $true)]$Driver,
        [Parameter(Mandatory = $true)]$Identity,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$File,
        [int]$EnumeratedPackage = 0
    )

    $list = @($File)
    $total = 0L
    foreach ($item in $list) { $total += [int64]$item.Bytes }

    $supersededByName = ''
    $supersededByVersion = ''
    if (@($Driver.PSObject.Properties.Name) -ccontains 'SupersededByName') { $supersededByName = [string]$Driver.SupersededByName }
    if (@($Driver.PSObject.Properties.Name) -ccontains 'SupersededByVersion') { $supersededByVersion = [string]$Driver.SupersededByVersion }

    return [PSCustomObject]@{
        Schema       = $script:BackupManifestSchema
        CreatedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        # Empty until the deletion this export exists for actually happens. Until then the package
        # is still in the store, so this directory is a copy of something, not the only copy of it.
        DeletedUtc   = ''
        ExecutionId  = [string](Get-WacExecutionId)
        DriverName   = [string]$Driver.DriverName
        OriginalName = [string]$Driver.OriginalName
        ProviderName = [string]$Driver.ProviderName
        ClassGuid    = [string]$Driver.ClassGuid
        ExtensionId  = [string]$Driver.ExtensionId
        SignerName   = [string]$Driver.SignerName
        VersionText  = [string]$Driver.VersionText
        Version      = [string]$Driver.Version
        IdentityName = [string]$Identity.Name
        IdentityHash = [string]$Identity.Hash
        Evidence     = [PSCustomObject]@{
            Command             = ('pnputil {0}' -f ($script:PnpUtilEnumArgument -join ' '))
            DeviceCount         = [int]$Driver.DeviceCount
            SupersededByName    = $supersededByName
            SupersededByVersion = $supersededByVersion
            EnumeratedPackage   = $EnumeratedPackage
        }
        FileCount    = $list.Count
        TotalBytes   = $total
        File         = $list
    }
}

function Test-WacDriverBackupIntact {
    <#
    .SYNOPSIS
        Re-hashes an export and compares it to the manifest that recorded it.
    .DESCRIPTION
        Run immediately before the deletion. Anything that changed the export between writing the
        manifest and removing the package - a file gone, a byte different, a file added - means the
        recoverable copy is not the copy that was verified, and the deletion must not go ahead.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $result = [PSCustomObject]@{ Intact = $false; Reason = '' }

    $current = Get-WacDriverBackupFileHash -Path $Path
    if (-not $current.Ok) {
        $result.Reason = $current.Reason
        return $result
    }

    $recorded = @($Manifest.File)
    $observed = @($current.File)

    if ($recorded.Count -ne $observed.Count) {
        $result.Reason = 'the export holds {0} file(s), the manifest recorded {1}' -f $observed.Count, $recorded.Count
        return $result
    }

    for ($i = 0; $i -lt $recorded.Count; $i++) {
        if ([string]$recorded[$i].Path -ine [string]$observed[$i].Path) {
            $result.Reason = 'expected {0}, found {1}' -f $recorded[$i].Path, $observed[$i].Path
            return $result
        }
        if ([int64]$recorded[$i].Bytes -ne [int64]$observed[$i].Bytes) {
            $result.Reason = '{0} is {1} byte(s), the manifest recorded {2}' -f $observed[$i].Path, $observed[$i].Bytes, $recorded[$i].Bytes
            return $result
        }
        if ([string]$recorded[$i].Sha256 -ine [string]$observed[$i].Sha256) {
            $result.Reason = '{0} does not match its recorded SHA-256' -f $observed[$i].Path
            return $result
        }
    }

    $result.Intact = $true
    return $result
}

function Test-WacDriverBackupIsResidue {
    <#
    .SYNOPSIS
        Tells this tool's own leftovers apart from the only copy of a package that really was deleted.
    .DESCRIPTION
        The backup root is PERSISTENT, so whatever a run leaves behind is what every later run walks
        into, and a guard that refuses every existing directory refuses that package forever.

        Residue is a directory whose export or whose deletion never completed: a failed or killed
        export, a manifest that was never written, or a deletion pnputil declined. In every one of
        those the package is still in the driver store - which is the only reason it can be a
        candidate again today - so the directory is not the only copy of anything and reclaiming it
        destroys nothing.

        A manifest carrying DeletedUtc is the opposite, because that stamp is written only after the
        package really was removed. Anything else unreadable is treated as an export that never
        finished, EXCEPT a manifest belonging to a different package: that is not ours to explain
        away by deleting it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Identity
    )

    $result = [PSCustomObject]@{ IsResidue = $true; Reason = 'it carries no backup manifest, so an earlier export never completed' }

    $manifestPath = Join-Path -Path $Path -ChildPath $script:BackupManifestName
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { return $result }

    $manifest = $null
    try {
        $manifest = [System.IO.File]::ReadAllText((Get-WacLongPath -Path $manifestPath)) | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $result.Reason = 'its manifest is not readable JSON, so an earlier export never completed'
        return $result
    }

    # Read defensively: this is a file on disk, and under Set-StrictMode 2.0 an absent property
    # throws rather than returning empty.
    $property = @()
    if ($null -ne $manifest) { $property = @($manifest.PSObject.Properties.Name) }

    if ($property -cnotcontains 'IdentityHash') {
        $result.Reason = 'its manifest records no package identity, so an earlier export never completed'
        return $result
    }

    if ([string]$manifest.IdentityHash -ine [string]$Identity.Hash) {
        $result.IsResidue = $false
        $result.Reason = 'its manifest records a different package identity'
        return $result
    }

    if ($property -cnotcontains 'DeletedUtc' -or [string]::IsNullOrWhiteSpace([string]$manifest.DeletedUtc)) {
        $result.Reason = 'its manifest records no completed deletion, so the package it holds is still installed'
        return $result
    }

    # Measured on both shipped hosts, and it is the opposite way round from what an earlier comment
    # here claimed: Windows PowerShell 5.1 leaves an ISO-8601 string as a System.String, while
    # PowerShell 7 parses it into a System.DateTime with Kind=Utc. So the raw value renders
    # differently on the two hosts, and only the PowerShell 7 shape needs normalising back.
    $stamp = $manifest.DeletedUtc
    if ($stamp -is [datetime]) { $stamp = $stamp.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

    $result.IsResidue = $false
    $result.Reason = 'its manifest records the deletion of that package on {0}' -f [string]$stamp
    return $result
}

function Remove-WacDriverBackupDirectory {
    <#
    .SYNOPSIS
        Removes one export directory this module owns. True when nothing is left at the path.
    .DESCRIPTION
        Directory.Delete's recursive form is used rather than Remove-Item -Recurse, which does not
        reliably stop at a reparse point under Windows PowerShell 5.1. Measured on both hosts
        against a junction planted inside the directory: the junction is unlinked, its TARGET is
        left completely untouched, and the call then throws UnauthorizedAccessException - so the
        worst case here is a directory that stays and a package that is never pruned, never a
        deletion that walked out of the backup root. The root itself is refused outright when it is
        a link, because an export directory this module created never is one.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    if (Test-WacIsReparsePoint -Path $Path) { return $false }

    try {
        [System.IO.Directory]::Delete((Get-WacLongPath -Path $Path), $true)
    }
    catch {
        # A locked or denied directory is reported by what is still there, not by the exception:
        # the caller only ever needs to know whether the path is clear.
        return (-not (Test-Path -LiteralPath $Path))
    }

    return (-not (Test-Path -LiteralPath $Path))
}

function Complete-WacDriverBackup {
    <#
    .SYNOPSIS
        Stamps the deletion into the manifest, which is what turns an export into a backup.
    .DESCRIPTION
        Called only once pnputil has really removed the package. Before the stamp the directory is a
        copy of something still installed and a later run may reclaim it; after it, the directory is
        the only way back and the collision guard refuses to touch it.

        It rewrites the object THIS run built rather than re-reading the file. Measured on both
        hosts: ConvertFrom-Json leaves an ISO-8601 string alone on Windows PowerShell 5.1 but parses
        it into a [datetime] on PowerShell 7, so a read-modify-write would round-trip CreatedUtc
        through a different type on one host and could rewrite it in another form.
        Rewriting the manifest is otherwise free - it is excluded from the hash list it records, and
        the verification the deletion rested on has already happened.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Manifest
    )

    $manifestPath = Get-WacLongPath -Path (Join-Path -Path $Path -ChildPath $script:BackupManifestName)

    try {
        $Manifest.DeletedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        [System.IO.File]::WriteAllText($manifestPath, ($Manifest | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    }
    catch {
        return $false
    }

    return $true
}

function Export-WacDriverBackup {
    <#
    .SYNOPSIS
        Exports one package into its own immutable directory and proves the copy before returning.
    .DESCRIPTION
        Everything a deletion depends on happens here, and every failure mode ends with the package
        still installed:

          collision  - the identity directory already holds a backup whose manifest records a
                       completed deletion. REFUSED, never merged or overwritten: that directory is
                       the only copy of a package that is gone. The same directory WITHOUT that
                       record is this tool's own residue and is reclaimed instead, because the
                       package it holds is still installed.
          containment- the identity directory would fall outside the backup root. REFUSED.
          timeout    - the export was killed on its deadline, so what is on disk is unknown.
          empty      - /export-driver reported success and produced no .inf. Nothing recoverable.
          mismatch   - the export changed between being hashed and being trusted.

        Only an Outcome of Succeeded may be followed by a deletion.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PnpUtil,
        [Parameter(Mandatory = $true)]$Driver,
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [int]$EnumeratedPackage = 0,
        [string]$Component = 'DriverPrune'
    )

    $result = [PSCustomObject]@{ Outcome = 'SafeSkip'; Reason = ''; Directory = ''; FileCount = 0; Manifest = $null }

    $identity = Get-WacDriverBackupIdentity -Driver $Driver
    $directory = Get-WacNormalizedPath -Path (Join-Path -Path $BackupRoot -ChildPath $identity.Name)
    if (-not $directory) {
        $result.Reason = 'the export directory path could not be normalised'
        return $result
    }

    if (-not (Test-WacIsWithinRoot -ChildPath $directory -RootPath $BackupRoot)) {
        # The identity is built from tool output, so it is untrusted input until this passes.
        $result.Outcome = 'SecurityRefusal'
        $result.Reason = 'the export directory resolved outside the backup root'
        return $result
    }
    $result.Directory = $directory

    if (Test-Path -LiteralPath $directory) {
        # The root is persistent, so refusing on sight refused this package on every later run - and
        # the two states that got it there, a declined deletion and a failed export, are both
        # benign. Only a directory that is the only copy of something may refuse.
        $residue = Test-WacDriverBackupIsResidue -Path $directory -Identity $identity
        if (-not $residue.IsResidue) {
            $result.Outcome = 'SecurityRefusal'
            $result.Reason = 'an export directory with the same package identity already exists and {0}, so overwriting it could destroy the only copy of an earlier deletion' -f $residue.Reason
            return $result
        }

        if (-not (Remove-WacDriverBackupDirectory -Path $directory)) {
            $result.Reason = 'an earlier export left a directory that could not be reclaimed ({0})' -f $residue.Reason
            return $result
        }

        Write-WacLog -Level INFO -Component $Component -Message 'Reclaimed the directory an earlier export left behind.' -Data @{
            driver = [string]$Driver.DriverName; directory = $directory; reason = $residue.Reason
        }
    }

    try {
        # No -Force: an existing directory must fail here rather than be silently adopted.
        [void](New-Item -Path $directory -ItemType Directory -ErrorAction Stop)
    }
    catch {
        $result.Reason = 'the export directory could not be created ({0}): {1}' -f (Get-WacIoFailureKind -ErrorRecord $_), $_.Exception.Message
        return $result
    }

    try {
        $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
        if ($timeoutMs -le 0) {
            $result.Outcome = 'Incomplete'
            $result.Reason = 'the run budget was exhausted before the export could start'
            return $result
        }

        $export = Invoke-WacProcess -FilePath $PnpUtil -ArgumentList @('/export-driver', [string]$Driver.DriverName, $directory) `
            -TimeoutMs $timeoutMs -Component $Component

        if ($export.TimedOut) {
            $result.Outcome = 'Incomplete'
            $result.Reason = 'the export exceeded its deadline and its process tree was terminated'
            return $result
        }

        if ($script:PnpUtilSuccessCode -notcontains $export.ExitCode) {
            $result.Reason = 'the export exited with {0}' -f $export.ExitCode
            return $result
        }

        $hashed = Get-WacDriverBackupFileHash -Path $directory
        if (-not $hashed.Ok) {
            $result.Reason = $hashed.Reason
            return $result
        }

        $file = @($hashed.File)
        $inf = @($file | Where-Object { [string]$_.Path -match '(?i)\.inf$' })
        if ($file.Count -eq 0 -or $inf.Count -eq 0) {
            $result.Reason = 'the export reported success but left no .inf behind, so nothing is recoverable'
            return $result
        }

        $manifest = New-WacDriverBackupManifest -Driver $Driver -Identity $identity -File $file -EnumeratedPackage $EnumeratedPackage

        try {
            $json = $manifest | ConvertTo-Json -Depth 6
            $manifestPath = Join-Path -Path $directory -ChildPath $script:BackupManifestName
            [System.IO.File]::WriteAllText((Get-WacLongPath -Path $manifestPath), $json, (New-Object System.Text.UTF8Encoding($false)))
        }
        catch {
            $result.Reason = 'the backup manifest could not be written ({0}): {1}' -f (Get-WacIoFailureKind -ErrorRecord $_), $_.Exception.Message
            return $result
        }

        $intact = Test-WacDriverBackupIntact -Path $directory -Manifest $manifest
        if (-not $intact.Intact) {
            $result.Outcome = 'SecurityRefusal'
            $result.Reason = 'the export did not match its own manifest ({0})' -f $intact.Reason
            return $result
        }

        $result.Outcome = 'Succeeded'
        $result.FileCount = $file.Count
        $result.Manifest = $manifest
        return $result
    }
    finally {
        # Nothing that fails to reach Succeeded deleted anything, so the directory is a copy of a
        # package that is still installed - worth nothing, and in the way of every later run.
        if ($result.Outcome -cne 'Succeeded') { [void](Remove-WacDriverBackupDirectory -Path $directory) }
    }
}

function Invoke-WacDriverPackagePrune {
    <#
    .SYNOPSIS
        Exports and then deletes driver packages that are superseded AND installed on nothing.
        Disabled by default.
    .DESCRIPTION
        Off unless the caller passes -Enabled: a wrong decision here removes a driver the machine
        needs, and the driver store documentation says staged files should not be modified
        programmatically at all.

        The whole step fails closed. If the structured enumeration is unavailable, malformed, or
        carries no device associations, nothing is deleted and the step safe-skips - the localized
        text output is never parsed as a fallback because Microsoft documents it as changeable and
        localized. Every surviving candidate is exported into a content-addressed directory and that
        copy is proved before its package is removed.

        /force, /uninstall and /reboot are never passed: they would delete a package in use, rip a
        driver off live devices, or restart the machine.
    #>
    [CmdletBinding()]
    param(
        [switch]$Enabled,
        [string]$BackupRoot
    )

    $category = 'Superseded driver packages (pnputil)'
    $component = 'DriverPrune'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    if (-not $Enabled) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'Driver package pruning is disabled by default; pass -Enabled to opt in.'))
    }

    $pnputil = Get-WacSystemToolPath -Leaf 'pnputil.exe'
    if (-not $pnputil) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'pnputil.exe was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'Driver package pruning requires administrator rights.'))
    }

    # No recoverable backup means no deletion. This is the fail-closed condition for the whole step.
    if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'No -BackupRoot was supplied, so no package can be exported before deletion.'))
    }

    $normalizedBackupRoot = Get-WacNormalizedPath -Path $BackupRoot
    if (-not $normalizedBackupRoot) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'The -BackupRoot path could not be normalised.'))
    }

    try {
        if (-not (Test-Path -LiteralPath $normalizedBackupRoot -PathType Container)) {
            [void](New-Item -Path $normalizedBackupRoot -ItemType Directory -Force -ErrorAction Stop)
        }
    }
    catch {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('The backup directory could not be created ({0}): {1}' -f (Get-WacIoFailureKind -ErrorRecord $_), $_.Exception.Message)))
    }

    $enumTimeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
    if ($enumTimeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail 'The run budget was exhausted before pnputil could start.'))
    }

    $enum = Invoke-WacProcess -FilePath $pnputil -ArgumentList $script:PnpUtilEnumArgument -TimeoutMs $enumTimeoutMs -Component $component

    if ($enum.TimedOut) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -Attempted $true -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail 'The driver enumeration exceeded its deadline and its process tree was terminated; nothing was pruned.'))
    }

    if ($script:PnpUtilSuccessCode -notcontains $enum.ExitCode) {
        # An older pnputil rejects an argument it does not know and prints its usage, so a non-zero
        # exit IS the feature detection for /devices and /format. Nothing is assumed from a version.
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('Structured driver enumeration is unavailable (pnputil exited with {0}); pruning was skipped.' -f $enum.ExitCode)))
    }

    $parsed = ConvertFrom-WacPnpUtilDriverXml -Text ([string]$enum.StandardOutput)
    if (-not $parsed.IsValid -or -not $parsed.HasDeviceEvidence) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('{0} Pruning was skipped.' -f $parsed.Reason)))
    }

    $enumerated = @($parsed.Driver).Count
    $candidates = @(Get-WacSupersededDriver -Driver $parsed.Driver)
    if ($candidates.Count -eq 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Succeeded' -Attempted $true -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('{0} driver package(s) enumerated, {1} dropped as incomplete; no package is both superseded and installed on nothing.' -f $enumerated, $parsed.DroppedRow)))
    }

    Write-WacLog -Level INFO -Component $component -Message 'Superseded driver packages found.' -Data @{
        candidates = $candidates.Count; enumerated = $enumerated; dropped = $parsed.DroppedRow
    }

    $deleted = 0
    $skipped = 0
    $refused = 0
    $incomplete = 0
    $rebootRequired = $false
    $outcome = 'Succeeded'

    foreach ($candidate in $candidates) {
        if (Test-WacDeadlineExpired) {
            $remaining = $candidates.Count - $deleted - $skipped - $refused - $incomplete
            $incomplete += $remaining
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
            Write-WacLog -Level WARNING -Component $component -Message 'The run deadline expired mid-prune.' -Data @{ remaining = $remaining }
            break
        }

        $backup = Export-WacDriverBackup -PnpUtil $pnputil -Driver $candidate -BackupRoot $normalizedBackupRoot `
            -EnumeratedPackage $enumerated -Component $component

        if ($backup.Outcome -cne 'Succeeded') {
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate $backup.Outcome
            if ($backup.Outcome -ceq 'SecurityRefusal') { $refused++ }
            elseif ($backup.Outcome -ceq 'Incomplete') { $incomplete++ }
            else { $skipped++ }

            $level = 'WARNING'
            if ($backup.Outcome -ceq 'SecurityRefusal') { $level = 'ERROR' }
            Write-WacLog -Level $level -Component $component -Message 'The package was left in place because its backup could not be trusted.' -Data @{
                driver = $candidate.DriverName; outcome = $backup.Outcome; reason = $backup.Reason; directory = $backup.Directory
            }
            continue
        }

        $deleteTimeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
        if ($deleteTimeoutMs -le 0) {
            $incomplete++
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
            continue
        }

        # Never /force, /uninstall or /reboot.
        $delete = Invoke-WacProcess -FilePath $pnputil -ArgumentList @('/delete-driver', [string]$candidate.DriverName) `
            -TimeoutMs $deleteTimeoutMs -Component $component

        if ($delete.TimedOut) {
            $incomplete++
            $outcome = Get-WacHigherOutcome -Current $outcome -Candidate 'Incomplete'
            Write-WacLog -Level WARNING -Component $component -Message 'The deletion exceeded its deadline, so whether the package was removed is unknown.' -Data @{
                driver = $candidate.DriverName; backup = $backup.Directory
            }
            continue
        }

        if ($script:PnpUtilSuccessCode -contains $delete.ExitCode) {
            $deleted++
            if ($script:PnpUtilRebootCode -contains $delete.ExitCode) { $rebootRequired = $true }

            # The stamp is what makes this directory a backup rather than a copy: from here the
            # package is gone and no later run may overwrite it.
            if (-not (Complete-WacDriverBackup -Path $backup.Directory -Manifest $backup.Manifest)) {
                Write-WacLog -Level WARNING -Component $component -Message 'The deletion could not be recorded in the backup manifest.' -Data @{
                    driver = $candidate.DriverName; backup = $backup.Directory
                }
            }
            Write-WacLog -Level INFO -Component $component -Message 'Removed a superseded driver package.' -Data @{
                driver = $candidate.DriverName; original = $candidate.OriginalName; version = [string]$candidate.Version
                supersededBy = $candidate.SupersededByName; exitCode = $delete.ExitCode
                backup = $backup.Directory; backupFiles = $backup.FileCount
            }
        }
        elseif ($script:PnpUtilBenignCode -contains $delete.ExitCode) {
            $skipped++
        }
        else {
            # pnputil refuses a package that is still in use. That is the protection working - and
            # because the package stayed, its export is a copy of something, not the only copy of
            # it. Keeping it would cost the space and collide with every later run.
            [void](Remove-WacDriverBackupDirectory -Path $backup.Directory)
            Write-WacLog -Level INFO -Component $component -Message 'pnputil declined to remove a package.' -Data @{ driver = $candidate.DriverName; exitCode = $delete.ExitCode }
            $skipped++
        }
    }

    $stopwatch.Stop()
    return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
        -Outcome $outcome -Attempted $true -RebootRequired $rebootRequired `
        -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
        -Detail ('candidates={0} deleted={1} skipped={2} refused={3} incomplete={4} enumerated={5} backup={6}' -f `
            $candidates.Count, $deleted, $skipped, $refused, $incomplete, $enumerated, $normalizedBackupRoot)))
}

Export-ModuleMember -Function @(
    'Get-WacDriverStoreSize', 'Invoke-WacPnpCleanHandler',
    'Get-WacDriverVersionPart', 'ConvertFrom-WacPnpUtilDriverXml', 'Get-WacSupersededDriver',
    'Get-WacDriverBackupIdentity', 'Get-WacDriverBackupFileHash', 'New-WacDriverBackupManifest',
    'Test-WacDriverBackupIntact', 'Test-WacDriverBackupIsResidue',
    'Export-WacDriverBackup', 'Invoke-WacDriverPackagePrune'
)
