<#
.SYNOPSIS
    Driver-store cleanup: the Windows pnpclean handler and opt-in superseded-package pruning.

.DESCRIPTION
    Split out of WindowsAutoCleanup.Steps.psm1 because the driver store is its own domain with its
    own risk profile: everything here talks to the pnp subsystem, parses an UNDOCUMENTED pnputil
    output shape, and can remove a package the machine still needs. Keeping it separate means the
    riskiest code in the project can be reviewed and tested on its own.

    Microsoft's driver-store documentation states that staged files "shouldn't be removed or modified
    in any way", and there is no reference page for pnpclean.dll at all. Both mechanisms are
    therefore treated as best-effort, and package pruning is off unless the caller opts in.
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

# Parsed by header name, never by ordinal: no Microsoft page names any /enum-drivers output field,
# so the column set is undocumented and may move between builds.
$script:PnpUtilRequiredColumn = @(
    'DriverName', 'OriginalName', 'ProviderName', 'ClassGuid', 'ExtensionId', 'DriverVersion', 'SignerName'
)

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
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'rundll32.exe or pnpclean.dll was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'The driver package cleanup handler requires administrator rights.'))
    }

    $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpCleanTimeoutMs
    if ($timeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'The run budget was exhausted before pnpclean could start.'))
    }

    $before = if ($MeasureDriverStore) { Get-WacDriverStoreSize } else { $null }

    $arguments = @(('{0},RunDLL_PnpClean' -f $pnpclean), '/DRIVERS', '/MAXCLEAN')
    $run = Invoke-WacProcess -FilePath $rundll32 -ArgumentList $arguments -TimeoutMs $timeoutMs -Component $component

    if ($run.TimedOut) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Failed $true -DurationMs ([int]$run.DurationMs) -Detail ('pnpclean exceeded its {0} ms deadline and its process tree was terminated.' -f $timeoutMs)))
    }

    $detail = 'rundll32.exe exited with {0}.' -f $run.ExitCode

    if ($MeasureDriverStore -and $before -and $before.Measured) {
        $after = Get-WacDriverStoreSize
        if ($after.Measured) {
            $freed = [int64]($before.Bytes - $after.Bytes)
            $detail = '{0} Driver store change: {1}.' -f $detail, (Format-WacBytes -Bytes ([Math]::Max(0L, $freed)))
        }
    }

    if ($run.ExitCode -eq 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Succeeded $true -DurationMs ([int]$run.DurationMs) -Detail $detail))
    }

    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Failed $true -DurationMs ([int]$run.DurationMs) -Detail $detail))
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

function ConvertFrom-WacPnpUtilCsv {
    <#
    .SYNOPSIS
        Parses 'pnputil /enum-drivers /format csv' output. Pure: no pnputil required.
    .DESCRIPTION
        /format is documented only for /enum-containers, so its use with /enum-drivers is
        undocumented: it works on current builds but carries no minimum-version or column-stability
        guarantee. This function therefore validates the header by NAME and reports exactly which
        required columns are missing, so the caller can fail closed instead of guessing. The
        localized text output is never parsed - it is English-only and produced wrong dates.
    .OUTPUTS
        IsValid, MissingColumn, Reason, Driver (DriverName, OriginalName, ProviderName, ClassGuid,
        ExtensionId, SignerName, Version, VersionText, Key).
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text)

    $result = [PSCustomObject]@{
        IsValid       = $false
        MissingColumn = @()
        Reason        = ''
        Driver        = @()
    }

    if ([string]::IsNullOrWhiteSpace($Text)) {
        $result.Reason = 'pnputil produced no output.'
        return $result
    }

    $lines = @($Text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $headerIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match ',' -and $lines[$i] -match '(?i)DriverName') { $headerIndex = $i; break }
    }

    if ($headerIndex -lt 0) {
        $result.Reason = 'No CSV header row was found in the pnputil output.'
        return $result
    }

    # Column names never contain a comma, so splitting the header is sufficient and avoids depending
    # on ConvertFrom-Csv having produced at least one data row before the header can be inspected.
    $headerField = @($lines[$headerIndex] -split ',' | ForEach-Object { $_.Trim().Trim('"').Trim() })
    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($required in $script:PnpUtilRequiredColumn) {
        $present = $false
        foreach ($field in $headerField) {
            if ($field -ieq $required) { $present = $true; break }
        }
        if (-not $present) { [void]$missing.Add($required) }
    }

    if ($missing.Count -gt 0) {
        $result.MissingColumn = @($missing.ToArray())
        $result.Reason = 'The pnputil CSV header is missing required columns: {0}.' -f (($missing.ToArray()) -join ', ')
        return $result
    }

    $csvText = ($lines[$headerIndex..($lines.Count - 1)] -join [Environment]::NewLine)
    try {
        $rows = @(($csvText | ConvertFrom-Csv -ErrorAction Stop))
    }
    catch {
        $result.Reason = 'The pnputil CSV could not be parsed: {0}' -f $_.Exception.Message
        return $result
    }

    $drivers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $rows) {
        $driverName = ([string]$row.DriverName).Trim()
        if ([string]::IsNullOrWhiteSpace($driverName)) { continue }

        $versionText = ([string]$row.DriverVersion).Trim()
        $version = Get-WacDriverVersionPart -Text $versionText
        if (-not $version) { continue }

        $originalName = ([string]$row.OriginalName).Trim()
        $providerName = ([string]$row.ProviderName).Trim()
        $classGuid    = ([string]$row.ClassGuid).Trim()
        $extensionId  = ([string]$row.ExtensionId).Trim()
        $signerName   = ([string]$row.SignerName).Trim()

        [void]$drivers.Add([PSCustomObject]@{
            DriverName   = $driverName
            OriginalName = $originalName
            ProviderName = $providerName
            ClassGuid    = $classGuid
            ExtensionId  = $extensionId
            SignerName   = $signerName
            Version      = $version
            VersionText  = $versionText
            Key          = (@($originalName, $classGuid, $extensionId, $providerName, $signerName) -join '|').ToLowerInvariant()
        })
    }

    $result.IsValid = $true
    $result.Driver = @($drivers.ToArray())
    return $result
}

function Get-WacSupersededDriver {
    <#
    .SYNOPSIS
        The strictly-older driver packages in each equivalence group. Pure: no pnputil required.
    .DESCRIPTION
        The equivalence key is OriginalName + ClassGuid + ExtensionId + ProviderName + SignerName.
        The previous key (INF name + class + provider) merged packages that differ by class GUID,
        extension or signer and could therefore delete a needed package.

        Only published oem<n>.inf packages are considered - those are the ones /delete-driver
        accepts - and only versions strictly BELOW the highest version in the group are returned, so
        a group whose top version is shared keeps every member.
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
            if ($null -eq $highest -or $member.Version -gt $highest) { $highest = $member.Version }
        }

        foreach ($member in $group.Group) {
            if ($member.Version -lt $highest) { [void]$candidates.Add($member) }
        }
    }

    return @($candidates.ToArray())
}

function Invoke-WacDriverPackagePrune {
    <#
    .SYNOPSIS
        Exports and then deletes superseded oem<n>.inf driver packages. Disabled by default.
    .DESCRIPTION
        Off unless the caller passes -Enabled: a wrong equivalence decision here removes a driver the
        machine needs, and the driver store documentation says staged files should not be modified
        programmatically at all.

        Enumeration probes the undocumented '/enum-drivers /format csv' switch. A bad exit code or a
        missing required column skips pruning entirely - the localized text output is never used as
        a fallback because it is English-only and produced wrong dates.

        Every candidate is exported with /export-driver before deletion, so a wrong decision is
        recoverable. /force, /uninstall and /reboot are never passed: they would delete a package in
        use, rip a driver off live devices, or restart the machine.
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
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'Driver package pruning is disabled by default; pass -Enabled to opt in.'))
    }

    $pnputil = Get-WacSystemToolPath -Leaf 'pnputil.exe'
    if (-not $pnputil) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'pnputil.exe was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'Driver package pruning requires administrator rights.'))
    }

    # No recoverable backup means no deletion. This is the fail-closed condition for the whole step.
    if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'No -BackupRoot was supplied, so no package can be exported before deletion.'))
    }

    $normalizedBackupRoot = Get-WacNormalizedPath -Path $BackupRoot
    if (-not $normalizedBackupRoot) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'The -BackupRoot path could not be normalised.'))
    }

    try {
        if (-not (Test-Path -LiteralPath $normalizedBackupRoot -PathType Container)) {
            [void](New-Item -Path $normalizedBackupRoot -ItemType Directory -Force -ErrorAction Stop)
        }
    }
    catch {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail ('The backup directory could not be created: {0}' -f $_.Exception.Message)))
    }

    $enumTimeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
    if ($enumTimeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -Detail 'The run budget was exhausted before pnputil could start.'))
    }

    $enum = Invoke-WacProcess -FilePath $pnputil -ArgumentList @('/enum-drivers', '/format', 'csv') -TimeoutMs $enumTimeoutMs -Component $component
    if ($enum.TimedOut -or ($script:PnpUtilSuccessCode -notcontains $enum.ExitCode)) {
        $reason = if ($enum.TimedOut) { 'it exceeded its deadline' } else { 'it exited with {0}' -f $enum.ExitCode }
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('Structured driver enumeration is unavailable ({0}); pruning was skipped.' -f $reason)))
    }

    $parsed = ConvertFrom-WacPnpUtilCsv -Text ([string]$enum.StandardOutput)
    if (-not $parsed.IsValid) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Skipped $true -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('{0} Pruning was skipped.' -f $parsed.Reason)))
    }

    $candidates = @(Get-WacSupersededDriver -Driver $parsed.Driver)
    if ($candidates.Count -eq 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true -Succeeded $true -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
            -Detail ('{0} driver package(s) enumerated; none superseded.' -f $parsed.Driver.Count)))
    }

    Write-WacLog -Level INFO -Component $component -Message 'Superseded driver packages found.' -Data @{ candidates = $candidates.Count; enumerated = $parsed.Driver.Count }

    $deleted = 0
    $skipped = 0
    $failed = 0
    $rebootRequired = $false

    foreach ($candidate in $candidates) {
        if (Test-WacDeadlineExpired) { $skipped += ($candidates.Count - $deleted - $skipped - $failed); break }

        $exportDirectory = Join-Path -Path $normalizedBackupRoot -ChildPath $candidate.DriverName
        try {
            if (-not (Test-Path -LiteralPath $exportDirectory -PathType Container)) {
                [void](New-Item -Path $exportDirectory -ItemType Directory -Force -ErrorAction Stop)
            }
        }
        catch {
            Write-WacLog -Level WARNING -Component $component -Message 'Could not create an export directory; the package was left in place.' -Data @{ driver = $candidate.DriverName; error = $_.Exception.Message }
            $skipped++
            continue
        }

        $exportTimeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
        if ($exportTimeoutMs -le 0) { $skipped++; continue }

        $export = Invoke-WacProcess -FilePath $pnputil -ArgumentList @('/export-driver', $candidate.DriverName, $exportDirectory) -TimeoutMs $exportTimeoutMs -Component $component
        if ($export.TimedOut -or ($script:PnpUtilSuccessCode -notcontains $export.ExitCode)) {
            Write-WacLog -Level WARNING -Component $component -Message 'Export failed, so the package was not deleted.' -Data @{ driver = $candidate.DriverName; exitCode = $export.ExitCode; timedOut = $export.TimedOut }
            $skipped++
            continue
        }

        $deleteTimeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpUtilTimeoutMs
        if ($deleteTimeoutMs -le 0) { $skipped++; continue }

        # Never /force, /uninstall or /reboot.
        $delete = Invoke-WacProcess -FilePath $pnputil -ArgumentList @('/delete-driver', $candidate.DriverName) -TimeoutMs $deleteTimeoutMs -Component $component

        if ($delete.TimedOut) {
            $failed++
            continue
        }

        if ($script:PnpUtilSuccessCode -contains $delete.ExitCode) {
            $deleted++
            if ($script:PnpUtilRebootCode -contains $delete.ExitCode) { $rebootRequired = $true }
            Write-WacLog -Level INFO -Component $component -Message 'Removed a superseded driver package.' -Data @{
                driver = $candidate.DriverName; original = $candidate.OriginalName; version = $candidate.Version.ToString(); exitCode = $delete.ExitCode
            }
        }
        elseif ($script:PnpUtilBenignCode -contains $delete.ExitCode) {
            $skipped++
        }
        else {
            # pnputil refuses a package that is still in use. That is the protection working.
            Write-WacLog -Level INFO -Component $component -Message 'pnputil declined to remove a package.' -Data @{ driver = $candidate.DriverName; exitCode = $delete.ExitCode }
            $skipped++
        }
    }

    $stopwatch.Stop()
    return (Write-WacStepResult -Component $component -Result (New-WacStepResult -Category $category -Attempted $true `
        -Succeeded ($failed -eq 0) -Failed ($failed -gt 0) -RebootRequired $rebootRequired `
        -DurationMs ([int]$stopwatch.Elapsed.TotalMilliseconds) `
        -Detail ('candidates={0} deleted={1} skipped={2} failed={3} backup={4}' -f $candidates.Count, $deleted, $skipped, $failed, $normalizedBackupRoot)))
}

Export-ModuleMember -Function @(
    'Get-WacDriverStoreSize', 'Invoke-WacPnpCleanHandler',
    'Get-WacDriverVersionPart', 'ConvertFrom-WacPnpUtilCsv', 'Get-WacSupersededDriver',
    'Invoke-WacDriverPackagePrune'
)
