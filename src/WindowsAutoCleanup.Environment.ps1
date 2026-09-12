<#
.SYNOPSIS
    Facts about the machine this run is executing on: privilege, OS edition, system drive, the
    canonical PowerShell host, real user profiles and free space.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1; see that file for why the parts are dot-sourced
    rather than imported. These answer "what is this machine" rather than "may this path be
    trusted"; the ACL rules that answer the second question are in
    WindowsAutoCleanup.Trust.ps1, and the two call each other in both directions.
#>

# ---------------------------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------------------------

function Test-WacIsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-WacIsWindowsServer {
    <#
    .SYNOPSIS
        Whether this is a Server SKU, read from the local registry rather than through CIM.
    .DESCRIPTION
        The Win32_OperatingSystem query this used to make is an RPC round trip to the WMI service,
        and its one caller is the run header - diagnostics written before a single cleanup step
        starts. A diagnostic that can block the process on an unavailable service is the wrong
        shape, so the documented InstallationType value under CurrentVersion is read instead:
        'Client', 'Server', 'Server Core' or 'Nano Server'. A local registry read has no service to
        wait on. Unreadable answers false, exactly as the CIM body did when the query failed.
    #>
    try {
        $current = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
            -Name 'InstallationType' -ErrorAction Stop
        return ([string]$current.InstallationType -match '(?i)\bServer\b')
    }
    catch {
        $null = $_
    }

    return $false
}

function Test-WacSystemDriveSupported {
    <#
    .SYNOPSIS
        The whole allow-list is written for C:. Anything else must fail loudly, not half-work.
    #>
    $systemDrive = Get-WacNormalizedPath -Path $env:SystemDrive
    # ORDINAL, not -ieq: the whole allow-list depends on this being the target drive.
    return ([string]::Equals($systemDrive, $script:TargetDrive, [System.StringComparison]::OrdinalIgnoreCase))
}

function Get-WacCanonicalPowerShellHost {
    <#
    .SYNOPSIS
        Returns a machine-wide, non-PATH-resolved PowerShell host path, or $null.
    .DESCRIPTION
        Get-Command searches PATH, which a standard user can extend, and can select a per-user or
        portable pwsh.exe. A host chosen that way must never be registered to run as SYSTEM, so only
        canonical machine locations are considered and each candidate must also pass the
        machine-trust check.
    #>
    param([switch]$SkipTrustCheck)

    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if ($env:ProgramFiles) {
        [void]$candidates.Add((Join-Path -Path $env:ProgramFiles -ChildPath 'PowerShell\7\pwsh.exe'))
    }
    [void]$candidates.Add((Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'))

    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        if ($SkipTrustCheck) { return $candidate }
        $trust = Test-WacPathIsMachineTrusted -Path $candidate
        if ($trust.IsTrusted) { return $candidate }
    }

    return $null
}

function Get-WacPathPresence {
    <#
    .SYNOPSIS
        'Present', 'Absent' or 'Unresolved' for one file or directory. Bounded; never throws.
    .DESCRIPTION
        Directory.Exists answers a BOOLEAN to a three-valued question. It is documented to return
        false when the path is missing AND when the caller cannot determine whether it exists -
        access denied, an IO error, a device that will not answer - so "not there" and "I was not
        allowed to look" arrive identically. Every caller that filtered on it therefore dropped an
        unreadable profile or cache silently, which is the one outcome this project is not allowed
        to report as a clean answer.

        The discrimination is the exception TYPE from a single enumeration of the parent for this
        one leaf: a missing parent raises DirectoryNotFoundException, which proves absence just as
        well as an empty result does, while UnauthorizedAccessException, SecurityException or
        IOException prove only that the question could not be answered. No recursion, no retry and
        no traversal beyond the parent, so the cost is one directory read.

        A path with no parent - a volume root - is answered directly, because there is nothing above
        it to enumerate.
    .OUTPUTS
        [string] 'Present', 'Absent' or 'Unresolved'.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Absent' }

    $long = Get-WacLongPath -Path $Path
    if ([System.IO.Directory]::Exists($long)) { return 'Present' }

    $parent = $null
    $leaf = ''
    try {
        $parent = [System.IO.Path]::GetDirectoryName($Path)
        $leaf = [System.IO.Path]::GetFileName($Path)
    }
    catch {
        return 'Unresolved'
    }

    # A volume root that Directory.Exists denied: there is no parent to ask, so the boolean is all
    # there is and a drive that will not answer stays unresolved rather than being called absent.
    if ([string]::IsNullOrEmpty($parent) -or [string]::IsNullOrEmpty($leaf)) {
        if ([System.IO.Directory]::Exists($long)) { return 'Present' }
        return 'Unresolved'
    }

    # A FILE where the parent directory should be: nothing can exist beneath it, so this is proven
    # absence. Without this the enumeration below raises IOException ("the directory name is
    # invalid") and the answer would be Unresolved - fail-closed, but it would manufacture a gap out
    # of a path that is simply not there. Measured: C:\Windows\notepad.exe\child.
    if ([System.IO.File]::Exists((Get-WacLongPath -Path $parent))) { return 'Absent' }

    try {
        $found = @([System.IO.Directory]::EnumerateFileSystemEntries((Get-WacLongPath -Path $parent), $leaf))
        if ($found.Count -gt 0) { return 'Present' }
        return 'Absent'
    }
    catch [System.IO.DirectoryNotFoundException] {
        # The parent itself is gone, so the child cannot exist. That is an answer.
        return 'Absent'
    }
    catch {
        return 'Unresolved'
    }
}

function Test-WacIsRealUserProfilePath {
    <#
    .SYNOPSIS
        Shared acceptance test for a candidate profile directory.
    .PARAMETER RequireUserHive
        Also demand ntuser.dat or ntuser.man. Microsoft's profile-cleanup sample uses that check to
        tell a real profile from an orphaned ProfileList entry, so it belongs to the registry
        FALLBACK path only. Win32_UserProfile already distinguishes real profiles through its
        documented Special property, and applying the hive check there would silently drop every
        profile whose root denies access to the current identity.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [switch]$RequireUserHive,
        [AllowNull()][System.Collections.Generic.List[object]]$Gap
    )

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $false }
    # Off-drive, inside the Windows directory, or a reparse point are DELIBERATE exclusions: the
    # answer is "not a profile we clean", not "we could not tell". Those never become gaps.
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { return $false }

    # This used to be a bare Directory.Exists, so a profile root that denied access to the running
    # identity was indistinguishable from one that was not there and vanished from the allow-list
    # without a word - the filter ran BEFORE the gap collector ever saw the path.
    $presence = Get-WacPathPresence -Path $normalized
    if ($presence -ceq 'Unresolved') {
        if ($null -ne $Gap) {
            [void]$Gap.Add([PSCustomObject]@{
                Source = 'UserProfile'
                Scope  = $normalized
                Reason = 'the profile directory could not be inspected, so it is neither cleaned nor proven absent'
            })
        }
        return $false
    }
    if ($presence -cne 'Present') { return $false }

    if (Test-WacIsReparsePoint -Path $normalized) { return $false }

    $systemRoot = Get-WacNormalizedPath -Path $env:SystemRoot
    if ($systemRoot -and (Test-WacIsWithinRoot -ChildPath $normalized -RootPath $systemRoot)) { return $false }

    if (-not $RequireUserHive) { return $true }

    # Same three-valued question for the hive. A profile whose root is readable but whose hive files
    # are not is an orphaned-or-locked-down entry we cannot classify; reporting it as "no hive,
    # therefore not a profile" is the guess this check exists to avoid.
    $unresolvedHive = $false
    foreach ($hive in @('ntuser.dat', 'ntuser.man')) {
        $hivePresence = Get-WacPathPresence -Path (Join-Path -Path $normalized -ChildPath $hive)
        if ($hivePresence -ceq 'Present') { return $true }
        if ($hivePresence -ceq 'Unresolved') { $unresolvedHive = $true }
    }

    if ($unresolvedHive -and $null -ne $Gap) {
        [void]$Gap.Add([PSCustomObject]@{
            Source = 'UserProfile'
            Scope  = $normalized
            Reason = 'the user hive could not be inspected, so this ProfileList entry was neither confirmed nor ruled out'
        })
    }

    return $false
}

function Get-WacUserProfilePath {
    <#
    .SYNOPSIS
        Real interactive user profile directories on C:.
    .DESCRIPTION
        Treating every directory under C:\Users as a profile is wrong: it picks up templates, stale
        folders and anything a user happened to create.
        Win32_UserProfile is the documented source, because its Special property is the supported way
        to separate real user profiles from service and system profiles. The ProfileList registry key
        is the fallback for hosts where the WMI class is unavailable; there the documented recipe is
        to skip the well-known SIDs S-1-5-18/19/20 and any '.bak' key, then confirm the profile with
        ntuser.dat/ntuser.man. The undocumented per-SID Flags/State values are never consulted.

        A returned list answers "which profiles are these" and cannot answer "was that all of them",
        and the two are different facts: a machine with no other profiles and a machine whose
        profiles could not be enumerated both hand back an empty array. Callers that need the second
        fact pass -Gap and read what was appended to it.
    .PARAMETER Gap
        Optional collector. One record per discovery source that could not be FINISHED is appended,
        so an unreadable source cannot be mistaken for an absent one. Paths that are deliberately
        excluded - a well-known service SID, a '.bak' entry, an off-drive or reparse-point profile -
        are not gaps: those are answers, not missing answers.
    #>
    param([AllowNull()][System.Collections.Generic.List[object]]$Gap)

    $results = New-Object 'System.Collections.Generic.List[string]'

    $addCandidate = {
        param([string]$Candidate, [bool]$RequireHive)

        $normalized = Get-WacNormalizedPath -Path $Candidate
        if (-not $normalized) { return }
        # The collector travels WITH the acceptance test: an unreadable profile is rejected inside
        # it, so a caller that only saw the returned list could never learn the path had been
        # dropped for a reason other than "not a profile".
        if (-not (Test-WacIsRealUserProfilePath -Path $normalized -RequireUserHive:$RequireHive -Gap $Gap)) { return }
        foreach ($existing in $results) {
            if ([string]::Equals($existing, $normalized, [System.StringComparison]::OrdinalIgnoreCase)) { return }
        }
        [void]$results.Add($normalized)
    }

    $wmiWorked = $false
    $cimError = ''
    # Reasons one ROW could not be processed, kept rather than reported immediately. The registry
    # pass below enumerates the same population, so a healthy fallback genuinely supplies what these
    # rows failed to give and the obligation is discharged; only a fallback that ALSO fails leaves
    # the machine unanswered, and that is when these become gaps.
    $cimRowFailure = New-Object 'System.Collections.Generic.List[string]'
    try {
        $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop)

        foreach ($userProfile in $profiles) {
            # Per row. A malformed or unreadable row used to escape to the outer catch, which stored
            # the error and left $wmiWorked ALREADY $true - it was set before this loop - so the
            # early return below handed back the rows read so far as if the enumeration had
            # finished: a partial profile list, no gap, and no fallback. Catching here keeps the
            # good rows AND keeps the provider honest about not having finished.
            try {
                if ($userProfile.Special) { continue }
                & $addCandidate ([string]$userProfile.LocalPath) $false
            }
            catch {
                [void]$cimRowFailure.Add([string]$_.Exception.Message)
                Write-WacLog -Level WARNING -Component 'Profiles' -Message 'A Win32_UserProfile row could not be examined; the ProfileList key must answer for it.' -Data @{ error = [string]$_.Exception.Message }
            }
        }

        # ONLY once every row has been processed, and only if every row was. This is the whole
        # repair: "the query returned" is not "the provider answered".
        $wmiWorked = ($cimRowFailure.Count -eq 0)
    }
    catch {
        $cimError = [string]$_.Exception.Message
        Write-WacLog -Level DEBUG -Component 'Profiles' -Message 'Win32_UserProfile is unavailable; falling back to the ProfileList registry key.' -Data @{ error = $cimError }
    }

    if ($cimRowFailure.Count -gt 0 -and [string]::IsNullOrEmpty($cimError)) {
        $cimError = ('{0} row(s) could not be examined: {1}' -f $cimRowFailure.Count, ($cimRowFailure -join '; '))
    }

    if ($wmiWorked -and $results.Count -gt 0) { return @($results.ToArray()) }

    # Below this line the registry key is the AUTHORITATIVE source only when the CIM query did not
    # finish. A healthy fallback recovering an unavailable provider is a complete discovery and must
    # not be reported as a gap; conversely, a CIM query that completed has already answered which
    # profiles exist, so a failure in this confirmation pass cannot un-answer it.
    $fallbackIsAuthoritative = (-not $wmiWorked)

    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $wellKnown = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')

    try {
        $subKeys = @(Get-ChildItem -LiteralPath $key -ErrorAction Stop)
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Profiles' -Message 'Could not read the ProfileList registry key; no user profiles will be cleaned.' -Data @{ error = $_.Exception.Message }
        if ($fallbackIsAuthoritative -and $null -ne $Gap) {
            [void]$Gap.Add([PSCustomObject]@{
                Source = 'UserProfile'
                Scope  = 'ProfileList'
                Reason = ('neither Win32_UserProfile ({0}) nor the ProfileList registry key ({1}) could be enumerated' -f $cimError, $_.Exception.Message)
            })
        }
        return @($results.ToArray())
    }

    foreach ($subKey in $subKeys) {
        $sid = Split-Path -Leaf $subKey.Name
        if ($sid.EndsWith('.bak', [System.StringComparison]::OrdinalIgnoreCase)) {
            # Deliberately excluded rather than unreadable: a '.bak' key is the documented marker of
            # a profile Windows itself renamed, so skipping it is an answer and not a missing one.
            Write-WacLog -Level WARNING -Component 'Profiles' -Message 'ProfileList holds a .bak entry; that profile is skipped.' -Data @{ sid = $sid }
            continue
        }
        if ($wellKnown -contains $sid) { continue }

        # No -Name: asking for one value makes "this key cannot be read" and "this key has no such
        # value" the same exception, and only the first is a gap. A ProfileList entry without a
        # ProfileImagePath is malformed, which the IsNullOrWhiteSpace check below already answers.
        $entry = $null
        try { $entry = Get-ItemProperty -LiteralPath $subKey.PSPath -ErrorAction Stop }
        catch {
            Write-WacLog -Level WARNING -Component 'Profiles' -Message 'A ProfileList entry could not be read; that profile was not examined.' -Data @{ sid = $sid; error = $_.Exception.Message }
            if ($fallbackIsAuthoritative -and $null -ne $Gap) {
                [void]$Gap.Add([PSCustomObject]@{
                    Source = 'UserProfile'
                    Scope  = $sid
                    Reason = ('the ProfileList entry could not be read ({0})' -f $_.Exception.Message)
                })
            }
            continue
        }

        $imagePath = ''
        if ($null -ne $entry -and (@($entry.PSObject.Properties.Name) -ccontains 'ProfileImagePath')) {
            $imagePath = [string]$entry.ProfileImagePath
        }

        if ([string]::IsNullOrWhiteSpace($imagePath)) { continue }
        & $addCandidate ([Environment]::ExpandEnvironmentVariables($imagePath)) $true
    }

    return @($results.ToArray())
}

function Get-WacFreeBytes {
    <#
    .SYNOPSIS
        Free bytes on a drive, or $null when the volume cannot answer. Telemetry only.
    .DESCRIPTION
        This used to query Win32_LogicalDisk. That is an RPC round trip to the WMI service with no
        bound of its own, made twice per run - once before the whole cleanup and once after it - so
        a wedged WMI repository could stall the run outside every step contract. DriveInfo is
        GetDiskFreeSpaceEx against the volume itself: no service to be unavailable, nothing to hang
        on. The registry/CIM fallback is gone with it; a second unbounded source is not a fallback.

        The value is a log line and a delta and is never an input to the run's verdict, so an
        unreadable volume returns $null and the footer prints 'Unknown'.
    #>
    param([string]$Drive = 'C:')

    try {
        $info = New-Object System.IO.DriveInfo($Drive)
        if ($info.IsReady) { return [int64]$info.AvailableFreeSpace }
    }
    catch {
        $null = $_
    }

    return $null
}

function Format-WacBytes {
    param([Nullable[Int64]]$Bytes)

    if ($null -eq $Bytes) { return 'Unknown' }
    if ($Bytes -lt 0) { return ('{0:N0} bytes' -f $Bytes) }

    $value = [double]$Bytes
    $units = @('bytes', 'KB', 'MB', 'GB', 'TB')
    $index = 0

    while ($value -ge 1024 -and $index -lt ($units.Count - 1)) {
        $value = $value / 1024
        $index++
    }

    if ($index -eq 0) { return ('{0:N0} {1}' -f $value, $units[$index]) }
    return ('{0:N2} {1}' -f $value, $units[$index])
}
