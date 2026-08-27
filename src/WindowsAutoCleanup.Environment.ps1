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
    return ($systemDrive -ieq $script:TargetDrive)
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
        [switch]$RequireUserHive
    )

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return $false }
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { return $false }
    if (-not [System.IO.Directory]::Exists((Get-WacLongPath -Path $normalized))) { return $false }
    if (Test-WacIsReparsePoint -Path $normalized) { return $false }

    $systemRoot = Get-WacNormalizedPath -Path $env:SystemRoot
    if ($systemRoot -and (Test-WacIsWithinRoot -ChildPath $normalized -RootPath $systemRoot)) { return $false }

    if (-not $RequireUserHive) { return $true }

    foreach ($hive in @('ntuser.dat', 'ntuser.man')) {
        # File.Exists returns false instead of writing to the error stream when access is denied,
        # which keeps a locked-down profile from polluting the caller's error output.
        if ([System.IO.File]::Exists((Get-WacLongPath -Path (Join-Path -Path $normalized -ChildPath $hive)))) { return $true }
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
    #>
    $results = New-Object 'System.Collections.Generic.List[string]'

    $addCandidate = {
        param([string]$Candidate, [bool]$RequireHive)

        $normalized = Get-WacNormalizedPath -Path $Candidate
        if (-not $normalized) { return }
        if (-not (Test-WacIsRealUserProfilePath -Path $normalized -RequireUserHive:$RequireHive)) { return }
        foreach ($existing in $results) {
            if ($existing -ieq $normalized) { return }
        }
        [void]$results.Add($normalized)
    }

    $wmiWorked = $false
    try {
        $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop)
        $wmiWorked = $true
        foreach ($userProfile in $profiles) {
            if ($userProfile.Special) { continue }
            & $addCandidate ([string]$userProfile.LocalPath) $false
        }
    }
    catch {
        Write-WacLog -Level DEBUG -Component 'Profiles' -Message 'Win32_UserProfile is unavailable; falling back to the ProfileList registry key.' -Data @{ error = $_.Exception.Message }
    }

    if ($wmiWorked -and $results.Count -gt 0) { return @($results.ToArray()) }

    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $wellKnown = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')

    try {
        $subKeys = @(Get-ChildItem -LiteralPath $key -ErrorAction Stop)
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Profiles' -Message 'Could not read the ProfileList registry key; no user profiles will be cleaned.' -Data @{ error = $_.Exception.Message }
        return @($results.ToArray())
    }

    foreach ($subKey in $subKeys) {
        $sid = Split-Path -Leaf $subKey.Name
        if ($sid.EndsWith('.bak', [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-WacLog -Level WARNING -Component 'Profiles' -Message 'ProfileList holds a .bak entry; that profile is skipped.' -Data @{ sid = $sid }
            continue
        }
        if ($wellKnown -contains $sid) { continue }

        $imagePath = $null
        try { $imagePath = [string](Get-ItemProperty -LiteralPath $subKey.PSPath -Name 'ProfileImagePath' -ErrorAction Stop).ProfileImagePath }
        catch { continue }

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
