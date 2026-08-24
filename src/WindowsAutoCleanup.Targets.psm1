<#
.SYNOPSIS
    The C:-only cleanup allow-list.

.DESCRIPTION
    One function builds every target, so there is exactly one place to audit what this tool is
    allowed to delete. Rules that hold for every entry:

      * the path is canonicalised through Core's Get-WacNormalizedPath and dropped unless it lives
        on the target drive, so a relocated profile on D: silently produces no target rather than an
        off-drive deletion;
      * duplicates are removed by Mode + normalised path, because %TEMP% under SYSTEM resolves to
        the same directory as the Windows Temp entry;
      * user profiles come from Core's Get-WacUserProfilePath (Win32_UserProfile / ProfileList), not
        from enumerating C:\Users, which treated templates and stray directories as profiles;
      * the roots are read from %SystemRoot% / %ProgramData% rather than hard-coded C:\Windows and
        C:\ProgramData, matching how the tools themselves resolve them.

    What is deliberately NOT here: browser history, cookies, saved passwords, WebCache, Recent items,
    Quick Access, pinned or frequent destinations, and the Chromium profile root itself. Only
    regenerable caches are listed.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the CALLER's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop

# Per-user cache directories, relative to a profile root. Order is the cleanup order.
$script:UserCacheTarget = @(
    @{ Category = 'User TEMP contents';                        Path = 'AppData\Local\Temp' }
    @{ Category = 'Internet cache (INetCache)';                Path = 'AppData\Local\Microsoft\Windows\INetCache' }
    @{ Category = 'Internet cache (Temporary Internet Files)'; Path = 'AppData\Local\Microsoft\Windows\Temporary Internet Files' }
    @{ Category = 'Internet cache (IECompatCache)';            Path = 'AppData\Local\Microsoft\Windows\IECompatCache' }
    @{ Category = 'Internet cache (IECompatUaCache)';          Path = 'AppData\Local\Microsoft\Windows\IECompatUaCache' }
    @{ Category = 'DirectX Shader Cache';                      Path = 'AppData\Local\D3DSCache' }
    @{ Category = 'Location Privacy cache';                    Path = 'AppData\Local\Microsoft\Windows\Location' }
    @{ Category = 'Location Privacy cache';                    Path = 'AppData\Local\Microsoft\Windows\LocationProvider' }
)

# Service profiles hold their own WinINET caches. They are not returned by Get-WacUserProfilePath
# because Win32_UserProfile marks them Special, so they are listed explicitly.
$script:ServiceProfileRelativeRoot = @(
    'System32\config\systemprofile'
    'SysWOW64\config\systemprofile'
    'ServiceProfiles\LocalService'
    'ServiceProfiles\NetworkService'
)

$script:ServiceProfileCacheTarget = @(
    @{ Category = 'Internet cache (system profiles)'; Path = 'AppData\Local\Microsoft\Windows\INetCache' }
    @{ Category = 'Internet cache (system profiles)'; Path = 'AppData\Local\Microsoft\Windows\Temporary Internet Files' }
    @{ Category = 'DirectX Shader Cache';             Path = 'AppData\Local\D3DSCache' }
)

# Chromium regenerates each of these on demand. The profile root itself is not a target: History,
# Cookies, 'Login Data', Bookmarks and the rest of the user's data live there.
$script:EdgeCacheSubPath = @(
    'Cache\Cache_Data'
    'Cache\js'
    'Cache\wasm'
    'Code Cache\js'
    'Code Cache\wasm'
    'DawnCache'
    'DawnWebGPUCache'
    'GPUCache'
    'ShaderCache\GPUCache'
    'Service Worker\CacheStorage'
    'Service Worker\ScriptCache'
)

function Add-WacTarget {
    <#
    .SYNOPSIS
        Appends one allow-list entry, or drops it when it is off-drive, unnormalisable, skipped by
        the caller, or already present.
    #>
    param(
        # AllowEmptyCollection is load-bearing: the parameter binder rejects an EMPTY ICollection as
        # "no value" for a Mandatory parameter, so without it the very first call - when the list is
        # still empty - fails and the allow-list comes back with zero targets.
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$TargetList,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Seen,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$SkipCategory,
        [Parameter(Mandatory = $true)][ValidateSet('Directory', 'Pattern')][string]$Mode,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Path,
        [switch]$DeleteRoot,
        [AllowEmptyCollection()][string[]]$Pattern = @()
    )

    foreach ($skip in $SkipCategory) {
        if ($Category -ieq $skip) { return }
    }

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) { return }
    if (-not (Test-WacIsOnTargetDrive -Path $normalized)) { return }
    if (-not $Seen.Add(('{0}|{1}' -f $Mode, $normalized))) { return }

    [void]$TargetList.Add([PSCustomObject]@{
        Mode       = $Mode
        Category   = $Category
        Path       = $normalized
        DeleteRoot = [bool]$DeleteRoot
        Pattern    = [string[]]$Pattern
    })
}

function Get-WacEdgeProfilePath {
    <#
    .SYNOPSIS
        The Chromium user-profile directories under one 'User Data' root.
    .DESCRIPTION
        Chromium names user profiles 'Default' and 'Profile <n>'. Every other directory under
        User Data ('BrowserMetrics', 'Ad Blocking', 'Application Guard', ...) is component-shared
        state, so matching the profile scheme keeps cleanup off data that is not a per-user cache.
    #>
    param([Parameter(Mandatory = $true)][string]$UserDataPath)

    $found = New-Object 'System.Collections.Generic.List[string]'

    if (-not (Test-Path -LiteralPath $UserDataPath -PathType Container)) { return @() }

    try {
        $children = @(Get-ChildItem -LiteralPath $UserDataPath -Directory -Force -ErrorAction Stop)
    }
    catch {
        Write-WacLog -Level DEBUG -Component 'Targets' -Message 'Could not enumerate an Edge User Data directory.' -Data @{ path = $UserDataPath; error = $_.Exception.Message }
        return @()
    }

    foreach ($child in $children) {
        if ($child.Name -ne 'Default' -and $child.Name -notmatch '^Profile \d+$') { continue }
        if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        [void]$found.Add($child.FullName)
    }

    return @($found.ToArray())
}

function Get-WacCleanupTarget {
    <#
    .SYNOPSIS
        The ordered, de-duplicated, C:-only cleanup allow-list.
    .PARAMETER SkipCategory
        Category names the caller wants disabled for this run. Matching is case-insensitive.
    .OUTPUTS
        Objects with Mode ('Directory' or 'Pattern'), Category, Path, DeleteRoot and Pattern.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([AllowEmptyCollection()][string[]]$SkipCategory = @())

    $targets = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $common = @{ TargetList = $targets; Seen = $seen; SkipCategory = @($SkipCategory) }

    $windowsRoot = Get-WacNormalizedPath -Path $env:SystemRoot
    $programData = Get-WacNormalizedPath -Path $env:ProgramData
    $driveRoot = (Get-WacTargetDrive) + '\'

    if ($windowsRoot) {
        Add-WacTarget @common -Mode Directory -Category 'Windows Temp contents' -Path (Join-Path -Path $windowsRoot -ChildPath 'Temp')
    }

    # Under SYSTEM this resolves to the Windows Temp directory again; the de-duplicator collapses it.
    Add-WacTarget @common -Mode Directory -Category 'Current user TEMP contents' -Path $env:TEMP

    foreach ($userProfilePath in (Get-WacUserProfilePath)) {
        foreach ($entry in $script:UserCacheTarget) {
            Add-WacTarget @common -Mode Directory -Category $entry.Category -Path (Join-Path -Path $userProfilePath -ChildPath $entry.Path)
        }

        # Pattern mode only. The Explorer directory also holds Quick Access, pinned and frequent
        # destination state, which must survive; only the generated cache databases are removed.
        # Explorer is not stopped, so a running Explorer may recreate the base databases at once.
        Add-WacTarget @common -Mode Pattern -Category 'Windows Explorer thumbnail cache' `
            -Path (Join-Path -Path $userProfilePath -ChildPath 'AppData\Local\Microsoft\Windows\Explorer') `
            -Pattern @('thumbcache_*.db', 'iconcache_*.db')

        $edgeUserData = Join-Path -Path $userProfilePath -ChildPath 'AppData\Local\Microsoft\Edge\User Data'
        foreach ($edgeProfilePath in (Get-WacEdgeProfilePath -UserDataPath $edgeUserData)) {
            foreach ($sub in $script:EdgeCacheSubPath) {
                $candidate = Join-Path -Path $edgeProfilePath -ChildPath $sub
                if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
                Add-WacTarget @common -Mode Directory -Category 'Microsoft Edge cache' -Path $candidate
            }
        }
    }

    if ($windowsRoot) {
        foreach ($relativeRoot in $script:ServiceProfileRelativeRoot) {
            $serviceProfileRoot = Join-Path -Path $windowsRoot -ChildPath $relativeRoot
            foreach ($entry in $script:ServiceProfileCacheTarget) {
                Add-WacTarget @common -Mode Directory -Category $entry.Category -Path (Join-Path -Path $serviceProfileRoot -ChildPath $entry.Path)
            }
        }
    }

    if ($programData) {
        # The cleanmgr 'Microsoft Defender Antivirus' handler maps to LocalCopy and Support.
        Add-WacTarget @common -Mode Directory -Category 'Defender cleanup files' -Path (Join-Path -Path $programData -ChildPath 'Microsoft\Windows Defender\LocalCopy')
        Add-WacTarget @common -Mode Directory -Category 'Defender cleanup files' -Path (Join-Path -Path $programData -ChildPath 'Microsoft\Windows Defender\Support')

        # Scan history is separate from that handler and stays locked under Tamper Protection even
        # for an elevated caller, so removal here is best-effort by design.
        foreach ($historyLeaf in @('Service', 'Results\Quick', 'Results\Resource')) {
            Add-WacTarget @common -Mode Directory -Category 'Defender scan history' -Path (Join-Path -Path $programData -ChildPath ('Microsoft\Windows Defender\Scans\History\' + $historyLeaf))
        }

        Add-WacTarget @common -Mode Directory -Category 'Delivery Optimization cache' -Path (Join-Path -Path $programData -ChildPath 'Microsoft\Windows\DeliveryOptimization\Cache')
        Add-WacTarget @common -Mode Directory -Category 'Location Privacy cache' -Path (Join-Path -Path $programData -ChildPath 'Microsoft\Windows\lfsvc\Cache')
        Add-WacTarget @common -Mode Directory -Category 'Location Privacy cache' -Path (Join-Path -Path $programData -ChildPath 'Microsoft\Windows\LocationProvider')
    }

    if ($windowsRoot) {
        # SoftwareDistribution\Download is documented only as a last-resort Windows Update repair
        # action whose procedure stops the servicing services first. Coordinating that is the
        # orchestrator's job (ledger P1-14); this list only names the location.
        Add-WacTarget @common -Mode Directory -Category 'Windows Update download cache contents' -Path (Join-Path -Path $windowsRoot -ChildPath 'SoftwareDistribution\Download')
        Add-WacTarget @common -Mode Directory -Category 'Downloaded Program Files' -Path (Join-Path -Path $windowsRoot -ChildPath 'Downloaded Program Files')
        Add-WacTarget @common -Mode Directory -Category 'Delivery Optimization cache' -Path (Join-Path -Path $windowsRoot -ChildPath 'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache')
        Add-WacTarget @common -Mode Directory -Category 'Delivery Optimization cache' -Path (Join-Path -Path $windowsRoot -ChildPath 'SoftwareDistribution\DeliveryOptimization\Cache')
        Add-WacTarget @common -Mode Directory -Category 'Windows Prefetch contents' -Path (Join-Path -Path $windowsRoot -ChildPath 'Prefetch')
    }

    # The only entry whose root is removed as well: an emptied Windows.old is worthless.
    Add-WacTarget @common -Mode Directory -Category 'Windows.old folder' -Path (Join-Path -Path $driveRoot -ChildPath 'Windows.old') -DeleteRoot

    return @($targets.ToArray())
}

Export-ModuleMember -Function @('Get-WacCleanupTarget', 'Get-WacEdgeProfilePath', 'Add-WacTarget')
