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

    Also deliberately NOT here: SoftwareDistribution\Download and the Delivery Optimization cache
    directories. Both belong to running services. The documented Windows Update repair procedure
    stops wuauserv (and bits and cryptsvc) and RENAMES the folder rather than deleting it, and this
    tool stops no service: it cannot record every original state and start mode, bound every wait
    and guarantee a verified restoration, so it does not start. Delivery Optimization is purged
    through its own supported cmdlet instead (Clear-WacDeliveryOptimizationCache), which coordinates
    with the service that owns the files, and the cleanmgr 'Delivery Optimization Files' handler
    remains available behind the opt-in legacy step.

    Building this list walks the filesystem and queries Win32_UserProfile, so callers that need the
    run budget enforced over it use Get-WacCleanupTargetSet, which returns an outcome alongside the
    list. Get-WacCleanupTarget itself stays unbounded: it is the worker the bound runs.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the CALLER's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop

# Captured at import: inside a module $PSCommandPath is this .psm1, and Invoke-WacBounded needs a
# real path to import into the runspace it creates.
$script:TargetsModulePath = $PSCommandPath

# A ceiling, not an expected duration: a healthy machine builds the list in well under a second.
$script:TargetBuildTimeoutMs = 1000 * 60 * 2

# Discovery evidence from the last Get-WacCleanupTarget call in THIS module instance, read back
# through Get-WacTargetDiscoveryGap. Module state rather than an out-parameter on the builder,
# because the builder runs inside the runspace Get-WacCleanupTargetSet bounds and the test rig
# replaces the builder itself: a reader the rig does not shadow keeps both shapes working.
$script:DiscoveryGap = @()

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
        # Display-category matching is deliberately linguistic, unlike filesystem identities.
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

        An empty result used to mean two different things. A User Data root that is absent or is not
        a directory at all genuinely has no profiles; a root that EXISTS and could not be enumerated
        has profiles nobody counted, and turning that into "no profiles" is how a failed discovery
        becomes a clean, empty success. Only the second one is appended to -Gap.
    .PARAMETER Gap
        Optional collector for discovery that could not be finished; see Get-WacCleanupTargetSet.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$UserDataPath,
        [AllowNull()][System.Collections.Generic.List[object]]$Gap
    )

    $found = New-Object 'System.Collections.Generic.List[string]'

    # Absent is an answer; unreadable is not. Test-Path answered false for BOTH, and that was the
    # documented ceiling of this check - a User Data root the running identity cannot reach at all
    # never reached the enumeration below, so it produced a clean empty result with no gap. The
    # three-valued probe separates them, so the only empty result that stays silent is a genuine
    # absence.
    $presence = Get-WacPathPresence -Path $UserDataPath
    if ($presence -ceq 'Unresolved') {
        Write-WacLog -Level WARNING -Component 'Targets' -Message 'An Edge User Data path could not be inspected, so its profiles are neither discovered nor ruled out.' -Data @{ path = $UserDataPath }
        if ($null -ne $Gap) {
            [void]$Gap.Add([PSCustomObject]@{
                Source = 'EdgeProfile'
                Scope  = $UserDataPath
                Reason = 'the User Data path could not be inspected, so it is neither enumerated nor proven absent'
            })
        }
        return @()
    }
    if ($presence -cne 'Present') { return @() }

    # Present, but possibly a FILE where a directory was expected: still an answer, not a gap.
    if (-not (Test-Path -LiteralPath $UserDataPath -PathType Container)) { return @() }

    try {
        $children = @(Get-ChildItem -LiteralPath $UserDataPath -Directory -Force -ErrorAction Stop)
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Targets' -Message 'An existing Edge User Data directory could not be enumerated, so its profiles were not discovered.' -Data @{ path = $UserDataPath; error = $_.Exception.Message }
        if ($null -ne $Gap) {
            [void]$Gap.Add([PSCustomObject]@{
                Source = 'EdgeProfile'
                Scope  = $UserDataPath
                Reason = ('the User Data directory exists but could not be enumerated ({0})' -f $_.Exception.Message)
            })
        }
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

        Discovery that could not be finished is recorded separately and read back through
        Get-WacTargetDiscoveryGap; it deliberately does not travel in the returned list, because
        this list is the allow-list of what may be DELETED and nothing else belongs in it.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([AllowEmptyCollection()][string[]]$SkipCategory = @())

    # Cleared first: evidence from a previous call must never be read as this one's.
    $script:DiscoveryGap = @()
    $gap = New-Object 'System.Collections.Generic.List[object]'

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

    foreach ($userProfilePath in (Get-WacUserProfilePath -Gap $gap)) {
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
        foreach ($edgeProfilePath in (Get-WacEdgeProfilePath -UserDataPath $edgeUserData -Gap $gap)) {
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

        Add-WacTarget @common -Mode Directory -Category 'Location Privacy cache' -Path (Join-Path -Path $programData -ChildPath 'Microsoft\Windows\lfsvc\Cache')
        Add-WacTarget @common -Mode Directory -Category 'Location Privacy cache' -Path (Join-Path -Path $programData -ChildPath 'Microsoft\Windows\LocationProvider')
    }

    if ($windowsRoot) {
        # SoftwareDistribution\Download and the Delivery Optimization cache directories used to be
        # listed here. They are gone on purpose: see the module header. Nothing in this list may be
        # a location a running service owns and this tool cannot quiesce.
        Add-WacTarget @common -Mode Directory -Category 'Downloaded Program Files' -Path (Join-Path -Path $windowsRoot -ChildPath 'Downloaded Program Files')
        Add-WacTarget @common -Mode Directory -Category 'Windows Prefetch contents' -Path (Join-Path -Path $windowsRoot -ChildPath 'Prefetch')
    }

    # The only entry whose root is removed as well: an emptied Windows.old is worthless.
    Add-WacTarget @common -Mode Directory -Category 'Windows.old folder' -Path (Join-Path -Path $driveRoot -ChildPath 'Windows.old') -DeleteRoot

    $script:DiscoveryGap = @($gap.ToArray())
    return @($targets.ToArray())
}

function Get-WacTargetDiscoveryGap {
    <#
    .SYNOPSIS
        The discovery sources the last Get-WacCleanupTarget call in this module instance could not
        finish - one record with Source, Scope and Reason each.
    .DESCRIPTION
        Read by Get-WacCleanupTargetSet from INSIDE the runspace it bounds, which is the only place
        the builder's module state exists. An empty list means every source answered, not that
        nobody asked: the builder clears this before it starts.
    #>
    [OutputType([object[]])]
    param()

    return @($script:DiscoveryGap)
}

function Get-WacCleanupTargetSet {
    <#
    .SYNOPSIS
        The allow-list built under a wall-clock bound, with an outcome instead of a silent empty list.
    .DESCRIPTION
        Building the list walks the filesystem - every profile's Edge 'User Data', every candidate
        cache directory - and queries Win32_UserProfile through CIM. Both block in the OS, and a
        call that blocks in the OS blocks every cooperative deadline check sitting behind it, so
        this work runs through Invoke-WacBounded.

        The distinction that matters is the one the bare list cannot express: an EMPTY allow-list
        and an allow-list that was never finished look identical to a caller, and the second one
        must not be reported as "nothing to clean". An expired or exceeded bound returns Incomplete
        with an empty Target, which the shared contract maps to a non-zero exit code.

        A bound that was never exceeded is not the same fact as a discovery that finished, and this
        used to promote any normally returned list straight to Succeeded. Three things are therefore
        reconciled before the outcome is settled: the bound's own verdict, the error stream of the
        runspace (a non-terminating error leaves Outcome Succeeded with HadErrors set), and the
        builder's structured record of the sources it could not finish. Any of the three makes the
        step Incomplete.

        The targets that WERE discovered are still returned when discovery was partial. Nothing in
        the list is less safe to delete because another source went unread, and refusing to clean a
        machine over an unreadable profile would be the blanket refusal this project does not make;
        the allow-list is never widened to compensate either.
    .OUTPUTS
        Outcome (Succeeded | Incomplete | Failed), Target, Gap, Detail, DurationMs.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$SkipCategory = @())

    # @(, ...) keeps the array ONE argument: Invoke-WacBounded adds each element of -ArgumentList as
    # its own positional argument, so an unwrapped array arrives as N of them.
    $bounded = Invoke-WacBounded -Component 'Targets' -TimeoutMs $script:TargetBuildTimeoutMs `
        -ImportModule @($script:TargetsModulePath) -ArgumentList @(, [string[]]@($SkipCategory)) -ScriptBlock {
            param($SkipCategory)
            # The gap reader has to be called HERE. The builder's module state lives in this
            # runspace and dies with it, so a caller outside the bound can never read it.
            $built = @(Get-WacCleanupTarget -SkipCategory ([string[]]@($SkipCategory)))
            [PSCustomObject]@{ Target = $built; Gap = @(Get-WacTargetDiscoveryGap) }
        }

    $outcome = [string]$bounded.Outcome
    $target = @()
    $gap = @()
    $detail = ''

    if ($bounded.Outcome -ceq 'Succeeded') {
        $survey = @($bounded.Output)[0]
        if ($null -eq $survey) {
            $outcome = 'Incomplete'
            $detail = 'The cleanup allow-list builder returned nothing at all.'
        }
        else {
            $target = @($survey.Target)
            $gap = @($survey.Gap)
            $detail = 'The allow-list holds {0} target(s).' -f $target.Count
        }

        if ($bounded.HadErrors) {
            # A worker error that was written to the error stream instead of thrown still means the
            # list may be short, and the bound alone reports that as a clean run.
            $outcome = 'Incomplete'
            $detail = '{0} The builder reported a non-terminating error: {1}' -f $detail, $bounded.Error
            Write-WacLog -Level WARNING -Component 'Targets' -Message 'The cleanup allow-list builder reported a non-terminating error, so the list may be short.' -Data @{ error = $bounded.Error }
        }

        if ($gap.Count -gt 0) {
            $outcome = 'Incomplete'
            $summary = (@($gap | ForEach-Object { '{0}:{1} ({2})' -f $_.Source, $_.Scope, $_.Reason }) -join '; ')
            $detail = '{0} {1} discovery source(s) could not be finished, so this is not proof that nothing else is eligible: {2}' -f $detail, $gap.Count, $summary
            # The durable record: this runs in the caller's process, where the run's log writer is,
            # rather than in the runspace the builder was bounded in.
            foreach ($entry in $gap) {
                Write-WacLog -Level WARNING -Component 'Targets' -Message 'A cleanup discovery source could not be finished.' -Data @{
                    source = [string]$entry.Source; scope = [string]$entry.Scope; reason = [string]$entry.Reason
                }
            }
        }
    }
    else {
        $detail = 'The cleanup allow-list could not be built: {0}' -f $bounded.Error
        Write-WacLog -Level WARNING -Component 'Targets' -Message 'The cleanup allow-list could not be built, so no target was attempted.' -Data @{
            outcome = $bounded.Outcome; error = $bounded.Error
        }
    }

    return [PSCustomObject]@{
        Outcome    = $outcome
        Target     = $target
        Gap        = $gap
        Detail     = $detail.Trim()
        DurationMs = [int]$bounded.DurationMs
    }
}

Export-ModuleMember -Function @('Get-WacCleanupTarget', 'Get-WacCleanupTargetSet', 'Get-WacEdgeProfilePath',
    'Get-WacTargetDiscoveryGap', 'Add-WacTarget')
