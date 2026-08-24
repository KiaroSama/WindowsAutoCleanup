#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.Targets: the C:-only allow-list invariants (ledger
    P1-13), the de-duplication and skip rules of Add-WacTarget, and Chromium profile discovery.

.DESCRIPTION
    The allow-list is the one place that decides what this tool may delete, so every case asserts on
    the RETURNED objects, never on the text of the module. Nothing here deletes anything: the only
    filesystem writes are disposable Chromium 'User Data' trees under TEMP, and every junction and
    sandbox is released in a finally block.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
foreach ($moduleLeaf in @('Core', 'FileSystem', 'Targets')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

# Built once: every call re-queries Win32_UserProfile, and each case below asserts on the very
# allow-list a real run would receive.
$script:AllTarget = @(Get-WacCleanupTarget)
$script:CleanupDrive = Get-WacTargetDrive
$script:UserProfile = @(Get-WacUserProfilePath)

# Browser and shell state that must never appear in the allow-list. 'History' is checked separately
# because the Defender SCAN history directory legitimately contains that word.
$script:ForbiddenUserState = 'Cookies|Login Data|WebCache|\\Recent|AutomaticDestinations|CustomDestinations|Bookmarks|Web Data|Top Sites|Favorites|Quick Access'

function New-TargetCollector {
    <#
    .SYNOPSIS
        A fresh (TargetList, Seen) pair so Add-WacTarget can be driven directly and deterministically.
    #>
    return [PSCustomObject]@{
        TargetList = (New-Object 'System.Collections.Generic.List[object]')
        Seen       = (New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
    }
}

function New-TestDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    [void][System.IO.Directory]::CreateDirectory($Path)
    return $Path
}

function Get-ModuleFunctionBody {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (& $Module { param($n) (Get-Item -Path ('function:' + $n)).ScriptBlock } $Name)
}

function Set-ModuleFunctionBody {
    <#
    .SYNOPSIS
        Replaces a name inside the Targets module's own scope so the allow-list can be built against
        a synthetic profile instead of whatever profiles this machine happens to have.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
}

# ---------------------------------------------------------------------------------------------
# Allow-list invariants (ledger P1-13)
# ---------------------------------------------------------------------------------------------

Test-Case 'every allow-list target lives on the target drive' {
    Assert-True ($script:AllTarget.Count -ge 10) ('the allow-list collapsed to {0} target(s)' -f $script:AllTarget.Count)

    foreach ($target in $script:AllTarget) {
        Assert-True (Test-WacIsOnTargetDrive -Path $target.Path) ('off-drive target: {0}' -f $target.Path)
        Assert-True ($target.Path.StartsWith($script:CleanupDrive + '\', [System.StringComparison]::OrdinalIgnoreCase)) `
            ('target is not under the cleanup drive: {0}' -f $target.Path)
    }
}

Test-Case 'no browser or shell state location is in the allow-list' {
    $leak = @($script:AllTarget | Where-Object { $_.Path -match $script:ForbiddenUserState })
    Assert-Equal 0 $leak.Count ('privacy/state paths reached the allow-list: {0}' -f (($leak | ForEach-Object { $_.Path }) -join '; '))
}

Test-Case 'the only allow-list path containing History is the Defender scan history' {
    foreach ($target in @($script:AllTarget | Where-Object { $_.Path -match '(?i)History' })) {
        Assert-Equal 'Defender scan history' $target.Category ('unexpected History path: {0}' -f $target.Path)
        Assert-True ($target.Path -match '(?i)\\Windows Defender\\Scans\\History\\') ('unexpected History path: {0}' -f $target.Path)
    }
}

Test-Case 'the allow-list holds no duplicate Mode and Path pair' {
    $duplicate = @($script:AllTarget |
        Group-Object -Property { '{0}|{1}' -f $_.Mode, $_.Path.ToLowerInvariant() } |
        Where-Object { $_.Count -gt 1 })

    Assert-Equal 0 $duplicate.Count ('duplicated: {0}' -f (($duplicate | ForEach-Object { $_.Name }) -join '; '))
}

Test-Case 'exactly one target deletes its own root and it is Windows.old' {
    $deleteRoot = @($script:AllTarget | Where-Object { $_.DeleteRoot })

    Assert-Equal 1 $deleteRoot.Count ('DeleteRoot targets: {0}' -f (($deleteRoot | ForEach-Object { $_.Path }) -join '; '))
    Assert-Equal (Join-Path -Path ($script:CleanupDrive + '\') -ChildPath 'Windows.old') $deleteRoot[0].Path
    Assert-Equal 'Windows.old folder' $deleteRoot[0].Category
    Assert-Equal 'Directory' $deleteRoot[0].Mode
}

Test-Case 'every Pattern target is the Explorer thumbnail cache and never deletes its root' {
    $pattern = @($script:AllTarget | Where-Object { $_.Mode -eq 'Pattern' })

    # One per real user profile: the entry is emitted inside the profile loop, and two profiles can
    # never normalise to the same Explorer directory.
    Assert-Equal $script:UserProfile.Count $pattern.Count 'the Explorer pattern target is not one-per-profile'

    foreach ($target in $pattern) {
        Assert-Equal 'Windows Explorer thumbnail cache' $target.Category
        Assert-False $target.DeleteRoot 'a Pattern target must never delete the Explorer directory itself'
        Assert-Equal 'thumbcache_*.db,iconcache_*.db' (@($target.Pattern) -join ',')
        Assert-True ($target.Path -match '(?i)\\AppData\\Local\\Microsoft\\Windows\\Explorer$') ('unexpected pattern path: {0}' -f $target.Path)
    }
}

Test-Case 'every Directory target carries no pattern list' {
    foreach ($target in @($script:AllTarget | Where-Object { $_.Mode -eq 'Directory' })) {
        Assert-Equal 0 (@($target.Pattern).Count) ('a Directory target carries patterns: {0}' -f $target.Path)
    }
}

Test-Case 'Windows Temp is resolved through the SystemRoot variable, not a hard-coded path' {
    $winTemp = @($script:AllTarget | Where-Object { $_.Category -eq 'Windows Temp contents' })

    Assert-Equal 1 $winTemp.Count
    Assert-Equal (Get-WacNormalizedPath -Path (Join-Path -Path $env:SystemRoot -ChildPath 'Temp')) $winTemp[0].Path
}

Test-Case 'every Edge cache target sits under a Chromium profile directory' {
    foreach ($target in @($script:AllTarget | Where-Object { $_.Category -eq 'Microsoft Edge cache' })) {
        Assert-True ($target.Path -match '(?i)\\User Data\\(Default|Profile \d+)\\') ('Edge target outside a profile: {0}' -f $target.Path)
    }
}

# ---------------------------------------------------------------------------------------------
# The per-profile rules, proved against a synthetic profile
#
# The invariants above can only assert on the paths THIS machine produces: an Edge subdirectory that
# does not exist is never emitted, so a privacy directory added to the module's list would go
# unnoticed on a host that has no Edge profile. The case below builds a profile that holds a cache
# directory and a privacy directory of every shape, so the decision is exercised on every host.
# ---------------------------------------------------------------------------------------------

Test-Case 'a profile offers its regenerable caches and none of its data directories' {
    $sandbox = New-TestSandbox -Prefix 'tg-profile'
    $targetsModule = Get-Module -Name 'WindowsAutoCleanup.Targets'
    $originalProfilePath = Get-ModuleFunctionBody -Module $targetsModule -Name 'Get-WacUserProfilePath'
    try {
        $profileRoot = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'Users\synthetic')
        $userData = Join-Path -Path $profileRoot -ChildPath 'AppData\Local\Microsoft\Edge\User Data'
        $chromiumProfile = Join-Path -Path $userData -ChildPath 'Default'

        $cacheLeaf = @('Cache\Cache_Data', 'Code Cache\js', 'GPUCache', 'Service Worker\CacheStorage')
        $dataLeaf = @('History', 'Cookies', 'Login Data', 'Bookmarks', 'Web Data', 'Top Sites',
            'Network', 'Local Storage', 'Session Storage', 'IndexedDB', 'Extensions', 'Sync Data')

        foreach ($leaf in ($cacheLeaf + $dataLeaf)) {
            [void](New-TestDirectory (Join-Path -Path $chromiumProfile -ChildPath $leaf))
        }

        $expectedCache = @($cacheLeaf | ForEach-Object { Get-WacNormalizedPath -Path (Join-Path -Path $chromiumProfile -ChildPath $_) } | Sort-Object)

        $syntheticRoot = Get-WacNormalizedPath -Path $profileRoot
        Set-ModuleFunctionBody -Module $targetsModule -Name 'Get-WacUserProfilePath' -Body ({ return @($syntheticRoot) }.GetNewClosure())

        $target = @(Get-WacCleanupTarget | Where-Object { $_.Path.StartsWith($syntheticRoot + '\', [System.StringComparison]::OrdinalIgnoreCase) })
        $edgeTarget = @($target | Where-Object { $_.Path -match '(?i)\\User Data\\' } | ForEach-Object { $_.Path } | Sort-Object)

        Assert-Equal $expectedCache.Count $edgeTarget.Count ('Edge targets: {0}' -f ($edgeTarget -join '; '))
        Assert-Equal ($expectedCache -join '|') ($edgeTarget -join '|') 'the Edge cache selection is not exactly the regenerable cache directories'

        foreach ($entry in $target) {
            Assert-False ($entry.Path -match $script:ForbiddenUserState) ('a profile data directory became a target: {0}' -f $entry.Path)
            Assert-False ($entry.Path -match '(?i)\\History$') ('a profile history directory became a target: {0}' -f $entry.Path)
            Assert-False ($entry.Path -ieq $chromiumProfile) 'the Chromium profile root itself became a target'
            Assert-False ($entry.Path -ieq $userData) 'the Chromium User Data root itself became a target'
            Assert-False $entry.DeleteRoot ('a per-profile target deletes its own root: {0}' -f $entry.Path)
        }

        $pattern = @($target | Where-Object { $_.Mode -eq 'Pattern' })
        Assert-Equal 1 $pattern.Count 'the profile did not produce exactly one thumbnail cache pattern target'
        Assert-Equal 'thumbcache_*.db,iconcache_*.db' (@($pattern[0].Pattern) -join ',')
        Assert-Equal (Get-WacNormalizedPath -Path (Join-Path -Path $profileRoot -ChildPath 'AppData\Local\Microsoft\Windows\Explorer')) $pattern[0].Path

        # The regenerable per-user caches still have to be offered.
        $userTemp = Get-WacNormalizedPath -Path (Join-Path -Path $profileRoot -ChildPath 'AppData\Local\Temp')
        Assert-True (@($target | ForEach-Object { $_.Path }) -ccontains $userTemp) 'the per-user TEMP directory was not offered'
    }
    finally {
        Set-ModuleFunctionBody -Module $targetsModule -Name 'Get-WacUserProfilePath' -Body $originalProfilePath
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# SkipCategory
# ---------------------------------------------------------------------------------------------

Test-Case 'SkipCategory is case-insensitive and removes only the categories it names' {
    $skipped = @(Get-WacCleanupTarget -SkipCategory @('wInDoWs PrEfEtCh CoNtEnTs', 'windows.old FOLDER'))

    Assert-Equal 0 (@($skipped | Where-Object { $_.Category -eq 'Windows Prefetch contents' }).Count) 'the prefetch category survived a case-insensitive skip'
    Assert-Equal 0 (@($skipped | Where-Object { $_.Category -eq 'Windows.old folder' }).Count) 'the Windows.old category survived a case-insensitive skip'
    Assert-Equal 0 (@($skipped | Where-Object { $_.DeleteRoot }).Count) 'skipping Windows.old must remove the only DeleteRoot target'

    $removed = @($script:AllTarget | Where-Object { $_.Category -eq 'Windows Prefetch contents' -or $_.Category -eq 'Windows.old folder' })
    Assert-Equal ($script:AllTarget.Count - $removed.Count) $skipped.Count 'SkipCategory removed more than the categories it was given'

    # Everything else has to come back identical.
    $keptKey = @($skipped | ForEach-Object { '{0}|{1}' -f $_.Mode, $_.Path })
    foreach ($target in $script:AllTarget) {
        if ($target.Category -eq 'Windows Prefetch contents' -or $target.Category -eq 'Windows.old folder') { continue }
        Assert-True ($keptKey -ccontains ('{0}|{1}' -f $target.Mode, $target.Path)) ('SkipCategory dropped an unrelated target: {0}' -f $target.Path)
    }
}

Test-Case 'SkipCategory with an unknown name changes nothing' {
    $skipped = @(Get-WacCleanupTarget -SkipCategory @('No Such Category'))
    Assert-Equal $script:AllTarget.Count $skipped.Count
}

Test-Case 'an empty SkipCategory returns the full allow-list' {
    Assert-Equal $script:AllTarget.Count (@(Get-WacCleanupTarget -SkipCategory @())).Count
}

# ---------------------------------------------------------------------------------------------
# Add-WacTarget: the rules every entry passes through
# ---------------------------------------------------------------------------------------------

Test-Case 'Add-WacTarget drops an off-drive path' {
    $offDrive = 'Z:'
    Assert-False ($offDrive -ieq $script:CleanupDrive) 'the probe drive must differ from the cleanup drive'

    # Concatenated, not Join-Path: Join-Path resolves the drive qualifier and throws on a drive that
    # is not mounted, which is exactly the case this asserts on.
    $collector = New-TargetCollector
    Add-WacTarget -TargetList $collector.TargetList -Seen $collector.Seen -SkipCategory @() `
        -Mode Directory -Category 'probe' -Path ($offDrive + '\Temp')

    Assert-Equal 0 $collector.TargetList.Count 'an off-drive path became a deletion target'
}

Test-Case 'Add-WacTarget drops an unnormalisable path' {
    $collector = New-TargetCollector
    foreach ($path in @('', '   ', 'C:relative\path', '\\server\share\cache')) {
        Add-WacTarget -TargetList $collector.TargetList -Seen $collector.Seen -SkipCategory @() `
            -Mode Directory -Category 'probe' -Path $path
    }

    Assert-Equal 0 $collector.TargetList.Count 'a UNC, drive-relative or empty path became a deletion target'
}

Test-Case 'Add-WacTarget collapses a duplicate path but keeps a different Mode' {
    $collector = New-TargetCollector
    $path = Join-Path -Path ($script:CleanupDrive + '\') -ChildPath 'Windows\Temp'

    Add-WacTarget -TargetList $collector.TargetList -Seen $collector.Seen -SkipCategory @() -Mode Directory -Category 'first' -Path $path
    Add-WacTarget -TargetList $collector.TargetList -Seen $collector.Seen -SkipCategory @() -Mode Directory -Category 'second' -Path ($path.ToLowerInvariant() + '\')
    Add-WacTarget -TargetList $collector.TargetList -Seen $collector.Seen -SkipCategory @() -Mode Pattern -Category 'third' -Path $path -Pattern @('*.db')

    Assert-Equal 2 $collector.TargetList.Count 'de-duplication must key on Mode AND path, case-insensitively'
    Assert-Equal 'first' $collector.TargetList[0].Category 'the first occurrence must win'
    Assert-Equal 'Pattern' $collector.TargetList[1].Mode
}

Test-Case 'Add-WacTarget honours SkipCategory case-insensitively' {
    $collector = New-TargetCollector
    Add-WacTarget -TargetList $collector.TargetList -Seen $collector.Seen -SkipCategory @('PROBE') `
        -Mode Directory -Category 'probe' -Path (Join-Path -Path ($script:CleanupDrive + '\') -ChildPath 'Windows\Temp')

    Assert-Equal 0 $collector.TargetList.Count
}

# ---------------------------------------------------------------------------------------------
# Get-WacEdgeProfilePath
# ---------------------------------------------------------------------------------------------

Test-Case 'Get-WacEdgeProfilePath returns only Default and numbered profiles' {
    $sandbox = New-TestSandbox -Prefix 'tg-edge'
    try {
        $userData = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'User Data')
        foreach ($leaf in @('Default', 'Profile 1', 'Profile 42', 'BrowserMetrics', 'Ad Blocking', 'Profile', 'Profile X', 'Profile 1 (2)', 'default extra')) {
            [void](New-TestDirectory (Join-Path -Path $userData -ChildPath $leaf))
        }
        [System.IO.File]::WriteAllText((Join-Path -Path $userData -ChildPath 'Local State'), '{}')

        $found = @(Get-WacEdgeProfilePath -UserDataPath $userData)
        $leafName = @($found | ForEach-Object { Split-Path -Leaf $_ } | Sort-Object)

        Assert-Equal 3 $found.Count ('returned: {0}' -f ($leafName -join '; '))
        Assert-Equal 'Default,Profile 1,Profile 42' ($leafName -join ',')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Get-WacEdgeProfilePath never returns a reparse point' {
    $sandbox = New-TestSandbox -Prefix 'tg-edgelink'
    try {
        $userData = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'User Data')
        [void](New-TestDirectory (Join-Path -Path $userData -ChildPath 'Default'))

        $outside = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'elsewhere')
        [System.IO.File]::WriteAllText((Join-Path -Path $outside -ChildPath 'must-survive.txt'), 'sentinel')
        $link = Join-Path -Path $userData -ChildPath 'Profile 7'
        New-Item -ItemType Junction -Path $link -Target $outside -ErrorAction Stop | Out-Null

        $found = @(Get-WacEdgeProfilePath -UserDataPath $userData)

        Assert-Equal 1 $found.Count ('returned: {0}' -f ($found -join '; '))
        Assert-Equal 'Default' (Split-Path -Leaf $found[0])
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $outside -ChildPath 'must-survive.txt')) 'the junction target was disturbed'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Get-WacEdgeProfilePath returns nothing for a missing or file-shaped User Data root' {
    $sandbox = New-TestSandbox -Prefix 'tg-edgemissing'
    try {
        Assert-Equal 0 (@(Get-WacEdgeProfilePath -UserDataPath (Join-Path -Path $sandbox -ChildPath 'absent'))).Count

        $file = Join-Path -Path $sandbox -ChildPath 'User Data'
        [System.IO.File]::WriteAllText($file, 'not a directory')
        Assert-Equal 0 (@(Get-WacEdgeProfilePath -UserDataPath $file)).Count
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
