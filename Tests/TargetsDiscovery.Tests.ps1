#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the COMPLETENESS of cleanup discovery (ledger WAC-07): an unreadable
    source must never be reported as an absent one, and a healthy fallback must never be reported
    as an unfinished run.

.DESCRIPTION
    Split out of Targets.Tests.ps1, which was at the 800-line ceiling. That suite answers "what may
    this tool delete"; this one answers the different question "is that all of it", which the old
    code could not express at all: Win32_UserProfile failing, the ProfileList key failing, one
    profile's ProfileImagePath failing and an Edge User Data directory refusing to enumerate all
    produced the same empty array a genuinely empty machine produces, and the bounded wrapper then
    promoted it to a clean success.

    Nothing here deletes anything and nothing runs a cleanup step. The filesystem writes are
    disposable profile-shaped trees under TEMP; the registry writes are a per-process scratch key
    under HKCU shaped like ProfileList, never the real key. Access denials are simulated by shadowing
    the provider call inside the module under test, because rewriting an ACL is banned in shipped
    code and this suite is shipped code.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
foreach ($moduleLeaf in @('Core', 'FileSystem', 'Targets')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

$script:CoreModule = Get-Module -Name 'WindowsAutoCleanup.Core'
$script:TargetsModule = Get-Module -Name 'WindowsAutoCleanup.Targets'

# A registry root unique to this process: the two hosts run their suites concurrently against the
# same HKCU hive, so a fixed key name would make them race each other.
$script:ProfileScratchRoot = 'HKCU:\Software\WacTests_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12)

function Set-ModuleFunctionBody {
    <#
    .SYNOPSIS
        Replaces a name inside a module's own scope. Only that module sees the replacement.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
}

function Remove-ModuleFunction {
    <#
    .SYNOPSIS
        Removes a shadow installed by Set-ModuleFunctionBody.
    .DESCRIPTION
        No scope qualifier: 'function:script:<name>' is accepted by Set-Item but does not remove.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    & $Module { param($n) Remove-Item -Path ('function:' + $n) -Force -ErrorAction SilentlyContinue } $Name
}

function New-TestDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    [void][System.IO.Directory]::CreateDirectory($Path)
    return $Path
}

function Get-GapText {
    <#
    .SYNOPSIS
        A one-line rendering of a gap collector, so a failed assertion names what was recorded.
    .DESCRIPTION
        foreach rather than @($Gap): wrapping a System.Collections.Generic.List[object] in @()
        throws "Argument types do not match" on BOTH shipped hosts, and this runs on the passing
        path too because an assertion's message argument is evaluated before the assertion is.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Gap)

    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in $Gap) { [void]$parts.Add(('{0}|{1}|{2}' -f $entry.Source, $entry.Scope, $entry.Reason)) }
    return ($parts -join ' ;; ')
}

# ---------------------------------------------------------------------------------------------
# Get-WacEdgeProfilePath
# ---------------------------------------------------------------------------------------------

Test-Case 'an existing Edge User Data directory that cannot be enumerated is a gap, not zero profiles' {
    $sandbox = New-TestSandbox -Prefix 'tg-edgedenied'
    try {
        $userData = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'User Data')
        [void](New-TestDirectory (Join-Path -Path $userData -ChildPath 'Default'))

        # The directory really exists and really holds a profile; only the ENUMERATION fails, which
        # is the shape an access-denied User Data directory has.
        Set-ModuleFunctionBody -Module $script:TargetsModule -Name 'Get-ChildItem' -Body ({
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [switch]$Directory, [switch]$Force
            )
            if ($LiteralPath -eq $userData) { throw (New-Object System.UnauthorizedAccessException('Access to the path is denied.')) }
            return (Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Directory:$Directory -Force:$Force -ErrorAction Stop)
        }.GetNewClosure())

        try {
            $gap = New-Object 'System.Collections.Generic.List[object]'
            $found = @(Get-WacEdgeProfilePath -UserDataPath $userData -Gap $gap)

            Assert-Equal 0 $found.Count 'an unreadable directory must not produce guessed profiles'
            Assert-Equal 1 $gap.Count ('the denied enumeration was reported as "no profiles": {0}' -f (Get-GapText -Gap $gap))
            Assert-Equal 'EdgeProfile' ([string]$gap[0].Source)
            Assert-Equal $userData ([string]$gap[0].Scope)
            Assert-True ([string]$gap[0].Reason -match 'could not be enumerated') ([string]$gap[0].Reason)
        }
        finally {
            Remove-ModuleFunction -Module $script:TargetsModule -Name 'Get-ChildItem'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an absent or file-shaped Edge User Data root is an answer, not a gap' {
    # Deliberately excluded and genuinely absent are ANSWERS. Reporting them would make an ordinary
    # machine that has never run Edge look like a failed discovery on every single run.
    $sandbox = New-TestSandbox -Prefix 'tg-edgeabsent'
    try {
        $gap = New-Object 'System.Collections.Generic.List[object]'
        Assert-Equal 0 (@(Get-WacEdgeProfilePath -UserDataPath (Join-Path -Path $sandbox -ChildPath 'absent') -Gap $gap)).Count

        $file = Join-Path -Path $sandbox -ChildPath 'User Data'
        [System.IO.File]::WriteAllText($file, 'not a directory')
        Assert-Equal 0 (@(Get-WacEdgeProfilePath -UserDataPath $file -Gap $gap)).Count

        Assert-Equal 0 $gap.Count ('an absent path was reported as unfinished discovery: {0}' -f (Get-GapText -Gap $gap))
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Get-WacUserProfilePath: CIM, its registry fallback, and which failures are actually gaps
#
# Both providers are shadowed inside the CORE module, which is where the function lives. The
# ProfileList replacement returns REAL scratch keys under HKCU rather than invented objects, so the
# code under test does the same Get-ItemProperty read it does in production.
# ---------------------------------------------------------------------------------------------

function New-ScratchProfileList {
    <#
    .SYNOPSIS
        A ProfileList-shaped scratch key: one SID pointing at a real synthetic profile directory and
        one that carries no ProfileImagePath at all.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$GoodProfilePath
    )

    foreach ($sid in @('S-1-5-21-100-100-100-1001', 'S-1-5-21-100-100-100-1002')) {
        [void](New-Item -Path (Join-Path -Path $KeyPath -ChildPath $sid) -Force -ErrorAction Stop)
    }
    [void](New-ItemProperty -LiteralPath (Join-Path -Path $KeyPath -ChildPath 'S-1-5-21-100-100-100-1001') `
        -Name 'ProfileImagePath' -PropertyType String -Value $GoodProfilePath -Force -ErrorAction Stop)
    return $KeyPath
}

function New-SyntheticProfileDirectory {
    <#
    .SYNOPSIS
        A directory the registry fallback accepts: on the cleanup drive and carrying a user hive.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    [void](New-TestDirectory $Path)
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'ntuser.dat'), 'hive')
    return (Get-WacNormalizedPath -Path $Path)
}

function Set-CimFailure {
    <#
    .SYNOPSIS
        Makes Win32_UserProfile unavailable inside Core, the way it is on a host whose WMI
        repository is broken.
    #>
    Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-CimInstance' -Body {
        param([Parameter(Mandatory = $true)][string]$ClassName)
        throw (New-Object System.InvalidOperationException(('the CIM class {0} is unavailable' -f $ClassName)))
    }
}

function Set-ProfileListSource {
    <#
    .SYNOPSIS
        Points Core's ProfileList enumeration at a scratch key, or makes it fail outright.
    #>
    param([string]$KeyPath, [switch]$Fail)

    $scratch = $KeyPath
    $shouldFail = [bool]$Fail
    Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-ChildItem' -Body ({
        param([Parameter(Mandatory = $true)][string]$LiteralPath)

        if ($LiteralPath -notmatch 'ProfileList') {
            return (Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -ErrorAction Stop)
        }
        if ($shouldFail) { throw (New-Object System.Security.SecurityException('Requested registry access is not allowed.')) }
        return (Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $scratch -ErrorAction Stop)
    }.GetNewClosure())
}

function Set-ProfileImagePathFailure {
    <#
    .SYNOPSIS
        Makes exactly ONE scratch SID unreadable, so the fallback returns a PARTIAL list rather than
        no list at all - the case a bare array cannot express.
    #>
    param([Parameter(Mandatory = $true)][string]$Sid)

    $failing = $Sid
    # -Name is optional here because the code under test deliberately reads the whole key: asking
    # for one value cannot tell an unreadable key from a key that simply has no such value.
    Set-ModuleFunctionBody -Module $script:CoreModule -Name 'Get-ItemProperty' -Body ({
        param([Parameter(Mandatory = $true)][string]$LiteralPath, [string]$Name)

        if ($LiteralPath -match $failing) { throw (New-Object System.Security.SecurityException('Requested registry access is not allowed.')) }
        if ($Name) { return (Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $LiteralPath -Name $Name -ErrorAction Stop) }
        return (Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $LiteralPath -ErrorAction Stop)
    }.GetNewClosure())
}

function Clear-ProfileShadow {
    foreach ($name in @('Get-CimInstance', 'Get-ChildItem', 'Get-ItemProperty')) {
        Remove-ModuleFunction -Module $script:CoreModule -Name $name
    }
}

Test-Case 'a CIM failure recovered by a healthy ProfileList fallback is a COMPLETE discovery' {
    # The one case that must NOT be flagged. A fallback exists to answer the question, and a machine
    # whose WMI service is unavailable is not a machine whose cleanup is unfinished.
    $sandbox = New-TestSandbox -Prefix 'tg-profok'
    try {
        $good = New-SyntheticProfileDirectory -Path (Join-Path -Path $sandbox -ChildPath 'Users\good')
        $scratch = New-ScratchProfileList -KeyPath (Join-Path -Path $script:ProfileScratchRoot -ChildPath 'Ok') -GoodProfilePath $good

        Set-CimFailure
        Set-ProfileListSource -KeyPath $scratch
        # The REAL Get-ItemProperty runs here, over a scratch list whose second SID carries no
        # ProfileImagePath at all. A malformed entry is an answer, so it must not become a gap.
        try {
            $gap = New-Object 'System.Collections.Generic.List[object]'
            $found = @(Get-WacUserProfilePath -Gap $gap)

            Assert-True ((@($found) -ccontains $good)) ('the fallback did not recover the profile: {0}' -f ($found -join '; '))
            Assert-Equal 0 $gap.Count ('a healthy fallback was reported as unfinished: {0}' -f (Get-GapText -Gap $gap))
        }
        finally {
            Clear-ProfileShadow
        }
    }
    finally {
        Remove-Item -LiteralPath $script:ProfileScratchRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'both profile providers failing is a gap, not an empty machine' {
    Set-CimFailure
    Set-ProfileListSource -Fail
    try {
        $gap = New-Object 'System.Collections.Generic.List[object]'
        $found = @(Get-WacUserProfilePath -Gap $gap)

        Assert-Equal 0 $found.Count 'an unanswered discovery must not invent profiles'
        Assert-Equal 1 $gap.Count ('two failed providers were reported as "no profiles": {0}' -f (Get-GapText -Gap $gap))
        Assert-Equal 'UserProfile' ([string]$gap[0].Source)
        Assert-Equal 'ProfileList' ([string]$gap[0].Scope)
        Assert-True ([string]$gap[0].Reason -match 'neither Win32_UserProfile') ([string]$gap[0].Reason)
    }
    finally {
        Clear-ProfileShadow
    }
}

Test-Case 'one unreadable profile leaves a partial list AND a gap naming it' {
    $sandbox = New-TestSandbox -Prefix 'tg-profpart'
    try {
        $good = New-SyntheticProfileDirectory -Path (Join-Path -Path $sandbox -ChildPath 'Users\good')
        $scratch = New-ScratchProfileList -KeyPath (Join-Path -Path $script:ProfileScratchRoot -ChildPath 'Partial') -GoodProfilePath $good

        Set-CimFailure
        Set-ProfileListSource -KeyPath $scratch
        Set-ProfileImagePathFailure -Sid 'S-1-5-21-100-100-100-1002'
        try {
            $gap = New-Object 'System.Collections.Generic.List[object]'
            $found = @(Get-WacUserProfilePath -Gap $gap)

            # The readable half is still returned: an unreadable neighbour is no reason to stop
            # cleaning a profile this run could read.
            Assert-True ((@($found) -ccontains $good)) ('the readable profile was dropped: {0}' -f ($found -join '; '))
            Assert-Equal 1 $gap.Count ('a dropped profile was reported as a complete list: {0}' -f (Get-GapText -Gap $gap))
            Assert-Equal 'UserProfile' ([string]$gap[0].Source)
            Assert-Equal 'S-1-5-21-100-100-100-1002' ([string]$gap[0].Scope)
        }
        finally {
            Clear-ProfileShadow
        }
    }
    finally {
        Remove-Item -LiteralPath $script:ProfileScratchRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a working CIM query is not made incomplete by a failing confirmation pass' {
    # Win32_UserProfile is the authoritative source. Once it has completed, a ProfileList read that
    # fails afterwards cannot un-answer the question, and treating it as a gap would make a run on a
    # locked-down machine permanently Incomplete over no missing content at all.
    Set-ProfileListSource -Fail
    try {
        $gap = New-Object 'System.Collections.Generic.List[object]'
        [void]@(Get-WacUserProfilePath -Gap $gap)

        Assert-Equal 0 $gap.Count ('an authoritative answer was overruled by its fallback: {0}' -f (Get-GapText -Gap $gap))
    }
    finally {
        Clear-ProfileShadow
    }
}

# ---------------------------------------------------------------------------------------------
# Get-WacCleanupTargetSet: the bound's verdict reconciled with what the builder actually did
#
# These run the REAL Invoke-WacBounded. The builder is replaced by pointing the module's import path
# at a small probe module, so the evidence genuinely travels out of the runspace the bound creates -
# which is the only place the builder's own module state exists.
# ---------------------------------------------------------------------------------------------

function Invoke-WithProbeBuilder {
    <#
    .SYNOPSIS
        Runs the assertion with Get-WacCleanupTargetSet bounding a probe builder instead of the real
        one, then puts the real import path back.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Body,
        [Parameter(Mandatory = $true)][scriptblock]$Assertion
    )

    $sandbox = New-TestSandbox -Prefix 'tg-probe'
    $original = & $script:TargetsModule { Get-Variable -Name 'TargetsModulePath' -ValueOnly -Scope Script }
    try {
        $probe = Join-Path -Path $sandbox -ChildPath 'WacProbeTargets.psm1'
        [System.IO.File]::WriteAllText($probe, $Body, (New-Object System.Text.UTF8Encoding($false)))
        & $script:TargetsModule { param($p) Set-Variable -Name 'TargetsModulePath' -Value $p -Scope Script } $probe

        & $Assertion
    }
    finally {
        & $script:TargetsModule { param($p) Set-Variable -Name 'TargetsModulePath' -Value $p -Scope Script } $original
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a discovery gap crosses the bound and makes the allow-list Incomplete' {
    $probe = @'
function Get-WacCleanupTarget {
    param([string[]]$SkipCategory = @())
    $null = $SkipCategory
    return @([PSCustomObject]@{ Mode = 'Directory'; Category = 'probe'; Path = 'C:\probe'; DeleteRoot = $false; Pattern = @() })
}

function Get-WacTargetDiscoveryGap {
    return @([PSCustomObject]@{ Source = 'UserProfile'; Scope = 'ProfileList'; Reason = 'the probe could not finish' })
}

Export-ModuleMember -Function @('Get-WacCleanupTarget', 'Get-WacTargetDiscoveryGap')
'@

    Invoke-WithProbeBuilder -Body $probe -Assertion {
        $set = Get-WacCleanupTargetSet

        Assert-Equal 'Incomplete' $set.Outcome ('an unfinished discovery was reported as a clean run: {0}' -f $set.Detail)
        Assert-Equal 1 (@($set.Gap)).Count ('the gap did not survive the runspace boundary: {0}' -f $set.Detail)
        Assert-Equal 'ProfileList' ([string]@($set.Gap)[0].Scope)
        Assert-True ($set.Detail -match 'could not be finished') $set.Detail

        # The targets that WERE found are still offered: a failed neighbour is not a reason to stop
        # cleaning what this run could see, and the list is never widened to compensate either.
        Assert-Equal 1 (@($set.Target)).Count ('the discovered targets were dropped: {0}' -f $set.Detail)
    }
}

Test-Case 'a non-terminating builder error makes the allow-list Incomplete' {
    # Invoke-WacBounded leaves Outcome Succeeded and sets HadErrors for an error the worker wrote
    # rather than threw, so the wrapper - not the bound - is what has to notice it.
    $probe = @'
function Get-WacCleanupTarget {
    param([string[]]$SkipCategory = @())
    $null = $SkipCategory
    Write-Error 'the probe could not read one profile'
    return @()
}

function Get-WacTargetDiscoveryGap { return @() }

Export-ModuleMember -Function @('Get-WacCleanupTarget', 'Get-WacTargetDiscoveryGap')
'@

    Invoke-WithProbeBuilder -Body $probe -Assertion {
        $set = Get-WacCleanupTargetSet

        Assert-Equal 'Incomplete' $set.Outcome ('a reported worker error was promoted to a clean run: {0}' -f $set.Detail)
        Assert-True ($set.Detail -match 'non-terminating error') $set.Detail
    }
}

Test-Case 'a genuinely empty discovery is still a clean success' {
    # The control for both cases above. "Nothing eligible exists" is an answer, and a run that read
    # every source and found nothing must not be dragged to a non-zero exit code.
    $probe = @'
function Get-WacCleanupTarget {
    param([string[]]$SkipCategory = @())
    $null = $SkipCategory
    return @()
}

function Get-WacTargetDiscoveryGap { return @() }

Export-ModuleMember -Function @('Get-WacCleanupTarget', 'Get-WacTargetDiscoveryGap')
'@

    Invoke-WithProbeBuilder -Body $probe -Assertion {
        $set = Get-WacCleanupTargetSet

        Assert-Equal 'Succeeded' $set.Outcome $set.Detail
        Assert-Equal 0 (@($set.Target)).Count
        Assert-Equal 0 (@($set.Gap)).Count
        Assert-True ($set.Detail -match 'holds 0 target') $set.Detail
    }
}

Test-Case 'off-drive, reparse-point and special profiles are exclusions, never gaps' {
    # The controls the over-reporting direction needs. Every one of these is a decision this tool
    # made deliberately, so recording them would put a permanent Incomplete on an ordinary machine
    # and teach the operator to ignore the one line that means something.
    $sandbox = New-TestSandbox -Prefix 'tg-excl'
    try {
        # A reparse point where a Chromium profile would be. It is skipped, and the root it points
        # at is not touched - but the User Data directory itself enumerated perfectly.
        $userData = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'User Data')
        [void](New-TestDirectory (Join-Path -Path $userData -ChildPath 'Default'))
        $outside = New-TestDirectory (Join-Path -Path $sandbox -ChildPath 'elsewhere')
        New-Item -ItemType Junction -Path (Join-Path -Path $userData -ChildPath 'Profile 7') -Target $outside -ErrorAction Stop | Out-Null

        $gap = New-Object 'System.Collections.Generic.List[object]'
        $found = @(Get-WacEdgeProfilePath -UserDataPath $userData -Gap $gap)

        Assert-Equal 1 $found.Count ('returned: {0}' -f ($found -join '; '))
        Assert-Equal 0 $gap.Count ('a skipped reparse point was reported as unfinished: {0}' -f (Get-GapText -Gap $gap))

        # The profile side: a well-known service SID, a '.bak' entry Windows itself renamed, and a
        # profile that lives off the cleanup drive. All three are answers.
        $scratch = Join-Path -Path $script:ProfileScratchRoot -ChildPath 'Excluded'
        $entry = @{
            'S-1-5-18'                    = (Join-Path -Path $env:SystemRoot -ChildPath 'System32\config\systemprofile')
            'S-1-5-21-100-100-100-9.bak'  = (Join-Path -Path $sandbox -ChildPath 'Users\renamed')
            'S-1-5-21-100-100-100-8'      = 'Z:\Users\offdrive'
        }
        foreach ($sid in @($entry.Keys)) {
            [void](New-Item -Path (Join-Path -Path $scratch -ChildPath $sid) -Force -ErrorAction Stop)
            [void](New-ItemProperty -LiteralPath (Join-Path -Path $scratch -ChildPath $sid) `
                -Name 'ProfileImagePath' -PropertyType String -Value ([string]$entry[$sid]) -Force -ErrorAction Stop)
        }

        Set-CimFailure
        Set-ProfileListSource -KeyPath $scratch
        try {
            $profileGap = New-Object 'System.Collections.Generic.List[object]'
            $profiles = @(Get-WacUserProfilePath -Gap $profileGap)

            Assert-Equal 0 $profiles.Count ('an excluded profile became a cleanup target: {0}' -f ($profiles -join '; '))
            Assert-Equal 0 $profileGap.Count ('a deliberate exclusion was reported as unfinished: {0}' -f (Get-GapText -Gap $profileGap))
        }
        finally {
            Clear-ProfileShadow
        }
    }
    finally {
        Remove-Item -LiteralPath $script:ProfileScratchRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
