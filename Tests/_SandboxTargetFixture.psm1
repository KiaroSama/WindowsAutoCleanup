#Requires -Version 5.1
<#
.SYNOPSIS
    The elevated harness's POSITIVE cleanup fixture: an explicit target set confined to one sandbox
    directory, validated before the child mutates anything and revalidated immediately before each
    delete (ledger WAC-10).

.DESCRIPTION
    This module has two homes and the same behaviour in both.

      * Tests\ - imported directly by SandboxPlanGuard.Tests.ps1, which is where every rejection in
        here is proven.
      * <scratch>\src\WindowsAutoCleanup.Targets.psm1 - copied over the real allow-list builder in a
        disposable scratch COPY of the repository, which is what the elevated harness launches. The
        shipped module is never edited and never reads anything this module reads.

    WHY IT EXISTS. The harness used to scope its child by DENY-LIST: it enumerated the categories the
    parent could see and passed them to -SkipCategory. That is unsound in two independent ways.
    A category name has to be KNOWN to be denied, and two real-profile categories - 'Microsoft Edge
    cache' and 'Windows Explorer thumbnail cache' - are built outside the static per-profile table
    the deny-list was read from, so neither was ever in it. And the parent's enumeration is not the
    child's: redirecting TEMP, ProgramData and LOCALAPPDATA does not redirect the profile paths CIM
    returns, so a parent that discovers no profile hands over a deny-list that scopes nothing while
    the elevated child discovers the operator's real profile and sweeps it.

    So the list is INVERTED. The child is given an explicit set of paths, every one of them built
    from the sandbox root, and the set is checked for containment before it is handed over. Nothing
    here consults a category name to decide what may be deleted: containment decides, which is why a
    category added to the shipped allow-list tomorrow needs no change here.

    THE ROOT IS PINNED ONCE. It is read from the WAC_VERIFY_SANDBOX_ROOT environment variable on
    first use and cached for the life of the process, so a variable changed mid-run cannot widen what
    the consumption check accepts. An absent, unnormalisable or non-existent value produces no
    targets at all and a terminating error - this fixture fails closed, and it is the only reader of
    that variable anywhere in the repository.
#>

Set-StrictMode -Version 2.0

# Core carries Get-WacNormalizedPath and Test-WacIsWithinRoot, the two primitives every check here
# is built on. Two homes, so the path is resolved rather than assumed: beside this file in a scratch
# src\ tree, or under the repository's src\ when the suite imports it from Tests\.
$script:CoreModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1'
if (-not (Test-Path -LiteralPath $script:CoreModulePath -PathType Leaf)) {
    $script:CoreModulePath = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'src\WindowsAutoCleanup.Core.psm1'
}
Import-Module -Name $script:CoreModulePath -DisableNameChecking -ErrorAction Stop

# Test-only, and read by nothing else in this repository. The shipped safety checks take no input
# from the environment; this fixture only ever NARROWS what may be deleted to one directory, and
# refuses outright when the value is missing or unusable.
$script:SandboxRootVariable = 'WAC_VERIFY_SANDBOX_ROOT'

# Pinned on first use. Null means "not read yet", never "no restriction".
$script:PinnedSandboxRoot = $null

function Reset-WacSandboxFixture {
    <#
    .SYNOPSIS
        Drops the pinned sandbox root so the next call re-reads the environment.
    .DESCRIPTION
        For the suite, which walks several roots in one process. A child runs one sandbox and never
        calls this.
    #>
    param()

    $script:PinnedSandboxRoot = $null
}

function Get-WacSandboxFixtureRoot {
    <#
    .SYNOPSIS
        The one directory this fixture may delete inside, pinned for the life of the process.
    #>
    param()

    if ($script:PinnedSandboxRoot) { return $script:PinnedSandboxRoot }

    $raw = [System.Environment]::GetEnvironmentVariable($script:SandboxRootVariable)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw ('{0} is not set, so no directory is authorised for deletion; refusing to produce a target' -f $script:SandboxRootVariable)
    }

    $normalized = Get-WacNormalizedPath -Path $raw
    if (-not $normalized) {
        throw ('{0} does not normalise to a usable path ({1}); refusing to produce a target' -f $script:SandboxRootVariable, $raw)
    }
    if (-not (Test-Path -LiteralPath $normalized -PathType Container)) {
        throw ('the sandbox root {0} is not an existing directory; refusing to produce a target' -f $normalized)
    }

    $script:PinnedSandboxRoot = $normalized
    return $script:PinnedSandboxRoot
}

function New-WacSandboxFixtureTarget {
    <#
    .SYNOPSIS
        The explicit positive target set: every path built from the sandbox root, nothing discovered.
    .DESCRIPTION
        Two of the three categories are exactly the ones the old deny-list could never contain,
        because the shipped builder constructs them outside its static per-profile table. They are
        here to make that difference visible in the fixture itself: under the inverted rule their
        names buy them nothing, and their PATHS are what put them in scope.

        An entry whose directory does not exist costs nothing - the sweep reports it as unattempted
        and writes no result line - so the set is the same for every scenario.
    #>
    param([Parameter(Mandatory = $true)][string]$SandboxRoot)

    return @(
        [PSCustomObject]@{
            Mode       = 'Directory'
            Category   = 'Defender cleanup files'
            Path       = (Join-Path -Path $SandboxRoot -ChildPath 'PD\Microsoft\Windows Defender\LocalCopy')
            DeleteRoot = $false
            Pattern    = [string[]]@()
        }
        [PSCustomObject]@{
            Mode       = 'Directory'
            Category   = 'Microsoft Edge cache'
            Path       = (Join-Path -Path $SandboxRoot -ChildPath 'LA\Microsoft\Edge\User Data\Default\Cache\Cache_Data')
            DeleteRoot = $false
            Pattern    = [string[]]@()
        }
        [PSCustomObject]@{
            Mode       = 'Pattern'
            Category   = 'Windows Explorer thumbnail cache'
            Path       = (Join-Path -Path $SandboxRoot -ChildPath 'LA\Microsoft\Windows\Explorer')
            DeleteRoot = $false
            Pattern    = [string[]]@('thumbcache_*.db', 'iconcache_*.db')
        }
    )
}

function Test-WacSandboxPlan {
    <#
    .SYNOPSIS
        Judges a whole deletion plan against one sandbox root. Valid only when EVERY entry is inside.
    .DESCRIPTION
        The check is Get-WacNormalizedPath plus the shipped Test-WacIsWithinRoot, which is
        prefix-safe at the separator - the reason a sibling named '...\sandbox-other' is outside
        '...\sandbox' while a plain StartsWith would accept it.

        An entry with no readable Path is rejected rather than skipped. A property getter that
        throws reads as $null on both shipped hosts instead of raising, so "it had no path" and "its
        path could not be read" are the same observation here, and both mean the entry cannot be
        proven contained.
    .OUTPUTS
        Valid, Checked, Rejected (one sentence per refused entry) and the normalised Root.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$Plan,
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$SandboxRoot
    )

    $rejected = New-Object 'System.Collections.Generic.List[string]'

    $root = Get-WacNormalizedPath -Path $SandboxRoot
    if (-not $root) {
        [void]$rejected.Add(('the sandbox root {0} does not normalise, so no entry can be proven contained' -f $SandboxRoot))
        return [PSCustomObject]@{ Valid = $false; Checked = 0; Rejected = @($rejected.ToArray()); Root = '' }
    }

    $checked = 0
    foreach ($entry in @($Plan)) {
        $checked++

        $path = ''
        $category = '<unnamed>'
        try { $path = [string]$entry.Path } catch { $path = '' }
        try { $category = [string]$entry.Category } catch { $category = '<unnamed>' }

        if ([string]::IsNullOrWhiteSpace($path)) {
            [void]$rejected.Add(('entry {0} (category {1}) carries no readable path' -f $checked, $category))
            continue
        }
        if (-not (Test-WacIsWithinRoot -ChildPath $path -RootPath $root)) {
            [void]$rejected.Add(('entry {0} is outside the sandbox: category={1} path={2} root={3}' -f $checked, $category, $path, $root))
        }
    }

    return [PSCustomObject]@{
        Valid    = ($rejected.Count -eq 0)
        Checked  = $checked
        Rejected = @($rejected.ToArray())
        Root     = $root
    }
}

function Assert-WacSandboxPlan {
    <#
    .SYNOPSIS
        The pre-mutation gate: returns the verdict, or throws naming every entry that is outside.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$Plan,
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$SandboxRoot
    )

    $verdict = Test-WacSandboxPlan -Plan $Plan -SandboxRoot $SandboxRoot
    if ($verdict.Valid) { return $verdict }

    throw ('the deletion plan was refused before any mutation: {0}' -f (@($verdict.Rejected) -join '; '))
}

function Assert-WacSandboxPath {
    <#
    .SYNOPSIS
        The consumption gate, run immediately before one delete against the PINNED root.
    .DESCRIPTION
        Separate from the plan gate on purpose: a plan is a set of objects a caller holds, and an
        object can be replaced between the moment the set was judged and the moment one of its
        entries is used. Judging the path again here is what makes the swap unprofitable.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Category,
        [Parameter(Mandatory = $true)][string]$Stage
    )

    $root = Get-WacSandboxFixtureRoot
    if (-not (Test-WacIsWithinRoot -ChildPath $Path -RootPath $root)) {
        throw ('{0} refused a target outside the sandbox at consumption: category={1} path={2} root={3}' -f `
                $Stage, $Category, $Path, $root)
    }
}

function Get-WacSandboxRealCommand {
    <#
    .SYNOPSIS
        The real FileSystem implementation this module shadows, taken from the module that owns it.
    .DESCRIPTION
        Resolved through the module rather than by name: this module exports functions with the same
        names, is imported after FileSystem, and therefore wins command resolution in the caller's
        session - so calling by name from in here would recurse.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $module = Get-Module -Name 'WindowsAutoCleanup.FileSystem'
    if (-not $module) {
        throw ('the FileSystem module is not loaded, so {0} cannot be delegated' -f $Name)
    }

    $command = $module.ExportedFunctions[$Name]
    if (-not $command) {
        throw ('the FileSystem module does not export {0}' -f $Name)
    }
    return $command
}

function Remove-WacTree {
    <#
    .SYNOPSIS
        Revalidates one directory target against the pinned sandbox root, then delegates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$DeleteRoot
    )

    Assert-WacSandboxPath -Path $Path -Category $Category -Stage 'Remove-WacTree'
    return (& (Get-WacSandboxRealCommand -Name 'Remove-WacTree') -Category $Category -Path $Path -DeleteRoot:([bool]$DeleteRoot))
}

function Remove-WacFilesByPattern {
    <#
    .SYNOPSIS
        Revalidates one pattern target against the pinned sandbox root, then delegates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Pattern
    )

    Assert-WacSandboxPath -Path $Path -Category $Category -Stage 'Remove-WacFilesByPattern'
    return (& (Get-WacSandboxRealCommand -Name 'Remove-WacFilesByPattern') -Category $Category -Path $Path -Pattern $Pattern)
}

function Get-WacCleanupTarget {
    <#
    .SYNOPSIS
        The fixture's allow-list. Same contract as the shipped builder, none of its discovery.
    .PARAMETER SkipCategory
        Honoured so the shipped call site keeps its meaning, but it is NOT what scopes this list.
        The old harness relied on exactly that, and the two categories it could not name escaped it.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([AllowEmptyCollection()][string[]]$SkipCategory = @())

    $root = Get-WacSandboxFixtureRoot
    $kept = New-Object 'System.Collections.Generic.List[object]'

    foreach ($entry in (New-WacSandboxFixtureTarget -SandboxRoot $root)) {
        $skipped = $false
        foreach ($name in @($SkipCategory)) {
            if ([string]$entry.Category -ieq [string]$name) {
                $skipped = $true
                break
            }
        }
        if (-not $skipped) { [void]$kept.Add($entry) }
    }

    return @($kept.ToArray())
}

function Get-WacTargetDiscoveryGap {
    <#
    .SYNOPSIS
        Always empty: this fixture discovers nothing, so there is nothing it could fail to finish.
    #>
    [OutputType([object[]])]
    param()

    return @()
}

function Get-WacEdgeProfilePath {
    <#
    .SYNOPSIS
        Always empty. Kept so the module presents the shipped surface; the fixture walks no profile.
    #>
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)][string]$UserDataPath,
        [AllowNull()][System.Collections.Generic.List[object]]$Gap
    )

    $null = $UserDataPath
    $null = $Gap
    return @()
}

function Get-WacCleanupTargetSet {
    <#
    .SYNOPSIS
        The bounded builder's contract, with the containment gate in front of the returned list.
    .DESCRIPTION
        THIS is the pre-mutation gate in a real run. Run.ps1 takes the target list from here and only
        then enters its deletion loop, so a plan holding one entry outside the sandbox returns
        Failed with an EMPTY list and the loop never runs - nothing is deleted, not even the entries
        that were legal.

        No runspace and no bound: there is nothing to bound. The shipped builder walks every profile
        and queries CIM; this one joins three paths to a string.
    .OUTPUTS
        Outcome (Succeeded | Failed), Target, Gap, Detail, DurationMs.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$SkipCategory = @())

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $outcome = 'Failed'
    $target = @()
    $detail = ''

    try {
        $root = Get-WacSandboxFixtureRoot
        $plan = @(Get-WacCleanupTarget -SkipCategory $SkipCategory)
        $verdict = Test-WacSandboxPlan -Plan $plan -SandboxRoot $root

        if ($verdict.Valid) {
            $outcome = 'Succeeded'
            $target = $plan
            $detail = 'The sandbox fixture holds {0} target(s), all proven inside {1}.' -f $verdict.Checked, $verdict.Root
        }
        else {
            $detail = 'The sandbox fixture plan was refused before any mutation: {0}' -f (@($verdict.Rejected) -join '; ')
            Write-WacLog -Level CRITICAL -Component 'Targets' -Message 'The sandbox fixture refused its own deletion plan; nothing was attempted.' -Data @{
                rejected = (@($verdict.Rejected) -join '; ')
            }
        }
    }
    catch {
        $detail = 'The sandbox fixture could not produce a plan: {0}' -f $_.Exception.Message
        Write-WacLog -Level CRITICAL -Component 'Targets' -Message 'The sandbox fixture could not produce a plan; nothing was attempted.' -Data @{
            error = $_.Exception.Message
        }
    }

    $watch.Stop()
    return [PSCustomObject]@{
        Outcome    = $outcome
        Target     = @($target)
        Gap        = @()
        Detail     = $detail
        DurationMs = [int]$watch.Elapsed.TotalMilliseconds
    }
}

Export-ModuleMember -Function @(
    'Reset-WacSandboxFixture', 'Get-WacSandboxFixtureRoot', 'New-WacSandboxFixtureTarget',
    'Test-WacSandboxPlan', 'Assert-WacSandboxPlan', 'Assert-WacSandboxPath',
    'Remove-WacTree', 'Remove-WacFilesByPattern',
    'Get-WacCleanupTarget', 'Get-WacCleanupTargetSet', 'Get-WacTargetDiscoveryGap', 'Get-WacEdgeProfilePath'
)
