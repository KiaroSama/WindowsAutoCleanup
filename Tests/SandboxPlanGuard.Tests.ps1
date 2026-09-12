#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the elevated harness's sandbox enforcement (ledger WAC-10): the child runs
    an explicit POSITIVE target set, that set is proven contained before anything is deleted, and
    every entry is proven again immediately before it is used.

.DESCRIPTION
    The defect these cases close was a DENY-LIST. The harness enumerated allow-list categories and
    disabled them by name, so scoping the child depended on the parent being able to NAME every
    category the child would build. Two of them it could not: 'Microsoft Edge cache' and
    'Windows Explorer thumbnail cache' are constructed outside the static per-profile table the
    deny-list was read from, so they were never in it. Worse, the parent's discovery is not the
    child's - redirecting TEMP, ProgramData and LOCALAPPDATA leaves the profile paths CIM returns
    alone - so a parent that found no profile produced a deny-list that denied nothing.

    Tests\_SandboxTargetFixture.psm1 inverts that, and this suite is where each rejection is proven.

    NOTHING HERE CAN DAMAGE THIS MACHINE, including while a fix is mutated out.

      * Every case that names a REAL machine path - a real user profile, a real Edge cache - calls
        the decision function only. No deleting code is reached on those paths under any mutation.
      * Every case that reaches a real remover works inside one disposable tree under TEMP, where
        the worst a broken guard can destroy is a file this suite created a moment earlier. The
        'outside' sentinels are outside the SANDBOX, which is the boundary under test; they are
        still inside the disposable tree.

    That is deliberate: the acceptance for this ledger item is to prove rejection, never to
    demonstrate damage.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot

# Order matters. The fixture deliberately shadows Remove-WacTree and Remove-WacFilesByPattern, and a
# module imported later wins command resolution, so the fixture goes LAST. The shipped Targets module
# is imported for one purpose only - reading its per-profile table as evidence - and its exported
# names are not what this suite calls.
foreach ($moduleLeaf in @('Core', 'FileSystem', 'Targets')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '_SandboxTargetFixture.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:ShippedTargets = Get-Module -Name 'WindowsAutoCleanup.Targets'

# The elevated harness, dot-sourced the way Invoke-ElevatedVerification.ps1 dot-sources it - nothing
# in it runs at dot-source time - plus the three locations it reads, set the way that script sets
# them. This is what lets the last case exercise the real scratch-copy builder instead of a
# restatement of it.
. (Join-Path -Path $PSScriptRoot -ChildPath '_ElevatedVerification.Harness.ps1')
$script:TestsRoot = $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'
# What floor((1800 - 300) / 60) gives for the harness's default -TimeoutSeconds. The number is not
# what any case here asserts; the command-line builder simply refuses to render without it.
$script:ChildBudgetMinutes = 25

# ---------------------------------------------------------------------------------------------
# One disposable tree, built once and read by every case (TESTING_OPTIMIZATION.md rule 2). Lazy
# rather than suite-scope, so a setup failure surfaces as a failing case with its message instead of
# killing the suite before it can print a TOTAL line.
#
#   <root>\sandbox              the authorised root
#   <root>\sandbox-other        a SIBLING whose name merely extends it - outside, and the exact
#                               shape a StartsWith comparison accepts
#   <root>\outside              where the sentinels live, and where an Edge cache that "appeared"
#                               after the plan was judged is modelled
# ---------------------------------------------------------------------------------------------

$script:Tree = $null

function Get-GuardTree {
    if ($script:Tree) { return $script:Tree }

    $root = New-TestSandbox -Prefix 'wac-sandboxguard'
    $sandbox = Join-Path -Path $root -ChildPath 'sandbox'
    $sibling = Join-Path -Path $root -ChildPath 'sandbox-other'
    $outsideEdge = Join-Path -Path $root -ChildPath 'outside\Edge\User Data\Default\Cache\Cache_Data'
    $bait = Join-Path -Path $sandbox -ChildPath 'PD\Microsoft\Windows Defender\LocalCopy'

    foreach ($directory in @($sandbox, $sibling, $outsideEdge, $bait)) {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }
    [System.IO.File]::WriteAllText((Join-Path -Path $bait -ChildPath 'bait.txt'), 'bait')
    [System.IO.File]::WriteAllText((Join-Path -Path $sibling -ChildPath 'sentinel.txt'), 'sibling sentinel')
    [System.IO.File]::WriteAllText((Join-Path -Path $outsideEdge -ChildPath 'data_1'), 'edge sentinel')

    $script:Tree = [PSCustomObject]@{
        Root        = $root
        Sandbox     = $sandbox
        Sibling     = $sibling
        OutsideEdge = $outsideEdge
        Bait        = $bait
        BaitFile    = (Join-Path -Path $bait -ChildPath 'bait.txt')
        Outside     = (Join-Path -Path $root -ChildPath 'outside')
    }
    return $script:Tree
}

function Set-GuardSandbox {
    <#
    .SYNOPSIS
        Points the fixture at one root and drops any root pinned by an earlier case.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)

    $env:WAC_VERIFY_SANDBOX_ROOT = $Path
    Reset-WacSandboxFixture
}

function Get-DirectorySnapshot {
    <#
    .SYNOPSIS
        One string carrying a directory's own attributes plus every descendant file's relative path,
        exact bytes, attributes and last-write time.
    .DESCRIPTION
        Content AND attributes, in one comparable value: "the sentinel survived" has to mean the
        bytes and the metadata are the ones that were there before, not merely that a file of that
        name still exists.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $info = New-Object System.IO.DirectoryInfo($Path)
    if (-not $info.Exists) { return 'MISSING' }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    [void]$lines.Add(('dir attributes={0}' -f [string]$info.Attributes))

    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force | Sort-Object -Property FullName)) {
        [void]$lines.Add(('{0} bytes={1} attributes={2} written={3}' -f `
            $file.FullName.Substring($Path.Length),
            [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($file.FullName)),
            [string]$file.Attributes,
            $file.LastWriteTimeUtc.Ticks))
    }

    return ($lines.ToArray() -join "`n")
}

function Invoke-PlanDeletion {
    <#
    .SYNOPSIS
        Run.ps1's deletion loop, exactly: dispatch each entry on its Mode and delete it.
    .DESCRIPTION
        The loop is reproduced rather than mocked because the ordering is the thing under test - the
        plan gate has to refuse before this runs at all, and the consumption gate has to refuse
        inside it.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Plan)

    foreach ($entry in @($Plan)) {
        if ([string]$entry.Mode -eq 'Pattern') {
            $null = Remove-WacFilesByPattern -Category $entry.Category -Path $entry.Path -Pattern $entry.Pattern
        }
        else {
            $null = Remove-WacTree -Category $entry.Category -Path $entry.Path -DeleteRoot:([bool]$entry.DeleteRoot)
        }
    }
}

function Invoke-PlanRun {
    <#
    .SYNOPSIS
        Gate then loop, in Run.ps1's order: the plan is judged as a whole, and only a plan that
        passed reaches the deletion loop.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Plan,
        [Parameter(Mandatory = $true)][string]$SandboxRoot
    )

    $null = Assert-WacSandboxPlan -Plan $Plan -SandboxRoot $SandboxRoot
    Invoke-PlanDeletion -Plan $Plan
}

function Invoke-Refusal {
    <#
    .SYNOPSIS
        Runs a block that is expected to refuse, and hands back whether it did and what it said.
    .DESCRIPTION
        Assert-Throws cannot be used for these cases. It throws on the spot when the block does NOT
        throw, which is exactly when the interesting evidence - "and nothing was deleted" - would
        have to be read. Every assertion after it would then be unreachable in the one run that
        matters, so the state check has to happen first and the refusal is asserted afterwards.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$ScriptBlock)

    $threw = $false
    $message = ''
    try { & $ScriptBlock | Out-Null }
    catch {
        $threw = $true
        $message = [string]$_
    }
    return [PSCustomObject]@{ Threw = $threw; Message = $message }
}

function Get-FileContentText {
    <#
    .SYNOPSIS
        One file's exact bytes as a comparable string.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    return [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($Path))
}

function New-PlanEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Mode = 'Directory',
        [string[]]$Pattern = @()
    )

    return [PSCustomObject]@{
        Mode = $Mode; Category = $Category; Path = $Path; DeleteRoot = $false; Pattern = [string[]]$Pattern
    }
}

function Get-RealProfileRoot {
    <#
    .SYNOPSIS
        A REAL user profile directory on this machine - what an elevated child discovers and what a
        parent with no profile of its own never sees.
    #>
    $profiles = @()
    try { $profiles = @(Get-WacUserProfilePath) } catch { $profiles = @() }
    foreach ($candidate in $profiles) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Container)) { return [string]$candidate }
    }

    # LOCALAPPDATA's parent is the profile root; used only when Win32_UserProfile answers nothing.
    if ($env:LOCALAPPDATA) {
        $fallback = Split-Path -Parent (Split-Path -Parent $env:LOCALAPPDATA)
        if ($fallback -and (Test-Path -LiteralPath $fallback -PathType Container)) { return [string]$fallback }
    }
    return ''
}

# ---------------------------------------------------------------------------------------------
# The fixture is fail-closed: no authorised root means no target, not an unrestricted one
# ---------------------------------------------------------------------------------------------

Test-Case 'With no authorised sandbox root the fixture produces no target at all' {
    Set-GuardSandbox -Path ''

    Assert-Throws -ScriptBlock { Get-WacSandboxFixtureRoot } -Pattern 'refusing to produce a target' `
        -Message 'an unset root was accepted as "no restriction"'

    $set = Get-WacCleanupTargetSet
    Assert-Equal 'Failed' ([string]$set.Outcome) 'a fixture with no authorised root did not refuse'
    Assert-Equal 0 @($set.Target).Count 'a fixture with no authorised root still named targets'

    # A root that is named but does not exist is the same answer, so a stale or mistyped value
    # cannot quietly become the whole filesystem.
    Set-GuardSandbox -Path (Join-Path -Path (Get-GuardTree).Root -ChildPath 'no-such-directory')
    Assert-Equal 'Failed' ([string](Get-WacCleanupTargetSet).Outcome) 'a non-existent root was accepted'
}

# ---------------------------------------------------------------------------------------------
# Parent/child profile disagreement - the failure that swept a real %TEMP% in a Hyper-V guest
# ---------------------------------------------------------------------------------------------

Test-Case 'A real profile path the parent never discovered is refused, and its category is not why' {
    $tree = Get-GuardTree
    $profileRoot = Get-RealProfileRoot
    if (-not $profileRoot) {
        Set-TestSkipped -Reason 'no real user profile directory could be resolved on this machine'
    }

    # What the CHILD builds when it discovers a profile the parent did not: three per-profile
    # categories, all under a real profile root, none of them inside the sandbox.
    $childDiscovered = @(
        New-PlanEntry -Category 'User TEMP contents' -Path (Join-Path -Path $profileRoot -ChildPath 'AppData\Local\Temp')
        New-PlanEntry -Category 'Microsoft Edge cache' -Path (Join-Path -Path $profileRoot -ChildPath 'AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data')
        New-PlanEntry -Category 'Windows Explorer thumbnail cache' -Mode 'Pattern' -Pattern @('thumbcache_*.db') `
            -Path (Join-Path -Path $profileRoot -ChildPath 'AppData\Local\Microsoft\Windows\Explorer')
    )

    $verdict = Test-WacSandboxPlan -Plan $childDiscovered -SandboxRoot $tree.Sandbox
    Assert-False $verdict.Valid 'a plan built from a real user profile was accepted for a sandbox run'
    Assert-Equal 3 @($verdict.Rejected).Count 'not every real-profile entry was rejected'

    # The inversion itself: the SAME category names, pointed inside the sandbox, are fine. So the
    # verdict is about the path and never about whether the name was on a list.
    $sameCategoriesInside = @(
        New-PlanEntry -Category 'User TEMP contents' -Path (Join-Path -Path $tree.Sandbox -ChildPath 'TMP')
        New-PlanEntry -Category 'Microsoft Edge cache' -Path (Join-Path -Path $tree.Sandbox -ChildPath 'LA\Edge')
        New-PlanEntry -Category 'Windows Explorer thumbnail cache' -Mode 'Pattern' -Pattern @('thumbcache_*.db') `
            -Path (Join-Path -Path $tree.Sandbox -ChildPath 'LA\Explorer')
    )
    Assert-True (Test-WacSandboxPlan -Plan $sameCategoriesInside -SandboxRoot $tree.Sandbox).Valid `
        'the same categories inside the sandbox were refused, so the check is reading names after all'
}

# ---------------------------------------------------------------------------------------------
# Every separately generated category, and one the allow-list has never heard of
# ---------------------------------------------------------------------------------------------

Test-Case 'Containment covers the categories no deny-list table can name, including a brand-new one' {
    $tree = Get-GuardTree

    # The evidence that the old mechanism could not have worked: the per-profile table the deny-list
    # was read from does not declare either separately generated category. Read from the SHIPPED
    # module, so this stays true only while that is true.
    $declared = @(& $script:ShippedTargets { $script:UserCacheTarget } | ForEach-Object { [string]$_.Category })
    Assert-True ($declared.Count -gt 0) 'the shipped per-profile table could not be read'
    foreach ($missing in @('Microsoft Edge cache', 'Windows Explorer thumbnail cache')) {
        Assert-False ($declared -contains $missing) `
            ('{0} is in the per-profile table now, so this case no longer describes the defect' -f $missing)
    }

    # One loop rather than one case per category: the assertion is identical and the input is a
    # string, so a second case would buy nothing (TESTING_OPTIMIZATION.md rule 3).
    $categories = @(
        'Microsoft Edge cache'                  # built per Edge profile, never in the table
        'Windows Explorer thumbnail cache'      # built per user profile, never in the table
        'User TEMP contents'                    # in the table
        'Defender cleanup files'                # not per-profile at all
        'Nobody has ever declared this category' # a category added to Targets.psm1 tomorrow
    )

    foreach ($category in $categories) {
        $outside = @(New-PlanEntry -Category $category -Path (Join-Path -Path $tree.Outside -ChildPath 'anything'))
        Assert-False (Test-WacSandboxPlan -Plan $outside -SandboxRoot $tree.Sandbox).Valid `
            ('an outside target was accepted for category {0}' -f $category)

        $inside = @(New-PlanEntry -Category $category -Path (Join-Path -Path $tree.Sandbox -ChildPath 'anything'))
        Assert-True (Test-WacSandboxPlan -Plan $inside -SandboxRoot $tree.Sandbox).Valid `
            ('an inside target was refused for category {0}' -f $category)
    }

    # An entry carrying no readable path is refused rather than passed over: a property that cannot
    # be read reads as $null on both hosts, and an unreadable path cannot be proven contained.
    Assert-False (Test-WacSandboxPlan -Plan @([PSCustomObject]@{ Category = 'shapeless' }) -SandboxRoot $tree.Sandbox).Valid `
        'an entry with no Path property was accepted'
}

# ---------------------------------------------------------------------------------------------
# Sibling prefix - the shape a StartsWith comparison accepts
# ---------------------------------------------------------------------------------------------

Test-Case 'A sibling whose name merely extends the sandbox is outside it, at both gates' {
    $tree = Get-GuardTree
    Set-GuardSandbox -Path $tree.Sandbox

    $sibling = Join-Path -Path $tree.Sibling -ChildPath 'cache'
    Assert-False (Test-WacSandboxPlan -Plan @(New-PlanEntry -Category 'sibling' -Path $sibling) -SandboxRoot $tree.Sandbox).Valid `
        'the plan gate accepted a sibling directory whose name extends the sandbox'

    $before = Get-DirectorySnapshot -Path $tree.Sibling
    $refusal = Invoke-Refusal -ScriptBlock { Remove-WacTree -Category 'sibling' -Path $tree.Sibling }
    Assert-Equal $before (Get-DirectorySnapshot -Path $tree.Sibling) 'the sibling sentinel changed'
    Assert-True $refusal.Threw 'the consumption gate accepted a sibling directory whose name extends the sandbox'
    Assert-True ($refusal.Message -match 'refused a target outside the sandbox at consumption') `
        ('the consumption gate refused for some other reason: {0}' -f $refusal.Message)
}

# ---------------------------------------------------------------------------------------------
# One outside entry refuses the whole plan, BEFORE anything is deleted
# ---------------------------------------------------------------------------------------------

Test-Case 'One outside entry refuses the whole plan before the first mutation' {
    $tree = Get-GuardTree
    Set-GuardSandbox -Path $tree.Sandbox

    # A legal entry FIRST, so "nothing was mutated" is a claim about ordering and not about the plan
    # happening to start with the bad entry.
    $plan = @(
        New-PlanEntry -Category 'Defender cleanup files' -Path $tree.Bait
        New-PlanEntry -Category 'Microsoft Edge cache' -Path $tree.OutsideEdge
    )

    $outsideBefore = Get-DirectorySnapshot -Path $tree.Outside

    # Gate then loop, exactly as Run.ps1 orders them, so the loop really would run if the gate let
    # the plan through - which is what makes the two state checks below load-bearing.
    $refusal = Invoke-Refusal -ScriptBlock { Invoke-PlanRun -Plan $plan -SandboxRoot $tree.Sandbox }

    # The ordering, stated as evidence: the LEGAL target is still there, so the refusal happened
    # before the loop rather than part-way through it.
    Assert-True (Test-Path -LiteralPath $tree.BaitFile -PathType Leaf) `
        'the legal target was deleted even though the plan was refused, so the gate ran too late'
    Assert-Equal $outsideBefore (Get-DirectorySnapshot -Path $tree.Outside) 'an outside sentinel changed'
    Assert-True $refusal.Threw 'a plan holding an outside entry was accepted'
    Assert-True ($refusal.Message -match 'refused before any mutation') `
        ('the plan was refused somewhere other than the pre-mutation gate: {0}' -f $refusal.Message)
}

# ---------------------------------------------------------------------------------------------
# Revalidation at consumption - an Edge cache that appears after the plan was judged
# ---------------------------------------------------------------------------------------------

Test-Case 'A target swapped after the plan was judged is refused at consumption' {
    $tree = Get-GuardTree
    Set-GuardSandbox -Path $tree.Sandbox

    $plan = @(New-PlanEntry -Category 'Defender cleanup files' -Path $tree.Bait)
    Assert-True (Assert-WacSandboxPlan -Plan $plan -SandboxRoot $tree.Sandbox).Valid `
        'the sandbox-only plan was refused, so the swap it models cannot be isolated'

    # Between the gate and the loop: Edge turned up, and this entry now points at a real cache
    # directory the plan gate never saw.
    $outsideBefore = Get-DirectorySnapshot -Path $tree.Outside
    $plan[0].Path = $tree.OutsideEdge

    $refusal = Invoke-Refusal -ScriptBlock { Invoke-PlanDeletion -Plan $plan }
    Assert-Equal $outsideBefore (Get-DirectorySnapshot -Path $tree.Outside) 'the swapped-in outside target was mutated'
    Assert-True $refusal.Threw 'a target swapped after the plan gate was deleted anyway'
    Assert-True ($refusal.Message -match 'refused a target outside the sandbox at consumption') `
        ('the swapped target was refused for some other reason: {0}' -f $refusal.Message)

    # The positive control. Without it a consumption gate that refused EVERYTHING would pass every
    # assertion above, and the harness would delete nothing while reporting success.
    $plan[0].Path = $tree.Bait
    Invoke-PlanDeletion -Plan $plan
    Assert-False (Test-Path -LiteralPath $tree.BaitFile -PathType Leaf) `
        'the legal sandbox target was not deleted, so the guard refuses work it should let through'
}

# ---------------------------------------------------------------------------------------------
# The injection mechanism itself: what the elevated harness actually launches
# ---------------------------------------------------------------------------------------------

Test-Case 'The scratch copy the harness launches carries the fixture, not the real allow-list' {
    $tree = Get-GuardTree

    $scratchSandbox = Join-Path -Path $tree.Root -ChildPath 'scratch-sandbox'
    [void][System.IO.Directory]::CreateDirectory($scratchSandbox)

    $scratchRun = New-VerificationScratchTree -Sandbox $scratchSandbox
    $scratchSrc = Join-Path -Path (Split-Path -Parent $scratchRun) -ChildPath 'src'

    Assert-Equal (Get-FileContentText -Path $script:RunPath) (Get-FileContentText -Path $scratchRun) `
        'the scratch Run.ps1 is not a copy of the shipped one'

    # THE INJECTION. The module the child loads as the allow-list builder is the fixture, and it is
    # NOT the shipped builder - both directions, because a copy that silently did nothing would
    # leave the real builder in place and the child would discover the operator's own profile.
    $injected = Join-Path -Path $scratchSrc -ChildPath 'WindowsAutoCleanup.Targets.psm1'
    $fixture = Join-Path -Path $PSScriptRoot -ChildPath '_SandboxTargetFixture.psm1'
    $shipped = Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Targets.psm1'
    Assert-Equal (Get-FileContentText -Path $fixture) (Get-FileContentText -Path $injected) `
        'the scratch allow-list builder is not the sandbox fixture'
    Assert-False ((Get-FileContentText -Path $shipped) -ceq (Get-FileContentText -Path $injected)) `
        'the scratch allow-list builder is still the shipped builder'

    # Everything else the child needs is there and unmodified; only the one module was replaced.
    foreach ($file in @(Get-ChildItem -LiteralPath $script:SrcRoot -File)) {
        if ($file.Name -ieq 'WindowsAutoCleanup.Targets.psm1') { continue }
        $copy = Join-Path -Path $scratchSrc -ChildPath $file.Name
        Assert-True (Test-Path -LiteralPath $copy -PathType Leaf) ('{0} is missing from the scratch tree' -f $file.Name)
        Assert-Equal (Get-FileContentText -Path $file.FullName) (Get-FileContentText -Path $copy) `
            ('{0} was modified on its way into the scratch tree' -f $file.Name)
    }

    # The harness and the fixture have to agree on the name of the variable that authorises the
    # sandbox, and they are in different files. A disagreement is fail-closed rather than dangerous -
    # the fixture would name no target at all - but it would fail every scenario for the wrong
    # reason, so it is checked here instead of being discovered in an elevated guest.
    $table = Get-SandboxEnvironment -Sandbox $scratchSandbox
    Assert-True ($table.ContainsKey('WAC_VERIFY_SANDBOX_ROOT')) 'the child environment authorises no sandbox root'
    Assert-Equal $scratchSandbox ([string]$table['WAC_VERIFY_SANDBOX_ROOT']) 'the child was authorised for a different directory'

    Set-GuardSandbox -Path ([string]$table['WAC_VERIFY_SANDBOX_ROOT'])
    Assert-Equal (Get-WacNormalizedPath -Path $scratchSandbox) (Get-WacSandboxFixtureRoot) `
        'the fixture does not read the variable the harness sets'

    # And the command line really points the child at the scratch copy. Pointing it at the shipped
    # Run.ps1 would load the real allow-list builder from the shipped src\ and the whole injection
    # would be inert, which is the one way this could fail silently.
    # The consumption gate reaches the child by shadowing: the fixture exports Remove-WacTree and
    # Remove-WacFilesByPattern, and the module imported LATER wins command resolution. That holds
    # only while Run.ps1 imports Targets after FileSystem. Reordering that list would silently leave
    # the child calling FileSystem directly with no revalidation at all, so it is checked here rather
    # than discovered in a guest.
    $importList = [regex]::Match((Get-Content -LiteralPath $scratchRun -Raw), "foreach\s*\(\s*\`$moduleName\s+in\s+@\(([^)]*)\)")
    Assert-True $importList.Success 'Run.ps1 no longer imports its modules from one named list'
    $order = @($importList.Groups[1].Value -split ',' | ForEach-Object { $_.Trim().Trim("'") })
    Assert-True ($order.IndexOf('FileSystem') -ge 0 -and $order.IndexOf('Targets') -gt $order.IndexOf('FileSystem')) `
        ('Run.ps1 imports Targets before FileSystem, so the fixture can no longer shadow the removers: {0}' -f ($order -join ', '))

    $commandLine = Get-RunChildCommandLine -ScriptPath $scratchRun -MutexName 'Global\WacVerifyUnitCase'
    Assert-True ($commandLine.IndexOf($scratchRun, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) `
        ('the child command line does not name the scratch Run.ps1: {0}' -f $commandLine)
    Assert-False ($commandLine.IndexOf($script:RunPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) `
        ('the child command line still names the shipped Run.ps1: {0}' -f $commandLine)
}

Complete-TestRun
