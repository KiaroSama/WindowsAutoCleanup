#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the elevated harness's MAINTENANCE containment (ledger WAC-10R): a
    sandboxed child services nothing on this machine, the run that proves it really executes, and
    the EXIT2 failure is attributed to the bait target rather than to whichever target was reported
    last.

.DESCRIPTION
    Two defects are closed here and each has its own cases.

      1. The "sandbox" ran real machine maintenance. Confining the FILE plan says nothing about
         DISM, pnpclean, pnputil, cleanmgr, the Delivery Optimization purge or the global Recycle
         Bin, none of which reaches the machine through an allow-list path - so EXIT2 and the
         uncontended EXIT3 control serviced the operator's computer while the summary called them
         sandbox scope.

      2. EXIT2's bait assertion read $target AFTER the parse loop had reassigned it, so with more
         than one completed target it checked the LAST target reported instead of the bait.

    WHAT IS EXECUTED, AND WHY IT IS NOT THE SCENARIO FUNCTION. The scenario functions launch
    Run.ps1 with -Scheduled, and Run.ps1 refuses an unelevated scheduled run before it reaches a
    single step, so calling Invoke-Exit2Scenario from an ordinary suite could only ever observe
    exit 1. The execution case therefore drives the REAL scratch tree the harness builds - the same
    modules, the same two injected fixtures, the same import order - through Run.ps1's own cleanup
    sequence in a child process, and reads the evidence the scenarios read. What it cannot cover is
    Run.ps1's own orchestration of that sequence, so a separate assertion checks that every entry
    point exercised here is still called by the shipped Run.ps1.

    NOTHING HERE CAN DAMAGE THIS MACHINE, including while a fix is mutated out. The child process
    deletes only inside a disposable tree under TEMP that this suite created a moment earlier, and
    the one call that asks for a real system tool asks for "dism.exe /?", which prints help text and
    changes nothing even in the world where the barrier under test has been removed.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# The elevated harness, dot-sourced the way Invoke-ElevatedVerification.ps1 dot-sources it - nothing
# in any of them runs at dot-source time - plus the three locations they read. This suite deliberately
# does NOT import _SandboxMaintenanceFixture.psm1 into its own process: that fixture arms the process
# invoker, and the case below has to be able to start a child.
. (Join-Path -Path $PSScriptRoot -ChildPath '_ElevatedVerification.Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_ElevatedVerification.Witness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_ElevatedVerification.SandboxScenarios.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_ElevatedVerification.MaintenanceScenario.ps1')
$script:TestsRoot = $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
# What floor((1800 - 300) / 60) gives for the harness's default -TimeoutSeconds. No case asserts the
# number; the command-line builder simply refuses to render without it.
$script:ChildBudgetMinutes = 25
# Set the way Invoke-ElevatedVerification.ps1 sets it, so the launch gate below is the ONLY thing
# standing between the refusal case and a started process. Without it a removed gate would fail that
# case on an unset variable instead of on the child it let through, which is a red for the wrong
# reason and would hide a gate that had stopped working.
$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

# ---------------------------------------------------------------------------------------------
# One disposable tree and ONE child run, built lazily and read by every case that needs them
# (TESTING_OPTIMIZATION.md rule 2). Lazy rather than suite-scope so a setup failure surfaces as a
# failing case with its message instead of killing the suite before it can print a TOTAL line.
# ---------------------------------------------------------------------------------------------

$script:Tree = $null
$script:Replay = $null

function Get-MaintenanceTree {
    if ($script:Tree) { return $script:Tree }

    $root = New-TestSandbox -Prefix 'wac-maintguard'

    # TWO sandboxes: one whose scratch tree carries the maintenance fixture, one whose does not.
    # The second is what the launch gate has to refuse, and it is also the shape every scenario
    # used to launch.
    $guarded = Join-Path -Path $root -ChildPath 'guarded'
    $plain = Join-Path -Path $root -ChildPath 'plain'
    foreach ($sandbox in @($guarded, $plain)) {
        foreach ($leaf in @('PD', 'LA', 'TMP')) {
            [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $sandbox -ChildPath $leaf))
        }
    }

    $guardedRun = New-VerificationScratchTree -Sandbox $guarded -InterceptMaintenance
    $plainRun = New-VerificationScratchTree -Sandbox $plain

    # The bait the sweep must really delete, and the two sibling targets that make "several
    # completed targets" the normal case rather than a special one.
    $bait = New-SandboxBait -Sandbox $guarded
    [void](New-SandboxSiblingTarget -Sandbox $guarded)

    $script:Tree = [PSCustomObject]@{
        Root        = $root
        Guarded     = $guarded
        Plain       = $plain
        GuardedRun  = $guardedRun
        PlainRun    = $plainRun
        GuardedSrc  = (Join-Path -Path (Split-Path -Parent $guardedRun) -ChildPath 'src')
        PlainSrc    = (Join-Path -Path (Split-Path -Parent $plainRun) -ChildPath 'src')
        Bait        = $bait
        BaitFile    = (Join-Path -Path $bait -ChildPath 'bait.txt')
    }
    return $script:Tree
}

function Get-ReplayScriptPath {
    <#
    .SYNOPSIS
        Writes Run.ps1's own cleanup sequence, run against the scratch tree, as a child script.
    .DESCRIPTION
        A single-quoted here-string, so nothing in it is expanded by the suite, and its one input
        arrives as an argument rather than through the suite's own environment. The child sets the
        redirected roots on ITSELF - which is exactly what Start-VerificationChild does for a real
        scenario - so the suite process never has its ProgramData or TEMP moved out from under it.

        The last probe is the point of the whole file: it asks Core to launch a real system tool
        directly, bypassing every entry point, and reports whether the process started. That is the
        POSITIVE form of "no real servicing can execute" - an absence of DISM lines would also be
        satisfied by a run that crashed at its first step.
    #>
    param([Parameter(Mandatory = $true)][string]$Directory)

    $path = Join-Path -Path $Directory -ChildPath 'replay.ps1'
    $body = @'
param([Parameter(Mandatory = $true)][string]$Root)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$env:WAC_VERIFY_SANDBOX_ROOT = $Root
$env:ProgramData = Join-Path -Path $Root -ChildPath 'PD'
$env:LOCALAPPDATA = Join-Path -Path $Root -ChildPath 'LA'
$env:TEMP = Join-Path -Path $Root -ChildPath 'TMP'
$env:TMP = $env:TEMP

# Run.ps1's own list, in Run.ps1's own order. The order is what makes the injected fixtures win
# command resolution, so reproducing it is part of what this child is for.
$source = Join-Path -Path $Root -ChildPath 'SRC\src'
foreach ($name in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
    Import-Module -Name (Join-Path -Path $source -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $name)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

Write-Host ('REPLAY stages=' + ((Get-WacMaintenanceStage) -join ','))
Write-Host ('REPLAY driversModule=' + (Get-Command -Name 'Invoke-WacComponentCleanup').ModuleName)

[void](Initialize-WacRun -BaseName 'WindowsAutoCleanup' -LogLevel 'DEBUG' -BudgetMinutes 5)
Write-Host ('REPLAY log=' + (Get-WacLogPath))

# Run.ps1's cleanup phase: the purge, the allow-list, the sweep, then the four tool-driven steps.
# Clear-WacRecycleBin is deliberately absent - every sandboxed child is launched with
# -SkipRecycleBin, so Run.ps1 does not call it and neither does this.
$purge = Clear-WacDeliveryOptimizationCache
$set = Get-WacCleanupTargetSet
$deleted = 0
foreach ($target in @($set.Target)) {
    $result = if ($target.Mode -eq 'Pattern') {
        Remove-WacFilesByPattern -Category $target.Category -Path $target.Path -Pattern $target.Pattern
    }
    else {
        Remove-WacTree -Category $target.Category -Path $target.Path -DeleteRoot:([bool]$target.DeleteRoot)
    }
    if ($result.Attempted) { Write-WacTreeResult -Result $result }
    $deleted += [int]$result.FilesDeleted
}
$dism = Invoke-WacComponentCleanup -ResetBase:$false
$pnpclean = Invoke-WacPnpCleanHandler
$prune = Invoke-WacDriverPackagePrune -Enabled:$false -BackupRoot (Get-WacDriverBackupRoot)
$legacy = Invoke-WacLegacyDiskCleanup -Enabled:$false -Category (Get-WacDiskCleanupCategory)

Write-Host ('REPLAY outcomes=' + ((@($purge, $dism, $pnpclean, $prune, $legacy) | ForEach-Object { [string]$_.Outcome }) -join ','))
Write-Host ('REPLAY targets=' + [string]$set.Outcome + ' count=' + @($set.Target).Count + ' deleted=' + $deleted)

# THE SECOND BARRIER, asked directly. dism.exe /? prints help and changes nothing, so this probe is
# safe even in the world where the barrier it tests has been removed - and Started tells us which
# world we are in.
#
# It gets its OWN witness directory, because a tripwire is exactly what it is trying to cause and
# the run's witness has to stay readable as "this run launched nothing". Re-pointing the authorised
# root is what Reset-WacMaintenanceFixture exists for, and it happens after the sweep is finished.
$probeRoot = Join-Path -Path $Root -ChildPath 'PROBE'
[void][System.IO.Directory]::CreateDirectory($probeRoot)
$env:WAC_VERIFY_SANDBOX_ROOT = $probeRoot
Reset-WacMaintenanceFixture

$tool = Join-Path -Path $env:SystemRoot -ChildPath 'System32\dism.exe'
$probeStarted = 'toolMissing'
if (Test-Path -LiteralPath $tool -PathType Leaf) {
    $probe = Invoke-WacProcess -FilePath $tool -ArgumentList @('/?') -TimeoutMs 20000 -Component 'ReplayProbe'
    $probeStarted = [string][bool]$probe.Started
}
Write-Host ('REPLAY probeStarted=' + $probeStarted)

Close-WacLog
Write-Host 'REPLAY ok'
exit 0
'@

    [System.IO.File]::WriteAllText($path, $body, $script:Utf8NoBom)
    return $path
}

function Get-Replay {
    <#
    .SYNOPSIS
        Runs the replay child ONCE and caches everything read from it.
    #>
    if ($script:Replay) { return $script:Replay }

    $tree = Get-MaintenanceTree
    $replayScript = Get-ReplayScriptPath -Directory $tree.Root
    $hostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

    # Bounded by Invoke-WacProcess's own deadline: no wait here is open-ended, and the owned tree is
    # terminated if the child overruns.
    $run = Invoke-WacProcess -FilePath $hostExe -Component 'MaintenanceReplay' -TimeoutMs 180000 `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $replayScript, $tree.Guarded)

    $field = @{}
    foreach ($line in @([string]$run.StandardOutput -split "`r?`n")) {
        $match = [regex]::Match($line, '^REPLAY\s+(?<rest>.+)$')
        if (-not $match.Success) { continue }
        foreach ($pair in [regex]::Matches($match.Groups['rest'].Value, '(?<key>[A-Za-z]+)=(?<value>\S*)')) {
            $field[[string]$pair.Groups['key'].Value] = [string]$pair.Groups['value'].Value
        }
    }

    $logText = ''
    if ($field.ContainsKey('log') -and (Test-Path -LiteralPath $field['log'] -PathType Leaf)) {
        $logText = [string][System.IO.File]::ReadAllText($field['log'])
    }

    $script:Replay = [PSCustomObject]@{
        ExitCode = $run.ExitCode
        TimedOut = [bool]$run.TimedOut
        Output   = [string]$run.StandardOutput
        Error    = [string]$run.StandardError
        Field    = $field
        Witness  = (Get-SandboxWitness -Text (Get-SandboxWitnessText -Sandbox $tree.Guarded))
        # The direct probe records into its own witness, so the run's witness above stays readable
        # as "this run launched nothing" while the barrier itself is still proved to be live.
        Probe    = (Get-SandboxWitness -Text (Get-SandboxWitnessText -Sandbox (Join-Path -Path $tree.Guarded -ChildPath 'PROBE')))
        LogText  = $logText
    }
    return $script:Replay
}

function Get-FileContentText {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($Path))
}

function New-ResultLine {
    <#
    .SYNOPSIS
        One '[Result] Target complete.' line in exactly the shape Write-WacTreeResult emits.
    .DESCRIPTION
        failed= is OMITTED when the count is zero - that is the shipped behaviour, and it is why the
        "no other target failed" check asks whether the field is present rather than comparing it
        with zero.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Failed = 0
    )

    $line = '[2026-09-13 00:00:00 UTC] [INFO] [Result] Target complete. | bytes=4 category="{0}" dirs=0 files=1 path="{1}"' -f $Category, $Path
    if ($Failed -gt 0) { $line = '{0} failed={1}' -f $line, $Failed }
    return $line
}

function Get-SourceText {
    param([Parameter(Mandatory = $true)][string]$Leaf)

    return [string][System.IO.File]::ReadAllText((Join-Path -Path $PSScriptRoot -ChildPath $Leaf))
}

# ---------------------------------------------------------------------------------------------
# The injection mechanism: what a sandboxed child actually loads
# ---------------------------------------------------------------------------------------------

Test-Case 'The scratch copy a sandboxed child runs carries the maintenance fixture and keeps the shipped driver module' {
    $tree = Get-MaintenanceTree

    $fixture = Join-Path -Path $PSScriptRoot -ChildPath '_SandboxMaintenanceFixture.psm1'
    $shipped = Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Drivers.psm1'
    $injected = Join-Path -Path $tree.GuardedSrc -ChildPath 'WindowsAutoCleanup.Drivers.psm1'
    $preserved = Join-Path -Path $tree.GuardedSrc -ChildPath 'WindowsAutoCleanup.Drivers.Shipped.psm1'

    # Both directions. A copy that silently did nothing would leave the shipped maintenance entry
    # points in place, and the child would service the operator's machine exactly as before.
    Assert-Equal (Get-FileContentText -Path $fixture) (Get-FileContentText -Path $injected) `
        'the scratch driver module is not the maintenance fixture'
    Assert-False ((Get-FileContentText -Path $shipped) -ceq (Get-FileContentText -Path $injected)) `
        'the scratch driver module is still the shipped one'

    # The real driver surface is not LOST, only stood in front of: the fixture imports this copy
    # back and re-exports it.
    Assert-Equal (Get-FileContentText -Path $shipped) (Get-FileContentText -Path $preserved) `
        'the shipped driver module was not preserved beside the fixture'

    # Everything else is untouched, so the child runs the real product with two modules replaced.
    foreach ($file in @(Get-ChildItem -LiteralPath $script:SrcRoot -File)) {
        if (@('WindowsAutoCleanup.Targets.psm1', 'WindowsAutoCleanup.Drivers.psm1') -contains $file.Name) { continue }
        $copy = Join-Path -Path $tree.GuardedSrc -ChildPath $file.Name
        Assert-Equal (Get-FileContentText -Path $file.FullName) (Get-FileContentText -Path $copy) `
            ('{0} was modified on its way into the scratch tree' -f $file.Name)
    }

    # The interception reaches the child by SHADOWING, and that works only while Drivers is the last
    # module Run.ps1 imports. Reordering that list would silently leave the child calling the real
    # DISM and pnpclean, so it is checked here rather than discovered in an elevated guest.
    $importList = [regex]::Match((Get-Content -LiteralPath $tree.GuardedRun -Raw), "foreach\s*\(\s*\`$moduleName\s+in\s+@\(([^)]*)\)")
    Assert-True $importList.Success 'Run.ps1 no longer imports its modules from one named list'
    $order = @($importList.Groups[1].Value -split ',' | ForEach-Object { $_.Trim().Trim("'") })
    Assert-Equal 'Drivers' ([string]$order[$order.Count - 1]) `
        ('Run.ps1 no longer imports Drivers last, so the maintenance fixture cannot shadow the steps: {0}' -f ($order -join ', '))

    # And the switch is what does it: a tree built without -InterceptMaintenance is the shipped one.
    Assert-Equal (Get-FileContentText -Path $shipped) (Get-FileContentText -Path (Join-Path -Path $tree.PlainSrc -ChildPath 'WindowsAutoCleanup.Drivers.psm1')) `
        'a tree built without -InterceptMaintenance was modified anyway'
}

# ---------------------------------------------------------------------------------------------
# The executed run: every maintenance step reached, every one stopped, the files still deleted
# ---------------------------------------------------------------------------------------------

Test-Case 'A real run over the scratch tree intercepts every maintenance step, launches no tool, and still deletes its files' {
    $tree = Get-MaintenanceTree
    $replay = Get-Replay

    # PRINTED FIRST. Asserting before printing throws away the only record of how far the child got.
    Write-Host ('    child exit={0} timedOut={1}' -f $replay.ExitCode, $replay.TimedOut)
    foreach ($key in @($replay.Field.Keys | Sort-Object)) { Write-Host ('    {0}={1}' -f $key, $replay.Field[$key]) }
    foreach ($line in @($replay.Witness.Intercepted)) { Write-Host ('    intercepted {0}' -f $line) }
    foreach ($line in @($replay.Witness.Tripwire)) { Write-Host ('    TRIPWIRE {0}' -f $line) }

    Assert-Equal 0 ([int]$replay.ExitCode) ('the replay child failed: {0}' -f $replay.Error.Trim())
    Assert-True ($replay.Output -match 'REPLAY ok') 'the replay child did not reach the end of Run.ps1''s cleanup sequence'

    # The fixture and the harness have to name the same five stages, and they are in different
    # files. A disagreement would leave a scenario asserting a stage nothing ever writes.
    Assert-Equal (($script:MaintenanceStage) -join ',') ([string]$replay.Field['stages']) `
        'the harness and the fixture disagree about which maintenance stages a sandboxed run reaches'

    # Every one of the five reached AND stopped. "Reached" is the half an absence check cannot give.
    foreach ($stage in $script:MaintenanceStage) {
        Assert-True (@($replay.Witness.Intercepted) -contains $stage) `
            ('the run never reached the {0} maintenance step: witness={1}' -f $stage, (@($replay.Witness.Intercepted) -join ', '))
    }
    Assert-Equal 0 @($replay.Witness.Tripwire).Count `
        ('a real system tool was reached despite the interception: {0}' -f (@($replay.Witness.Tripwire) -join ' | '))
    Assert-False (@($replay.Witness.Intercepted) -contains 'RecycleBin') `
        'the run reached the global Recycle Bin step, which Run.ps1 does not call under -SkipRecycleBin'

    # The second barrier, proved by asking for a real tool directly rather than by inferring it: the
    # process never started, AND the attempt was recorded, so the barrier is live rather than merely
    # never exercised.
    Assert-Equal 'False' ([string]$replay.Field['probeStarted']) `
        'Core launched a real system tool, so nothing stops a maintenance call the entry points missed'
    Assert-Equal 1 @($replay.Probe.Tripwire).Count `
        ('the direct tool launch was not recorded as a tripwire: {0}' -f (@($replay.Probe.Tripwire) -join ' | '))
    Assert-True (@($replay.Probe.Tripwire)[0] -match 'dism\.exe') `
        ('the tripwire does not name the tool that was asked for: {0}' -f @($replay.Probe.Tripwire)[0])

    # Every step returned the shipped SafeSkip, which is what keeps the run's exit code coming from
    # its files. A Failed or Incomplete here would change the code every scenario asserts.
    Assert-Equal 'SafeSkip,SafeSkip,SafeSkip,SafeSkip,SafeSkip' ([string]$replay.Field['outcomes']) `
        'a maintenance step returned something other than the shipped SafeSkip'

    # AND THE RUN STILL DID ITS REAL WORK. Without this the whole thing passes by doing nothing.
    Assert-Equal 'Succeeded' ([string]$replay.Field['targets']) 'the allow-list fixture refused its own plan'
    Assert-True ([int]$replay.Field['deleted'] -ge 3) `
        ('the sweep deleted {0} file(s), so the fixture-only run stopped deleting as well' -f $replay.Field['deleted'])
    Assert-False (Test-Path -LiteralPath $tree.BaitFile -PathType Leaf) 'the bait file survived a run that reported deletions'

    # The child's own log is the second, independent record of the same five interceptions - written
    # by the shipped logger, not by the witness writer.
    Assert-True ($replay.LogText.Length -gt 0) 'the replay child produced no readable run log'
    foreach ($category in @(
            'Windows component store cleanup (DISM)', 'Device driver packages (pnpclean)',
            'Delivery Optimization cache', 'Superseded driver packages (pnputil)',
            'Disk Cleanup handlers (cleanmgr)')) {
        $stepLine = @(Get-MatchingLine -Text $replay.LogText -Needle ('category="{0}"' -f $category))
        Assert-True ($stepLine.Count -ge 1) ('the run log carries no step result for {0}' -f $category)
        Assert-True ($stepLine[0] -match 'SANDBOX FIXTURE') `
            ('{0} was not recorded as intercepted in the child''s own log: {1}' -f $category, $stepLine[0])
    }
}

Test-Case 'Run.ps1 still calls every maintenance entry point the replay covers' {
    # The replay reproduces Run.ps1's sequence rather than running Run.ps1, because an unelevated
    # scheduled run exits before its first step. This is what keeps the reproduction honest: an
    # entry point Run.ps1 stopped calling, or started calling under another name, would leave the
    # replay proving the interception of something the product no longer does.
    $runText = [string][System.IO.File]::ReadAllText($script:RunPath)
    foreach ($entryPoint in @(
            'Clear-WacDeliveryOptimizationCache', 'Get-WacCleanupTargetSet', 'Invoke-WacComponentCleanup',
            'Invoke-WacPnpCleanHandler', 'Invoke-WacDriverPackagePrune', 'Invoke-WacLegacyDiskCleanup',
            'Clear-WacRecycleBin')) {
        Assert-True ($runText -match ('(?m)^\s*.*\b{0}\b' -f [regex]::Escape($entryPoint))) `
            ('Run.ps1 no longer calls {0}, so the replay covers a sequence the product does not run' -f $entryPoint)
    }
}

# ---------------------------------------------------------------------------------------------
# The launch gate - forgetting the fixture is a refusal, not a serviced machine
# ---------------------------------------------------------------------------------------------

Test-Case 'A child whose tree has no maintenance fixture is refused before it starts' {
    $tree = Get-MaintenanceTree

    Assert-True (Test-ChildMaintenanceFixture -Environment (Get-SandboxEnvironment -Sandbox $tree.Guarded)) `
        'the gate cannot see the fixture in a tree that carries it, so it would refuse every scenario'
    Assert-False (Test-ChildMaintenanceFixture -Environment (Get-SandboxEnvironment -Sandbox $tree.Plain)) `
        'the gate reports a fixture in a tree that has none'

    # The refusal itself, on the real function, with no process started either way.
    Assert-Throws -ScriptBlock {
        Start-VerificationChild -CommandLine '-NoProfile -Command exit 0' -Environment (Get-SandboxEnvironment -Sandbox $tree.Plain)
    } -Pattern 'carries no maintenance fixture' -Message 'a child that would service this machine was launched anyway'

    # An environment that authorises no sandbox at all cannot satisfy the gate by accident.
    Assert-False (Test-ChildMaintenanceFixture -Environment @{ ProgramData = $tree.Guarded }) `
        'the gate accepted an environment that names no sandbox root'
}

# ---------------------------------------------------------------------------------------------
# EXIT2 attribution - the bait's own result, in any order
# ---------------------------------------------------------------------------------------------

Test-Case 'Only the bait target supplies failed=1, whatever order the targets were reported in' {
    $tree = Get-MaintenanceTree
    $sandbox = $tree.Guarded
    $bait = Join-Path -Path $sandbox -ChildPath 'PD\Microsoft\Windows Defender\LocalCopy'
    $edge = Join-Path -Path $sandbox -ChildPath 'LA\Microsoft\Edge\User Data\Default\Cache\Cache_Data'
    $explorer = Join-Path -Path $sandbox -ChildPath 'LA\Microsoft\Windows\Explorer'

    $baitLine = New-ResultLine -Category 'Defender cleanup files' -Path $bait -Failed 1
    $edgeLine = New-ResultLine -Category 'Microsoft Edge cache' -Path $edge
    $explorerLine = New-ResultLine -Category 'Windows Explorer thumbnail cache' -Path $explorer

    # VARYING ORDER, one loop rather than three cases: the input is a string array and the assertion
    # is identical, so a second case would buy nothing (TESTING_OPTIMIZATION.md rule 3). The old
    # spelling read whichever target was reported LAST, so the middle and first orders are the ones
    # it got wrong and the last order is the one that hid the defect.
    $orders = @(
        @{ Name = 'bait last'; Lines = @($edgeLine, $explorerLine, $baitLine) }
        @{ Name = 'bait first'; Lines = @($baitLine, $edgeLine, $explorerLine) }
        @{ Name = 'bait in the middle'; Lines = @($edgeLine, $baitLine, $explorerLine) }
    )
    foreach ($order in $orders) {
        $verdict = Test-Exit2TargetEvidence -Text (@($order.Lines) -join "`r`n") -Sandbox $sandbox -BaitTarget $bait
        Assert-Equal 0 @($verdict.Problem).Count `
            ('a clean run was rejected with the targets reported {0}: {1}' -f $order.Name, (@($verdict.Problem) -join ' | '))
        Assert-True (@($verdict.Evidence) -contains ('the bait target {0} is the one that reported failed=1' -f (Get-WacNormalizedPath -Path $bait))) `
            ('the bait was not identified with the targets reported {0}' -f $order.Name)
    }

    # The failure has to be the BAIT's. A run where another target failed and the bait did not is
    # exit 2 for a reason this scenario cannot account for, and it was accepted before.
    $misattributed = @(
        (New-ResultLine -Category 'Microsoft Edge cache' -Path $edge -Failed 1)
        (New-ResultLine -Category 'Defender cleanup files' -Path $bait)
    )
    $verdict = Test-Exit2TargetEvidence -Text (@($misattributed) -join "`r`n") -Sandbox $sandbox -BaitTarget $bait
    Assert-True (@($verdict.Problem).Count -ge 1) 'a failure belonging to another target was accepted as the bait''s'
    Assert-True ((@($verdict.Problem) -join ' | ') -match 'other than the bait reported a failure') `
        ('the misattributed failure was rejected for some other reason: {0}' -f (@($verdict.Problem) -join ' | '))

    # A bait that did not fail at all, with a clean sibling present: the locked directory never
    # reached the Failed bucket, which is the whole subject of the EXIT2 scenario.
    $verdict = Test-Exit2TargetEvidence -Text (@($edgeLine, (New-ResultLine -Category 'Defender cleanup files' -Path $bait)) -join "`r`n") `
        -Sandbox $sandbox -BaitTarget $bait
    Assert-True ((@($verdict.Problem) -join ' | ') -match 'did not report exactly failed=1') `
        ('a bait that reported no failure was accepted: {0}' -f (@($verdict.Problem) -join ' | '))
}

Test-Case 'A sibling whose name merely extends the sandbox or the bait is not inside either' {
    $tree = Get-MaintenanceTree
    $sandbox = $tree.Guarded
    $bait = Join-Path -Path $sandbox -ChildPath 'PD\Microsoft\Windows Defender\LocalCopy'

    # Outside the SANDBOX, and by the shape a StartsWith comparison accepts: the sibling's name
    # merely extends the sandbox's.
    $outside = New-ResultLine -Category 'Defender cleanup files' -Path ($sandbox + '-other\LocalCopy') -Failed 1
    $verdict = Test-Exit2TargetEvidence -Text $outside -Sandbox $sandbox -BaitTarget $bait
    Assert-True ((@($verdict.Problem) -join ' | ') -match 'outside the sandbox was cleaned for real') `
        ('a sibling directory outside the sandbox was accepted: {0}' -f (@($verdict.Problem) -join ' | '))

    # Inside the sandbox but NOT the bait, by the same shape: 'LocalCopy2' extends 'LocalCopy', so a
    # substring match would have called it the bait and read its failure as the bait's.
    $nearMiss = New-ResultLine -Category 'Defender cleanup files' -Path ($bait + '2') -Failed 1
    $verdict = Test-Exit2TargetEvidence -Text $nearMiss -Sandbox $sandbox -BaitTarget $bait
    Assert-True ((@($verdict.Problem) -join ' | ') -match 'other than the bait reported a failure') `
        ('a directory whose name merely extends the bait was treated as the bait: {0}' -f (@($verdict.Problem) -join ' | '))

    # A line with no readable path cannot be proven contained, so it is refused rather than skipped.
    $verdict = Test-Exit2TargetEvidence -Text '[2026-09-13 00:00:00 UTC] [INFO] [Result] Target complete. | files=1' `
        -Sandbox $sandbox -BaitTarget $bait
    Assert-True ((@($verdict.Problem) -join ' | ') -match 'no readable path') `
        'a result line with no path was accepted'
}

# ---------------------------------------------------------------------------------------------
# The witness verdict itself
# ---------------------------------------------------------------------------------------------

Test-Case 'The witness verdict is positive: reaching every step is required, and a tripwire is fatal' {
    $tree = Get-MaintenanceTree

    $full = (@($script:MaintenanceStage | ForEach-Object { '2026-09-13 00:00:00 intercepted stage={0} detail=x' -f $_ }) -join "`r`n")
    $parsed = Get-SandboxWitness -Text $full
    Assert-Equal $script:MaintenanceStage.Count @($parsed.Intercepted).Count 'the parser lost an intercepted stage'
    Assert-Equal 0 @($parsed.Tripwire).Count 'the parser invented a tripwire'

    # A run that reached only some of the steps is NOT proof of containment: the missing ones were
    # never exercised, so nothing was established about them.
    $partialWitness = Join-Path -Path $tree.Root -ChildPath 'partial'
    [void][System.IO.Directory]::CreateDirectory($partialWitness)
    [System.IO.File]::WriteAllText((Join-Path -Path $partialWitness -ChildPath 'maintenance-witness.log'),
        "2026-09-13 00:00:00 intercepted stage=ComponentCleanup detail=x`r`n", $script:Utf8NoBom)

    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    Add-MaintenanceEvidence -Evidence $evidence -Problem $problem -Sandbox $partialWitness -Label 'test' -ExpectFullSequence
    Assert-True ($problem.Count -ge 1) 'a run that reached only one maintenance step was accepted as fully intercepted'

    # And the same witness is a PROBLEM for a run that was supposed to stop at a gate.
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    Add-MaintenanceEvidence -Evidence $evidence -Problem $problem -Sandbox $partialWitness -Label 'test'
    Assert-True ($problem.Count -ge 1) 'a gated run that reached a maintenance step anyway was accepted'

    # A tripwire and a Recycle Bin stage are each fatal on their own, in the full-sequence case.
    $loudWitness = Join-Path -Path $tree.Root -ChildPath 'loud'
    [void][System.IO.Directory]::CreateDirectory($loudWitness)
    $loud = @(@($script:MaintenanceStage | ForEach-Object { '2026-09-13 00:00:00 intercepted stage={0} detail=x' -f $_ }) + @(
            '2026-09-13 00:00:00 intercepted stage=RecycleBin detail=x'
            '2026-09-13 00:00:00 tripwire stage=Invoke-WacProcess detail=C:\Windows\System32\dism.exe'
        )) -join "`r`n"
    [System.IO.File]::WriteAllText((Join-Path -Path $loudWitness -ChildPath 'maintenance-witness.log'), $loud, $script:Utf8NoBom)

    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    Add-MaintenanceEvidence -Evidence $evidence -Problem $problem -Sandbox $loudWitness -Label 'test' -ExpectFullSequence
    Assert-True ((@($problem) -join ' | ') -match 'reached a REAL system tool') 'a tripwire did not fail the verdict'
    Assert-True ((@($problem) -join ' | ') -match 'global Recycle Bin') 'a Recycle Bin stage did not fail the verdict'
}

# ---------------------------------------------------------------------------------------------
# Scope reporting - which lanes are allowed to service this machine, and what a refusal records
# ---------------------------------------------------------------------------------------------

Test-Case 'The sandboxed lane may never declare machine scope, and the machine lanes always do' {
    # A source check, because this is a property of the CALL SITES rather than of any one run: the
    # defect being closed is precisely a scenario that serviced the machine while calling itself
    # sandboxed, and a scenario added tomorrow must not be able to do that quietly.
    $sandboxText = Get-SourceText -Leaf '_ElevatedVerification.SandboxScenarios.ps1'
    Assert-Equal 0 ([regex]::Matches($sandboxText, '-AllowRealMaintenance').Count) `
        'a sandboxed scenario declares machine scope, so it may service this machine'

    $builds = [regex]::Matches($sandboxText, 'New-VerificationScratchTree[^\r\n]*')
    Assert-True ($builds.Count -ge 4) ('the sandboxed scenarios build only {0} scratch tree(s)' -f $builds.Count)
    foreach ($build in $builds) {
        Assert-True ($build.Value -match '-InterceptMaintenance') `
            ('a sandboxed scenario builds a tree without the maintenance fixture: {0}' -f $build.Value.Trim())
    }

    # The machine lanes are the mirror image, and both files have to keep saying so.
    foreach ($leaf in @('_ElevatedVerification.MachineScenarios.ps1', '_ElevatedVerification.MaintenanceScenario.ps1')) {
        $machineText = Get-SourceText -Leaf $leaf
        Assert-True ([regex]::Matches($machineText, 'Start-VerificationChild[^\r\n]*-AllowRealMaintenance').Count -ge 1) `
            ('{0} launches a child without declaring machine scope' -f $leaf)
        Assert-Equal 0 ([regex]::Matches($machineText, 'New-VerificationScratchTree[^\r\n]*-InterceptMaintenance').Count) `
            ('{0} intercepts the maintenance it exists to exercise' -f $leaf)
    }
}

Test-Case 'The maintenance lane records NotArmed rather than passing as if it had run' {
    $previous = $env:WAC_VM_MAINTENANCE
    try {
        $env:WAC_VM_MAINTENANCE = ''
        $arming = Get-MaintenanceArming
        Assert-False $arming.Armed 'the maintenance lane armed itself without being asked'
        Assert-Equal 'NotArmed' ([string]$arming.Execution) 'an unarmed lane did not record NotArmed'

        # The record a whole run would produce: machine scope, no problems, and an Execution word
        # that a summary cannot mistake for having serviced anything. -TimeoutMs is required and
        # never reached, because the arming check comes before any sandbox is created.
        $record = Invoke-MaintenanceScenario -TimeoutMs 1000
        Assert-True $record.Passed ('the unarmed lane failed its own guard: {0}' -f (@($record.Problem) -join ' | '))
        Assert-True $record.Machine 'the maintenance lane does not report machine scope'
        Assert-Equal 'NotArmed' ([string]$record.Execution) 'an unarmed lane reported that it executed'

        # The armed-but-unelevated branch, exercised only where arming cannot start real maintenance.
        # On an elevated session this is left alone deliberately: setting the switch there would run
        # DISM and pnpclean on the operator's machine, which no unit suite may do.
        if (-not (Test-WacIsAdministrator)) {
            $env:WAC_VM_MAINTENANCE = '1'
            $unsupported = Get-MaintenanceArming
            Assert-False $unsupported.Armed 'the maintenance lane armed itself in an unelevated session'
            Assert-Equal 'Unsupported' ([string]$unsupported.Execution) 'an unelevated armed lane did not record Unsupported'
        }
    }
    finally {
        $env:WAC_VM_MAINTENANCE = $previous
    }
}

Complete-TestRun
