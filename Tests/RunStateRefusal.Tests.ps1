#Requires -Version 5.1
<#
.SYNOPSIS
    The four cases that prove a state or log directory the run REFUSED was never created, never
    written through, and never altered.

.DESCRIPTION
    Split out of RunExitCode.Tests.ps1 at the 800-line ceiling. The two suites share the preamble
    below verbatim, including the two additions to the rig's Core shim: a Test-WacStatePathIsTrusted
    that RECORDS every question and the path's existence at the moment of asking (the order proof),
    and a descriptor verdict that follows the same plan flag because a redirected %ProgramData%
    under TEMP is genuinely user-writable and the real rule would refuse every scenario for a reason
    unrelated to the case under test.

    RunExitCode.Tests.ps1 keeps the outcome-to-exit-code contract; this file keeps the "nothing was
    created or touched behind a refusal" contract.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'

Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_RunProbe.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_RunRig.ps1')

# ---------------------------------------------------------------------------------------------
# Two additions to the rig's Core shim, appended from HERE so the shared rig file is left alone.
# They are defined after the rig's own overrides, so these are the definitions that win.
#
#   * Test-WacStatePathIsTrusted RECORDS every question it is asked, and whether the path existed
#     at the moment of the question. That record is the ORDER proof: a verdict reached while the
#     candidate root did not yet exist cannot have been reached after the root was created. It also
#     answers in whichever SHAPE the plan names, including two shapes that are not answers at all.
#
#   * The owner/DACL verdict taken from the log directory's OWN HANDLE follows the same plan flag.
#     It is the second of the two answers a redirected %ProgramData% under TEMP cannot give
#     honestly: that directory is genuinely user-writable, so the real rule says "untrusted" there
#     (measured) and every scenario would fail to open a log for a reason unrelated to the case
#     under test. Only the DESCRIPTOR answer is stood in. The reparse test and the collision-failing
#     create are the kernel's answers, not this shim's, which is why the junction case below still
#     exercises the real guard.
#
#   * The degraded-mode sink is redirected into the sandbox. Write-WacFallbackLine tries the
#     machine's Application event log first and a test may not write there; Set-WacLogFallbackWriter
#     is the seam that exists for exactly this, and it reports 'Injected', so a line is PROVEN to
#     have reached a sink rather than merely not to have thrown.
# ---------------------------------------------------------------------------------------------

$script:ShimBody['Core'] = $script:ShimBody['Core'] + @'

function Test-WacStatePathIsTrusted {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path, [int]$MaxDepth = 64)
    $null = $MaxDepth

    $plan = Get-WacTestPlan
    [System.IO.File]::AppendAllText(([string]$env:WAC_TEST_PLAN + '.trustlog'),
        ('{0}|{1}{2}' -f $Path, [System.IO.Directory]::Exists($Path), [Environment]::NewLine),
        (New-Object System.Text.UTF8Encoding($false)))

    if ($plan['stateTrustThrows']) { throw 'test shim: the trust question cannot be answered here' }
    if ($plan['stateTrustNull']) { return $null }

    $reason = [string]$plan['stateReason']
    if (-not $reason) { $reason = 'test shim verdict' }

    return [PSCustomObject]@{
        Path = $Path
        IsTrusted = [bool]$plan['stateTrusted']
        Reason = $reason
        Checked = @(); Failures = @(); Writers = @()
    }
}

Set-WacLogFallbackWriter -Writer {
    param($line)
    [System.IO.File]::AppendAllText(([string]$env:WAC_TEST_PLAN + '.fallback'),
        ($line + [Environment]::NewLine), (New-Object System.Text.UTF8Encoding($false)))
}

Set-WacDirectoryTrustJudge -ScriptBlock {
    param($sddl)
    $null = $sddl
    return [PSCustomObject]@{
        IsTrusted = [bool](Get-WacTestPlan).stateTrusted
        Owner = $null
        Reason = 'test shim: handle descriptor verdict'
    }
}
'@

function Get-RigFallbackText {
    <#
    .SYNOPSIS
        Everything the run wrote to its degraded-mode sink, or '' when it wrote nothing there.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    $path = [string]$Rig.PlanPath + '.fallback'
    if (-not [System.IO.File]::Exists($path)) { return '' }
    return [System.IO.File]::ReadAllText($path)
}

function Get-RigTrustQuestion {
    <#
    .SYNOPSIS
        Every path the trust check was asked about, and whether it existed when it was asked.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    $path = [string]$Rig.PlanPath + '.trustlog'
    if (-not [System.IO.File]::Exists($path)) { return @() }

    return @([System.IO.File]::ReadAllLines($path) | Where-Object { $_ } | ForEach-Object {
            $field = $_.Split('|')
            [PSCustomObject]@{ Path = $field[0]; Existed = ([string]$field[1] -ceq 'True') }
        })
}

function Clear-RigProbeRecord {
    <#
    .SYNOPSIS
        Drops the trust and fallback records so one rig can carry several scenarios.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    foreach ($suffix in @('.trustlog', '.fallback')) {
        $path = [string]$Rig.PlanPath + $suffix
        if ([System.IO.File]::Exists($path)) { [System.IO.File]::Delete($path) }
    }
}

function Get-DirectoryFingerprint {
    <#
    .SYNOPSIS
        Everything about a directory that ANY create, write, append, copy or delete would move.
    .DESCRIPTION
        The directory's own LastWriteTimeUtc changes whenever an entry is added to it or removed
        from it, and every child contributes its name, its length, its own LastWriteTimeUtc and its
        bytes. Comparing the whole thing is a stronger proof than recording calls would be: it sees
        a FileStream(CreateNew) and a [System.IO.File]::Delete, neither of which is a cmdlet any
        recorder could intercept. 'ABSENT' is its own answer, so "never created" is not confused
        with "created and left empty".
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.IO.Directory]::Exists($Path)) { return 'ABSENT' }

    # Every -f expression is parenthesised: inside a method call the argument list splits on commas,
    # so .Add('{0}|{1}' -f $a, $b) passes TWO arguments and formats {1} against nothing.
    $line = New-Object 'System.Collections.Generic.List[string]'
    [void]$line.Add(('DIR|{0}' -f [System.IO.Directory]::GetLastWriteTimeUtc($Path).Ticks))

    foreach ($entry in @([System.IO.Directory]::GetFileSystemEntries($Path) | Sort-Object)) {
        if ([System.IO.Directory]::Exists($entry)) {
            [void]$line.Add(('SUBDIR|{0}|{1}' -f $entry, [System.IO.Directory]::GetLastWriteTimeUtc($entry).Ticks))
            continue
        }
        $info = New-Object System.IO.FileInfo($entry)
        [void]$line.Add(('FILE|{0}|{1}|{2}|{3}' -f $entry, $info.Length, $info.LastWriteTimeUtc.Ticks,
                [System.IO.File]::ReadAllText($entry)))
    }

    return ($line -join [Environment]::NewLine)
}

Test-Case 'A refused state directory is never created, and the refusal never travels through it' {
    # DEFECT 1 in its literal shape. New-WacLogFile created the directory and the log file, and only
    # THEN was that directory asked whether it could be trusted - so the refusal was written THROUGH
    # the very path it was refusing, while the documented guarantee said nothing is written before a
    # refusal. Asserting the exit code alone would not have caught it: the old code exited 7 too.
    #
    # Every DISTINCT shape of "no" is exercised, including the two that are not answers at all,
    # because the code has to key off IsTrusted and off an unanswerable question - never off a
    # chosen reason. See the comment on the shape list for why four reason-variants became one.
    # One rig carries them all: a refused root is never created, so no scenario can leave state for
    # the next one, and the fingerprint below would see it if one did.
    $rig = New-RunRig -Prefix 'rig-refused'
    try {
        $stateRoot = Join-Path -Path $rig.ProgramData -ChildPath 'WindowsAutoCleanup'

        # THREE shapes, not six. The four "why was it untrusted" variants - writable,
        # inherited-unsafe, reparse, inaccessible - reached identical code: they differed only in a
        # Reason string, which is assigned and logged and is never a branch condition anywhere in
        # src/ (asserted by ShippedCodeBan.Tests.ps1, so this reduction has a tripwire rather than an
        # assumption behind it). Each cost a full Run.ps1 child, about 3s per host. The two
        # indeterminate shapes below are NOT redundant: an unanswered verdict and a thrown one take
        # different paths, and the code has to key off IsTrusted and off an unanswerable question.
        foreach ($shape in @(
                @{ Name = 'untrusted'; Plan = @{ stateTrusted = $false
                        stateReason = 'Non-administrative principals hold write access: S-1-5-32-545'
                    }
                },
                @{ Name = 'indeterminate-no-verdict'; Plan = @{ stateTrustNull = $true } },
                @{ Name = 'indeterminate-throws'; Plan = @{ stateTrustThrows = $true } })) {

            Clear-RigProbeRecord -Rig $rig

            $plan = @{ targets = @((New-PlanTarget -Category 'Temp' -FilesDeleted 5)) }
            foreach ($key in $shape.Plan.Keys) { $plan[$key] = $shape.Plan[$key] }

            $result = Invoke-RunRig -Rig $rig -Plan $plan
            $note = ' [shape={0}] stderr: {1}' -f $shape.Name, $result.ErrorText

            Assert-True $result.Exited ('the run did not finish inside its bound.' + $note)
            Assert-Equal 7 $result.ExitCode ('a refused state directory did not exit 7.' + $note)

            # Nothing was created: not the log file, not its directory, not even the machine-wide
            # state root above it. An unanswered question is refused exactly like a "no".
            Assert-Equal 'ABSENT' (Get-DirectoryFingerprint -Path $stateRoot) `
            ('something was created under the refused state root.' + $note)
            Assert-Equal '' (Get-RigLogText -Rig $rig) `
            ('the refusal was written through the path it was refusing.' + $note)

            # The verdict still reached a sink and still says what it is: a refusal nobody can read
            # is the other way to fail this.
            $fallback = Get-RigFallbackText -Rig $rig
            Assert-True ($fallback.Contains('No machine-trusted state directory was found')) `
            ('the refusal reached no sink at all.' + $note + ' fallback: ' + $fallback)
            Assert-True ($fallback -cmatch '(^|\s)status=SecurityRefusal($|\s)') ('fallback: ' + $fallback + $note)
            Assert-True ($fallback -cmatch '(^|\s)exitCode=7($|\s)') ('fallback: ' + $fallback + $note)

            # The ORDER, from the check's own point of view. Both candidate roots were verified, and
            # each was asked about while it did not yet exist - which is only possible if the
            # question came before the creation rather than after it.
            $asked = @(Get-RigTrustQuestion -Rig $rig)
            Assert-Equal 2 $asked.Count ('both candidate roots must be verified before either is used.' + $note)
            foreach ($question in $asked) {
                Assert-False $question.Existed `
                ('the trust question was asked about a path that already existed: ' + $question.Path + $note)
            }
        }
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A refused state directory that already exists is left byte for byte as it was' {
    # The other half of "must not touch the refused path at all": refusing must not append to it,
    # copy into it, sweep it or delete anything in it either. The directory is pre-created with
    # content, fingerprinted, and compared afterwards - and that comparison sees a FileStream and a
    # File.Delete, which a recorder of cmdlet calls would not.
    $rig = New-RunRig -Prefix 'rig-refused-existing'
    try {
        $root = $rig.LogDirectory
        [void][System.IO.Directory]::CreateDirectory($root)

        $decoy = Join-Path -Path $root -ChildPath 'WindowsAutoCleanup_2000-01-01_00-00-00_UTC.log'
        [System.IO.File]::WriteAllText($decoy, 'evidence from an earlier run', $script:Utf8NoBom)
        [System.IO.File]::SetLastWriteTimeUtc($decoy, ([datetime]'2000-01-01T00:00:00Z'))

        $before = Get-DirectoryFingerprint -Path $root
        Assert-True ($before.Contains('evidence from an earlier run')) `
            'the fixture never wrote the file it is about to protect'

        $result = Invoke-RunRig -Rig $rig -Plan @{ stateTrusted = $false; targets = @() }

        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)
        Assert-Equal 7 $result.ExitCode ('stderr: ' + $result.ErrorText)
        Assert-Equal $before (Get-DirectoryFingerprint -Path $root) `
            'the refused state directory was added to, written to or deleted from'

        # And the check really did run against this directory, so the comparison above is evidence
        # rather than a coincidence of the run having stopped somewhere else entirely.
        Assert-True (@(Get-RigTrustQuestion -Rig $rig | Where-Object { $_.Path -ieq $root }).Count -eq 1) `
            'the refused directory was never the one the trust question was asked about'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A log directory planted as a link is refused by the run, and its target is untouched' {
    # Root 1 of audit brief 8, end to end. The pathname preflight ANSWERS TRUSTED here, so the only
    # thing between the run and the attacker's target is the guard that verifies the object actually
    # opened. Reverted to Test-Path plus New-Item -Force, Test-Path calls the junction a container
    # and the whole SYSTEM audit log lands inside the link's target - measured, and this case sees
    # it. The plant is a junction because a plain directory's owner depends on whether the suite is
    # elevated, and this must assert the same thing in a developer shell and on a hosted runner.
    $rig = New-RunRig -Prefix 'rig-planted-link'
    try {
        $outside = Join-Path -Path $rig.Sandbox -ChildPath 'outside'
        [void][System.IO.Directory]::CreateDirectory($outside)
        [System.IO.File]::WriteAllText((Join-Path -Path $outside -ChildPath 'sentinel.txt'), 'untouched', $script:Utf8NoBom)

        # BOTH candidates are planted, not just the first. An elevated run has two, and leaving the
        # second usable makes this case assert the fallback rather than the refusal - the run then
        # correctly logs into candidate 2 and exits 0, which is what "A refused state directory is
        # never created" already covers. The refusal is only the verdict when there is nowhere left
        # to go, so that is the state this case has to build.
        $fallbackRoot = Join-Path -Path $rig.WindowsRoot -ChildPath 'Logs\WindowsAutoCleanup'
        foreach ($planted in @($rig.LogDirectory, $fallbackRoot)) {
            [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $planted))
            New-Item -ItemType Junction -Path $planted -Target $outside -ErrorAction Stop | Out-Null
        }

        $before = Get-DirectoryFingerprint -Path $outside
        Assert-True ($before.Contains('untouched')) 'the fixture never wrote the sentinel it is about to protect'

        $result = Invoke-RunRig -Rig $rig -Plan @{ stateTrusted = $true; targets = @() }

        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)
        Assert-Equal $before (Get-DirectoryFingerprint -Path $outside) `
            'the link target was created under or written to'

        # 7, not Run.ps1's generic "no log anywhere" exit 1: the refusal was a SECURITY one and has
        # to reach the field the verdict is derived from, or a deliberate refusal reads to an
        # operator as a malfunction. Measured before that was wired up: it exited 1.
        Assert-Equal 7 $result.ExitCode `
        ('a refused state directory did not exit SecurityRefusal. stderr: ' + $result.ErrorText)

        $fallback = Get-RigFallbackText -Rig $rig
        Assert-True ($fallback -match 'reparse point') `
        ('the refusal never named what it refused: ' + $fallback)
        Assert-True ($fallback -cmatch '(^|\s)exitCode=7($|\s)') ('fallback: ' + $fallback)
    }
    finally {
        # Removed AS LINKS: a recursive delete would take the target's contents with it, and
        # Remove-Item throws a spurious NullReferenceException on some junctions under 5.1.
        foreach ($planted in @($rig.LogDirectory, (Join-Path -Path $rig.WindowsRoot -ChildPath 'Logs\WindowsAutoCleanup'))) {
            try { [System.IO.Directory]::Delete($planted, $false) } catch { $null = $_ }
        }
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A state trust verdict that was never reached refuses nothing' {
    # $null is NOT EVALUATED - the shape an unelevated run produces, whose log lives in the user's
    # own profile, and the shape a caller that named its own -CandidateRoot produces. It carries no
    # claim to refuse, so it must refuse nothing. The untrusted verdict is proved by the two cases
    # above, which is also where it now takes effect: before the log is opened, not after.
    $rig = New-RunRig -Prefix 'rig-trust'
    try {
        $notEvaluated = Invoke-RunRig -Rig $rig -Plan @{ stateEvaluated = $false; targets = @() }
        Assert-RigExit -Rig $rig -Result $notEvaluated -ExitCode 0 -Status 'Succeeded'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Complete-TestRun
