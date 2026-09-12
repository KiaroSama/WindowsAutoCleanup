#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-09: a run's identity is its suite path under Tests\ PLUS its host, recorded on completion.

.DESCRIPTION
    Run-Tests.ps1 discovers with -Recurse, so a suite may live in a subdirectory. It used to identify
    a run by Suite.BaseName + HostKind for its capture files, and by the bare file name alone in the
    manifest. Three separate holes came out of that:

      * both runs of a same-named pair were given the same .out/.err names, so their output collided
        in one pair of redirect files and one of them vanished while the run still exited 0;
      * both wrote the same manifest line, which Sort-Object -Unique folded into ONE entry - so the
        CI guard reported "all discovered suites ran" for a run in which only one of them had; and
      * the entry carried no host and was written at LAUNCH, so a suite that ran on pwsh could stand
        in for the 5.1 run it never had, and a started-then-vanished run still certified itself.

    The pair hole is latent while every suite name in this repository is distinct, which is exactly
    why it needs a test: nothing else would notice the day someone adds
    Tests\Integration\Deploy.Tests.ps1 beside Tests\Deploy.Tests.ps1, and the failure mode is a
    silently unrun suite rather than an error. The host and completion halves are not latent at all -
    they decide what the CI guard is able to prove on every run.

    COST. Spawning a runner is the expensive part, so ONE fixture run answers every question here:
    a disposable Tests tree holding a COPY of the real runner, two same-named suites in different
    directories, and one suite that exits 1, executed once across BOTH hosts with default workers.
    That single run exercises path identity, host identity, concurrent capture isolation, report
    identity and status recording together; the cases below only read its result. Copying the shipped
    runner rather than restating its logic is what keeps the test able to fail when the runner
    regresses. The fixture suites are plain scripts - printing a TOTAL line and exiting is the whole
    contract Run-Tests.ps1 has with a suite - so the harness is not needed inside them.

    An earlier shape of this suite spent 14 seconds per host driving a real idle-timeout kill to
    prove the recorded status is not a constant. A suite that exits 1 proves the same thing in about
    one second, so that is what ships.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')

$script:HostExecutable = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$script:SharedRun = $null

function New-RunnerFixture {
    <#
    .SYNOPSIS
        Builds <sandbox>\Tests with a copy of the real runner, two same-named suites and a failing one.
    #>
    $sandbox = New-TestSandbox -Prefix 'wac_runnerid'
    $tests = Join-Path -Path $sandbox -ChildPath 'Tests'
    [void][System.IO.Directory]::CreateDirectory($tests)

    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Run-Tests.ps1') -Destination $tests -Force

    # Deliberately the SAME file name in both directories. That is the input under test.
    foreach ($leaf in @('alpha', 'beta')) {
        $directory = Join-Path -Path $tests -ChildPath $leaf
        [void][System.IO.Directory]::CreateDirectory($directory)
        $body = @'
Write-Host 'MARKER-{0}'
Write-Host 'TOTAL cases=1 passed=1 failed=0 skipped=0 duration=1ms'
exit 0
'@ -f $leaf.ToUpperInvariant()
        Set-Content -LiteralPath (Join-Path $directory 'Same.Tests.ps1') -Value $body -Encoding UTF8
    }

    # A distinct, non-clean outcome, so the recorded status cannot be a constant that happens to fit.
    $failing = Join-Path -Path $tests -ChildPath 'gamma'
    [void][System.IO.Directory]::CreateDirectory($failing)
    Set-Content -LiteralPath (Join-Path $failing 'Fails.Tests.ps1') -Encoding UTF8 -Value @'
Write-Host 'TOTAL cases=1 passed=0 failed=1 skipped=0 duration=1ms'
exit 1
'@

    return [PSCustomObject]@{
        Runner   = (Join-Path -Path $tests -ChildPath 'Run-Tests.ps1')
        Manifest = (Join-Path -Path $sandbox -ChildPath 'executed.txt')
    }
}

function Get-SharedRun {
    <#
    .SYNOPSIS
        Runs the fixture once across both hosts and caches the result for every case.
    .DESCRIPTION
        Lazy rather than executed at suite scope: a failure here then surfaces as a failing CASE with
        its message, instead of killing the suite before it can print a TOTAL line.
    #>
    if ($null -ne $script:SharedRun) { return $script:SharedRun }

    $fixture = New-RunnerFixture
    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $fixture.Runner,
        '-ManifestPath', $fixture.Manifest,
        '-Host', 'both',
        # Short bounds: a fixture suite that does not finish in seconds is a failure worth seeing
        # quickly, and the runner's own 300s default would stall this suite instead.
        '-TimeoutSeconds', '60', '-IdleTimeoutSeconds', '30'
    )

    # 2>&1 on a native command turns its stderr into ErrorRecords, which $ErrorActionPreference =
    # 'Stop' then promotes to a terminating NativeCommandError - so a child that merely printed a
    # warning would abort this suite instead of failing an assertion. Relaxed only for the call.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $captured = & $script:HostExecutable @arguments 2>&1 }
    finally { $ErrorActionPreference = $previous }
    $code = $LASTEXITCODE

    $entries = @()
    if (Test-Path -LiteralPath $fixture.Manifest -PathType Leaf) {
        $entries = @(Get-Content -LiteralPath $fixture.Manifest | Where-Object { $_.Trim() })
    }

    $script:SharedRun = [PSCustomObject]@{
        ExitCode = $code
        Text     = (@($captured | ForEach-Object { [string]$_ }) -join "`n")
        Entries  = $entries
    }
    return $script:SharedRun
}

function Get-ManifestStatus {
    <#
    .SYNOPSIS
        Returns the status recorded for one path|host key, or $null when the key is absent.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Entries,
        [Parameter(Mandatory = $true)][string]$Key
    )

    foreach ($entry in $Entries) {
        $parts = $entry -split '\|', 3
        if ($parts.Count -lt 3) { continue }
        if (('{0}|{1}' -f $parts[0], $parts[1]) -eq $Key) { return $parts[2] }
    }
    return $null
}

Test-Case 'the manifest identifies a run by suite path AND host' {
    $run = Get-SharedRun

    # Three suites on two hosts is six runs. Under the bare-name scheme the two Same.Tests.ps1 files
    # folded into one line and the two hosts folded into each other, leaving two entries for six
    # runs - and the CI guard called that complete.
    Assert-Equal 6 $run.Entries.Count `
        ('three suites on two hosts is six runs, but the manifest holds ' + ($run.Entries -join ', '))

    foreach ($leaf in @('alpha', 'beta')) {
        foreach ($kind in @('pwsh', 'powershell')) {
            $key = '{0}\Same.Tests.ps1|{1}' -f $leaf, $kind
            Assert-Equal 'exit=0' (Get-ManifestStatus -Entries $run.Entries -Key $key) `
                ('the manifest has no clean entry for ' + $key + ': ' + ($run.Entries -join ', '))
        }
    }
}

Test-Case 'same-named suites keep separate capture files and separate report lines' {
    $run = Get-SharedRun

    # Both are in flight together, so each needs its own redirect files; under the shared-name scheme
    # one suite's entire output vanished into the other's capture file while the run still exited 0.
    foreach ($leaf in @('alpha', 'beta')) {
        Assert-True ($run.Text -match ('(?m)^--- {0}\\Same\.Tests\.ps1 ' -f $leaf)) `
            ('the ' + $leaf + ' suite was not reported under its own path: ' + $run.Text)
        Assert-True ($run.Text -match ('MARKER-' + $leaf.ToUpperInvariant())) `
            ('the ' + $leaf + ' suite output was lost')
    }
}

Test-Case 'the recorded status is the real outcome, not a constant' {
    $run = Get-SharedRun

    # What makes the status EVIDENCE. A manifest that always said exit=0 would satisfy every
    # assertion above while telling the CI guard nothing, and an entry written at launch could not
    # carry an outcome at all.
    Assert-Equal 1 $run.ExitCode 'a run containing a failing suite must fail'

    foreach ($kind in @('pwsh', 'powershell')) {
        Assert-Equal 'exit=1' (Get-ManifestStatus -Entries $run.Entries -Key ('gamma\Fails.Tests.ps1|{0}' -f $kind)) `
            ('the failing suite was not recorded as failing on ' + $kind + ': ' + ($run.Entries -join ', '))
    }
}

Test-Case 'a run that had a failure keeps its per-suite captures instead of deleting the only evidence' {
    # The runner writes one .out/.err pair per suite run and then deleted the whole directory in its
    # finally block, unconditionally. A suite that went red inside a 104-run parallel pass therefore
    # left NOTHING saying which assertion, on which host, with what message - which is exactly the
    # state one unexplainable red run left behind, and why it could never be diagnosed.
    #
    # The fixture already contains a deliberately failing suite, so this case costs nothing extra:
    # it reads the run every other case in this file already shares.
    $run = Get-SharedRun

    $evidence = @($run.Text -split "`r?`n" | Where-Object { $_ -match '^EVIDENCE ' })
    Assert-Equal 1 $evidence.Count `
        ('a run containing a failing suite did not report kept evidence. output: ' + $run.Text)

    $match = [regex]::Match($evidence[0], 'kept at (?<path>.+?)\s*$')
    Assert-True ($match.Success) ('the evidence line did not name a directory: ' + $evidence[0])
    $kept = $match.Groups['path'].Value

    try {
        Assert-True (Test-Path -LiteralPath $kept -PathType Container) `
            ('the captures were deleted even though a suite failed: ' + $kept)

        $files = @(Get-ChildItem -LiteralPath $kept -Filter '*.out' -File -ErrorAction SilentlyContinue)
        Assert-True ($files.Count -gt 0) 'the kept directory held no capture files at all'

        $text = (@($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n")
        Assert-True ($text -match 'failed=1') `
            'the kept captures do not contain the failing suite output, so they are not the evidence'
    }
    finally {
        # Kept on purpose by the runner, so this suite is what removes it: leaving one behind per run
        # would trade an evidence defect for a residue defect.
        if ($kept) { Remove-Item -LiteralPath $kept -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Complete-TestRun
