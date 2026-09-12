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

    The fixture is a DISPOSABLE Tests tree under TEMP holding a COPY of the real runner. Copying the
    shipped file rather than restating its logic is what keeps this test able to fail when the runner
    regresses. The fixture suites are plain scripts - printing a TOTAL line and exiting 0 is the
    entire contract Run-Tests.ps1 has with a suite - so the harness is not needed inside them.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')

$script:HostExecutable = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$script:HostKind = 'powershell'
if ($PSVersionTable.PSEdition -eq 'Core') { $script:HostKind = 'pwsh' }

function New-RunnerFixture {
    <#
    .SYNOPSIS
        Builds <sandbox>\Tests with a copy of the real runner and two same-named suites.
    .PARAMETER WithHang
        Adds a third suite that produces no output and never finishes on its own, so a caller can
        exercise the timeout status. It is bounded by the INNER runner's idle deadline, which is the
        mechanism under test; nothing waits on it blindly.
    #>
    param([switch]$WithHang)

    $sandbox = New-TestSandbox -Prefix 'wac_runnerid'
    $tests = Join-Path -Path $sandbox -ChildPath 'Tests'
    [void][System.IO.Directory]::CreateDirectory($tests)

    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Run-Tests.ps1') -Destination $tests -Force

    foreach ($leaf in @('alpha', 'beta')) {
        $directory = Join-Path -Path $tests -ChildPath $leaf
        [void][System.IO.Directory]::CreateDirectory($directory)

        # Deliberately the SAME file name in both directories. That is the input under test.
        $body = @'
Write-Host 'MARKER-{0}'
Write-Host 'TOTAL cases=1 passed=1 failed=0 skipped=0 duration=1ms'
exit 0
'@ -f $leaf.ToUpperInvariant()

        Set-Content -LiteralPath (Join-Path $directory 'Same.Tests.ps1') -Value $body -Encoding UTF8
    }

    if ($WithHang) {
        $directory = Join-Path -Path $tests -ChildPath 'gamma'
        [void][System.IO.Directory]::CreateDirectory($directory)
        Set-Content -LiteralPath (Join-Path $directory 'Hang.Tests.ps1') -Encoding UTF8 -Value @'
[void]([System.Threading.ManualResetEvent]::new($false).WaitOne(600000))
exit 0
'@
    }

    return [PSCustomObject]@{
        Runner   = (Join-Path -Path $tests -ChildPath 'Run-Tests.ps1')
        Manifest = (Join-Path -Path $sandbox -ChildPath 'executed.txt')
    }
}

function Invoke-RunnerFixture {
    <#
    .SYNOPSIS
        Runs the copied runner on the current host and returns its exit code, output and manifest.
    #>
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [int]$MaxWorkers,
        [string]$TestHost,
        [int]$TimeoutSeconds = 60,
        [int]$IdleTimeoutSeconds = 30
    )

    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $Fixture.Runner,
        '-ManifestPath', $Fixture.Manifest,
        # Short bounds: a fixture suite that does not finish in seconds is a failure worth seeing
        # quickly, and the runner's own 300s default would stall this case instead.
        '-TimeoutSeconds', [string]$TimeoutSeconds, '-IdleTimeoutSeconds', [string]$IdleTimeoutSeconds
    )
    if ($PSBoundParameters.ContainsKey('MaxWorkers')) { $arguments += @('-MaxWorkers', [string]$MaxWorkers) }
    if ($TestHost) { $arguments += @('-Host', $TestHost) }

    # 2>&1 on a native command turns its stderr into ErrorRecords, which $ErrorActionPreference =
    # 'Stop' then promotes to a terminating NativeCommandError - so a child that merely printed a
    # warning would abort this case instead of failing an assertion. Relaxed only for the call.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $captured = & $script:HostExecutable @arguments 2>&1 }
    finally { $ErrorActionPreference = $previous }
    $code = $LASTEXITCODE

    $entries = @()
    if (Test-Path -LiteralPath $Fixture.Manifest -PathType Leaf) {
        $entries = @(Get-Content -LiteralPath $Fixture.Manifest | Where-Object { $_.Trim() })
    }

    return [PSCustomObject]@{
        ExitCode = $code
        Text     = (@($captured | ForEach-Object { [string]$_ }) -join "`n")
        Entries  = $entries
    }
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

Test-Case 'two suites sharing a name in different directories produce two manifest entries' {
    $fixture = New-RunnerFixture

    # One worker, so the two runs are strictly sequential and no capture file can be contended.
    # This case therefore isolates the IDENTITY defect from any concurrency effect: the pre-fix
    # runner completed happily here and still reported a single suite as having executed.
    $run = Invoke-RunnerFixture -Fixture $fixture -MaxWorkers 1

    Assert-Equal 0 $run.ExitCode ('the fixture run failed: ' + $run.Text)
    Assert-Equal 2 $run.Entries.Count ('two suites ran but the manifest holds ' + ($run.Entries -join ', '))

    foreach ($leaf in @('alpha', 'beta')) {
        $key = '{0}\Same.Tests.ps1|{1}' -f $leaf, $script:HostKind
        Assert-Equal 'exit=0' (Get-ManifestStatus -Entries $run.Entries -Key $key) `
            ('the manifest has no clean entry for ' + $key + ': ' + ($run.Entries -join ', '))
    }
}

Test-Case 'each of the two same-named suites is reported under its own identity' {
    $fixture = New-RunnerFixture

    # Default workers, so both runs really are in flight together and each needs its own redirect
    # files. Under the shared-name scheme the second Start-Process opened a capture file the first
    # still held; either way the two runs could not be told apart in the report.
    $run = Invoke-RunnerFixture -Fixture $fixture

    Assert-Equal 0 $run.ExitCode ('the concurrent fixture run failed: ' + $run.Text)
    Assert-True ($run.Text -match '(?m)^--- alpha\\Same\.Tests\.ps1 ') `
        ('the alpha suite was not reported under its own path: ' + $run.Text)
    Assert-True ($run.Text -match '(?m)^--- beta\\Same\.Tests\.ps1 ') `
        ('the beta suite was not reported under its own path: ' + $run.Text)
    Assert-True ($run.Text -match 'MARKER-ALPHA') 'the alpha suite output was lost'
    Assert-True ($run.Text -match 'MARKER-BETA') 'the beta suite output was lost'
}

Test-Case 'the manifest separates the two hosts, so one host cannot stand in for the other' {
    $fixture = New-RunnerFixture

    # The host half of the identity. Without it a suite that ran on pwsh alone satisfies a guard
    # that believes it also ran on Windows PowerShell 5.1 - and the divergence between those two
    # hosts is where this project's defects actually live.
    $run = Invoke-RunnerFixture -Fixture $fixture -TestHost 'both'

    Assert-Equal 0 $run.ExitCode ('the two-host fixture run failed: ' + $run.Text)
    Assert-Equal 4 $run.Entries.Count `
        ('two suites on two hosts is four runs, but the manifest holds ' + ($run.Entries -join ', '))

    foreach ($leaf in @('alpha', 'beta')) {
        foreach ($kind in @('pwsh', 'powershell')) {
            $key = '{0}\Same.Tests.ps1|{1}' -f $leaf, $kind
            Assert-Equal 'exit=0' (Get-ManifestStatus -Entries $run.Entries -Key $key) `
                ('the manifest has no clean entry for ' + $key + ': ' + ($run.Entries -join ', '))
        }
    }
}

Test-Case 'a run that was killed is recorded as a timeout, not as a clean exit' {
    $fixture = New-RunnerFixture -WithHang

    # What makes the recorded status EVIDENCE rather than a constant. A manifest that always says
    # exit=0 would satisfy every assertion above while telling the guard nothing, and a manifest
    # written at launch could not carry a status at all. The hanging suite is bounded by the inner
    # runner's own 10s idle deadline - the mechanism under test - so nothing here waits blindly.
    $run = Invoke-RunnerFixture -Fixture $fixture -TimeoutSeconds 15 -IdleTimeoutSeconds 10

    Assert-True ($run.ExitCode -ne 0) 'a force-killed suite must fail the run'
    Assert-Equal 3 $run.Entries.Count ('the manifest holds ' + ($run.Entries -join ', '))

    $hangKey = 'gamma\Hang.Tests.ps1|{0}' -f $script:HostKind
    $hangStatus = Get-ManifestStatus -Entries $run.Entries -Key $hangKey
    Assert-True ($null -ne $hangStatus) ('the killed run left no manifest entry: ' + ($run.Entries -join ', '))
    Assert-True ($hangStatus -like 'timeout-*') `
        ('the killed run was recorded as [' + $hangStatus + '] rather than a timeout')

    Assert-Equal 'exit=0' (Get-ManifestStatus -Entries $run.Entries -Key ('alpha\Same.Tests.ps1|{0}' -f $script:HostKind)) `
        'a suite that finished cleanly beside the killed one lost its own status'
}

Complete-TestRun
