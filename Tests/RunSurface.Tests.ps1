#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for what the shipped entry points promise when they are read from outside:
    Run.ps1's parameter binding, its rendered help, the module commands it calls, and the driver
    backup reader the elevated verification harness uses.

.DESCRIPTION
    Every case that runs Run.ps1 runs it as a bounded child process against a sandboxed
    %ProgramData%, and either binds a poison-pill argument so the body can never start or asserts
    that no log was written at all.

    The unelevated case does not assume the suite is unelevated: it launches its child under a
    restricted SAFER_LEVELID_NORMALUSER token, so the same assertion holds on an elevated host,
    which is what every GitHub runner is.
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

$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# The script the restricted token runs. It is not a probe: it runs the REAL Run.ps1, and everything
# it reports back travels through a file, because it is started with no console and no inherited
# handle, so it has no stdout to write to and its own exit code says nothing about Run.ps1's.
$script:DeElevatedWrapperBody = @'
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$admin = $true
$code = -1
$note = ''
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Run.ps1 is started ONLY once the token is known to be unprivileged. If a machine ever fails to
    # de-elevate, an elevated -Scheduled run here would perform a real cleanup of the host, so this
    # reports the token instead and lets the caller decide.
    if (-not $admin) {
        # Started as a bounded process rather than called inline: an inline call has no deadline, so
        # a Run.ps1 that hung would hold this wrapper past its own bound and force the watchdog to
        # do the reporting - i.e. report nothing. Redirected and drained so a full pipe buffer
        # cannot deadlock it either.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $env:WAC_DEELEVATE_HOST
        $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Scheduled -BudgetMinutes 1 -MutexName "{1}"' -f `
            $env:WAC_DEELEVATE_RUN, $env:WAC_DEELEVATE_MUTEX
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $child = [System.Diagnostics.Process]::Start($psi)
        [void]$child.StandardOutput.ReadToEndAsync()
        [void]$child.StandardError.ReadToEndAsync()

        if ($child.WaitForExit([int]$env:WAC_DEELEVATE_CHILD_MS)) {
            $code = $child.ExitCode
        }
        else {
            & (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe') '/T' '/F' '/PID' $child.Id | Out-Null
            $note = 'CHILD-TIMEOUT'
        }
    }
}
catch {
    $note = 'WRAPPER-ERROR ' + $_.Exception.Message
}
finally {
    # Moved into place rather than written in place: the caller kills this tree the moment its
    # deadline expires, and a kill landing mid-write would leave a torn file that parses as a
    # finished run. Written from finally so even a wrapper that threw reports something - silence is
    # the one outcome the caller can only time out on.
    $partial = $env:WAC_DEELEVATE_RESULT + '.partial'
    [System.IO.File]::WriteAllText($partial, ('ADMIN={0}{1}EXIT={2}{1}NOTE={3}{1}' -f `
            $admin, [Environment]::NewLine, $code, $note))
    [System.IO.File]::Move($partial, $env:WAC_DEELEVATE_RESULT)
}

exit 0
'@

function Invoke-InheritedTokenRun {
    <#
    .SYNOPSIS
        Fallback when the machine cannot hand out a restricted token: run Run.ps1 under THIS token.
    .DESCRIPTION
        Legitimate only while this process is itself unprivileged, and then it proves exactly the
        same thing the de-elevated path does - an unelevated -Scheduled run must refuse to clean.
        On an ELEVATED host there is nothing to fall back to: starting Run.ps1 -Scheduled with a
        full token would perform a real cleanup of the machine running the tests, which is not a
        price a test may pay. That combination returns 'no-unprivileged-token' and the caller turns
        it into a skip, which fails the suite. See the risk note on the case itself.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    if (Test-WacIsAdministrator) {
        return [PSCustomObject]@{
            Status    = 'no-unprivileged-token'
            ExitCode  = -1
            Mechanism = 'none'
            Detail    = ('{0}; this host is elevated, so no unprivileged token is left to fall back to and a -Scheduled run here would clean the machine for real' -f $Reason)
        }
    }

    $probe = Invoke-Probe -TimeoutMs 25000 -Environment $Environment -CommandLine (
        ConvertTo-WacCommandLine -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:RunPath,
            '-Scheduled', '-BudgetMinutes', '1',
            '-MutexName', ('Global\WacTest{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))))

    if (-not $probe.Exited) {
        return [PSCustomObject]@{
            Status    = 'timeout'
            ExitCode  = -1
            Mechanism = 'inherited-unprivileged-token'
            Detail    = ('{0}; the fallback run under the token this suite already holds did not finish inside 25000 ms' -f $Reason)
        }
    }

    return [PSCustomObject]@{
        Status    = 'ok'
        ExitCode  = $probe.ExitCode
        Mechanism = 'inherited-unprivileged-token'
        Detail    = ('{0}; asserted against the unprivileged token this suite already holds instead' -f $Reason)
    }
}

function Invoke-DeElevatedRun {
    <#
    .SYNOPSIS
        Runs Run.ps1 -Scheduled under a genuinely unprivileged token, whatever token this suite holds.
    .DESCRIPTION
        Start-TestRestrictedProcess hands the wrapper a SAFER_LEVELID_NORMALUSER token: its
        Administrators SID is deny-only, the same shape UAC gives a filtered token. It needs no
        password, no consent prompt, no scheduled task and no elevation of its own, so it runs
        unattended on a developer shell and on the elevated GitHub windows-latest runner alike.
        Measured cost of the whole case on this machine, 2026-08-24: 1.9 s pwsh / 1.6 s powershell.

        The wrapper is a REAL child, so this function waits on its handle rather than polling for a
        file, and kills its tree by an id no recycled pid can alias. What still has to travel
        through a file is what the wrapper LEARNED: it is started with no console and no inherited
        handle, so it has no stdout, and its own exit code is not Run.ps1's.

        Everything it creates lives in the caller's sandbox, so Remove-TestSandbox is the cleanup.

        THE BUDGET, and why it is this small. Run-Tests.ps1 force-kills a suite that produces no
        output for IdleTimeoutSeconds, default 120, and this call prints nothing while it waits - so
        its entire duration is idle time. A deadline ABOVE that budget is worse than no deadline:
        the runner wins the race and the caller is killed before its own cleanup, so finally never
        runs and the sandbox survives. The default is 40 s, about 20x the measured cost and a third
        of the runner's budget. Worst case for the whole case is the still-elevated path: 40 s of
        waiting plus a 25 s fallback run, 65 s, still inside 120.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        # The bounds make two relations hold by construction rather than by a default value that is
        # one edit away from being wrong:
        #   lower 20000 keeps CHILD_MS (TimeoutMs-15 s) genuinely below TimeoutMs, so the wrapper can
        #     still report a hung Run.ps1 before this wait gives up; under it Math::Max clamps to 5 s
        #     and CHILD_MS would meet or exceed the wait it is supposed to pre-empt.
        #   upper 100000 keeps the whole call inside Run-Tests.ps1's 120 s default idle budget, so
        #     this function is always the one that kills the wrapper tree and always reaches its own
        #     cleanup. The bound is coupled to that runner default: Run-Tests.ps1 accepts
        #     -IdleTimeoutSeconds down to 10, and no ValidateRange here can see it.
        [ValidateRange(20000, 100000)][int]$TimeoutMs = 40000
    )

    $wrapper = Join-Path -Path $Sandbox -ChildPath 'DeElevate.ps1'
    $resultFile = Join-Path -Path $Sandbox -ChildPath 'DeElevate.result'
    [System.IO.File]::WriteAllText($wrapper, $script:DeElevatedWrapperBody)

    $childEnvironment = @{}
    foreach ($key in $Environment.Keys) { $childEnvironment[$key] = [string]$Environment[$key] }
    $childEnvironment['WAC_DEELEVATE_HOST'] = $script:HostExe
    $childEnvironment['WAC_DEELEVATE_RUN'] = $script:RunPath
    $childEnvironment['WAC_DEELEVATE_MUTEX'] = 'Global\WacTest{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8)
    $childEnvironment['WAC_DEELEVATE_RESULT'] = $resultFile
    $childEnvironment['WAC_DEELEVATE_CHILD_MS'] = [string][Math]::Max(5000, $TimeoutMs - 15000)

    $started = Start-TestRestrictedProcess -FilePath $script:HostExe -Environment $childEnvironment `
        -WorkingDirectory $script:RepoRoot -Arguments (ConvertTo-WacCommandLine -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wrapper))

    if (-not $started.Child) {
        # This machine cannot hand out a restricted token at all. That is a property of the MACHINE,
        # not of Run.ps1, so rather than proving nothing this degrades to the token this suite
        # already holds - which still asserts the contract whenever that token is unprivileged.
        return (Invoke-InheritedTokenRun -Environment $Environment -Reason (
                'no restricted token could be produced here: {0}' -f $started.Error))
    }

    $exited = $false
    try {
        $exited = $started.Child.WaitForExit($TimeoutMs)
        if (-not $exited) {
            # Killed by handle-pinned id: this process has held the child's handle since it was
            # created, so Windows cannot have reissued that id to anything else.
            [void](Stop-WacProcessTree -ProcessId $started.Child.Id)
            [void]$started.Child.WaitForExit(10000)
        }
    }
    finally {
        try { $started.Child.Dispose() } catch { $null = $_ }
    }

    if (-not (Test-Path -LiteralPath $resultFile -PathType Leaf)) {
        return [PSCustomObject]@{
            Status    = 'timeout'
            ExitCode  = -1
            Mechanism = 'safer-normaluser-createprocessasuser'
            Detail    = ('the de-elevated run wrote no result inside {0} ms; the wrapper {1}' -f `
                    $TimeoutMs, $(if ($exited) { 'exited without writing one' } else { 'never exited, so its tree was killed' }))
        }
    }

    $admin = ''
    $note = ''
    $exitCode = -1
    foreach ($line in @([System.IO.File]::ReadAllLines($resultFile))) {
        if ($line.StartsWith('ADMIN=', [System.StringComparison]::Ordinal)) { $admin = $line.Substring(6) }
        elseif ($line.StartsWith('EXIT=', [System.StringComparison]::Ordinal)) { $exitCode = [int]($line.Substring(5)) }
        elseif ($line.StartsWith('NOTE=', [System.StringComparison]::Ordinal)) { $note = $line.Substring(5) }
    }

    if (-not [string]::Equals($admin, 'False', [System.StringComparison]::Ordinal)) {
        # Same reasoning as a failed launch: the token came back privileged, so this machine cannot
        # de-elevate, but the suite's own token may still be able to prove the contract.
        return (Invoke-InheritedTokenRun -Environment $Environment -Reason (
                'the restricted token still reported IsInRole(Administrator)=[{0}], so Run.ps1 was deliberately not started' -f $admin))
    }

    if ($note) {
        # The wrapper reached its own reporting path, so this is a real hang inside Run.ps1 rather
        # than an unexplained silence, and it is reported as the failure it is.
        return [PSCustomObject]@{
            Status    = 'timeout'
            ExitCode  = -1
            Mechanism = 'safer-normaluser-createprocessasuser'
            Detail    = ('the de-elevated wrapper reported [{0}] instead of a clean Run.ps1 exit' -f $note)
        }
    }

    return [PSCustomObject]@{
        Status    = 'ok'
        ExitCode  = $exitCode
        Mechanism = 'safer-normaluser-createprocessasuser'
        Detail    = ''
    }
}

# ---------------------------------------------------------------------------------------------
# The Run.ps1 command-line contract
# ---------------------------------------------------------------------------------------------

Test-Case 'A scheduled run that is not elevated fails instead of cleaning' {
    # The child is DE-ELEVATED rather than merely inherited, so the assertions below are made
    # against a genuinely unprivileged token no matter which token this suite holds. The old shape
    # returned early when this process was elevated, which made it a guaranteed silent pass in
    # CI - ledger R-23.
    #
    # WHAT HAS BEEN MEASURED, AND WHAT HAS NOT. Every run of this case so far was made from a
    # NON-elevated session. On a non-elevated host the pre-R-23 code took the same branch and made
    # the same assertions, so those runs do not yet distinguish this shape from the old one: the
    # difference only shows on an ELEVATED host, and no elevated run has been made. That is what
    # the evidence line below is for - it names the token this suite held, the de-elevation
    # mechanism actually used and the exit code the child returned, so ONE elevated run of this
    # suite settles which path was taken instead of leaving it to be argued.
    #
    # RISK, stated plainly. The token now comes from SaferCreateLevel + SaferComputeTokenFromLevel
    # called here, and the process from CreateProcessAsUser - the same API runas /trustlevel:0x20000
    # uses internally, but WITHOUT runas, which is the only way to pass CREATE_NO_WINDOW and stop a
    # console (and, where Windows Terminal is the default terminal, a window that steals focus) from
    # being created at all. runas is proven on a hosted runner and this call is not, so if either
    # Safer call or CreateProcessAsUser behaves differently there, Invoke-DeElevatedRun degrades to
    # the FALLBACK: Run.ps1 under the token this suite already holds, which proves exactly the same
    # contract whenever that token is unprivileged, and on an elevated runner proves nothing and
    # therefore SKIPS - which exits the suite 3 and turns the whole CI run red.
    #
    # That is accepted deliberately: the only other option on an elevated host is to start Run.ps1
    # -Scheduled with a full token, which would perform a real cleanup of the runner. A red run
    # saying "this machine could not produce an unprivileged token" is a correct report; a green run
    # that proved nothing is what R-23 was. Nor is the token trusted on the API's word: the wrapper
    # reports the token it actually holds, and a token that came back privileged takes the same
    # fallback rather than letting an elevated -Scheduled run masquerade as a de-elevated one.
    # The obvious dependency scare does not apply: Secondary Logon (seclogon) is Stopped/Manual on
    # the machine these numbers came from and the Safer path still worked, so the mechanism does not
    # need that service running.
    $sandbox = New-TestSandbox -Prefix 'orch-scheduled'
    try {
        # An UNELEVATED run logs under the user's own profile on purpose: whoever CREATES
        # %ProgramData%\WindowsAutoCleanup becomes its owner and, through CREATOR OWNER inheritance,
        # gains full control of the directory the SYSTEM task later writes its audit log into. Both
        # roots are redirected so the case proves the log went to the per-user one and NOT to the
        # machine-wide one.
        #
        # -TimeoutMs is deliberately NOT passed: the shipped default is the value under test, and a
        # second number here is exactly how the deadline drifted past the test runner's idle budget.
        $result = Invoke-DeElevatedRun -Sandbox $sandbox -Environment @{
            ProgramData  = (Join-Path -Path $sandbox -ChildPath 'PD')
            LOCALAPPDATA = (Join-Path -Path $sandbox -ChildPath 'LA')
        }

        Write-Host ('      evidence: suiteElevated={0} mechanism={1} status={2} childExit={3}{4}' -f `
                (Test-WacIsAdministrator), $result.Mechanism, $result.Status, $result.ExitCode,
            $(if ($result.Detail) { ' detail=' + $result.Detail } else { '' }))

        # A hang is a real defect, so it fails. A machine that cannot hand out an unprivileged token
        # at all proved nothing, so it SKIPS - which is its own outcome, is excluded from passed=,
        # and exits the suite 3. It can no longer be mistaken for a pass.
        if ($result.Status -eq 'timeout') { Assert-True $false $result.Detail }
        if ($result.Status -ne 'ok') { Set-TestSkipped -Reason $result.Detail }

        Assert-Equal 1 $result.ExitCode 'a scheduled run without elevation must exit 1 rather than clean'

        $logs = @(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'LA\WindowsAutoCleanup\Logs') `
                -Filter 'WindowsAutoCleanup_*.log' -File -ErrorAction SilentlyContinue)
        Assert-Equal 1 $logs.Count 'the run did not create exactly one log file in the redirected per-user root'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $sandbox -ChildPath 'PD\WindowsAutoCleanup')) `
            'an unelevated run created the machine-wide state directory and would therefore own it'

        $text = [System.IO.File]::ReadAllText($logs[0].FullName)
        Assert-True ($text.Contains('[CRITICAL] [Run] Administrator privileges are required')) `
        ('the only thing this run says about its exit 1 was written below the highest level -LogLevel accepts: ' + $text)
        Assert-False ($text.Contains('[Summary]')) 'the run reached the cleanup summary without being elevated'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The shared pre-flight gate reports the cause of a refusal, not its symptom' {
    # The gate is dot-sourced rather than lifted, exactly as both entry points load it, so the
    # function under test is the shipped one. Nothing here has a side effect; it reads two verdicts.
    #
    # The ORDER is the assertion. Initialize-WacRun now refuses to create a log at all in a
    # directory it does not trust, so an untrusted state directory arrives here with BOTH answers
    # bad: no durable log, and a trust verdict that came back false. A gate that tested the log
    # first would return 6 and say "no durable audit log" - true, and the symptom of the refusal
    # rather than the refusal, with the exit code that outranks it silently dropped.
    . (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.EntryGate.ps1')

    $durable = [PSCustomObject]@{ IsDurable = $true; Reason = $null }
    $broken = [PSCustomObject]@{ IsDurable = $false; Reason = 'a log write failed' }
    $trusted = [PSCustomObject]@{ IsTrusted = $true; Path = 'C:\ProgramData\WindowsAutoCleanup\Logs'; Reason = 'ok' }
    $untrusted = [PSCustomObject]@{ IsTrusted = $false; Path = 'C:\ProgramData\WindowsAutoCleanup\Logs'; Reason = 'S-1-1-0 can replace children here' }

    $ok = Get-OperationSafetyVerdict -LogHealth $durable -StateTrust $trusted
    Assert-True $ok.Ok $ok.Reason
    Assert-Equal 0 $ok.ExitCode

    # Both bad: the security refusal outranks the incomplete audit trail, which is the same
    # precedence the run's own outcome table uses.
    $refused = Get-OperationSafetyVerdict -LogHealth $broken -StateTrust $untrusted
    Assert-False $refused.Ok
    Assert-Equal 7 $refused.ExitCode 'a refusal whose log never opened was reported as merely incomplete'
    Assert-True ($refused.Reason.Contains('not machine-trusted')) $refused.Reason

    # A log that failed for a reason of its own, with the trust question genuinely answered yes, is
    # still Incomplete - so the reordering above did not turn every log failure into a refusal.
    $incomplete = Get-OperationSafetyVerdict -LogHealth $broken -StateTrust $trusted
    Assert-Equal 6 $incomplete.ExitCode $incomplete.Reason

    # NOT EVALUATED is refused too, and it is refused as a security question rather than as a log
    # one - but only once the log has been ruled out as the thing that is actually known to be wrong.
    Assert-Equal 7 (Get-OperationSafetyVerdict -LogHealth $durable -StateTrust $null).ExitCode
    Assert-Equal 6 (Get-OperationSafetyVerdict -LogHealth $broken -StateTrust $null).ExitCode
    Assert-Equal 6 (Get-OperationSafetyVerdict -LogHealth $null -StateTrust $trusted).ExitCode
}

Test-Case 'No shipped entry point names its own state root, so none opts out of the trust preflight' {
    # Initialize-WacRun verifies machine trust for the roots the MODULE chose, and records NOT
    # EVALUATED for a caller that named its own -CandidateRoot: that location is then the caller's
    # choice and not a claim the module made. Sound exactly as long as nothing shipped names one -
    # so this pins it, rather than leaving it to be remembered by whoever edits an entry point next.
    foreach ($leaf in @('Run.ps1', 'Install-WindowsAutoCleanupTask.ps1', 'Uninstall-WindowsAutoCleanupTask.ps1')) {
        $path = Join-Path -Path $script:RepoRoot -ChildPath $leaf
        Assert-True (Test-Path -LiteralPath $path -PathType Leaf) ('a shipped entry point is missing: ' + $path)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        Assert-Equal 0 (@($errors).Count) ($leaf + ' does not parse')

        $calls = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst]
                }, $true) | Where-Object { $_.GetCommandName() -eq 'Initialize-WacRun' })
        Assert-Equal 1 $calls.Count ($leaf + ' no longer initialises the run exactly once')

        # Every named parameter, compared as a PREFIX: PowerShell binds -Candidate to -CandidateRoot
        # just as happily as the full spelling, so matching the exact name would miss it.
        foreach ($element in @($calls[0].CommandElements)) {
            if (-not ($element -is [System.Management.Automation.Language.CommandParameterAst])) { continue }
            $name = [string]$element.ParameterName
            if (-not $name) { continue }
            Assert-False ('CandidateRoot'.StartsWith($name, [System.StringComparison]::OrdinalIgnoreCase)) `
            ('{0} binds -{1}, which opts the run out of the machine-trust preflight' -f $leaf, $name)
        }
    }
}

Test-Case 'The deprecated -SkipAclHardening switch is still accepted by parameter binding' {
    $sandbox = New-TestSandbox -Prefix 'orch-acl'
    try {
        # -LogLevel NOPE is a poison pill: binding fails before the script body runs, so this proves
        # acceptance of -SkipAclHardening without ever letting a cleanup start.
        $accepted = Invoke-Probe -TimeoutMs 90000 -Environment @{ ProgramData = $sandbox } -CommandLine (
            ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:RunPath,
                '-SkipAclHardening', '-LogLevel', 'NOPE'))

        Assert-True $accepted.Exited 'the binding probe did not finish inside its bound'
        Assert-True ($accepted.ExitCode -ne 0) 'the poison-pill argument was accepted, so the body may have run'

        # Console line wrapping differs per host, so compare with whitespace removed.
        $acceptedText = ($accepted.ErrorText -replace '\s', '')
        Assert-True ($acceptedText.Contains('LogLevel')) $accepted.ErrorText
        Assert-False ($acceptedText.Contains('SkipAclHardening')) `
            'a task registered by an older installer would now fail to bind'

        $unknown = Invoke-Probe -TimeoutMs 90000 -Environment @{ ProgramData = $sandbox } -CommandLine (
            ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:RunPath,
                '-SkipAclHardeningX'))

        # The control: an unknown switch really is rejected by name, which is what makes the
        # assertion above evidence rather than a coincidence.
        Assert-True $unknown.Exited
        Assert-True ($unknown.ExitCode -ne 0)
        Assert-True ((($unknown.ErrorText -replace '\s', '')).Contains('SkipAclHardeningX')) $unknown.ErrorText

        $logs = @(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'WindowsAutoCleanup\Logs') `
                -Filter '*.log' -File -ErrorAction SilentlyContinue)
        Assert-Equal 0 $logs.Count 'a binding failure still executed the script body'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Get-Help renders every parameter and the exit-code table' {
    $sandbox = New-TestSandbox -Prefix 'orch-help'
    try {
        $probe = New-ProbeScript -Body $script:InspectProbeBody -Path (Join-Path -Path $sandbox -ChildPath 'inspect.ps1')

        $result = Invoke-Probe -TimeoutMs 90000 -Environment @{ WAC_PROBE_MODE = 'help'; WAC_PROBE_RUN = $script:RunPath } `
            -CommandLine (ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $probe))

        Assert-True $result.Exited 'the help probe did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)

        # Comment-based help only renders when the block is separated from #Requires by a blank
        # line; without it Get-Help falls back to a stub with no parameters and no notes.
        $expected = 'Scheduled,ResetWindowsUpdateBase,PruneSupersededDrivers,EnableLegacyDiskCleanup,SkipRecycleBin,' +
        'SkipCategory,LogLevel,BudgetMinutes,MutexName,SkipAclHardening'
        Assert-Equal $expected (Get-ProbeValue -Output $result.Output -Key 'PARAMS')

        $synopsis = [string](Get-ProbeValue -Output $result.Output -Key 'SYNOPSIS')
        Assert-True ($synopsis.Length -gt 20) ('the synopsis was [' + $synopsis + ']')

        $notes = [string](Get-ProbeValue -Output $result.Output -Key 'NOTES')
        Assert-True ($notes -match 'Exit codes') $notes
        foreach ($pair in @('0 success', '1 error', '2 completed', '3 another run', '4 elevation', '5 unsupported',
                '6 incomplete', '7 security refusal')) {
            Assert-True ($notes.Contains($pair)) ('the exit-code table is missing "' + $pair + '": ' + $notes)
        }

        $description = [string](Get-ProbeValue -Output $result.Output -Key 'DESCRIPTION')
        Assert-True ($description.Contains('-PruneSupersededDrivers')) `
            'the description no longer documents the opt-in destructive capabilities'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The five modules import together and every Wac command Run.ps1 calls resolves' {
    $sandbox = New-TestSandbox -Prefix 'orch-surface'
    try {
        $called = @{}
        foreach ($node in $script:RunAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $name = $node.GetCommandName()
            if ($name -and $name -match '^[A-Za-z]+-Wac[A-Za-z]+$') { $called[$name] = $true }
        }
        # Run.ps1 declares a few helpers of its own, and dot-sources one more file of them:
        # WindowsAutoCleanup.RunReport.ps1 holds the header, the outcome model and the footer, which
        # read this script's own $script: state and so cannot be a module. Neither set is part of
        # the module surface. The dot-source is asserted below, so this is an exclusion for code
        # that really is loaded and not a hole to hide an unresolved call in.
        $reportPath = Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.RunReport.ps1'
        Assert-True (Test-Path -LiteralPath $reportPath -PathType Leaf) ('the run report part is missing: ' + $reportPath)
        Assert-True ([System.IO.File]::ReadAllText($script:RunPath).Contains("'WindowsAutoCleanup.RunReport.ps1'")) `
            'Run.ps1 no longer loads the run report part, so its header and footer are undefined'

        $reportErrors = $null
        $reportTokens = $null
        $reportAst = [System.Management.Automation.Language.Parser]::ParseFile($reportPath, [ref]$reportTokens, [ref]$reportErrors)
        Assert-Equal 0 (@($reportErrors).Count) 'the run report part does not parse'

        foreach ($ast in @($script:RunAst, $reportAst)) {
            foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                if ($called.ContainsKey($node.Name)) { [void]$called.Remove($node.Name) }
            }
        }

        $names = @($called.Keys | Sort-Object)
        Assert-True ($names.Count -ge 20) ('only {0} module commands were found in Run.ps1' -f $names.Count)

        $probe = New-ProbeScript -Body $script:InspectProbeBody -Path (Join-Path -Path $sandbox -ChildPath 'inspect.ps1')
        $result = Invoke-Probe -TimeoutMs 120000 -CommandLine (ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $probe)) -Environment @{
            WAC_PROBE_MODE    = 'surface'
            WAC_PROBE_SRC     = $script:SrcRoot
            WAC_PROBE_COMMAND = ($names -join ',')
        }

        Assert-True $result.Exited 'the module-surface probe did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)
        Assert-Equal '' ([string](Get-ProbeValue -Output $result.Output -Key 'MISSING')) 'Run.ps1 calls commands the modules do not export'
        Assert-Equal ([string]$names.Count) ([string](Get-ProbeValue -Output $result.Output -Key 'CHECKED'))
        foreach ($module in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
            Assert-True ($result.Output.Contains('IMPORTED=' + $module)) ('module ' + $module + ' did not import: ' + $result.ErrorText)
        }
        Assert-Equal '' $result.ErrorText 'a module wrote to stderr while importing'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The elevated harness finds a driver backup by its manifest, not by the recycled oem name' {
    # Ledger item: backup directories became CONTENT-ADDRESSED (<stem>_<version>_<hash16>) because
    # oem<n>.inf is a name Windows re-issues to an unrelated package after a removal. The harness
    # still looked for Join-Path <backupRoot> <oem name>, a path that can now never exist, so it
    # would have raised its own BLOCKER for every package it really did remove.
    #
    # Invoke-ElevatedVerification.ps1 is not a suite - it refuses to run unelevated and the machine
    # scenarios change the machine - so the reader is LIFTED out of the file that defines it,
    # _ElevatedVerification.MachineScenarios.ps1, and exercised against a synthetic backup root.
    # Same idiom as the relaunch vector: the shipped function runs, not a copy of it.
    $harnessPath = Join-Path -Path $PSScriptRoot -ChildPath '_ElevatedVerification.MachineScenarios.ps1'
    $tokens = $null
    $errors = $null
    $harnessAst = [System.Management.Automation.Language.Parser]::ParseFile($harnessPath, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 (@($errors).Count) (($errors | ForEach-Object { [string]$_ }) -join ' ; ')

    # ConvertTo-VerificationUtcText comes along because PowerShell 7's ConvertFrom-Json hands back a
    # [datetime] where 5.1 hands back a string, and the reader normalises that.
    foreach ($name in @('ConvertTo-VerificationUtcText', 'Get-DriverBackupRecord')) {
        $definition = @($harnessAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
                }, $true) | Where-Object { $_.Name -eq $name })
        Assert-Equal 1 $definition.Count ('the harness must define exactly one {0}' -f $name)
        . ([scriptblock]::Create($definition[0].Extent.Text))
    }

    $sandbox = New-TestSandbox -Prefix 'orch-driverbackup'
    try {
        $root = Join-Path -Path $sandbox -ChildPath 'DriverBackup'

        # A real backup: content-addressed directory name, a manifest naming oem42.inf, a stamped
        # DeletedUtc and one exported file besides the manifest.
        $deleted = Join-Path -Path $root -ChildPath 'wacnet_1.2.3.4_0123456789abcdef'
        [void][System.IO.Directory]::CreateDirectory($deleted)
        [System.IO.File]::WriteAllText((Join-Path -Path $deleted -ChildPath 'wacnet.inf'), 'inf', $script:Utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path -Path $deleted -ChildPath 'wac-driver-backup.json'),
            (@{ Schema = 2; DriverName = 'oem42.inf'; OriginalName = 'wacnet.inf'
                CreatedUtc = '2026-08-24T00:00:00Z'; DeletedUtc = '2026-08-24T00:00:05Z' } | ConvertTo-Json),
            $script:Utf8NoBom)

        # An export of a package that is still installed: same shape, no DeletedUtc.
        $kept = Join-Path -Path $root -ChildPath 'wacaudio_9.9.9.9_fedcba9876543210'
        [void][System.IO.Directory]::CreateDirectory($kept)
        [System.IO.File]::WriteAllText((Join-Path -Path $kept -ChildPath 'wacaudio.inf'), 'inf', $script:Utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path -Path $kept -ChildPath 'wac-driver-backup.json'),
            (@{ Schema = 2; DriverName = 'oem7.inf'; OriginalName = 'wacaudio.inf'
                CreatedUtc = '2026-08-24T00:00:00Z'; DeletedUtc = '' } | ConvertTo-Json), $script:Utf8NoBom)

        # A directory that cannot be identified at all. It must be REPORTED, never skipped quietly.
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $root -ChildPath 'oem42.inf'))

        $records = @(Get-DriverBackupRecord -BackupRoot $root)
        Assert-Equal 3 $records.Count 'every child of the backup root must be accounted for'

        $found = @($records | Where-Object { $_.DriverName -ceq 'oem42.inf' })
        Assert-Equal 1 $found.Count 'the deleted package was not found through its manifest'
        Assert-Equal $deleted $found[0].Directory 'the record does not point at the content-addressed directory'
        Assert-Equal 1 $found[0].FileCount 'the manifest itself must not count as an exported file'
        Assert-Equal '2026-08-24T00:00:05Z' $found[0].DeletedUtc
        Assert-Equal '' $found[0].Unreadable

        $still = @($records | Where-Object { $_.DriverName -ceq 'oem7.inf' })
        Assert-Equal 1 $still.Count
        Assert-Equal '' $still[0].DeletedUtc 'an export of a package that is still installed must not claim a deletion'

        # The trap the old shape fell into: a directory NAMED after the oem package proves nothing.
        $unreadable = @($records | Where-Object { $_.Unreadable })
        Assert-Equal 1 $unreadable.Count 'a directory with no manifest was silently ignored'
        Assert-True ($unreadable[0].Unreadable.Contains('wac-driver-backup.json')) $unreadable[0].Unreadable
        Assert-Equal '' $unreadable[0].DriverName 'a directory name was mistaken for a package identity'

        Assert-Equal 0 (@(Get-DriverBackupRecord -BackupRoot (Join-Path -Path $sandbox -ChildPath 'never-created')).Count) `
        'a missing backup root must be empty rather than an error'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
