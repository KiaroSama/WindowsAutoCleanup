#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the Run.ps1 contract: the elevated-relaunch argument vector, parameter
    binding, the rendered help, and the module surface the entry point depends on.

.DESCRIPTION
    Run.ps1 executes its main body on load, so the relaunch builder is lifted out of the script's
    AST and defined on its own instead of dot-sourcing the whole file. Every assertion is made on
    the REAL returned vector, on the REAL command line built from it, or on what a REAL child
    process received - never on the text of the script, because a test that greps the source for
    '-ResetWindowsUpdateBase' is exactly what let ledger P0-2 ship: an explicit
    -ResetWindowsUpdateBase:$false was lost across the UAC relaunch while the old suite stayed green.

    Nothing here asserts on this process's own privilege level: the hosted Windows runner is
    elevated and a developer shell usually is not. The one case that needs a non-elevated child
    MAKES one, through Invoke-DeElevatedRun, which is INTENDED to assert the same thing in both
    places. That intent is only half measured: every run so far has been from a non-elevated
    session, where the code this replaced took the same branch anyway, so no run has yet shown the
    elevated path behaving. The case prints an evidence line naming the token it held, the
    mechanism it used and the child's exit code, so a single elevated run of this suite settles it.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'

Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# The host running this suite, taken from the live process rather than PATH, so the child is the
# same edition that is currently under test.
$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

# ---------------------------------------------------------------------------------------------
# Lifting the function under test out of Run.ps1
# ---------------------------------------------------------------------------------------------

$script:RunTokens = $null
$script:RunErrors = $null
$script:RunAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $script:RunPath, [ref]$script:RunTokens, [ref]$script:RunErrors)

$script:RelaunchAst = @($script:RunAst.FindAll({
            param($node)
            ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and
            ($node.Name -eq 'Get-WacRunRelaunchArgument')
        }, $true))

if ($script:RelaunchAst.Count -ne 1) {
    throw ('Run.ps1 must define exactly one Get-WacRunRelaunchArgument; found {0}.' -f $script:RelaunchAst.Count)
}

# Defining the extracted function is the whole point: the vector it returns is then produced by the
# shipped code, not by a copy of it living in this suite.
. ([scriptblock]::Create($script:RelaunchAst[0].Extent.Text))

function Get-RelaunchVector {
    <#
    .SYNOPSIS
        Sets the script-scope variables Run.ps1 would have bound, then returns the real vector.
    #>
    param(
        [hashtable]$Bound = @{},
        [bool]$Reset = $true,
        [bool]$Prune = $false,
        [bool]$Legacy = $false,
        [bool]$SkipBin = $false,
        [string]$Level = 'INFO',
        [int]$Budget = 210,
        [AllowEmptyCollection()][string[]]$Category = @(),
        [string]$Mutex = 'Global\WindowsAutoCleanup',
        [string]$ScriptFile = 'C:\Tools\WindowsAutoCleanup\Run.ps1'
    )

    $script:ResetWindowsUpdateBase = $Reset
    $script:PruneSupersededDrivers = $Prune
    $script:EnableLegacyDiskCleanup = $Legacy
    $script:SkipRecycleBin = $SkipBin
    $script:LogLevel = $Level
    $script:BudgetMinutes = $Budget
    $script:SkipCategory = @($Category)
    $script:MutexName = $Mutex
    $script:ScriptPath = $ScriptFile

    return @(Get-WacRunRelaunchArgument -Bound $Bound)
}

function Get-RelaunchPayload {
    <#
    .SYNOPSIS
        The PowerShell source the child will execute: the element after -Command.
    .DESCRIPTION
        The vector is -NoProfile -ExecutionPolicy Bypass [-HostSwitch...] -Command <payload>.
        -Command rather than -File is deliberate and load-bearing: Windows PowerShell 5.1 refuses to
        bind -Switch:$false under -File at all, so every switch value in this file is asserted on the
        payload PowerShell will actually parse.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Vector)

    for ($i = 0; $i -lt $Vector.Count; $i++) {
        if ([string]::Equals($Vector[$i], '-Command', [System.StringComparison]::Ordinal)) {
            if ($i + 1 -lt $Vector.Count) { return $Vector[$i + 1] }
        }
    }
    return ''
}

function Test-PayloadHasSwitch {
    <#
    .SYNOPSIS
        Ordinal check for an exact '-Name:$value' token in the payload.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Payload,
        [Parameter(Mandatory = $true)][string]$Token
    )

    return $Payload.IndexOf($Token, [System.StringComparison]::Ordinal) -ge 0
}

function Test-PayloadHasBareSwitch {
    <#
    .SYNOPSIS
        True when the payload carries '-Name' with no ':value' suffix, which would let the child fall
        back to its own default.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Payload,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return [regex]::IsMatch($Payload, ('(?<![\w:$])-' + [regex]::Escape($Name) + '(?![\w:])'))
}

function Test-VectorContains {
    <#
    .SYNOPSIS
        Ordinal membership. PowerShell's -contains is case-insensitive and would pass a casing
        regression in a switch name.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Vector,
        [Parameter(Mandatory = $true)][string]$Value
    )

    foreach ($element in $Vector) {
        if ([string]::Equals($element, $Value, [System.StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------------------------
# Child processes
# ---------------------------------------------------------------------------------------------

function Start-ProbeProcess {
    <#
    .SYNOPSIS
        Starts a child of the host running this suite with one pre-quoted command line.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [hashtable]$Environment = @{},
        [string]$HostExe
    )

    if (-not $HostExe) { $HostExe = $script:HostExe }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $HostExe
    $psi.Arguments = $CommandLine
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $script:RepoRoot
    foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }

    return [System.Diagnostics.Process]::Start($psi)
}

function Wait-ProbeProcess {
    <#
    .SYNOPSIS
        Bounded wait plus process-tree kill, so a child that never exits cannot hang this suite:
        "did not finish inside the bound" is the detected signal, not a stalled run.
    #>
    param(
        [Parameter(Mandatory = $true)]$Process,
        [int]$TimeoutMs = 90000
    )

    $outTask = $Process.StandardOutput.ReadToEndAsync()
    $errTask = $Process.StandardError.ReadToEndAsync()
    $exited = $Process.WaitForExit($TimeoutMs)

    if (-not $exited) {
        [void](Stop-WacProcessTree -ProcessId $Process.Id)
        [void]$Process.WaitForExit(10000)
    }

    [void]$outTask.Wait(5000)
    [void]$errTask.Wait(5000)

    $exitCode = -1
    if ($exited) { try { $exitCode = [int]$Process.ExitCode } catch { $exitCode = -1 } }

    return [PSCustomObject]@{
        Exited    = $exited
        ExitCode  = $exitCode
        Output    = $(if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' })
        ErrorText = $(if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' })
    }
}

function Invoke-Probe {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [hashtable]$Environment = @{},
        [int]$TimeoutMs = 90000,
        [string]$HostExe
    )

    $process = $null
    try {
        $process = Start-ProbeProcess -CommandLine $CommandLine -Environment $Environment -HostExe $HostExe
        return (Wait-ProbeProcess -Process $process -TimeoutMs $TimeoutMs)
    }
    finally {
        if ($process) { try { $process.Dispose() } catch { $null = $_ } }
    }
}

function Get-ProbeValue {
    <#
    .SYNOPSIS
        Reads one KEY=value line out of a probe's stdout.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Output,
        [Parameter(Mandatory = $true)][string]$Key
    )

    foreach ($line in @($Output -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith($Key + '=', [System.StringComparison]::Ordinal)) {
            return $trimmed.Substring($Key.Length + 1)
        }
    }
    return $null
}

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

# A parameter block that mirrors Run.ps1's, so a value that does not survive the command line shows
# up as the DEFAULT the parent never asked for - which is exactly how P0-2 behaved.
$script:ArgumentProbeBody = @'
[CmdletBinding()]
param(
    [switch]$Scheduled,
    [switch]$ResetWindowsUpdateBase = $true,
    [switch]$PruneSupersededDrivers,
    [switch]$EnableLegacyDiskCleanup,
    [switch]$SkipRecycleBin,
    [string[]]$SkipCategory = @(),
    [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
    [ValidateRange(1, 235)][int]$BudgetMinutes = 210,
    [string]$MutexName = 'Global\WindowsAutoCleanup'
)

Set-StrictMode -Version 2.0
$split = @($SkipCategory | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

Write-Output ('SELF=' + $PSCommandPath)
Write-Output ('RESET=' + [bool]$ResetWindowsUpdateBase)
Write-Output ('PRUNE=' + [bool]$PruneSupersededDrivers)
Write-Output ('LEGACY=' + [bool]$EnableLegacyDiskCleanup)
Write-Output ('SKIPBIN=' + [bool]$SkipRecycleBin)
Write-Output ('LOGLEVEL=' + $LogLevel)
Write-Output ('BUDGET=' + $BudgetMinutes)
Write-Output ('MUTEX=' + $MutexName)
Write-Output ('CATEGORY=' + ($split -join '|'))
exit 0
'@

$script:InspectProbeBody = @'
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:WAC_PROBE_MODE -eq 'help') {
    $help = Get-Help -Full -Name $env:WAC_PROBE_RUN
    Write-Output ('PARAMS=' + ((@($help.parameters.parameter) | ForEach-Object { $_.name }) -join ','))
    Write-Output ('SYNOPSIS=' + ((($help.Synopsis) -replace '\s+', ' ').Trim()))
    Write-Output ('DESCRIPTION=' + (((($help.description | Out-String)) -replace '\s+', ' ').Trim()))
    Write-Output ('NOTES=' + ((($help.alertSet.alert | Out-String) -replace '\s+', ' ').Trim()))
    exit 0
}

if ($env:WAC_PROBE_MODE -eq 'surface') {
    foreach ($name in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
        $path = Join-Path -Path $env:WAC_PROBE_SRC -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $name)
        Import-Module -Name $path -Force -DisableNameChecking -ErrorAction Stop
        Write-Output ('IMPORTED=' + $name)
    }

    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($command in @($env:WAC_PROBE_COMMAND -split ',' | Where-Object { $_ })) {
        if (-not (Get-Command -Name $command -CommandType Function -ErrorAction SilentlyContinue)) {
            [void]$missing.Add($command)
        }
    }

    Write-Output ('MISSING=' + ($missing -join ','))
    Write-Output ('CHECKED=' + @($env:WAC_PROBE_COMMAND -split ',' | Where-Object { $_ }).Count)
    exit 0
}

Write-Output 'MODE=unknown'
exit 9
'@

function New-ProbeScript {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Body
    )

    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    [System.IO.File]::WriteAllText($Path, $Body, (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}

# ---------------------------------------------------------------------------------------------
# The relaunch vector
# ---------------------------------------------------------------------------------------------

Test-Case 'Run.ps1 parses cleanly and keeps the relaunch vector in one testable function' {
    Assert-Equal 0 (@($script:RunErrors).Count) (($script:RunErrors | ForEach-Object { [string]$_ }) -join ' ; ')
    Assert-True (@($script:RunTokens).Count -gt 100) 'the parser produced no tokens for Run.ps1'

    $vector = Get-RelaunchVector
    Assert-True (Test-VectorContains -Vector $vector -Value '-Command') `
        ('the relaunch must go through -Command, not -File: ' + ($vector -join ' '))
    Assert-True ((Get-RelaunchPayload -Vector $vector).Length -gt 0) 'the -Command payload was empty'
}

Test-Case 'The default relaunch vector states every switch explicitly' {
    $vector = Get-RelaunchVector

    $expected = "-NoProfile -ExecutionPolicy Bypass -Command " +
        "`$LASTEXITCODE = 1; & 'C:\Tools\WindowsAutoCleanup\Run.ps1' -EnableLegacyDiskCleanup:`$false " +
        "-PruneSupersededDrivers:`$false -ResetWindowsUpdateBase:`$true -SkipRecycleBin:`$false " +
        "-BudgetMinutes '210' -LogLevel 'INFO'; exit `$LASTEXITCODE"

    Assert-Equal $expected ($vector -join ' ')
}

Test-Case 'An explicit -ResetWindowsUpdateBase:$false survives the relaunch (ledger P0-2)' {
    $vector = Get-RelaunchVector -Reset $false -Bound @{ ResetWindowsUpdateBase = $false }

    # The load-bearing assertion. A vector that merely CONTAINS the text '-ResetWindowsUpdateBase'
    # is the defect: the child then applies the $true default and DISM runs /ResetBase anyway.
    $payload = Get-RelaunchPayload -Vector $vector

    Assert-True (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$false') `
        ('the payload was ' + $payload)
    Assert-False (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$true') `
        'the child was told the opposite of what the parent was given'
    Assert-False (Test-PayloadHasBareSwitch -Payload $payload -Name 'ResetWindowsUpdateBase') `
        'a bare switch lets the child fall back to its default'

    $expected = "`$LASTEXITCODE = 1; & 'C:\Tools\WindowsAutoCleanup\Run.ps1' -EnableLegacyDiskCleanup:`$false " +
        "-PruneSupersededDrivers:`$false -ResetWindowsUpdateBase:`$false -SkipRecycleBin:`$false " +
        "-BudgetMinutes '210' -LogLevel 'INFO'; exit `$LASTEXITCODE"
    Assert-Equal $expected $payload
}

Test-Case 'An explicit -ResetWindowsUpdateBase:$true is emitted explicitly too' {
    $vector = Get-RelaunchVector -Reset $true -Bound @{ ResetWindowsUpdateBase = $true }

    $payload = Get-RelaunchPayload -Vector $vector
    Assert-True (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$true') $payload
    Assert-False (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$false') $payload
    Assert-False (Test-PayloadHasBareSwitch -Payload $payload -Name 'ResetWindowsUpdateBase') $payload
}

Test-Case 'The three opt-in switches round-trip in both states' {
    $off = Get-RelaunchPayload -Vector (Get-RelaunchVector)
    foreach ($name in @('PruneSupersededDrivers', 'EnableLegacyDiskCleanup', 'SkipRecycleBin')) {
        Assert-True (Test-PayloadHasSwitch -Payload $off -Token ('-{0}:$false' -f $name)) ('missing off state for ' + $name)
        Assert-False (Test-PayloadHasBareSwitch -Payload $off -Name $name) ('bare switch emitted for ' + $name)
    }

    $on = Get-RelaunchPayload -Vector (Get-RelaunchVector -Prune $true -Legacy $true -SkipBin $true `
        -Bound @{ PruneSupersededDrivers = $true; EnableLegacyDiskCleanup = $true; SkipRecycleBin = $true })
    foreach ($name in @('PruneSupersededDrivers', 'EnableLegacyDiskCleanup', 'SkipRecycleBin')) {
        Assert-True (Test-PayloadHasSwitch -Payload $on -Token ('-{0}:$true' -f $name)) ('missing on state for ' + $name)
        Assert-False (Test-PayloadHasSwitch -Payload $on -Token ('-{0}:$false' -f $name)) ('both states emitted for ' + $name)
    }

    # An opt-in switch the caller never asked for must still be stated, and stated as false.
    Assert-True (Test-PayloadHasSwitch -Payload $off -Token '-EnableLegacyDiskCleanup:$false')
}

Test-Case 'A script path containing spaces is quoted exactly once on the command line' {
    $spaced = 'C:\Program Files\Windows Auto Cleanup\Run.ps1'
    $vector = Get-RelaunchVector -ScriptFile $spaced

    # Two quoting layers, each applied exactly once: the payload single-quotes the path for the
    # PowerShell parser, and ConvertTo-WacCommandLine double-quotes the payload for CreateProcess.
    # Doing either twice is how a relaunch ends up looking for a directory called '"C:\Program'.
    $payload = Get-RelaunchPayload -Vector $vector
    Assert-True ($payload.StartsWith(("`$LASTEXITCODE = 1; & '" + $spaced + "' "), [System.StringComparison]::Ordinal)) $payload

    $commandLine = ConvertTo-WacCommandLine -ArgumentList $vector
    $expected = '-NoProfile -ExecutionPolicy Bypass -Command "' + $payload + '"'
    Assert-Equal $expected $commandLine
}

Test-Case 'SkipCategory appears only when it was bound and travels as one token' {
    $absent = Get-RelaunchVector -Category @('Temp')
    Assert-False (Test-VectorContains -Vector $absent -Value '-SkipCategory') `
        'an unbound -SkipCategory was forwarded to the child'

    $empty = Get-RelaunchVector -Category @() -Bound @{ SkipCategory = @() }
    Assert-False (Test-VectorContains -Vector $empty -Value '-SkipCategory') `
        'an empty -SkipCategory was forwarded as a value-less switch'

    $bound = Get-RelaunchPayload -Vector (Get-RelaunchVector -Category @('Windows Update cache', 'Temp') `
        -Bound @{ SkipCategory = @('Windows Update cache', 'Temp') })

    # Under -Command the child's parser sees a real ARRAY, so each category keeps its own quoting and
    # a space inside a category name can no longer split it into two elements.
    $expectedFragment = "-SkipCategory 'Windows Update cache','Temp'"
    Assert-True ($bound.IndexOf($expectedFragment, [System.StringComparison]::Ordinal) -ge 0) `
        ('the payload was ' + $bound)
}

Test-Case 'MutexName appears only when it was bound' {
    $absent = Get-RelaunchPayload -Vector (Get-RelaunchVector -Mutex 'Global\WindowsAutoCleanup')
    Assert-False ($absent.IndexOf('-MutexName', [System.StringComparison]::Ordinal) -ge 0) `
        'the default mutex name was forwarded even though it was never bound'

    $bound = Get-RelaunchPayload -Vector (Get-RelaunchVector -Mutex 'Global\WacTestProbe' `
        -Bound @{ MutexName = 'Global\WacTestProbe' })
    $expectedFragment = "-MutexName 'Global\WacTestProbe'"
    Assert-True ($bound.IndexOf($expectedFragment, [System.StringComparison]::Ordinal) -ge 0) $bound
}

Test-Case 'The elevated relaunch host binds the values the vector carries' {
    $sandbox = New-TestSandbox -Prefix 'orch-relaunch'
    try {
        # The child must be started by the host Run.ps1 would really elevate through, not by the
        # host running this suite: the two do not agree on -File and switch values (see the
        # companion case below), so testing the wrong one would prove nothing about the relaunch.
        $relaunchHost = Get-WacCanonicalPowerShellHost
        Assert-True ([bool]$relaunchHost) 'no machine-trusted PowerShell host was found, so the relaunch cannot be tested'

        $probe = New-ProbeScript -Body $script:ArgumentProbeBody `
            -Path (Join-Path -Path $sandbox -ChildPath 'Windows Auto Cleanup\Relaunch Probe.ps1')

        $vector = Get-RelaunchVector -ScriptFile $probe -Reset $false -Prune $true -Level 'DEBUG' -Budget 42 `
            -Category @('Windows Update cache', 'Temp') -Mutex 'Global\WacTestProbe' `
            -Bound @{
            ResetWindowsUpdateBase = $false
            PruneSupersededDrivers = $true
            SkipCategory           = @('Windows Update cache', 'Temp')
            MutexName              = 'Global\WacTestProbe'
        }

        $result = Invoke-Probe -CommandLine (ConvertTo-WacCommandLine -ArgumentList $vector) -TimeoutMs 90000 -HostExe $relaunchHost

        Assert-True $result.Exited 'the probe child did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ('the relaunch vector did not bind in ' + $relaunchHost + ': ' + $result.ErrorText)
        Assert-Equal $probe (Get-ProbeValue -Output $result.Output -Key 'SELF') 'the spaced script path did not survive quoting'
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'RESET') 'the child fell back to the default (ledger P0-2)'
        Assert-Equal 'True' (Get-ProbeValue -Output $result.Output -Key 'PRUNE')
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'LEGACY')
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'SKIPBIN')
        Assert-Equal 'DEBUG' (Get-ProbeValue -Output $result.Output -Key 'LOGLEVEL')
        Assert-Equal '42' (Get-ProbeValue -Output $result.Output -Key 'BUDGET')
        Assert-Equal 'Global\WacTestProbe' (Get-ProbeValue -Output $result.Output -Key 'MUTEX')
        Assert-Equal 'Windows Update cache|Temp' (Get-ProbeValue -Output $result.Output -Key 'CATEGORY')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The named half of the vector survives -File on the host running this suite' {
    $sandbox = New-TestSandbox -Prefix 'orch-named'
    try {
        $probe = New-ProbeScript -Body $script:ArgumentProbeBody `
            -Path (Join-Path -Path $sandbox -ChildPath 'Windows Auto Cleanup\Named Probe.ps1')

        # Named values and the script path only. The boolean half is covered by the case above,
        # against the host that actually receives it.
        $vector = Get-WacRelaunchArgument -ScriptPath $probe -NamedValue @{
            LogLevel      = 'WARNING'
            BudgetMinutes = '7'
            SkipCategory  = 'Windows Update cache,Temp'
            MutexName     = 'Global\WacTestProbe'
        }

        $result = Invoke-Probe -CommandLine (ConvertTo-WacCommandLine -ArgumentList $vector) -TimeoutMs 90000

        Assert-True $result.Exited 'the probe child did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)
        Assert-Equal $probe (Get-ProbeValue -Output $result.Output -Key 'SELF') 'the spaced script path did not survive quoting'
        Assert-Equal 'WARNING' (Get-ProbeValue -Output $result.Output -Key 'LOGLEVEL')
        Assert-Equal '7' (Get-ProbeValue -Output $result.Output -Key 'BUDGET')
        Assert-Equal 'Global\WacTestProbe' (Get-ProbeValue -Output $result.Output -Key 'MUTEX')
        # One -File token has to re-split into two categories, spaces and all.
        Assert-Equal 'Windows Update cache|Temp' (Get-ProbeValue -Output $result.Output -Key 'CATEGORY')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
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
        Assert-True ($text.Contains('[ERROR] [Run] Administrator privileges are required')) $text
        Assert-False ($text.Contains('[Summary]')) 'the run reached the cleanup summary without being elevated'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
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
        foreach ($node in $script:RunAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            # Run.ps1 declares a few helpers of its own; those are not part of the module surface.
            if ($called.ContainsKey($node.Name)) { [void]$called.Remove($node.Name) }
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

# ---------------------------------------------------------------------------------------------
# The exit-code contract, end to end through the REAL Run.ps1
#
# Run.ps1 is COPIED byte for byte into a sandbox that also holds a src\ of shim modules, and the
# copy is the file the child executes. Each shim is the shipped module text with a few overrides
# appended, so New-WacTreeResult, New-WacStepResult, New-WacDriverStepResult, Write-WacTreeResult
# and Write-WacStepResult stay the SHIPPED code and only the functions that would touch the machine
# - the sweep, DISM, pnpclean, pnputil, cleanmgr, the Recycle Bin - return a scripted result
# instead. Nothing here deletes anything, runs a system tool or reads the real allow-list, which is
# what makes it safe to run on a developer workstation.
#
# Three environmental facts a sandboxed run cannot have are replaced in the Core shim and nothing
# else is: Test-WacIsAdministrator (the whole run body is behind the elevation gate),
# Test-WacSystemDriveSupported, and the ACL verdict for the sandbox state directory - a redirected
# %ProgramData% under TEMP is genuinely user-writable, so the real check answers "untrusted" there
# (measured) and every scenario would exit 7 for a reason unrelated to the case under test. The
# degraded log and the expired budget are NOT faked: the shim calls the real Set-WacLogDegraded and
# moves the real deadline, so the mapping reads exactly the module state a real one produces.
# ---------------------------------------------------------------------------------------------

$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# One plan file drives every shim. Read lazily and cached, so a scenario is one JSON write.
$script:PlanReaderBody = @'
$script:TestPlan = $null

function Get-WacTestPlan {
    if ($null -ne $script:TestPlan) { return $script:TestPlan }

    $table = @{
        stateEvaluated = $true
        stateTrusted = $true
        logDegraded = $false
        deadlineExpired = $false
        targets = @()
        dismOutcome = 'Succeeded'
        deliveryOutcome = 'SafeSkip'
        pnpOutcome = 'Succeeded'
        pruneOutcome = 'SafeSkip'
        stripStepOutcome = $false
    }

    $path = [string]$env:WAC_TEST_PLAN
    if ($path -and [System.IO.File]::Exists($path)) {
        $parsed = ConvertFrom-Json ([System.IO.File]::ReadAllText($path))
        foreach ($property in $parsed.PSObject.Properties) { $table[$property.Name] = $property.Value }
    }

    $script:TestPlan = $table
    return $script:TestPlan
}
'@

$script:ShimBody = @{}

$script:ShimBody['Core'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')
$script:RealInitializeWacRun = ${function:Initialize-WacRun}

function Test-WacIsAdministrator { return $true }
function Test-WacSystemDriveSupported { return $true }

function Test-WacStatePathIsTrusted {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path, [int]$MaxDepth = 64)

    $null = $MaxDepth
    return [PSCustomObject]@{
        Path = $Path
        IsTrusted = [bool](Get-WacTestPlan).stateTrusted
        Reason = 'test shim verdict'
        Checked = @(); Failures = @(); Writers = @()
    }
}

function Initialize-WacRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$BaseName,
        [string[]]$CandidateRoot,
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
        [int]$BudgetMinutes = 210,
        [string]$BootstrapLogPath
    )

    $ok = & $script:RealInitializeWacRun @PSBoundParameters
    if (-not $ok) { return $ok }

    $plan = Get-WacTestPlan
    # Real module state, not a faked return value: Get-WacLogHealth, Get-WacStateTrust and
    # Test-WacDeadlineExpired stay the shipped functions reading the shipped variables.
    if ($plan.logDegraded) { Set-WacLogDegraded -Reason 'test shim: a log write failed' }
    if ($plan.deadlineExpired) { $script:DeadlineUtc = (Get-Date).ToUniversalTime().AddMinutes(-1) }
    if (-not $plan.stateEvaluated) { $script:StateTrust = $null }

    return $ok
}
'@

$script:ShimBody['FileSystem'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')

function Get-WacTestTargetResult {
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Path)

    $stats = New-WacDeletionStats
    $attempted = $false

    foreach ($spec in @((Get-WacTestPlan).targets)) {
        if ([string]$spec.category -cne $Category) { continue }
        foreach ($property in $spec.PSObject.Properties) {
            if ($property.Name -ceq 'category' -or $property.Name -ceq 'path') { continue }
            if ($property.Name -ceq 'attempted') { $attempted = [bool]$property.Value; continue }
            $stats.($property.Name) = [int64]$property.Value
        }
    }

    return (New-WacTreeResult -Category $Category -Path $Path -Stats $stats -Attempted $attempted)
}

function Remove-WacTree {
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Path, [switch]$DeleteRoot)
    $null = $DeleteRoot
    return (Get-WacTestTargetResult -Category $Category -Path $Path)
}

function Remove-WacFilesByPattern {
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Path, [string[]]$Pattern = @())
    $null = $Pattern
    return (Get-WacTestTargetResult -Category $Category -Path $Path)
}
'@

$script:ShimBody['Targets'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')

function Get-WacCleanupTarget {
    param([string[]]$SkipCategory = @())

    $skip = @($SkipCategory)
    foreach ($spec in @((Get-WacTestPlan).targets)) {
        $category = [string]$spec.category
        if ($skip -contains $category) { continue }
        [PSCustomObject]@{ Category = $category; Path = [string]$spec.path; Mode = 'Tree'; Pattern = @(); DeleteRoot = $false }
    }
}
'@

$script:ShimBody['Steps'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')

function New-WacTestStepResult {
    <#
    .SYNOPSIS
        A step result in whichever shape New-WacStepResult currently offers.
    .DESCRIPTION
        No .Outcome is added here on purpose: this is the LEGACY shape, so these steps prove
        Get-WacStepOutcome's boolean fallback. The Drivers shim returns the Outcome-carrying shape.
    #>
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Outcome)

    $argument = @{ Category = $Category; Attempted = $true; Detail = ('test shim: ' + $Outcome) }
    if ((Get-Command -Name 'New-WacStepResult').Parameters.ContainsKey('Outcome')) {
        $argument['Outcome'] = $Outcome
    }
    else {
        $argument['Succeeded'] = ($Outcome -ceq 'Succeeded')
        $argument['Skipped'] = ($Outcome -ceq 'SafeSkip')
        $argument['Failed'] = ($Outcome -ceq 'Failed' -or $Outcome -ceq 'Incomplete' -or $Outcome -ceq 'SecurityRefusal')
    }

    return (Write-WacStepResult -Result (New-WacStepResult @argument) -Component 'TestStep')
}

function Invoke-WacComponentCleanup {
    param([switch]$ResetBase)
    $null = $ResetBase
    return (New-WacTestStepResult -Category 'Component store cleanup' -Outcome ([string](Get-WacTestPlan).dismOutcome))
}

function Clear-WacTestOutcomeFreeResult {
    <#
    .SYNOPSIS
        The same result with .Outcome removed - a step from before the outcome contract.
    #>
    param([Parameter(Mandatory = $true)]$Result)

    $copy = New-Object PSObject
    foreach ($property in $Result.PSObject.Properties) {
        if ($property.Name -ceq 'Outcome') { continue }
        Add-Member -InputObject $copy -MemberType NoteProperty -Name $property.Name -Value $property.Value
    }
    return $copy
}

function Clear-WacDeliveryOptimizationCache {
    $result = New-WacTestStepResult -Category 'Delivery Optimization cache' -Outcome ([string](Get-WacTestPlan).deliveryOutcome)
    if ((Get-WacTestPlan).stripStepOutcome) { return (Clear-WacTestOutcomeFreeResult -Result $result) }
    return $result
}

function Invoke-WacLegacyDiskCleanup {
    param([switch]$Enabled, [AllowEmptyCollection()][string[]]$Category = @(), [int]$SageId = 9999)
    $null = $Enabled; $null = $Category; $null = $SageId
    return (New-WacTestStepResult -Category 'Legacy Disk Cleanup' -Outcome 'SafeSkip')
}

function Clear-WacRecycleBin {
    return (New-WacTestStepResult -Category 'Recycle Bin' -Outcome 'Succeeded')
}
'@

$script:ShimBody['Drivers'] = @'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Plan.ps1')

function New-WacTestDriverStepResult {
    param([Parameter(Mandatory = $true)][string]$Category, [Parameter(Mandatory = $true)][string]$Outcome)

    # The SHIPPED bridge, so these results carry .Outcome exactly as the real driver steps do.
    return (Write-WacStepResult -Component 'TestStep' -Result (New-WacDriverStepResult `
        -Category $Category -Outcome $Outcome -Attempted $true -Detail ('test shim: ' + $Outcome)))
}

function Invoke-WacPnpCleanHandler {
    return (New-WacTestDriverStepResult -Category 'Driver package cleanup' -Outcome ([string](Get-WacTestPlan).pnpOutcome))
}

function Invoke-WacDriverPackagePrune {
    param([switch]$Enabled, [string]$BackupRoot)
    $null = $Enabled; $null = $BackupRoot
    return (New-WacTestDriverStepResult -Category 'Driver package prune' -Outcome ([string](Get-WacTestPlan).pruneOutcome))
}
'@

function New-RunRig {
    <#
    .SYNOPSIS
        A sandbox holding a byte-identical copy of Run.ps1 and a src\ of shim modules.
    #>
    param([Parameter(Mandatory = $true)][string]$Prefix)

    $sandbox = New-TestSandbox -Prefix $Prefix
    $app = Join-Path -Path $sandbox -ChildPath 'app'
    $src = Join-Path -Path $app -ChildPath 'src'
    [void][System.IO.Directory]::CreateDirectory($src)
    foreach ($leaf in @('PD', 'LA', 'TMP')) {
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $sandbox -ChildPath $leaf))
    }

    $runCopy = Join-Path -Path $app -ChildPath 'Run.ps1'
    [System.IO.File]::Copy($script:RunPath, $runCopy)
    if ((New-Object System.IO.FileInfo($runCopy)).Length -ne (New-Object System.IO.FileInfo($script:RunPath)).Length) {
        throw 'the copied Run.ps1 is not the shipped one'
    }

    [System.IO.File]::WriteAllText((Join-Path -Path $src -ChildPath '_Plan.ps1'), $script:PlanReaderBody, $script:Utf8NoBom)
    foreach ($name in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
        $leaf = 'WindowsAutoCleanup.{0}.psm1' -f $name
        $text = [System.IO.File]::ReadAllText((Join-Path -Path $script:SrcRoot -ChildPath $leaf))
        [System.IO.File]::WriteAllText((Join-Path -Path $src -ChildPath $leaf),
            ($text + [Environment]::NewLine + $script:ShimBody[$name]), $script:Utf8NoBom)
    }

    return [PSCustomObject]@{
        Sandbox      = $sandbox
        RunPath      = $runCopy
        Src          = $src
        PlanPath     = Join-Path -Path $sandbox -ChildPath 'plan.json'
        ProgramData  = Join-Path -Path $sandbox -ChildPath 'PD'
        LocalAppData = Join-Path -Path $sandbox -ChildPath 'LA'
        Temp         = Join-Path -Path $sandbox -ChildPath 'TMP'
        LogDirectory = Join-Path -Path $sandbox -ChildPath 'PD\WindowsAutoCleanup\Logs'
        # Local\, not Global\: creating a Global\ kernel object needs SeCreateGlobalPrivilege, which
        # a developer shell does not hold, so every run here would exit 3 instead of the code under
        # test. Unique per rig so concurrent suites never collide.
        MutexName    = 'Local\WacRig{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12)
    }
}

function Remove-RunRig {
    <#
    .SYNOPSIS
        Removes a rig sandbox, retrying briefly while a just-exited child still holds a handle.
    .DESCRIPTION
        Measured: a delete issued immediately after the last child exits occasionally leaves the
        sandbox behind - Windows has not released the exited process's handles yet - and
        Remove-TestSandbox untracks the path whether or not the delete worked, so the end-of-suite
        sweep never comes back to it. Bounded by a deadline rather than by a fixed wait, and it
        never throws: this runs from a finally block, where a throw would replace the real failure
        with a cleanup one.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    $deadline = (Get-Date).AddSeconds(10)
    while ($true) {
        Remove-TestSandbox -Path $Rig.Sandbox
        if (-not (Test-Path -LiteralPath $Rig.Sandbox)) { return }
        if ((Get-Date) -ge $deadline) { break }
        Start-Sleep -Milliseconds 200
    }

    Write-Host ('      note: the rig sandbox outlived its removal bound and is left behind: {0}' -f $Rig.Sandbox)
}

function New-PlanTarget {
    <#
    .SYNOPSIS
        One scripted target result. Every counter name is a real New-WacDeletionStats field.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [bool]$Attempted = $true,
        [int]$FilesDeleted = 0,
        [int]$SkippedReparse = 0,
        [int]$SkippedOutOfRoot = 0,
        [int]$SkippedProtected = 0,
        [int]$SkippedDeadline = 0,
        [int]$RefusedIdentity = 0,
        [int]$RefusedOutOfRoot = 0,
        [int]$Failed = 0
    )

    return @{
        category         = $Category
        path             = 'C:\WacTestTarget\{0}' -f $Category
        attempted        = $Attempted
        FilesDeleted     = $FilesDeleted
        SkippedReparse   = $SkippedReparse
        SkippedOutOfRoot = $SkippedOutOfRoot
        SkippedProtected = $SkippedProtected
        SkippedDeadline  = $SkippedDeadline
        RefusedIdentity  = $RefusedIdentity
        RefusedOutOfRoot = $RefusedOutOfRoot
        Failed           = $Failed
    }
}

function Invoke-RunRig {
    <#
    .SYNOPSIS
        Writes the plan and runs the copied Run.ps1 as a bounded child. Returns the probe result.
    #>
    param(
        [Parameter(Mandatory = $true)]$Rig,
        [Parameter(Mandatory = $true)][hashtable]$Plan,
        [int]$TimeoutMs = 90000
    )

    [System.IO.File]::WriteAllText($Rig.PlanPath, ($Plan | ConvertTo-Json -Depth 6), $script:Utf8NoBom)

    # No -ResetWindowsUpdateBase:$false here: under -File, Windows PowerShell 5.1 hands the child
    # the literal string '$false' and parameter binding fails before the body runs (measured). The
    # DISM step is scripted by the plan anyway, so the switch has nothing to change.
    #
    # -BudgetMinutes 5 rather than 1: nothing here does real work, but a budget the machine could
    # plausibly outlive would make "a benign run exits 0" flaky in exactly the direction that hides
    # a defect. The expired-budget case moves the deadline explicitly instead of racing it.
    return (Invoke-Probe -TimeoutMs $TimeoutMs -CommandLine (ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Rig.RunPath,
                '-Scheduled', '-BudgetMinutes', '5', '-MutexName', $Rig.MutexName)) -Environment @{
            ProgramData   = $Rig.ProgramData
            LOCALAPPDATA  = $Rig.LocalAppData
            TEMP          = $Rig.Temp
            TMP           = $Rig.Temp
            WAC_TEST_PLAN = $Rig.PlanPath
        })
}

function Get-RigLogText {
    <#
    .SYNOPSIS
        The text of the newest run log in the rig, or '' when the run wrote none.
    #>
    param([Parameter(Mandatory = $true)]$Rig)

    $logs = @(Get-ChildItem -LiteralPath $Rig.LogDirectory -Filter 'WindowsAutoCleanup_*.log' -File -ErrorAction SilentlyContinue |
            Sort-Object -Property LastWriteTimeUtc -Descending)
    if ($logs.Count -eq 0) { return '' }
    return [System.IO.File]::ReadAllText($logs[0].FullName)
}

function Assert-RigExit {
    <#
    .SYNOPSIS
        Asserts the child's exit code AND the status the footer recorded, with the log as evidence.
    #>
    param(
        [Parameter(Mandatory = $true)]$Rig,
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][string]$Status
    )

    $text = Get-RigLogText -Rig $Rig
    Assert-True $Result.Exited ('the run did not finish inside its bound. stderr: ' + $Result.ErrorText)
    Assert-Equal $ExitCode $Result.ExitCode ('stderr: {0}{1}log: {2}' -f $Result.ErrorText, [Environment]::NewLine, $text)
    Assert-True ($text -cmatch ('(^|\s)status={0}($|\s)' -f $Status)) `
    ('the footer did not record status={0}: {1}' -f $Status, $text)
    Assert-True ($text -cmatch ('(^|\s)exitCode={0}($|\s)' -f $ExitCode)) `
    ('the footer did not record exitCode={0}: {1}' -f $ExitCode, $text)
}

Test-Case 'A benign run exits 0, and the same state a second time still exits 0' {
    # The trap this case exists for: a previous wave left a directory behind on run 1 that made
    # every later run refuse, so run 2 exited 7 with nothing wrong. Both runs use the SAME sandbox
    # and the same redirected %ProgramData%, so run 2 sees everything run 1 left behind.
    #
    # The counters are the ones a real elevated run really scores (measured: skipReparse=3,
    # skipOutOfRoot=1). They are benign and must not move the exit code.
    $rig = New-RunRig -Prefix 'rig-benign'
    try {
        $plan = @{ targets = @(
                (New-PlanTarget -Category 'Temp' -FilesDeleted 12 -SkippedReparse 3 -SkippedOutOfRoot 1),
                (New-PlanTarget -Category 'Caches' -SkippedProtected 2))
        }

        $first = Invoke-RunRig -Rig $rig -Plan $plan
        Assert-RigExit -Rig $rig -Result $first -ExitCode 0 -Status 'Succeeded'

        $second = Invoke-RunRig -Rig $rig -Plan $plan
        Assert-RigExit -Rig $rig -Result $second -ExitCode 0 -Status 'Succeeded'

        $logs = @(Get-ChildItem -LiteralPath $rig.LogDirectory -Filter 'WindowsAutoCleanup_*.log' -File)
        Assert-Equal 2 $logs.Count 'the second run did not write its own log beside the first'

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text -cmatch '(^|\s)skipReparse=3($|\s)') ('the benign counters never reached the totals: ' + $text)
        Assert-False ($text.Contains('[CRITICAL]')) ('a benign run logged a CRITICAL line: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A refused target exits 7 and is the one line the log cannot lose' {
    # Attempted is false: the target was refused BEFORE any deletion, which is the shape that used
    # to produce no [Result] line at all - the one event driving exit 7, invisible in the audit log.
    $rig = New-RunRig -Prefix 'rig-refusal'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @(
                (New-PlanTarget -Category 'Refused' -Attempted $false -RefusedIdentity 1)) }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 7 -Status 'SecurityRefusal'

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text.Contains('[Result] Target complete.')) `
        ('a target refused before it was attempted produced no result line: ' + $text)
        Assert-True ($text -cmatch '(^|\s)refusedIdentity=1($|\s)') $text
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A refusal outranks a failure: both together still exit 7' {
    $rig = New-RunRig -Prefix 'rig-precedence'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{
            dismOutcome = 'Failed'
            targets     = @((New-PlanTarget -Category 'Refused' -Attempted $false -RefusedOutOfRoot 1))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 7 -Status 'SecurityRefusal'

        # Both events are in the totals, so the 7 is a precedence decision and not a lost failure.
        $text = Get-RigLogText -Rig $rig
        Assert-True ($text -cmatch '(^|\s)failed=1($|\s)') ('the failure was dropped rather than outranked: ' + $text)
        Assert-True ($text -cmatch '(^|\s)refusedOutOfRoot=1($|\s)') $text
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A step failure exits 2, and so does a target failure' {
    $rig = New-RunRig -Prefix 'rig-failed'
    try {
        $step = Invoke-RunRig -Rig $rig -Plan @{ dismOutcome = 'Failed'; targets = @() }
        Assert-RigExit -Rig $rig -Result $step -ExitCode 2 -Status 'Failed'

        $target = Invoke-RunRig -Rig $rig -Plan @{ targets = @((New-PlanTarget -Category 'Temp' -Failed 3)) }
        Assert-RigExit -Rig $rig -Result $target -ExitCode 2 -Status 'Failed'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'An expired budget exits 6 rather than reporting success' {
    # The defect in its literal shape: incomplete work used to exit 0.
    $rig = New-RunRig -Prefix 'rig-budget'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ deadlineExpired = $true; targets = @(
                (New-PlanTarget -Category 'Temp' -FilesDeleted 1))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'
        Assert-True ((Get-RigLogText -Rig $rig).Contains('The run budget expired')) 'the incomplete run never said why'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A target that ran out of deadline exits 6' {
    $rig = New-RunRig -Prefix 'rig-deadline'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @(
                (New-PlanTarget -Category 'Temp' -FilesDeleted 4 -SkippedDeadline 9))
        }

        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'An Incomplete step outcome exits 6, not 2' {
    # Only reachable by READING .Outcome. The derived booleans make an Incomplete step Failed too,
    # so a mapping that trusted them would exit 2 here and this case would be red.
    $rig = New-RunRig -Prefix 'rig-stepincomplete'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ pruneOutcome = 'Incomplete'; targets = @() }
        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text -cmatch '(^|\s)stepIncomplete=1($|\s)') `
        ('the totals reported the step as a plain failure: ' + $text)
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A SecurityRefusal step outcome exits 7' {
    $rig = New-RunRig -Prefix 'rig-steprefusal'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ pruneOutcome = 'SecurityRefusal'; targets = @() }
        Assert-RigExit -Rig $rig -Result $result -ExitCode 7 -Status 'SecurityRefusal'

        Assert-True ((Get-RigLogText -Rig $rig) -cmatch '(^|\s)stepRefused=1($|\s)') 'the refusing step is not in the totals'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'An audit log that is not durable exits 6' {
    # Set-WacLogDegraded is the real function and Get-WacLogHealth the real reader; only the event
    # that trips it is injected, because a real write failure needs a broken volume.
    $rig = New-RunRig -Prefix 'rig-durable'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ logDegraded = $true; targets = @() }
        Assert-RigExit -Rig $rig -Result $result -ExitCode 6 -Status 'Incomplete'

        Assert-True ((Get-RigLogText -Rig $rig).Contains('durable audit log')) 'the incomplete run never said why'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'An untrusted state directory exits 7, and a verdict never reached does not' {
    $rig = New-RunRig -Prefix 'rig-trust'
    try {
        $untrusted = Invoke-RunRig -Rig $rig -Plan @{ stateTrusted = $false; targets = @() }
        Assert-RigExit -Rig $rig -Result $untrusted -ExitCode 7 -Status 'SecurityRefusal'
        Assert-True ((Get-RigLogText -Rig $rig).Contains('not machine-trusted')) 'the refusal was not explained'

        # $null is NOT EVALUATED - the shape an unelevated run produces, whose log lives in the
        # user's own profile. It carries no claim to refuse, so it must refuse nothing.
        $notEvaluated = Invoke-RunRig -Rig $rig -Plan @{ stateEvaluated = $false; targets = @() }
        Assert-RigExit -Rig $rig -Result $notEvaluated -ExitCode 0 -Status 'Succeeded'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A step result that states no outcome is never read as a success' {
    # Every shipped step returns .Outcome now. One that does not is a step this mapping cannot
    # classify, and the only safe reading of an unclassifiable step is that it did not succeed -
    # the alternative is a silent 0 for work whose result nobody could interpret.
    $rig = New-RunRig -Prefix 'rig-nooutcome'
    try {
        $result = Invoke-RunRig -Rig $rig -Plan @{ stripStepOutcome = $true; targets = @() }
        Assert-RigExit -Rig $rig -Result $result -ExitCode 2 -Status 'Failed'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'A module that cannot be imported is bootstrap-logged, folded into the run log and exits 1' {
    $rig = New-RunRig -Prefix 'rig-bootstrap'
    try {
        # A module that throws at import. Nothing inside a module can log that, which is the whole
        # reason the bootstrap log exists.
        [System.IO.File]::AppendAllText((Join-Path -Path $rig.Src -ChildPath 'WindowsAutoCleanup.Drivers.psm1'),
            ([Environment]::NewLine + "throw 'test shim: this module refuses to import'" + [Environment]::NewLine),
            $script:Utf8NoBom)

        $result = Invoke-RunRig -Rig $rig -Plan @{ targets = @() }

        Assert-True $result.Exited ('the run did not finish inside its bound. stderr: ' + $result.ErrorText)
        Assert-Equal 1 $result.ExitCode ('stderr: ' + $result.ErrorText)

        $text = Get-RigLogText -Rig $rig
        Assert-True ($text.Contains('[Bootstrap]')) ('the import failure never reached the durable run log: ' + $text)
        Assert-True ($text.Contains('WindowsAutoCleanup.Drivers.psm1')) $text
        Assert-True ($text.Contains('A required module could not be loaded')) $text
        Assert-False ($text.Contains('[Summary]')) 'the run cleaned with a module missing'

        # Adopted, so the bootstrap file is gone and the run leaves ONE audit artifact.
        $leftover = @(Get-ChildItem -LiteralPath $rig.Temp -Filter 'WindowsAutoCleanup-bootstrap-*.log' -File -ErrorAction SilentlyContinue)
        Assert-Equal 0 $leftover.Count 'the bootstrap log survived a run whose log adopted it'
    }
    finally {
        Remove-RunRig -Rig $rig
    }
}

Test-Case 'The elevated harness finds a driver backup by its manifest, not by the recycled oem name' {
    # Ledger item: backup directories became CONTENT-ADDRESSED (<stem>_<version>_<hash16>) because
    # oem<n>.inf is a name Windows re-issues to an unrelated package after a removal. The harness
    # still looked for Join-Path <backupRoot> <oem name>, a path that can now never exist, so it
    # would have raised its own BLOCKER for every package it really did remove.
    #
    # Invoke-ElevatedVerification.ps1 is not a suite - it refuses to run unelevated and the machine
    # scenarios change the machine - so the reader is LIFTED out of it and exercised against a
    # synthetic backup root. Same idiom as the relaunch vector above: the shipped function runs,
    # not a copy of it.
    $harnessPath = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-ElevatedVerification.ps1'
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
