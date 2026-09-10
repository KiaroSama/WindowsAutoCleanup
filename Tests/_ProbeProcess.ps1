<#
.SYNOPSIS
    Starting a child process for a test and waiting for it under a bound, in ONE implementation.

.DESCRIPTION
    Dot-sourced by _RunProbe.ps1 and _ProcessFixtures.ps1, which are in turn dot-sourced by the run
    suites and the process suites. It is not a suite: its name does not match Tests\*.Tests.ps1, so
    the runner never executes it on its own.

    This file exists because these two functions used to be defined TWICE, once in each of those
    fixtures, with incompatible parameter sets - one took -CommandLine, the other -ScriptPath - and
    near-identical 40-line Wait-ProbeProcess bodies that differed only in how they killed a stuck
    child. No suite loaded both, so the collision never fired, but the names bind by load order: the
    first suite that needed helpers from both files would have got a binding error or, worse, the
    wrong function. The two return shapes and timeouts were measured identical before merging.

    The kill path prefers the shipped Stop-WacProcessTree and falls back to taskkill when it is not
    loaded. That order matters: ProcessTree.Tests.ps1 is the suite that TESTS Stop-WacProcessTree,
    and it uses Start-ProbeProcess but never Wait-ProbeProcess, so no suite's cleanup depends on the
    function it is asserting about. The fallback keeps that true even if it ever does.
#>

# The host running this suite, taken from the live process rather than PATH, so the child is the
# same edition that is currently under test.
$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

function Start-ProbeProcess {
    <#
    .SYNOPSIS
        Starts a child of the host running this suite, by pre-quoted command line or by script path.
    .DESCRIPTION
        -ScriptPath composes the command line itself and takes its values through the environment,
        so a quoting defect in the code under test cannot corrupt the probe's own inputs.
    #>
    [CmdletBinding(DefaultParameterSetName = 'CommandLine')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'CommandLine')][string]$CommandLine,
        [Parameter(Mandatory = $true, ParameterSetName = 'ScriptPath')][string]$ScriptPath,
        [hashtable]$Environment = @{},
        [string]$HostExe
    )

    if (-not $HostExe) { $HostExe = $script:HostExe }

    if ($PSCmdlet.ParameterSetName -eq 'ScriptPath') {
        $CommandLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $HostExe
    $psi.Arguments = $CommandLine
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # Only the run suites set a repository working directory; the process suites do not care.
    if ($script:RepoRoot) { $psi.WorkingDirectory = $script:RepoRoot }
    foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }

    return [System.Diagnostics.Process]::Start($psi)
}

function Stop-ProbeProcessTree {
    <#
    .SYNOPSIS
        Kills a stuck probe and everything it started. Prefers the shipped function; falls back to
        taskkill so no suite's cleanup can depend on the function that suite is asserting about.
    #>
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    if (Get-Command -Name 'Stop-WacProcessTree' -ErrorAction SilentlyContinue) {
        [void](Stop-WacProcessTree -ProcessId $ProcessId)
        return
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe')
    $psi.Arguments = '/T /F /PID {0}' -f $ProcessId
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $killer = [System.Diagnostics.Process]::Start($psi)
    if ($killer) {
        [void]$killer.StandardOutput.ReadToEndAsync()
        [void]$killer.StandardError.ReadToEndAsync()
        [void]$killer.WaitForExit(10000)
        try { $killer.Dispose() } catch { $null = $_ }
    }
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

    try {
        $outTask = $Process.StandardOutput.ReadToEndAsync()
        $errTask = $Process.StandardError.ReadToEndAsync()
        $exited = $Process.WaitForExit($TimeoutMs)

        if (-not $exited) {
            Stop-ProbeProcessTree -ProcessId $Process.Id
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
    finally {
        if (-not $Process.HasExited) {
            Stop-ProbeProcessTree -ProcessId $Process.Id
            if (-not $Process.WaitForExit(10000)) { throw 'The probe survived its cleanup deadline.' }
        }
    }
}
