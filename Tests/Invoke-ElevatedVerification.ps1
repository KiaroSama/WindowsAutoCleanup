#Requires -Version 5.1

<#
.SYNOPSIS
    Elevated end-to-end verification of the three Run.ps1 exit codes no unit suite can reach -
    5 (the online system drive is not C:), 3 (another run holds the machine-wide lock) and
    2 (the run completed with at least one real deletion failure) - plus the two opt-in steps whose
    promises only a real, elevated, machine-changing run can test.

.DESCRIPTION
    This is NOT a Tests\*.Tests.ps1 suite and is deliberately named so Run-Tests.ps1 and the CI
    "every discovered suite ran" guard - both of which glob Tests\*.Tests.ps1 - never pick it up.
    It has to be started by hand, once, from an ELEVATED session, because all three exit codes sit
    behind Run.ps1's elevation gate.

    There are two classes of scenario and the summary keeps them apart.

    SANDBOXED - EXIT5, EXIT3, EXIT2. Each runs the REAL Run.ps1 as a bounded child process whose
    %ProgramData%, %LOCALAPPDATA%, %TEMP% and %TMP% are redirected into a disposable sandbox under
    %ProgramData%\WindowsAutoCleanup\Verification\Sandbox - NOT under %TEMP%, because an elevated
    child refuses a state directory that is not machine-trusted and a per-user temp directory is
    not one. The harness proves that root is trusted before it starts anything. So the
    run log, the machine state directory and every cleanup target derived from those roots land
    inside the sandbox instead of on the operator's machine. Every allow-list category except the
    single sandbox-confined one the scenario needs is disabled with -SkipCategory, the Recycle Bin
    with -SkipRecycleBin, and both destructive opt-ins are off.

    MACHINE-CHANGING - DRIVERS, CLEANMGR. These exist to test the two opt-in steps, so by definition
    they change the machine: DRIVERS exports and then deletes superseded oem<n>.inf driver packages,
    and CLEANMGR runs cleanmgr /sagerun, which enumerates EVERY drive in the computer. They run only
    when asked for by name or through -Scenario All; -Scenario Sandboxed runs the first three alone.
    They still redirect the same roots, still disable EVERY allow-list category, and still skip the
    Recycle Bin, so the only machine state either one may change is the state its own step owns.

    /ResetBase is excluded from EVERY scenario - it makes each installed update permanently
    un-installable. Every child is launched with -ResetWindowsUpdateBase:$false, and DRIVERS and
    CLEANMGR both assert from the child's own log that it really was off.

    WHAT THIS HARNESS STILL RUNS FOR REAL, and why it cannot be avoided: Steps' Get-WacSystemToolPath
    resolves dism.exe, rundll32.exe and cleanmgr.exe under %SystemRoot%, so the only way to make
    those steps report "not found" would be to redirect %SystemRoot%. That is not survivable:
    measured on this project's two hosts, Windows PowerShell 5.1 refuses to start at all with a
    redirected SystemRoot ("Internal Windows PowerShell error. Loading managed Windows PowerShell
    failed with error 8009001d") and PowerShell 7 starts but loses CIM. So the EXIT2 scenario, and
    the first run of the EXIT3 scenario, do perform the real DISM component-store cleanup (WITHOUT
    /ResetBase), the real pnpclean driver-package handler and the real Delivery Optimization cache
    purge. All three are supported, non-destructive maintenance operations, and the harness never
    kills them: the -BudgetMinutes budget handed to every child is DERIVED from -TimeoutSeconds so
    that it always expires first, which means a slow tool is terminated by Run.ps1's own production
    watchdog and never from outside. That ordering used to live in this comment only - any
    -TimeoutSeconds below the fixed 20-minute budget was accepted and silently inverted it.

.PARAMETER Scenario
    EXIT5, EXIT3, EXIT2, DRIVERS, CLEANMGR, Sandboxed (the three sandboxed exit-code scenarios only)
    or All (the default: all five).

.PARAMETER ResultPath
    Machine-readable JSON result file. Defaults to a timestamped file under
    %ProgramData%\WindowsAutoCleanup\Verification.

.PARAMETER TimeoutSeconds
    Wall-clock ceiling for one child process. The child's -BudgetMinutes budget is DERIVED from it
    as floor((TimeoutSeconds - 300) / 60) minutes, so "the child's own watchdog fires first" is a
    property of the arithmetic instead of a promise in a comment. The 300-second margin is what the
    child then has left to write its footer and close its log. A value too small to leave a whole
    minute of budget - anything under 360 - is REFUSED before any child starts rather than silently
    inverting the ordering, which is what the old fixed 20-minute budget did for anything under 1200.

.EXAMPLE
    .\Tests\Invoke-ElevatedVerification.ps1

.EXAMPLE
    .\Tests\Invoke-ElevatedVerification.ps1 -Scenario EXIT2

.NOTES
    Harness exit codes:
      0  every selected scenario passed
      1  at least one selected scenario failed
      2  the harness refused to run: not elevated, or a precondition was not met
#>

[CmdletBinding()]
param(
    [ValidateSet('EXIT5', 'EXIT3', 'EXIT2', 'DRIVERS', 'CLEANMGR', 'Sandboxed', 'All')][string]$Scenario = 'All',
    [string]$ResultPath,
    [ValidateRange(60, 7200)][int]$TimeoutSeconds = 1800
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# The budget handed to every child is DERIVED from the wall timeout rather than configured beside
# it. The harness's one safety promise is that a slow DISM is stopped by Run.ps1's own watchdog and
# never by an outside kill, and that promise holds only while the child's budget expires first.
# It used to be a fixed 20 minutes against a timeout accepted as low as 60 seconds, with nothing
# comparing the two, so any -TimeoutSeconds under 1200 inverted the ordering silently and the
# harness would have taskkilled a running DISM. Deriving the budget makes the ordering a property
# of the arithmetic; the 300-second margin is the child's own shutdown, footer and log flush. The
# comparison below enforces what the arithmetic alone cannot - a timeout too small to leave a whole
# minute of budget - and it refuses before any child is started.
$script:ChildBudgetMinutes = [int][Math]::Floor(($TimeoutSeconds - 300) / 60)
if ($script:ChildBudgetMinutes -lt 1 -or ($script:ChildBudgetMinutes * 60) -ge $TimeoutSeconds) {
    Write-Host ('REFUSED: -TimeoutSeconds {0} leaves a child budget of {1} minute(s), which cannot expire before the harness would kill the child. Pass at least 360.' -f `
        $TimeoutSeconds, $script:ChildBudgetMinutes)
    exit 2
}

# The sage profile Invoke-WacLegacyDiskCleanup defaults to, and the deadline for the harness's own
# pnputil snapshots. Both belong to the harness, not to the child: the child gets -BudgetMinutes.
$script:VerificationSageId = 9999
$script:PnpUtilProbeMs = 120000

foreach ($moduleName in @('Core', 'Targets')) {
    $modulePath = Join-Path -Path $script:SrcRoot -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $moduleName)
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        Write-Host ('REFUSED: a required module is missing: {0}' -f $modulePath)
        exit 2
    }
    Import-Module -Name $modulePath -Force -DisableNameChecking -ErrorAction Stop
}

# ------------------------------------------------------------------------------------------------
# Directory lock - the mechanism that manufactures a real Failed
# ------------------------------------------------------------------------------------------------

function Initialize-VerificationLock {
    <#
    .SYNOPSIS
        Compiles the CreateFileW wrapper used to hold a directory open with no sharing.
    #>
    if ('WacVerificationLock' -as [type]) { return $true }

    try {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class WacVerificationLock
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    private const uint FILE_LIST_DIRECTORY        = 0x00000001;
    private const uint SHARE_NOTHING              = 0x00000000;
    private const uint OPEN_EXISTING              = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    // Holds a DIRECTORY open with dwShareMode = 0. Every later attempt to LIST that directory -
    // including FindFirstFileEx, which is what DirectoryInfo.EnumerateFileSystemInfos uses - then
    // fails with ERROR_SHARING_VIOLATION, and .NET surfaces that as IOException.
    public static SafeFileHandle Open(string path)
    {
        SafeFileHandle handle = CreateFileW(path, FILE_LIST_DIRECTORY, SHARE_NOTHING, IntPtr.Zero,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);

        if (handle.IsInvalid)
        {
            throw new InvalidOperationException(
                "CreateFileW failed for " + path + " with error " + Marshal.GetLastWin32Error());
        }

        return handle;
    }
}
'@
        return $true
    }
    catch {
        Write-Host ('REFUSED: the directory-lock helper could not be compiled: {0}' -f $_.Exception.Message)
        return $false
    }
}

# ------------------------------------------------------------------------------------------------
# Sandbox
# ------------------------------------------------------------------------------------------------

function New-VerificationSandbox {
    <#
    .SYNOPSIS
        A disposable sandbox holding the redirected ProgramData, LOCALAPPDATA and TEMP roots.
    #>
    param([Parameter(Mandatory = $true)][string]$Prefix)

    $name = '{0}_{1}' -f $Prefix, [guid]::NewGuid().ToString('N').Substring(0, 12)
    $path = [System.IO.Path]::GetFullPath((Join-Path -Path $script:SandboxRoot -ChildPath $name))
    foreach ($leaf in @('PD', 'LA', 'TMP')) {
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $path -ChildPath $leaf))
    }
    return $path
}

function Remove-VerificationSandbox {
    <#
    .SYNOPSIS
        Bounded best-effort sandbox delete. A leftover sandbox is reported, never ignored.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }

    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        if (-not (Test-Path -LiteralPath $Path)) { return $true }
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return $true
        }
        catch {
            Start-Sleep -Milliseconds 200
        }
    }

    return (-not (Test-Path -LiteralPath $Path))
}

function Get-SandboxEnvironment {
    <#
    .SYNOPSIS
        The child environment block that pins every redirectable root inside the sandbox.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [hashtable]$Extra = @{}
    )

    $table = @{
        ProgramData  = (Join-Path -Path $Sandbox -ChildPath 'PD')
        LOCALAPPDATA = (Join-Path -Path $Sandbox -ChildPath 'LA')
        TEMP         = (Join-Path -Path $Sandbox -ChildPath 'TMP')
        TMP          = (Join-Path -Path $Sandbox -ChildPath 'TMP')
    }
    foreach ($key in $Extra.Keys) { $table[$key] = [string]$Extra[$key] }
    return $table
}

function Get-SandboxTargetPath {
    <#
    .SYNOPSIS
        The one allow-list directory this harness aims Run.ps1 at.
    .DESCRIPTION
        'Defender cleanup files' is the only category whose every entry is built purely from
        %ProgramData% (Targets.psm1), so redirecting ProgramData moves the whole category into the
        sandbox and leaves nothing of it pointing at the real machine.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    return (Join-Path -Path $Sandbox -ChildPath 'PD\Microsoft\Windows Defender\LocalCopy')
}

function New-SandboxBait {
    <#
    .SYNOPSIS
        Creates the sandbox allow-list directory with one bait file, and returns the directory.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $target = Get-SandboxTargetPath -Sandbox $Sandbox
    [void][System.IO.Directory]::CreateDirectory($target)
    [System.IO.File]::WriteAllText((Join-Path -Path $target -ChildPath 'bait.txt'), 'bait', $script:Utf8NoBom)
    return $target
}

function Get-SandboxLogText {
    <#
    .SYNOPSIS
        The concatenated text of every run log the child wrote inside its sandbox.
    .DESCRIPTION
        FileShare ReadWrite|Delete is load-bearing: the EXIT3 scenario reads the FIRST child's log
        while that child still holds the StreamWriter open, and a plain ReadAllText would fail with
        "the process cannot access the file".

        A file that still cannot be read after the bounded retry THROWS rather than being skipped.
        Every "the log must NOT contain X" assertion in this harness is only meaningful over a log
        that was actually read: swallowing the read failure and returning whatever else was
        available let an unreadable log satisfy those assertions and turned a defect into a PASS.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $directory = Join-Path -Path $Sandbox -ChildPath 'PD\WindowsAutoCleanup\Logs'
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { return '' }

    $files = @(Get-ChildItem -LiteralPath $directory -Filter 'WindowsAutoCleanup_*.log' -File -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) { return '' }

    $chunks = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in $files) {
        $content = $null
        $lastError = 'no error was captured'

        for ($attempt = 0; $attempt -lt 3; $attempt++) {
            try {
                $stream = New-Object System.IO.FileStream(
                    $file.FullName,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
                try {
                    $reader = New-Object System.IO.StreamReader($stream)
                    try { $content = [string]$reader.ReadToEnd() }
                    finally { $reader.Dispose() }
                }
                finally {
                    $stream.Dispose()
                }
            }
            catch {
                $lastError = $_.Exception.Message
            }

            if ($null -ne $content) { break }
            Start-Sleep -Milliseconds 200
        }

        if ($null -eq $content) {
            throw ('the run log {0} could not be read ({1}); no assertion over the log text can be trusted' -f $file.FullName, $lastError)
        }
        [void]$chunks.Add($content)
    }

    return (($chunks.ToArray()) -join "`r`n")
}

function Get-MatchingLine {
    <#
    .SYNOPSIS
        Every log line containing the needle, trimmed. The harness's only evidence primitive.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Needle
    )

    if ([string]::IsNullOrEmpty($Text)) { return @() }

    $found = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in @($Text -split "`r?`n")) {
        if ($line.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            [void]$found.Add($line.Trim())
        }
    }
    return @($found.ToArray())
}

# Every documented Run.ps1 exit code, so a mismatch names what the child actually reported rather
# than leaving a bare number to be looked up. 6 and 7 were added with the outcome contract: a
# scenario that suddenly reports one of them is usually the harness's own environment - an
# untrusted sandbox root or a budget that expired - and not the behaviour it was checking.
$script:RunExitCodeName = @{
    0 = 'success'
    1 = 'error, missing privileges, or an unhandled failure'
    2 = 'completed with at least one failure'
    3 = 'another run holds the machine-wide lock'
    4 = 'elevation was cancelled or failed'
    5 = 'unsupported system drive'
    6 = 'incomplete - the budget expired, a deadline was hit, or no durable audit log was produced'
    7 = 'security refusal - a safety check refused to proceed on evidence'
}

function Get-RunExitDetail {
    <#
    .SYNOPSIS
        An exit code with the meaning Run.ps1 documents for it.
    #>
    param([Parameter(Mandatory = $true)][int]$ExitCode)

    if ($script:RunExitCodeName.ContainsKey($ExitCode)) {
        return ('{0} [{1}]' -f $ExitCode, $script:RunExitCodeName[$ExitCode])
    }
    return ('{0} [not a documented Run.ps1 exit code]' -f $ExitCode)
}

function Test-KeyValue {
    <#
    .SYNOPSIS
        $true only when the log line carries key=value as a WHOLE token.
    .DESCRIPTION
        Write-WacLog renders its data as sorted key=value pairs joined by single spaces, and quotes
        any value containing whitespace. A substring test for 'failed=1' therefore also matches
        failed=10, failed=11 and failed=100 - it only disambiguates totals of 2..9, which is not
        what the EXIT2 design rests on. Anchoring on whitespace or a line end makes it exact.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line,
        [Parameter(Mandatory = $true)][string]$Pair
    )

    return ($Line -cmatch ('(^|\s){0}($|\s)' -f [regex]::Escape($Pair)))
}

# ------------------------------------------------------------------------------------------------
# Child processes
# ------------------------------------------------------------------------------------------------

function New-VerificationMutexName {
    <#
    .SYNOPSIS
        A run-unique machine-wide mutex name.
    .DESCRIPTION
        The production name is deliberately NOT reused: a verification run must never block, or be
        blocked by, the machine's real scheduled task.
    #>
    return ('Global\WacVerify{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12))
}

function Get-NonSandboxCategory {
    <#
    .SYNOPSIS
        Every allow-list category except the one kept, taken from the LIVE allow-list.
    .DESCRIPTION
        Enumerated rather than hard-coded so a category added to Targets.psm1 later is disabled by
        default instead of being cleaned for real the next time this harness runs.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Keep)

    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($target in (Get-WacCleanupTarget)) {
        if ($target.Category -ieq $Keep) { continue }
        if ($names.Contains($target.Category)) { continue }
        [void]$names.Add($target.Category)
    }
    return @($names.ToArray())
}

function Get-RunChildCommandLine {
    <#
    .SYNOPSIS
        The pre-quoted command line for one Run.ps1 child.
    .DESCRIPTION
        Built through the shipped Get-WacRelaunchArgument, so the child is launched exactly the way
        Run.ps1 launches its own elevated relaunch: -Command rather than -File, because -File cannot
        carry '-Switch:$false' on Windows PowerShell 5.1 and collapses an array into one string.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$MutexName,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$SkipCategory,
        [switch]$PruneSupersededDrivers,
        [switch]$EnableLegacyDiskCleanup
    )

    $booleanSwitch = @{
        # NEVER derived from a parameter. /ResetBase makes every installed update permanently
        # un-installable and is excluded from this harness outright, so every child - sandboxed or
        # machine-changing - is launched with it explicitly off.
        ResetWindowsUpdateBase  = $false
        PruneSupersededDrivers  = [bool]$PruneSupersededDrivers
        EnableLegacyDiskCleanup = [bool]$EnableLegacyDiskCleanup
        SkipRecycleBin          = $true
    }
    $namedValue = @{
        LogLevel      = 'DEBUG'
        BudgetMinutes = [string]$script:ChildBudgetMinutes
        MutexName     = $MutexName
    }

    $vector = Get-WacRelaunchArgument -ScriptPath $script:RunPath -HostSwitch @('-NonInteractive') `
        -BooleanSwitch $booleanSwitch -PresentSwitch @('Scheduled') -NamedValue $namedValue `
        -ArrayValue @{ SkipCategory = $SkipCategory }

    return (ConvertTo-WacCommandLine -ArgumentList $vector)
}

function Start-VerificationChild {
    <#
    .SYNOPSIS
        Starts one Run.ps1 child and immediately begins draining both of its pipes.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][hashtable]$Environment
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:HostExe
    $psi.Arguments = $CommandLine
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $script:RepoRoot
    foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }

    $process = [System.Diagnostics.Process]::Start($psi)

    return [PSCustomObject]@{
        Process = $process
        OutTask = $process.StandardOutput.ReadToEndAsync()
        ErrTask = $process.StandardError.ReadToEndAsync()
        Started = [datetime]::UtcNow
    }
}

function Wait-VerificationChild {
    <#
    .SYNOPSIS
        Bounded wait plus process-tree kill. "Did not finish inside the bound" is a DETECTED signal,
        never a stalled harness, and never success.
    #>
    param(
        [Parameter(Mandatory = $true)]$Child,
        [Parameter(Mandatory = $true)][int]$TimeoutMs
    )

    $exited = $Child.Process.WaitForExit($TimeoutMs)
    if (-not $exited) {
        [void](Stop-WacProcessTree -ProcessId $Child.Process.Id)
        [void]$Child.Process.WaitForExit(15000)
    }

    [void]$Child.OutTask.Wait(5000)
    [void]$Child.ErrTask.Wait(5000)

    $code = -1
    if ($exited) {
        try { $code = [int]$Child.Process.ExitCode } catch { $code = -1 }
    }

    return [PSCustomObject]@{
        Exited     = $exited
        ExitCode   = $code
        Output     = $(if ($Child.OutTask.IsCompleted) { [string]$Child.OutTask.Result } else { '' })
        ErrorText  = $(if ($Child.ErrTask.IsCompleted) { [string]$Child.ErrTask.Result } else { '' })
        DurationMs = [int]([datetime]::UtcNow - $Child.Started).TotalMilliseconds
    }
}

function Stop-VerificationChild {
    <#
    .SYNOPSIS
        Terminates a child that is still alive and always releases its handles.
    #>
    param([AllowNull()]$Child)

    if (-not $Child) { return }

    try {
        if (-not $Child.Process.HasExited) {
            [void](Stop-WacProcessTree -ProcessId $Child.Process.Id)
            [void]$Child.Process.WaitForExit(15000)
        }
    }
    catch {
        $null = $_
    }

    try { $Child.Process.Dispose() } catch { $null = $_ }
}

function Wait-ForSignal {
    <#
    .SYNOPSIS
        Polls a deterministic condition until a deadline. Never a blind sleep: the loop exits the
        moment the condition holds, and reports failure the moment the deadline passes.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [Parameter(Mandatory = $true)][int]$TimeoutMs
    )

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $signalled = $false
        try { $signalled = [bool](& $Condition) } catch { $signalled = $false }
        if ($signalled) { return $true }
        if ($watch.Elapsed.TotalMilliseconds -ge $TimeoutMs) { return $false }
        Start-Sleep -Milliseconds 200
    }
}

# ------------------------------------------------------------------------------------------------
# Scenario record
# ------------------------------------------------------------------------------------------------

function New-ScenarioRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][int]$ExpectedExitCode,
        [Parameter(Mandatory = $true)][int]$ActualExitCode,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Evidence,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Problem,
        [Parameter(Mandatory = $true)][int]$DurationMs,
        # DRIVERS and CLEANMGR change the operator's real machine. The flag rides on the record so
        # the console summary and the JSON result both say which rows did, rather than relying on
        # the reader remembering which names are sandboxed.
        [switch]$Machine
    )

    return [PSCustomObject]@{
        Name             = $Name
        Machine          = [bool]$Machine
        Expected         = $Expected
        ExpectedExitCode = $ExpectedExitCode
        ActualExitCode   = $ActualExitCode
        Evidence         = @($Evidence)
        Problem          = @($Problem)
        DurationMs       = $DurationMs
        Passed           = (@($Problem).Count -eq 0)
    }
}

function Add-ResetBaseEvidence {
    <#
    .SYNOPSIS
        Proves from the child's own log that /ResetBase really was excluded.
    .DESCRIPTION
        The operator excluded /ResetBase, so a machine-changing scenario has to show it was off
        rather than assume the switch survived the command line. Two independent facts: the child
        echoed resetWindowsUpdateBase=False in its configuration line, and DISM never wrote the
        warning it only emits when the switch IS on.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Evidence,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Problem,
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text
    )

    $configLines = @(Get-MatchingLine -Text $Text -Needle '[Run] Configuration.')
    if ($configLines.Count -eq 0) {
        [void]$Problem.Add('the log carries no [Run] Configuration. line, so the ResetBase exclusion is unproven')
    }
    elseif (-not (Test-KeyValue -Line $configLines[0] -Pair 'resetWindowsUpdateBase=False')) {
        [void]$Problem.Add(('the child did not record resetWindowsUpdateBase=False: {0}' -f $configLines[0]))
    }
    else {
        [void]$Evidence.Add($configLines[0])
    }

    if (@(Get-MatchingLine -Text $Text -Needle 'ResetBase is enabled').Count -gt 0) {
        [void]$Problem.Add('DISM logged its ResetBase warning, so /ResetBase reached the command line after all')
    }
}

function Add-LogEvidence {
    <#
    .SYNOPSIS
        Records the first line matching a needle as evidence, or records its absence as a problem.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Evidence,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Problem,
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Needle
    )

    $lines = @(Get-MatchingLine -Text $Text -Needle $Needle)
    if ($lines.Count -eq 0) {
        [void]$Problem.Add(('the log never contained: {0}' -f $Needle))
        return $false
    }

    [void]$Evidence.Add($lines[0])
    return $true
}

# ------------------------------------------------------------------------------------------------
# Scenario EXIT5 - the online system drive is not C:
# ------------------------------------------------------------------------------------------------

function Invoke-Exit5Scenario {
    <#
    .SYNOPSIS
        An elevated child whose %SystemDrive% is not C: must exit 5 and delete nothing.
    .DESCRIPTION
        Test-WacSystemDriveSupported compares Get-WacNormalizedPath of $env:SystemDrive against C:,
        and Run.ps1 runs that check AFTER the elevation gate and BEFORE the mutex, so the child has
        to be elevated for the branch to be reachable at all. SystemDrive is the one root that can
        be redirected without breaking the host: measured, both shipped hosts start normally with
        SystemDrive=Z: while neither survives a redirected SystemRoot.

        'Defender cleanup files' is the ONE category deliberately left enabled, and that is what
        makes the bait assertion mean anything. Every entry of that category is built purely from
        %ProgramData% (Targets.psm1), which this harness has already redirected into the sandbox, so
        keeping it on cannot reach the operator's machine - but a child that failed to see the
        redirected SystemDrive, ran past the exit-5 gate and swept its targets WOULD delete the
        bait. Skipping every category, as this scenario used to, made the check unfalsifiable: no
        cleanup target covering the bait directory could ever be constructed, so the file survived
        whether or not the redirect took effect. Every other category stays disabled, which is what
        keeps a run that got past the gate confined to the sandbox.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null

    try {
        $skip = @(Get-NonSandboxCategory -Keep 'Defender cleanup files')
        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        else {
            $sandbox = New-VerificationSandbox -Prefix 'wac-exit5'
            $baitFile = Join-Path -Path (New-SandboxBait -Sandbox $sandbox) -ChildPath 'bait.txt'

            $commandLine = Get-RunChildCommandLine -MutexName (New-VerificationMutexName) -SkipCategory $skip
            $table = Get-SandboxEnvironment -Sandbox $sandbox -Extra @{ SystemDrive = 'Z:' }

            $child = Start-VerificationChild -CommandLine $commandLine -Environment $table
            $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
            $exitCode = $result.ExitCode

            if (-not $result.Exited) {
                [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
            }
            if ($result.ExitCode -ne 5) {
                [void]$problem.Add(('expected exit 5, got {0}. stderr: {1}' -f (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
            }

            $text = Get-SandboxLogText -Sandbox $sandbox
            [void](Add-LogEvidence -Evidence $evidence -Problem $problem -Text $text `
                -Needle '[CRITICAL] [Run] The online system drive is not C:')

            foreach ($forbidden in @('[Result] Target complete.', '[Summary]')) {
                if (@(Get-MatchingLine -Text $text -Needle $forbidden).Count -gt 0) {
                    [void]$problem.Add(('the run reached "{0}" even though the system drive is unsupported' -f $forbidden))
                }
            }

            if (-not (Test-Path -LiteralPath $baitFile -PathType Leaf)) {
                [void]$problem.Add('the bait file inside the redirected allow-list directory was deleted')
            }
            else {
                [void]$evidence.Add(('bait intact: {0}' -f $baitFile))
            }
        }
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $child
        if (-not (Remove-VerificationSandbox -Path $sandbox)) {
            [void]$problem.Add(('the sandbox could not be removed: {0}' -f $sandbox))
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'EXIT5' -ExpectedExitCode 5 `
        -Expected 'exit 5, a CRITICAL system-drive line, and nothing deleted' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}

# ------------------------------------------------------------------------------------------------
# Scenario EXIT3 - another run holds the machine-wide lock
# ------------------------------------------------------------------------------------------------

function Invoke-Exit3Scenario {
    <#
    .SYNOPSIS
        Two overlapping elevated runs: the second must exit 3 and mutate nothing.
    .DESCRIPTION
        The deterministic signal that the FIRST run really owns the mutex is its own log. Run.ps1
        calls Clear-WacDeliveryOptimizationCache immediately after Enter-WacSingleInstance returns a
        mutex, and that step always writes a [DeliveryOptimization] result line (succeeded, skipped
        or failed). So a [DeliveryOptimization] line in the first child's log proves the mutex was
        held; polling for it with a deadline is a real signal, not a sleep.

        Probing the mutex directly was rejected: WaitOne(0) from this process would acquire the lock
        whenever the child had not taken it yet, and the child does not retry - it would exit 3 and
        the scenario would prove the opposite of what it claims.

        The second sandbox's bait check needs the same treatment as EXIT5's for the same reason:
        'Defender cleanup files' stays ENABLED so that a second child which failed to exit 3 and
        swept its targets would delete it. With every category skipped the file survived either way
        and the "mutated nothing" evidence line asserted nothing about the mutex at all. Both
        children share one command line, so the first child sweeps ITS OWN sandbox copy - which is
        exactly what EXIT2 already does, inside the sandbox and nowhere else.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $firstSandbox = ''
    $secondSandbox = ''
    $firstChild = $null
    $secondChild = $null

    try {
        $skip = @(Get-NonSandboxCategory -Keep 'Defender cleanup files')
        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        else {
            $mutexName = New-VerificationMutexName
            $firstSandbox = New-VerificationSandbox -Prefix 'wac-exit3-first'
            $secondSandbox = New-VerificationSandbox -Prefix 'wac-exit3-second'
            [void](New-SandboxBait -Sandbox $firstSandbox)
            $secondBait = Join-Path -Path (New-SandboxBait -Sandbox $secondSandbox) -ChildPath 'bait.txt'

            $commandLine = Get-RunChildCommandLine -MutexName $mutexName -SkipCategory $skip

            $firstChild = Start-VerificationChild -CommandLine $commandLine `
                -Environment (Get-SandboxEnvironment -Sandbox $firstSandbox)

            # Bound the wait for the lock at the wall timeout as well, so a first run that dies
            # during start-up cannot park this harness here.
            $sandboxForSignal = $firstSandbox
            $held = Wait-ForSignal -TimeoutMs ([Math]::Min($TimeoutMs, 300000)) -Condition {
                @(Get-MatchingLine -Text (Get-SandboxLogText -Sandbox $sandboxForSignal) -Needle '[DeliveryOptimization]').Count -gt 0
            }

            if (-not $held) {
                [void]$problem.Add('the first run never logged a post-mutex line, so it was never proven to hold the lock')
            }
            elseif ($firstChild.Process.HasExited) {
                [void]$problem.Add('the first run had already finished, so the second could not overlap it')
            }
            else {
                $holdLines = @(Get-MatchingLine -Text (Get-SandboxLogText -Sandbox $firstSandbox) -Needle '[DeliveryOptimization]')
                [void]$evidence.Add(('first run holds the lock: {0}' -f $holdLines[0]))

                $secondChild = Start-VerificationChild -CommandLine $commandLine `
                    -Environment (Get-SandboxEnvironment -Sandbox $secondSandbox)
                $secondResult = Wait-VerificationChild -Child $secondChild -TimeoutMs $TimeoutMs
                $exitCode = $secondResult.ExitCode

                if (-not $secondResult.Exited) {
                    [void]$problem.Add('the second child did not finish inside its wall timeout and its tree was terminated')
                }
                if ($secondResult.ExitCode -ne 3) {
                    [void]$problem.Add(('expected the second run to exit 3, got {0}. stderr: {1}' -f `
                        (Get-RunExitDetail -ExitCode $secondResult.ExitCode), $secondResult.ErrorText.Trim()))
                }

                $secondText = Get-SandboxLogText -Sandbox $secondSandbox
                [void](Add-LogEvidence -Evidence $evidence -Problem $problem -Text $secondText `
                    -Needle 'already holds the machine-wide lock')

                foreach ($forbidden in @('[Result] Target complete.', '[Summary]')) {
                    if (@(Get-MatchingLine -Text $secondText -Needle $forbidden).Count -gt 0) {
                        [void]$problem.Add(('the locked-out run reached "{0}" instead of exiting without mutating anything' -f $forbidden))
                    }
                }

                if (-not (Test-Path -LiteralPath $secondBait -PathType Leaf)) {
                    [void]$problem.Add('the locked-out run deleted the bait file, so it mutated state before exiting')
                }
                else {
                    [void]$evidence.Add(('locked-out run mutated nothing: {0} intact' -f $secondBait))
                }
            }

            $firstResult = Wait-VerificationChild -Child $firstChild -TimeoutMs $TimeoutMs
            if (-not $firstResult.Exited) {
                [void]$problem.Add('the first child did not finish inside its wall timeout and its tree was terminated')
            }
            if ($firstResult.ExitCode -eq 3) {
                [void]$problem.Add('the FIRST run also exited 3, so it never owned the lock and the scenario proved nothing')
            }
            else {
                [void]$evidence.Add(('the lock owner did not exit 3: it exited {0}' -f $firstResult.ExitCode))
            }
        }
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $secondChild
        Stop-VerificationChild -Child $firstChild
        foreach ($path in @($secondSandbox, $firstSandbox)) {
            if (-not (Remove-VerificationSandbox -Path $path)) {
                [void]$problem.Add(('the sandbox could not be removed: {0}' -f $path))
            }
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'EXIT3' -ExpectedExitCode 3 `
        -Expected 'the second overlapping run exits 3, mutates nothing, and the lock owner does not' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}

# ------------------------------------------------------------------------------------------------
# Scenario EXIT2 - the run completed with at least one real failure
# ------------------------------------------------------------------------------------------------

function Invoke-Exit2Scenario {
    <#
    .SYNOPSIS
        A real deletion failure inside the sandbox must produce failed>0 and exit 2.
    .DESCRIPTION
        WHY THIS PARTICULAR FAILURE IS COUNTED AS Failed AND NOT AS ONE OF THE SKIP COUNTERS.

        The sandbox allow-list directory holds a subdirectory that this harness opens with
        CreateFileW(dwShareMode = 0) and keeps open for the whole child run. Enumerating that
        subdirectory then fails with ERROR_SHARING_VIOLATION, which .NET raises as IOException, and
        Get-WacIoFailureKind classifies an IOException as 'Busy'. Invoke-WacTreeSweep
        (FileSystem.psm1) routes its enumeration failures like this:

            Denied   -> SkippedDenied
            NotFound -> SkippedVanished
            anything else, which includes Busy -> Failed++

        That "anything else" is the only branch in the traversal that increments Failed, and it is
        why a merely locked or protected FILE cannot be used here: Remove-WacLeaf maps a Busy file
        to PendingDeletes or SkippedLocked, a Denied one to SkippedDenied, and a Busy DIRECTORY to
        SkippedNotEmpty. None of those reach the Failed bucket, so none of them can produce exit 2.

        The guards that run BEFORE the enumeration all still pass, which is what makes the outcome
        deterministic rather than a fail-closed skip: Test-WacIsReparsePoint reads attributes through
        GetFileAttributesEx and opens no handle, and Test-WacPathResolvesToItself opens the directory
        for FILE_READ_ATTRIBUTES, which is exempt from the share-mode check. Only the FILE_READ_DATA
        access that a directory listing needs collides with the lock. Measured on both shipped hosts:
        Remove-WacTree returns Failed=1, FilesDeleted=1, SkippedNotEmpty=1.

        Alternatives considered and rejected: a path over MAX_PATH reaches the same Failed branch,
        but only under Windows PowerShell 5.1 - PowerShell 7 deletes it successfully - and a DISM or
        pnpclean non-zero exit also sets a step's Failed flag, but neither can be forced
        deterministically and both would mutate the real machine instead of the sandbox.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null
    $handle = $null

    try {
        $skip = @(Get-NonSandboxCategory -Keep 'Defender cleanup files')
        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        else {
            $sandbox = New-VerificationSandbox -Prefix 'wac-exit2'
            $target = New-SandboxBait -Sandbox $sandbox

            # bait.txt proves the sweep really ran; the locked subdirectory produces the failure.
            $deletable = Join-Path -Path $target -ChildPath 'bait.txt'
            $lockedDirectory = Join-Path -Path $target -ChildPath 'locked'
            $survivor = Join-Path -Path $lockedDirectory -ChildPath 'inside.txt'
            [void][System.IO.Directory]::CreateDirectory($lockedDirectory)
            [System.IO.File]::WriteAllText($survivor, 'inside', $script:Utf8NoBom)

            $handle = [WacVerificationLock]::Open($lockedDirectory)

            $commandLine = Get-RunChildCommandLine -MutexName (New-VerificationMutexName) -SkipCategory $skip
            $child = Start-VerificationChild -CommandLine $commandLine `
                -Environment (Get-SandboxEnvironment -Sandbox $sandbox)
            $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
            $exitCode = $result.ExitCode

            if (-not $result.Exited) {
                [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
            }
            if ($result.ExitCode -ne 2) {
                [void]$problem.Add(('expected exit 2, got {0}. stderr: {1}' -f (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
            }

            $text = Get-SandboxLogText -Sandbox $sandbox

            # Exactly one target may have been touched, and it must be the sandbox one: any other
            # [Result] line would mean an allow-list entry outside the sandbox was cleaned for real.
            $resultLines = @(Get-MatchingLine -Text $text -Needle '[Result] Target complete.')
            if ($resultLines.Count -ne 1) {
                [void]$problem.Add(('expected exactly one cleaned target, the log shows {0}' -f $resultLines.Count))
            }
            else {
                [void]$evidence.Add($resultLines[0])
                if ($resultLines[0].IndexOf($target, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    [void]$problem.Add(('the cleaned target was not the sandbox directory {0}' -f $target))
                }
                if (-not (Test-KeyValue -Line $resultLines[0] -Pair 'failed=1')) {
                    [void]$problem.Add('the target result did not report exactly failed=1, so the locked directory never reached the Failed bucket')
                }
            }

            # The totals line disambiguates: exactly failed=1 proves the exit 2 came from this
            # deletion and not from an unrelated DISM or pnpclean failure on the operator's machine.
            # Test-KeyValue rather than a substring test: IndexOf('failed=1') is also satisfied by
            # failed=10, failed=11 and failed=100, so it only ruled out totals of 2..9.
            $totalLines = @(Get-MatchingLine -Text $text -Needle '[Summary] Cleanup totals.')
            if ($totalLines.Count -eq 0) {
                [void]$problem.Add('the run never reached the summary totals')
            }
            else {
                [void]$evidence.Add($totalLines[0])
                if (-not (Test-KeyValue -Line $totalLines[0] -Pair 'failed=1')) {
                    [void]$problem.Add('the summary totals did not report exactly failed=1')
                }
            }

            # The footer records the run's OUTCOME by name now, not a sentence: status=Failed is
            # what maps to exit 2, and its absence means the 2 came from somewhere else.
            [void](Add-LogEvidence -Evidence $evidence -Problem $problem -Text $text -Needle 'status=Failed')

            if (Test-Path -LiteralPath $deletable -PathType Leaf) {
                [void]$problem.Add('the deletable bait file survived, so the sweep never really ran')
            }
            if (-not (Test-Path -LiteralPath $survivor -PathType Leaf)) {
                [void]$problem.Add('the file inside the locked directory was deleted, so the lock did not hold')
            }
        }
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $child
        if ($handle) { try { $handle.Dispose() } catch { $null = $_ } }
        if (-not (Remove-VerificationSandbox -Path $sandbox)) {
            [void]$problem.Add(('the sandbox could not be removed: {0}' -f $sandbox))
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'EXIT2' -ExpectedExitCode 2 `
        -Expected 'a real sandbox deletion failure produces failed=1 and exit 2' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}

# ------------------------------------------------------------------------------------------------
# Machine-state snapshots - used only by the two scenarios that change the real machine
# ------------------------------------------------------------------------------------------------

function Get-PublishedDriverName {
    <#
    .SYNOPSIS
        The published oem<n>.inf packages currently in the driver store.
    .DESCRIPTION
        Only oem<n>.inf packages can be removed by pnputil /delete-driver, and those are exactly the
        ones Get-WacSupersededDriver considers, so their names are the whole before/after diff.

        Deliberately NOT taken through the shipped ConvertFrom-WacPnpUtilCsv: a snapshot built with
        the same parser the step uses could not detect that parser going wrong. A regex over the raw
        pnputil output is independent of the CSV switch, the column names and the locale.

        Failure is reported as Ok=$false rather than as an empty set. The caller must refuse, not
        compare two empty sets and conclude that nothing was deleted.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $pnputil = Join-Path -Path $env:SystemRoot -ChildPath 'System32\pnputil.exe'
    if (-not (Test-Path -LiteralPath $pnputil -PathType Leaf)) {
        return [PSCustomObject]@{ Ok = $false; Name = @(); Reason = ('{0} does not exist' -f $pnputil) }
    }

    $run = Invoke-WacProcess -FilePath $pnputil -ArgumentList @('/enum-drivers') -TimeoutMs $TimeoutMs -Component 'Verify'
    if ($run.TimedOut) {
        return [PSCustomObject]@{ Ok = $false; Name = @(); Reason = 'pnputil /enum-drivers exceeded its deadline' }
    }
    if ($run.ExitCode -ne 0) {
        return [PSCustomObject]@{ Ok = $false; Name = @(); Reason = ('pnputil /enum-drivers exited with {0}' -f $run.ExitCode) }
    }

    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($match in ([regex]'(?i)\boem\d+\.inf\b').Matches([string]$run.StandardOutput)) {
        $name = $match.Value.ToLowerInvariant()
        if (-not $names.Contains($name)) { [void]$names.Add($name) }
    }

    return [PSCustomObject]@{ Ok = $true; Name = @($names.ToArray()); Reason = '' }
}

function Get-VolumeCacheStateFlag {
    <#
    .SYNOPSIS
        Every VolumeCaches handler's StateFlags<SageId>, with ABSENCE recorded as a state of its own.
    .DESCRIPTION
        Invoke-WacLegacyDiskCleanup writes a sage profile across the handlers and promises to put
        every one of them back exactly as it found it - including the handlers that had no
        StateFlags value at all. Nothing verified that promise on a real machine.

        The absent ones are the half that a naive check misses: storing 'absent' as a value rather
        than as a missing key is what lets the after-comparison catch a restore that left a value
        behind where there had been none. A hashtable is returned rather than a Dictionary because
        PowerShell unrolls a Dictionary on return and would hand the caller its entries instead.
    #>
    param([Parameter(Mandatory = $true)][int]$SageId)

    $keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    $valueName = 'StateFlags{0:0000}' -f $SageId
    $state = @{}

    foreach ($handler in @(Get-ChildItem -LiteralPath $keyPath -ErrorAction Stop)) {
        $name = [string](Split-Path -Leaf $handler.Name)
        $value = 'absent'
        try {
            $property = Get-ItemProperty -LiteralPath $handler.PSPath -Name $valueName -ErrorAction Stop
            $value = [string]([int]$property.$valueName)
        }
        catch {
            $value = 'absent'
        }
        $state[$name] = $value
    }

    return $state
}

function Compare-StateFlagSnapshot {
    <#
    .SYNOPSIS
        Every difference between two StateFlags snapshots, as readable lines. Empty means identical.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Before,
        [Parameter(Mandatory = $true)][hashtable]$After
    )

    $difference = New-Object 'System.Collections.Generic.List[string]'

    foreach ($name in @($Before.Keys)) {
        if (-not $After.ContainsKey($name)) {
            [void]$difference.Add(('{0}: the handler key itself disappeared' -f $name))
            continue
        }
        if ([string]$Before[$name] -cne [string]$After[$name]) {
            [void]$difference.Add(('{0}: was {1}, is now {2}' -f $name, $Before[$name], $After[$name]))
        }
    }

    foreach ($name in @($After.Keys)) {
        if (-not $Before.ContainsKey($name)) {
            [void]$difference.Add(('{0}: a handler key appeared' -f $name))
        }
    }

    return @($difference.ToArray())
}

# ------------------------------------------------------------------------------------------------
# Scenario DRIVERS - a real -PruneSupersededDrivers run (CHANGES THE MACHINE)
# ------------------------------------------------------------------------------------------------

function ConvertTo-VerificationUtcText {
    <#
    .SYNOPSIS
        A manifest timestamp as ISO-8601 UTC text, whatever ConvertFrom-Json made of it.
    .DESCRIPTION
        Measured on this project's two hosts: PowerShell 7's ConvertFrom-Json turns an ISO-8601
        string into a [datetime] and Windows PowerShell 5.1 leaves it a string, so a bare [string]
        cast yields '2026-08-24T00:00:05Z' on one host and a locale-formatted '08/24/2026
        00:00:05' on the other. Evidence that differs by host is evidence nobody can compare.
    #>
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [string]$Value
}

function Get-DriverBackupRecord {
    <#
    .SYNOPSIS
        Every wac-driver-backup.json under the backup root, with the directory holding it.
    .DESCRIPTION
        A backup directory is CONTENT-ADDRESSED - <stem>_<version>_<hash16> - because oem<n>.inf is
        a recyclable name that Windows hands to an unrelated package after a removal. So the oem
        name cannot be turned back into a path: Join-Path <backupRoot> <oem name> can never exist,
        and a check built on it reports 'no recoverable export' for every package that really was
        deleted. The manifest is the only thing that maps a directory back to the package it came
        from, so this reads that instead, and reports what it could not read rather than skipping.
    #>
    param([Parameter(Mandatory = $true)][string]$BackupRoot)

    $record = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) { return @($record.ToArray()) }

    foreach ($directory in @(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction SilentlyContinue)) {
        $manifestPath = Join-Path -Path $directory.FullName -ChildPath 'wac-driver-backup.json'
        $manifest = $null
        $unreadable = ''

        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            $unreadable = 'it holds no wac-driver-backup.json'
        }
        else {
            try { $manifest = ConvertFrom-Json ([System.IO.File]::ReadAllText($manifestPath, [System.Text.Encoding]::UTF8)) }
            catch { $unreadable = 'its manifest could not be parsed: {0}' -f $_.Exception.Message }
        }

        $driverName = ''
        $originalName = ''
        $deletedUtc = ''
        if ($manifest) {
            $property = @($manifest.PSObject.Properties.Name)
            if ($property -ccontains 'DriverName') { $driverName = [string]$manifest.DriverName }
            if ($property -ccontains 'OriginalName') { $originalName = [string]$manifest.OriginalName }
            if ($property -ccontains 'DeletedUtc') { $deletedUtc = ConvertTo-VerificationUtcText -Value $manifest.DeletedUtc }
            if (-not $driverName) { $unreadable = 'its manifest names no DriverName' }
        }

        # The manifest itself is not an export: a directory holding nothing else is not a
        # recoverable copy of anything.
        $fileCount = @(Get-ChildItem -LiteralPath $directory.FullName -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ine 'wac-driver-backup.json' }).Count

        [void]$record.Add([PSCustomObject]@{
            Directory    = $directory.FullName
            DriverName   = $driverName
            OriginalName = $originalName
            DeletedUtc   = $deletedUtc
            FileCount    = $fileCount
            Unreadable   = $unreadable
        })
    }

    return @($record.ToArray())
}

function Invoke-DriversScenario {
    <#
    .SYNOPSIS
        A real driver prune: every package that disappeared must have a recoverable export.
    .DESCRIPTION
        THIS SCENARIO CHANGES THE OPERATOR'S MACHINE. It is the only way to exercise
        Invoke-WacDriverPackagePrune's fail-closed contract - "export first, delete second, and
        never delete what could not be exported" - because the step refuses to do anything without
        administrator rights and a real driver store, so no unit suite can reach the contract.

        %ProgramData% is still redirected into the sandbox, so the run log AND the DriverBackup root
        land inside it. That is what makes the backup root deterministic, and it is why the sandbox
        is PRESERVED rather than deleted whenever a package really was removed: those exports are
        then the only recoverable copy, and destroying them here would break the very contract this
        scenario exists to verify.

        Every allow-list category is disabled and -ResetWindowsUpdateBase:$false is still passed, so
        the driver store is the only machine state this scenario is allowed to change.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null
    $keepSandbox = $false

    try {
        $skip = @(Get-NonSandboxCategory -Keep '')
        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        else {
            $before = Get-PublishedDriverName -TimeoutMs $script:PnpUtilProbeMs
            if (-not $before.Ok) {
                [void]$problem.Add(('refusing to start: the driver store could not be snapshotted before the run ({0})' -f $before.Reason))
            }
            else {
                $sandbox = New-VerificationSandbox -Prefix 'wac-drivers'
                $backupRoot = Join-Path -Path $sandbox -ChildPath 'PD\WindowsAutoCleanup\DriverBackup'
                [void]$evidence.Add(('driver packages before the run: {0}' -f $before.Name.Count))

                $commandLine = Get-RunChildCommandLine -MutexName (New-VerificationMutexName) `
                    -SkipCategory $skip -PruneSupersededDrivers
                $child = Start-VerificationChild -CommandLine $commandLine `
                    -Environment (Get-SandboxEnvironment -Sandbox $sandbox)
                $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
                $exitCode = $result.ExitCode

                if (-not $result.Exited) {
                    [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
                }
                if ($result.ExitCode -ne 0) {
                    [void]$problem.Add(('expected exit 0, got {0}. stderr: {1}' -f (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
                }

                # The machine-state assertions come FIRST, on purpose. Get-SandboxLogText throws
                # on a log it cannot read, and a throw before this point would leave $keepSandbox
                # false - which would delete the sandbox that holds the only recoverable copy of
                # whatever this run had just removed from the driver store.
                $after = Get-PublishedDriverName -TimeoutMs $script:PnpUtilProbeMs
                if (-not $after.Ok) {
                    [void]$problem.Add(('the driver store could not be snapshotted after the run ({0}), so nothing about it can be asserted' -f $after.Reason))
                    # Unknown means unsafe: keep whatever was exported rather than assume nothing was.
                    $keepSandbox = $true
                    [void]$evidence.Add(('the sandbox is PRESERVED because the driver store could not be re-read: {0}' -f $backupRoot))
                }
                else {
                    $removed = @($before.Name | Where-Object { $after.Name -notcontains $_ })
                    $appeared = @($after.Name | Where-Object { $before.Name -notcontains $_ })
                    [void]$evidence.Add(('driver packages after the run: {0}; removed {1}; appeared {2}' -f `
                        $after.Name.Count, $removed.Count, $appeared.Count))

                    if ($appeared.Count -gt 0) {
                        [void]$problem.Add(('the run ADDED driver package(s), which it must never do: {0}' -f ($appeared -join ', ')))
                    }

                    if ($removed.Count -gt 0) {
                        # From here the sandbox holds the only recoverable copy of what was deleted.
                        $keepSandbox = $true
                        [void]$evidence.Add(('the sandbox is PRESERVED: {0} holds the only recoverable copy of every deleted package' -f $backupRoot))

                        $backup = @(Get-DriverBackupRecord -BackupRoot $backupRoot)
                        [void]$evidence.Add(('backup directories under {0}: {1}' -f $backupRoot, $backup.Count))
                        foreach ($broken in @($backup | Where-Object { $_.Unreadable })) {
                            [void]$problem.Add(('the backup directory {0} cannot be identified - {1}' -f $broken.Directory, $broken.Unreadable))
                        }

                        foreach ($name in $removed) {
                            $match = @($backup | Where-Object { [string]$_.DriverName -ieq $name })
                            if ($match.Count -eq 0) {
                                [void]$problem.Add(('BLOCKER: {0} left the driver store and no manifest under {1} claims it, so nothing recoverable was exported' -f $name, $backupRoot))
                                continue
                            }
                            if ($match.Count -gt 1) {
                                [void]$problem.Add(('{0} is claimed by {1} backup directories, so which one is the recoverable copy is ambiguous' -f $name, $match.Count))
                            }

                            $exported = $match[0]
                            if ($exported.FileCount -lt 1) {
                                [void]$problem.Add(('BLOCKER: the backup for {0} at {1} holds nothing but its manifest' -f $name, $exported.Directory))
                            }
                            # DeletedUtc is what tells a backup apart from an export of a package
                            # that is still installed. Empty here means the manifest still claims
                            # the package is in the store, which a restore would read as "no copy
                            # of a deleted package".
                            if (-not $exported.DeletedUtc) {
                                [void]$problem.Add(('{0} was removed from the driver store but its manifest at {1} never recorded DeletedUtc' -f $name, $exported.Directory))
                            }
                            if ($exported.FileCount -ge 1 -and $exported.DeletedUtc) {
                                [void]$evidence.Add(('{0} ({1}) deleted at {2}; {3} file(s) exported to {4}' -f `
                                    $name, $exported.OriginalName, $exported.DeletedUtc, $exported.FileCount, $exported.Directory))
                            }
                        }
                    }
                }

                $text = Get-SandboxLogText -Sandbox $sandbox
                Add-ResetBaseEvidence -Evidence $evidence -Problem $problem -Text $text

                # The step logs itself whether it ran or skipped, so its absence and its default-off
                # skip are two different failures and both mean the opt-in never took effect.
                $stepLines = @(Get-MatchingLine -Text $text -Needle '[DriverPrune] Step complete.')
                if ($stepLines.Count -eq 0) {
                    [void]$problem.Add('the log carries no [DriverPrune] step result at all')
                }
                else {
                    [void]$evidence.Add($stepLines[0])
                    if ($stepLines[0].IndexOf('disabled by default', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        [void]$problem.Add('DriverPrune reported its default-off skip, so -PruneSupersededDrivers never reached the child')
                    }
                }
            }
        }
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $child
        if (-not $keepSandbox) {
            if (-not (Remove-VerificationSandbox -Path $sandbox)) {
                [void]$problem.Add(('the sandbox could not be removed: {0}' -f $sandbox))
            }
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'DRIVERS' -ExpectedExitCode 0 -Machine `
        -Expected 'a real driver prune: exit 0, the step really ran, and every deleted package has an export' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}

# ------------------------------------------------------------------------------------------------
# Scenario CLEANMGR - a real -EnableLegacyDiskCleanup run (CHANGES THE MACHINE, AND NOT ONLY C:)
# ------------------------------------------------------------------------------------------------

function Invoke-CleanmgrScenario {
    <#
    .SYNOPSIS
        A real legacy Disk Cleanup run: every StateFlags value must come back exactly as it was.
    .DESCRIPTION
        THIS SCENARIO CHANGES THE OPERATOR'S MACHINE, and unlike everything else in this harness it
        is not confined to C:. cleanmgr /sagerun enumerates EVERY drive in the computer and /d is
        ignored, which is why the step is opt-in - and why this scenario asserts that the child
        logged that warning rather than trusting the step to have written it.

        Invoke-WacLegacyDiskCleanup writes StateFlags9999 across the VolumeCaches handlers and
        restores the snapshot in a finally block, "including was absent". That promise had no test.
        Snapshotting every handler before and after, with absence as a first-class state, is the
        whole point here: a restore that turned an absent value into a written 0 would look correct
        to any check that only compared the handlers that already had a value.

        9999 is Invoke-WacLegacyDiskCleanup's own default SageId and the child is launched without
        -SageId, so the profile snapshotted here is the profile the child writes.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null

    try {
        $skip = @(Get-NonSandboxCategory -Keep '')
        $before = Get-VolumeCacheStateFlag -SageId $script:VerificationSageId

        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        elseif ($before.Count -eq 0) {
            [void]$problem.Add('refusing to start: no VolumeCaches handler could be read, so a restore could not be proven either way')
        }
        else {
            $absent = @($before.Keys | Where-Object { $before[$_] -ceq 'absent' })
            [void]$evidence.Add(('StateFlags{0:0000} before the run: {1} handler(s), {2} of them with no value at all' -f `
                $script:VerificationSageId, $before.Count, $absent.Count))

            $sandbox = New-VerificationSandbox -Prefix 'wac-cleanmgr'
            $commandLine = Get-RunChildCommandLine -MutexName (New-VerificationMutexName) `
                -SkipCategory $skip -EnableLegacyDiskCleanup
            $child = Start-VerificationChild -CommandLine $commandLine `
                -Environment (Get-SandboxEnvironment -Sandbox $sandbox)
            $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
            $exitCode = $result.ExitCode

            if (-not $result.Exited) {
                [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
            }
            if ($result.ExitCode -ne 0) {
                [void]$problem.Add(('expected exit 0, got {0}. stderr: {1}' -f (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
            }

            # The restore assertion runs FIRST: it is the machine state this scenario exists to
            # check, and Get-SandboxLogText throws on a log it cannot read, which would otherwise
            # skip it entirely.
            $after = Get-VolumeCacheStateFlag -SageId $script:VerificationSageId
            $difference = @(Compare-StateFlagSnapshot -Before $before -After $after)
            if ($difference.Count -gt 0) {
                foreach ($line in $difference) {
                    [void]$problem.Add(('the sage profile was NOT restored exactly - {0}' -f $line))
                }
            }
            else {
                [void]$evidence.Add(('StateFlags{0:0000} restored exactly across all {1} handler(s), the {2} absent one(s) included' -f `
                    $script:VerificationSageId, $after.Count, $absent.Count))
            }

            $text = Get-SandboxLogText -Sandbox $sandbox
            Add-ResetBaseEvidence -Evidence $evidence -Problem $problem -Text $text

            $stepLines = @(Get-MatchingLine -Text $text -Needle '[DiskCleanup] Step complete.')
            if ($stepLines.Count -eq 0) {
                [void]$problem.Add('the log carries no [DiskCleanup] step result at all')
            }
            else {
                [void]$evidence.Add($stepLines[0])
                if ($stepLines[0].IndexOf('disabled by default', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    [void]$problem.Add('DiskCleanup reported its default-off skip, so -EnableLegacyDiskCleanup never reached the child')
                }
            }

            [void](Add-LogEvidence -Evidence $evidence -Problem $problem -Text $text `
                -Needle 'enumerates EVERY drive in this computer')
        }
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $child
        if (-not (Remove-VerificationSandbox -Path $sandbox)) {
            [void]$problem.Add(('the sandbox could not be removed: {0}' -f $sandbox))
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'CLEANMGR' -ExpectedExitCode 0 -Machine `
        -Expected 'a real cleanmgr /sagerun: exit 0, the every-drive warning logged, and every StateFlags value restored exactly' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}

# ------------------------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $script:RunPath -PathType Leaf)) {
    Write-Host ('REFUSED: Run.ps1 was not found at {0}.' -f $script:RunPath)
    exit 2
}

if (-not (Test-WacIsAdministrator)) {
    Write-Host 'REFUSED: Invoke-ElevatedVerification.ps1 must run in an ELEVATED PowerShell session.'
    Write-Host '         Run.ps1 exit codes 5, 3 and 2 all sit behind its elevation gate, so an'
    Write-Host '         unelevated run could only ever observe the relaunch path.'
    Write-Host '         Start an elevated host, then run:'
    Write-Host ('             {0} -NoProfile -File "{1}"' -f `
        (Split-Path -Leaf ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)), $PSCommandPath)
    exit 2
}

if (-not (Initialize-VerificationLock)) { exit 2 }

$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
# NOT %TEMP%, which is where this used to live. Each sandbox becomes the child's %ProgramData%,
# and an ELEVATED child verifies that its state directory is machine-trusted: measured on a stock
# Windows 11 install, a sandbox under a per-user temp directory answers untrusted at every level
# of the chain, so every scenario that reached the footer would exit 7 (security refusal) instead
# of the code it was checking. %ProgramData%\WindowsAutoCleanup is trusted, and it is also a safer
# home for the DRIVERS sandbox, which is KEPT when it holds the only recoverable copy of a deleted
# driver package - a temp cleaner is exactly what must not reach that.
$script:SandboxRoot = [System.IO.Path]::GetFullPath((Join-Path -Path (Get-WacDataRoot) -ChildPath 'Verification\Sandbox'))
try { [void][System.IO.Directory]::CreateDirectory($script:SandboxRoot) }
catch {
    Write-Host ('REFUSED: the sandbox root {0} could not be created: {1}' -f $script:SandboxRoot, $_.Exception.Message)
    exit 2
}

# Run.ps1 only ever builds targets on C:, so a sandbox anywhere else would produce no target at all
# and every scenario would pass for the wrong reason.
if (-not (Test-WacIsOnTargetDrive -Path $script:SandboxRoot)) {
    Write-Host ('REFUSED: the sandbox root {0} is not on {1}, so no sandbox path could ever become an allow-list target.' -f `
        $script:SandboxRoot, (Get-WacTargetDrive))
    exit 2
}

# Refuse loudly rather than let every scenario report a security refusal the harness itself caused.
# This is the same check the child makes on its own state directory, made here on the directory
# the child's %ProgramData% will live in.
$script:SandboxTrust = Test-WacStatePathIsTrusted -Path $script:SandboxRoot
if (-not $script:SandboxTrust.IsTrusted) {
    Write-Host ('REFUSED: the sandbox root {0} is not machine-trusted, so every child would exit 7 (security refusal) whatever else it did.' -f $script:SandboxRoot)
    Write-Host ('         {0}' -f $script:SandboxTrust.Reason)
    exit 2
}

if (-not $ResultPath) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd_HH-mm-ss')
    $ResultPath = Join-Path -Path (Get-WacDataRoot) -ChildPath ('Verification\ElevatedVerification_{0}_UTC.json' -f $stamp)
}

$script:SandboxedScenario = @('EXIT5', 'EXIT3', 'EXIT2')
$script:MachineScenario = @('DRIVERS', 'CLEANMGR')

$selected = @($Scenario)
if ($Scenario -eq 'Sandboxed') { $selected = @($script:SandboxedScenario) }
elseif ($Scenario -eq 'All') { $selected = @($script:SandboxedScenario + $script:MachineScenario) }

$machineSelected = @($selected | Where-Object { $script:MachineScenario -contains $_ })

Write-Host ''
Write-Host ('WindowsAutoCleanup elevated verification - host {0}, scenarios {1}' -f $script:HostExe, ($selected -join ', '))
Write-Host ('Sandbox root {0}; child budget {1} min (derived); wall timeout {2}s per child.' -f `
    $script:SandboxRoot, $script:ChildBudgetMinutes, $TimeoutSeconds)
Write-Host 'The EXIT2 scenario and the first EXIT3 run execute the real DISM component cleanup'
Write-Host '(without /ResetBase), pnpclean and the Delivery Optimization purge; see the .DESCRIPTION.'
if ($machineSelected.Count -gt 0) {
    Write-Host ''
    Write-Host ('*** {0} CHANGE THIS MACHINE and are not sandboxed:' -f ($machineSelected -join ' and '))
    Write-Host '***   DRIVERS  deletes superseded driver packages, each exported first; if any package is'
    Write-Host '***            removed its sandbox is KEPT, because it then holds the only recoverable copy.'
    Write-Host '***   CLEANMGR runs cleanmgr /sagerun, which enumerates EVERY drive in this computer.'
    Write-Host '*** /ResetBase is excluded from every scenario. Use -Scenario Sandboxed for the safe set.'
}
Write-Host ''

$records = New-Object 'System.Collections.Generic.List[object]'
$timeoutMs = $TimeoutSeconds * 1000

foreach ($name in $selected) {
    Write-Host ('--- {0} starting' -f $name)

    $record = $null
    switch ($name) {
        'EXIT5' { $record = Invoke-Exit5Scenario -TimeoutMs $timeoutMs }
        'EXIT3' { $record = Invoke-Exit3Scenario -TimeoutMs $timeoutMs }
        'EXIT2' { $record = Invoke-Exit2Scenario -TimeoutMs $timeoutMs }
        'DRIVERS' { $record = Invoke-DriversScenario -TimeoutMs $timeoutMs }
        'CLEANMGR' { $record = Invoke-CleanmgrScenario -TimeoutMs $timeoutMs }
        default { throw ('no scenario is wired up for {0}' -f $name) }
    }

    [void]$records.Add($record)
    Write-Host ('--- {0} {1} ({2} ms)' -f $name, $(if ($record.Passed) { 'PASS' } else { 'FAIL' }), $record.DurationMs)
    foreach ($line in $record.Evidence) { Write-Host ('      evidence: {0}' -f $line) }
    foreach ($line in $record.Problem) { Write-Host ('      PROBLEM : {0}' -f $line) }
    Write-Host ''
}

$failed = @($records | Where-Object { -not $_.Passed })

$report = [PSCustomObject]@{
    Tool        = 'WindowsAutoCleanup elevated verification'
    ScriptPath  = $script:RunPath
    HostPath    = $script:HostExe
    PSVersion   = [string]$PSVersionTable.PSVersion
    FinishedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    Scenarios   = @($records.ToArray())
    PassedCount = ($records.Count - $failed.Count)
    FailedCount = $failed.Count
    MachineCount = @($records | Where-Object { $_.Machine }).Count
    OverallPass = ($failed.Count -eq 0)
}

$written = $ResultPath
try {
    $directory = Split-Path -Parent $ResultPath
    if ($directory -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }
    # An explicit -Depth: the default of 2 silently truncates the nested Evidence arrays on 5.1.
    [System.IO.File]::WriteAllText($ResultPath, ($report | ConvertTo-Json -Depth 6), $script:Utf8NoBom)
}
catch {
    $written = ''
    Write-Host ('WARNING the result file could not be written: {0}' -f $_.Exception.Message)
}

Write-Host '=========================================================================================='
Write-Host ('{0,-9} {1,-8} {2,-7} {3,-7} {4,-7} {5,11}  {6}' -f `
    'SCENARIO', 'SCOPE', 'RESULT', 'EXPECT', 'ACTUAL', 'DURATION', 'PROBLEMS')
Write-Host '------------------------------------------------------------------------------------------'

# Sandboxed rows first, then a banner, then the rows that changed this machine. The separation is
# the point: a reader must never have to remember which scenario names touch the real machine.
$machineHeaderShown = $false
foreach ($record in $records) {
    if ($record.Machine -and -not $machineHeaderShown) {
        Write-Host '--- these ones CHANGED THIS MACHINE (authorised, not sandboxed) ---------------------------'
        $machineHeaderShown = $true
    }
    Write-Host ('{0,-9} {1,-8} {2,-7} {3,-7} {4,-7} {5,8} ms  {6}' -f `
        $record.Name,
        $(if ($record.Machine) { 'MACHINE' } else { 'sandbox' }),
        $(if ($record.Passed) { 'PASS' } else { 'FAIL' }),
        $record.ExpectedExitCode,
        $record.ActualExitCode,
        $record.DurationMs,
        @($record.Problem).Count)
}
Write-Host '=========================================================================================='
Write-Host ('{0} of {1} scenario(s) passed.' -f $report.PassedCount, $records.Count)
if ($written) { Write-Host ('Result file: {0}' -f $written) }

if ($failed.Count -gt 0) { exit 1 }
exit 0
