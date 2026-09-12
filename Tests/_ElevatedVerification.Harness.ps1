<#
.SYNOPSIS
    The infrastructure every elevated verification scenario shares: the directory lock, the
    sandbox, the log reader, the exit-code table, the bounded child processes and the scenario
    record.

.DESCRIPTION
    Dot-sourced by Invoke-ElevatedVerification.ps1 after it has imported Core and Targets and
    computed $script:ChildBudgetMinutes. It defines functions only; nothing here runs at
    dot-source time, so the harness's own REFUSED checks still happen before any of it is used.
#>

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
        FileShare ReadWrite|Delete permits diagnostics while a child still holds its StreamWriter
        open; a plain ReadAllText can fail with "the process cannot access the file".

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

    # The live set above is only what THIS process managed to materialise, and that is NOT the same
    # set the child materialises. Measured in a Hyper-V guest: the harness enumerated 16 categories
    # including 'Current user TEMP contents' but NOT 'User TEMP contents', because
    # Get-WacUserProfilePath returned nothing here while it returned C:\Users\<name> in the child.
    # The per-profile category was therefore absent from the deny-list, survived -SkipCategory, and
    # the child swept the operator's REAL %USERPROFILE%\AppData\Local\Temp - outside the sandbox,
    # on a machine the brief forbids running destructive cleanup against. Windows Sandbox had hidden
    # it because no second profile path existed there.
    #
    # So the deny-list is built from what Targets.psm1 DECLARES, not from what one process happens
    # to resolve. Reading the module's own table is deliberate: an environment-dependent enumeration
    # is exactly what failed.
    $module = Get-Module -Name 'WindowsAutoCleanup.Targets'
    if (-not $module) {
        throw 'the Targets module is not loaded, so the per-profile categories cannot be denied; refusing to build a partial skip list'
    }
    $declared = @(& $module { $script:UserCacheTarget } | ForEach-Object { [string]$_.Category })
    if ($declared.Count -lt 1) {
        throw 'the declared per-profile category table is empty or unreadable; refusing to build a partial skip list'
    }
    foreach ($name in $declared) {
        if ($name -ieq $Keep) { continue }
        if ($names.Contains($name)) { continue }
        [void]$names.Add($name)
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
