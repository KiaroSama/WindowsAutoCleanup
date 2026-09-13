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
        # The one directory the injected fixture may build a target inside. It is read ONLY by
        # Tests\_SandboxTargetFixture.psm1, which exists only in the scratch copy the child runs;
        # no shipped file reads it, and the fixture refuses to name any target when it is absent.
        WAC_VERIFY_SANDBOX_ROOT = $Sandbox
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

function New-SandboxSiblingTarget {
    <#
    .SYNOPSIS
        Fills in the fixture's other two allow-list directories, so a run completes SEVERAL targets.
    .DESCRIPTION
        The fixture always names three targets and an entry whose directory does not exist is simply
        unattempted, so a sandbox holding only the bait produced exactly one result line. One line
        is what let a bait assertion get away with reading whichever target was reported LAST: with
        a single line the two are the same string. Creating the siblings is what makes the
        distinction observable in a real run, and it costs two directories and two files.
    .OUTPUTS
        The directories created, in the fixture's own order.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $edge = Join-Path -Path $Sandbox -ChildPath 'LA\Microsoft\Edge\User Data\Default\Cache\Cache_Data'
    $explorer = Join-Path -Path $Sandbox -ChildPath 'LA\Microsoft\Windows\Explorer'
    foreach ($directory in @($edge, $explorer)) { [void][System.IO.Directory]::CreateDirectory($directory) }

    [System.IO.File]::WriteAllText((Join-Path -Path $edge -ChildPath 'data_1'), 'edge', $script:Utf8NoBom)
    # thumbcache_*.db is one of the two patterns the fixture's Explorer entry carries, so this file
    # is inside the pattern target rather than merely inside the directory that holds it.
    [System.IO.File]::WriteAllText((Join-Path -Path $explorer -ChildPath 'thumbcache_96.db'), 'thumbs', $script:Utf8NoBom)

    return @($edge, $explorer)
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

function Get-ResultLinePath {
    <#
    .SYNOPSIS
        The `path=` value from one '[Result] Target complete.' log line, or $null.
    .DESCRIPTION
        Write-WacLog renders key=value pairs and quotes a value that contains a space, so both
        `path=C:\Temp\x` and `path="C:\Program Files\x"` occur. Taking the field rather than testing
        the whole line for a substring is what makes containment checkable: a sandbox path is a
        substring of a SIBLING directory whose name merely extends it, and it can also appear inside
        an unrelated field, so "the line mentions the sandbox" never meant "the target was inside it".

        The quoted form is matched first; otherwise the value runs to the next space, because the
        pairs are space-separated and a bare value therefore cannot contain one.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Line)

    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }

    $match = [regex]::Match($Line, '(?i)\bpath=(?:"(?<quoted>[^"]*)"|(?<bare>[^\s]+))')
    if (-not $match.Success) { return $null }
    if ($match.Groups['quoted'].Success) { return [string]$match.Groups['quoted'].Value }
    return [string]$match.Groups['bare'].Value
}

function New-VerificationScratchTree {
    <#
    .SYNOPSIS
        A disposable COPY of the repository inside the sandbox, with the allow-list builder replaced
        by the positive sandbox fixture. Returns the Run.ps1 the child must be launched from.
    .DESCRIPTION
        This replaces a DENY-LIST that could not work. The harness used to enumerate allow-list
        categories and disable them with -SkipCategory, which requires the parent to be able to NAME
        every category the child will build. It cannot. 'Microsoft Edge cache' and
        'Windows Explorer thumbnail cache' are constructed outside the static per-profile table the
        deny-list was read from, so neither was ever in it; and the parent's discovery is not the
        child's, because redirecting TEMP, ProgramData and LOCALAPPDATA leaves the profile paths CIM
        returns untouched. Measured in a Hyper-V guest: the parent resolved no second profile, handed
        over a deny-list that denied nothing for it, and the elevated child swept the operator's real
        %USERPROFILE%\AppData\Local\Temp.

        So the child is given an explicit POSITIVE set instead, and the set is proven contained
        before it is handed over and again immediately before each delete. The mechanism is a scratch
        COPY: the shipped tree is never edited, no shipped file learns a test-only switch, and the
        fixture lives only in a directory that is deleted with the sandbox.

        The copy is shallow on purpose - Run.ps1 plus the files directly under src\, which is the
        whole module set - so it costs one file copy each and not a directory walk.

        TWO fixtures are injected, not one, because file containment and machine maintenance are
        different problems (ledger WAC-10R). The allow-list fixture confines what the run may
        DELETE; it can say nothing about DISM, pnpclean, pnputil, cleanmgr, the Delivery
        Optimization purge or the global Recycle Bin, none of which reaches the machine through an
        allow-list path. _SandboxMaintenanceFixture.psm1 stops those, and it goes over the DRIVERS
        module because Drivers is the LAST module Run.ps1 imports - the only slot whose names win
        command resolution in the run's own scope. The shipped module is preserved beside it and
        re-imported by the fixture, so the real driver surface is still there.

        Leaving it out is not an accident anybody can have quietly: Start-VerificationChild REFUSES
        to launch a tree that has no maintenance fixture unless the caller says -AllowRealMaintenance
        there too. The gate is on the launch rather than on the copy because the launch is the
        dangerous act, and because a tree built only to be inspected never runs at all.
    .PARAMETER InterceptMaintenance
        Adds the maintenance fixture. Every sandboxed scenario passes it; DRIVERS, CLEANMGR and the
        armed MAINTENANCE lane deliberately do not, because servicing the machine is what they test.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [switch]$InterceptMaintenance
    )

    $scratch = Join-Path -Path $Sandbox -ChildPath 'SRC'
    $scratchSrc = Join-Path -Path $scratch -ChildPath 'src'
    [void][System.IO.Directory]::CreateDirectory($scratchSrc)

    Copy-Item -LiteralPath $script:RunPath -Destination (Join-Path -Path $scratch -ChildPath 'Run.ps1') -Force -ErrorAction Stop
    foreach ($file in @(Get-ChildItem -LiteralPath $script:SrcRoot -File)) {
        Copy-Item -LiteralPath $file.FullName -Destination (Join-Path -Path $scratchSrc -ChildPath $file.Name) -Force -ErrorAction Stop
    }

    # THE INJECTION. Same module name, same exported surface, an explicit sandbox-only target set.
    $fixture = Join-Path -Path $script:TestsRoot -ChildPath '_SandboxTargetFixture.psm1'
    if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
        throw ('the sandbox target fixture is missing at {0}; refusing to launch a child that would build the real allow-list' -f $fixture)
    }
    $injected = Join-Path -Path $scratchSrc -ChildPath 'WindowsAutoCleanup.Targets.psm1'
    Copy-Item -LiteralPath $fixture -Destination $injected -Force -ErrorAction Stop

    # Proven, not assumed. A copy that silently failed would leave the SHIPPED builder in place and
    # the child would discover the operator's real profile - the exact failure this exists to stop.
    $marker = 'WAC_VERIFY_SANDBOX_ROOT'
    if (([System.IO.File]::ReadAllText($injected)).IndexOf($marker, [System.StringComparison]::Ordinal) -lt 0) {
        throw ('the allow-list builder in {0} is not the sandbox fixture; refusing to launch the child' -f $injected)
    }

    if ($InterceptMaintenance) {
        # The shipped driver module is PRESERVED under its own name first - the fixture imports it
        # back and re-exports the whole driver surface, so nothing is lost - and only then is it
        # stood in front of. Losing this copy would leave the child without pnputil parsing, the
        # backup store and the prune step, so the order matters and the copy is checked.
        $driverSlot = Join-Path -Path $scratchSrc -ChildPath 'WindowsAutoCleanup.Drivers.psm1'
        $preserved = Join-Path -Path $scratchSrc -ChildPath 'WindowsAutoCleanup.Drivers.Shipped.psm1'
        Copy-Item -LiteralPath $driverSlot -Destination $preserved -Force -ErrorAction Stop

        $maintenance = Join-Path -Path $script:TestsRoot -ChildPath '_SandboxMaintenanceFixture.psm1'
        if (-not (Test-Path -LiteralPath $maintenance -PathType Leaf)) {
            throw ('the sandbox maintenance fixture is missing at {0}; refusing to launch a child that would service this machine' -f $maintenance)
        }
        Copy-Item -LiteralPath $maintenance -Destination $driverSlot -Force -ErrorAction Stop

        # Proven, not assumed, for the same reason the allow-list injection is: a copy that silently
        # failed would leave the SHIPPED maintenance entry points in place and the child would run
        # the real DISM, pnpclean and Delivery Optimization purge - the exact defect this closes.
        $maintenanceMarker = 'Write-WacMaintenanceWitness'
        if (([System.IO.File]::ReadAllText($driverSlot)).IndexOf($maintenanceMarker, [System.StringComparison]::Ordinal) -lt 0) {
            throw ('the maintenance entry points in {0} are not the sandbox fixture; refusing to launch the child' -f $driverSlot)
        }
        if (-not (Test-Path -LiteralPath $preserved -PathType Leaf)) {
            throw ('the shipped driver module was not preserved at {0}; refusing to launch the child' -f $preserved)
        }
    }

    $runPath = Join-Path -Path $scratch -ChildPath 'Run.ps1'
    if (-not (Test-Path -LiteralPath $runPath -PathType Leaf)) {
        throw ('the scratch copy of Run.ps1 was not created at {0}' -f $runPath)
    }
    return $runPath
}

function Get-RunChildCommandLine {
    <#
    .SYNOPSIS
        The pre-quoted command line for one Run.ps1 child.
    .DESCRIPTION
        Built through the shipped Get-WacRelaunchArgument, so the child is launched exactly the way
        Run.ps1 launches its own elevated relaunch: -Command rather than -File, because -File cannot
        carry '-Switch:$false' on Windows PowerShell 5.1 and collapses an array into one string.
    .PARAMETER ScriptPath
        The Run.ps1 to launch - always the scratch copy from New-VerificationScratchTree, so the
        child loads the injected fixture rather than the real allow-list builder.
    .PARAMETER SkipCategory
        Kept because Run.ps1 takes it, and deliberately no longer load-bearing. Scoping the child by
        category name is the defect the fixture replaced; containment, not naming, is what confines
        it now.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$MutexName,
        [AllowEmptyCollection()][string[]]$SkipCategory = @(),
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

    $vector = Get-WacRelaunchArgument -ScriptPath $ScriptPath -HostSwitch @('-NonInteractive') `
        -BooleanSwitch $booleanSwitch -PresentSwitch @('Scheduled') -NamedValue $namedValue `
        -ArrayValue @{ SkipCategory = $SkipCategory }

    return (ConvertTo-WacCommandLine -ArgumentList $vector)
}

function Test-ChildMaintenanceFixture {
    <#
    .SYNOPSIS
        $true when the scratch tree this child would run carries the maintenance fixture.
    .DESCRIPTION
        Read from the ENVIRONMENT the child is about to be given, because that is the only thing
        that is true of the child rather than of whatever the caller believes it prepared. The
        sandbox root it authorises is the sandbox the scratch tree lives in, so the driver slot the
        child will import is reachable from it without a second parameter that could disagree.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Environment)

    if (-not $Environment.ContainsKey('WAC_VERIFY_SANDBOX_ROOT')) { return $false }

    $sandbox = [string]$Environment['WAC_VERIFY_SANDBOX_ROOT']
    if ([string]::IsNullOrWhiteSpace($sandbox)) { return $false }

    $driverSlot = Join-Path -Path $sandbox -ChildPath 'SRC\src\WindowsAutoCleanup.Drivers.psm1'
    if (-not (Test-Path -LiteralPath $driverSlot -PathType Leaf)) { return $false }

    return (([System.IO.File]::ReadAllText($driverSlot)).IndexOf('Write-WacMaintenanceWitness', [System.StringComparison]::Ordinal) -ge 0)
}

function Start-VerificationChild {
    <#
    .SYNOPSIS
        Starts one Run.ps1 child and immediately begins draining both of its pipes.
    .DESCRIPTION
        THE LAUNCH GATE (ledger WAC-10R). A child whose scratch tree has no maintenance fixture will
        run the real DISM, the real pnpclean handler and the real Delivery Optimization purge on
        this machine, whatever the scenario calls itself. So launching one is refused here unless
        the caller states that intent by name, and the refusal happens before the process exists.

        It is on the launch, not on New-VerificationScratchTree, because the copy is harmless and
        the launch is not - and because a scenario author who forgets -InterceptMaintenance gets a
        loud refusal rather than a scenario that quietly services the operator's machine and
        reports sandbox scope, which is the defect this closes.
    .PARAMETER AllowRealMaintenance
        This child is MEANT to service the machine. Only DRIVERS, CLEANMGR and the armed
        MAINTENANCE lane pass it, and each of those records its row as machine-changing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        [switch]$AllowRealMaintenance
    )

    if (-not $AllowRealMaintenance -and -not (Test-ChildMaintenanceFixture -Environment $Environment)) {
        throw ('the scratch tree for this child carries no maintenance fixture, so it would run the ' +
            'real DISM, pnpclean and Delivery Optimization purge on this machine; refusing to launch it. ' +
            'Build the tree with -InterceptMaintenance, or declare the scenario machine-changing with ' +
            '-AllowRealMaintenance.')
    }

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
        # DRIVERS, CLEANMGR and MAINTENANCE change the operator's real machine. The flag rides on
        # the record so the console summary and the JSON result both say which rows did, rather
        # than relying on the reader remembering which names are sandboxed.
        [switch]$Machine,
        # What the row actually DID, which a pass alone never says (ledger WAC-10R). A lane that
        # refused because it was not armed passes its own guard and has validated nothing, so the
        # two are recorded as different words rather than as the same green:
        #   Executed    the work in the row's name really ran
        #   NotArmed    the lane is gated and the gate was closed; nothing was touched
        #   Unsupported this machine cannot run the lane at all
        #   Failed      the work ran and did not finish
        [ValidateSet('Executed', 'NotArmed', 'Unsupported', 'Failed')][string]$Execution = 'Executed'
    )

    return [PSCustomObject]@{
        Name             = $Name
        Machine          = [bool]$Machine
        Execution        = $Execution
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
