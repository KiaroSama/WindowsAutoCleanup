#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end tests for the two entry-point scripts, plus the standing proof that the removed
    ACL-hardening capability has not come back (ledger P0-6 / U-2, P1-12).

.DESCRIPTION
    The entry points are executed for real, in a child process whose %ProgramFiles%, %ProgramData%
    and %SystemRoot% point into a disposable sandbox. No canonical PowerShell host is findable
    there, so the elevation branch has to fail closed with exit code 4 and nothing is registered,
    deployed or deleted anywhere.

    That child is started through runas /trustlevel:0x20000, which hands it a Basic User token. The
    test therefore never depends on how the test process itself is running: an ELEVATED runner (all
    of GitHub's windows-latest images) would otherwise walk straight past the elevation branch and
    into code that talks to the live Task Scheduler. Every child is bounded by a wall-clock
    deadline, and its process tree is killed if it overruns.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# The log line shape every runtime record has to have: UTC stamp, level, component.
$script:LogLinePattern = '^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\] \[(DEBUG|INFO|WARNING|ERROR|CRITICAL)\] \[[A-Za-z]+\] \S'

function Get-TestHostPath {
    $name = 'powershell.exe'
    if ($PSVersionTable.PSEdition -eq 'Core') { $name = 'pwsh.exe' }
    return (Join-Path -Path $PSHOME -ChildPath $name)
}

function ConvertTo-WrapperLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return ("'" + $Value.Replace("'", "''") + "'")
}

function Wait-ChildProcessExit {
    <#
    .SYNOPSIS
        Waits, bounded, for the process whose id the wrapper recorded. Returns $true when it is gone.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$PidFile,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 20
    )

    if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) { return $true }

    $childId = 0
    if (-not [int]::TryParse(([System.IO.File]::ReadAllText($PidFile).Trim()), [ref]$childId)) { return $true }
    if ($childId -le 0) { return $true }

    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([datetime]::UtcNow -lt $deadline) {
        try { $null = [System.Diagnostics.Process]::GetProcessById($childId) }
        catch { return $true }
        Start-Sleep -Milliseconds 100
    }

    return $false
}

function Start-BoundedWrapper {
    <#
    .SYNOPSIS
        Starts one launcher, waits for it, then waits, bounded, for the wrapper's result file.
    .DESCRIPTION
        runas hands its child off instead of waiting for it, so the exit code has to arrive through
        a file the wrapper writes last. Both waits are bounded; the bound expiring IS the detected
        failure, and the caller kills the recorded process tree.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$ResultFile,
        [Parameter(Mandatory = $true)][string]$Label,
        [ValidateRange(5, 600)][int]$TimeoutSeconds = 45
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # Never the sandbox: a child's current directory holds a lock that would defeat its own cleanup.
    $psi.WorkingDirectory = $script:RepoRoot

    $diagnostic = ''
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    $launcher = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdout = $launcher.StandardOutput.ReadToEndAsync()
        $stderr = $launcher.StandardError.ReadToEndAsync()
        [void]$launcher.WaitForExit([int]($TimeoutSeconds * 1000))
        [void]$stdout.Wait(5000)
        [void]$stderr.Wait(5000)
        $diagnostic = ('[{0} exit={1}] {2}{3}' -f $Label, $launcher.ExitCode, [string]$stdout.Result, [string]$stderr.Result)
    }
    finally {
        try { $launcher.Dispose() } catch { $null = $_ }
    }

    while (-not (Test-Path -LiteralPath $ResultFile -PathType Leaf) -and [datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }

    return [PSCustomObject]@{
        TimedOut = -not (Test-Path -LiteralPath $ResultFile -PathType Leaf)
        Diagnostic = $diagnostic
    }
}

function Invoke-SandboxedEntryPoint {
    <#
    .SYNOPSIS
        Runs one entry point in a de-elevated, environment-redirected, bounded child process.
    .OUTPUTS
        ExitCode, Output, LogDirectory, DeploymentRoot, TimedOut, ChildExited, Diagnostic.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$ScriptName,
        [AllowEmptyCollection()][string[]]$EntryArgument = @(),
        [ValidateRange(10, 600)][int]$TimeoutSeconds = 45
    )

    $programFiles = Join-Path -Path $Sandbox -ChildPath 'PF'
    $programData = Join-Path -Path $Sandbox -ChildPath 'PD'
    $localAppData = Join-Path -Path $Sandbox -ChildPath 'LA'
    $systemRoot = Join-Path -Path $Sandbox -ChildPath 'WIN'
    foreach ($directory in @($programFiles, $programData, $systemRoot)) {
        [void][System.IO.Directory]::CreateDirectory($directory)
    }

    $wrapper = Join-Path -Path $Sandbox -ChildPath 'wrapper.ps1'
    $outFile = Join-Path -Path $Sandbox -ChildPath 'child.out'
    $resultFile = Join-Path -Path $Sandbox -ChildPath 'child.exit'
    $pidFile = Join-Path -Path $Sandbox -ChildPath 'child.pid'
    $entryPoint = Join-Path -Path $script:RepoRoot -ChildPath $ScriptName

    # A sandbox may be reused for a second run; a stale result file would be read as this run's.
    foreach ($stale in @($outFile, $resultFile, $pidFile)) {
        if (Test-Path -LiteralPath $stale -PathType Leaf) { [System.IO.File]::Delete($stale) }
    }

    # The wrapper, not the parent, redirects the environment: runas.exe itself has to keep the real
    # %SystemRoot% to be found and to start anything.
    $lines = @(
        ('$env:ProgramFiles = {0}' -f (ConvertTo-WrapperLiteral -Value $programFiles)),
        ('$env:ProgramData = {0}' -f (ConvertTo-WrapperLiteral -Value $programData)),
        # An UNELEVATED run deliberately logs under the user's own profile rather than creating
        # %ProgramData%\WindowsAutoCleanup: the creator of that directory becomes its owner and, via
        # CREATOR OWNER inheritance, gains full control of the tree the SYSTEM task later writes its
        # audit log into. These entry-point cases run de-elevated, so redirect LOCALAPPDATA too and
        # assert there.
        ('$env:LOCALAPPDATA = {0}' -f (ConvertTo-WrapperLiteral -Value $localAppData)),
        ('$env:SystemRoot = {0}' -f (ConvertTo-WrapperLiteral -Value $systemRoot)),
        ('[System.IO.File]::WriteAllText({0}, [string]$PID)' -f (ConvertTo-WrapperLiteral -Value $pidFile)),
        '$code = 90',
        'try {',
        ('    & {0} {1} *> {2}' -f (ConvertTo-WrapperLiteral -Value $entryPoint), ($EntryArgument -join ' '),
            (ConvertTo-WrapperLiteral -Value $outFile)),
        '    if ($null -ne $LASTEXITCODE) { $code = [int]$LASTEXITCODE }',
        '}',
        'catch {',
        '    $code = 91',
        ('    [System.IO.File]::AppendAllText({0}, ($_ | Out-String))' -f (ConvertTo-WrapperLiteral -Value $outFile)),
        '}',
        ('[System.IO.File]::WriteAllText({0}, [string]$code)' -f (ConvertTo-WrapperLiteral -Value $resultFile)),
        'exit $code'
    )
    [System.IO.File]::WriteAllLines($wrapper, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))

    $hostArguments = ConvertTo-WacCommandLine -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wrapper)
    $childCommand = ConvertTo-WacCommandLine -ArgumentList @(
        (Get-TestHostPath), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wrapper)

    $attempt = Start-BoundedWrapper -Label 'runas' -TimeoutSeconds $TimeoutSeconds -ResultFile $resultFile `
        -FileName (Join-Path -Path $env:SystemRoot -ChildPath 'System32\runas.exe') `
        -Arguments (ConvertTo-WacCommandLine -ArgumentList @('/trustlevel:0x20000', $childCommand))

    # If the Safer basic-user token is unavailable, an ordinary child of an unelevated parent is
    # already unelevated and is just as safe. From an ELEVATED parent it is NOT, so there is no
    # fallback there: the entry points would reach the live Task Scheduler.
    if ($attempt.TimedOut -and -not (Test-WacIsAdministrator)) {
        $direct = Start-BoundedWrapper -Label 'direct' -TimeoutSeconds $TimeoutSeconds -ResultFile $resultFile `
            -FileName (Get-TestHostPath) -Arguments $hostArguments
        $attempt = [PSCustomObject]@{
            TimedOut = $direct.TimedOut
            Diagnostic = ('{0} {1}' -f $attempt.Diagnostic, $direct.Diagnostic)
        }
    }

    $timedOut = $attempt.TimedOut
    $diagnostic = $attempt.Diagnostic
    if ($timedOut) {
        # Never leave an orphan behind, even when the child is not in this process's tree.
        try {
            if (Test-Path -LiteralPath $pidFile -PathType Leaf) {
                [void](Stop-WacProcessTree -ProcessId ([int]([System.IO.File]::ReadAllText($pidFile).Trim())))
            }
        }
        catch {
            $null = $_
        }
    }

    $exitCode = $null
    $childExited = $false
    if (-not $timedOut) {
        $exitCode = [int]([System.IO.File]::ReadAllText($resultFile).Trim())
        # The result file is the wrapper's last write, so the process is about to go. Waiting for it
        # is what lets the sandbox be deleted, and is the only way to prove nothing was left running.
        $childExited = Wait-ChildProcessExit -PidFile $pidFile -TimeoutSeconds 20
    }

    $output = ''
    if (Test-Path -LiteralPath $outFile -PathType Leaf) { $output = [System.IO.File]::ReadAllText($outFile) }

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output = $output
        LogDirectory = (Join-Path -Path $localAppData -ChildPath 'WindowsAutoCleanup\Logs')
        MachineLogDirectory = (Join-Path -Path $programData -ChildPath 'WindowsAutoCleanup\Logs')
        DeploymentRoot = (Join-Path -Path $programFiles -ChildPath 'WindowsAutoCleanup')
        TimedOut = $timedOut
        ChildExited = $childExited
        Diagnostic = $diagnostic
    }
}

function Get-SingleRunLog {
    <#
    .SYNOPSIS
        Asserts that a run produced exactly one log file, and returns its text.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$BaseName
    )

    Assert-True (Test-Path -LiteralPath $Directory -PathType Container) ('no log directory was created at {0}' -f $Directory)
    $logs = @(Get-ChildItem -LiteralPath $Directory -Filter ('{0}_*.log' -f $BaseName) -File)
    Assert-Equal 1 $logs.Count ('log files found: ' + ((@($logs | ForEach-Object { $_.Name })) -join ', '))

    return [System.IO.File]::ReadAllText($logs[0].FullName)
}

function Assert-LogLineShape {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Component
    )

    $lines = @(($Text -split "`r?`n") | Where-Object { $_.Trim() })
    Assert-True ($lines.Count -gt 0) 'the log file is empty'

    foreach ($line in $lines) {
        Assert-True ($line -match $script:LogLinePattern) ('malformed log line: ' + $line)
    }

    $ours = @($lines | Where-Object { $_ -match ('\] \[{0}\] ' -f [regex]::Escape($Component)) })
    Assert-True ($ours.Count -gt 0) ('no line carried the [{0}] component' -f $Component)
}

# ---------------------------------------------------------------------------------------------
# Entry points: the elevation branch fails closed (ledger P1-12)
# ---------------------------------------------------------------------------------------------

Test-Case 'The installer exits 4, logs the failure and deploys nothing when no trusted host exists' {
    $sandbox = New-TestSandbox -Prefix 'entry-install'
    try {
        $run = Invoke-SandboxedEntryPoint -Sandbox $sandbox -ScriptName 'Install-WindowsAutoCleanupTask.ps1' `
            -EntryArgument @('-NoPause', '-ResetWindowsUpdateBase:$false')

        Assert-False $run.TimedOut ('the installer never finished inside its bound. ' + $run.Diagnostic)
        Assert-Equal 4 $run.ExitCode ($run.Output + $run.Diagnostic)
        Assert-True $run.ChildExited 'the installer process was still running after it reported its exit code'
        Assert-False (Test-Path -LiteralPath $run.DeploymentRoot) 'a failed elevation still deployed the runtime'

        $log = Get-SingleRunLog -Directory $run.LogDirectory -BaseName 'Install-WindowsAutoCleanupTask'
        Assert-LogLineShape -Text $log -Component 'Installer'
        Assert-True ($log -match 'No machine-trusted PowerShell host') $log
        Assert-True ($log -match 'explicitParameters=NoPause,ResetWindowsUpdateBase') 'the explicit parameters were not recorded'
        Assert-False ($log -match 'Requesting elevation\.') 'elevation was attempted without a trusted host'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The uninstaller exits 4, logs the failure and removes nothing when no trusted host exists' {
    $sandbox = New-TestSandbox -Prefix 'entry-uninstall'
    try {
        $run = Invoke-SandboxedEntryPoint -Sandbox $sandbox -ScriptName 'Uninstall-WindowsAutoCleanupTask.ps1' `
            -EntryArgument @('-NoPause')

        Assert-False $run.TimedOut ('the uninstaller never finished inside its bound. ' + $run.Diagnostic)
        Assert-Equal 4 $run.ExitCode ($run.Output + $run.Diagnostic)
        Assert-True $run.ChildExited 'the uninstaller process was still running after it reported its exit code'
        Assert-False (Test-Path -LiteralPath $run.DeploymentRoot) 'the uninstaller created a deployment root'

        $log = Get-SingleRunLog -Directory $run.LogDirectory -BaseName 'Uninstall-WindowsAutoCleanupTask'
        Assert-LogLineShape -Text $log -Component 'Uninstaller'
        Assert-True ($log -match 'No machine-trusted PowerShell host') $log
        Assert-False ($log -match 'Requesting elevation\.') 'elevation was attempted without a trusted host'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Each entry-point run gets its own log file rather than sharing one' {
    $sandbox = New-TestSandbox -Prefix 'entry-twice'
    try {
        $first = Invoke-SandboxedEntryPoint -Sandbox $sandbox -ScriptName 'Uninstall-WindowsAutoCleanupTask.ps1' -EntryArgument @('-NoPause')
        Assert-Equal 4 $first.ExitCode ($first.Output + $first.Diagnostic)

        $second = Invoke-SandboxedEntryPoint -Sandbox $sandbox -ScriptName 'Uninstall-WindowsAutoCleanupTask.ps1' -EntryArgument @('-NoPause')
        Assert-Equal 4 $second.ExitCode ($second.Output + $second.Diagnostic)

        $logs = @(Get-ChildItem -LiteralPath $second.LogDirectory -Filter 'Uninstall-WindowsAutoCleanupTask_*.log' -File)
        Assert-Equal 2 $logs.Count 'the second run overwrote or reused the first run log'
        foreach ($log in $logs) {
            Assert-True ($log.Length -gt 0) ('{0} is empty' -f $log.Name)
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# The ACL-hardening capability stays deleted (ledger P0-6 / U-2)
# ---------------------------------------------------------------------------------------------

function Get-ShippedCodeToken {
    <#
    .SYNOPSIS
        Every non-comment token of one shipped file.
    .DESCRIPTION
        Comments are dropped deliberately: the modules DOCUMENT which APIs they never call, so a
        plain text search would report that documentation as a violation.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)

    Assert-Equal 0 @($errors).Count ('{0} does not parse' -f $Path)
    return @(@($tokens) | Where-Object { $_.Kind -ne 'Comment' })
}

function Get-ShippedFile {
    $files = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in @('Run.ps1', 'Install-WindowsAutoCleanupTask.ps1', 'Uninstall-WindowsAutoCleanupTask.ps1')) {
        [void]$files.Add((Join-Path -Path $script:RepoRoot -ChildPath $name))
    }
    foreach ($module in @(Get-ChildItem -LiteralPath (Join-Path -Path $script:RepoRoot -ChildPath 'src') -Filter '*.psm1' -File)) {
        [void]$files.Add($module.FullName)
    }
    return @($files.ToArray())
}

Test-Case 'No shipped file contains an ACL, owner or terminal-wrapper call' {
    # Word-anchored: the read-only FileSystemRights constant TakeOwnership, and Get-Acl / GetOwner /
    # GetAccessRules, are how the module VERIFIES trust and must not be mistaken for a mutation.
    $forbidden = '(?i)(\bSet-Acl\b|\bSetOwner\b|\bSetAccessRule|\bSetAccessControl\b|\bAddAccessRule|\bRemoveAccessRule|\bicacls\b|\btakeown\b|\bwt\.exe\b)'
    $files = Get-ShippedFile

    Assert-True ($files.Count -ge 9) ('only {0} shipped files were scanned' -f $files.Count)

    foreach ($file in $files) {
        $hits = @(@(Get-ShippedCodeToken -Path $file) | Where-Object { $_.Text -match $forbidden } | ForEach-Object { $_.Text })
        Assert-Equal 0 $hits.Count ('{0}: {1}' -f (Split-Path -Leaf $file), ($hits -join ', '))
    }
}

Test-Case 'No shipped file resolves an executable through Get-Command' {
    foreach ($file in Get-ShippedFile) {
        $tokens = Get-ShippedCodeToken -Path $file

        for ($i = 0; $i -lt $tokens.Count; $i++) {
            if ($tokens[$i].Text -notmatch '(?i)^Get-Command$') { continue }

            # Only the rest of the same statement can belong to this call.
            $offending = New-Object 'System.Collections.Generic.List[string]'
            for ($j = $i + 1; $j -lt $tokens.Count -and $j -le ($i + 12); $j++) {
                if ($tokens[$j].Kind -eq 'NewLine' -or $tokens[$j].Kind -eq 'Semi') { break }
                if ($tokens[$j].Text -match '(?i)(^Application$|\.exe|\.cmd|\.bat|\.com)') { [void]$offending.Add($tokens[$j].Text) }
            }

            Assert-Equal 0 $offending.Count ('{0}:{1} resolves an executable: {2}' -f `
                (Split-Path -Leaf $file), $tokens[$i].Extent.StartLineNumber, (@($offending.ToArray()) -join ', '))
        }
    }
}

Test-Case 'The shipped-code scanner flags a real call and ignores the same words in a comment' {
    $sandbox = New-TestSandbox -Prefix 'scan-control'
    try {
        $forbidden = '(?i)(\bSet-Acl\b|\bSetOwner\b|\bSetAccessRule|\bSetAccessControl\b|\bAddAccessRule|\bRemoveAccessRule|\bicacls\b|\btakeown\b|\bwt\.exe\b)'

        $clean = Join-Path -Path $sandbox -ChildPath 'clean.ps1'
        [System.IO.File]::WriteAllLines($clean, [string[]]@(
            '# Nothing here calls Set-Acl, SetOwner, icacls or takeown.',
            '<# .SYNOPSIS Never uses wt.exe either. #>',
            '$acl = Get-Acl -LiteralPath $env:SystemRoot',
            '$rights = [System.Security.AccessControl.FileSystemRights]::TakeOwnership',
            '$null = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])',
            '$null = $rights'
        ), (New-Object System.Text.UTF8Encoding($false)))

        $dirty = Join-Path -Path $sandbox -ChildPath 'dirty.ps1'
        [System.IO.File]::WriteAllLines($dirty, [string[]]@(
            '$acl = Get-Acl -LiteralPath $env:TEMP',
            '$acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier(''S-1-5-32-544'')))',
            'Set-Acl -LiteralPath $env:TEMP -AclObject $acl'
        ), (New-Object System.Text.UTF8Encoding($false)))

        $cleanHits = @(@(Get-ShippedCodeToken -Path $clean) | Where-Object { $_.Text -match $forbidden })
        Assert-Equal 0 $cleanHits.Count (($cleanHits | ForEach-Object { $_.Text }) -join ', ')

        $dirtyHits = @(@(Get-ShippedCodeToken -Path $dirty) | Where-Object { $_.Text -match $forbidden } | ForEach-Object { $_.Text })
        Assert-Equal 2 $dirtyHits.Count ($dirtyHits -join ', ')
        Assert-True ($dirtyHits -contains 'SetOwner') ($dirtyHits -join ', ')
        Assert-True ($dirtyHits -contains 'Set-Acl') ($dirtyHits -join ', ')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
