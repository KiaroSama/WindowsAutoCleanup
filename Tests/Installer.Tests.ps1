#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end tests for the two entry-point scripts: the elevation branch that fails closed, the
    one cross-operation lock, and the ordering and rollback wiring (ledger P1-12, B2-3, T-4).

.DESCRIPTION
    The entry points are executed for real, in a child process whose %ProgramFiles%, %ProgramData%
    and %SystemRoot% point into a disposable sandbox. No canonical PowerShell host is findable
    there, so the elevation branch has to fail closed with exit code 4 and nothing is registered,
    deployed or deleted anywhere.

    That child is started under a SAFER normal-user token by Start-TestRestrictedProcess, so the
    test never depends on how the test process itself is running: an ELEVATED runner (all of
    GitHub's windows-latest images) would otherwise walk straight past the elevation branch and into
    code that talks to the live Task Scheduler. The child REPORTS the token it got and a child that
    came back elevated fails the run, because every assertion here is only worth something against
    an unprivileged one. Every child is bounded by a wall-clock deadline and killed with its tree if
    it overruns.

    The one part of the contract that cannot be proven this way - a REAL registration under the live
    scheduler - is VmTaskLifecycle.Tests.ps1, and the standing proof that the removed ACL-hardening
    capability has not come back is ShippedCodeBan.Tests.ps1.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
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

function Start-BoundedWrapper {
    <#
    .SYNOPSIS
        Runs the wrapper as a bounded child and reports whether it left its result file behind.
    .DESCRIPTION
        The wrapper is a REAL child now, whether it was started under the restricted token or, on an
        unelevated host that could not produce one, as an ordinary process. So the bound is a wait on
        its own handle, the result file is already written by the time that wait returns - the
        wrapper writes it before it exits - and an overrun is killed by handle-pinned id, which no
        recycled pid can alias while this process still holds the handle.

        Nothing is redirected: with no console there is nothing to redirect to, and everything the
        caller reads travels through files the wrapper writes.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$ResultFile,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$Restricted,
        [ValidateRange(5, 600)][int]$TimeoutSeconds = 45
    )

    # Never the sandbox as working directory: a child's current directory holds a lock that would
    # defeat its own cleanup.
    $child = $null
    $launchError = ''
    if ($Restricted) {
        $started = Start-TestRestrictedProcess -FilePath $FileName -Arguments $Arguments -WorkingDirectory $script:RepoRoot
        $child = $started.Child
        $launchError = $started.Error
    }
    else {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FileName
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.WorkingDirectory = $script:RepoRoot
        try { $child = [System.Diagnostics.Process]::Start($psi) }
        catch { $child = $null; $launchError = $_.Exception.Message }
    }

    if (-not $child) {
        return [PSCustomObject]@{
            TimedOut = $true
            Exited = $false
            Diagnostic = ('[{0} did not start] {1}' -f $Label, $launchError)
        }
    }

    $exited = $false
    $exitCode = -1
    try {
        $exited = $child.WaitForExit([int]($TimeoutSeconds * 1000))
        if ($exited) { $exitCode = [int]$child.ExitCode }
        else {
            [void](Stop-WacProcessTree -ProcessId $child.Id)
            [void]$child.WaitForExit(10000)
        }
    }
    finally {
        try { $child.Dispose() } catch { $null = $_ }
    }

    return [PSCustomObject]@{
        TimedOut = -not (Test-Path -LiteralPath $ResultFile -PathType Leaf)
        Exited = $exited
        Diagnostic = ('[{0} exited={1} hostExit={2}]' -f $Label, $exited, $exitCode)
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
    $entryPoint = Join-Path -Path $script:RepoRoot -ChildPath $ScriptName

    # A sandbox may be reused for a second run; a stale result file would be read as this run's.
    foreach ($stale in @($outFile, $resultFile)) {
        if (Test-Path -LiteralPath $stale -PathType Leaf) { [System.IO.File]::Delete($stale) }
    }

    # The wrapper, not the parent, redirects the environment: %SystemRoot% has to stay real until
    # the host itself has started, and only the wrapper runs after that.
    $lines = @(
        ('$env:ProgramFiles = {0}' -f (ConvertTo-WrapperLiteral -Value $programFiles)),
        ('$env:ProgramData = {0}' -f (ConvertTo-WrapperLiteral -Value $programData)),
        # An UNELEVATED run deliberately logs under the user's own profile rather than creating
        # %ProgramData%\WindowsAutoCleanup: the creator of that directory becomes its owner and, via
        # CREATOR OWNER inheritance, gains full control of the tree the SYSTEM task later writes its
        # audit log into. These entry-point cases run de-elevated, so redirect LOCALAPPDATA too and
        # assert there.
        ('$env:LOCALAPPDATA = {0}' -f (ConvertTo-WrapperLiteral -Value $localAppData)),
        # WacNative is compiled HERE, while %SystemRoot% is still real, and the redirect follows.
        # Measured on both hosts: Windows PowerShell 5.1 compiles Add-Type by shelling out to
        # csc.exe and the strong-name provider under the REAL %SystemRoot%, so compiling after the
        # redirect fails with "Error signing assembly -- Provider DLL failed to initialize
        # correctly" and the run then produces NO log at all - which is what these three cases were
        # failing on, on 5.1 only. PowerShell 7 compiles in-process with Roslyn and never noticed.
        # The type is process-wide and Initialize-WacNative is idempotent, so the entry point's own
        # later call is a no-op. Nothing about the behaviour under test is stubbed by this: it only
        # moves WHEN the compile happens, and production never redirects %SystemRoot%.
        ('. {0}' -f (ConvertTo-WrapperLiteral -Value (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Native.ps1'))),
        'if (-not (Initialize-WacNative)) { throw ''the native surface would not compile before the redirect'' }',
        ('$env:SystemRoot = {0}' -f (ConvertTo-WrapperLiteral -Value $systemRoot)),
        # The token this child actually got. Everything asserted about an unelevated run is worth
        # nothing if the de-elevation quietly stopped working, so the child reports the token it
        # holds and the caller fails on it instead of trusting the API that handed it out.
        '$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())',
        '$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
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
        ('[System.IO.File]::WriteAllText({0}, ("ADMIN=$admin" + [Environment]::NewLine + "EXIT=$code"))' -f `
            (ConvertTo-WrapperLiteral -Value $resultFile)),
        'exit $code'
    )
    [System.IO.File]::WriteAllLines($wrapper, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))

    $hostArguments = ConvertTo-WacCommandLine -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wrapper)

    $attempt = Start-BoundedWrapper -Label 'restricted' -Restricted -TimeoutSeconds $TimeoutSeconds `
        -ResultFile $resultFile -FileName (Get-TestHostPath) -Arguments $hostArguments

    # If the Safer normal-user token is unavailable, an ordinary child of an unelevated parent is
    # already unelevated and is just as safe. From an ELEVATED parent it is NOT, so there is no
    # fallback there: the entry points would reach the live Task Scheduler.
    if ($attempt.TimedOut -and -not (Test-WacIsAdministrator)) {
        $direct = Start-BoundedWrapper -Label 'direct' -TimeoutSeconds $TimeoutSeconds -ResultFile $resultFile `
            -FileName (Get-TestHostPath) -Arguments $hostArguments
        $attempt = [PSCustomObject]@{
            TimedOut = $direct.TimedOut
            Exited = $direct.Exited
            Diagnostic = ('{0} {1}' -f $attempt.Diagnostic, $direct.Diagnostic)
        }
    }

    $timedOut = $attempt.TimedOut
    $diagnostic = $attempt.Diagnostic

    $exitCode = $null
    $childElevated = $false
    if (-not $timedOut) {
        foreach ($line in @([System.IO.File]::ReadAllLines($resultFile))) {
            if ($line.StartsWith('EXIT=', [System.StringComparison]::Ordinal)) { $exitCode = [int]$line.Substring(5).Trim() }
            elseif ($line.StartsWith('ADMIN=', [System.StringComparison]::Ordinal)) {
                $childElevated = [string]::Equals($line.Substring(6).Trim(), 'True', [System.StringComparison]::Ordinal)
            }
        }

        # Asserted HERE, in the one place every case goes through, so no case can be written that
        # forgets it: an elevated child walks past the elevation branch entirely, and the exit code
        # it reports then proves nothing about the contract under test.
        Assert-False $childElevated ('the child ran ELEVATED, so it never exercised the unelevated path. ' + $diagnostic)
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
        ChildExited = $attempt.Exited
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
# One cross-operation lock: exactly one mutator proceeds (ledger B2-3, T-4)
# ---------------------------------------------------------------------------------------------

function Wait-ForTestFile {
    <#
    .SYNOPSIS
        Waits for every named file to appear, bounded by a deadline. $true when they all did.
    .DESCRIPTION
        A deadline and a short poll, never a fixed sleep: the wait ends the moment the condition
        holds, and it always ends.
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$Path,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 45
    )

    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([datetime]::UtcNow -lt $deadline) {
        $missing = @($Path | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
        if ($missing.Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

Test-Case 'Concurrent cleanup, install and uninstall contend on one lock and exactly one mutates' {
    # Ledger B2-3. The three operations used to take DIFFERENT mutex names - Run.ps1
    # 'Global\WindowsAutoCleanup', the entry points 'Global\WindowsAutoCleanupInstaller' - so a
    # cleanup run and a deployment replacement could not see each other at all.
    #
    # The name under test is a unique Local\ one, deliberately: taking the real Global\ lock from a
    # test would contend with any genuine cleanup run on this machine and make the suite depend on
    # what else is happening. That all three entry points RESOLVE the shared name is proven
    # statically in Deploy.Tests.ps1; this proves what happens when they do.
    $sandbox = New-TestSandbox -Prefix 'lock-race'
    try {
        $lockName = 'Local\WacTestLock_' + [guid]::NewGuid().ToString('N')
        $programFiles = Join-Path -Path $sandbox -ChildPath 'PF'
        $checkout = Join-Path -Path $sandbox -ChildPath 'checkout'
        $barrier = Join-Path -Path $sandbox -ChildPath 'release.flag'
        [void][System.IO.Directory]::CreateDirectory($programFiles)
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $checkout -ChildPath 'src'))
        [System.IO.File]::WriteAllText((Join-Path -Path $checkout -ChildPath 'Run.ps1'), '# run')
        [System.IO.File]::WriteAllText((Join-Path -Path $checkout -ChildPath 'src\WindowsAutoCleanup.Core.psm1'), '# core')

        # Each role does what its entry point does: take the lock first, and only mutate the
        # deployment if it got it. 'install' stages and switches; 'uninstall' deletes; 'cleanup'
        # just holds, which is what a real run does for the whole of its work.
        $driver = Join-Path -Path $sandbox -ChildPath 'contender.ps1'
        [System.IO.File]::WriteAllLines($driver, [string[]]@(
            'param([string]$Role, [string]$LockName, [string]$ProgramFiles, [string]$Checkout, [string]$Barrier, [string]$ResultFile)',
            'Set-StrictMode -Version 2.0',
            '$ErrorActionPreference = ''Stop''',
            ('Import-Module -Name {0} -Force -DisableNameChecking' -f (ConvertTo-WrapperLiteral -Value (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1'))),
            ('Import-Module -Name {0} -Force -DisableNameChecking' -f (ConvertTo-WrapperLiteral -Value (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1'))),
            '$env:ProgramFiles = $ProgramFiles',
            '$outcome = ''REFUSED''',
            '$mutex = Enter-WacSingleInstance -Name $LockName',
            'if ($mutex) {',
            '    try {',
            '        if ($Role -eq ''install'') {',
            '            [void](New-WacDeploymentStage -SourceRoot $Checkout)',
            '            [void](Switch-WacDeploymentStage)',
            '        }',
            '        elseif ($Role -eq ''uninstall'') {',
            '            [void](Remove-WacDeployment -Path (Get-WacDeploymentSlotPath).Root)',
            '        }',
            '        $outcome = ''WON''',
            '        [System.IO.File]::WriteAllText($ResultFile, $outcome)',
            '        $deadline = [datetime]::UtcNow.AddSeconds(60)',
            '        while (-not (Test-Path -LiteralPath $Barrier) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }',
            '    }',
            '    finally { Exit-WacSingleInstance -Mutex $mutex }',
            '}',
            '[System.IO.File]::WriteAllText($ResultFile, $outcome)'
        ), (New-Object System.Text.UTF8Encoding($false)))

        $roles = @('cleanup', 'install', 'uninstall')
        $results = @{}
        $children = New-Object 'System.Collections.Generic.List[object]'
        try {
            foreach ($role in $roles) {
                $resultFile = Join-Path -Path $sandbox -ChildPath ('{0}.result' -f $role)
                $results[$role] = $resultFile

                $arguments = ConvertTo-WacCommandLine -ArgumentList @(
                    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $driver,
                    '-Role', $role, '-LockName', $lockName, '-ProgramFiles', $programFiles,
                    '-Checkout', $checkout, '-Barrier', $barrier, '-ResultFile', $resultFile)

                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = (Get-TestHostPath)
                $psi.Arguments = $arguments
                $psi.UseShellExecute = $false
                $psi.CreateNoWindow = $true
                $psi.WorkingDirectory = $script:RepoRoot
                [void]$children.Add([System.Diagnostics.Process]::Start($psi))
            }

            Assert-True (Wait-ForTestFile -Path @($results.Values) -TimeoutSeconds 60) `
                'not every contender reported before its deadline'

            # The winner holds the lock until this flag appears, so the losers cannot have been
            # refused merely because they were slow - the lock was genuinely held while they tried.
            [System.IO.File]::WriteAllText($barrier, 'go')

            foreach ($child in $children) {
                Assert-True ($child.WaitForExit(30000)) 'a contender was still running after its deadline'
                Assert-Equal 0 ([int]$child.ExitCode) 'a contender exited non-zero'
            }
        }
        finally {
            foreach ($child in $children) {
                try { if (-not $child.HasExited) { [void](Stop-WacProcessTree -ProcessId $child.Id) } } catch { $null = $_ }
                try { $child.Dispose() } catch { $null = $_ }
            }
        }

        $outcomes = @{}
        foreach ($role in $roles) { $outcomes[$role] = [System.IO.File]::ReadAllText($results[$role]).Trim() }
        $won = @($roles | Where-Object { $outcomes[$_] -eq 'WON' })
        $refused = @($roles | Where-Object { $outcomes[$_] -eq 'REFUSED' })

        Assert-Equal 1 $won.Count ('exactly one mutator may proceed; outcomes: ' + (($roles | ForEach-Object { '{0}={1}' -f $_, $outcomes[$_] }) -join ', '))
        Assert-Equal 2 $refused.Count (($roles | ForEach-Object { '{0}={1}' -f $_, $outcomes[$_] }) -join ', ')

        # And whatever the winner was, the deployment is never left half-written: either it is not
        # there at all, or it is complete and matches the manifest that was staged with it.
        $savedProgramFiles = $env:ProgramFiles
        try {
            $env:ProgramFiles = $programFiles
            $slots = Get-WacDeploymentSlotPath
            $ownership = Get-WacDeploymentOwnership -DeploymentRoot $slots.Root

            Assert-True (@('Absent', 'Managed') -contains $ownership.Kind) `
                ('the deployment was left in a {0} state after the race: {1}' -f $ownership.Kind, [string]$ownership.Reason)
            Assert-False $ownership.Tampered ('a partially written deployment survived the race: ' + ((@($ownership.Findings)) -join '; '))
            Assert-False (Test-Path -LiteralPath $slots.Staging) 'a staging slot was left behind by the race'
            if ($won[0] -eq 'install') {
                Assert-Equal 'Managed' $ownership.Kind ([string]$ownership.Reason)
                Assert-True (Test-Path -LiteralPath (Join-Path -Path $slots.Root -ChildPath 'src\WindowsAutoCleanup.Core.psm1') -PathType Leaf) `
                    'the winning install left an incomplete tree'
            }
        }
        finally {
            $env:ProgramFiles = $savedProgramFiles
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Ordering and rollback wiring (ledger B2-3)
#
# These are AST assertions rather than runtime ones, and deliberately so: both branches only exist
# in an ELEVATED run that talks to the live Task Scheduler, which is not something to execute on a
# workstation. Each of them is a gate a reviewer has removed before with the suite still green.
# ---------------------------------------------------------------------------------------------

function Get-EntryPointAst {
    param([Parameter(Mandatory = $true)][string]$Name)

    $path = Join-Path -Path $script:RepoRoot -ChildPath $Name
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 @($errors).Count ('{0} does not parse' -f $Name)
    return $ast
}

function Get-CallOffset {
    <#
    .SYNOPSIS
        The start offset of every call to a named command, in source order.
    #>
    param(
        [Parameter(Mandatory = $true)]$Ast,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $commands = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true))

    return @($commands | Where-Object { $_.GetCommandName() -eq $Name } | ForEach-Object { [int]$_.Extent.StartOffset } | Sort-Object)
}

function Get-EntryPointMain {
    <#
    .SYNOPSIS
        The Invoke-Main definition of one entry point.
    .DESCRIPTION
        Every ordering assertion below is about the order things HAPPEN, which is the order of calls
        inside Invoke-Main - not the order in which the helper functions those calls reach are
        defined higher up the file. Scoping the search here is what lets the rollback path have its
        own Register-ScheduledTask without that being mistaken for a second registration.
    #>
    param([Parameter(Mandatory = $true)]$Ast)

    $main = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Main'
    }, $true))

    Assert-Equal 1 $main.Count 'the entry point no longer has exactly one Invoke-Main'
    return $main[0]
}

Test-Case 'The installer resolves the existing task BEFORE it switches the new tree into place' {
    # The window this closes: copying over the live deployment first leaves the OLD task able to
    # start against the NEW files. Staging is fine - it writes to a different directory - but the
    # SWITCH must come after the old registration is gone.
    $ast = Get-EntryPointMain -Ast (Get-EntryPointAst -Name 'Install-WindowsAutoCleanupTask.ps1')

    $stage = @(Get-CallOffset -Ast $ast -Name 'New-WacDeploymentStage')
    $resolve = @(Get-CallOffset -Ast $ast -Name 'Resolve-ConflictingTask')
    $switch = @(Get-CallOffset -Ast $ast -Name 'Switch-WacDeploymentStage')
    $register = @(Get-CallOffset -Ast $ast -Name 'Register-ScheduledTask')

    Assert-Equal 1 $stage.Count 'the installer no longer stages the deployment exactly once'
    Assert-Equal 1 $switch.Count 'the installer no longer switches the staged tree exactly once'
    Assert-Equal 1 $register.Count 'the installer no longer registers the task exactly once'
    Assert-True ($resolve.Count -ge 1) 'the installer no longer resolves the existing task at all'

    Assert-True ($resolve[0] -lt $switch[0]) 'the new tree is switched into place before the old task is resolved'
    Assert-True ($switch[0] -lt $register[0]) 'the task is registered before the tree it runs is live'
    Assert-True ($stage[0] -lt $switch[0]) 'the tree is switched in before it is staged'

    # And the swap itself has to sit INSIDE the try whose catch rolls back, or a failure in the
    # switch, or in the walk that proves what went live, exits without restoring anything.
    $rollbackTry = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.TryStatementAst]
    }, $true) | Where-Object { $_.Extent.Text -match 'Undo-Installation' })
    Assert-Equal 1 $rollbackTry.Count 'the installer no longer has exactly one try whose catch rolls back'
    Assert-True ($switch[0] -gt [int]$rollbackTry[0].Extent.StartOffset -and $switch[0] -lt [int]$rollbackTry[0].Extent.EndOffset) `
        'the swap happens outside the try that rolls back, so a failed swap restores nothing'

    # Verification of the staged tree has to happen while it is still staged.
    $verify = @(Get-CallOffset -Ast $ast -Name 'Test-WacDeploymentTrusted')
    Assert-Equal 1 $verify.Count 'the installer no longer verifies trust exactly once'
    Assert-True ($stage[0] -lt $verify[0] -and $verify[0] -lt $switch[0]) `
        'the trust check no longer sits between staging and the switch, so an untrusted tree can go live'
}

Test-Case 'A failed registration rolls the installer back instead of leaving a half-installed machine' {
    $ast = Get-EntryPointAst -Name 'Install-WindowsAutoCleanupTask.ps1'

    $keepPrevious = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true) | Where-Object {
        $_.GetCommandName() -eq 'Switch-WacDeploymentStage' -and $_.Extent.Text -match '(?i)-KeepPrevious'
    })
    Assert-Equal 1 $keepPrevious.Count 'the previous tree is discarded at the swap, so a later failure has nothing to roll back to'

    # The rollback must be reachable from a catch, not from the happy path.
    $catches = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CatchClauseAst]
    }, $true) | Where-Object { $_.Extent.Text -match 'Undo-Installation' })
    Assert-True ($catches.Count -ge 1) 'no catch clause rolls the installation back'

    # And the previous tree is only discarded after everything has been asserted.
    $main = Get-EntryPointMain -Ast $ast
    $discard = @(Get-CallOffset -Ast $main -Name 'Remove-WacDeploymentPrevious')
    $assert = @(Get-CallOffset -Ast $main -Name 'Assert-RegisteredTask')
    Assert-Equal 1 $discard.Count
    Assert-True ($assert.Count -ge 1) 'the installer no longer reads the registered task back'
    Assert-True ($assert[0] -lt $discard[0]) 'the rollback point is thrown away before the task is verified'
}

Test-Case 'The uninstaller keeps the deployment files whenever a task could still reach them' {
    # Ledger B2-3. Deleting the tree while a registration still points at it converts a recoverable
    # state into a scheduled task that fails every night with a missing file.
    $ast = Get-EntryPointAst -Name 'Uninstall-WindowsAutoCleanupTask.ps1'

    $removals = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true) | Where-Object { $_.GetCommandName() -eq 'Remove-InstalledDeployment' })
    Assert-Equal 1 $removals.Count 'the deployment removal is no longer a single guarded call'

    $guards = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.IfStatementAst]
    }, $true) | Where-Object {
        $_.Extent.Text -match 'Remove-InstalledDeployment' -and
        $_.Extent.Text -match 'Test-WacTaskReferencesRoot' -and
        $_.Extent.Text -match '\$tasks\.Clean'
    })
    Assert-Equal 1 $guards.Count `
        'the deployment removal is no longer gated on both a clean task removal and nothing still referencing the tree'

    $text = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath 'Uninstall-WindowsAutoCleanupTask.ps1'))
    Assert-True ($text -match 'Get-WacDeploymentOwnership') 'the uninstaller deletes the deployment without proving it owns it'
    Assert-True ($text -match '(?s)Refused[\s\S]{0,600}?return 7') 'a refusal no longer produces the documented exit code 7'
}

Test-Case 'Both entry points map an undurable audit log to a non-success exit' {
    foreach ($name in @('Install-WindowsAutoCleanupTask.ps1', 'Uninstall-WindowsAutoCleanupTask.ps1')) {
        $text = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath $name))
        $ast = Get-EntryPointAst -Name $name

        Assert-True ($text -match '(?s)Get-WacLogHealth[\s\S]{0,900}?return 6') `
            ('{0} still reports success when its audit log was lost' -f $name)

        # Get-WacLogPath is $null exactly when logging failed, and Split-Path -Parent $null is a
        # terminating parameter-binding error on both shipped hosts (measured), so the retention
        # call used to kill the run that was reporting the log failure. Asserted over the AST, not
        # the text: the fix is DOCUMENTED in a comment in both files, and a text scan reads that
        # documentation as the defect it describes.
        $offending = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | Where-Object {
            $_.GetCommandName() -eq 'Split-Path' -and $_.Extent.Text -match 'Get-WacLogPath'
        })
        Assert-Equal 0 $offending.Count `
            ('{0} still derives the log directory in the way that throws when there is no log' -f $name)

        $safe = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst]
        }, $true) | Where-Object { $_.GetCommandName() -eq 'Get-WacLogDirectory' })
        Assert-True ($safe.Count -ge 1) ('{0} does not use the null-safe log directory helper' -f $name)
    }
}

Complete-TestRun
