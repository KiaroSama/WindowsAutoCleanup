<#
.SYNOPSIS
    Scheduled-task identity: which task is ours, the exact command lines the task and the installer's
    elevated relaunch run, and the verified removal of a task that passes the proof.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Deploy.psm1; see that file for why the parts are dot-sourced
    rather than imported. v1.1.0 registered with -Force and unregistered by name alone, so any
    unrelated task called WindowsAutoCleanup was silently replaced or deleted (ledger P0-4). Nothing
    here acts on a task that Test-WacTaskIsOurs has not proven belongs to this project.

    The task constants are declared here because the sentinel and the two descriptions ARE the
    identity. All parts share one session state, so a read from another part is the same variable.
#>

$script:TaskName = 'WindowsAutoCleanup'
$script:TaskFolder = '\WindowsAutoCleanup\'

# Register-ScheduledTask exposes only -Description, so a fixed sentinel inside the description is
# the sole ownership marker a PowerShell-only installer can write. Never change this value: an
# installed task with the old sentinel would stop being recognised as ours.
$script:TaskSentinel = 'WindowsAutoCleanupTaskId=9d1f6d2a-6d3a-4f77-9a41-2f2b0f1f5c10'

$script:TaskDescriptionText = 'Runs WindowsAutoCleanup daily to remove allow-listed temporary and cache locations from drive C:.'

# The exact description v1.0.0/v1.1.0 wrote at the ROOT task path. Used only to adopt that task.
$script:LegacyTaskDescription = 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.'

function Get-WacTaskName { return $script:TaskName }
function Get-WacTaskFolder { return $script:TaskFolder }
function Get-WacTaskSentinel { return $script:TaskSentinel }
function Get-WacTaskDescription { return ('{0} {1}' -f $script:TaskDescriptionText, $script:TaskSentinel) }

# ---------------------------------------------------------------------------------------------
# Scheduled-task identity
# ---------------------------------------------------------------------------------------------

function Test-WacTaskExecuteIsCanonicalHost {
    <#
    .SYNOPSIS
        True when a task action's Execute is one of the canonical machine-wide PowerShell hosts.
    .DESCRIPTION
        Ownership proof has to cover WHAT runs, not only which script it is pointed at. Accepting any
        rooted Execute means a task carrying our sentinel could run a user-writable binary as SYSTEM
        and still be judged "ours", which is the escalation the sentinel exists to prevent.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Execute)

    $normalized = Get-WacNormalizedPath -Path $Execute
    if (-not $normalized) { return $false }

    $canonical = New-Object 'System.Collections.Generic.List[string]'
    if ($env:ProgramFiles) {
        [void]$canonical.Add((Get-WacNormalizedPath -Path (Join-Path -Path $env:ProgramFiles -ChildPath 'PowerShell\7\pwsh.exe')))
    }
    [void]$canonical.Add((Get-WacNormalizedPath -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe')))

    foreach ($host51 in $canonical) {
        if ($host51 -and $normalized -ieq $host51) { return $true }
    }

    return $false
}

function Get-WacTaskScriptPath {
    <#
    .SYNOPSIS
        The normalised script path a task action runs, or $null.
    .DESCRIPTION
        Pure, so ownership proof can be asserted on directly instead of through a registered task.

        Two shapes have to be understood, and both matter:
          * `-Command "& '<path>' ..."` - what this version registers, because -File cannot carry a
            valued switch to Windows PowerShell 5.1 at all (see Core's Get-WacRelaunchArgument);
          * `-File <path>` - what versions before 1.2.0 registered. Still parsed so the legacy
            migration path can prove a pre-1.2 task belongs to this project before adopting it.
        Anything else returns $null, and ownership then fails closed.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Arguments)

    if ([string]::IsNullOrWhiteSpace($Arguments)) { return $null }

    # The -Command payload seeds $LASTEXITCODE, then calls the script with the call operator and a
    # single-quoted literal in which an embedded quote is doubled. Match the call operator wherever
    # it appears in the payload rather than assuming it comes first, so a future prologue statement
    # cannot silently break the ownership proof.
    $command = [regex]::Match($Arguments, "(?i)(?:^|\s)-Command\s+.*?&\s+'(?<path>(?:[^']|'')+)'")
    if ($command.Success) {
        return (Get-WacNormalizedPath -Path ($command.Groups['path'].Value -replace "''", "'"))
    }

    $file = [regex]::Match($Arguments, '(?i)(?:^|\s)-File\s+(?:"(?<quoted>[^"]+)"|(?<bare>[^\s"]+))')
    if (-not $file.Success) { return $null }

    $value = if ($file.Groups['quoted'].Success) { $file.Groups['quoted'].Value } else { $file.Groups['bare'].Value }
    return (Get-WacNormalizedPath -Path $value)
}

function Get-WacInstalledTask {
    <#
    .SYNOPSIS
        Returns the task registered at the canonical folder, and optionally the pre-1.2 task at the
        root folder.
    #>
    [CmdletBinding()]
    param([switch]$IncludeLegacy)

    $found = New-Object 'System.Collections.Generic.List[object]'

    $paths = New-Object 'System.Collections.Generic.List[string]'
    [void]$paths.Add($script:TaskFolder)
    if ($IncludeLegacy) { [void]$paths.Add('\') }

    foreach ($path in $paths) {
        try {
            $task = Get-ScheduledTask -TaskName $script:TaskName -TaskPath $path -ErrorAction Stop
        }
        catch {
            continue
        }
        if ($task) { [void]$found.Add($task) }
    }

    return @($found.ToArray())
}

function Get-WacTaskActionArgumentCandidate {
    <#
    .SYNOPSIS
        Every argument string this version can legitimately register for one deployed Run.ps1.
    .DESCRIPTION
        Ledger B2-3: "the arguments look about right" is not ownership proof. A permissive match
        accepts a trailing `; iwr evil | iex` inside the -Command payload, and the payload runs as
        SYSTEM. The only shape that cannot be talked around is the one this module GENERATES, so
        ownership compares the registered string ordinally against the complete set of strings
        Get-WacTaskActionArgument can produce for that script path - three independent switches,
        eight strings, no regex and therefore no regex hole.

        A task written by a FUTURE version whose action shape has changed will not match, and will
        be refused rather than silently replaced. That is the intended direction of the failure: the
        version that changes the shape adds its predecessor's generator here, in one place, instead
        of every reader loosening its matching.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RunScript)

    $candidates = New-Object 'System.Collections.Generic.List[string]'
    foreach ($resetBase in @($true, $false)) {
        foreach ($prune in @($true, $false)) {
            foreach ($legacy in @($true, $false)) {
                [void]$candidates.Add((Get-WacTaskActionArgument -RunScript $RunScript `
                    -ResetWindowsUpdateBase $resetBase `
                    -PruneSupersededDrivers:$prune `
                    -EnableLegacyDiskCleanup:$legacy))
            }
        }
    }

    return @($candidates.ToArray())
}

function Get-WacLegacyTaskScriptPath {
    <#
    .SYNOPSIS
        The Run.ps1 path a pre-1.2 task action runs, or $null when the string is not EXACTLY the
        shape the pre-1.2 installer wrote.
    .DESCRIPTION
        The two RELEASED installers each built the action as one interpolated literal, and they did
        not build the same one. Both shapes are recognised here, and nothing else is:

            v1.0.0  -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "<script>"
                    -Scheduled [ -ResetWindowsUpdateBase]
            v1.1.0  -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "<script>"
                    -Scheduled -ResetWindowsUpdateBase:$true|$false [ -SkipAclHardening]

        The dollar is not a typo and not interpolation: v1.1.0 built the suffix from a SINGLE-quoted
        '-ResetWindowsUpdateBase:${1}' -f ... .ToLowerInvariant(), so the registered string carries a
        literal '$'. Its own post-registration assertion (Install-WindowsAutoCleanupTask.ps1 at
        d3d5876, line 308) checks for exactly that text, which is how the shape is known rather than
        assumed.

        v1.1.0 ALWAYS emitted the ':$true'/':$false' suffix - never the bare switch - so recognising
        only the v1.0.0 form stranded every machine running the version most users actually have:
        the task parsed as neither ours nor legacy, Resolve-ConflictingTask refused it, and both
        entry points exited 7 with the vulnerable PATH-resolved-host task still registered and no
        way to remove it.

        The pattern is anchored at both ends, so nothing may precede or follow it. That is what the
        brief means by "no trailing command injection": a task whose arguments merely CONTAIN the old
        shape - with an extra `-Command "..."` bolted on, say - is not the old task and is refused,
        because unregistering it would be acting on something we did not identify.

        Note what is deliberately NOT required here: a canonical Execute. The pre-1.2 installer
        resolved its host with `Get-Command pwsh.exe`, so a real legacy task can and does point at a
        PATH-resolved portable PowerShell on a secondary drive. That is precisely the vulnerable
        registration this migration exists to REMOVE; demanding a canonical host would refuse it,
        leave it running, and register a second task beside it.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Arguments)

    if ([string]::IsNullOrWhiteSpace($Arguments)) { return $null }

    # Ordered alternation, both branches anchored by the shared $: the v1.1.0 form is tried first so
    # ' -ResetWindowsUpdateBase' cannot match the prefix of ' -ResetWindowsUpdateBase:$true' and
    # fail on the trailing token. -SkipAclHardening is legal ONLY after the ':$true'/':$false' suffix,
    # because that is the only order v1.1.0 could produce.
    $pattern = '^-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "(?<path>[^"]+)" -Scheduled(?: -ResetWindowsUpdateBase:\$(?:true|false)(?: -SkipAclHardening)?| -ResetWindowsUpdateBase)?$'
    $match = [regex]::Match($Arguments.Trim(), $pattern)
    if (-not $match.Success) { return $null }

    $path = Get-WacNormalizedPath -Path $match.Groups['path'].Value
    if (-not $path) { return $null }
    if (-not ([System.IO.Path]::GetFileName($path) -ieq 'Run.ps1')) { return $null }
    return $path
}

function Test-WacTaskIsOurs {
    <#
    .SYNOPSIS
        Ownership proof. Nothing may overwrite or delete a task that does not pass this.
    .DESCRIPTION
        v1.1.0 registered with -Force and unregistered by name alone, so any unrelated task called
        WindowsAutoCleanup was silently replaced or deleted (ledger P0-4).

        CURRENT shape - every one of these, or the task is not ours (ledger B2-3):
          * exactly one action;
          * Execute is one of the canonical machine-wide PowerShell hosts, not merely rooted;
          * Arguments equal, ORDINALLY, one of the eight strings this version generates for
            <DeploymentRoot>\Run.ps1 - so a trailing statement in the -Command payload cannot pass;
          * WorkingDirectory, when the task carries one, is the deployment root;
          * the description carries the fixed sentinel.

        LEGACY shape - only with -AllowLegacyMigration, only at the ROOT task path, and only to
        REMOVE or REPLACE it, never to keep it: the exact pre-1.2 description plus an exactly parsed
        pre-1.2 action running a Run.ps1 with -Scheduled. Its Execute is intentionally unconstrained;
        see Get-WacLegacyTaskScriptPath.

        Anything else is refused with a reason, and the caller must leave that task alone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Task,
        [string]$DeploymentRoot,
        [switch]$AllowLegacyMigration
    )

    $result = [PSCustomObject]@{
        TaskName = $null
        TaskPath = $null
        IsOurs = $false
        IsLegacy = $false
        ScriptPath = $null
        Reason = $null
    }

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }

    try { $result.TaskName = [string]$Task.TaskName } catch { $result.TaskName = $null }
    try { $result.TaskPath = [string]$Task.TaskPath } catch { $result.TaskPath = $null }

    $description = ''
    try { $description = [string]$Task.Description } catch { $description = '' }

    $actions = @()
    try { $actions = @($Task.Actions) } catch { $actions = @() }

    if ($actions.Count -ne 1) {
        $result.Reason = ('The task has {0} actions; ours has exactly one.' -f $actions.Count)
        return $result
    }

    $execute = ''
    $arguments = ''
    $workingDirectory = ''
    try { $execute = [string]$actions[0].Execute } catch { $execute = '' }
    try { $arguments = [string]$actions[0].Arguments } catch { $arguments = '' }
    # Absent on a stub and on some CIM shapes; an absent value cannot contradict the expectation, so
    # it is treated as "not stated" rather than as a mismatch.
    try { $workingDirectory = [string]$actions[0].WorkingDirectory } catch { $workingDirectory = '' }

    $carriesSentinel = ($description -and $description.Contains($script:TaskSentinel))

    if ($carriesSentinel) {
        # IsPathRooted alone accepts the drive-relative 'C:file' form, and normalisation alone
        # accepts a bare 'pwsh.exe' because GetFullPath resolves it against the current directory.
        $executeRooted = $false
        try { $executeRooted = [System.IO.Path]::IsPathRooted($execute) } catch { $executeRooted = $false }
        if (-not $executeRooted -or -not (Get-WacNormalizedPath -Path $execute)) {
            $result.Reason = 'The action executable is not a rooted local path.'
            return $result
        }

        # Rooted is not enough. Ownership has to cover WHAT runs, not only which script it points
        # at: a task carrying our sentinel but executing C:\Users\bob\evil.exe as SYSTEM would
        # otherwise be judged ours, adopted and left in place - the exact escalation the sentinel
        # exists to prevent.
        if (-not (Test-WacTaskExecuteIsCanonicalHost -Execute $execute)) {
            $result.Reason = ('The action executable {0} is not a canonical machine-wide PowerShell host.' -f $execute)
            return $result
        }

        $runScript = Join-Path -Path $DeploymentRoot -ChildPath 'Run.ps1'
        $matched = $false
        foreach ($candidate in (Get-WacTaskActionArgumentCandidate -RunScript $runScript)) {
            if ([string]::Equals($arguments, $candidate, [System.StringComparison]::Ordinal)) { $matched = $true; break }
        }
        if (-not $matched) {
            $result.Reason = ('The action arguments are not one this version registers for {0}.' -f $runScript)
            return $result
        }

        if ($workingDirectory) {
            $normalizedWorking = Get-WacNormalizedPath -Path $workingDirectory
            $normalizedRoot = Get-WacNormalizedPath -Path $DeploymentRoot
            if (-not $normalizedWorking -or -not $normalizedRoot -or ($normalizedWorking -ine $normalizedRoot)) {
                $result.Reason = ('The action working directory {0} is not the deployment root {1}.' -f $workingDirectory, $DeploymentRoot)
                return $result
            }
        }

        $result.IsOurs = $true
        $result.ScriptPath = (Get-WacNormalizedPath -Path $runScript)
        $result.Reason = 'The sentinel, the canonical host and the exact registered action all match.'
        return $result
    }

    if (-not $AllowLegacyMigration) {
        $result.Reason = 'The description does not carry the WindowsAutoCleanup ownership sentinel.'
        return $result
    }

    if ($result.TaskPath -and $result.TaskPath -ne '\') {
        $result.Reason = 'Only the pre-1.2 task at the root task path can be adopted.'
        return $result
    }
    if (-not $description -or -not $description.Contains($script:LegacyTaskDescription)) {
        $result.Reason = 'The description does not match the pre-1.2 WindowsAutoCleanup description.'
        return $result
    }

    $legacyScript = Get-WacLegacyTaskScriptPath -Arguments $arguments
    if (-not $legacyScript) {
        $result.Reason = 'The action arguments are not exactly the pre-1.2 -File Run.ps1 -Scheduled form.'
        return $result
    }

    $result.IsOurs = $true
    $result.IsLegacy = $true
    $result.ScriptPath = $legacyScript
    $result.Reason = ('Adopted the pre-1.2 task: old description text and an exactly parsed -Scheduled action running {0}.' -f $legacyScript)
    return $result
}

function Test-WacTaskReferencesRoot {
    <#
    .SYNOPSIS
        True when any of the given tasks would execute something inside the deployment root.
    .DESCRIPTION
        Ledger B2-3: the deployment files must survive if anything can still reach them. That
        includes a task the uninstaller REFUSED to touch - deleting the tree under a foreign task
        that happens to point into it turns "we left it alone" into "we broke it".

        Every place a path can hide in an action is looked at, not only the parsed script argument:
        the executable itself and the working directory are equally capable of naming the tree.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][object[]]$Task,
        [Parameter(Mandatory = $true)][string]$DeploymentRoot
    )

    foreach ($entry in @($Task)) {
        if (-not $entry) { continue }

        $actions = @()
        try { $actions = @($entry.Actions) } catch { $actions = @() }

        foreach ($action in $actions) {
            if (-not $action) { continue }

            $arguments = ''
            $execute = ''
            $working = ''
            try { $arguments = [string]$action.Arguments } catch { $arguments = '' }
            try { $execute = [string]$action.Execute } catch { $execute = '' }
            try { $working = [string]$action.WorkingDirectory } catch { $working = '' }

            foreach ($candidate in @((Get-WacTaskScriptPath -Arguments $arguments), $execute, $working)) {
                if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }
                $normalized = Get-WacNormalizedPath -Path ([string]$candidate)
                if (-not $normalized) { continue }
                if (Test-WacIsWithinRoot -ChildPath $normalized -RootPath $DeploymentRoot) { return $true }
            }
        }
    }

    return $false
}

function Remove-WacInstalledTask {
    <#
    .SYNOPSIS
        Unregisters a task that passes the ownership proof, then verifies it is really gone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Task,
        [string]$DeploymentRoot,
        [switch]$AllowLegacyMigration
    )

    $proof = Test-WacTaskIsOurs -Task $Task -DeploymentRoot $DeploymentRoot -AllowLegacyMigration:$AllowLegacyMigration

    $result = [PSCustomObject]@{
        TaskName = $proof.TaskName
        TaskPath = $proof.TaskPath
        Removed = $false
        Verified = $false
        Reason = $proof.Reason
    }

    if (-not $proof.IsOurs) {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'Refused to remove a task that is not ours.' -Data @{
            task = ('{0}{1}' -f $result.TaskPath, $result.TaskName); reason = $proof.Reason
        }
        return $result
    }

    try {
        Unregister-ScheduledTask -TaskName $result.TaskName -TaskPath $result.TaskPath -Confirm:$false -ErrorAction Stop
        $result.Removed = $true
    }
    catch {
        $result.Reason = $_.Exception.Message
        return $result
    }

    $still = $null
    try { $still = Get-ScheduledTask -TaskName $result.TaskName -TaskPath $result.TaskPath -ErrorAction Stop } catch { $still = $null }

    if ($still) {
        $result.Reason = 'Unregister-ScheduledTask reported success but the task is still registered.'
        Write-WacLog -Level ERROR -Component 'Deploy' -Message 'A task survived its own removal.' -Data @{ task = ('{0}{1}' -f $result.TaskPath, $result.TaskName) }
        return $result
    }

    $result.Verified = $true
    $result.Reason = 'Removed and verified absent.'
    Write-WacLog -Level INFO -Component 'Deploy' -Message 'Scheduled task removed.' -Data @{ task = ('{0}{1}' -f $result.TaskPath, $result.TaskName) }
    return $result
}

# ---------------------------------------------------------------------------------------------
# Argument vectors
# ---------------------------------------------------------------------------------------------

function Get-WacInstallerRelaunchArgument {
    <#
    .SYNOPSIS
        The child argument vector for the installer's elevated relaunch. Pure and order-stable.
    .DESCRIPTION
        Ledger P0-2: the old helper read its OWN empty $PSBoundParameters, so an explicit
        -ResetWindowsUpdateBase:$false never reached the elevated child and DISM ran /ResetBase.
        The caller snapshots the script's bound parameters and passes the effective VALUES here;
        ResetWindowsUpdateBase is always emitted in the explicit -Name:$true/$false form so the
        child's default can never re-apply.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$DailyRunTime,
        [bool]$ResetWindowsUpdateBase = $true,
        [switch]$PruneSupersededDrivers,
        [switch]$EnableLegacyDiskCleanup,
        [switch]$NoPause
    )

    $present = New-Object 'System.Collections.Generic.List[string]'
    if ($PruneSupersededDrivers) { [void]$present.Add('PruneSupersededDrivers') }
    if ($EnableLegacyDiskCleanup) { [void]$present.Add('EnableLegacyDiskCleanup') }
    if ($NoPause) { [void]$present.Add('NoPause') }

    return (Get-WacRelaunchArgument -ScriptPath $ScriptPath `
        -BooleanSwitch @{ ResetWindowsUpdateBase = $ResetWindowsUpdateBase } `
        -PresentSwitch @($present.ToArray()) `
        -NamedValue @{ DailyRunTime = $DailyRunTime })
}

function Get-WacTaskActionArgument {
    <#
    .SYNOPSIS
        The argument STRING the scheduled task action runs. Pure, so the installer can assert that
        what it registered is what it read back.
    .DESCRIPTION
        -ResetWindowsUpdateBase is always explicit for the same reason as the relaunch vector: a
        missing switch would let Run.ps1's $true default enable DISM /ResetBase on a task the user
        installed with -ResetWindowsUpdateBase:$false.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RunScript,
        [bool]$ResetWindowsUpdateBase = $true,
        [switch]$PruneSupersededDrivers,
        [switch]$EnableLegacyDiskCleanup
    )

    $present = New-Object 'System.Collections.Generic.List[string]'
    [void]$present.Add('Scheduled')
    if ($PruneSupersededDrivers) { [void]$present.Add('PruneSupersededDrivers') }
    if ($EnableLegacyDiskCleanup) { [void]$present.Add('EnableLegacyDiskCleanup') }

    # Same builder as the elevated relaunch, and for the same reason: the task host is
    # powershell.exe whenever PowerShell 7 is absent, and -File cannot carry -Switch:$false to
    # Windows PowerShell 5.1 at all - the task would die during parameter binding.
    $arguments = Get-WacRelaunchArgument -ScriptPath $RunScript `
        -BooleanSwitch @{ ResetWindowsUpdateBase = [bool]$ResetWindowsUpdateBase } `
        -PresentSwitch @($present.ToArray()) `
        -HostSwitch @('-NonInteractive', '-WindowStyle', 'Hidden')

    return (ConvertTo-WacCommandLine -ArgumentList $arguments)
}
