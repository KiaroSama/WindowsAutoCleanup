<#
.SYNOPSIS
    Deployment, machine-trust VERIFICATION and scheduled-task ownership proof.

.DESCRIPTION
    Three safety-critical responsibilities:

      * Copy the runtime into %ProgramFiles%\WindowsAutoCleanup through a staging directory and an
        atomic rename, so the SYSTEM task never executes the user's mutable checkout (ledger P0-3).
      * VERIFY that the deployed tree is machine-trusted. The v1.1.0 ACL-hardening capability was
        REMOVED on request (ledger P0-6 / U-2): it rewrote the owner and DACL of the user's own
        checkout and left the folder hard to delete. Nothing in this module calls Set-Acl,
        SetOwner, SetAccessRuleProtection, icacls or takeown. An unreadable or user-writable path
        is reported untrusted so every caller fails closed.
      * Prove a scheduled task belongs to this project before overwriting or deleting it. Both the
        installer and the uninstaller used to act on ANY task named WindowsAutoCleanup (P0-4).

    The FileSystem module's deletion primitives cannot be used here: Initialize-WacRun registers the
    deployment root as a PROTECTED root, so Remove-WacTree correctly refuses it. Deletion in this
    module is therefore direct, bounded, never follows a reparse point, and is restricted by an
    allow-list of exactly three canonical paths.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the caller's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop

# Only for Clear-WacBlockingAttribute: Copy-Item preserves a read-only attribute, and File.Delete
# throws on a read-only file. The FileSystem deletion primitives themselves are unusable here,
# because Initialize-WacRun registers the deployment root as a protected root and they refuse it.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.FileSystem.psm1') -DisableNameChecking -ErrorAction Stop

$script:TaskName = 'WindowsAutoCleanup'
$script:TaskFolder = '\WindowsAutoCleanup\'

# Register-ScheduledTask exposes only -Description, so a fixed sentinel inside the description is
# the sole ownership marker a PowerShell-only installer can write. Never change this value: an
# installed task with the old sentinel would stop being recognised as ours.
$script:TaskSentinel = 'WindowsAutoCleanupTaskId=9d1f6d2a-6d3a-4f77-9a41-2f2b0f1f5c10'

$script:TaskDescriptionText = 'Runs WindowsAutoCleanup daily to remove allow-listed temporary and cache locations from drive C:.'

# The exact description v1.0.0/v1.1.0 wrote at the ROOT task path. Used only to adopt that task.
$script:LegacyTaskDescription = 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.'

# The tree is Run.ps1 + src + LICENSE; 8 levels is far more than it can legitimately need.
$script:MaxTreeDepth = 8

function Get-WacTaskName { return $script:TaskName }
function Get-WacTaskFolder { return $script:TaskFolder }
function Get-WacTaskSentinel { return $script:TaskSentinel }
function Get-WacTaskDescription { return ('{0} {1}' -f $script:TaskDescriptionText, $script:TaskSentinel) }

# ---------------------------------------------------------------------------------------------
# Bounded, never-following tree walk
# ---------------------------------------------------------------------------------------------

function Test-WacIsExcludedDeploymentName {
    <#
    .SYNOPSIS
        True for a name that must never reach the deployment: logs and every dot-directory
        (.git, .ai, .claude, .kiro, .codex, .Comments, .ignoreme and anything like them).
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    if ($Name.StartsWith('.')) { return $true }
    if ($Name -ieq 'Logs') { return $true }
    return $false
}

function Get-WacDeploymentItem {
    <#
    .SYNOPSIS
        Depth-bounded walk that never descends into a reparse point.
    .DESCRIPTION
        Get-ChildItem -Recurse follows junctions, which both loops and escapes the tree. A reparse
        point found inside a deployment is reported rather than followed, because the copy never
        creates one and its presence means something else wrote into the tree.
    .OUTPUTS
        Records with Path, IsDirectory and IsReparsePoint. Nothing is filtered out: a delete pass
        that skipped a name would leave the parent directory non-empty and fail.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [int]$Depth = 0
    )

    $items = New-Object 'System.Collections.Generic.List[object]'
    if ($Depth -ge $script:MaxTreeDepth) { return @($items.ToArray()) }

    $children = @()
    try {
        $children = @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop)
    }
    catch {
        return @($items.ToArray())
    }

    foreach ($entry in $children) {
        $isDirectory = [bool]$entry.PSIsContainer
        $isReparse = Test-WacIsReparsePoint -Path $entry.FullName

        [void]$items.Add([PSCustomObject]@{
            Path = $entry.FullName
            IsDirectory = $isDirectory
            IsReparsePoint = $isReparse
        })

        if ($isDirectory -and -not $isReparse) {
            foreach ($child in (Get-WacDeploymentItem -Root $entry.FullName -Depth ($Depth + 1))) {
                [void]$items.Add($child)
            }
        }
    }

    return @($items.ToArray())
}

function Copy-WacDeploymentTree {
    <#
    .SYNOPSIS
        Recursive copy that skips excluded names and never follows a reparse point.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [int]$Depth = 0
    )

    if ($Depth -ge $script:MaxTreeDepth) {
        throw ("The source tree is deeper than {0} levels: {1}" -f $script:MaxTreeDepth, $Source)
    }

    if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
        New-Item -Path $Destination -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    foreach ($entry in @(Get-ChildItem -LiteralPath $Source -Force -ErrorAction Stop)) {
        if (Test-WacIsExcludedDeploymentName -Name $entry.Name) { continue }
        if (Test-WacIsReparsePoint -Path $entry.FullName) { continue }

        $target = Join-Path -Path $Destination -ChildPath $entry.Name
        if ($entry.PSIsContainer) {
            Copy-WacDeploymentTree -Source $entry.FullName -Destination $target -Depth ($Depth + 1)
        }
        else {
            Copy-Item -LiteralPath $entry.FullName -Destination $target -Force -ErrorAction Stop
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------------------------

function Get-WacDeploymentSlotPath {
    <#
    .SYNOPSIS
        The three canonical paths this module is ever allowed to delete.
    #>
    param([string]$DeploymentRoot)

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }
    $root = Get-WacNormalizedPath -Path $DeploymentRoot
    if (-not $root) { return $null }

    return [PSCustomObject]@{
        Root = $root
        Staging = ($root + '.staging')
        Previous = ($root + '.previous')
    }
}

function Remove-WacDeploymentEntry {
    <#
    .SYNOPSIS
        Deletes one file or one empty directory. Returns $null on success, or the failure message.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$IsDirectory
    )

    $longPath = Get-WacLongPath -Path $Path

    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        try {
            if ($IsDirectory) { [System.IO.Directory]::Delete($longPath, $false) }
            else { [System.IO.File]::Delete($longPath) }
            return $null
        }
        catch {
            # Classified rather than typed-caught: a .NET method exception reaches PowerShell wrapped,
            # and the two hosts disagree about whether a typed catch matches the inner exception.
            if ($attempt -eq 0 -and
                (Get-WacIoFailureKind -ErrorRecord $_) -eq 'Denied' -and
                (Clear-WacBlockingAttribute -LongPath $longPath)) {
                continue
            }
            return ('{0}: {1}' -f $Path, $_.Exception.Message)
        }
    }

    return ('{0}: the entry could not be deleted.' -f $Path)
}

function Remove-WacDeployment {
    <#
    .SYNOPSIS
        Deletes one deployment slot directory. Bounded, never follows a link, never touches a
        source checkout.
    .DESCRIPTION
        The allow-list is the point: only the canonical deployment root and its two swap slots can
        be passed. Anything else - above all the user's own checkout - is refused.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$DeploymentRoot
    )

    $result = [PSCustomObject]@{ Path = $Path; Removed = $false; Reason = $null }

    $slots = Get-WacDeploymentSlotPath -DeploymentRoot $DeploymentRoot
    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $slots -or -not $normalized) {
        $result.Reason = 'The path could not be normalised.'
        return $result
    }

    $allowed = @($slots.Root, $slots.Staging, $slots.Previous)
    $isAllowed = $false
    foreach ($candidate in $allowed) {
        if ($normalized -ieq $candidate) { $isAllowed = $true; break }
    }

    if (-not $isAllowed) {
        $result.Reason = 'Refused: only the deployment root and its swap slots may be deleted.'
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'Refused a delete outside the deployment slots.' -Data @{ path = $normalized }
        return $result
    }

    if (-not (Test-Path -LiteralPath $normalized -PathType Container)) {
        $result.Removed = $true
        $result.Reason = 'Nothing to remove.'
        return $result
    }

    if (Test-WacIsReparsePoint -Path $normalized) {
        # Delete the link itself, never its target. Remove-Item throws a spurious
        # NullReferenceException on some junctions under Windows PowerShell 5.1.
        try {
            [System.IO.Directory]::Delete((Get-WacLongPath -Path $normalized), $false)
            $result.Removed = $true
        }
        catch {
            $result.Reason = $_.Exception.Message
        }
        return $result
    }

    if (-not (Test-WacPathResolvesToItself -Path $normalized)) {
        $result.Reason = 'The path does not resolve to itself; a component may have been swapped.'
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'Refused a delete whose final path differs from the requested path.' -Data @{ path = $normalized }
        return $result
    }

    $items = @(Get-WacDeploymentItem -Root $normalized)

    # Deepest first by separator count, so a directory is always empty by the time it is deleted.
    # Sorting the path STRING would be culture-aware and is not a reliable depth order.
    foreach ($item in @($items | Sort-Object -Property @{ Expression = { $_.Path.Split('\').Length } } -Descending)) {
        $failure = Remove-WacDeploymentEntry -Path $item.Path -IsDirectory:$item.IsDirectory
        if ($failure) { $result.Reason = $failure }
    }

    $failure = Remove-WacDeploymentEntry -Path $normalized -IsDirectory
    if ($failure) { $result.Reason = $failure }
    else {
        $result.Removed = $true
        $result.Reason = $null
    }

    return $result
}

function Install-WacDeployment {
    <#
    .SYNOPSIS
        Copies Run.ps1, src\ and LICENSE into the machine-wide deployment root through an atomic
        staging swap.
    .DESCRIPTION
        A SYSTEM task must not execute a directory a standard user can rewrite, so the runtime is
        copied out of the checkout (ledger P0-3). The swap is move-old-aside / move-staging-in /
        delete-old, with a rollback, so an interrupted install never leaves a half-copied tree that
        the task would still run.
    .OUTPUTS
        DeploymentRoot, RunScript, FileCount.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SourceRoot)

    $source = Get-WacNormalizedPath -Path $SourceRoot
    if (-not $source -or -not (Test-Path -LiteralPath $source -PathType Container)) {
        throw ("The source directory does not exist: {0}" -f $SourceRoot)
    }

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) { throw 'The deployment root could not be resolved.' }

    if ((Test-WacIsWithinRoot -ChildPath $source -RootPath $slots.Root) -or
        (Test-WacIsWithinRoot -ChildPath $slots.Root -RootPath $source)) {
        throw ("The source checkout overlaps the deployment root ({0}); move the checkout elsewhere and re-run." -f $slots.Root)
    }

    $sourceRun = Join-Path -Path $source -ChildPath 'Run.ps1'
    $sourceSrc = Join-Path -Path $source -ChildPath 'src'
    if (-not (Test-Path -LiteralPath $sourceRun -PathType Leaf)) { throw ("Run.ps1 was not found in {0}." -f $source) }
    if (-not (Test-Path -LiteralPath $sourceSrc -PathType Container)) { throw ("The src directory was not found in {0}." -f $source) }

    foreach ($slot in @($slots.Staging, $slots.Previous)) {
        $cleared = Remove-WacDeployment -Path $slot
        if (-not $cleared.Removed) {
            throw ("A leftover deployment slot could not be cleared: {0} ({1})" -f $slot, $cleared.Reason)
        }
    }

    Write-WacLog -Level INFO -Component 'Deploy' -Message 'Staging the deployment.' -Data @{ source = $source; staging = $slots.Staging }

    New-Item -Path $slots.Staging -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath $sourceRun -Destination (Join-Path -Path $slots.Staging -ChildPath 'Run.ps1') -Force -ErrorAction Stop
    Copy-WacDeploymentTree -Source $sourceSrc -Destination (Join-Path -Path $slots.Staging -ChildPath 'src')

    $sourceLicense = Join-Path -Path $source -ChildPath 'LICENSE'
    if (Test-Path -LiteralPath $sourceLicense -PathType Leaf) {
        Copy-Item -LiteralPath $sourceLicense -Destination (Join-Path -Path $slots.Staging -ChildPath 'LICENSE') -Force -ErrorAction Stop
    }

    $movedAside = $false
    if (Test-Path -LiteralPath $slots.Root -PathType Container) {
        [System.IO.Directory]::Move($slots.Root, $slots.Previous)
        $movedAside = $true
    }

    try {
        [System.IO.Directory]::Move($slots.Staging, $slots.Root)
    }
    catch {
        if ($movedAside) {
            try { [System.IO.Directory]::Move($slots.Previous, $slots.Root) }
            catch { Write-WacLog -Level CRITICAL -Component 'Deploy' -Message 'The previous deployment could not be restored.' -Data @{ previous = $slots.Previous; root = $slots.Root } }
        }
        throw ("The staging directory could not be swapped into place: {0}" -f $_.Exception.Message)
    }

    if ($movedAside) {
        $discarded = Remove-WacDeployment -Path $slots.Previous
        if (-not $discarded.Removed) {
            # The new deployment is already live, so this is untidy rather than fatal.
            Write-WacLog -Level WARNING -Component 'Deploy' -Message 'The previous deployment could not be deleted.' -Data @{ path = $slots.Previous; reason = $discarded.Reason }
        }
    }

    $fileCount = @(Get-WacDeploymentItem -Root $slots.Root | Where-Object { -not $_.IsDirectory }).Count
    Write-WacLog -Level INFO -Component 'Deploy' -Message 'Deployment complete.' -Data @{ root = $slots.Root; files = $fileCount }

    return [PSCustomObject]@{
        DeploymentRoot = $slots.Root
        RunScript = (Join-Path -Path $slots.Root -ChildPath 'Run.ps1')
        FileCount = $fileCount
    }
}

function Test-WacDeploymentTrusted {
    <#
    .SYNOPSIS
        VERIFIES that a standard user cannot modify anything the SYSTEM task will execute.
    .DESCRIPTION
        Verification only. This function never mutates an ACL, an owner or an inheritance flag -
        that capability was removed (ledger P0-6 / U-2). Every directory and every deployed
        .ps1/.psm1 is checked, because write access to a directory is enough to replace the file
        inside it. Anything unreadable or unexpected leaves IsTrusted false so callers fail closed.
    #>
    [CmdletBinding()]
    param([string]$DeploymentRoot)

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }

    $result = [PSCustomObject]@{
        DeploymentRoot = $DeploymentRoot
        IsTrusted = $false
        CheckedCount = 0
        Untrusted = @()
        Reason = $null
    }

    $root = Get-WacNormalizedPath -Path $DeploymentRoot
    if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container)) {
        $result.Reason = 'The deployment root does not exist.'
        return $result
    }

    $untrusted = New-Object 'System.Collections.Generic.List[object]'
    $toCheck = New-Object 'System.Collections.Generic.List[string]'
    [void]$toCheck.Add($root)

    foreach ($item in @(Get-WacDeploymentItem -Root $root)) {
        if ($item.IsReparsePoint) {
            [void]$untrusted.Add([PSCustomObject]@{
                Path = $item.Path
                Reason = 'A reparse point inside the deployment can redirect execution outside it.'
                Owner = $null
            })
            continue
        }

        if (-not $item.IsDirectory) {
            if ([System.IO.Path]::GetExtension($item.Path) -notmatch '(?i)^\.psm?1$') { continue }
        }

        [void]$toCheck.Add($item.Path)
    }

    foreach ($path in $toCheck) {
        $trust = Test-WacPathIsMachineTrusted -Path $path
        if (-not $trust.IsTrusted) {
            [void]$untrusted.Add([PSCustomObject]@{ Path = $path; Reason = $trust.Reason; Owner = $trust.Owner })
        }
    }

    $checked = $toCheck.Count
    $result.CheckedCount = $checked
    if ($untrusted.Count -gt 0) {
        $result.Untrusted = @($untrusted.ToArray())
        $result.Reason = ('{0} of {1} deployed paths are writable by a non-administrative principal or unreadable.' -f $untrusted.Count, $checked)
        return $result
    }

    $result.IsTrusted = $true
    $result.Reason = ('All {0} deployed paths are administrative only.' -f $checked)
    return $result
}

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

function Test-WacTaskIsOurs {
    <#
    .SYNOPSIS
        Ownership proof. Nothing may overwrite or delete a task that does not pass this.
    .DESCRIPTION
        v1.1.0 registered with -Force and unregistered by name alone, so any unrelated task called
        WindowsAutoCleanup was silently replaced or deleted (ledger P0-4).

        A task is ours when its description carries the fixed sentinel AND its single action runs a
        rooted executable whose -File argument lives inside the canonical deployment root. The
        rooted-executable test is what rejects a PATH-resolved host.

        Migration: the pre-1.2 task at the ROOT path is adopted only with -AllowLegacyMigration and
        only when its description is the old text and its arguments run a Run.ps1 with -Scheduled.
        Anything else is refused with a reason rather than guessed at.
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
    try { $execute = [string]$actions[0].Execute } catch { $execute = '' }
    try { $arguments = [string]$actions[0].Arguments } catch { $arguments = '' }

    # IsPathRooted alone accepts the drive-relative 'C:file' form, and normalisation alone accepts a
    # bare 'pwsh.exe' because GetFullPath resolves it against the current directory. A PATH-resolved
    # host is exactly what must not be registered for SYSTEM, so both checks are required.
    $executeRooted = $false
    try { $executeRooted = [System.IO.Path]::IsPathRooted($execute) } catch { $executeRooted = $false }
    if (-not $executeRooted -or -not (Get-WacNormalizedPath -Path $execute)) {
        $result.Reason = 'The action executable is not a rooted local path.'
        return $result
    }

    # Rooted is not enough. Ownership has to cover WHAT runs, not only which script it points at:
    # a task carrying our sentinel but executing C:\Users\bob\evil.exe as SYSTEM would otherwise be
    # judged ours, adopted, and left in place - the exact escalation the sentinel exists to prevent.
    if (-not (Test-WacTaskExecuteIsCanonicalHost -Execute $execute)) {
        $result.Reason = ('The action executable {0} is not a canonical machine-wide PowerShell host.' -f $execute)
        return $result
    }

    $scriptPath = Get-WacTaskScriptPath -Arguments $arguments

    if ($description -and $description.Contains($script:TaskSentinel)) {
        if (-not $scriptPath) {
            $result.Reason = 'The description carries our sentinel but the action has no -File argument.'
            return $result
        }
        if (-not (Test-WacIsWithinRoot -ChildPath $scriptPath -RootPath $DeploymentRoot)) {
            $result.Reason = ('The action script {0} is outside the deployment root {1}.' -f $scriptPath, $DeploymentRoot)
            return $result
        }

        $result.IsOurs = $true
        $result.Reason = 'The description sentinel and the deployed action script both match.'
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
    if (-not $scriptPath -or -not ([System.IO.Path]::GetFileName($scriptPath) -ieq 'Run.ps1')) {
        $result.Reason = 'The action does not run a Run.ps1 file.'
        return $result
    }
    if ($arguments -notmatch '(?i)(^|\s)-Scheduled(\s|$|:)') {
        $result.Reason = 'The action arguments do not contain -Scheduled.'
        return $result
    }

    $result.IsOurs = $true
    $result.IsLegacy = $true
    $result.Reason = 'Adopted the pre-1.2 task: old description text and a -Scheduled Run.ps1 action.'
    return $result
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

Export-ModuleMember -Function @(
    'Get-WacTaskName', 'Get-WacTaskFolder', 'Get-WacTaskSentinel', 'Get-WacTaskDescription',
    'Test-WacIsExcludedDeploymentName', 'Get-WacDeploymentItem', 'Copy-WacDeploymentTree',
    'Get-WacDeploymentSlotPath', 'Install-WacDeployment', 'Remove-WacDeployment',
    'Test-WacDeploymentTrusted',
    'Get-WacTaskScriptPath', 'Test-WacTaskExecuteIsCanonicalHost',
    'Get-WacInstalledTask', 'Test-WacTaskIsOurs', 'Remove-WacInstalledTask',
    'Get-WacInstallerRelaunchArgument', 'Get-WacTaskActionArgument'
)
