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

    The implementation lives in the WindowsAutoCleanup.*.ps1 files beside this one, one per
    responsibility, and they are DOT-SOURCED rather than imported, for the reason Core.psm1
    records at length: a nested Import-Module gives each part its own session state, so a part
    could neither call another part reliably nor see its $script: state. This file keeps the
    stage-and-switch lifecycle, the one machine-wide operation lock, and the export list.
#>

Set-StrictMode -Version 2.0

# No -Force: force-reloading a nested module tears it out of the caller's session too.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop

# Only for Clear-WacBlockingAttribute: Copy-Item preserves a read-only attribute, and File.Delete
# throws on a read-only file. The FileSystem deletion primitives themselves are unusable here,
# because Initialize-WacRun registers the deployment root as a protected root and they refuse it.
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.FileSystem.psm1') -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DeploymentTree.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.DeploymentProof.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.ScheduledTask.ps1')

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

function Get-WacOperationLockName { return $script:OperationLockName }

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
    # -Depth 1 because the destination IS level 1 of the deployment - see Copy-WacDeploymentTree for
    # what the missing 1 used to cost.
    Copy-WacDeploymentTree -Source $sourceSrc -Destination (Join-Path -Path $slots.Staging -ChildPath 'src') -Depth 1

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

    # Throwing here is deliberate and the caller must be inside its rollback try: a deployment whose
    # contents cannot be enumerated is one nothing can verify, manifest or later delete, and it has
    # just gone live.
    $walk = Get-WacDeploymentItem -Root $slots.Root
    if (-not $walk.Complete) {
        throw ("The deployment that was switched into place could not be fully enumerated: {0}" -f
            ((@($walk.Failure | ForEach-Object { '{0}: {1}' -f $_.Path, $_.Reason }) | Select-Object -First 3) -join '; '))
    }

    $fileCount = @($walk.Entry | Where-Object { -not $_.IsDirectory }).Count
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
