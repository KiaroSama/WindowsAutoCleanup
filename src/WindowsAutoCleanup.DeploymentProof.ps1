<#
.SYNOPSIS
    The deployment manifest, the ownership proof read from it, and the machine-trust verdict on the
    deployed tree.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Deploy.psm1; see that file for why the parts are dot-sourced
    rather than imported. Two questions every mutation has to ask first live here: "is the directory
    at the deployment path ours" (the manifest, its project id and its hashes) and "can a standard
    user modify what the SYSTEM task will execute" (verification only - nothing in this file mutates
    an ACL, an owner or an inheritance flag; ledger P0-6 / U-2).

    The manifest constants are declared here because the manifest is what they describe. All parts
    share one session state, so New-WacDeploymentStage's read of $script:DeploymentVersion is the
    same variable, not a copy.
#>

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

function Get-WacDeploymentVersion { return $script:DeploymentVersion }
function Get-WacDeploymentProjectId { return $script:DeploymentProjectId }

function Get-WacDeploymentManifestPath {
    param([string]$DeploymentRoot)

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }
    return (Join-Path -Path $DeploymentRoot -ChildPath $script:DeploymentManifestName)
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
