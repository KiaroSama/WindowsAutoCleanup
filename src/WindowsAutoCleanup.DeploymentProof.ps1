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

# The DURABLE half of the swap transaction (ledger WAC-02R). $script:DeploymentTransaction describes
# a swap the current process is in the middle of and dies with that process, so a run killed between
# the two moves leaves a machine whose only evidence is the directories themselves - and those
# cannot say whether the run that made them ever committed. This record is written beside the slots
# before the first move and deleted at the commit point, so its PRESENCE means "a swap started and
# did not finish".
#
# It is never believed on its own. Every action it triggers is re-proven against hashes taken from
# the bytes on disk, so a stale, copied or hand-written record can start no deletion by itself.
$script:DeploymentJournalSchema = 1
$script:DeploymentJournalSuffix = '.transaction.json'

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

    # A manifest built from a walk that did not see the whole tree records fewer files than the tree
    # holds, and every later check reads that short list as the truth about it.
    $walk = Get-WacDeploymentItem -Root $StagingRoot
    if (-not $walk.Complete) {
        throw ("The staged tree could not be fully enumerated, so no manifest can describe it: {0}" -f
            ((@($walk.Failure | ForEach-Object { '{0}: {1}' -f $_.Path, $_.Reason }) | Select-Object -First 3) -join '; '))
    }

    foreach ($item in @($walk.Entry)) {
        if ($item.IsDirectory) { continue }
        if ($item.IsReparsePoint) { throw ("The staged tree contains a reparse point: {0}" -f $item.Path) }

        $relative = $item.Path
        if ($relative.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relative = $relative.Substring($prefix.Length)
        }
        if ([string]::Equals($relative, $script:DeploymentManifestName, [System.StringComparison]::OrdinalIgnoreCase)) { continue }

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
          Indeterminate - something is there and it could not be read. Refused: an unreadable
                      directory used to enumerate as EMPTY, which walked straight into the
                      pre-manifest adoption below and reported it as ours to replace and delete.
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

        IsOurs and IsHealthy answer DIFFERENT questions, and conflating them cost a machine its only
        good copy (ledger WAC-02R). IsOurs means "this run may replace or remove it": an empty
        directory and a deployment three of whose files were overwritten are both ours. IsHealthy
        means "this is a complete, verified deployment that can stand on its own", which only a
        Managed tree whose every recorded file still matches can be - an empty root, a tampered one
        and a pre-manifest one cannot. Anything that would DISCARD recovery material has to ask the
        second question; only adoption asks the first.
    .OUTPUTS
        Root, Exists, Kind, IsOurs, IsEmpty, IsHealthy, Version, Tampered, Findings, Reason.
    #>
    [CmdletBinding()]
    param([string]$DeploymentRoot)

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }

    $result = [PSCustomObject]@{
        Root = $DeploymentRoot
        Exists = $false
        Kind = 'Foreign'
        IsOurs = $false
        IsEmpty = $false
        IsHealthy = $false
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
    #
    # -ErrorAction Stop, and its own verdict when that fails. SilentlyContinue answered an
    # unreadable directory with an empty list, and an empty list is indistinguishable here from a
    # directory that really holds nothing - so a deployment path nothing could read reached the
    # pre-manifest adoption below and came back Unmanaged and IsOurs.
    $topLevel = @()
    try { $topLevel = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop) }
    catch {
        $result.Kind = 'Indeterminate'
        $result.Reason = ('The deployment directory could not be enumerated, so nothing about it can be proven: {0}' -f $_.Exception.Message)
        return $result
    }

    # Reported rather than inferred by a caller: an empty directory at the deployment path is what
    # an interrupted move leaves behind, and it reads as Unmanaged-and-ours below.
    $result.IsEmpty = ($topLevel.Count -eq 0)

    $unexpected = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in $topLevel) {
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
        $isEmpty = ($topLevel.Count -eq 0)
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
    # The ONLY shape that earns IsHealthy: our manifest, our project id, and every file it records
    # still hashing to what it recorded.
    $result.IsHealthy = (-not $result.Tampered)
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
    $checkedSet = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $reported = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    [void]$toCheck.Add($root)

    # An incomplete walk is a finding in its own right. The paths it never reached are precisely the
    # ones nothing has verified, and "we could not look" has to fail closed exactly like "we looked
    # and it is writable".
    $walk = Get-WacDeploymentItem -Root $root
    foreach ($problem in @($walk.Failure)) {
        $problemPath = [string]$problem.Path
        if (-not $reported.Add($problemPath)) { continue }
        [void]$untrusted.Add([PSCustomObject]@{
            Path = $problemPath
            Reason = ('The deployment could not be fully enumerated: {0}' -f [string]$problem.Reason)
            Owner = $null
        })
    }

    foreach ($item in @($walk.Entry)) {
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
        [void]$checkedSet.Add($path)
        $trust = Test-WacPathIsMachineTrusted -Path $path
        if (-not $trust.IsTrusted -and $reported.Add($path)) {
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
# Content identity, the durable transaction record, and what may be promoted out of a slot
# ---------------------------------------------------------------------------------------------

function Get-WacDeploymentFingerprint {
    <#
    .SYNOPSIS
        One SHA-256 over the complete file inventory of a deployment tree: the relative path,
        content hash and length of every file in it.
    .DESCRIPTION
        The manifest identifies a PROJECT and a VERSION. Two different builds of 1.2.0 carry the
        same project id, the same version and each its own self-consistent manifest, so neither
        kind, version nor "matches its own manifest" tells them apart - and a rollback comparing
        only those reported a tree it had never seen as the one it moved aside (ledger WAC-02R).
        This is computed from the bytes on disk rather than from what a file inside the tree claims
        about them, so it also catches a manifest rewritten to agree with edited files.

        An incomplete walk, a reparse point or an unreadable file yields NO fingerprint. A partial
        inventory that happened to compare equal would prove the opposite of what the caller asked.
    .OUTPUTS
        Fingerprint (uppercase SHA-256 or $null), FileCount, Complete, Reason.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    $result = [PSCustomObject]@{ Fingerprint = $null; FileCount = 0; Complete = $false; Reason = $null }

    $root = Get-WacNormalizedPath -Path $DeploymentRoot
    if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container)) {
        $result.Reason = 'There is no directory at this path to inventory.'
        return $result
    }

    $walk = Get-WacDeploymentItem -Root $root
    if (-not $walk.Complete) {
        $result.Reason = ('The tree could not be fully enumerated, so no inventory describes it: {0}' -f
            ((@($walk.Failure | ForEach-Object { '{0}: {1}' -f $_.Path, $_.Reason }) | Select-Object -First 3) -join '; '))
        return $result
    }

    $prefix = $root.TrimEnd('\') + '\'
    $lines = New-Object 'System.Collections.Generic.List[string]'

    foreach ($item in @($walk.Entry)) {
        if ($item.IsReparsePoint) {
            $result.Reason = ('The tree holds a reparse point, so its contents are not its own: {0}' -f $item.Path)
            return $result
        }
        if ($item.IsDirectory) { continue }

        $relative = [string]$item.Path
        if ($relative.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relative = $relative.Substring($prefix.Length)
        }

        $hash = Get-WacDeploymentFileHash -Path $item.Path
        if (-not $hash) {
            $result.Reason = ('A file could not be hashed, so the inventory would be short by one: {0}' -f $item.Path)
            return $result
        }

        [void]$lines.Add(('{0}|{1}|{2}' -f $relative.ToUpperInvariant(), $hash,
            [long](New-Object System.IO.FileInfo($item.Path)).Length))
    }

    if ($lines.Count -eq 0) {
        $result.Reason = 'The tree holds no files, so there is nothing to identify it by.'
        return $result
    }

    # ORDINAL, and not Sort-Object: the order of these lines decides the digest, and a culture-aware
    # sort makes the same tree fingerprint differently under a different locale.
    $ordered = [string[]]$lines.ToArray()
    [array]::Sort($ordered, [System.StringComparer]::Ordinal)

    $digest = $null
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($ordered -join "`n"))) }
    finally { $sha.Dispose() }

    $result.Fingerprint = ([System.BitConverter]::ToString($digest)).Replace('-', '').ToUpperInvariant()
    $result.FileCount = $lines.Count
    $result.Complete = $true
    $result.Reason = ('{0} file(s) inventoried.' -f $lines.Count)
    return $result
}

function Get-WacDeploymentJournalPath {
    <#
    .SYNOPSIS
        Where the durable transaction record lives: beside the slots, never inside one, so no move
        or delete of a slot can carry it off with them.
    #>
    param([string]$DeploymentRoot)

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }
    $root = Get-WacNormalizedPath -Path $DeploymentRoot
    if (-not $root) { return $null }
    return ($root + $script:DeploymentJournalSuffix)
}

function Write-WacDeploymentJournal {
    <#
    .SYNOPSIS
        Records the in-flight swap. $false when it could not be written; what that costs is the
        caller's decision, not this function's.
    #>
    param(
        [Parameter(Mandatory = $true)]$Record,
        [string]$DeploymentRoot
    )

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $DeploymentRoot
    if (-not $path) { return $false }

    # Never through a link. The record sits in an administrative directory, and writing through a
    # reparse point somebody else left at that name would write wherever they chose.
    #
    # Only when something is already THERE: Test-WacIsReparsePoint reads the attributes and fails
    # closed, so it answers true for a path that does not exist yet - which is every first write.
    if ((Test-Path -LiteralPath $path) -and (Test-WacIsReparsePoint -Path $path)) {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'The deployment transaction record could not be written: a reparse point stands at its path.' -Data @{ path = $path }
        return $false
    }

    # WRITTEN BESIDE, THEN SWAPPED IN. Writing over the live record meant a crash mid-write left a
    # TORN file - and a torn record is worse than none, because it destroyed the last complete one
    # while looking like an answer. The temporary file absorbs a partial write; the swap is what the
    # next process ever sees, and the displaced record is kept as the previous complete one.
    $staging = $path + '.new'
    $previous = $path + '.last'

    try {
        [System.IO.File]::WriteAllText($staging, (ConvertTo-Json -InputObject $Record -Depth 4),
            (New-Object System.Text.UTF8Encoding($false)))

        if (Test-Path -LiteralPath $path -PathType Leaf) {
            # Replace keeps a copy of what it displaced, so a record that is later found unreadable
            # still has a complete predecessor to reconcile against.
            [System.IO.File]::Replace($staging, $path, $previous, $true)
        }
        else {
            [System.IO.File]::Move($staging, $path)
        }
        return $true
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'The deployment transaction record could not be written.' -Data @{ path = $path; error = $_.Exception.Message }
        try { if (Test-Path -LiteralPath $staging -PathType Leaf) { [System.IO.File]::Delete($staging) } } catch { $null = $_ }
        return $false
    }
}

function Read-WacDeploymentJournal {
    <#
    .SYNOPSIS
        The transaction an earlier PROCESS left behind, or $null when there is none this run may
        act on.
    .DESCRIPTION
        Validated before it is handed back, because it comes off disk and a caller acts on it: our
        schema, our project id, and the deployment root it names has to be the root being
        reconciled. A record that fails any of those is not evidence about this machine's swap, so
        it is discarded rather than half-believed - and one that passes still proves nothing on its
        own, because the caller re-hashes both trees it describes before touching either.
    #>
    param([string]$DeploymentRoot)

    $result = [PSCustomObject]@{ State = 'Absent'; Record = $null; Reason = '' }

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }
    $expectedRoot = Get-WacNormalizedPath -Path $DeploymentRoot
    $path = Get-WacDeploymentJournalPath -DeploymentRoot $DeploymentRoot

    # THREE ANSWERS, NOT TWO. Absent, Valid and Unreadable are different facts and only one of them
    # is permission to act: "there was no transaction" can license discarding a recovery copy, while
    # "there is a record and it cannot be read" must never do so. Collapsing both to $null let a
    # torn or foreign record be read as "nothing happened here".
    if (-not $expectedRoot -or -not $path) {
        $result.State = 'Unreadable'
        $result.Reason = 'the transaction record path could not be resolved'
        return $result
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $result }
    if (Test-WacIsReparsePoint -Path $path) {
        $result.State = 'Unreadable'
        $result.Reason = 'a reparse point stands where the transaction record should be'
        return $result
    }

    $record = $null
    $failure = ''
    try { $record = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($path)) }
    catch { $record = $null; $failure = [string]$_.Exception.Message }

    if (-not $record) {
        $result.State = 'Unreadable'
        $result.Reason = ('the transaction record could not be parsed: {0}' -f $failure).Trim()
        return $result
    }

    $schema = 0
    $projectId = ''
    $root = ''
    try { $schema = [int]$record.Schema } catch { $schema = 0 }
    try { $projectId = [string]$record.ProjectId } catch { $projectId = '' }
    try { $root = [string]$record.Root } catch { $root = '' }

    if ($schema -ne $script:DeploymentJournalSchema -or
        -not [string]::Equals($projectId, $script:DeploymentProjectId, [System.StringComparison]::Ordinal) -or
        -not [string]::Equals($root, $expectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        # A record that is readable but describes something else is NOT absence either: something
        # wrote it, and guessing which deployment it belongs to is exactly the guess to refuse.
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'A deployment transaction record does not describe this deployment.' -Data @{
            path = $path; schema = $schema; root = $root
        }
        $result.State = 'Unreadable'
        $result.Reason = 'the transaction record does not describe this deployment'
        return $result
    }

    $result.State = 'Valid'
    $result.Record = $record
    return $result
}

function Remove-WacDeploymentJournal {
    <#
    .SYNOPSIS
        Ends the recorded transaction. Deleting this file is what says the swap it describes is no
        longer in flight, so it happens at the commit point and after a completed rollback - never
        merely because one step succeeded.
    #>
    param([string]$DeploymentRoot)

    $path = Get-WacDeploymentJournalPath -DeploymentRoot $DeploymentRoot
    if (-not $path) { return $false }
    if (-not (Test-Path -LiteralPath $path)) { return $true }

    try {
        [System.IO.File]::Delete((Get-WacLongPath -Path $path))
        return $true
    }
    catch {
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'The deployment transaction record could not be deleted.' -Data @{ path = $path; error = $_.Exception.Message }
        return $false
    }
}

function Test-WacRecoverySlotIsPromotable {
    <#
    .SYNOPSIS
        Whether the directory in a recovery slot may be moved back onto the deployment root.
    .DESCRIPTION
        That move used to be unconditional whenever the root was empty (ledger WAC-02R), so
        whatever stood in the slot - a foreign tree, a junction pointing anywhere on the machine -
        became what SYSTEM executes. Provenance first, then substance: ownership proves the slot is
        not a reparse point, resolves to itself, holds only names this project deploys and, when it
        carries a manifest, our project id; and it has to hold the Run.ps1 the task exists to run,
        because promoting an empty or gutted slot would put a deployment at the root that cannot
        run, having destroyed whatever was there to make room for it.
    .OUTPUTS
        Promotable, Ownership, Reason.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{ Promotable = $false; Ownership = $null; Reason = $null }

    $ownership = Get-WacDeploymentOwnership -DeploymentRoot $Path
    $result.Ownership = $ownership

    if (-not $ownership.Exists) {
        $result.Reason = 'there is nothing in the recovery slot to put back'
        return $result
    }
    if (-not $ownership.IsOurs) {
        $result.Reason = ('what is in the recovery slot cannot be proven ours: {0}' -f [string]$ownership.Reason)
        return $result
    }
    if (-not (Test-Path -LiteralPath (Join-Path -Path $ownership.Root -ChildPath 'Run.ps1') -PathType Leaf)) {
        $result.Reason = 'the recovery slot holds no Run.ps1, so it is not a deployment that could be put back'
        return $result
    }

    # OURS IS NOT THE SAME AS INTACT. A managed slot whose files no longer hash to its own manifest
    # is still recognisably ours - that is exactly what IsOurs means - and promoting it would put a
    # tampered or half-copied tree at the path SYSTEM executes. Only an unmanaged slot, which has no
    # manifest to disagree with, is exempt.
    if ([string]$ownership.Kind -ceq 'Managed' -and -not [bool]$ownership.IsHealthy) {
        $result.Reason = ('the recovery slot no longer matches its own manifest: {0}' -f [string]$ownership.Reason)
        return $result
    }

    # And what it becomes is code run as SYSTEM, so the same trust walk the deployment root gets
    # applies before it is promoted: a slot any non-administrative account can still write to is one
    # a standard user could have prepared. No ACL is changed - this only reads.
    $trust = Test-WacDeploymentTrusted -DeploymentRoot $ownership.Root
    if (-not [bool]$trust.IsTrusted) {
        $result.Reason = ('the recovery slot cannot be trusted to run as SYSTEM: {0}' -f [string]$trust.Reason)
        return $result
    }

    $result.Promotable = $true
    $result.Reason = [string]$ownership.Reason
    return $result
}
