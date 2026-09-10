<#
.SYNOPSIS
    Bounded, link-safe traversal, copy and deletion of the deployment slot directories.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Deploy.psm1; see that file for why the parts are dot-sourced
    rather than imported. This part owns every walk of a deployment tree and the only deletion this
    project performs outside the FileSystem module: Get-WacDeploymentItem never descends into a
    reparse point, Copy-WacDeploymentTree never creates one, and Remove-WacDeployment accepts only
    the three canonical slot paths Get-WacDeploymentSlotPath names.

    $script:MaxTreeDepth is declared here because the depth bound is a property of the walk. All
    parts share one session state, so a read of it from another part is the same variable.
#>

# The tree is Run.ps1 + src + LICENSE; 8 levels is far more than it can legitimately need.
$script:MaxTreeDepth = 8

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
    if ([string]::Equals($Name, 'Logs', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $false
}

function New-WacTreeWalkResult {
    <#
    .SYNOPSIS
        One shape for every return out of Get-WacDeploymentItem, so no exit can forget to say
        whether the walk saw the whole tree.
    #>
    param(
        [Parameter(Mandatory = $true)]$Item,
        [Parameter(Mandatory = $true)]$Failure
    )

    return [PSCustomObject]@{
        Entry = @($Item.ToArray())
        Complete = ($Failure.Count -eq 0)
        Failure = @($Failure.ToArray())
    }
}

function Get-WacDeploymentItem {
    <#
    .SYNOPSIS
        Depth-bounded walk that never descends into a reparse point, and that SAYS when it could not
        see the whole tree.
    .DESCRIPTION
        Get-ChildItem -Recurse follows junctions, which both loops and escapes the tree. A reparse
        point found inside a deployment is reported rather than followed, because the copy never
        creates one and its presence means something else wrote into the tree.

        The walk used to swallow every enumeration error and to stop silently at the depth limit, so
        an unreadable subtree and an empty one produced the same answer. That is how an inaccessible
        deployment root read as "empty, therefore ours", and how a file below the depth limit became
        invisible to the manifest, to the trust check and to the delete pass at once - copied, never
        recorded, never deletable. Incompleteness is a first-class result now: enumeration denial, a
        node that vanished mid-walk, a node that is neither a file nor a directory, a path that will
        not canonicalise, and depth exhaustion each leave Complete false, and every caller that
        would mutate on the strength of this walk has to refuse.
    .OUTPUTS
        Entry    - records with Path, IsDirectory and IsReparsePoint. Nothing is filtered out: a
                   delete pass that skipped a name would leave the parent non-empty and fail.
        Complete - false when anything at all could not be seen.
        Failure  - Path and Reason for each of those.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [int]$Depth = 0
    )

    $items = New-Object 'System.Collections.Generic.List[object]'
    $failures = New-Object 'System.Collections.Generic.List[object]'

    if ($Depth -ge $script:MaxTreeDepth) {
        [void]$failures.Add([PSCustomObject]@{
            Path = $Root
            Reason = ('The {0}-level depth limit was reached, so nothing below this directory was seen.' -f $script:MaxTreeDepth)
        })
        return (New-WacTreeWalkResult -Item $items -Failure $failures)
    }

    $children = @()
    try {
        $children = @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop)
    }
    catch {
        [void]$failures.Add([PSCustomObject]@{
            Path = $Root
            Reason = ('The directory could not be enumerated: {0}' -f $_.Exception.Message)
        })
        return (New-WacTreeWalkResult -Item $items -Failure $failures)
    }

    foreach ($entry in $children) {
        $path = ''
        try { $path = [string]$entry.FullName } catch { $path = '' }

        if ([string]::IsNullOrWhiteSpace($path) -or -not (Get-WacNormalizedPath -Path $path)) {
            [void]$failures.Add([PSCustomObject]@{
                Path = $Root
                Reason = 'An entry under this directory has no path that can be canonicalised.'
            })
            continue
        }

        # Neither a file nor a directory - a device, or some other provider item - is something this
        # walk cannot reason about, and therefore cannot claim to have accounted for.
        $isDirectory = ($entry -is [System.IO.DirectoryInfo])
        if (-not $isDirectory -and -not ($entry -is [System.IO.FileInfo])) {
            [void]$failures.Add([PSCustomObject]@{
                Path = $path
                Reason = 'The entry is neither a file nor a directory, so the walk cannot account for it.'
            })
            continue
        }

        # Re-checked rather than trusting the record the enumeration handed back: an entry that has
        # gone between then and now means the tree moved under the walk, which is missing evidence
        # rather than an absent file.
        if (-not (Test-Path -LiteralPath $path)) {
            [void]$failures.Add([PSCustomObject]@{
                Path = $path
                Reason = 'The entry disappeared while the tree was being walked.'
            })
            continue
        }

        $isReparse = Test-WacIsReparsePoint -Path $path

        [void]$items.Add([PSCustomObject]@{
            Path = $path
            IsDirectory = $isDirectory
            IsReparsePoint = $isReparse
        })

        if ($isDirectory -and -not $isReparse) {
            $child = Get-WacDeploymentItem -Root $path -Depth ($Depth + 1)
            foreach ($record in @($child.Entry)) { [void]$items.Add($record) }
            foreach ($problem in @($child.Failure)) { [void]$failures.Add($problem) }
        }
    }

    return (New-WacTreeWalkResult -Item $items -Failure $failures)
}

function Copy-WacDeploymentTree {
    <#
    .SYNOPSIS
        Recursive copy that skips excluded names and never follows a reparse point.
    .DESCRIPTION
        -Depth is the level of DESTINATION inside the deployment root, counting the root itself as
        0, and the caller has to say so: the top-level src copy passes 1, because it lands at
        <root>\src. That is not bookkeeping. Get-WacDeploymentItem counts from the deployment root
        and will not enumerate past level 8, while this guard used to count from the src directory
        instead - the two disagreed by exactly one level, so a file seven directories below src was
        copied into the deployment and then never enumerated, never manifested, never trust-checked
        and never deletable (measured: copied=True, enumerated=0). Counting from the same origin
        makes the deepest copyable item and the deepest enumerable item the same item.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [int]$Depth = 0
    )

    if ($Depth -ge $script:MaxTreeDepth) {
        throw ("The source tree is deeper than the {0} levels the deployment walk can enumerate: {1}" -f $script:MaxTreeDepth, $Source)
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
        # ORDINAL, not -ieq: this is the delete allow-list for the deployment slots.
        if ([string]::Equals($normalized, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) { $isAllowed = $true; break }
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

    # A walk that could not see everything is not permission to delete what it did see: that would
    # take real files out of a tree whose contents were never established, and the directory this
    # was asked to remove would then fail as non-empty anyway.
    $walk = Get-WacDeploymentItem -Root $normalized
    if (-not $walk.Complete) {
        $result.Reason = ('The tree could not be fully enumerated, so nothing was deleted: {0}' -f
            ((@($walk.Failure | ForEach-Object { '{0}: {1}' -f $_.Path, $_.Reason }) | Select-Object -First 3) -join '; '))
        Write-WacLog -Level WARNING -Component 'Deploy' -Message 'Refused a delete over a tree that could not be fully enumerated.' -Data @{
            path = $normalized; reason = $result.Reason
        }
        return $result
    }

    # Deepest first by separator count, so a directory is always empty by the time it is deleted.
    # Sorting the path STRING would be culture-aware and is not a reliable depth order.
    foreach ($item in @($walk.Entry | Sort-Object -Property @{ Expression = { $_.Path.Split('\').Length } } -Descending)) {
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
