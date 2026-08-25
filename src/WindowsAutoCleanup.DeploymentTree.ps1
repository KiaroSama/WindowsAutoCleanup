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
