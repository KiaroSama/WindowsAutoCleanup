<#
.SYNOPSIS
    Fail-closed, restartable campaign state and staged-payload verification.
#>
Set-StrictMode -Version 2.0

function Test-WacCampaignStateShape {
    param([AllowNull()]$State)
    try {
        if ($null -eq $State -or $State.schema -ne 1 -or $State.destructiveAuthorized -isnot [bool]) { return $false }
        if ([string]$State.campaignId -notmatch '^[a-fA-F0-9]{32}$' -or [string]$State.commit -notmatch '^[a-fA-F0-9]{40}$') { return $false }
        if (@('running', 'awaiting-power-cut', 'complete', 'failed') -cnotcontains $State.phase) { return $false }
        foreach ($key in @('scenarios', 'completed', 'results')) {
            if ($null -eq $State.$key -or $State.$key -is [string]) { return $false }
        }
        if (@($State.scenarios).Count -lt 1 -or @($State.scenarios | Select-Object -Unique).Count -ne @($State.scenarios).Count) { return $false }
        foreach ($scenario in @($State.scenarios)) {
            if (@('service-dispatched-maintenance', 'power-loss-during-install', 'power-loss-during-uninstall',
                'reboot-recovery', 'driver-prune', 'reset-base') -cnotcontains $scenario) { return $false }
        }
        if ([string]::IsNullOrWhiteSpace([string]$State.projectRoot) -or
            -not [IO.Path]::IsPathRooted([string]$State.projectRoot)) { return $false }
        foreach ($done in @($State.completed)) { if (@($State.scenarios) -cnotcontains $done) { return $false } }
        if ($State.phase -ceq 'awaiting-power-cut' -and @($State.scenarios) -cnotcontains $State.cutStep) { return $false }
        return $true
    }
    catch { return $false }
}

function Test-WacCampaignPathPresent {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $null = [IO.File]::GetAttributes($Path)
        return $true
    }
    catch [IO.FileNotFoundException] { return $false }
    catch [IO.DirectoryNotFoundException] { return $false }
    # Access denial, invalid name and all other failures deliberately propagate.
}

function Get-WacCampaignState {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-WacCampaignPathPresent -Path ($Path + '.pending')) {
        throw 'An interrupted state publication remains; preserve it and resolve before accepting another request.'
    }
    if (-not (Test-WacCampaignPathPresent -Path $Path)) { return $null }
    $attributes = [IO.File]::GetAttributes($Path)
    if (($attributes -band [IO.FileAttributes]::Directory) -or ($attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Campaign state is not a regular file.'
    }
    $state = [IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop
    if (-not (Test-WacCampaignStateShape -State $state)) { throw 'Campaign state is invalid; it is not a first-run absence.' }
    return $state
}

function Save-WacCampaignState {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$State)
    if (-not (Test-WacCampaignStateShape -State $State)) { throw 'Refusing to publish invalid campaign state.' }
    $directory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    if (-not [IO.Directory]::Exists($directory)) { throw 'Campaign state directory must already exist.' }
    # No overwrite of a stranded stage and no in-place truncation of the authoritative record.
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $State -Depth 12))
    $pending = $Path + '.pending'
    $stream = [IO.File]::Open($pending, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    # A failure deliberately leaves pending plus the previous authoritative file for inspection.
    if (Test-WacCampaignPathPresent -Path $Path) {
        $previous = Get-WacCampaignStateValue -Path $Path
        if ($previous.campaignId -cne $State.campaignId -or $previous.commit -cne $State.commit -or
            $previous.projectRoot -cne $State.projectRoot -or
            (@($previous.scenarios) -join '|') -cne (@($State.scenarios) -join '|')) {
            throw 'Publication cannot replace a different campaign identity.'
        }
        [IO.File]::Replace($pending, $Path, [Management.Automation.Language.NullString]::Value)
    }
    else { [IO.File]::Move($pending, $Path) }
}

function Get-WacCampaignStateValue {
    param([Parameter(Mandatory = $true)][string]$Path)
    $attributes = [IO.File]::GetAttributes($Path)
    if (($attributes -band [IO.FileAttributes]::Directory) -or ($attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The existing state is not a regular file.'
    }
    $state = [IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop
    if (-not (Test-WacCampaignStateShape -State $state)) { throw 'Existing campaign state cannot be overwritten without recovery.' }
    return $state
}

function Get-WacCampaignPayloadFingerprint {
    param([Parameter(Mandatory = $true)][string]$Directory, [switch]$Flush)
    $root = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $pending = New-Object 'Collections.Generic.Stack[string]'
    $pending.Push($root)
    $files = New-Object 'Collections.Generic.List[object]'
    while ($pending.Count -gt 0) {
        $directoryPath = $pending.Pop()
        $attributes = [IO.File]::GetAttributes($directoryPath)
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Campaign payload directory is a reparse point.' }
        foreach ($entry in @(Get-ChildItem -LiteralPath $directoryPath -Force -ErrorAction Stop)) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Campaign payload contains a reparse point.' }
            if ($entry.PSIsContainer) { $pending.Push($entry.FullName) } else { [void]$files.Add($entry) }
        }
    }
    $items = @($files.ToArray() | Sort-Object FullName)
    $rows = New-Object 'Collections.Generic.List[string]'
    foreach ($item in $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Campaign payload cannot contain reparse points.' }
        if ($item.PSIsContainer) { continue }
        if ($Flush) {
            $stream = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
            try { $stream.Flush($true) } finally { $stream.Dispose() }
        }
        $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        [void]$rows.Add($item.FullName.Substring($root.Length + 1).Replace('\', '/') + ':' + $hash)
    }
    if ($rows.Count -eq 0) { throw 'Campaign payload has no files.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($rows -join "`n"))).Replace('-', '')) }
    finally { $sha.Dispose() }
}

function Test-WacCampaignResume {
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$WorkRoot)
    try {
        $expected = Join-Path ([IO.Path]::GetFullPath($WorkRoot)) ([string]$State.commit).Substring(0, 12)
        if (-not [string]::Equals([IO.Path]::GetFullPath([string]$State.projectRoot), $expected, [StringComparison]::OrdinalIgnoreCase)) { return $false }
        if ((Get-WacCampaignPayloadFingerprint -Directory $expected) -cne $State.payloadFingerprint) { return $false }
        Import-Module (Join-Path $expected 'src\WindowsAutoCleanup.Core.psm1') -DisableNameChecking -ErrorAction Stop
        return [bool](Test-WacMachineRestartedSince -RaisedUtc $null -RaisedUptimeMs $State.cutUptimeMs).Restarted
    }
    catch { return $false }
}
