#Requires -Version 5.1
<#
.SYNOPSIS
    Safely cleans the allow-list locations on drive C: plus the full Disk Cleanup
    "Clean up system files" categories, DISM component store cleanup, and the
    Recycle Bin on drive C:.

.DESCRIPTION
    WindowsAutoCleanup is a silent, administrator-only cleanup script for Windows.
    It permanently removes files from the cleanup locations defined in this script,
    runs cleanmgr.exe with a sage profile for the standard Disk Cleanup categories,
    runs DISM component store cleanup, runs the Windows driver package cleanup
    handler, and clears the Recycle Bin on drive C: only.
    Locked or inaccessible files are skipped. The script avoids interactive prompts
    and writes concise logs next to the script.
#>

[CmdletBinding()]
param(
    # Used by Task Scheduler. Scheduled execution fails fast instead of trying an interactive UAC relaunch.
    [switch]$Scheduled,

    # Aggressive component cleanup is enabled by default to reduce Windows Update
    # Cleanup further. Installed Windows updates cannot be uninstalled afterwards.
    # Pass -ResetWindowsUpdateBase:$false to disable it for a specific manual run.
    [switch]$ResetWindowsUpdateBase = $true,

    # Skip the one-time project-folder ACL hardening step. This is useful for
    # development checkouts where normal Git/edit workflows must keep write access.
    [switch]$SkipAclHardening
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$script:ScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$script:ScriptRoot = Split-Path -Parent $script:ScriptPath
$script:LogRoot = Join-Path -Path $script:ScriptRoot -ChildPath 'Logs'
$script:LogPath = $null
$script:AclHardeningMarkerPath = Join-Path -Path $script:ScriptRoot -ChildPath '.WindowsAutoCleanupAclHardened'
$script:MoveFileExLoadWarningLogged = $false
$script:AttemptedCategories = New-Object 'System.Collections.Generic.List[string]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:Results = New-Object 'System.Collections.Generic.List[object]'
$script:TotalFilesDeleted = 0L
$script:TotalDirectoriesDeleted = 0L
$script:TotalReparsePointsDeleted = 0L
$script:TotalFailed = 0L
$script:TotalSkipped = 0L
$script:TotalPendingDeletes = 0L
$script:StartFreeBytesC = $null
$script:EndFreeBytesC = $null

# Sage profile id used to drive cleanmgr.exe /sagerun. Chosen to avoid collisions
# with profiles other tools may have set under HKLM:\...\VolumeCaches.
$script:DiskCleanupSageId = 9999

# Disk Cleanup categories enabled when running cleanmgr.exe.
# Recycle Bin is intentionally excluded here because cleanmgr would clean it on
# every drive. The Recycle Bin on drive C: is cleared separately by Clear-RecycleBinDriveC.
# Previous Installations (Windows.old) is also excluded because the script already
# removes Windows.old explicitly through the allow-list targets.
$script:DiskCleanupCategories = @(
    'Update Cleanup',                                # Windows Update Cleanup (skipped when DISM /ResetBase is enabled)
    'Microsoft Defender',                            # Microsoft Defender Antivirus (modern Windows)
    'Windows Defender',                              # Microsoft Defender Antivirus (older Windows)
    'Windows Upgrade Log Files',                     # Windows upgrade log files
    'Setup Log Files',                               # Older upgrade/setup log files
    'Downloaded Program Files',                      # Downloaded Program Files
    'Internet Cache Files',                          # Temporary Internet Files
    'Windows Error Reporting Files',                 # WER (older grouping)
    'Windows Error Reporting Archive Files',         # WER archive
    'Windows Error Reporting Queue Files',           # WER queue
    'Windows Error Reporting System Archive Files',  # WER system archive
    'Windows Error Reporting System Queue Files',    # WER system queue
    'Windows Error Reporting Temp Files',            # WER temp
    'D3D Shader Cache',                              # DirectX Shader Cache
    'Delivery Optimization Files',                   # Delivery Optimization Files
    'Device Driver Packages',                        # Device driver packages (also run directly through pnpclean.dll)
    'Language Pack',                                 # Language Resource Files
    'Temporary Files',                               # Temporary files
    'Thumbnail Cache'                                # Thumbnail cache
)

# Default timeout for long-running external cleanup tools.
$script:ExternalToolTimeoutMs = 1000 * 60 * 60 * 2  # 2 hours

# cleanmgr.exe is legacy and can hang on some handlers. Keep its watchdog short
# so DISM and driver cleanup remain the authoritative cleanup paths.
$script:DiskCleanupTimeoutMs = 1000 * 60 * 5  # 5 minutes

function Initialize-Log {
    try {
        if (-not (Test-Path -LiteralPath $script:LogRoot -PathType Container)) {
            New-Item -Path $script:LogRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        $name = 'WindowsAutoCleanup_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        $script:LogPath = Join-Path -Path $script:LogRoot -ChildPath $name
        New-Item -Path $script:LogPath -ItemType File -Force -ErrorAction Stop | Out-Null
    }
    catch {
        $fallbackRoot = if ($env:ProgramData) {
            Join-Path -Path $env:ProgramData -ChildPath 'WindowsAutoCleanup\Logs'
        }
        else {
            Join-Path -Path $env:SystemRoot -ChildPath 'Logs\WindowsAutoCleanup'
        }
        try {
            if (-not (Test-Path -LiteralPath $fallbackRoot -PathType Container)) {
                New-Item -Path $fallbackRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        }
        catch {
            $fallbackRoot = Join-Path -Path $env:SystemRoot -ChildPath 'Logs\WindowsAutoCleanup'
            try {
                if (-not (Test-Path -LiteralPath $fallbackRoot -PathType Container)) {
                    New-Item -Path $fallbackRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
            }
            catch { $null = $_ }
        }
        $script:LogPath = Join-Path -Path $fallbackRoot -ChildPath ('WindowsAutoCleanup_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        New-Item -Path $script:LogPath -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

function Write-CleanupLog {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('INFO','WARN','ERROR')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $script:LogPath) { return }

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Cleanup must stay silent even when logging fails.
        $null = $_
    }
}

function Add-CleanupWarning {
    param([Parameter(Mandatory = $true)][string]$Message)

    $script:Warnings.Add($Message) | Out-Null
    Write-CleanupLog -Level 'WARN' -Message $Message
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-PreferredPowerShellPath {
    # Prefer PowerShell 7 (pwsh.exe) when available; fall back to Windows PowerShell 5.1.
    # The script's #Requires -Version 5.1 is satisfied by both hosts.
    $pwshCmd = @(Get-Command -Name 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($pwshCmd.Count -gt 0) {
        $pwshPath = [string]$pwshCmd[0].Source
        if ($pwshPath -and (Test-Path -LiteralPath $pwshPath -PathType Leaf)) {
            return $pwshPath
        }
    }

    # Try the canonical PowerShell 7 install location even when not on PATH (for
    # example, when running under SYSTEM whose PATH may not include it).
    if ($env:ProgramFiles) {
        $defaultPwsh = Join-Path -Path $env:ProgramFiles -ChildPath 'PowerShell\7\pwsh.exe'
        if (Test-Path -LiteralPath $defaultPwsh -PathType Leaf) {
            return $defaultPwsh
        }
    }

    # Fall back to Windows PowerShell 5.1, which is always present on supported Windows.
    return (Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

function Invoke-ElevatedRelaunchIfNeeded {
    if (Test-IsAdministrator) { return }

    if ($Scheduled) {
        Initialize-Log
        Write-CleanupLog -Level 'ERROR' -Message 'Administrator privileges are required. Scheduled execution is not elevated.'
        exit 1
    }

    $powerShellExe = Get-PreferredPowerShellPath
    $scriptArg = '"{0}"' -f $script:ScriptPath
    $childArgs = '-NoProfile -ExecutionPolicy Bypass -File {0}' -f $scriptArg
    if ($PSBoundParameters.ContainsKey('ResetWindowsUpdateBase')) {
        $childArgs = '{0} -ResetWindowsUpdateBase:${1}' -f $childArgs, ([bool]$ResetWindowsUpdateBase).ToString().ToLowerInvariant()
    }
    if ($SkipAclHardening) {
        $childArgs = '{0} -SkipAclHardening' -f $childArgs
    }

    try {
        $wt = Get-Command -Name 'wt.exe' -ErrorAction SilentlyContinue
        if ($wt -and $wt.Source) {
            # Pass the preferred PowerShell binary explicitly so Windows Terminal does
            # not fall back to its default profile (which is usually Windows PowerShell 5.1).
            $wtArgs = '"{0}" {1}' -f $powerShellExe, $childArgs
            Start-Process -FilePath $wt.Source -ArgumentList $wtArgs -Verb RunAs -ErrorAction Stop | Out-Null
        }
        else {
            Start-Process -FilePath $powerShellExe -ArgumentList $childArgs -Verb RunAs -ErrorAction Stop | Out-Null
        }
        exit 0
    }
    catch {
        Initialize-Log
        Write-CleanupLog -Level 'ERROR' -Message ('Failed to relaunch as administrator: {0}' -f $_.Exception.Message)
        exit 1
    }
}

function Test-IsSafeScriptRootForAclHardening {
    $normalized = Get-NormalizedPath -Path $script:ScriptRoot
    if (-not $normalized) { return $false }

    if ($normalized -match '^[A-Za-z]:\\?$') { return $false }

    $unsafeExactRoots = @(
        $env:SystemRoot,
        (Join-Path -Path $env:SystemRoot -ChildPath 'System32'),
        (Join-Path -Path $env:SystemRoot -ChildPath 'SysWOW64'),
        'C:\Users',
        'C:\ProgramData',
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($root in $unsafeExactRoots) {
        $candidate = Get-NormalizedPath -Path $root
        if ($candidate -and [string]::Equals($normalized, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }

    return $true
}

function Set-WindowsAutoCleanupItemAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$IsDirectory
    )

    $systemSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $usersSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'
    $authenticatedUsersSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-11'
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    if ($IsDirectory) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
    }
    else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
    }

    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($systemSid)

    $acl.AddAccessRule(([System.Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow
    )))
    $acl.AddAccessRule(([System.Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow
    )))
    $acl.AddAccessRule(([System.Security.AccessControl.FileSystemAccessRule]::new(
        $usersSid,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inheritance,
        $propagation,
        $allow
    )))
    $acl.AddAccessRule(([System.Security.AccessControl.FileSystemAccessRule]::new(
        $authenticatedUsersSid,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inheritance,
        $propagation,
        $allow
    )))

    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Invoke-ScriptRootAclHardening {
    if (Test-Path -LiteralPath $script:AclHardeningMarkerPath -PathType Leaf) {
        Write-CleanupLog -Level 'INFO' -Message 'Script folder ACL hardening already applied; marker found.'
        return
    }

    if (-not (Test-IsAdministrator)) {
        Add-CleanupWarning 'Script folder ACL hardening skipped because administrator privileges are not active.'
        return
    }

    $root = Get-NormalizedPath -Path $script:ScriptRoot
    if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container) -or -not (Test-IsSafeScriptRootForAclHardening)) {
        Add-CleanupWarning ("Script folder ACL hardening skipped because the script root is unsafe: {0}" -f $script:ScriptRoot)
        return
    }

    Write-CleanupLog -Level 'INFO' -Message ("Applying one-time script folder ACL hardening: {0}" -f $root)

    $directories = New-Object 'System.Collections.Generic.List[string]'
    $files = New-Object 'System.Collections.Generic.List[string]'
    $skippedReparsePoints = 0L
    $failed = 0L

    try {
        $stack = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
        $stack.Push((New-Object System.IO.DirectoryInfo($root)))
        [void]$directories.Add($root)

        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            $items = $null
            try {
                $items = $current.GetFileSystemInfos()
            }
            catch {
                $failed++
                continue
            }

            foreach ($item in $items) {
                if (-not (Test-IsWithinRoot -ChildPath $item.FullName -RootPath $root)) {
                    $skippedReparsePoints++
                    continue
                }

                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $skippedReparsePoints++
                    continue
                }

                if ($item -is [System.IO.DirectoryInfo]) {
                    [void]$directories.Add($item.FullName)
                    $stack.Push($item)
                }
                else {
                    [void]$files.Add($item.FullName)
                }
            }
        }

        foreach ($file in $files) {
            try { Set-WindowsAutoCleanupItemAcl -Path $file -IsDirectory $false }
            catch { $failed++ }
        }

        $directories |
            Sort-Object -Property Length -Descending |
            ForEach-Object {
                try { Set-WindowsAutoCleanupItemAcl -Path $_ -IsDirectory $true }
                catch { $failed++ }
            }

        try {
            New-Item -Path $script:AclHardeningMarkerPath -ItemType File -Force -ErrorAction Stop | Out-Null
            Set-WindowsAutoCleanupItemAcl -Path $script:AclHardeningMarkerPath -IsDirectory $false
        }
        catch {
            $failed++
        }

        if ($failed -gt 0) {
            Add-CleanupWarning ("Script folder ACL hardening completed with {0} failed item(s) and {1} skipped reparse point(s)." -f $failed, $skippedReparsePoints)
        }
        else {
            Write-CleanupLog -Level 'INFO' -Message ("Script folder ACL hardening completed. Files={0}; Directories={1}; SkippedReparsePoints={2}." -f $files.Count, $directories.Count, $skippedReparsePoints)
        }
    }
    catch {
        Add-CleanupWarning ("Script folder ACL hardening failed: {0}" -f $_.Exception.Message)
    }
}

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $candidate = $Path.Trim()

    # Normalize extended-length paths that still point to a normal drive path.
    # UNC and volume-GUID forms are intentionally rejected by the C: allow-list.
    if ($candidate.StartsWith('\\?\', [System.StringComparison]::OrdinalIgnoreCase)) {
        if ($candidate -match '^\\\\\?\\([A-Za-z]:\\.*)$') {
            $candidate = $Matches[1]
        }
        elseif ($candidate -match '^\\\\\?\\([A-Za-z]:)$') {
            return $Matches[1].ToUpperInvariant()
        }
        else {
            return $null
        }
    }

    # Handle bare drive-letter inputs like 'C:' explicitly. Reject drive-relative
    # forms like 'C:foo' because .NET resolves them against a mutable per-drive CWD.
    if ($candidate -match '^[A-Za-z]:$') {
        return $candidate.ToUpperInvariant()
    }
    if ($candidate -match '^[A-Za-z]:(?!\\)') {
        return $null
    }

    try {
        return ([System.IO.Path]::GetFullPath($candidate)).TrimEnd('\')
    }
    catch {
        return $null
    }
}

function Test-IsOnCDrive {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = Get-NormalizedPath -Path $Path
    if (-not $normalized) { return $false }

    return ($normalized -ieq 'C:' -or $normalized.StartsWith('C:\', [System.StringComparison]::OrdinalIgnoreCase))
}

function Test-IsProtectedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = Get-NormalizedPath -Path $Path
    if (-not $normalized) { return $true }

    $protected = @(
        'C:',
        'C:\',
        'C:\Windows',
        'C:\Users',
        'C:\ProgramData',
        'C:\Program Files',
        'C:\Program Files (x86)',
        'C:\Windows\System32',
        'C:\Windows\SysWOW64'
    )

    foreach ($item in $protected) {
        $p = (Get-NormalizedPath -Path $item)
        if ($normalized -ieq $p) { return $true }
    }

    $scriptRootNormalized = Get-NormalizedPath -Path $script:ScriptRoot
    if ($scriptRootNormalized) {
        if ($normalized -ieq $scriptRootNormalized) { return $true }
        if ($normalized.StartsWith($scriptRootNormalized + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }

    return $false
}

function Test-IsSafeTargetPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = Get-NormalizedPath -Path $Path
    if (-not $normalized) { return $false }
    if (-not (Test-IsOnCDrive -Path $normalized)) { return $false }
    if (Test-IsProtectedPath -Path $normalized) { return $false }

    return $true
}

function Test-IsWithinRoot {
    param(
        [Parameter(Mandatory = $true)][string]$ChildPath,
        [Parameter(Mandatory = $true)][string]$RootPath
    )

    $child = Get-NormalizedPath -Path $ChildPath
    $root = Get-NormalizedPath -Path $RootPath
    if (-not $child -or -not $root) { return $false }

    return ($child -ieq $root -or $child.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase))
}

function Get-CDriveFreeBytes {
    try {
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        if ($disk -and $null -ne $disk.FreeSpace) { return [int64]$disk.FreeSpace }
    }
    catch {
        try {
            $drive = Get-PSDrive -Name C -ErrorAction Stop
            if ($drive -and $null -ne $drive.Free) { return [int64]$drive.Free }
        }
        catch { $null = $_ }
    }

    return $null
}

function Test-IsWindowsServer {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($null -ne $os.ProductType -and [int]$os.ProductType -ne 1) { return $true }
        if ($os.Caption -match '\bServer\b') { return $true }
    }
    catch { $null = $_ }

    return $false
}

function Format-Bytes {
    param([Nullable[Int64]]$Bytes)

    if ($null -eq $Bytes) { return 'Unknown' }
    if ($Bytes -lt 0) { return ('{0:N0} bytes' -f $Bytes) }

    $value = [double]$Bytes
    $units = @('bytes','KB','MB','GB','TB')
    $index = 0

    while ($value -ge 1024 -and $index -lt ($units.Count - 1)) {
        $value = $value / 1024
        $index++
    }

    if ($index -eq 0) { return ('{0:N0} {1}' -f $value, $units[$index]) }
    return ('{0:N2} {1}' -f $value, $units[$index])
}

function New-Result {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [int64]$FilesDeleted = 0,
        [int64]$DirectoriesDeleted = 0,
        [int64]$ReparsePointsDeleted = 0,
        [int64]$PendingDeletes = 0,
        [int64]$Skipped = 0,
        [int64]$Failed = 0
    )

    $result = [PSCustomObject]@{
        Category = $Category
        Path = $Path
        FilesDeleted = $FilesDeleted
        DirectoriesDeleted = $DirectoriesDeleted
        ReparsePointsDeleted = $ReparsePointsDeleted
        PendingDeletes = $PendingDeletes
        Skipped = $Skipped
        Failed = $Failed
    }

    $script:Results.Add($result) | Out-Null
    $script:TotalFilesDeleted += $FilesDeleted
    $script:TotalDirectoriesDeleted += $DirectoriesDeleted
    $script:TotalReparsePointsDeleted += $ReparsePointsDeleted
    $script:TotalPendingDeletes += $PendingDeletes
    $script:TotalSkipped += $Skipped
    $script:TotalFailed += $Failed
}

function Register-PendingDeleteOnReboot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = Get-NormalizedPath -Path $Path
    if (-not $normalized) { return $false }
    if (-not (Test-IsOnCDrive -Path $normalized)) { return $false }
    if (Test-IsProtectedPath -Path $normalized) { return $false }

    try {
        if (-not ('MoveFileExNative' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class MoveFileExNative
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
}
'@ -ErrorAction Stop | Out-Null
        }

        # MOVEFILE_DELAY_UNTIL_REBOOT = 0x4. Passing null as destination requests deletion.
        return [MoveFileExNative]::MoveFileEx($normalized, $null, 0x4)
    }
    catch {
        if (-not $script:MoveFileExLoadWarningLogged) {
            Add-CleanupWarning ("Pending-delete registration is unavailable: {0}" -f $_.Exception.Message)
            $script:MoveFileExLoadWarningLogged = $true
        }
        return $false
    }
}

function Remove-FileSystemInfoLeaf {
    param(
        [Parameter(Mandatory = $true)]$Item,
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][hashtable]$Stats
    )

    try {
        if (-not (Test-IsWithinRoot -ChildPath $Item.FullName -RootPath $RootPath)) {
            $Stats.Skipped++
            return
        }

        if (-not (Test-IsOnCDrive -Path $Item.FullName)) {
            $Stats.Skipped++
            return
        }

        if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            if ($Item -is [System.IO.DirectoryInfo]) {
                [System.IO.Directory]::Delete($Item.FullName, $false)
            }
            else {
                [System.IO.File]::Delete($Item.FullName)
            }
            $Stats.ReparsePointsDeleted++
            return
        }

        if ($Item -is [System.IO.DirectoryInfo]) {
            [System.IO.Directory]::Delete($Item.FullName, $false)
            $Stats.DirectoriesDeleted++
        }
        else {
            [System.IO.File]::Delete($Item.FullName)
            $Stats.FilesDeleted++
        }
    }
    catch [System.IO.IOException], [System.UnauthorizedAccessException] {
        # Locked or protected files are common in Defender and Explorer caches. If
        # possible, ask Windows to delete the file during the next boot before it is
        # opened again; otherwise keep the previous skip behavior.
        if (($Item -is [System.IO.FileInfo]) -and (Register-PendingDeleteOnReboot -Path $Item.FullName)) {
            $Stats.PendingDeletes++
        }
        else {
            $Stats.Skipped++
        }
    }
    catch {
        $Stats.Failed++
    }
}

function Remove-DirectoryTreeSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$DeleteRoot
    )

    $normalizedRoot = Get-NormalizedPath -Path $Path
    if (-not $normalizedRoot -or -not (Test-IsSafeTargetPath -Path $normalizedRoot)) {
        Add-CleanupWarning "Skipped unsafe target for '$Category': $Path"
        New-Result -Category $Category -Path $Path -Skipped 1
        return
    }

    if (-not (Test-Path -LiteralPath $normalizedRoot -PathType Container)) {
        New-Result -Category $Category -Path $normalizedRoot -Skipped 1
        return
    }

    # Refuse to traverse into a root that is itself a junction, symlink, or other
    # reparse point. Following it could redirect the cleanup at the start of the
    # operation. Reparse points discovered during traversal are handled separately
    # as leaves without recursion.
    try {
        $rootAttr = [System.IO.File]::GetAttributes($normalizedRoot)
        if (($rootAttr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Write-CleanupLog -Level 'INFO' -Message "Skipping reparse-point root for '$Category': $normalizedRoot"
            New-Result -Category $Category -Path $normalizedRoot -Skipped 1
            return
        }
    }
    catch {
        Add-CleanupWarning ("Could not read attributes for '{0}': {1}" -f $normalizedRoot, $_.Exception.Message)
        New-Result -Category $Category -Path $normalizedRoot -Failed 1
        return
    }

    $script:AttemptedCategories.Add($Category) | Out-Null
    Write-CleanupLog -Level 'INFO' -Message "Attempting category '$Category': $normalizedRoot"

    $stats = @{ FilesDeleted = 0L; DirectoriesDeleted = 0L; ReparsePointsDeleted = 0L; PendingDeletes = 0L; Skipped = 0L; Failed = 0L }
    $rootInfo = $null

    try {
        $rootInfo = New-Object System.IO.DirectoryInfo($normalizedRoot)
    }
    catch {
        $stats.Failed++
        New-Result -Category $Category -Path $normalizedRoot -Failed $stats.Failed
        return
    }

    $stack = New-Object 'System.Collections.Generic.Stack[System.IO.DirectoryInfo]'
    $directoriesForLaterDelete = New-Object 'System.Collections.Generic.List[System.IO.DirectoryInfo]'
    $stack.Push($rootInfo)

    while ($stack.Count -gt 0) {
        $current = $stack.Pop()

        try {
            $items = $current.GetFileSystemInfos()
        }
        catch [System.IO.IOException], [System.UnauthorizedAccessException] {
            # Directory was removed mid-traversal, is locked, or denies enumeration.
            # Treat as a skip rather than a hard failure.
            $stats.Skipped++
            continue
        }
        catch {
            $stats.Failed++
            continue
        }

        foreach ($item in $items) {
            if (-not (Test-IsWithinRoot -ChildPath $item.FullName -RootPath $normalizedRoot)) {
                $stats.Skipped++
                continue
            }

            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                Remove-FileSystemInfoLeaf -Item $item -RootPath $normalizedRoot -Stats $stats
                continue
            }

            if ($item -is [System.IO.DirectoryInfo]) {
                $directoriesForLaterDelete.Add($item) | Out-Null
                $stack.Push($item)
            }
            else {
                Remove-FileSystemInfoLeaf -Item $item -RootPath $normalizedRoot -Stats $stats
            }
        }
    }

    $directoriesForLaterDelete |
        Sort-Object -Property FullName -Descending |
        ForEach-Object {
            Remove-FileSystemInfoLeaf -Item $_ -RootPath $normalizedRoot -Stats $stats
        }

    if ($DeleteRoot) {
        try {
            if (-not (Test-IsProtectedPath -Path $normalizedRoot) -and (Test-IsSafeTargetPath -Path $normalizedRoot)) {
                [System.IO.Directory]::Delete($normalizedRoot, $false)
                $stats.DirectoriesDeleted++
            }
            else {
                $stats.Skipped++
            }
        }
        catch [System.IO.IOException], [System.UnauthorizedAccessException] {
            # Root is non-empty (children were locked) or denied. Skip.
            $stats.Skipped++
        }
        catch {
            $stats.Failed++
        }
    }

    New-Result `
        -Category $Category `
        -Path $normalizedRoot `
        -FilesDeleted $stats.FilesDeleted `
        -DirectoriesDeleted $stats.DirectoriesDeleted `
        -ReparsePointsDeleted $stats.ReparsePointsDeleted `
        -PendingDeletes $stats.PendingDeletes `
        -Skipped $stats.Skipped `
        -Failed $stats.Failed
}

function Remove-FilesByPatternSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$DirectoryPath,
        [Parameter(Mandatory = $true)][string[]]$Patterns
    )

    $normalizedRoot = Get-NormalizedPath -Path $DirectoryPath
    if (-not $normalizedRoot -or -not (Test-IsSafeTargetPath -Path $normalizedRoot)) {
        Add-CleanupWarning "Skipped unsafe target for '$Category': $DirectoryPath"
        New-Result -Category $Category -Path $DirectoryPath -Skipped 1
        return
    }

    if (-not (Test-Path -LiteralPath $normalizedRoot -PathType Container)) {
        New-Result -Category $Category -Path $normalizedRoot -Skipped 1
        return
    }

    $script:AttemptedCategories.Add($Category) | Out-Null
    Write-CleanupLog -Level 'INFO' -Message "Attempting category '$Category': $normalizedRoot"

    $stats = @{ FilesDeleted = 0L; DirectoriesDeleted = 0L; ReparsePointsDeleted = 0L; PendingDeletes = 0L; Skipped = 0L; Failed = 0L }

    foreach ($pattern in $Patterns) {
        try {
            # Avoid the automatic $Matches variable so the -match operator state is
            # never accidentally shadowed elsewhere in the script.
            $matchedFiles = Get-ChildItem -LiteralPath $normalizedRoot -Filter $pattern -File -Force -ErrorAction Stop
        }
        catch [System.IO.IOException], [System.UnauthorizedAccessException] {
            $stats.Skipped++
            continue
        }
        catch {
            $stats.Failed++
            continue
        }

        foreach ($matchedFile in $matchedFiles) {
            Remove-FileSystemInfoLeaf -Item $matchedFile -RootPath $normalizedRoot -Stats $stats
        }
    }

    New-Result `
        -Category $Category `
        -Path $normalizedRoot `
        -FilesDeleted $stats.FilesDeleted `
        -DirectoriesDeleted $stats.DirectoriesDeleted `
        -ReparsePointsDeleted $stats.ReparsePointsDeleted `
        -PendingDeletes $stats.PendingDeletes `
        -Skipped $stats.Skipped `
        -Failed $stats.Failed
}

function Get-UserProfileDirectories {
    $usersRoot = 'C:\Users'
    if (-not (Test-Path -LiteralPath $usersRoot -PathType Container)) { return @() }

    $excludedProfileNames = @('All Users', 'Default', 'Default User', 'Public')

    try {
        # Filter out reparse points such as the legacy 'Default User' and 'All Users'
        # junctions, plus non-interactive template/shared profiles. Following them
        # only adds skipped noise and can touch locations that are not user caches.
        return @(
            Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction Stop |
                Where-Object {
                    ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
                    $_.Name -notin $excludedProfileNames
                }
        )
    }
    catch {
        Add-CleanupWarning "Could not enumerate C:\Users: $($_.Exception.Message)"
        return @()
    }
}

function Add-UniqueDirectoryTarget {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Targets,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$DeleteRoot
    )

    $normalized = Get-NormalizedPath -Path $Path
    if (-not $normalized) { return }
    if (-not (Test-IsOnCDrive -Path $normalized)) { return }

    foreach ($target in $Targets) {
        if (($target.Mode -eq 'Directory') -and ((Get-NormalizedPath -Path $target.Path) -ieq $normalized) -and ($target.DeleteRoot -eq [bool]$DeleteRoot)) {
            return
        }
    }

    $Targets.Add([PSCustomObject]@{
        Mode = 'Directory'
        Category = $Category
        Path = $normalized
        DeleteRoot = [bool]$DeleteRoot
        Patterns = @()
    }) | Out-Null
}

function Add-UniquePatternTarget {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Targets,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Patterns
    )

    $normalized = Get-NormalizedPath -Path $Path
    if (-not $normalized) { return }
    if (-not (Test-IsOnCDrive -Path $normalized)) { return }

    foreach ($target in $Targets) {
        if (($target.Mode -eq 'Pattern') -and ((Get-NormalizedPath -Path $target.Path) -ieq $normalized)) {
            return
        }
    }

    $Targets.Add([PSCustomObject]@{
        Mode = 'Pattern'
        Category = $Category
        Path = $normalized
        DeleteRoot = $false
        Patterns = $Patterns
    }) | Out-Null
}

function Get-CleanupTargets {
    $targets = New-Object 'System.Collections.Generic.List[object]'

    Add-UniqueDirectoryTarget -Targets $targets -Category 'Windows Temp contents' -Path 'C:\Windows\Temp'

    if ($env:TEMP) {
        Add-UniqueDirectoryTarget -Targets $targets -Category 'Current user TEMP contents' -Path $env:TEMP
    }

    foreach ($userProfile in Get-UserProfileDirectories) {
        Add-UniqueDirectoryTarget -Targets $targets -Category 'User TEMP contents' -Path (Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\Temp')
        # Delete only generated shell cache databases. File Explorer privacy history,
        # Recent items, Quick Access state, and pinned/frequent destinations are
        # intentionally not touched. Explorer is not stopped; running Explorer may
        # recreate base cache databases immediately after deletion.
        Add-UniquePatternTarget -Targets $targets -Category 'Windows Explorer thumbnail cache' -Path (Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\Microsoft\Windows\Explorer') -Patterns @('thumbcache_*.db', 'iconcache_*.db')
        # WinINET / legacy IE / Edge-legacy cache. cleanmgr's "Temporary Internet Files"
        # category targets these folders but rarely empties them on Windows 11. WebCache is
        # intentionally not touched here because it is a database (browser URL history etc.),
        # not a discardable cache.
        Add-UniqueDirectoryTarget -Targets $targets -Category 'Internet cache (INetCache)' -Path (Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\Microsoft\Windows\INetCache')
        Add-UniqueDirectoryTarget -Targets $targets -Category 'Internet cache (Temporary Internet Files)' -Path (Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\Microsoft\Windows\Temporary Internet Files')
        Add-UniqueDirectoryTarget -Targets $targets -Category 'Internet cache (IECompatCache)' -Path (Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\Microsoft\Windows\IECompatCache')
        Add-UniqueDirectoryTarget -Targets $targets -Category 'Internet cache (IECompatUaCache)' -Path (Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\Microsoft\Windows\IECompatUaCache')
        Add-UniqueDirectoryTarget -Targets $targets -Category 'DirectX Shader Cache' -Path (Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\D3DSCache')
        Add-UniqueDirectoryTarget -Targets $targets -Category 'Location Privacy cache' -Path (Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\Microsoft\Windows\Location')
        Add-UniqueDirectoryTarget -Targets $targets -Category 'Location Privacy cache' -Path (Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\Microsoft\Windows\LocationProvider')

        # Microsoft Edge (Chromium) per-profile caches. cleanmgr does not touch these.
        # The cache folders are pure caches; Edge regenerates them on demand. Files held
        # open by a running Edge process (including background mode) will be skipped.
        #
        # Only directories that match Chromium's user-profile naming scheme are processed
        # ('Default' or 'Profile N'). The many sibling directories under User Data such as
        # 'Ad Blocking', 'BrowserMetrics', 'Application Guard', etc. are component-shared
        # state, not user profiles, and we deliberately skip them to keep the log focused
        # and avoid touching component data.
        $edgeUserData = Join-Path -Path $userProfile.FullName -ChildPath 'AppData\Local\Microsoft\Edge\User Data'
        if (Test-Path -LiteralPath $edgeUserData -PathType Container) {
            try {
                $edgeProfiles = @(
                    Get-ChildItem -LiteralPath $edgeUserData -Directory -Force -ErrorAction Stop |
                        Where-Object {
                            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
                            ($_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$')
                        }
                )
            }
            catch {
                $edgeProfiles = @()
            }
            foreach ($edgeProfile in $edgeProfiles) {
                $edgeCacheRoots = @(
                    'Cache\Cache_Data'
                    'Cache\js'
                    'Cache\wasm'
                    'Code Cache\js'
                    'Code Cache\wasm'
                    'DawnCache'
                    'DawnWebGPUCache'
                    'GPUCache'
                    'ShaderCache\GPUCache'
                    'Service Worker\CacheStorage'
                    'Service Worker\ScriptCache'
                )
                foreach ($sub in $edgeCacheRoots) {
                    $candidate = Join-Path -Path $edgeProfile.FullName -ChildPath $sub
                    if (Test-Path -LiteralPath $candidate -PathType Container) {
                        Add-UniqueDirectoryTarget -Targets $targets -Category 'Microsoft Edge cache' -Path $candidate
                    }
                }
            }
        }
    }

    foreach ($serviceProfileRoot in @(
        'C:\Windows\System32\config\systemprofile',
        'C:\Windows\SysWOW64\config\systemprofile',
        'C:\Windows\ServiceProfiles\LocalService',
        'C:\Windows\ServiceProfiles\NetworkService'
    )) {
        Add-UniqueDirectoryTarget -Targets $targets -Category 'Internet cache (system profiles)' -Path (Join-Path -Path $serviceProfileRoot -ChildPath 'AppData\Local\Microsoft\Windows\INetCache')
        Add-UniqueDirectoryTarget -Targets $targets -Category 'Internet cache (system profiles)' -Path (Join-Path -Path $serviceProfileRoot -ChildPath 'AppData\Local\Microsoft\Windows\Temporary Internet Files')
        Add-UniqueDirectoryTarget -Targets $targets -Category 'DirectX Shader Cache' -Path (Join-Path -Path $serviceProfileRoot -ChildPath 'AppData\Local\D3DSCache')
    }

    # The cleanmgr "Microsoft Defender Antivirus" display name maps to the
    # HKLM:\...\VolumeCaches\Windows Defender key. On this Windows build that key
    # targets LocalCopy and Support, while scan history remains Defender-protected.
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Defender cleanup files' -Path 'C:\ProgramData\Microsoft\Windows Defender\LocalCopy'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Defender cleanup files' -Path 'C:\ProgramData\Microsoft\Windows Defender\Support'

    # Microsoft Defender Antivirus scan history is separate from the cleanmgr
    # category above. On systems with Tamper Protection enabled these files are
    # locked even for elevated callers, so deletion is best-effort.
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Defender scan history' -Path 'C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Defender scan history' -Path 'C:\ProgramData\Microsoft\Windows Defender\Scans\History\Results\Quick'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Defender scan history' -Path 'C:\ProgramData\Microsoft\Windows Defender\Scans\History\Results\Resource'

    Add-UniqueDirectoryTarget -Targets $targets -Category 'Windows Update download cache contents' -Path 'C:\Windows\SoftwareDistribution\Download'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Downloaded Program Files' -Path 'C:\Windows\Downloaded Program Files'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Delivery Optimization cache' -Path 'C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Delivery Optimization cache' -Path 'C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Delivery Optimization cache' -Path 'C:\Windows\SoftwareDistribution\DeliveryOptimization\Cache'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Windows Prefetch contents' -Path 'C:\Windows\Prefetch'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Location Privacy cache' -Path 'C:\ProgramData\Microsoft\Windows\lfsvc\Cache'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Location Privacy cache' -Path 'C:\ProgramData\Microsoft\Windows\LocationProvider'
    Add-UniqueDirectoryTarget -Targets $targets -Category 'Windows.old folder' -Path 'C:\Windows.old' -DeleteRoot

    return $targets
}

function Get-DiskCleanupVolumeCacheRoots {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    )

    return @($roots | Where-Object { Test-Path -LiteralPath $_ })
}

function Get-EffectiveDiskCleanupCategories {
    $categories = @($script:DiskCleanupCategories)

    if ($ResetWindowsUpdateBase) {
        $categories = @($categories | Where-Object { $_ -ne 'Update Cleanup' })
        Write-CleanupLog -Level 'INFO' -Message 'Skipping cleanmgr Windows Update Cleanup category because DISM /ResetBase is enabled.'
    }

    return $categories
}

function Set-DiskCleanupStateFlags {
    param(
        [Parameter(Mandatory = $true)][int]$SageId,
        [Parameter(Mandatory = $true)][string[]]$Categories,
        [Parameter(Mandatory = $true)][int]$StateFlagValue
    )

    $valueName = 'StateFlags{0:0000}' -f $SageId

    $touched = $false
    foreach ($base in Get-DiskCleanupVolumeCacheRoots) {
        foreach ($cat in $Categories) {
            $key = Join-Path -Path $base -ChildPath $cat
            if (-not (Test-Path -LiteralPath $key)) { continue }
            try {
                New-ItemProperty -LiteralPath $key -Name $valueName -PropertyType DWord -Value $StateFlagValue -Force -ErrorAction Stop | Out-Null
                $touched = $true
            }
            catch {
                Add-CleanupWarning ("Could not set StateFlags on category '{0}' under '{1}': {2}" -f $cat, $base, $_.Exception.Message)
            }
        }
    }

    return $touched
}

function Clear-DiskCleanupStateFlags {
    param([Parameter(Mandatory = $true)][int]$SageId)

    $valueName = 'StateFlags{0:0000}' -f $SageId

    foreach ($base in Get-DiskCleanupVolumeCacheRoots) {
        Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-ItemProperty -LiteralPath $_.PSPath -Name $valueName -ErrorAction Stop
            }
            catch {
                # Property may not exist on this category. That is expected for
                # categories that we did not set; ignore.
                $null = $_
            }
        }
    }
}

function Invoke-DiskCleanup {
    $category = 'Disk Cleanup categories (cleanmgr)'

    $cleanmgr = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cleanmgr.exe'
    if (-not (Test-Path -LiteralPath $cleanmgr -PathType Leaf)) {
        Add-CleanupWarning "cleanmgr.exe not found; skipping Disk Cleanup categories."
        New-Result -Category $category -Path $cleanmgr -Skipped 1
        return
    }

    if (Test-IsWindowsServer) {
        $script:AttemptedCategories.Add($category) | Out-Null
        Write-CleanupLog -Level 'INFO' -Message "Skipping cleanmgr.exe on Windows Server; legacy Disk Cleanup handlers can hang on Server builds. DISM, pnpclean, pnputil, and explicit C: allow-list cleanup still run."
        New-Result -Category $category -Path $cleanmgr -Skipped 1
        return
    }

    $script:AttemptedCategories.Add($category) | Out-Null
    Write-CleanupLog -Level 'INFO' -Message ("Attempting category '{0}' via cleanmgr.exe /sagerun:{1}" -f $category, $script:DiskCleanupSageId)

    $stats = @{ FilesDeleted = 0L; DirectoriesDeleted = 0L; ReparsePointsDeleted = 0L; Skipped = 0L; Failed = 0L }
    $touched = $false
    $categories = Get-EffectiveDiskCleanupCategories

    try {
        # Clear stale flags from an abnormal previous exit before writing this run's profile.
        Clear-DiskCleanupStateFlags -SageId $script:DiskCleanupSageId

        $touched = Set-DiskCleanupStateFlags `
            -SageId $script:DiskCleanupSageId `
            -Categories $categories `
            -StateFlagValue 2

        if (-not $touched) {
            Add-CleanupWarning "No matching cleanmgr categories were found; skipping cleanmgr run."
            $stats.Skipped++
        }
        else {
            $sagerunArg = '/sagerun:{0}' -f $script:DiskCleanupSageId
            $proc = Start-Process -FilePath $cleanmgr -ArgumentList @('/d', 'C:', $sagerunArg) -WindowStyle Hidden -PassThru -ErrorAction Stop
            $exited = $proc.WaitForExit($script:DiskCleanupTimeoutMs)
            if (-not $exited) {
                try { $proc.Kill() } catch { $null = $_ }
                Add-CleanupWarning ("cleanmgr.exe did not exit within {0} minutes; the process was killed and the legacy Disk Cleanup step was skipped." -f [int]($script:DiskCleanupTimeoutMs / 60000))
                $stats.Skipped++
            }
            elseif ($proc.ExitCode -ne 0) {
                Add-CleanupWarning ("cleanmgr.exe exited with code {0}." -f $proc.ExitCode)
                $stats.Failed++
            }
        }
    }
    catch {
        Add-CleanupWarning ("cleanmgr.exe failed to start: {0}" -f $_.Exception.Message)
        $stats.Failed++
    }
    finally {
        if ($touched) {
            Clear-DiskCleanupStateFlags -SageId $script:DiskCleanupSageId
        }
    }

    New-Result `
        -Category $category `
        -Path $cleanmgr `
        -FilesDeleted $stats.FilesDeleted `
        -DirectoriesDeleted $stats.DirectoriesDeleted `
        -ReparsePointsDeleted $stats.ReparsePointsDeleted `
        -Skipped $stats.Skipped `
        -Failed $stats.Failed
}

function Invoke-ComponentCleanup {
    $category = 'Windows component store cleanup (DISM)'

    $dism = Join-Path -Path $env:SystemRoot -ChildPath 'System32\dism.exe'
    if (-not (Test-Path -LiteralPath $dism -PathType Leaf)) {
        Add-CleanupWarning "dism.exe not found; skipping component store cleanup."
        New-Result -Category $category -Path $dism -Skipped 1
        return
    }

    $script:AttemptedCategories.Add($category) | Out-Null
    $dismArgs = @('/Online', '/Cleanup-Image', '/StartComponentCleanup', '/Quiet')
    if ($ResetWindowsUpdateBase) {
        $dismArgs += '/ResetBase'
        Write-CleanupLog -Level 'WARN' -Message 'Windows Update ResetBase mode is enabled; installed Windows updates cannot be uninstalled after this DISM cleanup.'
    }

    Write-CleanupLog -Level 'INFO' -Message ("Attempting category '{0}' via dism.exe {1}" -f $category, ($dismArgs -join ' '))

    $stats = @{ FilesDeleted = 0L; DirectoriesDeleted = 0L; ReparsePointsDeleted = 0L; Skipped = 0L; Failed = 0L }

    try {
        $proc = Start-Process -FilePath $dism -ArgumentList $dismArgs -WindowStyle Hidden -PassThru -ErrorAction Stop
        $exited = $proc.WaitForExit($script:ExternalToolTimeoutMs)
        if (-not $exited) {
            try { $proc.Kill() } catch { $null = $_ }
            Add-CleanupWarning "dism.exe did not exit within the timeout; the process was killed."
            $stats.Failed++
        }
        elseif ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
            # Exit code 3010 means success but a reboot is required to finish.
            Add-CleanupWarning ("dism.exe exited with code {0}." -f $proc.ExitCode)
            $stats.Failed++
        }
    }
    catch {
        Add-CleanupWarning ("dism.exe failed to start: {0}" -f $_.Exception.Message)
        $stats.Failed++
    }

    New-Result `
        -Category $category `
        -Path $dism `
        -FilesDeleted $stats.FilesDeleted `
        -DirectoriesDeleted $stats.DirectoriesDeleted `
        -ReparsePointsDeleted $stats.ReparsePointsDeleted `
        -Skipped $stats.Skipped `
        -Failed $stats.Failed
}

function Get-DriverStoreSnapshot {
    $repository = Join-Path -Path $env:SystemRoot -ChildPath 'System32\DriverStore\FileRepository'
    $count = 0L
    $bytes = 0L

    if (Test-Path -LiteralPath $repository -PathType Container) {
        try {
            Get-ChildItem -LiteralPath $repository -Force -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                $count++
                $bytes += [int64]$_.Length
            }
        }
        catch {
            # Snapshot is diagnostic only; cleanup can still proceed.
            $null = $_
        }
    }

    return [PSCustomObject]@{
        Path = $repository
        Files = $count
        Bytes = $bytes
    }
}

function Invoke-PnpCleanDriverPackageCleanup {
    $category = 'Device Driver Packages (pnpclean.dll)'

    $rundll32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32\rundll32.exe'
    $pnpclean = Join-Path -Path $env:SystemRoot -ChildPath 'System32\pnpclean.dll'
    if (-not (Test-Path -LiteralPath $rundll32 -PathType Leaf) -or -not (Test-Path -LiteralPath $pnpclean -PathType Leaf)) {
        Add-CleanupWarning "pnpclean.dll or rundll32.exe not found; skipping Windows driver package cleanup handler."
        New-Result -Category $category -Path $pnpclean -Skipped 1
        return
    }
    if (-not (Test-IsAdministrator)) {
        Add-CleanupWarning "Administrator privileges are required for pnpclean.dll; skipping Windows driver package cleanup handler."
        New-Result -Category $category -Path $pnpclean -Skipped 1
        return
    }

    $script:AttemptedCategories.Add($category) | Out-Null
    Write-CleanupLog -Level 'INFO' -Message ("Attempting category '{0}' via pnpclean.dll /DRIVERS /MAXCLEAN" -f $category)

    $stats = @{ FilesDeleted = 0L; DirectoriesDeleted = 0L; ReparsePointsDeleted = 0L; Skipped = 0L; Failed = 0L }
    $before = Get-DriverStoreSnapshot

    try {
        $proc = Start-Process `
            -FilePath $rundll32 `
            -ArgumentList @("$pnpclean,RunDLL_PnpClean", '/DRIVERS', '/MAXCLEAN') `
            -WindowStyle Hidden `
            -PassThru `
            -ErrorAction Stop

        $exited = $proc.WaitForExit($script:ExternalToolTimeoutMs)
        if (-not $exited) {
            try { $proc.Kill() } catch { $null = $_ }
            Add-CleanupWarning "pnpclean.dll driver cleanup did not exit within the timeout; the process was killed."
            $stats.Failed++
        }
        elseif ($proc.ExitCode -ne 0) {
            Add-CleanupWarning ("pnpclean.dll driver cleanup exited with code {0}." -f $proc.ExitCode)
            $stats.Failed++
        }
    }
    catch {
        Add-CleanupWarning ("pnpclean.dll driver cleanup failed to start: {0}" -f $_.Exception.Message)
        $stats.Failed++
    }

    $after = Get-DriverStoreSnapshot
    if ($after.Files -lt $before.Files) {
        $stats.FilesDeleted = $before.Files - $after.Files
    }

    $bytesFreed = $before.Bytes - $after.Bytes
    if ($bytesFreed -gt 0) {
        Write-CleanupLog -Level 'INFO' -Message ("pnpclean.dll driver store reduction: {0} ({1:N0} bytes)." -f (Format-Bytes -Bytes $bytesFreed), $bytesFreed)
    }
    else {
        Write-CleanupLog -Level 'INFO' -Message 'pnpclean.dll did not report a measurable driver store size reduction.'
    }

    New-Result -Category $category -Path $pnpclean `
        -FilesDeleted $stats.FilesDeleted `
        -DirectoriesDeleted $stats.DirectoriesDeleted `
        -ReparsePointsDeleted $stats.ReparsePointsDeleted `
        -Skipped $stats.Skipped `
        -Failed $stats.Failed
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    $properties = @($InputObject.PSObject.Properties)
    foreach ($name in $Names) {
        $property = @($properties | Where-Object { $_.Name -ieq $name } | Select-Object -First 1)
        if ($property.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$property[0].Value)) {
            return ([string]$property[0].Value).Trim()
        }
    }

    $normalizedNames = @($Names | ForEach-Object { ($_ -replace '[^A-Za-z0-9]', '').ToLowerInvariant() })
    foreach ($property in $properties) {
        $normalizedPropertyName = ($property.Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
        if ($normalizedNames -contains $normalizedPropertyName -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return ([string]$property.Value).Trim()
        }
    }

    return $null
}

function ConvertTo-DriverDateVersion {
    param(
        [string]$DriverDateText,
        [string]$DriverVersionText
    )

    if ([string]::IsNullOrWhiteSpace($DriverDateText) -and $DriverVersionText -match '^\s*(\d{1,4}[./-]\d{1,2}[./-]\d{1,4})\s+(.+?)\s*$') {
        $DriverDateText = $Matches[1]
        $DriverVersionText = $Matches[2]
    }
    elseif ([string]::IsNullOrWhiteSpace($DriverVersionText) -and $DriverDateText -match '^\s*(\d{1,4}[./-]\d{1,2}[./-]\d{1,4})\s+(.+?)\s*$') {
        $DriverDateText = $Matches[1]
        $DriverVersionText = $Matches[2]
    }

    $driverDate = [datetime]::MinValue
    $dateParsed = $false
    $dateFormats = @('M/d/yyyy', 'MM/dd/yyyy', 'd/M/yyyy', 'dd/MM/yyyy', 'yyyy-MM-dd', 'yyyy/MM/dd', 'd.M.yyyy', 'dd.MM.yyyy', 'M.d.yyyy', 'MM.dd.yyyy', 'yyyy.MM.dd')
    if (-not [string]::IsNullOrWhiteSpace($DriverDateText)) {
        foreach ($format in $dateFormats) {
            if ([datetime]::TryParseExact($DriverDateText.Trim(), $format, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$driverDate)) {
                $dateParsed = $true
                break
            }
        }
        if (-not $dateParsed) {
            if ([datetime]::TryParse($DriverDateText.Trim(), [System.Globalization.CultureInfo]::CurrentCulture, [System.Globalization.DateTimeStyles]::None, [ref]$driverDate)) {
                $dateParsed = $true
            }
        }
    }

    $driverVersion = [version]'0.0.0.0'
    $versionParsed = $false
    if (-not [string]::IsNullOrWhiteSpace($DriverVersionText)) {
        $versionText = $DriverVersionText.Trim()
        if ($versionText -match '(\d+(?:\.\d+){1,3})') {
            $versionText = $Matches[1]
        }
        try {
            $driverVersion = [version]$versionText
            $versionParsed = $true
        }
        catch {
            $versionParsed = $false
        }
    }

    if (-not $dateParsed -or -not $versionParsed) { return $null }

    return [PSCustomObject]@{
        DriverDate = $driverDate
        DriverVersion = $driverVersion
    }
}

function New-DriverPackageRecord {
    param(
        [string]$PublishedName,
        [string]$OriginalName,
        [string]$ProviderName,
        [string]$ClassName,
        [string]$DriverDateText,
        [string]$DriverVersionText
    )

    if ([string]::IsNullOrWhiteSpace($PublishedName) -or
        [string]::IsNullOrWhiteSpace($OriginalName) -or
        [string]::IsNullOrWhiteSpace($ProviderName) -or
        [string]::IsNullOrWhiteSpace($ClassName)) {
        return $null
    }

    $parsedVersion = ConvertTo-DriverDateVersion -DriverDateText $DriverDateText -DriverVersionText $DriverVersionText
    if (-not $parsedVersion) { return $null }

    return [PSCustomObject]@{
        PublishedName = $PublishedName.Trim()
        OriginalName = $OriginalName.Trim().ToLowerInvariant()
        ProviderName = $ProviderName.Trim().ToLowerInvariant()
        ClassName = $ClassName.Trim().ToLowerInvariant()
        DriverDate = $parsedVersion.DriverDate
        DriverVersion = $parsedVersion.DriverVersion
    }
}

function ConvertFrom-PnPUtilCsvOutput {
    param([Parameter(Mandatory = $true)][string[]]$Lines)

    $textLines = @($Lines | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $headerIndex = -1
    for ($i = 0; $i -lt $textLines.Count; $i++) {
        if ($textLines[$i] -match ',' -and $textLines[$i] -match 'Published|Original|Provider|Class|Driver') {
            $headerIndex = $i
            break
        }
    }
    if ($headerIndex -lt 0) { return @() }

    $csvText = ($textLines[$headerIndex..($textLines.Count - 1)] -join [Environment]::NewLine)
    try {
        $rows = @($csvText | ConvertFrom-Csv -ErrorAction Stop)
    }
    catch {
        return @()
    }

    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $rows) {
        $record = New-DriverPackageRecord `
            -PublishedName (Get-ObjectPropertyValue -InputObject $row -Names @('Published Name', 'PublishedName', 'Published', 'DriverName')) `
            -OriginalName (Get-ObjectPropertyValue -InputObject $row -Names @('Original Name', 'OriginalName', 'Original INF Name', 'OriginalInfName')) `
            -ProviderName (Get-ObjectPropertyValue -InputObject $row -Names @('Provider Name', 'ProviderName', 'Provider')) `
            -ClassName (Get-ObjectPropertyValue -InputObject $row -Names @('Class Name', 'ClassName', 'Class')) `
            -DriverDateText (Get-ObjectPropertyValue -InputObject $row -Names @('Driver Date', 'DriverDate', 'Date')) `
            -DriverVersionText (Get-ObjectPropertyValue -InputObject $row -Names @('Driver Version', 'DriverVersion', 'Version'))
        if ($record) { [void]$records.Add($record) }
    }

    return $records.ToArray()
}

function ConvertFrom-PnPUtilTextOutput {
    param([Parameter(Mandatory = $true)][string[]]$Lines)

    $drivers = New-Object 'System.Collections.Generic.List[object]'
    $current = $null

    foreach ($line in $Lines) {
        $text = [string]$line

        if ($text -match '^\s*Published Name\s*:\s*(.+?)\s*$') {
            if ($current -and -not [string]::IsNullOrWhiteSpace($current.PublishedName)) {
                $record = New-DriverPackageRecord @current
                if ($record) { [void]$drivers.Add($record) }
            }
            $current = @{
                PublishedName = $Matches[1].Trim()
                OriginalName = $null
                ProviderName = $null
                ClassName = $null
                DriverDateText = $null
                DriverVersionText = $null
            }
            continue
        }

        if (-not $current) { continue }

        if ($text -match '^\s*Original Name\s*:\s*(.+?)\s*$') {
            $current.OriginalName = $Matches[1].Trim()
        }
        elseif ($text -match '^\s*Provider Name\s*:\s*(.+?)\s*$') {
            $current.ProviderName = $Matches[1].Trim()
        }
        elseif ($text -match '^\s*Class Name\s*:\s*(.+?)\s*$') {
            $current.ClassName = $Matches[1].Trim()
        }
        elseif ($text -match '^\s*Driver Version\s*:\s*(.+?)\s*$') {
            $current.DriverDateText = $Matches[1].Trim()
        }
    }

    if ($current -and -not [string]::IsNullOrWhiteSpace($current.PublishedName)) {
        $record = New-DriverPackageRecord @current
        if ($record) { [void]$drivers.Add($record) }
    }

    return $drivers.ToArray()
}

function Get-PnPUtilDriverPackages {
    param([Parameter(Mandatory = $true)][string]$PnPUtilPath)

    $csvLines = $null
    try {
        $csvLines = @(& $PnPUtilPath /enum-drivers /format csv 2>&1)
        $csvExitCode = $LASTEXITCODE
    }
    catch {
        $csvLines = $null
        $csvExitCode = 1
    }

    if ($csvExitCode -eq 0 -and $csvLines) {
        $csvDrivers = @(ConvertFrom-PnPUtilCsvOutput -Lines @($csvLines | ForEach-Object { [string]$_ }))
        if ($csvDrivers.Count -gt 0) {
            Write-CleanupLog -Level 'INFO' -Message 'Parsed pnputil driver list from locale-invariant CSV output.'
            return @($csvDrivers)
        }
    }

    $textLines = $null
    try {
        $textLines = @(& $PnPUtilPath /enum-drivers 2>&1)
    }
    catch {
        throw "pnputil /enum-drivers failed: $($_.Exception.Message)"
    }

    if ($LASTEXITCODE -ne 0) {
        throw "pnputil /enum-drivers exited with code $LASTEXITCODE."
    }

    $textDrivers = @(ConvertFrom-PnPUtilTextOutput -Lines @($textLines | ForEach-Object { [string]$_ }))
    if ($textDrivers.Count -eq 0 -and $csvLines) {
        Add-CleanupWarning 'pnputil structured CSV output was unavailable or unparseable, and text fallback did not produce driver records. Driver cleanup was skipped safely.'
    }
    return @($textDrivers)
}

function Test-DriverPackageSuperseded {
    param(
        [Parameter(Mandatory = $true)]$Candidate,
        [Parameter(Mandatory = $true)]$Newest
    )

    if ($Candidate.DriverDate -eq $Newest.DriverDate) {
        return ($Candidate.DriverVersion -lt $Newest.DriverVersion)
    }

    return ($Candidate.DriverDate -lt $Newest.DriverDate -and $Candidate.DriverVersion -le $Newest.DriverVersion)
}

function Invoke-DriverPackageCleanup {
    $category = 'Superseded driver packages (pnputil)'

    $pnputil = Join-Path -Path $env:SystemRoot -ChildPath 'System32\pnputil.exe'
    if (-not (Test-Path -LiteralPath $pnputil -PathType Leaf)) {
        Add-CleanupWarning "pnputil.exe not found; skipping driver package cleanup."
        New-Result -Category $category -Path $pnputil -Skipped 1
        return
    }

    $script:AttemptedCategories.Add($category) | Out-Null
    Write-CleanupLog -Level 'INFO' -Message ("Attempting category '{0}' via pnputil /enum-drivers /format csv + /delete-driver" -f $category)

    $stats = @{ FilesDeleted = 0L; DirectoriesDeleted = 0L; ReparsePointsDeleted = 0L; Skipped = 0L; Failed = 0L }

    try {
        $drivers = @(Get-PnPUtilDriverPackages -PnPUtilPath $pnputil)
    }
    catch {
        Add-CleanupWarning $_.Exception.Message
        New-Result -Category $category -Path $pnputil -Failed 1
        return
    }

    $oemDrivers = @(
        $drivers | Where-Object {
            $_.PublishedName -match '^oem\d+\.inf$' -and
            -not [string]::IsNullOrWhiteSpace($_.OriginalName) -and
            -not [string]::IsNullOrWhiteSpace($_.ProviderName) -and
            -not [string]::IsNullOrWhiteSpace($_.ClassName)
        }
    )

    if (-not $oemDrivers -or $oemDrivers.Count -eq 0) {
        New-Result -Category $category -Path $pnputil -Skipped 1
        return
    }

    # Group by original INF + class + provider. Keep the newest by date/version and
    # ask pnputil to delete only packages that are older by date and not newer by
    # version, or same-date lower-version packages. No /force or /uninstall flags
    # are used: pnputil will refuse anything still bound to a present device.
    $groups = $oemDrivers | Group-Object -Property OriginalName, ClassName, ProviderName
    $candidates = New-Object 'System.Collections.Generic.List[object]'

    foreach ($g in $groups) {
        if ($g.Count -lt 2) { continue }
        $sorted = $g.Group | Sort-Object -Property `
            @{ Expression = { $_.DriverDate }; Descending = $true },
            @{ Expression = { $_.DriverVersion }; Descending = $true }

        $newest = @($sorted | Select-Object -First 1)[0]
        $older = @(
            $sorted | Select-Object -Skip 1 | Where-Object {
                Test-DriverPackageSuperseded -Candidate $_ -Newest $newest
            }
        )

        foreach ($drv in $older) {
            [void]$candidates.Add($drv)
        }
    }

    if ($candidates.Count -eq 0) {
        Write-CleanupLog -Level 'INFO' -Message "No superseded driver packages were found."
        New-Result -Category $category -Path $pnputil
        return
    }

    Write-CleanupLog -Level 'INFO' -Message ("Found {0} superseded driver package candidate(s); attempting removal." -f $candidates.Count)

    foreach ($drv in $candidates) {
        $publishedName = $null
        try { $publishedName = [string]$drv.PublishedName } catch { $publishedName = $null }
        if ([string]::IsNullOrWhiteSpace($publishedName)) {
            $stats.Skipped++
            continue
        }

        Write-CleanupLog -Level 'INFO' -Message ("Trying superseded driver package removal: {0} ({1}, {2}, {3}, {4})" -f `
            $publishedName, $drv.OriginalName, $drv.ProviderName, $drv.DriverDate.ToString('yyyy-MM-dd'), $drv.DriverVersion)

        try {
            $proc = Start-Process -FilePath $pnputil -ArgumentList @('/delete-driver', $publishedName) -WindowStyle Hidden -PassThru -Wait -ErrorAction Stop
            if ($proc.ExitCode -eq 0) {
                $stats.FilesDeleted++
            }
            else {
                Write-CleanupLog -Level 'INFO' -Message ("pnputil refused or skipped driver package {0}; exit code {1}." -f $publishedName, $proc.ExitCode)
                $stats.Skipped++
            }
        }
        catch {
            Write-CleanupLog -Level 'INFO' -Message ("pnputil could not delete driver package {0}: {1}" -f $publishedName, $_.Exception.Message)
            $stats.Skipped++
        }
    }

    New-Result -Category $category -Path $pnputil `
        -FilesDeleted $stats.FilesDeleted `
        -DirectoriesDeleted $stats.DirectoriesDeleted `
        -ReparsePointsDeleted $stats.ReparsePointsDeleted `
        -Skipped $stats.Skipped `
        -Failed $stats.Failed
}

function Test-RecycleBinDriveCHasFiles {
    try {
        if (-not (Test-Path -LiteralPath 'C:\$Recycle.Bin' -PathType Container)) { return $false }
        $firstFile = Get-ChildItem -LiteralPath 'C:\$Recycle.Bin' -Force -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
        return ($null -ne $firstFile)
    }
    catch {
        # If enumeration itself fails, let Clear-RecycleBin be the source of truth.
        return $true
    }
}

function Clear-RecycleBinDriveC {
    $category = 'Recycle Bin (drive C: only)'
    $script:AttemptedCategories.Add($category) | Out-Null
    Write-CleanupLog -Level 'INFO' -Message ("Attempting category '{0}'" -f $category)

    $stats = @{ FilesDeleted = 0L; DirectoriesDeleted = 0L; ReparsePointsDeleted = 0L; Skipped = 0L; Failed = 0L }

    $clearCmd = Get-Command -Name 'Clear-RecycleBin' -ErrorAction SilentlyContinue
    if (-not $clearCmd) {
        Add-CleanupWarning "Clear-RecycleBin cmdlet not available; skipping Recycle Bin cleanup."
        $stats.Skipped++
        New-Result `
            -Category $category `
            -Path 'C:\$Recycle.Bin' `
            -Skipped $stats.Skipped
        return
    }

    if (-not (Test-RecycleBinDriveCHasFiles)) {
        $stats.Skipped++
    }
    else {
        try {
            Clear-RecycleBin -DriveLetter 'C' -Force -ErrorAction Stop
        }
        catch {
            # Empty Recycle Bin messages are localized. Confirm by state instead
            # of matching text from the exception message.
            if (-not (Test-RecycleBinDriveCHasFiles)) {
                $stats.Skipped++
            }
            else {
                Add-CleanupWarning ("Clear-RecycleBin failed for drive C: {0}" -f $_.Exception.Message)
                $stats.Failed++
            }
        }
    }

    New-Result `
        -Category $category `
        -Path 'C:\$Recycle.Bin' `
        -FilesDeleted $stats.FilesDeleted `
        -DirectoriesDeleted $stats.DirectoriesDeleted `
        -ReparsePointsDeleted $stats.ReparsePointsDeleted `
        -Skipped $stats.Skipped `
        -Failed $stats.Failed
}

function Write-RunHeader {
    Write-CleanupLog -Level 'INFO' -Message 'WindowsAutoCleanup started.'
    Write-CleanupLog -Level 'INFO' -Message ('Start time: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Write-CleanupLog -Level 'INFO' -Message ('Admin rights active: {0}' -f (Test-IsAdministrator))

    # Log the PowerShell host that is actually executing the script so it can be
    # distinguished from the host that double-click associated with the .ps1 file.
    try {
        $hostPath = $null
        try { $hostPath = (Get-Process -Id $PID -ErrorAction Stop).Path } catch { $hostPath = $null }
        $edition = if ($PSVersionTable.ContainsKey('PSEdition')) { $PSVersionTable.PSEdition } else { 'Desktop' }
        $versionString = '{0} {1} ({2})' -f $(if ($edition -eq 'Core') { 'PowerShell' } else { 'Windows PowerShell' }), $PSVersionTable.PSVersion, $edition
        if ($hostPath) {
            Write-CleanupLog -Level 'INFO' -Message ('PowerShell host: {0} at {1}' -f $versionString, $hostPath)
        } else {
            Write-CleanupLog -Level 'INFO' -Message ('PowerShell host: {0}' -f $versionString)
        }
    }
    catch {
        Write-CleanupLog -Level 'WARN' -Message ('Could not determine PowerShell host: {0}' -f $_.Exception.Message)
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        Write-CleanupLog -Level 'INFO' -Message ('OS version: {0} build {1}' -f $os.Caption, $os.BuildNumber)
    }
    catch {
        Write-CleanupLog -Level 'WARN' -Message ('Could not query OS version: {0}' -f $_.Exception.Message)
    }
    Write-CleanupLog -Level 'INFO' -Message ('Windows Server detected: {0}' -f (Test-IsWindowsServer))

    Write-CleanupLog -Level 'INFO' -Message 'Cleanup scope: drive C: only.'
    Write-CleanupLog -Level 'INFO' -Message 'Cleanup mode: allow-list locations + cleanmgr Disk Cleanup + DISM component cleanup + pnpclean/pnputil driver cleanup + Recycle Bin (C:).'
    Write-CleanupLog -Level 'INFO' -Message ('Windows Update ResetBase mode: {0}' -f ([bool]$ResetWindowsUpdateBase))
    Write-CleanupLog -Level 'INFO' -Message ('Script folder ACL hardening disabled by parameter: {0}' -f ([bool]$SkipAclHardening))
}

function Write-RunFooter {
    $script:Stopwatch.Stop()
    $elapsed = $script:Stopwatch.Elapsed.ToString('hh\:mm\:ss')

    $uniqueCategories = @($script:AttemptedCategories | Sort-Object -Unique)
    if ($uniqueCategories.Count -gt 0) {
        Write-CleanupLog -Level 'INFO' -Message ('Cleanup categories attempted: {0}' -f ($uniqueCategories -join '; '))
    }
    else {
        Write-CleanupLog -Level 'INFO' -Message 'Cleanup categories attempted: none'
    }

    foreach ($result in $script:Results) {
        Write-CleanupLog -Level 'INFO' -Message ('Result | Category="{0}" | Path="{1}" | Files={2} | Directories={3} | ReparsePoints={4} | PendingDeleteOnReboot={5} | Skipped={6} | Failed={7}' -f `
            $result.Category, $result.Path, $result.FilesDeleted, $result.DirectoriesDeleted, $result.ReparsePointsDeleted, $result.PendingDeletes, $result.Skipped, $result.Failed)
    }

    Write-CleanupLog -Level 'INFO' -Message ('Total files removed: {0}' -f $script:TotalFilesDeleted)
    Write-CleanupLog -Level 'INFO' -Message ('Total directories removed: {0}' -f $script:TotalDirectoriesDeleted)
    Write-CleanupLog -Level 'INFO' -Message ('Total reparse points removed: {0}' -f $script:TotalReparsePointsDeleted)
    Write-CleanupLog -Level 'INFO' -Message ('Pending deletes on reboot: {0}' -f $script:TotalPendingDeletes)
    Write-CleanupLog -Level 'INFO' -Message ('Skipped items summary: {0}' -f $script:TotalSkipped)
    Write-CleanupLog -Level 'INFO' -Message ('Failed items summary: {0}' -f $script:TotalFailed)

    $bytesFreed = $null
    if ($null -ne $script:StartFreeBytesC -and $null -ne $script:EndFreeBytesC) {
        $bytesFreed = [int64]($script:EndFreeBytesC - $script:StartFreeBytesC)
    }
    Write-CleanupLog -Level 'INFO' -Message ('Bytes freed where practical: {0}' -f (Format-Bytes -Bytes $bytesFreed))

    foreach ($warning in $script:Warnings) {
        Write-CleanupLog -Level 'WARN' -Message ('Summary warning: {0}' -f $warning)
    }

    if ($script:TotalFailed -gt 0 -or $script:Warnings.Count -gt 0) {
        Write-CleanupLog -Level 'WARN' -Message 'Final status: completed with warnings.'
    }
    else {
        Write-CleanupLog -Level 'INFO' -Message 'Final status: success.'
    }

    Write-CleanupLog -Level 'INFO' -Message ('Total time elapsed: {0}' -f $elapsed)
}

try {
    Invoke-ElevatedRelaunchIfNeeded
    Initialize-Log
    Write-RunHeader

    if (-not (Test-IsAdministrator)) {
        Write-CleanupLog -Level 'ERROR' -Message 'Administrator privileges are required.'
        exit 1
    }

    if ($SkipAclHardening) {
        Write-CleanupLog -Level 'INFO' -Message 'Script folder ACL hardening skipped by -SkipAclHardening.'
    }
    else {
        Invoke-ScriptRootAclHardening
    }

    $script:StartFreeBytesC = Get-CDriveFreeBytes

    foreach ($target in Get-CleanupTargets) {
        if ($target.Mode -eq 'Directory') {
            Remove-DirectoryTreeSafe -Category $target.Category -Path $target.Path -DeleteRoot:([bool]$target.DeleteRoot)
        }
        elseif ($target.Mode -eq 'Pattern') {
            Remove-FilesByPatternSafe -Category $target.Category -DirectoryPath $target.Path -Patterns $target.Patterns
        }
    }

    # Run the Windows component store cleanup (DISM) before the legacy Disk
    # Cleanup handlers. This keeps Windows Update Cleanup on the supported DISM
    # path when ResetBase is enabled and avoids cleanmgr blocking later cleanup.
    Invoke-ComponentCleanup
    Invoke-DiskCleanup
    Invoke-PnpCleanDriverPackageCleanup
    Invoke-DriverPackageCleanup
    Clear-RecycleBinDriveC

    $script:EndFreeBytesC = Get-CDriveFreeBytes
    Write-RunFooter

    if ($script:TotalFailed -gt 0) { exit 2 }
    exit 0
}
catch {
    if (-not $script:LogPath) { Initialize-Log }
    Write-CleanupLog -Level 'ERROR' -Message ('Unhandled error: {0}' -f $_.Exception.Message)
    Write-RunFooter
    exit 1
}
