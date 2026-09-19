#Requires -Version 5.1
<#
.SYNOPSIS
    Snapshot ownership controls across repeated cleanmgr attempts.
.DESCRIPTION
    Uses a unique HKCU profile and disposable control store; cleanmgr never executes.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
foreach ($leaf in @('Core', 'FileSystem', 'StepContract', 'RecycleBin', 'DiskCleanup', 'Steps')) {
    Import-Module (Join-Path $script:RepoRoot ('src\WindowsAutoCleanup.' + $leaf + '.psm1')) -Force -DisableNameChecking
}
. (Join-Path $PSScriptRoot '_StepHarness.ps1')
$script:StepModule = Get-Module WindowsAutoCleanup.DiskCleanup

function Invoke-ReviewSnapshotFixture {
    param([scriptblock]$Body)
    $relative = 'Software\WacReview6_' + [guid]::NewGuid().ToString('N')
    $key = 'HKCU:\' + $relative
    $created = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($relative + '\Temporary Files')
    try { $created.SetValue('StateFlags9999', 7, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $created.Close() }
    $saved = Get-ModuleVariableValue -Module $script:StepModule -Name VolumeCacheKeyPath
    Set-ModuleVariableValue -Module $script:StepModule -Name VolumeCacheKeyPath -Value $key
    try { Invoke-WithStubbedTool -StubToolPath -Body $Body }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name VolumeCacheKeyPath -Value $saved
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($relative)
    }
}

Test-Case 'A previous recovery snapshot remains intact and prevents a clean result' {
    Invoke-ReviewSnapshotFixture -Body {
        $name = Get-ModuleVariableValue -Module $script:StepModule -Name CleanMgrSnapshotName
        Assert-Equal 'Created' ([string](Write-WacControlFile -Name $name -Content 'ORIGINAL-RECOVERY-EVIDENCE').Kind)
        $run = Invoke-WacLegacyDiskCleanup -Enabled -Category @('Temporary Files')
        Assert-Equal 'Incomplete' ([string]$run.Outcome) 'an unresolved earlier profile was reported as a clean skip'
        Assert-Equal 0 $script:StubCall.Count 'a tool launched over unresolved recovery state'
        Assert-Equal 'ORIGINAL-RECOVERY-EVIDENCE' ([string](Read-WacControlFile -Name $name).Text) 'the earlier original was lost'
    }
}

Test-Case 'A snapshot created by an attempt with zero writes does not poison the next attempt' {
    Invoke-ReviewSnapshotFixture -Body {
        $saved = Get-ModuleFunctionBody -Module $script:StepModule -Name Enable-WacDiskCleanupCategory
        try {
            Set-ModuleFunctionBody -Module $script:StepModule -Name Enable-WacDiskCleanupCategory -Body {
                param($SageId, $Category, $KeyPath, $KnownHandler)
                $null = $SageId; $null = $Category; $null = $KeyPath; $null = $KnownHandler
                return [PSCustomObject]@{ Touched = 0; Failed = 0; Enabled = @() }
            }
            [void](Invoke-WacLegacyDiskCleanup -Enabled -Category @('Temporary Files'))
        }
        finally { Set-ModuleFunctionBody -Module $script:StepModule -Name Enable-WacDiskCleanupCategory -Body $saved }
        $name = Get-ModuleVariableValue -Module $script:StepModule -Name CleanMgrSnapshotName
        Assert-Equal 'Absent' ([string](Read-WacControlFile -Name $name).State) 'a zero-write attempt left a permanent snapshot collision'
        $next = Invoke-WacLegacyDiskCleanup -Enabled -Category @('Temporary Files')
        Assert-Equal 'Succeeded' ([string]$next.Outcome) $next.Detail
        Assert-Equal 1 $script:StubCall.Count 'the next attempt never reached its recorded tool'
    }
}
Complete-TestRun
