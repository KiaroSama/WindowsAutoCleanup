#Requires -Version 5.1
<#
.SYNOPSIS
    Records that decide what a later run may do survive a power cut whole, or not at all.
.DESCRIPTION
    Found by the live power-cut campaign (2026-09-27): a transaction record written with
    File.WriteAllText and published with File.Replace was TORN by a cut seconds later, and the next
    install and uninstall each refused on it - correctly, since unreadable is never absence, but
    forever. A cut cannot be simulated in a unit test, so the durability itself is pinned by what
    makes it: the data flushed to disk before the rename, and the rename issued write-through. Every
    publisher is held to routing through those, so removing either from any of them fails here.

    All files live in the harness sandbox. Nothing machine-scoped is written.
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function Get-FunctionText {
    param([Parameter(Mandatory = $true)][string]$File, [Parameter(Mandatory = $true)][string]$Name)
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:RepoRoot $File), [ref]$null, [ref]$parseErrors)
    Assert-Equal 0 @($parseErrors).Count ($File + ' no longer parses')
    $found = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true))
    Assert-Equal 1 $found.Count ('exactly one ' + $Name + ' must exist in ' + $File)
    return $found[0].Extent.Text
}

Test-Case 'A durable write then rename creates, replaces and leaves no staging file' {
    $sandbox = New-TestSandbox -Prefix 'durable'
    try {
        $path = Join-Path $sandbox 'record.json'
        $staging = $path + '.new'
        Write-WacFileDurable -Path $staging -Bytes ([Text.Encoding]::UTF8.GetBytes('first'))
        Move-WacFileDurable -Source $staging -Destination $path
        Assert-Equal 'first' ([IO.File]::ReadAllText($path))
        Write-WacFileDurable -Path $staging -Bytes ([Text.Encoding]::UTF8.GetBytes('second'))
        Move-WacFileDurable -Source $staging -Destination $path -Replace
        Assert-Equal 'second' ([IO.File]::ReadAllText($path))
        Assert-False (Test-Path -LiteralPath $staging) 'the staging file outlived the publication'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A refused rename throws and never damages the record it would have replaced' {
    $sandbox = New-TestSandbox -Prefix 'durable-refused'
    try {
        $path = Join-Path $sandbox 'record.json'
        [IO.File]::WriteAllText($path, 'kept')
        $staging = $path + '.new'
        Write-WacFileDurable -Path $staging -Bytes ([Text.Encoding]::UTF8.GetBytes('new'))
        Assert-Throws -ScriptBlock { Move-WacFileDurable -Source $staging -Destination $path } -Pattern 'Win32'
        $held = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        try { Assert-Throws -ScriptBlock { Move-WacFileDurable -Source $staging -Destination $path -Replace } -Pattern 'Win32' }
        finally { $held.Dispose() }
        Assert-Equal 'kept' ([IO.File]::ReadAllText($path))
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'The rename is write-through, and the staged data is flushed to disk' {
    & (Get-Module -Name 'WindowsAutoCleanup.Core') { Initialize-WacDurableFile }
    Assert-Equal 9 ([WacDurableFile]::MoveFlags($true)) 'a replacing rename must be MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH'
    Assert-Equal 8 ([WacDurableFile]::MoveFlags($false)) 'a first rename must be MOVEFILE_WRITE_THROUGH and must not replace'
    $text = Get-FunctionText -File 'src\WindowsAutoCleanup.DurableFile.ps1' -Name 'Write-WacFileDurable'
    Assert-True ($text -match '\.Flush\(\$true\)') 'the staged data is no longer flushed to disk before the rename'
}

Test-Case 'Every record publisher routes through the durable write and rename' {
    $journal = Get-FunctionText -File 'src\WindowsAutoCleanup.DeploymentJournal.ps1' -Name 'Write-WacDeploymentJournal'
    Assert-True ($journal -match 'Write-WacFileDurable') 'the transaction record is staged without a disk flush'
    Assert-True ($journal -match 'Move-WacFileDurable') 'the transaction record is published without write-through'
    Assert-False ($journal -match '\[System\.IO\.File\]::(WriteAllText|Replace|Move)\(') 'the transaction record still uses a non-durable file API'

    $store = Get-FunctionText -File 'src\WindowsAutoCleanup.DriverBackupStore.ps1' -Name 'Write-WacDriverBackupControlFile'
    Assert-True ($store -match '\.Flush\(\$true\)') 'a driver backup control file is written without a disk flush'
    $commit = Get-FunctionText -File 'src\WindowsAutoCleanup.DriverBackupStore.ps1' -Name 'Complete-WacDriverBackup'
    Assert-True ($commit -match 'Move-WacFileDurable') 'the driver backup manifest is published without write-through'
    Assert-False ($commit -match '\[System\.IO\.File\]::(Replace|Move|Delete)\(\$manifestPath') 'the manifest can still be deleted or renamed non-durably'

    $control = Get-FunctionText -File 'src\WindowsAutoCleanup.ControlFile.ps1' -Name 'Write-WacControlFile'
    Assert-True ($control -match '\.Flush\(\$true\)') 'a control file is written without a disk flush'
}

Complete-TestRun
