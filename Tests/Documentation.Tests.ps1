#Requires -Version 5.1

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_Harness.ps1')

Test-Case 'PowerShell examples in the README parse on the current host' {
    $readme = Join-Path (Split-Path -Parent $PSScriptRoot) 'README.md'
    $text = [System.IO.File]::ReadAllText($readme, [System.Text.Encoding]::UTF8)
    $blocks = [regex]::Matches($text, '(?ms)^```powershell\r?\n(.*?)^```[ \t]*\r?$')
    Assert-True ($blocks.Count -gt 0) 'no PowerShell examples were discovered'
    foreach ($block in $blocks) {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput(
            $block.Groups[1].Value, [ref]$tokens, [ref]$errors)
        Assert-Equal 0 @($errors).Count ('README example at offset {0}: {1}' -f
            $block.Index, (($errors | ForEach-Object { $_.Message }) -join '; '))
    }
}

Complete-TestRun
