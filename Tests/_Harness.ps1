#Requires -Version 5.1
<#
.SYNOPSIS
    Assertions, disposable sandboxes and the case runner shared by every Tests\*.Tests.ps1 suite.

.DESCRIPTION
    Dot-sourced rather than imported so a suite keeps one script scope and can reach module state
    directly. Pester is deliberately not a dependency: only 3.4.0 is installed on the development
    machine and hosted CI images drift, so the suites must rely on nothing beyond the two shipped
    PowerShell hosts.

    A suite is a plain script: dot-source this file, declare Test-Case blocks, call Complete-TestRun.
    Every case prints its line the moment it finishes, which is also what gives Run-Tests.ps1 its
    idle-progress signal.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:WacCases     = New-Object 'System.Collections.Generic.List[object]'
$script:WacSandboxes = New-Object 'System.Collections.Generic.List[string]'

function Get-WacTestLocation {
    param([Parameter(Mandatory = $true)]$Invocation)

    $file = '<inline>'
    if ($Invocation.ScriptName) { $file = Split-Path -Leaf $Invocation.ScriptName }
    return ('{0}:{1}' -f $file, $Invocation.ScriptLineNumber)
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Condition,
        [string]$Message = 'Expected a true value.'
    )

    if (-not $Condition) { throw ('{0} {1}' -f (Get-WacTestLocation $MyInvocation), $Message) }
}

function Assert-False {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Condition,
        [string]$Message = 'Expected a false value.'
    )

    if ($Condition) { throw ('{0} {1}' -f (Get-WacTestLocation $MyInvocation), $Message) }
}

function Assert-Equal {
    <#
    .SYNOPSIS
        Compares two values. Strings compare ORDINALLY, because PowerShell's -eq is case-insensitive
        and would silently pass a quoting or casing regression.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()]$Expected,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()]$Actual,
        [string]$Message = ''
    )

    if ($Expected -is [string] -and $Actual -is [string]) {
        $equal = [string]::Equals($Expected, $Actual, [System.StringComparison]::Ordinal)
    }
    elseif ($null -eq $Expected -or $null -eq $Actual) {
        $equal = ($null -eq $Expected -and $null -eq $Actual)
    }
    else {
        $equal = ($Expected -eq $Actual)
    }

    if (-not $equal) {
        $detail = 'expected [{0}] but got [{1}]' -f $Expected, $Actual
        if ($Message) { $detail = '{0} -- {1}' -f $Message, $detail }
        throw ('{0} {1}' -f (Get-WacTestLocation $MyInvocation), $detail)
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [string]$Pattern,
        [string]$Message = 'Expected a terminating error.'
    )

    $caught = $null
    try { & $ScriptBlock | Out-Null }
    catch { $caught = $_ }

    if (-not $caught) { throw ('{0} {1}' -f (Get-WacTestLocation $MyInvocation), $Message) }
    if ($Pattern -and ([string]$caught) -notmatch $Pattern) {
        throw ('{0} error did not match /{1}/: {2}' -f (Get-WacTestLocation $MyInvocation), $Pattern, $caught)
    }
}

function New-TestSandbox {
    <#
    .SYNOPSIS
        Creates a disposable directory under TEMP and tracks it for automatic cleanup.
    .DESCRIPTION
        The path is canonicalised through GetFullPath, the same call Get-WacNormalizedPath uses, so
        a comparison against a module return value cannot break on a CI runner whose TEMP is an 8.3
        name such as C:\Users\RUNNER~1\AppData\Local\Temp.
    #>
    param([string]$Prefix = 'wac')

    $name = '{0}_{1}' -f $Prefix, [guid]::NewGuid().ToString('N').Substring(0, 12)
    $path = [System.IO.Path]::GetFullPath((Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $name))
    [void][System.IO.Directory]::CreateDirectory($path)
    [void]$script:WacSandboxes.Add($path)
    return $path
}

function Remove-TestSandboxItem {
    <#
    .SYNOPSIS
        Best-effort recursive delete that survives read-only attributes, reparse points and >MAX_PATH.
    #>
    param([Parameter(Mandatory = $true)][string]$LongPath)

    $info = New-Object System.IO.DirectoryInfo($LongPath)
    if (-not $info.Exists) { return }

    $entries = @()
    try { $entries = @($info.GetFileSystemInfos()) } catch { $entries = @() }

    foreach ($entry in $entries) {
        $isReparse = $false
        try { $isReparse = (([int]$entry.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) }
        catch { $isReparse = $false }

        if (-not $isReparse) {
            try { $entry.Attributes = [System.IO.FileAttributes]::Normal } catch { $null = $_ }
        }

        try {
            if ($isReparse) {
                # Delete the link itself. Remove-Item throws a spurious NullReferenceException on
                # some junctions under Windows PowerShell 5.1.
                if ($entry -is [System.IO.DirectoryInfo]) { [System.IO.Directory]::Delete($entry.FullName, $false) }
                else { [System.IO.File]::Delete($entry.FullName) }
            }
            elseif ($entry -is [System.IO.DirectoryInfo]) {
                Remove-TestSandboxItem -LongPath $entry.FullName
            }
            else {
                [System.IO.File]::Delete($entry.FullName)
            }
        }
        catch {
            $null = $_
        }
    }

    try { [System.IO.Directory]::Delete($LongPath, $false) } catch { $null = $_ }
}

function Remove-TestSandbox {
    <#
    .SYNOPSIS
        Removes one sandbox, or every sandbox this suite created when -Path is omitted.
    #>
    param([string]$Path)

    if (-not $Path) {
        foreach ($tracked in @($script:WacSandboxes.ToArray())) { Remove-TestSandbox -Path $tracked }
        $script:WacSandboxes.Clear()
        return
    }

    $long = $Path
    if ($long.Length -ge 240 -and -not $long.StartsWith('\\?\')) { $long = '\\?\' + $long }
    Remove-TestSandboxItem -LongPath $long

    for ($i = $script:WacSandboxes.Count - 1; $i -ge 0; $i--) {
        if ($script:WacSandboxes[$i] -ieq $Path) { $script:WacSandboxes.RemoveAt($i) }
    }
}

function Test-Case {
    <#
    .SYNOPSIS
        Runs one case, records pass/fail with the failing line, and prints the result immediately.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $failure = $null

    try {
        & $Body | Out-Null
    }
    catch {
        $failure = [string]$_.Exception.Message
        # A non-assertion exception carries no call-site prefix, so take one from the error record.
        if ($failure -notmatch '^\S+\.ps1:\d+ ') {
            $where = '<unknown>'
            try {
                if ($_.InvocationInfo -and $_.InvocationInfo.ScriptName) {
                    $where = '{0}:{1}' -f (Split-Path -Leaf $_.InvocationInfo.ScriptName), $_.InvocationInfo.ScriptLineNumber
                }
            }
            catch { $where = '<unknown>' }
            $failure = '{0} {1}' -f $where, $failure
        }
    }

    $watch.Stop()
    $ms = [int]$watch.Elapsed.TotalMilliseconds

    [void]$script:WacCases.Add([PSCustomObject]@{ Name = $Name; Failure = $failure; DurationMs = $ms })

    if ($failure) { Write-Host ('FAIL  {0}  ({1} ms)  {2}' -f $Name, $ms, $failure) }
    else { Write-Host ('pass  {0}  ({1} ms)' -f $Name, $ms) }
}

function Complete-TestRun {
    <#
    .SYNOPSIS
        Cleans up tracked sandboxes, prints the suite total and exits non-zero on failure.
    #>
    param()

    Remove-TestSandbox

    $failed = @($script:WacCases | Where-Object { $_.Failure })
    $total = $script:WacCases.Count
    $elapsed = 0
    foreach ($case in $script:WacCases) { $elapsed += $case.DurationMs }

    Write-Host ('TOTAL cases={0} passed={1} failed={2} duration={3}ms' -f $total, ($total - $failed.Count), $failed.Count, $elapsed)

    # A suite that declared nothing is a silent false green, not a pass.
    if ($total -eq 0) {
        Write-Host 'FAIL  suite declared no cases.'
        exit 2
    }

    if ($failed.Count -gt 0) { exit 1 }
    exit 0
}
