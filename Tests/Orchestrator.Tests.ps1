#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the Run.ps1 contract: the elevated-relaunch argument vector, parameter
    binding, the rendered help, and the module surface the entry point depends on.

.DESCRIPTION
    Run.ps1 executes its main body on load, so the relaunch builder is lifted out of the script's
    AST and defined on its own instead of dot-sourcing the whole file. Every assertion is made on
    the REAL returned vector, on the REAL command line built from it, or on what a REAL child
    process received - never on the text of the script, because a test that greps the source for
    '-ResetWindowsUpdateBase' is exactly what let ledger P0-2 ship: an explicit
    -ResetWindowsUpdateBase:$false was lost across the UAC relaunch while the old suite stayed green.

    Nothing here asserts on this process's own privilege level: the hosted Windows runner is
    elevated and a developer shell usually is not. The one case that needs a non-elevated process
    reports itself as not applicable instead of asserting.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'
$script:RunPath = Join-Path -Path $script:RepoRoot -ChildPath 'Run.ps1'

Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

# The host running this suite, taken from the live process rather than PATH, so the child is the
# same edition that is currently under test.
$script:HostExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

# ---------------------------------------------------------------------------------------------
# Lifting the function under test out of Run.ps1
# ---------------------------------------------------------------------------------------------

$script:RunTokens = $null
$script:RunErrors = $null
$script:RunAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $script:RunPath, [ref]$script:RunTokens, [ref]$script:RunErrors)

$script:RelaunchAst = @($script:RunAst.FindAll({
            param($node)
            ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and
            ($node.Name -eq 'Get-WacRunRelaunchArgument')
        }, $true))

if ($script:RelaunchAst.Count -ne 1) {
    throw ('Run.ps1 must define exactly one Get-WacRunRelaunchArgument; found {0}.' -f $script:RelaunchAst.Count)
}

# Defining the extracted function is the whole point: the vector it returns is then produced by the
# shipped code, not by a copy of it living in this suite.
. ([scriptblock]::Create($script:RelaunchAst[0].Extent.Text))

function Get-RelaunchVector {
    <#
    .SYNOPSIS
        Sets the script-scope variables Run.ps1 would have bound, then returns the real vector.
    #>
    param(
        [hashtable]$Bound = @{},
        [bool]$Reset = $true,
        [bool]$Prune = $false,
        [bool]$Legacy = $false,
        [bool]$SkipBin = $false,
        [string]$Level = 'INFO',
        [int]$Budget = 210,
        [AllowEmptyCollection()][string[]]$Category = @(),
        [string]$Mutex = 'Global\WindowsAutoCleanup',
        [string]$ScriptFile = 'C:\Tools\WindowsAutoCleanup\Run.ps1'
    )

    $script:ResetWindowsUpdateBase = $Reset
    $script:PruneSupersededDrivers = $Prune
    $script:EnableLegacyDiskCleanup = $Legacy
    $script:SkipRecycleBin = $SkipBin
    $script:LogLevel = $Level
    $script:BudgetMinutes = $Budget
    $script:SkipCategory = @($Category)
    $script:MutexName = $Mutex
    $script:ScriptPath = $ScriptFile

    return @(Get-WacRunRelaunchArgument -Bound $Bound)
}

function Get-RelaunchPayload {
    <#
    .SYNOPSIS
        The PowerShell source the child will execute: the element after -Command.
    .DESCRIPTION
        The vector is -NoProfile -ExecutionPolicy Bypass [-HostSwitch...] -Command <payload>.
        -Command rather than -File is deliberate and load-bearing: Windows PowerShell 5.1 refuses to
        bind -Switch:$false under -File at all, so every switch value in this file is asserted on the
        payload PowerShell will actually parse.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Vector)

    for ($i = 0; $i -lt $Vector.Count; $i++) {
        if ([string]::Equals($Vector[$i], '-Command', [System.StringComparison]::Ordinal)) {
            if ($i + 1 -lt $Vector.Count) { return $Vector[$i + 1] }
        }
    }
    return ''
}

function Test-PayloadHasSwitch {
    <#
    .SYNOPSIS
        Ordinal check for an exact '-Name:$value' token in the payload.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Payload,
        [Parameter(Mandatory = $true)][string]$Token
    )

    return $Payload.IndexOf($Token, [System.StringComparison]::Ordinal) -ge 0
}

function Test-PayloadHasBareSwitch {
    <#
    .SYNOPSIS
        True when the payload carries '-Name' with no ':value' suffix, which would let the child fall
        back to its own default.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Payload,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return [regex]::IsMatch($Payload, ('(?<![\w:$])-' + [regex]::Escape($Name) + '(?![\w:])'))
}

function Test-VectorContains {
    <#
    .SYNOPSIS
        Ordinal membership. PowerShell's -contains is case-insensitive and would pass a casing
        regression in a switch name.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Vector,
        [Parameter(Mandatory = $true)][string]$Value
    )

    foreach ($element in $Vector) {
        if ([string]::Equals($element, $Value, [System.StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------------------------
# Child processes
# ---------------------------------------------------------------------------------------------

function Start-ProbeProcess {
    <#
    .SYNOPSIS
        Starts a child of the host running this suite with one pre-quoted command line.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [hashtable]$Environment = @{},
        [string]$HostExe
    )

    if (-not $HostExe) { $HostExe = $script:HostExe }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $HostExe
    $psi.Arguments = $CommandLine
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $script:RepoRoot
    foreach ($key in $Environment.Keys) { $psi.EnvironmentVariables[$key] = [string]$Environment[$key] }

    return [System.Diagnostics.Process]::Start($psi)
}

function Wait-ProbeProcess {
    <#
    .SYNOPSIS
        Bounded wait plus process-tree kill, so a child that never exits cannot hang this suite:
        "did not finish inside the bound" is the detected signal, not a stalled run.
    #>
    param(
        [Parameter(Mandatory = $true)]$Process,
        [int]$TimeoutMs = 90000
    )

    $outTask = $Process.StandardOutput.ReadToEndAsync()
    $errTask = $Process.StandardError.ReadToEndAsync()
    $exited = $Process.WaitForExit($TimeoutMs)

    if (-not $exited) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe')
        $psi.Arguments = '/T /F /PID {0}' -f $Process.Id
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $killer = [System.Diagnostics.Process]::Start($psi)
        if ($killer) {
            [void]$killer.StandardOutput.ReadToEndAsync()
            [void]$killer.StandardError.ReadToEndAsync()
            [void]$killer.WaitForExit(10000)
            try { $killer.Dispose() } catch { $null = $_ }
        }
        [void]$Process.WaitForExit(10000)
    }

    [void]$outTask.Wait(5000)
    [void]$errTask.Wait(5000)

    $exitCode = -1
    if ($exited) { try { $exitCode = [int]$Process.ExitCode } catch { $exitCode = -1 } }

    return [PSCustomObject]@{
        Exited    = $exited
        ExitCode  = $exitCode
        Output    = $(if ($outTask.IsCompleted) { [string]$outTask.Result } else { '' })
        ErrorText = $(if ($errTask.IsCompleted) { [string]$errTask.Result } else { '' })
    }
}

function Invoke-Probe {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [hashtable]$Environment = @{},
        [int]$TimeoutMs = 90000,
        [string]$HostExe
    )

    $process = $null
    try {
        $process = Start-ProbeProcess -CommandLine $CommandLine -Environment $Environment -HostExe $HostExe
        return (Wait-ProbeProcess -Process $process -TimeoutMs $TimeoutMs)
    }
    finally {
        if ($process) { try { $process.Dispose() } catch { $null = $_ } }
    }
}

function Get-ProbeValue {
    <#
    .SYNOPSIS
        Reads one KEY=value line out of a probe's stdout.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Output,
        [Parameter(Mandatory = $true)][string]$Key
    )

    foreach ($line in @($Output -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith($Key + '=', [System.StringComparison]::Ordinal)) {
            return $trimmed.Substring($Key.Length + 1)
        }
    }
    return $null
}

# A parameter block that mirrors Run.ps1's, so a value that does not survive the command line shows
# up as the DEFAULT the parent never asked for - which is exactly how P0-2 behaved.
$script:ArgumentProbeBody = @'
[CmdletBinding()]
param(
    [switch]$Scheduled,
    [switch]$ResetWindowsUpdateBase = $true,
    [switch]$PruneSupersededDrivers,
    [switch]$EnableLegacyDiskCleanup,
    [switch]$SkipRecycleBin,
    [string[]]$SkipCategory = @(),
    [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')][string]$LogLevel = 'INFO',
    [ValidateRange(1, 235)][int]$BudgetMinutes = 210,
    [string]$MutexName = 'Global\WindowsAutoCleanup'
)

Set-StrictMode -Version 2.0
$split = @($SkipCategory | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

Write-Output ('SELF=' + $PSCommandPath)
Write-Output ('RESET=' + [bool]$ResetWindowsUpdateBase)
Write-Output ('PRUNE=' + [bool]$PruneSupersededDrivers)
Write-Output ('LEGACY=' + [bool]$EnableLegacyDiskCleanup)
Write-Output ('SKIPBIN=' + [bool]$SkipRecycleBin)
Write-Output ('LOGLEVEL=' + $LogLevel)
Write-Output ('BUDGET=' + $BudgetMinutes)
Write-Output ('MUTEX=' + $MutexName)
Write-Output ('CATEGORY=' + ($split -join '|'))
exit 0
'@

$script:InspectProbeBody = @'
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:WAC_PROBE_MODE -eq 'help') {
    $help = Get-Help -Full -Name $env:WAC_PROBE_RUN
    Write-Output ('PARAMS=' + ((@($help.parameters.parameter) | ForEach-Object { $_.name }) -join ','))
    Write-Output ('SYNOPSIS=' + ((($help.Synopsis) -replace '\s+', ' ').Trim()))
    Write-Output ('DESCRIPTION=' + (((($help.description | Out-String)) -replace '\s+', ' ').Trim()))
    Write-Output ('NOTES=' + ((($help.alertSet.alert | Out-String) -replace '\s+', ' ').Trim()))
    exit 0
}

if ($env:WAC_PROBE_MODE -eq 'surface') {
    foreach ($name in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
        $path = Join-Path -Path $env:WAC_PROBE_SRC -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $name)
        Import-Module -Name $path -Force -DisableNameChecking -ErrorAction Stop
        Write-Output ('IMPORTED=' + $name)
    }

    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($command in @($env:WAC_PROBE_COMMAND -split ',' | Where-Object { $_ })) {
        if (-not (Get-Command -Name $command -CommandType Function -ErrorAction SilentlyContinue)) {
            [void]$missing.Add($command)
        }
    }

    Write-Output ('MISSING=' + ($missing -join ','))
    Write-Output ('CHECKED=' + @($env:WAC_PROBE_COMMAND -split ',' | Where-Object { $_ }).Count)
    exit 0
}

Write-Output 'MODE=unknown'
exit 9
'@

function New-ProbeScript {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Body
    )

    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    [System.IO.File]::WriteAllText($Path, $Body, (New-Object System.Text.UTF8Encoding($false)))
    return $Path
}

# ---------------------------------------------------------------------------------------------
# The relaunch vector
# ---------------------------------------------------------------------------------------------

Test-Case 'Run.ps1 parses cleanly and keeps the relaunch vector in one testable function' {
    Assert-Equal 0 (@($script:RunErrors).Count) (($script:RunErrors | ForEach-Object { [string]$_ }) -join ' ; ')
    Assert-True (@($script:RunTokens).Count -gt 100) 'the parser produced no tokens for Run.ps1'

    $vector = Get-RelaunchVector
    Assert-True (Test-VectorContains -Vector $vector -Value '-Command') `
        ('the relaunch must go through -Command, not -File: ' + ($vector -join ' '))
    Assert-True ((Get-RelaunchPayload -Vector $vector).Length -gt 0) 'the -Command payload was empty'
}

Test-Case 'The default relaunch vector states every switch explicitly' {
    $vector = Get-RelaunchVector

    $expected = "-NoProfile -ExecutionPolicy Bypass -Command " +
        "`$LASTEXITCODE = 1; & 'C:\Tools\WindowsAutoCleanup\Run.ps1' -EnableLegacyDiskCleanup:`$false " +
        "-PruneSupersededDrivers:`$false -ResetWindowsUpdateBase:`$true -SkipRecycleBin:`$false " +
        "-BudgetMinutes '210' -LogLevel 'INFO'; exit `$LASTEXITCODE"

    Assert-Equal $expected ($vector -join ' ')
}

Test-Case 'An explicit -ResetWindowsUpdateBase:$false survives the relaunch (ledger P0-2)' {
    $vector = Get-RelaunchVector -Reset $false -Bound @{ ResetWindowsUpdateBase = $false }

    # The load-bearing assertion. A vector that merely CONTAINS the text '-ResetWindowsUpdateBase'
    # is the defect: the child then applies the $true default and DISM runs /ResetBase anyway.
    $payload = Get-RelaunchPayload -Vector $vector

    Assert-True (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$false') `
        ('the payload was ' + $payload)
    Assert-False (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$true') `
        'the child was told the opposite of what the parent was given'
    Assert-False (Test-PayloadHasBareSwitch -Payload $payload -Name 'ResetWindowsUpdateBase') `
        'a bare switch lets the child fall back to its default'

    $expected = "`$LASTEXITCODE = 1; & 'C:\Tools\WindowsAutoCleanup\Run.ps1' -EnableLegacyDiskCleanup:`$false " +
        "-PruneSupersededDrivers:`$false -ResetWindowsUpdateBase:`$false -SkipRecycleBin:`$false " +
        "-BudgetMinutes '210' -LogLevel 'INFO'; exit `$LASTEXITCODE"
    Assert-Equal $expected $payload
}

Test-Case 'An explicit -ResetWindowsUpdateBase:$true is emitted explicitly too' {
    $vector = Get-RelaunchVector -Reset $true -Bound @{ ResetWindowsUpdateBase = $true }

    $payload = Get-RelaunchPayload -Vector $vector
    Assert-True (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$true') $payload
    Assert-False (Test-PayloadHasSwitch -Payload $payload -Token '-ResetWindowsUpdateBase:$false') $payload
    Assert-False (Test-PayloadHasBareSwitch -Payload $payload -Name 'ResetWindowsUpdateBase') $payload
}

Test-Case 'The three opt-in switches round-trip in both states' {
    $off = Get-RelaunchPayload -Vector (Get-RelaunchVector)
    foreach ($name in @('PruneSupersededDrivers', 'EnableLegacyDiskCleanup', 'SkipRecycleBin')) {
        Assert-True (Test-PayloadHasSwitch -Payload $off -Token ('-{0}:$false' -f $name)) ('missing off state for ' + $name)
        Assert-False (Test-PayloadHasBareSwitch -Payload $off -Name $name) ('bare switch emitted for ' + $name)
    }

    $on = Get-RelaunchPayload -Vector (Get-RelaunchVector -Prune $true -Legacy $true -SkipBin $true `
        -Bound @{ PruneSupersededDrivers = $true; EnableLegacyDiskCleanup = $true; SkipRecycleBin = $true })
    foreach ($name in @('PruneSupersededDrivers', 'EnableLegacyDiskCleanup', 'SkipRecycleBin')) {
        Assert-True (Test-PayloadHasSwitch -Payload $on -Token ('-{0}:$true' -f $name)) ('missing on state for ' + $name)
        Assert-False (Test-PayloadHasSwitch -Payload $on -Token ('-{0}:$false' -f $name)) ('both states emitted for ' + $name)
    }

    # An opt-in switch the caller never asked for must still be stated, and stated as false.
    Assert-True (Test-PayloadHasSwitch -Payload $off -Token '-EnableLegacyDiskCleanup:$false')
}

Test-Case 'A script path containing spaces is quoted exactly once on the command line' {
    $spaced = 'C:\Program Files\Windows Auto Cleanup\Run.ps1'
    $vector = Get-RelaunchVector -ScriptFile $spaced

    # Two quoting layers, each applied exactly once: the payload single-quotes the path for the
    # PowerShell parser, and ConvertTo-WacCommandLine double-quotes the payload for CreateProcess.
    # Doing either twice is how a relaunch ends up looking for a directory called '"C:\Program'.
    $payload = Get-RelaunchPayload -Vector $vector
    Assert-True ($payload.StartsWith(("`$LASTEXITCODE = 1; & '" + $spaced + "' "), [System.StringComparison]::Ordinal)) $payload

    $commandLine = ConvertTo-WacCommandLine -ArgumentList $vector
    $expected = '-NoProfile -ExecutionPolicy Bypass -Command "' + $payload + '"'
    Assert-Equal $expected $commandLine
}

Test-Case 'SkipCategory appears only when it was bound and travels as one token' {
    $absent = Get-RelaunchVector -Category @('Temp')
    Assert-False (Test-VectorContains -Vector $absent -Value '-SkipCategory') `
        'an unbound -SkipCategory was forwarded to the child'

    $empty = Get-RelaunchVector -Category @() -Bound @{ SkipCategory = @() }
    Assert-False (Test-VectorContains -Vector $empty -Value '-SkipCategory') `
        'an empty -SkipCategory was forwarded as a value-less switch'

    $bound = Get-RelaunchPayload -Vector (Get-RelaunchVector -Category @('Windows Update cache', 'Temp') `
        -Bound @{ SkipCategory = @('Windows Update cache', 'Temp') })

    # Under -Command the child's parser sees a real ARRAY, so each category keeps its own quoting and
    # a space inside a category name can no longer split it into two elements.
    $expectedFragment = "-SkipCategory 'Windows Update cache','Temp'"
    Assert-True ($bound.IndexOf($expectedFragment, [System.StringComparison]::Ordinal) -ge 0) `
        ('the payload was ' + $bound)
}

Test-Case 'MutexName appears only when it was bound' {
    $absent = Get-RelaunchPayload -Vector (Get-RelaunchVector -Mutex 'Global\WindowsAutoCleanup')
    Assert-False ($absent.IndexOf('-MutexName', [System.StringComparison]::Ordinal) -ge 0) `
        'the default mutex name was forwarded even though it was never bound'

    $bound = Get-RelaunchPayload -Vector (Get-RelaunchVector -Mutex 'Global\WacTestProbe' `
        -Bound @{ MutexName = 'Global\WacTestProbe' })
    $expectedFragment = "-MutexName 'Global\WacTestProbe'"
    Assert-True ($bound.IndexOf($expectedFragment, [System.StringComparison]::Ordinal) -ge 0) $bound
}

Test-Case 'The elevated relaunch host binds the values the vector carries' {
    $sandbox = New-TestSandbox -Prefix 'orch-relaunch'
    try {
        # The child must be started by the host Run.ps1 would really elevate through, not by the
        # host running this suite: the two do not agree on -File and switch values (see the
        # companion case below), so testing the wrong one would prove nothing about the relaunch.
        $relaunchHost = Get-WacCanonicalPowerShellHost
        Assert-True ([bool]$relaunchHost) 'no machine-trusted PowerShell host was found, so the relaunch cannot be tested'

        $probe = New-ProbeScript -Body $script:ArgumentProbeBody `
            -Path (Join-Path -Path $sandbox -ChildPath 'Windows Auto Cleanup\Relaunch Probe.ps1')

        $vector = Get-RelaunchVector -ScriptFile $probe -Reset $false -Prune $true -Level 'DEBUG' -Budget 42 `
            -Category @('Windows Update cache', 'Temp') -Mutex 'Global\WacTestProbe' `
            -Bound @{
            ResetWindowsUpdateBase = $false
            PruneSupersededDrivers = $true
            SkipCategory           = @('Windows Update cache', 'Temp')
            MutexName              = 'Global\WacTestProbe'
        }

        $result = Invoke-Probe -CommandLine (ConvertTo-WacCommandLine -ArgumentList $vector) -TimeoutMs 90000 -HostExe $relaunchHost

        Assert-True $result.Exited 'the probe child did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ('the relaunch vector did not bind in ' + $relaunchHost + ': ' + $result.ErrorText)
        Assert-Equal $probe (Get-ProbeValue -Output $result.Output -Key 'SELF') 'the spaced script path did not survive quoting'
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'RESET') 'the child fell back to the default (ledger P0-2)'
        Assert-Equal 'True' (Get-ProbeValue -Output $result.Output -Key 'PRUNE')
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'LEGACY')
        Assert-Equal 'False' (Get-ProbeValue -Output $result.Output -Key 'SKIPBIN')
        Assert-Equal 'DEBUG' (Get-ProbeValue -Output $result.Output -Key 'LOGLEVEL')
        Assert-Equal '42' (Get-ProbeValue -Output $result.Output -Key 'BUDGET')
        Assert-Equal 'Global\WacTestProbe' (Get-ProbeValue -Output $result.Output -Key 'MUTEX')
        Assert-Equal 'Windows Update cache|Temp' (Get-ProbeValue -Output $result.Output -Key 'CATEGORY')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The named half of the vector survives -File on the host running this suite' {
    $sandbox = New-TestSandbox -Prefix 'orch-named'
    try {
        $probe = New-ProbeScript -Body $script:ArgumentProbeBody `
            -Path (Join-Path -Path $sandbox -ChildPath 'Windows Auto Cleanup\Named Probe.ps1')

        # Named values and the script path only. The boolean half is covered by the case above,
        # against the host that actually receives it.
        $vector = Get-WacRelaunchArgument -ScriptPath $probe -NamedValue @{
            LogLevel      = 'WARNING'
            BudgetMinutes = '7'
            SkipCategory  = 'Windows Update cache,Temp'
            MutexName     = 'Global\WacTestProbe'
        }

        $result = Invoke-Probe -CommandLine (ConvertTo-WacCommandLine -ArgumentList $vector) -TimeoutMs 90000

        Assert-True $result.Exited 'the probe child did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)
        Assert-Equal $probe (Get-ProbeValue -Output $result.Output -Key 'SELF') 'the spaced script path did not survive quoting'
        Assert-Equal 'WARNING' (Get-ProbeValue -Output $result.Output -Key 'LOGLEVEL')
        Assert-Equal '7' (Get-ProbeValue -Output $result.Output -Key 'BUDGET')
        Assert-Equal 'Global\WacTestProbe' (Get-ProbeValue -Output $result.Output -Key 'MUTEX')
        # One -File token has to re-split into two categories, spaces and all.
        Assert-Equal 'Windows Update cache|Temp' (Get-ProbeValue -Output $result.Output -Key 'CATEGORY')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# The Run.ps1 command-line contract
# ---------------------------------------------------------------------------------------------

Test-Case 'A scheduled run that is not elevated fails instead of cleaning' {
    if (Test-WacIsAdministrator) {
        # Not applicable: this process is elevated, so the child would be too and would perform a
        # real cleanup. Asserting on the privilege level itself would pass in exactly one of the two
        # places this suite has to work.
        Write-Host '      (not applicable: this process is elevated, so a child cannot prove the unelevated path)'
        return
    }

    $sandbox = New-TestSandbox -Prefix 'orch-scheduled'
    try {
        $commandLine = ConvertTo-WacCommandLine -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:RunPath,
            '-Scheduled', '-BudgetMinutes', '1', '-MutexName', ('Global\WacTest{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8)))

        # An UNELEVATED run logs under the user's own profile on purpose: whoever CREATES
        # %ProgramData%\WindowsAutoCleanup becomes its owner and, through CREATOR OWNER inheritance,
        # gains full control of the directory the SYSTEM task later writes its audit log into. Both
        # roots are redirected so the case proves the log went to the per-user one and NOT to the
        # machine-wide one.
        $result = Invoke-Probe -CommandLine $commandLine -TimeoutMs 120000 `
            -Environment @{ ProgramData = (Join-Path -Path $sandbox -ChildPath 'PD'); LOCALAPPDATA = (Join-Path -Path $sandbox -ChildPath 'LA') }

        Assert-True $result.Exited 'Run.ps1 did not finish inside its bound'
        Assert-Equal 1 $result.ExitCode ($result.Output + $result.ErrorText)

        $logs = @(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'LA\WindowsAutoCleanup\Logs') `
                -Filter 'WindowsAutoCleanup_*.log' -File -ErrorAction SilentlyContinue)
        Assert-Equal 1 $logs.Count 'the run did not create exactly one log file in the redirected per-user root'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $sandbox -ChildPath 'PD\WindowsAutoCleanup')) `
            'an unelevated run created the machine-wide state directory and would therefore own it'

        $text = [System.IO.File]::ReadAllText($logs[0].FullName)
        Assert-True ($text.Contains('[ERROR] [Run] Administrator privileges are required')) $text
        Assert-False ($text.Contains('[Summary]')) 'the run reached the cleanup summary without being elevated'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The deprecated -SkipAclHardening switch is still accepted by parameter binding' {
    $sandbox = New-TestSandbox -Prefix 'orch-acl'
    try {
        # -LogLevel NOPE is a poison pill: binding fails before the script body runs, so this proves
        # acceptance of -SkipAclHardening without ever letting a cleanup start.
        $accepted = Invoke-Probe -TimeoutMs 90000 -Environment @{ ProgramData = $sandbox } -CommandLine (
            ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:RunPath,
                '-SkipAclHardening', '-LogLevel', 'NOPE'))

        Assert-True $accepted.Exited 'the binding probe did not finish inside its bound'
        Assert-True ($accepted.ExitCode -ne 0) 'the poison-pill argument was accepted, so the body may have run'

        # Console line wrapping differs per host, so compare with whitespace removed.
        $acceptedText = ($accepted.ErrorText -replace '\s', '')
        Assert-True ($acceptedText.Contains('LogLevel')) $accepted.ErrorText
        Assert-False ($acceptedText.Contains('SkipAclHardening')) `
            'a task registered by an older installer would now fail to bind'

        $unknown = Invoke-Probe -TimeoutMs 90000 -Environment @{ ProgramData = $sandbox } -CommandLine (
            ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:RunPath,
                '-SkipAclHardeningX'))

        # The control: an unknown switch really is rejected by name, which is what makes the
        # assertion above evidence rather than a coincidence.
        Assert-True $unknown.Exited
        Assert-True ($unknown.ExitCode -ne 0)
        Assert-True ((($unknown.ErrorText -replace '\s', '')).Contains('SkipAclHardeningX')) $unknown.ErrorText

        $logs = @(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'WindowsAutoCleanup\Logs') `
                -Filter '*.log' -File -ErrorAction SilentlyContinue)
        Assert-Equal 0 $logs.Count 'a binding failure still executed the script body'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Get-Help renders every parameter and the exit-code table' {
    $sandbox = New-TestSandbox -Prefix 'orch-help'
    try {
        $probe = New-ProbeScript -Body $script:InspectProbeBody -Path (Join-Path -Path $sandbox -ChildPath 'inspect.ps1')

        $result = Invoke-Probe -TimeoutMs 90000 -Environment @{ WAC_PROBE_MODE = 'help'; WAC_PROBE_RUN = $script:RunPath } `
            -CommandLine (ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $probe))

        Assert-True $result.Exited 'the help probe did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)

        # Comment-based help only renders when the block is separated from #Requires by a blank
        # line; without it Get-Help falls back to a stub with no parameters and no notes.
        $expected = 'Scheduled,ResetWindowsUpdateBase,PruneSupersededDrivers,EnableLegacyDiskCleanup,SkipRecycleBin,' +
        'SkipCategory,LogLevel,BudgetMinutes,MutexName,SkipAclHardening'
        Assert-Equal $expected (Get-ProbeValue -Output $result.Output -Key 'PARAMS')

        $synopsis = [string](Get-ProbeValue -Output $result.Output -Key 'SYNOPSIS')
        Assert-True ($synopsis.Length -gt 20) ('the synopsis was [' + $synopsis + ']')

        $notes = [string](Get-ProbeValue -Output $result.Output -Key 'NOTES')
        Assert-True ($notes -match 'Exit codes') $notes
        foreach ($pair in @('0 success', '1 error', '2 completed', '3 another run', '4 elevation', '5 unsupported')) {
            Assert-True ($notes.Contains($pair)) ('the exit-code table is missing "' + $pair + '": ' + $notes)
        }

        $description = [string](Get-ProbeValue -Output $result.Output -Key 'DESCRIPTION')
        Assert-True ($description.Contains('-PruneSupersededDrivers')) `
            'the description no longer documents the opt-in destructive capabilities'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The five modules import together and every Wac command Run.ps1 calls resolves' {
    $sandbox = New-TestSandbox -Prefix 'orch-surface'
    try {
        $called = @{}
        foreach ($node in $script:RunAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $name = $node.GetCommandName()
            if ($name -and $name -match '^[A-Za-z]+-Wac[A-Za-z]+$') { $called[$name] = $true }
        }
        foreach ($node in $script:RunAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            # Run.ps1 declares a few helpers of its own; those are not part of the module surface.
            if ($called.ContainsKey($node.Name)) { [void]$called.Remove($node.Name) }
        }

        $names = @($called.Keys | Sort-Object)
        Assert-True ($names.Count -ge 20) ('only {0} module commands were found in Run.ps1' -f $names.Count)

        $probe = New-ProbeScript -Body $script:InspectProbeBody -Path (Join-Path -Path $sandbox -ChildPath 'inspect.ps1')
        $result = Invoke-Probe -TimeoutMs 120000 -CommandLine (ConvertTo-WacCommandLine -ArgumentList @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $probe)) -Environment @{
            WAC_PROBE_MODE    = 'surface'
            WAC_PROBE_SRC     = $script:SrcRoot
            WAC_PROBE_COMMAND = ($names -join ',')
        }

        Assert-True $result.Exited 'the module-surface probe did not finish inside its bound'
        Assert-Equal 0 $result.ExitCode ($result.ErrorText)
        Assert-Equal '' ([string](Get-ProbeValue -Output $result.Output -Key 'MISSING')) 'Run.ps1 calls commands the modules do not export'
        Assert-Equal ([string]$names.Count) ([string](Get-ProbeValue -Output $result.Output -Key 'CHECKED'))
        foreach ($module in @('Core', 'FileSystem', 'Targets', 'Steps', 'Drivers')) {
            Assert-True ($result.Output.Contains('IMPORTED=' + $module)) ('module ' + $module + ' did not import: ' + $result.ErrorText)
        }
        Assert-Equal '' $result.ErrorText 'a module wrote to stderr while importing'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
