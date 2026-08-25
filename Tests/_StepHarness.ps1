<#
.SYNOPSIS
    The stubs and module-scope shadow helpers every WindowsAutoCleanup.Steps package suite installs.

.DESCRIPTION
    Dot-sourced by Steps.Tests.ps1, RecycleBin.Tests.ps1 and DiskCleanup.Tests.ps1. It is not a
    suite: its name does not match Tests\*.Tests.ps1, so the runner never executes it on its own.

    Every helper that reaches inside the code under test does so through $script:StepModule, which
    the SUITE sets to the module its own cases run in - Steps, RecycleBin or DiskCleanup. A shadow
    installed in the wrong module's session state is invisible to the function under test, so the
    variable is deliberately not defaulted here.
#>

$script:StepModule = $null

$script:System32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32'

$script:StubCall = New-Object 'System.Collections.Generic.List[object]'
$script:StubResult = @{}

$script:BoundedCall = New-Object 'System.Collections.Generic.List[object]'
$script:BoundedForce = @{}

# Handed to Set-WacProcessInvoker. It closes over this suite's script scope, so the recorded calls
# are visible to the assertions without any global state.
$script:RecordingInvoker = {
    param($FilePath, $ArgumentList, $TimeoutMs)

    $argv = @($ArgumentList)
    [void]$script:StubCall.Add([PSCustomObject]@{
        FilePath  = [string]$FilePath
        Arguments = $argv
        TimeoutMs = [int]$TimeoutMs
    })

    $exitCode = 0
    $timedOut = $false
    $standardOutput = ''

    $key = ''
    if ($argv.Count -gt 0) { $key = [string]$argv[0] }
    if ($script:StubResult.ContainsKey($key)) {
        $canned = $script:StubResult[$key]
        if ($canned.ContainsKey('ExitCode')) { $exitCode = $canned['ExitCode'] }
        if ($canned.ContainsKey('TimedOut')) { $timedOut = [bool]$canned['TimedOut'] }
        if ($canned.ContainsKey('Out')) { $standardOutput = [string]$canned['Out'] }
    }

    return [PSCustomObject]@{
        ExitCode       = $exitCode
        TimedOut       = $timedOut
        StandardOutput = $standardOutput
        StandardError  = ''
        DurationMs     = 5
        Started        = (-not $timedOut)
    }
}

# Handed to Set-WacStepBoundedInvoker. It records the bound it was given and then runs the block
# IN PROCESS, which is the whole point: the block keeps the module's session state, so a shadowed
# cmdlet inside it is the one that runs. A forced entry short-circuits it so the Incomplete and
# Failed branches can be reached without waiting for a real timeout.
$script:RecordingBounded = {
    param($ScriptBlock, $TimeoutMs, $ArgumentList, $Component, $IgnoreRunBudget)

    $index = $script:BoundedCall.Count
    [void]$script:BoundedCall.Add([PSCustomObject]@{
        Index           = $index
        TimeoutMs       = [int]$TimeoutMs
        Component       = [string]$Component
        IgnoreRunBudget = [bool]$IgnoreRunBudget
    })

    foreach ($key in @(('call:{0}' -f $index), [string]$Component)) {
        if (-not $script:BoundedForce.ContainsKey($key)) { continue }

        $forced = $script:BoundedForce[$key]
        $forcedOutcome = [string]$forced['Outcome']
        return [PSCustomObject]@{
            Outcome    = $forcedOutcome
            Started    = ($forcedOutcome -cne 'Incomplete')
            TimedOut   = ($forcedOutcome -ceq 'Incomplete')
            Output     = @()
            HadErrors  = ($forcedOutcome -cne 'Succeeded')
            Error      = [string]$forced['Error']
            DurationMs = 1
        }
    }

    $output = @()
    $failure = $null
    try { $output = @(& $ScriptBlock @ArgumentList) }
    catch { $failure = [string]$_.Exception.Message }

    $outcome = 'Succeeded'
    if ($failure) { $outcome = 'Failed' }

    return [PSCustomObject]@{
        Outcome    = $outcome
        Started    = $true
        TimedOut   = $false
        Output     = $output
        HadErrors  = ($null -ne $failure)
        Error      = $failure
        DurationMs = 1
    }
}

function Get-ModuleFunctionBody {
    <#
    .SYNOPSIS
        The scriptblock a name currently resolves to inside a module, so it can be put back exactly.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (& $Module { param($n) (Get-Item -Path ('function:' + $n)).ScriptBlock } $Name)
}

function Set-ModuleFunctionBody {
    <#
    .SYNOPSIS
        Replaces a name inside a module's own scope. Only the module sees the replacement.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
}

function Remove-ModuleFunction {
    <#
    .SYNOPSIS
        Removes a shadow installed by Set-ModuleFunctionBody.
    .DESCRIPTION
        No scope qualifier: 'function:script:<name>' is accepted by Set-Item but does not remove.
    #>
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    & $Module { param($n) Remove-Item -Path ('function:' + $n) -Force -ErrorAction SilentlyContinue } $Name
}

function Get-ModuleVariableValue {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (& $Module { param($n) Get-Variable -Name $n -ValueOnly -Scope Script } $Name)
}

function Set-ModuleVariableValue {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowNull()]$Value
    )

    & $Module { param($n, $v) Set-Variable -Name $n -Value $v -Scope Script } $Name $Value
}

function Invoke-WithBoundedSeam {
    <#
    .SYNOPSIS
        Runs a body with the recording bounded invoker installed, then removes it.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$Body)

    $script:BoundedCall.Clear()
    $script:BoundedForce = @{}

    Set-WacStepBoundedInvoker -Invoker $script:RecordingBounded
    try { & $Body }
    finally {
        Set-WacStepBoundedInvoker -Invoker $null
        $script:BoundedForce = @{}
    }
}

function Invoke-WithStubbedTool {
    <#
    .SYNOPSIS
        Runs a body with the recording process invoker and the bounded seam installed and the
        privilege check forced on, then restores all three.
    .DESCRIPTION
        The privilege stub is deliberately scoped to the same window as the invoker: outside a
        fixture the module sees the real check, so nothing in this suite can reach a real dism.exe or
        cleanmgr.exe even if a case forgets to arm the invoker.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [switch]$StubToolPath
    )

    $script:StubCall.Clear()
    $script:StubResult = @{}
    $script:BoundedCall.Clear()
    $script:BoundedForce = @{}

    $originalAdmin = Get-ModuleFunctionBody -Module $script:StepModule -Name 'Test-WacIsAdministrator'
    Set-ModuleFunctionBody -Module $script:StepModule -Name 'Test-WacIsAdministrator' -Body { return $true }

    $originalToolPath = $null
    if ($StubToolPath) {
        $originalToolPath = Get-ModuleFunctionBody -Module $script:StepModule -Name 'Get-WacSystemToolPath'
        # Existence is not probed: cleanmgr.exe ships only with the Desktop Experience, and whether
        # the runner happens to have it must not decide whether this behaviour is covered.
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Get-WacSystemToolPath' -Body {
            param([Parameter(Mandatory = $true)][string]$Leaf)
            return (Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath $Leaf)
        }
    }

    Set-WacProcessInvoker -Invoker $script:RecordingInvoker
    Set-WacStepBoundedInvoker -Invoker $script:RecordingBounded
    try {
        & $Body
    }
    finally {
        Set-WacProcessInvoker -Invoker $null
        Set-WacStepBoundedInvoker -Invoker $null
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Test-WacIsAdministrator' -Body $originalAdmin
        if ($originalToolPath) {
            Set-ModuleFunctionBody -Module $script:StepModule -Name 'Get-WacSystemToolPath' -Body $originalToolPath
        }
        $script:StubResult = @{}
        $script:BoundedForce = @{}
    }
}

function Invoke-WithExpiredDeadline {
    <#
    .SYNOPSIS
        Runs a body with the run budget already gone, then puts a budget far enough out that no
        later case in this suite is capped by it.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$Body)

    Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddSeconds(-5))
    try { & $Body }
    finally { Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddDays(30)) }
}
