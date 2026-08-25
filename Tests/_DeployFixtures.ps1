#Requires -Version 5.1
<#
.SYNOPSIS
    The redirected-%ProgramFiles% sandbox, the synthetic source checkout and the scheduled-task
    stubs every WindowsAutoCleanup.Deploy package suite installs.

.DESCRIPTION
    Dot-sourced by Deploy.Tests.ps1, DeploymentProof.Tests.ps1 and ScheduledTask.Tests.ps1. It is
    not a suite: its name does not match Tests\*.Tests.ps1, so the runner never executes it alone.

    Invoke-InDeploymentSandbox is the reason it is shared rather than copied. It redirects
    %ProgramFiles% into a disposable directory and restores it in a finally block, so a second copy
    that drifted would let a case write a deployment outside the sandbox it created.
#>

function Invoke-InDeploymentSandbox {
    <#
    .SYNOPSIS
        Runs a body with %ProgramFiles% pointed at a disposable sandbox, then restores it.
    .DESCRIPTION
        Get-WacDeploymentRoot reads the variable on every call, so redirecting it is what keeps a
        deployment test off the real machine. The body receives the sandbox path.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    $sandbox = New-TestSandbox -Prefix $Prefix
    $savedProgramFiles = $env:ProgramFiles
    try {
        $programFiles = Join-Path -Path $sandbox -ChildPath 'PF'
        [void][System.IO.Directory]::CreateDirectory($programFiles)
        $env:ProgramFiles = $programFiles
        & $Body $sandbox
    }
    finally {
        $env:ProgramFiles = $savedProgramFiles
        Remove-TestSandbox -Path $sandbox
    }
}

function New-TestCheckout {
    <#
    .SYNOPSIS
        A source checkout carrying every shape the deployment copy has to decide about.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$RunContent = '# run'
    )

    foreach ($directory in @('src', '.git', '.ai', 'Logs', 'src\nested')) {
        [void][System.IO.Directory]::CreateDirectory((Join-Path -Path $Path -ChildPath $directory))
    }

    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'Run.ps1'), $RunContent)
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'LICENSE'), 'MIT')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'README.md'), 'readme')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'src\WindowsAutoCleanup.Core.psm1'), '# core')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'src\nested\deep.psm1'), '# deep')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'src\.ignoreme'), 'x')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath '.git\config'), 'x')
    [System.IO.File]::WriteAllText((Join-Path -Path $Path -ChildPath 'Logs\old.log'), 'x')

    return $Path
}

function New-StubAction {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Execute,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Arguments,
        [AllowEmptyString()][string]$WorkingDirectory = ''
    )

    return [PSCustomObject]@{ Execute = $Execute; Arguments = $Arguments; WorkingDirectory = $WorkingDirectory }
}

function New-StubTask {
    <#
    .SYNOPSIS
        A stand-in for a ScheduledTask object. Test-WacTaskIsOurs reads only these members, so a
        stub exercises the whole proof without registering anything with the live scheduler.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TaskPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Description,
        [AllowEmptyCollection()][object[]]$Action = @()
    )

    return [PSCustomObject]@{
        TaskName = 'WindowsAutoCleanup'
        TaskPath = $TaskPath
        Description = $Description
        Actions = $Action
    }
}
