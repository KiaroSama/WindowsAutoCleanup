#Requires -Version 5.1
<#
.SYNOPSIS
    The machine DeploymentRollback.Tests.ps1 rolls back against: a stub Task Scheduler, and real
    deployment trees built through the module's own entry points.

.DESCRIPTION
    Dot-sourced by DeploymentRollback.Tests.ps1. It is not a suite: its name does not match
    Tests\*.Tests.ps1, so the runner never executes it alone.

    Its own responsibility is the DOUBLE, which is a different job from asserting on it. The stub
    scheduler registers whatever XML it is handed and hands back a task built from that XML, so a
    definition that comes back DIFFERENT is a real failure rather than an artefact of the stub;
    each -Drift is one field of that definition changed on the way in - the scheduler normalising
    something, or a different task landing at the same name - and getting that right is mechanism,
    not assertion.

    The deployment half is deliberately NOT doubled: Install-FixtureDeployment and New-FixtureStage
    build real trees through Install-WacDeployment and New-WacDeploymentStage, so the suite's
    SHA-256 assertions are made against files the production code wrote. Nothing here touches the
    live Task Scheduler, and %ProgramFiles% is redirected by the caller's Invoke-InDeploymentSandbox.

    What a consuming suite owes this file, in this order: $script:RepoRoot; an import of
    src\WindowsAutoCleanup.Deploy.psm1, because the module handle below is taken at dot-source time;
    _DeployFixtures.ps1 for New-TestCheckout and Invoke-InDeploymentSandbox; and the dot-source of
    src\WindowsAutoCleanup.InstallerTask.ps1, whose Undo-Installation binds against these stubs.
#>

$script:DeployModule = Get-Module -Name 'WindowsAutoCleanup.Deploy'

$script:InstallerMessage = New-Object 'System.Collections.Generic.List[string]'
$script:RegisteredTask = New-Object 'System.Collections.Generic.List[object]'
$script:RegisterDrift = 'none'

function Write-InstallerMessage {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'A stub keeps the signature its production caller binds against; not every parameter has to change its answer.')]
    param(
        [Parameter(Mandatory = $true)][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Data,
        [switch]$NoLog,
        [switch]$NoConsole
    )

    [void]$script:InstallerMessage.Add(('{0}: {1}' -f $Level, $Message))
}

function New-StubScheduledTask {
    <#
    .SYNOPSIS
        A stand-in for a registered task, carrying every part the rollback's read-back compares:
        the action, the principal it runs as, the settings that decide whether it runs, and the
        schedule it runs on.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Execute,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Arguments,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$WorkingDirectory,
        [bool]$Hidden = $true,
        [string]$UserId = 'S-1-5-18',
        [string]$StartBoundary = '2026-01-01T03:00:00',
        [bool]$Enabled = $true
    )

    return [PSCustomObject]@{
        TaskName = 'WindowsAutoCleanup'
        TaskPath = '\WindowsAutoCleanup\'
        Description = 'stub'
        Actions = @([PSCustomObject]@{ Execute = $Execute; Arguments = $Arguments; WorkingDirectory = $WorkingDirectory })
        Principal = [PSCustomObject]@{ UserId = $UserId; LogonType = 'ServiceAccount'; RunLevel = 'Highest' }
        Settings = [PSCustomObject]@{ Hidden = $Hidden; Enabled = $Enabled }
        Triggers = @([PSCustomObject]@{ StartBoundary = $StartBoundary; Enabled = $true; DaysInterval = 1 })
    }
}

function Get-WacInstalledTask {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'A stub keeps the signature its production caller binds against; not every parameter has to change its answer.')]
    param([switch]$IncludeLegacy)

    if ($script:RegisteredTask.Count -eq 0) {
        return [PSCustomObject]@{ State = 'Absent'; Task = @(); Failure = @() }
    }
    return [PSCustomObject]@{ State = 'Found'; Task = @($script:RegisteredTask.ToArray()); Failure = @() }
}

function Remove-WacInstalledTask {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'A stub keeps the signature its production caller binds against; not every parameter has to change its answer.')]
    param(
        [Parameter(Mandatory = $true)]$Task,
        [string]$DeploymentRoot,
        [switch]$AllowLegacyMigration,
        [switch]$RequireDefinitionCapture
    )

    $script:RegisteredTask.Clear()
    return [PSCustomObject]@{
        TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\'
        Removed = $true; Verified = $true; Captured = $false; Definition = $null
        CaptureReason = $null; Reason = 'Removed and verified absent.'
    }
}

function Register-ScheduledTask {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'A stub keeps the signature its production caller binds against; not every parameter has to change its answer.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Shadowing the real cmdlet IS the mechanism: the production caller resolves the name in this scope, and the shadow lives and dies with this test script.')]
    param($TaskName, $TaskPath, $Xml, $InputObject, [switch]$Force, $ErrorAction)

    # Registers what the XML actually says, so Restore-CapturedTask's read-back is compared against
    # a task built from the captured definition rather than against a fixture that cannot disagree.
    # Every DRIFT below is one field of that definition changed on the way in - the scheduler
    # normalising something, or a different task landing at the same name - and each is a thing the
    # machine would really have lost.
    $document = New-Object System.Xml.XmlDocument
    $document.LoadXml([string]$Xml)
    $exec = $document.SelectSingleNode("//*[local-name()='Actions']/*[local-name()='Exec']")

    $command = [string]$exec.SelectSingleNode("*[local-name()='Command']").InnerText
    $arguments = [string]$exec.SelectSingleNode("*[local-name()='Arguments']").InnerText
    $working = [string]$exec.SelectSingleNode("*[local-name()='WorkingDirectory']").InnerText

    $userId = 'S-1-5-18'
    $startBoundary = '2026-01-01T03:00:00'
    $enabled = $true
    $user = $document.SelectSingleNode("//*[local-name()='Principals']/*[local-name()='Principal']/*[local-name()='UserId']")
    if ($user) { $userId = [string]$user.InnerText }
    $boundary = $document.SelectSingleNode("//*[local-name()='Triggers']//*[local-name()='StartBoundary']")
    if ($boundary) { $startBoundary = [string]$boundary.InnerText }
    $enabledNode = $document.SelectSingleNode("//*[local-name()='Settings']/*[local-name()='Enabled']")
    if ($enabledNode) { $enabled = [string]::Equals(([string]$enabledNode.InnerText).Trim(), 'true', [System.StringComparison]::OrdinalIgnoreCase) }

    switch ($script:RegisterDrift) {
        'arguments' { $arguments = $arguments + ' -SomethingElse' }
        'user' { $userId = 'MACHINE\mobin' }
        'schedule' { $startBoundary = '2026-01-01T20:00:00' }
        'enabled' { $enabled = $false }
    }

    $script:RegisteredTask.Clear()
    [void]$script:RegisteredTask.Add((New-StubScheduledTask -Execute $command -Arguments $arguments -WorkingDirectory $working `
        -UserId $userId -StartBoundary $startBoundary -Enabled $enabled))
    return [PSCustomObject]@{ TaskName = $TaskName; TaskPath = $TaskPath }
}

function New-CapturedDefinition {
    <#
    .SYNOPSIS
        The shape Remove-WacInstalledTask hands back: the exported XML of the task it removed.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Execute,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    # The UTF-16 declaration is what Export-ScheduledTask really emits; LoadXml accepts it on both
    # hosts (measured), and a fixture that quietly dropped it would not exercise that.
    #
    # The principal and the trigger are here because they are half of what the machine loses when a
    # task is unregistered: a capture carrying only its action could not tell a restored task from
    # the same program running as somebody else, at another hour.
    $xml = '<?xml version="1.0" encoding="UTF-16"?>' +
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' +
        '<RegistrationInfo><Description>the task this run removed</Description></RegistrationInfo>' +
        '<Triggers><CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>' +
        '<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>ServiceAccount</LogonType></Principal></Principals>' +
        '<Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>' +
        ('<Actions Context="Author"><Exec><Command>{0}</Command><Arguments>{1}</Arguments><WorkingDirectory>{2}</WorkingDirectory></Exec></Actions>' -f
            [System.Security.SecurityElement]::Escape($Execute),
            [System.Security.SecurityElement]::Escape($Arguments),
            [System.Security.SecurityElement]::Escape($WorkingDirectory)) +
        '</Task>'

    return [PSCustomObject]@{
        TaskName = 'WindowsAutoCleanup'; TaskPath = '\WindowsAutoCleanup\'
        Captured = $true; Definition = $xml; CaptureReason = 'The definition was captured before the removal.'
    }
}

function Reset-RollbackFixture {
    <#
    .SYNOPSIS
        Clears the journal, the stub scheduler and the module's in-flight transaction, and chooses
        which field the next registration comes back with changed.
    #>
    param([ValidateSet('none', 'arguments', 'user', 'schedule', 'enabled')][string]$Drift = 'none')

    $script:InstallerMessage.Clear()
    $script:RegisteredTask.Clear()
    $script:RegisterDrift = $Drift
    & $script:DeployModule { $script:DeploymentTransaction = $null }
}

function Get-DeploymentTransaction {
    <#
    .SYNOPSIS
        The module's private transaction record. Reached through the module's own scope rather than
        by exporting it: a function is not made public to give a test somewhere to stand.
    #>
    return (& $script:DeployModule { $script:DeploymentTransaction })
}

# Same seam Deploy.Tests.ps1 uses; duplicated rather than moved into the shared fixture file so this
# suite owns the one move it has to make fail.
function Get-ModuleFunctionBody {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return (& $Module { param($n) (Get-Item -Path ('function:' + $n)).ScriptBlock } $Name)
}

function Set-ModuleFunctionBody {
    param(
        [Parameter(Mandatory = $true)]$Module,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    & $Module { param($n, $b) Set-Item -Path ('function:script:' + $n) -Value $b } $Name $Body
}

function Install-FixtureDeployment {
    <#
    .SYNOPSIS
        A complete, committed deployment built the way the installer builds one.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RunContent
    )

    $checkout = New-TestCheckout -Path (Join-Path -Path $Sandbox -ChildPath $Name) -RunContent $RunContent
    return (Install-WacDeployment -SourceRoot $checkout)
}

function New-FixtureStage {
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RunContent
    )

    $checkout = New-TestCheckout -Path (Join-Path -Path $Sandbox -ChildPath $Name) -RunContent $RunContent
    return (New-WacDeploymentStage -SourceRoot $checkout)
}
