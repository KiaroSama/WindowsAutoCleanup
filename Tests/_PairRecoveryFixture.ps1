#Requires -Version 5.1
<#
.SYNOPSIS
    A disposable installer PROCESS that can be stopped at any point of the deployment transaction,
    and resumed by a different process from whatever it left on disk.

.DESCRIPTION
    Dot-sourced by DeploymentPairRecovery.Tests.ps1. It is not a suite: its name does not match
    Tests\*.Tests.ps1, so the runner never executes it alone.

    Ledger WAC-02R needs BOTH halves of the transaction to be real at once. A filesystem-only
    recovery fixture cannot show a capture being retired against the wrong task, and a scheduler-only
    one cannot show the tree going back underneath it - the defect is precisely that the two halves
    were decided separately, so a fixture that holds only one of them proves nothing about the pair.

    What is REAL here: the Deploy module, the deployment slots, both durable records, the swap, the
    recovery plan, the installer's own Resolve-InterruptedTaskCapture, Resolve-ConflictingTask,
    Restore-CapturedTask and the file inventories. What is STUBBED: Core's logging and path helpers
    (the child needs no log), the machine-trust walk (a TEMP sandbox is genuinely user-writable, and
    asserting the CI runner's ACL is what a previous failure in this repo came from), and the Task
    Scheduler, which is backed by a JSON file in the sandbox so registrations survive the death of
    the process that made them, exactly as real ones would.

    The child dies by calling Environment.Exit at a NAMED point in the sequence, so a scenario stops
    where it means to rather than where a timer happens to land, and every resume is a genuinely new
    process reading nothing but the disk.
#>

function Get-PairDriverSource {
    <#
    .SYNOPSIS
        The child's driver script: the installer's real phase sequence, stoppable by name.
    .DESCRIPTION
        The phases are in the order Install-WindowsAutoCleanupTask.ps1 runs them, and each named
        stop point is the instant AFTER the step it names. WAC_PAIR_STOP is the name to stop at;
        anything else runs the sequence to the end.
    #>

    return @'
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repo = $env:WAC_PAIR_REPO
$env:ProgramFiles = $env:WAC_PAIR_PF

Import-Module -Name (Join-Path -Path $repo -ChildPath 'src\WindowsAutoCleanup.Core.psm1') -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $repo -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') -Force -DisableNameChecking -ErrorAction Stop
. (Join-Path -Path $repo -ChildPath 'src\WindowsAutoCleanup.InstallerTask.ps1')
. (Join-Path -Path $repo -ChildPath 'src\WindowsAutoCleanup.InstallerRecovery.ps1')

$module = Get-Module -Name 'WindowsAutoCleanup.Deploy'

function Write-InstallerMessage {
    param([string]$Level, [string]$Message, [hashtable]$Data = @{}, [switch]$NoLog)
    $null = $Data, $NoLog
    [System.IO.File]::AppendAllText($env:WAC_PAIR_JOURNAL, ('{0}|{1}{2}' -f $Level, $Message, [Environment]::NewLine))
}

function Add-PairEvent {
    param([string]$Entry)
    [System.IO.File]::AppendAllText($env:WAC_PAIR_JOURNAL, ('EVENT|' + $Entry + [Environment]::NewLine))
}

function Get-PairScheduler {
    if (-not (Test-Path -LiteralPath $env:WAC_PAIR_TASKS -PathType Leaf)) { return @() }
    $text = [System.IO.File]::ReadAllText($env:WAC_PAIR_TASKS)
    if ([string]::IsNullOrWhiteSpace($text)) { return @() }
    # The Where-Object is not decoration. Measured: Windows PowerShell 5.1 turns an empty JSON array
    # into $null, so @(ConvertFrom-Json '[]') is an array of ONE null element there while pwsh gives
    # an empty one - and under Set-StrictMode reading a property off that null is terminating.
    return @(@(ConvertFrom-Json -InputObject $text) | Where-Object { $_ })
}

function Set-PairScheduler {
    param([AllowEmptyCollection()][object[]]$Task)
    [System.IO.File]::WriteAllText($env:WAC_PAIR_TASKS, (ConvertTo-Json -InputObject @($Task) -Depth 12))
}

# The scheduler, inside the module's scope where Remove-WacInstalledTask resolves it.
#
# The store keeps only {TaskName, TaskPath, Xml}, and the task object is MATERIALISED on read.
# Storing the object instead round-tripped its StartBoundary through ConvertTo-Json: PowerShell's
# ConvertFrom-Json parses an ISO 8601 string back as a [datetime], so '2026-01-01T03:00:00' came
# out as '01/01/2026 03:00:00' and every read-back compared unequal to the capture it came from.
& $module {
    param($tasksPath)
    $script:PairTasks = $tasksPath

    function script:Get-PairStore {
        if (-not (Test-Path -LiteralPath $script:PairTasks -PathType Leaf)) { return @() }
        $text = [System.IO.File]::ReadAllText($script:PairTasks)
        if ([string]::IsNullOrWhiteSpace($text)) { return @() }
        # See Get-PairScheduler: 5.1 reads an empty JSON array as one null element.
        return @(@(ConvertFrom-Json -InputObject $text) | Where-Object { $_ })
    }

    function script:ConvertTo-PairTaskObject {
        # The XML a scenario registers, read back in the shape Get-ScheduledTask hands out. Only what
        # the comparison reads is materialised; every one of those is read through local-name() XPath,
        # so the exported namespace is irrelevant here as it is in the shipped code.
        param([string]$Xml, [string]$TaskName, [string]$TaskPath)

        $document = New-Object System.Xml.XmlDocument
        $document.LoadXml($Xml)
        $exec = $document.SelectSingleNode("//*[local-name()='Actions']/*[local-name()='Exec']")
        $trigger = $document.SelectSingleNode("//*[local-name()='Triggers']/*")

        $read = {
            param($node, $path)
            if (-not $node) { return '' }
            $child = $node.SelectSingleNode($path)
            if (-not $child) { return '' }
            return ([string]$child.InnerText).Trim()
        }

        $task = [PSCustomObject]@{
            TaskName = $TaskName
            TaskPath = $TaskPath
            Description = (& $read $document "//*[local-name()='RegistrationInfo']/*[local-name()='Description']")
            Xml = $Xml
            Actions = @([PSCustomObject]@{
                Execute = (& $read $exec "*[local-name()='Command']")
                Arguments = (& $read $exec "*[local-name()='Arguments']")
                WorkingDirectory = (& $read $exec "*[local-name()='WorkingDirectory']")
            })
            Principal = [PSCustomObject]@{
                UserId = (& $read $document "//*[local-name()='Principals']/*[local-name()='Principal']/*[local-name()='UserId']")
                LogonType = (& $read $document "//*[local-name()='Principals']/*[local-name()='Principal']/*[local-name()='LogonType']")
                RunLevel = (& $read $document "//*[local-name()='Principals']/*[local-name()='Principal']/*[local-name()='RunLevel']")
            }
            Settings = [PSCustomObject]@{
                Enabled = (& $read $document "//*[local-name()='Settings']/*[local-name()='Enabled']")
                Hidden = (& $read $document "//*[local-name()='Settings']/*[local-name()='Hidden']")
            }
            Triggers = @()
        }
        if ($trigger) {
            $task.Triggers = @([PSCustomObject]@{
                StartBoundary = (& $read $trigger "*[local-name()='StartBoundary']")
                Enabled = (& $read $trigger "*[local-name()='Enabled']")
                DaysInterval = (& $read $trigger "*[local-name()='ScheduleByDay']/*[local-name()='DaysInterval']")
            })
        }
        return $task
    }

    function script:Get-PairState {
        return @(@(Get-PairStore) | ForEach-Object {
            ConvertTo-PairTaskObject -Xml ([string]$_.Xml) -TaskName ([string]$_.TaskName) -TaskPath ([string]$_.TaskPath)
        })
    }

    function script:Get-ScheduledTask {
        param([string]$TaskName, [string]$TaskPath, [string]$ErrorAction)
        $null = $ErrorAction
        return @(@(Get-PairState) | Where-Object {
            [string]::Equals([string]$_.TaskName, $TaskName, [System.StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$_.TaskPath, $TaskPath, [System.StringComparison]::OrdinalIgnoreCase)
        })
    }

    function script:Export-ScheduledTask {
        param([string]$TaskName, [string]$TaskPath, [string]$ErrorAction)
        $null = $ErrorAction
        $found = @(@(Get-PairStore) | Where-Object {
            [string]::Equals([string]$_.TaskName, $TaskName, [System.StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$_.TaskPath, $TaskPath, [System.StringComparison]::OrdinalIgnoreCase)
        })
        if ($found.Count -eq 0) { return '' }
        return [string]$found[0].Xml
    }

    function script:Unregister-ScheduledTask {
        param([string]$TaskName, [string]$TaskPath, $Confirm, [string]$ErrorAction)
        $null = $Confirm, $ErrorAction
        $kept = @(@(Get-PairStore) | Where-Object {
            -not ([string]::Equals([string]$_.TaskName, $TaskName, [System.StringComparison]::OrdinalIgnoreCase) -and
                  [string]::Equals([string]$_.TaskPath, $TaskPath, [System.StringComparison]::OrdinalIgnoreCase))
        })
        [System.IO.File]::WriteAllText($script:PairTasks, (ConvertTo-Json -InputObject @($kept) -Depth 12))
    }

    # A TEMP sandbox is genuinely user-writable, so the real walk refuses it - correctly, and for a
    # reason that has nothing to do with what these scenarios are about. The walk itself is measured
    # against real injected roots in DeploymentProof.Tests.ps1.
    function script:Test-WacDeploymentTrusted {
        param([string]$DeploymentRoot)
        return ([PSCustomObject]@{ Root = $DeploymentRoot; DeploymentRoot = $DeploymentRoot; IsTrusted = $true
            Reason = 'sandbox trust forced for this fixture'; CheckedCount = 0; Findings = @(); Untrusted = @() })
    }
} $env:WAC_PAIR_TASKS

# Register-ScheduledTask is resolved in THIS scope by Restore-CapturedTask, so a function here beats
# the cmdlet. It records the XML, so a case can assert what went back byte for byte.
function Register-ScheduledTask {
    param($TaskName, $TaskPath, $InputObject, $Xml, [switch]$Force, $ErrorAction)
    $null = $InputObject, $Force, $ErrorAction

    Add-PairEvent ('register|' + $TaskName + '|' + $TaskPath)
    if ($env:WAC_PAIR_REGISTER -eq 'throw') { throw 'the scheduler refused the registration' }

    $kept = @(@(Get-PairScheduler) | Where-Object {
        -not ([string]::Equals([string]$_.TaskName, $TaskName, [System.StringComparison]::OrdinalIgnoreCase) -and
              [string]::Equals([string]$_.TaskPath, $TaskPath, [System.StringComparison]::OrdinalIgnoreCase))
    })
    Set-PairScheduler -Task @($kept + @([PSCustomObject]@{ TaskName = $TaskName; TaskPath = $TaskPath; Xml = [string]$Xml }))
    return ([PSCustomObject]@{ TaskName = $TaskName; TaskPath = $TaskPath })
}

function Stop-AtPoint {
    <#
    .SYNOPSIS
        The death of the process, at a named instant. Environment.Exit, not throw: a scenario about
        an interrupted run must not give the run a chance to unwind.
    #>
    param([string]$Name)

    Add-PairEvent ('reached|' + $Name)
    if ([string]::Equals($env:WAC_PAIR_STOP, $Name, [System.StringComparison]::Ordinal)) {
        Add-PairEvent ('stopped|' + $Name)
        [System.Environment]::Exit(70)
    }
}

# --------------------------------------------------------------------------------------------
# The installer's own phase sequence
# --------------------------------------------------------------------------------------------

$slots = Get-WacDeploymentSlotPath
$source = $env:WAC_PAIR_SOURCE

$plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
Add-PairEvent ('plan|' + [string]$plan.Verdict + '|linked=' + [bool]$plan.Linked)
Stop-AtPoint -Name 'after-plan'

if ([string]$plan.Verdict -eq 'Refuse') {
    Write-InstallerMessage -Level ERROR -Message ('Refusing to install: ' + [string]$plan.Reason)
    exit 1
}

$discovery = Get-WacInstalledTask -IncludeLegacy
$reconciled = Resolve-InterruptedTaskCapture -DeploymentRoot $slots.Root -Lookup $discovery -Plan $plan
Add-PairEvent ('reconcile|ok=' + [bool]$reconciled.Ok + '|restored=' + [int]$reconciled.Restored + '|accounted=' + [int]$reconciled.Accounted)
if (-not $reconciled.Ok) {
    Write-InstallerMessage -Level ERROR -Message ('Refusing to install: ' + [string]$reconciled.Reason)
    exit 1
}
Stop-AtPoint -Name 'after-reconcile'

# The FILE half, back to back with the task half and ahead of everything about the new install -
# the installer's own order since ledger WAC-02R. It used to live inside New-WacDeploymentStage,
# behind that function's source validation and behind the host and budget checks in front of it, so
# a run that restored the task half and then failed one of those returned leaving task A over
# files B.
$recovered = Resolve-WacDeploymentRecoverySlot -Slots $slots
Add-PairEvent ('recover|' + [string]$recovered.Action)
Stop-AtPoint -Name 'after-recover'

[void](New-WacDeploymentStage -SourceRoot $source)
Add-PairEvent 'staged'
Stop-AtPoint -Name 'after-stage'

$conflict = Resolve-ConflictingTask -DeploymentRoot $slots.Root
Add-PairEvent ('conflict|ok=' + [bool]$conflict.Ok + '|captured=' + @($conflict.Captured).Count)
Stop-AtPoint -Name 'after-capture'
if (-not $conflict.Ok) {
    Write-InstallerMessage -Level ERROR -Message ([string]$conflict.Reason)
    [void](Remove-WacDeployment -Path $slots.Staging)
    [void](Complete-TaskCaptureTransaction -DeploymentRoot $slots.Root -CapturedTask @($conflict.Captured))
    exit 7
}
Stop-AtPoint -Name 'after-unregister'

try {
    [void](Switch-WacDeploymentStage -KeepPrevious)
    Add-PairEvent 'switched'
    Stop-AtPoint -Name 'after-swap'

    $registered = Register-ScheduledTask -TaskName (Get-WacTaskName) -TaskPath (Get-WacTaskFolder) -Xml $env:WAC_PAIR_NEWXML -Force
    $null = $registered
    Add-PairEvent 'registered'
    Stop-AtPoint -Name 'after-register'

    $lookup = Get-WacInstalledTask
    if ($lookup.State -ne 'Found') { throw 'the task was registered but the scheduler does not report it registered' }
    Add-PairEvent 'read-back'
    Stop-AtPoint -Name 'after-readback'
}
catch {
    Write-InstallerMessage -Level ERROR -Message ('The installation could not be completed: ' + $_.Exception.Message)
    if (Undo-Installation -DeploymentRoot $slots.Root -CapturedTask @($conflict.Captured)) {
        [void](Remove-WacTaskCaptureRecord -DeploymentRoot $slots.Root)
        Write-InstallerMessage -Level ERROR -Message 'Final status: failed and rolled back.'
    }
    else {
        Write-InstallerMessage -Level CRITICAL -Message 'Final status: failed and the rollback is INCOMPLETE.'
    }
    exit 1
}

# The decision first, while the recovery copy is still there to roll back to, and neither half
# retired until it is on disk.
$decision = Set-WacDeploymentCommitted -Task @($lookup.Task)
Add-PairEvent ('decision|' + [bool]$decision.Recorded)
Stop-AtPoint -Name 'after-decision'

$committed = $false
$captureEnded = $false
if ([bool]$decision.Recorded) {
    $committed = [bool](Remove-WacDeploymentPrevious)
    Add-PairEvent ('committed|' + $committed)
    Stop-AtPoint -Name 'after-commit'

    $captureEnded = [bool](Remove-WacTaskCaptureRecord -DeploymentRoot $slots.Root)
    Add-PairEvent ('capture-ended|' + $captureEnded)
}
Stop-AtPoint -Name 'after-evidence'

if (-not $committed -or -not $captureEnded) {
    Write-InstallerMessage -Level ERROR -Message 'Final status: incomplete.'
    exit 6
}

Write-InstallerMessage -Level INFO -Message 'Final status: success'
exit 0
'@
}

function New-PairTaskXml {
    <#
    .SYNOPSIS
        A task definition in the shape Export-ScheduledTask emits, for one deployment root and one
        argument string. Two calls that differ only in Arguments are two DIFFERENT tasks that no
        name comparison can tell apart, which is the whole subject of this fixture.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$Arguments,
        [string]$Description,
        [string]$StartBoundary = '2026-01-01T03:00:00'
    )

    # Through the module's OWN generators, never hand-rolled. Test-WacTaskIsOurs compares the
    # argument string ordinally against the eight strings Get-WacTaskActionArgument can produce for
    # that script path, and requires the fixed sentinel inside the description - so a fixture that
    # spelled either itself would register a task the shipped code correctly refuses to recognise,
    # and every scenario would fail for a reason that has nothing to do with what it is about.
    if (-not $Arguments) {
        $Arguments = Get-WacTaskActionArgument -RunScript (Join-Path -Path $Root -ChildPath 'Run.ps1')
    }
    if (-not $Description) { $Description = Get-WacTaskDescription }

    return ('<?xml version="1.0" encoding="UTF-16"?>' +
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' +
        ('<RegistrationInfo><Description>{0}</Description></RegistrationInfo>' -f [System.Security.SecurityElement]::Escape($Description)) +
        ('<Triggers><CalendarTrigger><StartBoundary>{0}</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>' -f $StartBoundary) +
        '<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>ServiceAccount</LogonType></Principal></Principals>' +
        '<Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>' +
        ('<Actions Context="Author"><Exec><Command>{0}</Command><Arguments>{1}</Arguments><WorkingDirectory>{2}</WorkingDirectory></Exec></Actions>' -f
            [System.Security.SecurityElement]::Escape((Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe')),
            [System.Security.SecurityElement]::Escape($Arguments),
            [System.Security.SecurityElement]::Escape($Root)) +
        '</Task>')
}

function New-PairSandbox {
    <#
    .SYNOPSIS
        A redirected %ProgramFiles%, the driver script and an empty scheduler.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $programFiles = Join-Path -Path $Sandbox -ChildPath 'PF'
    [void][System.IO.Directory]::CreateDirectory($programFiles)
    [System.IO.File]::WriteAllText((Join-Path -Path $Sandbox -ChildPath 'tasks.json'), '[]')
    [System.IO.File]::WriteAllText((Join-Path -Path $Sandbox -ChildPath 'driver.ps1'), (Get-PairDriverSource),
        (New-Object System.Text.UTF8Encoding($false)))

    return ([PSCustomObject]@{
        ProgramFiles = $programFiles
        Root = (Join-Path -Path $programFiles -ChildPath 'WindowsAutoCleanup')
        Previous = (Join-Path -Path $programFiles -ChildPath 'WindowsAutoCleanup.previous')
        Staging = (Join-Path -Path $programFiles -ChildPath 'WindowsAutoCleanup.staging')
        SwapRecord = (Join-Path -Path $programFiles -ChildPath 'WindowsAutoCleanup.transaction.json')
        CaptureRecord = (Join-Path -Path $programFiles -ChildPath 'WindowsAutoCleanup.taskcapture.json')
        Tasks = (Join-Path -Path $Sandbox -ChildPath 'tasks.json')
        Driver = (Join-Path -Path $Sandbox -ChildPath 'driver.ps1')
    })
}

function Invoke-PairRun {
    <#
    .SYNOPSIS
        One bounded child process running the real phase sequence, optionally stopping dead at a
        named point.
    .OUTPUTS
        ExitCode, Journal (the lines in order), JournalText (whitespace-normalised), TimedOut.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Sandbox,
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)][string]$Source,
        [string]$Stop = '',
        [string]$NewArguments = '',
        [ValidateSet('ok', 'throw')][string]$Register = 'ok',
        [ValidateRange(10, 300)][int]$TimeoutSeconds = 120
    )

    $journal = Join-Path -Path $Sandbox -ChildPath 'journal.txt'
    [System.IO.File]::WriteAllText($journal, '')

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Join-Path -Path $PSHOME -ChildPath $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }))
    $psi.Arguments = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $Fixture.Driver)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $script:RepoRoot
    $psi.EnvironmentVariables['WAC_PAIR_REPO'] = $script:RepoRoot
    $psi.EnvironmentVariables['WAC_PAIR_PF'] = $Fixture.ProgramFiles
    $psi.EnvironmentVariables['WAC_PAIR_JOURNAL'] = $journal
    $psi.EnvironmentVariables['WAC_PAIR_TASKS'] = $Fixture.Tasks
    $psi.EnvironmentVariables['WAC_PAIR_SOURCE'] = $Source
    $psi.EnvironmentVariables['WAC_PAIR_STOP'] = $Stop
    $psi.EnvironmentVariables['WAC_PAIR_REGISTER'] = $Register
    $psi.EnvironmentVariables['WAC_PAIR_NEWXML'] = (New-PairTaskXml -Root $Fixture.Root -Arguments $NewArguments)

    $child = [System.Diagnostics.Process]::Start($psi)
    $exited = $false
    $code = $null
    try {
        $exited = $child.WaitForExit([int]($TimeoutSeconds * 1000))
        if (-not $exited) {
            [void](Stop-WacProcessTree -ProcessId $child.Id)
            [void]$child.WaitForExit(10000)
        }
        else { $code = [int]$child.ExitCode }
    }
    finally {
        try { $child.Dispose() } catch { $null = $_ }
    }

    $lines = @()
    if (Test-Path -LiteralPath $journal -PathType Leaf) {
        $lines = @(@([System.IO.File]::ReadAllLines($journal)) | Where-Object { $_.Trim() })
    }

    return ([PSCustomObject]@{
        ExitCode = $code
        Journal = $lines
        # Whitespace-normalised, because a phrase that reads as one line here can arrive wrapped:
        # measured in CI, Windows PowerShell 5.1 breaks a long message mid-phrase and a text
        # assertion against the laid-out form then fails on the runner and passes locally.
        JournalText = (($lines -join ' ') -replace '\s+', ' ')
        TimedOut = (-not $exited)
    })
}

function Test-PairJournalHas {
    param(
        [Parameter(Mandatory = $true)]$Run,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    return (@(@($Run.Journal) | Where-Object { $_ -match $Pattern }).Count -gt 0)
}

function Get-PairTask {
    <#
    .SYNOPSIS
        What the scheduler holds, read as the fixture's own JSON rather than through the code under
        test.
    #>
    param([Parameter(Mandatory = $true)]$Fixture)

    $text = [System.IO.File]::ReadAllText($Fixture.Tasks)
    if ([string]::IsNullOrWhiteSpace($text)) { return @() }
    # See the driver's own reader: 5.1 reads an empty JSON array as one null element.
    return @(@(ConvertFrom-Json -InputObject $text) | Where-Object { $_ })
}

function Get-PairInventory {
    <#
    .SYNOPSIS
        The file inventory of a slot - relative path and content hash, sorted - computed HERE rather
        than by the code under test, so a case compares files independently of task semantics.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return '<absent>' }

    $prefix = $Path.TrimEnd('\') + '\'
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        # The manifest records the moment it was written, so two deployments of the same checkout
        # never share one. It is excluded here precisely so a case can ask whether the FILES are the
        # same build without that timestamp answering for them.
        if ([string]::Equals($file.Name, 'wac-deployment.json', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $relative = $file.FullName
        if ($relative.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relative = $relative.Substring($prefix.Length)
        }
        [void]$lines.Add(('{0}|{1}' -f $relative.ToUpperInvariant(), (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash))
    }
    if ($lines.Count -eq 0) { return '<empty>' }

    $ordered = [string[]]$lines.ToArray()
    [array]::Sort($ordered, [System.StringComparer]::Ordinal)
    return ($ordered -join '; ')
}

function Get-PairTaskSemantics {
    <#
    .SYNOPSIS
        The full semantics of one stored registration as one comparable string, parsed HERE from the
        XML the scheduler holds.
    .DESCRIPTION
        Independent of the code under test on purpose: the defect was a pair whose two halves came
        from different generations and each looked perfectly consistent on its own, so a case that
        asked Test-WacCapturedTaskDefinition whether the task matched would have been asking the
        very comparison under test. This reads the stored definition directly, and a case reads the
        file inventory separately, so the pair is checked by two independent measurements.
    #>
    param([AllowNull()]$Task)

    if (-not $Task -or [string]::IsNullOrWhiteSpace([string]$Task.Xml)) { return '<none>' }

    $document = New-Object System.Xml.XmlDocument
    $document.LoadXml([string]$Task.Xml)
    $text = {
        param($path)
        $node = $document.SelectSingleNode($path)
        if (-not $node) { return '' }
        return ([string]$node.InnerText).Trim()
    }

    return (@(
        'name=' + [string]$Task.TaskName
        'path=' + [string]$Task.TaskPath
        'description=' + (& $text "//*[local-name()='RegistrationInfo']/*[local-name()='Description']")
        'execute=' + (& $text "//*[local-name()='Actions']/*[local-name()='Exec']/*[local-name()='Command']")
        'arguments=' + (& $text "//*[local-name()='Actions']/*[local-name()='Exec']/*[local-name()='Arguments']")
        'workingDirectory=' + (& $text "//*[local-name()='Actions']/*[local-name()='Exec']/*[local-name()='WorkingDirectory']")
        'userId=' + (& $text "//*[local-name()='Principals']/*[local-name()='Principal']/*[local-name()='UserId']")
        'runLevel=' + (& $text "//*[local-name()='Principals']/*[local-name()='Principal']/*[local-name()='RunLevel']")
        'logonType=' + (& $text "//*[local-name()='Principals']/*[local-name()='Principal']/*[local-name()='LogonType']")
        'enabled=' + (& $text "//*[local-name()='Settings']/*[local-name()='Enabled']")
        'hidden=' + (& $text "//*[local-name()='Settings']/*[local-name()='Hidden']")
        'triggers=' + @($document.SelectNodes("//*[local-name()='Triggers']/*")).Count
        'startBoundary=' + (& $text "//*[local-name()='Triggers']/*/*[local-name()='StartBoundary']")
        'daysInterval=' + (& $text "//*[local-name()='Triggers']/*/*[local-name()='ScheduleByDay']/*[local-name()='DaysInterval']")
    ) -join ';')
}
