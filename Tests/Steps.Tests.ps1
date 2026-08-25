#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the WindowsAutoCleanup.Steps entry point: the shared outcome contract, the
    DISM argument vector and exit-code mapping (invariant P0-2), and the C-only Delivery
    Optimization boundary (brief B2-1).

.DESCRIPTION
    No external tool is ever executed. Every step runs against Core's injected process invoker, which
    records the file path, argument vector and timeout it was handed and returns a canned result; the
    invoker is removed again in a finally block, and Test-WacIsAdministrator is only forced to $true
    while that invoker is installed, so a stray call outside a fixture can only ever be skipped.

    The in-process bounded work runs through the module's own bounded seam, installed the same way.
    That seam is what keeps the Delivery Optimization cases safe: Invoke-WacBounded runs its block as
    TEXT in a fresh runspace with a fresh import of the module, where a stub is invisible, so a test
    that let it do that would purge this machine's real cache. Through the seam the block keeps the
    module's session state, so the Get-Command shadow below is the only thing it can ever resolve.

    The Recycle Bin sweep is covered by RecycleBin.Tests.ps1 and the legacy cleanmgr step by
    DiskCleanup.Tests.ps1; the stubs all three share live in _StepHarness.ps1.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_StepHarness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
# The package entry point last, so its own non-forced imports bind to the instances forced here and
# a shadow installed in one of them is the one the code under test sees.
foreach ($moduleLeaf in @('Core', 'FileSystem', 'StepContract', 'RecycleBin', 'DiskCleanup', 'Steps')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

$script:StepModule = Get-Module -Name 'WindowsAutoCleanup.Steps'

function Invoke-WithStubbedDeliveryOptimization {
    <#
    .SYNOPSIS
        Runs a body with command discovery inside the module redirected to stubs, and the bounded
        seam installed.
    .DESCRIPTION
        Neither real Delivery Optimization cmdlet may ever run from a test, so Get-Command itself is
        shadowed inside the module for the duration: it can only ever hand back a stub, or nothing.
        The bounded blocks re-resolve the command by NAME, which is why shadowing discovery is
        sufficient to contain them. Every shadow is removed again afterwards.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [ValidateSet('Present', 'Absent', 'Failing')][string]$Mode = 'Present',
        [ValidateSet('Present', 'Absent', 'Empty', 'Failing')][string]$ConfigMode = 'Present',
        [string]$WorkingDirectory = 'C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache'
    )

    # The stubs assert their own inputs: the step has to purge with -Force, and must never ask for
    # pinned files to be deleted as well.
    $purgeMode = $Mode
    $purgeStub = {
        [CmdletBinding()] param([switch]$Force, [switch]$IncludePinnedFiles)
        if (-not $Force) { throw 'the cache purge was invoked without -Force' }
        if ($IncludePinnedFiles) { throw 'pinned Delivery Optimization files must never be purged' }
        $env:WAC_TEST_DO_CALLS = [string](1 + [int]$env:WAC_TEST_DO_CALLS)
        if ($purgeMode -eq 'Failing') { throw 'stubbed cache purge failed' }
    }.GetNewClosure()

    $configStubMode = $ConfigMode
    $configWorkingDirectory = $WorkingDirectory
    $configStub = {
        [CmdletBinding()] param()
        $env:WAC_TEST_DO_CONFIG_CALLS = [string](1 + [int]$env:WAC_TEST_DO_CONFIG_CALLS)
        if ($configStubMode -eq 'Failing') { throw 'stubbed Get-DOConfig failed' }
        if ($configStubMode -eq 'Empty') { return [PSCustomObject]@{ DownloadMode = 1 } }
        return [PSCustomObject]@{ DownloadMode = 1; WorkingDirectory = $configWorkingDirectory }
    }.GetNewClosure()

    if ($Mode -ne 'Absent') {
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Delete-DeliveryOptimizationCache' -Body $purgeStub
    }
    if ($ConfigMode -ne 'Absent') {
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Get-DOConfig' -Body $configStub
    }

    # Discovery hands back the stubs themselves through a closure, and $null for 'Absent'. Resolving
    # a name inside a stub would run in THIS suite's session state, not the module's, and silently
    # find nothing - which is why the real cmdlets can never be reached from here either.
    $deleteAvailable = ($Mode -ne 'Absent')
    $configAvailable = ($ConfigMode -ne 'Absent')
    $discovery = {
        param([Parameter(Position = 0)][string]$Name)
        if ($Name -eq 'Delete-DeliveryOptimizationCache' -and $deleteAvailable) { return $purgeStub }
        if ($Name -eq 'Get-DOConfig' -and $configAvailable) { return $configStub }
        return $null
    }.GetNewClosure()

    Set-ModuleFunctionBody -Module $script:StepModule -Name 'Get-Command' -Body $discovery

    $script:BoundedCall.Clear()
    $script:BoundedForce = @{}
    Set-WacStepBoundedInvoker -Invoker $script:RecordingBounded

    $env:WAC_TEST_DO_CALLS = '0'
    $env:WAC_TEST_DO_CONFIG_CALLS = '0'
    try {
        & $Body
    }
    finally {
        Set-WacStepBoundedInvoker -Invoker $null
        $script:BoundedForce = @{}
        Remove-ModuleFunction -Module $script:StepModule -Name 'Get-Command'
        Remove-ModuleFunction -Module $script:StepModule -Name 'Delete-DeliveryOptimizationCache'
        Remove-ModuleFunction -Module $script:StepModule -Name 'Get-DOConfig'
        Remove-Item -LiteralPath 'Env:WAC_TEST_DO_CALLS' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Env:WAC_TEST_DO_CONFIG_CALLS' -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------------------------
# The shared outcome contract
# ---------------------------------------------------------------------------------------------

Test-Case 'every outcome derives exactly one set of booleans' {
    $expected = @(
        @{ Outcome = 'Succeeded';       Succeeded = $true;  Skipped = $false; Failed = $false }
        @{ Outcome = 'SafeSkip';        Succeeded = $false; Skipped = $true;  Failed = $false }
        @{ Outcome = 'Incomplete';      Succeeded = $false; Skipped = $false; Failed = $true }
        @{ Outcome = 'SecurityRefusal'; Succeeded = $false; Skipped = $false; Failed = $true }
        @{ Outcome = 'Failed';          Succeeded = $false; Skipped = $false; Failed = $true }
    )

    foreach ($case in $expected) {
        $result = New-WacStepResult -Category 'c' -Outcome $case.Outcome
        Assert-Equal $case.Outcome $result.Outcome
        Assert-Equal $case.Succeeded $result.Succeeded ('Succeeded is wrong for {0}' -f $case.Outcome)
        Assert-Equal $case.Skipped $result.Skipped ('Skipped is wrong for {0}' -f $case.Outcome)
        Assert-Equal $case.Failed $result.Failed ('Failed is wrong for {0}' -f $case.Outcome)
    }
}

Test-Case 'an outcome overrides whatever booleans a caller also passed' {
    # A caller that passes both must not be able to produce a result the outcome cannot express.
    $result = New-WacStepResult -Category 'c' -Outcome 'SafeSkip' -Succeeded $true -Failed $true

    Assert-Equal 'SafeSkip' $result.Outcome
    Assert-True $result.Skipped
    Assert-False $result.Succeeded 'a stale Succeeded survived the outcome'
    Assert-False $result.Failed 'a stale Failed survived the outcome'
}

Test-Case 'a boolean-only caller keeps its own values and is labelled with an outcome' {
    $failed = New-WacStepResult -Category 'c' -Failed $true -Attempted $true
    Assert-Equal 'Failed' $failed.Outcome
    Assert-True $failed.Failed

    $skipped = New-WacStepResult -Category 'c' -Skipped $true
    Assert-Equal 'SafeSkip' $skipped.Outcome

    $succeeded = New-WacStepResult -Category 'c' -Succeeded $true
    Assert-Equal 'Succeeded' $succeeded.Outcome

    # Nothing set at all is benign, never a run-failing outcome invented out of nowhere.
    $nothing = New-WacStepResult -Category 'c'
    Assert-Equal 'SafeSkip' $nothing.Outcome
    Assert-False $nothing.Failed
}

Test-Case 'an unknown outcome name is rejected rather than silently accepted' {
    Assert-Throws -ScriptBlock { New-WacStepResult -Category 'c' -Outcome 'Fine' } -Pattern 'ValidateSet|argument'
}

# ---------------------------------------------------------------------------------------------
# DISM: the argument vector is the invariant (P0-2)
# ---------------------------------------------------------------------------------------------

Test-Case 'DISM runs exactly one process with the documented argument vector and no /ResetBase' {
    Invoke-WithStubbedTool -Body {
        $result = Invoke-WacComponentCleanup

        Assert-Equal 1 $script:StubCall.Count 'the component store step must run exactly one process'
        Assert-Equal (Join-Path -Path $script:System32 -ChildPath 'dism.exe') $script:StubCall[0].FilePath

        $argv = @($script:StubCall[0].Arguments)
        Assert-Equal 4 $argv.Count ('vector: {0}' -f ($argv -join ' '))
        Assert-Equal '/Online' $argv[0]
        Assert-Equal '/Cleanup-Image' $argv[1]
        Assert-Equal '/StartComponentCleanup' $argv[2]
        Assert-Equal '/Quiet' $argv[3]
        Assert-False ($argv -ccontains '/ResetBase') 'DISM must never receive /ResetBase by default'
        Assert-True $result.Attempted
    }
}

Test-Case 'DISM with -ResetBase:$false is byte-identical to the default vector' {
    Invoke-WithStubbedTool -Body {
        [void](Invoke-WacComponentCleanup -ResetBase:$false)

        Assert-Equal 1 $script:StubCall.Count
        $argv = @($script:StubCall[0].Arguments)
        Assert-Equal '/Online /Cleanup-Image /StartComponentCleanup /Quiet' ($argv -join ' ')
        Assert-False ($argv -ccontains '/ResetBase') '-ResetBase:$false still reached DISM'
    }
}

Test-Case 'DISM adds /ResetBase only when it is explicitly requested' {
    Invoke-WithStubbedTool -Body {
        [void](Invoke-WacComponentCleanup -ResetBase)

        $argv = @($script:StubCall[0].Arguments)
        Assert-Equal 5 $argv.Count ('vector: {0}' -f ($argv -join ' '))
        Assert-Equal '/Online /Cleanup-Image /StartComponentCleanup /ResetBase /Quiet' ($argv -join ' ')
    }
}

Test-Case 'DISM exit 0 is success with no reboot flag' {
    Invoke-WithStubbedTool -Body {
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Succeeded' $result.Outcome
        Assert-True $result.Succeeded
        Assert-False $result.RebootRequired
        Assert-False $result.Failed
        Assert-False $result.Skipped
        Assert-True $result.Attempted
    }
}

Test-Case 'DISM exit 3010 is success plus RebootRequired' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = 3010 }
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Succeeded' $result.Outcome
        Assert-True $result.RebootRequired
        Assert-False $result.Failed
    }
}

Test-Case 'DISM exit 3017 is a failure and is never folded into success' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = 3017 }
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Failed' $result.Outcome
        Assert-False $result.Succeeded
        Assert-True $result.Failed
        Assert-False $result.RebootRequired
        Assert-True $result.Attempted
    }
}

Test-Case 'a DISM timeout is incomplete, never a skip, and is bounded by the step ceiling' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = $null; TimedOut = $true }
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Incomplete' $result.Outcome
        Assert-False $result.Succeeded
        Assert-False $result.Skipped 'a killed DISM must not be reported as a benign skip'
        Assert-True $result.Failed 'an incomplete step must still reach the run footer'
        Assert-True ($script:StubCall[0].TimeoutMs -gt 0)
        Assert-True ($script:StubCall[0].TimeoutMs -le (1000 * 60 * 120)) ('timeout was {0} ms' -f $script:StubCall[0].TimeoutMs)
    }
}

Test-Case 'a DISM that never started is a failure, not a skip' {
    Invoke-WithStubbedTool -Body {
        $script:StubResult['/Online'] = @{ ExitCode = $null }
        $result = Invoke-WacComponentCleanup

        Assert-Equal 'Failed' $result.Outcome
        Assert-True $result.Failed
        Assert-False $result.Succeeded
        Assert-False $result.Skipped
    }
}

# ---------------------------------------------------------------------------------------------
# Delivery Optimization: the C-only boundary (brief B2-1)
# ---------------------------------------------------------------------------------------------

Test-Case 'Delivery Optimization resolves the cache location before it purges anything' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal '1' $env:WAC_TEST_DO_CONFIG_CALLS 'the effective cache location was not resolved exactly once'
        Assert-Equal '1' $env:WAC_TEST_DO_CALLS 'the cmdlet path was not taken exactly once'
        Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        Assert-True $result.Succeeded $result.Detail
        Assert-True $result.Attempted
        Assert-False $result.Skipped
        Assert-False $result.Failed

        # Both in-process cmdlets ran under a bound, and neither of them ignores the run budget.
        Assert-Equal 2 $script:BoundedCall.Count 'the config read and the purge must both be bounded'
        foreach ($call in $script:BoundedCall) {
            Assert-Equal 'DeliveryOptimization' $call.Component
            Assert-True ($call.TimeoutMs -gt 0) 'a bounded Delivery Optimization call was given no time at all'
            Assert-False $call.IgnoreRunBudget
        }
    }
}

Test-Case 'a Delivery Optimization cache on another drive is a SafeSkip that names the drive' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -WorkingDirectory 'D:\DOCache' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-True $result.Skipped
        Assert-False $result.Failed 'a relocated cache is an expected steady state, not a failure'
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'an off-drive cache was purged anyway'
        Assert-True ($result.Detail -match 'drive D:') $result.Detail
        Assert-True ($result.Detail -match 'D:\\DOCache') $result.Detail

        # Twice over the same configuration stays exactly as benign.
        $second = Clear-WacDeliveryOptimizationCache
        Assert-Equal 'SafeSkip' $second.Outcome $second.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the second run purged an off-drive cache'
    }
}

Test-Case 'a cache location given as an environment variable is expanded before it is judged' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -WorkingDirectory '%SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\DO' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        # DOModifyCacheDrive accepts environment variables, a drive letter or a full path, so an
        # unexpanded string must not be compared against the drive as-is.
        Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        Assert-Equal '1' $env:WAC_TEST_DO_CALLS
        Assert-True ($result.Detail -match 'ServiceProfiles') $result.Detail
        Assert-False ($result.Detail -match '%SystemRoot%') ('the path was never expanded: {0}' -f $result.Detail)
    }
}

Test-Case 'an unresolvable cache location fails closed and purges nothing' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Empty' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'a cache whose location is unknown was purged anyway'
        Assert-True ($result.Detail -match 'WorkingDirectory') $result.Detail
    }

    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -WorkingDirectory '\\server\share\do' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'a UNC cache location was purged anyway'
        Assert-True ($result.Detail -match 'could not be normalised') $result.Detail
    }
}

Test-Case 'a cache location that is not an absolute path fails closed, wherever the process sits' {
    # The guard promises that a location which cannot be determined is NOT purged. GetFullPath
    # COMPLETES a relative value against the process's current directory, so this case first puts
    # that directory on the TARGET drive: without a rooted check every value below comes back as
    # C:\something, passes the on-drive test, and the cache is purged on that evidence.
    #
    # 'C:' is in the list because it is not the drive root - it is the current directory ON C:,
    # which is the same ambiguity wearing a drive letter.
    $previous = [System.Environment]::CurrentDirectory
    try {
        [System.Environment]::CurrentDirectory = ((Get-WacTargetDrive) + '\')

        foreach ($value in @('DOCache', '..\DOCache', '%WAC_NO_SUCH_VARIABLE%\Cache', 'C:', 'not a path at all')) {
            Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -WorkingDirectory $value -Body {
                $result = Clear-WacDeliveryOptimizationCache

                Assert-Equal 'SafeSkip' $result.Outcome ('{0} -> {1}' -f $value, $result.Detail)
                Assert-False $result.Attempted ('{0} was treated as a location to act on' -f $value)
                Assert-Equal '0' $env:WAC_TEST_DO_CALLS ('a location that could not be determined was purged anyway: ' + $value)
                Assert-True ($result.Detail -match 'not an absolute path') ('{0} -> {1}' -f $value, $result.Detail)
                Assert-True ($result.Detail.Contains($value)) ('the refused value is not named: ' + $result.Detail)
            }
        }

        # A drive-relative form reaches the same refusal through the normaliser, which rejects it
        # for the same reason: 'C:DOCache' resolves against a per-drive working directory.
        Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -WorkingDirectory 'C:DOCache' -Body {
            $result = Clear-WacDeliveryOptimizationCache

            Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
            Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'a drive-relative location was purged anyway'
            Assert-True ($result.Detail -match 'could not be normalised') $result.Detail
        }

        # An empty or blank WorkingDirectory is the same refusal one branch earlier, and it must
        # stay a refusal rather than fall through to the current directory.
        foreach ($blank in @('', '   ')) {
            Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -WorkingDirectory $blank -Body {
                $result = Clear-WacDeliveryOptimizationCache

                Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
                Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'a blank location was purged anyway'
                Assert-True ($result.Detail -match 'no WorkingDirectory') $result.Detail
            }
        }
    }
    finally {
        [System.Environment]::CurrentDirectory = $previous
    }
}

Test-Case 'Delivery Optimization is a SafeSkip when the configuration cmdlet is absent' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Absent' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the cache was purged without resolving where it is'
        Assert-True ($result.Detail -match 'Get-DOConfig is unavailable') $result.Detail
    }
}

Test-Case 'a configuration read that exceeds its bound is Incomplete and purges nothing' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        $script:BoundedForce['call:0'] = @{ Outcome = 'Incomplete'; Error = 'the work did not finish within 1 ms.' }
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Incomplete' $result.Outcome $result.Detail
        Assert-True $result.Failed 'an unresolved location must reach the exit code'
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the cache was purged after the location read timed out'
    }
}

Test-Case 'a configuration read that throws is reported, never treated as C:' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Failing' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Failed' $result.Outcome $result.Detail
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the cache was purged after the location read failed'
        Assert-True ($result.Detail -match 'stubbed Get-DOConfig failed') $result.Detail
    }
}

Test-Case 'Delivery Optimization is a SafeSkip when the purge cmdlet is absent' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Absent' -ConfigMode 'Present' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-True $result.Skipped $result.Detail
        Assert-False $result.Attempted 'an absent cmdlet must not be reported as attempted'
        Assert-False $result.Failed
        Assert-Equal '0' $env:WAC_TEST_DO_CALLS
        Assert-Equal '0' $env:WAC_TEST_DO_CONFIG_CALLS 'availability must be settled before the configuration is read'
    }
}

Test-Case 'a Delivery Optimization purge failure is reported, never swallowed' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Failing' -ConfigMode 'Present' -Body {
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Failed' $result.Outcome $result.Detail
        Assert-True $result.Failed $result.Detail
        Assert-False $result.Succeeded
        Assert-True $result.Attempted
        Assert-True ($result.Detail -match 'stubbed cache purge failed') $result.Detail
    }
}

Test-Case 'a purge that exceeds its bound is Incomplete, not a completed purge' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        $script:BoundedForce['call:1'] = @{ Outcome = 'Incomplete'; Error = 'the work did not finish within 1 ms.' }
        $result = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Incomplete' $result.Outcome $result.Detail
        Assert-False $result.Succeeded 'a purge that never finished reported success'
        Assert-True $result.Failed
    }
}

Test-Case 'an exhausted run budget stops Delivery Optimization before it resolves anything' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        Invoke-WithExpiredDeadline -Body {
            $result = Clear-WacDeliveryOptimizationCache

            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-Equal '0' $env:WAC_TEST_DO_CONFIG_CALLS
            Assert-Equal '0' $env:WAC_TEST_DO_CALLS 'the cache was purged after the budget expired'
        }
    }
}

Test-Case 'a step result is logged at the level its outcome deserves' {
    # A step whose outcome makes the run exit 7 must not be missing from the log of that run.
    # CRITICAL is the highest level -LogLevel accepts, so the case runs the log AT that level:
    # everything written below it is gone, which is the whole point of the assertion pair.
    $sandbox = New-TestSandbox -Prefix 'steps-level'
    try {
        Assert-True (Initialize-WacRun -BaseName 'steplevel' -CandidateRoot @($sandbox) -LogLevel 'CRITICAL' -BudgetMinutes 60) `
            'no run log was created, so no line could be captured'
        $logPath = Get-WacLogPath

        [void](Write-WacStepResult -Component 'Case' -Result (New-WacStepResult -Category 'refusing' `
                    -Outcome 'SecurityRefusal' -Attempted $true -Detail 'a refusing step'))
        [void](Write-WacStepResult -Component 'Case' -Result (New-WacStepResult -Category 'unfinished' `
                    -Outcome 'Incomplete' -Attempted $true -Detail 'an unfinished step'))
        [void](Write-WacStepResult -Component 'Case' -Result (New-WacStepResult -Category 'fine' `
                    -Outcome 'Succeeded' -Attempted $true -Detail 'a successful step'))
        Close-WacLog

        $text = [System.IO.File]::ReadAllText($logPath)
        Assert-True ($text -cmatch '\[CRITICAL\] \[Case\] Step complete\..*outcome=SecurityRefusal') `
        ('a refusing step was logged below CRITICAL and this run kept nothing: ' + $text)

        # The other direction. A level hard-wired to CRITICAL would satisfy the assertion above and
        # be just as wrong, so the two outcomes that are NOT refusals have to be missing here.
        Assert-False ($text.Contains('outcome=Succeeded')) ('a successful step is not CRITICAL: ' + $text)
        Assert-False ($text.Contains('outcome=Incomplete')) ('an incomplete step is not CRITICAL: ' + $text)
    }
    finally {
        Close-WacLog
        Set-WacDeadline -DeadlineUtc ((Get-Date).ToUniversalTime().AddDays(30))
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'two Delivery Optimization runs in a row stay benign' {
    Invoke-WithStubbedDeliveryOptimization -Mode 'Present' -ConfigMode 'Present' -Body {
        $first = Clear-WacDeliveryOptimizationCache
        $second = Clear-WacDeliveryOptimizationCache

        Assert-Equal 'Succeeded' $first.Outcome $first.Detail
        Assert-Equal 'Succeeded' $second.Outcome $second.Detail
        Assert-False $second.Failed 'the second run over the same state stopped being benign'
        Assert-Equal '2' $env:WAC_TEST_DO_CALLS
    }
}

Complete-TestRun
