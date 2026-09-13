#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-15: what a bounded worker can CALL, proven through real workers rather than through the
    in-process seam that hides the answer.

.DESCRIPTION
    Invoke-WacStepBounded runs its block as TEXT in a fresh runspace whose first statement imports
    the PACKAGE. The block therefore sees exactly what that package EXPORTS and nothing else - the
    defining module's private scope is gone. A block calling an unexported helper is not a style
    problem: the call fails with "the term is not recognized", the phase reports Incomplete, and in
    the cleanmgr step that means the read-back can never pass and the tool is never launched.

    That shipped. `Test-WacDiskCleanupProfileExact` was private while the `readback` phase called
    it, and every existing case used the recording bounded invoker - which runs the block IN
    PROCESS, where the private scope is still there. The seam that makes those suites cheap is
    exactly the seam that conceals this class of defect, so these cases deliberately do not use it.

    Two levels of proof, both empirical:

      * ONE guard over every bounded call site in src\, resolved through a real worker. It fails for
        any future block that calls something the worker cannot see, not only for the one that did.
      * The complete enabled cleanmgr sequence - snapshot, write, exact read-back, recorded launch,
        restore - through real bounded workers against a disposable HKCU key.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:SrcRoot = Join-Path -Path $script:RepoRoot -ChildPath 'src'

# The package entry point LAST, so its own non-forced imports bind to the instances forced here and
# a shadow installed in one of them is the instance the code under test actually sees.
foreach ($moduleLeaf in @('Core', 'FileSystem', 'StepContract', 'RecycleBin', 'DiskCleanup', 'Steps')) {
    Import-Module -Name (Join-Path -Path $script:SrcRoot -ChildPath ('WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

. (Join-Path -Path $PSScriptRoot -ChildPath '_StepHarness.ps1')

$script:StepModule = Get-Module -Name 'WindowsAutoCleanup.DiskCleanup'
$script:ScratchKeyRoot = 'HKCU:\Software\WacWorker_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12)

function Get-BoundedWorkerCall {
    <#
    .SYNOPSIS
        Every project command invoked inside a block handed to a bounded runner, with the package
        that block's worker will import.
    .DESCRIPTION
        Read off the AST rather than by text search, so a renamed helper or a new phase is covered
        without anyone remembering to update a list. Invoke-WacStepBounded always imports the Steps
        package; Invoke-WacBounded imports what its caller names, and every current caller names its
        OWN module - a site that does something else resolves to nothing and is reported, because
        silently skipping an unclassifiable call site is how a guard stops guarding.
    #>
    $found = New-Object 'System.Collections.Generic.List[object]'

    foreach ($file in @(Get-ChildItem -LiteralPath $script:SrcRoot -File |
            Where-Object { $_.Extension -ceq '.ps1' -or $_.Extension -ceq '.psm1' })) {

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)

        $calls = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst] -and
                    @('Invoke-WacStepBounded', 'Invoke-WacBounded') -contains $node.GetCommandName()
                }, $true))

        foreach ($call in $calls) {
            $runner = [string]$call.GetCommandName()
            $package = if ($runner -ceq 'Invoke-WacStepBounded') {
                Join-Path -Path $script:SrcRoot -ChildPath 'WindowsAutoCleanup.Steps.psm1'
            }
            elseif ($file.Extension -ceq '.psm1') { $file.FullName }
            else { $null }

            foreach ($block in @($call.CommandElements |
                    Where-Object { $_ -is [System.Management.Automation.Language.ScriptBlockExpressionAst] })) {

                foreach ($inner in @($block.FindAll({
                                param($node)
                                $node -is [System.Management.Automation.Language.CommandAst]
                            }, $true))) {

                    $name = [string]$inner.GetCommandName()
                    # Only this project's own surface. A built-in is in every runspace by definition.
                    if (-not $name -or $name -notlike '*-Wac*') { continue }
                    [void]$found.Add([PSCustomObject]@{ File = $file.Name; Runner = $runner; Package = $package; Command = $name })
                }
            }
        }
    }

    return @($found.ToArray())
}

function New-ScratchVolumeCacheKey {
    <#
    .SYNOPSIS
        A disposable VolumeCaches-shaped key under HKCU. Never the real HKLM one.
    #>
    param([Parameter(Mandatory = $true)][string]$KeyPath)

    # CreateSubKey, not New-Item: the provider probes a parent by ENUMERATING it, and both hosts
    # create and delete scratch roots under HKCU:\Software at the same time.
    $relative = $KeyPath -replace '^(?i)HKCU:\\', ''
    foreach ($handler in @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files')) {
        $created = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(($relative + '\' + $handler))
        if ($null -eq $created) { throw ('the scratch key {0} could not be created' -f $handler) }
        $created.Close()
    }
    return $KeyPath
}

function Get-ScratchStateFlag {
    param([Parameter(Mandatory = $true)][string]$KeyPath, [Parameter(Mandatory = $true)][string]$Handler)

    try {
        $property = Get-ItemProperty -LiteralPath (Join-Path -Path $KeyPath -ChildPath $Handler) -Name 'StateFlags9999' -ErrorAction Stop
        return [int]$property.'StateFlags9999'
    }
    catch { return $null }
}

function Invoke-WithRealWorker {
    <#
    .SYNOPSIS
        The step stubs WITHOUT the bounded seam, so every bounded phase runs in a real runspace.
    .DESCRIPTION
        Deliberately the one thing Invoke-WithStubbedTool does not offer. Only the external tool and
        two environment facts are stood in; the bounded runner, the exact checker and every registry
        phase are the shipped code.
    #>
    param([Parameter(Mandatory = $true)][scriptblock]$Body)

    $script:StubCall.Clear()
    $script:StubResult = @{}
    Reset-WacAbandonedMutator
    Set-WacStepBoundedInvoker -Invoker $null

    $storeSandbox = New-TestSandbox -Prefix 'worker-control'
    Set-WacControlRoot -Path (Join-Path -Path $storeSandbox -ChildPath 'Control')
    Set-WacDirectoryTrustJudge -ScriptBlock {
        param($Sddl, $Strict)
        $null = $Sddl; $null = $Strict
        return [PSCustomObject]@{ IsTrusted = $true; Owner = $null; Reason = 'test shim: descriptor verdict'; Writers = @() }
    }

    $originalAdmin = Get-ModuleFunctionBody -Module $script:StepModule -Name 'Test-WacIsAdministrator'
    Set-ModuleFunctionBody -Module $script:StepModule -Name 'Test-WacIsAdministrator' -Body { return $true }

    $originalToolPath = Get-ModuleFunctionBody -Module $script:StepModule -Name 'Get-WacSystemToolPath'
    Set-ModuleFunctionBody -Module $script:StepModule -Name 'Get-WacSystemToolPath' -Body {
        param([Parameter(Mandatory = $true)][string]$Leaf)
        return (Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath $Leaf)
    }

    Set-WacProcessInvoker -Invoker $script:RecordingInvoker
    try { & $Body }
    finally {
        Set-WacProcessInvoker -Invoker $null
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Test-WacIsAdministrator' -Body $originalAdmin
        Set-ModuleFunctionBody -Module $script:StepModule -Name 'Get-WacSystemToolPath' -Body $originalToolPath
        Set-WacDirectoryTrustJudge -ScriptBlock $null
        Set-WacControlRoot -Path $null
        Remove-TestSandbox -Path $storeSandbox
        $script:StubResult = @{}
    }
}

Test-Case 'every command a bounded block calls is reachable from inside a real worker' {
    # THE CLASS GUARD. It resolves the names in a real worker rather than comparing them against a
    # hand-kept export list, because the export list is not the contract - what the runspace can see
    # is, and that is decided by the import the runner performs.
    $calls = Get-BoundedWorkerCall
    Assert-True ($calls.Count -gt 0) 'no bounded call site was found at all, so this guard proves nothing'

    $unclassified = @($calls | Where-Object { -not $_.Package })
    Assert-Equal 0 $unclassified.Count `
    ('a bounded call site names a package this guard cannot resolve: {0}' -f (@($unclassified | ForEach-Object { $_.File + '/' + $_.Command }) -join ', '))

    $missing = New-Object 'System.Collections.Generic.List[string]'
    foreach ($group in @($calls | Group-Object -Property Package)) {
        $wanted = @(@($group.Group | ForEach-Object { [string]$_.Command }) | Sort-Object -Unique)

        # ONE worker per package, not one per name: the runspace and its import cost about 700 ms
        # here, and the question is the same for every name in the group.
        $run = Invoke-WacBounded -TimeoutMs 60000 -ImportModule @($group.Name) -ArgumentList @(, $wanted) -ScriptBlock {
            param($Names)
            $absent = @()
            foreach ($name in @($Names)) {
                if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) { $absent += $name }
            }
            return (, $absent)
        }

        Assert-Equal 'Succeeded' ([string]$run.Outcome) `
        ('the probe worker for {0} did not complete: {1}' -f (Split-Path -Leaf $group.Name), [string]$run.Error)

        foreach ($name in @(@($run.Output)[0])) {
            if ($name) { [void]$missing.Add(('{0} is called inside a bounded block but is not exported by {1}' -f $name, (Split-Path -Leaf $group.Name))) }
        }
    }

    Assert-Equal 0 $missing.Count (@($missing.ToArray()) -join '; ')
}

Test-Case 'the exact read-back resolves and answers inside a real worker' {
    # The WAC-15 regression itself, at the narrowest point. Before the export this returned
    # Incomplete with "The term 'Test-WacDiskCleanupProfileExact' is not recognized", which the
    # step maps to "the profile did not read back" - so cleanmgr was never started.
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
            [void](New-ItemProperty -LiteralPath (Join-Path -Path $key -ChildPath $handler) `
                    -Name 'StateFlags9999' -PropertyType DWord -Value 2 -Force -ErrorAction Stop)
        }
        [void](New-ItemProperty -LiteralPath (Join-Path -Path $key -ChildPath 'Offline Pages Files') `
                -Name 'StateFlags9999' -PropertyType DWord -Value 0 -Force -ErrorAction Stop)

        Set-WacStepBoundedInvoker -Invoker $null
        $run = Invoke-WacStepBounded -Component 'DiskCleanup' -Label 'readback' -TimeoutMs 60000 `
            -ArgumentList @(9999, @('Temporary Files', 'Thumbnail Cache'), $key) -ScriptBlock {
                param($SageId, $Expected, $KeyPath)
                Test-WacDiskCleanupProfileExact -SageId $SageId -Expected $Expected -KeyPath $KeyPath
            }

        Assert-Equal 'Succeeded' ([string]$run.Outcome) `
        ('the read-back helper could not be resolved by the real worker: ' + [string]$run.Error)
        $exact = @($run.Output)[0]
        Assert-True ($null -ne $exact) 'the real worker returned nothing at all'
        Assert-True ([bool]$exact.Ok) ('an exact selection did not read back as exact: ' + [string]$exact.Reason)
        Assert-Equal 2 (@($exact.Enabled)).Count ('enabled set: ' + (@($exact.Enabled) -join ','))
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'the real worker still refuses a selection that is not exact' {
    # The control. Without it "always Ok" satisfies the case above, and an unverified profile
    # reaching /sagerun is the outcome this whole read-back exists to prevent.
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    try {
        # A handler nobody asked for is switched on - exactly the leftover /sageset state the
        # read-back is there to catch.
        [void](New-ItemProperty -LiteralPath (Join-Path -Path $key -ChildPath 'Temporary Files') `
                -Name 'StateFlags9999' -PropertyType DWord -Value 2 -Force -ErrorAction Stop)
        [void](New-ItemProperty -LiteralPath (Join-Path -Path $key -ChildPath 'Thumbnail Cache') `
                -Name 'StateFlags9999' -PropertyType DWord -Value 2 -Force -ErrorAction Stop)

        Set-WacStepBoundedInvoker -Invoker $null
        $run = Invoke-WacStepBounded -Component 'DiskCleanup' -Label 'readback' -TimeoutMs 60000 `
            -ArgumentList @(9999, @('Temporary Files'), $key) -ScriptBlock {
                param($SageId, $Expected, $KeyPath)
                Test-WacDiskCleanupProfileExact -SageId $SageId -Expected $Expected -KeyPath $KeyPath
            }

        Assert-Equal 'Succeeded' ([string]$run.Outcome) ('the probe did not complete: ' + [string]$run.Error)
        $exact = @($run.Output)[0]
        Assert-False ([bool]$exact.Ok) 'a profile carrying an unrequested enabled handler read back as exact'
    }
    finally {
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-Case 'the whole enabled cleanmgr sequence runs through real bounded workers' {
    # The acceptance the brief asks for: snapshot, write, exact read-back, ONE recorded launch and
    # restore, with only the external tool and two environment facts stood in. Every registry phase
    # here is the shipped code in a real runspace against a disposable HKCU key.
    $key = New-ScratchVolumeCacheKey -KeyPath (Join-Path -Path $script:ScratchKeyRoot -ChildPath 'VolumeCaches')
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $key
    try {
        # One handler starts with somebody else's leftover selection. It must be switched off for
        # the run and put back byte for byte afterwards.
        [void](New-ItemProperty -LiteralPath (Join-Path -Path $key -ChildPath 'Offline Pages Files') `
                -Name 'StateFlags9999' -PropertyType DWord -Value 7 -Force -ErrorAction Stop)

        $before = @{}
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files')) {
            $before[$handler] = Get-ScratchStateFlag -KeyPath $key -Handler $handler
        }

        Invoke-WithRealWorker -Body {
            $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999 -Category @('Temporary Files', 'Thumbnail Cache')

            Assert-Equal 'Succeeded' ([string]$result.Outcome) ('the enabled run did not succeed: ' + [string]$result.Detail)
            Assert-Equal 1 $script:StubCall.Count ('the step must launch exactly one process: {0}' -f $script:StubCall.Count)
            Assert-Equal '/sagerun:9999' ([string]@($script:StubCall[0].Arguments)[0]) 'the launch did not carry only /sagerun'
        }

        foreach ($handler in @('Temporary Files', 'Thumbnail Cache', 'Offline Pages Files')) {
            Assert-Equal $before[$handler] (Get-ScratchStateFlag -KeyPath $key -Handler $handler) `
            ('the profile was not restored exactly for {0}' -f $handler)
        }
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $script:ScratchKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Complete-TestRun
