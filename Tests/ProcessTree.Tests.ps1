#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for WindowsAutoCleanup.ProcessTree.ps1: proving that a process, and everything
    it started, has stopped.

.DESCRIPTION
    These exercise the real functions against real child processes. taskkill is replaced by a
    compiled stand-in that terminates nothing, so what the shipped escalation can reach on its own
    is the thing under test rather than what Windows would have done anyway.

    Split out of Process.Tests.ps1 alongside the source split: everything here is about the EVIDENCE
    that work is over, and Process.Tests.ps1 keeps the cases about starting it.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath '_ProcessFixtures.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
# ---------------------------------------------------------------------------------------------
# Fixtures for the process-tree cases (ledger T-9)
# ---------------------------------------------------------------------------------------------

$script:TreeProbeBody = @'
Set-StrictMode -Version 2.0

if ($env:WAC_TREE_MODE -eq 'exit') { exit 0 }

if ($env:WAC_TREE_MODE -eq 'parent') {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:WAC_TREE_HOST
    $psi.Arguments = '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 240"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $spawned = [System.Diagnostics.Process]::Start($psi)
    Set-Content -LiteralPath $env:WAC_TREE_PIDFILE -Value ([string]$spawned.Id) -Encoding ASCII
}

Start-Sleep -Seconds 240
exit 0
'@

# A stand-in taskkill.exe. It records the argument vector it was handed and exits with whatever
# code the environment asks for, WITHOUT terminating anything - which is precisely the shape that
# used to be indistinguishable from a real kill.
$script:FakeTaskkillSource = @'
using System;
using System.IO;

public class WacFakeTaskkill
{
    public static int Main(string[] args)
    {
        string log = Environment.GetEnvironmentVariable("WAC_FAKE_TASKKILL_LOG");
        if (!string.IsNullOrEmpty(log))
        {
            File.AppendAllText(log, string.Join(" ", args) + Environment.NewLine);
        }

        int code = 0;
        int.TryParse(Environment.GetEnvironmentVariable("WAC_FAKE_TASKKILL_EXIT"), out code);
        return code;
    }
}
'@

$script:FakeTaskkillRoot = $null

function Get-FakeTaskkillRoot {
    <#
    .SYNOPSIS
        A directory that can stand in for %SystemRoot%, holding System32\taskkill.exe.
    .DESCRIPTION
        Stop-WacProcessTree resolves taskkill under $env:SystemRoot, so redirecting that variable
        inside the running process is enough to substitute it. Setting it is safe here and only
        here: the loader resolved this process's DLLs long before a test can touch the variable.

        The stand-in is COMPILED rather than faked with a copied Windows binary, because the cases
        need a chosen exit code and a recorded argument vector, and no shipped executable offers
        both. Add-Type -OutputType ConsoleApplication is not an option - measured, it works on
        Windows PowerShell 5.1 and fails on PowerShell 7 with "Both the assembly types
        'ConsoleApplication' and 'WindowsApplication' are not currently supported" - so the .NET
        Framework csc.exe every Windows install ships is used instead (measured 209-335 ms).

        Built once per suite. Returns $null when no compiler is present.
    #>
    if ($script:FakeTaskkillRoot) { return $script:FakeTaskkillRoot }

    $compiler = $null
    foreach ($relative in @('Microsoft.NET\Framework64\v4.0.30319\csc.exe', 'Microsoft.NET\Framework\v4.0.30319\csc.exe')) {
        $candidate = Join-Path -Path $env:SystemRoot -ChildPath $relative
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $compiler = $candidate; break }
    }
    if (-not $compiler) { return $null }

    $sandbox = New-TestSandbox -Prefix 'fakekill'
    $system32 = Join-Path -Path $sandbox -ChildPath 'System32'
    [void][System.IO.Directory]::CreateDirectory($system32)

    $source = Join-Path -Path $sandbox -ChildPath 'FakeTaskkill.cs'
    Set-Content -LiteralPath $source -Value $script:FakeTaskkillSource -Encoding ASCII
    $exe = Join-Path -Path $system32 -ChildPath 'taskkill.exe'

    [void](Invoke-WacProcess -FilePath $compiler -TimeoutMs 120000 `
            -ArgumentList @('/nologo', '/target:exe', ('/out:' + $exe), $source))

    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $null }

    $script:FakeTaskkillRoot = $sandbox
    return $sandbox
}

function Wait-ForTestFile {
    <#
    .SYNOPSIS
        Bounded wait for a probe to publish a value. Polling with a deadline, never a blind sleep.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$TimeoutMs = 30000
    )

    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([datetime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $text = ''
            try { $text = ([System.IO.File]::ReadAllText($Path)).Trim() } catch { $text = '' }
            if ($text) { return $text }
        }
        Start-Sleep -Milliseconds 50
    }

    return $null
}

function Stop-TestProcess {
    param($Process)

    if (-not $Process) { return }
    try { if (-not $Process.HasExited) { $Process.Kill() } } catch { $null = $_ }
    try { [void]$Process.WaitForExit(10000) } catch { $null = $_ }
    try { $Process.Dispose() } catch { $null = $_ }
}

# ---------------------------------------------------------------------------------------------
# Process-tree termination (ledger B2-6 part A, T-9)
# ---------------------------------------------------------------------------------------------

Test-Case 'Stop-WacProcessTree terminates a hung parent AND its child' {
    $sandbox = New-TestSandbox -Prefix 'tree'
    $parent = $null
    $child = $null
    try {
        $probe = Join-Path -Path $sandbox -ChildPath 'tree.ps1'
        Set-Content -LiteralPath $probe -Value $script:TreeProbeBody -Encoding ASCII
        $pidFile = Join-Path -Path $sandbox -ChildPath 'child.pid'

        $parent = Start-ProbeProcess -ScriptPath $probe -Environment @{
            WAC_TREE_MODE    = 'parent'
            WAC_TREE_HOST    = $script:HostExe
            WAC_TREE_PIDFILE = $pidFile
        }

        $childId = Wait-ForTestFile -Path $pidFile
        Assert-True ([bool]$childId) 'the probe never reported the child it started'

        # Bound to a HANDLE before the kill, so neither answer below can be forged by PID reuse.
        $child = Get-Process -Id ([int]$childId) -ErrorAction Stop
        Assert-False $child.HasExited 'the child was not running before the kill'

        $verdict = Stop-WacProcessTree -ProcessId $parent.Id -TimeoutMs 20000
        Assert-True $verdict.Proven ('the tree kill reported failure: ' + $verdict.Reason)
        Assert-True ($parent.WaitForExit(15000)) 'the parent survived the tree kill'
        Assert-True ($child.WaitForExit(15000)) 'the child survived the tree kill'

        # The child has to be an identity the kill BOUND, not one that happened to die with its
        # parent: a verdict that never saw it cannot have proved anything about it.
        Assert-True (@($verdict.Bound) -contains $child.Id) `
            ('the child was never bound: ' + (@($verdict.Bound) -join ','))
    }
    finally {
        Stop-TestProcess -Process $parent
        Stop-TestProcess -Process $child
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Stop-WacProcessTree treats an already-exited target as done and never runs taskkill' {
    $fakeRoot = Get-FakeTaskkillRoot
    if (-not $fakeRoot) { Set-TestSkipped -Reason 'no .NET Framework csc.exe to build the stand-in taskkill' }

    $sandbox = New-TestSandbox -Prefix 'gone'
    $realRoot = $env:SystemRoot
    $probeProcess = $null
    try {
        $probe = Join-Path -Path $sandbox -ChildPath 'tree.ps1'
        Set-Content -LiteralPath $probe -Value $script:TreeProbeBody -Encoding ASCII

        $probeProcess = Start-ProbeProcess -ScriptPath $probe -Environment @{ WAC_TREE_MODE = 'exit' }
        Assert-True ($probeProcess.WaitForExit(60000)) 'the probe never exited'

        # THE PREMISE, asserted instead of assumed. This case used to reach a different branch
        # entirely: Get-Process cannot see a process that has exited, so the old body returned on
        # its "no such process" path and the already-exited test below it was never evaluated -
        # deleting that test left the whole suite green. What keeps the id openable here is the
        # handle $probeProcess still holds from Process.Start, and an OPEN handle that is already
        # signalled is precisely the state the fast path exists for. It is also the only way this
        # case can pass at all now, since nothing in the path under test asks about the id.
        Assert-True (Initialize-WacNative) 'the native helpers did not load'
        $handle = [IntPtr]::Zero
        Assert-Equal 0 ([WacNative]::OpenProcessForTermination($probeProcess.Id, [ref]$handle)) `
            'the exited target could not be opened, so the branch under test was not reachable'
        try {
            Assert-Equal 0 ([WacNative]::WaitForProcessExit($handle, 0)) `
                'the exited target was not signalled, so this is not the already-exited branch'
        }
        finally {
            [WacNative]::CloseProcessHandle($handle)
        }

        $log = Join-Path -Path $sandbox -ChildPath 'taskkill.log'
        $env:WAC_FAKE_TASKKILL_LOG = $log
        $env:WAC_FAKE_TASKKILL_EXIT = '255'
        $env:SystemRoot = $fakeRoot

        $verdict = Stop-WacProcessTree -ProcessId $probeProcess.Id -TimeoutMs 3000
        $env:SystemRoot = $realRoot

        # "Already gone" must never become a false alarm: the caller wanted it gone and it is gone.
        Assert-True $verdict.Proven 'a target that had already exited was reported as not terminated'
        Assert-False (Test-Path -LiteralPath $log) 'taskkill was run against a process that had already exited'
    }
    finally {
        $env:SystemRoot = $realRoot
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_LOG' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_EXIT' -ErrorAction SilentlyContinue
        Stop-TestProcess -Process $probeProcess
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Stop-WacProcessTree reports an id that nothing owns as gone, without running taskkill' {
    $fakeRoot = Get-FakeTaskkillRoot
    if (-not $fakeRoot) { Set-TestSkipped -Reason 'no .NET Framework csc.exe to build the stand-in taskkill' }

    $sandbox = New-TestSandbox -Prefix 'noowner'
    $realRoot = $env:SystemRoot
    try {
        # The OTHER way a target can be gone, and the one the code must not confuse with "the state
        # could not be read". 2147483647 is above every id Windows allocates, so this is the arm
        # itself rather than a race against a real process that might still be exiting.
        Assert-True (Initialize-WacNative) 'the native helpers did not load'
        $handle = [IntPtr]::Zero
        Assert-Equal 87 ([WacNative]::OpenProcessForTermination(2147483647, [ref]$handle)) `
            'the premise failed: that id did not report ERROR_INVALID_PARAMETER'

        $log = Join-Path -Path $sandbox -ChildPath 'taskkill.log'
        $env:WAC_FAKE_TASKKILL_LOG = $log
        $env:WAC_FAKE_TASKKILL_EXIT = '0'
        $env:SystemRoot = $fakeRoot

        $verdict = Stop-WacProcessTree -ProcessId 2147483647 -TimeoutMs 1000
        $env:SystemRoot = $realRoot

        Assert-True $verdict.Proven 'an id no process owns was not reported as gone'
        Assert-False (Test-Path -LiteralPath $log) 'taskkill was run against an id nothing owns'
    }
    finally {
        $env:SystemRoot = $realRoot
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_LOG' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_EXIT' -ErrorAction SilentlyContinue
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'Stop-WacProcessTree does not report a target it could not open as terminated' {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    try {
        Set-WacLogWriter -Writer (
            [PSCustomObject]@{} | Add-Member -MemberType ScriptMethod -Name WriteLine `
                -Value { param($text) [void]$lines.Add([string]$text) }.GetNewClosure() -PassThru)

        # "Cannot tell" is not "it is gone". Only a protected process really refuses
        # SYNCHRONIZE|PROCESS_TERMINATE - PID 4 and csrss both measured 5 ERROR_ACCESS_DENIED on
        # each host - and handing one of those to a kill path is not a case to run on a
        # workstation, so the failure is injected. The id stays one nothing can own, so a seam that
        # silently failed to take could still not reach a real process.
        Set-WacProcessHandleOpener -Opener {
            param($processId)
            $null = $processId
            [PSCustomObject]@{ Handle = [IntPtr]::Zero; Win32Error = 5 }
        }

        Assert-False (Stop-WacProcessTree -ProcessId 2147483647 -TimeoutMs 500).Proven `
            'a target whose state could not be read at all was reported as terminated'

        $warned = @($lines | Where-Object { $_ -match 'unverifiable' })
        Assert-Equal 1 $warned.Count 'unreadable state was swallowed instead of warned about'
        Assert-True ($warned[0] -match '\[WARNING\]') ('the reason was not a WARNING: ' + $warned[0])
        Assert-True ($warned[0] -match 'win32Error=5') ('the reason did not survive: ' + $warned[0])
    }
    finally {
        Set-WacProcessHandleOpener -Opener $null
        Reset-WacTestLog
    }
}

# The three single-target cases that used to sit here - a stand-in taskkill exiting 0, exiting 255,
# and missing entirely, each against ONE sleeping process - were removed rather than kept beside the
# tree cases below. Each of the three tree cases runs the same taskkill shape against a parent AND a
# child, asserts the same taskkill argument vector and the same verdict, and additionally proves the
# child died: they are strict supersets, and keeping both would have doubled the runtime of the
# slowest suite in the project to assert the smaller half twice.


# ---------------------------------------------------------------------------------------------
# The tree, not just the root (ledger: taskkill /T is not evidence)
#
# Every case below replaces taskkill with a stand-in that terminates NOTHING, or removes it
# entirely, so the only thing that can reach the child is the shipped code's own escalation. A body
# that binds and kills the root alone leaves the child running and still answers Proven, which is
# exactly the defect these exist to keep out.
# ---------------------------------------------------------------------------------------------

function Start-TestTree {
    <#
    .SYNOPSIS
        A parent process with one live child. The caller MUST dispose both.
    .OUTPUTS
        Parent and Child, both bound to a real Process object before anything is killed.
    #>
    param([Parameter(Mandatory = $true)][string]$Sandbox)

    $probe = Join-Path -Path $Sandbox -ChildPath 'tree.ps1'
    if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
        Set-Content -LiteralPath $probe -Value $script:TreeProbeBody -Encoding ASCII
    }

    $pidFile = Join-Path -Path $Sandbox -ChildPath 'child.pid'
    $parent = Start-ProbeProcess -ScriptPath $probe -Environment @{
        WAC_TREE_MODE    = 'parent'
        WAC_TREE_HOST    = $script:HostExe
        WAC_TREE_PIDFILE = $pidFile
    }

    $childId = Wait-ForTestFile -Path $pidFile
    if (-not $childId) { throw 'the probe never reported the child it started' }

    return [PSCustomObject]@{ Parent = $parent; Child = (Get-Process -Id ([int]$childId) -ErrorAction Stop) }
}

function Test-TreeSurvivesUselessTaskkill {
    <#
    .SYNOPSIS
        Runs the shipped tree kill against a real parent+child while taskkill can do nothing, and
        asserts that BOTH processes end up dead and the verdict says so.
    .PARAMETER TaskkillExit
        The code the stand-in returns after doing nothing. -1 means there is no taskkill at all:
        the stand-in root is replaced by an empty directory, so Process.Start throws.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][int]$TaskkillExit
    )

    $fakeRoot = $null
    if ($TaskkillExit -ge 0) {
        $fakeRoot = Get-FakeTaskkillRoot
        if (-not $fakeRoot) { Set-TestSkipped -Reason 'no .NET Framework csc.exe to build the stand-in taskkill' }
    }

    $sandbox = New-TestSandbox -Prefix $Prefix
    $realRoot = $env:SystemRoot
    $tree = $null
    try {
        $tree = Start-TestTree -Sandbox $sandbox
        Assert-False $tree.Parent.HasExited 'the parent was not running before the kill'
        Assert-False $tree.Child.HasExited 'the child was not running before the kill'

        $log = Join-Path -Path $sandbox -ChildPath 'taskkill.log'
        if ($TaskkillExit -ge 0) {
            $env:WAC_FAKE_TASKKILL_LOG = $log
            $env:WAC_FAKE_TASKKILL_EXIT = [string]$TaskkillExit
            $env:SystemRoot = $fakeRoot
        }
        else {
            # An empty stand-in root: there is no System32\taskkill.exe at all.
            $env:SystemRoot = $sandbox
        }

        $verdict = Stop-WacProcessTree -ProcessId $tree.Parent.Id -TimeoutMs 20000
        $env:SystemRoot = $realRoot

        if ($TaskkillExit -ge 0) {
            Assert-False (Test-Path -LiteralPath $log) 'an unvalidated taskkill tree walk was invoked'
        }
        Assert-Equal $null $verdict.TaskkillExit 'termination must use only validated handles'

        # THE assertion. The child is a grandchild of this suite and was never named to anything:
        # only a body that ENUMERATED the tree and bound the child before killing can reach it.
        Assert-True ($tree.Child.WaitForExit(20000)) `
            'the child survived, so termination reached the root and nothing below it'
        Assert-True ($tree.Parent.WaitForExit(20000)) 'the parent survived'

        Assert-True $verdict.Proven ('the tree kill did not report proof: ' + $verdict.Reason)
        Assert-Equal 0 (@($verdict.Survivor).Count) `
            ('the verdict named survivors: ' + (@($verdict.Survivor) -join ','))
        Assert-True (@($verdict.Bound) -contains $tree.Parent.Id) 'the root was never bound'
        Assert-True (@($verdict.Bound) -contains $tree.Child.Id) `
            ('the child was never bound, so nothing proved it died: ' + (@($verdict.Bound) -join ','))
    }
    finally {
        $env:SystemRoot = $realRoot
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_LOG' -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Env:\WAC_FAKE_TASKKILL_EXIT' -ErrorAction SilentlyContinue
        if ($tree) {
            Stop-TestProcess -Process $tree.Parent
            Stop-TestProcess -Process $tree.Child
        }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'A taskkill that exits 0 and kills nothing still leaves no survivor in the tree' {
    Test-TreeSurvivesUselessTaskkill -Prefix 'treeliar' -TaskkillExit 0
}

Test-Case 'A taskkill that refuses still leaves no survivor in the tree' {
    # 255 is what a real taskkill returns when it will not terminate the target; 128 is "not found".
    Test-TreeSurvivesUselessTaskkill -Prefix 'treerefused' -TaskkillExit 255
}

Test-Case 'A missing taskkill still leaves no survivor in the tree' {
    Test-TreeSurvivesUselessTaskkill -Prefix 'treenokill' -TaskkillExit (-1)
}

Test-Case 'A descendant whose state cannot be read keeps the verdict unproven' {
    # The mirror image of the root case above, one level down. An identity that will not open is
    # unreadable state, and unreadable state has never been evidence here - so a tree containing one
    # cannot be reported as proven gone however completely the root died.
    $sandbox = New-TestSandbox -Prefix 'treeblind'
    $tree = $null
    try {
        $tree = Start-TestTree -Sandbox $sandbox
        $childId = $tree.Child.Id
        $rootId = $tree.Parent.Id

        # Only the CHILD refuses to open, and with 5 ERROR_ACCESS_DENIED - what a protected process
        # really answers, measured on both hosts. The root still opens for real, so the case cannot
        # pass by failing early on the root.
        Set-WacProcessHandleOpener -Opener {
            param($processId)
            if ($processId -eq $childId) { return [PSCustomObject]@{ Handle = [IntPtr]::Zero; Win32Error = 5 } }
            $handle = [IntPtr]::Zero
            $code = [WacNative]::OpenProcessForTermination($processId, [ref]$handle)
            return [PSCustomObject]@{ Handle = $handle; Win32Error = $code }
        }.GetNewClosure()

        $verdict = Stop-WacProcessTree -ProcessId $rootId -TimeoutMs 10000

        Assert-False $verdict.Proven 'a tree holding an identity nobody could read was reported as proven gone'
        Assert-True (@($verdict.Survivor) -contains $childId) `
            ('the unreadable child is missing from the survivors: ' + (@($verdict.Survivor) -join ','))
    }
    finally {
        Set-WacProcessHandleOpener -Opener $null
        if ($tree) {
            Stop-TestProcess -Process $tree.Parent
            Stop-TestProcess -Process $tree.Child
        }
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'The root exit check runs BEFORE the tree is read, so a dead pid never adopts strangers' {
    <#
        This is an ordering rule, so it is asserted as one. The behavioural case above passes either
        way on a quiet machine: it only fails when an unrelated process happens to carry the exited
        pid as its recorded parent, which is a 3%-per-round event under load and 0% at rest.

        Why the order matters, measured rather than argued: Windows never clears
        th32ParentProcessID when a parent exits, and it reuses process ids. Over 400 rounds of
        start-exit-enumerate under six churn workers, 12 rounds showed an ALREADY-EXITED id with
        recorded children, and they were live unrelated processes - conhost.exe, and once
        Microsoft.CmdPal.UI.exe. Reading the tree first bound those and then terminated them.

        A tree may only be owned if it was observed while its root was alive.
    #>
    $module = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'src\WindowsAutoCleanup.ProcessTree.ps1'
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($module, [ref]$null, [ref]$parseErrors)
    Assert-Equal 0 @($parseErrors).Count 'the module no longer parses'

    $body = @($ast.FindAll({
                param($node)
                ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and
                ($node.Name -eq 'Stop-WacProcessTree')
            }, $true))
    Assert-Equal 1 $body.Count 'exactly one Stop-WacProcessTree must exist'

    $text = $body[0].Extent.Text
    $rootCheck = $text.IndexOf('WaitForProcessExit($root.Handle, 0)', [System.StringComparison]::Ordinal)
    $treeRead = $text.IndexOf('Get-WacProcessDescendantId', [System.StringComparison]::Ordinal)

    Assert-True ($rootCheck -ge 0) 'the root exit check is gone entirely'
    Assert-True ($treeRead -ge 0) 'the descendant enumeration is gone entirely'
    Assert-True ($rootCheck -lt $treeRead) `
        'the tree is read before the root exit check, so an exited target can adopt an unrelated live process and kill it'
}
Complete-TestRun
