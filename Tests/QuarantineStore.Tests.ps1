#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-14: the file that decides whether the next run may change this machine has to be written,
    read and retired somewhere nobody else can create a name.

.DESCRIPTION
    The marker used to sit directly under the state root, and this project's OWN state-trust rule
    permits a non-administrative principal to create new names there. The writer checked the final
    name for a reparse point and then wrote a predictable `<name>.new` with no check at all, so a
    link preplanted at the temporary name was written through to wherever it pointed before the swap
    was ever attempted. The reader treated `Test-Path -PathType Leaf` answering false as absence,
    which is also what a directory, a denied probe and a dangling link answer.

    Every case here plants something at the marker name and asserts on a SENTINEL OUTSIDE the store
    - its contents, byte for byte - rather than on a refusal message. A refusal message can be
    produced by code that already wrote through the link.

    The store root and the owner/DACL verdict are seams, because an unelevated suite can neither
    create under %SystemRoot%\Logs nor own a TEMP directory the way the real rule demands. Nothing
    else is stood in: the collision-failing create, the reparse refusal and the hard-link refusal are
    all answered by the kernel through the handle, which is the half that matters.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

foreach ($moduleLeaf in @('FileSystem', 'StepContract', 'RecycleBin', 'DiskCleanup', 'Steps')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}
. (Join-Path -Path $PSScriptRoot -ChildPath '_StepHarness.ps1')
$script:StepModule = Get-Module -Name 'WindowsAutoCleanup.DiskCleanup'

$script:MarkerName = Get-WacQuarantineMarkerName

function Use-TestControlStore {
    <#
    .SYNOPSIS
        Runs a body with the control store redirected into a sandbox and the descriptor verdict
        answered, then restores both.
    .DESCRIPTION
        -Untrusted answers the descriptor question with a REFUSAL instead, which is how the
        "the store cannot be proven administrative" branch is reached without touching an ACL.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [switch]$Untrusted
    )

    Set-WacControlRoot -Path $Root
    Set-WacDirectoryTrustJudge -ScriptBlock ([scriptblock]::Create((
        'param($Sddl, $Strict) $null = $Sddl; $null = $Strict; ' +
        'return [PSCustomObject]@{ IsTrusted = $' + (-not $Untrusted).ToString().ToLowerInvariant() +
        '; Owner = $null; Reason = "test shim: descriptor verdict"; Writers = @() }')))
    try { & $Body }
    finally {
        Set-WacDirectoryTrustJudge -ScriptBlock $null
        Restore-SuiteControlStore
    }
}

function New-StoreSandbox {
    <#
    .SYNOPSIS
        A sandbox holding the store directory, and a sentinel file OUTSIDE it with known contents.
    #>
    param([Parameter(Mandatory = $true)][string]$Prefix)

    $sandbox = New-TestSandbox -Prefix $Prefix
    $store = Join-Path -Path $sandbox -ChildPath 'Control'
    $outside = Join-Path -Path $sandbox -ChildPath 'outside'
    [void][System.IO.Directory]::CreateDirectory($store)
    [void][System.IO.Directory]::CreateDirectory($outside)

    $sentinel = Join-Path -Path $outside -ChildPath 'sentinel.txt'
    [System.IO.File]::WriteAllText($sentinel, 'SENTINEL-ORIGINAL', (New-Object System.Text.UTF8Encoding($false)))

    return [PSCustomObject]@{
        Sandbox = $sandbox; Store = $store; Outside = $outside; Sentinel = $sentinel
        Marker = Join-Path -Path $store -ChildPath $script:MarkerName
    }
}

function Assert-SentinelIntact {
    param([Parameter(Mandatory = $true)]$Fixture, [Parameter(Mandatory = $true)][string]$What)

    Assert-True ([System.IO.File]::Exists($Fixture.Sentinel)) ('{0}: the sentinel outside the store was destroyed' -f $What)
    Assert-Equal 'SENTINEL-ORIGINAL' ([System.IO.File]::ReadAllText($Fixture.Sentinel)) `
    ('{0}: the sentinel outside the store was written through' -f $What)
}

function New-LinkOrSkip {
    <#
    .SYNOPSIS
        Creates a link of the given kind, or returns $false when this host will not make one.
    .DESCRIPTION
        A junction and a hard link need no privilege; a symbolic link does unless Developer Mode is
        on. A case that cannot create its link says so in its assertion rather than passing quietly,
        because a planted-link case that silently did not plant a link proves nothing.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][ValidateSet('Junction', 'HardLink')][string]$Kind
    )

    try {
        [void](New-Item -ItemType $Kind -Path $Path -Target $Target -ErrorAction Stop)
        return $true
    }
    catch { return $false }
}

Test-Case 'a planted ordinary file at the marker name is never written through' {
    # The collision-failing create is the whole guard: an existing name is refused, not opened,
    # truncated or appended to. Before, a write went to a predictable temporary name with no check
    # on it at all and then replaced the final one.
    $fixture = New-StoreSandbox -Prefix 'ctl-plant-file'
    try {
        [System.IO.File]::WriteAllText($fixture.Marker, 'PLANTED', (New-Object System.Text.UTF8Encoding($false)))

        Use-TestControlStore -Root $fixture.Store -Body {
            $written = Write-WacControlFile -Name $script:MarkerName -Content '{"ProcessId":1}'
            Assert-Equal 'Present' ([string]$written.Kind) ('a planted name was not reported as already present: ' + [string]$written.Reason)
        }

        Assert-Equal 'PLANTED' ([System.IO.File]::ReadAllText($fixture.Marker)) 'the planted file was overwritten'
        Assert-SentinelIntact -Fixture $fixture -What 'planted ordinary file'
    }
    finally { Remove-TestSandbox -Path $fixture.Sandbox }
}

Test-Case 'a junction at the marker name is neither followed nor believed' {
    # A reparse point carries no useful contents and must never be resolved. The write must not
    # reach the junction's target, and the read must say Unreadable - NOT Absent, which is what a
    # leaf-type probe answers for a link whose target is a directory.
    $fixture = New-StoreSandbox -Prefix 'ctl-plant-junction'
    try {
        $planted = New-LinkOrSkip -Path $fixture.Marker -Target $fixture.Outside -Kind 'Junction'
        Assert-True $planted 'this host could not create a junction, so the case would prove nothing'

        Use-TestControlStore -Root $fixture.Store -Body {
            $written = Write-WacControlFile -Name $script:MarkerName -Content '{"ProcessId":1}'
            Assert-True (@('Present', 'Failed') -ccontains [string]$written.Kind) `
            ('a junction at the marker name was written through: ' + [string]$written.Kind)

            $read = Read-WacControlFile -Name $script:MarkerName
            Assert-Equal 'Unreadable' ([string]$read.State) `
            ('a junction read as something this run could act on: {0} / {1}' -f [string]$read.State, [string]$read.Reason)
        }

        Assert-SentinelIntact -Fixture $fixture -What 'planted junction'
        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $fixture.Outside -Filter $script:MarkerName -Force -ErrorAction SilentlyContinue)).Count `
        'the write followed the junction and landed in its target'
    }
    finally { Remove-TestSandbox -Path $fixture.Sandbox }
}

Test-Case 'an extra hard link at the marker name is refused, not read' {
    # The case a reparse check misses ENTIRELY: a hard link carries no reparse attribute and
    # resolves to an ordinary path. Only the link COUNT read from the handle tells them apart, and
    # these bytes being reachable under a name somebody else chose is the whole problem.
    $fixture = New-StoreSandbox -Prefix 'ctl-plant-hardlink'
    try {
        $planted = New-LinkOrSkip -Path $fixture.Marker -Target $fixture.Sentinel -Kind 'HardLink'
        Assert-True $planted 'this host could not create a hard link, so the case would prove nothing'

        Use-TestControlStore -Root $fixture.Store -Body {
            $read = Read-WacControlFile -Name $script:MarkerName
            Assert-Equal 'Unreadable' ([string]$read.State) `
            ('a multi-link file was read as a control record: ' + [string]$read.Reason)

            $written = Write-WacControlFile -Name $script:MarkerName -Content '{"ProcessId":1}'
            Assert-True (@('Present', 'Failed') -ccontains [string]$written.Kind) `
            ('a hard link at the marker name was written through: ' + [string]$written.Kind)
        }

        Assert-SentinelIntact -Fixture $fixture -What 'planted hard link'
    }
    finally { Remove-TestSandbox -Path $fixture.Sandbox }
}

Test-Case 'a directory at the marker name is unreadable, not absent' {
    # `Test-Path -PathType Leaf` answers FALSE here, which the old reader called absence - and
    # absence is the one answer that licenses mutating the machine.
    $fixture = New-StoreSandbox -Prefix 'ctl-plant-dir'
    try {
        [void][System.IO.Directory]::CreateDirectory($fixture.Marker)

        Use-TestControlStore -Root $fixture.Store -Body {
            Assert-Equal 'Unreadable' ([string](Read-WacControlFile -Name $script:MarkerName).State) `
            'a directory standing at the marker name read as absence'
        }
    }
    finally { Remove-TestSandbox -Path $fixture.Sandbox }
}

Test-Case 'a store that cannot be proven administrative is never read as empty' {
    # The other direction of the same rule. If the store itself cannot be proven, its contents
    # cannot be ruled out either, so the answer is Unreadable and the run fails closed.
    $fixture = New-StoreSandbox -Prefix 'ctl-untrusted'
    try {
        Use-TestControlStore -Root $fixture.Store -Untrusted -Body {
            Assert-Equal 'Unreadable' ([string](Read-WacControlFile -Name $script:MarkerName).State) `
            'an unprovable store reported that no control file exists'
            Assert-Equal 'Failed' ([string](Write-WacControlFile -Name $script:MarkerName -Content 'x').Kind) `
            'a control file was written into a store that could not be proven'
            Assert-False (Remove-WacControlFile -Name $script:MarkerName) `
            'retirement from an unprovable store was reported as done'
        }

        Assert-False ([System.IO.File]::Exists($fixture.Marker)) 'a refused write left a file behind anyway'
    }
    finally { Remove-TestSandbox -Path $fixture.Sandbox }
}

Test-Case 'a clean write leaves exactly one name in the store and no temporary' {
    # The `.new` is gone, not guarded. This asserts the absence of the whole class rather than the
    # safety of one more pathname check.
    $fixture = New-StoreSandbox -Prefix 'ctl-no-temp'
    try {
        Use-TestControlStore -Root $fixture.Store -Body {
            Assert-Equal 'Created' ([string](Write-WacControlFile -Name $script:MarkerName -Content '{"ProcessId":7}').Kind) 'the first write did not create'
        }

        $entries = @(Get-ChildItem -LiteralPath $fixture.Store -Force | ForEach-Object { $_.Name })
        Assert-Equal 1 $entries.Count ('the store holds more than the record itself: ' + ($entries -join ', '))
        Assert-Equal $script:MarkerName $entries[0] ('an unexpected name was created: ' + $entries[0])
    }
    finally { Remove-TestSandbox -Path $fixture.Sandbox }
}

Test-Case 'two clean runs write, retire and write again with no residue' {
    # The benign steady state. A store that accumulates anything across ordinary runs is a store
    # that will eventually refuse one.
    $fixture = New-StoreSandbox -Prefix 'ctl-two-runs'
    try {
        Use-TestControlStore -Root $fixture.Store -Body {
            foreach ($pass in 1, 2) {
                Assert-Equal 'Created' ([string](Write-WacControlFile -Name $script:MarkerName -Content ('{"ProcessId":' + $pass + '}')).Kind) `
                ('pass {0}: the write did not create' -f $pass)
                Assert-Equal 'Valid' ([string](Read-WacControlFile -Name $script:MarkerName).State) ('pass {0}: the record did not read back' -f $pass)
                Assert-True (Remove-WacControlFile -Name $script:MarkerName) ('pass {0}: the record was not retired' -f $pass)
                Assert-Equal 'Absent' ([string](Read-WacControlFile -Name $script:MarkerName).State) ('pass {0}: a retired record still reads' -f $pass)
            }
        }

        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $fixture.Store -Force)).Count 'two clean runs left residue in the store'
    }
    finally { Remove-TestSandbox -Path $fixture.Sandbox }
}

Test-Case 'a marker left in the old location quarantines the run and is neither read nor deleted' {
    # Migration, and deliberately conservative. Its contents may not be believed - anyone could have
    # created that name - and it may not be deleted either, because that would discard a real
    # operator's real uncertainty on the strength of the same distrust.
    $fixture = New-StoreSandbox -Prefix 'ctl-legacy'
    $savedProgramData = [string]$env:ProgramData
    try {
        $legacyRoot = Join-Path -Path $fixture.Sandbox -ChildPath 'PD'
        $legacyDir = Join-Path -Path $legacyRoot -ChildPath 'WindowsAutoCleanup'
        [void][System.IO.Directory]::CreateDirectory($legacyDir)
        $legacyMarker = Join-Path -Path $legacyDir -ChildPath $script:MarkerName
        [System.IO.File]::WriteAllText($legacyMarker, 'LEGACY-CONTENTS', (New-Object System.Text.UTF8Encoding($false)))
        $env:ProgramData = $legacyRoot

        Use-TestControlStore -Root $fixture.Store -Body {
            Assert-Equal 'Present' ([string](Test-WacLegacyControlFile -Name $script:MarkerName)) 'the legacy marker was not detected'

            $resolved = Resolve-WacQuarantine
            Assert-Equal 'Quarantined' ([string]$resolved.State) ('a legacy marker did not quarantine the run: ' + [string]$resolved.Reason)
            Assert-False (Test-WacMutationAllowed) 'a run carrying a legacy marker was allowed to mutate'
        }

        Assert-True ([System.IO.File]::Exists($legacyMarker)) 'the legacy marker was deleted rather than reported'
        Assert-Equal 'LEGACY-CONTENTS' ([System.IO.File]::ReadAllText($legacyMarker)) 'the legacy marker was rewritten'
    }
    finally {
        $env:ProgramData = $savedProgramData
        Reset-WacAbandonedMutator
        Remove-TestSandbox -Path $fixture.Sandbox
    }
}

Test-Case 'a step that cannot record its recovery copy declines BEFORE it mutates' {
    # The consumer half of the store's contract (ledger WAC-05R). cleanmgr BORROWS somebody else's
    # sage profile: it switches handlers on, runs, and puts the originals back. Those originals used
    # to exist only in this process's memory, so a run that wrote the profile and was then abandoned
    # left them recoverable from a variable that no longer existed - and a later run, having proved
    # this host gone, would retire the quarantine and lose them for ever.
    #
    # So the copy is written BEFORE the first value is touched, and a store that cannot take it is a
    # reason to change nothing at all. Declining there costs the machine nothing, which is exactly
    # why it is the right place to stop.
    $fixture = New-StoreSandbox -Prefix 'ctl-decline'
    $key = 'HKCU:\Software\WacCtl_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 12)
    $volumeCaches = Join-Path -Path $key -ChildPath 'VolumeCaches'
    $originalKeyPath = Get-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath'
    try {
        $relative = $volumeCaches -replace '^(?i)HKCU:\\', ''
        foreach ($handler in @('Temporary Files', 'Thumbnail Cache')) {
            $created = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(($relative + '\' + $handler))
            if ($null -eq $created) { throw 'the scratch key could not be created' }
            $created.Close()
        }
        [void](New-ItemProperty -LiteralPath (Join-Path -Path $volumeCaches -ChildPath 'Temporary Files') `
                -Name 'StateFlags9999' -PropertyType DWord -Value 4 -Force -ErrorAction Stop)

        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $volumeCaches

        Invoke-WithStubbedTool -StubToolPath -Body {
            # Invoke-WithStubbedTool has just armed a WRITABLE store; this case is about the other
            # answer, so the verdict is flipped for the duration of the call.
            Use-TestControlStore -Root $fixture.Store -Untrusted -Body {
                $result = Invoke-WacLegacyDiskCleanup -Enabled -SageId 9999 -Category @('Temporary Files')

                Assert-Equal 'SafeSkip' ([string]$result.Outcome) `
                ('a step that could not record its recovery copy did not decline: ' + [string]$result.Detail)
                Assert-Equal 0 $script:StubCall.Count 'cleanmgr was launched although nothing could be recovered afterwards'
            }
        }

        # The machine, not the message: the borrowed value is exactly as it was.
        $after = (Get-ItemProperty -LiteralPath (Join-Path -Path $volumeCaches -ChildPath 'Temporary Files') -Name 'StateFlags9999').'StateFlags9999'
        Assert-Equal 4 ([int]$after) 'the profile was written although the originals could not be recorded'
    }
    finally {
        Set-ModuleVariableValue -Module $script:StepModule -Name 'VolumeCacheKeyPath' -Value $originalKeyPath
        Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
        Remove-TestSandbox -Path $fixture.Sandbox
    }
}

Complete-TestRun
