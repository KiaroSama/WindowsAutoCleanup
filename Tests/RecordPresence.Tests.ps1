#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-14R: the four probes that decide whether a RECORD is there, and what each of their answers
    is allowed to authorise.

.DESCRIPTION
    Absence authorises destruction in this project - retiring a quarantine marker, reclaiming a
    recovery slot, closing a transaction record - so an absence that is really "I could not look" is
    the dangerous direction, and all four of these probes produced one:

      * Test-WacControlStorePresence and Test-WacLegacyControlFile asked Directory.Exists about the
        container. That call is documented to answer false for a path it was not ALLOWED to inspect
        exactly as it does for one that is not there, so a store standing behind a parent whose
        attributes cannot be read reported as absent - and an absent store has never held a record.
      * Get-WacJournalPathState and Get-WacDeploymentRecoveryPathState enumerated the parent for the
        name and then threw the result away with [void] before answering Absent regardless. The one
        piece of positive evidence they collected was discarded, and the answer it was collected for
        was given anyway. Their other half was fail-SHUT: a parent proven not to exist was reported
        as one that could not be read, so a machine with nothing installed looked unresolvable.

    All four now route through Get-WacPathPresence, which was already in this project doing exactly
    this job for the profile walk: it classifies by the exception a single enumeration THROWS, so
    DirectoryNotFoundException is the container genuinely not being there while denial, a security
    refusal or an I/O error are not answers at all, and it READS that enumeration's result.

    THESE CASES EXERCISE THE READERS, not the probes. Read-WacControlFile, Resolve-WacQuarantine,
    Read-WacDeploymentJournal, Remove-WacDeploymentJournal and Get-WacDeploymentRecoveryPlan are
    what turn a probe's answer into a decision about somebody's machine, so that is where the
    assertions are.

    The denied directories are REAL, created with icacls inside this suite's own sandbox and
    restored in a finally block. Nothing outside the sandbox is touched and no production permission
    is changed. Exactly one shape cannot be staged on a Windows filesystem at all - a type probe
    answering no while the enumeration lists the name - and that one case, alone, replaces
    Get-WacPathPresence inside the Deploy module's own scope.
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

$script:DeployModule = Get-Module -Name 'WindowsAutoCleanup.Deploy'
$script:MarkerName = Get-WacQuarantineMarkerName
$script:Icacls = Join-Path -Path $env:SystemRoot -ChildPath 'System32\icacls.exe'
$script:Cmd = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cmd.exe'

# ---------------------------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------------------------

function Block-TestPathAccess {
    <#
    .SYNOPSIS
        Denies list and read to EVERYONE on paths inside this suite's own sandbox.
    .DESCRIPTION
        Everyone (S-1-1-0) by SID rather than by name: the deny has to bite whatever account runs
        the suite - elevated on a CI image, ordinary here - and a localised group name would not
        resolve on every image. The owner keeps READ_CONTROL and WRITE_DAC implicitly whatever the
        DACL says, which is what lets the paired finally block put it back.

        Denying the container alone does not reproduce the defect. A directory's attributes can be
        read either through its own DACL or through its parent's listing, so the shape the old code
        collapsed - Directory.Exists answering false for a directory that IS there - needs both
        routes closed, which is why callers pass the directory AND its parent.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Path)

    foreach ($entry in $Path) { & $script:Icacls $entry /deny '*S-1-1-0:(RD,RX)' | Out-Null }
}

function Unblock-TestPathAccess {
    <#
    .SYNOPSIS
        Removes what Block-TestPathAccess added, OUTERMOST FIRST. Never throws: it runs in a finally
        block, where an exception would replace the case's real failure with this one.
    .DESCRIPTION
        The order is the whole function. icacls has to read a directory's attributes before it can
        rewrite that directory's DACL, and an owner's implicit rights cover READ_CONTROL and
        WRITE_DAC but not FILE_READ_ATTRIBUTES - so while the parent's listing is still denied,
        icacls on the child exits 5 and the deny stays put. Measured: clearing the child first left
        the sandbox permanently undeletable and the run's own residue sweep reported it. Callers
        pass deepest-first, so this walks the array backwards.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Path)

    for ($index = $Path.Count - 1; $index -ge 0; $index--) {
        try { & $script:Icacls $Path[$index] /remove:d '*S-1-1-0' | Out-Null } catch { $null = $_ }
    }
}

function Use-TestControlStore {
    <#
    .SYNOPSIS
        Runs a body with the control store redirected into a sandbox and the descriptor verdict
        answered, then restores both. -Untrusted answers it with a refusal instead.
    .DESCRIPTION
        An unelevated suite can neither create under %SystemRoot%\Logs nor own a TEMP directory the
        way the real strict rule demands, so the root and the owner/DACL verdict are seams. Nothing
        else is stood in - the presence probe under test runs against the real filesystem.
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
        Set-WacControlRoot -Path $null
    }
}

function New-TestDanglingLink {
    <#
    .SYNOPSIS
        A link at $Path whose target does not exist. Returns the shape that was created, or ''.
    .DESCRIPTION
        A file symbolic link needs SeCreateSymbolicLinkPrivilege or Developer Mode, so it is tried
        first and a junction - which needs neither, and can also point at nothing - is the fallback.
        Both are a link to a target that is not there; the shape that succeeded is returned so a
        failing case can name it.

        mklink rather than New-Item: Windows PowerShell 5.1's New-Item -ItemType SymbolicLink
        checks that the target exists and refuses, which is the one property this fixture needs it
        not to have.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$MissingTarget
    )

    # Caught, not allowed to propagate. A refused mklink exits non-zero and writes to stderr, and
    # both of those are terminating under this suite's $ErrorActionPreference - which would turn the
    # symbolic-link attempt into a suite failure instead of the fallback it is meant to be.
    try { & $script:Cmd /c mklink "$Path" "$MissingTarget" 2>&1 | Out-Null } catch { $null = $_ }
    if (Test-Path -LiteralPath $Path) { return 'SymbolicLink' }

    try { & $script:Cmd /c mklink /J "$Path" "$MissingTarget" 2>&1 | Out-Null } catch { $null = $_ }
    if (Test-Path -LiteralPath $Path) { return 'Junction' }

    return ''
}

function Remove-TestDanglingLink {
    param([Parameter(Mandatory = $true)][string]$Path)

    try { [System.IO.File]::Delete($Path) } catch { $null = $_ }
    try { [System.IO.Directory]::Delete($Path, $false) } catch { $null = $_ }
}

function Set-DeployPresenceShadow {
    <#
    .SYNOPSIS
        Makes Get-WacPathPresence answer Present for exactly these paths, INSIDE the Deploy module.
    .DESCRIPTION
        The one disagreement no filesystem here can stage: both type probes answering no while the
        enumeration lists the name. Measured on both hosts, Windows reports a dangling link, a
        denied entry and a denied container through one of the two type probes, so this shape has to
        be injected - and it is the shape the discarded [void] enumeration was about.

        Built with [scriptblock]::Create over literal text rather than a closure. A scriptblock
        installed into a module keeps the session state it was CREATED in, so a closure captured
        here would read this file's variables while running as the module - and the shadow has to
        answer for the module, not for the suite.

        Installed in the DEPLOY module, not in Core. A replacement written into Core's own scope is
        not what an importer resolves: measured on both hosts, a Deploy part went on calling the
        real function. A name defined in Deploy's own scope shadows the imported one, and that is
        what the parts actually resolve.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Path)

    $literals = @($Path | ForEach-Object { "'" + ([string]$_).Replace("'", "''") + "'" })
    $lines = @(
        'param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)'
        ('$targets = @({0})' -f ($literals -join ', '))
        'foreach ($candidate in $targets) {'
        '    if ([string]::Equals($candidate, $Path, [System.StringComparison]::OrdinalIgnoreCase)) {'
        '        return "Present"'
        '    }'
        '}'
        'return "Absent"'
    )

    & $script:DeployModule { param($name, $body) Set-Item -Path ('function:script:' + $name) -Value $body } `
        'Get-WacPathPresence' ([scriptblock]::Create($lines -join [System.Environment]::NewLine))
}

function Remove-DeployPresenceShadow {
    & $script:DeployModule { param($name) Remove-Item -Path ('function:' + $name) -Force -ErrorAction SilentlyContinue } `
        'Get-WacPathPresence'
}

function New-ControlFixture {
    <#
    .SYNOPSIS
        A sandbox holding Logs\WindowsAutoCleanup\Control, plus an EMPTY stand-in %ProgramData%.
    .DESCRIPTION
        The empty legacy root matters. Resolve-WacQuarantine asks the legacy probe FIRST and returns
        on anything but Absent, so a case about the CURRENT store would otherwise be answered by
        whatever the real machine happens to have under %ProgramData%.
    #>
    param([Parameter(Mandatory = $true)][string]$Prefix)

    $sandbox = New-TestSandbox -Prefix $Prefix
    $logs = Join-Path -Path $sandbox -ChildPath 'Logs'
    $parent = Join-Path -Path $logs -ChildPath 'WindowsAutoCleanup'
    $store = Join-Path -Path $parent -ChildPath 'Control'
    $programData = Join-Path -Path $sandbox -ChildPath 'PD'
    [void][System.IO.Directory]::CreateDirectory($store)
    [void][System.IO.Directory]::CreateDirectory($programData)

    return [PSCustomObject]@{
        Sandbox = $sandbox; Logs = $logs; Parent = $parent; Store = $store
        ProgramData = $programData
        Marker = Join-Path -Path $store -ChildPath $script:MarkerName
    }
}

function Invoke-WithProgramData {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    $saved = [string]$env:ProgramData
    try {
        $env:ProgramData = $Path
        & $Body
    }
    finally {
        $env:ProgramData = $saved
        Reset-WacAbandonedMutator
    }
}

function Invoke-WithProgramFiles {
    <#
    .SYNOPSIS
        Runs a body with %ProgramFiles% pointed at $Path, which need NOT exist.
    .DESCRIPTION
        Invoke-InDeploymentSandbox always creates its directory, and one case here is specifically
        about a deployment root whose parent is genuinely not there.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    $saved = [string]$env:ProgramFiles
    try {
        $env:ProgramFiles = $Path
        & $Body (Get-WacDeploymentRoot)
    }
    finally { $env:ProgramFiles = $saved }
}

function Get-DeploymentProbePath {
    <#
    .SYNOPSIS
        The record and recovery-slot paths of a deployment root, without installing anything.
    #>
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    return [PSCustomObject]@{
        Root = $DeploymentRoot
        Record = Get-WacDeploymentJournalPath -DeploymentRoot $DeploymentRoot
        Previous = (Get-WacDeploymentSlotPath -DeploymentRoot $DeploymentRoot).Previous
    }
}

# ---------------------------------------------------------------------------------------------
# The control store: a container nobody could inspect is not an empty container
# ---------------------------------------------------------------------------------------------

Test-Case 'A control store behind a parent nobody can read is PRESENT, and its record survives' {
    # The dangerous direction, with nothing simulated. The store is really there and really holds a
    # marker; only its parent's attributes are unreadable. Directory.Exists then answers false for a
    # directory that exists, the old probe read that as Absent, and Absent is what tells
    # Read-WacControlFile that no record has ever been written - which clears the quarantine and
    # lets the next run mutate the machine.
    $fixture = New-ControlFixture -Prefix 'r14-store-denied'
    [System.IO.File]::WriteAllText($fixture.Marker, 'MARKER-ORIGINAL', (New-Object System.Text.UTF8Encoding($false)))
    $denied = @($fixture.Parent, $fixture.Logs)
    try {
        Block-TestPathAccess -Path $denied

        # The precondition the case rests on. If the deny ever stops biting, this says so rather
        # than letting the assertions below pass over a readable directory.
        Assert-False ([System.IO.Directory]::Exists($fixture.Parent)) `
            'the fixture did not reproduce an unreadable parent, so nothing below is measured'

        Invoke-WithProgramData -Path $fixture.ProgramData -Body {
            Use-TestControlStore -Root $fixture.Store -Untrusted -Body {
                Assert-Equal 'Present' ([string](Test-WacControlStorePresence)) `
                    'a store that IS there was reported absent because its parent could not be inspected'

                $read = Read-WacControlFile -Name $script:MarkerName
                Assert-Equal 'Unreadable' ([string]$read.State) `
                    ('a record that could not be ruled out was reported absent: ' + [string]$read.Reason)

                $resolved = Resolve-WacQuarantine
                Assert-Equal 'Quarantined' ([string]$resolved.State) `
                    ('an unreadable store released the quarantine: ' + [string]$resolved.Reason)
                Assert-False (Test-WacMutationAllowed) 'a run that could not read its own store was allowed to mutate'
            }
        }
    }
    finally {
        Unblock-TestPathAccess -Path $denied
        Reset-WacAbandonedMutator
        Remove-TestSandbox -Path $fixture.Sandbox
    }

    Assert-False ([System.IO.Directory]::Exists($fixture.Sandbox)) 'the denied sandbox was not restored and removed'
}

Test-Case 'A control store that cannot be listed is UNKNOWN even when nothing is in it' {
    # The parent is readable here - only its CONTENTS are refused - so the store may or may not be
    # there and this build cannot say which. It is the answer, not the absence of one: an absence
    # would license retiring records the store may still hold.
    $fixture = New-ControlFixture -Prefix 'r14-store-unlistable'
    [System.IO.Directory]::Delete($fixture.Store, $true)
    $denied = @($fixture.Parent)
    try {
        Block-TestPathAccess -Path $denied

        Use-TestControlStore -Root $fixture.Store -Untrusted -Body {
            Assert-Equal 'Unknown' ([string](Test-WacControlStorePresence)) `
                'a store whose parent refused enumeration was given a clear-state answer'
            Assert-Equal 'Unreadable' ([string](Read-WacControlFile -Name $script:MarkerName).State) `
                'a store nobody could list was read as one that has never held a record'
        }
    }
    finally {
        Unblock-TestPathAccess -Path $denied
        Remove-TestSandbox -Path $fixture.Sandbox
    }
}

Test-Case 'A legacy marker behind an unreadable root is not missing, and is neither read nor deleted' {
    # The migration probe, and the most expensive absence in the project: 'Absent' from here is what
    # lets a run past the legacy gate entirely. A %ProgramData% whose listing is refused answered
    # exactly that, while the marker sat in it untouched.
    $fixture = New-ControlFixture -Prefix 'r14-legacy-denied'
    $legacyRoot = Join-Path -Path $fixture.ProgramData -ChildPath 'WindowsAutoCleanup'
    [void][System.IO.Directory]::CreateDirectory($legacyRoot)
    $legacyMarker = Join-Path -Path $legacyRoot -ChildPath $script:MarkerName
    [System.IO.File]::WriteAllText($legacyMarker, 'LEGACY-ORIGINAL', (New-Object System.Text.UTF8Encoding($false)))
    $denied = @($legacyRoot, $fixture.ProgramData)
    try {
        Block-TestPathAccess -Path $denied
        Assert-False ([System.IO.Directory]::Exists($legacyRoot)) `
            'the fixture did not reproduce an unreadable legacy root, so nothing below is measured'

        Invoke-WithProgramData -Path $fixture.ProgramData -Body {
            Assert-Equal 'Unknown' ([string](Test-WacLegacyControlFile -Name $script:MarkerName)) `
                'a legacy location nobody could read was reported as one holding no marker'

            Use-TestControlStore -Root $fixture.Store -Body {
                $resolved = Resolve-WacQuarantine
                Assert-Equal 'Quarantined' ([string]$resolved.State) `
                    ('an unreadable legacy location released the quarantine: ' + [string]$resolved.Reason)
                Assert-False (Test-WacMutationAllowed) 'a run that could not read the legacy location was allowed to mutate'
            }
        }
    }
    finally {
        Unblock-TestPathAccess -Path $denied
        Reset-WacAbandonedMutator
    }

    Assert-True ([System.IO.File]::Exists($legacyMarker)) 'the legacy marker was deleted rather than reported'
    Assert-Equal 'LEGACY-ORIGINAL' ([System.IO.File]::ReadAllText($legacyMarker)) 'the legacy marker was rewritten'
    Remove-TestSandbox -Path $fixture.Sandbox
}

Test-Case 'A legacy marker whose own bytes are denied is still a marker, and is left alone' {
    # A denied ENTRY whose parent lists normally. Nothing here can open the file, which is precisely
    # why its presence has to be answered from the parent's listing rather than from an attempt to
    # look inside it - and why the answer stays Present rather than becoming an inspection failure.
    $fixture = New-ControlFixture -Prefix 'r14-legacy-entry'
    $legacyRoot = Join-Path -Path $fixture.ProgramData -ChildPath 'WindowsAutoCleanup'
    [void][System.IO.Directory]::CreateDirectory($legacyRoot)
    $legacyMarker = Join-Path -Path $legacyRoot -ChildPath $script:MarkerName
    [System.IO.File]::WriteAllText($legacyMarker, 'LEGACY-ORIGINAL', (New-Object System.Text.UTF8Encoding($false)))
    $denied = @($legacyMarker)
    try {
        Block-TestPathAccess -Path $denied
        Assert-Throws { [System.IO.File]::ReadAllText($legacyMarker) } -Message `
            'the fixture did not reproduce a denied entry, so nothing below is measured'

        Invoke-WithProgramData -Path $fixture.ProgramData -Body {
            Assert-Equal 'Present' ([string](Test-WacLegacyControlFile -Name $script:MarkerName)) `
                'a marker whose bytes are denied was reported as no marker at all'

            Use-TestControlStore -Root $fixture.Store -Body {
                Assert-Equal 'Quarantined' ([string](Resolve-WacQuarantine).State) `
                    'a marker nobody could open released the quarantine'
            }
        }
    }
    finally {
        Unblock-TestPathAccess -Path $denied
        Reset-WacAbandonedMutator
    }

    Assert-Equal 'LEGACY-ORIGINAL' ([System.IO.File]::ReadAllText($legacyMarker)) 'the legacy marker was rewritten'
    Remove-TestSandbox -Path $fixture.Sandbox
}

Test-Case 'A dangling link at the legacy marker name is a marker, not an absence' {
    # A link whose target does not exist is the shape Test-Path answers false for, and it is also
    # the shape somebody plants when they want a record to look retired. The probe answers from the
    # parent's listing, which sees the NAME, so the link is never followed to decide it.
    $fixture = New-ControlFixture -Prefix 'r14-legacy-link'
    $legacyRoot = Join-Path -Path $fixture.ProgramData -ChildPath 'WindowsAutoCleanup'
    [void][System.IO.Directory]::CreateDirectory($legacyRoot)
    $legacyMarker = Join-Path -Path $legacyRoot -ChildPath $script:MarkerName
    $shape = New-TestDanglingLink -Path $legacyMarker -MissingTarget (Join-Path -Path $fixture.Sandbox -ChildPath 'no-such-target')
    try {
        Assert-True ($shape -ne '') 'neither a symbolic link nor a junction could be created, so nothing is measured'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $fixture.Sandbox -ChildPath 'no-such-target')) `
            'the link target exists, so the link is not dangling'

        Invoke-WithProgramData -Path $fixture.ProgramData -Body {
            Assert-Equal 'Present' ([string](Test-WacLegacyControlFile -Name $script:MarkerName)) `
                ('a dangling ' + $shape + ' at the marker name was reported as no marker at all')
        }
    }
    finally {
        Remove-TestDanglingLink -Path $legacyMarker
        Remove-TestSandbox -Path $fixture.Sandbox
    }
}

Test-Case 'A store that is genuinely absent stays absent, and a normal first record still works' {
    # The other half of the same rule, and the one a fail-closed fix breaks if it stops discriminating.
    # A container proven not to be there has never held a record, so this HAS to read as absence or a
    # machine that has simply never quarantined would never clean anything again.
    $fixture = New-ControlFixture -Prefix 'r14-store-absent'
    try {
        $missing = Join-Path -Path $fixture.Sandbox -ChildPath 'NoSuchStore'
        Set-WacControlRoot -Path $missing
        try {
            Assert-Equal 'Absent' ([string](Test-WacControlStorePresence)) `
                'a store that is genuinely not there was not reported absent'
        }
        finally { Set-WacControlRoot -Path $null }

        Invoke-WithProgramData -Path $fixture.ProgramData -Body {
            Assert-Equal 'Absent' ([string](Test-WacLegacyControlFile -Name $script:MarkerName)) `
                'an empty legacy location was not reported absent'

            Use-TestControlStore -Root $fixture.Store -Body {
                Assert-Equal 'Absent' ([string](Read-WacControlFile -Name $script:MarkerName).State) `
                    'an empty store did not read as absence'
                Assert-Equal 'Created' ([string](Write-WacControlFile -Name $script:MarkerName -Content '{"a":1}').Kind) `
                    'a first record could not be written'
                Assert-Equal 'Valid' ([string](Read-WacControlFile -Name $script:MarkerName).State) `
                    'a record that was just written did not read back'
                Assert-True (Remove-WacControlFile -Name $script:MarkerName) 'a record could not be retired'
                Assert-Equal 'Absent' ([string](Read-WacControlFile -Name $script:MarkerName).State) `
                    'a retired record still reads'
            }
        }
    }
    finally { Remove-TestSandbox -Path $fixture.Sandbox }
}

# ---------------------------------------------------------------------------------------------
# The deployment records: a probe that proved nothing may not close a transaction
# ---------------------------------------------------------------------------------------------

Test-Case 'A type probe that disagrees with the enumeration leaves both records open' {
    # The discarded [void] enumeration, exercised through the readers that act on it. Nothing is on
    # disk: the enumeration is what says a name is there, and the old code computed that answer and
    # then threw it away, so a record standing under a shape neither type probe reports was closed
    # as though the transaction had never happened.
    $sandbox = New-TestSandbox -Prefix 'r14-disagree'
    try {
        $programFiles = Join-Path -Path $sandbox -ChildPath 'PF'
        [void][System.IO.Directory]::CreateDirectory($programFiles)

        Invoke-WithProgramFiles -Path $programFiles -Body {
            param($root)

            $probe = Get-DeploymentProbePath -DeploymentRoot $root
            Assert-Equal 'Absent' ([string](Read-WacDeploymentJournal -DeploymentRoot $root).State) `
                'the baseline is not an empty deployment root, so the shadow below proves nothing'

            # ONE PATH AT A TIME, and that is not tidiness. The plan reads the transaction record
            # first and refuses on it before the slot is ever probed, so a shadow covering both
            # would have the record's answer standing in for the slot's - and SlotState starts life
            # at 'Unreadable', so the slot assertion would hold without the slot probe running at
            # all. Each site has to be the only thing disagreeing when it is measured.
            Set-DeployPresenceShadow -Path @($probe.Record)
            try {
                $read = Read-WacDeploymentJournal -DeploymentRoot $root
                Assert-Equal 'Unreadable' ([string]$read.State) `
                    'a name the enumeration listed was reported as no record at all'
                Assert-True ([string]$read.Reason -match 'cannot identify') `
                    ('the refusal does not name what it found: ' + [string]$read.Reason)

                Assert-False (Remove-WacDeploymentJournal -DeploymentRoot $root) `
                    'a record that could not be ruled out was reported deleted'
            }
            finally { Remove-DeployPresenceShadow }

            Set-DeployPresenceShadow -Path @($probe.Previous)
            try {
                $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $root
                Assert-Equal 'Absent' ([string]$plan.Swap.State) `
                    'the transaction record did not answer absent, so the slot is not what refused'
                Assert-Equal 'Refuse' ([string]$plan.Verdict) `
                    ('a slot this build could not identify was reconciled anyway: ' + [string]$plan.Reason)
                Assert-Equal 'Unreadable' ([string]$plan.SlotState) ([string]$plan.Reason)
                Assert-True ([string]$plan.Reason -match 'recovery slot') `
                    ('the refusal is not about the slot: ' + [string]$plan.Reason)
            }
            finally { Remove-DeployPresenceShadow }

            Assert-Equal 'Absent' ([string](Read-WacDeploymentJournal -DeploymentRoot $root).State) `
                'the shadow outlived the case that installed it'
        }
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A directory at the record name and a file at the slot name both refuse' {
    # The two type mismatches, one each way: File.Exists is false for a directory and
    # Directory.Exists is false for a file, and each of those false answers used to mean "nothing
    # here" to the reader that acts on it.
    $sandbox = New-TestSandbox -Prefix 'r14-mismatch'
    try {
        $programFiles = Join-Path -Path $sandbox -ChildPath 'PF'
        [void][System.IO.Directory]::CreateDirectory($programFiles)

        Invoke-WithProgramFiles -Path $programFiles -Body {
            param($root)

            $probe = Get-DeploymentProbePath -DeploymentRoot $root
            [void][System.IO.Directory]::CreateDirectory($probe.Record)
            [System.IO.File]::WriteAllText($probe.Previous, 'not a directory')

            $read = Read-WacDeploymentJournal -DeploymentRoot $root
            Assert-Equal 'Unreadable' ([string]$read.State) 'a directory at the record name read as no record'
            Assert-True ([string]$read.Reason -match 'directory') ([string]$read.Reason)

            $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $root
            Assert-Equal 'Refuse' ([string]$plan.Verdict) ([string]$plan.Reason)

            Assert-False (Remove-WacDeploymentJournal -DeploymentRoot $root) `
                'a record name this build could not inspect was reported deleted'
            Assert-True ([System.IO.Directory]::Exists($probe.Record)) 'the unidentified object was deleted anyway'
            Assert-True ([System.IO.File]::Exists($probe.Previous)) 'the unidentified slot was deleted anyway'
        }
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A denied record with a readable parent, and a dangling link at its name, both refuse' {
    # Two entries whose parent lists perfectly well. Neither may be read as absence: the first is a
    # record this process cannot open, the second is a name pointing at nothing. Both leave a
    # transaction that a later run must not assume finished.
    $sandbox = New-TestSandbox -Prefix 'r14-entry'
    try {
        $programFiles = Join-Path -Path $sandbox -ChildPath 'PF'
        [void][System.IO.Directory]::CreateDirectory($programFiles)

        Invoke-WithProgramFiles -Path $programFiles -Body {
            param($root)

            $probe = Get-DeploymentProbePath -DeploymentRoot $root
            [System.IO.File]::WriteAllText($probe.Record, '{"Schema":1}')

            # The restore sits in a finally INSIDE this block. The enclosing case's variables are in
            # another scope, so a deny recorded out there would never be seen by its finally and the
            # sandbox would survive the run as an undeletable directory.
            Block-TestPathAccess -Path @($probe.Record)
            try {
                Assert-Throws { [System.IO.File]::ReadAllText($probe.Record) } -Message `
                    'the fixture did not reproduce a denied record, so nothing below is measured'

                $read = Read-WacDeploymentJournal -DeploymentRoot $root
                Assert-Equal 'Unreadable' ([string]$read.State) 'a record nobody could open read as no record'
                Assert-Equal 'Refuse' ([string](Get-WacDeploymentRecoveryPlan -DeploymentRoot $root).Verdict) `
                    'a transaction whose record could not be opened was reconciled anyway'
            }
            finally { Unblock-TestPathAccess -Path @($probe.Record) }

            [System.IO.File]::Delete($probe.Record)

            $missingTarget = Join-Path -Path $sandbox -ChildPath 'no-such-target'
            $shape = New-TestDanglingLink -Path $probe.Record -MissingTarget $missingTarget
            try {
                Assert-True ($shape -ne '') 'neither a symbolic link nor a junction could be created, so nothing is measured'
                Assert-Equal 'Unreadable' ([string](Read-WacDeploymentJournal -DeploymentRoot $root).State) `
                    ('a dangling ' + $shape + ' at the record name read as no record')

                # Retiring it is allowed - a link is an object, and deleting the link retires the
                # name - but only the LINK may go. Following it would create or delete whatever the
                # planter pointed it at.
                [void](Remove-WacDeploymentJournal -DeploymentRoot $root)
                Assert-False (Test-Path -LiteralPath $missingTarget) 'the link was followed instead of retired'
            }
            finally { Remove-TestDanglingLink -Path $probe.Record }
        }
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A deployment root whose parent does not exist is absence, not an inspection failure' {
    # The fail-SHUT half. A parent proven not to be there cannot hold a record, and reporting that
    # as "could not be read" refused every machine with nothing installed: staging refused on a
    # transaction record that could not exist, and the recovery plan refused to reconcile a slot
    # that could not exist either.
    $sandbox = New-TestSandbox -Prefix 'r14-noparent'
    try {
        $missing = Join-Path -Path $sandbox -ChildPath 'NoSuchProgramFiles'
        Assert-False ([System.IO.Directory]::Exists($missing)) 'the fixture parent exists, so nothing is measured'

        Invoke-WithProgramFiles -Path $missing -Body {
            param($root)

            $read = Read-WacDeploymentJournal -DeploymentRoot $root
            Assert-Equal 'Absent' ([string]$read.State) `
                ('a record whose parent is proven missing was not reported absent: ' + [string]$read.Reason)

            $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $root
            Assert-Equal 'None' ([string]$plan.Verdict) ([string]$plan.Reason)
            Assert-Equal 'Absent' ([string]$plan.SlotState) ([string]$plan.Reason)

            Assert-True (Remove-WacDeploymentJournal -DeploymentRoot $root) `
                'ending a transaction that never existed reported failure'
        }
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Test-Case 'A first installation onto a clean machine still installs and leaves nothing outstanding' {
    # The end-to-end guard on the whole change: every probe above answers Absent here, and that has
    # to keep meaning "go ahead". A fail-closed repair that cannot tell proven absence from an
    # unproven one turns into a machine that can never be installed on.
    Invoke-InDeploymentSandbox -Prefix 'r14-first-install' -Body {
        param($sandbox)

        $slots = Get-WacDeploymentSlotPath
        Assert-Equal 'Absent' ([string](Read-WacDeploymentJournal -DeploymentRoot $slots.Root).State) `
            'a clean machine did not read as having no transaction'

        [void](Install-WacDeployment -SourceRoot (New-TestCheckout -Path (Join-Path -Path $sandbox -ChildPath 'v1') -RunContent '# first'))

        Assert-Equal '# first' ([System.IO.File]::ReadAllText((Join-Path -Path $slots.Root -ChildPath 'Run.ps1'))) `
            'the first installation did not land'

        $plan = Get-WacDeploymentRecoveryPlan -DeploymentRoot $slots.Root
        Assert-Equal 'None' ([string]$plan.Verdict) ([string]$plan.Reason)
        Assert-Equal 'Absent' ([string]$plan.SlotState) ([string]$plan.Reason)
        Assert-Equal 'Absent' ([string](Read-WacDeploymentJournal -DeploymentRoot $slots.Root).State) `
            'a committed installation left a transaction record behind'
    }
}

Complete-TestRun
