#Requires -Version 5.1
<#
.SYNOPSIS
    The driver-backup hardening cases: the STRICT owner/DACL rule taken from the object's own
    handle, the three fixed-name control files against planted files, links and HARD links, both
    directory-creation race interleavings, and the pre-relocation root that must never be forgotten.

.DESCRIPTION
    pnputil.exe is never executed and no real driver is ever touched.

    WHAT IS ASSERTED HERE, AND WHAT DELIBERATELY IS NOT. The strict rule's answer on a real sandbox
    depends on WHO OWNS %TEMP%, and that differs between an unelevated developer shell and an
    elevated hosted runner - the exact shape that reads as a pass in one place and a failure in the
    other. So no case here asserts IsTrusted or Owner for a sandbox path. The rule itself is
    exercised as a PURE FUNCTION over descriptors, the inheritance defect is proved on a real
    directory by asserting only on the Writers DELTA between a parent and the child created under
    it, and the call sites are proved to ask the strict question through the judge seam. Each half
    is host-independent, and together they cover the defect end to end.

    The planted-name cases run with the suite-level judge from _DriverFixtures installed, and that
    does not soften them: a collision-failing create is refused by the KERNEL, and a link or a hard
    link is caught by what GetFileInformationByHandle reports about the opened object. Neither
    answer passes through the judge at all.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
foreach ($moduleLeaf in @('Core', 'FileSystem', 'Steps', 'Drivers')) {
    Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath ('src\WindowsAutoCleanup.{0}.psm1' -f $moduleLeaf)) `
        -Force -DisableNameChecking -ErrorAction Stop
}

$script:DriversModule = Get-Module -Name 'WindowsAutoCleanup.Drivers'

. (Join-Path -Path $PSScriptRoot -ChildPath '_DriverFixtures.ps1')

# The ancestor walk over a TEMP sandbox is genuinely untrusted on every runner, so the cases that
# are about something else answer it yes. The walk itself is measured in DriverBackup.Tests.ps1.
Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacStatePathIsTrusted' -Body {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [ValidateRange(1, 128)][int]$MaxDepth = 64
    )
    $null = $MaxDepth
    return [PSCustomObject]@{
        Path = $Path; IsTrusted = $true; Reason = 'sandbox trust forced for this suite'
        Checked = @($Path); Failures = @(); Writers = @()
    }
}

$script:PendingName = 'wac-driver-delete.pending'
$script:CommitName = $script:ManifestName + '.commit'
$script:Users = 'S-1-5-32-545'

# ---------------------------------------------------------------------------------------------
# Reaching the module's internals
# ---------------------------------------------------------------------------------------------

function Write-ControlFile {
    param([string]$Path, [string]$Name, [string]$Content)
    return (& $script:DriversModule { param($p, $n, $c) Write-WacDriverBackupControlFile -Path $p -Name $n -Content $c } $Path $Name $Content)
}

function Read-ControlFile {
    param([string]$Path, [string]$Name)
    return (& $script:DriversModule { param($p, $n) Read-WacDriverBackupControlFile -Path $p -Name $n } $Path $Name)
}

function Set-BackupDeletePending {
    param([string]$Path, [string]$DriverName)
    return (& $script:DriversModule { param($p, $d) Set-WacDriverBackupDeletePending -Path $p -DriverName $d } $Path $DriverName)
}

function Test-BackupDeletePending {
    param([string]$Path)
    return (& $script:DriversModule { param($p) Test-WacDriverBackupDeletePending -Path $p } $Path)
}

function Complete-BackupUnderTest {
    param([string]$Path, $Manifest)
    return (& $script:DriversModule { param($p, $m) Complete-WacDriverBackup -Path $p -Manifest $m } $Path $Manifest)
}

function Test-LegacyRoot {
    param([AllowEmptyString()][AllowNull()][string]$Path)
    return (& $script:DriversModule { param($p) Test-WacLegacyDriverBackupRootUnresolved -Path $p } $Path)
}

# ---------------------------------------------------------------------------------------------
# Planting the three shapes
# ---------------------------------------------------------------------------------------------

function New-PlantedName {
    <#
    .SYNOPSIS
        Puts one of the three attacker shapes at a predictable name and says whether it worked.
    .DESCRIPTION
        'File' is an ordinary planted file, which a pathname write would TRUNCATE. 'Symlink' is a
        file symlink to a sentinel outside the sandbox, which a pathname write would FOLLOW.
        'HardLink' is a second directory entry for that same sentinel - no reparse attribute, an
        ordinary final path, invisible to every check except the link count - which a pathname write
        would overwrite IN PLACE.

        Returns $false when the host refuses the shape; only the symlink can do that, and only where
        neither Developer Mode nor elevation is available.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('File', 'Symlink', 'HardLink')][string]$Shape,
        [Parameter(Mandatory = $true)][string]$Sentinel
    )

    $full = Join-Path -Path $Directory -ChildPath $Name
    if ($Shape -eq 'File') {
        [System.IO.File]::WriteAllText($full, 'planted by the test', (New-Object System.Text.UTF8Encoding($false)))
        return $true
    }

    $switch = '/H'
    if ($Shape -eq 'Symlink') { $switch = '' }
    $argument = @('/c', 'mklink')
    if ($switch) { $argument += $switch }
    $argument += @($full, $Sentinel)

    $cmd = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cmd.exe'
    [void](Invoke-WacProcess -FilePath $cmd -TimeoutMs 30000 -ArgumentList $argument)
    return (Test-Path -LiteralPath $full)
}

function New-TestSentinel {
    param([Parameter(Mandatory = $true)][string]$Path)
    [System.IO.File]::WriteAllText($Path, 'SENTINEL-BYTES', (New-Object System.Text.UTF8Encoding($false)))
    return 'SENTINEL-BYTES'
}

# ---------------------------------------------------------------------------------------------
# The strict rule, as a pure function
# ---------------------------------------------------------------------------------------------

Test-Case 'the strict rule refuses the create and write grants the relaxed rule is built to ignore' {
    <#
        THE DEFECT, stated as the two rules disagreeing. The relaxed rule asks only whether an
        existing child can be REPLACED, so it accepts every one of these; the strict rule asks
        whether a non-administrator can put anything here at all, and a driver backup needs that
        answer because it is the only copy of a package about to be deleted.

        0x100116 is what Windows really produced when this was measured on disk: WriteData,
        AppendData, WriteExtendedAttributes, WriteAttributes and SYNCHRONIZE.
    #>
    $judge = & (Get-Module WindowsAutoCleanup.Core) { $script:DirectoryTrustJudge }
    Set-WacDirectoryTrustJudge -ScriptBlock $null
    try {
        foreach ($mask in @('0x100116', '0x40000000', '0x2', '0x4', '0x10000000')) {
            $sddl = 'O:BAG:BAD:(A;;{0};;;BU)(A;;FA;;;BA)' -f $mask
            $strict = Test-WacTrustedDirectoryDescriptor -Sddl $sddl -Strict
            Assert-False $strict.IsTrusted ('the strict rule accepted BUILTIN\Users {0}: {1}' -f $mask, $strict.Reason)
            Assert-True (@($strict.Writers) -contains $script:Users) `
                ('the strict refusal of {0} never named the principal: {1}' -f $mask, (@($strict.Writers) -join ', '))
        }

        # And the relaxed rule accepts the two that are pure create/write grants, which is why it
        # could never have been the rule here. GENERIC_ALL it does catch, so it is excluded.
        foreach ($mask in @('0x100116', '0x40000000', '0x2', '0x4')) {
            $relaxed = Test-WacTrustedDirectoryDescriptor -Sddl ('O:BAG:BAD:(A;;{0};;;BU)(A;;FA;;;BA)' -f $mask)
            Assert-True $relaxed.IsTrusted ('the relaxed rule has changed and now refuses {0}, so this case is measuring the wrong thing' -f $mask)
        }

        # No false positives: a read grant, and an inherit-only grant, are both accepted. An
        # inherit-only ACE genuinely grants nothing on the object carrying it - which is exactly why
        # the parent verdict is not enough, and why the CHILD has to be asked separately.
        foreach ($sddl in @('O:BAG:BAD:(A;;0x120089;;;BU)(A;;FA;;;BA)', 'O:BAG:BAD:(A;OICIIO;0x100116;;;BU)(A;;FA;;;BA)')) {
            $verdict = Test-WacTrustedDirectoryDescriptor -Sddl $sddl -Strict
            Assert-True $verdict.IsTrusted ('the strict rule refused a descriptor that grants nothing effective: {0} / {1}' -f $sddl, $verdict.Reason)
        }

        # The owner half, and the unanswerable descriptor.
        $userOwned = Test-WacTrustedDirectoryDescriptor -Sddl 'O:S-1-5-21-1-2-3-1001G:BAD:(A;;FA;;;BA)' -Strict
        Assert-False $userOwned.IsTrusted 'the strict rule accepted a user-owned directory'
        $empty = Test-WacTrustedDirectoryDescriptor -Sddl 'O:BAG:BAD:' -Strict
        Assert-False $empty.IsTrusted 'the strict rule read an empty DACL as nobody having write access'
    }
    finally {
        Set-WacDirectoryTrustJudge -ScriptBlock $judge
    }
}

Test-Case 'the strict descriptor rule and the strict path rule use one write mask, not two' {
    <#
        Test-WacStrictAclIsAdministrative is a descriptor-level twin of Test-WacPathIsMachineTrusted,
        because that one can only be asked about a pathname and the whole point here is to ask an
        open handle. Two copies of a security rule is one copy that gets fixed and one that does not,
        so until the path-based rule delegates to the descriptor-based one the two masks are pinned
        together mechanically: an edit to either that is not made to both fails here.
    #>
    $normalize = {
        param($Text)
        $start = $Text.IndexOf('$writeRights =')
        Assert-True ($start -ge 0) 'the write mask could not be located'
        $end = $Text.IndexOf('TakeOwnership)', $start)
        Assert-True ($end -gt $start) 'the write mask does not end where it used to'
        return (($Text.Substring($start, $end - $start + 'TakeOwnership)'.Length)) -replace '\s+', ' ')
    }

    $trust = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Trust.ps1'))
    $store = [System.IO.File]::ReadAllText((Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.TrustedStore.ps1'))

    Assert-Equal (& $normalize $trust) (& $normalize $store) `
        'the strict write mask has drifted between the path rule and the descriptor rule'
    Assert-True ($store -match '0x40000000 -bor 0x10000000') 'the descriptor rule stopped looking at the generic rights'
    Assert-True ($trust -match '0x40000000 -bor 0x10000000') 'the path rule stopped looking at the generic rights'
}

# ---------------------------------------------------------------------------------------------
# The inheritance defect, on a real directory
# ---------------------------------------------------------------------------------------------

Test-Case 'an inherit-only parent ACE becomes an effective writer on the directory this call creates' {
    <#
        DEFECT 1(a), measured rather than argued. The pre-create verdict is taken on the PARENT,
        where an inherit-only ACE grants nothing and Writers is therefore empty - and the child
        created under it inherits the same mask with the inherit-only flag CLEARED. Measured on this
        machine before the fix: parent (A;OICIIO;0x100116;;;BU), child (A;OICIID;0x100116;;;BU).

        NOTHING HERE ASSERTS OWNERSHIP OR IsTrusted, deliberately. A TEMP sandbox is owned by
        whoever ran the suite, so both answers differ between an unelevated developer shell and an
        elevated runner. The Writers DELTA does not: BUILTIN\Users is absent from the parent's list
        and present in the child's on every host, which is precisely the escalation.
    #>
    $judge = & (Get-Module WindowsAutoCleanup.Core) { $script:DirectoryTrustJudge }
    Set-WacDirectoryTrustJudge -ScriptBlock $null
    $sandbox = New-TestSandbox -Prefix 'dr-inherit'
    try {
        $parent = Join-Path -Path $sandbox -ChildPath 'root'
        [void][System.IO.Directory]::CreateDirectory($parent)

        # The creating identity keeps full control or nothing below could be created at all; the
        # assertions never mention it. BUILTIN\Users gets an INHERIT-ONLY write grant, which is the
        # ACE the relaxed rule is built to ignore and the one that becomes effective one level down.
        $acl = Get-Acl -LiteralPath $parent
        $acl.SetAccessRuleProtection($true, $false)
        $me = ([Security.Principal.WindowsIdentity]::GetCurrent()).User
        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $me, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($script:Users)),
            [System.Security.AccessControl.FileSystemRights]::Write, $inherit,
            [System.Security.AccessControl.PropagationFlags]::InheritOnly,
            [System.Security.AccessControl.AccessControlType]::Allow)))
        Set-Acl -LiteralPath $parent -AclObject $acl

        $parentVerdict = Open-WacTrustedDirectory -Path $parent -RequireStrictTrust
        Close-WacTrustedDirectory -Handle $parentVerdict.Handle
        Assert-False (@($parentVerdict.Writers) -contains $script:Users) `
            ('the parent already reports BUILTIN\Users as an effective writer, so this case is not measuring inheritance: {0}' -f $parentVerdict.Sddl)

        $child = Join-Path -Path $parent -ChildPath 'DriverBackup'
        $childVerdict = Open-WacTrustedDirectory -Path $child -RequireStrictTrust
        Close-WacTrustedDirectory -Handle $childVerdict.Handle

        Assert-Equal 1 @($childVerdict.Created).Count 'the child directory was not created by this call'
        Assert-True (@($childVerdict.Writers) -contains $script:Users) `
            ('BUILTIN\Users can write into the created backup root and it was not reported: {0}' -f $childVerdict.Sddl)
        Assert-False $childVerdict.IsTrusted ('a directory BUILTIN\Users can write into was accepted: {0}' -f $childVerdict.Reason)
        # Isolate the inherited writer from the sandbox owner's independent refusal. This changes
        # only an IN-MEMORY descriptor; the real directory's owner and ACL stay untouched.
        $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($childVerdict.Sddl)
        $descriptor.Owner = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $descriptorText = $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        $strict = Test-WacTrustedDirectoryDescriptor -Sddl $descriptorText -Strict
        Assert-False $strict.IsTrusted 'the inherited writer alone must refuse the child'
        Assert-True ($strict.Reason -match $script:Users) ('the refusal never named the writer: {0}' -f $strict.Reason)

        $relaxed = Test-WacTrustedDirectoryDescriptor -Sddl $descriptorText
        Assert-False ([string]$relaxed.Reason -match $script:Users) `
            ('the relaxed rule has changed and now names BUILTIN\Users, so this comparison is stale: {0}' -f $relaxed.Reason)
    }
    finally {
        Set-WacDirectoryTrustJudge -ScriptBlock $judge
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the export path asks the strict question of the root and of every identity directory' {
    <#
        The wiring half. The judge is told WHICH rule was asked for, so a call site that quietly went
        back to the relaxed one is visible: this judge answers yes to the relaxed question and no to
        the strict one, so any refusal below can only have come from a strict ask.
    #>
    $judge = & (Get-Module WindowsAutoCleanup.Core) { $script:DirectoryTrustJudge }
    Set-WacDirectoryTrustJudge -ScriptBlock {
        param($Sddl, $Strict)
        $null = $Sddl
        if ($Strict) {
            return [PSCustomObject]@{
                IsTrusted = $false; Owner = 'S-1-5-32-544'; Writers = @('S-1-5-32-545')
                Reason = 'Non-administrative principals can create or modify content here: S-1-5-32-545'
            }
        }
        return [PSCustomObject]@{ IsTrusted = $true; Owner = 'S-1-5-32-544'; Reason = 'relaxed rule accepted' }
    }
    $sandbox = New-TestSandbox -Prefix 'dr-strictwire'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row (New-SupersededPair)) }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot `
                -LegacyBackupRoot (Join-Path -Path $sandbox -ChildPath 'no-legacy')

            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'S-1-5-32-545') ('the refusal never named the principal: {0}' -f $result.Detail)
            Assert-Equal 0 $script:StubCall.Count 'a process ran under a backup root that failed the strict rule'
        }

        # And the identity directory in its own right, with the root allowed through - in BOTH the
        # states it can be in. The refusal text says which branch produced it, so a case that only
        # ever reached one of them cannot pass for the other.
        [void][System.IO.Directory]::CreateDirectory($backupRoot)
        $driver = @(Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf' -DeviceStatus @())))[0]
        $identity = Get-WacDriverBackupIdentity -Driver $driver
        $directory = Join-Path -Path $backupRoot -ChildPath $identity.Name

        Invoke-WithStubbedTool -Body {
            $result = Export-WacDriverBackup -PnpUtil $script:PnpUtilPath -Driver $driver -BackupRoot $backupRoot
            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Reason
            Assert-True ($result.Reason -match 'could not be created and proved') `
                ('the just-created identity directory was never asked the strict question: {0}' -f $result.Reason)
            Assert-True ($result.Reason -match 'S-1-5-32-545') ('the refusal never named the principal: {0}' -f $result.Reason)
            Assert-Equal 0 @(Get-ExportCall).Count 'a package was exported into a directory that failed the strict rule'
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup directory failed the strict rule'
        }

        # The EXISTING identity directory, which reaches the strict proof down the other branch -
        # the one that runs before the residue guard is allowed to read anything.
        [void][System.IO.Directory]::CreateDirectory($directory)
        [System.IO.File]::WriteAllText((Join-Path -Path $directory -ChildPath 'planted.txt'), 'planted',
            (New-Object System.Text.UTF8Encoding($false)))

        Invoke-WithStubbedTool -Body {
            $result = Export-WacDriverBackup -PnpUtil $script:PnpUtilPath -Driver $driver -BackupRoot $backupRoot
            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Reason
            Assert-True ($result.Reason -match 'already exists') `
                ('the existing identity directory was never asked the strict question: {0}' -f $result.Reason)
            Assert-True ($result.Reason -match 'S-1-5-32-545') ('the refusal never named the principal: {0}' -f $result.Reason)
            Assert-Equal 0 @(Get-ExportCall).Count 'a package was exported into an existing directory that failed the strict rule'
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup directory failed the strict rule'
        }

        Assert-True (Test-Path -LiteralPath (Join-Path -Path $directory -ChildPath 'planted.txt')) `
            'a directory that failed the strict rule was reclaimed on the say-so of what it contained'
    }
    finally {
        Set-WacDirectoryTrustJudge -ScriptBlock $judge
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# The three predictable control names
# ---------------------------------------------------------------------------------------------

Test-Case 'no control file is ever written through a planted file, symlink or hard link' {
    <#
        DEFECT 1(c). All three names used a pathname WriteAllText, which TRUNCATES an ordinary
        planted file, FOLLOWS a symlink to wherever it points, and writes THROUGH a hard link into
        the bytes of a file somewhere else entirely. The hard link is the one a reparse check misses
        completely: it has no reparse attribute and an ordinary final path.

        The sentinel lives OUTSIDE the sandbox directory on purpose, so "the sentinel is unchanged"
        is a statement about not writing outside, not just about not writing.
    #>
    # A shape the host will not create is recorded and reported as a SKIP at the end, never passed
    # over in silence: the other shapes are still asserted first, and the case then fails the run
    # rather than reporting green over coverage nobody obtained.
    $unavailable = ''
    foreach ($name in @($script:ManifestName, $script:PendingName, $script:CommitName)) {
        foreach ($shape in @('File', 'Symlink', 'HardLink')) {
            $sandbox = New-TestSandbox -Prefix 'dr-plant'
            try {
                $outside = Join-Path -Path $sandbox -ChildPath 'outside'
                [void][System.IO.Directory]::CreateDirectory($outside)
                $sentinel = Join-Path -Path $outside -ChildPath 'sentinel.txt'
                $expected = New-TestSentinel -Path $sentinel

                $directory = Join-Path -Path $sandbox -ChildPath 'export'
                [void][System.IO.Directory]::CreateDirectory($directory)

                if (-not (New-PlantedName -Directory $directory -Name $name -Shape $shape -Sentinel $sentinel)) {
                    if ($shape -eq 'Symlink') { $unavailable = 'file symlink'; continue }
                    Assert-True $false ('{0} could not be planted as {1}' -f $name, $shape)
                }

                $written = Write-ControlFile -Path $directory -Name $name -Content 'THIS MUST NEVER LAND'
                Assert-False $written.Ok ('{0} planted as {1} was written through: {2}' -f $name, $shape, $written.Reason)

                Assert-Equal $expected ([System.IO.File]::ReadAllText($sentinel)) `
                    ('{0} planted as {1} let a write reach the sentinel outside the directory' -f $name, $shape)
                Assert-False ([System.IO.File]::ReadAllText((Join-Path -Path $directory -ChildPath $name)) -match 'THIS MUST NEVER LAND') `
                    ('{0} planted as {1} was truncated and rewritten' -f $name, $shape)
            }
            finally {
                Remove-TestSandbox -Path $sandbox
            }
        }
    }

    if ($unavailable) { Set-TestSkipped -Reason ('this host would not create a {0}, so that shape was never exercised' -f $unavailable) }
}

Test-Case 'no control file is ever read through a planted symlink or hard link' {
    <#
        The other direction, and it decides just as much: the residue guard reads the manifest and
        then RECURSIVELY DELETES the directory when it says the export never completed, and the
        reconciliation reads it to learn which package to confirm and commit. A read that follows a
        link is a decision made on a file the attacker chose.

        An ordinary planted file is deliberately NOT refused here. Its content is judged by the
        rules above it - a manifest for a different package, or one that is not JSON - and refusing
        every existing file would refuse this tool's own manifest.
    #>
    $unavailable = ''
    foreach ($shape in @('Symlink', 'HardLink')) {
        $sandbox = New-TestSandbox -Prefix 'dr-readplant'
        try {
            $outside = Join-Path -Path $sandbox -ChildPath 'outside'
            [void][System.IO.Directory]::CreateDirectory($outside)
            $sentinel = Join-Path -Path $outside -ChildPath 'sentinel.txt'
            [void](New-TestSentinel -Path $sentinel)

            $directory = Join-Path -Path $sandbox -ChildPath 'export'
            [void][System.IO.Directory]::CreateDirectory($directory)

            if (-not (New-PlantedName -Directory $directory -Name $script:ManifestName -Shape $shape -Sentinel $sentinel)) {
                if ($shape -eq 'Symlink') { $unavailable = 'file symlink'; continue }
                Assert-True $false ('the manifest name could not be planted as {0}' -f $shape)
            }

            $read = Read-ControlFile -Path $directory -Name $script:ManifestName
            Assert-Equal 'Refused' ([string]$read.Kind) ('a manifest planted as {0} was read: {1}' -f $shape, $read.Reason)
            Assert-Equal '' ([string]$read.Text) ('the content of a {0} reached the caller' -f $shape)

            # And the guard that reclaims a directory refuses to decide on it rather than reading it.
            $driver = @(Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf' -DeviceStatus @())))[0]
            $identity = Get-WacDriverBackupIdentity -Driver $driver
            $residue = Test-WacDriverBackupIsResidue -Path $directory -Identity $identity
            Assert-False $residue.IsResidue ('a directory whose manifest is a {0} was classified as reclaimable residue' -f $shape)
            Assert-True ($residue.Reason -match 'could not be read') $residue.Reason

            # A plain file at the same name IS read, so the refusal above is about the shape and not
            # about the reader having stopped working.
            $plain = Join-Path -Path $sandbox -ChildPath 'plain'
            [void][System.IO.Directory]::CreateDirectory($plain)
            [System.IO.File]::WriteAllText((Join-Path -Path $plain -ChildPath $script:ManifestName), '{"IdentityHash":"x"}',
                (New-Object System.Text.UTF8Encoding($false)))
            Assert-Equal 'Read' ([string](Read-ControlFile -Path $plain -Name $script:ManifestName).Kind) `
                'an ordinary control file could not be read at all'
        }
        finally {
            Remove-TestSandbox -Path $sandbox
        }
    }

    if ($unavailable) { Set-TestSkipped -Reason ('this host would not create a {0}, so that shape was never exercised' -f $unavailable) }
}

Test-Case 'a planted marker stops the deletion, and a planted manifest stops the commit' {
    <#
        The two orderings the brief pins, exercised against the planted names rather than against
        the happy path: the marker goes down BEFORE pnputil is asked to remove anything, so a marker
        that cannot be written is a reason not to delete at all; and the manifest becomes durable
        BEFORE any count advances, so a commit that cannot prove its own write leaves the marker
        standing and the export protected.
    #>
    $sandbox = New-TestSandbox -Prefix 'dr-order'
    try {
        $outside = Join-Path -Path $sandbox -ChildPath 'outside'
        [void][System.IO.Directory]::CreateDirectory($outside)
        $sentinel = Join-Path -Path $outside -ChildPath 'sentinel.txt'
        $expected = New-TestSentinel -Path $sentinel

        $directory = Join-Path -Path $sandbox -ChildPath 'export'
        [void][System.IO.Directory]::CreateDirectory($directory)
        [void](New-PlantedName -Directory $directory -Name $script:PendingName -Shape 'HardLink' -Sentinel $sentinel)

        Assert-False (Set-BackupDeletePending -Path $directory -DriverName 'oem1.inf') `
            'a marker was reported written over a hard link to a file outside the directory'
        Assert-Equal $expected ([System.IO.File]::ReadAllText($sentinel)) 'writing the marker reached the sentinel'
        # It still reads as pending, which is the protective answer: something is standing at the
        # name and this run cannot tell what happened here.
        Assert-True (Test-BackupDeletePending -Path $directory) 'an unreadable marker was read as no deletion attempt'

        # The commit half, in its own directory so the marker above cannot decide it.
        $second = Join-Path -Path $sandbox -ChildPath 'export2'
        [void][System.IO.Directory]::CreateDirectory($second)
        [System.IO.File]::WriteAllText((Join-Path -Path $second -ChildPath 'acme.inf'), 'abc', (New-Object System.Text.UTF8Encoding($false)))

        $driver = @(Get-WacSupersededDriver -Driver (Get-ParsedDriver -Row (New-SupersededPair)))[0]
        $identity = Get-WacDriverBackupIdentity -Driver $driver
        $manifest = New-WacDriverBackupManifest -Driver $driver -Identity $identity -File (Get-WacDriverBackupFileHash -Path $second).File
        [void](New-PlantedName -Directory $second -Name $script:ManifestName -Shape 'HardLink' -Sentinel $sentinel)
        Assert-True (Set-BackupDeletePending -Path $second -DriverName 'oem1.inf') 'the marker could not be written'

        Assert-False (Complete-BackupUnderTest -Path $second -Manifest $manifest) `
            'a commit reported success over a manifest that is a hard link to a file outside the directory'
        Assert-Equal $expected ([System.IO.File]::ReadAllText($sentinel)) 'the commit reached the sentinel'
        Assert-True (Test-BackupDeletePending -Path $second) 'a failed commit cleared the marker that protects the export'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $second -ChildPath $script:CommitName)) `
            'the refused commit left its staging file behind'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# Both creation-race interleavings
# ---------------------------------------------------------------------------------------------

Test-Case 'the identity directory is refused whether it appears before the check or after it' {
    <#
        The two interleavings, both deterministic. Neither uses a sleep or a second thread: the
        window is microseconds wide and a race a test cannot lose is not a test.

        BEFORE THE CHECK - the name already exists when the export starts, and here it is a junction
        pointing outside the backup root. The walk and the handle both refuse it, and its target must
        be untouched afterwards.

        AFTER THE CHECK, BEFORE THE CREATE - Set-WacDirectoryCreateProbe stands in exactly that
        window and creates the directory itself. The bound create is collision-failing, so the name
        comes back as STATUS_OBJECT_NAME_COLLISION and is refused rather than adopted. New-Item
        -Force, which this replaced, would have adopted it.
    #>
    $sandbox = New-TestSandbox -Prefix 'dr-race'
    $link = ''
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        [void][System.IO.Directory]::CreateDirectory($backupRoot)
        $elsewhere = Join-Path -Path $sandbox -ChildPath 'elsewhere'
        [void][System.IO.Directory]::CreateDirectory($elsewhere)
        $bystander = Join-Path -Path $elsewhere -ChildPath 'bystander.txt'
        $expected = New-TestSentinel -Path $bystander

        $driver = @(Get-ParsedDriver -Row @((New-PnpUtilRow -DriverName 'oem1.inf' -DeviceStatus @())))[0]
        $identity = Get-WacDriverBackupIdentity -Driver $driver
        $link = Join-Path -Path $backupRoot -ChildPath $identity.Name

        $cmd = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cmd.exe'
        [void](Invoke-WacProcess -FilePath $cmd -TimeoutMs 30000 -ArgumentList @('/c', 'mklink', '/J', $link, $elsewhere))
        if (-not (Test-Path -LiteralPath $link)) { Set-TestSkipped -Reason 'this filesystem refused to create a junction' }

        Invoke-WithStubbedTool -Body {
            $result = Export-WacDriverBackup -PnpUtil $script:PnpUtilPath -Driver $driver -BackupRoot $backupRoot
            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Reason
            Assert-Equal 0 @(Get-ExportCall).Count 'a package was exported through a junction planted at the identity name'
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup went through a junction'
        }
        Assert-Equal $expected ([System.IO.File]::ReadAllText($bystander)) 'the refused export wrote through the junction into its target'
        Assert-Equal 1 @(Get-ChildItem -LiteralPath $elsewhere -Force).Count 'the refused export added content through the junction'

        [System.IO.Directory]::Delete($link, $false)
        $link = ''

        # Interleaving two. The probe fires between the existence probe and the bound create, and
        # only for the identity name, so creating the backup root itself is untouched.
        Set-WacDirectoryCreateProbe -ScriptBlock {
            param($Child)
            if ([System.IO.Path]::GetFileName($Child) -ine $identity.Name) { return }
            [void][System.IO.Directory]::CreateDirectory($Child)
            [System.IO.File]::WriteAllText((Join-Path -Path $Child -ChildPath 'attacker.txt'), 'planted in the window',
                (New-Object System.Text.UTF8Encoding($false)))
        }.GetNewClosure()
        try {
            Invoke-WithStubbedTool -Body {
                $result = Export-WacDriverBackup -PnpUtil $script:PnpUtilPath -Driver $driver -BackupRoot $backupRoot
                Assert-Equal 'SecurityRefusal' $result.Outcome $result.Reason
                Assert-True ($result.Reason -match 'appeared after it was checked for') `
                    ('the directory that appeared in the window was adopted rather than refused: {0}' -f $result.Reason)
                Assert-Equal 0 @(Get-ExportCall).Count 'a package was exported into a directory that appeared in the create window'
                Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup directory appeared in the create window'
            }
        }
        finally {
            Set-WacDirectoryCreateProbe -ScriptBlock $null
        }

        $attacker = Join-Path -Path (Join-Path -Path $backupRoot -ChildPath $identity.Name) -ChildPath 'attacker.txt'
        Assert-True (Test-Path -LiteralPath $attacker) 'the refused export deleted a directory it had refused to adopt'
        Assert-Equal 'planted in the window' ([System.IO.File]::ReadAllText($attacker)) 'the refused export rewrote content it never proved'
    }
    finally {
        Set-WacDirectoryCreateProbe -ScriptBlock $null
        if ($link -and (Test-Path -LiteralPath $link)) { try { [System.IO.Directory]::Delete($link, $false) } catch { $null = $_ } }
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# The pre-relocation root
# ---------------------------------------------------------------------------------------------

Test-Case 'the pre-relocation backup root is detected, never believed, and never left silent' {
    <#
        DEFECT 1, third half. Get-WacLegacyDriverBackupRoot was declared and exported and had ZERO
        production callers, so an unresolved deletion left in the old %ProgramData% location was
        forgotten for the life of the machine while this step went on reporting clean runs over the
        top of it.

        It is now probed on every enabled run and raises the FLOOR under the outcome rather than
        replacing it, so a real refusal or failure still wins. Nothing in it is read, moved,
        committed or removed - the assertion below is that the planted manifest, which would have
        named a package to confirm and commit had anyone believed it, is byte-identical afterwards.
    #>
    $sandbox = New-TestSandbox -Prefix 'dr-legacy'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $legacy = Join-Path -Path $sandbox -ChildPath 'LegacyDriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        # An empty legacy root, and an absent one, are both benign steady states and must not
        # manufacture a non-success outcome on every run forever.
        [void][System.IO.Directory]::CreateDirectory($legacy)
        foreach ($path in @($legacy, (Join-Path -Path $sandbox -ChildPath 'never-existed'), '')) {
            $verdict = Test-LegacyRoot -Path $path
            Assert-False $verdict.Unresolved ('a benign legacy root was reported unresolved: {0} / {1}' -f $path, $verdict.Detail)
        }

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $clean = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot -LegacyBackupRoot $legacy
            Assert-Equal 'Succeeded' $clean.Outcome ('an empty legacy root made a clean run non-success: {0}' -f $clean.Detail)
            Assert-True ($clean.Detail -match 'deleted=1') $clean.Detail
        }

        # Now the state the brief is about: an unresolved deletion the old root still holds. The
        # manifest names a package and carries no DeletedUtc, which is exactly the shape that would
        # drive a commit if anything here believed it.
        $orphan = Join-Path -Path $legacy -ChildPath 'acme_1.0.0.0_deadbeefdeadbeef'
        [void][System.IO.Directory]::CreateDirectory($orphan)
        $record = '{"Schema":2,"DriverName":"oem7.inf","DeletedUtc":"","IdentityHash":"deadbeef"}'
        [System.IO.File]::WriteAllText((Join-Path -Path $orphan -ChildPath $script:ManifestName), $record,
            (New-Object System.Text.UTF8Encoding($false)))
        [System.IO.File]::WriteAllText((Join-Path -Path $orphan -ChildPath $script:PendingName), 'driver=oem7.inf',
            (New-Object System.Text.UTF8Encoding($false)))

        $verdict = Test-LegacyRoot -Path $legacy
        Assert-True $verdict.Unresolved 'a non-empty legacy root was reported as nothing to do'
        Assert-Equal 1 $verdict.EntryCount 'the legacy root was miscounted'

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            # A fresh root: the run above already committed a backup for this package, and refusing
            # to export over it is a different behaviour that would mask the one under test.
            $result = Invoke-WacDriverPackagePrune -Enabled -LegacyBackupRoot $legacy `
                -BackupRoot (Join-Path -Path $sandbox -ChildPath 'DriverBackup2')

            Assert-Equal 'Incomplete' $result.Outcome ('a run carrying unresolved legacy state reported clean: {0}' -f $result.Detail)
            Assert-False $result.Succeeded $result.Detail
            Assert-True ($result.Detail -match 'pre-relocation') ('the operator is never told where to look: {0}' -f $result.Detail)
            Assert-True ($result.Detail -match ([regex]::Escape($legacy))) ('the outcome never names the directory: {0}' -f $result.Detail)
            # Never read into a decision: oem7.inf is named only by the manifest in the legacy root,
            # and nothing may confirm, export or delete it.
            Assert-Equal 0 @($script:StubCall | Where-Object { @($_.Arguments) -contains 'oem7.inf' }).Count `
                'a package named only by the legacy root reached pnputil'
        }

        Assert-Equal $record ([System.IO.File]::ReadAllText((Join-Path -Path $orphan -ChildPath $script:ManifestName))) `
            'the legacy manifest was rewritten'
        Assert-True (Test-Path -LiteralPath (Join-Path -Path $orphan -ChildPath $script:PendingName)) `
            'the legacy pending marker was cleared by a run that may not touch it'
        Assert-Equal 1 @(Get-ChildItem -LiteralPath $legacy -Force).Count 'the legacy root was migrated or emptied'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'the manifest file list is ordered ordinally, so both hosts produce the same order' {
    # This list is compared INDEX BY INDEX when an export is verified, so its order is part of the
    # contract. Sort-Object is culture-sensitive, and the two hosts were MEASURED to disagree with
    # each other over these very names under the same en-US culture: oem-a.inf sorts 5th under
    # pwsh 7 and 7th under Windows PowerShell 5.1. A manifest written by the scheduled task under
    # one host and verified by an operator under the other would then report a path mismatch for a
    # backup whose files and hashes are all intact.
    #
    # The expected order is computed ORDINALLY in the test. Ordinal ordering is host-independent by
    # definition, so this same assertion passing under both hosts IS the cross-host proof. What it
    # does not prove: that a manifest physically written by 5.1 verifies under 7 - the harness runs
    # one host per process and never hands one process's file to another.
    $sandbox = New-TestSandbox -Prefix 'dbh-order'
    try {
        # Every name must differ by more than CASE: NTFS is case-insensitive, so OEM_b.cat and
        # oem_B.cat are one file and the list would silently come back one entry short.
        $names = @('oem_a.inf', 'oem-a.inf', 'oemA.inf', 'oem1.sys', 'oem_b.cat', 'oemZ.dll')
        foreach ($name in $names) {
            [System.IO.File]::WriteAllText((Join-Path -Path $sandbox -ChildPath $name), $name)
        }

        $hashed = Get-WacDriverBackupFileHash -Path $sandbox
        Assert-True $hashed.Ok ('the file list could not be built: ' + [string]$hashed.Reason)

        $expected = @($names)
        [array]::Sort($expected, [System.StringComparer]::OrdinalIgnoreCase)

        $actual = @($hashed.File | ForEach-Object { [string]$_.Path })
        Assert-Equal $expected.Count $actual.Count 'the file list lost or gained an entry'
        for ($i = 0; $i -lt $expected.Count; $i++) {
            Assert-Equal $expected[$i] $actual[$i] ('manifest order differs at index ' + $i + ': ' + ($actual -join ','))
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'intact legacy manifests remain valid regardless of recorded file order' {
    $sandbox = New-TestSandbox -Prefix 'dbh-legacy-order'
    try {
        foreach ($name in @('oem-a.inf', 'oem_a.inf')) {
            [System.IO.File]::WriteAllText((Join-Path $sandbox $name), $name,
                (New-Object System.Text.UTF8Encoding($false)))
        }
        $hashed = Get-WacDriverBackupFileHash -Path $sandbox
        Assert-True $hashed.Ok $hashed.Reason
        $recorded = @($hashed.File)
        [array]::Reverse($recorded)
        $manifest = [PSCustomObject]@{ File = $recorded }
        $verified = Test-WacDriverBackupIntact -Path $sandbox -Manifest $manifest
        Assert-True $verified.Intact $verified.Reason

        $manifest.File[0].Sha256 = 'invalid'
        Assert-False (Test-WacDriverBackupIntact -Path $sandbox -Manifest $manifest).Intact `
            'order-independent verification ignored a changed hash'
    }
    finally { Remove-TestSandbox -Path $sandbox }
}

Complete-TestRun
