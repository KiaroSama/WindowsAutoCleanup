<#
.SYNOPSIS
    The two scenarios that CHANGE THIS MACHINE - DRIVERS and CLEANMGR - and the snapshots that
    measure what they changed.

.DESCRIPTION
    Dot-sourced by Invoke-ElevatedVerification.ps1. Neither scenario is sandboxed: a real
    -PruneSupersededDrivers run removes driver packages and a real -EnableLegacyDiskCleanup run is
    not limited to the target drive, so both are gated behind their own opt-in switches in Main.

    The driver backup root is OUTSIDE the sandbox, and this file never spells it out: it is asked
    for with the same Get-WacDriverBackupRoot the shipped code calls, and then checked against the
    root the child's own step result names. Invoke-DriversScenario carries the whole argument.

    Get-DriverBackupRecord and ConvertTo-VerificationUtcText are also lifted out of this file by AST
    and exercised against a synthetic backup root in Tests\RunSurface.Tests.ps1.
#>

# ------------------------------------------------------------------------------------------------
# Machine-state snapshots - used only by the two scenarios that change the real machine
# ------------------------------------------------------------------------------------------------

function Get-PublishedDriverName {
    <#
    .SYNOPSIS
        The published oem<n>.inf packages currently in the driver store.
    .DESCRIPTION
        Only oem<n>.inf packages can be removed by pnputil /delete-driver, and those are exactly the
        ones Get-WacSupersededDriver considers, so their names are the whole before/after diff.

        Deliberately NOT taken through the shipped ConvertFrom-WacPnpUtilCsv: a snapshot built with
        the same parser the step uses could not detect that parser going wrong. A regex over the raw
        pnputil output is independent of the CSV switch, the column names and the locale.

        Failure is reported as Ok=$false rather than as an empty set. The caller must refuse, not
        compare two empty sets and conclude that nothing was deleted.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $pnputil = Join-Path -Path $env:SystemRoot -ChildPath 'System32\pnputil.exe'
    if (-not (Test-Path -LiteralPath $pnputil -PathType Leaf)) {
        return [PSCustomObject]@{ Ok = $false; Name = @(); Reason = ('{0} does not exist' -f $pnputil) }
    }

    $run = Invoke-WacProcess -FilePath $pnputil -ArgumentList @('/enum-drivers') -TimeoutMs $TimeoutMs -Component 'Verify'
    if ($run.TimedOut) {
        return [PSCustomObject]@{ Ok = $false; Name = @(); Reason = 'pnputil /enum-drivers exceeded its deadline' }
    }
    if ($run.ExitCode -ne 0) {
        return [PSCustomObject]@{ Ok = $false; Name = @(); Reason = ('pnputil /enum-drivers exited with {0}' -f $run.ExitCode) }
    }

    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($match in ([regex]'(?i)\boem\d+\.inf\b').Matches([string]$run.StandardOutput)) {
        $name = $match.Value.ToLowerInvariant()
        if (-not $names.Contains($name)) { [void]$names.Add($name) }
    }

    return [PSCustomObject]@{ Ok = $true; Name = @($names.ToArray()); Reason = '' }
}

function Get-VolumeCacheStateFlag {
    <#
    .SYNOPSIS
        Every VolumeCaches handler's StateFlags<SageId>, with ABSENCE recorded as a state of its own.
    .DESCRIPTION
        Invoke-WacLegacyDiskCleanup writes a sage profile across the handlers and promises to put
        every one of them back exactly as it found it - including the handlers that had no
        StateFlags value at all. Nothing verified that promise on a real machine.

        The absent ones are the half that a naive check misses: storing 'absent' as a value rather
        than as a missing key is what lets the after-comparison catch a restore that left a value
        behind where there had been none. A hashtable is returned rather than a Dictionary because
        PowerShell unrolls a Dictionary on return and would hand the caller its entries instead.
    #>
    param([Parameter(Mandatory = $true)][int]$SageId)

    $keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    $valueName = 'StateFlags{0:0000}' -f $SageId
    $state = @{}

    foreach ($handler in @(Get-ChildItem -LiteralPath $keyPath -ErrorAction Stop)) {
        $name = [string](Split-Path -Leaf $handler.Name)
        $value = 'absent'
        try {
            $property = Get-ItemProperty -LiteralPath $handler.PSPath -Name $valueName -ErrorAction Stop
            $value = [string]([int]$property.$valueName)
        }
        catch {
            $value = 'absent'
        }
        $state[$name] = $value
    }

    return $state
}

function Compare-StateFlagSnapshot {
    <#
    .SYNOPSIS
        Every difference between two StateFlags snapshots, as readable lines. Empty means identical.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Before,
        [Parameter(Mandatory = $true)][hashtable]$After
    )

    $difference = New-Object 'System.Collections.Generic.List[string]'

    foreach ($name in @($Before.Keys)) {
        if (-not $After.ContainsKey($name)) {
            [void]$difference.Add(('{0}: the handler key itself disappeared' -f $name))
            continue
        }
        if ([string]$Before[$name] -cne [string]$After[$name]) {
            [void]$difference.Add(('{0}: was {1}, is now {2}' -f $name, $Before[$name], $After[$name]))
        }
    }

    foreach ($name in @($After.Keys)) {
        if (-not $Before.ContainsKey($name)) {
            [void]$difference.Add(('{0}: a handler key appeared' -f $name))
        }
    }

    return @($difference.ToArray())
}

# ------------------------------------------------------------------------------------------------
# Scenario DRIVERS - a real -PruneSupersededDrivers run (CHANGES THE MACHINE)
# ------------------------------------------------------------------------------------------------

function ConvertTo-VerificationUtcText {
    <#
    .SYNOPSIS
        A manifest timestamp as ISO-8601 UTC text, whatever ConvertFrom-Json made of it.
    .DESCRIPTION
        Measured on this project's two hosts: PowerShell 7's ConvertFrom-Json turns an ISO-8601
        string into a [datetime] and Windows PowerShell 5.1 leaves it a string, so a bare [string]
        cast yields '2026-08-24T00:00:05Z' on one host and a locale-formatted '08/24/2026
        00:00:05' on the other. Evidence that differs by host is evidence nobody can compare.
    #>
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [string]$Value
}

function Get-DriverBackupRecord {
    <#
    .SYNOPSIS
        Every wac-driver-backup.json under the backup root, with the directory holding it.
    .DESCRIPTION
        A backup directory is CONTENT-ADDRESSED - <stem>_<version>_<hash16> - because oem<n>.inf is
        a recyclable name that Windows hands to an unrelated package after a removal. So the oem
        name cannot be turned back into a path: Join-Path <backupRoot> <oem name> can never exist,
        and a check built on it reports 'no recoverable export' for every package that really was
        deleted. The manifest is the only thing that maps a directory back to the package it came
        from, so this reads that instead, and reports what it could not read rather than skipping.
    #>
    param([Parameter(Mandatory = $true)][string]$BackupRoot)

    $record = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) { return @($record.ToArray()) }

    foreach ($directory in @(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction SilentlyContinue)) {
        $manifestPath = Join-Path -Path $directory.FullName -ChildPath 'wac-driver-backup.json'
        $manifest = $null
        $unreadable = ''

        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            $unreadable = 'it holds no wac-driver-backup.json'
        }
        else {
            try { $manifest = ConvertFrom-Json ([System.IO.File]::ReadAllText($manifestPath, [System.Text.Encoding]::UTF8)) }
            catch { $unreadable = 'its manifest could not be parsed: {0}' -f $_.Exception.Message }
        }

        $driverName = ''
        $originalName = ''
        $deletedUtc = ''
        if ($manifest) {
            $property = @($manifest.PSObject.Properties.Name)
            if ($property -ccontains 'DriverName') { $driverName = [string]$manifest.DriverName }
            if ($property -ccontains 'OriginalName') { $originalName = [string]$manifest.OriginalName }
            if ($property -ccontains 'DeletedUtc') { $deletedUtc = ConvertTo-VerificationUtcText -Value $manifest.DeletedUtc }
            if (-not $driverName) { $unreadable = 'its manifest names no DriverName' }
        }

        # The manifest itself is not an export: a directory holding nothing else is not a
        # recoverable copy of anything.
        $fileCount = @(Get-ChildItem -LiteralPath $directory.FullName -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ine 'wac-driver-backup.json' }).Count

        [void]$record.Add([PSCustomObject]@{
            Directory    = $directory.FullName
            DriverName   = $driverName
            OriginalName = $originalName
            DeletedUtc   = $deletedUtc
            FileCount    = $fileCount
            Unreadable   = $unreadable
        })
    }

    return @($record.ToArray())
}

function Get-DriverBackupSnapshot {
    <#
    .SYNOPSIS
        Every backup record under a root, with "could not be read" kept apart from "holds nothing".
    .DESCRIPTION
        Get-DriverBackupRecord enumerates with -ErrorAction SilentlyContinue, so a root this
        process cannot list comes back as an empty set - which is indistinguishable from a root
        that has never held an export. The whole scenario turns on that difference: "this run
        exported nothing" is a claim, and it may only be made about a root that was really read.

        Absent is Ok, and normal. The root is created by the first export, so on a fresh machine it
        does not exist yet; Exists records that separately, which is what lets the after-snapshot
        tell "still absent" from "read, and empty".
    #>
    param([Parameter(Mandatory = $true)][string]$BackupRoot)

    if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) {
        return [PSCustomObject]@{
            Ok = $true; Exists = $false; Record = @(); Reason = 'the backup root does not exist yet'
        }
    }

    try {
        # -ErrorAction Stop on the one enumeration whose failure would hide every export at once.
        # A denied, locked or redirected root has to refuse; it must never report zero backups.
        [void]@(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction Stop)
    }
    catch {
        return [PSCustomObject]@{
            Ok = $false; Exists = $true; Record = @()
            Reason = ('it could not be listed: {0}' -f $_.Exception.Message)
        }
    }

    return [PSCustomObject]@{
        Ok = $true; Exists = $true; Reason = ''
        Record = @(Get-DriverBackupRecord -BackupRoot $BackupRoot)
    }
}

function Compare-DriverBackupSnapshot {
    <#
    .SYNOPSIS
        The after-records, each carrying an Origin of new, restamped or pre-existing.
    .DESCRIPTION
        The backup root is PERSISTENT and lives outside every sandbox, so on a machine that has run
        this scenario before it legitimately holds earlier exports. Matching a package removed NOW
        against one of those would let a backup made weeks ago vouch for today's deletion - and
        oem<n>.inf is a name Windows RE-ISSUES after a removal, so an old backup can carry the very
        name of an unrelated package this run has just deleted. Only a directory this run created
        or completed may answer for a removal.

        restamped is the one shape that shares a path with something older. Export-WacDriverBackup
        reclaims its OWN residue - an identity directory whose manifest records no completed
        deletion, so the package in it is still installed - and re-exports into the same name, so
        the copy there afterwards is this run's work. A directory that already recorded a deletion
        is refused by the export instead, so it can only ever stay pre-existing.

        A PowerShell hashtable compares string keys without case, which is the comparison a path
        needs; both sides come from the same enumeration, so the spellings agree either way.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Before,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$After
    )

    $stamp = @{}
    foreach ($record in $Before) { $stamp[[string]$record.Directory] = [string]$record.DeletedUtc }

    foreach ($record in $After) {
        $origin = 'new'
        $directory = [string]$record.Directory
        if ($stamp.ContainsKey($directory)) {
            $origin = 'pre-existing'
            if (-not $stamp[$directory] -and [string]$record.DeletedUtc) { $origin = 'restamped' }
        }
        Add-Member -InputObject $record -MemberType NoteProperty -Name 'Origin' -Value $origin -Force
    }

    return @($After)
}

function Get-LoggedDriverBackupRoot {
    <#
    .SYNOPSIS
        The backup root the CHILD says it used, read out of its own [DriverPrune] step result.
    .DESCRIPTION
        Asking Get-WacDriverBackupRoot instead of spelling the path out here removes the stale
        copy, but it does not by itself prove the child agreed. The child's environment is not this
        process's - %ProgramData%, %LOCALAPPDATA% and %TEMP% are all redirected into the sandbox -
        so a root derived from any of those would differ between the two processes while both
        called the same function and neither noticed. The step's own result line closes that gap by
        naming the root it actually used.

        Write-WacLog quotes any value containing whitespace, and the step Detail always contains
        whitespace, so it is rendered as one quoted value with backup= last inside it. A Windows
        path cannot contain a double quote, so "up to the next quote, or the end of the line" is
        exact - and it stays exact only while backup= remains the LAST field in that Detail. It has
        to stop at the quote rather than at whitespace, because a backup root may legitimately
        contain a space. Anything appended after it in Invoke-WacDriverPackagePrune's Detail
        template lands inside the captured text and turns the comparison below red; the mismatch
        message prints what was captured, so the cause is visible rather than mysterious.

        An early return names no root at all and yields an empty string; the caller decides whether
        that is benign.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text)

    foreach ($line in @(Get-MatchingLine -Text $Text -Needle '[DriverPrune] Step complete.')) {
        $match = [regex]::Match($line, '(?i)\bbackup=([^"]+)')
        if ($match.Success) { return ([string]$match.Groups[1].Value).Trim() }
    }

    return ''
}

function Add-BackupRootAgreementEvidence {
    <#
    .SYNOPSIS
        The last word on WHERE, and the only one that comes from the child rather than from this
        process: the root the scenario inspected must be the root production wrote to.
    .DESCRIPTION
        Everything else this scenario reports about backups describes $BackupRoot. This is what
        makes describing it an answer about production, rather than about a directory that merely
        has the right name in the harness's own environment - the exact failure the whole gate was
        rebuilt for.

        An early return names no root, and that is benign only while nothing was removed. When the
        store lost a package, or when the count could not be established at all (-1), a step result
        that never named its root leaves the inspection unattributable, and unattributable is not
        proven.

        Both sides go through Get-WacNormalizedPath, because a path comparison whose two sides were
        canonicalised differently is not a comparison. When the logged text cannot be normalised it
        is compared as written rather than dropped: an unnormalisable root is still evidence, and
        discarding it would silently turn a mismatch into agreement.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Evidence,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Problem,
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Text,
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [Parameter(Mandatory = $true)][int]$RemovedCount
    )

    $logged = Get-LoggedDriverBackupRoot -Text $Text
    if (-not $logged) {
        if ($RemovedCount -eq 0) {
            [void]$Evidence.Add('the step returned before naming a backup root, which every early return does; nothing above claims otherwise')
        }
        else {
            [void]$Problem.Add('the [DriverPrune] step result never named the backup root it used, so the root inspected above cannot be shown to be the one production wrote to')
        }
        return
    }

    $normalized = [string](Get-WacNormalizedPath -Path $logged)
    if (-not $normalized) { $normalized = $logged }

    if ($normalized -ieq $BackupRoot) {
        [void]$Evidence.Add(('the child recorded backup={0}, the same root this scenario snapshotted' -f $normalized))
        return
    }

    [void]$Problem.Add(('BLOCKER: the child exported to {0} while this scenario inspected {1}, so nothing it reported about backups describes what production wrote' -f `
        $normalized, $BackupRoot))
}

function Add-DriverBackupEvidence {
    <#
    .SYNOPSIS
        Reports what the backup root holds, and refuses to let a backup made earlier answer for a
        package removed now.
    .DESCRIPTION
        Every directory this run created or completed is named in the evidence as PRESERVED. That
        is a statement about what this harness does NOT do: nothing here deletes anything under the
        backup root - the finally block removes the sandbox, and the root is not inside it - and
        nothing may be added that does, because an export this run made can be the only copy of the
        package it has just deleted.

        A removal is answered only by a fresh directory. When the sole claimant pre-dates the run,
        that is reported as its own blocker rather than as "no manifest claims it": the two mean
        different things to whoever reads them, and the second would be a falsehood about a
        directory that is sitting right there.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Evidence,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Problem,
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)]$After,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Removed
    )

    if (-not $After.Ok) {
        [void]$Problem.Add(('the backup root {0} could not be read after the run ({1}), so nothing about what it holds can be asserted' -f `
            $BackupRoot, $After.Reason))
        return
    }

    $record = @(Compare-DriverBackupSnapshot -Before @($Before.Record) -After @($After.Record))
    $fresh = @($record | Where-Object { [string]$_.Origin -cne 'pre-existing' })
    $earlier = @($record | Where-Object { [string]$_.Origin -ceq 'pre-existing' })

    [void]$Evidence.Add(('backup directories under {0}: {1} in total, {2} already there before this run, {3} created or completed by it{4}' -f `
        $BackupRoot, $record.Count, $earlier.Count, $fresh.Count,
        $(if ($After.Exists) { '' } else { ' - the root does not exist' })))

    foreach ($made in $fresh) {
        [void]$Evidence.Add(('PRESERVED ({0}): {1} holds {2} exported file(s) for {3}' -f `
            $made.Origin, $made.Directory, $made.FileCount,
            $(if ($made.DriverName) { $made.DriverName } else { 'a package it does not name' })))
    }

    foreach ($broken in @($fresh | Where-Object { $_.Unreadable })) {
        [void]$Problem.Add(('the backup directory {0} cannot be identified - {1}' -f $broken.Directory, $broken.Unreadable))
    }

    foreach ($name in $Removed) {
        $match = @($fresh | Where-Object { [string]$_.DriverName -ieq $name })
        if ($match.Count -eq 0) {
            $stale = @($earlier | Where-Object { [string]$_.DriverName -ieq $name })
            if ($stale.Count -gt 0) {
                [void]$Problem.Add(('BLOCKER: {0} left the driver store, and the only manifest under {1} claiming that name was already there before this run ({2}), so THIS run exported nothing recoverable for it' -f `
                    $name, $BackupRoot, $stale[0].Directory))
            }
            else {
                [void]$Problem.Add(('BLOCKER: {0} left the driver store and no manifest under {1} claims it, so nothing recoverable was exported' -f $name, $BackupRoot))
            }
            continue
        }
        if ($match.Count -gt 1) {
            [void]$Problem.Add(('{0} is claimed by {1} backup directories this run made, so which one is the recoverable copy is ambiguous' -f $name, $match.Count))
        }

        $exported = $match[0]
        if ($exported.FileCount -lt 1) {
            [void]$Problem.Add(('BLOCKER: the backup for {0} at {1} holds nothing but its manifest' -f $name, $exported.Directory))
        }
        # DeletedUtc is what tells a backup apart from an export of a package that is still
        # installed. Empty here means the manifest still claims the package is in the store, which
        # a restore would read as "no copy of a deleted package".
        if (-not $exported.DeletedUtc) {
            [void]$Problem.Add(('{0} was removed from the driver store but its manifest at {1} never recorded DeletedUtc' -f $name, $exported.Directory))
        }
        if ($exported.FileCount -ge 1 -and $exported.DeletedUtc) {
            [void]$Evidence.Add(('{0} ({1}) deleted at {2}; {3} file(s) exported to {4} ({5})' -f `
                $name, $exported.OriginalName, $exported.DeletedUtc, $exported.FileCount, $exported.Directory, $exported.Origin))
        }
    }
}

function Invoke-DriversScenario {
    <#
    .SYNOPSIS
        A real driver prune: every package that disappeared must have an export THIS RUN made.
    .DESCRIPTION
        THIS SCENARIO CHANGES THE OPERATOR'S MACHINE. It is the only way to exercise
        Invoke-WacDriverPackagePrune's fail-closed contract - "export first, delete second, and
        never delete what could not be exported" - because the step refuses to do anything without
        administrator rights and a real driver store, so no unit suite can reach the contract.

        The exports do NOT land in the sandbox, and this file must never assume they do. That
        assumption is exactly what broke this gate: %ProgramData% is redirected into the sandbox
        and the backup root used to derive from it, so the scenario read
        PD\WindowsAutoCleanup\DriverBackup inside the sandbox. The root then moved to
        %SystemRoot%\Logs\WindowsAutoCleanup\DriverBackup, because %ProgramData% carries an
        inherited BUILTIN\Users grant that no healthy install can shed - and %SystemRoot% is the
        one root this harness must NOT redirect, so the exports stopped landing anywhere inside the
        sandbox while this file went on inspecting it.

        Two things keep that from recurring. The root is ASKED FOR, through the same
        Get-WacDriverBackupRoot that Run.ps1 calls, instead of being spelled out a second time. And
        because this process's environment is not the child's, the root it snapshotted is then
        compared with the one the child's own [DriverPrune] step result names, so a root that moves
        under a redirected variable turns this scenario red instead of silently pointing it at an
        empty directory.

        That root is persistent and shared with the machine, so a backup that was already there may
        not answer for a package removed now. Compare-DriverBackupSnapshot separates the two, and
        only a directory this run created or completed satisfies a removal.

        Nothing here deletes anything under that root, and nothing may be added that does: an
        export this run made can be the only copy of the package it has just deleted. The only
        thing the finally block removes is the sandbox, which now holds the run log and nothing
        else - and that sandbox is still KEPT after a real removal, because the log is this
        machine's own record of it.

        Every allow-list category is disabled and -ResetWindowsUpdateBase:$false is still passed, so
        the driver store is the only machine state this scenario is allowed to change.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null
    $keepSandbox = $false
    $removed = @()
    # -1 is "not known", which is not the same as none: the after-snapshot of the store can fail.
    $removedCount = -1

    try {
        # Gathered rather than nested. Every one of these has to hold before a package may be
        # deleted, and a refusal has to name which one did not.
        $refusal = New-Object 'System.Collections.Generic.List[string]'

        $backupRoot = [string](Get-WacNormalizedPath -Path (Get-WacDriverBackupRoot))
        if (-not $backupRoot) {
            [void]$refusal.Add('the path Get-WacDriverBackupRoot names could not be normalised')
        }

        $before = Get-PublishedDriverName -TimeoutMs $script:PnpUtilProbeMs
        if (-not $before.Ok) {
            [void]$refusal.Add(('the driver store could not be snapshotted before the run ({0})' -f $before.Reason))
        }

        $backupBefore = [PSCustomObject]@{ Ok = $false; Exists = $false; Record = @(); Reason = 'it was never taken' }
        if ($backupRoot) {
            $backupBefore = Get-DriverBackupSnapshot -BackupRoot $backupRoot
            if (-not $backupBefore.Ok) {
                [void]$refusal.Add(('the backup root {0} could not be read before the run ({1}), so an export found afterwards could not be told apart from one that was already there' -f `
                    $backupRoot, $backupBefore.Reason))
            }
        }

        if ($refusal.Count -gt 0) {
            foreach ($line in $refusal) { [void]$problem.Add(('refusing to start: {0}' -f $line)) }
        }
        else {
            $sandbox = New-VerificationSandbox -Prefix 'wac-drivers'
            [void]$evidence.Add(('driver packages before the run: {0}' -f $before.Name.Count))
            [void]$evidence.Add(('backup root, from Get-WacDriverBackupRoot and OUTSIDE the sandbox: {0} - {1}' -f `
                $backupRoot,
                $(if ($backupBefore.Exists) { '{0} export(s) were already there' -f @($backupBefore.Record).Count } else { 'it does not exist yet' })))

            # Recorded, not re-judged. The child applies this same verdict to this same directory
            # and refuses the whole step on anything but a trusted root with no non-administrative
            # writer, which surfaces here as exit 7; printing it saves reading the log to find out
            # why a refusal happened.
            $rootTrust = Test-WacStatePathIsTrusted -Path $backupRoot
            [void]$evidence.Add(('the backup root answers IsTrusted={0} writers=[{1}] {2}' -f `
                [bool]$rootTrust.IsTrusted, (@($rootTrust.Writers) -join ', '), [string]$rootTrust.Reason))

            # The allow-list this child gets is the injected sandbox fixture, so the only cleanup
            # targets it can name are inside the sandbox and the driver step is the one thing here
            # that touches the machine. That is stronger than the deny-list this used to pass, which
            # could only disable categories the parent was able to name.
            $commandLine = Get-RunChildCommandLine -ScriptPath (New-VerificationScratchTree -Sandbox $sandbox) `
                -MutexName (New-VerificationMutexName) -PruneSupersededDrivers
            # -AllowRealMaintenance: MACHINE scope by definition, so the launch gate is told by name.
            $child = Start-VerificationChild -CommandLine $commandLine -AllowRealMaintenance `
                -Environment (Get-SandboxEnvironment -Sandbox $sandbox)
            $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
            $exitCode = $result.ExitCode

            if (-not $result.Exited) {
                [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
            }
            if ($result.ExitCode -ne 0) {
                [void]$problem.Add(('expected exit 0, got {0}. stderr: {1}' -f (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
            }

            # The machine-state snapshots come FIRST, on purpose. Get-SandboxLogText throws on a log
            # it cannot read, and a throw before this point would leave $keepSandbox false and
            # destroy the run log of whatever this child had just deleted from the driver store.
            $after = Get-PublishedDriverName -TimeoutMs $script:PnpUtilProbeMs
            $backupAfter = Get-DriverBackupSnapshot -BackupRoot $backupRoot

            if (-not $after.Ok) {
                [void]$problem.Add(('the driver store could not be snapshotted after the run ({0}), so nothing about it can be asserted' -f $after.Reason))
                # Unknown means unsafe: keep the log of whatever this run did.
                $keepSandbox = $true
            }
            else {
                $removed = @($before.Name | Where-Object { $after.Name -notcontains $_ })
                $removedCount = $removed.Count
                $appeared = @($after.Name | Where-Object { $before.Name -notcontains $_ })
                [void]$evidence.Add(('driver packages after the run: {0}; removed {1}; appeared {2}' -f `
                    $after.Name.Count, $removed.Count, $appeared.Count))

                if ($appeared.Count -gt 0) {
                    [void]$problem.Add(('the run ADDED driver package(s), which it must never do: {0}' -f ($appeared -join ', ')))
                }

                if ($removed.Count -gt 0) {
                    # The exports themselves are outside the sandbox and are never touched here.
                    # The sandbox is kept for its run log, which is the audit record of a real
                    # deletion on this machine.
                    $keepSandbox = $true
                    [void]$evidence.Add(('the sandbox is PRESERVED for its run log, this machine''s record of a real driver deletion: {0}' -f $sandbox))
                }
            }

            Add-DriverBackupEvidence -Evidence $evidence -Problem $problem -BackupRoot $backupRoot `
                -Before $backupBefore -After $backupAfter -Removed $removed

            $text = Get-SandboxLogText -Sandbox $sandbox
            Add-ResetBaseEvidence -Evidence $evidence -Problem $problem -Text $text

            # The step logs itself whether it ran or skipped, so its absence and its default-off
            # skip are two different failures and both mean the opt-in never took effect.
            $stepLines = @(Get-MatchingLine -Text $text -Needle '[DriverPrune] Step complete.')
            if ($stepLines.Count -eq 0) {
                [void]$problem.Add('the log carries no [DriverPrune] step result at all')
            }
            else {
                [void]$evidence.Add($stepLines[0])
                if ($stepLines[0].IndexOf('disabled by default', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    [void]$problem.Add('DriverPrune reported its default-off skip, so -PruneSupersededDrivers never reached the child')
                }
            }

            Add-BackupRootAgreementEvidence -Evidence $evidence -Problem $problem -Text $text `
                -BackupRoot $backupRoot -RemovedCount $removedCount
        }
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $child
        if (-not $keepSandbox) {
            if (-not (Remove-VerificationSandbox -Path $sandbox)) {
                [void]$problem.Add(('the sandbox could not be removed: {0}' -f $sandbox))
            }
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'DRIVERS' -ExpectedExitCode 0 -Machine `
        -Expected 'a real driver prune: exit 0, the step really ran, and every deleted package has an export this run made' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}

# ------------------------------------------------------------------------------------------------
# Scenario CLEANMGR - a real -EnableLegacyDiskCleanup run (CHANGES THE MACHINE, AND NOT ONLY C:)
# ------------------------------------------------------------------------------------------------

function Invoke-CleanmgrScenario {
    <#
    .SYNOPSIS
        A real legacy Disk Cleanup run: every StateFlags value must come back exactly as it was.
    .DESCRIPTION
        THIS SCENARIO CHANGES THE OPERATOR'S MACHINE, and unlike everything else in this harness it
        is not confined to C:. cleanmgr /sagerun enumerates EVERY drive in the computer and /d is
        ignored, which is why the step is opt-in - and why this scenario asserts that the child
        logged that warning rather than trusting the step to have written it.

        Invoke-WacLegacyDiskCleanup writes StateFlags9999 across the VolumeCaches handlers and
        restores the snapshot in a finally block, "including was absent". That promise had no test.
        Snapshotting every handler before and after, with absence as a first-class state, is the
        whole point here: a restore that turned an absent value into a written 0 would look correct
        to any check that only compared the handlers that already had a value.

        9999 is Invoke-WacLegacyDiskCleanup's own default SageId and the child is launched without
        -SageId, so the profile snapshotted here is the profile the child writes.
    #>
    param([Parameter(Mandatory = $true)][int]$TimeoutMs)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $problem = New-Object 'System.Collections.Generic.List[string]'
    $exitCode = -1
    $sandbox = ''
    $child = $null

    try {
        $before = Get-VolumeCacheStateFlag -SageId $script:VerificationSageId

        if ($before.Count -eq 0) {
            [void]$problem.Add('refusing to start: no VolumeCaches handler could be read, so a restore could not be proven either way')
        }
        else {
            $absent = @($before.Keys | Where-Object { $before[$_] -ceq 'absent' })
            [void]$evidence.Add(('StateFlags{0:0000} before the run: {1} handler(s), {2} of them with no value at all' -f `
                $script:VerificationSageId, $before.Count, $absent.Count))

            $sandbox = New-VerificationSandbox -Prefix 'wac-cleanmgr'
            # The injected sandbox fixture is this child's whole allow-list, so cleanmgr's own
            # handlers are the only thing here that reaches the machine.
            $commandLine = Get-RunChildCommandLine -ScriptPath (New-VerificationScratchTree -Sandbox $sandbox) `
                -MutexName (New-VerificationMutexName) -EnableLegacyDiskCleanup
            # -AllowRealMaintenance: MACHINE scope by definition, so the launch gate is told by name.
            $child = Start-VerificationChild -CommandLine $commandLine -AllowRealMaintenance `
                -Environment (Get-SandboxEnvironment -Sandbox $sandbox)
            $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
            $exitCode = $result.ExitCode

            if (-not $result.Exited) {
                [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
            }
            if ($result.ExitCode -ne 0) {
                [void]$problem.Add(('expected exit 0, got {0}. stderr: {1}' -f (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
            }

            # The restore assertion runs FIRST: it is the machine state this scenario exists to
            # check, and Get-SandboxLogText throws on a log it cannot read, which would otherwise
            # skip it entirely.
            $after = Get-VolumeCacheStateFlag -SageId $script:VerificationSageId
            $difference = @(Compare-StateFlagSnapshot -Before $before -After $after)
            if ($difference.Count -gt 0) {
                foreach ($line in $difference) {
                    [void]$problem.Add(('the sage profile was NOT restored exactly - {0}' -f $line))
                }
            }
            else {
                [void]$evidence.Add(('StateFlags{0:0000} restored exactly across all {1} handler(s), the {2} absent one(s) included' -f `
                    $script:VerificationSageId, $after.Count, $absent.Count))
            }

            $text = Get-SandboxLogText -Sandbox $sandbox
            Add-ResetBaseEvidence -Evidence $evidence -Problem $problem -Text $text

            $stepLines = @(Get-MatchingLine -Text $text -Needle '[DiskCleanup] Step complete.')
            if ($stepLines.Count -eq 0) {
                [void]$problem.Add('the log carries no [DiskCleanup] step result at all')
            }
            else {
                [void]$evidence.Add($stepLines[0])
                if ($stepLines[0].IndexOf('disabled by default', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    [void]$problem.Add('DiskCleanup reported its default-off skip, so -EnableLegacyDiskCleanup never reached the child')
                }
            }

            [void](Add-LogEvidence -Evidence $evidence -Problem $problem -Text $text `
                -Needle 'enumerates EVERY drive in this computer')
        }
    }
    catch {
        [void]$problem.Add(('the scenario threw: {0}' -f $_.Exception.Message))
    }
    finally {
        Stop-VerificationChild -Child $child
        if (-not (Remove-VerificationSandbox -Path $sandbox)) {
            [void]$problem.Add(('the sandbox could not be removed: {0}' -f $sandbox))
        }
    }

    $watch.Stop()
    return (New-ScenarioRecord -Name 'CLEANMGR' -ExpectedExitCode 0 -Machine `
        -Expected 'a real cleanmgr /sagerun: exit 0, the every-drive warning logged, and every StateFlags value restored exactly' `
        -ActualExitCode $exitCode -Evidence @($evidence.ToArray()) -Problem @($problem.ToArray()) `
        -DurationMs ([int]$watch.Elapsed.TotalMilliseconds))
}
