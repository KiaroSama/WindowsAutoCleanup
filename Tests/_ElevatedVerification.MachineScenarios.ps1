<#
.SYNOPSIS
    The two scenarios that CHANGE THIS MACHINE - DRIVERS and CLEANMGR - and the snapshots that
    measure what they changed.

.DESCRIPTION
    Dot-sourced by Invoke-ElevatedVerification.ps1. Neither scenario is sandboxed: a real
    -PruneSupersededDrivers run removes driver packages and a real -EnableLegacyDiskCleanup run is
    not limited to the target drive, so both are gated behind their own opt-in switches in Main.

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

function Invoke-DriversScenario {
    <#
    .SYNOPSIS
        A real driver prune: every package that disappeared must have a recoverable export.
    .DESCRIPTION
        THIS SCENARIO CHANGES THE OPERATOR'S MACHINE. It is the only way to exercise
        Invoke-WacDriverPackagePrune's fail-closed contract - "export first, delete second, and
        never delete what could not be exported" - because the step refuses to do anything without
        administrator rights and a real driver store, so no unit suite can reach the contract.

        %ProgramData% is still redirected into the sandbox, so the run log AND the DriverBackup root
        land inside it. That is what makes the backup root deterministic, and it is why the sandbox
        is PRESERVED rather than deleted whenever a package really was removed: those exports are
        then the only recoverable copy, and destroying them here would break the very contract this
        scenario exists to verify.

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

    try {
        $skip = @(Get-NonSandboxCategory -Keep '')
        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        else {
            $before = Get-PublishedDriverName -TimeoutMs $script:PnpUtilProbeMs
            if (-not $before.Ok) {
                [void]$problem.Add(('refusing to start: the driver store could not be snapshotted before the run ({0})' -f $before.Reason))
            }
            else {
                $sandbox = New-VerificationSandbox -Prefix 'wac-drivers'
                $backupRoot = Join-Path -Path $sandbox -ChildPath 'PD\WindowsAutoCleanup\DriverBackup'
                [void]$evidence.Add(('driver packages before the run: {0}' -f $before.Name.Count))

                $commandLine = Get-RunChildCommandLine -MutexName (New-VerificationMutexName) `
                    -SkipCategory $skip -PruneSupersededDrivers
                $child = Start-VerificationChild -CommandLine $commandLine `
                    -Environment (Get-SandboxEnvironment -Sandbox $sandbox)
                $result = Wait-VerificationChild -Child $child -TimeoutMs $TimeoutMs
                $exitCode = $result.ExitCode

                if (-not $result.Exited) {
                    [void]$problem.Add('the child did not finish inside its wall timeout and its tree was terminated')
                }
                if ($result.ExitCode -ne 0) {
                    [void]$problem.Add(('expected exit 0, got {0}. stderr: {1}' -f (Get-RunExitDetail -ExitCode $result.ExitCode), $result.ErrorText.Trim()))
                }

                # The machine-state assertions come FIRST, on purpose. Get-SandboxLogText throws
                # on a log it cannot read, and a throw before this point would leave $keepSandbox
                # false - which would delete the sandbox that holds the only recoverable copy of
                # whatever this run had just removed from the driver store.
                $after = Get-PublishedDriverName -TimeoutMs $script:PnpUtilProbeMs
                if (-not $after.Ok) {
                    [void]$problem.Add(('the driver store could not be snapshotted after the run ({0}), so nothing about it can be asserted' -f $after.Reason))
                    # Unknown means unsafe: keep whatever was exported rather than assume nothing was.
                    $keepSandbox = $true
                    [void]$evidence.Add(('the sandbox is PRESERVED because the driver store could not be re-read: {0}' -f $backupRoot))
                }
                else {
                    $removed = @($before.Name | Where-Object { $after.Name -notcontains $_ })
                    $appeared = @($after.Name | Where-Object { $before.Name -notcontains $_ })
                    [void]$evidence.Add(('driver packages after the run: {0}; removed {1}; appeared {2}' -f `
                        $after.Name.Count, $removed.Count, $appeared.Count))

                    if ($appeared.Count -gt 0) {
                        [void]$problem.Add(('the run ADDED driver package(s), which it must never do: {0}' -f ($appeared -join ', ')))
                    }

                    if ($removed.Count -gt 0) {
                        # From here the sandbox holds the only recoverable copy of what was deleted.
                        $keepSandbox = $true
                        [void]$evidence.Add(('the sandbox is PRESERVED: {0} holds the only recoverable copy of every deleted package' -f $backupRoot))

                        $backup = @(Get-DriverBackupRecord -BackupRoot $backupRoot)
                        [void]$evidence.Add(('backup directories under {0}: {1}' -f $backupRoot, $backup.Count))
                        foreach ($broken in @($backup | Where-Object { $_.Unreadable })) {
                            [void]$problem.Add(('the backup directory {0} cannot be identified - {1}' -f $broken.Directory, $broken.Unreadable))
                        }

                        foreach ($name in $removed) {
                            $match = @($backup | Where-Object { [string]$_.DriverName -ieq $name })
                            if ($match.Count -eq 0) {
                                [void]$problem.Add(('BLOCKER: {0} left the driver store and no manifest under {1} claims it, so nothing recoverable was exported' -f $name, $backupRoot))
                                continue
                            }
                            if ($match.Count -gt 1) {
                                [void]$problem.Add(('{0} is claimed by {1} backup directories, so which one is the recoverable copy is ambiguous' -f $name, $match.Count))
                            }

                            $exported = $match[0]
                            if ($exported.FileCount -lt 1) {
                                [void]$problem.Add(('BLOCKER: the backup for {0} at {1} holds nothing but its manifest' -f $name, $exported.Directory))
                            }
                            # DeletedUtc is what tells a backup apart from an export of a package
                            # that is still installed. Empty here means the manifest still claims
                            # the package is in the store, which a restore would read as "no copy
                            # of a deleted package".
                            if (-not $exported.DeletedUtc) {
                                [void]$problem.Add(('{0} was removed from the driver store but its manifest at {1} never recorded DeletedUtc' -f $name, $exported.Directory))
                            }
                            if ($exported.FileCount -ge 1 -and $exported.DeletedUtc) {
                                [void]$evidence.Add(('{0} ({1}) deleted at {2}; {3} file(s) exported to {4}' -f `
                                    $name, $exported.OriginalName, $exported.DeletedUtc, $exported.FileCount, $exported.Directory))
                            }
                        }
                    }
                }

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
            }
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
        -Expected 'a real driver prune: exit 0, the step really ran, and every deleted package has an export' `
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
        $skip = @(Get-NonSandboxCategory -Keep '')
        $before = Get-VolumeCacheStateFlag -SageId $script:VerificationSageId

        if ($skip.Count -lt 10) {
            [void]$problem.Add(('refusing to start: only {0} allow-list categories could be disabled' -f $skip.Count))
        }
        elseif ($before.Count -eq 0) {
            [void]$problem.Add('refusing to start: no VolumeCaches handler could be read, so a restore could not be proven either way')
        }
        else {
            $absent = @($before.Keys | Where-Object { $before[$_] -ceq 'absent' })
            [void]$evidence.Add(('StateFlags{0:0000} before the run: {1} handler(s), {2} of them with no value at all' -f `
                $script:VerificationSageId, $before.Count, $absent.Count))

            $sandbox = New-VerificationSandbox -Prefix 'wac-cleanmgr'
            $commandLine = Get-RunChildCommandLine -MutexName (New-VerificationMutexName) `
                -SkipCategory $skip -EnableLegacyDiskCleanup
            $child = Start-VerificationChild -CommandLine $commandLine `
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
