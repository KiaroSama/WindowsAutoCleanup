#Requires -Version 5.1
<#
.SYNOPSIS
    Behavioural tests for the WindowsAutoCleanup.Drivers entry point (ledger T-6): the pnpclean
    handler, and the pruning step that must export and verify a recoverable copy before any package
    is deleted.

.DESCRIPTION
    pnputil.exe and rundll32.exe are never executed and no real driver is ever touched. Both steps
    run against Core's injected process invoker, which records every file path and argument vector,
    fabricates an export inside a disposable sandbox, and returns a canned result. The invoker and
    the forced privilege check are installed together and removed together in a finally block, so
    outside a fixture the module can only ever skip.

    The parser and the supersedence decision the pruning step consumes are covered by
    DriverInventory.Tests.ps1, and the backup primitives by DriverBackup.Tests.ps1.
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

# ---------------------------------------------------------------------------------------------
# Invoke-WacPnpCleanHandler
# ---------------------------------------------------------------------------------------------

Test-Case 'the pnpclean handler is invoked through rundll32 with only /DRIVERS and /MAXCLEAN' {
    Invoke-WithStubbedTool -StubToolPath -Body {
        $result = Invoke-WacPnpCleanHandler

        Assert-Equal 1 $script:StubCall.Count 'the pnpclean step must run exactly one process'
        Assert-Equal (Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath 'rundll32.exe') $script:StubCall[0].FilePath

        $argv = @($script:StubCall[0].Arguments)
        Assert-Equal 3 $argv.Count ('vector: {0}' -f ($argv -join ' '))
        Assert-Equal ('{0}\System32\pnpclean.dll,RunDLL_PnpClean' -f $env:SystemRoot) $argv[0]
        Assert-Equal '/DRIVERS' $argv[1]
        Assert-Equal '/MAXCLEAN' $argv[2]

        Assert-Equal 'Succeeded' $result.Outcome $result.Detail
        Assert-True $result.Succeeded $result.Detail
        Assert-False $result.Failed
        # Measuring the store walks the whole FileRepository, so it must stay opt-in.
        Assert-False ($result.Detail -match 'Driver store change') $result.Detail
    }
}

Test-Case 'a pnpclean timeout is incomplete, not a clean run, and is bounded by the step ceiling' {
    Invoke-WithStubbedTool -StubToolPath -Body {
        $script:StubResult[('{0}\System32\pnpclean.dll,RunDLL_PnpClean' -f $env:SystemRoot)] = @{ ExitCode = $null; TimedOut = $true }
        $result = Invoke-WacPnpCleanHandler

        Assert-Equal 'Incomplete' $result.Outcome $result.Detail
        Assert-True $result.Failed $result.Detail
        Assert-False $result.Succeeded
        Assert-True ($script:StubCall[0].TimeoutMs -gt 0)
        Assert-True ($script:StubCall[0].TimeoutMs -le (1000 * 60 * 120)) ('timeout was {0} ms' -f $script:StubCall[0].TimeoutMs)
    }
}

Test-Case 'a non-zero pnpclean exit code is a failure' {
    Invoke-WithStubbedTool -StubToolPath -Body {
        $script:StubResult[('{0}\System32\pnpclean.dll,RunDLL_PnpClean' -f $env:SystemRoot)] = @{ ExitCode = 2 }
        $result = Invoke-WacPnpCleanHandler

        Assert-Equal 'Failed' $result.Outcome $result.Detail
        Assert-True $result.Failed $result.Detail
        Assert-False $result.Succeeded
        Assert-True $result.Attempted
    }
}

# ---------------------------------------------------------------------------------------------
# Invoke-WacDriverPackagePrune
# ---------------------------------------------------------------------------------------------

Test-Case 'driver pruning is disabled by default and runs no process at all' {
    Invoke-WithStubbedTool -Body {
        $result = Invoke-WacDriverPackagePrune

        Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
        Assert-True $result.Skipped $result.Detail
        Assert-False $result.Attempted
        Assert-False $result.Succeeded
        Assert-Equal 0 $script:StubCall.Count 'the disabled pruning step still started a process'
    }
}

Test-Case 'pruning without a backup root is skipped before anything is enumerated' {
    Invoke-WithStubbedTool -Body {
        foreach ($result in @((Invoke-WacDriverPackagePrune -Enabled), (Invoke-WacDriverPackagePrune -Enabled -BackupRoot '   '))) {
            Assert-Equal 'SafeSkip' $result.Outcome $result.Detail
            Assert-True $result.Skipped $result.Detail
            Assert-False $result.Attempted
        }

        Assert-Equal 0 $script:StubCall.Count 'pruning enumerated the driver store with nowhere to export to'
    }
}

Test-Case 'the enumeration asks for device associations in the structured format' {
    $sandbox = New-TestSandbox -Prefix 'dr-enumargs'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row (New-SupersededPair)) }
            [void](Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot)

            $argv = @($script:StubCall[0].Arguments)
            Assert-Equal '/enum-drivers /devices /format xml' ($argv -join ' ') 'the enumeration no longer asks for device associations'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a superseded deviceless package is exported into its identity directory before it is deleted' {
    $sandbox = New-TestSandbox -Prefix 'dr-prune'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        # Computed out here, from pure functions only: a scriptblock invoked with & gets its own
        # scope, so a value assigned inside the stub body would never reach these assertions.
        $candidate = @(Get-WacSupersededDriver -Driver (ConvertFrom-WacPnpUtilDriverXml -Text $xml).Driver)[0]
        $identity = Get-WacDriverBackupIdentity -Driver $candidate

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            # Wrapped at the CALL: a one-element return unrolls to a scalar, and .Count on a scalar
            # throws under Set-StrictMode 2.0 on Windows PowerShell 5.1.
            $export = @(Get-ExportCall)
            $delete = @(Get-DeleteCall)

            Assert-Equal 1 $export.Count 'exactly one package should have been exported'
            Assert-Equal 1 $delete.Count 'exactly one package should have been deleted'
            Assert-True ($script:StubCall.IndexOf($export[0]) -lt $script:StubCall.IndexOf($delete[0])) 'the package was deleted before it was exported'

            Assert-Equal 'oem1.inf' $export[0].Arguments[1]
            Assert-Equal 2 $delete[0].Arguments.Count ('delete vector: {0}' -f ($delete[0].Arguments -join ' '))
            Assert-Equal 'oem1.inf' $delete[0].Arguments[1] 'the wrong package was deleted'

            Assert-Equal (Get-WacNormalizedPath -Path (Join-Path -Path $backupRoot -ChildPath $identity.Name)) $export[0].Arguments[2] `
                'the export directory is not the immutable package identity'

            foreach ($call in $script:StubCall) {
                Assert-Equal $script:PnpUtilPath $call.FilePath
                foreach ($forbidden in @('/force', '/uninstall', '/reboot')) {
                    Assert-False (@($call.Arguments) -ccontains $forbidden) ('{0} reached pnputil: {1}' -f $forbidden, ($call.Arguments -join ' '))
                }
                Assert-True ($call.TimeoutMs -gt 0)
                Assert-True ($call.TimeoutMs -le (1000 * 60 * 2)) ('timeout was {0} ms' -f $call.TimeoutMs)
            }

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=1 skipped=0 refused=0 incomplete=0') $result.Detail
            Assert-False $result.Failed $result.Detail
            Assert-False $result.RebootRequired
        }

        $exportDirectory = Join-Path -Path $backupRoot -ChildPath $identity.Name
        Assert-True (Test-Path -LiteralPath $exportDirectory -PathType Container) 'no export directory was created for the deleted package'
        Assert-False (Test-Path -LiteralPath (Join-Path -Path $backupRoot -ChildPath 'oem1.inf')) 'the export was still named after the recyclable oem number'

        $manifestPath = Join-Path -Path $exportDirectory -ChildPath $script:ManifestName
        Assert-True (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'the deletion left no manifest behind'

        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        Assert-Equal 'oem1.inf' $manifest.DriverName
        Assert-Equal 'oem2.inf' $manifest.Evidence.SupersededByName
        Assert-Equal 0 $manifest.Evidence.DeviceCount
        Assert-Equal 1 $manifest.FileCount
        Assert-Equal 'exported.inf' $manifest.File[0].Path
        Assert-True ($manifest.File[0].Sha256 -cmatch '^[0-9a-f]{64}$') $manifest.File[0].Sha256
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a backup collision is refused rather than overwritten' {
    # THE GUARD. oem numbers are recycled, so a directory that already carries this identity may be
    # the only recoverable copy of an earlier deletion. Refusing beats merging into it.
    $sandbox = New-TestSandbox -Prefix 'dr-collision'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)
        $driver = @(Get-WacSupersededDriver -Driver (ConvertFrom-WacPnpUtilDriverXml -Text $xml).Driver)[0]
        $identity = Get-WacDriverBackupIdentity -Driver $driver

        $existing = Join-Path -Path $backupRoot -ChildPath $identity.Name
        [void](New-Item -Path $existing -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path -Path $existing -ChildPath 'earlier.inf') -Value 'the only copy' -Encoding ASCII -NoNewline

        # What makes it the only copy is the manifest record that its package really was deleted.
        # Without that record the same directory is only this tool's own leftovers.
        $earlier = New-WacDriverBackupManifest -Driver $driver -Identity $identity `
            -File @([PSCustomObject]@{ Path = 'earlier.inf'; Bytes = 13L; Sha256 = ('a' * 64) })
        $earlier.DeletedUtc = '2020-01-01T00:00:00Z'
        Set-Content -LiteralPath (Join-Path -Path $existing -ChildPath $script:ManifestName) `
            -Value ($earlier | ConvertTo-Json -Depth 6) -Encoding ASCII

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 0 @(Get-ExportCall).Count 'a colliding identity was exported over'
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup collided'
            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
            Assert-True $result.Failed 'a refusal was reported as a clean run'
            Assert-True ($result.Detail -match 'refused=1') $result.Detail
        }

        Assert-Equal 'the only copy' (Get-Content -LiteralPath (Join-Path -Path $existing -ChildPath 'earlier.inf') -Raw) `
            'the earlier backup was modified'
        Assert-Equal 2 (@(Get-ChildItem -LiteralPath $existing -File)).Count 'the earlier backup was merged into'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a second run against the same persistent backup root is never a refusal' {
    # THE REGRESSION. Run.ps1 hands this step a PERSISTENT root under the data directory, so run 2
    # walks into whatever run 1 left behind - and nothing here clears the root between the two runs,
    # because nothing clears it on a real machine either.
    #
    # Every run-1 ending below is benign: pnputil declining the deletion is the protection working,
    # and an export that failed or was killed deleted nothing. None of them may turn the next run
    # into a SecurityRefusal, which under the run-level precedence is exit 7 on a healthy machine.
    $scenario = @(
        @{ Name = 'pnputil declined the deletion'; Key = '/delete-driver'; Canned = @{ ExitCode = 5 } },
        @{ Name = 'the export failed';             Key = '/export-driver'; Canned = @{ ExitCode = 87 } },
        @{ Name = 'the export was killed';         Key = '/export-driver'; Canned = @{ ExitCode = $null; TimedOut = $true } }
    )

    foreach ($entry in $scenario) {
        $sandbox = New-TestSandbox -Prefix 'dr-rerun'
        try {
            $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
            $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $script:StubResult[$entry['Key']] = $entry['Canned']
                $first = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-False ($first.Outcome -ceq 'SecurityRefusal') ('run 1, {0}: {1}' -f $entry['Name'], $first.Detail)
            }

            # The machine is unchanged and the next day's run enumerates the same package.
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $second = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 'Succeeded' $second.Outcome ('run 2 after {0}: {1}' -f $entry['Name'], $second.Detail)
                Assert-True ($second.Detail -match 'deleted=1 skipped=0 refused=0 incomplete=0') `
                    ('run 2 after {0}: {1}' -f $entry['Name'], $second.Detail)
                Assert-Equal 1 @(Get-ExportCall).Count ('run 2 after {0} exported nothing' -f $entry['Name'])
            }
        }
        finally {
            Remove-TestSandbox -Path $sandbox
        }
    }
}

Test-Case 'the guard keeps refusing the only copy of a package that really was deleted' {
    # The other half of the same decision: the guard has to survive the fix. A directory whose
    # manifest records a completed deletion is unrecoverable once it is overwritten. The same
    # directory without that record is a run that died before its deletion, and the package it holds
    # is still installed - which is the only reason it can be a candidate again at all.
    $sandbox = New-TestSandbox -Prefix 'dr-guard'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)
        $candidate = @(Get-WacSupersededDriver -Driver (ConvertFrom-WacPnpUtilDriverXml -Text $xml).Driver)[0]
        $identity = Get-WacDriverBackupIdentity -Driver $candidate
        $directory = Join-Path -Path $backupRoot -ChildPath $identity.Name
        $manifestPath = Join-Path -Path $directory -ChildPath $script:ManifestName

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot
            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-Equal 1 @(Get-DeleteCall).Count $result.Detail
        }

        $stamped = Get-Content -LiteralPath $manifestPath -Raw
        Assert-True ($stamped -cmatch '"DeletedUtc":\s+"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"') `
            ('the deletion was never recorded in the manifest: {0}' -f $stamped)
        Assert-True ($stamped -cmatch '"CreatedUtc":\s+"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"') `
            ('stamping the deletion rewrote CreatedUtc into another form: {0}' -f $stamped)

        # The identical package is installed again and superseded again. THAT is a real collision.
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
            Assert-Equal 0 @(Get-ExportCall).Count 'the only copy of a deleted package was exported over'
            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup collided'
            Assert-True ($result.Detail -match 'refused=1') $result.Detail
        }

        Assert-Equal 'inf-content' (Get-Content -LiteralPath (Join-Path -Path $directory -ChildPath 'exported.inf') -Raw) `
            'the only copy of the deleted package was modified'

        # Strip the record the deletion left behind: a run killed between its export and its
        # deletion leaves exactly this, and its package is still in the store. Edited as TEXT so
        # the rest of the manifest reaches the module exactly as the module itself wrote it.
        Set-Content -LiteralPath $manifestPath -Encoding ASCII `
            -Value ($stamped -replace '"DeletedUtc":\s+"[^"]*"', '"DeletedUtc":  ""')

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-Equal 1 @(Get-DeleteCall).Count 'the leftovers of an interrupted run were not reclaimed'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'two different packages that both call themselves oem5.inf get separate backups' {
    # The reuse case the oem-named directory could not survive: oem5.inf is deleted, its number is
    # handed to an unrelated package, and the next run backs that one up too.
    $sandbox = New-TestSandbox -Prefix 'dr-reuse'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $first = New-PnpUtilDriverXml -Row (New-SupersededPair -CandidateName 'oem5.inf' -KeeperName 'oem6.inf' -OriginalName 'acme.inf')
        $second = New-PnpUtilDriverXml -Row (New-SupersededPair -CandidateName 'oem5.inf' -KeeperName 'oem7.inf' -OriginalName 'widget.inf')

        foreach ($xml in @($first, $second)) {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot
                Assert-Equal 'Succeeded' $result.Outcome $result.Detail
                Assert-Equal 1 @(Get-DeleteCall).Count $result.Detail
            }
        }

        $directory = @(Get-ChildItem -LiteralPath $backupRoot -Directory)
        Assert-Equal 2 $directory.Count 'the reused oem number collapsed two packages into one backup'

        $original = @($directory | ForEach-Object {
            (Get-Content -LiteralPath (Join-Path -Path $_.FullName -ChildPath $script:ManifestName) -Raw | ConvertFrom-Json).OriginalName
        } | Sort-Object)
        Assert-Equal 'acme.inf,widget.inf' ($original -join ',')
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an export that does not match its manifest is refused before the deletion' {
    $sandbox = New-TestSandbox -Prefix 'dr-mismatch'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        # The re-hash that happens between writing the manifest and deleting the package sees a
        # different digest - which is exactly what a concurrent write to the backup would look like.
        $script:HashCall = 0
        $original = Get-ModuleFunctionBody -Module $script:DriversModule -Name 'Get-WacDriverBackupFileHash'
        Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Get-WacDriverBackupFileHash' -Body {
            param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path)
            if ([string]::IsNullOrWhiteSpace($Path)) { throw 'the export was hashed without a path' }
            $script:HashCall++
            $digest = 'a' * 64
            if ($script:HashCall -ge 2) { $digest = 'b' * 64 }
            return [PSCustomObject]@{ Ok = $true; Reason = ''; File = @([PSCustomObject]@{ Path = 'exported.inf'; Bytes = 11L; Sha256 = $digest }) }
        }

        try {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 1 @(Get-ExportCall).Count
                Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its backup no longer matched its manifest'
                Assert-Equal 'SecurityRefusal' $result.Outcome $result.Detail
                Assert-True ($result.Detail -match 'refused=1') $result.Detail
            }
        }
        finally {
            Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Get-WacDriverBackupFileHash' -Body $original
        }

        Assert-Equal 2 $script:HashCall 'the export was never re-verified against its manifest'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an export that produces no inf deletes nothing' {
    $sandbox = New-TestSandbox -Prefix 'dr-emptyexport'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        foreach ($file in @(@{}, @{ 'readme.txt' = 'not a driver' })) {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $script:StubResult['/export-driver'] = @{ ExitCode = 0; File = $file }
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its export held no driver'
                Assert-True ($result.Detail -match 'deleted=0 skipped=1') $result.Detail
            }
            # NOT cleared between iterations, on purpose: an export that produced nothing worth
            # keeping has to clean up after itself, or it becomes tomorrow's collision.
            Assert-Equal 0 (@(Get-ChildItem -LiteralPath $backupRoot -Directory)).Count `
                'an export that left no driver behind still left its directory behind'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a failed export leaves the package in place, and a timed-out export is incomplete' {
    $sandbox = New-TestSandbox -Prefix 'dr-badexport'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/export-driver'] = @{ ExitCode = 87 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted although its export failed'
            Assert-False $result.Failed $result.Detail
            Assert-True ($result.Detail -match 'deleted=0 skipped=1') $result.Detail
        }

        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $backupRoot -Directory)).Count `
            'a failed export left its directory behind for the next run to collide with'

        # Same root, deliberately not cleared: the killed export has to survive whatever the failed
        # one left, because on a real machine it would have to.
        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/export-driver'] = @{ ExitCode = $null; TimedOut = $true }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted after its export was killed'
            Assert-Equal 'Incomplete' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'incomplete=1') $result.Detail
        }

        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $backupRoot -Directory)).Count `
            'a killed export left a directory whose contents are unknown'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'no uncertain enumeration ever reaches a deletion' {
    # One table, one assertion: whatever the structured output turns out to be, if it does not prove
    # a package is superseded AND installed on nothing, nothing is exported and nothing is deleted.
    $pair = New-SupersededPair
    $uncertain = @(
        @{ Name = 'a failed enumeration';        Canned = @{ ExitCode = 1; Out = (New-PnpUtilDriverXml -Row $pair) };          Outcome = 'SafeSkip' },
        @{ Name = 'a timed-out enumeration';     Canned = @{ ExitCode = $null; TimedOut = $true; Out = (New-PnpUtilDriverXml -Row $pair) }; Outcome = 'Incomplete' },
        @{ Name = 'empty output';                Canned = @{ ExitCode = 0; Out = '' };                                        Outcome = 'SafeSkip' },
        @{ Name = 'the localized text output';   Canned = @{ ExitCode = 0; Out = "Microsoft PnP Utility`r`n`r`nPublished Name: oem1.inf" }; Outcome = 'SafeSkip' },
        @{ Name = 'truncated xml';               Canned = @{ ExitCode = 0; Out = '<PnpUtil><Driver DriverName="oem1.inf">' }; Outcome = 'SafeSkip' },
        @{ Name = 'a foreign root';              Canned = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row $pair -RootElement 'Containers') }; Outcome = 'SafeSkip' },
        @{ Name = 'no device association at all'; Canned = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row @(
                (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @()),
                (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @()))) };          Outcome = 'SafeSkip' },
        @{ Name = 'the candidate still has a device'; Canned = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row @(
                (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @('Disconnected')),
                (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @('Started')))) };  Outcome = 'Succeeded' },
        @{ Name = 'the candidate row is incomplete'; Canned = @{ ExitCode = 0; Out = (New-PnpUtilDriverXml -Row @(
                (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @() -Omit @('SignerName')),
                (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @('Started')))) };  Outcome = 'Succeeded' }
    )

    $sandbox = New-TestSandbox -Prefix 'dr-uncertain'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'

        foreach ($entry in $uncertain) {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = $entry['Canned']
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 0 @(Get-DeleteCall).Count ('{0} reached a deletion' -f $entry['Name'])
                Assert-Equal 0 @(Get-ExportCall).Count ('{0} reached an export' -f $entry['Name'])
                Assert-Equal $entry['Outcome'] $result.Outcome ('{0}: {1}' -f $entry['Name'], $result.Detail)
            }
        }

        Assert-Equal 0 (@(Get-ChildItem -LiteralPath $backupRoot -Directory)).Count 'an uncertain enumeration still created a backup directory'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'pnputil exit 259 is benign and exit 3010 is success plus RebootRequired' {
    $sandbox = New-TestSandbox -Prefix 'dr-exitcode'
    try {
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 259 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot (Join-Path -Path $sandbox -ChildPath 'b259')

            Assert-Equal 'Succeeded' $result.Outcome 'ERROR_NO_MORE_ITEMS was reported as a failure'
            Assert-False $result.Failed $result.Detail
            Assert-False $result.RebootRequired
        }

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 3010 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot (Join-Path -Path $sandbox -ChildPath 'b3010')

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True $result.RebootRequired 'a reboot-required deletion did not surface a reboot'
            Assert-False $result.Failed
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a package pnputil refuses is skipped, and a deletion timeout is incomplete' {
    $sandbox = New-TestSandbox -Prefix 'dr-refused'
    try {
        $xml = New-PnpUtilDriverXml -Row (New-SupersededPair)

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = 5 }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot (Join-Path -Path $sandbox -ChildPath 'refused')

            Assert-False $result.Failed 'a package still in use must not be a run failure'
            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True ($result.Detail -match 'deleted=0 skipped=1') $result.Detail
        }

        # The package is still installed, so its export is a copy of something, not the only copy of
        # it. Keeping it would waste the space and collide with every later run.
        Assert-Equal 0 (@(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'refused') -Directory)).Count `
            'a package pnputil declined to remove kept a backup nothing can ever recover from'

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $script:StubResult['/delete-driver'] = @{ ExitCode = $null; TimedOut = $true }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot (Join-Path -Path $sandbox -ChildPath 'killed')

            Assert-Equal 'Incomplete' $result.Outcome 'a killed pnputil was reported as a clean run'
            Assert-True $result.Failed
            Assert-False $result.Succeeded
            Assert-True ($result.Detail -match 'incomplete=1') $result.Detail
        }

        # The opposite case: whether the package survived a killed deletion is unknown, so the one
        # copy that might be all there is stays exactly where it is.
        Assert-Equal 1 (@(Get-ChildItem -LiteralPath (Join-Path -Path $sandbox -ChildPath 'killed') -Directory)).Count `
            'a killed deletion threw away the export that might be the only copy left'
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'a deadline that expires mid-prune stops the loop and reports the rest as incomplete' {
    $sandbox = New-TestSandbox -Prefix 'dr-deadline'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -DriverVersion '01/01/2020 1.0.0.0' -DeviceStatus @()),
            (New-PnpUtilRow -DriverName 'oem2.inf' -DriverVersion '01/01/2021 2.0.0.0' -DeviceStatus @()),
            (New-PnpUtilRow -DriverName 'oem3.inf' -DriverVersion '01/01/2022 3.0.0.0' -DeviceStatus @('Started'))
        )

        # Forced rather than timed: a real clock would make this case flaky, and the branch under
        # test is "what does the loop do once the budget is gone", not how long that takes.
        $originalExpired = Get-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacDeadlineExpired'
        Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacDeadlineExpired' -Body { return $true }

        try {
            Invoke-WithStubbedTool -Body {
                $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
                $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

                Assert-Equal 0 @(Get-ExportCall).Count 'the prune kept working past its deadline'
                Assert-Equal 0 @(Get-DeleteCall).Count 'a package was deleted after the deadline expired'
                Assert-Equal 'Incomplete' $result.Outcome $result.Detail
                Assert-True ($result.Detail -match 'candidates=2 deleted=0 skipped=0 refused=0 incomplete=2') $result.Detail
            }
        }
        finally {
            Set-ModuleFunctionBody -Module $script:DriversModule -Name 'Test-WacDeadlineExpired' -Body $originalExpired
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Test-Case 'an enumeration with nothing to prune succeeds and touches nothing' {
    $sandbox = New-TestSandbox -Prefix 'dr-nothing'
    try {
        $backupRoot = Join-Path -Path $sandbox -ChildPath 'DriverBackup'
        $xml = New-PnpUtilDriverXml -Row @(
            (New-PnpUtilRow -DriverName 'oem1.inf' -OriginalName 'acme.inf' -DriverVersion '03/04/2024 1.0.0.0' -DeviceStatus @('Started')),
            (New-PnpUtilRow -DriverName 'oem2.inf' -OriginalName 'widget.inf' -DriverVersion '12/07/2020 2.0.0.0' -DeviceStatus @('Started'))
        )

        Invoke-WithStubbedTool -Body {
            $script:StubResult['/enum-drivers'] = @{ ExitCode = 0; Out = $xml }
            $result = Invoke-WacDriverPackagePrune -Enabled -BackupRoot $backupRoot

            Assert-Equal 'Succeeded' $result.Outcome $result.Detail
            Assert-True $result.Attempted
            Assert-False $result.Failed
            Assert-Equal 1 $script:StubCall.Count 'a package was touched although nothing was superseded'
            Assert-True ($result.Detail -match '2 driver package\(s\) enumerated') $result.Detail
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

Complete-TestRun
