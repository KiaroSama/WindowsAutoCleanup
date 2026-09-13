<#
.SYNOPSIS
    The pnpclean step: sweeping driver packages Windows itself reports as orphaned, and reporting
    what the driver store weighed before and after.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Drivers.psm1, which keeps the OTHER driver step - the opt-in
    prune of superseded packages through pnputil. They live apart because they are two different
    tools making two different decisions, and only the file size made that look like one subject:
    this one asks Windows which packages it considers orphaned and lets rundll32 act on the answer,
    while the prune picks candidates itself, exports a recoverable copy first, and proves each
    removal against the store afterwards. Nothing here decides what to delete.

    Get-WacDriverStoreSize travels with it because it has exactly one caller and exists for this
    step's before/after report, not as a general measurement.
#>

# ---------------------------------------------------------------------------------------------
# 2. pnpclean driver package handler
# ---------------------------------------------------------------------------------------------

function Get-WacDriverStoreSize {
    <#
    .SYNOPSIS
        File count and byte total of the driver store FileRepository.
    .DESCRIPTION
        This walks a very large tree, so it is only ever called when the caller explicitly asks for
        the measurement: taking it before AND after every pnpclean run cost real minutes for a
        diagnostic number nothing depended on.
    #>
    $repository = $null
    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        $repository = Join-Path -Path $env:SystemRoot -ChildPath 'System32\DriverStore\FileRepository'
    }

    $result = [PSCustomObject]@{ Path = $repository; Files = 0L; Bytes = 0L; Measured = $false }
    if (-not $repository -or -not (Test-Path -LiteralPath $repository -PathType Container)) { return $result }

    try {
        $info = New-Object System.IO.DirectoryInfo((Get-WacLongPath -Path $repository))
        foreach ($file in $info.EnumerateFiles('*', [System.IO.SearchOption]::AllDirectories)) {
            if (Test-WacDeadlineExpired) { return $result }
            $result.Files++
            try { $result.Bytes += [int64]$file.Length } catch { $null = $_ }
        }
        $result.Measured = $true
    }
    catch {
        Write-WacLog -Level DEBUG -Component 'PnpClean' -Message 'The driver store could not be measured.' -Data @{ error = $_.Exception.Message }
    }

    return $result
}

function Invoke-WacPnpCleanHandler {
    <#
    .SYNOPSIS
        Runs the Windows driver package cleanup handler, bounded.
    .DESCRIPTION
        rundll32.exe <System32>\pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN. This entry point has
        no Microsoft reference page at all; it is used because it is the same handler the Disk
        Cleanup 'Device Driver Packages' category invokes, and it decides for itself what is safe to
        remove instead of this tool guessing.
    #>
    [CmdletBinding()]
    param([switch]$MeasureDriverStore)

    $category = 'Device driver packages (pnpclean)'
    $component = 'PnpClean'

    $rundll32 = Get-WacSystemToolPath -Leaf 'rundll32.exe'
    $pnpclean = Get-WacSystemToolPath -Leaf 'pnpclean.dll'
    if (-not $rundll32 -or -not $pnpclean) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'rundll32.exe or pnpclean.dll was not found under System32.'))
    }

    if (-not (Test-WacIsAdministrator)) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'SafeSkip' -Detail 'The driver package cleanup handler requires administrator rights.'))
    }

    $timeoutMs = Get-WacStepTimeoutMs -RequestedMs $script:PnpCleanTimeoutMs
    if ($timeoutMs -le 0) {
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -Detail 'The run budget was exhausted before pnpclean could start.'))
    }

    $before = $null
    if ($MeasureDriverStore) { $before = Get-WacDriverStoreSize }

    $arguments = @(('{0},RunDLL_PnpClean' -f $pnpclean), '/DRIVERS', '/MAXCLEAN')
    $run = Invoke-WacProcess -FilePath $rundll32 -ArgumentList $arguments -TimeoutMs $timeoutMs -Component $component

    if ($run.TimedOut) {
        # Killed on its deadline. It may have removed packages and it may not have, and nothing here
        # can tell which - that is precisely what Incomplete means.
        return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
            -Outcome 'Incomplete' -Attempted $true -DurationMs ([int]$run.DurationMs) `
            -Detail ('pnpclean exceeded its {0} ms deadline and its process tree was terminated.' -f $timeoutMs)))
    }

    $detail = 'rundll32.exe exited with {0}.' -f $run.ExitCode

    if ($MeasureDriverStore -and $before -and $before.Measured) {
        $after = Get-WacDriverStoreSize
        if ($after.Measured) {
            $freed = [int64]($before.Bytes - $after.Bytes)
            $detail = '{0} Driver store change: {1}.' -f $detail, (Format-WacBytes -Bytes ([Math]::Max(0L, $freed)))
        }
    }

    $outcome = 'Failed'
    if ($run.ExitCode -eq 0) { $outcome = 'Succeeded' }

    # rundll32 returns as soon as it has handed the work over, so its code is the weakest of the
    # three facts available. The shared rule keeps the other two from being dropped.
    $settled = Resolve-WacSettledOutcome -Outcome $outcome -Detail $detail -Run $run

    return (Write-WacStepResult -Component $component -Result (New-WacDriverStepResult -Category $category `
        -Outcome $settled.Outcome -Attempted $true -DurationMs ([int]$run.DurationMs) -Detail $settled.Detail))
}
