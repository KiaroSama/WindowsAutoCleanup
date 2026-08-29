<#
.SYNOPSIS
    The fixed machine locations this tool reads, writes and installs into.
.DESCRIPTION
    Split out of RunState because these answer a different question. RunState owns the LIFECYCLE of
    one run - its log handle, its budget, its trust verdict - while these four answer only "where",
    from the environment, with no state and no side effect. Keeping them together also puts the two
    that differ in their trust requirement side by side, which is the comparison that matters:
    the data root cannot exclude a standard user from creating names and the backup root must.

    Each is a function rather than a constant because the environment variables are redirected by
    the test harnesses, and a value captured at import time would freeze the real machine's paths
    into every sandbox.
#>

function Get-WacDataRoot {
    <#
    .SYNOPSIS
        Machine-wide state/log root. Never inside a directory this tool cleans.
    #>
    if ($env:ProgramData) { return (Join-Path -Path $env:ProgramData -ChildPath 'WindowsAutoCleanup') }
    return (Join-Path -Path $env:SystemRoot -ChildPath 'Logs\WindowsAutoCleanup')
}

function Get-WacDeploymentRoot {
    <#
    .SYNOPSIS
        Canonical machine-wide install location for the runtime the scheduled task executes.
    #>
    if ($env:ProgramFiles) { return (Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsAutoCleanup') }
    return (Join-Path -Path $env:SystemRoot -ChildPath 'WindowsAutoCleanup')
}

function Get-WacDriverBackupRoot {
    <#
    .SYNOPSIS
        Where driver-package exports live. Deliberately NOT under the data root.
    .DESCRIPTION
        A driver backup is the only copy of a package this tool is about to delete, so the standard
        that applies to it is stricter than the one for a log: no non-administrative principal may
        create a name here at all. The data root cannot meet it. Measured on stock Windows 11,
        C:\ProgramData carries an inherited BUILTIN\Users:(CI)(WD,AD,WEA,WA) that every child
        inherits, so %ProgramData%\WindowsAutoCleanup\DriverBackup reports Writers=BUILTIN\Users on
        a perfectly healthy install and always will. %SystemRoot%\Logs does not: measured,
        Test-WacStatePathIsTrusted answers IsTrusted with Writers=[] there.

        This project may not rewrite an ACL - a test fails the build if Set-Acl, SetOwner, icacls or
        takeown reappears - so the location is the whole lever, and it is enough.

        %SystemRoot%\WindowsAutoCleanup was the other candidate and is rejected on purpose: it is
        Get-WacDeploymentRoot's own fallback, so on a host without %ProgramFiles% the backups would
        land inside the deployment tree the installer swaps out atomically on upgrade.
    #>
    return (Join-Path -Path $env:SystemRoot -ChildPath 'Logs\WindowsAutoCleanup\DriverBackup')
}

function Get-WacLegacyDriverBackupRoot {
    <#
    .SYNOPSIS
        The pre-relocation backup root, so an unresolved deletion left there is never forgotten.
    .DESCRIPTION
        Reported, never read into a decision and never written to or deleted: the reason it stopped
        being the backup root is that its trust cannot be established, and acting on a manifest
        found there would be acting on exactly the evidence that is not trustworthy. An operator
        who needs one of those exports recovers it by hand, which is the same answer this project
        already gives for a pending marker it cannot resolve.
    #>
    if (-not $env:ProgramData) { return $null }
    return (Join-Path -Path $env:ProgramData -ChildPath 'WindowsAutoCleanup\DriverBackup')
}
