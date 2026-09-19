<#
.SYNOPSIS
    Whether the deployment this runtime executes from is the settled result of a finished
    installation, or one half of a generation that never closed (ledger WAC-02R).

.DESCRIPTION
    An installation has two halves - the tree at the deployment root and the scheduled registration
    that runs it - and they are made coherent by one generation, recorded durably beside the root
    while that generation is in flight and deleted when it commits. A record still standing there
    therefore means exactly one thing: some process started a deployment operation and did not
    finish it, so nothing on this machine has established that the tree and the registration belong
    to each other.

    The runtime used to ask nothing about that. A scheduled cleanup fires on its trigger whatever
    state the last installer left, so an upgrade killed between its two halves was followed, hours
    later, by a SYSTEM-privileged run that deleted files under an authority nobody had reconciled -
    task A's schedule executing tree B, with the run's own audit log recording it as an ordinary
    successful night. The refusal is cheap and the window is small; the run it prevents is neither.

    Dot-sourced by WindowsAutoCleanup.Core.psm1 rather than by the deployment module, because the
    runtime deliberately does not import the installer's module: Run.ps1 loads Core and the step
    modules only. This file therefore answers the question from the paths alone, and never reads,
    parses, believes or writes the records themselves - an unfinished generation is reconciled by an
    installer under the common lock, not by a cleanup run that happens to notice one.
#>

# The two durable records a deployment operation leaves BESIDE its root, named here rather than
# imported for the reason above. WindowsAutoCleanup.DeploymentJournal.ps1 owns the originals;
# DeploymentFence.Tests.ps1 parses both files and fails if the two ever drift, which is the guard
# the operation-lock name already carries between this module and Run.ps1.
$script:FenceRecordSuffix = @('.transaction.json', '.taskcapture.json', '.uninstall.json')

function Test-WacDeploymentGenerationSettled {
    <#
    .SYNOPSIS
        $true only when NO deployment transaction is outstanding beside the deployment root.
    .DESCRIPTION
        Absent is the only answer that settles anything. 'Unresolved' - the path could not be read -
        is not absence and is not treated as one: that is the same distinction the rest of this
        project is built on, and the direction it fails in costs a night's cleanup rather than a
        mutation made under an authority that was never established.
    .OUTPUTS
        Settled, Reason and Outstanding (the record paths that answered).
    #>
    param([AllowNull()][AllowEmptyString()][string]$DeploymentRoot)

    $result = [PSCustomObject]@{ Settled = $false; Reason = ''; Outstanding = @() }

    if ([string]::IsNullOrWhiteSpace($DeploymentRoot)) { $DeploymentRoot = Get-WacDeploymentRoot }
    $root = Get-WacNormalizedPath -Path $DeploymentRoot
    if ([string]::IsNullOrWhiteSpace([string]$root)) {
        $result.Reason = 'the deployment root could not be resolved, so whether an installation is still outstanding could not be established'
        return $result
    }

    $present = New-Object 'System.Collections.Generic.List[string]'
    $unreadable = New-Object 'System.Collections.Generic.List[string]'
    foreach ($suffix in $script:FenceRecordSuffix) {
        $path = [string]$root + [string]$suffix
        switch ([string](Get-WacPathPresence -Path $path)) {
            'Absent' { }
            'Present' { [void]$present.Add($path) }
            default { [void]$unreadable.Add($path) }
        }
    }

    if ($present.Count -gt 0) {
        $result.Outstanding = @($present.ToArray())
        $result.Reason = ('an installation left a transaction record beside this deployment, so nothing has established that the tree and the registration that runs it belong to the same generation: {0}' -f
            (@($present.ToArray()) -join ', '))
        return $result
    }

    if ($unreadable.Count -gt 0) {
        $result.Outstanding = @($unreadable.ToArray())
        $result.Reason = ('whether an installation left a transaction outstanding could not be read, which is not the same as none: {0}' -f
            (@($unreadable.ToArray()) -join ', '))
        return $result
    }

    $result.Settled = $true
    $result.Reason = 'no deployment transaction is outstanding beside this deployment.'
    return $result
}