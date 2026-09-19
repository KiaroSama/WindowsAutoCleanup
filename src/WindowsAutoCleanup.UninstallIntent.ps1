<#
.SYNOPSIS
    Durable uninstall intent, retained until task, file and older recovery records are retired.
.DESCRIPTION
    Removing files is not sufficient to end a captured registration. A crash between removal and
    evidence cleanup must never let an older install capture resurrect that registration. Only the
    uninstaller may finish this intent; installation and runtime admission refuse while it exists.
#>
function Set-WacUninstallIntent {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DeploymentRoot)

    $existing = Read-WacDeploymentJournal -DeploymentRoot $DeploymentRoot -Kind Uninstall
    if ([string]$existing.State -ceq 'Unreadable') { return $false }
    if ([string]$existing.State -ceq 'Valid') {
        return ([string](Get-WacJournalField -Record $existing.Record -Name Operation) -ceq 'Uninstall')
    }
    return (Write-WacDeploymentJournal -DeploymentRoot $DeploymentRoot -Kind Uninstall -Record ([PSCustomObject]@{
        Schema = $script:DeploymentJournalSchema
        ProjectId = $script:DeploymentProjectId
        Root = (Get-WacNormalizedPath -Path $DeploymentRoot)
        TransactionId = ([guid]::NewGuid().ToString('N'))
        Operation = 'Uninstall'
        StartedUtc = ([datetime]::UtcNow.ToString('o'))
    }))
}
