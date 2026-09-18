<#
.SYNOPSIS
    Shared infrastructure for WindowsAutoCleanup: logging, path safety, the run deadline,
    the bounded external-process runner, single-instance locking and machine-trust checks.

.DESCRIPTION
    Nothing here has a side effect until Initialize-WacRun is called. The module owns its own state
    so callers cannot corrupt it by accident, and the seams tests need (Set-WacProcessInvoker, an
    injectable mutex name, an injectable clock deadline) are explicit rather than implied.

    The implementation lives in the WindowsAutoCleanup.*.ps1 files beside this one, one per
    responsibility, and they are DOT-SOURCED rather than imported. That is measured, not stylistic.

    A nested Import-Module gives each imported file its own session state, so a function in one
    part could neither call a function in another part nor see its $script: state. Measured on both
    shipped hosts: such a cross-part call resolves only while THIS module is imported at global
    scope, because the callee is then reachable through the global fallback - and every sibling
    module (FileSystem, Targets, Steps, Drivers, Deploy) imports this one from module scope, where
    that fallback does not exist. It would therefore fail precisely where the product uses it.

    Nor is there an import order that would avoid the problem: path safety logs, the run log
    registers protected roots and asks the trust rules a question, the trust rules ask the
    environment one, and the environment logs. Those four are one cycle by construction. Dot-
    sourcing keeps them in the single session state this code already assumed, so the split is a
    file-level one and no call or $script: reference changes meaning.
#>

Set-StrictMode -Version 2.0

# Captured at import: inside a module $PSCommandPath is this .psm1 (measured on both hosts), and
# Invoke-WacBounded needs a real path to import into the runspace it creates. It has to stay in
# THIS file: inside a dot-sourced part $PSCommandPath is that part's own path, and importing a
# part into a fresh runspace would give the bounded block a fragment of the module.
$script:CoreModulePath      = $PSCommandPath

. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Native.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Path.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.TrustedStore.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Locations.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Budget.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.ControlFile.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Quarantine.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.RunState.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Process.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Environment.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsAutoCleanup.Trust.ps1')

Export-ModuleMember -Function @(
    'Initialize-WacNative',
    'Get-WacNormalizedPath', 'Get-WacLongPath', 'Get-WacTargetDrive',
    'Test-WacIsOnTargetDrive', 'Test-WacIsProtectedPath', 'Test-WacIsProtectedSubtree',
    'Test-WacIsSafeTargetPath', 'Test-WacIsWithinRoot',
    'Add-WacProtectedRoot', 'Clear-WacProtectedRoot',
    'Get-WacFinalPath', 'Test-WacPathResolvesToItself', 'Test-WacFinalPathMatches',
    'Get-WacFixedProtectedRoot', 'Test-WacIsReparsePoint',
    'Test-WacIsDeleteOnRebootAllowed', 'Register-WacDeleteOnReboot',
    'Get-WacIoFailureKind',
    'Open-WacTrustedDirectory', 'New-WacBoundFile', 'Open-WacBoundFile', 'Close-WacTrustedDirectory',
    'Test-WacTrustedDirectoryDescriptor', 'Test-WacStrictAclIsAdministrative',
    'Set-WacDirectoryCreateProbe', 'Set-WacDirectoryTrustJudge',
    'Get-WacDataRoot', 'Get-WacFallbackDataRoot', 'Get-WacDeploymentRoot', 'Get-WacDriverBackupRoot', 'Get-WacLegacyDriverBackupRoot',
    'Get-WacControlRoot', 'Set-WacControlRoot', 'Get-WacLegacyControlRoot',
    'Write-WacControlFile', 'Read-WacControlFile', 'Remove-WacControlFile', 'Test-WacLegacyControlFile',
    'Test-WacControlStorePresence',
    'Initialize-WacRun', 'Write-WacLog', 'Close-WacLog', 'Get-WacLogPath', 'Get-WacExecutionId',
    'Get-WacLogDirectory', 'Get-WacLogHealth', 'Get-WacStateTrust',
    'Set-WacLogFallbackWriter', 'Set-WacLogWriter',
    'New-WacLogFile', 'Remove-WacOldLog',
    'Set-WacDeadline', 'Get-WacRemainingMs', 'Test-WacDeadlineExpired', 'Get-WacStepTimeoutMs',
    'Reset-WacShutdownReserve', 'Get-WacShutdownReserveMs', 'Request-WacShutdownReserveMs',
    'Request-WacWaitMs',
    'Reset-WacAbandonedMutator', 'Get-WacAbandonedMutatorCount', 'Test-WacMutationAllowed',
    'Add-WacAbandonedMutator', 'Resolve-WacQuarantine', 'Get-WacQuarantineMarkerName',
    'Get-WacMachineUptimeMs', 'Test-WacMachineRestartedSince',
    'Read-WacQuarantineMarker', 'Remove-WacQuarantineMarker', 'Test-WacQuarantineProcessGone',
    'Write-WacQuarantineMarker', 'Get-WacCurrentProcessCreated',
    'ConvertTo-WacCommandLineArgument', 'ConvertTo-WacCommandLine',
    'ConvertTo-WacPowerShellLiteral', 'Get-WacRelaunchCommand', 'Get-WacRelaunchArgument',
    'Stop-WacProcessTree', 'Set-WacProcessHandleOpener',
    'Start-WacOwnedProcess', 'Get-WacOwnedTreeState', 'Set-WacOwnedProcessLauncher',
    'Set-WacOwnedProcessFault', 'Get-WacOwnedProcessRawCloseCount',
    'Wait-WacOwnedTreeQuiet', 'Set-WacOwnedRunFault',
    'Initialize-WacOwnedProcessNative',
    'Invoke-WacProcess', 'Set-WacProcessInvoker', 'Get-WacProcessInvoker', 'Invoke-WacBounded',
    'Enter-WacSingleInstance', 'Exit-WacSingleInstance',
    'Test-WacIsAdministrator', 'Test-WacIsWindowsServer', 'Test-WacSystemDriveSupported',
    'Get-WacCanonicalPowerShellHost', 'Get-WacPathPresence', 'Get-WacUserProfilePath', 'Test-WacIsRealUserProfilePath', 'Get-WacFreeBytes', 'Format-WacBytes',
    'Test-WacPathIsMachineTrusted', 'Test-WacSidIsAdministrator', 'Test-WacStatePathIsTrusted'
)
