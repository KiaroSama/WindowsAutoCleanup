#Requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '..')).Path

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) { throw $Message }
}

function Assert-Matches {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Text -notmatch $Pattern) { throw $Message }
}

function Assert-NotMatches {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Text -match $Pattern) { throw $Message }
}

function ConvertFrom-PowerShellFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        $messages = $parseErrors | ForEach-Object { '{0}: {1}' -f $_.Extent.StartLineNumber, $_.Message }
        throw "PowerShell parse failed for $Path`n$($messages -join "`n")"
    }

    return $ast
}

$mainScript = Join-Path -Path $repoRoot -ChildPath 'Run.ps1'
$installerScript = Join-Path -Path $repoRoot -ChildPath 'Install-WindowsAutoCleanupTask.ps1'
$uninstallerScript = Join-Path -Path $repoRoot -ChildPath 'Uninstall-WindowsAutoCleanupTask.ps1'
$readmePath = Join-Path -Path $repoRoot -ChildPath 'README.md'

$mainAst = ConvertFrom-PowerShellFile -Path $mainScript
[void](ConvertFrom-PowerShellFile -Path $installerScript)
[void](ConvertFrom-PowerShellFile -Path $uninstallerScript)

$mainText = Get-Content -LiteralPath $mainScript -Raw
$installerText = Get-Content -LiteralPath $installerScript -Raw
$uninstallerText = Get-Content -LiteralPath $uninstallerScript -Raw
$readmeText = Get-Content -LiteralPath $readmePath -Raw

Assert-Matches -Text $mainText -Pattern "'Thumbnail Cache'" -Message 'Disk Cleanup should enable the Thumbnail Cache category.'
Assert-Matches -Text $mainText -Pattern "'D3D Shader Cache'" -Message 'Disk Cleanup should enable the DirectX Shader Cache category.'
Assert-Matches -Text $mainText -Pattern 'thumbcache_\*\.db' -Message 'Main cleanup script should clear thumbnail cache database files.'
Assert-Matches -Text $mainText -Pattern 'iconcache_\*\.db' -Message 'Main cleanup script should clear icon cache database files counted by Disk Cleanup thumbnails.'
Assert-NotMatches -Text $mainText -Pattern 'ExplorerStartupLog|AutomaticDestinations|CustomDestinations|TypedPaths' -Message 'Main cleanup script must not clear File Explorer history, Quick Access state, or startup logs.'
Assert-NotMatches -Text $mainText -Pattern 'Stop-Process\s+.*explorer|taskkill(\.exe)?\s+.*explorer|Restart-Computer' -Message 'Main cleanup script must not restart File Explorer or reboot the computer.'
Assert-Matches -Text $readmeText -Pattern 'Windows Explorer shell cache files counted by Disk Cleanup' -Message 'README should document thumbnail/icon cache cleanup.'

foreach ($scriptText in @($mainText, $installerText, $uninstallerText)) {
    Assert-Matches -Text $scriptText -Pattern 'Get-Command\s+-Name\s+''pwsh\.exe''' -Message 'Scripts must prefer PowerShell 7 when it is installed.'
    Assert-Matches -Text $scriptText -Pattern 'Get-Command\s+-Name\s+''wt\.exe''' -Message 'Manual elevation paths must prefer Windows Terminal when available.'
    Assert-Matches -Text $scriptText -Pattern '-Verb\s+RunAs' -Message 'Manual launches must self-elevate with RunAs.'
}

foreach ($scriptText in @($installerText, $uninstallerText)) {
    Assert-Matches -Text $scriptText -Pattern '-PassThru\s+-Wait|-Wait\s+-PassThru' -Message 'Installer and uninstaller should wait for elevated child processes and return their exit code.'
}

Assert-Matches -Text $installerText -Pattern '-WindowStyle\s+Hidden' -Message 'Scheduled task action must use a hidden PowerShell window.'
Assert-Matches -Text $installerText -Pattern '-RunLevel\s+Highest' -Message 'Scheduled task principal must use highest privileges.'
Assert-Matches -Text $installerText -Pattern '(?s)New-ScheduledTaskSettingsSet.*-Hidden' -Message 'Scheduled task settings must be marked Hidden.'
Assert-Matches -Text $installerText -Pattern '(?s)New-ScheduledTaskSettingsSet.*-Compatibility\s+Win8' -Message 'Scheduled task compatibility must use the highest compatibility exposed by the ScheduledTasks module.'
Assert-Matches -Text $installerText -Pattern '\$TaskPath\s+=\s+''\\''' -Message 'Installer must register the task under an explicit root TaskPath.'
Assert-Matches -Text $installerText -Pattern 'Register-ScheduledTask.*-TaskPath\s+\$TaskPath' -Message 'Installer must pass the explicit TaskPath when registering.'
Assert-Matches -Text $installerText -Pattern 'registeredHidden' -Message 'Installer must verify Hidden after registration.'
Assert-Matches -Text $installerText -Pattern 'registeredRunLevel' -Message 'Installer must verify Highest run level after registration.'
Assert-Matches -Text $installerText -Pattern 'registeredCompatibility' -Message 'Installer must verify task compatibility after registration.'
Assert-Matches -Text $installerText -Pattern 'registeredActionExecute' -Message 'Installer must verify the registered action executable.'
Assert-Matches -Text $installerText -Pattern '\[switch\]\$NoPause' -Message 'Installer must support -NoPause for automation.'
Assert-Matches -Text $mainText -Pattern '\[switch\]\$ResetWindowsUpdateBase\s*=\s*\$true' -Message 'Main script must enable DISM ResetBase mode by default.'
Assert-Matches -Text $mainText -Pattern '/ResetBase' -Message 'Main script must pass /ResetBase when ResetWindowsUpdateBase is enabled.'
Assert-Matches -Text $mainText -Pattern 'DiskCleanupTimeoutMs\s*=\s*1000\s*\*\s*60\s*\*\s*5' -Message 'cleanmgr must use a short timeout because it is a legacy optional cleanup path.'
Assert-Matches -Text $mainText -Pattern 'Where-Object\s*\{\s*\$_\s+-ne\s+''Update Cleanup''\s*\}' -Message 'cleanmgr Update Cleanup must be skipped when DISM ResetBase is enabled.'
Assert-Matches -Text $mainText -Pattern 'function\s+Test-IsWindowsServer' -Message 'Main script must detect Windows Server builds.'
Assert-Matches -Text $mainText -Pattern 'Skipping cleanmgr\.exe on Windows Server' -Message 'cleanmgr must be skipped by default on Windows Server.'
Assert-Matches -Text $mainText -Pattern 'legacy Disk Cleanup step was skipped[\s\S]*\$stats\.Skipped\+\+' -Message 'cleanmgr timeouts should be treated as skipped legacy cleanup, not a failed run.'
Assert-Matches -Text $mainText -Pattern 'Invoke-ComponentCleanup[\s\S]*Invoke-DiskCleanup' -Message 'DISM component cleanup must run before cleanmgr.'
Assert-Matches -Text $installerText -Pattern '\[switch\]\$ResetWindowsUpdateBase\s*=\s*\$true' -Message 'Installer must enable ResetWindowsUpdateBase in the scheduled task by default.'
Assert-Matches -Text $installerText -Pattern 'childArgs.*-DailyRunTime' -Message 'Installer self-elevation must preserve -DailyRunTime.'
Assert-Matches -Text $mainText -Pattern 'childArgs.*-ResetWindowsUpdateBase:' -Message 'Main script self-elevation must preserve explicit ResetWindowsUpdateBase true/false values.'
Assert-Matches -Text $installerText -Pattern 'childArgs.*-ResetWindowsUpdateBase:' -Message 'Installer self-elevation must preserve explicit ResetWindowsUpdateBase true/false values.'
Assert-Matches -Text $installerText -Pattern 'childArgs.*-NoPause' -Message 'Installer self-elevation must preserve -NoPause.'
Assert-Matches -Text $installerText -Pattern 'taskArguments.*-ResetWindowsUpdateBase:' -Message 'Installer must always add the explicit ResetWindowsUpdateBase true/false value to the scheduled action.'
Assert-Matches -Text $mainText -Pattern '\[switch\]\$SkipAclHardening' -Message 'Main script must support -SkipAclHardening for development checkouts.'
Assert-Matches -Text $installerText -Pattern '\[switch\]\$SkipAclHardening' -Message 'Installer must support -SkipAclHardening for scheduled runs.'
Assert-Matches -Text $installerText -Pattern 'ExecutionTimeLimit\s+\(New-TimeSpan -Hours 4\)' -Message 'Scheduled task must allow enough time for DISM plus cleanmgr on Server builds.'
Assert-Matches -Text $uninstallerText -Pattern '\[switch\]\$NoPause' -Message 'Uninstaller must support -NoPause for automation.'
Assert-Matches -Text $uninstallerText -Pattern 'childArgs.*-NoPause' -Message 'Uninstaller self-elevation must preserve -NoPause.'
Assert-Matches -Text $uninstallerText -Pattern 'Unregister-ScheduledTask.*-TaskPath\s+\$TaskPath' -Message 'Uninstaller must remove the explicit root TaskPath.'
Assert-Matches -Text $mainText -Pattern 'pnputil\s+/enum-drivers' -Message 'Driver cleanup should enumerate the same driver store view exposed by pnputil.'
Assert-Matches -Text $mainText -Pattern '/format\s+csv' -Message 'Driver cleanup should prefer locale-invariant pnputil CSV output.'
Assert-Matches -Text $mainText -Pattern 'ConvertFrom-Csv' -Message 'Driver cleanup should parse structured pnputil output.'
Assert-NotMatches -Text $mainText -Pattern 'Get-WindowsDriver\s+-Online' -Message 'Driver cleanup should not depend only on Get-WindowsDriver for superseded package detection.'
Assert-Matches -Text $mainText -Pattern 'RunDLL_PnpClean' -Message 'Driver cleanup should invoke the Windows pnpclean handler used by Disk Cleanup.'
Assert-Matches -Text $mainText -Pattern '/DRIVERS' -Message 'pnpclean driver cleanup should pass /DRIVERS.'
Assert-Matches -Text $mainText -Pattern '/MAXCLEAN' -Message 'pnpclean driver cleanup should pass /MAXCLEAN.'
Assert-Matches -Text $mainText -Pattern 'Invoke-ScriptRootAclHardening' -Message 'Main cleanup script should harden its project folder ACL on first elevated run.'
Assert-Matches -Text $mainText -Pattern '\.WindowsAutoCleanupAclHardened' -Message 'ACL hardening should use a marker file so it is one-time.'
Assert-Matches -Text $mainText -Pattern 'S-1-5-18' -Message 'ACL hardening should grant SYSTEM access.'
Assert-Matches -Text $mainText -Pattern 'S-1-5-32-544' -Message 'ACL hardening should grant Administrators access.'
Assert-Matches -Text $mainText -Pattern 'S-1-5-32-545' -Message 'ACL hardening should limit regular Users.'
Assert-Matches -Text $mainText -Pattern 'ReadAndExecute' -Message 'ACL hardening should leave regular users with read/execute only.'
Assert-Matches -Text $mainText -Pattern 'SetAccessRuleProtection\(\$true,\s*\$false\)' -Message 'ACL hardening should disable inherited write/delete permissions.'
Assert-Matches -Text $mainText -Pattern 'ProgramData.*WindowsAutoCleanup' -Message 'Log fallback should avoid TEMP locations that the script cleans.'
Assert-NotMatches -Text $mainText -Pattern 'foreach \(\$profile in Get-UserProfileDirectories\)' -Message 'Cleanup target enumeration must not shadow the PowerShell $profile automatic variable.'

# Load only function definitions from the main script. This gives real function-level
# coverage without executing the destructive cleanup entry point.
$script:ScriptRoot = $repoRoot
$script:LogPath = $null
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:Results = New-Object 'System.Collections.Generic.List[object]'
$script:AttemptedCategories = New-Object 'System.Collections.Generic.List[string]'
$script:TotalFilesDeleted = 0L
$script:TotalDirectoriesDeleted = 0L
$script:TotalReparsePointsDeleted = 0L
$script:TotalFailed = 0L
$script:TotalSkipped = 0L
$script:TotalPendingDeletes = 0L

$functionDefinitions = $mainAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true)

foreach ($functionDefinition in $functionDefinitions) {
    . ([scriptblock]::Create($functionDefinition.Extent.Text))
}

Assert-Condition -Condition ((Get-NormalizedPath -Path 'C:') -eq 'C:') -Message 'Bare drive paths must normalize to the drive root form.'
Assert-Condition -Condition (-not (Test-IsOnCDrive -Path 'C:foo')) -Message 'Drive-relative paths must be rejected instead of resolving against per-drive CWD.'
Assert-Condition -Condition (Test-IsOnCDrive -Path '\\?\C:\Windows\Temp') -Message 'Extended-length C: paths should stay inside the C: allow-list.'
Assert-Condition -Condition (Test-IsOnCDrive -Path 'C:\Windows\Temp') -Message 'C:\Windows\Temp should be recognized as on C:.'
Assert-Condition -Condition (-not (Test-IsOnCDrive -Path 'D:\Temp')) -Message 'Non-C: paths must be rejected.'
Assert-Condition -Condition (Test-IsProtectedPath -Path 'C:\Windows') -Message 'Protected roots must remain protected.'
Assert-Condition -Condition (-not (Test-IsSafeTargetPath -Path 'C:\Windows')) -Message 'Protected roots must not be safe cleanup targets.'
Assert-Condition -Condition (Test-IsSafeTargetPath -Path 'C:\Windows\Temp') -Message 'Allowed cleanup locations under protected roots should pass target validation.'
Assert-Condition -Condition (Test-IsSafeScriptRootForAclHardening) -Message 'Repository root should be safe for ACL hardening during validation.'

$targets = @(Get-CleanupTargets)
Assert-Condition -Condition ($targets.Count -gt 0) -Message 'Get-CleanupTargets should produce cleanup targets.'
Assert-Condition -Condition (-not (($targets.Path -join ';') -match 'C:\\Users\\(?:Public|Default)\\')) -Message 'Get-CleanupTargets should exclude non-interactive Public and Default profile templates.'
foreach ($target in $targets) {
    Assert-Condition -Condition (Test-IsOnCDrive -Path $target.Path) -Message "Cleanup target must stay on C:: $($target.Path)"
}

$explorerTargets = @(
    $targets | Where-Object {
        $_.Category -match 'File Explorer history|Quick Access|Recent' -or
        $_.Path -match '\\Recent($|\\)|AutomaticDestinations|CustomDestinations' -or
        (($_.Patterns -join ' ') -match 'ExplorerStartupLog|AutomaticDestinations|CustomDestinations')
    }
)
Assert-Condition -Condition ($explorerTargets.Count -eq 0) -Message 'Get-CleanupTargets must not include File Explorer history, Recent, Quick Access, or icon/startup cache targets.'

$thumbnailTargets = @(
    $targets | Where-Object {
        $_.Category -eq 'Windows Explorer thumbnail cache' -and
        $_.Path -match '\\AppData\\Local\\Microsoft\\Windows\\Explorer$' -and
        (($_.Patterns -join ' ') -match 'thumbcache_\*\.db') -and
        (($_.Patterns -join ' ') -match 'iconcache_\*\.db')
    }
)
Assert-Condition -Condition ($thumbnailTargets.Count -gt 0) -Message 'Get-CleanupTargets should include Windows Explorer thumbcache_*.db and iconcache_*.db cleanup targets.'

$diskCleanupDirectTargets = @(
    $targets | Where-Object {
        $_.Category -in @(
            'DirectX Shader Cache',
            'Delivery Optimization cache',
            'Defender cleanup files',
            'Downloaded Program Files',
            'Internet cache (system profiles)'
        )
    }
)
Assert-Condition -Condition ($diskCleanupDirectTargets.Count -gt 0) -Message 'Get-CleanupTargets should include direct targets for stubborn Disk Cleanup categories.'

$csvDrivers = @(ConvertFrom-PnPUtilCsvOutput -Lines @(
    'DriverName,OriginalName,ProviderName,ClassName,DriverVersion',
    'oem10.inf,driver.inf,Vendor,System,2024-01-02 2.3.4.5'
))
Assert-Condition -Condition ($csvDrivers.Count -eq 1 -and $csvDrivers[0].PublishedName -eq 'oem10.inf') -Message 'pnputil CSV parser should produce driver records.'
$dotDateCsvDrivers = @(ConvertFrom-PnPUtilCsvOutput -Lines @(
    'DriverName,OriginalName,ProviderName,ClassName,DriverVersion',
    'oem11.inf,driver.inf,Vendor,System,14.02.2022 1.2.0.44'
))
Assert-Condition -Condition ($dotDateCsvDrivers.Count -eq 1 -and $dotDateCsvDrivers[0].DriverDate -eq [datetime]'2022-02-14') -Message 'pnputil CSV parser should accept dot-separated locale date values.'
$newestDriver = [PSCustomObject]@{ DriverDate = [datetime]'2024-01-01'; DriverVersion = [version]'1.0.0.0' }
$sideBranchDriver = [PSCustomObject]@{ DriverDate = [datetime]'2023-12-01'; DriverVersion = [version]'2.0.0.0' }
Assert-Condition -Condition (-not (Test-DriverPackageSuperseded -Candidate $sideBranchDriver -Newest $newestDriver)) -Message 'Driver cleanup must not delete a higher-version side branch only because its date is older.'

Write-Host 'Validation passed.'
