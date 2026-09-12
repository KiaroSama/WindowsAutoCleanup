#Requires -Version 5.1
<#
.SYNOPSIS
    WAC-11: the task-argument decoder must recover exactly what the literal encoder wrote.

.DESCRIPTION
    ConvertTo-WacPowerShellLiteral escapes for the PowerShell parser, and the parser terminates a
    single-quoted literal on FOUR characters - the ASCII apostrophe plus U+2018, U+2019 and U+201B -
    so the encoder doubles all four. The old decoder was a regex that collapsed only the ASCII pair,
    which made encoder and decoder disagree about every typographic quote.

    That disagreement is not cosmetic. Measured here before the fix, with a deployment at
    `C:\O<U+2019>Name\WindowsAutoCleanup`:

        decoded         : C:\O<U+2019><U+2019>Name\WindowsAutoCleanup\Run.ps1
        expected        : C:\O<U+2019>Name\WindowsAutoCleanup\Run.ps1
        references root : False

    A `False` there is the uninstaller concluding that nothing reaches the deployment, and deleting
    files a registered task still runs. Office and OneDrive autocorrect an ASCII apostrophe into
    U+2019 inside user and folder names, so no crafted input is required to reach it.

    These cases go through the REAL builder (Get-WacTaskActionArgument) rather than a hand-written
    argument string, so encoder and decoder are tested as the pair they have to be: if either side
    changes its escaping rules alone, the round trip breaks here.

    Non-ASCII quotes are constructed with [char] codes because every PowerShell file in this
    repository is pure ASCII (RepositoryHygiene.Tests.ps1).
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Deploy.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

$script:Host51 = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:RightQuote = [string][char]0x2019
$script:LeftQuote = [string][char]0x2018
$script:ReversedQuote = [string][char]0x201B

function New-DecodingTask {
    <#
    .SYNOPSIS
        A stub task whose ONLY reference to a deployment is the script path inside its arguments.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Arguments,
        [string]$WorkingDirectory = ''
    )

    $action = [PSCustomObject]@{
        Execute          = $script:Host51
        Arguments        = $Arguments
        WorkingDirectory = $WorkingDirectory
    }
    return [PSCustomObject]@{ Actions = @($action) }
}

Test-Case 'every quote the encoder escapes survives the builder and comes back out of the decoder' {
    # The round trip that pins encoder and decoder together. A path is only correctly recovered when
    # BOTH sides agree on the escape rule, which is why this runs the shipped builder rather than a
    # literal argument string written by hand.
    $paths = @(
        'C:\Program Files\WindowsAutoCleanup\Run.ps1',
        ('C:\O' + $script:RightQuote + 'Name\Run.ps1'),
        ('C:\' + $script:LeftQuote + 'Quoted\Run.ps1'),
        ('C:\' + $script:ReversedQuote + 'Reversed\Run.ps1'),
        "C:\It's Here\Run.ps1",
        ('C:\Mixed ' + $script:LeftQuote + "one's" + $script:RightQuote + ' two\Run.ps1'),
        ("C:\Doubled''Ascii\Run.ps1")
    )

    foreach ($path in $paths) {
        $arguments = Get-WacTaskActionArgument -RunScript $path -ResetWindowsUpdateBase $false
        $decoded = Get-WacTaskScriptPath -Arguments $arguments
        Assert-Equal (Get-WacNormalizedPath -Path $path) $decoded `
            ('the decoder did not recover the path the builder encoded. arguments: ' + $arguments)
    }
}

Test-Case 'all eight switch combinations decode to the same script path' {
    # The payload gains and loses tokens around the literal. The decoder must find the call target
    # regardless of what follows it, and must not be satisfied by a prefix of the path.
    $path = 'C:\Program Files\O' + $script:RightQuote + 'Name\Run.ps1'
    $expected = Get-WacNormalizedPath -Path $path

    $seen = 0
    foreach ($reset in @($true, $false)) {
        foreach ($prune in @($true, $false)) {
            foreach ($legacy in @($true, $false)) {
                $arguments = Get-WacTaskActionArgument -RunScript $path -ResetWindowsUpdateBase $reset `
                    -PruneSupersededDrivers:$prune -EnableLegacyDiskCleanup:$legacy
                Assert-Equal $expected (Get-WacTaskScriptPath -Arguments $arguments) `
                    ('combination reset={0} prune={1} legacy={2} did not decode' -f $reset, $prune, $legacy)
                $seen++
            }
        }
    }

    Assert-Equal 8 $seen 'the eight documented switch combinations were not all exercised'
}

Test-Case 'a deployment named only through the arguments is still found when its path carries a smart quote' {
    # THE case the old decoder got wrong, and the reason it mattered. The quote sits in the ROOT
    # component, so mis-decoding moves the path OUTSIDE the deployment and the reference disappears
    # entirely - measured as references root : False before the fix. With the quote only in the LEAF
    # the wrong path still lands inside the root and the bug stays invisible, which is how it
    # survived earlier review.
    $root = 'C:\O' + $script:RightQuote + 'Name\WindowsAutoCleanup'
    $arguments = Get-WacTaskActionArgument -RunScript (Join-Path -Path $root -ChildPath 'Run.ps1') -ResetWindowsUpdateBase $false

    # No WorkingDirectory and an Execute outside the tree: the argument is the only reference left.
    Assert-True (Test-WacTaskReferencesRoot -Task @((New-DecodingTask -Arguments $arguments)) -DeploymentRoot $root) `
        'a task that still runs the deployment was not detected, so the uninstaller would delete files under it'
}

Test-Case 'an argument shape the decoder cannot read preserves the files instead of clearing them' {
    # Ownership must be strict, but THIS question decides whether files may be deleted, so the safe
    # answer to "I could not tell" is "keep them". A payload that announces a script and does not
    # decode may name the deployment in a shape older or newer than anything here parses.
    $root = 'C:\Program Files\WindowsAutoCleanup'

    $unreadable = @(
        '-NoProfile -Command "& $someVariable -Scheduled"',
        '-NoProfile -Command "& (Get-Item C:\x).FullName"',
        '-NoProfile -Command "& ''C:\a\one.ps1''; & ''C:\b\two.ps1''"',
        '-File'
    )
    foreach ($arguments in $unreadable) {
        Assert-True (Test-WacTaskReferencesRoot -Task @((New-DecodingTask -Arguments $arguments)) -DeploymentRoot $root) `
            ('an undecodable script argument was treated as proof of no reference: ' + $arguments)
    }

    # ...and the narrowness that keeps ordinary uninstalls working: a task naming no script at all
    # is not made to block removal, and neither is one whose script decodes elsewhere.
    Assert-False (Test-WacTaskReferencesRoot -Task @((New-DecodingTask -Arguments '/silent /install')) -DeploymentRoot $root) `
        'an unrelated task with no script argument blocked removal, which would make uninstall impossible'
    Assert-False (Test-WacTaskReferencesRoot -Task @((New-DecodingTask -Arguments '-File "C:\Other\Thing.ps1"')) -DeploymentRoot $root) `
        'a task whose script decodes outside the deployment blocked removal'
}

Test-Case 'the decoder parses a hostile payload without executing any of it' {
    # ParseInput builds an AST and evaluates nothing. If that ever changed, the sentinel file would
    # appear - a foreign task's arguments are attacker-influenced text that this code reads as SYSTEM.
    $sandbox = New-TestSandbox -Prefix 'wac_decode'
    $sentinel = Join-Path -Path $sandbox -ChildPath 'executed.txt'

    $payloads = @(
        ('-Command "& ''C:\a\Run.ps1''; Set-Content -LiteralPath ''{0}'' -Value x"' -f $sentinel),
        ('-Command "Set-Content -LiteralPath ''{0}'' -Value x; & ''C:\a\Run.ps1''"' -f $sentinel),
        ('-File "{0}"' -f $sentinel)
    )

    foreach ($arguments in $payloads) {
        $null = Get-WacTaskScriptPath -Arguments $arguments
        $null = Test-WacTaskReferencesRoot -Task @((New-DecodingTask -Arguments $arguments)) -DeploymentRoot 'C:\Program Files\WindowsAutoCleanup'
    }

    Assert-False (Test-Path -LiteralPath $sentinel) 'decoding a task argument executed the payload'
}

Test-Case 'the legacy -File shape still decodes exactly as it did before' {
    # Pre-1.2.0 tasks are adopted through this path. Changing the -Command branch must not disturb
    # it, or the migration stops recognising its own predecessor and refuses to adopt.
    Assert-Equal (Get-WacNormalizedPath -Path 'C:\Program Files\WindowsAutoCleanup\Run.ps1') `
        (Get-WacTaskScriptPath -Arguments '-NoProfile -File "C:\Program Files\WindowsAutoCleanup\Run.ps1" -Scheduled') `
        'the quoted legacy -File form stopped decoding'
    Assert-Equal (Get-WacNormalizedPath -Path 'C:\WAC\Run.ps1') `
        (Get-WacTaskScriptPath -Arguments '-NoProfile -File C:\WAC\Run.ps1 -Scheduled') `
        'the bare legacy -File form stopped decoding'
    Assert-Equal $null (Get-WacTaskScriptPath -Arguments '') 'an empty argument string must decode to nothing'
    Assert-Equal $null (Get-WacTaskScriptPath -Arguments '/silent /install') 'a non-PowerShell argument string must decode to nothing'
}

Complete-TestRun
