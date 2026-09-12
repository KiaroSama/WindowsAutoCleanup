#Requires -Version 5.1
<#
.SYNOPSIS
    The data/code boundary of ConvertTo-WacPowerShellLiteral: a value must never become code.

.DESCRIPTION
    Everything interpolated into a -Command relaunch payload goes through that encoder, so it is the
    single boundary between a caller-supplied value and executable PowerShell. It had NO tests at all,
    which is exactly why WAC-03 survived: the encoder doubled the ASCII apostrophe and nothing else,
    while the PowerShell PARSER also terminates a single-quoted literal on the typographic quotes
    U+2018 and U+2019.

    Measured before the fix: ConvertTo-WacPowerShellLiteral on `C:\O<U+2019>Neil\Run.ps1` produced
    'C:\O<U+2019>Neil\Run.ps1', and [scriptblock]::Create on it failed with "The string is missing the
    terminator: '." That is an ordinary path - Office and OneDrive autocorrect ASCII apostrophes into
    U+2019 in user and folder names - so this broke real machines, and a crafted value could close the
    literal and append code.

    These cases assert the PARSER's answer, not a spelling: every value is encoded, parsed and
    executed, and the result must be byte-identical to the input. An assertion on the encoded string's
    shape would pass over any encoder that merely looked right.
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '_Harness.ps1')

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
Import-Module -Name (Join-Path -Path $script:RepoRoot -ChildPath 'src\WindowsAutoCleanup.Core.psm1') `
    -Force -DisableNameChecking -ErrorAction Stop

function Assert-LiteralRoundTrips {
    <#
    .SYNOPSIS
        Encodes a value, PARSES and EXECUTES the literal, and requires the original back, ordinally.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$What
    )

    $literal = ConvertTo-WacPowerShellLiteral -Value $Value

    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($literal, [ref]$null, [ref]$errors)
    Assert-Equal 0 @($errors).Count ('{0}: the literal does not parse. encoded: {1}' -f $What, $literal)

    $actual = [string](& ([scriptblock]::Create($literal)))
    Assert-Equal $Value $actual ('{0}: the value did not survive the literal. encoded: {1}' -f $What, $literal)
}

# ---------------------------------------------------------------------------------------------
# The boundary itself
# ---------------------------------------------------------------------------------------------

Test-Case 'a typographic apostrophe survives the literal instead of terminating it' {
    # WAC-03, and the reason it matters on ordinary machines rather than only crafted input.
    $right = [string][char]0x2019
    $left = [string][char]0x2018

    Assert-LiteralRoundTrips -Value ('C:\O' + $right + 'Neil\Run.ps1') -What 'U+2019 in a path'
    Assert-LiteralRoundTrips -Value ('C:\' + $left + 'quoted' + $right + '\Run.ps1') -What 'U+2018 and U+2019'
    Assert-LiteralRoundTrips -Value $right -What 'a lone U+2019'
    Assert-LiteralRoundTrips -Value ($right + $right) -What 'two adjacent U+2019'
}

Test-Case 'an ASCII apostrophe still survives, including doubled and at the edges' {
    Assert-LiteralRoundTrips -Value "C:\O'Neil\Run.ps1" -What 'ASCII apostrophe'
    Assert-LiteralRoundTrips -Value "''" -What 'two adjacent ASCII apostrophes'
    Assert-LiteralRoundTrips -Value "'leading" -What 'leading apostrophe'
    Assert-LiteralRoundTrips -Value "trailing'" -What 'trailing apostrophe'
    Assert-LiteralRoundTrips -Value "'" -What 'a lone apostrophe'
}

Test-Case 'no metacharacter a value may legally contain becomes code' {
    # A single-quoted literal is inert, so these must pass through untouched once the literal is
    # correctly terminated. They are asserted because the relaunch payload carries real paths and
    # user-supplied category names.
    foreach ($value in @(
            'C:\Program Files\WindowsAutoCleanup\Run.ps1',
            '$env:SystemRoot',
            '$(Write-Host pwned)',
            'a`nb',
            'semi;colon',
            'double"quote',
            'back\slash\end\',
            'brace}and{brace',
            'pipe|amp&caret^',
            [string][char]0x00A0 + 'nbsp',
            'tab' + [string][char]9 + 'end')) {
        Assert-LiteralRoundTrips -Value $value -What ('metacharacter value: ' + $value)
    }
}

Test-Case 'an empty value produces a literal that parses to an empty string' {
    Assert-LiteralRoundTrips -Value '' -What 'empty string'
}

Test-Case 'an injection sentinel never executes' {
    # The failure this boundary exists to prevent, stated as behaviour rather than as a spelling: if
    # the literal can be closed, the text after it runs. The sentinel writes a file; the file must
    # never appear, and the payload must come back as ordinary DATA.
    $sandbox = New-TestSandbox -Prefix 'literal-inject'
    try {
        $sentinel = Join-Path -Path $sandbox -ChildPath 'executed.txt'
        $right = [string][char]0x2019

        foreach ($payload in @(
                ("x" + $right + "; Set-Content -LiteralPath '" + $sentinel + "' -Value pwned; " + $right + "y"),
                ("x'; Set-Content -LiteralPath '" + $sentinel + "' -Value pwned; 'y"))) {

            $literal = ConvertTo-WacPowerShellLiteral -Value $payload
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseInput($literal, [ref]$null, [ref]$errors)
            Assert-Equal 0 @($errors).Count ('the injection payload produced an unparsable literal: ' + $literal)

            $actual = [string](& ([scriptblock]::Create($literal)))
            Assert-Equal $payload $actual 'the injection payload did not come back as data'
            Assert-False (Test-Path -LiteralPath $sentinel) 'the injected command EXECUTED'
        }
    }
    finally {
        Remove-TestSandbox -Path $sandbox
    }
}

# ---------------------------------------------------------------------------------------------
# The callers that carry these values
# ---------------------------------------------------------------------------------------------

Test-Case 'a relaunch vector carrying a typographic apostrophe parses as one argument' {
    # The encoder is not used in isolation: Get-WacRelaunchArgument interpolates it into a -Command
    # payload. A literal that terminates early there does not merely lose the value, it changes what
    # the elevated child runs.
    $right = [string][char]0x2019
    $path = 'C:\O' + $right + 'Neil\WindowsAutoCleanup\Run.ps1'

    $argument = Get-WacRelaunchArgument -ScriptPath $path `
        -BooleanSwitch @{ ResetWindowsUpdateBase = $false } `
        -PresentSwitch @() -NamedValue @{} -ArrayValue @{}

    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($argument, [ref]$null, [ref]$errors)
    Assert-Equal 0 @($errors).Count ('the relaunch payload does not parse: ' + $argument)

    # Assert what the PARSER yields, not what the text looks like. A correctly escaped literal does
    # NOT contain the raw path - the terminating characters are doubled inside it - so a substring
    # search would demand exactly the broken encoding this case exists to reject.
    $literals = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $node.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::SingleQuoted
            }, $true) | ForEach-Object { [string]$_.Value })

    Assert-True ($literals -ccontains $path) `
    ('no single-quoted literal in the payload parses back to the script path. parsed literals: ' +
        ($literals -join ' | ') + ' -- payload: ' + $argument)

    Assert-True ($argument -cmatch '-ResetWindowsUpdateBase:\$false') `
    ('the explicit false switch did not survive: ' + $argument)
}

Complete-TestRun
