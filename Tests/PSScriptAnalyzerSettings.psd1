@{
    IncludeDefaultRules = $true

    # CI treats anything at these levels as a build failure, so the exclusions below have to be
    # deliberate rather than convenient.
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # This is an interactive console tool; its console text IS the product, and the installer
        # and uninstaller have no other transport for it.
        'PSAvoidUsingWriteHost',

        # -WhatIf on the internal deletion primitives would advertise a safety guarantee they do not
        # implement. Safety here is the allow-list, the protected-root check and the run deadline;
        # the user-facing confirmation belongs to the entry-point scripts.
        'PSUseShouldProcessForStateChangingFunctions',

        # The plural nouns in this codebase are units and record names (Bytes, Ms, Stats), not
        # collections, so the rule's assumption does not hold.
        'PSUseSingularNouns',

        # -ResetWindowsUpdateBase must default to $true and must survive being passed as
        # -ResetWindowsUpdateBase:$false, which requires an explicitly defaulted switch.
        'PSAvoidDefaultValueSwitchParameter'
    )
}
