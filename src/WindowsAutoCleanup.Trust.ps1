<#
.SYNOPSIS
    The owner and DACL rules that decide whether SYSTEM may safely execute, or write state into, a
    path - and every ancestor of it.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1; see that file for why the parts are dot-sourced
    rather than imported. Nothing here mutates a security descriptor; it reads one and refuses when
    the answer cannot be established, which is why every unreadable condition returns IsTrusted
    false rather than being swallowed.
#>

# ---------------------------------------------------------------------------------------------
# Machine trust
# ---------------------------------------------------------------------------------------------

function Test-WacPathIsMachineTrusted {
    <#
    .SYNOPSIS
        True when a standard user cannot modify the path, so SYSTEM may safely execute it.
    .DESCRIPTION
        This VERIFIES; it never mutates an ACL. Two conditions must both hold:
          * the owner is SYSTEM, Administrators, TrustedInstaller, or an administrator account -
            an owner implicitly keeps WRITE_DAC, so a user-owned file can be rewritten at any moment
            no matter how good its DACL looks;
          * no non-administrative principal holds a write-class right.
        Anything unreadable returns IsTrusted=$false so callers fail closed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $result = [PSCustomObject]@{
        Path = $Path
        IsTrusted = $false
        Owner = $null
        Reason = $null
        UntrustedWriters = @()
    }

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized -or -not (Test-Path -LiteralPath $normalized)) {
        $result.Reason = 'Path does not exist.'
        return $result
    }

    try {
        $acl = Get-Acl -LiteralPath $normalized -ErrorAction Stop
    }
    catch {
        $result.Reason = ('Security descriptor is unreadable: {0}' -f $_.Exception.Message)
        return $result
    }

    $trustedOwnerSids = @(
        'S-1-5-18',                                                                   # SYSTEM
        'S-1-5-32-544',                                                               # BUILTIN\Administrators
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'              # TrustedInstaller
    )

    $ownerSid = $null
    try { $ownerSid = [string]$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { $ownerSid = $null }
    $result.Owner = $ownerSid

    $ownerTrusted = $false
    if ($ownerSid) {
        if ($trustedOwnerSids -contains $ownerSid) {
            $ownerTrusted = $true
        }
        else {
            # An individual administrator owning the path is acceptable: that account can already
            # rewrite any ACL on the machine, so it is not an escalation. A non-admin owner is not.
            $ownerTrusted = Test-WacSidIsAdministrator -Sid $ownerSid
        }
    }

    if (-not $ownerTrusted) {
        $result.Reason = ('Owner {0} is not an administrative principal; an owner implicitly keeps WRITE_DAC.' -f $ownerSid)
        return $result
    }

    # Only ATOMIC write-class bits belong in this mask. Composite values such as Modify and
    # FullControl also contain read and Synchronize bits, so OR-ing them in makes the mask match a
    # plain ReadAndExecute ACE and reports every System32 binary as untrusted. The composites are
    # still caught, because each of them contains these atomic bits.
    $writeRights = [int]([System.Security.AccessControl.FileSystemRights]::WriteData) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::AppendData) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::WriteAttributes) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::Delete) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::ChangePermissions) -bor
                   [int]([System.Security.AccessControl.FileSystemRights]::TakeOwnership)

    # GENERIC_WRITE (0x40000000) and GENERIC_ALL (0x10000000) are not translated into specific
    # rights inside a raw ACE, so a mask built only from specific rights cannot see them.
    $genericWriteRights = 0x40000000 -bor 0x10000000

    $untrusted = New-Object 'System.Collections.Generic.List[string]'

    try {
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    }
    catch {
        $result.Reason = ('Access rules are unreadable: {0}' -f $_.Exception.Message)
        return $result
    }

    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

        # An InheritOnly ACE grants nothing on THIS object; it is a template for children. Skipping
        # it is not a loophole, it is the definition. It matters because System32 and %ProgramFiles%
        # both carry an inherit-only CREATOR OWNER GENERIC_ALL entry, which would otherwise mark
        # every Windows directory untrusted. Whether a non-admin can create a child here - the thing
        # CREATOR OWNER would then apply to - is decided by the effective write rules below.
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        try { $propagation = $rule.PropagationFlags } catch { $propagation = [System.Security.AccessControl.PropagationFlags]::None }
        if (([int]$propagation -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }

        if ((([int]$rule.FileSystemRights -band [int]$writeRights) -eq 0) -and
            (([int]$rule.FileSystemRights -band [int]$genericWriteRights) -eq 0)) { continue }

        $sid = [string]$rule.IdentityReference.Value
        if ($trustedOwnerSids -contains $sid) { continue }
        if (Test-WacSidIsAdministrator -Sid $sid) { continue }

        [void]$untrusted.Add($sid)
    }

    if ($untrusted.Count -gt 0) {
        $result.UntrustedWriters = @($untrusted.ToArray() | Sort-Object -Unique)
        $result.Reason = ('Non-administrative principals hold write access: {0}' -f ($result.UntrustedWriters -join ', '))
        return $result
    }

    # Zero rules is an EMPTY DACL, not a NULL one. Measured through this exact managed API on both
    # shipped hosts: 'O:BAG:BAD:NO_ACCESS_CONTROL' (a real NULL DACL, which grants everyone full
    # access) comes back as ONE rule, Allow S-1-1-0 0xFFFFFFFF, so the loop above already refuses it
    # on the write bits. It is 'O:BAG:BAD:' - a present but empty DACL - that yields zero rules.
    # Either way there is nothing here to evaluate, and no real protected object looks like this, so
    # fail closed rather than read an empty rule set as "nobody has write access".
    if ($rules.Count -eq 0) {
        $result.Reason = 'The security descriptor exposes no access rules to evaluate.'
        return $result
    }

    $result.IsTrusted = $true
    $result.Reason = 'Owner and DACL are administrative only.'
    return $result
}

function Test-WacAncestorAclIsAdministrative {
    <#
    .SYNOPSIS
        The ancestor trust rule, taken over a descriptor the caller already holds.
    .DESCRIPTION
        An ancestor is NOT asked the leaf's question. Test-WacPathIsMachineTrusted asks "can a
        non-administrator write anything here at all", which is right for the directory that holds
        the audit log and wrong one level up: the default DACL of C:\ grants Authenticated Users
        CreateDirectories, so the strict question marks every volume root untrusted and no state
        root on a healthy Windows install would ever pass.

        Creating a NEW name beside an existing one cannot replace the existing one. Redirecting or
        removing an existing child needs one of Delete, DeleteSubdirectoriesAndFiles,
        ChangePermissions, TakeOwnership, or GENERIC_ALL (which is not decomposed into specific
        rights inside a raw ACE). GENERIC_WRITE is deliberately absent: on a directory it maps to
        add-file, add-subdirectory, write-EA, write-attributes and READ_CONTROL, none of which
        reaches an existing child.

        The OWNER test stays strict, because an owner implicitly keeps WRITE_DAC and can grant
        itself any of the above at any moment.
    .OUTPUTS
        IsTrusted / Owner / Reason.
    #>
    param([Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$Acl)

    $verdict = [PSCustomObject]@{ IsTrusted = $false; Owner = $null; Reason = $null }

    $ownerSid = $null
    try { $ownerSid = [string]$Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { $ownerSid = $null }
    $verdict.Owner = $ownerSid

    if (-not (Test-WacSidIsAdministrator -Sid ([string]$ownerSid))) {
        $verdict.Reason = ('Owner {0} is not an administrative principal; an owner implicitly keeps WRITE_DAC.' -f $ownerSid)
        return $verdict
    }

    $replaceRights = [int]([System.Security.AccessControl.FileSystemRights]::Delete) -bor
                     [int]([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -bor
                     [int]([System.Security.AccessControl.FileSystemRights]::ChangePermissions) -bor
                     [int]([System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    $genericAll = 0x10000000

    $rules = $null
    try { $rules = @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) }
    catch {
        $verdict.Reason = ('Access rules are unreadable: {0}' -f $_.Exception.Message)
        return $verdict
    }

    if ($rules.Count -eq 0) {
        $verdict.Reason = 'The security descriptor exposes no access rules to evaluate.'
        return $verdict
    }

    $writers = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        try { $propagation = $rule.PropagationFlags } catch { $propagation = [System.Security.AccessControl.PropagationFlags]::None }
        if (([int]$propagation -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }

        if ((([int]$rule.FileSystemRights -band $replaceRights) -eq 0) -and
            (([int]$rule.FileSystemRights -band $genericAll) -eq 0)) { continue }

        $sid = [string]$rule.IdentityReference.Value
        if (Test-WacSidIsAdministrator -Sid $sid) { continue }

        [void]$writers.Add($sid)
    }

    if ($writers.Count -gt 0) {
        $verdict.Reason = ('Non-administrative principals can replace children here: {0}' -f
            ((@($writers.ToArray() | Sort-Object -Unique)) -join ', '))
        return $verdict
    }

    $verdict.IsTrusted = $true
    $verdict.Reason = 'Owner and DACL are administrative only.'
    return $verdict
}

function Test-WacStatePathIsTrusted {
    <#
    .SYNOPSIS
        Proves a log / state / driver-backup path is on a local fixed disk, free of reparse points,
        and writable only by administrative principals - itself AND every ancestor up to the root.
    .DESCRIPTION
        %ProgramData%\WindowsAutoCleanup holds the audit log a SYSTEM task writes and the driver
        backups a restore would read. Checking the leaf alone proves less than it looks: write
        access to a PARENT is enough to rename the whole directory aside and drop a different one
        in its place, and a reparse point anywhere in the chain redirects the whole thing.

        The question asked of every level - leaf included - is "can a non-administrator REPLACE,
        delete or redirect this", not the stricter "can a non-administrator write anything here at
        all" that Test-WacPathIsMachineTrusted asks of executable code. Measured on a stock Windows
        11 install: C:\ProgramData grants BUILTIN\Users (S-1-5-32-545) create-file and
        create-folder, and that ACE is inherited by %ProgramData%\WindowsAutoCleanup. Since this
        project is forbidden to rewrite an ACL, the strict question would answer "untrusted" on
        every default machine forever, which is not a finding - it is a check nobody can act on.

        That residual risk is REPORTED rather than hidden: Writers lists the non-administrative
        principals that can create new content in the leaf, so a caller that needs the stricter
        guarantee - driver backups being read back during a restore, for instance - can require it
        to be empty without this function having to refuse every run to say so.

        Nothing here is swallowed. An unreadable descriptor, a reparse point, an unresolvable
        ancestor and a chain longer than -MaxDepth are all recorded as FAILURES and all leave
        IsTrusted false, because every one of them means the trust question was not answered - and
        an unanswered security question is not a yes.

        A path that does not exist yet is legitimate on a first run, so the nearest existing
        ancestor is verified instead and Reason says so. That is the directory the leaf will be
        created in, which is the thing that has to be trustworthy.
    .OUTPUTS
        Path (what was actually verified), IsTrusted, Reason, Checked, Failures, Writers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [ValidateRange(1, 128)][int]$MaxDepth = 64
    )

    $result = [PSCustomObject]@{
        Path = $Path
        IsTrusted = $false
        Reason = $null
        Checked = @()
        Failures = @()
        Writers = @()
    }

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) {
        $result.Reason = 'The path is not a usable local drive path.'
        return $result
    }

    $drive = $null
    try { $drive = New-Object System.IO.DriveInfo($normalized.Substring(0, 2)) } catch { $drive = $null }
    if (-not $drive) {
        $result.Reason = ('The volume for {0} could not be inspected.' -f $normalized)
        return $result
    }
    if (-not $drive.IsReady -or [string]$drive.DriveType -ne 'Fixed') {
        $result.Reason = ('{0} is not on a ready local fixed disk (DriveType={1}).' -f $normalized, $drive.DriveType)
        return $result
    }

    # Walk down to the first component that exists. Bounded by MaxDepth like the walk back up, so a
    # pathological path cannot spin here either.
    $existing = $normalized
    $descend = 0
    while (-not (Test-Path -LiteralPath $existing)) {
        $descend++
        if ($descend -gt $MaxDepth) {
            $result.Reason = ('No existing ancestor of {0} was found within {1} levels.' -f $normalized, $MaxDepth)
            return $result
        }

        $parent = [System.IO.Path]::GetDirectoryName($existing)
        if ([string]::IsNullOrEmpty($parent)) {
            $result.Reason = ('No existing ancestor of {0} exists.' -f $normalized)
            return $result
        }
        $existing = Get-WacNormalizedPath -Path $parent
        if (-not $existing) {
            $result.Reason = ('An ancestor of {0} could not be canonicalised.' -f $normalized)
            return $result
        }
    }

    $result.Path = $existing
    $checked = New-Object 'System.Collections.Generic.List[string]'
    $failures = New-Object 'System.Collections.Generic.List[object]'

    $current = $existing
    $isLeaf = $true
    $depth = 0
    $reachedRoot = $false

    while ($true) {
        $depth++
        if ($depth -gt $MaxDepth) {
            [void]$failures.Add([PSCustomObject]@{
                Path = $current
                Reason = ('The ancestor chain exceeded the {0}-level depth limit before reaching the volume root.' -f $MaxDepth)
            })
            break
        }

        $probe = $current
        if ($probe -match '^[A-Za-z]:$') { $probe = $probe + '\' }
        [void]$checked.Add($probe)

        if (Test-WacIsReparsePoint -Path $probe) {
            [void]$failures.Add([PSCustomObject]@{
                Path = $probe
                Reason = 'The path is a reparse point, or its attributes are unreadable; either way it can redirect elsewhere.'
            })
        }
        else {
            # Get-Acl on a bare 'X:' is DRIVE-RELATIVE and returns the session's current directory
            # on that drive, which is why $probe was re-rooted to 'X:\' above.
            $acl = $null
            try { $acl = Get-Acl -LiteralPath $probe -ErrorAction Stop }
            catch {
                [void]$failures.Add([PSCustomObject]@{
                    Path = $probe
                    Reason = ('Security descriptor is unreadable: {0}' -f $_.Exception.Message)
                })
            }

            if ($acl) {
                $verdict = Test-WacAncestorAclIsAdministrative -Acl $acl
                if (-not $verdict.IsTrusted) {
                    [void]$failures.Add([PSCustomObject]@{ Path = $probe; Reason = $verdict.Reason })
                }
            }

            # The stricter question is asked of the leaf only, and only to REPORT the answer.
            if ($isLeaf) {
                $strict = Test-WacPathIsMachineTrusted -Path $probe
                if (-not $strict.IsTrusted) { $result.Writers = @($strict.UntrustedWriters) }
            }
        }

        if ($current -match '^[A-Za-z]:$') { $reachedRoot = $true; break }

        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent)) { $reachedRoot = $true; break }

        $next = Get-WacNormalizedPath -Path $parent
        if (-not $next -or [string]::Equals($next, $current, [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$failures.Add([PSCustomObject]@{
                Path = $current
                Reason = 'The ancestor chain could not be followed to the volume root.'
            })
            break
        }

        $current = $next
        $isLeaf = $false
    }

    $result.Checked = @($checked.ToArray())
    $result.Failures = @($failures.ToArray())

    if ($failures.Count -gt 0) {
        $result.Reason = (@($failures.ToArray() | ForEach-Object { '{0}: {1}' -f $_.Path, $_.Reason }) -join ' | ')
        return $result
    }

    if (-not $reachedRoot) {
        $result.Reason = 'The ancestor chain did not reach the volume root.'
        return $result
    }

    $result.IsTrusted = $true
    $result.Reason = ('{0} and all {1} ancestors are local, non-reparse, and cannot be replaced by a non-administrator.' -f $existing, ($checked.Count - 1))
    if ($result.Writers.Count -gt 0) {
        $result.Reason = ('{0} Non-administrative principals can still create content in it: {1}' -f
            $result.Reason, ($result.Writers -join ', '))
    }
    return $result
}

function Test-WacSidIsAdministrator {
    <#
    .SYNOPSIS
        True when the SID is a built-in administrative principal or a member of local Administrators.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Sid)

    if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }

    $alwaysAdmin = @(
        'S-1-5-18',        # SYSTEM
        'S-1-5-32-544',    # BUILTIN\Administrators
        'S-1-5-32-549',    # Server Operators
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
    )
    if ($alwaysAdmin -contains $Sid) { return $true }

    # Well-known groups that must never be treated as administrative.
    $neverAdmin = @(
        'S-1-1-0',      # Everyone
        'S-1-5-11',     # Authenticated Users
        'S-1-5-32-545', # BUILTIN\Users
        'S-1-5-32-546', # Guests
        'S-1-5-4',      # INTERACTIVE
        'S-1-5-113',    # Local account
        'S-1-3-0',      # CREATOR OWNER
        'S-1-5-32-547'  # Power Users
    )
    if ($neverAdmin -contains $Sid) { return $false }

    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        foreach ($member in $members) {
            # ORDINAL, not -ieq: a SID match decides administrator membership.
            if ([string]::Equals([string]$member.SID.Value, $Sid, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
    }
    catch {
        # Get-LocalGroupMember is unavailable or failed (domain member, restricted SKU). Fall back to
        # the current elevated identity, which is who is installing.
        try {
            $current = [Security.Principal.WindowsIdentity]::GetCurrent()
            if ([string]::Equals([string]$current.User.Value, $Sid, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-WacIsAdministrator)) { return $true }
        }
        catch {
            $null = $_
        }
    }

    return $false
}
