<#
.SYNOPSIS
    The trusted-directory primitive: create or open ONE directory with collision-failing semantics,
    prove what the object actually is from its own handle, and hand that handle back pinned.

.DESCRIPTION
    Dot-sourced by WindowsAutoCleanup.Core.psm1; see that file for why the parts are dot-sourced
    rather than imported.

    It exists because two unrelated callers had the same hole. The run log and the driver-backup
    store both asked a pathname whether a directory was trustworthy, then created that directory
    with New-Item -Force, and New-Item -Force ADOPTS whatever is already there. On the default
    %ProgramData% descriptor a local standard user may create names, so the predictable candidate
    directory can be introduced in the window between the two - and the object actually written to
    was never verified at all. Two separate repairs of the same hole would have been worse than one,
    so both halves call this.

    THREAT MODEL. A local standard user who can create names inside a directory this tool writes
    into. That user is in scope and is defended against. An administrator is not: an administrator
    can take ownership and rewrite any descriptor on the machine, and needs no race to do it.
#>

$script:DirectoryCreateProbe = $null
$script:DirectoryTrustJudge  = $null

# STATUS_OBJECT_NAME_COLLISION. Compared as unsigned TEXT because an NTSTATUS is a negative [int]
# in PowerShell and comparing those numerically is how a sign-extension slip turns a refusal into
# an acceptance.
$script:StatusNameCollision = '0xC0000035'

# FILE_ATTRIBUTE_REPARSE_POINT.
$script:AttributeReparsePoint = 0x00000400

function Set-WacDirectoryCreateProbe {
    <#
    .SYNOPSIS
        Test seam. A scriptblock run immediately BEFORE each directory is created, and nothing else.
    .DESCRIPTION
        The check-to-create window is the defect this file exists to close, so a test has to be able
        to stand inside that window deterministically. A sleep or a thread cannot: the window is
        microseconds wide and the suite forbids blind waits. The probe receives the full path about
        to be created and its return value is ignored; an exception it throws is swallowed, because
        a test seam may not change the behaviour it is observing.

        $null in production, and no shipped code sets it. Same shape as Set-WacProcessInvoker and
        Set-WacBoundDeleteOverride.
    #>
    param([AllowNull()][scriptblock]$ScriptBlock)
    $script:DirectoryCreateProbe = $ScriptBlock
}

function Set-WacDirectoryTrustJudge {
    <#
    .SYNOPSIS
        Test seam. Replaces the owner/DACL judgement Test-WacTrustedDirectoryDescriptor makes.
    .DESCRIPTION
        The scriptblock receives the SDDL read from the directory's own handle and must return an
        object with IsTrusted and Reason. Pass $null to restore the real rule.

        It exists because the real answer is not reproducible in a test: a sandbox under %TEMP% is
        owned by whoever ran the suite, so the verdict would depend on whether that account is a
        local administrator - true on every hosted Windows runner, usually false in a developer
        shell. Asserting on it would pass in exactly one of the two places it has to work.

        The seam does NOT weaken the cases that matter. The reparse refusal and the collision-
        failing create are judged by the kernel, not by this scriptblock, so both race tests run
        against the real rule with the judge untouched.
    #>
    param([AllowNull()][scriptblock]$ScriptBlock)
    $script:DirectoryTrustJudge = $ScriptBlock
}

function Test-WacTrustedDirectoryDescriptor {
    <#
    .SYNOPSIS
        Judges an owner+DACL, supplied as SDDL, by the same rule the state-path preflight applies.
    .DESCRIPTION
        The rule is Test-WacAncestorAclIsAdministrative - administrative owner, and no non-
        administrative principal able to delete, replace or re-permission what is here. It is NOT
        the stricter "can a non-administrator write anything at all" rule: %ProgramData% grants
        BUILTIN\Users create-file and create-folder by default and this project may not rewrite an
        ACL, so the strict rule would refuse every stock Windows machine forever. Creating a NEW
        name beside an existing one cannot replace the existing one, and every file this primitive
        creates is created collision-failing, so a new name cannot be planted under one either.

        An SDDL that cannot be parsed is a refusal, not an exception: an unanswered security
        question is not a yes.
    .OUTPUTS
        IsTrusted / Owner / Reason.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Sddl)

    if ($script:DirectoryTrustJudge) { return (& $script:DirectoryTrustJudge $Sddl) }

    if ([string]::IsNullOrWhiteSpace($Sddl)) {
        return [PSCustomObject]@{ IsTrusted = $false; Owner = $null; Reason = 'The directory exposed no security descriptor to evaluate.' }
    }

    $security = New-Object System.Security.AccessControl.DirectorySecurity
    try {
        $security.SetSecurityDescriptorSddlForm($Sddl)
    }
    catch {
        return [PSCustomObject]@{
            IsTrusted = $false; Owner = $null
            Reason = ('The security descriptor could not be interpreted: {0}' -f $_.Exception.Message)
        }
    }

    return (Test-WacAncestorAclIsAdministrative -Acl $security)
}

function Get-WacOpenablePath {
    <#
    .SYNOPSIS
        A normalised path in the form an open can take. A bare 'X:' names the per-drive working
        directory rather than the volume root, so it gets its separator back.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -match '^[A-Za-z]:$') { return ($Path + '\') }
    return $Path
}

function Test-WacBoundDirectoryIdentity {
    <#
    .SYNOPSIS
        Asks an OPEN handle what object it is bound to, and compares that with what was asked for.
    .DESCRIPTION
        Two refusals, both from the handle rather than from the name:
          * FILE_ATTRIBUTE_REPARSE_POINT means the object is a link. The handle was opened with
            FILE_FLAG_OPEN_REPARSE_POINT so the link itself is what we hold, and it is refused
            rather than followed. What GetFinalPathNameByHandleW returns for such a handle is
            undocumented, so no identity claim is built on it.
          * A resolved path that differs from the requested one means some component was a link or
            was swapped before the open landed. Either way this is not the object we asked for.
    .OUTPUTS
        IsTrusted / FinalPath / Reason.
    #>
    param(
        [Parameter(Mandatory = $true)][IntPtr]$Handle,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    $result = [PSCustomObject]@{ IsTrusted = $false; FinalPath = $null; Reason = $null }

    $attributes = [uint32]0
    $finalPath = $null
    $status = [WacNative]::DescribeHandle($Handle, [ref]$attributes, [ref]$finalPath)
    if ($status -ne 0) {
        $result.Reason = ('{0} could not describe itself through its own handle (Win32 {1}).' -f $ExpectedPath, $status)
        return $result
    }

    if (([int]$attributes -band $script:AttributeReparsePoint) -ne 0) {
        $result.Reason = ('{0} is a reparse point, so it can redirect elsewhere.' -f $ExpectedPath)
        return $result
    }

    if ([string]::IsNullOrEmpty($finalPath)) {
        $result.Reason = ('{0} would not resolve to a final path, so its identity is unknown.' -f $ExpectedPath)
        return $result
    }

    if ($finalPath -ine $ExpectedPath) {
        $result.Reason = ('{0} actually resolved to {1}, so it is not the object that was asked for.' -f $ExpectedPath, $finalPath)
        return $result
    }

    $result.FinalPath = $finalPath
    $result.IsTrusted = $true
    $result.Reason = 'The open handle resolves to the requested path and is not a reparse point.'
    return $result
}

function Test-WacBoundDirectoryVolume {
    <#
    .SYNOPSIS
        The volume a resolved path is on must be a ready, local, fixed disk.
    #>
    param([Parameter(Mandatory = $true)][string]$FinalPath)

    $result = [PSCustomObject]@{ IsTrusted = $false; Reason = $null }

    $drive = $null
    try { $drive = New-Object System.IO.DriveInfo($FinalPath.Substring(0, 2)) } catch { $drive = $null }
    if (-not $drive) {
        $result.Reason = ('The volume for {0} could not be inspected.' -f $FinalPath)
        return $result
    }
    if (-not $drive.IsReady -or [string]$drive.DriveType -ne 'Fixed') {
        $result.Reason = ('{0} is not on a ready local fixed disk (DriveType={1}).' -f $FinalPath, $drive.DriveType)
        return $result
    }

    $result.IsTrusted = $true
    $result.Reason = 'The path is on a ready local fixed disk.'
    return $result
}

function Open-WacTrustedDirectory {
    <#
    .SYNOPSIS
        Creates or opens one directory and returns a PINNED handle to the object that was really
        created or opened, having proved what that object is.

    .DESCRIPTION
        THE CONTRACT, in enough detail to call it correctly without reading the body.

        INPUT
          -Path                 the directory wanted, in any form Get-WacNormalizedPath accepts.
          -RequireMachineTrust  additionally demand an administrative owner and DACL and a local
                                fixed volume. Pass it whenever SYSTEM will rely on what is written
                                here. Do NOT pass it for a location inside the invoking user's own
                                profile: the user owns that by construction and the rule would
                                refuse it, correctly and uselessly.
          -MaxCreate            how many missing components may be created (default 8).

        OUTPUT - always an object, never $null:
          Path        the normalised path that was asked for
          FinalPath   the handle's own resolved path, or $null when nothing was opened
          Handle      an open [IntPtr] directory handle, or [IntPtr]::Zero
          Created     the paths this call created, in creation order, top down
          IsTrusted   $true only when every proof below passed
          Reason      why, in words. Always populated, on success as well as on refusal
          Sddl        the descriptor the verdict was reached on, or $null

        WHAT IT PROVES, in order, stopping at the first failure:
          1. The deepest EXISTING ancestor of -Path is opened and pinned before anything is created,
             and it must not be a reparse point and must resolve to its own name. Nothing is created
             under an unverified anchor.
          2. Every missing component is created RELATIVE TO THAT HANDLE with the collision-failing
             disposition. A name that already exists comes back as a collision and is REFUSED, never
             adopted, and the create is anchored to a directory object we hold open rather than to a
             path walked from the volume root - so no swap of any ancestor can move where it lands.
             This is the half New-Item -Force does not have, in either respect.
          3. The leaf handle is asked, again, what object it is: not a reparse point, and resolving
             to the requested path.
          4. With -RequireMachineTrust: the volume is a ready local fixed disk, and the owner and
             DACL are read FROM THE HANDLE and judged by Test-WacTrustedDirectoryDescriptor.

        THE PIN. The handle is opened with a share mode that withholds DELETE, so while the caller
        holds it the directory cannot be renamed out of the way or deleted by anyone. That is what
        makes a later create through New-WacBoundFile land in the object that was verified.

        WHAT IT DOES NOT CLOSE. Read this before relying on it.
          * IT DOES NOT VERIFY ANCESTORS. Nothing above the deepest existing ancestor is inspected
            at all, and the anchor's own owner and DACL are never read. The caller must have proved
            the chain separately - Test-WacStatePathIsTrusted is that check - and must run it BEFORE
            calling this, because a refusal afterwards would already have created directories.
          * The pin protects the LEAF, not its parents. A principal holding delete rights on an
            ancestor can still move the whole subtree. Writes through the handle follow the object
            and stay correct; a pathname operation by any other caller would not.
          * It does not stop an administrator, and is not meant to.
          * The descriptor answer is a point in time. An owner implicitly keeps WRITE_DAC, so a
            directory that passes now can be re-permissioned a moment later. The verdict is good for
            the handle it was taken on and is re-taken on every open.
          * It says nothing about CONTENT. A directory that already existed may hold anything,
            including planted names. Create through New-WacBoundFile, whose create fails on
            collision, rather than trusting a name to be free.
          * It does not undo itself. Components created before a later step refuses are LEFT IN
            PLACE and named in Created; they were created by this process under a proved anchor, so
            they are ours, and deleting on a refusal would be a destructive action taken on an
            unproven belief.
          * IT DOES NOT CLOSE THE HANDLE IT RETURNS. On success the caller owns it and must pass it
            to Close-WacTrustedDirectory. On every refusal Handle is [IntPtr]::Zero and nothing is
            left open.
          * Without the native surface it refuses outright rather than falling back to a pathname
            create, because the fallback IS the defect. That makes the run's audit log depend on
            Add-Type succeeding, which is a real widening: before this, a host that could not compile
            still logged. It is a deliberate trade and it fails LOUDLY - Initialize-WacRun returns
            false, the reason reaches the verified fallback sink, and the entry point exits non-zero.

            One measured consequence, because it costs an hour to rediscover: on Windows PowerShell
            5.1 Add-Type compiles through csc.exe and the crypto provider under the REAL %SystemRoot%,
            so a process that has REDIRECTED $env:SystemRoot cannot compile at all - measured, it
            fails with "Error signing assembly -- Provider DLL failed to initialize correctly", and a
            run in such a process therefore gets no log. PowerShell 7 compiles in-process with
            Roslyn and is unaffected. Production never redirects %SystemRoot%; test harnesses that
            do must compile the type before they redirect it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Path,
        [switch]$RequireMachineTrust,
        [ValidateRange(1, 32)][int]$MaxCreate = 8
    )

    $verdict = [PSCustomObject]@{
        Path = $null
        FinalPath = $null
        Handle = [IntPtr]::Zero
        Created = @()
        IsTrusted = $false
        Reason = $null
        Sddl = $null
    }

    $normalized = Get-WacNormalizedPath -Path $Path
    if (-not $normalized) {
        $verdict.Reason = 'The path is not a usable local drive path.'
        return $verdict
    }
    $verdict.Path = $normalized

    if ($normalized -match '^[A-Za-z]:$') {
        $verdict.Reason = 'A volume root is not a state directory and is never created or adopted here.'
        return $verdict
    }

    if (-not (Initialize-WacNative)) {
        $verdict.Reason = 'The native surface is unavailable, so no directory can be bound to a handle.'
        return $verdict
    }

    # Which components are missing, and where the existing chain stops. This probe is by pathname
    # and is deliberately NOT trusted: it only decides what to attempt. Whether each attempt is
    # legitimate is decided by the collision-failing create below, which is bound to a handle.
    $missing = New-Object 'System.Collections.Generic.List[string]'
    $anchor = $normalized
    while (-not [System.IO.Directory]::Exists((Get-WacOpenablePath $anchor))) {
        if ([System.IO.File]::Exists($anchor)) {
            $verdict.Reason = ('{0} exists and is a file, not a directory.' -f $anchor)
            return $verdict
        }
        if ($missing.Count -ge $MaxCreate) {
            $verdict.Reason = ('More than {0} missing directories would have to be created under {1}.' -f $MaxCreate, $normalized)
            return $verdict
        }

        $name = [System.IO.Path]::GetFileName($anchor)
        $parent = [System.IO.Path]::GetDirectoryName($anchor)
        if ([string]::IsNullOrEmpty($name) -or [string]::IsNullOrEmpty($parent)) {
            $verdict.Reason = ('No existing ancestor of {0} could be found.' -f $normalized)
            return $verdict
        }

        $missing.Insert(0, $name)
        $anchor = Get-WacNormalizedPath -Path $parent
        if (-not $anchor) {
            $verdict.Reason = ('An ancestor of {0} could not be canonicalised.' -f $normalized)
            return $verdict
        }
    }

    $created = New-Object 'System.Collections.Generic.List[string]'
    $handle = [IntPtr]::Zero
    $keepHandle = $false

    try {
        $opened = [IntPtr]::Zero
        $win32 = [WacNative]::OpenPinnedDirectory((Get-WacOpenablePath $anchor), [ref]$opened)
        if ($win32 -ne 0) {
            $verdict.Reason = ('{0} could not be opened and pinned (Win32 {1}).' -f $anchor, $win32)
            return $verdict
        }
        $handle = $opened

        $identity = Test-WacBoundDirectoryIdentity -Handle $handle -ExpectedPath $anchor
        if (-not $identity.IsTrusted) {
            $verdict.Reason = $identity.Reason
            return $verdict
        }

        foreach ($name in $missing) {
            $child = Join-Path -Path $anchor -ChildPath $name

            # The seam, and the only thing between the existence probe and the create.
            if ($script:DirectoryCreateProbe) {
                try { $null = & $script:DirectoryCreateProbe $child } catch { $null = $_ }
            }

            $childHandle = [IntPtr]::Zero
            $status = [WacNative]::CreateBoundDirectory($handle, $name, [ref]$childHandle)
            if ($status -ne 0) {
                if (('0x{0:X8}' -f $status) -eq $script:StatusNameCollision) {
                    $verdict.Reason = ('{0} appeared after it was checked for, so it was refused rather than adopted.' -f $child)
                }
                else {
                    $verdict.Reason = ('{0} could not be created (NTSTATUS 0x{1:X8}).' -f $child, $status)
                }
                return $verdict
            }

            [WacNative]::CloseNativeHandle($handle)
            $handle = $childHandle
            $anchor = $child
            [void]$created.Add($child)
        }

        # The leaf, asked one last time who it is. On the no-create path this is the same question
        # answered above; on the create path it is the one that catches an anchor that moved.
        $identity = Test-WacBoundDirectoryIdentity -Handle $handle -ExpectedPath $normalized
        if (-not $identity.IsTrusted) {
            $verdict.Reason = $identity.Reason
            return $verdict
        }
        $verdict.FinalPath = $identity.FinalPath

        if ($RequireMachineTrust) {
            $volume = Test-WacBoundDirectoryVolume -FinalPath $identity.FinalPath
            if (-not $volume.IsTrusted) {
                $verdict.Reason = $volume.Reason
                return $verdict
            }

            $sddl = $null
            $descriptorStatus = [WacNative]::GetHandleDescriptor($handle, [ref]$sddl)
            if ($descriptorStatus -ne 0) {
                $verdict.Reason = ('The owner and DACL of {0} could not be read from its handle (error {1}).' -f $normalized, $descriptorStatus)
                return $verdict
            }
            $verdict.Sddl = $sddl

            $judgement = Test-WacTrustedDirectoryDescriptor -Sddl $sddl
            if (-not $judgement.IsTrusted) {
                $verdict.Reason = ('{0} is not administrative-only: {1}' -f $normalized, [string]$judgement.Reason)
                return $verdict
            }
        }

        $verdict.Handle = $handle
        $verdict.IsTrusted = $true
        $verdict.Reason = ('{0} was {1} and is pinned by an open handle.' -f
            $normalized, $(if ($created.Count -gt 0) { 'created' } else { 'opened' }))
        $keepHandle = $true
        return $verdict
    }
    finally {
        # The caller is told what was created whichever way this ended, and a refusal never leaks a
        # handle: the pin it took is released here.
        $verdict.Created = @($created.ToArray())
        if (-not $keepHandle -and $handle.ToInt64() -ne 0) { [WacNative]::CloseNativeHandle($handle) }
    }
}

function New-WacBoundFile {
    <#
    .SYNOPSIS
        Creates ONE new file inside a directory handle, and refuses a name that is already taken.
    .DESCRIPTION
        The companion to Open-WacTrustedDirectory, and the only supported way to put a file into a
        directory that primitive proved. Two properties, both load-bearing:

          * COLLISION-FAILING. An existing name comes back as Collision. It is never opened,
            truncated, appended to or followed - so a planted file, a planted link and a planted
            hard link are all refused rather than written through.
          * BOUND. The create is resolved against the directory HANDLE, not against a path, so it
            cannot be redirected by anything that happens to the directory's name afterwards.

        -Name must be a single component; a separator is refused, because the kernel would resolve
        it and the anchoring would be lost.

        WHAT IT DOES NOT CLOSE: it says nothing about who may READ what is written. The file
        inherits the directory's descriptor, and judging that is Open-WacTrustedDirectory's job.
    .OUTPUTS
        Kind ('Created' / 'Collision' / 'Failed'), Stream (an open FileStream, or $null),
        and NtStatus. The caller owns the stream and must dispose it.
    #>
    param(
        [Parameter(Mandatory = $true)][IntPtr]$DirectoryHandle,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $result = [PSCustomObject]@{ Kind = 'Failed'; Stream = $null; NtStatus = 0 }

    if (-not (Initialize-WacNative)) { return $result }

    $handle = [IntPtr]::Zero
    $status = [WacNative]::CreateBoundFile($DirectoryHandle, $Name, [ref]$handle)
    $result.NtStatus = $status

    if ($status -ne 0) {
        if (('0x{0:X8}' -f $status) -eq $script:StatusNameCollision) { $result.Kind = 'Collision' }
        return $result
    }

    # The SafeFileHandle takes ownership immediately, so from here the handle is closed exactly
    # once: by the stream, or by disposing the wrapper if the stream could not be built over it.
    $safe = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($handle, $true)
    try {
        $result.Stream = New-Object System.IO.FileStream($safe, [System.IO.FileAccess]::Write)
        $result.Kind = 'Created'
    }
    catch {
        try { $safe.Dispose() } catch { $null = $_ }
        $result.Kind = 'Failed'
    }

    return $result
}

function Close-WacTrustedDirectory {
    <#
    .SYNOPSIS
        Releases the pin taken by Open-WacTrustedDirectory. Safe to call with a zero or $null handle.
    #>
    param([Parameter(Mandatory = $true)][AllowNull()]$Handle)

    if ($null -eq $Handle) { return }
    if (-not ('WacNative' -as [type])) { return }

    $value = [IntPtr]$Handle
    if ($value.ToInt64() -eq 0) { return }
    [WacNative]::CloseNativeHandle($value)
}
