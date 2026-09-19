from pathlib import Path
import hashlib
r = Path('.')
def edit(n, a, b):
    p = r / n
    s = p.read_text()
    assert s.count(a) == 1, (n, s.count(a))
    p.write_text(s.replace(a, b))
edit('Tests/DeploymentProof.Tests.ps1', "        'WindowsAutoCleanup.TaskMatch.ps1',", "        'WindowsAutoCleanup.TaskMatch.ps1', 'WindowsAutoCleanup.UninstallIntent.ps1',")
edit('src/WindowsAutoCleanup.OwnedRun.ps1', '[WacOwnedProcess]::WaitForExit($Launch.Process, (& $remaining))', '[WacOwnedProcess]::WaitForExit($Launch.Process, (Get-WacStepTimeoutMs -RequestedMs (& $remaining)))')
edit('src/WindowsAutoCleanup.OwnedRun.ps1', "if (-not $timedOut -and [string]$tree.State -ceq 'Alive' -and (& $remaining) -le 0) {", "if (-not $timedOut -and [string]$tree.State -ceq 'Alive' -and\n        ((& $remaining) -le 0 -or (Test-WacDeadlineExpired))) {")
edit('Tests/OwnedProcess.Tests.ps1', '            $launch = Start-WacOwnedProcess -FilePath $FilePath -ArgumentList $ArgumentList\n            Set-WacDeadline', '            $launch = Start-WacOwnedProcess -FilePath $FilePath -ArgumentList $ArgumentList\n            # Establish root exit before advancing the run deadline; the grandchild stays alive.\n            [void][WacOwnedProcess]::WaitForExit($launch.Process, 10000)\n            Set-WacDeadline')
edit('Tests/BudgetBoundary.Tests.ps1', '        $launch = Start-WacOwnedProcess -FilePath $FilePath -ArgumentList $ArgumentList\n        Set-WacDeadline', '        $launch = Start-WacOwnedProcess -FilePath $FilePath -ArgumentList $ArgumentList\n        # The unowned fixture measures drains after root exit, not a pre-start timeout.\n        if (-not $launch.Owned) { [void][WacOwnedProcess]::WaitForExit($launch.Process, 10000) }\n        Set-WacDeadline')
p = r / 'Tests/ProcessOwnership.Tests.ps1'
s = p.read_text()
a = s.index("Test-Case 'a child holding the inherited pipe")
b = s.index("Test-Case 'an ordinary tool", a)
old = s[a:b]
new = old.replace("'cmd.exe' -ArgumentList '/c','ping -n 4 127.0.0.1 >nul'", "'$script:HostExe' -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 15'")
new = new.replace('Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddMilliseconds(-1))', "Set-WacDeadline -DeadlineUtc ([datetime]::UtcNow.AddHours(1))\n        Set-WacOwnedProcessLauncher -Launcher { param($FilePath, $ArgumentList); $null = $FilePath; $null = $ArgumentList; return $null }")
new = new.replace('-TimeoutMs 20000', '-TimeoutMs 4000')
new = new.replace('        Remove-Item -LiteralPath $marker', '        Set-WacOwnedProcessLauncher -Launcher $null\n        Remove-Item -LiteralPath $marker')
new = new.replace('the grandchild is a bounded ping whose', 'the grandchild is a bounded PowerShell child whose')
new = new.replace('    # pid the root writes out, and the teardown kills it. The expired deadline plus a deliberately\n    # tiny recovery reserve is what clamps the read budget: past the deadline a drain draws from the\n    # reserve, so the reserve is the knob, and the case costs about a second instead of five.', '    # pid the root writes out, and the teardown kills it. Force the managed fallback: the owned\n    # path now correctly waits for and terminates descendants rather than returning this state.\n    # A live admission deadline lets the root run; the operation allowance bounds both pipe reads.')
assert new != old
p.write_text(s[:a] + new + s[b:])
p = r / 'README.md'
s = p.read_text()
a = s.index('### A run that refuses to clean from an unfinished installation')
b = s.index('## Concurrency', a)
replacement = '''### A run that refuses to clean from an unfinished installation

The runtime tree and scheduled registration are one recovery transaction. A record beside the
deployment root can describe either an unfinished generation or committed cleanup still pending.
The runtime refuses while either half is unresolved. Re-run the installer only when installation,
not removal, is the intended operation; it reconciles task definitions and file identities before
staging a new generation.

The durable commit includes the verified replacement task definition. Recovery restores the
original pair before commit, or the exact replacement pair after commit. An empty original task
set or deployment directory is explicit evidence, not a missing capture. Different generation IDs,
corrupted replacement contents and incomplete inspections refuse recovery without deleting evidence.
A locked capture keeps its authoritative commit record and recovery copy; an incomplete retirement
is not a successful installation.

An authorized uninstall first writes `<deployment-root>.uninstall.json`. While it remains, runtime
and install admission refuse rather than resurrecting a task from an older upgrade capture. Resume
the uninstaller to complete removal. It retires task captures, then the swap record, and the uninstall
intent last. Do not delete transaction records merely to clear a warning.

### A run that refuses to mutate anything

A timed-out mutator can leave work outside the thread or process that started it. The run records
`abandoned-mutation.json` in `%SystemRoot%\\Logs\\WindowsAutoCleanup\\Control` and stops conflicting
mutations. Cleanup, installation and removal all honor this gate.

Only explicitly host-confined work is classified `InProcess`; its recorded process ID and creation
time can establish that the host is gone. Other mutating bounded blocks default to `External`,
including service-dispatching cmdlets. An external marker cannot retire just because the WAC host
exited, its pipes closed, or civil time advanced. A recorded monotonic system uptime followed by a
lower current uptime supplies conservative restart evidence. Missing evidence, a failed probe or a
current counter not lower than the recorded one keeps the marker. A late check after a genuine
restart may therefore still require operator verification; changing the wall clock is not a remedy.

A quarantined run still writes its diagnostic report but starts no conflicting cleanup step.
Job ownership proves completion only for job members, not arbitrary service/WMI-dispatched work.
Old markers under `%ProgramData%\\WindowsAutoCleanup` remain untrusted and are neither followed nor
silently removed. Inspect unresolved work and recovery data before manually retiring any evidence.

The same strict control store protects the originals of a borrowed cleanmgr profile. Only a snapshot
created by the current attempt belongs to that attempt. A pre-existing snapshot blocks another
legacy-cleanmgr invocation with `Incomplete` and remains intact for controlled recovery. Verified
restoration retires the owned snapshot; a zero-write attempt retires only its own unnecessary copy.
A failed retirement remains `Incomplete`. Never overwrite or delete an earlier original to make a
later run appear clean.

'''
s = s[:a] + replacement + s[b:]
lines = s.splitlines()
for i, line in enumerate(lines):
    if line.startswith('| `src/WindowsAutoCleanup.Quarantine.ps1` |'):
        lines[i] = '| `src/WindowsAutoCleanup.Quarantine.ps1` | Durable mutation admission in the strict control store. In-process and external lifetimes are distinct; only positive process or monotonic restart evidence can retire uncertainty. |'
p.write_text('\n'.join(lines) + '\n')
p = r / 'src/WindowsAutoCleanup.Quarantine.ps1'
s = p.read_text()
a = s.index('    For a blocking READ')
b = s.index('    WHY IT HAD', a)
s = s[:a] + '''    A blocking read can be abandoned without authorizing a mutation. For writing work, the latch
    records uncertainty durably. Job membership establishes only the lifetime of actual members;
    service-dispatched work needs a separate external classification and cannot be cleared solely
    because the initiating WAC process or an initiating job exited.

''' + s[b:]
a = s.index('    WHAT CLEARS IT.')
b = s.index('    Within a run', a)
s = s[:a] + '''    WHAT CLEARS IT. InProcess work may retire only on positive process identity/lifetime evidence.
    External work requires conservative monotonic restart evidence; civil-clock age is never proof.
    Missing or inconclusive evidence preserves the marker. A late observation after a real restart
    may remain inconclusive rather than fabricating a reason to proceed.

''' + s[b:]
s = s.replace('and it does so only on proof that the process which wrote it is gone.', 'and only positive completion evidence may retire it.')
p.write_text(s)
for name in ('ci.yml', 'source-provenance.yml', 'review-regressions.yml'):
    p = r / '.github/workflows' / name
    s = p.read_text()
    assert '\nconcurrency:' not in s
    s = s.replace('\npermissions:', '\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true\n\npermissions:', 1)
    if name == 'ci.yml':
        s = s.replace('            ${{ runner.temp }}/run-environment.json\n', '            ${{ runner.temp }}/run-environment.json\n            .ci-work/windows/**/*.out\n            .ci-work/windows/**/*.err\n', 1)
    p.write_text(s)
expected = {
    '.github/workflows/ci.yml': 'd5be02df161e2ac48969cdb51d9a170037f5b18956266e8c6866f3253d626dbf',
    '.github/workflows/review-regressions.yml': 'f0e70470544966b8fb4aa30246eba11c5ef37f91928999794b3dcea0c37a2949',
    '.github/workflows/source-provenance.yml': '721c9a55f749afdef394c2e3cb3b59fd3057b3a42028ff5ad4fad7d3c3a034f0',
    'README.md': '0769ad76eae20fa32806231a3a0b79b90ed12322dd04e7dcb8074f9261777784',
    'Tests/BudgetBoundary.Tests.ps1': '105585ce05217204c554676b7f04a753762880e4f4dc779755694ef392954268',
    'Tests/DeploymentProof.Tests.ps1': 'd8f4d0fde997926519edcc3d02729ee1e41ef23762865398c02c69848e8b270f',
    'Tests/OwnedProcess.Tests.ps1': '522244513c5c9fa3077589225edcbd45dd57244353ec339a17786d8757d5eb88',
    'Tests/ProcessOwnership.Tests.ps1': 'c401ea60ef0e0dbc5fe24038a85dca77a88dbe83ce82e57d8e65db18de4f04ce',
    'src/WindowsAutoCleanup.OwnedRun.ps1': 'b9bbbd853eac6f6ad9ec3bf09045b515d41db4a3c38fd53fabbfb21b460c6797',
    'src/WindowsAutoCleanup.Quarantine.ps1': 'b0ec916a9d7928294e52479e6b7d3b3f26bc491ebf52756d6211b61786d7b05c',
}
for name, sha in expected.items():
    assert hashlib.sha256((r / name).read_bytes()).hexdigest() == sha, name
print('All final adjustments match the independently prepared source bytes.')
