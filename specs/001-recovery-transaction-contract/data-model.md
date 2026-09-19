# Data model: the durable records

Four records, four lifetimes. They are separate files because a single file's next write would
destroy the evidence the others exist to preserve.

## Swap record - beside the deployment root, `.transaction.json`

What a tree replacement was in the middle of. Rewritten at each stage of one move pair; deleted when
the transaction ends.

| Field | Meaning |
|---|---|
| `Schema`, `ProjectId`, `Root`, `Previous` | identity and validity of the record itself |
| `TransactionId` | the GENERATION: what binds this record to the capture record beside it |
| `Stage` | human-readable progress; nothing branches on it |
| `OriginalState` | `Absent`, `Empty` or `Substantive` - the distinction FR-001 turns on |
| `OriginalKind`, `OriginalVersion`, `OriginalTampered`, `OriginalFingerprint`, `OriginalFileCount` | what the original WAS, taken while it was still at the root |
| `ReplacementManifestHash` | the replacement's content identity, recorded BEFORE the first move |
| `Committed` | the decision, written only by the process that verified both halves |
| `ReplacementTask` | the verified replacement registration this commit is about |
| `TaskDecision` | whether the replacement registration was proven; gates every read of `ReplacementTask` |

## Task capture record - beside the deployment root, `.taskcapture.json`

The exact definitions of registrations taken away. It must outlive every stage of the swap, because
the machine can be missing a registration whatever the tree is doing. An explicitly EMPTY array is
meaningful: it records that a first installation found no original task, which is different from a
record that names nothing because it was never written.

## Uninstall intent record - beside the deployment root, `.uninstall.json`

That a removal began. Written before anything is removed; retired LAST, after the records that depend
on it. While it stands, installation and ordinary cleanup refuse.

## Quarantine record - the machine control store

That a mutation was abandoned. It belongs to the MACHINE, not to a deployment.

| Field | Meaning |
|---|---|
| `Kind` | `InProcess` or `External` - which retirement path may apply |
| `ProcessId`, `ProcessStartUtc` | identity for the in-process retirement path |
| `RaisedUptimeMs` | the monotonic reading a later process compares against |
| `RaisedUtc`, `Reason` | diagnostic only; never proof |

## Retirement order, by outcome

The surviving record must always be the one a retry still needs.

```
RestoreOriginal (rollback):
    verify/recover task A, restore the original files/state
    retire the swap journal;  on failure keep capture A and fail non-clean
    retire capture A;         a crash here leaves a capture-only retry, which is safe

CommitReplacement (commit):
    verify committed files B and replacement task B
    retire the original capture A;  on failure keep the commit journal
    retire the commit journal last; a retry can still prove task B
```

## Validation rules carried by every reader

- `Absent`, `Empty` and `Substantive` are carried end to end; none collapses into another.
- A record path that is a directory, malformed or unreadable is neither a valid record nor an absence.
- Only PROVEN absence is "nothing to retire"; an unreadable probe is a failed retirement.
- A failed retirement propagates as non-clean; it never becomes a warning followed by success.
- An optional field is read through the record accessor, never as a direct property: under strict
  mode a missing member throws, and an absent array field must read as "not recorded" rather than as
  one malformed entry.
