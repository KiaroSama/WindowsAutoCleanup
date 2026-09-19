# Research: restartable transactions

Two questions could not be answered by reading the handoff document, because the handoff does not
raise them. Both were settled from the repository and the delivered diff.

## Q1 - What do the two delivered workflows cost if they are merged?

**Decision**: remove both before merge.

**Evidence**:

- `.github/workflows/review-regressions.yml` runs the `Review6` filter on `windows-2022` only, on
  every push and pull request. The existing `validate` job already discovers every suite recursively
  and runs it on `windows-2022` AND `windows-2025`, on both PowerShell hosts, with a guard that fails
  when a suite on disk is not executed. The handoff itself states the dedicated cases "also execute
  in the full matrix; they are not additional unique scenarios". So the job adds no coverage and one
  permanent duplicate run per push.
- `.github/workflows/source-provenance.yml` archives the tracked tree, hashes it, and uploads it as
  an artifact on every push and pull request, retained 14 days. It exists so the integrating agent
  could check the delivered archive against a published SHA-256. That is a one-off delivery step; the
  workflow would outlive its purpose.

**Alternatives considered**: keep the regression job for a faster signal while working on recovery
(rejected — the same signal is one filtered local run away, and CI minutes are the owner's); keep
provenance behind manual dispatch only (rejected — nothing in the project consumes the artifact, and
an unused workflow is a maintenance liability rather than a capability).

## Q2 - Does the delivered restart proof hold on both hosts, and is it actually monotonic?

**Decision**: the delivered design is correct and supersedes the one currently on `main`.

**Evidence**: the baseline proved a restart by comparing MACHINE UPTIME against the RECORD'S AGE
computed from the civil clock, with a fixed margin. Those are two different clocks. A forward
correction of the civil clock inflates the computed age while uptime is unchanged, so the comparison
can report a restart that never happened - the exact failure the record exists to prevent. The
baseline also read the managed uptime property, which is absent on older hosts and returned nothing
there, so the proof was unavailable precisely where it degraded silently.

The delivered version persists the native counter at the moment the record is raised and proves a
restart only from a DECREASE of that counter, read through a `GetTickCount64` P/Invoke present on
both hosts. The civil timestamp is retained as diagnostic only. Missing, unreadable, equal or
increased readings are inconclusive and preserve the record.

**Alternatives considered**: the WMI last-boot time (rejected - an RPC round trip to a service this
project has already moved a diagnostic off for that reason, and it is itself derived from the civil
clock); a boot-identity value from the registry (rejected - it needs its own migration and reboot
tests, which the handoff correctly places outside this scope).

## What was NOT researched, and why

The handoff's claimed CI evidence (run ids, case counts, red-first checkpoints) is verified in the
tasks, not here: a claim about a past run is checked by reading that run, not by researching it.
