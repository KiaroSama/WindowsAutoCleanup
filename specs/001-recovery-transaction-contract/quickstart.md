# Quickstart: verifying this feature

## Prerequisites

- Windows with both hosts available (`powershell.exe` and `pwsh`).
- The repository checked out. The ordinary suites need no elevation.

## The ordinary verification

Run one filtered suite while working (a light check). The whole suite is NOT the local completion
pass: the heavy pass belongs to GitHub CI on the pushed SHA.

    .\Tests\Run-Tests.ps1 -Host both -Filter Review6

Expected: every suite reports `TOTAL cases=N passed=N failed=0 skipped=0`, and the run summary
reports `leakedSuiteProcesses=0`. A skipped case is a failure in this project, not a pass.

## The hygiene gates, in the order CI runs them

    git diff --check 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD
    Invoke-ScriptAnalyzer -Path src -Recurse -Settings .\Tests\PSScriptAnalyzerSettings.psd1

The whitespace gate runs BEFORE the tests in CI. A trailing blank line at end of file aborts the job
before anything is proven, and the suite-coverage guard then reports a missing manifest - one defect
presenting as two failures.

## The armed lifecycle lane

The real install / scheduled run / upgrade / uninstall lane changes the machine it runs on. It is
armed only on a disposable GitHub-hosted runner, in the `deployment-lifecycle` job, single-worker
because it owns exclusive machine state - one deployment root, one registration, one machine-wide
lock. Never arm it on a workstation.

    $env:WAC_VM_DEPLOYMENT_LIFECYCLE = '1'   # inside a disposable guest only, checkpoint taken first
    .\Tests\Run-Tests.ps1 -Host both -MaxWorkers 1 -Filter VmDeploymentLifecycle

An unarmed run reports the lane as refused. That is a pass that has validated nothing, and the CI job
fails on it deliberately.

## What "verified" means here

An acceptance item is verified when the behaviour it names has a test that goes RED once that
behaviour is removed from the SOURCE, with the failure landing on the assertion rather than on an
unrelated error. A passing suite over unchanged code proves only that the suite runs.
