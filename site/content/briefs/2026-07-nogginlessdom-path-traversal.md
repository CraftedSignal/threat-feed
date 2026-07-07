---
title: Path Traversal Vulnerability in @asymmetric-effort/nogginlessdom Allows Arbitrary File Write
slug: 2026-07-nogginlessdom-path-traversal
description: A path traversal vulnerability (GHSA-322x-v876-g883) in the `matchFileSnapshot` function of the `@asymmetric-effort/nogginlessdom` library allows an attacker to write arbitrary content to any filesystem path with write access when snapshot update mode is active, potentially leading to supply chain compromise in CI/CD environments.
date: "2026-07-03T11:29:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - supply-chain
  - ci/cd
  - npm
  - vulnerability
vendors:
  - asymmetric-effort
products:
  - nogginlessdom (<= 0.0.21)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: In CI/CD environments where test files may come from untrusted pull requests, this allows writing to any writable filesystem location.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: 'An attacker could overwrite configuration files, inject code into build artifacts, or modify CI pipeline definitions. Example: ''/home/runner/.github/workflows/backdoor.yml''.'
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: In CI environments, could overwrite CI config
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1565
    technique_name: Supply Chain Compromise
    evidence: An attacker could overwrite configuration files, inject code into build artifacts, or modify CI pipeline definitions.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-322x-v876-g883
---

A critical path traversal vulnerability, tracked as GHSA-322x-v876-g883, has been identified in the `matchFileSnapshot` function within the `@asymmetric-effort/nogginlessdom` JavaScript library, specifically in versions `0.0.21` and earlier. This flaw arises from insufficient validation of the `filePath` parameter when the library operates in snapshot update mode (e.g., `UPDATE_SNAPSHOTS=1` environment variable or `setUpdateMode('all')`). An attacker capable of controlling the `filePath` input during testing can exploit this to write arbitrary content to any location on the filesystem where the process has write permissions. This includes creating new directories and overwriting existing files, posing a significant risk, particularly in CI/CD pipelines where untrusted test inputs from pull requests could lead to supply chain compromise.

## Attack Chain

1.  An attacker crafts malicious test input that includes a specially constructed `filePath` parameter containing path traversal sequences (e.g., `../../../tmp/evil.txt`).
2.  The malicious test input is processed in an environment where the `@asymmetric-effort/nogginlessdom` library is used, and the snapshot update mode is active (`UPDATE_SNAPSHOTS=1` or `setUpdateMode('all')`).
3.  The vulnerable `matchFileSnapshot` function is called with the attacker-controlled `filePath` and arbitrary content.
4.  The `fs.existsSync(filePath)` check fails because the path is outside the expected directory, triggering the creation logic.
5.  The library’s `fs.mkdirSync(dir, { recursive: true });` function creates intermediate directories specified by the attacker in the malicious `filePath`.
6.  The `fs.writeFileSync(filePath, serialized, 'utf-8');` function writes attacker-controlled `serialized` content to the arbitrary `filePath`.
7.  In a CI/CD environment, this allows overwriting critical configuration files (e.g., `/home/runner/.github/workflows/backdoor.yml`), injecting malicious code into build artifacts, or modifying pipeline definitions.
8.  The successful write leads to arbitrary code execution, persistence within the build system, or compromise of distributed software.

## Impact

The vulnerability allows an attacker to perform arbitrary file writes, creating new directories and overwriting existing files with attacker-controlled content. In CI/CD environments, this is particularly severe as untrusted pull requests could trigger the exploit. Consequences include the complete compromise of build processes, such as overwriting CI configuration files to inject malicious steps, injecting malicious code directly into build artifacts, or modifying source code used in subsequent builds. This directly enables supply chain attacks, potentially affecting all downstream consumers of the compromised software. The specific number of victims is not available, but any organization using vulnerable versions of the library in their CI/CD systems is at risk.

## Recommendation

*   Upgrade `@asymmetric-effort/nogginlessdom` to version `0.0.22` or later immediately to apply the patch referenced in GHSA-322x-v876-g883.
*   Implement controls to prevent untrusted input from reaching build environments, especially in CI/CD pipelines.
*   Review CI/CD pipeline definitions and build artifacts for unauthorized modifications after applying the patch.
