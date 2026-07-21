---
title: '@vitest/browser File Access Bypass Vulnerability (GHSA-p63j-vcc4-9vmv)'
slug: 2026-07-vitest-browser-file-access-bypass
description: A critical vulnerability in `@vitest/browser`'s Browser Mode allows arbitrary file system access due to a bypass of the `allowWrite` permission gate and lack of path confinement, enabling an attacker to read, create, overwrite, or delete files on the local filesystem where the Vitest process is running.
date: "2026-07-21T19:38:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - vulnerability
  - file-access
  - RCE
  - web-dev
vendors:
  - Vitest
products:
  - '@vitest/browser (>= 4.0.0, < 4.1.10)'
  - '@vitest/browser (< 3.2.7)'
  - '@vitest/browser (>= 5.0.0-beta.1, < 5.0.0-beta.6)'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Several of these commands accept a file path from the browser and act on it without checking the `allowWrite` permission gate and without confining the path to the project directory.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: '`upload` (Playwright + WebdriverIO) - Arbitrary local file read; contents are loaded into the page and readable by test code. Highest-impact case.'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: '`upload` (Playwright + WebdriverIO) - Arbitrary local file read; contents are loaded into the page and readable by test code.'
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: '`deleteTracing` - Deletes arbitrary files by path.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Impact
    technique_id: T1491
    technique_name: Defacement
    evidence: '`takeScreenshot` (Playwright + WebdriverIO) - Writes a PNG to an arbitrary path (absolute path used verbatim), creating parent directories.'
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-p63j-vcc4-9vmv
---

A critical vulnerability (GHSA-p63j-vcc4-9vmv) in the `@vitest/browser` package, affecting versions prior to `3.2.7`, between `4.0.0` and `4.1.10`, and between `5.0.0-beta.1` and `5.0.0-beta.6`, has been identified. This flaw allows an attacker to bypass the `allowWrite` permission gate and path confinement mechanisms within Vitest's Browser Mode. The Browser Mode exposes built-in commands that interact with the local filesystem, such as `upload`, `takeScreenshot`, `screenshotMatcher`, `stopChunkTrace`, `deleteTracing`, and `annotateTraces`. These commands accept file paths from the browser without validating the `allowWrite` setting or confining paths to the project directory. Consequently, if the Browser Mode API is network-exposed (e.g., `test.api.host` is set, or the dev server is reachable remotely), a client can exploit this to read, create, overwrite, or delete files on the system where Vitest is running, even when `allowWrite` is explicitly set to `false`. While the writes are limited to specific content types (PNG, zip archives), the arbitrary file read capability poses a significant risk of sensitive data exfiltration.

## Attack Chain

1. **Initial Access**: The attacker gains network access to the Vitest Browser Mode API, typically by exploiting a misconfigured `test.api.host` or a publicly exposed development server.
2. **API Interaction**: The attacker sends a crafted request to a vulnerable Browser Mode command (e.g., `upload`, `takeScreenshot`, `deleteTracing`).
3. **Path Traversal/Absolute Path Injection**: The attacker includes an absolute path or path traversal sequences (e.g., `../`) in the file path parameter of the command.
4. **Permission Bypass**: The vulnerable command processes the client-supplied path without checking the `allowWrite` permission gate.
5. **Arbitrary File Operation**: Depending on the command used, the Vitest process performs an operation on the specified arbitrary file path.
 * `upload` or `annotateTraces`: Reads the contents of an arbitrary local file and discloses them to the attacker.
 * `takeScreenshot`, `screenshotMatcher`, `stopChunkTrace`: Creates or overwrites files (e.g., PNGs, .zip archives) at arbitrary locations.
 * `deleteTracing`: Deletes arbitrary files by path.
6. **Impact**: The attacker achieves arbitrary file read/write/delete capabilities, leading to data exfiltration, system manipulation, or denial of service.

## Impact

The vulnerability allows an attacker with network access to the Vitest Browser Mode API to perform arbitrary file system operations on the host running the Vitest process. This can lead to severe consequences, including the exfiltration of sensitive data from any accessible file (e.g., configuration files, private keys, source code) via commands like `upload` or `annotateTraces`. Attackers can also compromise system integrity by creating, overwriting, or deleting critical files using commands such as `takeScreenshot` or `deleteTracing`. While writes are limited to specific file types (PNGs, zip archives), the ability to delete arbitrary files or overwrite existing ones with attacker-controlled, albeit type-restricted, content could lead to a denial of service or further system compromise. The severity is particularly high if the Vitest environment has elevated privileges or contains sensitive data.

## Recommendation

* **Patch Vulnerable Vitest Installations**: Immediately update `@vitest/browser` to a fixed version: `>= 3.2.7`, `>= 4.1.10`, or `>= 5.0.0-beta.6`.
* **Network Segmentation**: Ensure that the Vitest Browser Mode API (`test.api.host`) is not exposed to untrusted networks or the internet. Restrict network access to only trusted development environments.
* **Principle of Least Privilege**: Run Vitest processes with the minimum necessary file system permissions to limit the blast radius of any potential exploitation.
* **Monitor for Anomalous File Activity**: Implement logging and monitoring for unusual file read, write, or delete operations originating from Vitest processes that exceed expected behavior.
