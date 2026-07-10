---
title: BuildKit Malicious Frontend File Escape Vulnerability
slug: 2024-01-buildkit-file-escape
description: A malicious BuildKit frontend can craft API messages that write files outside the BuildKit state directory, leading to file escape, fixed in v0.28.1+ and requires using an untrusted frontend with `#syntax` or `--build-arg BUILDKIT_SYNTAX`.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buildkit
  - file-escape
  - privilege-escalation
  - cve-2026-33747
vendors:
  - Docker
products:
  - BuildKit
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-4c29-8rgm-jvjj
rules:
  - title: Detect Suspicious BuildKit Frontend Usage
    description: 'Detects the use of potentially untrusted BuildKit frontends specified via #syntax or --build-arg BUILDKIT_SYNTAX, which is a prerequisite for CVE-2026-33747 exploitation.'
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect BuildKit File Creation Outside State Directory
    description: Detects file creation events outside the default BuildKit state directory.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-33747 describes a file escape vulnerability in BuildKit versions prior to v0.28.1. The vulnerability stems from a malicious BuildKit frontend's ability to craft API messages that cause files to be written outside of the designated BuildKit state directory for the execution context. This issue arises when using a custom, untrusted BuildKit frontend set via either the `#syntax` directive within a Dockerfile or through the `--build-arg BUILDKIT_SYNTAX` build argument. Exploitation requires the use of an untrusted frontend, and well-known frontends like `docker/dockerfile` are not affected. Successful exploitation allows an attacker to write arbitrary files to the host system, potentially leading to privilege escalation or code execution. Defenders should ensure BuildKit is updated to v0.28.1 or later and exercise caution when using custom frontends.

## Attack Chain

1. An attacker crafts a malicious BuildKit frontend.
2. The victim builds an image using BuildKit, specifying the malicious frontend via `#syntax` in the Dockerfile or `--build-arg BUILDKIT_SYNTAX`.
3. BuildKit initiates the build process, handing control to the malicious frontend.
4. The malicious frontend crafts a specific API message designed to exploit the file escape vulnerability.
5. BuildKit processes the crafted API message without proper validation of file paths.
6. The malicious frontend instructs BuildKit to write a file to a location outside of the BuildKit state directory.
7. BuildKit, lacking sufficient path sanitization, writes the file to the attacker-controlled path on the host system.
8. The attacker achieves arbitrary file write, potentially leading to code execution or privilege escalation.

## Impact

Successful exploitation of CVE-2026-33747 allows an attacker to write arbitrary files on the host system where BuildKit is running. This can lead to a variety of consequences, including privilege escalation by overwriting system binaries, arbitrary code execution by placing malicious executables in startup directories, or data exfiltration by accessing sensitive files. The severity is high because it breaks container isolation and allows for host compromise. The number of potential victims is dependent on the adoption of BuildKit and the use of custom frontends.

## Recommendation

*   Upgrade BuildKit to version v0.28.1 or later to patch CVE-2026-33747.
*   Exercise extreme caution when using custom BuildKit frontends. Avoid using untrusted frontends specified via `#syntax` or `--build-arg BUILDKIT_SYNTAX`.
*   Implement the provided Sigma rule `Detect Suspicious BuildKit Frontend Usage` to detect the usage of custom frontends.
*   Implement the provided Sigma rule `Detect BuildKit File Creation Outside State Directory` to detect file creation events.
