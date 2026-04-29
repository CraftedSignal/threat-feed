---
title: OpenClaw Arbitrary File Read and Credential Exfiltration Vulnerability
slug: 2026-04-openclaw-file-read
description: The openclaw package is vulnerable to arbitrary file read and credential exfiltration due to media local roots self-whitelisting in `appendLocalMediaParentRoots`, allowing a model to initiate arbitrary host file reads, potentially leading to credential exfiltration.
date: "2026-04-03T02:53:58Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - arbitrary-file-read
  - credential-exfiltration
  - openclaw
  - npm
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://github.com/advisories/GHSA-57gh-m6rq-54cf
rules:
  - title: Detect OpenClaw Arbitrary File Read Attempt
    description: Detects attempts to read sensitive files via the openclaw application by monitoring process execution and file access patterns.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - process_creation
      - windows
  - title: Detect OpenClaw File Access to Sensitive Locations
    description: This rule detects file access events from OpenClaw to sensitive locations that could indicate arbitrary file read attempts.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1005
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The `openclaw` npm package, versions 2026.3.28 and earlier, contains a vulnerability related to media local roots self-whitelisting in the `appendLocalMediaParentRoots` function. This flaw enables a malicious model to initiate arbitrary file reads on the host system. While the tool-fs root expansion requires prior configuration, the vulnerability can still be exploited, resulting in a narrower impact than a default-critical scenario. The vulnerability was reported by @tdjackey and patched in version 2026.3.31. Defenders should ensure they are running version 2026.3.31 or later of the `openclaw` package to mitigate the risk of arbitrary file read and potential credential exfiltration.

## Attack Chain

1. A malicious actor crafts or modifies an existing OpenClaw model.
2. The model includes instructions to trigger the `appendLocalMediaParentRoots` function within the `src/media/local-roots.ts` file.
3. Due to the self-whitelisting behavior, the function expands the allowed media parent directories, potentially including sensitive system directories.
4. The model leverages the expanded directory access to request the reading of arbitrary files on the host system.
5. The `openclaw` application processes the model's file read request without proper validation due to the bypassed whitelisting.
6. Sensitive files, such as configuration files or credential stores, are read by the application.
7. The extracted data, including credentials, are then potentially exfiltrated by the malicious model.
8. The attacker gains unauthorized access to sensitive data or systems.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files on the host system where the `openclaw` application is running. This can lead to the exfiltration of sensitive information, including credentials, API keys, or other confidential data. While the exact number of affected installations is unknown, any system running a vulnerable version of the `openclaw` package (<=2026.3.28) is susceptible. The impact is narrowed because the tool-fs root expansion requires prior configuration.

## Recommendation

*   Upgrade the `openclaw` npm package to version 2026.3.31 or later to remediate the vulnerability (reference: Affected Packages / Versions).
*   Implement input validation and sanitization to prevent arbitrary file paths from being processed by the `appendLocalMediaParentRoots` function (reference: `src/media/local-roots.ts`).
*   Deploy the Sigma rule to detect attempts to access sensitive files via the `openclaw` application (reference: Sigma rule below).
*   Review and restrict the tool-fs root expansion configuration to minimize the impact of potential exploitation (reference: Current Maintainer Triage).
