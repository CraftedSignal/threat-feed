---
title: OpenClaw Arbitrary File Read and Credential Exfiltration Vulnerability
slug: 2026-04-openclaw-file-read
description: The openclaw package is vulnerable to arbitrary file read and credential exfiltration due to media local roots self-whitelisting in `appendLocalMediaParentRoots`, allowing a model to initiate arbitrary host file reads, potentially leading to credential exfiltration.
date: "2026-04-03T02:53:58Z"
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

The `openclaw` npm package, versions 2026.3.28 and earlier, contains a vulnerability related to media local roots self-whitelisting in the `appendLocalMediaParentRoots` function. This flaw enables a malicious model to initiate arbitrary file reads on the host system. While the tool-fs root expansion requires prior configuration, the vulnerability can still be exploited, resulting in a narrower impact than a default-critical scenario. The vulnerability was reported by @tdjackey and patched in…
