---
title: OpenClaw fetchWithSsrFGuard replays unsafe request bodies across cross-origin redirects
slug: 2024-01-openclaw-ssrf
description: The `fetchWithSsrFGuard` function in OpenClaw replays unsafe request bodies across cross-origin redirects, potentially leading to the exposure of sensitive information when following cross-origin redirects in versions prior to 2026.4.8.
date: "2024-01-10T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - openclaw
  - cross-origin
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-qx8j-g322-qj6m
rules:
  - title: Detect OpenClaw fetchWithSsrFGuard Cross-Origin Request with Body
    description: Detects outbound network connections from OpenClaw with a request body when following cross-origin redirects, indicating potential SSRF vulnerability exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect OpenClaw process creation
    description: Detects OpenClaw process creation events, useful for tracking execution and potentially identifying malicious behavior related to SSRF exploitation.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw, a user-controlled local assistant, is vulnerable to a security issue where the `fetchWithSsrFGuard` function replays unsafe request bodies and headers across cross-origin redirects. Specifically, when a guarded fetch operation encounters a cross-origin redirect, it may inadvertently resend sensitive data contained within the request body or headers to a different origin than intended. This vulnerability affects OpenClaw versions prior to 2026.4.8. The patched version, 2026.4.8, addresses this issue. The fix was verified against commit `d7c3210cd6f5fdfdc1beff4c9541673e814354d5`. This issue is scoped to the OpenClaw trust model and does not assume a multi-tenant service boundary.

## Attack Chain

1. A user initiates a fetch request via OpenClaw's `fetchWithSsrFGuard` function.
2. The fetch request includes a body or sensitive headers intended for a specific origin.
3. The initial server responds with an HTTP 302 redirect to a different origin.
4. The `fetchWithSsrFGuard` function, due to the vulnerability, replays the original request body and headers to the new origin.
5. The destination server receives the unintended data.
6. The destination server processes the data based on the replayed request.
7. The destination server may inadvertently expose or misuse the sensitive data from the original request.

## Impact

Successful exploitation of this vulnerability could lead to the exposure of sensitive user data to unintended third-party servers. While the specific number of victims is not mentioned, any OpenClaw user initiating fetch requests across different origins is potentially at risk. The severity is high because sensitive information such as API keys, authentication tokens, or personal data could be compromised if replayed to a malicious or untrusted destination.

## Recommendation

- Upgrade OpenClaw to version 2026.4.8 or later to remediate the vulnerability.
- Implement additional checks and validations on the server-side to verify the origin and integrity of incoming requests.
- Review and audit existing `fetchWithSsrFGuard` implementations to ensure proper handling of cross-origin redirects.
