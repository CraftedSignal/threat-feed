---
title: OpenClaw Webhook Replay Vulnerability (CVE-2026-41395)
slug: 2026-04-openclaw-webhook-replay
description: OpenClaw before 2026.3.28 is vulnerable to webhook replay attacks due to improper signature verification, allowing attackers to reorder query parameters and trigger duplicate voice-call processing.
date: "2026-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - webhook
  - replay-attack
  - plivo
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-41395
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41395
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-8689-gm9g-jgr6
  - https://www.vulncheck.com/advisories/openclaw-webhook-replay-via-query-parameter-reordering-in-plivo-v3
rules:
  - title: Detect Suspicious Webhook Replay
    description: Detects potential webhook replay attacks by identifying duplicate webhook requests within a short timeframe.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Potential Webhook Query Parameter Reordering
    description: Detects potential webhook query parameter reordering by looking for the same parameters with only their order changed.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.3.28 is susceptible to a webhook replay vulnerability affecting Plivo V3 signature verification. The vulnerability arises from the application's method of canonicalizing query parameter ordering for signature verification while simultaneously employing raw URLs for replay detection. This discrepancy allows attackers to manipulate the order of query parameters within a captured, valid, signed webhook, effectively bypassing the replay cache detection mechanism. This could lead to the unintended execution of duplicate voice-call processing. The vulnerability was reported on April 28, 2026, and poses a risk to systems relying on OpenClaw for processing Plivo webhooks.

## Attack Chain

1.  Attacker captures a valid, signed webhook request from Plivo to OpenClaw.
2.  Attacker analyzes the captured webhook request, noting the query parameters and their order.
3.  Attacker reorders the query parameters in the captured webhook request, while maintaining the validity of the signature (due to OpenClaw's canonicalization of query ordering for signature verification).
4.  Attacker replays the modified webhook request to the OpenClaw server.
5.  OpenClaw processes the replayed webhook request because the replay detection mechanism is bypassed due to the reordered query parameters resulting in a different raw URL.
6.  The OpenClaw application initiates a duplicate voice-call processing as a result of the replayed webhook.
7.  The victim experiences unintended or duplicate voice calls.

## Impact

Successful exploitation of this vulnerability can lead to unintended or duplicate voice calls, potentially causing disruption of services and financial implications due to unnecessary call charges. While the direct impact is limited to the processing of voice calls, the vulnerability highlights a weakness in webhook security that could be exploited further in other contexts. The severity is rated as HIGH with a CVSS v3.1 score of 7.5.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to remediate the vulnerability (CVE-2026-41395).
*   Implement server-side logging for all incoming webhook requests, capturing the raw request URL and timestamp. Deploy the Sigma rule `Detect Suspicious Webhook Replay` to identify potential replay attacks based on duplicate URLs within a short timeframe.
*   Consider implementing additional server-side validation of webhook requests, such as verifying the timestamp to ensure it falls within an acceptable window.
