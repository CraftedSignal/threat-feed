---
title: Nautobot Webhook SSRF Vulnerability
slug: 2026-05-nautobot-ssrf
description: Nautobot's Webhook feature is vulnerable to server-side request forgery (SSRF), allowing users with `add` or `change` permissions to make requests to unauthorized hosts, which is fixed in versions 2.4.33 and 3.1.2 by introducing settings to restrict webhook functionality.
date: "2026-05-13T15:32:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - nautobot
  - cve-2026-44797
vendors:
  - Nautobot
products:
  - Nautobot (< 2.4.33)
  - Nautobot (>= 3.0.0a2, < 3.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-c35q-vxrp-ph26
  - https://github.com/nautobot/nautobot/commit/16aa4aa9796ab7a31c4d615ec945e1f16d8c77c4
  - https://github.com/nautobot/nautobot/commit/7324c8f0d8c7245fbc691e15d729adc2d2707d08
rules:
  - title: Detect Suspicious Nautobot Webhook Configuration
    description: Detects CVE-2026-44797 exploitation -- attempts to configure Nautobot Webhooks with non-HTTP(S) schemes.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious Nautobot Webhook Configuration to Private IP
    description: Detects CVE-2026-44797 exploitation -- attempts to configure Nautobot Webhooks pointing to private IP addresses.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Nautobot's `Webhook` data model is susceptible to server-side request forgery (SSRF) due to insufficient restrictions on webhook destinations. This vulnerability allows users with the ability to create or modify `Webhook` records to potentially initiate requests to internal or otherwise restricted hosts and IP addresses. This can lead to information disclosure, internal network scanning, or exploitation of other internal services. The vulnerability affects Nautobot versions prior to 2.4.33 and versions between 3.0.0a2 and 3.1.2. Patches were released on May 13, 2026, in Nautobot v2.4.33 and v3.1.2 to address this issue. New settings `WEBHOOK_ALLOWED_SCHEMES`, `WEBHOOK_ADDITIONAL_BLOCKED_NETWORKS`, and `WEBHOOK_ALLOWED_HOSTS` are introduced to mitigate the risk.

## Attack Chain

1. An attacker gains unauthorized access to a Nautobot account with permissions to manage Webhook objects (add or change).
2. The attacker creates a new Webhook or modifies an existing one.
3. The attacker configures the Webhook to send requests to an internal or restricted IP address or hostname. This could be an internal service, a local network address, or a blocked external host.
4. A triggering event occurs within Nautobot that activates the Webhook (e.g., device creation, change of status).
5. Nautobot's Webhook functionality initiates an HTTP/HTTPS request to the attacker-specified destination.
6. The target host receives the request originating from the Nautobot server.
7. The attacker observes the response from the target host or uses the SSRF to interact with internal services.
8. The attacker leverages the SSRF to potentially gather sensitive information, bypass access controls, or exploit vulnerable internal services.

## Impact

Successful exploitation of this SSRF vulnerability can lead to the exposure of internal network infrastructure, sensitive data residing on internal services, or the ability to pivot to other internal systems. The impact depends on the accessibility and vulnerabilities of the targeted internal services. Without proper restrictions, attackers could potentially compromise the entire Nautobot server and the network it resides on.

## Recommendation

*   Upgrade to Nautobot version 2.4.33 or 3.1.2 or later to apply the patches for CVE-2026-44797.
*   Review user permissions and restrict `add` and `change` permissions for the `Webhook` data model to only trusted administrators.
*   Audit existing `Webhook` records for suspicious or unauthorized destination URLs and IP addresses as recommended in the advisory.
*   Configure the `WEBHOOK_ALLOWED_SCHEMES` setting to restrict Webhooks to only HTTP and HTTPS protocols.
*   Utilize the `WEBHOOK_ADDITIONAL_BLOCKED_NETWORKS` setting to block access to internal networks (e.g., RFC1918 addresses) or other prohibited IP ranges.
*   If necessary, use the `WEBHOOK_ALLOWED_HOSTS` setting to explicitly allow access to specific hosts that are otherwise blocked by `WEBHOOK_ADDITIONAL_BLOCKED_NETWORKS`.
*   Deploy the Sigma rule to detect potentially malicious Webhook configurations.
