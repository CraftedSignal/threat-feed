---
title: 'New API: SSRF Protection Bypass via Unresolved Hostname in Notification URLs'
slug: 2026-07-ssrf-protection-bypass-unresolved-hostname
description: An SSRF protection bypass vulnerability, CVE-2026-33655, in the QuantumNous new-api, affecting versions prior to v0.12.0-alpha.1, allows authenticated users to send requests to internal HTTP services by configuring notification URLs with unresolved hostnames, leading to potential sensitive internal data exposure through timing, errors, or response-dependent behavior.
date: "2026-07-07T13:16:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - api
  - vulnerability
  - bypass
  - web-application
vendors:
  - QuantumNous
products:
  - new-api (< 0.12.0-alpha.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated users could configure notification URLs for Webhook, Bark, or Gotify notifications and point a hostname at an internal or metadata IP address.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Depending on the target environment, this could expose sensitive internal data through timing, errors, or response-dependent behavior.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6qcr-qxgr-m7fv
  - CVE-2026-33655
---

A significant vulnerability, CVE-2026-33655, has been identified in the QuantumNous `new-api` application, impacting all versions prior to `v0.12.0-alpha.1`. This Server-Side Request Forgery (SSRF) protection bypass allows authenticated users to interact with internal HTTP services that would otherwise be inaccessible. The flaw stems from a default configuration where `ApplyIPFilterForDomain` is disabled, meaning the application fails to resolve hostnames in notification URLs (Webhook, Bark, Gotify) to their IP addresses before applying IP filtering rules. This oversight permits an attacker to specify a hostname that resolves to an internal or metadata IP address, causing the vulnerable server to initiate outbound connections to these sensitive internal targets. This capability can be leveraged for internal network reconnaissance and information disclosure, posing a substantial risk to affected deployments.

## Attack Chain

1.  **Initial Access (Authenticated User)**: An attacker gains or compromises a legitimate user account within the vulnerable `new-api` application, as this vulnerability requires authenticated access to configure notification URLs.
2.  **Identify Internal Targets**: The attacker identifies potential internal HTTP services or cloud metadata endpoints accessible from the `new-api` deployment network through reconnaissance or prior knowledge.
3.  **Configure Notification URL**: The authenticated attacker accesses the application's notification settings (e.g., Webhook, Bark, or Gotify) where custom URLs can be specified.
4.  **SSRF Payload Insertion**: The attacker crafts a notification URL containing an unresolved hostname (e.g., `localhost`, `169.254.169.254.nip.io` or a custom hostname resolving to an internal IP) that points to the identified internal target.
5.  **Server Initiates Request**: Upon a triggering event, the `new-api` application attempts to resolve the provided hostname and initiate an outbound connection for the notification.
6.  **IP Filtering Bypass**: Due to the default `ApplyIPFilterForDomain: false` setting in affected versions, the application does not resolve the hostname to its IP address and compare it against the configured internal/metadata IP blocklist before making the connection.
7.  **Internal Network Interaction**: The `new-api` server proceeds to make a direct network request to the internal IP address or metadata endpoint disguised by the attacker's crafted hostname.
8.  **Information Disclosure**: The attacker observes the application's behavior (e.g., timing, error messages, or direct responses) to discover internal network topology, sensitive data, or credentials, potentially leading to further exploitation and unauthorized access.

## Impact

Successful exploitation of CVE-2026-33655 allows a regular authenticated user to bypass existing SSRF protections and compel the `new-api` server to initiate connections to internal HTTP services or cloud metadata APIs. Depending on the target environment, this can lead to significant information disclosure. Attackers can leverage timing analysis, error messages, or direct responses to map internal networks, enumerate services, or exfiltrate sensitive data such as API keys, cloud credentials, or private configuration details. While the advisory does not specify observed victim counts or sectors, any organization using affected `new-api` versions in an environment with accessible internal HTTP services is at risk of unauthorized data exposure and potential lateral movement.

## Recommendation

*   Immediately upgrade to `new-api` version `v0.12.0-alpha.1` or later to address CVE-2026-33655.
*   If immediate upgrade is not possible, explicitly enable `ApplyIPFilterForDomain: true` in your `new-api` configuration to enforce hostname resolution and IP filtering.
*   Implement an allowlist for domains that can be used in notification URLs, restricting connectivity to only known, legitimate external services.
*   Disable user-configurable notification URLs within the `new-api` where practical, limiting the attack surface for this and similar vulnerabilities.
*   Enforce robust outbound network filtering at the host or network layer, blocking connections from the `new-api` server to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254/32) and other unauthorized destinations.
