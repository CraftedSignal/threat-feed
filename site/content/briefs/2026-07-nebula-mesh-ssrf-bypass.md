---
title: Nebula-mesh Non-Admin SSRF Bypass via Webhook Configuration
slug: 2026-07-nebula-mesh-ssrf-bypass
description: 'A vulnerability in Nebula-mesh allows non-admin operators with the ''user'' role to bypass Server-Side Request Forgery (SSRF) protection by setting `allow_private: true` on webhook subscriptions, enabling the server to make requests to internal or loopback network addresses, which can lead to internal network probing, blind interaction with internal services, and potentially the exfiltration of cloud IAM credentials.'
date: "2026-07-14T20:34:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - server-side-request-forgery
  - ssrf
  - privilege-escalation
  - authorization-bypass
  - web-application
  - nebula-mesh
vendors:
  - ForgeKeep
products:
  - nebula-mesh (>= 0.6.0, <= 0.7.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1090
    technique_name: Proxy
    evidence: A non-admin operator gains server-side request capability against internal-only/loopback addresses, outside the admin boundary the codebase enforces everywhere else. Enables internal reachability probing and blind POST interaction with internal services.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Network Information
    evidence: A non-admin operator gains server-side request capability against internal-only/loopback addresses... Enables internal reachability probing and blind POST interaction with internal services. The dispatcher's delivery-recording path stores success/failure and error text only, never the target's response body... a reachability oracle over internal addresses.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7rx3-5wx3-5v76
rules:
  - title: Detect Nebula-mesh Server Outbound Connections to Internal/Loopback IPs (SSRF Attempt)
    description: Detects the Nebula-mesh server making outbound network connections to internal, loopback, or link-local IP addresses, which indicates a successful SSRF bypass as described in GHSA-7rx3-5wx3-5v76. A low-privilege operator can configure webhooks to trigger such connections.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1090.003
      - T1592.001
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

A critical authorization bypass vulnerability (GHSA-7rx3-5wx3-5v76) in ForgeKeep's Nebula-mesh, affecting versions 0.6.0 through 0.7.1, allows non-admin operators to bypass server-side request forgery (SSRF) protection. Specifically, a user with the `user` role can enable `allow_private: true` when configuring webhook subscriptions (`POST`/`PATCH /api/v1/webhook-subscriptions`), a field that lacks proper administrative access checks. This action forces the Nebula-mesh server's webhook dispatcher to use an unguarded HTTP client, circumventing internal network access controls and enabling connections to private, loopback, or link-local IP addresses. This flaw grants low-privileged attackers the ability to probe internal networks, interact blindly with internal services, and potentially exfiltrate sensitive data, such as cloud IAM credentials, escalating their privileges within the environment.

## Attack Chain

1. A non-admin operator (with `user` role) obtains a legitimate API key for the Nebula-mesh management interface.
2. The operator sends an HTTP POST request to `/api/v1/webhook-subscriptions`, including `allow_private: true` in the JSON request body, along with a target internal or loopback URL (e.g., `http://127.0.0.1:9999/internal-admin`).
3. The Nebula-mesh server processes this request and creates a webhook subscription, persisting the `allow_private: true` setting without performing an administrative role check.
4. The operator triggers an event that corresponds to the webhook's subscription criteria (e.g., `host.enrolled`, `host.blocked`, `host.unblocked`) for a resource they legitimately own.
5. Upon receiving the event, the Nebula-mesh server's webhook dispatcher prepares to send a notification. Due to `allow_private: true`, it selects an unguarded HTTP client, bypassing the standard SSRF protection mechanisms.
6. The Nebula-mesh server initiates an outbound HTTP POST request from its own network context to the internal or loopback URL specified by the operator.
7. The operator can query the status of the created webhook subscription (`GET /api/v1/webhook-subscriptions/{id}`) to observe `last_status` and `last_error` fields, functioning as a reachability oracle for internal services.
8. Through iterative probing and blind interaction, the attacker can map the internal network, identify vulnerable services, and potentially extract sensitive information like cloud metadata or access control credentials, leading to privilege escalation.

## Impact

A successful exploitation grants a non-admin operator server-side request capabilities against internal-only or loopback addresses, completely circumventing the security boundaries enforced for administrators. This exposure enables malicious actors to perform extensive internal network reconnaissance, identify and interact with sensitive internal services that are not typically exposed, and potentially exfiltrate critical information such as cloud IAM credentials from metadata services (depending on the cloud provider's metadata service version, e.g., IMDSv1). The consequence is a significant privilege escalation from a low-privileged user account, allowing for broader unauthorized access and potential control over the Nebula-mesh deployment and its underlying infrastructure.

## Recommendation

* Patch Nebula-mesh to a version greater than 0.7.1 (or the fix release for GHSA-7rx3-5wx3-5v76) immediately to remediate the vulnerability.
* Deploy the Sigma rule `Detect Nebula-mesh Server Outbound Connections to Internal/Loopback IPs (SSRF Attempt)` to your SIEM to detect suspicious network connections originating from the Nebula-mesh server to private, loopback, or link-local IP addresses.
* Implement network segmentation to restrict outbound connections from the Nebula-mesh server to only explicitly authorized and necessary internal services, limiting the impact of any potential SSRF.
