---
title: Unauthenticated SSRF and Secret Exfiltration in Flyto Core
slug: 2026-07-flyto-ssrf-exfiltration
description: An unauthenticated SSRF vulnerability in the Flyto Core /run endpoint allows attackers to exfiltrate the internal FLYTO_RUNNER_SECRET and perform unauthorized requests against internal infrastructure.
date: "2026-07-30T15:29:02Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - ssrf
  - credential-theft
  - vulnerability
  - cve-2026-67426
vendors:
  - Flyto
products:
  - Flyto Core
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The standalone flyto-verification service exposes POST /run with no authentication, on all interfaces.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'The service unconditionally attaches X-Internal-Key: $FLYTO_RUNNER_SECRET to outgoing requests.'
    confidence_band: high
cves:
  - id: CVE-2026-67426
    cvss: 9.3
    epss: 0.00291
references:
  - https://github.com/advisories/GHSA-jx74-cqjv-2c67
rules:
  - title: Detect Exploitation of Flyto Core CVE-2026-67426
    description: Detects unauthenticated POST requests to the /run endpoint of the Flyto verification service, which is indicative of exploitation attempts.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Flyto Core versions 2.26.6 and earlier are vulnerable to a critical SSRF and credential exfiltration flaw in the `flyto-verification` service. The `/run` endpoint, which is exposed by default on all interfaces (0.0.0.0) via the standard Docker configuration, lacks authentication. When a request is submitted to this endpoint, the `callback_url` parameter is processed without validation against an allowlist or SSRF protection guards.

Crucially, the service automatically appends the internal `FLYTO_RUNNER_SECRET` as an `X-Internal-Key` header to any outgoing request initiated by the `callback_url`. An attacker can specify an arbitrary URL, forcing the service to send the secret to an attacker-controlled listener. This exfiltration allows for the impersonation of the service when communicating with the primary engine. Furthermore, the vulnerability enables SSRF attacks against internal network resources or cloud metadata services (e.g., 169.254.169.254) using arbitrary JSON payloads.

## Attack Chain

1. Attacker identifies a reachable Flyto Core verification service listening on port 8344 on a target network.
2. Attacker crafts an unauthenticated `POST` request to the `/run` endpoint.
3. Attacker sets the `callback_url` parameter to a malicious URI (e.g., `http://attacker-controlled-host.tld/`).
4. The service receives the request and fails to validate the `callback_url` against the expected `target_allowed` allowlist.
5. The `post_callback` function prepares an outbound request, fetching the `FLYTO_RUNNER_SECRET` from the process environment.
6. The service sends the request to the attacker's URI, including the `X-Internal-Key` header containing the secret.
7. Attacker captures the `FLYTO_RUNNER_SECRET` from the incoming request logs.
8. Attacker uses the stolen secret to authenticate and forge legitimate callbacks to the primary Flyto engine.

## Impact

Successful exploitation leads to a total loss of confidentiality regarding the internal runner secret and potential full compromise of the Flyto workflow engine. By bypassing authentication, attackers can interact with internal cloud metadata services, exfiltrate sensitive environment configuration, and gain the ability to submit unauthorized workflows or callbacks, effectively masquerading as a legitimate runner.

## Recommendation

1. Immediately restrict access to the `/run` endpoint using network-level controls (e.g., firewall rules or security groups) so it is only accessible from trusted internal IP ranges.
2. Bind the `flyto-verification` service to `127.0.0.1` instead of `0.0.0.0` in the `Dockerfile` and service configuration to prevent exposure to external network segments.
3. Patch to a version where `callback_url` is validated against a strict allowlist and protected by SSRF guards.
4. Rotate the `FLYTO_RUNNER_SECRET` immediately, as any instance running 2.26.6 or earlier must be assumed to have had this secret compromised.
5. Implement authentication (e.g., via OAuth or API keys) for all endpoints in the `flyto-verification` service to ensure that only authorized users can trigger the execution workflow.
