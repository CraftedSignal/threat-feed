---
title: SSRF Vulnerability in utcp-http via Unvalidated Redirects
slug: 2026-08-utcp-ssrf
description: The utcp-http library performs security validation on the initial URL but fails to re-validate the target during HTTP redirects, enabling SSRF attacks to reach internal services or cloud metadata endpoints.
date: "2026-08-25T16:01:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - library-vulnerability
  - cloud-security
vendors:
  - universal-tool-calling-protocol
products:
  - utcp-http
  - '@utcp/http'
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: On a cloud instance with IMDSv1 enabled... this yields the instance role's IAM credentials.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9qhg-99ww-9mqc
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade utcp-http to 1.1.4
      owner: IT Operations
      due: 24h
      evidence: Fixed in utcp-http 1.1.4.
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound access to cloud metadata services from application hosts
      owner: Security Engineering
      addresses: SSRF mitigation
      evidence: This vector bypasses the GHSA-39j6-4867-gg4w mitigation via unvalidated redirects.
---

The `utcp-http` library (and its TypeScript counterpart `@utcp/http`) contains a Server-Side Request Forgery (SSRF) vulnerability due to improper handling of HTTP redirects during tool invocation. The library's `HttpCommunicationProtocol.call_tool` method validates the initial tool URL against a security policy before execution. However, the subsequent request is performed with `aiohttp`'s default `allow_redirects=True` setting without re-validating the target of any `3xx` redirect responses. 

An attacker controlling the registered tool endpoint can provide a redirect to internal network services, such as the IMDSv1 cloud metadata service (e.g., `169.254.169.254`) or internal administrative panels. Because the library does not inspect the `Location` header or re-run the `ensure_secure_url` check on follow-up requests, it inadvertently bypasses intended network segmentation controls. This vulnerability, which effectively functions as an SSRF-to-exfiltration primitive, is particularly impactful in cloud environments where it can lead to the theft of IAM credentials. The issue was addressed in version 1.1.4 by implementing per-hop revalidation of redirect targets.

## Attack Chain

1. The attacker registers a tool or manual endpoint in the UTCP-enabled application using an attacker-controlled URL that passes initial security checks (e.g., any `https://` endpoint).
2. The application's `call_tool` method validates the provided attacker-controlled URL and confirms it satisfies the `ensure_secure_url` policy.
3. The `utcp-http` library initiates a `GET` request to the attacker's server.
4. The attacker's server responds with an HTTP `302 Found` status code and a `Location` header pointing to an internal-only resource (e.g., `http://169.254.169.254/latest/meta-data/iam/security-credentials/`).
5. The library's `aiohttp` client automatically follows the redirect to the target internal resource.
6. The internal resource processes the request and returns sensitive data (e.g., IAM credentials) in the response body.
7. The library captures the response body from the internal resource and returns it to the caller, completing the exfiltration of the data to the attacker.

## Impact

Successful exploitation allows for blind-to-readable SSRF, enabling unauthorized access to internal HTTP services not directly reachable from the public internet. On cloud-hosted instances configured with IMDSv1, this allows attackers to retrieve instance IAM credentials, resulting in full infrastructure or service compromise.

## Recommendation

- Upgrade `utcp-http` and `@utcp/http` to version 1.1.4 or higher immediately.
- Audit all registered tool or manual endpoints to identify and remove any attacker-influenced or untrusted URL inputs.
- Implement network-level restrictions (such as egress filtering or host-based firewall rules) to prevent the UTCP process from accessing cloud metadata services and internal local network segments.
