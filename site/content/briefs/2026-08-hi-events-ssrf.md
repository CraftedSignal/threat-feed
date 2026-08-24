---
title: 'CVE-2026-76838: Server-Side Request Forgery in Hi.Events Webhook Dispatcher'
slug: 2026-08-hi-events-ssrf
description: Hi.Events fails to re-validate webhook destinations at dispatch time, allowing attackers to perform Server-Side Request Forgery (SSRF) and exfiltrate internal data via redirects.
date: "2026-08-24T20:06:25Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Hi.Events
products:
  - Hi.Events (< 1.11.1-beta)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Hi.Events validates a webhook destination only when it is registered, never when it is used.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: WebhookResponseHandlerService stores the body on the webhook log and WebhookLogResource returns it from the webhook logs endpoint, so the requester reads what the internal service replied rather than inferring it.
    confidence_band: high
cves:
  - id: CVE-2026-76838
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76838
---

Hi.Events is vulnerable to Server-Side Request Forgery (SSRF) due to improper validation of webhook destination URLs. The application only validates the destination hostname during the registration phase using the NoInternalUrlRule. However, this check is not repeated at the time of dispatch in the WebhookDispatchService. Furthermore, the application configuration for the underlying Guzzle client enables automatic redirect following by default. 

An attacker can bypass the initial filter by registering a URL that redirects to internal resources, loopback addresses (127.0.0.1), or cloud metadata endpoints (e.g., 169.254.169.254). Additionally, because the application does not re-resolve hostnames at dispatch, an attacker can modify the DNS records of a previously registered domain to point to internal IP addresses. The application stores the response from these unauthorized internal requests and exposes them via the webhook logs endpoint, allowing an attacker to exfiltrate sensitive data. This affects both event and organizer webhooks in versions prior to 1.11.1-beta.

## Impact

The vulnerability allows an attacker to interact with internal services or cloud metadata services that are not accessible from the public internet. By leveraging the application's webhook log functionality, the attacker can retrieve responses from these internal services, leading to potential data exfiltration of internal configuration, credentials, or metadata.

## Recommendation

- Upgrade Hi.Events to version 1.11.1-beta or later, which implements re-validation at dispatch, address pinning, and validation of all redirect hops.
- Review webhook logs for entries containing suspicious responses from internal IP ranges or cloud metadata endpoints.
- Implement egress filtering at the network level to restrict the server from initiating connections to private, loopback, and cloud metadata ranges unless explicitly required.
