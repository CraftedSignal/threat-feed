---
title: Credential Exfiltration and SSRF in utcp-http via OAuth2 tokenUrl
slug: 2026-08-utcp-http-auth-bypass
description: The utcp-http library fails to validate the tokenUrl field in OpenAPI specifications, enabling an attacker to redirect OAuth2 credential submissions to arbitrary endpoints or perform SSRF attacks.
date: "2026-08-25T16:01:48Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - utcp-http (<= 1.1.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attacker does not need to be authenticated to serve a malicious OpenAPI spec; the victim only needs to register the spec and call one of its generated tools.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566.002
    technique_name: Spearphishing Link
    evidence: An attacker who controls an OpenAPI spec can embed an arbitrary tokenUrl in the OAuth2 security scheme.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch or upgrade utcp-http to remediate the missing ensure_secure_url() check.
      owner: IT Operations
      due: 24h
      evidence: Remediation patch section provided in advisory
  hunt_leads:
    - lead: Analyze outgoing POST requests from services using utcp-http for suspicious token endpoint domains.
      technique_id: T1190
      data_needed:
        - Egress proxy logs
        - Application network logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The library POSTs the victim's client_id and client_secret to the attacker-supplied token endpoint.
---

The `utcp-http` library (versions <= 1.1.3) contains a critical trust boundary bypass vulnerability that allows for unauthorized credential exfiltration and Server-Side Request Forgery (SSRF). The library automatically extracts OAuth2 configuration, specifically the `tokenUrl` field, from remote OpenAPI specifications during the conversion process without performing any security validation. While the library enforces secure URL checks for discovery and tool invocation, these safeguards are omitted when performing OAuth2 token requests. An attacker can craft a malicious OpenAPI specification containing an arbitrary `tokenUrl`, which, when registered and triggered by a victim, causes the library to perform a POST request containing the victim's OAuth2 `client_id` and `client_secret` to an attacker-controlled endpoint. This vulnerability poses a significant risk to applications that register third-party OpenAPI specifications while utilizing OAuth2 authentication.

## Attack Chain

1. The attacker hosts a malicious OpenAPI specification on an accessible server, defining an OAuth2 security scheme with a custom, attacker-controlled `tokenUrl`.
2. The victim registers the attacker's OpenAPI spec URL within their application using `utcp-http`.
3. The `OpenApiConverter` component fetches and parses the specification, extracting the malicious `tokenUrl` into an `OAuth2Auth` object without validation.
4. The victim invokes an OAuth2-protected tool via the `utcp-http` client.
5. The `HttpCommunicationProtocol` triggers the `_handle_oauth2` method to retrieve an access token prior to the actual tool request.
6. The `_handle_oauth2` method performs an `asyncio` POST request using the verbatim, unvalidated `tokenUrl` extracted from the specification.
7. The victim's application sends `client_id` and `client_secret` credentials to the attacker's server, or performs an SSRF request to internal infrastructure.
8. The attacker captures the exfiltrated credentials to gain unauthorized access to protected resources on behalf of the victim.

## Impact

Successful exploitation leads to immediate credential theft of OAuth2 `client_id` and `client_secret` pairs, providing attackers with full impersonation capabilities for the victim's identity. Furthermore, the lack of URL validation permits SSRF attacks against internal network resources, such as cloud metadata services (e.g., 169.254.169.254) or private internal APIs that are otherwise inaccessible from the public internet. Organizations that rely on `utcp-http` to integrate third-party or untrusted OpenAPI specifications are at high risk.

## Recommendation

Prioritized, concrete actions for detection and remediation:
- Upgrade `utcp-http` to a patched version once available or implement the suggested remediation patch manually.
- Implement the `ensure_secure_url()` check within `openapi_converter.py` and `http_communication_protocol.py` to validate `tokenUrl` parameters before use.
- Audit all registered OpenAPI specifications to ensure `tokenUrl` domains align with known, trusted identity providers.
- Monitor web application logs for outgoing POST requests from the `utcp-http` client to unusual or external IP addresses in the `tokenUrl` field.
- Restrict the network environment of the service using `utcp-http` to prevent egress to unauthorized endpoints, reducing the impact of potential SSRF.
