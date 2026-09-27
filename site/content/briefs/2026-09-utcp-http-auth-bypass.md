---
title: Credential Exfiltration via Unvalidated OAuth2 TokenUrl in utcp-http
slug: 2026-09-utcp-http-auth-bypass
description: The utcp-http library before version 1.1.4 fails to validate the OAuth2 tokenUrl field in remote OpenAPI specifications, allowing attackers to redirect and capture client credentials.
date: "2026-09-27T19:09:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:utcp:utcp-http:*:*:*:*:*:*:*:*
vendors:
  - utcp
products:
  - utcp-http (< 1.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: When a victim registers an attacker-controlled OpenAPI spec and invokes a generated OAuth2-protected tool, the library POSTs the victim's client_id and client_secret to the attacker-supplied token endpoint without URL validation.
    confidence_band: high
cves:
  - id: CVE-2026-101059
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101059
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade utcp-http to version 1.1.4 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-101059 patch requirement.
  mitigation_plan:
    - priority: immediate
      action: Review and restrict remote OpenAPI specification sources.
      owner: Security Operations
      addresses: CVE-2026-101059
      evidence: Source describes vulnerability in remote OpenAPI specification processing.
---

The utcp-http library, version 1.1.4 and prior, contains a critical vulnerability related to the improper validation of the OAuth2 tokenUrl field retrieved from remote OpenAPI specifications. When a developer or user registers a malicious or compromised OpenAPI specification, the library blindly processes the provided tokenUrl value. Upon invoking a tool generated from this specification, the library performs an automated HTTP POST request to the attacker-defined endpoint. This request includes the victim's client_id and client_secret credentials, effectively exfiltrating them to an arbitrary destination under the attacker's control. This vulnerability poses a significant risk to applications relying on utcp-http for OAuth2-protected tool integration, as it facilitates credential theft through the manipulation of remote schema definitions.

## Impact

Successful exploitation allows for the theft of OAuth2 client_id and client_secret credentials, potentially leading to unauthorized access to downstream services or APIs protected by these credentials. If the stolen credentials provide broad permissions, the impact could extend to significant data exposure or unauthorized actions within the victim's integrated services.

## Recommendation

* Upgrade the utcp-http library to version 1.1.4 or later immediately to incorporate necessary URL validation logic.
* Audit all currently registered or dynamically loaded OpenAPI specifications to ensure that the tokenUrl fields point to trusted and expected domains.
* Implement strict allowlisting for domains allowed in the OAuth2 configuration if dynamic remote specification loading is required.
