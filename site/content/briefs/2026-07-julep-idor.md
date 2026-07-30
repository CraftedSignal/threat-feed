---
title: Insecure Direct Object Reference Vulnerability in Julep
slug: 2026-07-julep-idor
description: An insecure direct object reference (IDOR) vulnerability in Julep allows authenticated tenants to bypass authorization checks and access the execution data of other tenants via the get_execution_details endpoint.
date: "2026-07-30T15:33:43Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - julep-ai
products:
  - julep
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can supply arbitrary execution_id values to retrieve sensitive execution records including task inputs, outputs, metadata, and temporal task tokens from other tenants.
    confidence_band: high
cves:
  - id: CVE-2026-67348
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67348
  - https://github.com/julep-ai/julep/issues/1615
  - https://www.vulncheck.com/advisories/julep-insecure-direct-object-reference-via-get-executions-execution-id
rules:
  - title: Detect Potential IDOR Exploitation in Julep
    description: Detects potential IDOR exploitation by identifying an abnormally high number of distinct execution_id retrievals by a single user session within a short timeframe.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
---

Julep is affected by an insecure direct object reference (IDOR) vulnerability (CVE-2026-67348) located in the 'get_execution_details' endpoint. This flaw allows an authenticated tenant to retrieve unauthorized information by manipulating the 'execution_id' parameter. Successful exploitation grants the attacker access to sensitive data belonging to other tenants, including task inputs, outputs, execution metadata, and temporal task tokens. Given that these tokens can be used for further impersonation or unauthorized actions within the platform, this vulnerability poses a significant risk to multi-tenant cloud environments. The issue was identified and patched in commit '5371a620af2582868eb121e6489a8cc14836fd50'.

## Attack Chain

1. Attacker authenticates to the Julep platform using legitimate tenant credentials.
2. Attacker observes network traffic while interacting with their own execution tasks.
3. Attacker identifies the 'get_execution_details' API call structure and the associated 'execution_id' parameter.
4. Attacker iterates or guesses 'execution_id' values belonging to other tenants.
5. Attacker sends a crafted HTTP GET request to the 'get_execution_details' endpoint with an unauthorized 'execution_id'.
6. The server fails to validate whether the requester owns the requested 'execution_id'.
7. The server returns the sensitive execution records, including task inputs and temporal task tokens, to the unauthorized attacker.
8. Attacker uses the stolen temporal task tokens to perform further actions within the context of the victim tenant.

## Impact

The vulnerability results in a direct loss of confidentiality for all tenants sharing the same Julep instance. By extracting task inputs, outputs, and temporal task tokens, attackers can perform identity impersonation, data exfiltration, and potentially influence task execution logic for other users. This affects organizations relying on Julep for multi-tenant workflow orchestration.

## Recommendation

1. Upgrade Julep to commit '5371a620af2582868eb121e6489a8cc14836fd50' or later to resolve CVE-2026-67348.
2. Review web server logs for high volumes of requests to the 'get_execution_details' endpoint containing varying 'execution_id' values from a single authenticated session.
3. Inspect access logs for instances where a single UserID successfully retrieves data for a large number of distinct 'execution_id' records that do not align with their expected project activity.
