---
title: MaxKey Unauthorized Access via Hard-coded JWT Signing Secret
slug: 2026-08-maxkey-jwt-auth-bypass
description: MaxKey contains a critical vulnerability due to a hard-coded JWT signing secret that allows unauthenticated attackers to forge authentication tokens and gain administrative access.
date: "2026-08-11T19:49:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - MaxKey
products:
  - MaxKey
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MaxKey contains an unauthorized access vulnerability due to a hard-coded JWT signing secret in application-maxkey.properties that allows unauthenticated attackers to forge valid JWT tokens.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.003
    technique_name: 'Use Alternate Authentication Material: Pass the Ticket'
    evidence: Attackers can craft a JWT token signed with the publicly known default secret and obtain a fully authenticated admin session.
    confidence_band: high
cves:
  - id: CVE-2026-69102
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69102
rules:
  - title: Detect CVE-2026-69102 Exploitation - Unauthorized JWT Authentication Attempt
    description: Detects potential exploitation attempts by monitoring access to the trust-based JWT login endpoint used in MaxKey.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Rotate the JWT signing secret in application-maxkey.properties
      owner: IT Operations
      due: 24h
      evidence: Source documentation identifies this file as containing the hard-coded secret.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /sign/login/jwt/trust endpoint
      owner: IT Operations
      addresses: CVE-2026-69102
      evidence: Blocking access limits exposure to unauthenticated exploitation.
---

MaxKey contains an unauthorized access vulnerability (CVE-2026-69102) stemming from a hard-coded JWT signing secret within the 'application-maxkey.properties' file. This flaw permits unauthenticated attackers to forge valid JWT tokens, allowing them to bypass traditional authentication mechanisms. By submitting a forged token signed with the known static secret to the '/sign/login/jwt/trust' endpoint, an attacker can impersonate any user, including administrators. Successful exploitation grants the attacker full administrative access to the SSO platform, enabling the modification of SSO configurations and the exfiltration of downstream application secrets. This vulnerability is highly critical due to the ease of exploitation and the significant impact on centralized authentication security.

## Impact

The vulnerability poses a severe threat to organizations using MaxKey for SSO, as it allows for complete compromise of the identity provider. Successful exploitation results in full administrative access, potentially leading to unauthorized access to all downstream applications integrated via SSO, exfiltration of credentials or sensitive configuration tokens, and long-term persistent access to the organization's identity infrastructure.

## Recommendation

* Immediately audit all MaxKey deployments to identify and rotate the JWT signing secret found in 'application-maxkey.properties'.
* Restrict network access to the '/sign/login/jwt/trust' endpoint to known, trusted management IP addresses.
* Monitor web server logs for suspicious POST requests to the '/sign/login/jwt/trust' path, specifically looking for anomalous successful authentication attempts originating from untrusted sources.
* Apply patches provided by the MaxKey project immediately upon availability.
