---
title: Authentication Bypass in Netherman Portal del Hermano
slug: 2026-10-netherman-auth-bypass
description: An authentication flaw in the Netherman Portal del Hermano password-recovery flow allows attackers to perform account takeovers by exploiting rate-limit gaps and error-message oracles.
date: "2026-10-12T22:44:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:netherman:portal_del_hermano:*:*:*:*:*:*:*:*
tags:
  - cve-2026-53997
  - authentication-bypass
  - web-security
vendors:
  - Netherman
products:
  - Portal del Hermano (< 2026-10-06)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: The vulnerability allows attackers to brute-force the date of birth and IBAN digits.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110.004
    technique_name: 'Brute Force: Credential Stuffing'
    evidence: The endpoint lacks rate limiting, allowing attackers to systematically enumerate verification factors.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555.003
    technique_name: Credentials from Web Browsers
    evidence: Successful account takeover allows access to profile data and fiscal documents.
    confidence_band: high
cves:
  - id: CVE-2026-53997
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53997
iocs:
  - type: domain
    value: portaldelhermano.es
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Portal del Hermano to version 2026-10-06 or later
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists before 2026-10-06
  hunt_leads:
    - lead: Monitor web server access logs for repeated POST requests to /password/create-access or /password/email by a single source IP
      technique_id: T1110
      data_needed:
        - webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Lack of rate limiting on password reset endpoints
  mitigation_plan:
    - priority: immediate
      action: Patch software to version released on 2026-10-06
      owner: IT Operations
      addresses: CVE-2026-53997
      evidence: NVD vulnerability disclosure
---

The Netherman Portal del Hermano platform (portaldelhermano.es) contained a critical broken authentication vulnerability in its password-recovery mechanism prior to October 6, 2026. The vulnerability stems from the implementation of the /password/create-access and /password/email endpoints, which fail to enforce rate limits and provide granular error messages that act as validation oracles. An unauthenticated attacker can query these endpoints to systematically confirm individual identity-verification factors, specifically the DNI, date of birth, phone number, and last four digits of an IBAN. By leveraging these oracles, an attacker can brute-force the required identity components to hijack user accounts. Upon successful validation, the attacker can supply their own email address to receive the password reset token, resulting in full unauthorized access to the victim's profile, including sensitive fiscal documents and full banking details.

## Impact

Successful exploitation allows for full account takeover of any member account across the platform. This leads to the exposure of highly sensitive personal data, including complete IBANs, fiscal records, and personal identification information stored within the portal. Given the nature of the information hosted on the site, unauthorized access poses significant risks of identity theft and financial fraud for all affected users.

## Recommendation

- Upgrade the Portal del Hermano application to the version released on or after 2026-10-06.
- Audit logs for the /password/create-access and /password/email endpoints to identify anomalous spikes in requests from single source IPs, which may indicate enumeration attempts targeting the identification oracle.
- Implement strict rate limiting on all authentication and password recovery endpoints to prevent automated enumeration and brute-force attacks.
- Standardize error responses for authentication flows to ensure that distinct messages cannot be used to distinguish between valid and invalid input fields.
