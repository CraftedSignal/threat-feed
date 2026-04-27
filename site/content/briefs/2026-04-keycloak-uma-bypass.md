---
title: Keycloak UMA Policy Bypass Vulnerability (CVE-2026-4636)
slug: 2026-04-keycloak-uma-bypass
description: CVE-2026-4636 describes a vulnerability in Keycloak where an authenticated user with the uma_protection role can bypass User-Managed Access (UMA) policy validation, leading to unauthorized access to victim-owned resources.
date: "2026-04-02T13:16:27Z"
severities:
  - high
tags:
  - keycloak
  - uma
  - policy-bypass
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-4636
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4636
rules:
  - title: Keycloak UMA Policy Creation with Cross-User Resource IDs
    description: Detects UMA policy creation requests in Keycloak that include resource IDs not owned by the requesting user, indicating a potential CVE-2026-4636 exploit.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Keycloak Unauthorized Access via Requesting Party Token (RPT)
    description: Detects access attempts using Requesting Party Tokens (RPT) to access resources that the user should not have access to based on existing UMA policies, potentially indicating exploitation of CVE-2026-4636.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability, identified as CVE-2026-4636, has been discovered in Keycloak, a popular open-source identity and access management solution. This flaw allows an authenticated user who possesses the `uma_protection` role to bypass User-Managed Access (UMA) policy validation. By exploiting this vulnerability, an attacker can manipulate policy creation requests to include resource identifiers that belong to other users. This circumvents the intended access controls and enables the attacker to…
