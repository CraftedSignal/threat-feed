---
title: Keycloak UMA Policy Bypass Vulnerability (CVE-2026-4636)
slug: 2026-04-keycloak-uma-bypass
description: CVE-2026-4636 describes a vulnerability in Keycloak where an authenticated user with the uma_protection role can bypass User-Managed Access (UMA) policy validation, leading to unauthorized access to victim-owned resources.
date: "2026-04-02T13:16:27Z"
severities:
  - high
type: advisory
types:
  - advisory
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

A vulnerability, identified as CVE-2026-4636, has been discovered in Keycloak, a popular open-source identity and access management solution. This flaw allows an authenticated user who possesses the `uma_protection` role to bypass User-Managed Access (UMA) policy validation. By exploiting this vulnerability, an attacker can manipulate policy creation requests to include resource identifiers that belong to other users. This circumvents the intended access controls and enables the attacker to gain unauthorized permissions to resources owned by victims. The scope of the attack is limited to Keycloak instances where UMA is enabled and users have the `uma_protection` role. This can lead to significant data breaches and unauthorized actions performed under the guise of legitimate users.

## Attack Chain

1. An attacker authenticates to Keycloak with an account that has the `uma_protection` role.
2. The attacker initiates a request to create a new UMA policy.
3. The attacker crafts the policy creation request to include resource identifiers that belong to other users. This is done even though the URL path in the request specifies a resource owned by the attacker.
4. The UMA policy validation mechanism fails to properly verify the ownership of the included resource identifiers.
5. Keycloak creates the UMA policy, granting the attacker unauthorized permissions to the victim-owned resources.
6. The attacker obtains a Requesting Party Token (RPT) for the victim's resources using the newly created policy.
7. The attacker uses the RPT to access the victim's resources, potentially accessing sensitive information.
8. The attacker performs unauthorized actions on the victim's resources, leveraging the gained permissions.

## Impact

Successful exploitation of CVE-2026-4636 allows an attacker to gain unauthorized access to resources managed by Keycloak. This can lead to the exposure of sensitive data, such as personal information, financial records, or confidential business documents. The number of affected users depends on the scope of the attacker's access and the number of resources they can compromise. The impact could range from individual account compromise to widespread data breaches affecting entire organizations relying on Keycloak for access control.

## Recommendation

*   Apply the patch or upgrade to a version of Keycloak that resolves CVE-2026-4636 as soon as it becomes available.
*   Monitor Keycloak logs for suspicious UMA policy creation requests that include resource identifiers not owned by the requesting user. Create a Sigma rule based on webserver logs and filter for POST requests on `/auth/realms/<realm>/authz/protection/uma-policy/` with suspicious resource IDs in the body.
*   Implement additional access controls and validation mechanisms to verify the ownership of resource identifiers during UMA policy creation.
*   Review existing UMA policies to identify and remove any policies that may have been created maliciously using this vulnerability.
