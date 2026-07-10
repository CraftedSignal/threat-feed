---
title: n8n External Secrets Authorization Bypass Vulnerability
slug: 2024-01-n8n-auth-bypass
description: An authorization bypass vulnerability in n8n allows authenticated users without 'externalSecret:list' permission to retrieve plaintext values of external secrets when saving credentials, if the attacker knows or can guess the secret name.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - vulnerability
  - n8n
vendors:
  - n8n
products:
  - n8n
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-fxcw-h3qj-8m8p
rules:
  - title: Detect n8n Credential Saving with External Secret Reference
    description: Detects attempts to save credentials in n8n that reference external secrets, potentially indicating an authorization bypass attempt (though this may not be directly visible in logs without custom n8n logging).  This is a best-effort detection given available information.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect n8n Credential Update with External Secret Reference
    description: Detects attempts to update credentials in n8n by referencing external secrets, potentially leading to an authorization bypass (requires specific logging within n8n to confirm). This rule detects modifications via PUT requests.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

n8n is susceptible to an authorization bypass vulnerability related to external secrets management. This vulnerability, identified as CVE-2026-33722, affects n8n instances configured with external secrets vaults. An authenticated user, lacking the necessary 'externalSecret:list' permission, can exploit this flaw to access sensitive information. Specifically, when saving a credential, a user can reference an external secret by its external name, which circumvents the permission check and retrieves the secret's plaintext value. This bypass allows unauthorized access to secrets stored in connected vaults, even without admin or owner privileges. The vulnerability impacts n8n versions prior to 1.123.23 and versions 2.0.0-rc.0 up to 2.6.4. Defenders should prioritize upgrading affected instances to patched versions to mitigate the risk of unauthorized secret access.

## Attack Chain

1. An attacker gains valid user credentials for an n8n instance.
2. The n8n instance is configured to use an external secrets vault.
3. The attacker identifies (or guesses) the name of a secret stored in the external vault.
4. The attacker attempts to create or modify a credential within n8n.
5. While creating/modifying the credential, the attacker references the external secret by its name.
6. The application attempts to resolve the secret.
7. Due to the authorization bypass, the secret's plaintext value is retrieved and displayed to the attacker during the credential saving process.
8. The attacker successfully retrieves the secret without possessing the 'externalSecret:list' permission.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to sensitive secrets stored in external vaults connected to n8n. The number of affected organizations depends on the adoption rate of n8n with external secrets configured. Potential damage includes exposure of API keys, database credentials, and other sensitive data, leading to data breaches, unauthorized access to systems, and further lateral movement within the affected environment. This is a high-severity vulnerability, as it directly leads to the compromise of confidential information.

## Recommendation

*   Upgrade n8n instances to version 1.123.23 or 2.6.4 or later to patch CVE-2026-33722.
*   If upgrading is not immediately feasible, restrict n8n access to fully trusted users only as a temporary mitigation.
*   Disable external secrets integration until the patch can be applied, as a temporary measure to prevent exploitation, per the advisory.
*   Monitor n8n application logs for attempts to access external secrets by users without the 'externalSecret:list' permission (though no specific rule is provided as the logs may not expose this).
