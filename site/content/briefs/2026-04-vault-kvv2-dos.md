---
title: Vault kvv2 Policy Bypass Vulnerability Leading to Denial-of-Service (CVE-2026-3605)
slug: 2026-04-vault-kvv2-dos
description: An authenticated user with access to a kvv2 path through a policy containing a glob may be able to delete secrets they were not authorized to read or write, resulting in denial-of-service, addressed in Vault versions 2.0.0, 1.21.5, 1.20.10, and 1.19.16.
date: "2026-04-17T04:16:03Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - vault
  - kvv2
  - denial-of-service
  - cve-2026-3605
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-3605
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3605
  - https://discuss.hashicorp.com/t/hcsec-2026-05-vault-kvv2-metadata-and-secret-deletion-policy-bypass-denial-of-service/77342
iocs:
  - type: email
    value: nvd@nist.gov
ioc_counts:
  email: 1
rules:
  - title: Vault Secret Deletion by User with Glob Policy
    description: Detects secret deletion operations in Vault audit logs performed by users with policies containing glob patterns, potentially indicating exploitation of CVE-2026-3605.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Vault Audit Log - Secret Deletion via API
    description: Detects potential exploitation of CVE-2026-3605 by monitoring Vault audit logs for secret deletion events performed via the API by users with wide-ranging permissions.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-3605 is a vulnerability in HashiCorp Vault's kvv2 secrets engine where an authenticated user can delete secrets they lack read/write authorization for, leading to a denial-of-service. This occurs when a policy associated with the user contains a glob allowing access to a kvv2 path. The vulnerability does *not* permit cross-namespace secret deletion or unauthorized data reading. This issue impacts Vault Community Edition and Vault Enterprise. Affected versions include all releases prior to the fixes in Vault Community Edition 2.0.0 and Vault Enterprise 2.0.0, 1.21.5, 1.20.10, and 1.19.16. Successful exploitation allows an attacker to disrupt applications relying on the deleted secrets.

## Attack Chain

1. An attacker obtains valid credentials for a Vault user account.
2. The attacker identifies a kvv2 secrets path protected by a policy containing a glob (e.g., `secret/data/*`).
3. The attacker authenticates to Vault using their credentials via the Vault CLI or API (`vault login -method=...`).
4. The attacker uses the Vault CLI or API to attempt to delete a secret within the globbed path (`vault kv delete secret/data/unauthorized-secret`).
5. Due to the policy misconfiguration, the delete operation succeeds, even though the attacker lacks explicit read or write permissions for the specific secret.
6. The target secret is removed from the Vault backend.
7. Applications or services relying on the deleted secret experience failures or unexpected behavior.
8. Repeated secret deletion leads to widespread application disruption, resulting in a denial-of-service.

## Impact

Successful exploitation of CVE-2026-3605 allows an authenticated user to cause a denial-of-service by deleting secrets they are not authorized to manage. While the vulnerability does not allow unauthorized data access or cross-namespace deletion, the impact can be significant for organizations relying on Vault for secrets management. The number of affected systems depends on the scope of the vulnerable policy and the attacker's access. The primary impact is application downtime and potential data loss due to deleted secrets.

## Recommendation

*   Upgrade Vault Community Edition and Vault Enterprise to versions 2.0.0, 1.21.5, 1.20.10, or 1.19.16 to patch CVE-2026-3605.
*   Review and revise Vault policies containing globs (`secret/data/*`) to ensure appropriate least-privilege access control and prevent unauthorized deletion, referencing the vulnerability description in this brief.
*   Monitor Vault audit logs for `secret/delete` operations performed by users with policies containing broad globs, using the provided Sigma rule for guidance.
*   Implement regular backups of Vault secrets to mitigate the impact of accidental or malicious deletion, in case this vulnerability is exploited.
