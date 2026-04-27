---
title: Vault kvv2 Policy Bypass Vulnerability Leading to Denial-of-Service (CVE-2026-3605)
slug: 2026-04-vault-kvv2-dos
description: An authenticated user with access to a kvv2 path through a policy containing a glob may be able to delete secrets they were not authorized to read or write, resulting in denial-of-service, addressed in Vault versions 2.0.0, 1.21.5, 1.20.10, and 1.19.16.
date: "2026-04-17T04:16:03Z"
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

CVE-2026-3605 is a vulnerability in HashiCorp Vault's kvv2 secrets engine where an authenticated user can delete secrets they lack read/write authorization for, leading to a denial-of-service. This occurs when a policy associated with the user contains a glob allowing access to a kvv2 path. The vulnerability does *not* permit cross-namespace secret deletion or unauthorized data reading. This issue impacts Vault Community Edition and Vault Enterprise. Affected versions include all releases prior…
