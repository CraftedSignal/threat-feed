---
title: Authorization Bypass in Red Hat Quay
slug: 2026-07-quay-auth-bypass
description: An incorrect authorization vulnerability in Red Hat Quay allows read-only superusers to view and impersonate robot account tokens, potentially leading to unauthorized repository access.
date: "2026-07-29T17:17:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - container-security
  - auth-bypass
vendors:
  - Red Hat
products:
  - Red Hat Quay 3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A user configured in GLOBAL_READONLY_SUPER_USERS is able to view robot account tokens for repositories they are not a member of, allowing an attacker with read-only superuser privileges to impersonate any robot account.
    confidence_band: high
cves:
  - id: CVE-2026-18255
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18255
  - https://access.redhat.com/security/cve/CVE-2026-18255
  - https://bugzilla.redhat.com/show_bug.cgi?id=2508454
---

A security vulnerability identified as CVE-2026-18255 affects Red Hat Quay 3. The issue stems from an incorrect authorization flaw (CWE-863) where users assigned to the GLOBAL_READONLY_SUPER_USERS role can improperly access and view robot account tokens associated with repositories they do not own or possess membership in. By successfully retrieving these tokens, an attacker with read-only superuser privileges can impersonate any robot account within the environment, effectively bypassing intended access restrictions. This vulnerability poses a significant risk to the integrity and confidentiality of container image registries managed by Red Hat Quay. Administrators should prioritize identifying users with excessive read-only privileges and applying relevant security patches provided by Red Hat to mitigate this privilege escalation vector.

## Impact

Successful exploitation allows for the unauthorized impersonation of robot accounts, which may be used for automated image pulls, pushes, or other CI/CD pipeline activities. Depending on the privileges granted to the targeted robot accounts, this could lead to the unauthorized exfiltration of container images or the injection of malicious images into repositories, impacting the software supply chain of affected organizations.

## Recommendation

- Update Red Hat Quay 3 instances to the latest security version provided by Red Hat to remediate CVE-2026-18255.
- Review the list of users configured within the GLOBAL_READONLY_SUPER_USERS role and apply the principle of least privilege.
- Audit access logs for unusual patterns of repository access or API token retrieval by administrative accounts.
