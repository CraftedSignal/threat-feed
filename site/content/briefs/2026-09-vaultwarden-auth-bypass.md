---
title: Vaultwarden Access Control Bypass via Membership Validation Failure
slug: 2026-09-vaultwarden-auth-bypass
description: Vaultwarden versions 1.37.3 and earlier fail to validate organization membership status, allowing revoked or pending members to retain unauthorized access to sensitive cipher data.
date: "2026-09-23T00:39:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vaultwarden:vaultwarden:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - access-control
  - authentication
vendors:
  - Vaultwarden
products:
  - Vaultwarden (<= 1.37.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Vaultwarden through 1.37.3 omits organization membership status validation from three cipher access-restriction queries, allowing revoked and not-yet-confirmed members to retain read, write, delete, and attachment access to organization ciphers.
    confidence_band: high
cves:
  - id: CVE-2026-95814
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95814
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Vaultwarden to a version newer than 1.37.3
      owner: IT Operations
      addresses: CVE-2026-95814
      evidence: Vaultwarden through 1.37.3 omits organization membership status validation
---

Vaultwarden versions 1.37.3 and earlier contain a critical vulnerability in the organization access control logic. The application fails to properly enforce membership status checks within key cipher access-restriction functions, specifically `get_user_collections_access_flags`, `get_group_collections_access_flags`, and `is_in_full_access_group`. As a result, users who have been revoked from an organization or users whose membership is currently in a pending state retain their ability to perform read, write, and delete operations on organization-managed ciphers, as well as interact with associated attachments. This flaw allows unauthorized individuals to access or modify protected credentials beyond their intended privilege level. Defenders should prioritize updating to the latest patched version to ensure proper access control enforcement.

## Impact

Successful exploitation allows unauthorized users to access, modify, or delete organization-wide secrets and attachments. This could lead to massive credential exposure within enterprise Vaultwarden deployments, effectively granting revoked or unvetted users complete control over corporate secrets.

## Recommendation

- Upgrade all Vaultwarden instances to a version later than 1.37.3 immediately.
- Review organization audit logs for access activity by users with revoked or pending statuses.
- Ensure all service accounts and API clients utilizing the Vaultwarden API are patched and audited for abnormal cipher access patterns.
