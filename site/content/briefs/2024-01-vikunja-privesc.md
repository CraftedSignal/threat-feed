---
title: Vikunja Link Share Hash Disclosure Leads to Privilege Escalation
slug: 2024-01-vikunja-privesc
description: The Vikunja application is vulnerable to privilege escalation, where the LinkSharing.ReadAll() method permits authenticated users to list all link shares, including secret hashes, without proper authorization checks, allowing an attacker with a read-only link share to escalate to full admin access.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vikunja
  - privilege-escalation
  - credential-access
vendors:
  - Vikunja
products:
  - Vikunja
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-8hp8-9fhr-pfm9
rules:
  - title: Vikunja Link Share ReadAll Hash Disclosure
    description: Detects attempts to list all link shares for a project without proper authorization, potentially revealing sensitive link share hashes.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Vikunja Admin Privilege Escalation via Link Share Authentication
    description: Detects authentication attempts using link share hashes, which might indicate privilege escalation if preceded by unauthorized hash disclosure.
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

Vikunja, a self-hosted to-do list application, suffers from a privilege escalation vulnerability due to improper access control in its link sharing feature. The `LinkSharing.ReadAll()` method allows authenticated users to list all link shares for a project, including their secret hashes. This bypasses the intended `LinkSharing.CanRead()` check, enabling an attacker with a read-only link share to retrieve hashes for write or admin link shares on the same project. By authenticating with these leaked hashes, an attacker can escalate to full administrative privileges. The vulnerability affects versions of Vikunja prior to 2.2.2. This issue is significant because it allows unauthenticated or low-privileged users to gain complete control over a Vikunja project without requiring valid credentials.

## Attack Chain

1.  Attacker obtains a read-only link share URL for a Vikunja project.
2.  Attacker authenticates to the Vikunja API using the read-only link share hash via a POST request to `/api/v1/shares/READ_ONLY_HASH/auth`, receiving a JWT.
3.  Attacker uses the read-only JWT to make a GET request to `/api/v1/projects/PROJECT_ID/shares`, listing all link shares associated with the project, including their hashes. This bypasses the intended `CanRead()` permission check.
4.  The `ReadAll()` method returns the `Hash` field, which is used for authentication, for all link shares, including admin shares.
5.  Attacker extracts the hash of an admin-level link share from the API response.
6.  Attacker authenticates to the Vikunja API using the leaked admin link share hash via a POST request to `/api/v1/shares/ADMIN_HASH/auth`, receiving a new JWT with administrative privileges.
7.  Attacker uses the admin JWT to perform administrative actions such as deleting the project via a DELETE request to `/api/v1/projects/PROJECT_ID`.
8.  The attacker successfully escalates privileges and gains full control over the Vikunja project, causing disruption or data loss.

## Impact

This vulnerability allows an attacker with minimal access (a read-only link share) to gain full administrative control over a Vikunja project. This can lead to data breaches, unauthorized modifications, or complete deletion of project data. The vulnerability poses a high risk, especially for projects that utilize a tiered sharing approach, where read-only shares are publicly available while admin shares are intended for internal use. Successful exploitation grants the attacker the ability to perform any action within the affected project, leading to significant disruption and potential data loss.

## Recommendation

*   Apply the patch or upgrade to Vikunja version 2.2.2 or later to address CVE-2026-33680.
*   Implement the authorization check in `LinkSharing.ReadAll()` as described in the advisory to prevent unauthorized access to link share hashes.
*   Deploy the Sigma rule `Vikunja_LinkShare_ReadAll_Hash_Disclosure` to detect attempts to list all link shares without proper authorization using the vulnerable `ReadAllWeb` handler.
*   Monitor web server logs for unusual API calls to `/api/v1/projects/*/shares` (where * is the project ID) that may indicate exploitation attempts, and investigate any anomalous activity.
