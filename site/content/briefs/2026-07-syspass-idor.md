---
title: sysPass Insecure Direct Object Reference Vulnerability (CVE-2026-65708)
slug: 2026-07-syspass-idor
description: An insecure direct object reference vulnerability (CVE-2026-65708) in sysPass versions up to 3.2.11 allows authenticated attackers to bypass access controls, accessing, enumerating, and manipulating account file attachments by manipulating numeric file IDs in `AccountFileController` actions without proper authorization checks, leading to unauthorized data access.
date: "2026-07-24T17:18:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - access-control-bypass
  - web-application
  - data-exfiltration
vendors:
  - sysPass
products:
  - sysPass <= 3.2.11
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: allows any authenticated attacker to access account file attachments
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: access account file attachments belonging to accounts they do not have ACL permissions for by exploiting missing authorization checks... to enumerate and manipulate any attachment in the vault
    confidence_band: high
cves:
  - id: CVE-2026-65708
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65708
---

A critical insecure direct object reference (IDOR) vulnerability, identified as CVE-2026-65708, has been discovered in sysPass versions up to and including 3.2.11. This flaw enables any authenticated attacker to bypass account-level access controls within the application. By exploiting missing authorization checks in the `AccountFileController`, attackers can manipulate specific numeric file IDs when performing actions such as downloading, viewing, deleting, uploading, or listing attachments. This allows them to access, enumerate, and manipulate any file attachment stored in the sysPass vault, regardless of their assigned permissions for the associated accounts. This vulnerability significantly compromises data confidentiality and integrity by allowing unauthorized access to sensitive information.

## Attack Chain

1. An authenticated attacker logs into the sysPass application with valid user credentials.
2. The attacker crafts an HTTP request targeting the `AccountFileController` component, attempting an action like `download`, `view`, `delete`, `upload`, or `list` an account file attachment.
3. Instead of providing a legitimate file ID associated with their authorized accounts, the attacker supplies an arbitrary numeric file ID in the request parameters.
4. Due to missing authorization checks in the `AccountFileController`, the application processes the request for the supplied arbitrary file ID without verifying the attacker's access permissions for the associated account.
5. The sysPass application serves the requested attachment, allows its deletion, or permits other specified manipulation, effectively bypassing the intended account-level access controls.
6. The attacker successfully accesses, enumerates, or manipulates account file attachments belonging to accounts they do not have legitimate permissions for.

## Impact

Successful exploitation of CVE-2026-65708 results in unauthorized access to sensitive data stored in sysPass file attachments. Attackers can view, download, modify, or delete any file attachment within the system, leading to severe data breaches, loss of sensitive information, or data corruption. This impacts the confidentiality and integrity of all data stored in sysPass attachments across an organization, potentially exposing credentials, financial documents, or other critical business assets. The vulnerability's CVSS v3.1 base score of 8.1 highlights its significant risk.

## Recommendation

* Patch CVE-2026-65708 immediately by upgrading sysPass to a version greater than 3.2.11.
* Implement strict authorization checks for all file-related operations within the `AccountFileController` to ensure that only authorized users can access specific file IDs.
* Monitor web server access logs for repeated or unusual requests to sysPass `AccountFileController` endpoints (e.g., `download`, `view`, `delete`, `upload`, `list` actions) that involve varying or non-sequential file IDs, especially from single authenticated users.
