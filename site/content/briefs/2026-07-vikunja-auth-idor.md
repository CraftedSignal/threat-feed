---
title: Authorization Flaws in Vikunja Expose Share Hashes and Allow Attachment Manipulation
slug: 2026-07-vikunja-auth-idor
description: Authorization flaws in Vikunja before version 2.2.1 allow authenticated users with read access to escalate privileges by obtaining admin-level share hashes via the LinkSharing.ReadAll endpoint, and also permit instance-wide data exfiltration and destruction by manipulating task attachments through an Insecure Direct Object Reference (IDOR) vulnerability in the GetTaskAttachment endpoint.
date: "2026-07-10T15:18:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authorization-bypass
  - idor
  - data-exfiltration
  - data-destruction
  - web-application
  - cve
vendors:
  - Vikunja
products:
  - Vikunja (before 2.2.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: enabling permission escalation to admin-level shares
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
    evidence: allowing attackers to download all file attachments across all projects instance-wide
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: allowing attackers to... delete all file attachments across all projects instance-wide
    confidence_band: high
cves:
  - id: CVE-2026-56765
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56765
  - https://github.com/go-vikunja/vikunja/security/advisories/GHSA-2pv8-4c52-mf8j
  - https://www.vulncheck.com/advisories/vikunja-unauthenticated-instance-wide-data-breach-via-link-share-hash-disclosure-chained-with-cross-project-attachment-idor
---

CVE-2026-56765 details two critical authorization flaws affecting Vikunja versions prior to 2.2.1. The first vulnerability resides in the `LinkSharing.ReadAll` API endpoint, which inadvertently exposes sensitive share hashes to any authenticated user possessing read access. This exposure allows an attacker to obtain hashes for admin-level shares, facilitating a privilege escalation to gain unauthorized access to administrative functions or content. The second flaw is an Insecure Direct Object Reference (IDOR) found in the `GetTaskAttachment` endpoint. While this endpoint performs initial permission checks based on user-supplied task IDs, it subsequently fetches attachments by sequential ID without proper ownership verification. This oversight enables an attacker to bypass access controls, leading to the unauthorized download and deletion of all file attachments across every project within the Vikunja instance, resulting in severe data breach and data loss risks.

## Attack Chain

1. An authenticated attacker, with at least read access to the Vikunja instance, sends a request to the `LinkSharing.ReadAll` API endpoint.
2. The `LinkSharing.ReadAll` endpoint responds by exposing sensitive share hashes, including those associated with admin-level shares, to the attacker.
3. The attacker utilizes the obtained admin-level share hashes to bypass intended access controls and escalate their privileges to gain unauthorized access to administrative functions or content.
4. (Potentially independently or chained) The attacker sends requests to the `GetTaskAttachment` endpoint, supplying arbitrary task IDs.
5. The `GetTaskAttachment` endpoint performs permission checks against the *supplied* task ID but then fetches attachments by *sequential ID* from the backend data store.
6. The endpoint fails to verify ownership or authorization for the attachments retrieved by sequential ID, allowing the attacker to bypass access controls.
7. The attacker iterates through sequential attachment IDs, downloading all file attachments across all projects throughout the entire Vikunja instance, leading to data exfiltration.
8. The attacker can also leverage the same IDOR to send delete requests for these sequential attachment IDs, resulting in the deletion of all file attachments across all projects instance-wide.

## Impact

Successful exploitation of CVE-2026-56765 leads to critical security consequences impacting the entire Vikunja instance. Attackers can escalate their privileges to administrative levels, gaining unauthorized control over the platform's features and data. More significantly, the IDOR vulnerability allows for an instance-wide data breach, enabling attackers to download all user-uploaded file attachments from every project. This could expose sensitive business documents, personal information, or proprietary data. Furthermore, the ability to delete all file attachments across all projects poses a severe data destruction risk, potentially leading to irreversible data loss and significant operational disruption.

## Recommendation

* Patch Vikunja installations to version 2.2.1 or later immediately to remediate CVE-2026-56765.
* Review access logs for the `LinkSharing.ReadAll` and `GetTaskAttachment` endpoints for suspicious or excessive access patterns.
* Implement API gateway logging to capture full HTTP request and response bodies for deeper analysis of unexpected data exposure or IDOR attempts on `CVE-2026-56765` related endpoints.
