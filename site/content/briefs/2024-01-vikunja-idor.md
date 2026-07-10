---
title: Vikunja Unauthenticated Instance-Wide Data Breach via Link Share and IDOR
slug: 2024-01-vikunja-idor
description: Chained authorization flaws in Vikunja allow an unauthenticated attacker to download and delete all file attachments across all projects by disclosing share hashes and exploiting cross-project attachment access.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vikunja
  - idor
  - privilege-escalation
  - data-breach
vendors:
  - Vikunja
products:
  - Vikunja
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-2pv8-4c52-mf8j
  - https://github.com/go-vikunja/vikunja/security/advisories/GHSA-8hp8-9fhr-pfm9
  - https://github.com/go-vikunja/vikunja/security/advisories/GHSA-jfmm-mjcp-8wq2
rules:
  - title: Detect Vikunja Link Share Enumeration
    description: Detects attempts to enumerate link shares, potentially indicating the start of a privilege escalation attack.
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
  - title: Detect Vikunja Cross-Project Attachment Download via IDOR
    description: Detects potential cross-project attachment download attempts in Vikunja by monitoring for sequential attachment ID access.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1020
    data_sources:
      - webserver
      - linux
rules_count: 2
---

An unauthenticated attacker can exploit two chained vulnerabilities in Vikunja, a self-hosted to-do list application, to achieve instance-wide data exfiltration and destruction. The vulnerability lies in versions 2.2.0 and earlier. The first vulnerability involves the disclosure of link share hashes, including those with administrative privileges, via the `ReadAll` endpoint for link shares. The second vulnerability is a cross-project attachment IDOR (Insecure Direct Object Reference) that arises from improper permission checks in the `ReadOne`/`GetTaskAttachment` endpoint. By chaining these vulnerabilities, an attacker can escalate privileges from a read-only link share to an administrative role, enumerate all attachments across all projects, and then download or delete any attachment, regardless of project membership or access controls. This poses a significant risk to the confidentiality and integrity of data stored within Vikunja instances.

## Attack Chain

1. Attacker obtains a URL for a public link share (e.g., via social engineering or accidental exposure).
2. Attacker authenticates to the Vikunja API using the read-only link share hash via `POST /shares/{hash}/auth` to obtain a JWT.
3. The attacker enumerates all link shares for the project associated with the initial share using `GET /projects/{id}/shares`. The API discloses all share hashes, including those with admin privileges.
4. The attacker authenticates using an admin-level share hash via `POST /shares/{admin_hash}/auth` to escalate privileges.
5. The attacker identifies an accessible task ID within the project using `GET /projects/{id}/tasks`. This task is only used to bypass initial checks.
6. The attacker exploits the attachment IDOR by sending requests like `GET /tasks/{accessible_task}/attachments/{1..N}` to enumerate attachment IDs sequentially across all projects.  The server checks permissions against the specified task but serves attachments based solely on the attachment ID.
7. The attacker downloads attachments from any project by iterating through attachment IDs.
8. If the attacker escalated to an admin share, they can delete attachments from other projects using `DELETE /tasks/{accessible_task}/attachments/{TARGET_ATTACHMENT_ID}` causing data loss.

## Impact

Successful exploitation of these vulnerabilities leads to a complete breach of data confidentiality and integrity. An attacker, starting with just a publicly shared link, can download every file attachment across all projects, potentially exposing sensitive documents, images, and other confidential information. The vulnerability allows for the deletion of arbitrary attachments, leading to significant data loss. The impact is amplified by the minimal attack prerequisites and the wide blast radius, affecting all projects and users within the Vikunja instance. Given that link shares are designed for external collaboration, a single leaked link can compromise the entire Vikunja instance.

## Recommendation

*   Apply the recommended fixes as outlined in the advisory ([https://github.com/advisories/GHSA-2pv8-4c52-mf8j](https://github.com/advisories/GHSA-2pv8-4c52-mf8j)). Specifically, ensure that the `Hash` field is cleared in `ReadAll` responses for link shares.
*   Implement the suggested fix for the attachment IDOR by verifying task ownership in the `ReadOne` method within `pkg/models/task_attachment.go`.
*   Deploy the Sigma rule to detect suspicious attachment downloads across projects based on sequential attachment ID enumeration.
*   Deploy the Sigma rule to detect link share enumeration, as this is the initial step in the attack chain.
*   Monitor web server logs for unusual patterns of API requests, particularly to the `/projects/{id}/shares` and `/tasks/{accessible_task}/attachments/{1..N}` endpoints.
