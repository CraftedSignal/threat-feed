---
title: Vikunja IDOR in Task Attachment ReadOne Allows Cross-Project File Access and Deletion
slug: 2024-01-vikunja-idor
description: Vikunja is vulnerable to an IDOR in TaskAttachment.ReadOne(), allowing cross-project file access and deletion by exploiting the lack of task ID validation, potentially leading to confidentiality breaches and data loss.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vikunja
  - idor
  - file-access
  - data-loss
vendors:
  - Vikunja
products:
  - Vikunja
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-jfmm-mjcp-8wq2
rules:
  - title: Detect Vikunja Unauthorized Attachment Access via IDOR
    description: Detects attempts to access Vikunja attachments using an IDOR vulnerability by monitoring GET requests to the attachment endpoint with differing task and attachment IDs.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Vikunja Unauthorized Attachment Deletion via IDOR
    description: Detects attempts to delete Vikunja attachments using an IDOR vulnerability by monitoring DELETE requests to the attachment endpoint with differing task and attachment IDs.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Vikunja, a self-hostable to-do list application, is susceptible to an Insecure Direct Object Reference (IDOR) vulnerability in its `TaskAttachment.ReadOne()` function.  This flaw, present in versions 2.2.0 and earlier, arises because the system only validates the attachment ID when retrieving files, neglecting to verify the associated task ID. An authenticated attacker can exploit this by crafting requests that reference attachments belonging to other projects.  By combining a valid task ID from a project they have access to with the sequential, easily enumerable IDs of attachments from other projects, they can bypass intended access controls and download or delete arbitrary files. The root cause lies in `pkg/models/task_attachment.go` and `pkg/models/task_attachment_permissions.go`. This oversight permits unauthorized access to sensitive documents and potential data destruction, impacting the confidentiality and integrity of data stored within the Vikunja instance.

## Attack Chain

1. The attacker gains initial access to a Vikunja instance with a valid user account.
2. The attacker creates their own project and task within the Vikunja instance to obtain a valid `task_id`.
3. The attacker identifies a target attachment ID, either through enumeration or prior knowledge. Attachment IDs are sequential integers, making enumeration trivial.
4. The attacker crafts a GET request to download a file attachment, using their own valid `task_id` in the URL but specifying the target attachment's `attachment_id`. For example: `/api/v1/tasks/<attacker_task_id>/attachments/<target_attachment_id>`.
5. The Vikunja server's `TaskAttachment.ReadOne()` function retrieves the attachment based solely on the `attachment_id`, bypassing task ID validation.
6.  The `CanRead()` permission check validates access to the attacker's task, specified in the URL, allowing the request to proceed.
7. The attacker receives the victim's file attachment, achieving unauthorized access to sensitive data.
8. The attacker can also send a DELETE request to `/api/v1/tasks/<attacker_task_id>/attachments/<target_attachment_id>` to delete the file. The `CanDelete()` permission check validates access to the attacker's task, allowing the deletion of an arbitrary attachment.

## Impact

This vulnerability allows any authenticated Vikunja user to potentially access or delete any file attachment within the entire system.  This could expose confidential documents and proprietary information, leading to a significant breach of confidentiality.  Furthermore, unauthorized deletion of attachments can result in data loss and disrupt operations. The vulnerability impacts all Vikunja instances running versions 2.2.0 or earlier.  Due to the sequential nature of attachment IDs, an attacker can easily enumerate and access a large number of attachments with minimal effort, potentially impacting hundreds or thousands of files depending on the size of the Vikunja instance.

## Recommendation

*   Apply the recommended fix by adding `task_id` validation to the `ReadOne` function in `pkg/models/task_attachment.go` (see content above) to prevent unauthorized access.
*   Deploy the Sigma rule "Detect Vikunja Unauthorized Attachment Access via IDOR" to identify potential exploitation attempts based on HTTP request patterns targeting attachment endpoints.
*   Deploy the Sigma rule "Detect Vikunja Unauthorized Attachment Deletion via IDOR" to identify potential exploitation attempts based on HTTP DELETE requests targeting attachment endpoints.
*   Monitor web server logs for unusual access patterns to the `/api/v1/tasks/*/attachments/*` endpoint, particularly requests originating from users who do not typically access those tasks.
