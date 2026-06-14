---
title: 'praisonai-platform: Cross-Workspace Label IDOR Vulnerability'
slug: 2026-05-praisonai-idor
description: Praison AI's praisonai-platform is vulnerable to an insecure direct object reference (IDOR) in the label endpoints (CVE-2026-47414), allowing cross-workspace label modification and information disclosure due to improper validation of label and issue IDs.
date: "2026-05-29T22:51:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - vulnerability
  - privilege-escalation
  - collection
  - impact
  - cloud
vendors:
  - Praison AI
products:
  - praisonai-platform
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-5jx9-w35f-vp65
  - CVE-2026-47414
rules:
  - title: Detect Cross-Workspace Label Modification via IDOR
    description: Detects CVE-2026-47414 exploitation - an attempt to modify a label using an invalid workspace ID, indicating a cross-workspace IDOR attack.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Cross-Workspace Label Deletion via IDOR
    description: Detects CVE-2026-47414 exploitation - an attempt to delete a label using an invalid workspace ID, indicating a cross-workspace IDOR attack.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

The praisonai-platform is vulnerable to an Insecure Direct Object Reference (IDOR) vulnerability affecting label management endpoints. The vulnerability resides in `src/praisonai-platform/praisonai_platform/services/label_service.py` (lines 35-100) and `src/praisonai-platform/praisonai_platform/api/routes/labels.py` (lines 42-106), and is tracked as CVE-2026-47414. Specifically, the application fails to validate if the `label_id` and `issue_id` provided in API requests belong to the workspace associated with the request. Instead, it relies solely on `require_workspace_member(workspace_id)` for access control, without extending this validation to the data layer. This allows an attacker with valid credentials for one workspace to manipulate labels and issue associations in other workspaces. The affected package is `pip/praisonai-platform` with versions 0.1.2 and earlier.

## Attack Chain

1. The attacker registers a workspace `W_attacker` and obtains a valid authentication token for this workspace.
2. The attacker identifies `label_id` (`L_T`) and `issue_id` (`I_T`) from a target workspace `W_target`. These IDs can be harvested from responses (e.g., `list_labels` for attacker's workspace, or from issue records, activity feeds, exported dumps or error messages of the target workspace).
3. The attacker crafts a `PATCH` request to `/workspaces/W_attacker/labels/L_T` with a malicious payload to rename or recolor the label. This bypasses access control because the application only checks the attacker's workspace membership, not whether the label belongs to that workspace.
4. The `LabelService.update(L_T, ...)` function is called, modifying the foreign label in the database without proper authorization, resulting in the label's name and color being changed across the target workspace.
5. The attacker can send a `DELETE` request to `/workspaces/W_attacker/labels/L_T`. The `LabelService.delete(L_T)` function is called, deleting the label from the database and potentially disrupting associations within the target workspace.
6. The attacker crafts a `POST` request to `/workspaces/W_attacker/issues/I_T/labels/L_T2` to attach a foreign label `L_T2` to a foreign issue `I_T`.
7. The `LabelService.add_to_issue(I_T, L_T2)` function is executed, writing the association row without validating that either the issue or label ID belong to the attacker's workspace.
8. The attacker now has the ability to rewrite and delete labels from other workspaces, attach arbitrary labels to issues in other workspaces, detach valid labels from issues in other workspaces, and read the current label set on any issue.

## Impact

Successful exploitation of this IDOR vulnerability allows an attacker to rename and delete labels across workspaces, attach and detach labels on issues in unauthorized workspaces, and list label assignments for any issue. This can lead to data corruption, disruption of triage workflows due to incorrect labeling, and unauthorized information disclosure. The vulnerability has a CVSS score of 6.3 (sec-moderate) with high integrity damage, low confidentiality impact, and low availability impact. If combined with the IssueService IDOR, an attacker can tamper with both the issue and its labels, making detection even more difficult.

## Recommendation

*   Apply the suggested fix provided in the advisory to `src/praisonai-platform/praisonai_platform/services/label_service.py` and `src/praisonai-platform/praisonai_platform/api/routes/labels.py` to ensure workspace validation for label and issue IDs.
*   Deploy the Sigma rule "Detect Cross-Workspace Label Modification via IDOR" to identify malicious `PATCH` requests attempting to modify labels using a workspace ID mismatch.
*   Deploy the Sigma rule "Detect Cross-Workspace Label Deletion via IDOR" to identify malicious `DELETE` requests attempting to delete labels using a workspace ID mismatch.
*   Upgrade `pip/praisonai-platform` to a version greater than 0.1.2 to mitigate CVE-2026-47414.
