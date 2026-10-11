---
title: Vearch Incorrect Authorization Vulnerability (CVE-2026-108746)
slug: 2026-10-vearch-auth-bypass
description: Vearch versions 3.5.2 through 3.5.9 contain an incorrect authorization vulnerability allowing authenticated non-root users to perform unauthorized document modifications and escalate privileges to cluster administrator.
date: "2026-10-11T14:01:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vearch:vearch:3.5.2:*:*:*:*:*:*:*
  - cpe:2.3:a:vearch:vearch:3.5.9:*:*:*:*:*:*:*
vendors:
  - Vearch
products:
  - Vearch (3.5.2-3.5.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated non-root users can upsert and delete documents with read-only access, or call PUT /roles to grant their role WriteRead privileges, escalating toward cluster administrator access.
    confidence_band: high
cves:
  - id: CVE-2026-108746
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108746
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Vearch to a patched version beyond 3.5.9
      owner: IT Operations
      due: 48h
      evidence: Source confirms versions 3.5.2 through 3.5.9 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the Vearch management API, specifically the PUT /roles endpoint.
      owner: Security Operations
      addresses: CVE-2026-108746
      evidence: Vulnerability allows privilege escalation via PUT /roles API.
---

Vearch versions 3.5.2 through 3.5.9 are affected by an incorrect authorization vulnerability located in the Role.HasPermissionForResources function. The flaw manifests because the function fails to correctly validate or respect stored ReadOnly or None privilege levels assigned to resources within a role. Consequently, an authenticated user who is not a root administrator can bypass these restrictions to perform unauthorized upsert and delete operations on documents. Furthermore, the vulnerability enables an attacker to manipulate role permissions via the PUT /roles API to grant their own account WriteRead privileges, facilitating an escalation of access toward cluster administrator. This issue represents a significant risk to data integrity and cluster security, as it allows standard authenticated users to transcend their intended access controls within the Vearch distributed vector database environment.

## Impact

Successful exploitation allows authenticated users to read, modify, or delete sensitive data within the Vearch database regardless of assigned read-only restrictions. By leveraging the PUT /roles API, an attacker can grant themselves administrative privileges, potentially leading to full control over the Vearch cluster. This vulnerability affects all environments running Vearch versions 3.5.2 through 3.5.9.

## Recommendation

- Upgrade Vearch to a version outside the affected range (3.5.2-3.5.9).
- Implement strict network segmentation to limit access to the Vearch API, especially the /roles endpoint.
- Review all current role and privilege assignments in the Vearch cluster for unauthorized modifications or unexpected elevated permissions.
- Enable strict API access logging to detect unauthorized calls to the PUT /roles endpoint.
