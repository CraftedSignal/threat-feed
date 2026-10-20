---
title: Insecure Direct Object Reference in Coze Studio workflow.go
slug: 2026-10-coze-studio-idor
description: Coze Studio versions up to 0.5.1 are vulnerable to an IDOR flaw in workflow.go allowing authenticated users to perform unauthorized operations on other tenants workflows.
date: "2026-10-20T02:32:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bytedance:coze_studio:*:*:*:*:*:*:*:*
tags:
  - idor
  - web-vulnerability
  - cloud
vendors:
  - ByteDance
products:
  - Coze Studio (<= 0.5.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated users can manipulate workflowID and spaceID parameters ... to perform unauthorized read, execution, modification, or deletion operations on workflows belonging to other tenants.
    confidence_band: high
cves:
  - id: CVE-2026-77935
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77935
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Coze Studio to a version greater than 0.5.1.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-77935 advisory for Coze Studio.
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected Coze Studio instances.
      owner: IT Operations
      addresses: CVE-2026-77935
      evidence: CVE-2026-77935
---

Coze Studio versions up to and including 0.5.1 contain an Insecure Direct Object Reference (IDOR) vulnerability within the workflow.go component. This vulnerability stems from insufficient access control checks when processing workflow identifiers. An authenticated user can supply foreign workflowIDs associated with another tenant while pairing them with their own spaceID. 

By manipulating parameters in specific API routes, including save, update_meta, batch_delete, canvas, test_run, and nodeDebug, an attacker can read, execute, overwrite, or delete workflows belonging to other spaces. Because the application fails to validate that the requested workflowID resides within the context of the user's authorized spaceID, the integrity and confidentiality of cross-tenant workflows are compromised. This impact is significant as it allows for the manipulation of workflows across the entire multi-tenant environment.

## Impact

The vulnerability allows unauthorized authenticated users to compromise the workflows of other tenants. Success leads to data exfiltration, unauthorized execution of automation logic, modification of business processes, or permanent deletion of workflows. This impacts the integrity and availability of services for any organization hosting workflows on a shared or multi-tenant Coze Studio instance.

## Recommendation

- Upgrade Coze Studio to a patched version beyond 0.5.1 as soon as it becomes available.
- Implement strict request validation at the application firewall level for all API routes involving workflowID and spaceID parameters.
- Audit access logs for instances where a single authenticated user session interacts with multiple distinct spaceIDs.
- Patch CVE-2026-77935 immediately upon release of the vendor security update.
