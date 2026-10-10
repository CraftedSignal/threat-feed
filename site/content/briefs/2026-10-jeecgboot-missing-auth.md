---
title: Missing Authorization Vulnerability in JeecgBoot SysLogController
slug: 2026-10-jeecgboot-missing-auth
description: JeecgBoot versions 3.9.5 and earlier contain a missing authorization vulnerability in the SysLogController that allows low-privileged authenticated users to delete system audit logs via a specially crafted request.
date: "2026-10-10T23:57:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jeecg:jeecgboot:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - authorization
  - jeecgboot
vendors:
  - Jeecg
products:
  - JeecgBoot (<= 3.9.5)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Low-privileged attackers can send a DELETE request with ids set to allclear to wipe the entire sys_log table, erasing all users' audit trails.
    confidence_band: high
cves:
  - id: CVE-2026-108623
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108623
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch JeecgBoot instances to a version beyond 3.9.5
      owner: IT Operations
      due: 72h
      evidence: JeecgBoot through 3.9.5 contains a missing authorization vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the SysLogController deleteBatch endpoint via application-level authorization
      owner: IT Operations
      addresses: CVE-2026-108623
      evidence: Missing authorization vulnerability in the SysLogController deleteBatch handler.
---

JeecgBoot through version 3.9.5 contains a missing authorization vulnerability in the SysLogController deleteBatch handler. This vulnerability allows an authenticated user, regardless of their privilege level, to delete system audit logs by sending a crafted DELETE request. By providing the parameter ids=allclear to the relevant endpoint, an attacker can trigger the removal of all entries within the sys_log database table. This action effectively wipes out system audit trails, hindering forensic investigations and security monitoring efforts. This flaw is rated with a CVSS v3.1 base score of 7.1, reflecting its potential impact on security logging integrity. The vulnerability persists in all versions up to and including 3.9.5, necessitating a patch to enforce proper access control checks within the SysLogController.

## Impact

Successful exploitation results in the permanent deletion of system audit logs, which directly impacts an organization's ability to monitor user activity and perform incident response. By clearing the sys_log table, an attacker can hide evidence of other malicious activities, complicating post-incident forensic analysis. This vulnerability affects all environments running vulnerable versions of JeecgBoot that are exposed to low-privileged users.

## Recommendation

- Upgrade all JeecgBoot instances to a patched version that enforces authorization checks on the SysLogController deleteBatch handler.
- Implement strict access controls for web application endpoints to ensure that delete operations are restricted to authorized administrative roles.
- Review existing audit logs for suspicious activity involving the SysLogController, particularly patterns involving the deletion of large volumes of records in a single request.
