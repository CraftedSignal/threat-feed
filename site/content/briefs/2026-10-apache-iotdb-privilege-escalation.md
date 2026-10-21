---
brief_id: brief-2026-10-21-apache-iotdb-privilege-escalation
event_id: brief-2026-10-21-apache-iotdb-privilege-escalation
revision: 1
activity_at: "2026-10-21T17:06:50Z"
title: 'Apache IoTDB: Privilege escalation in Legacy Pipe protocol (CVE-2026-59229)'
slug: 2026-10-apache-iotdb-privilege-escalation
description: Apache IoTDB versions 2.0.0 through 2.0.10 contain a privilege escalation vulnerability where the Legacy Pipe receiver protocol uses a hardcoded root identity to perform unauthorized data operations.
date: "2026-10-21T17:06:50Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; patch available
cpes:
  - cpe:2.3:a:apache:iotdb:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - iotdb
  - vulnerability
vendors:
  - Apache
products:
  - IoTDB (< 2.0.11)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A user with only SYSTEM-level privileges (such as USE_PIPE or MAINTAIN) who does NOT have WRITE_DATA or DELETE_DATA permissions on target databases can send specially crafted PipeData messages
    confidence_band: high
cves:
  - id: CVE-2026-59229
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/292
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache IoTDB to version 2.0.11 or later
      owner: IT Operations
      addresses: CVE-2026-59229
      evidence: Source advises version 2.0.11 as the fix
---

Apache IoTDB versions 2.0.0 through 2.0.10 are vulnerable to a privilege escalation flaw in the Legacy Pipe receiver protocol (CVE-2026-59229). The vulnerability stems from the protocol using a hardcoded SUPER_USER (root) identity when executing data loading and deletion operations. An authenticated attacker possessing only system-level privileges (such as USE_PIPE or MAINTAIN) can bypass authorization checks to perform WRITE_DATA or DELETE_DATA operations on unauthorized databases by sending specially crafted PipeData messages.

## Impact

Successful exploitation allows authenticated users with restricted system-level permissions to perform data modification or deletion tasks that they are otherwise unauthorized to execute.

## Recommendation

Upgrade Apache IoTDB to version 2.0.11 or later to resolve the hardcoded credential usage in the Legacy Pipe receiver protocol.
