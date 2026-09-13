---
title: Insecure Direct Object Reference in CAPEv2 REST API
slug: 2026-09-capev2-idor
description: CAPEv2 versions up to commit 471ee4b contain an IDOR vulnerability allowing authenticated users to access and delete arbitrary analysis tasks.
date: "2026-09-13T11:25:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:capev2:capev2:*:*:*:*:*:*:*:*
tags:
  - webserver
  - idor
  - api-security
vendors:
  - CAPEv2
products:
  - CAPEv2 (<= 471ee4b)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can enumerate all tasks in the system and delete arbitrary analyses by sending requests to task view and delete endpoints without ownership verification.
    confidence_band: high
cves:
  - id: CVE-2026-90768
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90768
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review REST API access logs for anomalous enumeration of task IDs
      owner: SOC
      due: 24h
      evidence: Source notes users can enumerate all tasks
  mitigation_plan:
    - priority: immediate
      action: Upgrade CAPEv2 instance to commit post-471ee4b
      owner: IT Operations
      addresses: CVE-2026-90768
      evidence: NVD vulnerability disclosure
---

CAPEv2 up to commit 471ee4b contains an insecure direct object reference (IDOR) vulnerability within its REST API endpoints. The software fails to implement proper ownership validation checks for analysis tasks. Consequently, any authenticated user can bypass access controls to enumerate, read, and delete analysis tasks submitted by other users. This vulnerability is significant in shared sandbox environments where multiple researchers or analysts utilize the same CAPEv2 instance, as it allows for unauthorized data exfiltration or the destruction of historical analysis evidence. Defenders should restrict access to the REST API and monitor for suspicious enumeration patterns or unauthorized deletion requests.

## Impact

Successful exploitation allows authenticated users to enumerate all tasks within the system and delete arbitrary analyses. This results in loss of integrity for sandbox reporting and unauthorized access to sensitive malware analysis results.

## Recommendation

Update CAPEv2 to a commit after 471ee4b to ensure task ownership validation is enforced. Implement strict access control lists on the REST API endpoint and monitor web server access logs for anomalous patterns in URL parameters associated with task IDs.
