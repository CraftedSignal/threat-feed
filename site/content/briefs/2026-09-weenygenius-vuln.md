---
title: Unauthenticated Endpoint Spoofing in WeenyGenius
slug: 2026-09-weenygenius-vuln
description: WeenyGenius by Howyar Technologies contains a missing authentication vulnerability allowing unauthenticated network-adjacent attackers to spoof teacher or student roles and achieve remote control of student workstations.
date: "2026-09-11T09:12:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:howyar:weenygenius:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - lab-management
vendors:
  - Howyar Technologies
products:
  - WeenyGenius
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
    evidence: Unauthenticated attackers on the same network can easily spoof student or teacher endpoints.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Impersonating a teacher can induce student computers to initiate connections, thereby gaining remote control.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Impersonating a teacher can induce student computers to initiate connections.
    confidence_band: med
cves:
  - id: CVE-2026-89176
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89176
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Isolate WeenyGenius management traffic via network segmentation
      owner: IT Operations
      addresses: CVE-2026-89176
      evidence: Missing authentication allows spoofing of teacher/student endpoints on the same network
---

Howyar Technologies WeenyGenius, a computer lab management system, is affected by a missing authentication vulnerability (CVE-2026-89176). This flaw allows an unauthenticated attacker present on the local network to spoof the identity of either a student or teacher endpoint. By successfully masquerading as a teacher node, an attacker can transmit unauthorized commands to student workstations. This capability enables the attacker to initiate connections from student machines, potentially leading to unauthorized remote control and the disruption of classroom activities. Because the application lacks sufficient authentication mechanisms, any attacker with network connectivity to the lab environment can interact with the management service and influence endpoint behavior without providing credentials.

## Impact

Successful exploitation allows unauthenticated attackers to gain remote control over student workstations within a laboratory environment. This can lead to the total disruption of classroom operations, unauthorized access to student work, and potential further lateral movement within the network if student endpoints are leveraged as a beachhead.

## Recommendation

Defenders should prioritize the identification of WeenyGenius deployments within their network environment and ensure they are segmented from untrusted users. If patching is unavailable, implement network-level access control lists to restrict traffic to the management service to known authorized teacher workstations only.
