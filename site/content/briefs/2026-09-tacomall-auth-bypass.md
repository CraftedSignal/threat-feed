---
title: Improper Authorization in Tacomall via OrgStaffServiceImpl
slug: 2026-09-tacomall-auth-bypass
description: Tacomall 1.0.0 is vulnerable to an improper authorization flaw in the OrgStaffServiceImpl.add function, allowing remote attackers to manipulate isAdmin or jobId arguments to achieve unauthorized access.
date: "2026-09-29T06:25:35Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:realjerrytang:tacomall:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authorization-bypass
  - api-security
vendors:
  - realjerrytang
products:
  - tacomall (1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-102293
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102293
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review application logs for attempts to modify isAdmin/jobId parameters
      owner: SOC
      due: 24h
      evidence: Source document identifies manipulation of isAdmin/jobId as the attack vector
  mitigation_plan:
    - priority: immediate
      action: Restrict access to api-admin backend via network controls
      owner: IT Operations
      addresses: CVE-2026-102293
      evidence: Vulnerability allows remote exploitation via api-admin component
---

A security vulnerability has been identified in the 'tacomall' application version 1.0.0, developed by 'realjerrytang'. The flaw resides in the 'OrgStaffServiceImpl.add' function within the 'ApiMaApplication.java' file of the 'api-admin' backend component. An attacker can exploit this vulnerability by manipulating the 'isAdmin' or 'jobId' arguments during an organizational staff addition request. This improper authorization defect allows remote, unauthenticated, or low-privileged attackers to gain elevated privileges or perform actions intended for administrators. The vulnerability is currently being tracked as CVE-2026-102293, and proof-of-concept exploit code is publicly available, increasing the likelihood of in-the-wild exploitation. Defenders should monitor for unexpected API requests targeting the 'OrgStaffServiceImpl' endpoint.

## Impact

Successful exploitation of this vulnerability leads to broken access control, enabling unauthorized administrative actions within the Tacomall environment. Depending on the environment, this could allow an attacker to create new administrative accounts, modify existing user permissions, or extract sensitive organizational staff data. The exposure of administrative functions via an insecure API endpoint poses a high risk to the confidentiality and integrity of the application data.

## Recommendation

1. Inventory all instances of Tacomall version 1.0.0 and assess the exposure of the 'api-admin' backend.
2. Implement strict input validation and server-side authorization checks on the 'OrgStaffServiceImpl.add' API endpoint to verify user identity before processing 'isAdmin' or 'jobId' parameter modifications.
3. If patching is not immediately feasible, restrict network access to the management backend using an IP allowlist or VPN, ensuring only authorized administrators can reach the vulnerable API.
4. Monitor application server logs for abnormal request patterns targeting 'OrgStaffServiceImpl.add', specifically looking for suspicious modifications to user role parameters.
