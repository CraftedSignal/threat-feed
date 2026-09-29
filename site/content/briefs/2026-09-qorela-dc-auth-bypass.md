---
title: Missing Authorization Vulnerability in Interprobe Qorela DC
slug: 2026-09-qorela-dc-auth-bypass
description: A missing authorization vulnerability (CVE-2026-87748) in Interprobe Qorela DC allows authenticated users to escalate privileges and perform unauthorized actions.
date: "2026-09-29T12:27:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:interprobe:qorela_dc:1.6.1-rc29:*:*:*:*:*:*:*
vendors:
  - Interprobe Information Technologies
products:
  - Qorela DC (1.6.1-RC29 to < 1.6.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The flaw allows authenticated users to perform privilege abuse, potentially leading to unauthorized actions within the system.
    confidence_band: high
cves:
  - id: CVE-2026-87748
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87748
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Qorela DC to version 1.6.2 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-87748 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Qorela DC v1.6.2.
      owner: IT Operations
      addresses: CVE-2026-87748
      evidence: NVD vulnerability disclosure
---

Interprobe Information Technologies Inc. has disclosed a missing authorization vulnerability, identified as CVE-2026-87748, affecting the Qorela DC platform. The vulnerability exists within versions 1.6.1-RC29 through versions prior to 1.6.2. This flaw allows an authenticated user to bypass existing authorization controls, facilitating unauthorized privilege escalation and system manipulation. As a result, attackers who have established low-privilege access to the Qorela DC interface can leverage this vulnerability to gain broader administrative or functional control, potentially leading to unauthorized system configuration changes or data access. Organizations utilizing Qorela DC are urged to update to version 1.6.2 or later to remediate the vulnerability.

## Impact

Successful exploitation of this vulnerability permits authenticated users to perform unauthorized actions beyond their intended scope. This privilege abuse can lead to total loss of integrity and confidentiality within the Qorela DC management interface, depending on the sensitive operations accessible through the bypassed authorization checks.

## Recommendation

- Upgrade all instances of Qorela DC to version 1.6.2 or later to address the authorization flaw documented in CVE-2026-87748.
- Review access logs for Qorela DC to identify unusual administrative actions or privilege changes originating from low-privileged service or user accounts.
- Restrict access to the Qorela DC management interface to trusted networks and implement robust authentication controls to minimize the exposure of the application to potentially compromised accounts.
