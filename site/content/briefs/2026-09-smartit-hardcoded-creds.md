---
title: Hard-coded Credentials in SmartIT Desktop Manager
slug: 2026-09-smartit-hardcoded-creds
description: SmartIT Desktop Manager contains a hard-coded credentials vulnerability that allows unauthenticated remote attackers to retrieve SSH service account credentials for the SmartIT Agent via application source code.
date: "2026-09-04T03:24:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:lightstar:smartit_desktop_manager:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - credential-exposure
  - remote-access
vendors:
  - Lightstar
products:
  - SmartIT Desktop Manager
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Unauthenticated remote attackers can obtain the SSH service account credentials and passwords for the SmartIT Agent directly from the application source code.
    confidence_band: high
cves:
  - id: CVE-2026-85146
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85146
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all hosts running SmartIT Desktop Manager or Agent.
      owner: IT Operations
      due: 24h
      evidence: Source reporting of hard-coded credentials in SmartIT Desktop Manager.
  mitigation_plan:
    - priority: immediate
      action: Restrict inbound SSH access to SmartIT Agent endpoints to known administrative subnets.
      owner: IT Operations
      addresses: CVE-2026-85146
      evidence: Hard-coded credentials allow unauthorized SSH access.
---

Lightstar SmartIT Desktop Manager is affected by a hard-coded credentials vulnerability (CVE-2026-85146). The vulnerability stems from the inclusion of SSH service account credentials directly within the application's source code. An unauthenticated remote attacker with access to the application binary or source code can extract these hard-coded secrets. Once obtained, the attacker can leverage these credentials to authenticate via SSH to any endpoint running the SmartIT Agent, potentially leading to full administrative control over the affected infrastructure. Given the critical nature of these credentials, this vulnerability poses a significant risk to organizations using the SmartIT Desktop Manager, as it provides a clear path for lateral movement and system compromise without requiring prior authentication.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to gain unauthorized SSH access to internal systems managed by SmartIT Agents. This can result in complete system compromise, data exfiltration, and the ability to persist within the environment, impacting any organization utilizing the SmartIT Desktop Manager platform.

## Recommendation

- Identify all instances of SmartIT Desktop Manager and SmartIT Agent within the environment.
- Contact Lightstar support to determine if a security update exists to remove hard-coded credentials.
- If no patch is available, isolate systems running the SmartIT Agent from untrusted networks and restrict SSH access to authorized management segments.
- Implement strict ingress filtering for SSH (TCP/22) to prevent unauthorized remote access using the exposed service account credentials.
