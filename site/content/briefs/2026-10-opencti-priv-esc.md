---
title: OpenCTI Privilege Escalation Vulnerability
slug: 2026-10-opencti-priv-esc
description: A vulnerability in OpenCTI allows a remote, authenticated attacker to escalate their privileges to administrator level.
date: "2026-10-02T14:20:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - security-advisory
vendors:
  - OpenCTI
products:
  - OpenCTI
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in OpenCTI ausnutzen, um Administratorrechte zu erlangen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3717
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review OpenCTI application logs for unauthorized administrative privilege changes.
      owner: SOC
      due: 24h
      evidence: Source confirms potential for admin privilege escalation.
  mitigation_plan:
    - priority: immediate
      action: Check vendor portal for the latest security update and apply patch.
      owner: IT Operations
      addresses: Privilege escalation vulnerability in OpenCTI
      evidence: BSI advisory recommends addressing the security flaw.
---

The BSI has released a security advisory regarding a vulnerability in OpenCTI. A remote, authenticated attacker can exploit this flaw to gain unauthorized administrative access to the platform. OpenCTI is a widely used threat intelligence management platform that handles sensitive cyber security data, making unauthorized administrative access a high-risk event for organizations. Authenticated users with lower-level permissions can manipulate the system to obtain full control, potentially leading to the modification, exfiltration, or deletion of threat intelligence data stored within the instance. Administrators are advised to review their current OpenCTI deployment and consult the vendor's security updates for patch availability or mitigation strategies.

## Impact

Successful exploitation allows a low-privileged authenticated user to gain full administrative rights. This impact includes total compromise of the OpenCTI instance, enabling the attacker to access, modify, or exfiltrate sensitive threat intelligence, manipulate user accounts, and potentially gain further access to the underlying server infrastructure if the application is not properly sandboxed.

## Recommendation

* Monitor system logs and access logs for suspicious administrative actions performed by accounts that typically do not hold high-level privileges.
* Audit current user roles within OpenCTI to identify any unauthorized privilege assignments.
* Review all vendor-provided security patches for OpenCTI and apply the latest available updates to remediate this vulnerability.
