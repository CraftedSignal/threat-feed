---
title: 'CVE-2026-0292: Prisma Access Agent Local Security Inspection Bypass'
slug: 2026-08-prisma-access-bypass
description: A local authentication bypass vulnerability in the Palo Alto Networks Prisma Access Agent for Windows enables an administrative user to disable security inspections and manipulate network traffic.
date: "2026-08-12T16:47:59Z"
type: threat
types:
  - threat
severities:
  - low
exploited: true
tags:
  - vulnerability
  - windows
  - network-security
vendors:
  - Palo Alto Networks
products:
  - Prisma Access Agent
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability enables a local administrator to bypass security inspection.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0292
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Prisma Access Agent to 26.3 or later on all Windows endpoints
      owner: IT Operations
      due: 72h
      evidence: Vendor recommendation for CVE-2026-0292
---

Palo Alto Networks has disclosed a vulnerability (CVE-2026-0292) affecting the Prisma Access Agent on Windows, specifically versions 24.0 through 26.2.2. The flaw resides in the network driver component and is classified as an authentication bypass (CWE-290). An attacker who has already gained local administrative privileges on the target system can leverage this vulnerability to bypass the security inspection capabilities of the agent. This effectively removes the protective controls enforced by the Prisma Access Agent, allowing the adversary to intercept or inject arbitrary network traffic originating from or destined to the host. There is no evidence of exploitation in the wild at this time, and the vulnerability cannot be exploited remotely or by low-privileged users.

## Impact

Successful exploitation of this vulnerability allows an already high-privileged user to undermine the security posture of an endpoint by disabling network inspection. This could facilitate man-in-the-middle attacks or data exfiltration from the host system while bypassing enterprise security policy enforcement. The vulnerability affects all enterprise deployments of the Prisma Access Agent on Windows within the stated version range.

## Recommendation

* Prioritize the deployment of Prisma Access Agent version 26.3 or later across the enterprise Windows fleet.
* Restrict administrative privileges on managed endpoints to reduce the likelihood of a local attacker achieving the necessary access level to trigger this flaw.
* Monitor for unauthorized modifications to security driver configurations on Windows hosts via standard configuration management auditing.
