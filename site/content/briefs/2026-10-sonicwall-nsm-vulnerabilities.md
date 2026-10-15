---
title: Multiple Vulnerabilities in SonicWall Network Security Manager
slug: 2026-10-sonicwall-nsm-vulnerabilities
description: Multiple vulnerabilities in SonicWall Network Security Manager versions prior to 4.4.0, including CVE-2026-100232 and CVE-2026-96540, allow unauthenticated attackers to achieve remote code execution and bypass security policies.
date: "2026-10-15T16:26:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sonicwall:network_security_manager_on_prem:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - security-policy-bypass
vendors:
  - SonicWall
products:
  - Network Security Manager On-Prem (< 4.4.0)
cves:
  - id: CVE-2026-100232
  - id: CVE-2026-96540
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1320/
  - https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0018
  - https://www.cve.org/CVERecord?id=CVE-2026-100232
  - https://www.cve.org/CVERecord?id=CVE-2026-96540
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade SonicWall Network Security Manager On-Prem to version 4.4.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Vendor security bulletin SNWLID-2026-0018
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface access via network ACLs.
      owner: Security Engineering
      addresses: CVE-2026-100232, CVE-2026-96540
      evidence: General security best practices for management consoles
---

Multiple vulnerabilities have been identified in SonicWall Network Security Manager (NSM) On-Prem, affecting VMWare, Hyper-V, Azure, and KVM deployments. These security flaws, tracked under CVE-2026-100232 and CVE-2026-96540, pose a significant risk to organizational infrastructure by allowing remote attackers to bypass security policy enforcement and execute arbitrary code. 

The flaws reside in versions prior to 4.4.0. Given the role of NSM in managing and monitoring firewall appliances, exploitation could allow an attacker to gain broad control over the management plane of an organization's network security perimeter. Defenders should prioritize patching all instances of NSM On-Prem to version 4.4.0 or later as advised by the SonicWall PSIRT bulletin SNWLID-2026-0018.

## Impact

Successful exploitation of these vulnerabilities enables unauthorized remote code execution and policy bypass, which can lead to complete compromise of the Network Security Manager appliance, unauthorized access to managed network devices, and potential exfiltration of sensitive configuration data or credentials stored within the security management ecosystem.

## Recommendation

* Immediately upgrade all instances of SonicWall Network Security Manager On-Prem to version 4.4.0 or later to address CVE-2026-100232 and CVE-2026-96540.
* Restrict access to the Network Security Manager management interface to trusted administrative network segments and ensure that the management interface is not exposed to the public internet.
* Review audit logs on the NSM appliance for unexpected configuration changes or unauthorized service executions following the update.
