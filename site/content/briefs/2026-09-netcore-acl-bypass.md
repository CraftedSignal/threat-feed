---
title: Missing Authorization Vulnerability in Netcore NBR100V2
slug: 2026-09-netcore-acl-bypass
description: An unauthenticated remote authorization bypass vulnerability exists in the Netcore NBR100V2 router, allowing attackers to manipulate system configurations via the ACL Handler component.
date: "2026-09-28T08:49:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:netcore:nbr100v2:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - network-security
  - acl-bypass
vendors:
  - Netcore
products:
  - NBR100V2 (1.3.240614.030928)
cves:
  - id: CVE-2026-101000
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101000
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external access to management interface of affected Netcore devices
      owner: IT Operations
      due: 24h
      evidence: Source classifies as critical missing authorization reachable remotely
  mitigation_plan:
    - priority: immediate
      action: Isolate NBR100V2 devices from public-facing segments
      owner: IT Operations
      addresses: CVE-2026-101000
      evidence: High CVSS score and public exploit availability
---

A critical missing authorization vulnerability has been identified in the Netcore NBR100V2 router (firmware version 1.3.240614.030928). The vulnerability exists within the ACL Handler component, specifically impacting the 'uci.apply' function. This flaw is rooted in an improperly defined access control list (ACL) within the '/usr/share/rpcd/acl.d/unauthenticated.json' configuration file. 

The vulnerability allows remote, unauthenticated attackers to manipulate the 'section' argument, potentially resulting in unauthorized system configuration changes. Given that the exploit has been publicly disclosed and the vendor has not provided a response or a patch, systems running this specific firmware version are at significant risk of unauthorized administrative control. Defenders should prioritize identifying and isolating these devices from external networks.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to bypass authorization controls, which can lead to unauthorized modification of router configurations. Given the base CVSS score of 10.0, the potential for total system compromise is high. This affects enterprise and home-office deployments relying on the Netcore NBR100V2 router for network security and traffic management.

## Recommendation

- Immediately restrict access to the management interface of Netcore NBR100V2 routers to trusted internal IP ranges or VPNs only.
- Disable remote administrative access on all internet-facing Netcore NBR100V2 devices.
- Monitor network traffic logs for unusual HTTP POST requests directed at internal ACL handling endpoints or attempts to interact with the 'uci.apply' function.
- As no vendor patch is currently available, evaluate replacing the affected hardware or isolating it behind a hardened perimeter gateway.
