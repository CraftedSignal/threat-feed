---
title: Remote Code Execution via HNAP1 in D-Link DIR-823G
slug: 2026-09-dlink-buffer-overflow
description: A stack-based buffer overflow vulnerability in the HNAP1 component of D-Link DIR-823G allows remote attackers to execute arbitrary code via malformed parameters in SetStaticRouteSettings.
date: "2026-09-14T05:30:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:d_link:dir_823g:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - network-infrastructure
  - cve-2026-90680
vendors:
  - D-Link
products:
  - DIR-823G (1.0.2B05_20181207)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The attack can be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The manipulation of the argument PAddress/SubnetMask/Gateway results in stack-based buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-90680
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90680
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate D-Link DIR-823G routers from internet-facing network segments.
      owner: IT Operations
      due: 24h
      evidence: Critical severity (9.9) RCE vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to HNAP1 web interface to trusted internal IP addresses only.
      owner: IT Operations
      addresses: CVE-2026-90680
      evidence: Vulnerability in /HNAP1/SetStaticRouteSettings.
---

A critical security vulnerability, identified as CVE-2026-90680, has been disclosed in the D-Link DIR-823G router, specifically affecting firmware version 1.0.2B05_20181207. The vulnerability resides within the HNAP1 (Home Network Administration Protocol) component. Specifically, the function responsible for processing static route settings, located at /HNAP1/SetStaticRouteSettings, improperly handles input parameters.

An attacker can exploit this via the PAddress, SubnetMask, or Gateway arguments. The underlying issue is an unsafe call to the strcpy function, which leads to a stack-based buffer overflow when provided with excessively long input strings. Because this interface is reachable over the network, a remote, unauthenticated attacker could leverage this flaw to crash the device or achieve remote code execution (RCE) with the privileges of the HNAP1 service. This impacts the integrity and availability of the affected network infrastructure.

## Impact

Successful exploitation of this vulnerability allows for full remote compromise of the D-Link DIR-823G router. Given the position of these devices on the network perimeter, an attacker could intercept traffic, modify DNS settings, or gain a foothold for lateral movement into the internal network. The vulnerability carries a CVSS v3.1 base score of 9.9, reflecting its critical nature.

## Recommendation

Defenders should prioritize identifying any D-Link DIR-823G devices currently active within their environment. Since the vendor has not provided an updated firmware patch in the provided disclosure, immediate isolation or removal of these devices from internet-facing positions is required. Implement strict firewall controls to limit access to the HNAP1 interface to only trusted internal management subnets.
