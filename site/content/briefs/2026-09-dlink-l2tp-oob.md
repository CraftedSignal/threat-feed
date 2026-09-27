---
title: Remote Out-of-Bounds Write in D-Link DIR-895L L2TP Parser
slug: 2026-09-dlink-l2tp-oob
description: A critical out-of-bounds write vulnerability (CVE-2026-100740) in the D-Link DIR-895L L2TP control channel parser allows remote attackers to potentially achieve code execution.
date: "2026-09-27T03:02:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:dlink:dir-895l_firmware:a1_102b07:*:*:*:*:*:*:*
tags:
  - cve
  - remote-code-execution
  - router
  - vulnerability
vendors:
  - D-Link
products:
  - DIR-895L (A1_102b07)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The attack may be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Performing a manipulation results in out-of-bounds write.
    confidence_band: high
cves:
  - id: CVE-2026-100740
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100740
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Network Operations
  immediate_actions:
    - action: Isolate affected D-Link DIR-895L routers from the public internet.
      owner: Network Operations
      due: 24h
      evidence: High CVSS score and public exploit availability.
  mitigation_plan:
    - priority: immediate
      action: Block UDP port 1701 traffic on the WAN interface of the affected routers.
      owner: Network Operations
      addresses: CVE-2026-100740
      evidence: Remote out-of-bounds write via L2TP control channel.
---

D-Link DIR-895L firmware version A1_102b07 contains a critical security vulnerability identified as CVE-2026-100740. The flaw resides within the L2TP Control Channel Parser, specifically inside the tunnel_set_params function located in tunnel.c. An attacker can trigger an out-of-bounds write via a crafted remote request. Because this is a memory corruption vulnerability within a networking component, successful exploitation could lead to arbitrary code execution or a denial-of-service condition for the affected router. Publicly available exploit material exists, increasing the risk of exploitation. Defenders should treat this as a high-priority risk for edge network devices.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.9, reflecting its severity as a remote, unauthenticated code execution vector. Successful exploitation compromises the integrity and availability of the affected D-Link DIR-895L device, potentially allowing an attacker to intercept traffic, pivot into the local network, or render the device unusable.

## Recommendation

* Immediately identify and isolate all D-Link DIR-895L (firmware A1_102b07) devices from the internet-facing edge of the network.
* Check the vendor support portal for official firmware patches addressing CVE-2026-100740 and apply them immediately upon release.
* If no patch is available, implement firewall rules to block unsolicited inbound L2TP traffic (typically UDP port 1701) directed at the router's WAN interface.
