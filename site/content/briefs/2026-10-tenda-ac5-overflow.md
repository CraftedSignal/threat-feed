---
title: Remote Stack-Based Buffer Overflow in Tenda AC5
slug: 2026-10-tenda-ac5-overflow
description: A critical remote stack-based buffer overflow vulnerability in the Tenda AC5 router allows unauthenticated attackers to execute arbitrary code via the wifiPwd parameter.
date: "2026-10-06T08:53:33Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:tenda:ac5:02.03.01.111_multi:*:*:*:*:*:*:*
vendors:
  - Tenda
products:
  - AC5 (02.03.01.111_multi)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105778
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105778
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to the web management interface of Tenda AC5 devices
      owner: IT Operations
      due: 24h
      evidence: Exploit has been disclosed to the public
  mitigation_plan:
    - priority: immediate
      action: Disable remote web management for Tenda AC5 devices
      owner: IT Operations
      addresses: CVE-2026-105778
      evidence: Critical severity CVSS 9.9
---

A critical stack-based buffer overflow vulnerability has been identified in Tenda AC5 router firmware version 02.03.01.111_multi. The flaw is located within the Wifi Handler component, specifically within the '/goform/setWifi' endpoint. An unauthenticated remote attacker can trigger this vulnerability by sending a maliciously crafted 'wifiPwd' argument to the device. Exploitation of this flaw allows for arbitrary code execution or a denial of service condition. Given that the exploit code has been disclosed to the public, there is a high risk of active exploitation. Defenders should monitor for unexpected traffic directed at the router's web management interface and evaluate exposure of these devices.

## Impact

Successful exploitation of this vulnerability results in full device compromise, allowing an attacker to execute arbitrary code with the privileges of the web management process. This can lead to persistent unauthorized access, lateral movement within the local network, or persistent denial of service. The vulnerability is rated at a CVSS v3.1 base score of 9.9, reflecting its critical nature and ease of remote exploitation without authentication.

## Recommendation

- Identify all Tenda AC5 devices within the environment, specifically those running firmware version 02.03.01.111_multi.
- Implement access control lists (ACLs) on the perimeter firewall to restrict access to the web management interface of identified Tenda devices from untrusted networks.
- Monitor network traffic logs for anomalous HTTP POST requests directed at '/goform/setWifi'.
- Monitor for firmware update availability from Tenda and apply patches to all vulnerable AC5 devices as soon as they are released.
