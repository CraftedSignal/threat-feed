---
title: Unauthenticated Backdoor in Zbtlink and MoreQuick Router Firmware
slug: 2026-08-zbtlink-backdoor
description: Multiple Zbtlink and MoreQuick router models contain an unauthenticated backdoor service, 'yunmgrd', which allows remote attackers to execute root commands and manipulate network traffic.
date: "2026-08-27T13:40:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Zbtlink
  - MoreQuick
products:
  - L3_V2_8 (3.0.0.4.528)
  - WE826-T2 (19.1101)
  - ZBT-7628 (1.0.0.2.007)
  - ZBT-ZBT7621 (1.0.0.3.001)
  - MQAC-7620 (1.0.0.2.000)
  - MQAC-7620A (1.0.0.2.000)
  - MQAP-7620 (1.0.0.2.000)
  - MQAP-7620A (1.0.0.2.000)
  - MQAP-7628 (1.0.0.2.000)
  - AP522 (1.0.0.2.014)
  - AP7628 (3.0.0.4.380)
  - HC5661A (3.0.0.4.380)
  - APG721B (19.0809)
  - HK300 (1.0.0.2.032)
  - MAP-N10 (1.0.0.2.044)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: An attacker can also ... open reverse SSH tunnels.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.002
    technique_name: 'Application Layer Protocol: File Transfer Protocols'
    evidence: ship a backdoor command-and-control implant (yunmgrd) reachable over an unauthenticated cleartext UDP channel to a hardcoded C2 server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
    evidence: An attacker ... can hijack the channel and execute arbitrary commands as root.
    confidence_band: high
cves:
  - id: CVE-2026-74232
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74232
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Inventory Zbtlink and MoreQuick router hardware
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-74232 affects multiple specific firmware models.
---

Security researchers have identified a critical vulnerability, CVE-2026-74232, affecting a wide range of Zbtlink and MoreQuick router models. The affected devices ship with a persistent backdoor service known as 'yunmgrd'. This service listens on an unauthenticated, cleartext UDP channel and communicates with a hardcoded command-and-control (C2) server. 

An attacker positioned on the network path can intercept or hijack these UDP communications to issue unauthorized commands, gaining remote code execution (RCE) with root privileges on the device. Once root access is achieved, attackers can perform full device control, including exfiltration of sensitive PPPoE credentials, hijacking of DNS entries for redirection purposes, and the establishment of persistent reverse SSH tunnels. Given the lack of authentication and the use of cleartext protocols, this vulnerability represents a significant risk for the confidentiality and integrity of network traffic passing through these devices.

## Impact

The vulnerability allows full administrative control over the affected routers. Successful exploitation enables attackers to gain persistence, steal sensitive network authentication credentials, perform man-in-the-middle attacks via DNS manipulation, and pivot deeper into the local network through reverse SSH tunnels. This affects multiple residential and small-business router models from Zbtlink and MoreQuick, impacting users across diverse sectors.

## Recommendation

- Perform an inventory of all router hardware to identify the specific models and firmware versions listed in the affected products section.
- Isolate any identified vulnerable hardware from internet-facing segments until the vendor provides patched firmware.
- Implement egress filtering at the network perimeter to block unauthorized UDP traffic to unknown destinations if specific C2 infrastructure IPs are identified in future intelligence.
- Monitor network logs for unusual UDP traffic patterns originating from or destined to router management interfaces.
