---
title: Command Injection Vulnerability in Tenda Smart Camera ATE Module
slug: 2026-08-tenda-rce
description: Multiple Tenda smart camera models are susceptible to unauthenticated remote command injection via the 'CAte::HandleCmd' function, allowing attackers to execute arbitrary system commands.
date: "2026-08-13T22:04:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Tenda
products:
  - CH7
  - CH7G
  - CH10
  - CP3
  - CP3 Pro
  - CP7
  - TC3B14C
  - TC3B15C
  - TC3T14C
  - TC3T15C
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This manipulation causes command injection.
    confidence_band: high
cves:
  - id: CVE-2026-19747
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19747
  - https://vuldb.com/vuln/389498
  - https://github.com/howitouchyou/Tenda-Smart-Camera-Vulnerability/blob/main/Tenda%20Command%20Injection/Tenda%20Command%20Injection.md
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory and isolate vulnerable Tenda smart cameras from direct internet exposure.
      owner: IT Operations
      due: 24h
      evidence: Critical severity CVSS score indicates potential for widespread exploitation.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor firmware updates once available and enforce network-level segmentation.
      owner: IT Operations
      addresses: CVE-2026-19747
      evidence: NVD vulnerability entry.
---

A critical command injection vulnerability (CVE-2026-19747) has been identified in the ATE module of several Tenda smart camera models, including the CH7, CH7G, CH10, CP3, CP3 Pro, CP7, and various TC3-series variants. The flaw exists within the 'CAte::HandleCmd' function contained in the 'Kylin' file. By sending specially crafted requests, a remote, unauthenticated attacker can trigger this vulnerability to execute arbitrary system commands on the targeted device. Affected firmware versions include all builds up to 20260625. This vulnerability is particularly concerning due to its remote, unauthenticated nature and the high likelihood of resulting in full device compromise, potentially enabling attackers to pivot into the local network or integrate the cameras into botnets.

## Attack Chain

1. Attacker performs network reconnaissance to identify accessible Tenda smart camera interfaces.
2. Attacker probes the device's web or command-handling API to target the ATE module.
3. Attacker crafts a malicious request string containing shell metacharacters intended for the 'CAte::HandleCmd' function.
4. Attacker transmits the crafted request to the camera's network port.
5. The 'Kylin' component processes the input without sufficient sanitization of the input parameters.
6. The underlying system shell interprets and executes the injected malicious commands.
7. Attacker achieves command execution with system-level privileges on the camera.
8. Attacker establishes persistent access or exfiltrates device configuration data.

## Impact

Successful exploitation allows for full control of the affected smart camera, potentially enabling the use of the device for unauthorized surveillance, lateral movement within the network, or participation in distributed denial-of-service (DDoS) campaigns. Given the ubiquity of these devices in home and small office environments, the exposure of these credentials or local network access presents a significant security risk to end users.

## Recommendation

* Identify and inventory all Tenda camera models listed in the affected products section within the local network.
* Restrict network access to these camera interfaces to trusted management subnets to prevent remote exploitation from the internet.
* Contact Tenda for firmware updates that address the 'CAte::HandleCmd' command injection vulnerability and apply them immediately.
* Monitor perimeter and internal network logs for abnormal HTTP or API traffic directed at Tenda devices, specifically looking for unusual shell syntax in request parameters.
