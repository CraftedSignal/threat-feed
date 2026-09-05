---
title: Remote Command Injection Vulnerability in Tenda CP3
slug: 2026-09-tenda-cp3-rce
description: An unauthenticated remote command injection vulnerability in Tenda CP3 firmware version 27.5.57.101 allows attackers to execute arbitrary system commands via the AlarmVoiceURL argument.
date: "2026-09-05T23:34:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:tenda:cp3:27.5.57.101:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - firmware-vulnerability
  - iot
vendors:
  - Tenda
products:
  - CP3 (27.5.57.101)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument AlarmVoiceURL results in os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-86148
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86148
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to Tenda CP3 management interfaces from external networks
      owner: IT Operations
      due: 24h
      evidence: Critical severity vulnerability in network-facing component
  mitigation_plan:
    - priority: immediate
      action: Remove affected cameras from direct public internet exposure
      owner: IT Operations
      addresses: CVE-2026-86148
      evidence: NVD vulnerability disclosure
---

A critical command injection vulnerability, identified as CVE-2026-86148, has been discovered in the Tenda CP3 security camera firmware version 27.5.57.101. The vulnerability resides in the SystemAsh function within the Apis/system.c file of the Kylin component. An attacker can exploit this flaw by sending a crafted HTTP request that includes malicious shell metacharacters within the AlarmVoiceURL argument. Successful exploitation allows an unauthenticated remote attacker to execute arbitrary operating system commands with the privileges of the underlying firmware process, potentially leading to a full system compromise. This is a network-exploitable vulnerability requiring no user interaction, posing a significant risk to affected devices exposed to the internet.

## Impact

The vulnerability allows full remote code execution on the Tenda CP3 device. If exploited, an attacker could gain persistent access, use the device as a pivot point for further network reconnaissance or lateral movement, intercept traffic, or incorporate the device into a botnet. Given the nature of security cameras, this could also lead to the exposure of sensitive video feeds and private user data.

## Recommendation

Prioritized actions for security teams managing Tenda CP3 devices:

- Audit network perimeter logs for HTTP requests directed at Tenda CP3 devices containing suspicious metacharacters (e.g., ;, |, &, $, `) in URI parameters or POST bodies.
- Isolate affected Tenda CP3 cameras from the public internet by placing them behind a firewall or VPN, ensuring management interfaces are not exposed.
- Contact the vendor for firmware updates addressing the SystemAsh function vulnerability; if no patch is available, restrict access to the device's web management interface to trusted internal IP addresses only.
