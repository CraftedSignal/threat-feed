---
title: Remote Command Injection in GL.iNet Router Firewall RPC
slug: 2026-08-glinet-rce
description: An OS command injection vulnerability in the Firewall-management RPC component of GL.iNet BE9300 and MT6000 routers allows remote, unauthenticated attackers to execute arbitrary system commands via crafted network parameters.
date: "2026-08-17T08:44:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - firewall
  - networking
  - cve
vendors:
  - GL.iNet
products:
  - BE9300 (4.8.x)
  - MT6000 (4.8.x)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument dest_port/dest_ip leads to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-19982
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19982
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade affected GL.iNet firmware to 4.9.0 to mitigate CVE-2026-19982
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 4.9.0 is able to resolve this issue.
  mitigation_plan:
    - priority: immediate
      action: Restrict remote access to router management RPC interfaces
      owner: IT Operations
      addresses: CVE-2026-19982
      evidence: The attack may be initiated remotely.
---

Researchers have identified a critical security vulnerability (CVE-2026-19982) affecting GL.iNet BE9300 and MT6000 series routers running firmware version 4.8.x. The flaw exists within the Firewall-management Remote Procedure Call (RPC) component. An unauthenticated remote attacker can exploit this by sending specially crafted requests containing malicious input in the 'dest_port' or 'dest_ip' arguments. This manipulation leads to OS command injection, granting the attacker the ability to execute arbitrary code with the privileges of the underlying firmware process. GL.iNet has confirmed the vulnerability and released firmware version 4.9.0 to address the flaw. Defenders should prioritize updating internet-facing devices and restricting management interface access to trusted networks.

## Impact

Successful exploitation allows for full system compromise of the affected router, potentially leading to unauthorized network access, data exfiltration, or the establishment of persistent backdoors within the user's network environment. The vulnerability impacts specific high-performance router models commonly deployed in enterprise and small office environments.

## Recommendation

* Immediately upgrade all GL.iNet BE9300 and MT6000 devices to firmware version 4.9.0.
* Restrict access to the router management interface (RPC/Web UI) to authorized, internal IP addresses only.
* Monitor firewall logs for anomalous RPC requests containing shell metacharacters (e.g., ;, |, &, $, `) within the 'dest_port' or 'dest_ip' parameter fields.
