---
title: Critical Vulnerabilities in Xiiaozet LK100W
slug: 2026-08-xiiaozet-lk100w
description: Xiiaozet LK100W devices running firmware prior to v2.1.240 are vulnerable to multiple high-severity flaws, including OS command injection and authentication bypass, which could allow remote attackers to achieve full device compromise.
date: "2026-08-27T16:06:09Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - ics
  - cve
  - rce
  - authentication-bypass
vendors:
  - Xiiaozet
products:
  - LK100W
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Xiiaozet LK100W is vulnerable to OS command injection through its web-based management interface.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An authenticated attacker may be able to execute arbitrary operating system commands with elevated privileges.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-239-01
  - https://www.cve.org/CVERecord?id=CVE-2026-78037
  - https://www.cve.org/CVERecord?id=CVE-2026-78239
  - https://www.cve.org/CVERecord?id=CVE-2026-76943
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all Xiiaozet LK100W devices to v2.1.240
      owner: IT Operations
      due: 24h
      evidence: Xiiaozet recommends users update to v2.1.240.
  mitigation_plan:
    - priority: immediate
      action: Isolate management interfaces from the internet
      owner: IT Operations
      addresses: CVE-2026-78037, CVE-2026-78239, CVE-2026-76943
      evidence: Minimize network exposure for all control system devices and/or systems, ensuring they are not accessible from the internet.
---

Xiiaozet LK100W devices running firmware versions earlier than 2.1.240 are affected by a suite of critical vulnerabilities (CVE-2026-78037, CVE-2026-78239, CVE-2026-76943). These vulnerabilities collectively allow for authentication bypass, unauthorized invocation of critical management functions, and OS command injection via the web-based management interface. An attacker can leverage these flaws to execute arbitrary operating system commands with elevated privileges, potentially resulting in complete device takeover. These devices are used in Information Technology infrastructure globally. There is currently no report of active exploitation in the wild, but the high CVSS scores and the nature of the vulnerabilities - specifically the ability for unauthenticated remote code execution - pose a significant risk to affected organizations.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to achieve full device compromise, potentially enabling data exfiltration, lateral movement within the network, or the ability to disrupt critical IT operations. The vulnerabilities affect Xiiaozet LK100W devices deployed globally, placing Information Technology infrastructure at risk. If exploited, an attacker could gain persistent access to the management environment, undermining the integrity and confidentiality of the entire device.

## Recommendation

- Upgrade all Xiiaozet LK100W devices to firmware version 2.1.240 immediately to address CVE-2026-78037, CVE-2026-78239, and CVE-2026-76943.
- Restrict network access to the web-based management interface of all Xiiaozet LK100W devices, ensuring they are not exposed directly to the internet.
- Isolate control system networks containing these devices behind firewalls and ensure only authorized personnel can access the management interfaces via secure methods such as VPNs.
- Implement monitoring on network egress and ingress traffic to identify unusual activity originating from or directed toward these devices, especially focusing on unauthorized HTTP requests to management endpoints.
