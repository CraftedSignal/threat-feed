---
title: Shibby Tomato Router Firmware Stack-Based Buffer Overflow (CVE-2026-15548)
slug: 2026-07-shibby-tomato-overflow
description: A critical stack-based buffer overflow vulnerability (CVE-2026-15548) exists in Shibby Tomato router firmware versions up to 1.28.0000, specifically in the `sub_407220` function of the `/usr/sbin/httpd` component related to DNS List Rendering, allowing remote attackers to achieve high impact on confidentiality, integrity, and availability.
date: "2026-07-13T10:17:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - router
  - firmware
  - buffer-overflow
  - rce
  - CVE-2026-15548
vendors:
  - Shibby
products:
  - Tomato (All versions up to 1.28.0000)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A security vulnerability has been detected in Shibby Tomato up to 1.28.0000. ... The attack is possible to be carried out remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation leads to stack-based buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-15548
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15548
  - https://gitee.com/Fengyi-Wang/CVE/issues/IJTQ5R
  - https://vuldb.com/cve/CVE-2026-15548
  - https://vuldb.com/submit/855121
  - https://vuldb.com/vuln/377898
  - https://vuldb.com/vuln/377898/cti
---

A significant security vulnerability, identified as CVE-2026-15548, has been discovered in Shibby Tomato router firmware, affecting all versions up to and including 1.28.0000. This flaw resides within the `sub_407220` function of the `/usr/sbin/httpd` daemon, specifically impacting the DNS List Rendering component. The vulnerability is a stack-based buffer overflow, which can be remotely triggered by a malicious actor. Successful exploitation allows for the execution of arbitrary code, leading to complete compromise of the affected router. Given that the Shibby Tomato project is superseded by FreshTomato, users of the affected firmware are advised to migrate or upgrade immediately to mitigate this high-severity risk.

## Attack Chain

1. An attacker identifies a Shibby Tomato router running a vulnerable firmware version (up to 1.28.0000) that is accessible remotely via its HTTP management interface.
2. The attacker crafts a specially designed HTTP request targeting the vulnerable DNS List Rendering component, which is handled by the `/usr/sbin/httpd` process.
3. The crafted request contains an oversized or malformed input directed towards the `sub_407220` function.
4. When the `sub_407220` function processes this malicious input, it causes a stack-based buffer overflow within the `/usr/sbin/httpd` process.
5. The buffer overflow overwrites critical memory regions on the stack, allowing the attacker to inject and execute arbitrary code on the router.
6. Successful remote code execution grants the attacker full control over the compromised Shibby Tomato router, potentially enabling further network penetration or data manipulation.

## Impact

Successful exploitation of CVE-2026-15548 leads to remote code execution on the affected Shibby Tomato router. This gives attackers complete control over the device, potentially allowing them to modify router configurations, intercept network traffic, launch further attacks against internal networks, or use the device as a pivot point. The vulnerability has a CVSS v3.1 base score of 8.8 (High), indicating severe impacts on confidentiality, integrity, and availability. All users of Shibby Tomato firmware up to version 1.28.0000 are at risk. The project being superseded by FreshTomato highlights the need for immediate action from users.

## Recommendation

* **Patching/Migration**: Migrate immediately to FreshTomato firmware or a patched version if available, as Shibby Tomato is no longer maintained.
* **Network Segmentation**: Isolate router management interfaces on a dedicated management network, restricting access only to trusted administrative hosts.
* **Log Monitoring**: Review router web server logs for suspicious or malformed HTTP requests, especially those targeting DNS list functionalities.
