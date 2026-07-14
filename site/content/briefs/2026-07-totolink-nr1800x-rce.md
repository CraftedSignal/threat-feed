---
title: Critical Remote Code Execution in Totolink NR1800X Routers (CVE-2026-15701)
slug: 2026-07-totolink-nr1800x-rce
description: A critical stack-based buffer overflow vulnerability, CVE-2026-15701 (CVSS 9.8), in Totolink NR1800X firmware version 9.1.0u.6279_B20210910 allows remote attackers to execute arbitrary code by manipulating the 'Host' argument in the 'Form_Logout' function, with a public exploit available.
date: "2026-07-14T19:47:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer-overflow
  - remote-code-execution
  - firmware
  - router
  - vulnerability
vendors:
  - Totolink
products:
  - NR1800X 9.1.0u.6279_B20210910
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A weakness has been identified in Totolink NR1800X... The attack is possible to be carried out remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This manipulation of the argument Host causes stack-based buffer overflow. ... The exploit has been made available to the public and could be used for attacks.
    confidence_band: high
cves:
  - id: CVE-2026-15701
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15701
  - https://github.com/fu9-dotom/cve/issues/1
  - https://vuldb.com/cve/CVE-2026-15701
  - https://vuldb.com/submit/856136
  - https://vuldb.com/vuln/378248
  - https://vuldb.com/vuln/378248/cti
  - https://www.totolink.net/
iocs:
  - type: url
    value: https://github.com/fu9-dotom/cve/issues/1
  - type: url
    value: https://vuldb.com/cve/CVE-2026-15701
  - type: url
    value: https://vuldb.com/submit/856136
  - type: url
    value: https://vuldb.com/vuln/378248
  - type: url
    value: https://vuldb.com/vuln/378248/cti
ioc_counts:
  url: 5
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-15701, has been discovered in Totolink NR1800X router firmware version 9.1.0u.6279_B20210910. This flaw specifically affects the `Form_Logout` function within the `/formLogout.htm` file, part of the integrated lighttpd web server component. By crafting a malicious request that manipulates the `Host` argument, a remote, unauthenticated attacker can trigger a stack-based buffer overflow, leading to arbitrary code execution on the device. The vulnerability carries a CVSS v3.1 base score of 9.8 (Critical), indicating severe impact and ease of exploitation. A public exploit for this vulnerability has been made available, making affected devices immediate targets for compromise. Defenders must prioritize patching to prevent attackers from gaining full control over their network infrastructure.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable Totolink NR1800X router with firmware version 9.1.0u.6279_B20210910 exposed to the internet.
2. The attacker crafts a specially designed HTTP request, targeting the `/formLogout.htm` endpoint served by the lighttpd component on the device.
3. This malicious request includes a manipulated and oversized `Host` header argument, specifically crafted to exceed the buffer allocated for it in the `Form_Logout` function.
4. When the `Form_Logout` function attempts to process the oversized `Host` argument, a stack-based buffer overflow occurs.
5. The overflow allows the attacker to overwrite critical memory regions on the device's stack, enabling the injection and execution of arbitrary malicious code.
6. The attacker achieves remote code execution with high privileges on the router, establishing initial access to the device and potentially to the internal network segment.
7. With control over the router, the attacker can then perform various actions such as network reconnaissance, traffic manipulation, data exfiltration, or further lateral movement into the connected network.

## Impact

Successful exploitation of CVE-2026-15701 grants unauthenticated remote attackers full control over the vulnerable Totolink NR1800X router. This critical access can lead to severe consequences, including network compromise, data theft, or the use of the router as a pivot point for further attacks on internal networks. Attackers could redirect traffic, inject malicious content, or disable network services, causing significant operational disruption and data breaches. Given the critical CVSS score of 9.8 and the public availability of an exploit, organizations using affected devices face an immediate and severe risk of widespread compromise.

## Recommendation

* Immediately patch Totolink NR1800X routers to a fixed firmware version to address CVE-2026-15701.
* Block all network traffic originating from the IOCs listed in this brief at the firewall or network edge.
* Review network device logs for unusual HTTP requests to `/formLogout.htm` or abnormally long `Host` headers, particularly from external sources.
