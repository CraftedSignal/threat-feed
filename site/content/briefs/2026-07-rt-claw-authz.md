---
title: 'CVE-2026-16200: Remote Authorization Bypass in zevorn rt-claw'
slug: 2026-07-rt-claw-authz
description: A high-severity remote authorization bypass vulnerability (CVE-2026-16200) has been identified in zevorn rt-claw versions up to 0.2.0, specifically within the RPC Handler's claw_tool_invoke function, allowing remote exploitation with a public exploit.
date: "2026-07-19T01:17:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authorization-bypass
vendors:
  - zevorn
products:
  - rt-claw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The manipulation leads to incorrect authorization. Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-16200
    cvss: 7.3
references:
  - https://github.com/zevorn/rt-claw/
  - https://github.com/zevorn/rt-claw/issues/133
  - https://vuldb.com/cve/CVE-2026-16200
  - https://vuldb.com/submit/857622
  - https://vuldb.com/vuln/380016
  - https://vuldb.com/vuln/380016/cti
---

A high-severity authorization bypass vulnerability, tracked as CVE-2026-16200, affects zevorn rt-claw software versions up to 0.2.0. The flaw resides within the `claw_tool_invoke` function, part of the RPC Handler component (located in `claw/services/swarm/swarm.c`), allowing an attacker to perform unauthorized actions. Remote exploitation of this vulnerability is possible, and an exploit has reportedly been disclosed to the public. This means the flaw can be leveraged by attackers without requiring direct access to the system. While the project was notified of the issue via an issue report, as of July 19, 2026, no patch or response has been provided, leaving affected systems exposed to potential exploitation. Defenders should prioritize patching this vulnerability once an update becomes available.

## Attack Chain

1. **Reconnaissance**: An attacker identifies publicly exposed zevorn rt-claw instances running vulnerable versions (up to 0.2.0) on the network.
2. **Vulnerability Identification**: The attacker correlates the identified instance with the known CVE-2026-16200 vulnerability affecting the RPC Handler.
3. **Exploit Crafting**: Leveraging the publicly disclosed exploit details, the attacker crafts a malicious RPC request specifically designed to target the `claw_tool_invoke` function.
4. **Authorization Bypass**: The crafted RPC request is sent to the vulnerable zevorn rt-claw instance. The inherent flaw in the `claw_tool_invoke` function's authorization logic allows this request to bypass normal security checks.
5. **Unauthorized Execution**: The `claw_tool_invoke` function processes the attacker's request, executing commands or operations that the attacker would not normally be authorized to perform.
6. **Impact Realization**: This leads to unauthorized access, modification, or disclosure of sensitive information, or potentially other forms of system compromise, depending on the specific functionality exposed through the `claw_tool_invoke` function.

## Impact

The successful exploitation of CVE-2026-16200 can lead to severe consequences due to the unauthorized actions an attacker can perform. Given that the vulnerability allows for incorrect authorization within the RPC Handler, attackers could gain unauthorized access to critical functionalities, manipulate system settings, or exfiltrate sensitive data without proper authentication. The public disclosure of an exploit significantly increases the risk, as it lowers the barrier for less sophisticated attackers to leverage this flaw. Organizations using vulnerable versions of zevorn rt-claw face a high risk of system compromise, data breaches, and operational disruption until a patch is released and applied.

## Recommendation

* **Patch CVE-2026-16200** immediately once a fix is made available by the vendor to prevent remote authorization bypass.
* **Monitor external network traffic** for unusual RPC activity directed towards zevorn rt-claw instances, as the RPC Handler is the affected component.
* **Implement strict network segmentation** to limit exposure of zevorn rt-claw instances, especially preventing their direct exposure to the internet.
