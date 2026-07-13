---
title: OpenClaw Git Ext Transport Vulnerability Allows Unauthorized Code Execution (CVE-2026-62200)
slug: 2026-07-openclaw-git-ext-transport-rce
description: A critical vulnerability, CVE-2026-62200, in OpenClaw versions before 2026.6.1 allows a lower-trust caller to execute or persist unauthorized actions via the Git ext transport feature, potentially leading to remote code execution due to improper host exec environment filtering.
date: "2026-07-13T22:30:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - openclaw
  - git
vendors:
  - OpenClaw
products:
  - OpenClaw (before 2026.6.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a lower-trust caller or configured input path could execute or persist actions beyond the caller's intended authorization.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: a lower-trust caller or configured input path could execute or persist actions beyond the caller's intended authorization.
    confidence_band: high
cves:
  - id: CVE-2026-62200
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62200
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-9969-8g9h-rxwm
  - https://www.vulncheck.com/advisories/openclaw-authentication-bypass-via-git-ext-transport
---

OpenClaw versions before 2026.6.1 are affected by CVE-2026-62200, a critical vulnerability stemming from inadequate host exec environment filtering within its Git ext transport feature. This flaw, with a CVSS 3.1 base score of 8.8 (High), allows a lower-trust caller or a manipulated input path to execute or persist unauthorized actions. If the vulnerable feature is enabled and network-reachable, an attacker can bypass intended authorization boundaries, leading to arbitrary code execution on the underlying system. This poses a significant risk to organizations utilizing affected OpenClaw instances, as it could result in full system compromise, data exfiltration, or the establishment of persistent backdoors without the need for high-level authentication. Defenders should prioritize patching to prevent potential exploitation of this flaw.

## Attack Chain

1. **Initial Access**: A lower-trust caller, such as an authenticated but low-privileged user, or a controlled input path, gains access to the vulnerable OpenClaw instance.
2. **Exploitation of Vulnerability**: The attacker crafts and submits malicious input specifically designed to abuse the Git ext transport feature.
3. **Environment Filtering Bypass**: The crafted malicious input successfully bypasses the flawed host exec environment filtering mechanism within OpenClaw.
4. **Command Injection**: Due to the filtering bypass, the system misinterprets and processes the malicious input as legitimate commands.
5. **Unauthorized Execution**: The injected commands are executed on the host system, typically with the privileges of the OpenClaw application.
6. **Persistence Establishment (Optional)**: The attacker may leverage the newly gained execution primitive to establish persistence on the compromised system.
7. **Impact Achievement**: The attacker achieves their objective, which could include further system compromise, data exfiltration, or complete control over the affected system.

## Impact

Successful exploitation of CVE-2026-62200 could lead to unauthorized remote code execution on the server hosting the OpenClaw application. This level of access grants attackers the ability to compromise the entire system, leading to data theft, alteration, or destruction. Furthermore, attackers could establish persistent access, allowing them to maintain a foothold within the affected environment for future malicious activities, potentially impacting the confidentiality, integrity, and availability of critical systems and sensitive information. The vulnerability does not require high privileges for exploitation, expanding its potential reach.

## Recommendation

* Patch CVE-2026-62200 immediately by upgrading OpenClaw to version 2026.6.1 or later.
* Review access controls for OpenClaw instances to ensure only authorized and necessary personnel have access, reducing the exposure to lower-trust callers.
* Monitor OpenClaw server logs for unusual process creation or network activity that could indicate attempts to exploit the Git ext transport feature.
