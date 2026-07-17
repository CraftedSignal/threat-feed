---
title: OpenClaw Vulnerability Allows Untrusted Workspace Plugin Loading (CVE-2026-62222)
slug: 2026-07-openclaw-untrusted-plugin-loading
description: A vulnerability, CVE-2026-62222, exists in OpenClaw versions prior to 2026.5.22, where an attacker with lower-trust caller access or control over configured input paths can exploit a flaw in the setup-mode discovery to load untrusted workspace plugins, leading to arbitrary code execution, persistence, and privilege escalation.
date: "2026-07-17T02:30:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - privilege-escalation
  - persistence
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.5.22)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers with lower-trust caller access or control over configured input paths can execute or persist actions beyond their intended authorization level.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Attackers with lower-trust caller access or control over configured input paths can execute or persist actions beyond their intended authorization level.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can execute or persist actions beyond their intended authorization level.
    confidence_band: high
cves:
  - id: CVE-2026-62222
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62222
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-rh6r-vvfc-86jq
  - https://www.vulncheck.com/advisories/openclaw-untrusted-plugin-loading-via-setup-mode
iocs:
  - type: url
    value: https://github.com/openclaw/openclaw/security/advisories/GHSA-rh6r-vvfc-86jq
  - type: url
    value: https://www.vulncheck.com/advisories/openclaw-untrusted-plugin-loading-via-setup-mode
ioc_counts:
  url: 2
---

OpenClaw versions before 2026.5.22 are affected by CVE-2026-62222, a high-severity vulnerability (CVSS v3.1 Base Score 7.8) residing in the application's setup-mode discovery mechanism. This flaw enables the loading of untrusted workspace plugins. Attackers who have either lower-trust caller access to the OpenClaw environment or can control configured input paths can exploit this vulnerability. Successful exploitation allows the attacker to execute arbitrary code, establish persistence on the affected system, and escalate privileges beyond their intended authorization level. The vulnerability, first published by NVD on July 17, 2026, impacts organizations using vulnerable OpenClaw installations, potentially exposing their systems to full compromise through arbitrary code execution.

## Attack Chain

1. An attacker gains lower-trust caller access to the OpenClaw environment or successfully controls specific input paths configured for OpenClaw.
2. The attacker crafts a malicious workspace plugin designed to perform unauthorized actions (e.g., execute code, establish persistence).
3. The attacker then places the malicious plugin in a controlled input path or leverages their existing lower-trust access to trigger its loading during OpenClaw's setup-mode discovery.
4. Due to the vulnerability (CVE-2026-62222), OpenClaw fails to properly validate the plugin during its setup-mode discovery and loads the untrusted malicious workspace plugin.
5. The malicious plugin executes within the context of the OpenClaw application, allowing the attacker to perform actions beyond their authorized level.
6. This unauthorized execution can lead to arbitrary code execution, enabling the attacker to run commands on the underlying system.
7. The attacker can use this capability to establish persistence mechanisms, ensuring continued access to the system.
8. Ultimately, the attacker can leverage the executed code to escalate privileges within the system, potentially gaining full control.

## Impact

The successful exploitation of CVE-2026-62222 can lead to severe consequences for organizations utilizing vulnerable OpenClaw instances. Attackers can achieve arbitrary code execution, allowing them to take complete control of the affected system. This includes the ability to install additional malware, exfiltrate sensitive data, disrupt operations, or use the compromised system as a pivot point for further network intrusion. While no specific victim counts or targeted sectors are detailed in the advisory, any organization using OpenClaw software in an environment where attackers could control input paths or gain lower-trust access faces a significant risk of compromise.

## Recommendation

* Patch CVE-2026-62222 immediately by upgrading OpenClaw to version 2026.5.22 or later.
* Review access controls for OpenClaw's configured input paths to ensure only trusted users and processes can modify them.
* Monitor system logs for unusual process creation or network connections originating from the OpenClaw application, which could indicate exploitation of CVE-2026-62222.
