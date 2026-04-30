---
title: JetBrains YouTrack RCE via Sandbox Bypass (CVE-2026-33392)
slug: 2026-04-jetbrains-rce
description: A high privileged user can achieve remote code execution via sandbox bypass in JetBrains YouTrack before version 2025.3.131383, identified as CVE-2026-33392, potentially leading to complete system compromise.
date: "2026-04-17T08:16:17Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-33392
  - rce
  - jetbrains
  - youtrack
  - sandbox-bypass
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33392
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33392
  - https://www.jetbrains.com/privacy-security/issues-fixed/
rules:
  - title: Detect Potential YouTrack Sandbox Bypass Attempts
    description: Detects suspicious HTTP requests that may indicate an attempt to exploit a sandbox bypass vulnerability in JetBrains YouTrack.  Looks for potentially malicious characters and keywords commonly associated with code injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
  - title: Detect YouTrack Process Creation from Suspicious Web Paths
    description: Detects process creation events originating from common web server directories, potentially indicating code execution originating from a compromised YouTrack installation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-33392 describes a remote code execution (RCE) vulnerability affecting JetBrains YouTrack servers before version 2025.3.131383. This vulnerability allows a high privileged user to bypass the application's sandbox and execute arbitrary code on the underlying system. While the specific exploitation details are not provided in the source, successful exploitation would grant the attacker complete control over the YouTrack server and potentially the entire network. Given the potential for complete system compromise, organizations using affected versions of YouTrack should prioritize patching this vulnerability.

## Attack Chain

1.  Attacker authenticates to the YouTrack server with a high-privileged account.
2.  Attacker crafts a malicious payload designed to exploit the sandbox bypass. This payload leverages the improper neutralization of special elements used in a template engine (CWE-1336).
3.  The attacker injects the malicious payload into a vulnerable field or function within YouTrack, such as a custom workflow or template.
4.  The YouTrack server processes the malicious payload, failing to properly sanitize the input.
5.  The injected payload bypasses the intended security sandbox restrictions.
6.  Arbitrary code is executed on the YouTrack server, outside the intended sandbox environment.
7.  The attacker leverages the gained code execution to install a webshell or other persistent access mechanisms.
8.  The attacker uses the compromised YouTrack server as a pivot point to access other systems within the network, potentially leading to data exfiltration or further malicious activities.

## Impact

Successful exploitation of CVE-2026-33392 allows a high privileged user to execute arbitrary code on the YouTrack server. This can lead to complete system compromise, including data theft, modification, or destruction. The impact is especially significant for organizations that rely on YouTrack for critical project management and issue tracking, as a compromised server can disrupt operations, expose sensitive information, and damage reputation.

## Recommendation

*   Immediately upgrade JetBrains YouTrack to version 2025.3.131383 or later to patch CVE-2026-33392.
*   Implement the provided Sigma rule to detect potential exploitation attempts against YouTrack servers.
*   Review and restrict high-privilege user access within YouTrack to minimize the potential attack surface.
*   Monitor web server logs for suspicious activity, particularly requests containing unusual characters or patterns indicative of code injection attempts, to assist with detection of similar exploits.
