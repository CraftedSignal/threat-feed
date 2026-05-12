---
title: 'CVE-2026-42893: M365 Copilot Command Injection Vulnerability'
slug: 2026-05-m365-copilot-cmd-injection
description: CVE-2026-42893 is a command injection vulnerability in M365 Copilot that allows an unauthorized attacker to perform tampering over a network.
date: "2026-05-12T18:53:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - cve
  - m365
  - copilot
vendors:
  - Microsoft
products:
  - M365 Copilot
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-42893
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42893
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42893
rules:
  - title: Detect M365 Copilot Command Injection Attempts
    description: Detects CVE-2026-42893 exploitation — Suspicious HTTP requests indicative of command injection attempts in M365 Copilot
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-42893 is a command injection vulnerability affecting M365 Copilot. This vulnerability allows an unauthorized attacker to perform tampering over a network. The vulnerability stems from improper neutralization of special elements used in a command. Successful exploitation could allow attackers to execute arbitrary commands, potentially leading to data modification or system compromise within the M365 Copilot environment. Microsoft has acknowledged the vulnerability.

## Attack Chain

1.  Attacker identifies an endpoint within M365 Copilot that processes user-supplied input without proper sanitization.
2.  The attacker crafts a malicious input string containing command injection payloads, such as shell metacharacters (e.g., ;, |, &, $, >, <, `).
3.  The attacker sends the crafted input to the vulnerable endpoint via a network request.
4.  M365 Copilot processes the input and attempts to execute it as a system command.
5.  The command injection payload is interpreted by the underlying operating system, allowing the attacker to execute arbitrary commands.
6.  The attacker leverages the command execution to modify data, escalate privileges, or perform other malicious actions within the M365 Copilot environment.

## Impact

Successful exploitation of CVE-2026-42893 allows an attacker to perform unauthorized tampering within the M365 Copilot environment. The vulnerability allows the attacker to perform unauthorized actions, modify or delete critical data, and potentially gain further access to other systems on the network.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-42893 on all affected M365 Copilot instances; reference the URL in the References section for the update.
*   Deploy the Sigma rule `Detect M365 Copilot Command Injection Attempts` to your SIEM to detect potential exploitation attempts.
*   Monitor web server logs for suspicious requests containing command injection payloads, as described in the Attack Chain.
