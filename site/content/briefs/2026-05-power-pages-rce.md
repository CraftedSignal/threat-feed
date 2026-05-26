---
title: CVE-2026-23652 - Microsoft Power Pages Command Injection
slug: 2026-05-power-pages-rce
description: CVE-2026-23652 is a critical command injection vulnerability in Microsoft Power Pages, allowing an unauthorized attacker to execute arbitrary code over the network by injecting commands.
date: "2026-05-26T13:52:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - command injection
  - remote code execution
  - microsoft
vendors:
  - Microsoft
products:
  - Power Pages
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-23652
    cvss: 10
    epss: 0.00075
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23652
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-23652
rules:
  - title: Detect CVE-2026-23652 Exploitation Attempt via Command Injection
    description: Detects CVE-2026-23652 exploitation attempt — suspicious HTTP request containing shell metacharacters in the query string
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-23652 Exploitation Attempt via POST Request
    description: Detects CVE-2026-23652 exploitation attempt — suspicious HTTP POST request containing shell metacharacters
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-23652 describes a command injection vulnerability affecting Microsoft Power Pages. This flaw allows an unauthenticated, remote attacker to execute arbitrary code on the system by injecting malicious commands into the application. The vulnerability stems from improper neutralization of special elements used within a command. Successful exploitation results in full compromise of the Power Pages instance. Defenders should apply available patches immediately.

## Attack Chain

1.  The attacker identifies a vulnerable Microsoft Power Pages instance exposed to the network.
2.  The attacker crafts a malicious HTTP request containing a command injection payload within a user-supplied input field.
3.  The Power Pages application fails to properly sanitize the input, passing the attacker-controlled data to a system command.
4.  The injected command is executed by the underlying operating system with the privileges of the Power Pages application.
5.  The attacker leverages the command execution to establish a reverse shell to an attacker-controlled server.
6.  The attacker uses the reverse shell to gain interactive access to the compromised server.
7.  The attacker performs reconnaissance to discover sensitive data and credentials.
8.  The attacker uses the gained access to pivot to other systems on the network and potentially exfiltrate sensitive information or cause further damage.

## Impact

Successful exploitation of CVE-2026-23652 can lead to complete compromise of the affected Microsoft Power Pages instance. This can result in unauthorized access to sensitive data, modification of website content, and potential lateral movement to other systems on the network. Given the critical severity and ease of exploitation (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H), organizations using Power Pages are at high risk.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-23652 on all Power Pages instances immediately, as referenced in the advisory URL.
*   Implement input validation and sanitization measures to prevent command injection attacks, particularly in user-supplied input fields in Power Pages.
*   Deploy the Sigma rule "Detect CVE-2026-23652 Exploitation Attempt via Command Injection" to monitor for exploitation attempts.
*   Monitor web server logs for suspicious HTTP requests containing shell metacharacters.
