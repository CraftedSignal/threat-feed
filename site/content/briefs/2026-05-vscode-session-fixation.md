---
title: CVE-2026-41613 - Visual Studio Code Session Fixation Vulnerability
slug: 2026-05-vscode-session-fixation
description: CVE-2026-41613 is a session fixation vulnerability in Visual Studio Code that allows an unauthorized attacker to elevate privileges over a network.
date: "2026-05-12T18:53:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - session-fixation
  - privilege-escalation
  - vscode
vendors:
  - Microsoft
products:
  - Visual Studio Code
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-41613
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41613
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41613
rules:
  - title: Detect Suspicious VS Code Session Fixation
    description: Detects CVE-2026-41613 exploitation — attempts to fix a session ID in Visual Studio Code by monitoring suspicious HTTP requests setting cookies from untrusted domains.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
  - title: Detect VS Code OS Command Injection via Session
    description: Detects CVE-2026-41613 and related OS Command Injection (CWE-78) when a session is hijacked and used to trigger command execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-41613 is a session fixation vulnerability affecting Visual Studio Code. An attacker can exploit this vulnerability to potentially elevate their privileges over a network. The vulnerability exists due to improper session management within the application. The CVSS v3.1 base score is rated as 8.8 (High), indicating significant potential impact. Successful exploitation could allow an attacker to perform actions with the privileges of a legitimate user. Defenders should apply the relevant patches as provided by Microsoft to mitigate this risk.

## Attack Chain

1.  Attacker crafts a malicious link or redirects a user to a controlled domain.
2.  The user, while authenticated to Visual Studio Code, clicks the link or is redirected.
3.  The attacker's domain sets a specific session ID via a cookie.
4.  The user then accesses a legitimate Visual Studio Code resource, carrying the attacker-controlled session ID.
5.  The Visual Studio Code server accepts the attacker-controlled session ID, associating it with the legitimate user's account.
6.  The attacker uses the pre-set session ID to access the user's account within Visual Studio Code.
7.  The attacker can now perform actions within the Visual Studio Code environment with the elevated privileges of the legitimate user.

## Impact

Successful exploitation of CVE-2026-41613 allows an attacker to gain unauthorized access to a user's Visual Studio Code session, potentially leading to code exfiltration, unauthorized code modifications, or other malicious activities. The impact could be significant if the compromised user has elevated privileges within the development environment.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-41613 in Visual Studio Code (reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41613).
*   Implement the "Detect Suspicious VS Code Session Fixation" Sigma rule to monitor for malicious session activity.
*   Monitor web traffic for suspicious redirects or links that lead to untrusted domains setting session cookies.
