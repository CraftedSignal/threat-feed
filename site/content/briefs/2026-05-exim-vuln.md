---
title: Exim Internet Mailer Vulnerability (Versions 4.97 to 4.99.2)
slug: 2026-05-exim-vuln
description: A critical vulnerability exists in Exim Internet Mailer versions 4.97 to 4.99.2, requiring users and administrators to apply necessary updates.
date: "2026-05-13T15:04:34Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - exim
  - vulnerability
  - rce
vendors:
  - Exim
products:
  - Exim Internet Mailer (4.97 to 4.99.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://cyber.gc.ca/en/alerts-advisories/exim-security-advisory-av26-460
  - https://www.exim.org/static/doc/security/EXIM-Security-2026-05-01.1/EXIM-Security-2026-05-01.1.txt
  - https://www.exim.org/download.html
  - https://www.exim.org/
rules:
  - title: Detect Suspicious Exim Process Creation
    description: Detects suspicious process creation by the Exim mail transfer agent, potentially indicating exploitation of a vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Network Connection from Exim
    description: Detects unusual outbound network connections from the Exim process that might indicate command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

On May 12, 2026, Exim published a security advisory addressing a critical vulnerability within Exim Internet Mailer, specifically affecting versions 4.97 through 4.99.2. This vulnerability poses a significant risk to systems running these versions, potentially allowing unauthorized access or control. Administrators and users are strongly advised to review the Exim security advisory and apply the recommended updates promptly to mitigate potential exploitation. The Exim Internet Mailer is a widely used mail transfer agent (MTA) on Unix-like operating systems, making this a potentially widespread issue. Failure to address this vulnerability could lead to severe consequences, including data breaches, system compromise, and denial-of-service conditions.

## Attack Chain

1.  Attacker identifies a vulnerable Exim server running versions 4.97 to 4.99.2.
2.  Attacker crafts a malicious email or network request designed to exploit the specific vulnerability.
3.  The malicious input is sent to the Exim server via SMTP or other supported protocols.
4.  The Exim process parses the malicious input, triggering the vulnerability.
5.  The vulnerability allows the attacker to execute arbitrary code on the server.
6.  Attacker establishes a reverse shell or other form of remote access.
7.  Attacker escalates privileges to gain root or system-level access.
8.  Attacker installs malware, exfiltrates data, or performs other malicious activities.

## Impact

Successful exploitation of this vulnerability can lead to complete compromise of the Exim server. Depending on the server's role and network configuration, this could allow attackers to steal sensitive data, send spam, or pivot to other systems on the network. The vulnerability could impact a wide range of organizations using the affected Exim versions.

## Recommendation

*   Immediately update Exim Internet Mailer to a patched version as recommended by the Exim security advisory [https://www.exim.org/static/doc/security/EXIM-Security-2026-05-01.1/EXIM-Security-2026-05-01.1.txt].
*   Monitor Exim logs for suspicious activity that might indicate attempted exploitation of this vulnerability.
*   Implement network segmentation to limit the impact of a successful compromise.
