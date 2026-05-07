---
title: Notepad++ Vulnerability in Version 8.9.3 and Prior
slug: 2026-04-notepad-vuln
description: A vulnerability exists in Notepad++ version 8.9.3 and prior, prompting a security advisory and the release of version 8.9.4 to address the issue.
date: "2026-04-29T12:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - vulnerability
  - notepad++
  - patch
vendors:
  - Notepad++
products:
  - Notepad++ 8.9.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://cyber.gc.ca/en/alerts-advisories/notepad-security-advisory-av26-395
  - https://community.notepad-plus-plus.org/topic/27512/notepad-release-8-9-4
  - https://community.notepad-plus-plus.org/category/1/announcements
rules:
  - title: Detect Suspicious Notepad++ Child Processes
    description: Detects suspicious child processes spawned by Notepad++, which may indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Notepad++ Writing Executables
    description: Detects Notepad++ writing executable files, which may indicate malware creation or modification.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - windows
rules_count: 2
---

On April 26, 2026, Notepad++ released a security advisory to address a vulnerability affecting version 8.9.3 and prior. The advisory urges users and administrators to update to version 8.9.4. While the specific nature of the vulnerability is not detailed in the advisory, the update is considered necessary for maintaining system security. The advisory does not specify any active exploitation of the vulnerability, but users of affected versions should update promptly to mitigate potential risks.

## Attack Chain

1.  Attacker identifies a vulnerable Notepad++ instance running version 8.9.3 or earlier.
2.  Attacker crafts a malicious file or input designed to exploit the undisclosed vulnerability.
3.  User opens the malicious file or interacts with the crafted input within Notepad++.
4.  The vulnerability is triggered, potentially leading to arbitrary code execution.
5.  Attacker gains control of the Notepad++ process.
6.  Attacker leverages the compromised Notepad++ process to escalate privileges.
7.  Attacker uses the escalated privileges to execute further malicious actions on the system.
8.  Attacker achieves their objective, such as data exfiltration or system compromise.

## Impact

Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code, potentially leading to sensitive data compromise, system takeover, or further malicious activities on the affected machine. The impact scope is limited to systems running vulnerable versions of Notepad++. The specific number of affected users is unknown.

## Recommendation

*   Upgrade to Notepad++ version 8.9.4 or later as recommended in the [Notepad++ release 8.9.4](https://community.notepad-plus-plus.org/topic/27512/notepad-release-8-9-4).
*   Monitor process execution for unusual or suspicious activity originating from Notepad++ using process creation logs.
*   Deploy the Sigma rule `Detect Suspicious Notepad++ Child Processes` to identify potentially malicious child processes spawned by Notepad++.
