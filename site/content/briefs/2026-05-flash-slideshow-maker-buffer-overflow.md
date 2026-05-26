---
title: Flash Slideshow Maker Professional 5.20 Buffer Overflow Vulnerability (CVE-2018-25377)
slug: 2026-05-flash-slideshow-maker-buffer-overflow
description: Flash Slideshow Maker Professional 5.20 is vulnerable to a buffer overflow in the registration dialog, allowing local attackers to execute arbitrary code with system privileges by exploiting structured exception handling and crafting a malicious payload for the Name and Code fields.
date: "2026-05-26T14:16:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - privilege-escalation
  - execution
products:
  - Flash Slideshow Maker Professional 5.20
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2018-25377
    cvss: 8.4
    epss: 0.00013
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25377
  - http://flash.dvd-photo-slideshow.com/
  - https://www.exploit-db.com/exploits/45355
  - https://www.vulncheck.com/advisories/flash-slideshow-maker-professional-buffer-overflow-seh
rules:
  - title: Detects CVE-2018-25377 Exploitation Attempt — Suspicious Child Process of Flash Slideshow Maker
    description: Detects CVE-2018-25377 exploitation attempt — Monitors for the creation of suspicious child processes from Flash Slideshow Maker Professional, indicating potential code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2018-25377 Exploitation Attempt — Suspicious Outbound Network Connection from Flash Slideshow Maker
    description: Detects CVE-2018-25377 exploitation attempt — Monitors for outbound network connections from Flash Slideshow Maker Professional, which is not expected behavior.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Flash Slideshow Maker Professional version 5.20 is susceptible to a buffer overflow vulnerability (CVE-2018-25377) within its registration process. This flaw enables a local attacker to execute arbitrary code with elevated system privileges. The vulnerability is triggered via a crafted payload pasted into the "Name" and "Code" fields within the "Help > Register" dialog. Successful exploitation leads to a reverse shell with system privileges, posing a significant risk to affected systems. The advisory was published in May 2026, though the underlying software flaw dates back to 2018.

## Attack Chain

1.  The attacker gains local access to a system with Flash Slideshow Maker Professional 5.20 installed.
2.  The attacker crafts a malicious payload designed to exploit a buffer overflow when processed by the application.
3.  The attacker opens the Flash Slideshow Maker Professional application.
4.  The attacker navigates to the "Help > Register" dialog within the application.
5.  The attacker pastes the crafted malicious payload into the "Name" and "Code" fields of the registration dialog.
6.  The attacker triggers the registration process, causing the application to process the malicious payload without proper size validation.
7.  The buffer overflow occurs, overwriting memory and hijacking control flow via structured exception handling (SEH).
8.  The attacker gains a reverse shell with system privileges on the compromised system.

## Impact

Successful exploitation of this buffer overflow vulnerability (CVE-2018-25377) allows a local attacker to execute arbitrary code with system-level privileges. This grants the attacker full control over the affected system, enabling them to install malware, steal sensitive data, or perform other malicious activities. This vulnerability poses a significant risk to any system running the affected version of Flash Slideshow Maker Professional 5.20.

## Recommendation

*   Apply appropriate input validation to the Name and Code fields.
*   Monitor process creations for suspicious child processes of Flash Slideshow Maker Professional using the process creation rule below.
*   Monitor for unexpected network connections originating from the Flash Slideshow Maker Professional process using the network connection rule below.
