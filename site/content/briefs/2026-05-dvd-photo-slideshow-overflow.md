---
title: SocuSoft DVD Photo Slideshow Professional Stack-Based Buffer Overflow (CVE-2018-25373)
slug: 2026-05-dvd-photo-slideshow-overflow
description: SocuSoft DVD Photo Slideshow Professional 8.07 is vulnerable to a stack-based buffer overflow (CVE-2018-25373) in the registration name field, allowing local attackers to execute arbitrary code by exploiting structured exception handling.
date: "2026-05-26T14:15:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - code-execution
  - windows
vendors:
  - SocuSoft
products:
  - DVD Photo Slideshow Professional 8.07
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
cves:
  - id: CVE-2018-25373
    cvss: 8.4
    epss: 0.00013
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25373
  - http://www.dvd-photo-slideshow.com/
  - https://www.exploit-db.com/exploits/45346
  - https://www.vulncheck.com/advisories/dvd-photo-slideshow-professional-buffer-overflow-seh
rules:
  - title: Detect CVE-2018-25373 Exploitation - Suspicious Process Launched by DVDPhotoSlideshow
    description: Detects CVE-2018-25373 exploitation — Monitors for suspicious processes launched by DVDPhotoSlideshow.exe, indicating potential code execution via buffer overflow.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2018-25373 Attempt - DVDPhotoSlideshow Launching Uncommon System Binaries
    description: Detects CVE-2018-25373 potential exploitation — identifies instances where DVDPhotoSlideshow.exe launches unusual system binaries like cmd.exe, powershell.exe, wscript.exe, potentially indicating successful code execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

SocuSoft DVD Photo Slideshow Professional 8.07 is susceptible to a stack-based buffer overflow vulnerability, identified as CVE-2018-25373. This flaw resides within the registration name field and allows a local attacker to execute arbitrary code. The vulnerability can be exploited by leveraging structured exception handling (SEH) overwrite techniques. A malicious actor can craft a specially designed text file containing junk bytes, an overwritten SEH chain, and shellcode. This crafted payload can then be pasted into the Registration Name field via Help > Register to trigger code execution, thereby compromising the affected system. This vulnerability poses a significant risk, as it enables unauthorized code execution on a local machine.

## Attack Chain

1.  Attacker crafts a malicious text file containing a buffer overflow payload.
2.  The payload includes junk bytes to reach the SEH overwrite point.
3.  The payload contains an overwritten SEH chain pointing to attacker-controlled code.
4.  The payload contains shellcode designed to execute arbitrary commands.
5.  The attacker opens the SocuSoft DVD Photo Slideshow Professional application.
6.  The attacker navigates to Help > Register within the application.
7.  The attacker pastes the crafted text file contents into the Registration Name field.
8.  The application attempts to process the oversized input, triggering the buffer overflow and SEH overwrite, leading to the execution of the attacker's shellcode. The attacker achieves arbitrary code execution on the system.

## Impact

Successful exploitation of this vulnerability (CVE-2018-25373) allows a local attacker to execute arbitrary code within the context of the SocuSoft DVD Photo Slideshow Professional application. This could lead to complete system compromise, data theft, or installation of malware. Since the vulnerability is local, an attacker needs prior access to the system. The impact is high due to the potential for complete system compromise.

## Recommendation

*   Apply any available patches or updates from SocuSoft to address CVE-2018-25373 if they exist.
*   Monitor process creation events for unexpected processes launched by the `DVDPhotoSlideshow.exe` application using the provided Sigma rule.
*   Implement restrictions on pasting from the clipboard into applications, where possible, to mitigate the attack vector described.
