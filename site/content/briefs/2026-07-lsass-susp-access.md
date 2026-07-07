---
title: Detecting Suspicious GrantedAccess Flags on LSASS
slug: 2026-07-lsass-susp-access
description: This brief details a detection for potentially suspicious `GrantedAccess` flags when a process attempts to access `LSASS.exe`, indicating possible credential dumping attempts by adversaries, which can lead to lateral movement and privilege escalation on Windows systems.
date: "2026-07-03T14:21:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-dumping
  - windows
  - post-exploitation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Detects process access requests to LSASS process with potentially suspicious access flags, commonly used to dump credentials from LSASS memory.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries often use command and scripting interpreters to launch tools that access LSASS.
    confidence_band: med
references:
  - https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
  - https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow
  - https://web.archive.org/web/20230208123920/https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
  - https://web.archive.org/web/20230420013146/http://security-research.dyndns.org/pub/slides/FIRST2017/FIRST-2017_Tom-Ueltschi_Sysmon_FINAL_notes.pdf
rules:
  - title: Detect Potentially Suspicious GrantedAccess Flags on LSASS
    description: Detects attempts to access the Local Security Authority Subsystem Service (LSASS) process with specific, potentially suspicious GrantedAccess flags often associated with credential dumping tools like Mimikatz or custom memory readers.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - s0002
    techniques:
      - T1003.001
    data_sources:
      - process_access
      - windows
rules_count: 1
---

This threat brief focuses on a critical post-exploitation technique used by various adversaries: credential dumping from the Local Security Authority Subsystem Service (LSASS) process. Published by SigmaHQ, this detection rule identifies attempts to open `LSASS.exe` with specific, often excessive, `GrantedAccess` flags. While not tied to a single threat actor or campaign, this behavior is a hallmark of tools like Mimikatz, Lazagne, or custom credential dumpers. Successfully obtaining credentials from LSASS allows attackers to move laterally across a network, escalate privileges, and maintain persistence. Detection engineers should implement robust logging for process access events to identify these suspicious interactions and mitigate potential compromise. This technique is frequently observed in ransomware campaigns, espionage operations, and financially motivated attacks, making its detection vital for Windows endpoint security.

## Attack Chain

1.  **Initial Access**: Adversary gains initial access to a target system via various methods (e.g., phishing, exploiting a vulnerable service, weak credentials).
2.  **Execution**: Malicious code (e.g., malware dropper, attacker-controlled script) is executed on the compromised system.
3.  **Privilege Escalation**: If necessary, the attacker elevates privileges to a level that allows interaction with critical system processes like LSASS.
4.  **Process Access Attempt**: An attacker-controlled process attempts to open the `lsass.exe` process with specific, often excessive, `GrantedAccess` rights for reading its memory.
5.  **Credential Dumping**: The attacker's process reads the memory of `LSASS` to extract sensitive authentication material, such as NTLM hashes, Kerberos tickets, or plaintext passwords.
6.  **Lateral Movement & Impact**: Stolen credentials are used to authenticate to other systems, facilitating lateral movement within the network or enabling further actions like data exfiltration or ransomware deployment.

## Impact

Credential dumping from LSASS is a severe security event. If successful, attackers can obtain sensitive authentication material (e.g., NTLM hashes, Kerberos tickets) for legitimate user accounts, including administrative credentials. This enables seamless lateral movement within the network, allowing adversaries to access other systems and resources without needing to crack passwords. The impact can range from complete domain compromise to widespread data exfiltration or the deployment of ransomware across the enterprise. Organizations in all sectors are targeted by this technique, as credentials are a universal key to system access, leading to significant financial losses, data breaches, and operational disruption.

## Recommendation

*   Enable Sysmon Event ID 10 (ProcessAccess) logging on all Windows endpoints to capture detailed information about processes accessing other processes.
*   Deploy the "Detect Potentially Suspicious GrantedAccess Flags on LSASS" Sigma rule to your SIEM/EDR platform and tune it for your environment.
*   Review and tune the `falsepositives` section of the Sigma rule with specific exclusions for known legitimate security products (e.g., EDR, AV, PAM) that may legitimately access LSASS.
*   Investigate all high-severity alerts generated by the "Detect Potentially Suspicious GrantedAccess Flags on LSASS" rule for potential credential dumping activity.
