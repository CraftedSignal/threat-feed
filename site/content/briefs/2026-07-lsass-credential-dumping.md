---
title: Potential Credential Dumping Activity via LSASS Process Access
slug: 2026-07-lsass-credential-dumping
description: Adversaries frequently target the Local Security Authority Subsystem Service (LSASS) process on Windows systems to dump credentials, employing tools like Mimikatz, NanoDump, or Procdump to extract sensitive authentication material for lateral movement and persistence.
date: "2026-07-03T14:20:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - post-exploitation
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The brief detects process access requests to the LSASS process with specific call trace calls and access masks. This behaviour is expressed by many credential dumping tools such as Mimikatz, NanoDump, Invoke-Mimikatz, Procdump.
    confidence_band: high
references:
  - https://web.archive.org/web/20230329170326/https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html
  - https://web.archive.org/web/20230208123920/https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.001/T1003.001.md
  - https://research.splunk.com/endpoint/windows_possible_credential_dumping/
rules:
  - title: Potential Credential Dumping Activity Via LSASS
    description: Detects process access requests to the LSASS process with specific call trace calls and access masks, indicative of credential dumping tools like Mimikatz or Procdump.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - s0002
    techniques:
      - T1003.001
    data_sources:
      - process_access
      - windows
rules_count: 1
---

Credential dumping from the Local Security Authority Subsystem Service (LSASS) is a critical post-exploitation technique widely utilized by adversaries to steal user credentials, often leading to significant compromises including lateral movement, privilege escalation, and data exfiltration. Attackers leverage various tools, such as Mimikatz, NanoDump, Invoke-Mimikatz, or even built-in Windows utilities like Task Manager or Procdump, to access the memory of the `lsass.exe` process. This memory contains sensitive authentication data, including NTLM hashes and Kerberos tickets, which can then be used in pass-the-hash or pass-the-ticket attacks. Detecting these attempts is crucial for identifying an adversary's presence on a compromised system and preventing further progression of an attack. The technique is a staple for many threat groups, from financially motivated cybercriminals to state-sponsored APTs.

## Attack Chain

1.  **Initial Compromise**: An adversary first gains initial access to a Windows system, typically through phishing, exploitation of a vulnerability, or other initial access vectors.
2.  **Execution of Dumping Tool**: The attacker executes a credential dumping tool (e.g., `mimikatz.exe`, `NanoDump.exe`, `procdump.exe`, or a PowerShell script like `Invoke-Mimikatz`).
3.  **Process Open Request**: The executed tool attempts to open the `lsass.exe` process to gain read access to its memory.
4.  **Granted Access Negotiation**: The tool requests specific memory access rights to `lsass.exe` (e.g., `0x1038` for `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`).
5.  **Memory Access and Dumping**: The tool uses specific system libraries and functions (e.g., `dbgcore.dll`, `dbghelp.dll`, `kernel32.dll`, `kernelbase.dll`, `ntdll.dll`) to access and dump the `lsass.exe` process memory.
6.  **Credential Extraction**: Sensitive information such as NTLM hashes, Kerberos tickets, or plaintext passwords are extracted from the dumped memory.
7.  **Post-Dumping Activity**: The adversary uses the harvested credentials for lateral movement within the network, privilege escalation, or maintaining persistence.

## Impact

Successful credential dumping from LSASS allows attackers to gain unauthorized access to other systems and services within an organization, escalating privileges and enabling widespread lateral movement. This can lead to a complete compromise of the domain, including access to sensitive data, intellectual property, or critical infrastructure. Organizations can face severe financial losses from data breaches, regulatory fines, operational disruption, and significant reputational damage. The average cost of a data breach can run into millions of dollars, with credential theft being a primary enabler of these breaches.

## Recommendation

*   Deploy the Sigma rule "Potential Credential Dumping Activity Via LSASS" to your SIEM to detect process access to `lsass.exe` with suspicious access masks and call traces.
*   Ensure Sysmon (specifically ProcessAccess events) is configured to capture `process_access` events for the `lsass.exe` process on all critical Windows endpoints.
*   Implement strong access controls and Least Privilege principles to limit the ability of non-administrative users and processes to open `lsass.exe` for memory read operations.
*   Regularly review `process_access` logs for suspicious activity targeting `lsass.exe`, especially from processes that are not standard system utilities or security software.
