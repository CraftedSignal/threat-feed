---
title: Potential Credential Access via LSASS Memory Dump
slug: 2024-01-lsass-memory-dump
description: This rule detects suspicious access to the LSASS process, indicative of an attempt to dump LSASS memory for credential access by monitoring process access events with call traces including dbgcore.dll or dbghelp.dll, which export MiniDumpWriteDump, while excluding known crash handlers.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - threat-detection
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
  - https://www.elastic.co/security-labs/detect-credential-access
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
rules:
  - title: Potential Credential Access via LSASS Memory Dump using dbgcore
    description: Detects suspicious access to LSASS handle from a call trace pointing to DBGCore.dll, indicating a potential LSASS memory dump.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
  - title: Potential Credential Access via LSASS Memory Dump using dbghelp
    description: Detects suspicious access to LSASS handle from a call trace pointing to DBGHelp.dll, indicating a potential LSASS memory dump.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies suspicious attempts to dump the LSASS (Local Security Authority Subsystem Service) memory, a common technique used by attackers to gain access to credentials stored in memory. The rule focuses on process access events where the call trace includes either `dbgcore.dll` or `dbghelp.dll`, both of which export the `MiniDumpWriteDump` method. This method is frequently leveraged by attackers to create a memory dump of the LSASS process, which can then be analyzed offline to extract sensitive information such as usernames, passwords, and Kerberos tickets. The rule excludes legitimate system processes such as `WerFault.exe` to reduce false positives. The detection leverages Windows Sysmon event ID 10. This type of attack can lead to widespread compromise of systems and accounts if successful, making it critical for defenders to identify and respond to promptly.

## Attack Chain

1. An attacker gains initial access to a system via phishing, exploiting a vulnerability, or other means.
2. The attacker executes a malicious process or script on the compromised system.
3. The malicious process attempts to access the LSASS process (lsass.exe).
4. The process uses `dbgcore.dll` or `dbghelp.dll` to call the `MiniDumpWriteDump` function.
5. A memory dump of the LSASS process is created on the file system.
6. The attacker retrieves the LSASS memory dump file.
7. The attacker uses credential harvesting tools to extract credentials from the dump file.
8. The attacker uses the stolen credentials for lateral movement or to achieve other objectives, such as data exfiltration or ransomware deployment.

## Impact

Successful exploitation can lead to the compromise of domain credentials, allowing attackers to move laterally within the network, escalate privileges, and potentially gain control of critical systems. This can lead to data breaches, financial loss, and reputational damage. The scope of the impact depends on the level of access granted to the compromised accounts and the sensitivity of the data they can access.

## Recommendation

*   Enable Sysmon process-creation and process-access logging to activate the rules above.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Monitor process access events (Sysmon Event ID 10) for access to `lsass.exe` where the call trace includes `dbgcore.dll`.
*   Investigate any processes accessing LSASS with `MiniDumpWriteDump` that are not known and trusted system processes.
*   Implement strong access controls to limit which processes and users can access the LSASS process.
