---
title: LSASS Memory Dump Creation Detection
slug: 2024-01-lsass-memory-dump
description: This rule detects the creation of LSASS memory dumps, which may indicate a credential access attempt via tools like Task Manager, SQL Dumper, Dumpert, and AndrewSpecial.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - lsass
  - memory-dump
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/outflanknl/Dumpert
  - https://github.com/hoangprod/AndrewSpecial
  - https://attack.mitre.org/techniques/T1003/
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/tactics/TA0006/
rules:
  - title: LSASS Memory Dump Creation
    description: Detects the creation of LSASS memory dumps based on filename.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
      - T1003.001
    data_sources:
      - file_event
      - windows
  - title: Detect Dumpert LSASS Dump Creation
    description: Detects LSASS memory dumps created by Dumpert.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
      - T1003.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Local Security Authority Subsystem Service (LSASS) is a process in Windows operating systems responsible for enforcing security policy. Attackers target LSASS to steal credentials stored in memory. This detection identifies the creation of memory dump files with filenames compatible with credential dumping tools or that start with 'lsass', potentially indicating credential access attempts. The rule aims to detect suspicious memory dump creation indicative of credential theft. This activity is often associated with tools like Task Manager, SQL Dumper, as well as pentesting tools Dumpert and AndrewSpecial. The detection logic excludes legitimate SQL dumper and WerFault.exe processes to reduce false positives.

## Attack Chain

1. An attacker gains initial access to a system via phishing, exploitation of a vulnerability, or stolen credentials (not explicitly covered in this source).
2. The attacker executes a privileged process or leverages an existing one (e.g., Task Manager, SQLDumper.exe).
3. The privileged process is used to create a memory dump file of the LSASS process. This can be achieved using built-in tools or specialized tools like Dumpert or AndrewSpecial.
4. The memory dump file is written to disk with a recognizable name such as "lsass.dmp", "dumpert.dmp", or "SQLDmpr*.mdmp". The file path is typically in a location accessible to the attacker.
5. The attacker retrieves the LSASS memory dump file from the compromised system.
6. The attacker analyzes the memory dump file offline using credential extraction tools like Mimikatz.
7. The attacker obtains user credentials, including passwords and NTLM hashes, from the LSASS memory dump.
8. The attacker uses the stolen credentials to move laterally within the network, access sensitive data, or achieve other malicious objectives.

## Impact

Successful exploitation and credential dumping can lead to widespread compromise of an organization's network. Stolen credentials can be used for lateral movement, privilege escalation, and data exfiltration. The impact includes unauthorized access to sensitive data, financial loss, and reputational damage. The severity is high due to the potential for widespread compromise.

## Recommendation

*   Deploy the Sigma rule "LSASS Memory Dump Creation" to your SIEM and tune for your environment to detect the creation of LSASS memory dumps (rule.query).
*   Monitor file creation events for filenames matching patterns used by credential dumping tools: lsass*.dmp, dumpert.dmp, Andrew.dmp, SQLDmpr*.mdmp, Coredump.dmp (rule.query).
*   Investigate any process creating LSASS memory dumps, especially if the process is not WerFault.exe or SQLDumper.exe in known good paths (rule.query).
*   Enable Sysmon file creation events logging to provide the necessary data for the detection rules above (logsource).
