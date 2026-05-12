---
title: LSASS Process Access via Windows API
slug: 2026-05-lsass-process-access
description: This rule identifies access attempts to the LSASS handle, which may indicate an attempt to dump credentials from LSASS memory by detecting specific API calls (OpenProcess, OpenThread, ReadProcessMemory) targeting the 'lsass.exe' process.
date: "2026-05-12T19:21:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - lsass
vendors:
  - Microsoft
products:
  - Microsoft Defender XDR
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1106
    technique_name: Native API
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md
rules:
  - title: Detect LSASS Process Access via OpenProcess API
    description: Detects access to LSASS process via OpenProcess API call
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: Detect LSASS Process Access via ReadProcessMemory API
    description: Detects access to LSASS process via ReadProcessMemory API call
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Local Security Authority Subsystem Service (LSASS) is a crucial Windows component that manages user authentication and security policies. Attackers may attempt to access the LSASS process handle to dump credentials from memory for lateral movement and privilege escalation. This rule detects attempts to access LSASS by monitoring for specific API calls (OpenProcess, OpenThread, ReadProcessMemory) targeting the "lsass.exe" process. The rule leverages data from Elastic Defend and Microsoft Defender XDR, analyzing API events on Windows systems, excluding common false positives related to standard program files and Windows Defender processes.

## Attack Chain

1.  An attacker gains initial access to a Windows system, potentially through phishing, exploitation of a vulnerability, or compromised credentials.
2.  The attacker executes a malicious program or script on the compromised system.
3.  The malicious program attempts to access the LSASS process using Windows API calls such as `OpenProcess` or `OpenThread`.
4.  The program requests specific access rights necessary for reading LSASS memory.
5.  If successful, the program reads the memory contents of the LSASS process.
6.  The attacker extracts sensitive information such as usernames, passwords, and Kerberos tickets from the dumped LSASS memory.
7.  The attacker uses the stolen credentials to move laterally to other systems within the network.
8.  The attacker escalates privileges and gains control over critical assets.

## Impact

Successful credential dumping from LSASS memory can lead to a complete compromise of the Windows domain. Attackers can use stolen credentials to move laterally, escalate privileges, and gain unauthorized access to sensitive data. This can result in data breaches, financial loss, and reputational damage. If successful, attackers can compromise administrator accounts, allowing them to control the entire infrastructure.

## Recommendation

*   Deploy the Sigma rule provided below to detect suspicious LSASS process access attempts, and tune for your environment to reduce false positives.
*   Enable endpoint detection and response (EDR) solutions like Elastic Defend and Microsoft Defender XDR to capture API events and process execution data as referenced in the rule's logsource.
*   Monitor `process.Ext.api.parameters.desired_access` to assess the access rights requested by processes attempting to access LSASS, as described in the investigation guide.
*   Implement the Osquery queries to examine the DNS cache, host services, and unsigned executables as shown in the overview to enhance investigation capabilities.
*   Add exceptions based on `process.executable`, `process.code_signature.subject_name`, and `process.Ext.api.parameters.desired_access_numeric` as documented to reduce false positives in environments with known legitimate LSASS access.
