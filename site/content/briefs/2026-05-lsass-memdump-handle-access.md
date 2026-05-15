---
title: LSASS Memory Dump Handle Access
slug: 2026-05-lsass-memdump-handle-access
description: Detection of handle requests to the LSASS process with specific access masks commonly used by tools to dump memory, indicating potential credential access attempts.
date: "2026-05-15T19:38:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - lsass
  - memdump
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
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4656
  - https://twitter.com/jsecurity101/status/1227987828534956033?s=20
  - https://attack.mitre.org/techniques/T1003/001/
  - https://threathunterplaybook.com/notebooks/windows/06_credential_access/WIN-170105221010.html
  - http://findingbad.blogspot.com/2017/
  - https://www.elastic.co/security-labs/detect-credential-access
rules:
  - title: LSASS Memory Dump Handle Access
    description: Detects handle requests for LSASS process with specific access masks indicative of memory dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: Windows Event 4656 - LSASS Object Access
    description: Detects Windows Event ID 4656 events indicating access to the LSASS process with specific access masks used for memory dumping.
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

This detection identifies handle requests targeting the Local Security Authority Subsystem Service (LSASS) on Windows systems. LSASS is responsible for enforcing security policy, including user authentication and access token creation. Attackers often target LSASS to extract credential material stored in its memory, enabling lateral movement. The rule focuses on detecting specific access masks (0x1fffff, 0x1010, 0x120089, 0x1F3FFF) associated with memory dumping tools. This detection is tool-agnostic, meaning it doesn't rely on specific tool names like Mimikatz or Procdump, but rather on the low-level behavior of requesting access to LSASS memory. The rule aims to identify potential credential access attempts regardless of the specific tool used. The original detection rule was created on 2022/02/16 and updated on 2026/05/12.

## Attack Chain

1. An attacker gains initial access to a Windows system.
2. The attacker escalates privileges to an administrative or SYSTEM level account.
3. The attacker uses a tool like Mimikatz, SharpDump, or a custom script to request a handle to the LSASS process.
4. The handle request specifies an access mask such as 0x1fffff, 0x1010, 0x120089, or 0x1F3FFF, indicating an intention to read process memory.
5. The tool uses the obtained handle to read memory from the LSASS process.
6. The attacker parses the dumped memory to extract credentials, such as usernames, passwords, and NTLM hashes.
7. The attacker uses the stolen credentials to move laterally to other systems on the network.
8. The attacker achieves their final objective, such as data exfiltration or system compromise.

## Impact

Successful exploitation allows attackers to steal user credentials stored in LSASS memory. These credentials can be used to perform lateral movement, escalate privileges, and gain access to sensitive data. This can lead to a complete compromise of the affected systems and potentially the entire network, depending on the scope of the attacker's access and objectives. The number of victims and sectors targeted are dependent on the attacker.

## Recommendation

*   Enable Audit Handle Manipulation to generate the required event logs for the detections: <https://ela.st/audit-handle-manipulation>.
*   Deploy the "LSASS Memory Dump Handle Access" Sigma rule to your SIEM and tune for your environment (see below).
*   Investigate processes accessing LSASS memory that are not explicitly excluded in the Sigma rule.
*   Monitor for unexpected processes accessing LSASS and correlate with other suspicious activity.
*   Review and harden LSASS protection configurations as outlined in vendor documentation.
