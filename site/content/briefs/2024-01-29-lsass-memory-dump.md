---
title: Potential LSASS Memory Dump Activity
slug: 2024-01-29-lsass-memory-dump
description: This brief covers the potential for credential access via LSASS memory dumping, a technique used to steal credentials from memory, though specific details are absent from the provided source.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - https://www.reddit.com/r/blueteamsec/comments/1rviscr/ghost_in_the_ppl_lsass_memory_dump/
rules:
  - title: Detect LSASS Memory Dump via Procdump
    description: Detects the execution of procdump with arguments commonly used to dump the LSASS process.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: Detect LSASS Access via Handle
    description: Detects process access to LSASS via handle
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief addresses the potential threat of LSASS memory dumping, a common technique used by attackers to steal credentials stored in the Local Security Authority Subsystem Service (LSASS) process memory. While the provided source material lacks specific details regarding a particular actor, campaign, or tool, it highlights the general risk associated with unauthorized access to LSASS memory. Successful LSASS memory dumps can lead to the compromise of user credentials, domain accounts, and other sensitive information, enabling lateral movement and privilege escalation within a network. Defenders should implement robust monitoring and prevention measures to detect and prevent LSASS memory dumping attempts.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to a system through unspecified means (e.g., phishing, exploitation of vulnerabilities, or stolen credentials).
2. **Privilege Escalation (Optional):** The attacker may need to escalate privileges to gain sufficient access to dump LSASS memory. This might involve exploiting local vulnerabilities or using techniques like token impersonation.
3. **LSASS Process Identification:** The attacker identifies the LSASS process, typically using tools like Task Manager, Process Explorer, or command-line utilities.
4. **Memory Dump Execution:** The attacker uses a tool (e.g., Task Manager, procdump, or custom malware) to create a memory dump of the LSASS process.
5. **Dump File Acquisition:** The attacker retrieves the memory dump file from the compromised system. This could involve transferring the file to a remote server or storing it locally for later exfiltration.
6. **Credential Extraction:** The attacker uses tools like Mimikatz or pypykatz to parse the LSASS memory dump file and extract credentials, including passwords, NTLM hashes, and Kerberos tickets.
7. **Lateral Movement:** The attacker uses the stolen credentials to move laterally to other systems within the network, compromising additional accounts and resources.
8. **Objective Completion:** The attacker uses the compromised systems and credentials to achieve their final objective, which could include data exfiltration, ransomware deployment, or disruption of services.

## Impact

Successful LSASS memory dumping can lead to widespread credential compromise, enabling attackers to move laterally throughout a network and gain access to sensitive data and critical systems. The impact can range from data breaches and financial losses to disruption of operations and reputational damage. Organizations in all sectors are at risk, as LSASS memory dumping is a common technique used by both opportunistic and targeted attackers. A successful attack allows threat actors to gain privileged access to internal resources, leading to severe consequences.

## Recommendation

*   Enable and monitor process creation events with Sysmon, specifically focusing on processes attempting to access LSASS memory (reference: Sysmon process_creation logging).
*   Deploy a Sigma rule to detect suspicious processes attempting to dump LSASS memory using common tools like procdump or custom scripts (reference: the Sigma rule below).
*   Implement Protected Processes Light (PPL) for LSASS to prevent unauthorized access to its memory (reference: Microsoft documentation on PPL).
*   Monitor for the creation of large files in unusual locations, which could indicate a memory dump operation (reference: file_event log source).
