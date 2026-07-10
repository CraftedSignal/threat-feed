---
title: Potential Credential Access via Windows Utilities
slug: 2024-01-credential-dump-tools
description: This brief detects the execution of known Windows utilities such as procdump, ntdsutil, and diskshadow, often abused to dump LSASS memory or the Active Directory database (NTDS.dit) in preparation for credential access, potentially leading to widespread compromise.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - lsass
  - ntdsutil
  - procdump
  - windows
vendors:
  - Microsoft
products:
  - Windows
  - Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://lolbas-project.github.io/
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
rules:
  - title: Detect Procdump LSASS Memory Dump
    description: Detects the execution of Procdump with arguments commonly used to dump LSASS memory.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
  - title: Detect NTDSUtil or Diskshadow Activity
    description: Detects the execution of NTDSUtil or Diskshadow with arguments commonly used to create snapshots of the Active Directory database.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the abuse of legitimate Windows utilities to dump credentials from LSASS memory or the Active Directory database (NTDS.dit). Attackers commonly use these techniques to gain access to sensitive information, such as user credentials and Kerberos tickets, which can then be used for lateral movement and privilege escalation. The utilities commonly used include procdump, ProcessDump.exe, WriteMiniDump.exe, RUNDLL32.exe, RdrLeakDiag.exe, SqlDumper.exe, TTTracer.exe, ntdsutil.exe, and diskshadow.exe. These tools are often abused because they are typically present in a standard Windows installation, making their malicious use harder to detect. This activity is often a precursor to a larger attack, such as ransomware deployment or data exfiltration. The Elastic detection rule was last updated on 2026/04/07, indicating continued relevance.

## Attack Chain

1.  An attacker gains initial access to a Windows system through various means (e.g., phishing, exploitation of a vulnerability).
2.  The attacker executes a command shell (e.g., cmd.exe or PowerShell) to run reconnaissance commands and identify potential targets.
3.  The attacker uses procdump.exe with the `-ma` flag to create a full memory dump of the LSASS process.
4.  Alternatively, the attacker utilizes RUNDLL32.exe to invoke MiniDump functionality for LSASS process dumping.
5.  The attacker uses ntdsutil.exe to create a snapshot of the Active Directory database (NTDS.dit) if the compromised host is a domain controller.
6.  The attacker uses diskshadow.exe to create shadow copies, which can then be used to access the NTDS.dit database.
7.  The attacker copies the dumped LSASS memory or NTDS.dit file to a location where they can extract credentials offline.
8.  The attacker uses credential extraction tools to parse the dumped memory or database and obtain user credentials and other sensitive information.

## Impact

A successful credential dumping attack can have severe consequences. Attackers can use the compromised credentials to move laterally within the network, access sensitive data, and escalate their privileges. This can lead to data breaches, financial losses, and reputational damage. In environments with Active Directory, a compromise of the NTDS.dit file can result in a complete compromise of the entire domain, affecting all users and systems. Depending on the compromised accounts, attackers can encrypt critical systems with ransomware or exfiltrate sensitive data.

## Recommendation

*   Enable Sysmon process-creation logging to capture command-line arguments for all processes, allowing for detection of credential dumping tools (reference: logsource with category "process_creation" and product "windows").
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious execution of credential dumping utilities.
*   Monitor for unexpected execution of `procdump.exe` with the `-ma` flag, as this is a common indicator of LSASS memory dumping (reference: Sigma rule "Detect Procdump LSASS Memory Dump").
*   Implement strict access controls on domain controllers to limit which users and systems can access the NTDS.dit file and LSASS process, reducing the attack surface (reference: overview).
*   Monitor for unusual uses of `ntdsutil.exe` or `diskshadow.exe`, especially on systems that are not domain controllers (reference: Sigma rule "Detect NTDSUtil or Diskshadow Activity").
