---
title: Kerberos Ticket Dump via Kirbi File Creation
slug: 2024-01-03-kirbi-file-creation
description: The creation of .kirbi files on Windows systems indicates potential Kerberos ticket dumping using tools like Mimikatz, preceding Pass-The-Ticket attacks.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - kerberos
  - mimikatz
  - pass-the-ticket
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
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
references:
  - https://attack.mitre.org/techniques/T1003/
  - https://attack.mitre.org/techniques/T1558/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_kirbi_file.toml
rules:
  - title: Detect Kirbi File Creation via Sysmon
    description: Detects the creation of .kirbi files, indicative of Kerberos ticket dumping.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
      - T1558
    data_sources:
      - file_event
      - windows
  - title: Detect Kirbi File Creation via Process and Extension
    description: Detects creation of a .kirbi file written by suspicious process.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
      - T1558
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The creation of `.kirbi` files on a Windows host is a strong indicator of Kerberos ticket dumping, often performed by attackers aiming to steal credentials and move laterally within a network. Tools like Mimikatz are commonly used to extract Kerberos tickets, which are then saved as `.kirbi` files. This activity is often a precursor to Pass-the-Ticket (PTT) attacks, where attackers use the stolen tickets to impersonate legitimate users and gain unauthorized access to resources. This technique allows attackers to bypass traditional authentication mechanisms and move undetected across the network. This activity is actively detected by the Elastic Detection Engine, SentinelOne, Microsoft Defender XDR, Crowdstrike, and Sysmon logs, making it a valuable event for defenders to monitor.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a Windows host, often through phishing or exploiting a vulnerability.
2.  Privilege Escalation: The attacker may need to escalate privileges to run credential dumping tools effectively.
3.  Credential Dumping: The attacker executes a tool like Mimikatz on the compromised host.
4.  Kerberos Ticket Extraction: Mimikatz extracts Kerberos tickets from memory, including TGTs (Ticket Granting Tickets).
5.  Kirbi File Creation: The extracted Kerberos tickets are saved as `.kirbi` files on the file system.
6.  Ticket Analysis: The attacker analyzes the dumped tickets to identify valuable credentials for lateral movement.
7.  Pass-the-Ticket: The attacker uses the stolen Kerberos tickets to authenticate to other systems and services on the network, impersonating legitimate users.
8.  Lateral Movement and Data Exfiltration/Ransomware: The attacker leverages the compromised accounts to move laterally within the network, accessing sensitive data or deploying ransomware.

## Impact

Successful exploitation allows attackers to perform Pass-the-Ticket attacks, impersonating legitimate users and gaining unauthorized access to critical systems and data. This can lead to significant data breaches, financial losses, and reputational damage. Organizations in all sectors are vulnerable, particularly those relying heavily on Kerberos for authentication. The compromise of privileged accounts can grant attackers complete control over the network.

## Recommendation

*   Deploy the "Kirbi File Creation" Sigma rule to your SIEM and tune for your environment to detect the creation of `.kirbi` files.
*   Monitor process execution for known credential dumping tools like Mimikatz using a process_creation rule targeting common Mimikatz command-line arguments.
*   Enable Sysmon file creation logging to capture `.kirbi` file creation events and related process information.
*   Implement strict access controls and the principle of least privilege to minimize the impact of compromised accounts.
*   Regularly review and audit Kerberos configuration and activity to identify and address potential vulnerabilities.
