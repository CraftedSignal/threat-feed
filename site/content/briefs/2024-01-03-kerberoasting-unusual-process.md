---
title: Kerberos Traffic from Unusual Process
slug: 2024-01-03-kerberoasting-unusual-process
description: Detects network connections to the standard Kerberos port from an unusual process other than lsass.exe, potentially indicating Kerberoasting or Pass-the-Ticket activity on Windows systems.
date: "2024-01-03T14:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - kerberoasting
  - credential-access
  - lateral-movement
  - windows
vendors:
  - Elastic
  - SentinelOne
  - Amazon
  - BlackBerry
  - DBeaver
  - Docker
  - Google
  - Microsoft
  - JetBrains
  - Mozilla
  - Oracle
  - Puppet Labs
  - Rapid7
  - Silverfort
  - Tenable
  - VMware
  - GFI
  - SAP
  - Zscaler
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Corretto JDK
  - UEM Proxy Server
  - UEM Core
  - dbeaver.exe
  - Docker
  - Chrome
  - Internet Explorer
  - PyCharm Community Edition
  - Firefox
  - VirtualBox
  - Puppet
  - nexpose
  - Silverfort AD Adapter
  - Nessus
  - VMware View
  - Advanced Port Scanner
  - DesktopCentral Agent
  - LanGuard
  - SAP BusinessObjects
  - SuperScan
  - ZSATunnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_kerberoasting_unusual_process.toml
  - https://attack.mitre.org/techniques/T1558/
  - https://attack.mitre.org/techniques/T1558/003/
  - https://attack.mitre.org/techniques/T1550/
  - https://attack.mitre.org/techniques/T1550/003/
rules:
  - title: Detect Kerberos Traffic from Non-Standard Process
    description: Detects network connections to the standard Kerberos port (88) from processes other than lsass.exe.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - lateral_movement
    techniques:
      - T1550.003
      - T1558.003
    data_sources:
      - network_connection
      - windows
  - title: Detect Kerberos Traffic from Non-Standard Process - CommandLine
    description: Detects network connections to the standard Kerberos port (88) from processes with suspicious command lines.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - lateral_movement
    techniques:
      - T1550.003
      - T1558.003
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection identifies unusual processes initiating network connections to the standard Kerberos port (88) on Windows systems. Typically, the `lsass.exe` process handles Kerberos traffic on domain-joined hosts. The rule aims to detect processes other than `lsass.exe` communicating with the Kerberos port, which could indicate malicious activity such as Kerberoasting (T1558.003) or Pass-the-Ticket (T1550.003). The detection is designed to work with data from Elastic Defend and SentinelOne Cloud Funnel. This can help security teams identify potential credential access attempts and lateral movement within the network.

## Attack Chain

1. An attacker compromises a user account or system within the domain.
2. The attacker executes a malicious binary or script (e.g., PowerShell) on the compromised system.
3. The malicious process attempts to request Kerberos service tickets (TGS) for various services within the domain. This is done by connecting to the Kerberos port (88) on a domain controller.
4. The attacker uses tools like `Rubeus` or `Kerberoast.ps1` to enumerate and request TGS tickets.
5. The unusual process (not `lsass.exe`) sends Kerberos traffic to the domain controller.
6. The attacker extracts the Kerberos tickets from memory or network traffic.
7. The attacker cracks the offline TGS tickets to obtain service account passwords (Kerberoasting).
8. The attacker uses the compromised service account credentials to move laterally within the network or access sensitive data.

## Impact

A successful Kerberoasting or Pass-the-Ticket attack can lead to unauthorized access to sensitive resources and lateral movement within the network. Attackers can compromise service accounts with elevated privileges, potentially leading to domain-wide compromise. Detection of this behavior can prevent attackers from gaining access to critical assets. While the exact number of victims and sectors targeted are unknown, this technique is widely used by various threat actors in targeted attacks.

## Recommendation

*   Deploy the "Kerberos Traffic from Unusual Process" Sigma rule to your SIEM and tune for your environment. Enable network connection logging to capture the necessary traffic.
*   Investigate any alerts triggered by the Sigma rule, focusing on the process execution chain and potential malicious binaries.
*   Review event ID 4769 for suspicious ticket requests as mentioned in the rule's documentation.
*   Examine host services for suspicious entries as outlined in the original Elastic detection rule using Osquery.
*   Monitor for processes connecting to port 88, filtering out legitimate Kerberos clients like `lsass.exe`, using the "Detect Kerberos Traffic from Non-Standard Process" Sigma rule.
*   Investigate processes identified by the rule and compare them to the list of legitimate processes to identify unauthorized connections to the Kerberos port.
