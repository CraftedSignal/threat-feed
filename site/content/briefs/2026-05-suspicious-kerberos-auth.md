---
title: Suspicious Kerberos Authentication Ticket Request
slug: 2026-05-suspicious-kerberos-auth
description: This rule detects suspicious Kerberos authentication ticket requests by correlating network connections to the standard Kerberos port (88) from a source machine with a Kerberos authentication ticket request from the target domain controller, which could indicate lateral movement or credential access attempts within a Windows domain.
date: "2026-05-12T17:45:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - threat-detection
  - windows
vendors:
  - Microsoft
  - VMware
  - Omnissa
  - IGEL
  - Elastic
products:
  - Elastic Defend
  - Windows
  - Horizon
  - RemoteManager
  - VMware View
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.002
    technique_name: 'Remote Services: SMB/Windows Admin Shares'
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558.003
    technique_name: 'Steal or Forge Kerberos Tickets: Kerberos Golden Ticket'
references:
  - https://github.com/its-a-feature/bifrost
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
rules:
  - title: Detect Suspicious Kerberos Network Connection
    description: Detects network connections to Kerberos port 88 from unusual processes, excluding system processes.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Kerberos Authentication Request (Event 4768/4769)
    description: Detects Kerberos authentication ticket requests (event IDs 4768 and 4769) in Windows Security Logs.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - lateral_movement
    techniques:
      - T1558.003
    data_sources:
      - authentication
      - windows
rules_count: 2
---

This detection rule correlates network connections to the standard Kerberos port (88) by an unusual process from the source machine with a Kerberos authentication ticket request from the target domain controller. It aims to identify potential lateral movement or credential access attempts within a Windows domain. The rule focuses on identifying processes other than the standard `lsass.exe` or known Tomcat services making Kerberos requests. This is important for defenders as Kerberos is a critical authentication protocol and unusual activity can signal malicious behavior. The rule leverages EQL and considers data from various sources including endpoint events, Sysmon, and Windows Security Event Logs.

## Attack Chain

1.  An attacker compromises a Windows endpoint within the network.
2.  The attacker executes a malicious tool or leverages an existing binary to request a Kerberos ticket (TGT or TGS).
3.  This tool establishes a network connection to the domain controller on port 88 (Kerberos).
4.  The domain controller receives the Kerberos ticket request, logging event codes 4768 (Kerberos authentication ticket request) or 4769 (Kerberos service ticket request).
5.  The detection rule identifies this network connection originating from an unusual process (not lsass.exe or known tomcat services) on the endpoint.
6.  The rule correlates this network connection with the corresponding Kerberos authentication event on the domain controller within a defined timeframe (3 seconds).
7.  Successful authentication may allow the attacker to move laterally within the network or access sensitive resources.
8.  The attacker uses the obtained Kerberos ticket to authenticate to other systems or services in the domain, furthering their objectives.

## Impact

A successful attack can lead to lateral movement within the network, unauthorized access to sensitive data, and potential compromise of critical systems. The rule's risk score is 73, indicating a high level of risk associated with this type of activity. Organizations could experience data breaches, financial losses, and reputational damage if such attacks are not detected and mitigated promptly.

## Recommendation

*   Deploy the provided EQL rule to your SIEM or Elastic environment to detect suspicious Kerberos authentication ticket requests.
*   Enable Sysmon event ID 3 (Network Connection) logging to provide the necessary network connection data.
*   Enable auditing for Kerberos authentication service (event ID 4768) and Kerberos service ticket operations (event ID 4769) on domain controllers.
*   Investigate any triggered alerts by examining the process executable, command line, target user name, and associated network activity as described in the rule's `note` section.
*   Tune the rule's process exceptions to account for legitimate Kerberos-capable clients in your environment.
*   Prioritize investigation of alerts where the source process is unsigned, renamed, user-writable, signer-mismatched, or outside known AD audit, Kerberos diagnostic, or security-test tooling as detailed in the note section.
