---
title: Windows Firewall Rule Deletion Detection
slug: 2024-01-windows-firewall-rule-deletion
description: Detection of Windows Firewall rule deletion events (Event ID 4948) indicating potential attacker attempts to bypass security controls or malware disabling protections for persistence and command-and-control.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - firewall
  - windows
  - endpoint
vendors:
  - Microsoft
  - Splunk
products:
  - Windows
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4948
rules:
  - title: Detect Windows Firewall Rule Deletion via Netsh
    description: Detects the deletion of Windows Firewall rules using the `netsh` command-line tool, which is a common method used by attackers to disable or weaken firewall defenses.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows Firewall Rule Deletion Event ID 4948
    description: Detects Windows Firewall rule deletion events based on Windows Event ID 4948, indicating a change in firewall configuration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This brief focuses on detecting the deletion of Windows Firewall rules, as identified by Windows Security Event ID 4948. The unauthorized removal of firewall rules can be a critical indicator of malicious activity, as attackers may attempt to weaken the system's defenses to facilitate lateral movement, persistence, or command-and-control communication. This activity is often associated with malware infections or targeted attacks where adversaries seek to bypass security controls. Monitoring for unexpected or anomalous firewall rule deletions is crucial for maintaining network security posture and detecting potential security breaches.

## Attack Chain

1.  The attacker gains initial access to the system through various means (e.g., phishing, exploiting a vulnerability).
2.  The attacker escalates privileges to obtain necessary permissions to modify firewall settings.
3.  The attacker identifies existing firewall rules that impede their malicious activities.
4.  The attacker executes commands via the command line or PowerShell to delete specific firewall rules using `netsh` or PowerShell cmdlets (e.g., `Remove-NetFirewallRule`).
5.  Windows Security Event Log generates Event ID 4948, recording the details of the firewall rule deletion, including the rule name, user, and process responsible.
6.  With the firewall rules removed, the attacker establishes unauthorized network connections for command-and-control or lateral movement.
7.  The attacker deploys malware or executes malicious code to achieve their objectives (e.g., data exfiltration, ransomware deployment).

## Impact

Successful deletion of Windows Firewall rules can lead to significant security breaches. Attackers can bypass network security controls, establish unauthorized connections, and compromise sensitive data. This can result in data breaches, financial losses, and reputational damage. The detection of firewall rule deletions allows security teams to quickly respond to potential threats and prevent further damage. This activity has been observed in conjunction with ransomware campaigns like Medusa and ShrinkLocker.

## Recommendation

*   Enable Windows Security Event Logging and ensure Event ID 4948 is captured and forwarded to your SIEM for analysis to detect Windows Firewall rule deletions.
*   Deploy the Sigma rules provided below to your SIEM to detect suspicious firewall rule deletion activity and tune for your environment.
*   Investigate any instances of Event ID 4948, correlating with other security events to identify potential malicious activity.
*   Monitor process execution for command-line or PowerShell commands used to delete firewall rules (e.g., `netsh`, `Remove-NetFirewallRule`).
*   Implement strict access control policies to limit the number of users with permissions to modify firewall settings.
