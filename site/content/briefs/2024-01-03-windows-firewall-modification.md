---
title: Windows Firewall Rule Modification Detection
slug: 2024-01-03-windows-firewall-modification
description: This detection identifies instances where a Windows Firewall rule has been modified, potentially indicating an attempt to weaken security policies and allow malicious traffic or prevent legitimate communications.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - firewall
  - windows
  - anomaly
vendors:
  - Microsoft
  - Splunk
products:
  - Windows
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4947
rules:
  - title: Windows Firewall Rule Modification
    description: Detects modifications to Windows Firewall rules based on Event ID 4947
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Modifying Firewall Rule
    description: Detects suspicious processes modifying Windows Firewall rules by monitoring for Event ID 4947 and filtering known legitimate processes
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The modification of Windows Firewall rules can indicate malicious activity, as attackers may attempt to weaken security policies to facilitate unauthorized access or evade detection. Windows Event Log Security event ID 4947 is generated when a firewall rule is modified. Monitoring these events and correlating them with other security incidents can help security teams identify and respond to potential threats. This activity is leveraged by threat actors post-compromise to enable lateral movement and command and control traffic. This activity is associated with ransomware campaigns such as ShrinkLocker and Medusa.

## Attack Chain

1. An attacker gains initial access to a system through various means, such as phishing or exploiting a vulnerability.
2. The attacker escalates privileges to gain administrative rights, which are necessary to modify firewall rules.
3. The attacker uses built-in Windows tools or custom scripts to modify existing firewall rules or create new ones.
4. The modification might involve opening specific ports to allow unauthorized inbound traffic.
5. Or, disabling rules that block outbound communication to a command-and-control server.
6. The attacker validates that the firewall rule changes have been successfully implemented.
7. The attacker leverages the modified firewall rules to facilitate lateral movement within the network.
8. The attacker achieves their objective, such as data exfiltration or deploying ransomware.

## Impact

Successful modification of Windows Firewall rules can significantly weaken a system's security posture. This can lead to unauthorized access, data breaches, and malware infections. The impact can range from individual system compromise to widespread network infiltration, potentially affecting hundreds or thousands of systems within an organization. This activity is observed in ransomware campaigns, such as ShrinkLocker and Medusa.

## Recommendation

*   Enable Windows Security Event Log collection with Event ID 4947 to monitor firewall rule modifications.
*   Deploy the Sigma rule "Windows Firewall Rule Modification" to your SIEM (Splunk) and tune for your environment.
*   Investigate any unexpected or unauthorized firewall rule modifications, correlating them with other security events.
*   Implement strict access controls to limit the ability to modify firewall rules to authorized personnel only.
