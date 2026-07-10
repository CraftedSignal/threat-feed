---
title: Detection of Vulnerable Windows Driver Installation
slug: 2024-01-vulnerable-driver-load
description: This analytic detects the installation of known vulnerable Windows drivers, potentially indicating persistence or privilege escalation attempts by threat actors exploiting these drivers for elevated privileges and system compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerable-driver
  - privilege-escalation
  - persistence
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://loldrivers.io/
  - https://github.com/SpikySabra/Kernel-Cactus
  - https://github.com/wavestone-cdt/EDRSandblast
  - https://research.splunk.com/endpoint/a2b1f1ef-221f-4187-b2a4-d4b08ec745f4/
  - https://www.splunk.com/en_us/blog/security/these-are-the-drivers-you-are-looking-for-detect-and-prevent-malicious-drivers.html
rules:
  - title: Detect Vulnerable Driver Installation via Event ID 7045
    description: Detects the installation of known vulnerable drivers based on Windows Event ID 7045.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Vulnerable Driver Installation via ImagePath
    description: Detects the installation of known vulnerable drivers based on matching ImagePath in process creation events.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying the installation of vulnerable Windows drivers, a tactic often employed by attackers to achieve persistence or escalate privileges. The technique involves exploiting known weaknesses in legitimate, but outdated or flawed, drivers to gain unauthorized access and control over a system. By monitoring Windows System service install events (EventCode 7045), the detection cross-references loaded drivers against a list of known vulnerable drivers (LoLdrivers). Successful exploitation can lead to arbitrary code execution with elevated privileges, ultimately compromising the entire system and enabling data exfiltration or other malicious activities. This is a Windows Event Log adaptation of the Sysmon driver loaded detection.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the system through various means (not specified).
2.  **Privilege Escalation:** The attacker identifies a vulnerable driver present on the system or deploys one.
3.  **Driver Installation:** The attacker triggers the installation of the vulnerable driver, which is logged as a Windows System Event 7045.
4.  **Exploitation:** The attacker leverages the known vulnerabilities within the installed driver to execute arbitrary code in kernel mode.
5.  **System Control:** Successful exploitation grants the attacker elevated privileges, allowing them to bypass security restrictions.
6.  **Persistence:** The attacker establishes persistence by using the exploited driver to maintain a foothold on the system.
7.  **Lateral Movement (potential):** With elevated privileges, the attacker could move laterally within the network to compromise additional systems.
8.  **Data Exfiltration / System Damage:** The attacker executes their final objective, such as exfiltrating sensitive data or causing damage to the compromised system.

## Impact

Successful exploitation of vulnerable drivers can have severe consequences, including complete system compromise, data theft, and the deployment of malware. While specific victim counts are unavailable, the impact can range from individual workstations to entire enterprise networks. Sectors most vulnerable are those with outdated security practices and unpatched systems. The consequences include significant financial losses, reputational damage, and potential regulatory fines.

## Recommendation

*   Enable and monitor Windows Event Log System with EventCode 7045, ensuring that "kernel mode driver" service types are being ingested (data_source).
*   Implement the Sigma rule "Detect Vulnerable Driver Installation via Event ID 7045" to identify potentially malicious driver installations (rules).
*   Regularly update the list of known vulnerable drivers (LoLdrivers) used in the detection to maintain accuracy (references).
*   Investigate any positive matches from the Sigma rule, focusing on the driver's version, signer, and installation path, as indicated by the event logs (search).
*   Use the provided drilldown searches to further investigate the detection results and associated risk events for impacted systems (drilldown_searches).
