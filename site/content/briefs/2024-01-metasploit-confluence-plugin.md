---
title: Metasploit Exploitation via Malicious Confluence Plugin
slug: 2024-01-metasploit-confluence-plugin
description: A Metasploit module exploits Atlassian Confluence servers by deploying a malicious Java plugin that downloads Meterpreter, granting the attacker full control over the compromised system.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - confluence
  - metasploit
  - meterpreter
  - plugin
  - exploitation
  - attack
vendors:
  - Atlassian
  - Splunk
products:
  - Confluence Data Center
  - Confluence Server
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1608
    technique_name: Stage Capabilities
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_metasploit_confluence_plugin_execution.yml
rules:
  - title: Detect Metasploit Confluence Plugin Execution
    description: Detects java.exe executing with specific command line arguments indicative of Metasploit's Confluence plugin exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Process Execution from Temp Directory
    description: Detects processes executing from the AppData\Local\Temp directory, which could indicate malware or exploitation activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the exploitation of Atlassian Confluence servers using a Metasploit module that deploys a malicious Java plugin. The attack begins with the deployment of a specially crafted plugin to the Confluence server. This plugin is designed to execute arbitrary code, and the Metasploit module leverages this to download and execute Meterpreter. Successful exploitation grants the attacker complete control over the Confluence server. Defenders should be aware that successful exploitation provides a foothold for lateral movement and data exfiltration.

## Attack Chain

1. The attacker exploits a vulnerability in Atlassian Confluence via a Metasploit module (T1190).
2. A malicious Java plugin is uploaded to the Confluence server, typically through a web request.
3. The Confluence server executes the malicious plugin within the Java Runtime Environment (`java.exe`).
4. The plugin initiates a network connection to download Meterpreter.
5. Meterpreter is downloaded to a temporary directory, often within the `AppData\\Local\\Temp` path.
6. Meterpreter executes, establishing a reverse shell to the attacker's command and control (C2) server.
7. The attacker gains full control over the Confluence server, enabling further exploitation activities.
8. The attacker may leverage this access for lateral movement, data exfiltration, or deploying ransomware.

## Impact

Successful exploitation of Atlassian Confluence servers through malicious plugins can lead to complete system compromise. This can result in the loss of sensitive data, disruption of services, and potential lateral movement to other systems within the network. Due to the widespread use of Confluence in enterprise environments, a successful attack can impact numerous organizations.

## Recommendation

*   Deploy the Sigma rule `Detect Metasploit Confluence Plugin Execution` to detect malicious java plugin execution used by metasploit for Atlassian Confluence exploitation.
*   Monitor process execution for `java.exe` spawning processes from temporary directories (`AppData\\Local\\Temp`) as a potential indicator of malicious plugin activity, which is covered in the Sigma rule `Detect Metasploit Confluence Plugin Execution`.
*   Implement network monitoring to detect outbound connections from Confluence servers to unusual or suspicious IP addresses, potentially indicating Meterpreter C2 communication.
*   Review and patch Atlassian Confluence instances for known vulnerabilities that may be exploited by Metasploit modules, referencing the analytic story `Confluence Data Center and Confluence Server Vulnerabilities`.
