---
title: Suspicious HTML File Creation Leading to Potential Payload Delivery
slug: 2024-01-suspicious-html-creation
description: This detection identifies the creation of HTML files with high entropy and large size, followed by execution via a browser process, indicating potential HTML smuggling and malicious payload delivery on Windows systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - html-smuggling
  - phishing
  - initial-access
  - windows
  - evasion
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_evasion_suspicious_htm_file_creation.toml
rules:
  - title: Suspicious HTML File Creation in Downloads Directory
    description: Detects the creation of HTML files with high entropy or large size in common download directories, potentially indicating HTML smuggling.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1027.006
      - T1566.001
    data_sources:
      - file_event
      - windows
  - title: Browser Opening HTML File from Suspicious Location
    description: Detects browser processes opening HTML files from common download or temporary directories with specific command-line arguments, indicating potential execution of smuggled payloads.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Internet Explorer Opening HTML File from Suspicious Location
    description: Detects Internet Explorer processes opening HTML files with two arguments from common download or temporary directories.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule identifies a suspicious sequence of events indicative of HTML smuggling, where adversaries embed malicious payloads within seemingly benign HTML files to bypass security filters. The rule focuses on Windows systems and monitors for the creation of HTML files exhibiting characteristics such as high entropy (>=5) and large size (>=150,000 bytes) or very large size (>=1,000,000 bytes) within common download and temporary directories (e.g., Downloads, Content.Outlook, AppData\\Local\\Temp). Subsequently, it tracks the execution of browser processes (e.g., chrome.exe, firefox.exe, iexplore.exe) opening these HTML files with specific command-line arguments (e.g., --single-argument, -url). The detection aims to uncover initial access attempts, defense evasion, and user execution of malicious files delivered through HTML smuggling techniques.

## Attack Chain

1.  A user receives a phishing email containing a malicious HTML attachment.
2.  The user opens the attachment, triggering the download of a large HTML file to the Downloads folder.
3.  The HTML file contains obfuscated JavaScript code that, when executed, reconstructs a malicious payload (e.g., a Cobalt Strike beacon).
4.  The file is saved with an .htm or .html extension in a temporary or download directory.
5.  A browser process (chrome.exe, firefox.exe, etc.) is initiated to open the HTML file, often with specific arguments like "--single-argument" or "-url".
6.  The browser renders the HTML, executing the embedded JavaScript.
7.  The JavaScript deobfuscates and executes the smuggled payload, initiating a reverse shell connection to a command-and-control server.
8.  The attacker gains initial access to the compromised system and can proceed with lateral movement or data exfiltration.

## Impact

Successful exploitation via HTML smuggling can lead to initial access to a targeted system, potentially enabling attackers to perform lateral movement, data exfiltration, or ransomware deployment. While the specific number of victims and targeted sectors are not explicitly stated in the source, the technique is broadly applicable and can affect any Windows user who interacts with malicious HTML attachments or downloads from untrusted sources. The consequences of successful exploitation range from data breaches and financial losses to reputational damage and operational disruption.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM and tune the file path and browser process filters for your environment.
*   Enable file integrity monitoring (FIM) on common download and temporary directories to detect the creation of suspicious HTML files as described in the Sigma rules.
*   Implement network egress filtering to block connections to known malicious command-and-control servers and domains to prevent payload execution.
*   Educate users about the risks of opening attachments from untrusted sources and train them to recognize phishing emails as outlined in the Overview.
*   Utilize endpoint detection and response (EDR) solutions to monitor process execution and network connections for anomalous behavior associated with HTML smuggling.
