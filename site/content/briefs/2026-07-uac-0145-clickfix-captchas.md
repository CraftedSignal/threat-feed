---
title: UAC-0145 Uses ClickFix CAPTCHAs to Distribute Data-Stealing Malware
slug: 2026-07-uac-0145-clickfix-captchas
description: Russian state-sponsored threat actor UAC-0145 (Sandworm sub-cluster) is actively targeting Ukrainian organizations by using fake ClickFix CAPTCHAs on compromised websites to trick users into executing malicious PowerShell commands, leading to the deployment of data-stealing malware on Windows and Android devices.
date: "2026-07-19T14:18:35Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UAC-0145
tags:
  - malware
  - state-sponsored
  - data-theft
  - social-engineering
  - windows
  - android
  - ukraine
  - backdoor
affected_os:
  - Windows
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: In these attacks, threat actors have been found to leverage fake CAPTCHA checks on compromised websites that instruct prospective targets to execute a PowerShell command in the terminal.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: instruct prospective targets to execute a PowerShell command in the terminal.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: downloading and saving a VBS file in the Startup autorun directory; one of the variants of such a program was called GHETTOVIBE
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: downloading and saving a VBS file in the Startup autorun directory
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: SCOUTCURL, a PowerShell script that performs basic reconnaissance by harvesting details about the infected machine.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: retrieving commands or data from an external server or from legitimate sites like steamcommunity[.]com.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: intended for downloading and saving a VBS file
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
    evidence: COWARDDUCK that can clandestinely collect the following details - Contacts, Files matching certain extensions ... Geolocation in real time
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: the malware uses the Dropbox cloud service API to upload files
    confidence_band: high
references:
  - https://thehackernews.com/2026/07/uac-0145-uses-clickfix-captchas-to.html
rules:
  - title: Detect PowerShell Downloading and Saving VBS to Startup Directory
    description: Detects PowerShell commands attempting to download a VBS file and save it to a Windows Startup directory, often used for persistence by UAC-0145.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.001
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious VBS File Creation in Startup Directory
    description: Detects the creation or modification of VBS files within the Windows Startup directory, a common persistence mechanism used by UAC-0145.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

UAC-0145, a sub-cluster within the Russian state-sponsored Sandworm hacking unit (affiliated with GRU), has been observed actively targeting Ukrainian devices with data-stealing malware. Between June and July 2026, the group compromised at least 10 websites, employing a social engineering technique dubbed "ClickFix CAPTCHA." This method involves injecting fake CAPTCHA checks that instruct targets to execute specific PowerShell commands. These commands facilitate the download and persistence of malicious VBS files, such as "GHETTOVIBE," in the Startup directory. The campaign also leverages tools like SCOUTCURL for reconnaissance, FLUIDLEECH and LOADLOOP as loaders, and FREAKYPOLL as a Python backdoor. Additionally, UAC-0145 distributes backdoored Android APKs via messaging apps, containing the COWARDDUCK malware, which exfiltrates sensitive data using the Dropbox API. This campaign marks a shift from previous tactics, utilizing advanced web manipulation techniques like Cloaking.House and SMARTAXE to deliver tailored malicious content.

## Attack Chain

1. **Web Compromise and Traffic Manipulation**: Threat actors compromise at least 10 legitimate websites between June and July 2026. They utilize traffic filtering services like Cloaking.House and a bespoke tool called SMARTAXE to dynamically alter web page content and selectively serve malicious payloads based on the visitor's profile.
2. **Social Engineering via Fake CAPTCHA**: Fake CAPTCHA checks (ClickFix strategy) are injected into the compromised web pages, instructing targeted Ukrainian users to execute a malicious PowerShell command in their terminal to "verify" themselves. The EtherHiding technique is used to retrieve C2 domain names from an Ethereum smart contract specified in the source code.
3. **Initial Execution and Persistence (Windows)**: The user executes the provided PowerShell command. This command is designed to download a malicious VBS file (e.g., named GHETTOVIBE) and place it into the Windows Startup directory, ensuring the malware executes upon system boot or user login.
4. **Payload Delivery and Reconnaissance (Windows)**: Loaders such as FLUIDLEECH (masquerading as antivirus software) and LOADLOOP are deployed to facilitate further malicious activity. A PowerShell script named SCOUTCURL is executed to perform basic reconnaissance, gathering system information from the infected machine. A Python backdoor, FREAKYPOLL, is also delivered.
5. **Initial Access (Android)**: In parallel to Windows attacks, the threat actor distributes backdoored Android APK files via messaging applications. These APKs are disguised as legitimate security tools but contain the COWARDDUCK malware.
6. **Android Malware Execution and Data Collection**: Upon installation, COWARDDUCK collects sensitive data including contacts, specific file types (e.g., .conf, .json, .ovpn, .txt, .doc, .docx, .xls, .xlsx, .pptx, .zip, .rar) from directories like "DCIM", "Documents", "Downloads", "Pictures", and "Alarms", as well as real-time geolocation data.
7. **Command and Control / Exfiltration**: Both Windows and Android malware establish command and control. The COWARDDUCK malware specifically leverages the Dropbox cloud service API for uploading collected files and retrieves further commands or data from an external server or legitimate-looking sites such as steamcommunity[.]com.
8. **Final Objective**: The ultimate goal is data exfiltration and persistent access to victim systems for espionage and intelligence gathering.

## Impact

The campaign has resulted in the compromise of at least 10 websites between June and July 2026, leading to the infection of Ukrainian devices. If successful, attackers gain persistent access, perform reconnaissance, and exfiltrate sensitive data, including user contacts, specific document types (e.g., configurations, VPN files, office documents, archives) from common user directories, and real-time geolocation from Android devices. The use of masqueraded software like FLUIDLEECH increases the risk of undetected infections and broad data theft, enabling sophisticated espionage operations.

## Recommendation

* **Monitor process creation logs for suspicious PowerShell activity**: Deploy the "Detect PowerShell Downloading and Saving VBS to Startup Directory" Sigma rule to identify attempts to download and place malicious VBS files in persistence locations.
* **Monitor file event logs for suspicious VBS file creation**: Implement the "Detect Suspicious VBS File Creation in Startup Directory" Sigma rule to detect the creation or modification of VBS files in critical autostart directories.
* **Educate users about social engineering and suspicious commands**: Train users, particularly in targeted regions, to be wary of executing commands provided by websites, especially those masquerading as CAPTCHA challenges.
* **Enable logging for PowerShell and script execution**: Ensure comprehensive logging for PowerShell, VBScript, and Python execution to capture activities related to SCOUTCURL, FLUIDLEECH, LOADLOOP, and FREAKYPOLL.
* **Implement mobile endpoint detection**: For Android devices, utilize Mobile Threat Defense (MTD) solutions to detect and prevent the installation of unauthorized APKs distributed via messaging apps, such as those containing COWARDDUCK.
