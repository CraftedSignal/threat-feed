---
title: Detecting Windows Screen Capture via PowerShell Script
slug: 2024-01-03-powershell-screen-capture
description: This analytic detects the execution of a PowerShell script designed to capture screen images on a host, leveraging PowerShell Script Block Logging to identify specific script block text patterns associated with screen capture activities, potentially indicating an attempt to exfiltrate sensitive information via desktop screenshots.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - screen-capture
  - powershell
  - exfiltration
  - windows
  - apt
vendors:
  - Microsoft
products:
  - Windows
  - PowerShell
  - .NET Framework
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
references:
  - https://twitter.com/_CERT_UA/status/1620781684257091584
  - https://cert.gov.ua/article/3761104
rules:
  - title: Detect PowerShell Screen Capture via Drawing Methods
    description: Detects PowerShell scripts using drawing methods to capture screenshots.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1113
    data_sources:
      - powershell
      - windows
  - title: Detect PowerShell Screen Capture via Windows API Calls
    description: Detects PowerShell scripts using Windows API calls (Add-Type) to capture screenshots.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1113
    data_sources:
      - powershell
      - windows
rules_count: 2
---

This detection focuses on identifying PowerShell scripts used to capture screen images on Windows systems. The technique involves leveraging the .NET framework's drawing capabilities within PowerShell to create screenshots. While legitimate uses exist, adversaries can employ this method to exfiltrate sensitive visual data from compromised systems. The detection relies on PowerShell Script Block Logging (EventCode 4104) to analyze script content for specific patterns related to screen capture functions. Successful execution can lead to unauthorized access to sensitive information displayed on the screen, potentially leading to data breaches. Several threat actors, including APT37 (Rustonotto), Winter Vivern, Water Gamayun, and BlankGrabber Stealer, have been known to utilize PowerShell for malicious activities, including information gathering.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the target system, potentially through methods like exploiting vulnerabilities or using stolen credentials.
2.  **Privilege Escalation (Optional):** Depending on the attacker's initial privileges, they may attempt to escalate privileges to gain necessary permissions for executing the screen capture script effectively.
3.  **PowerShell Execution:** The attacker executes a PowerShell script on the compromised host.
4.  **Screen Capture Implementation:** The PowerShell script utilizes .NET libraries (`System.Drawing`) to capture screen images. The script often contains commands that create a `Bitmap` object, get a `Graphics` object from it, and then use `CopyFromScreen` to copy the screen content.
5.  **Data Staging:** The captured screenshot is saved to a file on the local system, often in a common image format like PNG or JPG.
6.  **Obfuscation/Encoding (Optional):** The attacker might encode or obfuscate the captured image to evade detection during exfiltration.
7.  **Data Exfiltration:** The screenshot is exfiltrated from the compromised system using various methods, such as uploading to a remote server, sending via email, or transferring through other network protocols.
8.  **Cleanup:** The attacker might delete the PowerShell script and the captured screenshot to remove traces of their activity.

## Impact

Successful exploitation allows attackers to capture sensitive information displayed on the screen, including credentials, financial data, personal information, and confidential documents. This can lead to data breaches, identity theft, financial loss, and reputational damage. The number of victims can vary depending on the scope of the attack, ranging from individual users to entire organizations. Targeted sectors may include finance, healthcare, government, and technology.

## Recommendation

*   Enable PowerShell Script Block Logging (EventCode 4104) to collect the necessary data for the provided Sigma rules and Splunk search (https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.1/add-other-data-to-splunk-uba/configure-powershell-logging-to-see-powershell-anomalies-in-splunk-uba).
*   Deploy the Sigma rule "Detect PowerShell Screen Capture via Drawing Methods" to identify screen capture attempts based on specific drawing API calls within PowerShell scripts.
*   Investigate any identified PowerShell screen capture activity to determine its legitimacy and potential impact.
*   Block execution of unsigned or untrusted PowerShell scripts to prevent malicious code from running on endpoints.
