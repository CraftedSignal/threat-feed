---
title: Suspicious PowerShell Command Removing Windows Defender Directory
slug: 2024-01-03-powershell-defender-removal
description: A PowerShell command attempting to remove the Windows Defender directory is detected via PowerShell Script Block Logging, potentially indicating an attacker's attempt to disable endpoint protection for further malicious activities.
date: "2024-01-03T14:22:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - powershell
  - defense-evasion
  - windows-defender
  - endpoint
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/powershell_remove_windows_defender_directory.yml
rules:
  - title: Detect Windows Defender Directory Removal via PowerShell
    description: Detects PowerShell commands attempting to remove the Windows Defender directory by looking for 'rmdir' and the Defender path in Script Block Logging.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows Defender Directory Removal via PowerShell Script Block Logging
    description: Detects PowerShell commands attempting to remove the Windows Defender directory using PowerShell Script Block Logging (EventCode 4104).
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses a specific PowerShell command designed to remove the Windows Defender directory, a critical component of endpoint security on Windows systems. Attackers may attempt to delete or corrupt Windows Defender to bypass its protection mechanisms, allowing them to execute malicious activities undetected. The detection focuses on identifying PowerShell commands containing "rmdir" and targeting the specific path associated with Windows Defender. This activity is typically observed following successful initial access and privilege escalation, as attackers attempt to establish persistence or conduct data exfiltration without interference from security software. The original Splunk analytic was published in May 2026, highlighting the enduring relevance of this technique.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to the system through various methods, such as phishing, exploiting vulnerabilities, or using stolen credentials.
2. **Privilege Escalation:** The attacker elevates their privileges to gain administrative rights, enabling them to perform sensitive actions on the system.
3. **Defense Evasion:** The attacker attempts to disable or impair security controls.
4. **PowerShell Execution:** The attacker leverages PowerShell to execute malicious commands.
5. **Directory Removal:** The attacker executes the `rmdir` command within a PowerShell script, targeting the Windows Defender directory.
6. **Bypass Security Controls:** By removing the Windows Defender directory, the attacker disables real-time protection and other security features.
7. **Lateral Movement/Data Exfiltration:** With endpoint protection disabled, the attacker can move laterally within the network, steal sensitive data, or deploy ransomware without triggering alerts.
8. **Impact:** The attacker achieves their final objective, such as data theft, system disruption, or financial gain, due to the compromised security posture of the endpoint.

## Impact

Successful removal of the Windows Defender directory can have severe consequences. It allows attackers to bypass endpoint protection, leading to undetected malware infections, data breaches, and system compromise. Depending on the attacker's objective, this can result in significant financial losses, reputational damage, and operational disruption. Such techniques have been observed in destructive malware campaigns targeting organizations.

## Recommendation

*   Enable PowerShell Script Block Logging on all endpoints to provide visibility into executed PowerShell commands. Reference: [https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.1/add-other-data-to-splunk-uba/configure-powershell-logging-to-see-powershell-anomalies-in-splunk-uba](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.1/add-other-data-to-splunk-uba/configure-powershell-logging-to-see-powershell-anomalies-in-splunk-uba).
*   Deploy the Sigma rule "Detect Windows Defender Directory Removal via PowerShell" to your SIEM to detect the specific `rmdir` command targeting the Windows Defender directory.
*   Review and tune the provided Sigma rules for false positives in your specific environment.
