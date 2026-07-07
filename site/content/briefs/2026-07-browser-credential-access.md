---
title: Windows Credential Access from Browser Password Store Detection
slug: 2026-07-browser-credential-access
description: This brief describes a detection for suspicious activity on Windows systems where an uncommon or unauthorized process attempts to access browser user data profiles, a common behavior observed in Trojan Stealers like SnakeKeylogger to harvest sensitive browser information and credentials for exfiltration.
date: "2026-07-03T13:11:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - stealer
  - windows
  - endpoint-detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The following analytic identifies a possible non-common browser process accessing its browser user data profile. This tactic/technique has been observed in various Trojan Stealers, such as SnakeKeylogger, which attempt to gather sensitive browser information and credentials.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This tactic/technique has been observed in various Trojan Stealers, such as SnakeKeylogger, which attempt to gather sensitive browser information and credentials as part of their exfiltration strategy.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: This tactic/technique has been observed in various Trojan Stealers, such as SnakeKeylogger, which attempt to gather sensitive browser information and credentials as part of their exfiltration strategy.
    confidence_band: med
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.404keylogger
  - https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/snake-keylogger-malware/
rules:
  - title: Suspicious Process Accessing Browser User Data
    description: Detects non-standard processes attempting to access sensitive browser user data directories, indicative of stealer malware activity like SnakeKeylogger. This rule targets Windows Event Code 4663 for file access.
    platform: sigma
    severity: high
    tactics:
      - collection
      - credential_access
    techniques:
      - T1005
      - T1555
      - T1555.003
    data_sources:
      - file_event
      - windows
      - security
rules_count: 1
---

Threat actors, often employing various Trojan Stealers such as SnakeKeylogger (mentioned in the source), frequently target web browser password stores and user profiles to extract sensitive information and credentials. This activity is a critical step in their data exfiltration strategy, enabling further compromise, financial fraud, or identity theft. The detection focuses on identifying processes that unexpectedly access browser user data directories on Windows systems. It specifically looks for instances where a process other than the legitimate browser application (e.g., `chrome.exe` accessing Chrome's user data) attempts to read or modify these sensitive files, indicating potential malicious activity. The methodology involves monitoring Windows Security Event Log 4663 for object access attempts and comparing the accessing process against a predefined list of allowed browser applications.

## Attack Chain

1.  **Initial Access**: The attacker gains initial access to the victim's system, commonly through phishing emails containing malicious attachments or links, or compromised websites leading to drive-by downloads.
2.  **Execution**: The malicious payload, such as SnakeKeylogger, is executed on the victim's machine, often disguised as a legitimate application or document.
3.  **Discovery**: The malware identifies the presence of installed web browsers and their respective user data directories, which store credentials, cookies, and other sensitive information.
4.  **Credential Access**: The stealer malware initiates access to specific browser user data profiles and password stores (e.g., `Login Data` or `key4.db` files), attempting to read or decrypt stored credentials. This step often involves a non-browser process accessing these files.
5.  **Collection**: Once accessed, the malware collects the harvested credentials, autofill data, cookies, and other valuable information from the browser's database files.
6.  **Exfiltration**: The collected sensitive data is then encrypted and exfiltrated to the attacker's command and control (C2) server over various channels, typically HTTP/HTTPS.
7.  **Impact**: The exfiltrated credentials are used for unauthorized access to online accounts, financial fraud, further network compromise, or sale on underground forums.

## Impact

Successful exploitation results in significant data compromise, including user credentials, financial information, and personal data stored within web browsers. This can lead to unauthorized access to corporate and personal accounts, financial fraud, and identity theft. While the source does not provide specific victim counts, stealer malware campaigns are widespread and impact individuals and organizations across all sectors globally. The exfiltration of credentials can serve as a stepping stone for further lateral movement within an organization's network, escalating the initial compromise to a full-scale breach.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious browser credential access attempts by unauthorized processes.
*   Enable Windows Security Event Log 4663 by configuring "Audit Object Access" for both "Success" and "Failure" events in Group Policy.
*   Tune the `browser_app_list` lookup (or equivalent whitelist) within your detection system to accurately reflect legitimate browser applications and their expected access paths, reducing false positives.
*   Implement strong phishing awareness training for all users to reduce the likelihood of initial access by stealer malware.
