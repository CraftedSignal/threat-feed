---
title: Detection of Taskkill Command to Terminate Browser Processes
slug: 2024-01-03-taskkill-browser-processes
description: This analytic detects the use of the taskkill command to terminate known browser processes, a technique employed by malware such as Braodo stealer to steal credentials by forcefully closing browsers like Chrome, Edge, and Firefox to unlock files containing sensitive information.
date: "2024-01-03T10:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Braodo Stealer
tags:
  - credential-theft
  - malware
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://x.com/suyog41/status/1825869470323056748
  - https://g0njxa.medium.com/from-vietnam-to-united-states-malware-fraud-and-dropshipping-98b7a7b2c36d
rules:
  - title: Detect Taskkill Browser Process Termination
    description: Detects the use of taskkill.exe to terminate common web browser processes, potentially indicating credential theft attempts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Parent Process Taskkill Browser Termination
    description: Detects parent process that triggers taskkill.exe to terminate common web browser processes, potentially indicating credential theft attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies the use of `taskkill.exe` to terminate several known browser processes. This technique is often employed by malware, such as the Braodo stealer, to steal credentials. By forcefully closing browsers like Chrome, Edge, and Firefox, the malware can unlock files that store sensitive information, such as passwords and login data. The detection focuses on identifying `taskkill` commands targeting these browsers, which indicates potentially malicious intent. Early detection allows security teams to investigate and prevent further credential theft and system compromise. This behavior has been observed in malware campaigns originating from Vietnam, targeting credentials for fraud and dropshipping operations.

## Attack Chain

1.  A malicious process is initiated on the system, often through social engineering or exploitation of a vulnerability.
2.  The malicious process executes `taskkill.exe` with specific arguments targeting browser processes.
3.  `taskkill.exe` attempts to terminate processes named `chrome.exe`, `firefox.exe`, `brave.exe`, `opera.exe`, `msedge.exe`, or `chromium.exe`.
4.  If successful, the browser processes are terminated abruptly.
5.  The malware gains access to browser data files, which are normally locked while the browsers are running.
6.  The malware extracts sensitive data from these files, such as usernames, passwords, and cookies.
7.  The stolen credentials are used for unauthorized access to accounts or services.
8.  The attacker exfiltrates the stolen data to a remote server for further malicious activity.

## Impact

Successful execution of this attack chain leads to the theft of sensitive credentials stored by web browsers. This can result in unauthorized access to user accounts, financial fraud, and identity theft. Victims may experience significant financial losses and reputational damage. The technique is used by malware such as Braodo stealer, which is known to target credentials for fraud and dropshipping operations.

## Recommendation

*   Deploy the Sigma rule `Detect Taskkill Browser Process Termination` to your SIEM and tune for your environment.
*   Enable Sysmon EventID 1 logging to capture process creation events, a requirement for the Sigma rule.
*   Investigate any instances of `taskkill.exe` being used to terminate browser processes, as identified by the Sigma rule.
*   Monitor endpoint processes for unusual behavior, particularly processes attempting to access browser data files.
