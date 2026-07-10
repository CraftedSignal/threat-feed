---
title: Malicious Termination of Browser Processes via Taskkill
slug: 2024-01-browser-process-termination
description: The use of taskkill to forcibly terminate browser processes such as Chrome, Firefox, and Edge, often associated with credential-stealing malware like Braodo stealer, is detected, allowing it to unlock and steal sensitive browser data.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Braodo Stealer
tags:
  - credential-theft
  - taskkill
  - braodo-stealer
  - windows
vendors:
  - Google
  - Microsoft
  - Brave Software
  - Opera Software
  - Mozilla
products:
  - Chrome
  - Edge
  - Brave
  - Opera
  - Firefox
  - Chromium
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://x.com/suyog41/status/1825869470323056748
  - https://g0njxa.medium.com/from-vietnam-to-united-states-malware-fraud-and-dropshipping-98b7a7b2c36d
rules:
  - title: Detect Browser Process Termination via Taskkill
    description: Detects the use of the taskkill command to terminate common browser processes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Parent Process Terminating Browser Processes via Taskkill
    description: Detects when a non-standard parent process is killing browser processes via taskkill, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on the detection of malicious activity where the `taskkill` command is used to terminate popular web browser processes on Windows systems. This technique is notably employed by the Braodo stealer malware, as well as other malware families targeting credentials. The Braodo stealer and similar malware forcibly close browsers like Chrome, Edge, Brave, Opera, Firefox, and Chromium, in order to unlock files containing sensitive data such as saved passwords, cookies, and login data. This allows the malware to then steal this data. The detection focuses on identifying `taskkill` commands specifically targeting these browser executables, which is a strong indicator of malicious intent. Identifying this activity early allows security teams to investigate potential credential theft and broader system compromise. The referenced research indicates this technique has been observed being used since at least late 2025.

## Attack Chain

1.  Initial Access: The user inadvertently downloads and executes a malicious executable, possibly delivered through social engineering or drive-by download.
2.  Persistence: The malware establishes persistence on the system, ensuring it remains active even after a reboot. This may involve creating registry keys or scheduled tasks.
3.  Process Injection/Execution: The malware injects malicious code into a legitimate process or executes a new process to carry out its activities.
4.  Browser Enumeration: The malware enumerates the running processes on the system to identify instances of targeted browsers (Chrome, Firefox, Edge, etc.).
5.  Taskkill Execution: The malware executes the `taskkill` command with the `/F` (force) option to terminate the identified browser processes. For example, `taskkill /F /IM chrome.exe`.
6.  Data Access: With the browser processes terminated, the malware accesses the browser's data files (e.g., credential databases, cookies) without the browser's protection mechanisms in place.
7.  Credential Theft: The malware extracts sensitive information such as usernames, passwords, and session cookies from the accessed data files.
8.  Data Exfiltration: The stolen credentials and other sensitive data are exfiltrated to a remote command-and-control server controlled by the attacker.

## Impact

Successful execution of this attack chain can result in the theft of sensitive user credentials, including usernames, passwords, and session cookies. This can lead to unauthorized access to user accounts, financial fraud, identity theft, and further compromise of the targeted system and network. This technique is actively used by credential stealers and has been associated with data theft affecting potentially thousands of users.

## Recommendation

*   Deploy the "Detect Browser Process Termination via Taskkill" Sigma rule to your SIEM to detect the malicious use of the `taskkill` command targeting browser processes.
*   Monitor process creation events for the execution of `taskkill.exe` with command-line arguments targeting common browser executables. Enable Sysmon EventID 1 for process creation logging to capture this activity.
*   Review the references provided in this brief to understand the context and tactics of the threat actor, and assess your organization's risk profile accordingly.
*   Educate users about the risks of downloading and executing untrusted files to prevent initial infection.
