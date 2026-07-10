---
title: Chrome Credential Theft via Password Store Copying
slug: 2024-01-02-chrome-credential-theft
description: The Braodo stealer and other malware copy Chrome's Local State and Login Data files to temporary directories to steal encrypted user credentials.
date: "2024-01-02T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Braodo Stealer
tags:
  - credential-access
  - malware
  - windows
vendors:
  - Google
products:
  - Chrome
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://x.com/suyog41/status/1825869470323056748
  - https://g0njxa.medium.com/from-vietnam-to-united-states-malware-fraud-and-dropshipping-98b7a7b2c36d
rules:
  - title: Detect Chrome Password Store Files Copied to Temp Directories
    description: Detects the copying of Chrome's Local State and Login Data files to temporary directories.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.003
    data_sources:
      - file_event
      - windows
  - title: Detect Login Data File Copied to Temp Directory
    description: Detects the copying of Chrome's Login Data file to temporary directories.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This threat brief addresses the tactic of copying Chrome's Local State and Login Data files into temporary directories, a technique leveraged by malware such as the Braodo stealer. These files contain sensitive, encrypted user credentials, including saved passwords and login session details. Attackers target these files to decrypt and exfiltrate user credentials, leading to unauthorized access and potential data breaches. This activity is frequently observed in temporary directories, where malware stages and processes stolen data. Defenders need to monitor for this specific file copying behavior to detect and prevent credential theft attempts originating from malware. The behavior has been observed in attacks attributed to the Scattered Lapsus$ Hunters and the BlankGrabber Stealer campaigns.

## Attack Chain

1.  User downloads and executes a malicious file, potentially a software installer or document containing an embedded payload.
2.  The malicious file executes and drops the stealer malware (e.g., Braodo Stealer) onto the system.
3.  The malware begins searching for sensitive files and directories, specifically targeting Chrome's password stores.
4.  The malware copies "Local State" and "Login Data" files from Chrome's user profile directory (e.g., `C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default`) to a temporary directory (e.g., `C:\Users\<username>\AppData\Local\Temp`).
5.  The malware attempts to decrypt the copied credential data using built-in decryption routines or external libraries.
6.  Successful decryption reveals usernames, passwords, and session tokens stored by Chrome.
7.  The stolen credentials are then staged for exfiltration, often compressed or encrypted to evade detection.
8.  The stolen data is exfiltrated to a remote command-and-control server controlled by the attacker.

## Impact

Successful credential theft can lead to significant damage, including unauthorized access to user accounts, data breaches, and financial losses. Victims of the Braodo stealer and similar malware could have their social media, email, banking, and other online accounts compromised. If successful, attackers can gain access to sensitive company resources.

## Recommendation

*   Deploy the Sigma rule "Detect Chrome Password Store Files Copied to Temp Directories" to identify suspicious file copying activity (see "rules" section).
*   Enable Sysmon Event ID 11 (FileCreate) to capture file creation events, which is necessary for the provided Sigma rule (see "rules" section).
*   Investigate any alerts triggered by the Sigma rule by examining the process responsible for the file copying, the destination directory, and the user account involved.
*   Monitor file creation events in temporary directories for unusual file names or file extensions, as attackers may attempt to disguise stolen data (see "rules" section).
