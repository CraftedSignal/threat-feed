---
title: Generic Ransomware Detection on macOS
slug: 2024-01-ransomware-detection
description: This brief outlines a method for generically detecting ransomware on macOS by monitoring file I/O events and identifying the rapid creation of encrypted files by untrusted processes, as proposed by Objective-See.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ransomware
  - malware
  - macos
vendors:
  - Apple
  - Kaspersky
  - Palo Alto Networks
products:
  - Transmission
  - OSX/FileCoder
affected_os:
  - OS X
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://objective-see.org/blog/blog_0x0F.html
rules:
  - title: macOS Ransomware File Creation
    description: Detects rapid creation or modification of files with potential ransomware extensions by untrusted processes.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - file_event
      - macos
  - title: Untrusted Process Creating Encrypted Files
    description: Detects an untrusted process rapidly creating encrypted files by monitoring process creation and file modification events.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

This research, published by Objective-See in April 2016, explores techniques for generic ransomware detection on macOS. The core concept revolves around monitoring file system events to identify processes rapidly creating encrypted files. The research highlights the increasing prevalence of ransomware, even on macOS, citing examples like KeRanger, which infected thousands of Mac users via a compromised version of Transmission. The author proposes a detection mechanism that leverages file I/O monitoring, encryption detection, and trust assessment of processes to identify and potentially block ransomware activity. The aim is to provide a proactive defense against new and unknown ransomware variants that evade traditional signature-based antivirus solutions. This research has version 1.0, meaning, likely room for improvement.

## Attack Chain

1.  The user downloads and executes a malicious application, or a legitimate application compromised with ransomware (e.g., KeRanger in Transmission).
2.  The ransomware component initiates, often after a period of dormancy.
3.  The ransomware process begins enumerating files within the user's home directory (/Users) and potentially other locations like /Volumes.
4.  For each targeted file, the ransomware process opens the file for reading and writing (O_RDWR).
5.  The process reads the file content into memory.
6.  The ransomware uses a cryptographic algorithm (e.g., libsodium) to encrypt the file content.
7.  The encrypted content is written back to the file, overwriting the original data. The encrypted files may have a new extension, such as ".encrypted".
8.  A ransom note (e.g., README_FOR_DECRYPT.txt) is created in directories containing encrypted files, providing instructions for payment and decryption.

## Impact

A successful ransomware attack can result in the complete loss of access to user data.  Organizations and individuals affected by ransomware face potential financial losses due to ransom payments, business disruption, and recovery costs. The research mentions that CryptoWall 3.0 ransomware operators made $325 million, highlighting the financial incentives driving ransomware development and deployment. The KeRanger ransomware infected thousands of Mac users.

## Recommendation

*   Deploy the Sigma rule `macOS Ransomware File Creation` to detect suspicious file modifications by untrusted processes within user directories based on file I/O events.
*   Monitor process creation events and correlate them with file modification events, specifically targeting processes not signed by Apple or baselined using the `Untrusted Process Creating Encrypted Files` Sigma rule.
*   Implement file integrity monitoring (FIM) on critical user directories to detect unauthorized file modifications, complementing the generic ransomware detection approach.
