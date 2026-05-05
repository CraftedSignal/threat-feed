---
title: CloudZ RAT Abuses Microsoft Phone Link to Steal SMS and OTPs
slug: 2026-05-cloudz-pheno
description: A new version of the CloudZ RAT utilizes the Pheno plugin to hijack Microsoft Phone Link connections, enabling the theft of SMS messages and one-time passwords (OTPs) from victims' mobile devices.
date: "2026-05-05T10:03:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloudz
  - malware
  - rat
  - microsoft-phone-link
  - credential-theft
  - otp
  - sms
vendors:
  - Microsoft
products:
  - Phone Link
  - Windows 10
  - Windows 11
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.bleepingcomputer.com/news/security/cloudz-malware-abuses-microsoft-phone-link-to-steal-sms-and-otps/
rules:
  - title: Detect CloudZ RAT Loader Execution from Temp Directory
    description: Detects the execution of the CloudZ RAT loader from the temporary directory, which is a common tactic used by this malware.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Access to Phone Link SQLite Database
    description: Detects processes attempting to access the Microsoft Phone Link SQLite database file, which may indicate malicious activity related to data theft.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A new variant of the CloudZ remote access tool (RAT) has been observed deploying a novel plugin named Pheno. This plugin specifically targets the Microsoft Phone Link application, pre-installed on Windows 10 and 11, to intercept SMS messages and one-time passwords (OTPs) from connected mobile devices (Android and iOS). The observed intrusion campaign began in January 2026, with researchers assessing that the primary goal of the threat actor is to steal credentials and temporary passcodes. The attacker leverages the Phone Link application's SQLite database, which stores SMS messages and potentially authenticator application notifications, to gain access to sensitive information without directly compromising the mobile device. The CloudZ RAT also uses rotating user-agent strings and anti-caching headers to evade detection.

## Attack Chain

1. The victim executes a fake ScreenConnect update.
2. A Rust-based loader is dropped onto the system.
3. A .NET loader is deployed, which contains anti-analysis checks (time-based sandbox evasion, Wireshark, Fiddler, Procmon, Sysmon).
4. The .NET loader installs the CloudZ RAT.
5. Persistence is established via a scheduled task.
6. The Pheno plugin monitors for active Microsoft Phone Link sessions.
7. Pheno accesses the local SQLite database of the Phone Link application.
8. SMS messages and one-time passwords (OTPs) are stolen from the database, granting the attacker access to sensitive information.

## Impact

Successful exploitation allows attackers to bypass SMS-based multi-factor authentication (MFA) and gain unauthorized access to protected accounts and systems. The impact can include financial fraud, data theft, and further compromise of the victim's digital assets. While the exact number of victims remains unknown, the targeted theft of credentials and OTPs suggests a broad campaign aimed at a wide range of individuals and organizations. The sectors targeted are currently unknown.

## Recommendation

*   Monitor process creation events for execution of processes originating from temporary directories, as this is often where the initial loader may execute from. Deploy the Sigma rule `Detect CloudZ RAT Loader Execution from Temp Directory` to identify this behavior.
*   Implement network monitoring to detect suspicious HTTP traffic from infected hosts. Pay attention to rotating user-agent strings and the presence of anti-caching headers.
*   Consider disabling or restricting the use of Microsoft Phone Link in enterprise environments where SMS-based OTPs are used.
*   Encourage users to switch to authenticator apps that do not rely on SMS or push notifications and to adopt phishing-resistant MFA solutions like hardware security keys.
