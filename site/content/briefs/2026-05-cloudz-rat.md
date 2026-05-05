---
title: CloudZ RAT Abusing Windows Phone Link to Steal OTPs
slug: 2026-05-cloudz-rat
description: An unknown attacker is using the CloudZ RAT and its Pheno plugin to hijack the Microsoft Phone Link application and intercept SMS and OTP messages from connected mobile devices, active since at least January 2026.
date: "2026-05-05T10:01:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloudz
  - rat
  - pheno
  - phone-link
  - otp
  - credential-theft
vendors:
  - Microsoft
products:
  - Windows 10
  - Windows 11
  - Windows Phone Link
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
references:
  - https://blog.talosintelligence.com/cloudz-pheno-infostealer/
rules:
  - title: Detect Suspicious RegAsm Execution for Persistence
    description: Detects the execution of regasm.exe (Microsoft .NET Framework Assembly Registration Utility) to load a .NET assembly from an unusual location, which is used for persistence by the CloudZ RAT.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Detect .NET Loader Download via Curl
    description: Detects the download of the .NET loader from an attacker-controlled staging server using curl.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Cisco Talos discovered an intrusion campaign, active since at least January 2026, involving the deployment of the CloudZ RAT and a novel plugin named "Pheno". The attackers are leveraging these tools to steal credentials and potentially one-time passwords (OTPs) by abusing the Microsoft Phone Link application in Windows. CloudZ utilizes the Pheno plugin to monitor and hijack the PC-to-phone bridge established by Phone Link. This allows the attacker to scan for active Phone Link processes and intercept sensitive mobile data, such as SMS messages and OTPs, without directly infecting the mobile device. The CloudZ RAT also employs various anti-analysis techniques, including dynamic execution of critical functions in memory and checks to evade debuggers and sandbox environments.

## Attack Chain

1.  The attack begins with an unknown initial access vector, leading to the execution of a fake ScreenConnect application update.
2.  This malicious executable drops and executes an intermediate .NET loader executable.
3.  The .NET loader decrypts and deploys the modular CloudZ RAT onto the victim's machine.
4.  Upon execution, the CloudZ RAT decrypts its configuration data and establishes an encrypted connection to its command-and-control (C2) server.
5.  CloudZ exfiltrates credentials from the victim's machine browser data and downloads and implants the Pheno plugin.
6.  The Pheno plugin performs reconnaissance of the Microsoft Phone Link application on the victim machine and writes reconnaissance data to an output file.
7.  CloudZ reads the Phone Link application data from the staging folder.
8.  CloudZ sends the exfiltrated credentials, along with the data obtained from the Phone Link application, to the C2 server, potentially compromising SMS-based OTP messages and other authenticator application notification messages.

## Impact

This campaign poses a significant threat to users of the Microsoft Phone Link application, potentially exposing sensitive information, including SMS-based OTPs, to unauthorized access. Successful exploitation can lead to account compromise, financial fraud, and other malicious activities. The number of victims and specific sectors targeted are currently unknown, but the potential for widespread impact is considerable given the prevalence of Windows 10 and 11 and the use of OTPs for multi-factor authentication.

## Recommendation

*   Monitor process creation events for execution of `regasm.exe` with command-line arguments pointing to unusual locations, especially within the `C:\ProgramData` directory, using the Sigma rule "Detect Suspicious RegAsm Execution for Persistence".
*   Detect connections to the known malicious URL `hxxps[://]calm-wildflower-1349[.]hellohiall[.]workers[.]dev` at the network level or endpoint using a network connection monitoring tool or web proxy.
*   Enable process monitoring and file access auditing for the Microsoft Phone Link application database files (e.g., "PhoneExperiences-*.db") to detect unauthorized access or modification by suspicious processes.
