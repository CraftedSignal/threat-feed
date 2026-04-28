---
title: Windows AutoLogger Session Tampering Detection
slug: 2024-01-autologger-tampering
description: Attackers may disable AutoLogger sessions by modifying specific registry values to evade detection and prevent security monitoring of early boot activities and system events, a technique observed in intrusions involving IcedID and XingLocker ransomware.
date: "2024-01-03T15:00:00Z"
severities:
  - high
exploited: true
tags:
  - attack.defense-evasion
  - attack.t1562.002
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://twitter.com/MichalKoczwara/status/1553634816016498688
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf
  - https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
  - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
rules:
  - title: Potential AutoLogger Sessions Tampering
    description: Detects tampering with autologger trace sessions which is a technique used by attackers to disable logging.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Wevtutil Usage to Disable Autologger
    description: Detects suspicious usage of wevtutil.exe to disable autologger sessions
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Tampering of Defender Autologger via Registry
    description: Detects tampering with Defender Autologger sessions through registry modifications.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Attackers are increasingly targeting Windows Event Tracing (ETW) and AutoLogger sessions to evade detection. The AutoLogger session is crucial as it records events early in the operating system boot process, providing security solutions with essential telemetry. This technique involves tampering with registry keys associated with AutoLogger sessions, specifically disabling or stopping them by setting DWORD values to 0. This is done to blind security solutions, preventing them from monitoring early boot activities and critical system events. Disabling these sessions allows adversaries to operate with less scrutiny, making it harder to detect malicious activities during the initial phases of a system compromise. This technique has been observed in attacks involving IcedID and XingLocker ransomware.

## Attack Chain

1.  Initial access is achieved through an as-yet-unspecified method (e.g., exploitation, phishing).
2.  The attacker gains administrative privileges on the target system.
3.  The attacker identifies AutoLogger sessions to disable, focusing on those relevant to security monitoring, such as '\EventLog-' or '\Defender'.
4.  The attacker modifies the registry to disable the targeted AutoLogger sessions. This involves setting the 'Enabled' or 'Start' DWORD values under the `HKLM\System\CurrentControlSet\Control\WMI\Autologger` registry key to 0.
5.  The attacker may use tools like `wevtutil.exe` or directly interact with the registry via PowerShell or `cmd.exe` to make these changes.
6.  The security monitoring capabilities reliant on the tampered AutoLogger sessions are effectively impaired or disabled.
7.  With logging impaired, the attacker proceeds with the main objectives, such as lateral movement, data exfiltration, or ransomware deployment, with a reduced risk of detection.
8.  The ultimate goal is to compromise the system, steal data, or deploy ransomware, bypassing security measures that rely on early boot and system event logging.

## Impact

Successful tampering with AutoLogger sessions can significantly reduce the visibility of security solutions, allowing attackers to operate undetected for extended periods. This can lead to delayed incident response, increased dwell time, and greater potential for damage, including data breaches, financial losses, and reputational damage. The sectors most at risk are those heavily reliant on Windows-based systems and proactive security monitoring. The DFIR Report documented a case where adversaries moved from IcedID infection to XingLocker ransomware deployment within 24 hours, highlighting the speed and potential impact of these attacks.

## Recommendation

*   Deploy the Sigma rule `Potential AutoLogger Sessions Tampering` to your SIEM to detect malicious registry modifications related to AutoLogger sessions.
*   Investigate any registry modifications under the `\Control\WMI\Autologger\` path, focusing on changes to `Enabled` or `Start` values, as identified in the Sigma rule.
*   Monitor process creation events for `wevtutil.exe` modifying registry keys related to AutoLogger, as specified in the `filter_main_wevtutil` section of the Sigma rule.
*   Correlate registry modification events with process execution events to identify the source of the tampering, paying close attention to processes originating from the Windows Defender platform, as outlined in the `filter_main_defender` section of the Sigma rule.
*   Implement endpoint detection and response (EDR) solutions with robust registry monitoring capabilities to identify and block unauthorized modifications to AutoLogger settings.
