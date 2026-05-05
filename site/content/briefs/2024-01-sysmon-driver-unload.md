---
title: Sysmon Driver Unload via fltMC.exe
slug: 2024-01-sysmon-driver-unload
description: Detection of the Sysmon filter driver being unloaded via `fltMC.exe`, which can blind security monitoring and allow malicious actions to go undetected.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - impair-defenses
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Sysmon
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.ired.team/offensive-security/defense-evasion/unloading-sysmon-driver
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/unload_sysmon_filter_driver.yml
rules:
  - title: Sysmon Driver Unload via FltMC.exe
    description: Detects the use of fltMC.exe to unload the Sysmon filter driver.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Parent Process of fltMC.exe
    description: Detects suspicious parent processes executing fltMC.exe, which could indicate malicious activity related to disabling the Sysmon driver.
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

Attackers may attempt to disable or uninstall security tools like Sysmon to evade detection and hide malicious activities on a compromised system. This is achieved by unloading the Sysmon filter driver using `fltMC.exe`, a legitimate Windows utility. Once Sysmon is disabled, adversaries can execute further attacks without being logged, potentially leading to data breaches, privilege escalation, or persistent access within the environment. This technique is significant because it directly impacts the visibility and effectiveness of security monitoring.

## Attack Chain

1. The attacker gains initial access to the system through various means (e.g., compromised credentials, exploiting vulnerabilities, or social engineering).
2. The attacker escalates privileges if necessary to gain administrative rights on the system.
3. The attacker uses `fltMC.exe` to unload the Sysmon filter driver (`SysmonDrv`). The command executed is typically `fltMC.exe unload SysmonDrv`.
4. The operating system processes the `fltMC.exe` command, removing the Sysmon filter driver from the system.
5. Sysmon ceases to collect event data as its driver is no longer active.
6. The attacker executes malicious commands, scripts, or binaries without being logged by Sysmon.
7. The attacker establishes persistence, moves laterally, exfiltrates data, or achieves other objectives without Sysmon alerting.

## Impact

Successful unloading of the Sysmon driver allows attackers to operate without being detected by Sysmon. This can lead to a complete loss of visibility into attacker activities, enabling data breaches, privilege escalation, and persistent access. The impact is significant as it directly undermines the effectiveness of security monitoring and incident response capabilities.

## Recommendation

*   Deploy the Sigma rule `Sysmon Driver Unload via FltMC.exe` to detect the execution of `fltMC.exe` with the `unload` and `SysmonDrv` parameters.
*   Enable Sysmon process creation logging (Event ID 1) to ensure the required data is available for detection.
*   Investigate any instances of `fltMC.exe` being used to unload drivers, especially if the parent process is suspicious.
*   Consider implementing host-based intrusion prevention system (HIPS) rules to prevent the execution of `fltMC.exe` or restrict its usage to authorized administrators.
