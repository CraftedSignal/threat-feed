---
title: Persistence via Microsoft Office Add-Ins File Creation
slug: 2026-05-persistence-office-addins
description: This rule detects attempts to establish persistence on Windows endpoints by abusing Microsoft Office add-ins through the creation of malicious files in Office startup directories.
date: "2026-05-12T18:39:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - ms-office
  - add-ins
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Office AddIns
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - CrowdStrike FDR
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_ms_office_addins_file.toml
rules:
  - title: Persistence via Microsoft Office AddIns File Creation
    description: Detects the creation of Microsoft Office add-ins in startup directories to establish persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Suspicious Process Writing Office Addin
    description: Detects a suspicious process writing an Office addin file type.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The rule identifies potential persistence mechanisms employed by attackers leveraging Microsoft Office add-ins. It focuses on the creation of specific file types, including `.wll`, `.xll`, `.ppa`, `.ppam`, `.xla`, and `.xlam`, in directories such as `C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Word\\Startup\\*`, `C:\\Users\\*\\AppData\\Roaming\\Microsoft\\AddIns\\*`, and `C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\*`. The detection logic also incorporates Crowdstrike specific conditions using NT Object paths. This technique allows malicious actors to execute code each time the corresponding Microsoft Office application starts, achieving persistence on the system. This activity matters because attackers can gain a foothold within an organization and maintain unauthorized access even after system reboots.

## Attack Chain

1.  The attacker gains initial access to the system, potentially through phishing or exploitation of a vulnerability.
2.  The attacker identifies a user's profile on the targeted Windows system.
3.  The attacker writes a malicious Office add-in file (e.g., a `.wll`, `.xll`, `.ppa`, `.ppam`, `.xla`, or `.xlam` file) to one of the Office startup directories, such as `C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Word\\Startup\\*`.
4.  The attacker may use a dropper or installer to place the malicious file in the startup directory.
5.  The system restarts or the user launches the corresponding Microsoft Office application (Word, Excel, PowerPoint).
6.  The Office application loads the malicious add-in file from the startup directory.
7.  The malicious add-in executes its payload, providing the attacker with persistent access to the system.
8.  The attacker can now perform various malicious activities, such as data exfiltration, lateral movement, or further exploitation.

## Impact

Successful exploitation can lead to persistent unauthorized access to the compromised system. This allows the attacker to maintain a foothold within the network, potentially leading to data theft, disruption of services, or further propagation of malware. The compromised system could be leveraged as a staging point for lateral movement or for launching attacks against other internal resources.

## Recommendation

*   Enable Sysmon Event ID 11 (File Create) logging to capture file creation events, especially in Office startup directories, to activate the detection logic.
*   Deploy the Sigma rule "Persistence via Microsoft Office AddIns File Creation" to your SIEM and tune for your environment to detect malicious add-in creation.
*   Monitor process creation events for Microsoft Office applications (WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE) loading add-ins from untrusted locations.
*   Restrict write access to Office startup directories and add-in loader locations to prevent unauthorized file creation.
*   Investigate alerts related to file creations described by `file.path` and `file.extension` in the rule query.
