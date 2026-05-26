---
title: macOS TCC Database Modification for Privacy Control Bypass
slug: 2026-05-tcc-db-modification
description: Adversaries may attempt to bypass macOS privacy controls by directly modifying the Transparency, Consent, and Control (TCC) SQLite database using sqlite3, potentially gaining unauthorized access to sensitive resources.
date: "2026-05-26T07:44:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*
tags:
  - privacy-bypass
  - defense-evasion
  - macos
vendors:
  - Apple
products:
  - macOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2020-9934
    cvss: 5.5
    epss: 0.0244
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/defense_evasion_privacy_controls_tcc_database_modification.toml
  - https://applehelpwriter.com/2016/08/29/discovering-how-dropbox-hacks-your-mac/
  - https://github.com/bp88/JSS-Scripts/blob/master/TCC.db%20Modifier.sh
  - https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8
rules:
  - title: Detect TCC Database Modification via sqlite3
    description: Detects the use of sqlite3 to directly modify the TCC database, potentially bypassing macOS privacy controls.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1548.006
    data_sources:
      - process_creation
      - macos
  - title: Detect TCC Database Modification from Scripting Parent Process
    description: Detects sqlite3 modifying the TCC database with a scripting language as the parent process.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1548.006
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

Attackers may attempt to evade macOS privacy controls by directly modifying the TCC (Transparency, Consent, and Control) database. The TCC database manages application permissions for sensitive resources like the camera, microphone, address book, and calendar. By using tools like `sqlite3` to manipulate this database, adversaries can grant themselves unauthorized access to these resources. This technique has been observed in previous bypasses of the TCC framework, such as the vulnerability described in CVE-2020-9934. This is a post-exploitation technique that can be used to expand access after initial compromise.

## Attack Chain

1.  Initial access is gained to the macOS system through an unrelated exploit (e.g., phishing, software vulnerability).
2.  The attacker executes a shell (e.g., `bash`, `zsh`) or scripting language (e.g., `osascript`, `python`) on the target system.
3.  The attacker uses `sqlite3` to interact with the TCC database located at `/*/Application Support/com.apple.TCC/TCC.db`.
4.  The `sqlite3` process modifies entries in the TCC database to grant unauthorized access to protected resources (camera, microphone, contacts, etc.).
5.  The attacker then executes an application that leverages the newly granted TCC permissions.
6.  The application accesses previously restricted resources without prompting the user for consent.
7.  The attacker exfiltrates the sensitive data obtained through unauthorized access.

## Impact

Successful exploitation allows unauthorized access to sensitive user data protected by macOS privacy controls. This can lead to data theft, privacy violations, and further compromise of the system. This is a local privilege escalation, giving the attacker access to resources normally protected by TCC.

## Recommendation

*   Deploy the Sigma rule `Detect TCC Database Modification via sqlite3` to identify suspicious processes using `sqlite3` to modify the TCC database.
*   Investigate any process execution events where `sqlite3` is used with arguments targeting the TCC database (`/*/Application Support/com.apple.TCC/TCC.db`).
*   Monitor for unusual parent processes of `sqlite3` such as scripting environments (`osascript`, `bash`, `zsh`, `Terminal`, `Python*`) as highlighted in the rule.
*   Investigate processes accessing protected resources (camera, microphone, contacts) without prior user consent.
*   Enable Elastic Defend integration to collect process execution data required for the detection rules.
