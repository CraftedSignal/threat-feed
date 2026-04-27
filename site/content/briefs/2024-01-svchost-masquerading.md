---
title: Potential Svchost Masquerading
slug: 2024-01-svchost-masquerading
description: This rule detects attempts to masquerade as the Service Host process `svchost.exe` to evade detection and blend in with normal system activity by detecting svchost.exe processes running from non-standard locations.
date: "2024-01-03T10:00:00Z"
severities:
  - high
tags:
  - defense-evasion
  - masquerading
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1036/005/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_masquerading_as_svchost.toml
rules:
  - title: Potential Svchost Masquerading
    description: Detects svchost.exe processes running from non-standard locations.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1036.005
    data_sources:
      - process_creation
      - windows
  - title: Svchost Masquerading with Suspicious Parent
    description: Detects svchost.exe processes running from non-standard locations with suspicious parent processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1036.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to masquerade as the Service Host process (`svchost.exe`) to evade detection and blend in with normal system activity. This technique involves renaming a malicious executable to `svchost.exe` and placing it outside of standard Windows directories. Masquerading allows malicious processes to hide among legitimate system processes, making them harder to detect using traditional methods. This activity is often part of a larger attack chain, potentially leading to further…
