---
title: WebServer Access Logs Deleted
slug: 2026-04-websvr-log-deletion
description: Detection of web server access log deletion across Windows, Linux, and macOS systems indicates potential defense evasion and destruction of forensic evidence by threat actors.
date: "2026-04-01T14:12:42Z"
severities:
  - medium
tags:
  - defense-evasion
  - indicator-removal
  - file-deletion
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
references:
  - https://attack.mitre.org/techniques/T1070/
  - https://attack.mitre.org/techniques/T1070/004/
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_deleting_websvr_access_logs.toml
rules:
  - title: WebServer Access Logs Deleted - Linux
    description: Detects the deletion of web server access logs on Linux systems.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - file_event
      - linux
  - title: WebServer Access Logs Deleted - Windows
    description: Detects the deletion of web server access logs on Windows systems.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This rule detects the deletion of web server access logs, a common tactic used by attackers to cover their tracks and hinder forensic investigations. The deletion of these logs may indicate an attempt to evade detection or destroy forensic evidence on a system. This detection rule focuses on identifying deletion events in directories commonly used for web server logs, such as those used by Apache and IIS. The rule covers multiple operating systems, providing a broad detection capability. This…
