---
title: Suspicious Modification of Sensitive Linux Files
slug: 2024-01-sensitive-file-modification
description: This threat brief covers the detection of suspicious processes modifying sensitive files on Linux systems, potentially indicating malicious attempts to persist, escalate privileges, or disrupt system operations.
date: "2024-01-03T15:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - file-integrity
  - privilege-escalation
  - persistence
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_sensitive_file_access.yml
  - https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview#which-files-should-i-monitor
rules:
  - title: Potential Suspicious Change To Sensitive/Critical Files via Redirection
    description: Detects changes to sensitive and critical files using command-line utilities with output redirection.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1565.001
    data_sources:
      - process_creation
      - linux
  - title: Potential Suspicious Change To Sensitive/Critical Files via Text Editors
    description: Detects changes to sensitive and critical files using text editors like vi, vim, nano, or emacs.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1565.001
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Sed Usage on mdadm.conf
    description: Detects suspicious usage of sed to modify mdadm.conf, excluding legitimate mdadm updates.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1565.001
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Attackers often target sensitive and critical files on Linux systems to maintain persistence, escalate privileges, or disrupt system operations. These files include system configuration files, authentication files, and critical application files. Monitoring changes to these files is crucial for detecting malicious activity. This brief focuses on identifying suspicious process executions that could indicate unauthorized modification of sensitive files. The detection strategy covers processes…
