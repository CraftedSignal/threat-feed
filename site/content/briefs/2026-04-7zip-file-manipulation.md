---
title: 7-Zip Vulnerability Allows File Manipulation
slug: 2026-04-7zip-file-manipulation
description: A remote, anonymous attacker can exploit a vulnerability in 7-Zip to manipulate files, leading to potential data integrity issues.
date: "2026-04-01T09:21:35Z"
severities:
  - medium
tags:
  - 7-zip
  - file-manipulation
  - vulnerability
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0009
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-1750
rules:
  - title: Suspicious 7-Zip Command Line Arguments
    description: Detects 7-Zip execution with suspicious arguments indicative of potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - integrity_impact
    data_sources:
      - process_creation
      - windows
  - title: 7-Zip File Overwrite Detection
    description: Detects file overwrite events performed by 7-Zip that may indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - integrity_impact
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A vulnerability exists in 7-Zip that allows a remote, anonymous attacker to manipulate files. This vulnerability poses a risk to data integrity and could potentially be exploited to introduce malicious content or alter existing files without proper authorization. The specific version(s) of 7-Zip affected are not detailed in the source. Due to the lack of specificity of the source, defenders should treat all versions of 7-Zip as potentially vulnerable until further information is available. This…
