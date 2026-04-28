---
title: Path Traversal Vulnerability in engineer-your-data
slug: 2026-04-engineer-your-data-path-traversal
description: A path traversal vulnerability (CVE-2026-7214) exists in eghuzefa's engineer-your-data up to version 0.1.3, allowing remote attackers to read or write arbitrary files by manipulating the WORKSPACE_PATH argument.
date: "2026-04-28T02:16:08Z"
severities:
  - high
tags:
  - path-traversal
  - vulnerability
vendors:
  - eghuzefa
products:
  - engineer-your-data (<= 0.1.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7214
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7214
rules:
  - title: Detect Engineer-Your-Data Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-7214) in engineer-your-data by identifying requests with path traversal sequences in the WORKSPACE_PATH parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Engineer-Your-Data File Access via Traversal
    description: Detects file access attempts resulting from path traversal in engineer-your-data by monitoring for file access events with unusual paths.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7214, has been discovered in eghuzefa's engineer-your-data, specifically affecting versions up to 0.1.3. This flaw resides within the `read_file`, `write_file`, `list_files`, and `file_inf` functions of the `src/server.py` file. Successful exploitation allows a remote attacker to bypass directory restrictions and access or modify files outside the intended `WORKSPACE_PATH`. The vulnerability's ease of exploitation is increased by the public…
