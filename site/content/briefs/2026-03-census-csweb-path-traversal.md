---
title: Census CSWeb 8.0.1 Path Traversal Vulnerability (CVE-2025-60946)
slug: 2026-03-census-csweb-path-traversal
description: CVE-2025-60946 details a vulnerability in Census CSWeb 8.0.1, where arbitrary file path input is permitted, allowing a remote, authenticated attacker to access unintended file directories.
date: "2026-03-24T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - cve-2025-60946
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-60946
  - https://github.com/csprousers/csweb/commit/eba0b59a243390a1a4f9524cce6dbc0314bf0d91
  - https://github.com/hx381/cspro-exploits
  - https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-079-01.json
rules:
  - title: Detect Census CSWeb Path Traversal Attempt
    description: Detects potential path traversal attempts against Census CSWeb by identifying common traversal sequences in web server logs.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Census CSWeb Path Traversal in Request
    description: Detects path traversal attempts in web requests targeting Census CSWeb by searching for encoded traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Census CSWeb 8.0.1 is vulnerable to path traversal (CVE-2025-60946). A remote, authenticated attacker can supply arbitrary file path input and access unintended file directories. This allows the attacker to read sensitive files or potentially overwrite existing files, leading to information disclosure or code execution. The vulnerability was reported on March 23, 2026, and is fixed in version 8.1.0 alpha. Defenders should upgrade to the patched version to prevent potential exploitation of this…
