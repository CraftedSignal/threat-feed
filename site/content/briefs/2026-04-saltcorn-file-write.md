---
title: Unauthenticated Arbitrary File Write in Saltcorn
slug: 2026-04-saltcorn-file-write
description: Unauthenticated attackers can exploit a vulnerability in Saltcorn versions prior to 1.4.5, 1.5.5, and 1.6.0-beta.4 to write arbitrary files and list directory contents on the server.
date: "2026-04-11T12:00:00Z"
severities:
  - critical
tags:
  - saltcorn
  - file-write
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40163
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40163
rules:
  - title: Detect Saltcorn Offline Changes Endpoint Abuse
    description: Detects suspicious POST requests to the /sync/offline_changes endpoint, indicative of CVE-2026-40163 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Saltcorn Upload Finished Endpoint Abuse
    description: Detects suspicious GET requests to the /sync/upload_finished endpoint, often used after exploiting CVE-2026-40163.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Saltcorn, a no-code database application builder, is vulnerable to an unauthenticated arbitrary file write vulnerability. Specifically, versions prior to 1.4.5, 1.5.5, and 1.6.0-beta.4 are affected. An attacker can leverage the POST `/sync/offline_changes` endpoint to create arbitrary directories and write a `changes.json` file with attacker-controlled content anywhere on the server's filesystem. Subsequently, the GET `/sync/upload_finished` endpoint allows an unauthenticated attacker to list…
