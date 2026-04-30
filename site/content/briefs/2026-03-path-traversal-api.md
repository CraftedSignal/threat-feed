---
title: Path Traversal Vulnerability in API File Upload Endpoint (CVE-2026-5027)
slug: 2026-03-path-traversal-api
description: The 'POST /api/v2/files' endpoint is vulnerable to path traversal due to improper sanitization of the 'filename' parameter, potentially allowing attackers to write files to arbitrary locations on the filesystem and achieve remote code execution.
date: "2026-03-27T15:17:04Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - file-upload
  - cve-2026-5027
  - web-application
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5027
  - https://www.tenable.com/security/research/tra-2026-26
rules:
  - title: Detect Suspicious File Upload with Path Traversal
    description: Detects potential path traversal attempts in file upload requests by checking for '../' sequences in the filename.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Creation from Web Server
    description: Detects files being created in sensitive directories by the web server process, which may indicate successful path traversal exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-5027 exposes a critical vulnerability in the 'POST /api/v2/files' endpoint, where the 'filename' parameter within multipart form data is not properly sanitized. This flaw allows an attacker to manipulate the filename by injecting path traversal sequences such as '../', leading to the ability to write files to arbitrary locations on the server's filesystem. This vulnerability was reported by Tenable Network Security, Inc. and has a CVSS v3.1 base score of 8.8 (HIGH). Successful…
