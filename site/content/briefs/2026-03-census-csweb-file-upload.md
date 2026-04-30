---
title: Census CSWeb 8.0.1 Arbitrary File Upload Vulnerability
slug: 2026-03-census-csweb-file-upload
description: A remote, authenticated attacker can exploit an arbitrary file upload vulnerability in Census CSWeb 8.0.1 (CVE-2025-60947) to upload malicious files, potentially leading to remote code execution.
date: "2026-03-24T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - file-upload
  - remote-code-execution
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-60947
  - https://github.com/csprousers/csweb/commit/eba0b59a243390a1a4f9524cce6dbc0314bf0d91
  - https://github.com/hx381/cspro-exploits
rules:
  - title: Detect Suspicious File Uploads via Webserver Logs
    description: Detects attempts to upload files with suspicious extensions via web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Web Shell Uploads
    description: Detects potential web shell uploads by monitoring for POST requests with common web shell file extensions and a 200 OK response.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Census CSWeb 8.0.1 is vulnerable to an arbitrary file upload vulnerability (CVE-2025-60947). An authenticated attacker can leverage this vulnerability to upload malicious files to the server. Successful exploitation could allow the attacker to achieve remote code execution on the targeted system. The vulnerability was patched in version 8.1.0 alpha. This poses a significant risk to organizations using the affected CSWeb version, potentially leading to data breaches, system compromise, and…
