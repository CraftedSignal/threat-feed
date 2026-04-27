---
title: Vvveb CMS 1.0.8 Remote Code Execution via Malicious Upload
slug: 2026-04-vvveb-rce
description: Vvveb CMS 1.0.8 is vulnerable to remote code execution, allowing authenticated attackers to upload a PHP webshell with a .phtml extension, bypass extension restrictions, and execute arbitrary operating system commands by requesting the uploaded file.
date: "2026-04-21T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-6249
  - rce
  - web-application
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6249
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6249
rules:
  - title: Detect Suspicious PHTML Request
    description: Detects HTTP requests to .phtml files, which may indicate exploitation of CVE-2026-6249 in Vvveb CMS.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect PHTML Upload in Webserver Logs
    description: Detects successful uploads of `.phtml` files to the webserver, indicating a potential webshell upload.
    platform: sigma
    severity: high
    tactics:
      - persistence
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Vvveb CMS version 1.0.8 is susceptible to a remote code execution (RCE) vulnerability (CVE-2026-6249) due to insufficient input validation in the media upload handler. An authenticated attacker can exploit this flaw by uploading a malicious PHP webshell disguised with a `.phtml` extension, which bypasses the server's intended extension deny-list. The uploaded webshell is then accessible within the publicly available media directory. By crafting a specific HTTP request to access the uploaded…
