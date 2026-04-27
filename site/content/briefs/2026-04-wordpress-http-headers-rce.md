---
title: WordPress HTTP Headers Plugin Remote Code Execution via File Path Manipulation (CVE-2026-4132)
slug: 2026-04-wordpress-http-headers-rce
description: The HTTP Headers WordPress plugin is vulnerable to remote code execution (RCE) due to insufficient validation of the htpasswd file path and lack of sanitization of the username, allowing authenticated administrators to write arbitrary code to the server.
date: "2026-04-22T09:16:24Z"
severities:
  - critical
tags:
  - wordpress
  - rce
  - plugin
  - cve-2026-4132
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1565
    technique_name: Data Manipulation
cves:
  - id: CVE-2026-4132
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4132
rules:
  - title: Detect PHP File Creation in Web Directories
    description: Detects the creation of PHP files in common web directories by the web server process, potentially indicating malicious file upload or RCE attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1565
    data_sources:
      - file_event
      - linux
  - title: Detect Unsanitized Username Injection in HTTP Headers Plugin htpasswd File
    description: Detects modifications to the .htpasswd file with usernames containing PHP tags, potentially indicating a RCE attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1565
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The HTTP Headers plugin for WordPress, versions up to and including 1.19.2, is vulnerable to remote code execution (RCE) due to a file path manipulation vulnerability (CVE-2026-4132). This vulnerability stems from the plugin's insufficient validation of the 'hh_htpasswd_path' option, which controls the location of the .htpasswd file. Furthermore, the 'hh_www_authenticate_user' option, used for setting the username for HTTP Basic Authentication, lacks proper sanitization. This allows attackers…
