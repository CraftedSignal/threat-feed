---
title: AGiXT Path Traversal Vulnerability (CVE-2026-39981)
slug: 2026-04-agixt-path-traversal
description: AGiXT versions prior to 1.9.2 are vulnerable to path traversal (CVE-2026-39981) due to insufficient validation in the safe_join() function, allowing authenticated attackers to read, write, or delete arbitrary files.
date: "2026-04-09T18:17:02Z"
severities:
  - critical
tags:
  - path-traversal
  - cve
  - agixt
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-39981
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39981
  - https://github.com/Josh-XT/AGiXT/commit/2079ea5a88fa671a921bf0b5eba887a5a1b73d5f
  - https://github.com/Josh-XT/AGiXT/releases/tag/v1.9.2
  - https://github.com/Josh-XT/AGiXT/security/advisories/GHSA-5gfj-64gh-mgmw
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Detect AGiXT Path Traversal Attempt via Web Logs
    description: Detects potential path traversal attempts targeting AGiXT by monitoring web server logs for suspicious URL patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect AGiXT Arbitrary File Write via Web Logs
    description: Detects potential arbitrary file write attempts by monitoring web server logs for suspicious POST requests with file extensions commonly used for configuration or code.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AGiXT, a dynamic AI Agent Automation Platform, contains a critical vulnerability (CVE-2026-39981) affecting versions prior to 1.9.2. The vulnerability lies in the `safe_join()` function within the `essential_abilities` extension. This function fails to adequately validate file paths, creating an opportunity for authenticated attackers to perform directory traversal attacks. By exploiting this flaw, an attacker can manipulate file paths to access files outside the designated agent workspace…
