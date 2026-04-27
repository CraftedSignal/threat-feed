---
title: ChurchCRM Pre-Authentication Remote Code Execution Vulnerability (CVE-2026-39337)
slug: 2026-04-churchcrm-rce
description: A critical pre-authentication remote code execution vulnerability in ChurchCRM versions prior to 7.1.0 allows unauthenticated attackers to inject arbitrary PHP code during the initial installation process, leading to complete server compromise.
date: "2026-04-07T18:16:45Z"
severities:
  - critical
tags:
  - rce
  - cve-2026-39337
  - churchcrm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.005
    technique_name: 'Command and Scripting Interpreter: PHP'
cves:
  - id: CVE-2026-39337
    cvss: 10
  - id: CVE-2025-62521
    cvss: 10
    epss: 0.58723
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39337
  - https://github.com/ChurchCRM/CRM/security/advisories/GHSA-pm2v-ggh4-mp7p
rules:
  - title: Detect Suspicious POST Requests to ChurchCRM Install Endpoint
    description: Detects potential exploitation attempts targeting the ChurchCRM setup wizard by monitoring for suspicious POST requests to the installation endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Code Injection via User Agent
    description: Detects potential PHP code injection attempts by monitoring for suspicious User-Agent strings containing PHP tags.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ChurchCRM, an open-source church management system, is vulnerable to a critical pre-authentication remote code execution (RCE) flaw, identified as CVE-2026-39337. This vulnerability affects versions prior to 7.1.0. Unauthenticated attackers can exploit the setup wizard during the initial installation process to inject arbitrary PHP code, leading to complete server compromise. The root cause lies in the insufficient sanitization of the "$dbPassword" variable. This vulnerability is a result of an…
