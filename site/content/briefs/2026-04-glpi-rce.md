---
title: GLPI Template Injection RCE (CVE-2026-26026)
slug: 2026-04-glpi-rce
description: GLPI versions 11.0.0 to before 11.0.6 are vulnerable to remote code execution (RCE) via template injection by an authenticated administrator, allowing for arbitrary code execution on the server.
date: "2026-04-06T15:17:07Z"
severities:
  - critical
tags:
  - cve-2026-26026
  - template-injection
  - rce
  - glpi
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-26026
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26026
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-2c98-648q-h27h
ioc_counts:
  email: 1
rules:
  - title: Detect GLPI Template Injection Attempts
    description: Detects potential template injection attempts in GLPI by monitoring for specific patterns in HTTP requests to template management endpoints.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect GLPI Template Injection RCE
    description: Detects possible remote code execution via template injection in GLPI by monitoring for commands being executed on the web server.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

GLPI is a widely used open-source IT asset management software. A critical vulnerability, CVE-2026-26026, affects versions 11.0.0 to 11.0.5. This vulnerability stems from a template injection flaw that can be exploited by a logged-in administrator. Successful exploitation allows the administrator to achieve remote code execution (RCE) on the underlying server. The vulnerability was reported on April 6, 2026, and has been patched in version 11.0.6. Organizations using vulnerable versions of GLPI…
