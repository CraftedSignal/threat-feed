---
title: Adobe ColdFusion Improper Input Validation RCE
slug: 2026-04-coldfusion-rce
description: Adobe ColdFusion versions 2023.18, 2025.6, and earlier are vulnerable to improper input validation, potentially leading to arbitrary code execution without user interaction.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-27304
  - coldfusion
  - rce
  - improper-input-validation
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-27304
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27304
  - https://helpx.adobe.com/security/products/coldfusion/apsb26-38.html
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious ColdFusion URI Access
    description: Detects suspicious URI access to ColdFusion server
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - windows
  - title: Detect Suspicious ColdFusion POST Request
    description: Detects suspicious POST requests to ColdFusion server
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - windows
rules_count: 2
---

Adobe ColdFusion versions 2023.18, 2025.6, and earlier are susceptible to an improper input validation vulnerability (CVE-2026-27304). This flaw allows for arbitrary code execution within the security context of the current user. The vulnerability is exploitable remotely and requires no user interaction, increasing the potential impact. This vulnerability was disclosed on April 14, 2026. Given the severity and ease of exploitation, organizations using affected ColdFusion versions should…
