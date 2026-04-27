---
title: Langflow Multiple Vulnerabilities
slug: 2026-04-langflow-vulns
description: Multiple vulnerabilities in Langflow allow an attacker to manipulate files, disclose sensitive information, or conduct cross-site scripting attacks.
date: "2026-04-20T10:38:57Z"
severities:
  - medium
tags:
  - langflow
  - vulnerability
  - xss
  - file-manipulation
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1565
    technique_name: Data Manipulation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1178
rules:
  - title: Langflow Suspicious File Access
    description: Detects attempts to access sensitive files within a Langflow installation that may indicate file manipulation or information disclosure attempts.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1565
    data_sources:
      - webserver
      - linux
  - title: Langflow Potential XSS Attempt
    description: Detects potential Cross-Site Scripting (XSS) attempts in Langflow by looking for common XSS payloads in request parameters.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Langflow is affected by multiple vulnerabilities that could allow attackers to perform malicious actions. While specific details such as CVEs and exploited versions are not provided, the identified vulnerabilities enable attackers to manipulate files, potentially leading to data corruption or unauthorized modifications. The disclosure of sensitive information is another significant risk, potentially exposing credentials or other confidential data. Finally, the possibility of Cross-Site…
