---
title: Langflow Multiple Vulnerabilities Allow Information Disclosure, Data Manipulation, and XSS
slug: 2026-03-langflow-vulns
description: An anonymous or authenticated remote attacker can exploit multiple vulnerabilities in Langflow to disclose information, manipulate data, and execute cross-site scripting attacks.
date: "2026-03-30T11:08:56Z"
severities:
  - high
tags:
  - langflow
  - vulnerability
  - xss
  - data-manipulation
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0900
rules:
  - title: Detect HTTP Data Manipulation Methods
    description: Detects potential data manipulation attempts by looking for unusual HTTP request methods like PUT, PATCH, or DELETE against Langflow web server
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect XSS attempts via Script Tags
    description: Detects possible XSS attacks through the use of `<script>` tags in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Langflow is vulnerable to multiple security flaws that could be exploited by remote attackers. These vulnerabilities range from information disclosure to data manipulation and cross-site scripting (XSS). The vulnerabilities can be exploited by both anonymous and authenticated attackers, increasing the potential attack surface. Successful exploitation could lead to unauthorized access to sensitive information, modification of data, and execution of malicious scripts within the context of the…
