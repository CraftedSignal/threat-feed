---
title: IBM App Connect Enterprise Multiple Vulnerabilities
slug: 2026-04-ibm-app-connect
description: A remote, anonymous attacker can exploit multiple vulnerabilities in IBM App Connect Enterprise to cause a denial-of-service condition or bypass security measures, enabling cross-site scripting attacks.
date: "2026-04-01T09:21:09Z"
severities:
  - high
tags:
  - vulnerability
  - dos
  - xss
  - ibm
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0772
rules:
  - title: Detect Potential XSS Attempt in HTTP Request
    description: Detects potential Cross-Site Scripting (XSS) attempts by identifying common XSS payloads in HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP 503 Errors Potentially Indicating DoS
    description: Detects a high number of HTTP 503 (Service Unavailable) errors from a single source IP, potentially indicating a Denial-of-Service attack.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities have been identified in IBM App Connect Enterprise that could be exploited by a remote, anonymous attacker. Successful exploitation could lead to a denial-of-service (DoS) condition, rendering the application unavailable, or the bypass of existing security measures. The security bypass could enable cross-site scripting (XSS) attacks, potentially compromising user data and system integrity. IBM App Connect Enterprise is an integration platform that connects applications…
