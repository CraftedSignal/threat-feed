---
title: WeGIA Stored Cross-Site Scripting Vulnerability (CVE-2026-40286)
slug: 2026-04-wegia-xss
description: A stored Cross-Site Scripting (XSS) vulnerability exists in WeGIA versions prior to 3.6.10, allowing attackers to inject malicious scripts into the 'Member Name' field during member registration, leading to persistent execution upon user access.
date: "2026-04-17T21:16:34Z"
severities:
  - medium
tags:
  - xss
  - web-application
  - cve-2026-40286
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40286
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40286
  - https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-42rc-rvrx-cmmw
rules:
  - title: Detect WeGIA XSS Attempt via HTTP Request
    description: Detects potential XSS attacks against WeGIA by searching for script tags or event handlers in HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WeGIA XSS Attempt via HTTP Request with Base64 Encoding
    description: Detects potential XSS attacks against WeGIA by searching for base64 encoded script tags or event handlers in HTTP request parameters.
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

WeGIA, a web manager for charitable institutions, is vulnerable to Stored Cross-Site Scripting (XSS) in versions prior to 3.6.10. The vulnerability, identified as CVE-2026-40286, resides in the 'Member Registration' function, specifically the 'Member Name' field. Attackers can inject malicious JavaScript code into this field. Because input is not properly validated and sanitized, the injected script is then stored in the application database.  Any user accessing the profile containing the…
