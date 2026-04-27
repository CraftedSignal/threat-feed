---
title: Multiple Vulnerabilities in libpng Allow Remote Code Execution and Denial of Service
slug: 2026-04-libpng-vulns
description: A remote, anonymous attacker can exploit multiple vulnerabilities in libpng to execute arbitrary program code or cause a denial of service.
date: "2026-04-01T09:21:36Z"
severities:
  - critical
tags:
  - libpng
  - vulnerability
  - remote-code-execution
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0870
rules:
  - title: Detect Application Crashes Related to Image Processing
    description: Detects application crashes potentially caused by malformed image processing
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - application
      - windows
  - title: Detect Suspicious File Creation by Processes Handling Images
    description: Detects suspicious file creations by applications that handle images, which may indicate exploit attempts
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified in libpng, a widely used library for handling PNG image format. These vulnerabilities could allow a remote, anonymous attacker to execute arbitrary program code or cause a denial of service (DoS). The vulnerabilities stem from weaknesses in how libpng parses and processes PNG image files. While the specifics of the vulnerabilities are not detailed in this advisory, the potential impact necessitates immediate attention from defenders who utilize…
