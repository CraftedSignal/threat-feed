---
title: Multiple Vulnerabilities in libpng Allow Remote Code Execution and Denial of Service
slug: 2026-03-libpng-vulns
description: Multiple vulnerabilities in libpng allow a remote, anonymous attacker to perform denial of service attacks and execute arbitrary code.
date: "2026-03-24T10:20:58Z"
severities:
  - critical
tags:
  - libpng
  - vulnerability
  - denial-of-service
  - code execution
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
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2663
rules:
  - title: Detect Suspicious PNG File Uploads
    description: Detects attempts to upload PNG files with unusually large sizes or other anomalous characteristics, potentially indicating an exploit attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect Process Creating PNG files
    description: Detects creation of PNG files by unusual processes, potentially indicating malicious activity
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified within the libpng library. A remote, anonymous attacker can exploit these vulnerabilities to achieve both denial of service (DoS) and arbitrary code execution. The libpng library is a widely used component in numerous applications, making this a critical vulnerability with a broad potential impact. Successful exploitation could lead to application crashes, system instability, or complete system compromise, depending on the context in which libpng is…
