---
title: 'CVE-2026-32071: Windows LSASS Null Pointer Dereference DoS'
slug: 2026-04-lsass-dos
description: CVE-2026-32071 is a null pointer dereference vulnerability in the Windows Local Security Authority Subsystem Service (LSASS), allowing an unauthorized network attacker to cause a denial-of-service condition.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-32071
  - denial-of-service
  - windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-32071
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32071
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32071
ioc_counts:
  email: 1
rules:
  - title: Detect LSASS Process Crash
    description: Detects LSASS process termination which may indicate a denial-of-service attack
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
  - title: Detect Network traffic to LSASS
    description: Detects network connections to LSASS service which may indicate an exploit attempt
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32071 is a security vulnerability affecting the Windows Local Security Authority Subsystem Service (LSASS). This vulnerability, reported on April 14, 2026, stems from a null pointer dereference error. An unauthenticated attacker, positioned on the network, can exploit this flaw to trigger a denial-of-service (DoS) condition. LSASS is a critical component responsible for security policies, user authentication, and access token management. A successful exploitation of this vulnerability…
