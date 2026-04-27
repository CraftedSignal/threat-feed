---
title: CrowdStrike LogScale Unauthenticated Path Traversal Vulnerability (CVE-2026-40050)
slug: 2026-04-crowdstrike-logscale-path-traversal
description: A critical unauthenticated path traversal vulnerability (CVE-2026-40050) in CrowdStrike LogScale allows remote attackers to read arbitrary files from the server filesystem if a specific cluster API endpoint is exposed, necessitating immediate patching for self-hosted customers.
date: "2026-04-22T12:00:00Z"
severities:
  - critical
tags:
  - path-traversal
  - vulnerability
  - logscale
  - crowdstrike
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40050
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40050
rules:
  - title: Detect LogScale Path Traversal Attempts
    description: Detects potential path traversal attempts against LogScale servers by monitoring HTTP requests with common path traversal sequences.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect LogScale HTTP 400 Errors Indicative of Exploitation
    description: Detects HTTP 400 errors from LogScale servers when processing suspicious path traversal payloads
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

CrowdStrike has disclosed CVE-2026-40050, a critical unauthenticated path traversal vulnerability affecting specific versions of LogScale. This vulnerability allows unauthenticated remote attackers to read arbitrary files from the server's filesystem. The vulnerability resides in a specific cluster API endpoint. CrowdStrike mitigated the vulnerability for LogScale SaaS customers on April 7, 2026, by deploying network-layer blocks. CrowdStrike self-hosted LogScale customers are urged to upgrade…
