---
title: LORIS File Traversal Vulnerability (CVE-2026-34392)
slug: 2026-04-loris-file-traversal
description: A file traversal vulnerability (CVE-2026-34392) in LORIS versions 20.0.0 to before 27.0.3 and 28.0.1 allows an unauthenticated attacker to download arbitrary files via the static file router.
date: "2026-04-08T19:25:21Z"
severities:
  - high
tags:
  - file-traversal
  - web-application
  - cve-2026-34392
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34392
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34392
  - https://github.com/aces/Loris/security/advisories/GHSA-rfj5-58hv-wc5f
rules:
  - title: LORIS File Traversal Attempt via Static Endpoints
    description: Detects attempts to exploit CVE-2026-34392 by using directory traversal sequences in requests to LORIS static file endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: LORIS File Traversal via Encoded Traversal Sequences
    description: Detects attempts to exploit CVE-2026-34392 using URL encoded directory traversal sequences.
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

LORIS (Longitudinal Online Research and Imaging System) is a self-hosted web application used for data and project management in neuroimaging research. A critical file traversal vulnerability, identified as CVE-2026-34392, exists within the static file router of LORIS versions 20.0.0 to before 27.0.3 and 28.0.1. This flaw allows an unauthenticated attacker to access and download unintended files by manipulating requests to the `/static`, `/css`, and `/js` endpoints. Successful exploitation of…
