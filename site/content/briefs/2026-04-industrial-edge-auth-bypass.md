---
title: Industrial Edge Management Authentication Bypass Vulnerability (CVE-2026-33892)
slug: 2026-04-industrial-edge-auth-bypass
description: CVE-2026-33892 allows an unauthenticated remote attacker to bypass authentication and impersonate a legitimate user in affected Industrial Edge Management Pro and Virtual versions by exploiting improper enforcement of user authentication on remote connections to devices, potentially enabling unauthorized access and control.
date: "2026-04-14T09:16:36Z"
severities:
  - high
tags:
  - CVE-2026-33892
  - authentication-bypass
  - industrial-control-system
  - edge-management
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33892
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33892
rules:
  - title: Detect Suspicious Network Connection to Industrial Edge Management
    description: Detects network connections to Industrial Edge Management systems on non-standard ports, which could indicate exploitation of CVE-2026-33892
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Industrial Edge Management Authentication Bypass Attempt
    description: Detects potential authentication bypass attempts on Industrial Edge Management Pro via webserver logs.
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

A critical authentication bypass vulnerability, CVE-2026-33892, affects Industrial Edge Management Pro V1 (versions >= V1.7.6 and < V1.15.17), Industrial Edge Management Pro V2 (versions >= V2.0.0 and < V2.1.1), and Industrial Edge Management Virtual (versions >= V2.2.0 and < V2.8.0). The flaw stems from a failure to properly enforce user authentication on remote connections to managed devices. An unauthenticated attacker can exploit this vulnerability to circumvent authentication mechanisms…
