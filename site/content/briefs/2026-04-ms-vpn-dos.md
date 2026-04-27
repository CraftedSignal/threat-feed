---
title: Microsoft VPN Browser+ 1.1.0.0 Denial of Service Vulnerability (CVE-2018-25241)
slug: 2026-04-ms-vpn-dos
description: An unauthenticated attacker can cause a denial of service by crashing Microsoft VPN Browser+ 1.1.0.0 via oversized input to the search functionality, leading to application termination.
date: "2026-04-04T14:16:19Z"
severities:
  - medium
tags:
  - dos
  - cve-2018-25241
  - microsoft
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2018-25241
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25241
  - https://www.exploit-db.com/exploits/46198
  - https://www.microsoft.com/store/productId/9NFFFFS5Z2C7
  - https://www.vulncheck.com/advisories/microsoft-vpn-browser-denial-of-service
rules:
  - title: Microsoft VPN Browser+ Crash After Large Search Input
    description: Detects crashes of Microsoft VPN Browser+ after potentially processing a large search input, indicating a possible denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - application
      - windows
  - title: Detect Large Input to Microsoft VPN Browser+ via Process Creation
    description: Detects the execution of cmd.exe or powershell.exe after a long string is used in vpnBrowser.exe to identify exploitation of CVE-2018-25241.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Microsoft VPN Browser+ version 1.1.0.0 is susceptible to a denial-of-service (DoS) vulnerability (CVE-2018-25241). This vulnerability allows an unauthenticated attacker to crash the application by providing an overly large input string to the search functionality. The application fails to handle the oversized input correctly, leading to an unhandled exception and subsequent termination. This poses a risk to users relying on the application for VPN services, as it can be easily disrupted without…
