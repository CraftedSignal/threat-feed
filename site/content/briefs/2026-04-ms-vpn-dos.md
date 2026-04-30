---
title: Microsoft VPN Browser+ 1.1.0.0 Denial of Service Vulnerability (CVE-2018-25241)
slug: 2026-04-ms-vpn-dos
description: An unauthenticated attacker can cause a denial of service by crashing Microsoft VPN Browser+ 1.1.0.0 via oversized input to the search functionality, leading to application termination.
date: "2026-04-04T14:16:19Z"
severities:
  - medium
type: advisory
types:
  - advisory
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

Microsoft VPN Browser+ version 1.1.0.0 is susceptible to a denial-of-service (DoS) vulnerability (CVE-2018-25241). This vulnerability allows an unauthenticated attacker to crash the application by providing an overly large input string to the search functionality. The application fails to handle the oversized input correctly, leading to an unhandled exception and subsequent termination. This poses a risk to users relying on the application for VPN services, as it can be easily disrupted without requiring any form of authentication. The vulnerability was reported in April 2026.

## Attack Chain

1.  The attacker identifies a vulnerable instance of Microsoft VPN Browser+ 1.1.0.0.
2.  The attacker opens the application interface.
3.  The attacker locates the search bar within the application.
4.  The attacker pastes an extremely large string (e.g., several megabytes) into the search bar.
5.  The application attempts to process the oversized search query.
6.  Due to inadequate input validation, the application triggers an unhandled exception.
7.  The exception leads to the immediate termination of the Microsoft VPN Browser+ process.
8.  The user experiences a denial of service as the application is no longer running.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, rendering the Microsoft VPN Browser+ application unusable. Users relying on the application for VPN connectivity will be unable to establish or maintain secure connections, potentially exposing them to security risks. While the impact is limited to denial of service, the ease of exploitation and lack of authentication requirements make it a notable concern. The number of affected users depends on the adoption rate of Microsoft VPN Browser+ 1.1.0.0.

## Recommendation

*   Monitor application logs for crashes associated with unusually large search queries to detect potential exploitation attempts (application logs).
*   Implement input validation and sanitization on the search functionality to prevent processing of oversized input strings.
*   Deploy the Sigma rule to detect processes crashing after large input to the Microsoft VPN Browser+ search (Sigma rule).
*   Consider upgrading or patching Microsoft VPN Browser+ to a version that addresses this vulnerability, if available (CVE-2018-25241).
